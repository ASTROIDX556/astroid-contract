//! Time-lock enforcement across the proposal contract boundary (issue #209).
//!
//! The proposal crate's own unit tests pin the arithmetic of the release
//! criteria; these scenarios drive the *deployed* contract from outside the
//! crate, with a real SAC-token deposit escrowed behind the vote, and advance
//! the deterministic ledger clock (sequence and timestamp together, exactly as
//! the host fixes them for a real invocation) one step at a time.
//!
//! What they pin down is the boundary: a premature execution attempt is
//! refused with the distinct `TimelockNotExpired` code and moves no funds, the
//! attempt made at the exact release instant succeeds, and the configured
//! delay is observable on-chain through the `timelock`, `release_at` and
//! `timelock_status` views so a client can check before spending a
//! transaction.

use astroid_multisig::{MultiSigContract, MultiSigContractClient, SignerWeight};
use astroid_proposal::{ProposalContract, ProposalContractClient, ProposalState};
use astroid_shared::errors::Error;
use astroid_shared::types::AssetAmount;
use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::{token, vec, Address, Env, String, Vec};

/// Ledger timestamp the harness starts every scenario at.
const START: u64 = 1_000;
/// The mandatory cooling-off period every scenario configures.
const TIMELOCK: u64 = 3_600;

struct Harness {
    env: Env,
    proposals: ProposalContractClient<'static>,
    asset: Address,
    proposer: Address,
    approvers: std::vec::Vec<Address>,
    contract: Address,
}

fn setup(timelock: u64) -> Harness {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().with_mut(|l| {
        l.sequence_number = 1;
        l.timestamp = START;
    });

    let mut approvers = std::vec::Vec::new();
    for _ in 0..3 {
        approvers.push(Address::generate(&env));
    }

    let multisig_id = env.register_contract(None, MultiSigContract);
    let multisig = MultiSigContractClient::new(&env, &multisig_id);
    let mut signers = Vec::new(&env);
    for approver in &approvers {
        signers.push_back(SignerWeight {
            address: approver.clone(),
            weight: 1,
        });
    }
    multisig.initialize(&signers, &2);

    let contract_id = env.register_contract(None, ProposalContract);
    let proposals = ProposalContractClient::new(&env, &contract_id);
    proposals.initialize(&timelock, &multisig_id);

    let asset = env
        .register_stellar_asset_contract_v2(Address::generate(&env))
        .address();
    let proposer = Address::generate(&env);
    token::StellarAssetClient::new(&env, &asset).mint(&proposer, &100_000);

    Harness {
        env,
        proposals,
        asset,
        proposer,
        approvers,
        contract: contract_id,
    }
}

/// Create a proposal escrowing `deposit` behind a two-of-three approval.
fn create(h: &Harness, deposit: i128) -> u64 {
    let mut approvers = Vec::new(&h.env);
    for a in &h.approvers {
        approvers.push_back(a.clone());
    }
    let deposit: Vec<AssetAmount> = vec![
        &h.env,
        AssetAmount {
            asset: h.asset.clone(),
            amount: deposit,
        },
    ];
    h.proposals.create(
        &h.proposer,
        &String::from_str(&h.env, "acme"),
        &String::from_str(&h.env, "wallet-1"),
        &String::from_str(&h.env, "policy-1"),
        &approvers,
        &vec![&h.env],
        &2,
        &deposit,
        &(START + 100_000),
        &0,
    )
}

fn balance(h: &Harness, who: &Address) -> i128 {
    token::TokenClient::new(&h.env, &h.asset).balance(who)
}

/// Advance the mock ledger to `sequence` / `timestamp` together, as the host
/// fixes them for a real invocation.
fn advance(h: &Harness, sequence: u32, timestamp: u64) {
    h.env.ledger().with_mut(|l| {
        l.sequence_number = sequence;
        l.timestamp = timestamp;
    });
}

fn approve_to_threshold(h: &Harness, id: u64) {
    h.proposals.approve(&h.approvers[0], &id);
    h.proposals.approve(&h.approvers[1], &id);
    assert_eq!(h.proposals.state(&id), ProposalState::Approved);
}

#[test]
fn premature_execution_is_refused_with_the_distinct_code_and_moves_nothing() {
    let h = setup(TIMELOCK);
    let id = create(&h, 5_000);

    // The deposit is held by the contract from creation onwards.
    assert_eq!(balance(&h, &h.contract), 5_000);
    assert_eq!(balance(&h, &h.proposer), 95_000);

    approve_to_threshold(&h, id);
    let release = START + TIMELOCK;

    // One second before the release instant: refused with the dedicated
    // premature-execution code, the proposal stays `Approved` and the deposit
    // stays put.
    advance(&h, 2, release - 1);
    assert_eq!(
        h.proposals.try_execute(&h.proposer, &id),
        Err(Ok(Error::TimelockNotExpired))
    );
    assert_eq!(h.proposals.state(&id), ProposalState::Approved);
    assert_eq!(balance(&h, &h.contract), 5_000);
    assert_eq!(balance(&h, &h.proposer), 95_000);
    assert!(!h.proposals.can_execute(&id));

    // The refusal is deterministic: the same ledger yields the same code, and
    // the caller-authorization gate still precedes it, so nobody can even reach
    // the schedule check without authorizing as the proposer.
    let intruder = Address::generate(&h.env);
    assert_eq!(
        h.proposals.try_execute(&intruder, &id),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(
        h.proposals.try_execute(&h.proposer, &id),
        Err(Ok(Error::TimelockNotExpired))
    );
}

#[test]
fn execution_at_the_exact_release_instant_succeeds_and_settles_cleanly() {
    let h = setup(TIMELOCK);
    let id = create(&h, 5_000);
    approve_to_threshold(&h, id);
    let release = START + TIMELOCK;

    advance(&h, 2, release);
    assert!(h.proposals.can_execute(&id));
    h.proposals.execute(&h.proposer, &id);

    assert_eq!(h.proposals.state(&id), ProposalState::Executed);
    // The escrowed deposit returns to the proposer and the contract holds none.
    assert_eq!(balance(&h, &h.proposer), 100_000);
    assert_eq!(balance(&h, &h.contract), 0);

    // The lifecycle closes cleanly behind a matured time-lock.
    h.proposals.close(&h.proposer, &id);
    assert_eq!(h.proposals.state(&id), ProposalState::Closed);
    // And a second execution is a state error, never a second release.
    assert_eq!(
        h.proposals.try_execute(&h.proposer, &id),
        Err(Ok(Error::ProposalNotApproved))
    );
    assert_eq!(balance(&h, &h.proposer), 100_000);
}

#[test]
fn the_release_criteria_are_observable_before_spending_a_transaction() {
    let h = setup(TIMELOCK);
    let id = create(&h, 5_000);

    // The configured delay is readable, and a pending proposal has no release
    // instant to report.
    assert_eq!(h.proposals.timelock(), TIMELOCK);
    assert_eq!(h.proposals.release_at(&id), 0);
    let pending = h.proposals.timelock_status(&id);
    assert!(!pending.armed);
    assert_eq!(pending.release_at, 0);

    approve_to_threshold(&h, id);
    assert_eq!(h.proposals.release_at(&id), START + TIMELOCK);

    // The countdown the client polls matches the instant the entrypoint will
    // accept, step for step, with the boundary resolved inclusively.
    for (sequence, timestamp, expected) in [
        (2u32, START, TIMELOCK),
        (3, START + 1_800, 1_800),
        (4, START + TIMELOCK - 1, 1),
        (5, START + TIMELOCK, 0),
    ] {
        advance(&h, sequence, timestamp);
        let status = h.proposals.timelock_status(&id);
        assert_eq!(status.remaining, expected, "at t = {timestamp}");
        assert_eq!(status.blocking(), expected != 0, "at t = {timestamp}");
        assert_eq!(
            h.proposals.can_execute(&id),
            expected == 0,
            "at t = {timestamp}"
        );
    }
}

#[test]
fn a_zero_time_lock_settles_without_any_cooling_off() {
    let h = setup(0);
    let id = create(&h, 5_000);

    assert_eq!(h.proposals.timelock(), 0);
    approve_to_threshold(&h, id);

    // No delay configured: the time-lock never arms, so the same ledger that
    // was `Approved` a moment ago executes immediately.
    let status = h.proposals.timelock_status(&id);
    assert!(!status.armed);
    assert!(status.released);
    assert_eq!(status.remaining, 0);
    assert_eq!(h.proposals.release_at(&id), 0);
    assert!(h.proposals.can_execute(&id));

    h.proposals.execute(&h.proposer, &id);
    assert_eq!(h.proposals.state(&id), ProposalState::Executed);
    assert_eq!(balance(&h, &h.proposer), 100_000);
}

#[test]
fn a_delay_that_cannot_be_represented_fails_closed_rather_than_early() {
    // `approved_at + timelock` overflows a ledger timestamp. The release
    // criteria are unresolvable, so the contract refuses deterministically
    // instead of truncating into the past and releasing on approval.
    let h = setup(u64::MAX);
    let id = create(&h, 5_000);
    approve_to_threshold(&h, id);

    assert_eq!(h.proposals.try_release_at(&id), Err(Ok(Error::Overflow)));
    assert_eq!(
        h.proposals.try_timelock_status(&id),
        Err(Ok(Error::Overflow))
    );
    assert_eq!(
        h.proposals.try_execute(&h.proposer, &id),
        Err(Ok(Error::Overflow))
    );
    assert_eq!(h.proposals.state(&id), ProposalState::Approved);
    assert!(!h.proposals.can_execute(&id));
    assert_eq!(balance(&h, &h.contract), 5_000);
}

#[test]
fn a_timelocked_proposal_still_chains_behind_its_prerequisite_after_maturity() {
    // The time-lock delays execution; it must not let a dependent proposal
    // jump its chain. Both the dependency report and the eventual release
    // keep their own, distinct error codes.
    let h = setup(TIMELOCK);
    let first = create(&h, 5_000);
    let mut approvers = Vec::new(&h.env);
    for a in &h.approvers {
        approvers.push_back(a.clone());
    }
    let second = h.proposals.create(
        &h.proposer,
        &String::from_str(&h.env, "acme"),
        &String::from_str(&h.env, "wallet-2"),
        &String::from_str(&h.env, "policy-1"),
        &approvers,
        &vec![&h.env, first],
        &2,
        &vec![&h.env],
        &(START + 100_000),
        &0,
    );

    // Both reach their threshold on the same ledger, so both mature together.
    approve_to_threshold(&h, first);
    approve_to_threshold(&h, second);
    assert_eq!(h.proposals.release_at(&first), START + TIMELOCK);
    assert_eq!(h.proposals.release_at(&second), START + TIMELOCK);

    // Matured, but the prerequisite has not executed: the chain still blocks,
    // and the report is the dependency code, not the timelock one.
    advance(&h, 2, START + TIMELOCK);
    assert!(!h.proposals.can_execute(&second));
    assert_eq!(
        h.proposals.try_execute(&h.proposer, &second),
        Err(Ok(Error::PrerequisiteNotMet))
    );

    // The prerequisite settles, and the dependent runs in the same ledger.
    h.proposals.execute(&h.proposer, &first);
    h.proposals.execute(&h.proposer, &second);

    assert_eq!(h.proposals.state(&first), ProposalState::Executed);
    assert_eq!(h.proposals.state(&second), ProposalState::Executed);
    assert_eq!(balance(&h, &h.proposer), 100_000);
}
