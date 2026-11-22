//! Multisig threshold verification on proposal execution (Issue #537).
//!
//! The proposal contract enacts governance decisions on behalf of the
//! multisig. Reaching `Approved` is not enough to execute: on every execution
//! attempt the proposal re-derives its tally from the *live* multisig and
//! refuses before any state change when:
//!
//! | Condition                                          | Error                |
//! |----------------------------------------------------|----------------------|
//! | verified signer weight < multisig threshold        | `ThresholdNotMet`    |
//! | allow-list quorum / majority no longer met         | `ThresholdNotMet`    |
//! | multisig emergency lock engaged                    | `EmergencyLock`      |
//!
//! Each scenario deploys a real multisig with weighted signers (3 / 2 / 1)
//! next to the proposal contract, escrows a real SAC-token deposit behind the
//! vote, and checks both the error code and that nothing moved: the proposal
//! stays `Approved` and the deposit stays in custody. The `can_execute` view
//! must agree with the entrypoint in every case.

use astroid_multisig::{MultiSigContract, MultiSigContractClient, SignerWeight};
use astroid_proposal::{ProposalContract, ProposalContractClient, ProposalState};
use astroid_shared::constants::THRESHOLD_CHANGE_DELAY_LEDGERS;
use astroid_shared::errors::Error;
use astroid_shared::types::AssetAmount;
use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::{token, vec, Address, Env, String, Vec};

const START: u64 = 1_000;
const DEPOSIT: i128 = 2_500;

struct Harness {
    env: Env,
    multisig: MultiSigContractClient<'static>,
    proposals: ProposalContractClient<'static>,
    asset: Address,
    proposer: Address,
    /// Weight 3.
    alice: Address,
    /// Weight 2.
    bob: Address,
    /// Weight 1.
    carol: Address,
}

/// Deploy a 3/2/1-weighted multisig with `threshold`, and a proposal contract
/// bound to it with no timelock so the threshold is the only execution gate.
fn setup(threshold: u32) -> Harness {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().with_mut(|l| {
        l.sequence_number = 1;
        l.timestamp = START;
    });

    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    let carol = Address::generate(&env);

    let multisig_id = env.register_contract(None, MultiSigContract);
    let multisig = MultiSigContractClient::new(&env, &multisig_id);
    multisig.initialize(
        &vec![
            &env,
            SignerWeight {
                address: alice.clone(),
                weight: 3,
            },
            SignerWeight {
                address: bob.clone(),
                weight: 2,
            },
            SignerWeight {
                address: carol.clone(),
                weight: 1,
            },
        ],
        &threshold,
    );

    let proposal_id = env.register_contract(None, ProposalContract);
    let proposals = ProposalContractClient::new(&env, &proposal_id);
    proposals.initialize(&0, &multisig_id);

    let asset = env
        .register_stellar_asset_contract_v2(Address::generate(&env))
        .address();
    let proposer = Address::generate(&env);
    token::StellarAssetClient::new(&env, &asset).mint(&proposer, &(DEPOSIT * 10));

    Harness {
        env,
        multisig,
        proposals,
        asset,
        proposer,
        alice,
        bob,
        carol,
    }
}

/// Create a proposal whose allow-list is every signer, with an allow-list
/// threshold of `allow_list_threshold`.
fn create(h: &Harness, allow_list_threshold: u32) -> u64 {
    let approvers: Vec<Address> = vec![&h.env, h.alice.clone(), h.bob.clone(), h.carol.clone()];
    let deposit: Vec<AssetAmount> = vec![
        &h.env,
        AssetAmount {
            asset: h.asset.clone(),
            amount: DEPOSIT,
        },
    ];
    h.proposals.create(
        &h.proposer,
        &String::from_str(&h.env, "acme"),
        &String::from_str(&h.env, "wallet-1"),
        &String::from_str(&h.env, "policy-1"),
        &approvers,
        &vec![&h.env],
        &allow_list_threshold,
        &deposit,
        &(START + 1_000_000),
        &0,
    )
}

fn custody(h: &Harness) -> i128 {
    token::TokenClient::new(&h.env, &h.asset).balance(&h.proposals.address)
}

/// The refusal invariants every failing scenario shares: the exact error,
/// no state change, the deposit still in custody, and a view that agrees.
fn assert_refused(h: &Harness, id: u64, expected: Error) {
    let custody_before = custody(h);
    assert_eq!(h.proposals.try_execute(&h.proposer, &id), Err(Ok(expected)));
    assert_eq!(h.proposals.state(&id), ProposalState::Approved);
    assert_eq!(custody(h), custody_before);
    assert!(!h.proposals.can_execute(&id));
}

fn assert_executes(h: &Harness, id: u64) {
    assert!(h.proposals.can_execute(&id));
    h.proposals.execute(&h.proposer, &id);
    assert_eq!(h.proposals.state(&id), ProposalState::Executed);
}

#[test]
fn weight_meeting_the_threshold_exactly_executes() {
    // alice (3) + carol (1) = 4 == threshold.
    let h = setup(4);
    let id = create(&h, 2);
    h.proposals.approve(&h.alice, &id);
    h.proposals.approve(&h.carol, &id);

    assert_executes(&h, id);
    // The deposit is returned to the proposer on execution.
    assert_eq!(custody(&h), 0);
}

#[test]
fn approved_by_head_count_but_under_weight_is_refused_with_threshold_not_met() {
    // bob (2) + carol (1) = 3 < 4: the allow-list threshold (2 approvals) and a
    // strict majority are met, so the proposal is `Approved`, but the
    // multisig weight is not.
    let h = setup(4);
    let id = create(&h, 2);
    h.proposals.approve(&h.bob, &id);
    h.proposals.approve(&h.carol, &id);
    assert_eq!(h.proposals.state(&id), ProposalState::Approved);

    assert_refused(&h, id, Error::QUORUM_NOT_MET);

    // Topping the weight up clears the gate without re-creating anything.
    h.proposals.approve(&h.alice, &id);
    assert_executes(&h, id);
}

#[test]
fn threshold_raised_after_approval_is_enforced_at_execution() {
    // alice (3) + bob (2) = 5 clears the original threshold of 4 ...
    let h = setup(4);
    let id = create(&h, 2);
    h.proposals.approve(&h.alice, &id);
    h.proposals.approve(&h.bob, &id);
    assert!(h.proposals.can_execute(&id));

    // ... but governance raises the threshold to 6 before execution.
    h.multisig.set_threshold(&h.alice, &6);
    h.env.ledger().with_mut(|l| {
        l.sequence_number += THRESHOLD_CHANGE_DELAY_LEDGERS;
    });
    h.multisig.finalize_threshold(&h.alice);
    assert_eq!(h.multisig.get_total_weight(), 6);

    // The live threshold applies: 5 < 6.
    assert_refused(&h, id, Error::QUORUM_NOT_MET);

    h.proposals.approve(&h.carol, &id);
    assert_executes(&h, id);
}

#[test]
fn removed_signer_weight_no_longer_counts_toward_execution() {
    // Threshold 3: alice (3) alone would be enough weight, bob (2) + carol (1)
    // also exactly reach it.
    let h = setup(3);
    let id = create(&h, 2);
    h.proposals.approve(&h.bob, &id);
    h.proposals.approve(&h.carol, &id);
    assert!(h.proposals.can_execute(&id));

    // Carol leaves the multisig: her recorded approval stops counting, so the
    // verified weight drops to 2 < 3 and the head count to 1 of 3.
    h.multisig.remove_signer(&h.alice, &h.carol);

    assert_refused(&h, id, Error::ThresholdNotMet);
}

#[test]
fn emergency_lock_on_the_multisig_blocks_execution() {
    let h = setup(4);
    let id = create(&h, 2);
    h.proposals.approve(&h.alice, &id);
    h.proposals.approve(&h.bob, &id);
    assert!(h.proposals.can_execute(&id));

    h.multisig.set_emergency_lock(&h.alice, &true);
    assert_refused(&h, id, Error::EmergencyLock);

    // Releasing the lock restores execution with the same votes.
    h.multisig.set_emergency_lock(&h.alice, &false);
    assert_executes(&h, id);
}

#[test]
fn pending_proposal_is_refused_before_any_threshold_check() {
    let h = setup(4);
    let id = create(&h, 2);
    h.proposals.approve(&h.alice, &id);
    assert_eq!(h.proposals.state(&id), ProposalState::Pending);

    assert_eq!(
        h.proposals.try_execute(&h.proposer, &id),
        Err(Ok(Error::ProposalNotApproved))
    );
    assert!(!h.proposals.can_execute(&id));
    assert_eq!(custody(&h), DEPOSIT);
}
