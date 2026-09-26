#![cfg(test)]
extern crate std;

use crate::{ProposalContract, ProposalContractClient, ProposalState};
use astroid_shared::constants::{MAX_APPROVERS, MAX_DEPENDENCIES};
use astroid_shared::errors::Error;
use astroid_shared::types::AssetAmount;
use soroban_sdk::testutils::{Address as _, Events, Ledger};
use soroban_sdk::{vec, Address, Env, IntoVal, String, Symbol, Val, Vec};

struct Harness {
    env: Env,
    client: ProposalContractClient<'static>,
    proposer: Address,
    approvers: std::vec::Vec<Address>,
}

fn setup(num_approvers: u32) -> Harness {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000);
    let contract_id = env.register_contract(None, ProposalContract);
    let client = ProposalContractClient::new(&env, &contract_id);
    client.initialize(&0);

    let proposer = Address::generate(&env);
    let mut approvers = std::vec::Vec::new();
    for _ in 0..num_approvers {
        approvers.push(Address::generate(&env));
    }
    Harness {
        env,
        client,
        proposer,
        approvers,
    }
}

/// Like [`setup`], but with a mandatory non-zero timelock configured at
/// initialization.
fn setup_timelocked(num_approvers: u32, timelock: u64) -> Harness {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000);
    let contract_id = env.register_contract(None, ProposalContract);
    let client = ProposalContractClient::new(&env, &contract_id);
    client.initialize(&timelock);

    let proposer = Address::generate(&env);
    let mut approvers = std::vec::Vec::new();
    for _ in 0..num_approvers {
        approvers.push(Address::generate(&env));
    }
    Harness {
        env,
        client,
        proposer,
        approvers,
    }
}

fn approver_vec(h: &Harness) -> Vec<Address> {
    let mut v = Vec::new(&h.env);
    for a in &h.approvers {
        v.push_back(a.clone());
    }
    v
}

/// Create an independent proposal (no prerequisites).
fn create(h: &Harness, threshold: u32, expires_at: u64) -> u64 {
    create_with_deps(h, threshold, expires_at, &[])
}

/// Create a proposal that depends on `deps`.
fn create_with_deps(h: &Harness, threshold: u32, expires_at: u64, deps: &[u64]) -> u64 {
    h.client.create(
        &h.proposer,
        &String::from_str(&h.env, "acme"),
        &String::from_str(&h.env, "wallet-1"),
        &String::from_str(&h.env, "policy-1"),
        &approver_vec(h),
        &dep_vec(h, deps),
        &threshold,
        &vec![&h.env],
        &expires_at,
        &0,
    )
}

/// `create_with_deps` in its fallible form, for the rejection paths.
fn try_create_with_deps(h: &Harness, deps: &[u64]) -> Result<u64, Error> {
    h.client
        .try_create(
            &h.proposer,
            &String::from_str(&h.env, "acme"),
            &String::from_str(&h.env, "wallet-1"),
            &String::from_str(&h.env, "policy-1"),
            &approver_vec(h),
            &dep_vec(h, deps),
            &2,
            &vec![&h.env],
            &0,
            &0,
        )
        .map(|ok| ok.unwrap())
        .map_err(|err| err.unwrap())
}

fn dep_vec(h: &Harness, deps: &[u64]) -> Vec<u64> {
    let mut v = Vec::new(&h.env);
    for d in deps {
        v.push_back(*d);
    }
    v
}

/// Whether any event carrying `symbol` in its topics has been emitted.
fn emitted(env: &Env, symbol: &str) -> bool {
    let want: Val = Symbol::new(env, symbol).into_val(env);
    env.events()
        .all()
        .iter()
        .any(|(_contract_id, topics, _data)| topics.contains(want))
}

/// Drive a proposal all the way to `Executed`.
fn approve_and_execute(h: &Harness, id: u64) {
    h.client.approve(&h.approvers[0], &id);
    h.client.approve(&h.approvers[1], &id);
    h.client.execute(&h.proposer, &id);
}

#[test]
fn create_starts_pending() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    assert_eq!(h.client.state(&id), ProposalState::Pending);
}

#[test]
fn full_lifecycle_to_closed() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    h.client.approve(&h.approvers[0], &id);
    let approvals = h.client.approve(&h.approvers[1], &id);
    assert_eq!(approvals, 2);
    assert_eq!(h.client.state(&id), ProposalState::Approved);

    h.client.execute(&h.proposer, &id);
    assert_eq!(h.client.state(&id), ProposalState::Executed);

    h.client.close(&h.proposer, &id);
    assert_eq!(h.client.state(&id), ProposalState::Closed);
}

#[test]
fn execute_before_approved_fails() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    h.client.approve(&h.approvers[0], &id); // only 1 of 2
    let res = h.client.try_execute(&h.proposer, &id);
    assert_eq!(res, Err(Ok(Error::ProposalNotApproved)));
}

#[test]
fn non_approver_cannot_approve() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    let stranger = Address::generate(&h.env);
    let res = h.client.try_approve(&stranger, &id);
    assert_eq!(res, Err(Ok(Error::NotAnApprover)));
}

#[test]
fn double_approval_rejected() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    h.client.approve(&h.approvers[0], &id);
    let res = h.client.try_approve(&h.approvers[0], &id);
    assert_eq!(res, Err(Ok(Error::AlreadySigned)));
}

#[test]
fn reject_moves_to_rejected() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    h.client.reject(&h.approvers[0], &id);
    assert_eq!(h.client.state(&id), ProposalState::Rejected);
    // Cannot approve a rejected proposal.
    let res = h.client.try_approve(&h.approvers[1], &id);
    assert_eq!(res, Err(Ok(Error::InvalidProposalState)));
}

#[test]
fn only_proposer_can_cancel() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    let res = h.client.try_cancel(&h.approvers[0], &id);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
    h.client.cancel(&h.proposer, &id);
    assert_eq!(h.client.state(&id), ProposalState::Cancelled);
}

#[test]
fn expired_proposal_cannot_be_approved() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    // Advance beyond expiry.
    h.env.ledger().set_timestamp(6_000);
    let res = h.client.try_approve(&h.approvers[0], &id);
    assert_eq!(res, Err(Ok(Error::ProposalExpired)));
    // The failed approval is rolled back by the host, so the proposal is still
    // Pending on-chain. The terminal `Expired` transition is recorded only via
    // the permissionless `expire()` path (see `explicit_expire_transition`).
    assert_eq!(h.client.state(&id), ProposalState::Pending);
    h.client.expire(&id);
    assert_eq!(h.client.state(&id), ProposalState::Expired);
}

#[test]
fn explicit_expire_transition() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    // Cannot expire before the deadline: the proposal has not entered the
    // Expired state, so the transition does not apply yet.
    let early = h.client.try_expire(&id);
    assert_eq!(early, Err(Ok(Error::InvalidProposalState)));
    h.env.ledger().set_timestamp(6_000);
    h.client.expire(&id);
    assert_eq!(h.client.state(&id), ProposalState::Expired);
}

#[test]
fn create_with_bad_threshold_fails() {
    let h = setup(2);
    // threshold 3 > 2 approvers
    let res = h.client.try_create(
        &h.proposer,
        &String::from_str(&h.env, "acme"),
        &String::from_str(&h.env, "wallet-1"),
        &String::from_str(&h.env, "policy-1"),
        &approver_vec(&h),
        &dep_vec(&h, &[]),
        &3,
        &vec![&h.env],
        &5_000,
        &0,
    );
    assert_eq!(res, Err(Ok(Error::InvalidThreshold)));
}

#[test]
fn create_with_past_expiry_fails() {
    let h = setup(2);
    let res = h.client.try_create(
        &h.proposer,
        &String::from_str(&h.env, "acme"),
        &String::from_str(&h.env, "wallet-1"),
        &String::from_str(&h.env, "policy-1"),
        &approver_vec(&h),
        &dep_vec(&h, &[]),
        &1,
        &vec![&h.env],
        &500, // in the past (now = 1000)
        &0,
    );
    assert_eq!(res, Err(Ok(Error::InvalidInput)));
}

// ---------------------------------------------------------------------------
// Dependency chaining
// ---------------------------------------------------------------------------

#[test]
fn independent_proposal_declares_no_dependencies() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    assert_eq!(h.client.dependencies(&id), dep_vec(&h, &[]));
    assert!(h.client.dependencies_met(&id));
}

#[test]
fn chain_executes_in_order() {
    let h = setup(3);
    let first = create(&h, 2, 5_000);
    let second = create_with_deps(&h, 2, 5_000, &[first]);
    let third = create_with_deps(&h, 2, 5_000, &[second]);

    assert_eq!(h.client.dependencies(&second), dep_vec(&h, &[first]));

    approve_and_execute(&h, first);
    assert_eq!(h.client.state(&first), ProposalState::Executed);

    assert!(h.client.dependencies_met(&second));
    approve_and_execute(&h, second);

    assert!(h.client.dependencies_met(&third));
    approve_and_execute(&h, third);
    assert_eq!(h.client.state(&third), ProposalState::Executed);
}

#[test]
fn execution_blocked_until_prerequisite_executes() {
    let h = setup(3);
    let first = create(&h, 2, 5_000);
    let second = create_with_deps(&h, 2, 5_000, &[first]);

    // Fully approved, but its prerequisite has not executed.
    h.client.approve(&h.approvers[0], &second);
    h.client.approve(&h.approvers[1], &second);
    assert_eq!(h.client.state(&second), ProposalState::Approved);
    assert!(!h.client.dependencies_met(&second));

    assert_eq!(
        h.client.try_execute(&h.proposer, &second),
        Err(Ok(Error::PrerequisiteNotMet))
    );
    // The blocked proposal stays Approved and remains executable later.
    assert_eq!(h.client.state(&second), ProposalState::Approved);

    approve_and_execute(&h, first);
    h.client.execute(&h.proposer, &second);
    assert_eq!(h.client.state(&second), ProposalState::Executed);
}

#[test]
fn approval_is_not_blocked_by_dependencies() {
    let h = setup(3);
    let first = create(&h, 2, 5_000);
    let second = create_with_deps(&h, 2, 5_000, &[first]);

    // A dependent proposal can still gather approvals ahead of its
    // prerequisite; only execution is sequenced.
    h.client.approve(&h.approvers[0], &second);
    let approvals = h.client.approve(&h.approvers[1], &second);
    assert_eq!(approvals, 2);
    assert_eq!(h.client.state(&second), ProposalState::Approved);
}

#[test]
fn all_prerequisites_must_execute() {
    let h = setup(3);
    let a = create(&h, 2, 5_000);
    let b = create(&h, 2, 5_000);
    let dependent = create_with_deps(&h, 2, 5_000, &[a, b]);

    h.client.approve(&h.approvers[0], &dependent);
    h.client.approve(&h.approvers[1], &dependent);

    approve_and_execute(&h, a);
    // One of two prerequisites done is not enough.
    assert!(!h.client.dependencies_met(&dependent));
    assert_eq!(
        h.client.try_execute(&h.proposer, &dependent),
        Err(Ok(Error::PrerequisiteNotMet))
    );

    approve_and_execute(&h, b);
    h.client.execute(&h.proposer, &dependent);
    assert_eq!(h.client.state(&dependent), ProposalState::Executed);
}

#[test]
fn failed_prerequisite_blocks_the_chain_permanently() {
    let h = setup(3);
    let first = create(&h, 2, 5_000);
    let second = create_with_deps(&h, 2, 5_000, &[first]);

    h.client.approve(&h.approvers[0], &first);
    h.client.approve(&h.approvers[1], &first);
    h.client.fail(&h.proposer, &first);
    assert_eq!(h.client.state(&first), ProposalState::Failed);

    h.client.approve(&h.approvers[0], &second);
    h.client.approve(&h.approvers[1], &second);
    assert!(!h.client.dependencies_met(&second));
    assert_eq!(
        h.client.try_execute(&h.proposer, &second),
        Err(Ok(Error::PrerequisiteNotMet))
    );
    // Failed is terminal, so the prerequisite can never be satisfied.
    assert_eq!(
        h.client.try_execute(&h.proposer, &first),
        Err(Ok(Error::ProposalNotApproved))
    );
}

#[test]
fn cancelled_prerequisite_blocks_the_chain() {
    let h = setup(3);
    let first = create(&h, 2, 5_000);
    let second = create_with_deps(&h, 2, 5_000, &[first]);
    h.client.cancel(&h.proposer, &first);

    h.client.approve(&h.approvers[0], &second);
    h.client.approve(&h.approvers[1], &second);
    assert_eq!(
        h.client.try_execute(&h.proposer, &second),
        Err(Ok(Error::PrerequisiteNotMet))
    );
}

#[test]
fn closed_prerequisite_still_satisfies_dependents() {
    let h = setup(3);
    let first = create(&h, 2, 5_000);
    let second = create_with_deps(&h, 2, 5_000, &[first]);

    approve_and_execute(&h, first);
    // Tidying an executed prerequisite away must not block its dependents.
    h.client.close(&h.proposer, &first);
    assert_eq!(h.client.state(&first), ProposalState::Closed);

    assert!(h.client.dependencies_met(&second));
    approve_and_execute(&h, second);
    assert_eq!(h.client.state(&second), ProposalState::Executed);
}

#[test]
fn self_reference_is_rejected_as_circular() {
    let h = setup(3);
    // The next id would be 1, so depending on 1 is a self-reference.
    assert_eq!(
        try_create_with_deps(&h, &[1]),
        Err(Error::CircularDependencyDetected)
    );
}

#[test]
fn forward_reference_is_rejected_as_circular() {
    let h = setup(3);
    let first = create(&h, 2, 5_000);
    // Depending on a not-yet-created proposal is the only way an edge could
    // point forward, which is the only way a cycle could form.
    assert_eq!(
        try_create_with_deps(&h, &[first + 5]),
        Err(Error::CircularDependencyDetected)
    );
}

#[test]
fn duplicate_dependencies_are_collapsed() {
    let h = setup(3);
    let first = create(&h, 2, 5_000);
    let dependent = create_with_deps(&h, 2, 5_000, &[first, first, first]);
    // Stored once, so execution reads the prerequisite exactly once.
    assert_eq!(h.client.dependencies(&dependent), dep_vec(&h, &[first]));
}

#[test]
fn too_many_dependencies_rejected() {
    let h = setup(3);
    let mut deps = std::vec::Vec::new();
    for _ in 0..=MAX_DEPENDENCIES {
        deps.push(create(&h, 2, 5_000));
    }
    assert_eq!(try_create_with_deps(&h, &deps), Err(Error::InvalidInput));
}

#[test]
fn blocked_execution_emits_dependency_failure_event() {
    let h = setup(3);
    let first = create(&h, 2, 5_000);
    let second = create_with_deps(&h, 2, 5_000, &[first]);

    // Fully approved, but the prerequisite has not executed.
    h.client.approve(&h.approvers[0], &second);
    h.client.approve(&h.approvers[1], &second);
    assert_eq!(
        h.client.try_execute(&h.proposer, &second),
        Err(Ok(Error::PrerequisiteNotMet))
    );
    assert!(emitted(&h.env, "dep_fail"));
    assert!(!emitted(&h.env, "dep_ok"));
}

#[test]
fn satisfied_chain_emits_dependency_success_event() {
    let h = setup(3);
    let first = create(&h, 2, 5_000);
    let second = create_with_deps(&h, 2, 5_000, &[first]);

    approve_and_execute(&h, first);
    h.client.approve(&h.approvers[0], &second);
    h.client.approve(&h.approvers[1], &second);
    h.client.execute(&h.proposer, &second);
    assert_eq!(h.client.state(&second), ProposalState::Executed);

    assert!(emitted(&h.env, "dep_ok"));
    assert!(!emitted(&h.env, "dep_fail"));
}

#[test]
fn is_executed_reflects_completion_states() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);

    // Not executed while pending or merely approved.
    assert!(!h.client.is_executed(&id));
    h.client.approve(&h.approvers[0], &id);
    h.client.approve(&h.approvers[1], &id);
    assert!(!h.client.is_executed(&id));

    // Executed, and still satisfied once tidied away into Closed.
    h.client.execute(&h.proposer, &id);
    assert!(h.client.is_executed(&id));
    h.client.close(&h.proposer, &id);
    assert!(h.client.is_executed(&id));
}

#[test]
fn failed_is_never_executed() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    h.client.approve(&h.approvers[0], &id);
    h.client.approve(&h.approvers[1], &id);
    h.client.fail(&h.proposer, &id);
    assert_eq!(h.client.state(&id), ProposalState::Failed);
    assert!(!h.client.is_executed(&id));
}

#[test]
fn fail_requires_approval_and_the_proposer() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);

    // Pending, not yet approved.
    assert_eq!(
        h.client.try_fail(&h.proposer, &id),
        Err(Ok(Error::ProposalNotApproved))
    );

    h.client.approve(&h.approvers[0], &id);
    h.client.approve(&h.approvers[1], &id);
    assert_eq!(
        h.client.try_fail(&h.approvers[0], &id),
        Err(Ok(Error::Unauthorized))
    );

    h.client.fail(&h.proposer, &id);
    assert_eq!(h.client.state(&id), ProposalState::Failed);
}

#[test]
fn test_cancellation_grace_window() {
    let h = setup(3);
    h.env.ledger().set_timestamp(100);
    let id = h.client.create(
        &h.proposer,
        &String::from_str(&h.env, "org"),
        &String::from_str(&h.env, "w1"),
        &String::from_str(&h.env, "p1"),
        &approver_vec(&h),
        &dep_vec(&h, &[]),
        &2,
        &vec![&h.env],
        &0,
        &50, // 50 seconds grace period
    );

    // Fast forward 51 seconds
    h.env.ledger().set_timestamp(151);

    // Cancel should fail
    let res = h.client.try_cancel(&h.proposer, &id);
    assert_eq!(res, Err(Ok(Error::CancellationWindowClosed)));

    // Create a new one and cancel inside window
    let id2 = h.client.create(
        &h.proposer,
        &String::from_str(&h.env, "org"),
        &String::from_str(&h.env, "w1"),
        &String::from_str(&h.env, "p1"),
        &approver_vec(&h),
        &dep_vec(&h, &[]),
        &2,
        &vec![&h.env],
        &0,
        &50,
    );

    h.env.ledger().set_timestamp(160);
    h.client.cancel(&h.proposer, &id2); // works since 160 < 151 + 50 (created at 151)

    assert_eq!(h.client.state(&id2), crate::ProposalState::Cancelled);
}

// ---------------------------------------------------------------------------
// Expiration gating
//
// The deadline is read from `env.ledger().timestamp()` at the moment of each
// call, so the tests drive the deterministic ledger forward with
// `env.ledger().with_mut` — sequence and timestamp together, exactly as the
// host fixes them for a real invocation — and assert that every transition of
// a stale proposal fails with the dedicated `ProposalExpired` code.
// ---------------------------------------------------------------------------

/// Advance the mock ledger to `sequence` / `timestamp`.
fn advance(h: &Harness, sequence: u32, timestamp: u64) {
    h.env.ledger().with_mut(|l| {
        l.sequence_number = sequence;
        l.timestamp = timestamp;
    });
}

#[test]
fn expired_proposal_cannot_be_rejected() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    advance(&h, 6, 6_000);
    let res = h.client.try_reject(&h.approvers[0], &id);
    assert_eq!(res, Err(Ok(Error::ProposalExpired)));
    assert_eq!(h.client.state(&id), ProposalState::Pending);
}

#[test]
fn expired_proposal_cannot_be_cancelled() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    advance(&h, 6, 6_000);
    let res = h.client.try_cancel(&h.proposer, &id);
    assert_eq!(res, Err(Ok(Error::ProposalExpired)));
    assert_eq!(h.client.state(&id), ProposalState::Pending);
}

#[test]
fn expired_proposal_cannot_be_executed() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    h.client.approve(&h.approvers[0], &id);
    h.client.approve(&h.approvers[1], &id);
    assert_eq!(h.client.state(&id), ProposalState::Approved);

    advance(&h, 6, 6_000);
    let res = h.client.try_execute(&h.proposer, &id);
    assert_eq!(res, Err(Ok(Error::ProposalExpired)));
    // The stale approval never turned into an execution.
    assert_eq!(h.client.state(&id), ProposalState::Approved);
}

#[test]
fn expired_proposal_cannot_be_failed() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    h.client.approve(&h.approvers[0], &id);
    h.client.approve(&h.approvers[1], &id);

    advance(&h, 6, 6_000);
    // The deadline, not the proposer, is what ended it: `expire` settles it.
    let res = h.client.try_fail(&h.proposer, &id);
    assert_eq!(res, Err(Ok(Error::ProposalExpired)));
    assert_eq!(h.client.state(&id), ProposalState::Approved);
}

#[test]
fn expiry_boundary_is_inclusive() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);

    advance(&h, 5, 4_999);
    h.client.approve(&h.approvers[0], &id);

    // One second later the deadline has been reached, so it counts as stale.
    advance(&h, 6, 5_000);
    assert_eq!(
        h.client.try_approve(&h.approvers[1], &id),
        Err(Ok(Error::ProposalExpired))
    );
    assert!(h.client.is_expired(&id));
    h.client.expire(&id);
    assert_eq!(h.client.state(&id), ProposalState::Expired);
}

#[test]
fn ledger_timeline_blocks_every_stale_transition() {
    let h = setup(3);
    let id = create(&h, 2, 5_000); // created on sequence 1 at t = 1_000

    // Milestone 1 — ledger 2, well before the deadline: approvals flow.
    advance(&h, 2, 2_000);
    h.client.approve(&h.approvers[0], &id);
    assert_eq!(h.client.state(&id), ProposalState::Pending);

    // Milestone 2 — ledger 6, past the deadline: every live transition is
    // refused with the dedicated expired code, whatever the caller's rights.
    advance(&h, 6, 5_001);
    assert_eq!(
        h.client.try_approve(&h.approvers[1], &id),
        Err(Ok(Error::ProposalExpired))
    );
    assert_eq!(
        h.client.try_reject(&h.approvers[1], &id),
        Err(Ok(Error::ProposalExpired))
    );
    assert_eq!(
        h.client.try_cancel(&h.proposer, &id),
        Err(Ok(Error::ProposalExpired))
    );
    assert_eq!(
        h.client.try_execute(&h.proposer, &id),
        Err(Ok(Error::ProposalExpired))
    );
    assert_eq!(
        h.client.try_fail(&h.proposer, &id),
        Err(Ok(Error::ProposalExpired))
    );
    // Nothing mutated: the proposal is still exactly where milestone 1 left it.
    assert_eq!(h.client.state(&id), ProposalState::Pending);
    assert_eq!(h.client.get(&id).approvals, 1);

    // Milestone 3 — the permissionless transition records the terminal state.
    h.client.expire(&id);
    assert_eq!(h.client.state(&id), ProposalState::Expired);
    assert_eq!(
        h.client.try_expire(&id),
        Err(Ok(Error::InvalidProposalState))
    );
}

#[test]
fn proposal_without_deadline_never_expires() {
    let h = setup(3);
    let id = create(&h, 2, 0); // no deadline
    advance(&h, 99, 4_000_000_000);
    assert!(!h.client.is_expired(&id));
    assert_eq!(
        h.client.try_expire(&id),
        Err(Ok(Error::InvalidProposalState))
    );
    // Still fully live: an approval lands normally.
    h.client.approve(&h.approvers[0], &id);
    assert_eq!(h.client.state(&id), ProposalState::Pending);
}

#[test]
fn is_expired_view_tracks_ledger_deadline() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    assert!(!h.client.is_expired(&id));
    advance(&h, 5, 4_999);
    assert!(!h.client.is_expired(&id));
    advance(&h, 6, 5_000);
    assert!(h.client.is_expired(&id));
}

#[test]
fn cleanup_requires_a_passed_deadline() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    assert_eq!(
        h.client.try_cleanup_expired(&id),
        Err(Ok(Error::InvalidProposalState))
    );
    // A proposal without a deadline can never be purged either.
    let never = create(&h, 2, 0);
    assert_eq!(
        h.client.try_cleanup_expired(&never),
        Err(Ok(Error::InvalidProposalState))
    );
    assert_eq!(h.client.state(&id), ProposalState::Pending);
}

#[test]
fn cleanup_waits_for_the_deposit_returning_transition() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    advance(&h, 6, 6_000);
    // Stale, but the record still holds a live proposal (and its deposit):
    // purging now would strand it, so the caller must expire it first.
    assert_eq!(
        h.client.try_cleanup_expired(&id),
        Err(Ok(Error::InvalidProposalState))
    );
    h.client.expire(&id);
    h.client.cleanup_expired(&id);
    assert_eq!(h.client.try_get(&id), Err(Ok(Error::NotFound)));
}

#[test]
fn cleanup_purges_the_record_and_its_approval_flags() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    h.client.approve(&h.approvers[0], &id);
    advance(&h, 6, 6_000);
    h.client.expire(&id);
    h.client.cleanup_expired(&id);

    assert_eq!(h.client.try_get(&id), Err(Ok(Error::NotFound)));
    // With the record gone, the approval flag can no longer be consulted.
    assert_eq!(
        h.client.try_approve(&h.approvers[1], &id),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn stale_prerequisite_blocks_the_dependent_chain() {
    let h = setup(3);
    let first = create(&h, 2, 5_000);
    // The dependent proposal carries no deadline of its own, so only the
    // prerequisite's expiry is under test.
    let second = create_with_deps(&h, 2, 0, &[first]);

    advance(&h, 6, 6_000);
    // The prerequisite is stale: it can neither execute nor be approved, so
    // the dependent proposal stays blocked rather than inheriting a stale step.
    assert_eq!(
        h.client.try_execute(&h.proposer, &first),
        Err(Ok(Error::ProposalExpired))
    );
    h.client.expire(&first);
    assert_eq!(h.client.state(&first), ProposalState::Expired);

    // Approving the dependent is unaffected by its prerequisite's expiry ...
    h.client.approve(&h.approvers[0], &second);
    h.client.approve(&h.approvers[1], &second);
    // ... but execution is still gated on the prerequisite having executed.
    assert_eq!(
        h.client.try_execute(&h.proposer, &second),
        Err(Ok(Error::PrerequisiteNotMet))
    );
}

// ------------------------------------------------------------- timelock ----

/// Full approval, then a `get` view handy for timelock assertions.
fn approve_to_threshold(h: &Harness, id: u64) {
    h.client.approve(&h.approvers[0], &id);
    h.client.approve(&h.approvers[1], &id);
    assert_eq!(h.client.state(&id), ProposalState::Approved);
}

#[test]
fn approval_records_timestamp_used_by_the_timelock() {
    let h = setup_timelocked(3, 100);
    let id = create(&h, 2, 10_000);
    assert_eq!(h.client.get(&id).approved_at, 0);

    // Ledger time is 1_000 from setup: approval stamps exactly that moment.
    h.client.approve(&h.approvers[0], &id);
    h.client.approve(&h.approvers[1], &id);
    assert_eq!(h.client.state(&id), ProposalState::Approved);
    assert_eq!(h.client.get(&id).approved_at, 1_000);

    // Execution is refused well inside the 100s window.
    h.env.ledger().set_timestamp(1_050);
    let res = h.client.try_execute(&h.proposer, &id);
    assert_eq!(res, Err(Ok(Error::TimelockNotExpired)));
    assert_eq!(h.client.state(&id), ProposalState::Approved);

    // approved_at survives execution, recorded in the executed state too.
    h.env.ledger().set_timestamp(1_100);
    h.client.execute(&h.proposer, &id);
    assert_eq!(h.client.state(&id), ProposalState::Executed);
    assert_eq!(h.client.get(&id).approved_at, 1_000);
}

#[test]
fn execute_within_timelock_window_is_refused() {
    let h = setup_timelocked(3, 100);
    let id = create(&h, 2, 10_000);
    approve_to_threshold(&h, id);

    // One second before the delay elapses the proposal is still locked.
    h.env.ledger().set_timestamp(1_099);
    let res = h.client.try_execute(&h.proposer, &id);
    assert_eq!(res, Err(Ok(Error::TimelockNotExpired)));
    assert_eq!(h.client.state(&id), ProposalState::Approved);

    // Exactly at release time execution is allowed (gate is `< release_at`).
    h.env.ledger().set_timestamp(1_100);
    h.client.execute(&h.proposer, &id);
    assert_eq!(h.client.state(&id), ProposalState::Executed);
}

#[test]
fn execute_after_timelock_window_succeeds() {
    let h = setup_timelocked(3, 100);
    let id = create(&h, 2, 10_000);
    approve_to_threshold(&h, id);

    // Long past the window, execution proceeds normally and emits "executed".
    h.env.ledger().set_timestamp(5_000);
    h.client.execute(&h.proposer, &id);
    assert_eq!(h.client.state(&id), ProposalState::Executed);

    // Close still works from the executed state (timelock is behind us).
    h.client.close(&h.proposer, &id);
    assert_eq!(h.client.state(&id), ProposalState::Closed);
}

#[test]
fn zero_timelock_allows_immediate_execution() {
    let h = setup(3); // timelock 0 — the historical behaviour.
    let id = create(&h, 2, 5_000);
    approve_to_threshold(&h, id);
    h.client.execute(&h.proposer, &id);
    assert_eq!(h.client.state(&id), ProposalState::Executed);
}

#[test]
fn timelock_only_gates_execution_not_state_transitions() {
    let h = setup_timelocked(3, 100);
    let id = create(&h, 2, 10_000);
    approve_to_threshold(&h, id);

    // The timelock does not affect dependency queries.
    assert!(h.client.dependencies_met(&id));

    // Marking the proposal failed inside the window is still permitted.
    h.env.ledger().set_timestamp(1_050);
    let res = h.client.try_execute(&h.proposer, &id);
    assert_eq!(res, Err(Ok(Error::TimelockNotExpired)));
    h.client.fail(&h.proposer, &id);
    assert_eq!(h.client.state(&id), ProposalState::Failed);
}

// ---------------------------------------------------------------------------
// Deterministic error codes
//
// A proposal passes through a lifecycle, and each stage has its own reason for
// refusing: the wrong caller, the wrong state, a closed window, a missing
// quorum. Those four are all reachable at the same point in a proposal's life
// and an agent has to tell them apart to know whether to wait, re-approve, or
// give up.
// ---------------------------------------------------------------------------

#[test]
fn unknown_proposal_ids_are_not_found() {
    let h = setup(3);
    let ghost = create(&h, 2, 0) + 1_000;

    assert_eq!(h.client.try_get(&ghost), Err(Ok(Error::NotFound)));
    assert_eq!(
        h.client.try_approve(&h.approvers[0], &ghost),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(
        h.client.try_execute(&h.proposer, &ghost),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(h.client.try_expire(&ghost), Err(Ok(Error::NotFound)));
    assert_eq!(
        h.client.try_cancel(&h.proposer, &ghost),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn proposal_creation_rejects_malformed_configuration() {
    let h = setup(3);
    let org = String::from_str(&h.env, "acme");
    let wallet = String::from_str(&h.env, "wallet-1");
    let policy = String::from_str(&h.env, "policy-1");
    let no_deps: Vec<u64> = Vec::new(&h.env);
    let no_deposit: Vec<AssetAmount> = Vec::new(&h.env);

    // A blank organization names nothing.
    assert_eq!(
        h.client.try_create(
            &h.proposer,
            &String::from_str(&h.env, ""),
            &wallet,
            &policy,
            &approver_vec(&h),
            &no_deps,
            &2,
            &no_deposit,
            &0,
            &0
        ),
        Err(Ok(Error::InvalidInput))
    );
    // No approvers means no quorum is reachable.
    let no_approvers: Vec<Address> = Vec::new(&h.env);
    assert_eq!(
        h.client.try_create(
            &h.proposer,
            &org,
            &wallet,
            &policy,
            &no_approvers,
            &no_deps,
            &1,
            &no_deposit,
            &0,
            &0
        ),
        Err(Ok(Error::InvalidInput))
    );
    // A threshold outside `[1, approvers]` is its own diagnosis, not malformed
    // input: the approver set is fine, the number asked of it is not.
    for threshold in [0, 4] {
        assert_eq!(
            h.client.try_create(
                &h.proposer,
                &org,
                &wallet,
                &policy,
                &approver_vec(&h),
                &no_deps,
                &threshold,
                &no_deposit,
                &0,
                &0
            ),
            Err(Ok(Error::InvalidThreshold))
        );
    }
    // A deadline already past cannot be met.
    assert_eq!(
        h.client.try_create(
            &h.proposer,
            &org,
            &wallet,
            &policy,
            &approver_vec(&h),
            &no_deps,
            &2,
            &no_deposit,
            &1_000,
            &0
        ),
        Err(Ok(Error::InvalidInput))
    );
    // More approvers than the cap allows: the approver set is the problem, not
    // the threshold asked of it.
    let mut too_many_approvers: Vec<Address> = Vec::new(&h.env);
    for _ in 0..=MAX_APPROVERS {
        too_many_approvers.push_back(Address::generate(&h.env));
    }
    assert_eq!(
        h.client.try_create(
            &h.proposer,
            &org,
            &wallet,
            &policy,
            &too_many_approvers,
            &no_deps,
            &1,
            &no_deposit,
            &0,
            &0
        ),
        Err(Ok(Error::InvalidInput))
    );
    // More prerequisites than the cap allows.
    let mut too_many: Vec<u64> = Vec::new(&h.env);
    for i in 0..=MAX_DEPENDENCIES {
        too_many.push_back(i as u64);
    }
    assert_eq!(
        h.client.try_create(
            &h.proposer,
            &org,
            &wallet,
            &policy,
            &approver_vec(&h),
            &too_many,
            &2,
            &no_deposit,
            &0,
            &0
        ),
        Err(Ok(Error::InvalidInput))
    );
    // A non-positive deposit is a bad amount, and must not be pulled.
    let asset = Address::generate(&h.env);
    let bad_deposit: Vec<AssetAmount> = vec![&h.env, AssetAmount { asset, amount: 0 }];
    assert_eq!(
        h.client.try_create(
            &h.proposer,
            &org,
            &wallet,
            &policy,
            &approver_vec(&h),
            &no_deps,
            &2,
            &bad_deposit,
            &0,
            &0
        ),
        Err(Ok(Error::InvalidAmount))
    );
}

#[test]
fn a_proposal_depending_on_itself_is_a_dependency_cycle() {
    let h = setup(3);
    let first = create(&h, 2, 0);
    // Depending on a proposal that does not exist yet is a cycle, not a
    // dangling reference: ids are handed out densely, so a forward dependency
    // can never resolve.
    let forward = first + 1;
    let cyclic = h.client.try_create(
        &h.proposer,
        &String::from_str(&h.env, "acme"),
        &String::from_str(&h.env, "wallet-1"),
        &String::from_str(&h.env, "policy-1"),
        &approver_vec(&h),
        &vec![&h.env, forward],
        &2,
        &vec![&h.env],
        &0,
        &0,
    );
    assert_eq!(cyclic, Err(Ok(Error::CircularDependencyDetected)));
    // Depending on an earlier proposal is legitimate, and the follower reports
    // the unmet prerequisite rather than refusing to be created.
    let follower = create_with_deps(&h, 2, 0, &[first]);
    h.client.approve(&h.approvers[0], &follower);
    h.client.approve(&h.approvers[1], &follower);
    assert_eq!(
        h.client.try_execute(&h.proposer, &follower),
        Err(Ok(Error::PrerequisiteNotMet))
    );
}

#[test]
fn only_approvers_may_approve_and_nobody_approves_twice() {
    let h = setup(3);
    let stranger = Address::generate(&h.env);
    let id = create(&h, 2, 0);

    // A stranger is not on the approver list, which is a different refusal from
    // being on it and having already voted.
    assert_eq!(
        h.client.try_approve(&stranger, &id),
        Err(Ok(Error::NotAnApprover))
    );
    assert_eq!(
        h.client.try_reject(&stranger, &id),
        Err(Ok(Error::NotAnApprover))
    );
    // Each approval reports the running tally...
    assert_eq!(h.client.approve(&h.approvers[0], &id), 1);
    // ...and voting twice is refused.
    assert_eq!(
        h.client.try_approve(&h.approvers[0], &id),
        Err(Ok(Error::AlreadySigned))
    );
    assert_eq!(h.client.approve(&h.approvers[1], &id), 2);

    // Rejecting settles the whole proposal for everyone, so the vote it
    // recorded no longer has anywhere to go.
    let doomed = create(&h, 2, 0);
    h.client.approve(&h.approvers[0], &doomed);
    h.client.reject(&h.approvers[1], &doomed);
    assert_eq!(h.client.get(&doomed).state, ProposalState::Rejected);
    assert_eq!(
        h.client.try_approve(&h.approvers[2], &doomed),
        Err(Ok(Error::InvalidProposalState))
    );
    assert_eq!(
        h.client.try_reject(&h.approvers[2], &doomed),
        Err(Ok(Error::InvalidProposalState))
    );
    // A settled proposal is not executable either.
    assert_eq!(
        h.client.try_execute(&h.proposer, &doomed),
        Err(Ok(Error::ProposalNotApproved))
    );
}

#[test]
fn executing_without_a_quorum_is_proposal_not_approved() {
    let h = setup(3);
    let stranger = Address::generate(&h.env);
    let id = create(&h, 2, 0);

    // The proposer is the only caller allowed to execute, so a stranger is told
    // it may not even try...
    assert_eq!(
        h.client.try_execute(&stranger, &id),
        Err(Ok(Error::Unauthorized))
    );
    // ...and the proposer is told the real reason: one signature is short of the
    // two the threshold demands.
    assert_eq!(
        h.client.try_execute(&h.proposer, &id),
        Err(Ok(Error::ProposalNotApproved))
    );
    h.client.approve(&h.approvers[0], &id);
    assert_eq!(
        h.client.try_execute(&h.proposer, &id),
        Err(Ok(Error::ProposalNotApproved))
    );
    h.client.approve(&h.approvers[1], &id);
    h.client.execute(&h.proposer, &id);
    assert_eq!(h.client.get(&id).state, ProposalState::Executed);
    // Once executed there is no longer an approval to act on, which is the same
    // diagnosis as never having reached quorum.
    assert_eq!(
        h.client.try_execute(&h.proposer, &id),
        Err(Ok(Error::ProposalNotApproved))
    );
}

#[test]
fn an_approved_proposal_waits_out_its_timelock() {
    let h = setup_timelocked(3, 500);
    let id = create(&h, 2, 0);
    h.client.approve(&h.approvers[0], &id);
    h.client.approve(&h.approvers[1], &id);

    // Approved, but the timelock has not run: the proposal is not executable
    // yet, which is distinct from never having reached quorum.
    assert_eq!(
        h.client.try_execute(&h.proposer, &id),
        Err(Ok(Error::TimelockNotExpired))
    );
    h.env.ledger().set_timestamp(1_000 + 500);
    h.client.execute(&h.proposer, &id);
    assert_eq!(h.client.get(&id).state, ProposalState::Executed);
}

#[test]
fn an_expired_proposal_is_reported_as_expired_not_merely_unapproved() {
    let h = setup(3);
    let id = create(&h, 2, 2_000);
    h.client.approve(&h.approvers[0], &id);
    h.env.ledger().set_timestamp(2_000);

    // Past the deadline every lifecycle action reports expiry, so a caller can
    // tell "too late" from "not enough signatures".
    assert_eq!(
        h.client.try_execute(&h.proposer, &id),
        Err(Ok(Error::ProposalExpired))
    );
    assert_eq!(
        h.client.try_approve(&h.approvers[1], &id),
        Err(Ok(Error::ProposalExpired))
    );
    assert_eq!(
        h.client.try_cancel(&h.proposer, &id),
        Err(Ok(Error::ProposalExpired))
    );
    // Expiring it is what finally moves the record on.
    h.client.expire(&id);
    assert_eq!(h.client.get(&id).state, ProposalState::Expired);
    // A proposal with nothing to do is not expirable twice.
    assert_eq!(
        h.client.try_expire(&id),
        Err(Ok(Error::InvalidProposalState))
    );
}

#[test]
fn cancelling_is_gated_on_the_proposer_and_the_window() {
    let h = setup(3);
    let stranger = Address::generate(&h.env);
    let open = h.client.create(
        &h.proposer,
        &String::from_str(&h.env, "acme"),
        &String::from_str(&h.env, "wallet-1"),
        &String::from_str(&h.env, "policy-1"),
        &approver_vec(&h),
        &Vec::new(&h.env),
        &2,
        &vec![&h.env],
        &0,
        &1_000,
    );
    let windowed = h.client.create(
        &h.proposer,
        &String::from_str(&h.env, "acme"),
        &String::from_str(&h.env, "wallet-1"),
        &String::from_str(&h.env, "policy-1"),
        &approver_vec(&h),
        &Vec::new(&h.env),
        &2,
        &vec![&h.env],
        &0,
        &100,
    );

    // Only the proposer may cancel, even once the proposal is approved.
    assert_eq!(
        h.client.try_cancel(&stranger, &windowed),
        Err(Ok(Error::Unauthorized))
    );
    // Inside its window a cancellation is allowed and terminal.
    h.client.cancel(&h.proposer, &windowed);
    assert_eq!(h.client.get(&windowed).state, ProposalState::Cancelled);
    assert_eq!(
        h.client.try_cancel(&h.proposer, &windowed),
        Err(Ok(Error::InvalidProposalState))
    );

    // Past its window the same call is refused for a different reason: the
    // proposer gave up the right, and the proposal must now run to a decision.
    assert_eq!(h.client.get(&open).state, ProposalState::Pending);
    h.env.ledger().set_timestamp(1_000 + 1_001);
    assert_eq!(
        h.client.try_cancel(&h.proposer, &open),
        Err(Ok(Error::CancellationWindowClosed))
    );
    // A window of zero never closes, so a still-pending proposal can always be
    // withdrawn by its proposer.
    let forever = create(&h, 2, 0);
    h.client.cancel(&h.proposer, &forever);
    assert_eq!(h.client.get(&forever).state, ProposalState::Cancelled);
}

#[test]
fn failing_a_proposal_is_proposer_only_and_needs_approval() {
    let h = setup(3);
    let stranger = Address::generate(&h.env);
    let pending = create(&h, 2, 0);
    let approved = create(&h, 2, 0);

    // Failing is the proposer's escape hatch and nothing else.
    assert_eq!(
        h.client.try_fail(&stranger, &approved),
        Err(Ok(Error::Unauthorized))
    );
    // A proposal that never reached quorum cannot be failed either; it can only
    // be approved, rejected, or expire.
    assert_eq!(
        h.client.try_fail(&h.proposer, &pending),
        Err(Ok(Error::ProposalNotApproved))
    );
    h.client.approve(&h.approvers[0], &approved);
    h.client.approve(&h.approvers[1], &approved);
    h.client.fail(&h.proposer, &approved);
    assert_eq!(h.client.get(&approved).state, ProposalState::Failed);
    // A failed proposal no longer holds the approval it would execute on.
    assert_eq!(
        h.client.try_execute(&h.proposer, &approved),
        Err(Ok(Error::ProposalNotApproved))
    );
}

#[test]
fn cleanup_only_applies_to_settled_proposals() {
    let h = setup(3);
    let id = create(&h, 2, 5_000);
    // Nothing has happened yet, so there is nothing to clean up.
    assert_eq!(
        h.client.try_cleanup_expired(&id),
        Err(Ok(Error::InvalidProposalState))
    );
    h.client.approve(&h.approvers[0], &id);
    h.client.approve(&h.approvers[1], &id);
    h.client.execute(&h.proposer, &id);
    h.client.close(&h.proposer, &id);
    h.env.ledger().set_timestamp(5_000);

    h.client.cleanup_expired(&id);
    // Cleanup removes the record outright, so a later read is a missing
    // proposal rather than a stale one still reporting a state.
    assert_eq!(h.client.try_get(&id), Err(Ok(Error::NotFound)));
    assert_eq!(
        h.client.try_approve(&h.approvers[0], &id),
        Err(Ok(Error::NotFound))
    );
    // And cleaning up twice is a missing record, not a bad state.
    assert_eq!(h.client.try_cleanup_expired(&id), Err(Ok(Error::NotFound)));
}
