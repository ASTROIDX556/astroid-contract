#![cfg(test)]
extern crate std;

use crate::{ProposalContract, ProposalContractClient, ProposalState};
use astroid_shared::constants::MAX_DEPENDENCIES;
use astroid_shared::errors::Error;
use soroban_sdk::testutils::{Address as _, Events, Ledger};
use soroban_sdk::{Address, Env, IntoVal, String, Symbol, Val, Vec};

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
        &soroban_sdk::vec![&h.env],
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
            &soroban_sdk::vec![&h.env],
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
        &soroban_sdk::vec![&h.env],
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
        &soroban_sdk::vec![&h.env],
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
        &soroban_sdk::vec![&h.env],
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
        &soroban_sdk::vec![&h.env],
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

// ------------------------------------------------------ quorum / majority ----
//
// `execute` re-validates the tally that earned `Approved`: the configured
// threshold, the participation quorum (an integer-scaled percentage of the
// allow-list) and a strict majority. The cases below pin the boundaries — an
// exact tie, and tallies one vote short of a bar — where a threshold-only
// check would let a barely-supported proposal fire.

#[test]
fn quorum_calculation_rounds_up_with_integer_scaling() {
    // ceil(eligible * percent / 100) — exact shares stay exact ...
    assert_eq!(ProposalContract::quorum_required(4, 50), 2);
    assert_eq!(ProposalContract::quorum_required(2, 50), 1);
    // ... partial shares round up so they can never slip under the bar.
    assert_eq!(ProposalContract::quorum_required(5, 50), 3); // 2.5 -> 3
    assert_eq!(ProposalContract::quorum_required(3, 60), 2); // 1.8 -> 2

    // Degenerate bounds: the full allow-list, and no participation at all.
    assert_eq!(ProposalContract::quorum_required(7, 100), 7);
    assert_eq!(ProposalContract::quorum_required(0, 50), 0);
    assert_eq!(ProposalContract::quorum_required(7, 0), 0);
    // A percentage above 100 is clamped: never more than the allow-list.
    assert_eq!(ProposalContract::quorum_required(4, 250), 4);
}

#[test]
fn majority_check_never_accepts_a_tie() {
    // The bar is always one past half of the allow-list ...
    assert_eq!(ProposalContract::majority_required(4), 3);
    assert_eq!(ProposalContract::majority_required(5), 3);
    // ... an empty allow-list can never be reached by any tally ...
    assert_eq!(ProposalContract::majority_required(0), 1);
    // Exactly half of an even allow-list is a tie, not a majority ...
    assert!(!ProposalContract::has_majority(2, 4));
    assert!(ProposalContract::has_majority(3, 4));
    // ... and one short of an odd one is still short.
    assert!(!ProposalContract::has_majority(2, 5));
    assert!(ProposalContract::has_majority(3, 5));
    assert!(!ProposalContract::has_majority(1, 3));
    assert!(ProposalContract::has_majority(2, 3));
    // A sole voter is its own majority.
    assert!(ProposalContract::has_majority(1, 1));
}

#[test]
fn tied_vote_blocks_execution() {
    let h = setup(4);
    let id = create(&h, 2, 5_000); // threshold 2 — exactly half of 4
    h.client.approve(&h.approvers[0], &id);
    h.client.approve(&h.approvers[1], &id);
    assert_eq!(h.client.state(&id), ProposalState::Approved);

    // 2 in favour, 2 not voted: the configured threshold and the quorum (2 of
    // 4) are both met, but a tie is not a majority, so execution is refused
    // with the threshold code and nothing changes.
    assert_eq!(
        h.client.try_execute(&h.proposer, &id),
        Err(Ok(Error::ThresholdNotMet))
    );
    assert_eq!(h.client.state(&id), ProposalState::Approved);
    assert_eq!(h.client.get(&id).approvals, 2);
}

#[test]
fn narrowly_missing_the_quorum_blocks_execution() {
    let h = setup(5);
    let id = create(&h, 2, 5_000); // clears its own threshold: 2 of 5
    h.client.approve(&h.approvers[0], &id);
    h.client.approve(&h.approvers[1], &id);
    assert_eq!(h.client.state(&id), ProposalState::Approved);

    // Quorum for 5 voters at 50% is ceil(2.5) == 3, so two approvals fall
    // exactly one vote short of the participation bar — the tally may not
    // execute despite `Approved` (the protocol-wide threshold code covers
    // every vote bar, quorum included).
    assert_eq!(
        h.client.try_execute(&h.proposer, &id),
        Err(Ok(Error::ThresholdNotMet))
    );
    assert_eq!(h.client.state(&id), ProposalState::Approved);

    // The tally cannot be topped up either (the state gate owns approvals
    // now), so the proposer's escape hatch is to fail the proposal.
    assert_eq!(
        h.client.try_approve(&h.approvers[2], &id),
        Err(Ok(Error::InvalidProposalState))
    );
    h.client.fail(&h.proposer, &id);
    assert_eq!(h.client.state(&id), ProposalState::Failed);
}

#[test]
fn exact_quorum_and_majority_boundary_executes() {
    let h = setup(5);
    // 5 voters: quorum = 3 and majority = 3 — this tally sits exactly on
    // both bars rather than clearing them with room to spare.
    let id = create(&h, 3, 5_000);
    h.client.approve(&h.approvers[0], &id);
    h.client.approve(&h.approvers[1], &id);
    h.client.approve(&h.approvers[2], &id);
    assert_eq!(h.client.state(&id), ProposalState::Approved);

    // One approval fewer would be refused; exactly three clears every bar.
    h.client.execute(&h.proposer, &id);
    assert_eq!(h.client.state(&id), ProposalState::Executed);
}

#[test]
fn narrowly_missing_the_threshold_never_approves_and_cannot_execute() {
    let h = setup(4);
    let id = create(&h, 3, 5_000); // needs 3 of 4
    h.client.approve(&h.approvers[0], &id);
    h.client.approve(&h.approvers[1], &id); // 2 of 3 — one vote short
    assert_eq!(h.client.state(&id), ProposalState::Pending);

    // Below the configured threshold the proposal never reached `Approved`,
    // so the state gate refuses execution before quorum even applies.
    assert_eq!(
        h.client.try_execute(&h.proposer, &id),
        Err(Ok(Error::ProposalNotApproved))
    );
    assert_eq!(h.client.state(&id), ProposalState::Pending);

    // The missing approval completes the threshold and, with it, quorum and
    // majority — the same proposal then executes normally.
    h.client.approve(&h.approvers[2], &id);
    assert_eq!(h.client.state(&id), ProposalState::Approved);
    h.client.execute(&h.proposer, &id);
    assert_eq!(h.client.state(&id), ProposalState::Executed);
}
