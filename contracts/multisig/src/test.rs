#![cfg(test)]
extern crate std;

use crate::{BatchCall, MultiSigContract, MultiSigContractClient};
use astroid_shared::constants::{MAX_BATCH_CALLS, MAX_SIGNER_WEIGHT};
use crate::{BatchCall, MultiSigContract, MultiSigContractClient, SignerWeight};
use astroid_shared::constants::MAX_BATCH_CALLS;
use astroid_shared::errors::Error;
use soroban_sdk::testutils::{Address as _, AuthorizedFunction, Ledger};
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, vec, Address, Bytes, Env, IntoVal, Symbol,
    Val, Vec,
};

/// Minimal stateful contract used as a batch sub-call target: it stores values
/// keyed by id and exposes a couple of always-failing functions to exercise the
/// atomic rollback and error-mapping paths.
#[contract]
pub struct BatchHelper;

#[contracttype]
#[derive(Clone)]
enum HKey {
    Value(u64),
}

#[contractimpl]
impl BatchHelper {
    pub fn store(env: Env, key: u64, value: u64) {
        env.storage().instance().set(&HKey::Value(key), &value);
    }

    pub fn get(env: Env, key: u64) -> u64 {
        env.storage().instance().get(&HKey::Value(key)).unwrap_or(0)
    }

    /// Always fails with a contract error (atomic rollback + error propagation).
    pub fn fail(_env: Env) -> Result<(), Error> {
        Err(Error::InvalidInput)
    }

    /// Always panics (maps to [`Error::BatchCallFailed`]).
    pub fn boom(_env: Env) {
        panic!("boom");
    }
}

struct Harness {
    env: Env,
    client: MultiSigContractClient<'static>,
    signers: std::vec::Vec<Address>,
}

fn sw(a: &Address, w: u32) -> SignerWeight {
    SignerWeight {
        address: a.clone(),
        weight: w,
    }
}

fn setup(weights: &[u32], threshold: u32) -> Harness {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, MultiSigContract);
    let client = MultiSigContractClient::new(&env, &contract_id);

    let mut signers = std::vec::Vec::new();
    let mut sv = Vec::new(&env);
    for w in weights {
        let a = Address::generate(&env);
        sv.push_back(sw(&a, *w));
        signers.push(a);
    }
    client.initialize(&sv, &threshold);
    Harness {
        env,
        client,
        signers,
    }
}

fn payload(env: &Env) -> Bytes {
    Bytes::from_array(env, &[1, 2, 3, 4])
}

#[test]
fn initialize_state() {
    let h = setup(&[1, 1, 1], 2);
    assert_eq!(h.client.get_threshold(), 2);
    assert_eq!(h.client.get_signers().len(), 3);
    assert!(h.client.is_signer(&h.signers[0]));
    assert!(!h.client.is_locked());
}

#[test]
fn bad_threshold_rejected_on_init() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, MultiSigContract);
    let client = MultiSigContractClient::new(&env, &contract_id);
    let mut sv = Vec::new(&env);
    // Total weight = 2, threshold 3 > total rejected.
    sv.push_back(sw(&Address::generate(&env), 1));
    sv.push_back(sw(&Address::generate(&env), 1));
    let res = client.try_initialize(&sv, &3);
    assert_eq!(res, Err(Ok(Error::InvalidThreshold)));
}

#[test]
fn zero_weight_rejected_on_init() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, MultiSigContract);
    let client = MultiSigContractClient::new(&env, &contract_id);
    let mut sv = Vec::new(&env);
    sv.push_back(sw(&Address::generate(&env), 0));
    sv.push_back(sw(&Address::generate(&env), 1));
    let res = client.try_initialize(&sv, &1);
    assert_eq!(res, Err(Ok(Error::InvalidSignerWeight)));
}

#[test]
fn duplicate_signer_rejected_on_init() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, MultiSigContract);
    let client = MultiSigContractClient::new(&env, &contract_id);
    let a = Address::generate(&env);
    let mut sv = Vec::new(&env);
    sv.push_back(sw(&a, 1));
    sv.push_back(sw(&a, 1));
    let res = client.try_initialize(&sv, &1);
    assert_eq!(res, Err(Ok(Error::InvalidInput)));
}

#[test]
fn weighted_approval_met_by_single_heavy_signer() {
    // Weights 5, 1, 1 with threshold 5: proposer (weight 5) alone executes.
    let h = setup(&[5, 1, 1], 5);
    let id = h.client.propose(
        &h.signers[0],
        &symbol_short!("payment"),
        &payload(&h.env),
        &0,
    );
    // Proposer's own weight (5) already meets threshold 5.
    h.client.execute(&h.signers[0], &id);
    assert!(h.client.get_proposal(&id).executed);
}

#[test]
fn weighted_threshold_requires_combined_weight() {
    // Weights 2, 2, 1 with threshold 3.
    let h = setup(&[2, 2, 1], 3);
    let id = h.client.propose(
        &h.signers[0],
        &symbol_short!("payment"),
        &payload(&h.env),
        &0,
    );
    // Proposer contributes 2; one more signer (2) -> total 4 >= 3.
    let weight = h.client.approve(&h.signers[1], &id);
    assert_eq!(weight, 4);
    h.client.execute(&h.signers[2], &id);
    assert!(h.client.get_proposal(&id).executed);
}

#[test]
fn execute_below_weight_threshold_fails() {
    // Weights 2, 2, 1 with threshold 3.
    let h = setup(&[2, 2, 1], 3);
    let _id = h.client.propose(
        &h.signers[0],
        &symbol_short!("payment"),
        &payload(&h.env),
        &0,
    );
    // Only the weight-1 signer approves -> total 3 (proposer 2 + 1) < 3? 2+1=3 == threshold.
    // Use the lightest signer only so total stays below threshold.
    let id2 = h.client.propose(
        &h.signers[2],
        &symbol_short!("payment"),
        &payload(&h.env),
        &0,
    );
    // proposer weight 1; approve with weight-2 signer -> 1+2 = 3 meets threshold.
    // Instead approve with weight-2 signer only on a proposal from weight-1 signer gives 3.
    // To stay below, approve with no one: just proposer weight 1 < 3.
    let res = h.client.try_execute(&h.signers[0], &id2);
    assert_eq!(res, Err(Ok(Error::InsufficientWeight)));
}

#[test]
fn non_signer_cannot_propose_or_approve() {
    let h = setup(&[1, 1, 1], 2);
    let stranger = Address::generate(&h.env);
    let res = h
        .client
        .try_propose(&stranger, &symbol_short!("payment"), &payload(&h.env), &0);
    assert_eq!(res, Err(Ok(Error::NotASigner)));
}

#[test]
fn double_approval_rejected() {
    let h = setup(&[1, 1, 1], 2);
    let id = h.client.propose(
        &h.signers[0],
        &symbol_short!("payment"),
        &payload(&h.env),
        &0,
    );
    // Proposer already auto-approved.
    let res = h.client.try_approve(&h.signers[0], &id);
    assert_eq!(res, Err(Ok(Error::AlreadySigned)));
}

#[test]
fn time_lock_blocks_early_execution() {
    let h = setup(&[2, 2], 4);
    h.env.ledger().set_timestamp(1_000);
    let unlock = 5_000u64;
    let id = h.client.propose(
        &h.signers[0],
        &symbol_short!("payment"),
        &payload(&h.env),
        &unlock,
    );
    h.client.approve(&h.signers[1], &id);
    // Threshold met (4), but time lock not reached.
    let res = h.client.try_execute(&h.signers[0], &id);
    assert_eq!(res, Err(Ok(Error::TimeLocked)));

    // Advance past the lock.
    h.env.ledger().set_timestamp(6_000);
    h.client.execute(&h.signers[0], &id);
    assert!(h.client.get_proposal(&id).executed);
}

#[test]
fn emergency_lock_blocks_actions() {
    let h = setup(&[1, 1], 2);
    h.client.set_emergency_lock(&h.signers[0], &true);
    assert!(h.client.is_locked());
    let res = h.client.try_propose(
        &h.signers[0],
        &symbol_short!("payment"),
        &payload(&h.env),
        &0,
    );
    assert_eq!(res, Err(Ok(Error::EmergencyLock)));

    // Unlock and resume.
    h.client.set_emergency_lock(&h.signers[0], &false);
    let id = h.client.propose(
        &h.signers[0],
        &symbol_short!("payment"),
        &payload(&h.env),
        &0,
    );
    h.client.approve(&h.signers[1], &id);
    h.client.execute(&h.signers[0], &id);
    assert!(h.client.get_proposal(&id).executed);
}

#[test]
fn add_and_remove_signer_with_weight() {
    let h = setup(&[1, 1, 1], 2);
    let new_signer = Address::generate(&h.env);
    h.client.add_signer(&h.signers[0], &new_signer, &3);
    assert!(h.client.is_signer(&new_signer));
    let stored = h.client.get_signers();
    assert!(stored
        .iter()
        .any(|s| s.address == new_signer && s.weight == 3));

    h.client.remove_signer(&h.signers[0], &new_signer);
    assert!(!h.client.is_signer(&new_signer));
}

#[test]
fn cannot_add_signer_with_zero_weight() {
    let h = setup(&[1, 1, 1], 2);
    let extra = Address::generate(&h.env);
    let res = h.client.try_add_signer(&h.signers[0], &extra, &0);
    assert_eq!(res, Err(Ok(Error::InvalidSignerWeight)));
}

#[test]
fn cannot_add_duplicate_signer() {
    let h = setup(&[1, 1, 1], 2);
    let res = h.client.try_add_signer(&h.signers[0], &h.signers[1], &1);
    assert_eq!(res, Err(Ok(Error::AlreadyExists)));
}

#[test]
fn update_signer_weight_and_reach_threshold() {
    // Weights 1, 1 with threshold 2.
    let h = setup(&[1, 1], 2);
    // Bump signer[0] to weight 5; must keep total >= threshold (ok).
    h.client.set_signer_weight(&h.signers[1], &h.signers[0], &5);
    let stored = h.client.get_signers();
    assert!(stored
        .iter()
        .any(|s| s.address == h.signers[0] && s.weight == 5));

    // A proposal from signer[0] now meets threshold alone.
    let id = h.client.propose(
        &h.signers[0],
        &symbol_short!("payment"),
        &payload(&h.env),
        &0,
    );
    h.client.execute(&h.signers[1], &id);
    assert!(h.client.get_proposal(&id).executed);
}

#[test]
fn cannot_drop_total_weight_below_threshold() {
    // Weights 2, 1 with threshold 3.
    let h = setup(&[2, 1], 3);
    // Removing signer[0] (weight 2) leaves 1 < 3 -> rejected.
    let res = h.client.try_remove_signer(&h.signers[1], &h.signers[0]);
    assert_eq!(res, Err(Ok(Error::InvalidThreshold)));

    // Lowering signer[0] weight to 1 would drop total to 2 < 3 -> rejected.
    let res = h
        .client
        .try_set_signer_weight(&h.signers[1], &h.signers[0], &1);
    assert_eq!(res, Err(Ok(Error::InvalidThreshold)));
}

#[test]
fn set_threshold_bounds_enforced() {
    // Weights 1, 1, 1 total 3, threshold 2.
    let h = setup(&[1, 1, 1], 2);
    // Threshold larger than total weight is rejected.
    let res = h.client.try_set_threshold(&h.signers[0], &4);
    assert_eq!(res, Err(Ok(Error::InvalidThreshold)));
    // Valid update works.
    h.client.set_threshold(&h.signers[0], &3);
    assert_eq!(h.client.get_threshold(), 3);
}

#[test]
fn non_signer_cannot_change_config() {
    let h = setup(&[1, 1, 1], 2);
    let stranger = Address::generate(&h.env);
    let extra = Address::generate(&h.env);
    assert_eq!(
        h.client.try_add_signer(&stranger, &extra, &1),
        Err(Ok(Error::NotASigner))
    );
    assert_eq!(
        h.client.try_set_threshold(&stranger, &1),
        Err(Ok(Error::NotASigner))
    );
    assert_eq!(
        h.client.try_set_signer_weight(&stranger, &h.signers[0], &5),
        Err(Ok(Error::NotASigner))
    );
}

// --- batch execution ---

struct BatchHarness {
    env: Env,
    client: MultiSigContractClient<'static>,
    helper: Address,
    helper_client: BatchHelperClient<'static>,
    signers: std::vec::Vec<Address>,
}

/// Register the multisig plus a stateful helper contract and initialize with
/// `n` signers and the given threshold.
fn setup_batch(n: u32, threshold: u32) -> BatchHarness {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, MultiSigContract);
    let client = MultiSigContractClient::new(&env, &contract_id);

    let helper = env.register_contract(None, BatchHelper);
    let helper_client = BatchHelperClient::new(&env, &helper);

    let mut signers = std::vec::Vec::new();
    let mut sv = Vec::new(&env);
    for _ in 0..n {
        let a = Address::generate(&env);
        sv.push_back(SignerWeight {
            address: a.clone(),
            weight: 1,
        });
        signers.push(a);
    }
    client.initialize(&sv, &threshold);
    BatchHarness {
        env,
        client,
        helper,
        helper_client,
        signers,
    }
}

/// Build a `Vec<Address>` from indices into the harness signer list.
fn approvers(env: &Env, signers: &[Address], idx: &[usize]) -> Vec<Address> {
    let mut v = Vec::new(env);
    for i in idx {
        v.push_back(signers[*i].clone());
    }
    v
}

fn store_call(env: &Env, helper: &Address, key: u64, value: u64) -> BatchCall {
    BatchCall {
        contract: helper.clone(),
        func: symbol_short!("store"),
        args: vec![env, key.into_val(env), value.into_val(env)],
    }
}

fn fail_call(env: &Env, helper: &Address) -> BatchCall {
    BatchCall {
        contract: helper.clone(),
        func: symbol_short!("fail"),
        args: Vec::new(env),
    }
}

fn boom_call(env: &Env, helper: &Address) -> BatchCall {
    BatchCall {
        contract: helper.clone(),
        func: symbol_short!("boom"),
        args: Vec::new(env),
    }
}

#[test]
fn batch_executes_all_calls_under_single_threshold_check() {
    let h = setup_batch(3, 2);
    let calls = vec![
        &h.env,
        store_call(&h.env, &h.helper, 1, 100),
        store_call(&h.env, &h.helper, 2, 200),
    ];
    // Caller (s0) plus one approver (s1) reach threshold 2.
    h.client.execute_batch(
        &h.signers[0],
        &1,
        &calls,
        &approvers(&h.env, &h.signers, &[1]),
    );
    assert_eq!(h.helper_client.get(&1), 100);
    assert_eq!(h.helper_client.get(&2), 200);
    assert_eq!(h.client.get_last_batch_nonce(), 1);
}

#[test]
fn batch_below_threshold_rejected() {
    let h = setup_batch(3, 2);
    let calls = vec![&h.env, store_call(&h.env, &h.helper, 1, 100)];
    // Only the caller's signature (weight 1) < threshold 2.
    let res = h.client.try_execute_batch(
        &h.signers[0],
        &1,
        &calls,
        &approvers(&h.env, &h.signers, &[]),
    );
    assert_eq!(res, Err(Ok(Error::ThresholdNotMet)));
    // Nothing was executed and the nonce was not consumed.
    assert_eq!(h.helper_client.get(&1), 0);
    assert_eq!(h.client.get_last_batch_nonce(), 0);
}

#[test]
fn batch_rejects_non_signer_approver() {
    let h = setup_batch(3, 2);
    let stranger = Address::generate(&h.env);
    let calls = vec![&h.env, store_call(&h.env, &h.helper, 1, 100)];
    let app = vec![&h.env, h.signers[1].clone(), stranger];
    let res = h.client.try_execute_batch(&h.signers[0], &1, &calls, &app);
    assert_eq!(res, Err(Ok(Error::NotASigner)));
}

#[test]
fn batch_duplicate_approvers_do_not_stack_weight() {
    let h = setup_batch(3, 2);
    let calls = vec![&h.env, store_call(&h.env, &h.helper, 1, 100)];
    // The caller listed as approver too must still count once: 1 < threshold 2.
    let app = vec![&h.env, h.signers[0].clone()];
    let res = h.client.try_execute_batch(&h.signers[0], &1, &calls, &app);
    assert_eq!(res, Err(Ok(Error::ThresholdNotMet)));
}

#[test]
fn batch_nonce_replay_rejected() {
    let h = setup_batch(3, 2);
    let calls = vec![&h.env, store_call(&h.env, &h.helper, 1, 100)];
    let app = approvers(&h.env, &h.signers, &[1]);
    h.client.execute_batch(&h.signers[0], &1, &calls, &app);

    // Replaying the same nonce is rejected.
    let res = h.client.try_execute_batch(&h.signers[0], &1, &calls, &app);
    assert_eq!(res, Err(Ok(Error::InvalidNonce)));
    // A nonce below the initial counter is rejected too.
    let res = h.client.try_execute_batch(&h.signers[0], &0, &calls, &app);
    assert_eq!(res, Err(Ok(Error::InvalidNonce)));

    // Nonces are monotonic, not strictly sequential: gaps are allowed.
    let calls2 = vec![&h.env, store_call(&h.env, &h.helper, 2, 200)];
    h.client.execute_batch(&h.signers[0], &5, &calls2, &app);
    assert_eq!(h.client.get_last_batch_nonce(), 5);
}

#[test]
fn batch_rolls_back_all_calls_on_sub_call_failure() {
    let h = setup_batch(3, 2);
    // store(1) succeeds, then the middle call fails, then store(2) would run.
    let calls = vec![
        &h.env,
        store_call(&h.env, &h.helper, 1, 100),
        fail_call(&h.env, &h.helper),
        store_call(&h.env, &h.helper, 2, 200),
    ];
    let res = h.client.try_execute_batch(
        &h.signers[0],
        &1,
        &calls,
        &approvers(&h.env, &h.signers, &[1]),
    );
    // The callee's own contract error is surfaced...
    assert_eq!(res, Err(Ok(Error::InvalidInput)));
    // ...and no partial state was committed (atomicity).
    assert_eq!(h.helper_client.get(&1), 0);
    assert_eq!(h.helper_client.get(&2), 0);
    // The nonce was rolled back too, so the same batch can be retried.
    assert_eq!(h.client.get_last_batch_nonce(), 0);
}

#[test]
fn batch_sub_call_panic_maps_to_batch_call_failed() {
    let h = setup_batch(3, 2);
    let calls = vec![
        &h.env,
        store_call(&h.env, &h.helper, 1, 100),
        boom_call(&h.env, &h.helper),
    ];
    let res = h.client.try_execute_batch(
        &h.signers[0],
        &1,
        &calls,
        &approvers(&h.env, &h.signers, &[1]),
    );
    assert_eq!(res, Err(Ok(Error::BatchCallFailed)));
    assert_eq!(h.helper_client.get(&1), 0);
    assert_eq!(h.client.get_last_batch_nonce(), 0);
}

#[test]
fn batch_signatures_cover_the_entire_payload() {
    let h = setup_batch(3, 2);
    let calls = vec![
        &h.env,
        store_call(&h.env, &h.helper, 1, 100),
        store_call(&h.env, &h.helper, 2, 200),
    ];
    let app = approvers(&h.env, &h.signers, &[1]);
    h.client.execute_batch(&h.signers[0], &7, &calls, &app);

    let auths = h.env.auths();
    // The caller AND every approver authorized exactly the batch payload
    // `(nonce, calls)` — the same payload the contract re-derives internally.
    let expected: Vec<Val> = vec![&h.env, 7u64.into_val(&h.env), calls.to_val()];
    for signer in [&h.signers[0], &h.signers[1]] {
        assert!(
            auths.iter().any(|(addr, inv)| {
                addr == signer
                    && inv.function
                        == AuthorizedFunction::Contract((
                            h.client.address.clone(),
                            Symbol::new(&h.env, "execute_batch"),
                            expected.clone(),
                        ))
            }),
            "signer {signer:?} did not authorize the exact batch payload"
        );
    }
}

#[test]
fn batch_rejects_empty_calls() {
    let h = setup_batch(3, 2);
    let calls = Vec::new(&h.env);
    let res = h.client.try_execute_batch(
        &h.signers[0],
        &1,
        &calls,
        &approvers(&h.env, &h.signers, &[1]),
    );
    assert_eq!(res, Err(Ok(Error::InvalidInput)));
}

#[test]
fn batch_rejects_too_many_calls() {
    let h = setup_batch(3, 2);
    let mut calls = Vec::new(&h.env);
    for i in 0..MAX_BATCH_CALLS + 1 {
        calls.push_back(store_call(&h.env, &h.helper, i as u64, i as u64));
    }
    let res = h.client.try_execute_batch(
        &h.signers[0],
        &1,
        &calls,
        &approvers(&h.env, &h.signers, &[1]),
    );
    assert_eq!(res, Err(Ok(Error::InvalidInput)));
}

#[test]
fn batch_requires_signer_caller() {
    let h = setup_batch(3, 2);
    let stranger = Address::generate(&h.env);
    let calls = vec![&h.env, store_call(&h.env, &h.helper, 1, 100)];
    let res =
        h.client
            .try_execute_batch(&stranger, &1, &calls, &approvers(&h.env, &h.signers, &[1]));
    assert_eq!(res, Err(Ok(Error::NotASigner)));
}

#[test]
fn batch_blocked_by_emergency_lock() {
    let h = setup_batch(3, 2);
    h.client.set_emergency_lock(&h.signers[0], &true);
    let calls = vec![&h.env, store_call(&h.env, &h.helper, 1, 100)];
    let res = h.client.try_execute_batch(
        &h.signers[0],
        &1,
        &calls,
        &approvers(&h.env, &h.signers, &[1]),
    );
    assert_eq!(res, Err(Ok(Error::EmergencyLock)));
}

// --- weighted threshold verification ---

/// Collect the given harness signers into a contract `Vec<Address>`.
fn signatories(env: &Env, signers: &[Address], idx: &[usize]) -> Vec<Address> {
    let mut v = Vec::new(env);
    for i in idx {
        v.push_back(signers[*i].clone());
    }
    v
}

#[test]
fn signers_carry_the_default_weight() {
    let h = setup(3, 2);
    // An unweighted multisig is a plain N-of-M one: every signer weighs 1.
    for signer in &h.signers {
        assert_eq!(h.client.get_signer_weight(signer), 1);
    }
    assert_eq!(h.client.get_total_weight(), 3);
    // A non-signer carries no weight at all.
    assert_eq!(h.client.get_signer_weight(&Address::generate(&h.env)), 0);
}

#[test]
fn verify_threshold_accumulates_weight_of_each_signature() {
    let h = setup(3, 2);
    let msg = payload(&h.env);
    // Two distinct signers at weight 1 each exactly reach threshold 2.
    let weight = h
        .client
        .verify_threshold(&signatories(&h.env, &h.signers, &[0, 1]), &msg);
    assert_eq!(weight, 2);
}

#[test]
fn verify_threshold_is_bound_to_the_payload() {
    let h = setup(3, 2);
    let msg = payload(&h.env);
    let sigs = signatories(&h.env, &h.signers, &[0, 1]);
    h.client.verify_threshold(&sigs, &msg);

    // Each signature covers the exact payload, so it cannot be replayed against
    // a different one.
    let auths = h.env.auths();
    let expected: Vec<Val> = vec![&h.env, msg.to_val()];
    for signer in [&h.signers[0], &h.signers[1]] {
        assert!(
            auths.iter().any(|(addr, inv)| {
                addr == signer
                    && inv.function
                        == AuthorizedFunction::Contract((
                            h.client.address.clone(),
                            Symbol::new(&h.env, "verify_threshold"),
                            expected.clone(),
                        ))
            }),
            "signer {signer:?} did not authorize the exact payload"
        );
    }
}

#[test]
fn verify_threshold_at_the_exact_boundary() {
    let h = setup(3, 2);
    // s0 weighs 2, so the aggregate is 4 and a threshold of 3 becomes reachable.
    h.client.set_signer_weight(&h.signers[0], &h.signers[0], &2);
    assert_eq!(h.client.get_total_weight(), 4);
    h.client.set_threshold(&h.signers[0], &3);
    let msg = payload(&h.env);

    // 2 + 1 == 3 is exactly the threshold and passes.
    assert_eq!(
        h.client
            .verify_threshold(&signatories(&h.env, &h.signers, &[0, 1]), &msg),
        3
    );
    // 1 + 1 == 2 is one short and fails.
    assert_eq!(
        h.client
            .try_verify_threshold(&signatories(&h.env, &h.signers, &[1, 2]), &msg),
        Err(Ok(Error::ThresholdNotMet))
    );
}

#[test]
fn verify_threshold_rejects_insufficient_weight() {
    let h = setup(3, 2);
    let msg = payload(&h.env);
    // A single weight-1 signature is short of threshold 2.
    assert_eq!(
        h.client
            .try_verify_threshold(&signatories(&h.env, &h.signers, &[0]), &msg),
        Err(Ok(Error::ThresholdNotMet))
    );
}

#[test]
fn verify_threshold_counts_duplicate_signers_once() {
    let h = setup(3, 2);
    let msg = payload(&h.env);
    // The same key repeated cannot stack its own weight to reach the threshold.
    assert_eq!(
        h.client
            .try_verify_threshold(&signatories(&h.env, &h.signers, &[0, 0, 0]), &msg),
        Err(Ok(Error::ThresholdNotMet))
    );

    // With enough weight of its own the single signer passes, still counted once.
    h.client.set_signer_weight(&h.signers[0], &h.signers[0], &2);
    assert_eq!(
        h.client
            .verify_threshold(&signatories(&h.env, &h.signers, &[0, 0]), &msg),
        2
    );
}

#[test]
fn verify_threshold_rejects_unregistered_signers() {
    let h = setup(3, 2);
    let msg = payload(&h.env);
    let mut sigs = signatories(&h.env, &h.signers, &[0]);
    sigs.push_back(Address::generate(&h.env));
    assert_eq!(
        h.client.try_verify_threshold(&sigs, &msg),
        Err(Ok(Error::NotASigner))
    );
}

#[test]
fn verify_threshold_rejects_empty_signature_set() {
    let h = setup(3, 2);
    assert_eq!(
        h.client
            .try_verify_threshold(&Vec::new(&h.env), &payload(&h.env)),
        Err(Ok(Error::InvalidInput))
    );
}

#[test]
fn verify_threshold_blocked_by_emergency_lock() {
    let h = setup(3, 2);
    h.client.set_emergency_lock(&h.signers[0], &true);
    assert_eq!(
        h.client
            .try_verify_threshold(&signatories(&h.env, &h.signers, &[0, 1]), &payload(&h.env)),
        Err(Ok(Error::EmergencyLock))
    );
}

#[test]
fn proposal_approvals_accumulate_signer_weight() {
    let h = setup(3, 3);
    // A weight-3 proposer satisfies threshold 3 on its own signature.
    h.client.set_signer_weight(&h.signers[0], &h.signers[0], &3);
    let id = h.client.propose(
        &h.signers[0],
        &symbol_short!("payment"),
        &payload(&h.env),
        &0,
    );
    assert_eq!(h.client.get_proposal(&id).approvals, 3);
    h.client.execute(&h.signers[0], &id);
    assert!(h.client.get_proposal(&id).executed);
}

#[test]
fn weighted_approval_reaches_threshold() {
    let h = setup(3, 3);
    h.client.set_signer_weight(&h.signers[0], &h.signers[1], &2);
    let id = h.client.propose(
        &h.signers[0],
        &symbol_short!("payment"),
        &payload(&h.env),
        &0,
    );
    // Proposer weighs 1; the weight-2 approver takes the total to exactly 3.
    assert_eq!(h.client.approve(&h.signers[1], &id), 3);
    h.client.execute(&h.signers[0], &id);
    assert!(h.client.get_proposal(&id).executed);
}

#[test]
fn light_approvals_still_fall_short() {
    let h = setup(3, 3);
    h.client.set_signer_weight(&h.signers[0], &h.signers[0], &2);
    h.client.set_threshold(&h.signers[0], &4);
    let id = h.client.propose(
        &h.signers[1],
        &symbol_short!("payment"),
        &payload(&h.env),
        &0,
    );
    // 1 + 1 == 2 < 4.
    assert_eq!(h.client.approve(&h.signers[2], &id), 2);
    assert_eq!(
        h.client.try_execute(&h.signers[1], &id),
        Err(Ok(Error::ThresholdNotMet))
    );
}

#[test]
fn batch_execution_uses_signer_weights() {
    let h = setup_batch(3, 2);
    h.client.set_signer_weight(&h.signers[0], &h.signers[0], &2);
    let calls = vec![&h.env, store_call(&h.env, &h.helper, 1, 100)];
    // The weight-2 caller alone now meets threshold 2, with no approvers.
    h.client
        .execute_batch(&h.signers[0], &1, &calls, &Vec::new(&h.env));
    assert_eq!(h.helper_client.get(&1), 100);
}

#[test]
fn signer_weight_bounds_are_enforced() {
    let h = setup(3, 2);
    assert_eq!(
        h.client
            .try_set_signer_weight(&h.signers[0], &h.signers[1], &0),
        Err(Ok(Error::InvalidSignerWeight))
    );
    assert_eq!(
        h.client
            .try_set_signer_weight(&h.signers[0], &h.signers[1], &(MAX_SIGNER_WEIGHT + 1)),
        Err(Ok(Error::InvalidSignerWeight))
    );
    // The bound itself is allowed.
    h.client
        .set_signer_weight(&h.signers[0], &h.signers[1], &MAX_SIGNER_WEIGHT);
    assert_eq!(h.client.get_signer_weight(&h.signers[1]), MAX_SIGNER_WEIGHT);
}

#[test]
fn weight_changes_cannot_strand_the_multisig() {
    let h = setup(3, 3);
    // Weight s0 up to 3 (aggregate 5) and raise the threshold to match.
    h.client.set_signer_weight(&h.signers[0], &h.signers[0], &3);
    h.client.set_threshold(&h.signers[0], &5);
    // Aggregate is 5; taking s0 back down to 1 would leave 3 < 5.
    assert_eq!(
        h.client
            .try_set_signer_weight(&h.signers[0], &h.signers[0], &1),
        Err(Ok(Error::InvalidThreshold))
    );
    assert_eq!(h.client.get_total_weight(), 5);
}

#[test]
fn removing_a_signer_accounts_for_its_weight() {
    let h = setup(3, 3);
    h.client.set_signer_weight(&h.signers[0], &h.signers[0], &3);
    // Aggregate 5, threshold 3: dropping a weight-1 signer still leaves 4.
    h.client.remove_signer(&h.signers[0], &h.signers[2]);
    assert_eq!(h.client.get_total_weight(), 4);
    // Dropping the weight-3 signer would leave 1 < 3.
    assert_eq!(
        h.client.try_remove_signer(&h.signers[0], &h.signers[0]),
        Err(Ok(Error::InvalidThreshold))
    );
}

#[test]
fn removed_signer_weight_does_not_linger() {
    let h = setup(3, 2);
    let extra = Address::generate(&h.env);
    h.client.add_signer_with_weight(&h.signers[0], &extra, &5);
    assert_eq!(h.client.get_signer_weight(&extra), 5);
    assert_eq!(h.client.get_total_weight(), 8);

    h.client.remove_signer(&h.signers[0], &extra);
    assert_eq!(h.client.get_signer_weight(&extra), 0);
    // Re-adding without a weight starts from the default, not the stale 5.
    h.client.add_signer(&h.signers[0], &extra);
    assert_eq!(h.client.get_signer_weight(&extra), 1);
    assert_eq!(h.client.get_total_weight(), 4);
}

#[test]
fn threshold_may_exceed_the_signer_count_once_weighted() {
    let h = setup(3, 2);
    // Threshold 5 is unreachable with three weight-1 signers.
    assert_eq!(
        h.client.try_set_threshold(&h.signers[0], &5),
        Err(Ok(Error::InvalidThreshold))
    );
    // Weighting a signer makes the same threshold reachable.
    h.client.set_signer_weight(&h.signers[0], &h.signers[0], &3);
    h.client.set_threshold(&h.signers[0], &5);
    assert_eq!(h.client.get_threshold(), 5);
}

#[test]
fn only_signers_can_reweight_and_only_signers_can_be_weighted() {
    let h = setup(3, 2);
    let stranger = Address::generate(&h.env);
    assert_eq!(
        h.client.try_set_signer_weight(&stranger, &h.signers[1], &2),
        Err(Ok(Error::NotASigner))
    );
    assert_eq!(
        h.client.try_set_signer_weight(&h.signers[0], &stranger, &2),
        Err(Ok(Error::NotASigner))
    );
    assert_eq!(
        h.client
            .try_add_signer_with_weight(&h.signers[0], &stranger, &0),
        Err(Ok(Error::InvalidSignerWeight))
    );
}
