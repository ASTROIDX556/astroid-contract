#![cfg(test)]
extern crate std;

use crate::{MultiSigContract, MultiSigContractClient};
use astroid_shared::errors::Error;
use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::{symbol_short, Address, Bytes, Env, Map};

struct Harness {
    env: Env,
    client: MultiSigContractClient<'static>,
    signers: std::vec::Vec<Address>,
}

fn setup(weights: std::vec::Vec<u32>, threshold: u32) -> Harness {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, MultiSigContract);
    let client = MultiSigContractClient::new(&env, &contract_id);

    let mut signers = std::vec::Vec::new();
    let mut sm = Map::new(&env);
    for weight in weights {
        let a = Address::generate(&env);
        sm.set(a.clone(), weight);
        signers.push(a);
    }
    client.initialize(&sm, &threshold);
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
    let h = setup(std::vec![1, 1, 1], 2);
    assert_eq!(h.client.get_threshold(), 2);
    assert_eq!(h.client.get_signers().keys().len(), 3);
    assert!(h.client.is_signer(&h.signers[0]));
    assert!(!h.client.is_locked());
}

#[test]
fn bad_threshold_rejected_on_init() {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, MultiSigContract);
    let client = MultiSigContractClient::new(&env, &contract_id);
    let mut sm = Map::new(&env);
    sm.set(Address::generate(&env), 1);
    sm.set(Address::generate(&env), 1);
    // threshold 3 > 2 signers
    let res = client.try_initialize(&sm, &3);
    assert_eq!(res, Err(Ok(Error::InvalidThreshold)));
}

#[test]
fn propose_approve_execute_happy_path() {
    let h = setup(std::vec![1, 1, 1], 2);
    let id = h.client.propose(
        &h.signers[0],
        &symbol_short!("payment"),
        &payload(&h.env),
        &0,
    );
    // proposer auto-approved (1); second signer approves -> 2 == threshold.
    let approvals = h.client.approve(&h.signers[1], &id);
    assert_eq!(approvals, 2);
    h.client.execute(&h.signers[2], &id);
    assert!(h.client.get_proposal(&id).executed);
}

#[test]
fn execute_below_threshold_fails() {
    let h = setup(std::vec![1, 1, 1], 2);
    let id = h.client.propose(
        &h.signers[0],
        &symbol_short!("payment"),
        &payload(&h.env),
        &0,
    );
    // Only proposer's approval (1) < threshold (2).
    let res = h.client.try_execute(&h.signers[0], &id);
    assert_eq!(res, Err(Ok(Error::ThresholdNotMet)));
}

#[test]
fn non_signer_cannot_propose_or_approve() {
    let h = setup(std::vec![1, 1, 1], 2);
    let stranger = Address::generate(&h.env);
    let res = h
        .client
        .try_propose(&stranger, &symbol_short!("payment"), &payload(&h.env), &0);
    assert_eq!(res, Err(Ok(Error::NotASigner)));
}

#[test]
fn double_approval_rejected() {
    let h = setup(std::vec![1, 1, 1], 2);
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
    let h = setup(std::vec![1, 1], 2);
    h.env.ledger().set_timestamp(1_000);
    let unlock = 5_000u64;
    let id = h.client.propose(
        &h.signers[0],
        &symbol_short!("payment"),
        &payload(&h.env),
        &unlock,
    );
    h.client.approve(&h.signers[1], &id);
    // Threshold met, but time lock not reached.
    let res = h.client.try_execute(&h.signers[0], &id);
    assert_eq!(res, Err(Ok(Error::TimeLocked)));

    // Advance past the lock.
    h.env.ledger().set_timestamp(6_000);
    h.client.execute(&h.signers[0], &id);
    assert!(h.client.get_proposal(&id).executed);
}

#[test]
fn emergency_lock_blocks_actions() {
    let h = setup(std::vec![1, 1], 2);
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
fn add_and_remove_signer() {
    let h = setup(std::vec![1, 1, 1], 2);
    let new_signer = Address::generate(&h.env);
    h.client.add_signer(&h.signers[0], &new_signer, &1);
    assert!(h.client.is_signer(&new_signer));
    assert_eq!(h.client.get_signers().keys().len(), 4);

    h.client.remove_signer(&h.signers[0], &new_signer);
    assert!(!h.client.is_signer(&new_signer));
}

#[test]
fn cannot_add_duplicate_signer() {
    let h = setup(std::vec![1, 1, 1], 2);
    let res = h.client.try_add_signer(&h.signers[0], &h.signers[1], &1);
    assert_eq!(res, Err(Ok(Error::AlreadyExists)));
}

#[test]
fn cannot_remove_below_threshold() {
    let h = setup(std::vec![1, 1], 2);
    // Removing any signer would make it impossible to reach threshold 2.
    let res = h.client.try_remove_signer(&h.signers[0], &h.signers[1]);
    assert_eq!(res, Err(Ok(Error::InvalidThreshold)));
}

#[test]
fn set_threshold_bounds_enforced() {
    let h = setup(std::vec![1, 1, 1], 2);
    // Threshold larger than signer count is rejected.
    let res = h.client.try_set_threshold(&h.signers[0], &4);
    assert_eq!(res, Err(Ok(Error::InvalidThreshold)));
    // Valid update works.
    h.client.set_threshold(&h.signers[0], &3);
    assert_eq!(h.client.get_threshold(), 3);
}

#[test]
fn non_signer_cannot_change_config() {
    let h = setup(std::vec![1, 1, 1], 2);
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
}

#[test]
fn execute_dynamic_weights() {
    let h = setup(std::vec![50, 30, 30], 80);
    // Signer 0 has 50 weight. Signer 1 has 30 weight. Signer 2 has 30 weight.
    let id = h.client.propose(
        &h.signers[1], // weight 30
        &symbol_short!("payment"),
        &payload(&h.env),
        &0,
    );
    // Only proposer's approval (30) < threshold (80).
    let res = h.client.try_execute(&h.signers[1], &id);
    assert_eq!(res, Err(Ok(Error::ThresholdNotMet)));

    h.client.approve(&h.signers[2], &id);
    // 30 + 30 = 60 < 80
    let res2 = h.client.try_execute(&h.signers[1], &id);
    assert_eq!(res2, Err(Ok(Error::ThresholdNotMet)));

    h.client.approve(&h.signers[0], &id);
    // 60 + 50 = 110 >= 80 -> succeeds!
    h.client.execute(&h.signers[0], &id);
    assert!(h.client.get_proposal(&id).executed);
}
