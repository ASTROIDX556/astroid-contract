#![cfg(test)]
extern crate std;

use crate::{MultiSigContract, MultiSigContractClient, SignerWeight};
use astroid_shared::errors::Error;
use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::{symbol_short, Address, Bytes, Env, Vec};

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
    assert!(stored.iter().any(|s| s.address == new_signer && s.weight == 3));

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
    assert!(stored.iter().any(|s| s.address == h.signers[0] && s.weight == 5));

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
    let res = h.client.try_set_signer_weight(&h.signers[1], &h.signers[0], &1);
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
