use astroid_shared::errors::Error;
use soroban_sdk::{testutils::Address as _, Address, BytesN, Env, String};

use crate::{PolicyContract, PolicyContractClient};

fn setup<'a>(env: &Env, owner: &Address) -> PolicyContractClient<'a> {
    let id = env.register_contract(None, PolicyContract);
    let client = PolicyContractClient::new(env, &id);
    client.initialize();
    client.register_policy(
        owner,
        &String::from_str(env, "max_txn"),
        &BytesN::from_array(env, &[42; 32]),
        &1_000_000,
        &0,
        &None,
        &None,
        &0,
    );
    client
}

#[test]
fn allows_spend_below_max() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);
    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &recip, &999_999,)
        .is_ok());
}

#[test]
fn denies_spend_above_max() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);
    let r = p.try_check_transfer(
        &String::from_str(&env, "max_txn"),
        &asset,
        &recip,
        &1_000_001,
    );
    assert!(r.is_err());
}

#[test]
fn allowlist_recipient_enforced() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let allowed = Address::generate(&env);
    let blocked = Address::generate(&env);
    let asset = Address::generate(&env);
    let id = env.register_contract(None, PolicyContract);
    let client = PolicyContractClient::new(&env, &id);
    client.initialize();
    client.register_policy(
        &owner,
        &String::from_str(&env, "vendor_list"),
        &BytesN::from_array(&env, &[7; 32]),
        &0,
        &0,
        &Some(allowed.clone()),
        &None,
        &0,
    );

    // Allowed recipient passes
    assert!(client
        .try_check_transfer(&String::from_str(&env, "vendor_list"), &asset, &allowed, &1,)
        .is_ok());

    // Other recipient denied
    assert!(client
        .try_check_transfer(&String::from_str(&env, "vendor_list"), &asset, &blocked, &1,)
        .is_err());
}

#[test]
fn disable_denies_everything() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    p.set_enabled(&owner, &String::from_str(&env, "max_txn"), &false);
    assert!(p
        .try_check_transfer(
            &String::from_str(&env, "max_txn"),
            &asset,
            &Address::generate(&env),
            &1,
        )
        .is_err());
}

#[test]
fn test_evaluate_policy_fee_limit() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let contract_id = env.register_contract(None, PolicyContract);
    let client = PolicyContractClient::new(&env, &contract_id);
    client.initialize();

    let p_id = String::from_str(&env, "fee_policy");
    client.register_policy(
        &admin,
        &p_id,
        &BytesN::from_array(&env, &[0; 32]),
        &0,
        &1000, // max fee
        &None,
        &None,
        &0,
    );

    assert_eq!(client.evaluate_policy(&p_id, &500), ());
    assert_eq!(client.try_evaluate_policy(&p_id, &1500), Err(Ok(Error::FeeLimitExceeded)));
}
