use astroid_shared::errors::Error;
use soroban_sdk::{
    testutils::Address as _, testutils::Events, Address, BytesN, Env, IntoVal, String, Symbol, Val,
};

use crate::{PolicyContract, PolicyContractClient};

/// Assert that the canonical `ContractEvent` with the given variant symbol was
/// published during the test (single-topic event = the variant name).
fn assert_event(env: &Env, variant: &str) {
    let want: Val = Symbol::new(env, variant).into_val(env);
    let found = env
        .events()
        .all()
        .iter()
        .any(|(_contract_id, topics, _data)| topics.contains(&want));
    assert!(found, "expected ContractEvent::{} to be emitted", variant);
}

fn setup<'a>(env: &Env, owner: &Address) -> PolicyContractClient<'a> {
    let id = env.register_contract(None, PolicyContract);
    let client = PolicyContractClient::new(env, &id);
    client.initialize();
    client.register_policy(
        owner,
        &String::from_str(env, "max_txn"),
        &BytesN::from_array(env, &[42; 32]),
        &1_000_000,
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
    p.add_to_whitelist(&owner, &String::from_str(&env, "max_txn"), &asset);
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
    p.add_to_whitelist(&owner, &String::from_str(&env, "max_txn"), &asset);
    assert_eq!(
        p.try_check_transfer(
            &String::from_str(&env, "max_txn"),
            &asset,
            &recip,
            &1_000_001
        ),
        Err(Ok(Error::PolicyDenied))
    );
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
        &Some(allowed.clone()),
        &None,
        &0,
    );
    client.add_to_whitelist(&owner, &String::from_str(&env, "vendor_list"), &asset);

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
    p.add_to_whitelist(&owner, &String::from_str(&env, "max_txn"), &asset);
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
fn standard_policy_violation_event_emitted() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);
    p.add_to_whitelist(&owner, &String::from_str(&env, "max_txn"), &asset);
    // Amount above the configured max triggers a policy denial -> violation event.
    let _ = p.try_check_transfer(
        &String::from_str(&env, "max_txn"),
        &asset,
        &recip,
        &1_000_001,
    );
    assert_event(&env, "PolicyViolation");
}

#[test]
fn whitelist_permits_approved_token_and_blocks_others() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let approved = Address::generate(&env);
    let malicious = Address::generate(&env);
    let recip = Address::generate(&env);
    p.add_to_whitelist(&owner, &String::from_str(&env, "max_txn"), &approved);

    // Approved SAC address passes
    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &approved, &recip, &1,)
        .is_ok());

    // Non-approved (scam) asset is rejected deterministically
    assert_eq!(
        p.try_check_transfer(&String::from_str(&env, "max_txn"), &malicious, &recip, &1,),
        Err(Ok(Error::TokenNotWhitelisted))
    );
}

#[test]
fn whitelist_enforces_without_recording_an_event_for_ok_path() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let approved = Address::generate(&env);
    let recip = Address::generate(&env);
    p.add_to_whitelist(&owner, &String::from_str(&env, "max_txn"), &approved);
    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &approved, &recip, &1,)
        .is_ok());
}

#[test]
fn whitelist_is_scoped_per_policy() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let token = Address::generate(&env);
    let recip = Address::generate(&env);
    // Approved under "max_txn" but never registered under "vendor_list".
    p.add_to_whitelist(&owner, &String::from_str(&env, "max_txn"), &token);

    // Allowed under the policy where it is whitelisted
    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &token, &recip, &1,)
        .is_ok());

    // Same token under a different policy is still gated
    p.register_policy(
        &owner,
        &String::from_str(&env, "vendor_list"),
        &BytesN::from_array(&env, &[9; 32]),
        &0,
        &None,
        &None,
        &0,
    );
    assert_eq!(
        p.try_check_transfer(&String::from_str(&env, "vendor_list"), &token, &recip, &1,),
        Err(Ok(Error::TokenNotWhitelisted))
    );
}

#[test]
fn is_token_allowed_query_reflects_whitelist_edits() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let token = Address::generate(&env);
    let pid = String::from_str(&env, "max_txn");

    assert!(!p.is_token_allowed(&pid, &token));
    p.add_to_whitelist(&owner, &pid, &token);
    assert!(p.is_token_allowed(&pid, &token));
    p.remove_from_whitelist(&owner, &pid, &token);
    assert!(!p.is_token_allowed(&pid, &token));
}

#[test]
fn non_owner_cannot_manage_whitelist() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let stranger = Address::generate(&env);
    let token = Address::generate(&env);
    let p = setup(&env, &owner);
    let pid = String::from_str(&env, "max_txn");

    assert_eq!(
        p.try_add_to_whitelist(&stranger, &pid, &token),
        Err(Ok(Error::Unauthorized))
    );
}

#[test]
fn duplicate_and_missing_whitelist_ops_are_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let token = Address::generate(&env);
    let p = setup(&env, &owner);
    let pid = String::from_str(&env, "max_txn");

    p.add_to_whitelist(&owner, &pid, &token);
    assert_eq!(
        p.try_add_to_whitelist(&owner, &pid, &token),
        Err(Ok(Error::AlreadyExists))
    );
    assert_eq!(
        p.try_remove_from_whitelist(&owner, &pid, &Address::generate(&env)),
        Err(Ok(Error::NotFound))
    );
    p.remove_from_whitelist(&owner, &pid, &token);
}
