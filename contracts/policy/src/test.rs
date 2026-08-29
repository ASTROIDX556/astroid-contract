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
fn standard_policy_violation_event_emitted() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);
    // Amount above the configured max triggers a policy denial -> violation event.
    let _ = p.try_check_transfer(
        &String::from_str(&env, "max_txn"),
        &asset,
        &recip,
        &1_000_001,
    );
    assert_event(&env, "PolicyViolation");
}

// --- asset blacklist ---

const MAX_TXN: &str = "max_txn";

#[test]
fn blacklisted_asset_is_denied() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let good = Address::generate(&env);
    let bad = Address::generate(&env);
    let recip = Address::generate(&env);
    let policy_id = String::from_str(&env, MAX_TXN);

    // Nothing is blacklisted yet, so both assets pass.
    assert!(p.try_check_transfer(&policy_id, &good, &recip, &1).is_ok());
    assert!(p.try_check_transfer(&policy_id, &bad, &recip, &1).is_ok());

    p.add_asset_blacklist(&owner, &policy_id, &bad);
    assert!(p.is_asset_blacklisted(&policy_id, &bad));
    assert!(!p.is_asset_blacklisted(&policy_id, &good));

    // The blacklisted asset is now rejected with its own deterministic error...
    assert_eq!(
        p.try_check_transfer(&policy_id, &bad, &recip, &1),
        Err(Ok(Error::AssetBlacklisted))
    );
    // ...while every other asset still flows.
    assert!(p.try_check_transfer(&policy_id, &good, &recip, &1).is_ok());
}

#[test]
fn blacklist_removal_restores_the_asset() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);
    let policy_id = String::from_str(&env, MAX_TXN);

    p.add_asset_blacklist(&owner, &policy_id, &asset);
    assert!(p
        .try_check_transfer(&policy_id, &asset, &recip, &1)
        .is_err());

    p.remove_asset_blacklist(&owner, &policy_id, &asset);
    assert!(!p.is_asset_blacklisted(&policy_id, &asset));
    assert!(p.try_check_transfer(&policy_id, &asset, &recip, &1).is_ok());
}

#[test]
fn blacklist_beats_the_asset_allow_list() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);
    let id = env.register_contract(None, PolicyContract);
    let client = PolicyContractClient::new(&env, &id);
    client.initialize();
    let policy_id = String::from_str(&env, "single_asset");
    client.register_policy(
        &owner,
        &policy_id,
        &BytesN::from_array(&env, &[9; 32]),
        &0,
        &None,
        &Some(asset.clone()),
        &0,
    );

    // The asset is explicitly allow-listed, so it passes today.
    assert!(client
        .try_check_transfer(&policy_id, &asset, &recip, &1)
        .is_ok());

    // Blacklisting the same asset must win over the allow-list.
    client.add_asset_blacklist(&owner, &policy_id, &asset);
    assert_eq!(
        client.try_check_transfer(&policy_id, &asset, &recip, &1),
        Err(Ok(Error::AssetBlacklisted))
    );
}

#[test]
fn blacklist_is_scoped_to_its_policy() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);
    let client = setup(&env, &owner);
    let first = String::from_str(&env, MAX_TXN);
    let second = String::from_str(&env, "other");
    client.register_policy(
        &owner,
        &second,
        &BytesN::from_array(&env, &[3; 32]),
        &1_000_000,
        &None,
        &None,
        &0,
    );

    client.add_asset_blacklist(&owner, &first, &asset);

    // Only the policy that listed the asset denies it.
    assert!(client
        .try_check_transfer(&first, &asset, &recip, &1)
        .is_err());
    assert!(client
        .try_check_transfer(&second, &asset, &recip, &1)
        .is_ok());
    assert!(!client.is_asset_blacklisted(&second, &asset));
}

#[test]
fn only_the_owner_can_manage_the_blacklist() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let stranger = Address::generate(&env);
    let asset = Address::generate(&env);
    let p = setup(&env, &owner);
    let policy_id = String::from_str(&env, MAX_TXN);

    assert_eq!(
        p.try_add_asset_blacklist(&stranger, &policy_id, &asset),
        Err(Ok(Error::Unauthorized))
    );
    p.add_asset_blacklist(&owner, &policy_id, &asset);
    assert_eq!(
        p.try_remove_asset_blacklist(&stranger, &policy_id, &asset),
        Err(Ok(Error::Unauthorized))
    );
    assert!(p.is_asset_blacklisted(&policy_id, &asset));
}

#[test]
fn blacklist_management_rejects_bad_input() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let asset = Address::generate(&env);
    let p = setup(&env, &owner);
    let policy_id = String::from_str(&env, MAX_TXN);

    // Removing an asset that was never listed.
    assert_eq!(
        p.try_remove_asset_blacklist(&owner, &policy_id, &asset),
        Err(Ok(Error::NotFound))
    );
    p.add_asset_blacklist(&owner, &policy_id, &asset);
    // Listing it twice.
    assert_eq!(
        p.try_add_asset_blacklist(&owner, &policy_id, &asset),
        Err(Ok(Error::AlreadyExists))
    );
    // Unknown policy.
    assert_eq!(
        p.try_add_asset_blacklist(&owner, &String::from_str(&env, "nope"), &asset),
        Err(Ok(Error::NotFound))
    );
}
