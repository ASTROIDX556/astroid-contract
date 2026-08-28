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

/// Register a policy and return a client for whitelist tests.
fn register<'a>(env: &'a Env, owner: &Address, policy_id: &str) -> PolicyContractClient<'a> {
    let id = env.register_contract(None, PolicyContract);
    let client = PolicyContractClient::new(env, &id);
    client.initialize();
    client.register_policy(
        owner,
        &String::from_str(env, policy_id),
        &BytesN::from_array(env, &[9; 32]),
        &0,
        &None,
        &None,
        &0,
    );
    client
}

#[test]
fn whitelist_allows_listed_and_blocks_unlisted() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let client = register(&env, &owner, "wl");
    let asset = Address::generate(&env);
    let a = Address::generate(&env);
    let b = Address::generate(&env);
    let stranger = Address::generate(&env);

    client.set_whitelist_enabled(&owner, &String::from_str(&env, "wl"), &true);
    client.add_whitelist(&owner, &String::from_str(&env, "wl"), &a);
    client.add_whitelist(&owner, &String::from_str(&env, "wl"), &b);

    // Listed recipients pass.
    assert!(client
        .try_check_transfer(&String::from_str(&env, "wl"), &asset, &a, &1)
        .is_ok());
    assert!(client
        .try_check_transfer(&String::from_str(&env, "wl"), &asset, &b, &1)
        .is_ok());
    // Unlisted recipient is blocked.
    assert!(client
        .try_check_transfer(&String::from_str(&env, "wl"), &asset, &stranger, &1)
        .is_err());
}

#[test]
fn empty_whitelist_denies_all_recipients() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let client = register(&env, &owner, "wl_empty");
    let asset = Address::generate(&env);
    let anyone = Address::generate(&env);

    client.set_whitelist_enabled(&owner, &String::from_str(&env, "wl_empty"), &true);
    // Whitelist mode active with no entries — fail closed, every recipient denied.
    assert!(client
        .try_check_transfer(&String::from_str(&env, "wl_empty"), &asset, &anyone, &1)
        .is_err());
}

#[test]
fn whitelist_removal_blocks_previously_allowed() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let client = register(&env, &owner, "wl_rem");
    let asset = Address::generate(&env);
    let a = Address::generate(&env);

    client.set_whitelist_enabled(&owner, &String::from_str(&env, "wl_rem"), &true);
    client.add_whitelist(&owner, &String::from_str(&env, "wl_rem"), &a);
    assert!(client
        .try_check_transfer(&String::from_str(&env, "wl_rem"), &asset, &a, &1)
        .is_ok());

    client.remove_whitelist(&owner, &String::from_str(&env, "wl_rem"), &a);
    // Removing an absent entry fails with NotFound.
    assert!(client
        .try_remove_whitelist(&owner, &String::from_str(&env, "wl_rem"), &a)
        .is_err());
    // The previously allowed recipient is now blocked.
    assert!(client
        .try_check_transfer(&String::from_str(&env, "wl_rem"), &asset, &a, &1)
        .is_err());
}

#[test]
fn whitelist_disabled_allows_any_recipient() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let client = register(&env, &owner, "wl_off");
    let asset = Address::generate(&env);
    let anyone = Address::generate(&env);

    // Default state: whitelist mode off, anyone passes.
    assert!(client
        .try_check_transfer(&String::from_str(&env, "wl_off"), &asset, &anyone, &1)
        .is_ok());
    // Toggle off again after enabling also opens the gate.
    client.set_whitelist_enabled(&owner, &String::from_str(&env, "wl_off"), &true);
    client.set_whitelist_enabled(&owner, &String::from_str(&env, "wl_off"), &false);
    assert!(client
        .try_check_transfer(&String::from_str(&env, "wl_off"), &asset, &anyone, &1)
        .is_ok());
}

#[test]
fn non_owner_cannot_manage_whitelist() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let intruder = Address::generate(&env);
    let client = register(&env, &owner, "wl_auth");
    let pid = String::from_str(&env, "wl_auth");
    let target = Address::generate(&env);

    assert!(client
        .try_set_whitelist_enabled(&intruder, &pid, &true)
        .is_err());
    assert!(client.try_add_whitelist(&intruder, &pid, &target).is_err());
    assert!(client
        .try_remove_whitelist(&intruder, &pid, &target)
        .is_err());
}

#[test]
fn duplicate_whitelist_add_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let client = register(&env, &owner, "wl_dup");
    let pid = String::from_str(&env, "wl_dup");
    let target = Address::generate(&env);

    client.add_whitelist(&owner, &pid, &target);
    assert!(client.try_add_whitelist(&owner, &pid, &target).is_err());
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
