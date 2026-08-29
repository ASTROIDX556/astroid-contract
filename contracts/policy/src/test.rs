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

// --- registry-authorized upgrades ---

/// The upgrade surface is wired to `astroid_interfaces::upgrade`, whose
/// end-to-end behaviour against a real registry is covered in the registry
/// crate. These assertions pin this contract's own gating: an upgrade is
/// impossible before an authority exists, and a caller that is not the upgrade
/// admin is rejected before the registry is ever consulted.
#[test]
fn upgrade_is_gated_by_the_configured_authority() {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register_contract(None, crate::PolicyContract);
    let client = crate::PolicyContractClient::new(&env, &id);

    let admin = Address::generate(&env);
    let registry = Address::generate(&env);
    let stranger = Address::generate(&env);
    let wasm_hash = soroban_sdk::BytesN::from_array(&env, &[1u8; 32]);

    // No authority configured yet.
    assert_eq!(
        client.try_check_upgrade(&admin, &wasm_hash),
        Err(Ok(astroid_shared::errors::Error::NotInitialized))
    );

    client.set_upgrade_authority(&admin, &admin, &registry);
    let authority = client.get_upgrade_authority();
    assert_eq!(authority.admin, admin);
    assert_eq!(authority.registry, registry);

    // A stranger can neither dry-run nor perform an upgrade...
    assert_eq!(
        client.try_check_upgrade(&stranger, &wasm_hash),
        Err(Ok(astroid_shared::errors::Error::Unauthorized))
    );
    assert_eq!(
        client.try_upgrade(&stranger, &wasm_hash),
        Err(Ok(astroid_shared::errors::Error::Unauthorized))
    );
    // ...nor rotate the authority to itself.
    assert_eq!(
        client.try_set_upgrade_authority(&stranger, &stranger, &registry),
        Err(Ok(astroid_shared::errors::Error::Unauthorized))
    );
}
