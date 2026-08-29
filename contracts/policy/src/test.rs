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

// ── Multi-token allowance ─────────────────────────────────────────────

#[test]
fn set_and_get_allowance_per_asset() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let xlm = Address::generate(&env);
    let usdc = Address::generate(&env);
    let pid = String::from_str(&env, "max_txn");
    // Initially 0 for both assets.
    assert_eq!(p.get_allowance(&pid, &xlm), 0);
    assert_eq!(p.get_allowance(&pid, &usdc), 0);

    p.set_allowance(&owner, &pid, &xlm, &5000);
    p.set_allowance(&owner, &pid, &usdc, &10000);
    assert_eq!(p.get_allowance(&pid, &xlm), 5000);
    assert_eq!(p.get_allowance(&pid, &usdc), 10000);

    // Overwrite one without affecting the other.
    p.set_allowance(&owner, &pid, &xlm, &7000);
    assert_eq!(p.get_allowance(&pid, &xlm), 7000);
    assert_eq!(p.get_allowance(&pid, &usdc), 10000);
}

#[test]
fn check_allowance_success_and_exceeded() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let pid = String::from_str(&env, "max_txn");
    p.set_allowance(&owner, &pid, &asset, &1000);

    // Within limit succeeds.
    assert!(p.try_check_allowance(&pid, &asset, &800).is_ok());
    // Exact limit succeeds.
    assert!(p.try_check_allowance(&pid, &asset, &1000).is_ok());
    // Over limit fails with deterministic error.
    let err = p.try_check_allowance(&pid, &asset, &1001).unwrap_err();
    assert_eq!(
        err,
        Ok(astroid_shared::errors::Error::PolicyAllowanceExceeded)
    );
    let err2 = p
        .try_check_transfer(&pid, &asset, &Address::generate(&env), &1001)
        .unwrap_err();
    assert_eq!(
        err2,
        Ok(astroid_shared::errors::Error::PolicyAllowanceExceeded)
    );
}

#[test]
fn update_allowance_decrements_and_guards() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let pid = String::from_str(&env, "max_txn");
    p.set_allowance(&owner, &pid, &asset, &1000);

    p.update_allowance(&owner, &pid, &asset, &400);
    assert_eq!(p.get_allowance(&pid, &asset), 600);
    p.update_allowance(&owner, &pid, &asset, &600);
    assert_eq!(p.get_allowance(&pid, &asset), 0);

    // Further consume beyond zero fails.
    let err = p
        .try_update_allowance(&owner, &pid, &asset, &1)
        .unwrap_err();
    assert_eq!(
        err,
        Ok(astroid_shared::errors::Error::PolicyAllowanceExceeded)
    );
    assert_eq!(p.get_allowance(&pid, &asset), 0);
}

#[test]
fn allowance_multi_asset_isolation() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let xlm = Address::generate(&env);
    let usdc = Address::generate(&env);
    let pid = String::from_str(&env, "max_txn");
    p.set_allowance(&owner, &pid, &xlm, &1000);
    p.set_allowance(&owner, &pid, &usdc, &5000);

    // Consume XLM does not affect USDC.
    p.update_allowance(&owner, &pid, &xlm, &800);
    assert_eq!(p.get_allowance(&pid, &xlm), 200);
    assert_eq!(p.get_allowance(&pid, &usdc), 5000);

    // Check_transfer respects per-asset limits.
    let recip = Address::generate(&env);
    assert!(p.try_check_transfer(&pid, &xlm, &recip, &200).is_ok());
    assert!(
        p.try_check_transfer(&pid, &xlm, &recip, &201).unwrap_err()
            == Ok(astroid_shared::errors::Error::PolicyAllowanceExceeded)
    );
    assert!(p.try_check_transfer(&pid, &usdc, &recip, &5000).is_ok());
    assert!(
        p.try_check_transfer(&pid, &usdc, &recip, &5001)
            .unwrap_err()
            == Ok(astroid_shared::errors::Error::PolicyAllowanceExceeded)
    );
}

#[test]
fn allowance_unlimited_when_not_set() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let pid = String::from_str(&env, "max_txn");
    // No allowance set => check succeeds even for large amount (unless max_amount gate)
    assert!(p.try_check_allowance(&pid, &asset, &1_000_000).is_ok());
    // check_transfer also succeeds within max_amount, despite no allowance entry.
    assert!(p
        .try_check_transfer(&pid, &asset, &Address::generate(&env), &500_000)
        .is_ok());
}

#[test]
fn set_allowance_requires_owner_and_valid_amount() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let stranger = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let pid = String::from_str(&env, "max_txn");

    let res = p.try_set_allowance(&stranger, &pid, &asset, &1000);
    assert_eq!(res, Err(Ok(astroid_shared::errors::Error::Unauthorized)));

    let res2 = p.try_set_allowance(&owner, &pid, &asset, &-5);
    assert_eq!(res2, Err(Ok(astroid_shared::errors::Error::InvalidAmount)));

    let res3 = p.try_update_allowance(&stranger, &pid, &asset, &100);
    assert_eq!(res3, Err(Ok(astroid_shared::errors::Error::Unauthorized)));
}

#[test]
fn check_transfer_without_allowance_still_enforces_max() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let pid = String::from_str(&env, "max_txn");
    // max_amount is 1_000_000, so even with no allowance, max gate still applies.
    assert!(p
        .try_check_transfer(&pid, &asset, &Address::generate(&env), &1_000_001)
        .is_err());
}

#[test]
fn allowance_checked_math_no_overflow_panic() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let pid = String::from_str(&env, "max_txn");
    p.set_allowance(&owner, &pid, &asset, &500);
    // Consuming exactly 500 then trying to consume more should be clean error, not panic.
    p.update_allowance(&owner, &pid, &asset, &500);
    assert_eq!(p.get_allowance(&pid, &asset), 0);
    let err = p
        .try_update_allowance(&owner, &pid, &asset, &1)
        .unwrap_err();
    assert_eq!(
        err,
        Ok(astroid_shared::errors::Error::PolicyAllowanceExceeded)
    );
}
