use soroban_sdk::{
    testutils::{Address as _, Events, Ledger},
    Address, BytesN, Env, IntoVal, String, Symbol, Val,
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
        .any(|(_contract_id, topics, _data)| topics.contains(want));
    assert!(found, "expected ContractEvent::{} to be emitted", variant);
}

fn setup<'a>(env: &Env, owner: &Address) -> PolicyContractClient<'a> {
    let id = env.register_contract(None, PolicyContract);
    let client = PolicyContractClient::new(env, &id);
    client.initialize(owner);
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
    client.initialize(&owner);
    client.register_policy(
        &owner,
        &String::from_str(&env, "vendor_list"),
        &BytesN::from_array(&env, &[7; 32]),
        &0,
        &Some(allowed.clone()),
        &None,
        &0,
    );

    assert!(client
        .try_check_transfer(&String::from_str(&env, "vendor_list"), &asset, &allowed, &1,)
        .is_ok());

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
    let _ = p.try_check_transfer(
        &String::from_str(&env, "max_txn"),
        &asset,
        &recip,
        &1_000_001,
    );
    assert_event(&env, "PolicyViolation");
}

// --- Pause tests ---

#[test]
fn pause_blocks_evaluation_and_unpause_resumes() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000);
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &recip, &1,)
        .is_ok());
    assert!(!p.paused());

    p.pause(&owner, &500);
    assert!(p.paused());
    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &recip, &1,)
        .is_err());

    env.ledger().set_timestamp(1_500);
    assert!(!p.paused());
    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &recip, &1,)
        .is_ok());
}

#[test]
fn indefinite_pause_requires_unpause() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000);
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    p.pause(&owner, &0);
    assert!(p.paused());
    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &recip, &1,)
        .is_err());

    env.ledger().set_timestamp(1_000_000);
    assert!(p.paused());

    p.unpause(&owner);
    assert!(!p.paused());
    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &recip, &1,)
        .is_ok());
}

#[test]
fn pause_duration_cap_enforced() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let res = p.try_pause(&owner, &(2_592_000 + 1));
    assert!(res.is_err());
    assert!(!p.paused());
}

#[test]
fn only_admin_can_pause() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let intruder = Address::generate(&env);
    let p = setup(&env, &owner);
    let res = p.try_pause(&intruder, &100);
    assert!(res.is_err());
    assert!(!p.paused());
}

// --- Merchant blacklist tests ---

#[test]
fn merchant_blacklist_blocks_transfers() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let blocked_merchant = Address::generate(&env);

    p.add_merchant_blacklist(
        &owner,
        &String::from_str(&env, "max_txn"),
        &blocked_merchant,
    );

    let result = p.try_check_transfer(
        &String::from_str(&env, "max_txn"),
        &asset,
        &blocked_merchant,
        &100,
    );
    assert!(result.is_err());

    let safe_merchant = Address::generate(&env);
    assert!(p
        .try_check_transfer(
            &String::from_str(&env, "max_txn"),
            &asset,
            &safe_merchant,
            &100,
        )
        .is_ok());
}

#[test]
fn merchant_blacklist_removal_allows_transfers() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let merchant = Address::generate(&env);

    p.add_merchant_blacklist(&owner, &String::from_str(&env, "max_txn"), &merchant);
    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &merchant, &100,)
        .is_err());

    p.remove_merchant_blacklist(&owner, &String::from_str(&env, "max_txn"), &merchant);
    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &merchant, &100,)
        .is_ok());
}

#[test]
fn merchant_blacklist_unauthorized_add_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let unauthorized = Address::generate(&env);
    let p = setup(&env, &owner);
    let merchant = Address::generate(&env);

    let result =
        p.try_add_merchant_blacklist(&unauthorized, &String::from_str(&env, "max_txn"), &merchant);
    assert!(result.is_err());
}

#[test]
fn merchant_blacklist_duplicate_add_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let merchant = Address::generate(&env);

    p.add_merchant_blacklist(&owner, &String::from_str(&env, "max_txn"), &merchant);
    let result =
        p.try_add_merchant_blacklist(&owner, &String::from_str(&env, "max_txn"), &merchant);
    assert!(result.is_err());
}

#[test]
fn merchant_blacklist_nonexistent_remove_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let merchant = Address::generate(&env);

    let result =
        p.try_remove_merchant_blacklist(&owner, &String::from_str(&env, "max_txn"), &merchant);
    assert!(result.is_err());
}

#[test]
fn merchant_blocked_event_emitted() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let blocked_merchant = Address::generate(&env);

    p.add_merchant_blacklist(
        &owner,
        &String::from_str(&env, "max_txn"),
        &blocked_merchant,
    );

    let _ = p.try_check_transfer(
        &String::from_str(&env, "max_txn"),
        &asset,
        &blocked_merchant,
        &100,
    );
    assert_event(&env, "PolicyViolation");
}

// --- Category blacklist tests ---

#[test]
fn category_blacklist_blocks_categories() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);

    p.add_category_blacklist(
        &owner,
        &String::from_str(&env, "max_txn"),
        &String::from_str(&env, "gambling"),
    );

    let result = p.try_check_category(
        &String::from_str(&env, "max_txn"),
        &String::from_str(&env, "gambling"),
    );
    assert!(result.is_err());

    assert!(p
        .try_check_category(
            &String::from_str(&env, "max_txn"),
            &String::from_str(&env, "groceries"),
        )
        .is_ok());

    assert!(p
        .try_check_category(
            &String::from_str(&env, "max_txn"),
            &String::from_str(&env, ""),
        )
        .is_ok());
}

#[test]
fn category_blacklist_removal_allows_categories() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);

    p.add_category_blacklist(
        &owner,
        &String::from_str(&env, "max_txn"),
        &String::from_str(&env, "gambling"),
    );
    assert!(p
        .try_check_category(
            &String::from_str(&env, "max_txn"),
            &String::from_str(&env, "gambling"),
        )
        .is_err());

    p.remove_category_blacklist(
        &owner,
        &String::from_str(&env, "max_txn"),
        &String::from_str(&env, "gambling"),
    );
    assert!(p
        .try_check_category(
            &String::from_str(&env, "max_txn"),
            &String::from_str(&env, "gambling"),
        )
        .is_ok());
}

#[test]
fn category_blacklist_unauthorized_add_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let unauthorized = Address::generate(&env);
    let p = setup(&env, &owner);

    let result = p.try_add_category_blacklist(
        &unauthorized,
        &String::from_str(&env, "max_txn"),
        &String::from_str(&env, "gambling"),
    );
    assert!(result.is_err());
}

#[test]
fn category_blacklist_duplicate_add_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);

    p.add_category_blacklist(
        &owner,
        &String::from_str(&env, "max_txn"),
        &String::from_str(&env, "gambling"),
    );
    let result = p.try_add_category_blacklist(
        &owner,
        &String::from_str(&env, "max_txn"),
        &String::from_str(&env, "gambling"),
    );
    assert!(result.is_err());
}

#[test]
fn category_blacklist_nonexistent_remove_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);

    let result = p.try_remove_category_blacklist(
        &owner,
        &String::from_str(&env, "max_txn"),
        &String::from_str(&env, "gambling"),
    );
    assert!(result.is_err());
}

#[test]
fn category_blacklist_empty_category_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);

    let result = p.try_add_category_blacklist(
        &owner,
        &String::from_str(&env, "max_txn"),
        &String::from_str(&env, ""),
    );
    assert!(result.is_err());
}

#[test]
fn category_restricted_event_emitted() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);

    p.add_category_blacklist(
        &owner,
        &String::from_str(&env, "max_txn"),
        &String::from_str(&env, "gambling"),
    );

    let _ = p.try_check_category(
        &String::from_str(&env, "max_txn"),
        &String::from_str(&env, "gambling"),
    );
    assert_event(&env, "PolicyViolation");
}

// --- Blocklist tests ---

#[test]
fn blocklist_blocks_transfers() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let blocked = Address::generate(&env);
    let safe = Address::generate(&env);

    p.add_to_blocklist(&owner, &String::from_str(&env, "max_txn"), &blocked);

    let result = p.try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &blocked, &100);
    assert!(result.is_err());

    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &safe, &100,)
        .is_ok());
}

#[test]
fn blocklist_removal_allows_transfers() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    p.add_to_blocklist(&owner, &String::from_str(&env, "max_txn"), &recip);
    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &recip, &100,)
        .is_err());

    p.remove_from_blocklist(&owner, &String::from_str(&env, "max_txn"), &recip);
    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &recip, &100,)
        .is_ok());
}

#[test]
fn blocklist_unauthorized_add_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let unauthorized = Address::generate(&env);
    let p = setup(&env, &owner);
    let addr = Address::generate(&env);

    let result = p.try_add_to_blocklist(&unauthorized, &String::from_str(&env, "max_txn"), &addr);
    assert!(result.is_err());
}

#[test]
fn blocklist_duplicate_add_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let addr = Address::generate(&env);

    p.add_to_blocklist(&owner, &String::from_str(&env, "max_txn"), &addr);
    let result = p.try_add_to_blocklist(&owner, &String::from_str(&env, "max_txn"), &addr);
    assert!(result.is_err());
}

#[test]
fn blocklist_nonexistent_remove_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let addr = Address::generate(&env);

    let result = p.try_remove_from_blocklist(&owner, &String::from_str(&env, "max_txn"), &addr);
    assert!(result.is_err());
}

#[test]
fn blocklist_violation_event_emitted() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let blocked = Address::generate(&env);

    p.add_to_blocklist(&owner, &String::from_str(&env, "max_txn"), &blocked);

    let _ = p.try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &blocked, &100);
    assert_event(&env, "PolicyViolation");
}

// --- Asset whitelist tests ---

#[test]
fn asset_whitelist_allows_whitelisted_asset() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);

    p.set_asset_whitelist_enabled(&owner, &String::from_str(&env, "max_txn"), &true);
    p.add_asset_to_whitelist(&owner, &String::from_str(&env, "max_txn"), &asset);

    let recip = Address::generate(&env);
    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &recip, &100,)
        .is_ok());
}

#[test]
fn asset_whitelist_add_remove_roundtrip() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);

    p.set_asset_whitelist_enabled(&owner, &String::from_str(&env, "max_txn"), &true);
    p.add_asset_to_whitelist(&owner, &String::from_str(&env, "max_txn"), &asset);

    p.remove_asset_from_whitelist(&owner, &String::from_str(&env, "max_txn"), &asset);

    assert!(p
        .try_validate_asset(&String::from_str(&env, "max_txn"), &asset)
        .is_err());
}

#[test]
fn asset_whitelist_unauthorized_add_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let unauthorized = Address::generate(&env);
    let p = setup(&env, &owner);
    let addr = Address::generate(&env);

    let result = p.try_add_to_blocklist(&unauthorized, &String::from_str(&env, "max_txn"), &addr);
    assert!(result.is_err());
}

#[test]
fn asset_whitelist_duplicate_add_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);

    p.add_asset_to_whitelist(&owner, &String::from_str(&env, "max_txn"), &asset);

    let result = p.try_add_asset_to_whitelist(&owner, &String::from_str(&env, "max_txn"), &asset);
    assert!(result.is_err());
}

#[test]
fn asset_whitelist_nonexistent_remove_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);

    let result =
        p.try_remove_asset_from_whitelist(&owner, &String::from_str(&env, "max_txn"), &asset);
    assert!(result.is_err());
}

#[test]
fn asset_whitelist_empty_default_passes_validate() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);

    assert!(p
        .try_validate_asset(&String::from_str(&env, "max_txn"), &asset)
        .is_ok());
}

#[test]
fn asset_whitelist_violation_event_emitted() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    p.set_asset_whitelist_enabled(&owner, &String::from_str(&env, "max_txn"), &true);

    let _ = p.try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &recip, &100);
    assert_event(&env, "PolicyViolation");
}

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
    // Over limit fails with the deterministic policy-denial code.
    let err = p.try_check_allowance(&pid, &asset, &1001).unwrap_err();
    assert_eq!(err, Ok(astroid_shared::errors::Error::PolicyDenied));
    let err2 = p
        .try_check_transfer(&pid, &asset, &Address::generate(&env), &1001)
        .unwrap_err();
    assert_eq!(err2, Ok(astroid_shared::errors::Error::PolicyDenied));
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

    // Further consume beyond zero fails cleanly.
    let err = p
        .try_update_allowance(&owner, &pid, &asset, &1)
        .unwrap_err();
    assert_eq!(err, Ok(astroid_shared::errors::Error::PolicyDenied));
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
            == Ok(astroid_shared::errors::Error::PolicyDenied)
    );
    assert!(p.try_check_transfer(&pid, &usdc, &recip, &5000).is_ok());
    assert!(
        p.try_check_transfer(&pid, &usdc, &recip, &5001)
            .unwrap_err()
            == Ok(astroid_shared::errors::Error::PolicyDenied)
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
    // No allowance set => check succeeds even for large amount (unless max_amount gate).
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
    // Consuming exactly 500 then trying to consume more is a clean error, not a panic.
    p.update_allowance(&owner, &pid, &asset, &500);
    assert_eq!(p.get_allowance(&pid, &asset), 0);
    let err = p
        .try_update_allowance(&owner, &pid, &asset, &1)
        .unwrap_err();
    assert_eq!(err, Ok(astroid_shared::errors::Error::PolicyDenied));
}
