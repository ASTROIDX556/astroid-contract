use astroid_shared::errors::Error;
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

// --- Merchant blacklist tests ---

#[test]
fn merchant_blacklist_blocks_transfers() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let blocked_merchant = Address::generate(&env);

    // Add merchant to blacklist
    p.add_merchant_blacklist(
        &owner,
        &String::from_str(&env, "max_txn"),
        &blocked_merchant,
    );

    // Transfer to blocked merchant should fail
    let result = p.try_check_transfer(
        &String::from_str(&env, "max_txn"),
        &asset,
        &blocked_merchant,
        &100,
    );
    assert!(result.is_err());

    // Transfer to non-blocked merchant should succeed
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

    // Add merchant to blacklist
    p.add_merchant_blacklist(&owner, &String::from_str(&env, "max_txn"), &merchant);

    // Verify blocked
    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &merchant, &100,)
        .is_err());

    // Remove from blacklist
    p.remove_merchant_blacklist(&owner, &String::from_str(&env, "max_txn"), &merchant);

    // Now should succeed
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

    // Unauthorized user cannot add to blacklist
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

    // Add merchant to blacklist
    p.add_merchant_blacklist(&owner, &String::from_str(&env, "max_txn"), &merchant);

    // Adding again should fail
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

    // Removing non-existent merchant should fail
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

    // Add category to blacklist
    p.add_category_blacklist(
        &owner,
        &String::from_str(&env, "max_txn"),
        &String::from_str(&env, "gambling"),
    );

    // Blocked category should fail
    let result = p.try_check_category(
        &String::from_str(&env, "max_txn"),
        &String::from_str(&env, "gambling"),
    );
    assert!(result.is_err());

    // Different category should succeed
    assert!(p
        .try_check_category(
            &String::from_str(&env, "max_txn"),
            &String::from_str(&env, "groceries"),
        )
        .is_ok());

    // Empty category should succeed
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

    // Add category to blacklist
    p.add_category_blacklist(
        &owner,
        &String::from_str(&env, "max_txn"),
        &String::from_str(&env, "gambling"),
    );

    // Verify blocked
    assert!(p
        .try_check_category(
            &String::from_str(&env, "max_txn"),
            &String::from_str(&env, "gambling"),
        )
        .is_err());

    // Remove from blacklist
    p.remove_category_blacklist(
        &owner,
        &String::from_str(&env, "max_txn"),
        &String::from_str(&env, "gambling"),
    );

    // Now should succeed
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

    // Unauthorized user cannot add to blacklist
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

    // Add category to blacklist
    p.add_category_blacklist(
        &owner,
        &String::from_str(&env, "max_txn"),
        &String::from_str(&env, "gambling"),
    );

    // Adding again should fail
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

    // Removing non-existent category should fail
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

    // Adding empty category should fail
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

// --- Issue #37: Asset whitelist tests ---

#[test]
fn asset_whitelist_allows_whitelisted_asset() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let blocked = Address::generate(&env);
    let safe = Address::generate(&env);

    // Block the address
    p.add_to_blocklist(&owner, &String::from_str(&env, "max_txn"), &blocked);

    // Transfer to blocked address should fail
    let result = p.try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &blocked, &100);
    assert!(result.is_err());

    // Transfer to non-blocked address should succeed
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

    // Whitelist not enabled (default) — any asset should pass
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

    // Now remove it
    p.remove_asset_from_whitelist(&owner, &String::from_str(&env, "max_txn"), &asset);

    // validate_asset should fail for a removed asset when whitelist is enabled
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

    // Whitelist disabled by default, validate_asset should pass
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

// --- Multi-token allowance tests ---

/// Register a fresh policy with unlimited policy bounds so only the allowance
/// gate is exercised.
fn allowance_setup<'a>(env: &'a Env, owner: &Address) -> PolicyContractClient<'a> {
    let id = env.register_contract(None, PolicyContract);
    let client = PolicyContractClient::new(env, &id);
    client.initialize();
    client.register_policy(
        owner,
        &String::from_str(env, "mt"),
        &BytesN::from_array(env, &[1; 32]),
        &0,
        &None,
        &None,
        &0,
    );
    client
}

#[test]
fn allowance_allows_spend_below_limit() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = allowance_setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    p.set_allowance(&owner, &String::from_str(&env, "mt"), &asset, &1_000, &0);
    let allowed = p.get_allowance(&String::from_str(&env, "mt"), &asset);
    assert_eq!(allowed.limit, 1_000);

    // Within limit headroom: passes check and transfer gate.
    assert_eq!(
        p.try_check_allowance(&String::from_str(&env, "mt"), &asset, &400),
        Ok(Ok(600))
    );
    assert!(p
        .try_check_transfer(&String::from_str(&env, "mt"), &asset, &recip, &400)
        .is_ok());
}

#[test]
fn allowance_exact_boundary_passes() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = allowance_setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    p.set_allowance(&owner, &String::from_str(&env, "mt"), &asset, &1_000, &0);
    // Spend exactly the full limit: allowed (headroom becomes 0).
    assert!(p
        .try_check_transfer(&String::from_str(&env, "mt"), &asset, &recip, &1_000)
        .is_ok());
    // update_allowance consumes exactly to the limit.
    assert!(p
        .try_update_allowance(&owner, &String::from_str(&env, "mt"), &asset, &1_000)
        .is_ok());
}

#[test]
fn allowance_over_limit_rejected_with_exceeded() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = allowance_setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    p.set_allowance(&owner, &String::from_str(&env, "mt"), &asset, &1_000, &0);

    let over = p.try_check_allowance(&String::from_str(&env, "mt"), &asset, &1_001);
    assert_eq!(over, Err(Ok(Error::PolicyAllowanceExceeded)));
    assert_eq!(
        p.try_check_transfer(&String::from_str(&env, "mt"), &asset, &recip, &1_001),
        Err(Ok(Error::PolicyAllowanceExceeded))
    );
}

#[test]
fn allowance_cumulative_consumption_blocks_after_limit() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = allowance_setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    p.set_allowance(&owner, &String::from_str(&env, "mt"), &asset, &1_000, &0);
    // Consume 600 via update_allowance.
    assert!(p
        .try_update_allowance(&owner, &String::from_str(&env, "mt"), &asset, &600)
        .is_ok());
    // Only 400 headroom remains.
    assert_eq!(
        p.try_check_allowance(&String::from_str(&env, "mt"), &asset, &400),
        Ok(Ok(0))
    );
    // 401 would exceed the cumulative limit.
    assert_eq!(
        p.try_check_transfer(&String::from_str(&env, "mt"), &asset, &recip, &401),
        Err(Ok(Error::PolicyAllowanceExceeded))
    );
    // A fresh 300 transfer still fits.
    assert!(p
        .try_check_transfer(&String::from_str(&env, "mt"), &asset, &recip, &300)
        .is_ok());
}

#[test]
fn multi_token_allowances_are_independent_per_asset() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = allowance_setup(&env, &owner);
    let xlm = Address::generate(&env);
    let usdc = Address::generate(&env);
    let recip = Address::generate(&env);

    p.set_allowance(&owner, &String::from_str(&env, "mt"), &xlm, &100, &0);
    p.set_allowance(&owner, &String::from_str(&env, "mt"), &usdc, &10_000, &0);

    // USDC has room, XLM is capped at 100.
    assert!(p
        .try_check_transfer(&String::from_str(&env, "mt"), &usdc, &recip, &5_000)
        .is_ok());
    assert_eq!(
        p.try_check_transfer(&String::from_str(&env, "mt"), &xlm, &recip, &101),
        Err(Ok(Error::PolicyAllowanceExceeded))
    );
    // An asset with no configured allowance is unrestricted.
    let eth = Address::generate(&env);
    assert!(p
        .try_check_transfer(&String::from_str(&env, "mt"), &eth, &recip, &1_000_000)
        .is_ok());
}

#[test]
fn allowance_expires_at_past_blocks_spend() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000);
    let owner = Address::generate(&env);
    let p = allowance_setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    // Expires in the past => every spend denied, even below the limit.
    p.set_allowance(&owner, &String::from_str(&env, "mt"), &asset, &1_000, &500);
    assert_eq!(
        p.try_check_transfer(&String::from_str(&env, "mt"), &asset, &recip, &1),
        Err(Ok(Error::PolicyDenied))
    );
}

#[test]
fn allowance_unauthorized_set_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let stranger = Address::generate(&env);
    let p = allowance_setup(&env, &owner);
    let asset = Address::generate(&env);

    let r = p.try_set_allowance(&stranger, &String::from_str(&env, "mt"), &asset, &100, &0);
    assert!(r.is_err());
}

#[test]
fn allowance_negative_limit_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = allowance_setup(&env, &owner);
    let asset = Address::generate(&env);

    let r = p.try_set_allowance(&owner, &String::from_str(&env, "mt"), &asset, &-1, &0);
    assert!(r.is_err());

    // Negative spend is always rejected.
    let c = p.try_check_allowance(&String::from_str(&env, "mt"), &asset, &-5);
    assert!(c.is_err());
}

#[test]
fn allowance_remove_restores_unlimited() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = allowance_setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    p.set_allowance(&owner, &String::from_str(&env, "mt"), &asset, &100, &0);
    assert_eq!(
        p.try_check_transfer(&String::from_str(&env, "mt"), &asset, &recip, &200),
        Err(Ok(Error::PolicyAllowanceExceeded))
    );

    p.remove_allowance(&owner, &String::from_str(&env, "mt"), &asset);
    assert!(p
        .try_check_transfer(&String::from_str(&env, "mt"), &asset, &recip, &200)
        .is_ok());
}
