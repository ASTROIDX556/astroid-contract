use core::borrow::Borrow;
use soroban_sdk::{
    testutils::Address as _, testutils::Events, Address, BytesN, Env, IntoVal, String, Symbol, Val,
};

use crate::{PolicyContract, PolicyContractClient, PolicyRule, RuleMatch, RuleTarget};

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

/// Assert that a `try_*` result is an `Err` matching `Error::RuleDenied`.
fn assert_rule_denied(
    result: &Result<
        Result<(), soroban_sdk::ConversionError>,
        Result<astroid_shared::errors::Error, soroban_sdk::InvokeError>,
    >,
) {
    match result {
        Err(Ok(astroid_shared::errors::Error::RuleDenied)) => {}
        other => panic!("expected RuleDenied, got {:?}", other),
    }
}

// ── Existing behaviour (no rules) ──────────────────────────────────────

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

// ── Exact destination allowlist ────────────────────────────────────────

#[test]
fn exact_destination_allowlist_match() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let allowed = Address::generate(&env);

    p.add_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "allow_v1"),
            rule_match: RuleMatch::Allow,
            target: RuleTarget::Destination,
            value: allowed.to_string(),
        },
    );

    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &allowed, &100,)
        .is_ok());
}

#[test]
fn exact_destination_allowlist_no_match_falls_through() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let allowed = Address::generate(&env);
    let other = Address::generate(&env);

    p.add_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "allow_v1"),
            rule_match: RuleMatch::Allow,
            target: RuleTarget::Destination,
            value: allowed.to_string(),
        },
    );

    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &other, &100,)
        .is_ok());
}

// ── Exact destination denylist ─────────────────────────────────────────

#[test]
fn exact_destination_denylist_match() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let denied = Address::generate(&env);

    p.add_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "deny_v1"),
            rule_match: RuleMatch::Deny,
            target: RuleTarget::Destination,
            value: denied.to_string(),
        },
    );

    let r = p.try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &denied, &100);
    assert!(r.is_err());
    assert_rule_denied(&r);
}

#[test]
fn exact_destination_denylist_non_matching_passes() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let denied = Address::generate(&env);
    let other = Address::generate(&env);

    p.add_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "deny_v1"),
            rule_match: RuleMatch::Deny,
            target: RuleTarget::Destination,
            value: denied.to_string(),
        },
    );

    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &other, &100,)
        .is_ok());
}

// ── Wildcard destination matching ──────────────────────────────────────

#[test]
fn wildcard_destination_deny_matches_prefix() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let target_addr = Address::generate(&env);

    // Build a wildcard pattern from the first 4 chars of the address string.
    let addr_str = target_addr.to_string();
    let addr_len = addr_str.len() as usize;
    let mut addr_buf = [0u8; 128];
    addr_str.copy_into_slice(&mut addr_buf[..addr_len]);
    let prefix_len = 4.min(addr_len);
    let mut pat_bytes = soroban_sdk::Bytes::new(&env);
    for &b in addr_buf.iter().take(prefix_len) {
        pat_bytes.push_back(b);
    }
    pat_bytes.push_back(b'*');
    let pat_buf = pat_bytes.to_buffer::<128>();
    let pattern = String::from_bytes(&env, pat_buf.borrow());

    p.add_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "wild_deny"),
            rule_match: RuleMatch::Deny,
            target: RuleTarget::Destination,
            value: pattern,
        },
    );

    let r = p.try_check_transfer(
        &String::from_str(&env, "max_txn"),
        &asset,
        &target_addr,
        &100,
    );
    assert!(r.is_err());
}

#[test]
fn wildcard_destination_deny_does_not_match_unrelated() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let unrelated = Address::generate(&env);

    let pattern = String::from_str(&env, "ZZZZZ*");

    p.add_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "wild_deny"),
            rule_match: RuleMatch::Deny,
            target: RuleTarget::Destination,
            value: pattern,
        },
    );

    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &unrelated, &100,)
        .is_ok());
}

#[test]
fn wildcard_destination_allow_matches_prefix() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let allowed = Address::generate(&env);

    let addr_str = allowed.to_string();
    let addr_len = addr_str.len() as usize;
    let mut addr_buf = [0u8; 128];
    addr_str.copy_into_slice(&mut addr_buf[..addr_len]);
    let prefix_len = 4.min(addr_len);
    let mut pat_bytes = soroban_sdk::Bytes::new(&env);
    for &b in addr_buf.iter().take(prefix_len) {
        pat_bytes.push_back(b);
    }
    pat_bytes.push_back(b'*');
    let pat_buf = pat_bytes.to_buffer::<128>();
    let pattern = String::from_bytes(&env, pat_buf.borrow());

    p.add_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "wild_allow"),
            rule_match: RuleMatch::Allow,
            target: RuleTarget::Destination,
            value: pattern,
        },
    );

    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &allowed, &100,)
        .is_ok());
}

// ── Multiple rule configurations ───────────────────────────────────────

#[test]
fn first_matching_rule_wins() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let addr = Address::generate(&env);
    let addr_str = addr.to_string();

    p.add_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "deny_first"),
            rule_match: RuleMatch::Deny,
            target: RuleTarget::Destination,
            value: addr_str.clone(),
        },
    );
    p.add_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "allow_second"),
            rule_match: RuleMatch::Allow,
            target: RuleTarget::Destination,
            value: addr_str,
        },
    );

    let r = p.try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &addr, &100);
    assert!(r.is_err());
}

#[test]
fn allow_then_deny_different_addresses() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let addr_a = Address::generate(&env);
    let addr_b = Address::generate(&env);

    p.add_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "allow_a"),
            rule_match: RuleMatch::Allow,
            target: RuleTarget::Destination,
            value: addr_a.to_string(),
        },
    );
    p.add_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "deny_b"),
            rule_match: RuleMatch::Deny,
            target: RuleTarget::Destination,
            value: addr_b.to_string(),
        },
    );

    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &addr_a, &100,)
        .is_ok());

    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &addr_b, &100,)
        .is_err());
}

// ── Asset / payload parameter matching ─────────────────────────────────

#[test]
fn exact_asset_deny_match() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    p.add_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "deny_asset"),
            rule_match: RuleMatch::Deny,
            target: RuleTarget::Asset,
            value: asset.to_string(),
        },
    );

    let r = p.try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &recip, &100);
    assert!(r.is_err());
}

#[test]
fn exact_asset_allow_match() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let allowed_asset = Address::generate(&env);
    let other_asset = Address::generate(&env);
    let recip = Address::generate(&env);

    p.add_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "allow_asset"),
            rule_match: RuleMatch::Allow,
            target: RuleTarget::Asset,
            value: allowed_asset.to_string(),
        },
    );

    assert!(p
        .try_check_transfer(
            &String::from_str(&env, "max_txn"),
            &allowed_asset,
            &recip,
            &100,
        )
        .is_ok());

    assert!(p
        .try_check_transfer(
            &String::from_str(&env, "max_txn"),
            &other_asset,
            &recip,
            &100,
        )
        .is_ok());
}

#[test]
fn mixed_destination_and_asset_rules() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let denied_recip = Address::generate(&env);
    let ok_recip = Address::generate(&env);

    p.add_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "deny_recip"),
            rule_match: RuleMatch::Deny,
            target: RuleTarget::Destination,
            value: denied_recip.to_string(),
        },
    );
    p.add_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "allow_asset"),
            rule_match: RuleMatch::Allow,
            target: RuleTarget::Asset,
            value: asset.to_string(),
        },
    );

    let r = p.try_check_transfer(
        &String::from_str(&env, "max_txn"),
        &asset,
        &denied_recip,
        &100,
    );
    assert!(r.is_err());

    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &ok_recip, &100,)
        .is_ok());
}

// ── Deterministic denial errors ────────────────────────────────────────

#[test]
fn rule_denied_returns_structured_error() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let denied = Address::generate(&env);

    p.add_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "deny_v1"),
            rule_match: RuleMatch::Deny,
            target: RuleTarget::Destination,
            value: denied.to_string(),
        },
    );

    let r = p.try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &denied, &50);
    assert!(r.is_err());
    assert_rule_denied(&r);
}

#[test]
fn rule_denied_emits_violation_event() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let denied = Address::generate(&env);

    p.add_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "deny_v1"),
            rule_match: RuleMatch::Deny,
            target: RuleTarget::Destination,
            value: denied.to_string(),
        },
    );

    let _ = p.try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &denied, &50);
    assert_event(&env, "PolicyViolation");
}

// ── No matching rule / backward compatibility ───────────────────────────

#[test]
fn empty_rule_set_preserves_existing_behaviour() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &recip, &999_999,)
        .is_ok());
    assert!(p
        .try_check_transfer(
            &String::from_str(&env, "max_txn"),
            &asset,
            &recip,
            &1_000_001,
        )
        .is_err());
}

#[test]
fn no_matching_rule_allows_transfer() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    let other = Address::generate(&env);
    p.add_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "deny_other"),
            rule_match: RuleMatch::Deny,
            target: RuleTarget::Destination,
            value: other.to_string(),
        },
    );

    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &recip, &100,)
        .is_ok());
}

// ── Rule CRUD operations ───────────────────────────────────────────────

#[test]
fn add_rule_and_retrieve() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);

    let rule = PolicyRule {
        id: String::from_str(&env, "r1"),
        rule_match: RuleMatch::Deny,
        target: RuleTarget::Destination,
        value: String::from_str(&env, "GXYZ*"),
    };
    p.add_rule(&owner, &String::from_str(&env, "max_txn"), &rule);

    let rules = p.get_rules(&String::from_str(&env, "max_txn"));
    assert_eq!(rules.len(), 1);
    assert_eq!(rules.get_unchecked(0).id, String::from_str(&env, "r1"));
}

#[test]
fn remove_rule_works() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);

    p.add_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "r1"),
            rule_match: RuleMatch::Deny,
            target: RuleTarget::Destination,
            value: String::from_str(&env, "GXYZ*"),
        },
    );
    assert_eq!(p.get_rules(&String::from_str(&env, "max_txn")).len(), 1);

    p.remove_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &String::from_str(&env, "r1"),
    );
    assert_eq!(p.get_rules(&String::from_str(&env, "max_txn")).len(), 0);
}

#[test]
fn remove_nonexistent_rule_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);

    let r = p.try_remove_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &String::from_str(&env, "nope"),
    );
    assert!(r.is_err());
}

#[test]
fn add_duplicate_rule_id_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);

    let rule = PolicyRule {
        id: String::from_str(&env, "r1"),
        rule_match: RuleMatch::Deny,
        target: RuleTarget::Destination,
        value: String::from_str(&env, "GABC*"),
    };
    p.add_rule(&owner, &String::from_str(&env, "max_txn"), &rule);

    let r = p.try_add_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "r1"),
            rule_match: RuleMatch::Allow,
            target: RuleTarget::Asset,
            value: String::from_str(&env, "GDEF*"),
        },
    );
    assert!(r.is_err());
}

#[test]
fn non_owner_cannot_add_rule() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let stranger = Address::generate(&env);

    let r = p.try_add_rule(
        &stranger,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "r1"),
            rule_match: RuleMatch::Deny,
            target: RuleTarget::Destination,
            value: String::from_str(&env, "GABC*"),
        },
    );
    assert!(r.is_err());
}

#[test]
fn non_owner_cannot_remove_rule() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let stranger = Address::generate(&env);

    p.add_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "r1"),
            rule_match: RuleMatch::Deny,
            target: RuleTarget::Destination,
            value: String::from_str(&env, "GABC*"),
        },
    );

    let r = p.try_remove_rule(
        &stranger,
        &String::from_str(&env, "max_txn"),
        &String::from_str(&env, "r1"),
    );
    assert!(r.is_err());
}

// ── Edge cases ─────────────────────────────────────────────────────────

#[test]
fn empty_pattern_matches_nothing() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    p.add_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "empty_pat"),
            rule_match: RuleMatch::Deny,
            target: RuleTarget::Destination,
            value: String::from_str(&env, ""),
        },
    );

    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &recip, &100,)
        .is_ok());
}

#[test]
fn lone_wildcard_matches_nothing() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    p.add_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "star_only"),
            rule_match: RuleMatch::Deny,
            target: RuleTarget::Destination,
            value: String::from_str(&env, "*"),
        },
    );

    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &recip, &100,)
        .is_ok());
}

#[test]
fn get_rules_returns_empty_for_unregistered_policy() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);

    let rules = p.get_rules(&String::from_str(&env, "nonexistent"));
    assert_eq!(rules.len(), 0);
}

#[test]
fn removed_rule_no_longer_affects_evaluation() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let addr = Address::generate(&env);

    p.add_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "deny_addr"),
            rule_match: RuleMatch::Deny,
            target: RuleTarget::Destination,
            value: addr.to_string(),
        },
    );

    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &addr, &100,)
        .is_err());

    p.remove_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &String::from_str(&env, "deny_addr"),
    );

    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &addr, &100,)
        .is_ok());
}

#[test]
fn rules_persist_across_multiple_transfers() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let denied = Address::generate(&env);

    p.add_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "deny_v1"),
            rule_match: RuleMatch::Deny,
            target: RuleTarget::Destination,
            value: denied.to_string(),
        },
    );

    let r1 = p.try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &denied, &10);
    let r2 = p.try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &denied, &20);
    assert!(r1.is_err());
    assert!(r2.is_err());
}

#[test]
fn scalar_gates_still_enforced_with_rules() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    p.add_rule(
        &owner,
        &String::from_str(&env, "max_txn"),
        &PolicyRule {
            id: String::from_str(&env, "allow_r"),
            rule_match: RuleMatch::Allow,
            target: RuleTarget::Destination,
            value: recip.to_string(),
        },
    );

    let r = p.try_check_transfer(
        &String::from_str(&env, "max_txn"),
        &asset,
        &recip,
        &1_000_001,
    );
    assert!(r.is_err());
}
