use astroid_interfaces::PolicyClient;
use astroid_policy::{
    PolicyCombinationStrategy, PolicyContract, PolicyContractClient, PolicyDecision,
    PolicyDenialReason, RuleNode, RuleOp, RuleTree, TransactionPayload,
};
use astroid_shared::errors::Error;
use soroban_sdk::{
    testutils::{Address as _, Events, Ledger},
    vec, Address, BytesN, Env, IntoVal, String, Symbol, TryFromVal, Val, Vec,
};

const POLICY_ID: &str = "composition";

fn policy_id(env: &Env) -> String {
    String::from_str(env, POLICY_ID)
}

fn setup<'a>(
    env: &'a Env,
    owner: &Address,
    max_amount: i128,
    strategy: Option<PolicyCombinationStrategy>,
) -> (PolicyContractClient<'a>, PolicyClient<'a>) {
    setup_with_expiry(env, owner, max_amount, strategy, 0)
}

fn setup_with_expiry<'a>(
    env: &'a Env,
    owner: &Address,
    max_amount: i128,
    strategy: Option<PolicyCombinationStrategy>,
    expires_at: u64,
) -> (PolicyContractClient<'a>, PolicyClient<'a>) {
    let address = env.register_contract(None, PolicyContract);
    let managed = PolicyContractClient::new(env, &address);
    managed.initialize();
    managed.register_policy(
        owner,
        &policy_id(env),
        &BytesN::from_array(env, &[31; 32]),
        &max_amount,
        &None,
        &None,
        &expires_at,
        &strategy,
    );
    (managed, PolicyClient::new(env, &address))
}

fn transaction(asset: &Address, recipient: &Address, amount: i128) -> TransactionPayload {
    TransactionPayload {
        asset: asset.clone(),
        recipient: recipient.clone(),
        amount,
    }
}

fn decision(
    managed: &PolicyContractClient<'_>,
    env: &Env,
    asset: &Address,
    recipient: &Address,
    amount: i128,
) -> PolicyDecision {
    managed.evaluate_policy(&policy_id(env), &transaction(asset, recipient, amount))
}

fn assert_violation(env: &Env, reason: &str) {
    let violation: Val = Symbol::new(env, "violation").into_val(env);
    let expected: Val = Symbol::new(env, reason).into_val(env);
    assert!(
        env.events().all().iter().any(|(_, topics, data)| {
            topics.contains(violation)
                && Vec::<Val>::try_from_val(env, &data)
                    .map(|payload| payload.contains(expected))
                    .unwrap_or(false)
        }),
        "expected a PolicyViolation event naming {reason}"
    );
}

fn leaf(op: RuleOp, value_i128: i128, value_address: Address) -> RuleNode {
    RuleNode {
        op,
        value_i128,
        value_address,
        children_start: 0,
        children_end: 0,
    }
}

fn amount_rule(env: &Env, max: i128) -> RuleTree {
    let mut tree = soroban_sdk::Vec::new(env);
    tree.push_back(leaf(RuleOp::MaxAmount, max, Address::generate(env)));
    tree
}

fn recipient_rule(env: &Env, recipient: &Address) -> RuleTree {
    let mut tree = soroban_sdk::Vec::new(env);
    tree.push_back(leaf(RuleOp::AllowedRecipient, 0, recipient.clone()));
    tree
}

fn asset_rule(env: &Env, asset: &Address) -> RuleTree {
    let mut tree = soroban_sdk::Vec::new(env);
    tree.push_back(leaf(RuleOp::AllowedAsset, 0, asset.clone()));
    tree
}

fn not_blacklisted_rule(env: &Env) -> RuleTree {
    let mut tree = soroban_sdk::Vec::new(env);
    tree.push_back(RuleNode {
        op: RuleOp::Not,
        value_i128: 0,
        value_address: Address::generate(env),
        children_start: 1,
        children_end: 2,
    });
    tree.push_back(leaf(
        RuleOp::RecipientBlacklisted,
        0,
        Address::generate(env),
    ));
    tree
}

fn branch(env: &Env, op: RuleOp, children: soroban_sdk::Vec<RuleNode>) -> RuleTree {
    let mut tree = soroban_sdk::Vec::new(env);
    let end = 1 + children.len();
    tree.push_back(RuleNode {
        op,
        value_i128: 0,
        value_address: Address::generate(env),
        children_start: 1,
        children_end: end,
    });
    for child in children.iter() {
        tree.push_back(child);
    }
    tree
}

fn deep_chain_tree(env: &Env) -> RuleTree {
    let mut tree = soroban_sdk::Vec::new(env);
    for i in 0..15u32 {
        tree.push_back(RuleNode {
            op: RuleOp::Not,
            value_i128: 0,
            value_address: Address::generate(env),
            children_start: i + 1,
            children_end: i + 2,
        });
    }
    tree.push_back(leaf(RuleOp::MaxAmount, i128::MAX, Address::generate(env)));
    tree
}

#[test]
fn allowlist_and_ceiling_authorize_only_the_intersection() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let (managed, iface) = setup(&env, &owner, 500, None);
    let asset = Address::generate(&env);
    let vendor = Address::generate(&env);
    let stranger = Address::generate(&env);

    managed.set_recipient_whitelist_enabled(&owner, &policy_id(&env), &true);
    managed.add_recipient_to_whitelist(&owner, &policy_id(&env), &vendor);

    assert_eq!(
        iface.try_check_transfer(&policy_id(&env), &asset, &vendor, &500),
        Ok(Ok(()))
    );
    assert_eq!(
        iface.try_check_transfer(&policy_id(&env), &asset, &vendor, &501),
        Err(Ok(Error::PolicyConstraintUnmet))
    );
    assert_eq!(
        iface.try_check_transfer(&policy_id(&env), &asset, &stranger, &100),
        Err(Ok(Error::PolicyDenied))
    );
    assert_violation(&env, "above_max");
    assert_violation(&env, "not_whitelisted");
}

#[test]
fn granular_decisions_name_the_first_gate_that_refused() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let (managed, _iface) = setup(&env, &owner, 500, None);
    let asset = Address::generate(&env);
    let vendor = Address::generate(&env);
    let stranger = Address::generate(&env);

    managed.set_recipient_whitelist_enabled(&owner, &policy_id(&env), &true);
    managed.add_recipient_to_whitelist(&owner, &policy_id(&env), &vendor);

    let allowed = decision(&managed, &env, &asset, &vendor, 500);
    assert!(allowed.allowed());
    assert_eq!(allowed.reason(), None);
    assert_eq!(allowed.max_transaction_amount, 500);

    let over = decision(&managed, &env, &asset, &vendor, 501);
    assert_eq!(
        over.reason(),
        Some(PolicyDenialReason::AboveMaxTransactionLimit)
    );

    let unlisted = decision(&managed, &env, &asset, &stranger, 100);
    assert_eq!(
        unlisted.reason(),
        Some(PolicyDenialReason::RecipientNotWhitelisted)
    );
}

#[test]
fn enabled_allowlist_with_no_entries_fails_closed_before_the_ceiling() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let (managed, iface) = setup(&env, &owner, 1_000, None);
    let asset = Address::generate(&env);
    let recipient = Address::generate(&env);

    managed.set_recipient_whitelist_enabled(&owner, &policy_id(&env), &true);
    assert_eq!(
        iface.try_check_transfer(&policy_id(&env), &asset, &recipient, &10_000),
        Err(Ok(Error::PolicyDenied))
    );
    assert_eq!(
        decision(&managed, &env, &asset, &recipient, 1).reason(),
        Some(PolicyDenialReason::RecipientNotWhitelisted)
    );

    managed.set_recipient_whitelist_enabled(&owner, &policy_id(&env), &false);
    assert_eq!(
        iface.try_check_transfer(&policy_id(&env), &asset, &recipient, &100),
        Ok(Ok(()))
    );
}

#[test]
fn asset_allowlist_scalar_ceiling_and_rule_ceiling_compose() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let (managed, iface) = setup(&env, &owner, 400, None);
    let asset = Address::generate(&env);
    let other_asset = Address::generate(&env);
    let recipient = Address::generate(&env);

    managed.set_asset_whitelist_enabled(&owner, &policy_id(&env), &true);
    managed.add_asset_to_whitelist(&owner, &policy_id(&env), &asset);
    managed.add_policy_rule(&owner, &policy_id(&env), &asset_rule(&env, &asset));
    managed.add_policy_rule(&owner, &policy_id(&env), &amount_rule(&env, 300));

    assert_eq!(
        iface.try_check_transfer(&policy_id(&env), &asset, &recipient, &300),
        Ok(Ok(()))
    );
    assert_eq!(
        iface.try_check_transfer(&policy_id(&env), &asset, &recipient, &350),
        Err(Ok(Error::PolicyDenied))
    );
    assert_eq!(
        decision(&managed, &env, &asset, &recipient, 350).reason(),
        Some(PolicyDenialReason::RuleStackDenied)
    );
    assert_eq!(
        iface.try_check_transfer(&policy_id(&env), &other_asset, &recipient, &10),
        Err(Ok(Error::AssetNotAuthorized))
    );
    assert_eq!(
        decision(&managed, &env, &other_asset, &recipient, 10).reason(),
        Some(PolicyDenialReason::AssetNotWhitelisted)
    );
}

#[test]
fn asset_denylist_overrides_asset_allowlist_and_amount_rules() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let (managed, iface) = setup(&env, &owner, 0, None);
    let asset = Address::generate(&env);
    let recipient = Address::generate(&env);

    managed.set_asset_whitelist_enabled(&owner, &policy_id(&env), &true);
    managed.add_asset_to_whitelist(&owner, &policy_id(&env), &asset);
    managed.add_policy_rule(&owner, &policy_id(&env), &amount_rule(&env, 1_000_000));
    assert_eq!(
        iface.try_check_transfer(&policy_id(&env), &asset, &recipient, &1_000),
        Ok(Ok(()))
    );

    managed.add_asset_blacklist(&owner, &policy_id(&env), &asset);
    assert_eq!(
        iface.try_check_transfer(&policy_id(&env), &asset, &recipient, &1),
        Err(Ok(Error::PolicyDenied))
    );
    assert_eq!(
        decision(&managed, &env, &asset, &recipient, 1).reason(),
        Some(PolicyDenialReason::AssetBlacklisted)
    );
    assert_violation(&env, "asset_blacklisted");

    managed.remove_asset_blacklist(&owner, &policy_id(&env), &asset);
    assert_eq!(
        iface.try_check_transfer(&policy_id(&env), &asset, &recipient, &1_000),
        Ok(Ok(()))
    );
}

#[test]
fn recipient_denylist_beats_recipient_allowlist_with_a_dedicated_error() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let (managed, iface) = setup(&env, &owner, 1_000, None);
    let asset = Address::generate(&env);
    let vendor = Address::generate(&env);

    managed.set_recipient_whitelist_enabled(&owner, &policy_id(&env), &true);
    managed.add_recipient_to_whitelist(&owner, &policy_id(&env), &vendor);
    managed.add_policy_rule(&owner, &policy_id(&env), &recipient_rule(&env, &vendor));
    assert_eq!(
        iface.try_check_transfer(&policy_id(&env), &asset, &vendor, &100),
        Ok(Ok(()))
    );

    managed.add_blacklist(&owner, &policy_id(&env), &vendor);
    assert_eq!(
        iface.try_check_transfer(&policy_id(&env), &asset, &vendor, &100),
        Err(Ok(Error::PolicyRecipientRestricted))
    );
    assert_eq!(
        decision(&managed, &env, &asset, &vendor, 100).reason(),
        Some(PolicyDenialReason::RecipientBlacklisted)
    );
    assert_violation(&env, "blacklisted");
}

#[test]
fn merchant_denylist_short_circuits_before_ceiling_allowlist_and_rules() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let (managed, iface) = setup(&env, &owner, 1, None);
    let asset = Address::generate(&env);
    let merchant = Address::generate(&env);

    managed.set_recipient_whitelist_enabled(&owner, &policy_id(&env), &true);
    managed.add_recipient_to_whitelist(&owner, &policy_id(&env), &merchant);
    managed.add_policy_rule(&owner, &policy_id(&env), &amount_rule(&env, 1));
    managed.add_merchant_blacklist(&owner, &policy_id(&env), &merchant);

    assert_eq!(
        iface.try_check_transfer(&policy_id(&env), &asset, &merchant, &1_000_000),
        Err(Ok(Error::PolicyMerchantBlocked))
    );
    assert_eq!(
        decision(&managed, &env, &asset, &merchant, 1_000_000).reason(),
        Some(PolicyDenialReason::MerchantBlacklisted)
    );
    assert_violation(&env, "merchant_blocked");
}

#[test]
fn recipient_denylist_precedes_merchant_denylist_for_one_address() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let (managed, iface) = setup(&env, &owner, 0, None);
    let asset = Address::generate(&env);
    let address = Address::generate(&env);

    managed.add_merchant_blacklist(&owner, &policy_id(&env), &address);
    managed.add_blacklist(&owner, &policy_id(&env), &address);
    assert_eq!(
        iface.try_check_transfer(&policy_id(&env), &asset, &address, &1),
        Err(Ok(Error::PolicyRecipientRestricted))
    );
    assert_eq!(
        decision(&managed, &env, &asset, &address, 1).reason(),
        Some(PolicyDenialReason::RecipientBlacklisted)
    );
}

#[test]
fn rule_stack_short_circuits_before_a_later_unevaluable_rule() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let (managed, iface) = setup(&env, &owner, 0, None);
    let asset = Address::generate(&env);
    let recipient = Address::generate(&env);
    let deep = deep_chain_tree(&env);
    let deny = amount_rule(&env, 10);

    managed.add_policy_rule(&owner, &policy_id(&env), &deny);
    managed.add_policy_rule(&owner, &policy_id(&env), &deep);
    assert_eq!(
        iface.try_check_transfer(&policy_id(&env), &asset, &recipient, &100),
        Err(Ok(Error::PolicyDenied))
    );
    assert_eq!(
        managed.try_evaluate_policy_rules(&policy_id(&env), &transaction(&asset, &recipient, 100)),
        Ok(Ok(false))
    );

    managed.clear_policy_rules(&owner, &policy_id(&env));
    managed.add_policy_rule(&owner, &policy_id(&env), &deep);
    managed.add_policy_rule(&owner, &policy_id(&env), &deny);
    assert_eq!(
        iface.try_check_transfer(&policy_id(&env), &asset, &recipient, &100),
        Err(Ok(Error::InvalidInput))
    );
}

#[test]
fn any_strategy_short_circuits_on_the_first_passing_rule() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let (managed, iface) = setup(&env, &owner, 0, Some(PolicyCombinationStrategy::Any));
    let asset = Address::generate(&env);
    let recipient = Address::generate(&env);
    let stranger = Address::generate(&env);

    managed.add_policy_rule(&owner, &policy_id(&env), &amount_rule(&env, 10));
    managed.add_policy_rule(&owner, &policy_id(&env), &not_blacklisted_rule(&env));
    assert_eq!(
        iface.try_check_transfer(&policy_id(&env), &asset, &recipient, &100),
        Ok(Ok(()))
    );

    managed.clear_policy_rules(&owner, &policy_id(&env));
    managed.add_policy_rule(&owner, &policy_id(&env), &not_blacklisted_rule(&env));
    managed.add_policy_rule(&owner, &policy_id(&env), &deep_chain_tree(&env));
    assert_eq!(
        iface.try_check_transfer(&policy_id(&env), &asset, &recipient, &100),
        Ok(Ok(()))
    );

    managed.clear_policy_rules(&owner, &policy_id(&env));
    managed.add_policy_rule(&owner, &policy_id(&env), &amount_rule(&env, 10));
    managed.add_policy_rule(&owner, &policy_id(&env), &recipient_rule(&env, &stranger));
    assert_eq!(
        iface.try_check_transfer(&policy_id(&env), &asset, &recipient, &100),
        Err(Ok(Error::PolicyDenied))
    );
    assert_eq!(
        decision(&managed, &env, &asset, &recipient, 100).reason(),
        Some(PolicyDenialReason::RuleStackDenied)
    );
}

#[test]
fn composite_rule_rule_stack_and_scalar_ceiling_all_constrain_a_spend() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let (managed, iface) = setup(&env, &owner, 1_000, None);
    let asset = Address::generate(&env);
    let vendor = Address::generate(&env);
    let stranger = Address::generate(&env);

    managed.set_composite_rule(&owner, &policy_id(&env), &amount_rule(&env, 500));
    managed.add_policy_rule(&owner, &policy_id(&env), &recipient_rule(&env, &vendor));

    assert_eq!(
        iface.try_check_transfer(&policy_id(&env), &asset, &vendor, &500),
        Ok(Ok(()))
    );
    assert_eq!(
        iface.try_check_transfer(&policy_id(&env), &asset, &vendor, &501),
        Err(Ok(Error::PolicyDenied))
    );
    assert_eq!(
        decision(&managed, &env, &asset, &vendor, 501).reason(),
        Some(PolicyDenialReason::CompositeRuleDenied)
    );
    assert_eq!(
        iface.try_check_transfer(&policy_id(&env), &asset, &stranger, &100),
        Err(Ok(Error::PolicyDenied))
    );
    assert_eq!(
        decision(&managed, &env, &asset, &stranger, 100).reason(),
        Some(PolicyDenialReason::RuleStackDenied)
    );
    assert_violation(&env, "rule_denied");
    assert_violation(&env, "rules_denied");
}

#[test]
fn nested_or_rule_admits_either_an_allowlisted_recipient_or_a_small_amount() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let (managed, iface) = setup(&env, &owner, 0, None);
    let asset = Address::generate(&env);
    let vendor = Address::generate(&env);
    let stranger = Address::generate(&env);

    let tree = branch(
        &env,
        RuleOp::Or,
        vec![
            &env,
            leaf(RuleOp::MaxAmount, 100, Address::generate(&env)),
            leaf(RuleOp::AllowedRecipient, 0, vendor.clone()),
        ],
    );
    managed.add_policy_rule(&owner, &policy_id(&env), &tree);

    assert_eq!(
        iface.try_check_transfer(&policy_id(&env), &asset, &vendor, &1_000),
        Ok(Ok(()))
    );
    assert_eq!(
        iface.try_check_transfer(&policy_id(&env), &asset, &stranger, &100),
        Ok(Ok(()))
    );
    assert_eq!(
        iface.try_check_transfer(&policy_id(&env), &asset, &stranger, &101),
        Err(Ok(Error::PolicyDenied))
    );
}

#[test]
fn nested_and_not_rules_compose_with_the_recipient_denylist_short_circuit() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let (managed, iface) = setup(&env, &owner, 0, None);
    let asset = Address::generate(&env);
    let good = Address::generate(&env);
    let bad = Address::generate(&env);

    managed.add_blacklist(&owner, &policy_id(&env), &bad);
    let mut tree = soroban_sdk::Vec::new(&env);
    tree.push_back(RuleNode {
        op: RuleOp::And,
        value_i128: 0,
        value_address: Address::generate(&env),
        children_start: 1,
        children_end: 3,
    });
    tree.push_back(leaf(RuleOp::MaxAmount, 500, Address::generate(&env)));
    tree.push_back(RuleNode {
        op: RuleOp::Not,
        value_i128: 0,
        value_address: Address::generate(&env),
        children_start: 3,
        children_end: 4,
    });
    tree.push_back(leaf(
        RuleOp::RecipientBlacklisted,
        0,
        Address::generate(&env),
    ));
    managed.add_policy_rule(&owner, &policy_id(&env), &tree);

    assert_eq!(
        iface.try_check_transfer(&policy_id(&env), &asset, &good, &400),
        Ok(Ok(()))
    );
    assert_eq!(
        iface.try_check_transfer(&policy_id(&env), &asset, &good, &501),
        Err(Ok(Error::PolicyDenied))
    );
    assert_eq!(
        iface.try_check_transfer(&policy_id(&env), &asset, &bad, &400),
        Err(Ok(Error::PolicyRecipientRestricted))
    );
    assert_eq!(
        decision(&managed, &env, &asset, &bad, 400).reason(),
        Some(PolicyDenialReason::RecipientBlacklisted)
    );
}

#[test]
fn allowance_ceiling_and_recipient_allowlist_are_all_enforced() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let (managed, iface) = setup(&env, &owner, 1_000, None);
    let asset = Address::generate(&env);
    let vendor = Address::generate(&env);

    managed.set_recipient_whitelist_enabled(&owner, &policy_id(&env), &true);
    managed.add_recipient_to_whitelist(&owner, &policy_id(&env), &vendor);
    managed.set_allowance(&owner, &policy_id(&env), &asset, &300, &0);

    assert_eq!(
        iface.try_check_transfer(&policy_id(&env), &asset, &vendor, &300),
        Ok(Ok(()))
    );
    assert_eq!(
        iface.try_check_transfer(&policy_id(&env), &asset, &vendor, &301),
        Err(Ok(Error::AllowanceExceeded))
    );
    assert_eq!(
        decision(&managed, &env, &asset, &vendor, 301).reason(),
        Some(PolicyDenialReason::AllowanceExceeded)
    );
}

#[test]
fn expired_allowance_denies_an_otherwise_valid_spend() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().with_mut(|l| l.timestamp = 1_000);
    let owner = Address::generate(&env);
    let (managed, iface) = setup(&env, &owner, 1_000, None);
    let asset = Address::generate(&env);
    let vendor = Address::generate(&env);

    managed.set_recipient_whitelist_enabled(&owner, &policy_id(&env), &true);
    managed.add_recipient_to_whitelist(&owner, &policy_id(&env), &vendor);
    managed.set_allowance(&owner, &policy_id(&env), &asset, &500, &2_000);

    assert_eq!(
        iface.try_check_transfer(&policy_id(&env), &asset, &vendor, &100),
        Ok(Ok(()))
    );
    env.ledger().with_mut(|l| l.timestamp = 2_000);
    assert_eq!(
        iface.try_check_transfer(&policy_id(&env), &asset, &vendor, &100),
        Err(Ok(Error::AllowanceExpired))
    );
    assert_eq!(
        decision(&managed, &env, &asset, &vendor, 100).reason(),
        Some(PolicyDenialReason::AllowanceExpired)
    );
}

#[test]
fn disabled_policy_denies_before_any_allow_rule_can_pass() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let (managed, iface) = setup(&env, &owner, 1_000, None);
    let asset = Address::generate(&env);
    let vendor = Address::generate(&env);

    managed.set_recipient_whitelist_enabled(&owner, &policy_id(&env), &true);
    managed.add_recipient_to_whitelist(&owner, &policy_id(&env), &vendor);
    managed.add_policy_rule(&owner, &policy_id(&env), &recipient_rule(&env, &vendor));
    managed.set_enabled(&owner, &policy_id(&env), &false);

    assert_eq!(
        iface.try_check_transfer(&policy_id(&env), &asset, &vendor, &100),
        Err(Ok(Error::PolicyDenied))
    );
    assert_eq!(
        decision(&managed, &env, &asset, &vendor, 100).reason(),
        Some(PolicyDenialReason::Disabled)
    );
    assert_violation(&env, "disabled");
}

#[test]
fn expired_policy_denies_before_allowlists_and_ceiling() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().with_mut(|l| l.timestamp = 1_000);
    let owner = Address::generate(&env);
    let (managed, iface) = setup_with_expiry(&env, &owner, 1_000, None, 2_000);
    let asset = Address::generate(&env);
    let vendor = Address::generate(&env);

    managed.set_recipient_whitelist_enabled(&owner, &policy_id(&env), &true);
    managed.add_recipient_to_whitelist(&owner, &policy_id(&env), &vendor);
    assert_eq!(
        iface.try_check_transfer(&policy_id(&env), &asset, &vendor, &100),
        Ok(Ok(()))
    );

    env.ledger().with_mut(|l| l.timestamp = 2_000);
    assert_eq!(
        iface.try_check_transfer(&policy_id(&env), &asset, &vendor, &100),
        Err(Ok(Error::PolicyExpired))
    );
    assert_eq!(
        decision(&managed, &env, &asset, &vendor, 100).reason(),
        Some(PolicyDenialReason::Expired)
    );
    assert_violation(&env, "expired");
}

#[test]
fn transfer_window_denies_outside_approved_hours_even_when_every_rule_passes() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().with_mut(|l| l.timestamp = 43_200);
    let owner = Address::generate(&env);
    let (managed, iface) = setup(&env, &owner, 1_000, None);
    let asset = Address::generate(&env);
    let vendor = Address::generate(&env);

    managed.set_recipient_whitelist_enabled(&owner, &policy_id(&env), &true);
    managed.add_recipient_to_whitelist(&owner, &policy_id(&env), &vendor);
    managed.set_transfer_window(&owner, &policy_id(&env), &32_400, &61_200, &86_400);

    assert_eq!(
        iface.try_check_transfer(&policy_id(&env), &asset, &vendor, &100),
        Ok(Ok(()))
    );
    env.ledger().with_mut(|l| l.timestamp = 72_000);
    assert_eq!(
        iface.try_check_transfer(&policy_id(&env), &asset, &vendor, &100),
        Err(Ok(Error::PolicyDenied))
    );
    assert_eq!(
        decision(&managed, &env, &asset, &vendor, 100).reason(),
        Some(PolicyDenialReason::OutsideTransferWindow)
    );
}
