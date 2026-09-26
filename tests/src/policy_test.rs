//! Integration tests for multi-rule policy composition.
//!
//! The policy module is deployed into a shared mock [`Env`] and driven through
//! the **shared interface client** (`astroid_interfaces::PolicyClient`), which
//! is exactly how the rest of the protocol (treasury, wallet) asks a policy
//! whether a spend may happen. Rule management happens through the contract's
//! own client, so each test covers the full path: register rules → evaluate
//! through the interface → assert the canonical [`Error`] codes.
//!
//! The rules under test are the compound "whitelist recipient + max amount"
//! policy: independent rule trees stacked on one policy where **every** rule
//! must pass for a transaction to be authorized.

use astroid_interfaces::PolicyClient;
use astroid_policy::{
    PolicyContract, PolicyContractClient, RuleNode, RuleOp, RuleStrategy, RuleTree,
};
use astroid_shared::errors::Error;
use soroban_sdk::{testutils::Address as _, Address, BytesN, Env, String};

const POLICY_ID: &str = "org-governance";

/// Deploy the policy module and register a permissive base policy so only the
/// rule stack under test can deny a transfer.
fn setup<'a>(env: &'a Env, owner: &Address) -> (PolicyContractClient<'a>, PolicyClient<'a>) {
    let id = env.register_contract(None, PolicyContract);
    let managed = PolicyContractClient::new(env, &id);
    managed.initialize();
    managed.register_policy(
        owner,
        &String::from_str(env, POLICY_ID),
        &BytesN::from_array(env, &[23; 32]),
        &0,
        &None,
        &None,
        &0,
        &RuleStrategy::All,
    );
    (managed, PolicyClient::new(env, &id))
}

fn pid(env: &Env) -> String {
    String::from_str(env, POLICY_ID)
}

/// A single-node rule tree carrying an amount threshold.
fn amount_rule(env: &Env, max: i128) -> RuleTree {
    let mut tree = soroban_sdk::Vec::new(env);
    tree.push_back(RuleNode {
        op: RuleOp::MaxAmount,
        value_i128: max,
        value_address: Address::generate(env),
        children_start: 0,
        children_end: 0,
    });
    tree
}

/// A single-node rule tree whitelisting one recipient.
fn recipient_rule(env: &Env, recipient: Address) -> RuleTree {
    let mut tree = soroban_sdk::Vec::new(env);
    tree.push_back(RuleNode {
        op: RuleOp::AllowedRecipient,
        value_i128: 0,
        value_address: recipient,
        children_start: 0,
        children_end: 0,
    });
    tree
}

#[test]
fn compound_recipient_and_amount_rules_authorize_only_matching_transfers() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let (managed, iface) = setup(&env, &owner);
    let asset = Address::generate(&env);
    let vendor = Address::generate(&env);
    let stranger = Address::generate(&env);

    // Two independent governance rules stacked on the same policy.
    assert_eq!(
        managed.add_policy_rule(&owner, &pid(&env), &recipient_rule(&env, vendor.clone())),
        1
    );
    assert_eq!(
        managed.add_policy_rule(&owner, &pid(&env), &amount_rule(&env, 500)),
        2
    );
    assert_eq!(managed.get_policy_rules(&pid(&env)).len(), 2);

    // Whitelisted recipient, amount inside the cap: both rules pass.
    assert_eq!(
        iface.try_check_transfer(&pid(&env), &asset, &vendor, &500),
        Ok(Ok(()))
    );

    // Recipient rule fails (amount is irrelevant once one rule says no).
    assert_eq!(
        iface.try_check_transfer(&pid(&env), &asset, &stranger, &100),
        Err(Ok(Error::PolicyDenied))
    );

    // Amount rule fails for the whitelisted recipient.
    assert_eq!(
        iface.try_check_transfer(&pid(&env), &asset, &vendor, &501),
        Err(Ok(Error::PolicyDenied))
    );
}

#[test]
fn every_registered_rule_must_pass_before_authorization() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let (managed, iface) = setup(&env, &owner);
    let asset = Address::generate(&env);
    let vendor = Address::generate(&env);

    managed.add_policy_rule(&owner, &pid(&env), &recipient_rule(&env, vendor.clone()));
    managed.add_policy_rule(&owner, &pid(&env), &amount_rule(&env, 500));
    managed.add_policy_rule(&owner, &pid(&env), &{
        let mut tree = soroban_sdk::Vec::new(&env);
        tree.push_back(RuleNode {
            op: RuleOp::AllowedAsset,
            value_i128: 0,
            value_address: asset.clone(),
            children_start: 0,
            children_end: 0,
        });
        tree
    });
    assert_eq!(managed.get_policy_rules(&pid(&env)).len(), 3);

    // All three rules pass.
    assert_eq!(
        iface.try_check_transfer(&pid(&env), &asset, &vendor, &250),
        Ok(Ok(()))
    );

    // A single failing rule — here the asset — denies the transaction.
    let other_asset = Address::generate(&env);
    assert_eq!(
        iface.try_check_transfer(&pid(&env), &other_asset, &vendor, &250),
        Err(Ok(Error::PolicyDenied))
    );
}

#[test]
fn no_registered_rules_keeps_the_policy_permissive() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let (managed, iface) = setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    assert_eq!(managed.get_policy_rules(&pid(&env)).len(), 0);
    assert_eq!(
        iface.try_check_transfer(&pid(&env), &asset, &recip, &10_000),
        Ok(Ok(()))
    );
}

#[test]
fn removing_a_rule_retires_only_that_rule() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let (managed, iface) = setup(&env, &owner);
    let asset = Address::generate(&env);
    let vendor = Address::generate(&env);
    let stranger = Address::generate(&env);

    managed.add_policy_rule(&owner, &pid(&env), &recipient_rule(&env, vendor.clone()));
    managed.add_policy_rule(&owner, &pid(&env), &amount_rule(&env, 500));

    assert_eq!(
        iface.try_check_transfer(&pid(&env), &asset, &vendor, &600),
        Err(Ok(Error::PolicyDenied))
    );

    // Drop the amount rule (index 1); the whitelist keeps protecting the policy.
    managed.remove_policy_rule(&owner, &pid(&env), &1);
    assert_eq!(managed.get_policy_rules(&pid(&env)).len(), 1);
    assert_eq!(
        iface.try_check_transfer(&pid(&env), &asset, &vendor, &600),
        Ok(Ok(()))
    );
    assert_eq!(
        iface.try_check_transfer(&pid(&env), &asset, &stranger, &600),
        Err(Ok(Error::PolicyDenied))
    );

    // Clearing the stack restores the fully permissive base policy.
    managed.clear_policy_rules(&owner, &pid(&env));
    assert_eq!(managed.get_policy_rules(&pid(&env)).len(), 0);
    assert_eq!(
        iface.try_check_transfer(&pid(&env), &asset, &stranger, &600),
        Ok(Ok(()))
    );
}

#[test]
fn rule_stack_composes_with_the_scalar_policy_gates() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let id = env.register_contract(None, PolicyContract);
    let managed = PolicyContractClient::new(&env, &id);
    managed.initialize();
    // Scalar gate: policy-wide cap of 1_000 …
    managed.register_policy(
        &owner,
        &pid(&env),
        &BytesN::from_array(&env, &[5; 32]),
        &1_000,
        &None,
        &None,
        &0,
        &RuleStrategy::All,
    );
    let iface = PolicyClient::new(&env, &id);

    // … plus a whitelist rule that only accepts the vendor.
    let vendor = Address::generate(&env);
    managed.add_policy_rule(&owner, &pid(&env), &recipient_rule(&env, vendor.clone()));
    let asset = Address::generate(&env);
    let stranger = Address::generate(&env);

    // Within both gates.
    assert_eq!(
        iface.try_check_transfer(&pid(&env), &asset, &vendor, &900),
        Ok(Ok(()))
    );
    // Scalar cap denies before the rule stack is even consulted.
    assert_eq!(
        iface.try_check_transfer(&pid(&env), &asset, &vendor, &1_001),
        Err(Ok(Error::PolicyDenied))
    );
    // Rule stack denies the unlisted recipient under the scalar cap.
    assert_eq!(
        iface.try_check_transfer(&pid(&env), &asset, &stranger, &100),
        Err(Ok(Error::PolicyDenied))
    );
}

#[test]
fn only_the_policy_owner_manages_the_rule_stack() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let (managed, _iface) = setup(&env, &owner);
    let stranger = Address::generate(&env);
    let tree = amount_rule(&env, 100);

    assert_eq!(
        managed.try_add_policy_rule(&stranger, &pid(&env), &tree),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(
        managed.try_remove_policy_rule(&stranger, &pid(&env), &0),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(
        managed.try_clear_policy_rules(&stranger, &pid(&env)),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(managed.get_policy_rules(&pid(&env)).len(), 0);

    // A malformed rule is rejected at registration, not stored for later.
    let empty = soroban_sdk::Vec::new(&env);
    assert_eq!(
        managed.try_add_policy_rule(&owner, &pid(&env), &empty),
        Err(Ok(Error::InvalidInput))
    );
}
