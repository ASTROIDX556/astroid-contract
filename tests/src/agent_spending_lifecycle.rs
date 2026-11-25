//! End-to-end coverage of the complete agent spending lifecycle (Issue #446).
//!
//! The harness deploys the workspace in architectural order — registry →
//! wallet → treasury → budget → policy → escrow — and links every module
//! through the registry. These tests drive the five stages the issue calls out
//! in one place:
//!
//! 1. registry lookup resolves the deployed modules,
//! 2. the agent wallet is initialized and the agent is granted a role,
//! 3. the registered policy evaluates the proposed transfer,
//! 4. the budget is debited for the spend,
//! 5. value actually moves to the recipient.
//!
//! The negative cases assert the exact deterministic [`Error`] codes and that
//! no balance or accounting state changed, proving auth guards and policy /
//! budget gates fire before any value moves.

use astroid_budget::Period;
use astroid_shared::errors::Error;
use astroid_shared::types::ModuleKind;
use astroid_wallet::access::Role;
use soroban_sdk::{testutils::Address as _, Address};

use super::e2e_agent_spending::{
    fund_agent_wallet, register_active_policy, setup, string, token_balance, wire_policy,
    BUDGET_ID, ORG,
};

#[test]
fn registry_lookup_wallet_policy_budget_and_transfer_all_succeed() {
    let h = setup();

    // 1. The registry is the source of truth for every module the flow calls.
    assert_eq!(
        h.registry.lookup(&string(&h, ORG), &ModuleKind::Wallet),
        h.wallet.address
    );
    assert_eq!(
        h.registry.lookup(&string(&h, ORG), &ModuleKind::Treasury),
        h.treasury.address
    );
    assert_eq!(
        h.registry.lookup(&string(&h, ORG), &ModuleKind::Budget),
        h.budget.address
    );
    assert_eq!(
        h.registry.lookup(&string(&h, ORG), &ModuleKind::Policy),
        h.policy.address
    );
    assert!(h.registry.verify_owner(&string(&h, ORG), &h.org_owner));

    // 2. Wallet initialization and funding through the treasury.
    let wallet_id = fund_agent_wallet(&h, 10_000);
    assert_eq!(h.wallet.get_wallet(&wallet_id).owner, h.org_owner);
    assert_eq!(h.wallet.get_role(&wallet_id, &h.agent), Some(Role::Agent));
    assert_eq!(h.wallet.balance(&wallet_id, &h.asset), 10_000);

    // 3. Policy evaluation: only the listed recipient, at most 10_000.
    wire_policy(&h);
    h.wallet.set_policy(&h.admin, &h.policy.address);
    register_active_policy(&h, 10_000, true);

    // 4. Budget deduction: the envelope is debited for the planned spend.
    h.budget.allocate(
        &h.admin,
        &string(&h, BUDGET_ID),
        &5_000,
        &Period::None,
        &false,
        &0u64,
    );
    h.budget.consume(&h.admin, &string(&h, BUDGET_ID), &2_000);
    assert_eq!(h.budget.get(&string(&h, BUDGET_ID)).spent, 2_000);

    // 5. Value moves from the agent's wallet to the permitted recipient.
    let before = token_balance(&h, &h.recipient);
    h.wallet
        .transfer(&h.agent, &wallet_id, &h.recipient, &h.asset, &2_000);
    assert_eq!(token_balance(&h, &h.recipient), before + 2_000);
    assert_eq!(h.wallet.balance(&wallet_id, &h.asset), 8_000);
}

#[test]
fn policy_denial_aborts_the_lifecycle_without_moving_value() {
    let h = setup();
    let wallet_id = fund_agent_wallet(&h, 5_000);
    wire_policy(&h);
    h.wallet.set_policy(&h.admin, &h.policy.address);
    register_active_policy(&h, 10_000, true);

    let stranger = Address::generate(&h.env);
    let recipient_before = token_balance(&h, &h.recipient);
    let stranger_before = token_balance(&h, &stranger);

    assert_eq!(
        h.wallet
            .try_transfer(&h.agent, &wallet_id, &stranger, &h.asset, &1_000),
        Err(Ok(Error::PolicyDenied))
    );

    assert_eq!(h.wallet.balance(&wallet_id, &h.asset), 5_000);
    assert_eq!(token_balance(&h, &stranger), stranger_before);
    assert_eq!(token_balance(&h, &h.recipient), recipient_before);
}

#[test]
fn budget_exhaustion_blocks_the_spend_with_a_deterministic_code() {
    let h = setup();
    wire_policy(&h);
    register_active_policy(&h, 100_000, false);

    h.budget.allocate(
        &h.admin,
        &string(&h, BUDGET_ID),
        &1,
        &Period::None,
        &false,
        &0u64,
    );
    h.treasury
        .allocate_budget(&h.admin, &h.asset, &string(&h, BUDGET_ID));
    h.budget.consume(&h.admin, &string(&h, BUDGET_ID), &1);
    assert_eq!(h.budget.get(&string(&h, BUDGET_ID)).spent, 1);

    assert_eq!(
        h.treasury
            .try_withdraw(&h.admin, &h.asset, &h.recipient, &1_000),
        Err(Ok(Error::BUDGET_LIMIT_EXCEEDED))
    );
    assert_eq!(h.treasury.holding(&h.asset).total_out, 0);
    assert_eq!(token_balance(&h, &h.recipient), 0);
}

#[test]
fn unauthorized_caller_is_rejected_before_any_value_moves() {
    let h = setup();
    let wallet_id = fund_agent_wallet(&h, 5_000);
    let intruder = Address::generate(&h.env);
    let before = token_balance(&h, &h.recipient);

    assert_eq!(
        h.wallet
            .try_transfer(&intruder, &wallet_id, &h.recipient, &h.asset, &1_000),
        Err(Ok(Error::Unauthorized))
    );

    assert_eq!(h.wallet.balance(&wallet_id, &h.asset), 5_000);
    assert_eq!(token_balance(&h, &h.recipient), before);
}
