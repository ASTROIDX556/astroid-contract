#![cfg(test)]
extern crate std;

use soroban_sdk::{
    testutils::{Address as _, Events, Ledger},
    token, vec, Address, Env, IntoVal, String, Symbol, Val, Vec,
};

use astroid_shared::constants::MAX_BATCH_PAYMENTS;
use astroid_shared::errors::Error;
use astroid_shared::types::Payment;

use crate::{TreasuryContract, TreasuryContractClient};

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

struct Harness<'a> {
    env: soroban_sdk::Env,
    client: TreasuryContractClient<'a>,
    admin: Address,
    multisig: Address,
    asset: Address,
}

/// Register a treasury plus a test SAC token, approve that token for routing,
/// and mint `funded` of the asset to the admin so deposits move real value.
fn setup(org: &str, funded: i128) -> Harness<'static> {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let multisig = Address::generate(&env);

    let id = env.register_contract(None, TreasuryContract);
    let client = TreasuryContractClient::new(&env, &id);
    client.initialize(&String::from_str(&env, org), &admin);
    client.set_multisig(&admin, &multisig);

    let token_admin = Address::generate(&env);
    let asset = env
        .register_stellar_asset_contract_v2(token_admin)
        .address();

    if funded > 0 {
        token::StellarAssetClient::new(&env, &asset).mint(&admin, &funded);
    }
    client.add_approved_asset(&admin, &asset);

    Harness {
        env,
        client,
        admin,
        multisig,
        asset,
    }
}

fn token_balance(h: &Harness, who: &Address) -> i128 {
    token::TokenClient::new(&h.env, &h.asset).balance(who)
}

#[test]
fn full_flow_deposit_allocate_withdraw() {
    let h = setup("vault", 1_000);
    let recipient = Address::generate(&h.env);

    h.client.deposit(&h.admin, &h.asset, &1_000);
    // Internal accounting and real custody both reflect the deposit.
    assert_eq!(h.client.holding(&h.asset).total_in, 1_000);
    assert_eq!(token_balance(&h, &h.admin), 0);
    assert_eq!(token_balance(&h, &h.client.address), 1_000);

    h.client
        .allocate_budget(&h.admin, &h.asset, &String::from_str(&h.env, "maint"));

    h.client.withdraw(&h.admin, &h.asset, &recipient, &400);
    let holding = h.client.holding(&h.asset);
    assert_eq!(holding.total_in, 600);
    assert_eq!(holding.total_out, 400);
    // Real tokens left custody and reached the recipient.
    assert_eq!(token_balance(&h, &recipient), 400);
    assert_eq!(token_balance(&h, &h.client.address), 600);
}

#[test]
fn withdraw_rejected_when_not_admin() {
    let h = setup("vault", 500);
    let intruder = Address::generate(&h.env);
    h.client.deposit(&h.admin, &h.asset, &500);

    // intruder is not the admin — refused before any value moves.
    let res = h
        .client
        .try_withdraw(&intruder, &h.asset, &Address::generate(&h.env), &100);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
    assert_eq!(token_balance(&h, &h.client.address), 500);
}

#[test]
fn withdraw_overdraws() {
    let h = setup("vault", 50);
    h.client.deposit(&h.admin, &h.asset, &50);

    let res = h
        .client
        .try_withdraw(&h.admin, &h.asset, &Address::generate(&h.env), &100);
    assert_eq!(res, Err(Ok(Error::InsufficientFunds)));
    assert_eq!(token_balance(&h, &h.client.address), 50);
}

#[test]
fn frozen_treasury_rejects_withdrawals() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);
    h.client.freeze(&h.multisig);

    let res = h
        .client
        .try_withdraw(&h.admin, &h.asset, &Address::generate(&h.env), &10);
    assert_eq!(res, Err(Ok(Error::InvalidState)));
    assert_eq!(token_balance(&h, &h.client.address), 1_000);
}

#[test]
fn deposit_into_frozen_treasury_allowed() {
    let h = setup("vault", 1_000);
    h.client.freeze(&h.multisig);
    // Deposits should be allowed even when frozen (only outbound transfers are blocked)
    h.client.deposit(&h.admin, &h.asset, &100);
    // Value moved into the treasury despite being frozen.
    assert_eq!(token_balance(&h, &h.admin), 900);
    assert_eq!(token_balance(&h, &h.client.address), 100);
}

#[test]
fn prepare_holds_state() {
    let h = setup("vault", 0);
    let state = h.client.get();
    assert_eq!(state.org, String::from_str(&h.env, "vault"));
}

#[test]
fn allowance_caps_withdrawal_and_accumulates() {
    let h = setup("vault", 1_000);
    let recipient = Address::generate(&h.env);
    h.client.deposit(&h.admin, &h.asset, &1_000);
    // Approve a 500 ceiling for admin -> recipient in this asset.
    h.client
        .set_allowance(&h.admin, &h.admin, &recipient, &h.asset, &500, &0);

    // First withdrawal within the ceiling succeeds and is deducted.
    h.client.withdraw(&h.admin, &h.asset, &recipient, &400);
    let al = h.client.allowance(&h.admin, &recipient, &h.asset);
    assert_eq!(al.spent, 400);
    assert_eq!(token_balance(&h, &recipient), 400);

    // Second withdrawal exceeds the remaining 100 -> rejected at the allowance gate.
    let res = h.client.try_withdraw(&h.admin, &h.asset, &recipient, &200);
    assert_eq!(res, Err(Ok(Error::AllowanceExceeded)));
    assert_eq!(token_balance(&h, &recipient), 400);

    // A different recipient is not under the allowance, so it is allowed.
    let other = Address::generate(&h.env);
    h.client.withdraw(&h.admin, &h.asset, &other, &100);
    assert_eq!(token_balance(&h, &other), 100);
}

#[test]
fn expired_allowance_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(10_000);
    let admin = Address::generate(&env);
    let id = env.register_contract(None, TreasuryContract);
    let client = TreasuryContractClient::new(&env, &id);
    client.initialize(&String::from_str(&env, "vault"), &admin);
    let token_admin = Address::generate(&env);
    let asset = env
        .register_stellar_asset_contract_v2(token_admin)
        .address();
    token::StellarAssetClient::new(&env, &asset).mint(&admin, &1_000);
    client.add_approved_asset(&admin, &asset);
    client.deposit(&admin, &asset, &1_000);

    // Allowance already expired (expires_at in the past).
    let recipient = Address::generate(&env);
    client.set_allowance(&admin, &admin, &recipient, &asset, &500, &5_000);
    let res = client.try_withdraw(&admin, &asset, &recipient, &100);
    assert_eq!(res, Err(Ok(Error::AllowanceExpired)));
}

#[test]
fn remove_allowance_clears_cap() {
    let h = setup("vault", 1_000);
    let recipient = Address::generate(&h.env);
    h.client.deposit(&h.admin, &h.asset, &1_000);
    h.client
        .set_allowance(&h.admin, &h.admin, &recipient, &h.asset, &100, &0);
    h.client
        .remove_allowance(&h.admin, &h.admin, &recipient, &h.asset);
    // With no allowance in place the full balance may be withdrawn.
    h.client.withdraw(&h.admin, &h.asset, &recipient, &1_000);
    assert_eq!(token_balance(&h, &recipient), 1_000);
}

#[test]
fn test_milestone_releases() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let contract_id = env.register_contract(None, TreasuryContract);
    let client = TreasuryContractClient::new(&env, &contract_id);
    client.initialize(&soroban_sdk::String::from_str(&env, "org"), &admin);

    let token = env
        .register_stellar_asset_contract_v2(admin.clone())
        .address();
    let token_admin = token::StellarAssetClient::new(&env, &token);
    let token_client = token::TokenClient::new(&env, &token);
    client.add_approved_asset(&admin, &token);

    let to = Address::generate(&env);

    let mid = client.init_milestone_disbursement(&admin, &token, &to, &1000, &3);
    assert_eq!(mid, 1);

    // Deposit 1000 into treasury so we have funds
    token_admin.mint(&admin, &1000);
    client.deposit(&admin, &token, &1000);

    // release milestone 1
    client.release_next_milestone(&admin, &mid);
    assert_eq!(token_client.balance(&to), 333); // 1000 / 3

    // release milestone 2
    client.release_next_milestone(&admin, &mid);
    assert_eq!(token_client.balance(&to), 666);

    // release milestone 3 (final, catches remainder)
    client.release_next_milestone(&admin, &mid);
    assert_eq!(token_client.balance(&to), 1000);

    // releasing beyond fails
    let res = client.try_release_next_milestone(&admin, &mid);
    assert!(res.is_err());
}

#[test]
fn standard_events_emitted() {
    // Configuration changes publish a TreasuryConfigUpdated event. Setting a
    // (here placeholder) policy/budget address is enough to exercise the emit
    // path; we avoid a subsequent withdraw on this env because a real policy
    // gate is not wired up.
    let h = setup("vault", 0);
    h.client.set_policy(&h.admin, &h.admin);
    assert_event(&h.env, "TreasuryConfigUpdated");
    h.client.set_budget(&h.admin, &h.admin);
    assert_event(&h.env, "TreasuryConfigUpdated");

    // A successful withdraw (no policy/budget gates configured) publishes a
    // TransferExecuted event.
    let h2 = setup("vault", 1_000);
    let recipient = Address::generate(&h2.env);
    h2.client.deposit(&h2.admin, &h2.asset, &1_000);
    h2.client.withdraw(&h2.admin, &h2.asset, &recipient, &100);
    assert_event(&h2.env, "TransferExecuted");
}

#[test]
fn payout_schedule_limits_withdraw_per_interval() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);
    // Set payout schedule: max 300 per 1 hour
    h.client.set_payout_schedule(&h.admin, &300, &3_600);
    let recipient = Address::generate(&h.env);
    // First withdraw within limit
    h.client.withdraw(&h.admin, &h.asset, &recipient, &200);
    assert_eq!(token_balance(&h, &recipient), 200);
    // Second withdraw would exceed limit (200 + 200 > 300)
    let res = h.client.try_withdraw(&h.admin, &h.asset, &recipient, &200);
    assert_eq!(res, Err(Ok(Error::PayoutScheduleViolated)));
    // Can still withdraw up to the limit
    h.client.withdraw(&h.admin, &h.asset, &recipient, &100);
    assert_eq!(token_balance(&h, &recipient), 300);
}

#[test]
fn payout_schedule_resets_after_interval() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);
    h.client.set_payout_schedule(&h.admin, &300, &3_600);
    let recipient = Address::generate(&h.env);
    // Exhaust the interval
    h.client.withdraw(&h.admin, &h.asset, &recipient, &300);
    let res = h.client.try_withdraw(&h.admin, &h.asset, &recipient, &1);
    assert_eq!(res, Err(Ok(Error::PayoutScheduleViolated)));
    // Advance past the interval
    h.env.ledger().set_timestamp(1_700 + 3_600);
    // Should be able to withdraw again
    h.client.withdraw(&h.admin, &h.asset, &recipient, &200);
    assert_eq!(token_balance(&h, &recipient), 500);
}

#[test]
fn clear_payout_schedule_removes_limit() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);
    h.client.set_payout_schedule(&h.admin, &100, &3_600);
    // Clear the schedule
    h.client.clear_payout_schedule(&h.admin);
    let recipient = Address::generate(&h.env);
    // Can now withdraw more than the previous limit
    h.client.withdraw(&h.admin, &h.asset, &recipient, &500);
    assert_eq!(token_balance(&h, &recipient), 500);
}

#[test]
fn payout_schedule_invalid_params_rejected() {
    let h = setup("vault", 1_000);
    // max_per_interval must be positive
    let res = h.client.try_set_payout_schedule(&h.admin, &0, &3_600);
    assert_eq!(res, Err(Ok(Error::InvalidInput)));
    // interval_seconds must be positive
    let res = h.client.try_set_payout_schedule(&h.admin, &100, &0);
    assert_eq!(res, Err(Ok(Error::InvalidInput)));
}
