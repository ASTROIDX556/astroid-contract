use soroban_sdk::{
    testutils::Address as _, testutils::Events, token, Address, Env, IntoVal, String, Symbol, Val,
};

use astroid_shared::errors::Error;

use crate::{TreasuryContract, TreasuryContractClient};

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

struct Harness<'a> {
    env: Env,
    client: TreasuryContractClient<'a>,
    admin: Address,
    asset: Address,
}

/// Register a treasury plus a test SAC token, and mint `funded` of the asset to
/// the admin so deposits move real value.
fn setup(org: &str, funded: i128) -> Harness<'static> {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);

    let id = env.register_contract(None, TreasuryContract);
    let client = TreasuryContractClient::new(&env, &id);
    client.initialize(&String::from_str(&env, org), &admin);

    let token_admin = Address::generate(&env);
    let asset = env
        .register_stellar_asset_contract_v2(token_admin)
        .address();
    if funded > 0 {
        token::StellarAssetClient::new(&env, &asset).mint(&admin, &funded);
    }

    Harness {
        env,
        client,
        admin,
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
    h.client.freeze(&h.admin);

    let res = h
        .client
        .try_withdraw(&h.admin, &h.asset, &Address::generate(&h.env), &10);
    assert_eq!(res, Err(Ok(Error::InvalidState)));
    assert_eq!(token_balance(&h, &h.client.address), 1_000);
}

#[test]
fn deposit_into_frozen_treasury_rejected() {
    let h = setup("vault", 1_000);
    h.client.freeze(&h.admin);
    let res = h.client.try_deposit(&h.admin, &h.asset, &100);
    assert_eq!(res, Err(Ok(Error::InvalidState)));
    // No value moved on the rejected deposit.
    assert_eq!(token_balance(&h, &h.admin), 1_000);
}

#[test]
fn prepare_holds_state() {
    let h = setup("vault", 0);
    let state = h.client.get();
    assert_eq!(state.org, String::from_str(&h.env, "vault"));
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

// ── Allowance tracking ───────────────────────────────────────────────

#[test]
fn allowance_set_and_get() {
    let h = setup("vault", 0);
    let agent = Address::generate(&h.env);
    // Initially no allowance → 0
    assert_eq!(h.client.get_allowance(&agent), 0);
    h.client.set_allowance(&h.admin, &agent, &500);
    assert_eq!(h.client.get_allowance(&agent), 500);
    // Overwrite with higher value
    h.client.set_allowance(&h.admin, &agent, &1_000);
    assert_eq!(h.client.get_allowance(&agent), 1_000);
    // Zero allowance blocks (explicit 0 means no further withdraws)
    h.client.set_allowance(&h.admin, &agent, &0);
    assert_eq!(h.client.get_allowance(&agent), 0);
}

#[test]
fn allowance_successful_usage() {
    let h = setup("vault", 1_000);
    let agent = Address::generate(&h.env);
    h.client.deposit(&h.admin, &h.asset, &1_000);
    h.client.set_allowance(&h.admin, &agent, &600);

    // Withdraw within allowance succeeds and atomically decrements.
    h.client.withdraw(&h.admin, &h.asset, &agent, &400);
    assert_eq!(h.client.get_allowance(&agent), 200);
    assert_eq!(token_balance(&h, &agent), 400);
    assert_eq!(token_balance(&h, &h.client.address), 600);
    let holding = h.client.holding(&h.asset);
    assert_eq!(holding.total_in, 600);
    assert_eq!(holding.total_out, 400);
}

#[test]
fn allowance_exact_limit_boundary() {
    let h = setup("vault", 500);
    let agent = Address::generate(&h.env);
    h.client.deposit(&h.admin, &h.asset, &500);
    h.client.set_allowance(&h.admin, &agent, &500);

    // Exact match is allowed; remaining becomes 0.
    h.client.withdraw(&h.admin, &h.asset, &agent, &500);
    assert_eq!(h.client.get_allowance(&agent), 0);
    assert_eq!(token_balance(&h, &agent), 500);
    assert_eq!(token_balance(&h, &h.client.address), 0);

    // Any further withdraw, even 1 stroop, must fail with AllowanceExceeded.
    let res = h.client.try_withdraw(&h.admin, &h.asset, &agent, &1);
    assert_eq!(res, Err(Ok(Error::AllowanceExceeded)));
    // State unchanged after rejection.
    assert_eq!(h.client.get_allowance(&agent), 0);
    assert_eq!(token_balance(&h, &h.client.address), 0);
    assert_eq!(h.client.holding(&h.asset).total_in, 0);
}

#[test]
fn allowance_over_limit_rejection() {
    let h = setup("vault", 1_000);
    let agent = Address::generate(&h.env);
    h.client.deposit(&h.admin, &h.asset, &1_000);
    h.client.set_allowance(&h.admin, &agent, &300);

    // Attempt to withdraw more than allowance → deterministic error.
    let res = h.client.try_withdraw(&h.admin, &h.asset, &agent, &400);
    assert_eq!(res, Err(Ok(Error::AllowanceExceeded)));
    // No tokens moved, allowance unchanged, internal ledger untouched.
    assert_eq!(h.client.get_allowance(&agent), 300);
    assert_eq!(token_balance(&h, &agent), 0);
    assert_eq!(token_balance(&h, &h.client.address), 1_000);
    assert_eq!(h.client.holding(&h.asset).total_in, 1_000);
    assert_eq!(h.client.holding(&h.asset).total_out, 0);
}

#[test]
fn allowance_multiple_withdraws_decrement_atomically() {
    let h = setup("vault", 1_000);
    let agent = Address::generate(&h.env);
    h.client.deposit(&h.admin, &h.asset, &1_000);
    h.client.set_allowance(&h.admin, &agent, &1_000);

    h.client.withdraw(&h.admin, &h.asset, &agent, &300);
    assert_eq!(h.client.get_allowance(&agent), 700);
    h.client.withdraw(&h.admin, &h.asset, &agent, &400);
    assert_eq!(h.client.get_allowance(&agent), 300);
    h.client.withdraw(&h.admin, &h.asset, &agent, &300);
    assert_eq!(h.client.get_allowance(&agent), 0);
    assert_eq!(token_balance(&h, &agent), 1_000);

    // Exhausted → next withdraw fails.
    let res = h.client.try_withdraw(&h.admin, &h.asset, &agent, &1);
    assert_eq!(res, Err(Ok(Error::AllowanceExceeded)));
    assert_eq!(token_balance(&h, &agent), 1_000);
}

#[test]
fn allowance_zero_blocks_withdrawal() {
    let h = setup("vault", 1_000);
    let agent = Address::generate(&h.env);
    h.client.deposit(&h.admin, &h.asset, &1_000);
    h.client.set_allowance(&h.admin, &agent, &0);

    let res = h.client.try_withdraw(&h.admin, &h.asset, &agent, &10);
    assert_eq!(res, Err(Ok(Error::AllowanceExceeded)));
    assert_eq!(h.client.get_allowance(&agent), 0);
    assert_eq!(token_balance(&h, &agent), 0);
}

#[test]
fn allowance_non_admin_cannot_set() {
    let h = setup("vault", 0);
    let agent = Address::generate(&h.env);
    let intruder = Address::generate(&h.env);
    let res = h.client.try_set_allowance(&intruder, &agent, &500);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
    assert_eq!(h.client.get_allowance(&agent), 0);
}

#[test]
fn allowance_negative_amount_rejected() {
    let h = setup("vault", 0);
    let agent = Address::generate(&h.env);
    let res = h.client.try_set_allowance(&h.admin, &agent, &-10);
    assert_eq!(res, Err(Ok(Error::InvalidAmount)));
    assert_eq!(h.client.get_allowance(&agent), 0);
}

#[test]
fn allowance_per_beneficiary_isolation() {
    let h = setup("vault", 1_000);
    let alice = Address::generate(&h.env);
    let bob = Address::generate(&h.env);
    h.client.deposit(&h.admin, &h.asset, &1_000);
    h.client.set_allowance(&h.admin, &alice, &400);
    h.client.set_allowance(&h.admin, &bob, &700);

    h.client.withdraw(&h.admin, &h.asset, &alice, &400);
    assert_eq!(h.client.get_allowance(&alice), 0);
    assert_eq!(h.client.get_allowance(&bob), 700);
    // Bob still has full allowance independent of Alice's consumption.
    assert_eq!(token_balance(&h, &alice), 400);
    assert_eq!(token_balance(&h, &bob), 0);

    // Alice exhausted → next Alice withdraw fails, Bob still succeeds.
    let res = h.client.try_withdraw(&h.admin, &h.asset, &alice, &1);
    assert_eq!(res, Err(Ok(Error::AllowanceExceeded)));
    h.client.withdraw(&h.admin, &h.asset, &bob, &600);
    assert_eq!(h.client.get_allowance(&bob), 100);
    assert_eq!(token_balance(&h, &bob), 600);
}

#[test]
fn allowance_unlimited_when_not_set() {
    // Withdrawals to an address with no explicit allowance are unlimited
    // (backward compatibility with pre-allowance treasuries).
    let h = setup("vault", 1_000);
    let recipient = Address::generate(&h.env);
    h.client.deposit(&h.admin, &h.asset, &1_000);
    // No set_allowance call → withdraw succeeds.
    assert_eq!(h.client.get_allowance(&recipient), 0);
    h.client.withdraw(&h.admin, &h.asset, &recipient, &1_000);
    assert_eq!(token_balance(&h, &recipient), 1_000);
}

#[test]
fn allowance_over_limit_does_not_consume_budget_or_funds() {
    let h = setup("vault", 500);
    let agent = Address::generate(&h.env);
    h.client.deposit(&h.admin, &h.asset, &500);
    h.client.set_allowance(&h.admin, &agent, &100);
    // Even though treasury has 500 funds, allowance breach aborts before ledger debit.
    let res = h.client.try_withdraw(&h.admin, &h.asset, &agent, &200);
    assert_eq!(res, Err(Ok(Error::AllowanceExceeded)));
    assert_eq!(h.client.holding(&h.asset).total_in, 500);
    assert_eq!(h.client.holding(&h.asset).total_out, 0);
    assert_eq!(token_balance(&h, &h.client.address), 500);
}
