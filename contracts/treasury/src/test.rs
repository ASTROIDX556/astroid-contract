use soroban_sdk::{testutils::Address as _, token, Address, Env, String};

use astroid_shared::errors::Error;

use crate::{TreasuryContract, TreasuryContractClient};

struct Harness<'a> {
    env: Env,
    client: TreasuryContractClient<'a>,
    admin: Address,
    asset: Address,
    second_asset: Address,
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

    let token_admin2 = Address::generate(&env);
    let second_asset = env
        .register_stellar_asset_contract_v2(token_admin2)
        .address();

    if funded > 0 {
        token::StellarAssetClient::new(&env, &asset).mint(&admin, &funded);
    }

    Harness {
        env,
        client,
        admin,
        asset,
        second_asset,
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

// --- Allowance / reserve tests ---

#[test]
fn create_allowance_happy_path() {
    let h = setup("vault", 1_000);
    let spender = Address::generate(&h.env);
    h.client.deposit(&h.admin, &h.asset, &1_000);

    h.client.create_allowance(&h.admin, &spender, &h.asset, &500);
    let a = h.client.get_allowance(&h.asset, &spender);
    assert_eq!(a.amount, 500);
    assert_eq!(a.used, 0);
    assert_eq!(h.client.holding(&h.asset).total_allowances, 500);
}

#[test]
fn create_allowance_over_allocation_fails() {
    let h = setup("vault", 1_000);
    let spender = Address::generate(&h.env);
    h.client.deposit(&h.admin, &h.asset, &1_000);

    // Try to create allowance larger than deposited amount.
    let res = h.client.try_create_allowance(&h.admin, &spender, &h.asset, &2_000);
    assert_eq!(res, Err(Ok(Error::AllowanceExceeded)));
}

#[test]
fn create_allowance_duplicate_fails() {
    let h = setup("vault", 1_000);
    let spender = Address::generate(&h.env);
    h.client.deposit(&h.admin, &h.asset, &1_000);

    h.client.create_allowance(&h.admin, &spender, &h.asset, &200);
    let res = h.client.try_create_allowance(&h.admin, &spender, &h.asset, &200);
    assert_eq!(res, Err(Ok(Error::AllowanceAlreadyExists)));
}

#[test]
fn non_admin_cannot_create_allowance() {
    let h = setup("vault", 1_000);
    let stranger = Address::generate(&h.env);
    let spender = Address::generate(&h.env);
    h.client.deposit(&h.admin, &h.asset, &1_000);

    let res = h.client.try_create_allowance(&stranger, &spender, &h.asset, &100);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
}

#[test]
fn revoke_allowance_returns_capacity() {
    let h = setup("vault", 1_000);
    let spender = Address::generate(&h.env);
    h.client.deposit(&h.admin, &h.asset, &1_000);

    h.client.create_allowance(&h.admin, &spender, &h.asset, &500);
    assert_eq!(h.client.holding(&h.asset).total_allowances, 500);

    h.client.revoke_allowance(&h.admin, &spender, &h.asset);
    assert_eq!(h.client.holding(&h.asset).total_allowances, 0);

    // After revocation, spender's allowance is gone.
    let res = h.client.try_get_allowance(&h.asset, &spender);
    assert_eq!(res, Err(Ok(Error::AllowanceNotFound)));
}

#[test]
fn revoke_nonexistent_allowance_fails() {
    let h = setup("vault", 1_000);
    let spender = Address::generate(&h.env);
    let res = h.client.try_revoke_allowance(&h.admin, &spender, &h.asset);
    assert_eq!(res, Err(Ok(Error::AllowanceNotFound)));
}

#[test]
fn create_reserve_happy_path() {
    let h = setup("vault", 1_000);
    let spender = Address::generate(&h.env);
    h.client.deposit(&h.admin, &h.asset, &1_000);

    h.client.create_allowance(&h.admin, &spender, &h.asset, &500);
    let rid = h.client.create_reserve(&spender, &h.asset, &200);
    assert_eq!(rid, 1);

    let reserve = h.client.get_reserve(&h.asset, &rid);
    assert_eq!(reserve.amount, 200);
    assert_eq!(reserve.spender, spender);

    // Allowance used increased, reserves increased.
    let a = h.client.get_allowance(&h.asset, &spender);
    assert_eq!(a.used, 200);
    assert_eq!(h.client.holding(&h.asset).total_reserves, 200);
}

#[test]
fn create_reserve_exceeds_allowance_fails() {
    let h = setup("vault", 1_000);
    let spender = Address::generate(&h.env);
    h.client.deposit(&h.admin, &h.asset, &1_000);

    h.client.create_allowance(&h.admin, &spender, &h.asset, &100);
    let res = h.client.try_create_reserve(&spender, &h.asset, &200);
    assert_eq!(res, Err(Ok(Error::AllowanceExceeded)));
}

#[test]
fn release_reserve_happy_path() {
    let h = setup("vault", 1_000);
    let spender = Address::generate(&h.env);
    h.client.deposit(&h.admin, &h.asset, &1_000);

    h.client.create_allowance(&h.admin, &spender, &h.asset, &500);
    let rid = h.client.create_reserve(&spender, &h.asset, &300);
    h.client.release_reserve(&spender, &h.asset, &rid);

    // Allowance used returned to 0, reserves returned to 0.
    let a = h.client.get_allowance(&h.asset, &spender);
    assert_eq!(a.used, 0);
    assert_eq!(h.client.holding(&h.asset).total_reserves, 0);

    // Reserve entry removed.
    let res = h.client.try_get_reserve(&h.asset, &rid);
    assert_eq!(res, Err(Ok(Error::ReserveNotFound)));
}

#[test]
fn release_nonexistent_reserve_fails() {
    let h = setup("vault", 1_000);
    let spender = Address::generate(&h.env);
    h.client.deposit(&h.admin, &h.asset, &1_000);

    let res = h.client.try_release_reserve(&spender, &h.asset, &999);
    assert_eq!(res, Err(Ok(Error::ReserveNotFound)));
}

#[test]
fn unauthorized_release_reserve_fails() {
    let h = setup("vault", 1_000);
    let spender = Address::generate(&h.env);
    let other = Address::generate(&h.env);
    h.client.deposit(&h.admin, &h.asset, &1_000);

    h.client.create_allowance(&h.admin, &spender, &h.asset, &500);
    let rid = h.client.create_reserve(&spender, &h.asset, &200);

    // `other` did not create this reserve.
    let res = h.client.try_release_reserve(&other, &h.asset, &rid);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
}

#[test]
fn allowance_over_allocation_with_reserves() {
    let h = setup("vault", 1_000);
    let spender = Address::generate(&h.env);
    h.client.deposit(&h.admin, &h.asset, &1_000);

    // Create two allowances: 600 + 500 = 1100 > 1000 deposited.
    h.client.create_allowance(&h.admin, &spender, &h.asset, &600);
    let res = h.client.try_create_allowance(
        &h.admin,
        &Address::generate(&h.env),
        &h.asset,
        &500,
    );
    assert_eq!(res, Err(Ok(Error::AllowanceExceeded)));
}

#[test]
fn release_restore_allowance_capacity() {
    let h = setup("vault", 1_000);
    let spender = Address::generate(&h.env);
    h.client.deposit(&h.admin, &h.asset, &1_000);

    h.client.create_allowance(&h.admin, &spender, &h.asset, &400);

    // Reserve 300, release 300, then reserve 400 — should work.
    let rid = h.client.create_reserve(&spender, &h.asset, &300);
    h.client.release_reserve(&spender, &h.asset, &rid);
    let rid2 = h.client.create_reserve(&spender, &h.asset, &400);
    assert_eq!(rid2, 2);

    let a = h.client.get_allowance(&h.asset, &spender);
    assert_eq!(a.used, 400);
}

#[test]
fn create_reserve_zero_amount_fails() {
    let h = setup("vault", 1_000);
    let spender = Address::generate(&h.env);
    h.client.deposit(&h.admin, &h.asset, &1_000);
    h.client.create_allowance(&h.admin, &spender, &h.asset, &500);

    let res = h.client.try_create_reserve(&spender, &h.asset, &0);
    assert_eq!(res, Err(Ok(Error::InvalidAmount)));
}

#[test]
fn reserve_on_second_asset() {
    let h = setup("vault", 0);
    let spender = Address::generate(&h.env);

    // Fund second asset directly.
    token::StellarAssetClient::new(&h.env, &h.second_asset).mint(&h.admin, &500);
    h.client.deposit(&h.admin, &h.second_asset, &500);

    h.client.create_allowance(&h.admin, &spender, &h.second_asset, &300);
    let rid = h.client.create_reserve(&spender, &h.second_asset, &100);
    assert_eq!(rid, 1);

    assert_eq!(h.client.holding(&h.second_asset).total_reserves, 100);
    assert_eq!(h.client.holding(&h.asset).total_reserves, 0);
}
