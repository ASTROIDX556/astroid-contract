use soroban_sdk::{testutils::Address as _, token, Address, Env, String};

use astroid_shared::errors::Error;

use crate::{TreasuryContract, TreasuryContractClient};

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
fn test_milestone_releases() {
    let env = Env::default();
    env.mock_all_auths();
    
    let admin = Address::generate(&env);
    let contract_id = env.register_contract(None, TreasuryContract);
    let client = TreasuryContractClient::new(&env, &contract_id);
    client.initialize(&soroban_sdk::String::from_str(&env, "org"), &admin);
    
    let token = env.register_stellar_asset_contract_v2(admin.clone()).address();
    let token_admin = token::StellarAssetClient::new(&env, &token);
    let token_client = token::TokenClient::new(&env, &token);
    
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
