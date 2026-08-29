#![cfg(test)]
extern crate std;

use crate::{RateLimitConfig, RateUsage, WalletContract, WalletContractClient};
use astroid_shared::errors::Error;
use astroid_shared::types::ResourceState;
use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::{token, Address, Env};

struct Harness {
    env: Env,
    client: WalletContractClient<'static>,
    token: Address,
}

fn setup() -> Harness {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let contract_id = env.register_contract(None, WalletContract);
    let client = WalletContractClient::new(&env, &contract_id);
    client.initialize(&admin);

    // A test SAC token whose admin can mint funds to users.
    let token_admin = Address::generate(&env);
    let token = env
        .register_stellar_asset_contract_v2(token_admin.clone())
        .address();

    Harness { env, client, token }
}

fn mint(h: &Harness, to: &Address, amount: i128) {
    let sac = token::StellarAssetClient::new(&h.env, &h.token);
    sac.mint(to, &amount);
}

fn token_balance(h: &Harness, who: &Address) -> i128 {
    token::TokenClient::new(&h.env, &h.token).balance(who)
}

#[test]
fn create_wallet_starts_active() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    let w = h.client.get_wallet(&id);
    assert_eq!(w.owner, owner);
    assert_eq!(w.state, ResourceState::Active);
}

#[test]
fn deposit_credits_internal_balance_and_moves_tokens() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    mint(&h, &owner, 1_000);

    h.client.deposit(&id, &owner, &h.token, &400);
    assert_eq!(h.client.balance(&id, &h.token), 400);
    assert_eq!(token_balance(&h, &owner), 600);
}

#[test]
fn transfer_moves_value_and_debits_wallet() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    mint(&h, &owner, 1_000);
    h.client.deposit(&id, &owner, &h.token, &1_000);

    h.client.transfer(&owner, &id, &recipient, &h.token, &250);
    assert_eq!(h.client.balance(&id, &h.token), 750);
    assert_eq!(token_balance(&h, &recipient), 250);
}

#[test]
fn withdraw_returns_to_owner() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    mint(&h, &owner, 1_000);
    h.client.deposit(&id, &owner, &h.token, &1_000);

    h.client.withdraw(&owner, &id, &h.token, &300);
    assert_eq!(h.client.balance(&id, &h.token), 700);
    assert_eq!(token_balance(&h, &owner), 300);
}

#[test]
fn transfer_more_than_balance_fails() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    mint(&h, &owner, 100);
    h.client.deposit(&id, &owner, &h.token, &100);

    let res = h
        .client
        .try_transfer(&owner, &id, &recipient, &h.token, &500);
    assert_eq!(res, Err(Ok(Error::InsufficientFunds)));
}

#[test]
fn non_owner_cannot_transfer() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let intruder = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    mint(&h, &owner, 100);
    h.client.deposit(&id, &owner, &h.token, &100);

    let res = h
        .client
        .try_transfer(&intruder, &id, &recipient, &h.token, &10);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
}

#[test]
fn transfer_while_frozen_fails_wallet_frozen() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    mint(&h, &owner, 100);
    h.client.deposit(&id, &owner, &h.token, &100);

    h.client.freeze(&owner, &id);
    assert_eq!(h.client.get_wallet(&id).state, ResourceState::Frozen);

    let res = h
        .client
        .try_transfer(&owner, &id, &recipient, &h.token, &10);
    assert_eq!(res, Err(Ok(Error::WalletFrozen)));
}

#[test]
fn admin_can_freeze_then_owner_unfreezes() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);

    // Owner freezes, then unfreezes back to Active.
    h.client.freeze(&owner, &id);
    h.client.unfreeze(&owner, &id);
    assert_eq!(h.client.get_wallet(&id).state, ResourceState::Active);
}

#[test]
fn transfer_while_paused_fails() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    mint(&h, &owner, 100);
    h.client.deposit(&id, &owner, &h.token, &100);

    h.client.pause(&owner, &id);
    let res = h
        .client
        .try_transfer(&owner, &id, &recipient, &h.token, &10);
    assert_eq!(res, Err(Ok(Error::WalletPaused)));

    h.client.unpause(&owner, &id);
    h.client.transfer(&owner, &id, &recipient, &h.token, &10);
    assert_eq!(token_balance(&h, &recipient), 10);
}

#[test]
fn archived_wallet_rejects_transfer_and_deposit() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    mint(&h, &owner, 100);
    h.client.deposit(&id, &owner, &h.token, &100);

    h.client.archive(&owner, &id);
    assert_eq!(h.client.get_wallet(&id).state, ResourceState::Archived);

    assert_eq!(
        h.client
            .try_transfer(&owner, &id, &recipient, &h.token, &10),
        Err(Ok(Error::WalletArchived))
    );
    mint(&h, &owner, 100);
    assert_eq!(
        h.client.try_deposit(&id, &owner, &h.token, &10),
        Err(Ok(Error::WalletArchived))
    );
}

#[test]
fn zero_amount_transfer_rejected() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    let res = h.client.try_transfer(&owner, &id, &recipient, &h.token, &0);
    assert_eq!(res, Err(Ok(Error::InvalidAmount)));
}

#[test]
fn unknown_wallet_fails_not_found() {
    let h = setup();
    let stranger = Address::generate(&h.env);
    let res = h.client.try_get_wallet(&999);
    assert_eq!(res, Err(Ok(Error::NotFound)));
    let res2 = h.client.try_freeze(&stranger, &999);
    assert_eq!(res2, Err(Ok(Error::NotFound)));
}

// --- rate limiting ---

/// Fund a wallet and return a funded harness-scoped setup.
fn funded_wallet(h: &Harness, amount: i128) -> (Address, Address, u64) {
    let owner = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    mint(h, &owner, amount);
    h.client.deposit(&id, &owner, &h.token, &amount);
    (owner, recipient, id)
}

#[test]
fn rate_limit_disabled_by_default() {
    let h = setup();
    let (owner, recipient, id) = funded_wallet(&h, 1_000);
    assert_eq!(
        h.client.get_rate_limit(&id),
        RateLimitConfig {
            max_volume: 0,
            max_count: 0,
            window_seconds: 0,
        }
    );
    // No config -> transfers flow freely and no usage is recorded.
    h.client.transfer(&owner, &id, &recipient, &h.token, &400);
    h.client.transfer(&owner, &id, &recipient, &h.token, &400);
    assert_eq!(
        h.client.get_rate_usage(&id),
        RateUsage {
            volume: 0,
            count: 0
        }
    );
}

#[test]
fn rate_limit_rejects_volume_over_window_cap() {
    let h = setup();
    let (owner, recipient, id) = funded_wallet(&h, 1_000);
    h.env.ledger().set_timestamp(1_000);
    h.client.set_rate_limit(&owner, &id, &500, &100, &1_000);

    h.client.transfer(&owner, &id, &recipient, &h.token, &300);
    assert_eq!(h.client.balance(&id, &h.token), 700);
    assert_eq!(
        h.client.get_rate_usage(&id),
        RateUsage {
            volume: 300,
            count: 1
        }
    );

    // 300 + 300 > 500 window volume cap -> rejected before funds move.
    let res = h
        .client
        .try_transfer(&owner, &id, &recipient, &h.token, &300);
    assert_eq!(res, Err(Ok(Error::RateLimitExceeded)));
    assert_eq!(h.client.balance(&id, &h.token), 700);
    assert_eq!(h.client.get_rate_usage(&id).volume, 300);
}

#[test]
fn rate_limit_rejects_count_over_window_cap() {
    let h = setup();
    let (owner, recipient, id) = funded_wallet(&h, 1_000);
    h.env.ledger().set_timestamp(1_000);
    // Volume unlimited, at most 2 outbound transactions per window.
    h.client.set_rate_limit(&owner, &id, &0, &2, &1_000);

    h.client.transfer(&owner, &id, &recipient, &h.token, &10);
    h.client.transfer(&owner, &id, &recipient, &h.token, &10);
    assert_eq!(h.client.get_rate_usage(&id).count, 2);

    let res = h
        .client
        .try_transfer(&owner, &id, &recipient, &h.token, &10);
    assert_eq!(res, Err(Ok(Error::RateLimitExceeded)));
}

#[test]
fn rate_limit_resets_across_window_boundary() {
    let h = setup();
    let (owner, recipient, id) = funded_wallet(&h, 1_000);
    h.env.ledger().set_timestamp(1_000);
    h.client.set_rate_limit(&owner, &id, &500, &2, &1_000);

    h.client.transfer(&owner, &id, &recipient, &h.token, &200);
    h.client.transfer(&owner, &id, &recipient, &h.token, &200);
    // Window 1 is exhausted (2 txs / 400 volume).
    let res = h
        .client
        .try_transfer(&owner, &id, &recipient, &h.token, &100);
    assert_eq!(res, Err(Ok(Error::RateLimitExceeded)));

    // Same window (still within [1000, 2000)) stays blocked.
    h.env.ledger().set_timestamp(1_999);
    let res = h
        .client
        .try_transfer(&owner, &id, &recipient, &h.token, &100);
    assert_eq!(res, Err(Ok(Error::RateLimitExceeded)));

    // Next epoch window resets both caps.
    h.env.ledger().set_timestamp(2_000);
    h.client.transfer(&owner, &id, &recipient, &h.token, &400);
    assert_eq!(h.client.balance(&id, &h.token), 200);
    assert_eq!(
        h.client.get_rate_usage(&id),
        RateUsage {
            volume: 400,
            count: 1
        }
    );
}

#[test]
fn withdraw_counts_toward_rate_limit() {
    let h = setup();
    let (owner, _recipient, id) = funded_wallet(&h, 1_000);
    h.env.ledger().set_timestamp(1_000);
    h.client.set_rate_limit(&owner, &id, &500, &100, &1_000);

    h.client
        .transfer(&owner, &id, &Address::generate(&h.env), &h.token, &300);
    // A 300 withdraw would push the window to 600 > 500.
    let res = h.client.try_withdraw(&owner, &id, &h.token, &300);
    assert_eq!(res, Err(Ok(Error::RateLimitExceeded)));
    // A 200 withdraw fits.
    h.client.withdraw(&owner, &id, &h.token, &200);
    assert_eq!(h.client.get_rate_usage(&id).volume, 500);
}

#[test]
fn rate_limit_is_per_wallet() {
    let h = setup();
    let (owner_a, recipient_a, id_a) = funded_wallet(&h, 1_000);
    let (owner_b, recipient_b, id_b) = funded_wallet(&h, 1_000);
    h.env.ledger().set_timestamp(1_000);
    h.client.set_rate_limit(&owner_a, &id_a, &100, &1, &1_000);

    h.client
        .transfer(&owner_a, &id_a, &recipient_a, &h.token, &100);
    let res = h
        .client
        .try_transfer(&owner_a, &id_a, &recipient_a, &h.token, &10);
    assert_eq!(res, Err(Ok(Error::RateLimitExceeded)));

    // Wallet B has no limits and is unaffected.
    h.client
        .transfer(&owner_b, &id_b, &recipient_b, &h.token, &500);
    h.client
        .transfer(&owner_b, &id_b, &recipient_b, &h.token, &500);
    assert_eq!(h.client.balance(&id_b, &h.token), 0);
}

#[test]
fn rate_limit_config_requires_owner() {
    let h = setup();
    let (owner, _recipient, id) = funded_wallet(&h, 100);
    let intruder = Address::generate(&h.env);
    let res = h
        .client
        .try_set_rate_limit(&intruder, &id, &100, &10, &1_000);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
    // Owner can still configure.
    h.client.set_rate_limit(&owner, &id, &100, &10, &1_000);
    assert_eq!(h.client.get_rate_limit(&id).max_volume, 100);
}

#[test]
fn rate_limit_disabled_by_zero_window() {
    let h = setup();
    let (owner, recipient, id) = funded_wallet(&h, 1_000);
    h.env.ledger().set_timestamp(1_000);
    // window_seconds = 0 disables the feature even with caps set.
    h.client.set_rate_limit(&owner, &id, &10, &1, &0);

    h.client.transfer(&owner, &id, &recipient, &h.token, &400);
    h.client.transfer(&owner, &id, &recipient, &h.token, &400);
    assert_eq!(h.client.balance(&id, &h.token), 200);
}

#[test]
fn rate_limit_config_rejects_negative_volume() {
    let h = setup();
    let (owner, _recipient, id) = funded_wallet(&h, 100);
    let res = h.client.try_set_rate_limit(&owner, &id, &-1, &10, &1_000);
    assert_eq!(res, Err(Ok(Error::InvalidInput)));
}
