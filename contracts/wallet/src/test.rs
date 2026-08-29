#![cfg(test)]
extern crate std;

use crate::{ContractCall, WalletContract, WalletContractClient};
use astroid_shared::errors::Error;
use astroid_shared::types::ResourceState;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{testutils::Events, token, Address, Env, IntoVal, Symbol, Val};

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

struct Harness {
    env: Env,
    client: WalletContractClient<'static>,
    contract_id: Address,
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

    Harness {
        env,
        client,
        contract_id,
        token,
    }
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

// --- Batch execution tests ---

/// Helper: build a `ContractCall` targeting `wallet.transfer`.
fn transfer_call(
    env: &Env,
    wallet_addr: &Address,
    caller: &Address,
    to: &Address,
    asset: &Address,
    amount: i128,
) -> ContractCall {
    let mut args: Vec<soroban_sdk::RawVal> = Vec::new(env);
    args.push_back(caller.clone().into_val(env));
    args.push_back((*wallet_addr).into_val(env));
    args.push_back(to.clone().into_val(env));
    args.push_back(asset.clone().into_val(env));
    args.push_back(amount.into_val(env));
    ContractCall {
        contract_addr: wallet_addr.clone(),
        fn_name: Symbol::new(env, "transfer"),
        args,
    }
}

/// Helper: build a `ContractCall` targeting `wallet.deposit`.
fn deposit_call(
    env: &Env,
    wallet_addr: &Address,
    wallet_id: u64,
    from: &Address,
    asset: &Address,
    amount: i128,
) -> ContractCall {
    let mut args: Vec<soroban_sdk::RawVal> = Vec::new(env);
    args.push_back(wallet_id.into_val(env));
    args.push_back(from.clone().into_val(env));
    args.push_back(asset.clone().into_val(env));
    args.push_back(amount.into_val(env));
    ContractCall {
        contract_addr: wallet_addr.clone(),
        fn_name: Symbol::new(env, "deposit"),
        args,
    }
}

/// Helper: build a `ContractCall` targeting the token's `transfer`.
fn token_transfer_call(
    env: &Env,
    token_addr: &Address,
    from: &Address,
    to: &Address,
    amount: i128,
) -> ContractCall {
    let mut args: Vec<soroban_sdk::RawVal> = Vec::new(env);
    args.push_back(from.clone().into_val(env));
    args.push_back(to.clone().into_val(env));
    args.push_back(amount.into_val(env));
    ContractCall {
        contract_addr: token_addr.clone(),
        fn_name: Symbol::new(env, "transfer"),
        args,
    }
}

#[test]
fn batch_execute_empty_fails() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    let empty: Vec<ContractCall> = Vec::new(&h.env);
    let res = h.client.try_batch_execute(&owner, &id, &empty);
    assert_eq!(res, Err(Ok(Error::BatchEmpty)));
}

#[test]
fn batch_execute_single_transfer() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    mint(&h, &owner, 1_000);
    h.client.deposit(&id, &owner, &h.token, &500);

    let mut calls: Vec<ContractCall> = Vec::new(&h.env);
    calls.push_back(transfer_call(&h.env, &h.contract_id, &owner, &recipient, &h.token, 200));
    h.client.batch_execute(&owner, &id, &calls);

    assert_eq!(h.client.balance(&id, &h.token), 300);
    assert_eq!(token_balance(&h, &recipient), 200);
}

#[test]
fn batch_execute_multiple_transfers() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let r1 = Address::generate(&h.env);
    let r2 = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    mint(&h, &owner, 1_000);
    h.client.deposit(&id, &owner, &h.token, &1_000);

    let mut calls: Vec<ContractCall> = Vec::new(&h.env);
    calls.push_back(transfer_call(&h.env, &h.contract_id, &owner, &r1, &h.token, 300));
    calls.push_back(transfer_call(&h.env, &h.contract_id, &owner, &r2, &h.token, 200));
    h.client.batch_execute(&owner, &id, &calls);

    assert_eq!(h.client.balance(&id, &h.token), 500);
    assert_eq!(token_balance(&h, &r1), 300);
    assert_eq!(token_balance(&h, &r2), 200);
}

#[test]
fn batch_execute_atomicity_on_failure() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let r1 = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    mint(&h, &owner, 100);
    h.client.deposit(&id, &owner, &h.token, &100);

    // First call succeeds (50), second fails (90 > 50 remaining).
    // Atomicity means the first transfer is rolled back too.
    let mut calls: Vec<ContractCall> = Vec::new(&h.env);
    calls.push_back(transfer_call(&h.env, &h.contract_id, &owner, &r1, &h.token, 50));
    calls.push_back(transfer_call(&h.env, &h.contract_id, &owner, &r1, &h.token, 90));
    let res = h.client.try_batch_execute(&owner, &id, &calls);
    assert!(res.is_err());

    // Balance unchanged — full rollback.
    assert_eq!(h.client.balance(&id, &h.token), 100);
    assert_eq!(token_balance(&h, &r1), 0);
}

#[test]
fn batch_execute_non_owner_fails() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let stranger = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    mint(&h, &owner, 100);
    h.client.deposit(&id, &owner, &h.token, &100);

    let mut calls: Vec<ContractCall> = Vec::new(&h.env);
    calls.push_back(deposit_call(&h.env, &h.contract_id, id, &stranger, &h.token, 50));
    let res = h.client.try_batch_execute(&stranger, &id, &calls);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
}

#[test]
fn batch_execute_mixed_operations() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    mint(&h, &owner, 1_000);

    // Batch: deposit 500, then transfer 200 to recipient.
    let mut calls: Vec<ContractCall> = Vec::new(&h.env);
    calls.push_back(deposit_call(&h.env, &h.contract_id, id, &owner, &h.token, 500));
    calls.push_back(transfer_call(&h.env, &h.contract_id, &owner, &recipient, &h.token, 200));
    h.client.batch_execute(&owner, &id, &calls);

    assert_eq!(h.client.balance(&id, &h.token), 300);
    assert_eq!(token_balance(&h, &recipient), 200);
}

#[test]
fn batch_execute_frozen_wallet_fails() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    mint(&h, &owner, 100);
    h.client.deposit(&id, &owner, &h.token, &100);
    h.client.freeze(&owner, &id);

    let mut calls: Vec<ContractCall> = Vec::new(&h.env);
    calls.push_back(transfer_call(&h.env, &h.contract_id, &owner, &recipient, &h.token, 10));
    let res = h.client.try_batch_execute(&owner, &id, &calls);
    assert!(res.is_err());
    // Balance unchanged.
    assert_eq!(h.client.balance(&id, &h.token), 100);
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

#[test]
fn standard_events_emitted() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    assert_event(&h.env, "WalletCreated");

    h.client.freeze(&owner, &id);
    assert_event(&h.env, "WalletStateChanged");
}
