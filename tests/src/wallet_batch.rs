//! Cross-contract batch execution (Issue #301).
//!
//! The wallet's `batch_execute` fires several sub-calls atomically in one
//! Soroban invocation. The wallet-side unit tests cover the full validation
//! matrix; here the same entrypoint is driven through *deployed contract
//! boundaries* from outside the wallet crate, with a real Stellar Asset
//! Contract as the batch callee, to prove the entrypoint and its
//! `ContractCall` payload decode correctly across crates and that a failing
//! sub-call reverts the whole batch through the host's own rollback.

use astroid_shared::errors::Error;
use astroid_wallet::{ContractCall, WalletContractClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{token, Address, Env, IntoVal, Symbol, Vec};

/// Deploy the wallet, create a wallet for `owner`, mint and deposit `deposit`
/// of a fresh SAC token, and grant `agent` the Agent role.
struct BatchHarness {
    env: Env,
    wallet: WalletContractClient<'static>,
    token: Address,
    custody: Address,
}

fn setup(deposit: i128) -> (BatchHarness, Address, Address, u64) {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let wallet_id = env.register_contract(None, astroid_wallet::WalletContract);
    let wallet = WalletContractClient::new(&env, &wallet_id);
    wallet.initialize(&admin);

    let owner = Address::generate(&env);
    let agent = Address::generate(&env);
    let id = wallet.create_wallet(&owner);
    wallet.grant_role(&owner, &id, &agent, &astroid_wallet::access::Role::Agent);

    let token_admin = Address::generate(&env);
    let token = env
        .register_stellar_asset_contract_v2(token_admin.clone())
        .address();
    token::StellarAssetClient::new(&env, &token).mint(&owner, &deposit);
    wallet.deposit(&id, &owner, &token, &deposit);

    let h = BatchHarness {
        env,
        wallet,
        token,
        custody: wallet_id,
    };
    (h, owner, agent, id)
}

/// Build a `ContractCall` transferring `amount` of the harness token out of
/// the wallet contract's custody to `to`.
fn custody_transfer_call(h: &BatchHarness, to: &Address, amount: i128) -> ContractCall {
    let mut args: Vec<soroban_sdk::Val> = Vec::new(&h.env);
    args.push_back(h.custody.clone().into_val(&h.env));
    args.push_back(to.clone().into_val(&h.env));
    args.push_back(amount.into_val(&h.env));
    ContractCall {
        contract_addr: h.token.clone(),
        fn_name: Symbol::new(&h.env, "transfer"),
        args,
    }
}

fn token_balance(h: &BatchHarness, who: &Address) -> i128 {
    token::TokenClient::new(&h.env, &h.token).balance(who)
}

#[test]
fn batch_execute_moves_value_across_the_contract_boundary() {
    let (h, _owner, agent, id) = setup(1_000);
    let r1 = Address::generate(&h.env);
    let r2 = Address::generate(&h.env);

    let mut calls: Vec<ContractCall> = Vec::new(&h.env);
    calls.push_back(custody_transfer_call(&h, &r1, 300));
    calls.push_back(custody_transfer_call(&h, &r2, 200));

    let executed = h.wallet.batch_execute(&agent, &id, &calls);
    assert_eq!(executed, 2);
    assert_eq!(token_balance(&h, &r1), 300);
    assert_eq!(token_balance(&h, &r2), 200);
    assert_eq!(token_balance(&h, &h.custody), 500);
}

#[test]
fn batch_execute_failure_reverts_every_leg_across_contracts() {
    let (h, _owner, agent, id) = setup(100);
    let r1 = Address::generate(&h.env);
    let r2 = Address::generate(&h.env);

    // The second leg overdraws the 100-token custody, failing after the
    // first leg already succeeded.
    let mut calls: Vec<ContractCall> = Vec::new(&h.env);
    calls.push_back(custody_transfer_call(&h, &r1, 60));
    calls.push_back(custody_transfer_call(&h, &r2, 80));

    let res = h.wallet.try_batch_execute(&agent, &id, &calls);
    assert!(res.is_err(), "overdrawing leg must fail the batch");

    // Cross-contract rollback: the first leg's 60 tokens never left custody.
    assert_eq!(token_balance(&h, &r1), 0);
    assert_eq!(token_balance(&h, &r2), 0);
    assert_eq!(token_balance(&h, &h.custody), 100);
}

#[test]
fn batch_execute_requires_a_wallet_role_across_contracts() {
    let (h, _owner, _agent, id) = setup(100);
    let stranger = Address::generate(&h.env);

    let mut calls: Vec<ContractCall> = Vec::new(&h.env);
    calls.push_back(custody_transfer_call(&h, &Address::generate(&h.env), 10));

    let res = h.wallet.try_batch_execute(&stranger, &id, &calls);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));

    // Payload guards are enforced at the boundary too.
    let empty: Vec<ContractCall> = Vec::new(&h.env);
    assert_eq!(
        h.wallet.try_batch_execute(&stranger, &id, &empty),
        Err(Ok(Error::Unauthorized))
    );
}

#[test]
fn batch_execute_empty_batch_is_refused_at_the_boundary() {
    let (h, owner, _agent, id) = setup(100);
    let empty: Vec<ContractCall> = Vec::new(&h.env);
    let res = h.wallet.try_batch_execute(&owner, &id, &empty);
    assert_eq!(res, Err(Ok(Error::InvalidInput)));
}

#[test]
fn batch_execute_callee_error_surfaces_deterministically() {
    let (h, _owner, agent, id) = setup(100);

    // Calling a function that does not exist on the token contract fails at
    // the system level and is reported as BatchCallFailed.
    let mut calls: Vec<ContractCall> = Vec::new(&h.env);
    calls.push_back(ContractCall {
        contract_addr: h.token.clone(),
        fn_name: Symbol::new(&h.env, "no_such_function"),
        args: Vec::new(&h.env),
    });
    let res = h.wallet.try_batch_execute(&agent, &id, &calls);
    assert_eq!(res, Err(Ok(Error::BatchCallFailed)));
}
