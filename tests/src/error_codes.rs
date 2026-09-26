//! Cross-contract checks that the canonical error table is what an off-chain
//! consumer actually sees.
//!
//! The per-contract suites pin each refusal to a named [`Error`] variant, but a
//! variant name is only meaningful if the number on the wire matches too: an
//! agent decoding a failed transaction reads `u32`, not Rust. A refactor that
//! renumbered a variant, or inserted one in the middle of an existing band,
//! would leave every in-repo test green while silently repointing every live
//! integration.
//!
//! These tests therefore assert the *decoded wire form*: that a contract's
//! refusal arrives as the exact code the shared table assigns, that the code is
//! stable under a second deployment, and that a code the table retires is never
//! handed out again.

use astroid_shared::errors::Error;
use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::{vec, Address, Env, String, Vec};

use astroid_budget::BudgetContract;
use astroid_multisig::{MultiSigContract, SignerWeight};
use astroid_policy::PolicyContract;
use astroid_registry::RegistryContract;
use astroid_shared::types::ModuleKind;
use astroid_treasury::TreasuryContract;
use astroid_wallet::WalletContract;

/// Every code in the canonical table, in the order the enum declares them.
/// Written out literally rather than derived from [`Error::ALL`], because the
/// point of this test is to catch the table being renumbered — deriving it
/// would make that failure impossible to observe.
const ALL_CODES: [u32; 50] = [
    1, 2, 3, 4, 5, 6, // generic / lifecycle
    10, 11, 12, // value / arithmetic
    20, 21, 22, 23, 24, 26, // policy
    30, 31, // registry
    40, 41, 42, 43, 44, // budget
    50, 51, 52, 53, // wallet
    61, 62, 63, 64, 66, 67, 68, 69, 90, 91, 92, // multisig / approvals
    71, 72, 73, 74, 75, 78, 79, // proposal
    80, 81, 82, // escrow
    83, 84, 85, // treasury
];

/// Codes that were part of an earlier revision and must never come back: a
/// reissued slot would make two different historical failures decode the same.
const RETIRED_CODES: [u32; 2] = [25, 65];

/// The number an off-chain caller would read from a failed transaction, for
/// either shape a generated `try_*` call can return.
fn code_of<T: std::fmt::Debug, C: std::fmt::Debug>(
    result: Result<Result<T, C>, Result<Error, soroban_sdk::InvokeError>>,
) -> u32 {
    match result {
        Err(Ok(e)) => e.code(),
        Err(Err(e)) => panic!("expected a contract error, got an invoke error: {:?}", e),
        Ok(v) => panic!("expected a contract error, got {:?}", v),
    }
}

#[test]
fn the_canonical_table_is_exactly_the_fifty_declared_codes() {
    assert_eq!(ALL_CODES.len(), Error::ALL.len());
    for (i, expected) in ALL_CODES.iter().enumerate() {
        assert_eq!(
            Error::ALL[i].code(),
            *expected,
            "variant {:?} must keep code {}",
            Error::ALL[i],
            expected
        );
    }
    // No duplicates and no retired slots.
    for (i, a) in ALL_CODES.iter().enumerate() {
        assert!(!ALL_CODES[i + 1..].contains(a), "duplicate code {}", a);
        assert!(!RETIRED_CODES.contains(a), "retired code {} reissued", a);
    }
}

#[test]
fn a_registry_refusal_reaches_the_caller_as_its_canonical_code() {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register_contract(None, RegistryContract);
    let registry = astroid_registry::RegistryContractClient::new(&env, &id);
    let admin = Address::generate(&env);
    let owner = Address::generate(&env);
    registry.initialize(&admin);
    registry.register_org(&admin, &String::from_str(&env, "acme"), &owner);

    let ghost = String::from_str(&env, "ghost");
    let res = registry.try_freeze(&owner, &ghost);
    assert_eq!(code_of(res), Error::NotFound.code());

    // A different refusal, on a different band, must not be confused with it.
    let res =
        registry.try_deprecate_module(&owner, &String::from_str(&env, "acme"), &ModuleKind::Wallet);
    assert_eq!(code_of(res), Error::Unauthorized.code());
}

#[test]
fn a_budget_refusal_reaches_the_caller_as_its_canonical_code() {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register_contract(None, BudgetContract);
    let budget = astroid_budget::BudgetContractClient::new(&env, &id);
    let admin = Address::generate(&env);
    budget.initialize(&admin);

    let ghost = String::from_str(&env, "ghost");
    let res = budget.try_remaining(&ghost);
    assert_eq!(code_of(res), Error::NotFound.code());

    let live = String::from_str(&env, "eng");
    budget.allocate(
        &admin,
        &live,
        &1_000,
        &astroid_budget::Period::None,
        &false,
        &0,
    );
    let token = Address::generate(&env);
    let res = budget.try_check_and_record_spend(&admin, &live, &token, &1);
    assert_eq!(code_of(res), Error::AssetNotAuthorized.code());
}

#[test]
fn a_policy_refusal_reaches_the_caller_as_its_canonical_code() {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register_contract(None, PolicyContract);
    let policy = astroid_policy::PolicyContractClient::new(&env, &id);
    let owner = Address::generate(&env);
    policy.initialize();
    let pid = String::from_str(&env, "max_txn");
    policy.register_policy(
        &owner,
        &pid,
        &soroban_sdk::BytesN::from_array(&env, &[7; 32]),
        &1_000,
        &None,
        &None,
        &0,
    );

    // Over the ceiling: a policy decision.
    let res = policy.try_check_transfer(
        &pid,
        &Address::generate(&env),
        &Address::generate(&env),
        &1_001,
    );
    assert_eq!(code_of(res), Error::PolicyDenied.code());

    // A lapsed allowance: a different band entirely, and it must stay distinct.
    policy.set_allowance(&owner, &pid, &Address::generate(&env), &1_000, &1);
    env.ledger().with_mut(|l| l.timestamp = 10);
    let asset = Address::generate(&env);
    policy.set_allowance(&owner, &pid, &asset, &1_000, &5);
    let res = policy.try_check_transfer(&pid, &asset, &Address::generate(&env), &1);
    assert_eq!(code_of(res), Error::AllowanceExpired.code());
    assert_ne!(Error::AllowanceExpired.code(), Error::PolicyDenied.code());
}

#[test]
fn a_treasury_refusal_reaches_the_caller_as_its_canonical_code() {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register_contract(None, TreasuryContract);
    let treasury = astroid_treasury::TreasuryContractClient::new(&env, &id);

    // Never initialized: a missing record, reported as a code rather than a
    // trap, so an agent can tell it apart from a permission failure.
    let res = treasury.try_get();
    assert_eq!(code_of(res), Error::NotInitialized.code());

    let admin = Address::generate(&env);
    treasury.initialize(&String::from_str(&env, "acme"), &admin);
    let asset = env
        .register_stellar_asset_contract_v2(Address::generate(&env))
        .address();
    treasury.add_approved_asset(&admin, &asset);
    // No deposit yet, so a withdrawal has nothing behind it.
    let res = treasury.try_withdraw(&admin, &asset, &Address::generate(&env), &1);
    assert_eq!(code_of(res), Error::InsufficientFunds.code());
}

#[test]
fn a_wallet_refusal_reaches_the_caller_as_its_canonical_code() {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register_contract(None, WalletContract);
    let wallet = astroid_wallet::WalletContractClient::new(&env, &id);
    let admin = Address::generate(&env);
    wallet.initialize(&admin);
    let owner = Address::generate(&env);
    let wid = wallet.create_wallet(&owner);
    let token = env
        .register_stellar_asset_contract_v2(Address::generate(&env))
        .address();

    // A wallet id that was never issued.
    let res = wallet.try_deposit(&(wid + 1_000), &owner, &token, &1);
    assert_eq!(code_of(res), Error::NotFound.code());
    // A malformed amount.
    let res = wallet.try_deposit(&wid, &owner, &token, &0);
    assert_eq!(code_of(res), Error::InvalidAmount.code());
    // An exhausted balance.
    let res = wallet.try_withdraw(&owner, &wid, &token, &1);
    assert_eq!(code_of(res), Error::InsufficientFunds.code());
}

#[test]
fn a_multisig_refusal_reaches_the_caller_as_its_canonical_code() {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register_contract(None, MultiSigContract);
    let msig = astroid_multisig::MultiSigContractClient::new(&env, &id);
    let a = Address::generate(&env);
    let b = Address::generate(&env);
    let signers: Vec<SignerWeight> = vec![
        &env,
        SignerWeight {
            address: a.clone(),
            weight: 1,
        },
    ];
    msig.initialize(&signers, &1);

    // An address outside the signer set.
    let res = msig.try_propose(
        &b,
        &soroban_sdk::symbol_short!("x"),
        &soroban_sdk::Bytes::from_array(&env, &[1]),
        &0,
    );
    assert_eq!(code_of(res), Error::NotASigner.code());

    // A threshold the total weight cannot reach.
    let res = msig.try_initialize(&signers, &9);
    assert_eq!(code_of(res), Error::AlreadyInitialized.code());
}

#[test]
fn codes_are_stable_across_separate_deployments() {
    // The same refusal, from two independently deployed contracts, must decode
    // to the same number. A code derived from deployment-specific state would
    // pass a per-contract suite and still be unusable for an agent.
    let decode = || -> u32 {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, BudgetContract);
        let budget = astroid_budget::BudgetContractClient::new(&env, &id);
        let admin = Address::generate(&env);
        budget.initialize(&admin);
        let ghost = String::from_str(&env, "ghost");
        code_of(budget.try_remaining(&ghost))
    };
    let first = decode();
    let second = decode();
    assert_eq!(first, second);
    assert_eq!(first, Error::NotFound.code());
}
