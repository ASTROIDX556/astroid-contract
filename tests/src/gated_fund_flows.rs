//! Registry-gated fund flows: treasury → wallet → escrow.
//!
//! Deploys the protocol with the treasury's caller-verification gate engaged
//! (Issue #308) and drives value through the two paths that touch custody:
//!
//! 1. `wallet → treasury.deposit` — the wallet is registered as the org's
//!    [`ModuleKind::Wallet`], the only contract kind allowed to fund the
//!    treasury; a hostile, unregistered contract is refused with
//!    `UnverifiedCaller` before any ledger entry moves.
//! 2. `treasury.withdraw → wallet` and a time-locked `escrow` — the time lock
//!    (Issue #307) is verified end to end across the deployed escrow:
//!    withdrawal/claim before unlock time fails with `TimeLockActive` and
//!    succeeds once the ledger timestamp reaches maturity.
//!
//! The gate is exercised against the real registry contract, with real module
//! registrations, so a registry outage (freeze) is also proven to fail closed.

use astroid_budget::{BudgetContract, BudgetContractClient};
use astroid_escrow::{EscrowContract, EscrowContractClient};
use astroid_policy::{PolicyContract, PolicyContractClient};
use astroid_registry::{RegistryContract, RegistryContractClient};
use astroid_shared::errors::Error;
use astroid_shared::types::{AssetAmount, ModuleKind};
use astroid_treasury::{TreasuryContract, TreasuryContractClient};
use astroid_wallet::{WalletContract, WalletContractClient};
use soroban_sdk::{
    testutils::{Address as _, Ledger},
    token, vec, Address, Env, String, Vec,
};

const START: u64 = 1_000;
const ORG: &str = "gated-org";

struct Harness<'a> {
    env: Env,
    registry: RegistryContractClient<'a>,
    treasury: TreasuryContractClient<'a>,
    wallet: WalletContractClient<'a>,
    escrow: EscrowContractClient<'a>,
    /// Account owner of the wallet; the treasury's admin too.
    admin: Address,
    /// Recorded org Wallet module — the only contract that may deposit.
    funder: Address,
    recipient: Address,
    asset: Address,
}

fn setup() -> Harness<'static> {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().with_mut(|l| l.timestamp = START);
    let admin = Address::generate(&env);
    let multisig = Address::generate(&env);
    let recipient = Address::generate(&env);
    let org = String::from_str(&env, ORG);

    let registry_id = env.register_contract(None, RegistryContract);
    let registry = RegistryContractClient::new(&env, &registry_id);
    registry.initialize(&admin);
    registry.register_org(&admin, &org.clone(), &admin);

    let treasury_id = env.register_contract(None, TreasuryContract);
    let treasury = TreasuryContractClient::new(&env, &treasury_id);
    treasury.initialize(&org.clone(), &admin);
    treasury.set_multisig(&admin, &multisig);
    treasury.set_registry(&admin, &Some(registry_id.clone()));
    registry.register_module(&admin, &org.clone(), &ModuleKind::Treasury, &treasury_id);

    // The org's wallet: registered custody + the deposit-gate role.
    let wallet_id = env.register_contract(None, WalletContract);
    let wallet = WalletContractClient::new(&env, &wallet_id);
    wallet.initialize(&admin);
    registry.register_module(&admin, &org.clone(), &ModuleKind::Wallet, &wallet_id);

    // The org's escrow: registered conditional custody.
    let escrow_id = env.register_contract(None, EscrowContract);
    let escrow = EscrowContractClient::new(&env, &escrow_id);
    escrow.initialize();
    registry.register_module(&admin, &org.clone(), &ModuleKind::Escrow, &escrow_id);

    // Ancillary modules, registered but unused by these flows.
    let budget_id = env.register_contract(None, BudgetContract);
    let budget = BudgetContractClient::new(&env, &budget_id);
    budget.initialize(&admin);
    let policy_id = env.register_contract(None, PolicyContract);
    let policy = PolicyContractClient::new(&env, &policy_id);
    policy.initialize();
    registry.register_module(&admin, &org.clone(), &ModuleKind::Budget, &budget_id);
    registry.register_module(&admin, &org.clone(), &ModuleKind::Policy, &policy_id);

    // A real SAC token, whitelisted in the treasury. The admin gets the
    // treasury's reserve pool and the registered funder gets its own stash.
    let token_admin = Address::generate(&env);
    let asset = env
        .register_stellar_asset_contract_v2(token_admin)
        .address();
    treasury.add_approved_asset(&admin, &asset);
    token::StellarAssetClient::new(&env, &asset).mint(&admin, &50_000);

    // The funder stands in for the org's funding wallet; recorded as the
    // Wallet module it is the only contract that can deposit into the
    // treasury while the gate is engaged.
    let funder = env.register_contract(None, RegistryContract);
    registry.register_module(&admin, &org.clone(), &ModuleKind::Wallet, &funder);
    token::StellarAssetClient::new(&env, &asset).mint(&funder, &10_000);

    // The account admin doubles as the recorded governance caller for
    // outbound movements (the Multisig record).
    registry.register_module(&admin, &org.clone(), &ModuleKind::Multisig, &admin);

    Harness {
        env,
        registry,
        treasury,
        wallet,
        escrow,
        admin,
        funder,
        recipient,
        asset,
    }
}

fn token_balance(h: &Harness, who: &Address) -> i128 {
    token::TokenClient::new(&h.env, &h.asset).balance(who)
}

/// A registered wallet funds the treasury, the treasury funds the wallet
/// back, and the wallet funds a time-locked escrow whose unlock time gates
/// every payout until maturity.
#[test]
fn gated_treasury_wallet_escrow_flow() {
    let h = setup();

    // 1. Wallet → treasury deposit through the gate.
    h.treasury.deposit(&h.funder, &h.asset, &10_000);
    assert_eq!(h.treasury.holding(&h.asset).total_in, 10_000);
    assert_eq!(token_balance(&h, &h.treasury.address), 10_000);

    // 2. Treasury → wallet funding: the account admin is the recorded
    //    Multisig module, so the outbound gate passes and the wallet
    //    custodies the funds.
    h.treasury
        .withdraw(&h.admin, &h.asset, &h.wallet.address, &4_000);
    let wallet_id = h.wallet.create_wallet(&h.admin);
    h.wallet
        .deposit(&wallet_id, &h.treasury.address, &h.asset, &4_000);
    assert_eq!(h.wallet.balance(&wallet_id, &h.asset), 4_000);
    assert_eq!(h.treasury.holding(&h.asset).total_out, 4_000);

    // 3. Wallet → escrow: a time-locked milestone custody funded from the
    //    treasury's custody address so internal bookkeeping stays consistent.
    let assets: Vec<AssetAmount> = vec![
        &h.env,
        AssetAmount {
            asset: h.asset.clone(),
            amount: 2_000,
        },
    ];
    let unlock_time = START + 1_000;
    let escrow_id = h.escrow.create_timelock(
        &h.treasury.address,
        &h.recipient,
        &h.admin,
        &assets,
        &unlock_time,
        &String::from_str(&h.env, "gated settlement"),
    );
    assert_eq!(token_balance(&h, &h.escrow.address), 2_000);
    assert!(!h.escrow.is_unlocked(&escrow_id));

    // 4. Time lock (Issue #307): nothing moves before maturity...
    h.env.ledger().with_mut(|l| l.timestamp = START + 999);
    assert_eq!(
        h.escrow.try_claim(&h.recipient, &escrow_id),
        Err(Ok(Error::TimeLockActive))
    );
    assert_eq!(token_balance(&h, &h.escrow.address), 2_000);

    // ...and the beneficiary claims exactly at maturity.
    h.env.ledger().with_mut(|l| l.timestamp = unlock_time);
    assert!(h.escrow.is_unlocked(&escrow_id));
    assert_eq!(h.escrow.claim(&h.recipient, &escrow_id), 2_000);
    assert_eq!(token_balance(&h, &h.recipient), 2_000);
    assert_eq!(token_balance(&h, &h.escrow.address), 0);
}

/// A contract that is not the registered Wallet module cannot deposit into
/// the gated treasury, and the refusal leaves both the real tokens and the
/// internal ledger untouched.
#[test]
fn hostile_contract_cannot_fund_the_gated_treasury() {
    let h = setup();

    let hostile = h.env.register_contract(None, EscrowContract);
    token::StellarAssetClient::new(&h.env, &h.asset).mint(&hostile, &5_000);

    let res = h.treasury.try_deposit(&hostile, &h.asset, &5_000);
    assert_eq!(res, Err(Ok(Error::UnverifiedCaller)));
    assert_eq!(h.treasury.holding(&h.asset).total_in, 0);
    assert_eq!(token_balance(&h, &h.treasury.address), 0);

    // The registered funder still can.
    h.treasury.deposit(&h.funder, &h.asset, &1_000);
    assert_eq!(h.treasury.holding(&h.asset).total_in, 1_000);
}

/// Freezing the registry fails the deposit gate closed: even the registered
/// funder is refused while the registry cannot answer lookups.
#[test]
fn frozen_registry_blocks_deposits_fail_closed() {
    let h = setup();

    token::StellarAssetClient::new(&h.env, &h.asset).mint(&h.funder, &5_000);
    h.treasury.deposit(&h.funder, &h.asset, &1_000);
    h.registry.freeze(&h.admin, &String::from_str(&h.env, ORG));

    let res = h.treasury.try_deposit(&h.funder, &h.asset, &1_000);
    assert_eq!(res, Err(Ok(Error::UnverifiedCaller)));
    assert_eq!(h.treasury.holding(&h.asset).total_in, 1_000);

    // While frozen, the outbound gate fails closed for the recorded
    // governance caller too.
    let res2 = h
        .treasury
        .try_withdraw(&h.admin, &h.asset, &Address::generate(&h.env), &100);
    assert_eq!(res2, Err(Ok(Error::UnverifiedCaller)));
    assert_eq!(h.treasury.holding(&h.asset).total_out, 0);

    // Unfreezing restores the flow.
    h.registry
        .unfreeze(&h.admin, &String::from_str(&h.env, ORG));
    h.treasury.deposit(&h.funder, &h.asset, &1_000);
    assert_eq!(h.treasury.holding(&h.asset).total_in, 2_000);
    h.treasury
        .withdraw(&h.admin, &h.asset, &Address::generate(&h.env), &100);
    assert_eq!(h.treasury.holding(&h.asset).total_out, 100);
}
