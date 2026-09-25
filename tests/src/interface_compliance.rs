//! Interface compliance across the workspace.
//!
//! Every contract that claims to serve a shared trait from `astroid-interfaces`
//! is checked twice:
//!
//! 1. **At compile time** — generic `implements_*::<Contract>()` trait-bound
//!    helpers fail the build the moment a contract's `impl Trait for Contract`
//!    block is removed or its signatures drift from the trait.
//! 2. **At runtime** — each deployed contract is driven through the generated
//!    *interface* client (not its own test client), proving the on-chain
//!    entrypoints decode the same arguments and canonical error codes the
//!    shared client expects.

use astroid_budget::BudgetContract;
use astroid_escrow::EscrowContract;
use astroid_interfaces::upgrade::UpgradeAuthority;
use astroid_interfaces::{
    BudgetClient, BudgetInterface, MultisigClient, MultisigInterface, PolicyClient,
    PolicyInterface, RegistryClient, RegistryInterface, TreasuryClient, TreasuryInterface,
    UpgradeableClient, UpgradeableInterface, INTERFACE_VERSION,
};
use astroid_multisig::{MultiSigContract, MultiSigContractClient, SignerWeight};
use astroid_policy::PolicyContract;
use astroid_proposal::ProposalContract;
use astroid_registry::RegistryContract;
use astroid_shared::errors::Error;
use astroid_shared::types::ModuleKind;
use astroid_treasury::{TreasuryContract, TreasuryContractClient};
use astroid_wallet::WalletContract;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{vec, Address, Env, String};

// ---------------------------------------------------------------------------
// Compile-time compliance
// ---------------------------------------------------------------------------

fn implements_registry<T: RegistryInterface>() {}
fn implements_policy<T: PolicyInterface>() {}
fn implements_budget<T: BudgetInterface>() {}
fn implements_treasury<T: TreasuryInterface>() {}
fn implements_multisig<T: MultisigInterface>() {}
fn implements_upgradeable<T: UpgradeableInterface>() {}

/// Never called at runtime: it exists so the trait bounds are checked by the
/// compiler for every contract listed in the `astroid-interfaces` table.
#[allow(dead_code)]
fn interface_table_compiles() {
    implements_registry::<RegistryContract>();
    implements_policy::<PolicyContract>();
    implements_budget::<BudgetContract>();
    implements_treasury::<TreasuryContract>();
    implements_multisig::<MultiSigContract>();

    implements_upgradeable::<RegistryContract>();
    implements_upgradeable::<WalletContract>();
    implements_upgradeable::<MultiSigContract>();
    implements_upgradeable::<ProposalContract>();
    implements_upgradeable::<TreasuryContract>();
    implements_upgradeable::<BudgetContract>();
    implements_upgradeable::<PolicyContract>();
    implements_upgradeable::<EscrowContract>();
}

// ---------------------------------------------------------------------------
// Runtime compliance
// ---------------------------------------------------------------------------

#[test]
fn interface_version_is_pinned() {
    // Bumping the version is a deliberate act; this catches accidental edits.
    assert_eq!(INTERFACE_VERSION, 1);
}

#[test]
fn every_contract_serves_the_upgradeable_interface() {
    let env = Env::default();
    env.mock_all_auths();

    let contracts = [
        env.register_contract(None, RegistryContract),
        env.register_contract(None, WalletContract),
        env.register_contract(None, MultiSigContract),
        env.register_contract(None, ProposalContract),
        env.register_contract(None, TreasuryContract),
        env.register_contract(None, BudgetContract),
        env.register_contract(None, PolicyContract),
        env.register_contract(None, EscrowContract),
    ];
    let admin = Address::generate(&env);
    let registry = Address::generate(&env);

    for id in contracts.iter() {
        let client = UpgradeableClient::new(&env, id);
        assert_eq!(
            client.try_get_upgrade_authority(),
            Err(Ok(Error::NotInitialized))
        );
        client.set_upgrade_authority(&admin, &admin, &registry);
        assert_eq!(
            client.get_upgrade_authority(),
            UpgradeAuthority {
                admin: admin.clone(),
                registry: registry.clone(),
            }
        );
        // A non-admin is rejected with the canonical code through the shared client.
        let intruder = Address::generate(&env);
        assert_eq!(
            client.try_set_upgrade_authority(&intruder, &intruder, &registry),
            Err(Ok(Error::Unauthorized))
        );
    }
}

#[test]
fn registry_policy_and_budget_decode_canonical_errors() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let unknown = String::from_str(&env, "missing");

    let registry_id = env.register_contract(None, RegistryContract);
    astroid_registry::RegistryContractClient::new(&env, &registry_id).initialize(&admin);
    assert_eq!(
        RegistryClient::new(&env, &registry_id).try_lookup(&unknown, &ModuleKind::Treasury),
        Err(Ok(Error::NotFound))
    );

    let policy_id = env.register_contract(None, PolicyContract);
    astroid_policy::PolicyContractClient::new(&env, &policy_id).initialize();
    let asset = Address::generate(&env);
    assert_eq!(
        PolicyClient::new(&env, &policy_id).try_check_transfer(&unknown, &asset, &admin, &1),
        Err(Ok(Error::NotFound))
    );

    let budget_id = env.register_contract(None, BudgetContract);
    astroid_budget::BudgetContractClient::new(&env, &budget_id).initialize(&admin);
    assert_eq!(
        BudgetClient::new(&env, &budget_id).try_remaining(&unknown),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn treasury_serves_the_treasury_interface() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);

    let id = env.register_contract(None, TreasuryContract);
    TreasuryContractClient::new(&env, &id).initialize(&String::from_str(&env, "acme"), &admin);

    let token_admin = Address::generate(&env);
    let asset = env
        .register_stellar_asset_contract_v2(token_admin)
        .address();

    let treasury = TreasuryClient::new(&env, &id);
    assert!(!treasury.is_paused());
    assert!(!treasury.is_approved_asset(&asset));
    assert_eq!(
        treasury.try_balance(&asset),
        Err(Ok(Error::AssetNotAuthorized))
    );

    TreasuryContractClient::new(&env, &id).add_approved_asset(&admin, &asset);
    assert!(treasury.is_approved_asset(&asset));
    assert_eq!(treasury.balance(&asset), 0);
}

#[test]
fn multisig_serves_the_multisig_interface() {
    let env = Env::default();
    env.mock_all_auths();
    let a = Address::generate(&env);
    let b = Address::generate(&env);
    let outsider = Address::generate(&env);

    let id = env.register_contract(None, MultiSigContract);
    MultiSigContractClient::new(&env, &id).initialize(
        &vec![
            &env,
            SignerWeight {
                address: a.clone(),
                weight: 2,
            },
            SignerWeight {
                address: b.clone(),
                weight: 1,
            },
        ],
        &2,
    );

    let multisig = MultisigClient::new(&env, &id);
    assert_eq!(multisig.get_threshold(), 2);
    assert!(multisig.is_signer(&a));
    assert!(!multisig.is_signer(&outsider));
    assert_eq!(multisig.get_signer_weight(&a), 2);
    assert_eq!(multisig.get_signer_weight(&outsider), 0);
}
