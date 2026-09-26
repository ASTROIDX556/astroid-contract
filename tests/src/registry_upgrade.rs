//! Registry-gated upgrade verification across contracts (Issue #217).
//!
//! The registry is the source of truth for which implementation code may back
//! each module kind. These tests drive that rule from the outside: a real
//! member contract (the wallet) consults the registry before swapping its code,
//! and a consumer contract resolves a version through the registry's
//! verification surface with a cross-contract call.

use astroid_registry::{RegistryContract, RegistryContractClient};
use astroid_shared::errors::Error;
use astroid_shared::types::ModuleKind;
use astroid_wallet::{WalletContract, WalletContractClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{contract, contractimpl, Address, BytesN, Env};

/// Test-only consumer that resolves an upgrade target through the registry,
/// the way a deployer contract would before acting on it.
#[contract]
pub struct UpgradePlanner;

#[contractimpl]
impl UpgradePlanner {
    /// Return the address of `(kind, version)` only if it runs `wasm_hash`,
    /// surfacing the registry's error code unchanged otherwise.
    pub fn resolve(
        env: Env,
        registry: Address,
        kind: ModuleKind,
        version: u32,
        wasm_hash: BytesN<32>,
    ) -> Result<Address, Error> {
        match RegistryContractClient::new(&env, &registry)
            .try_verify_version(&kind, &version, &wasm_hash)
        {
            Ok(Ok(address)) => Ok(address),
            Err(Ok(error)) => Err(error),
            _ => panic!("registry returned an undecodable result"),
        }
    }
}

struct Harness<'a> {
    env: Env,
    admin: Address,
    registry: RegistryContractClient<'a>,
    wallet: WalletContractClient<'a>,
    planner: UpgradePlannerClient<'a>,
}

fn setup() -> Harness<'static> {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);

    let registry_id = env.register_contract(None, RegistryContract);
    let registry = RegistryContractClient::new(&env, &registry_id);
    registry.initialize(&admin);

    let wallet_id = env.register_contract(None, WalletContract);
    let wallet = WalletContractClient::new(&env, &wallet_id);
    wallet.initialize(&admin);
    wallet.set_upgrade_authority(&admin, &admin, &registry_id);

    let planner_id = env.register_contract(None, UpgradePlanner);
    let planner = UpgradePlannerClient::new(&env, &planner_id);

    Harness {
        env,
        admin,
        registry,
        wallet,
        planner,
    }
}

fn hash(env: &Env, seed: u8) -> BytesN<32> {
    BytesN::from_array(env, &[seed; 32])
}

#[test]
fn verified_version_resolves_across_contracts() {
    let h = setup();
    let v2 = Address::generate(&h.env);
    let code = hash(&h.env, 2);
    h.registry
        .add_approved_wasm(&h.admin, &ModuleKind::Wallet, &code);
    h.registry
        .register_version(&h.admin, &ModuleKind::Wallet, &2, &v2, &code);

    assert_eq!(
        h.planner
            .resolve(&h.registry.address, &ModuleKind::Wallet, &2, &code),
        v2
    );
    assert_eq!(h.registry.get_latest(&ModuleKind::Wallet), v2);
}

#[test]
fn consumer_sees_deterministic_errors_for_bad_targets() {
    let h = setup();
    let v1 = Address::generate(&h.env);
    let code = hash(&h.env, 1);
    let other = hash(&h.env, 9);
    h.registry
        .add_approved_wasm(&h.admin, &ModuleKind::Wallet, &code);
    h.registry
        .register_version(&h.admin, &ModuleKind::Wallet, &1, &v1, &code);

    let registry = &h.registry.address;
    // Unknown version.
    assert_eq!(
        h.planner
            .try_resolve(registry, &ModuleKind::Wallet, &7, &code),
        Err(Ok(Error::NotFound))
    );
    // Known version, wrong code.
    assert_eq!(
        h.planner
            .try_resolve(registry, &ModuleKind::Wallet, &1, &other),
        Err(Ok(Error::InvalidInput))
    );
    // Code revoked after registration.
    h.registry
        .remove_approved_wasm(&h.admin, &ModuleKind::Wallet, &code);
    assert_eq!(
        h.planner
            .try_resolve(registry, &ModuleKind::Wallet, &1, &code),
        Err(Ok(Error::Unauthorized))
    );
}

#[test]
fn stranger_cannot_publish_a_version_or_approve_its_code() {
    let h = setup();
    let attacker = Address::generate(&h.env);
    let malicious = Address::generate(&h.env);
    let code = hash(&h.env, 66);

    assert_eq!(
        h.registry
            .try_add_approved_wasm(&attacker, &ModuleKind::Wallet, &code),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(
        h.registry
            .try_register_version(&attacker, &ModuleKind::Wallet, &1, &malicious, &code),
        Err(Ok(Error::Unauthorized))
    );
    // Even the admin cannot publish code that was never approved.
    assert_eq!(
        h.registry
            .try_register_version(&h.admin, &ModuleKind::Wallet, &1, &malicious, &code),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(
        h.registry.try_get_latest(&ModuleKind::Wallet),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn member_upgrade_requires_its_upgrade_admin() {
    let h = setup();
    let stranger = Address::generate(&h.env);
    let code = hash(&h.env, 3);
    h.registry
        .add_approved_wasm(&h.admin, &ModuleKind::Wallet, &code);

    // Approved code, wrong caller: the wallet refuses before touching its code.
    assert_eq!(
        h.wallet.try_upgrade(&stranger, &code),
        Err(Ok(Error::Unauthorized))
    );
}

#[test]
fn member_upgrade_refuses_code_not_approved_for_its_kind() {
    let h = setup();
    let unapproved = hash(&h.env, 4);
    let treasury_code = hash(&h.env, 5);
    h.registry
        .add_approved_wasm(&h.admin, &ModuleKind::Treasury, &treasury_code);

    assert_eq!(
        h.wallet.try_upgrade(&h.admin, &unapproved),
        Err(Ok(Error::Unauthorized))
    );
    // Approval for another kind does not satisfy the wallet's gate.
    assert_eq!(
        h.wallet.try_upgrade(&h.admin, &treasury_code),
        Err(Ok(Error::Unauthorized))
    );
}

#[test]
fn revoking_code_stops_member_upgrades_and_version_verification() {
    let h = setup();
    let v1 = Address::generate(&h.env);
    let code = hash(&h.env, 6);
    h.registry
        .add_approved_wasm(&h.admin, &ModuleKind::Wallet, &code);
    h.registry
        .register_version(&h.admin, &ModuleKind::Wallet, &1, &v1, &code);
    h.registry
        .remove_approved_wasm(&h.admin, &ModuleKind::Wallet, &code);

    assert_eq!(
        h.wallet.try_upgrade(&h.admin, &code),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(
        h.registry
            .try_verify_version(&ModuleKind::Wallet, &1, &code),
        Err(Ok(Error::Unauthorized))
    );
}
