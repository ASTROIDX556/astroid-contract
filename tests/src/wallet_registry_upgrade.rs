//! Wallet upgrade authorization sourced from the registry (Issue #524).
//!
//! The wallet no longer trusts a local admin list when replacing its code. It
//! asks the registry wired in instance storage whether the caller may roll
//! wallet code forward and whether the proposed Wasm is still approved, then
//! swaps code only when both answers are positive.

use astroid_registry::{RegistryContract, RegistryContractClient, RegistryRole};
use astroid_shared::errors::Error;
use astroid_shared::types::ModuleKind;
use astroid_wallet::{WalletContract, WalletContractClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Bytes, BytesN, Env, String};

struct Harness<'a> {
    env: Env,
    admin: Address,
    owner: Address,
    org: String,
    registry: RegistryContractClient<'a>,
    wallet: WalletContractClient<'a>,
}

fn setup() -> Harness<'static> {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);

    let registry_id = env.register_contract(None, RegistryContract);
    let registry = RegistryContractClient::new(&env, &registry_id);
    registry.initialize(&admin);

    let owner = Address::generate(&env);
    let org = String::from_str(&env, "acme");
    registry.register_org(&admin, &org, &owner);

    let wallet_id = env.register_contract(None, WalletContract);
    let wallet = WalletContractClient::new(&env, &wallet_id);
    wallet.initialize(&admin);
    wallet.set_registry(&admin, &registry_id);
    wallet.set_org(&admin, &org);

    Harness {
        env,
        admin,
        owner,
        org,
        registry,
        wallet,
    }
}

fn approved_code(env: &Env, registry: &RegistryContractClient, admin: &Address) -> BytesN<32> {
    let wasm = [
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x00, 0x1e, 0x11, b'c', b'o', b'n', b't',
        b'r', b'a', b'c', b't', b'e', b'n', b'v', b'm', b'e', b't', b'a', b'v', b'0', 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00, 0x00,
    ];
    let code = env
        .deployer()
        .upload_contract_wasm(Bytes::from_slice(env, &wasm));
    registry.add_approved_wasm(admin, &ModuleKind::Wallet, &code);
    code
}

#[test]
fn protocol_maintainer_upgrades_when_registry_authorizes_caller_and_code() {
    let h = setup();
    let code = approved_code(&h.env, &h.registry, &h.admin);

    assert!(h
        .registry
        .is_upgrade_authorized(&h.org, &h.admin, &ModuleKind::Wallet));
    assert!(h.registry.is_wasm_approved(&ModuleKind::Wallet, &code));

    h.wallet.upgrade(&h.admin, &code);
}

#[test]
fn delegated_governance_upgrader_is_accepted_by_the_wallet() {
    let h = setup();
    let upgrader = Address::generate(&h.env);
    h.registry
        .grant_role(&h.owner, &h.org, &upgrader, &RegistryRole::ModuleUpgrader);
    let code = approved_code(&h.env, &h.registry, &h.admin);

    assert!(h
        .registry
        .is_upgrade_authorized(&h.org, &upgrader, &ModuleKind::Wallet));
    h.wallet.upgrade(&upgrader, &code);
}

#[test]
fn unauthorized_key_cannot_upgrade_registry_approved_code() {
    let h = setup();
    let stranger = Address::generate(&h.env);
    let code = approved_code(&h.env, &h.registry, &h.admin);

    assert!(!h
        .registry
        .is_upgrade_authorized(&h.org, &stranger, &ModuleKind::Wallet));
    assert_eq!(
        h.wallet.try_upgrade(&stranger, &code),
        Err(Ok(Error::Unauthorized))
    );
}

#[test]
fn revoking_the_registry_role_immediately_blocks_the_upgrade() {
    let h = setup();
    let upgrader = Address::generate(&h.env);
    h.registry
        .grant_role(&h.owner, &h.org, &upgrader, &RegistryRole::ModuleUpgrader);
    h.registry.revoke_role(&h.owner, &h.org, &upgrader);
    let code = approved_code(&h.env, &h.registry, &h.admin);

    assert_eq!(
        h.wallet.try_upgrade(&upgrader, &code),
        Err(Ok(Error::Unauthorized))
    );
}

#[test]
fn authorized_caller_cannot_install_code_the_registry_has_not_approved() {
    let h = setup();
    let unapproved = BytesN::from_array(&h.env, &[7; 32]);

    assert_eq!(
        h.wallet.try_upgrade(&h.admin, &unapproved),
        Err(Ok(Error::Unauthorized))
    );
}

#[test]
fn upgrade_without_a_registry_is_not_initialized() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let wallet_id = env.register_contract(None, WalletContract);
    let wallet = WalletContractClient::new(&env, &wallet_id);
    wallet.initialize(&admin);
    let code = BytesN::from_array(&env, &[7; 32]);

    assert_eq!(
        wallet.try_upgrade(&admin, &code),
        Err(Ok(Error::NotInitialized))
    );
}
