#![cfg(test)]
extern crate std;

use crate::{RegistryContract, RegistryContractClient};
use astroid_shared::errors::Error;
use astroid_shared::types::ModuleKind;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{Address, Env, String};

fn setup() -> (Env, RegistryContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, RegistryContract);
    let client = RegistryContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin);
    (env, client, admin)
}

#[test]
fn initialize_sets_admin() {
    let (_env, client, admin) = setup();
    assert_eq!(client.get_admin(), admin);
}

#[test]
fn initialize_twice_fails() {
    let (env, client, _admin) = setup();
    let other = Address::generate(&env);
    let res = client.try_initialize(&other);
    assert_eq!(res, Err(Ok(Error::AlreadyInitialized)));
}

#[test]
fn register_and_lookup_org_and_module() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    assert_eq!(client.get_org_owner(&org), owner);
    assert!(client.verify_owner(&org, &owner));

    let wallet = Address::generate(&env);
    client.register_module(&owner, &org, &ModuleKind::Wallet, &wallet);
    assert_eq!(client.lookup(&org, &ModuleKind::Wallet), wallet);
}

#[test]
fn duplicate_org_fails() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    let res = client.try_register_org(&admin, &org, &owner);
    assert_eq!(res, Err(Ok(Error::AlreadyExists)));
}

#[test]
fn non_admin_cannot_register_org() {
    let (env, client, _admin) = setup();
    let intruder = Address::generate(&env);
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    let res = client.try_register_org(&intruder, &org, &owner);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
}

#[test]
fn lookup_missing_module_fails() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    let res = client.try_lookup(&org, &ModuleKind::Treasury);
    assert_eq!(res, Err(Ok(Error::NotFound)));
}

#[test]
fn org_owner_can_transfer_ownership() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    let new_owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    client.set_org_owner(&owner, &org, &new_owner);
    assert_eq!(client.get_org_owner(&org), new_owner);
}

#[test]
fn stranger_cannot_transfer_ownership() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    let stranger = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    let res = client.try_set_org_owner(&stranger, &org, &stranger);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
}

#[test]
fn version_lookup_upgrade_strategy() {
    let (env, client, admin) = setup();
    let v1 = Address::generate(&env);
    let v2 = Address::generate(&env);
    client.register_version(&admin, &ModuleKind::Wallet, &1, &v1);
    client.register_version(&admin, &ModuleKind::Wallet, &2, &v2);
    assert_eq!(client.get_version(&ModuleKind::Wallet, &1), v1);
    assert_eq!(client.get_version(&ModuleKind::Wallet, &2), v2);
    // Latest points at the highest registered version.
    assert_eq!(client.get_latest(&ModuleKind::Wallet), v2);
}

#[test]
fn register_version_zero_fails() {
    let (env, client, admin) = setup();
    let addr = Address::generate(&env);
    let res = client.try_register_version(&admin, &ModuleKind::Wallet, &0, &addr);
    assert_eq!(res, Err(Ok(Error::InvalidInput)));
}

#[test]
fn remove_module_works_and_missing_fails() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    let wallet = Address::generate(&env);
    client.register_module(&owner, &org, &ModuleKind::Wallet, &wallet);
    client.remove_module(&owner, &org, &ModuleKind::Wallet);
    assert_eq!(
        client.try_lookup(&org, &ModuleKind::Wallet),
        Err(Ok(Error::NotFound))
    );
    // Removing again fails.
    assert_eq!(
        client.try_remove_module(&owner, &org, &ModuleKind::Wallet),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn deprecate_module_blocks_lookup_but_allows_legacy_read() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    let wallet = Address::generate(&env);
    client.register_module(&owner, &org, &ModuleKind::Wallet, &wallet);
    assert_eq!(client.lookup(&org, &ModuleKind::Wallet), wallet);

    client.deprecate_module(&admin, &org, &ModuleKind::Wallet);
    assert!(client.is_module_deprecated(&org, &ModuleKind::Wallet));
    // Routing rejects new interactions targeting the deprecated module.
    assert_eq!(
        client.try_lookup(&org, &ModuleKind::Wallet),
        Err(Ok(Error::ModuleDeprecated))
    );
    // ...but the raw address stays readable for legacy migrations.
    assert_eq!(client.get_module_address(&org, &ModuleKind::Wallet), wallet);
}

#[test]
fn non_admin_cannot_deprecate_module() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    let wallet = Address::generate(&env);
    client.register_module(&owner, &org, &ModuleKind::Wallet, &wallet);
    // Neither a stranger nor even the org owner may deprecate: admin-only.
    let intruder = Address::generate(&env);
    assert_eq!(
        client.try_deprecate_module(&intruder, &org, &ModuleKind::Wallet),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(
        client.try_deprecate_module(&owner, &org, &ModuleKind::Wallet),
        Err(Ok(Error::Unauthorized))
    );
    assert!(!client.is_module_deprecated(&org, &ModuleKind::Wallet));
}

#[test]
fn deprecate_missing_module_fails() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    let res = client.try_deprecate_module(&admin, &org, &ModuleKind::Wallet);
    assert_eq!(res, Err(Ok(Error::NotFound)));
}

#[test]
fn reactivate_module_restores_routing() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    let wallet = Address::generate(&env);
    client.register_module(&owner, &org, &ModuleKind::Wallet, &wallet);

    client.deprecate_module(&admin, &org, &ModuleKind::Wallet);
    assert_eq!(
        client.try_lookup(&org, &ModuleKind::Wallet),
        Err(Ok(Error::ModuleDeprecated))
    );
    client.reactivate_module(&admin, &org, &ModuleKind::Wallet);
    assert!(!client.is_module_deprecated(&org, &ModuleKind::Wallet));
    assert_eq!(client.lookup(&org, &ModuleKind::Wallet), wallet);
}

#[test]
fn re_registered_module_clears_deprecation() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    let v1 = Address::generate(&env);
    let v2 = Address::generate(&env);
    client.register_module(&owner, &org, &ModuleKind::Wallet, &v1);
    client.deprecate_module(&admin, &org, &ModuleKind::Wallet);

    // Re-pointing the module at a new implementation clears the flag so the
    // freshly registered address is routable immediately.
    client.register_module(&owner, &org, &ModuleKind::Wallet, &v2);
    assert!(!client.is_module_deprecated(&org, &ModuleKind::Wallet));
    assert_eq!(client.lookup(&org, &ModuleKind::Wallet), v2);
}

#[test]
fn removed_deprecated_module_returns_not_found() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    let wallet = Address::generate(&env);
    client.register_module(&owner, &org, &ModuleKind::Wallet, &wallet);
    client.deprecate_module(&admin, &org, &ModuleKind::Wallet);

    client.remove_module(&owner, &org, &ModuleKind::Wallet);
    // Removing the record also removes its deprecation flag.
    assert!(!client.is_module_deprecated(&org, &ModuleKind::Wallet));
    assert_eq!(
        client.try_lookup(&org, &ModuleKind::Wallet),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn admin_rotation() {
    let (env, client, admin) = setup();
    let new_admin = Address::generate(&env);
    client.set_admin(&admin, &new_admin);
    assert_eq!(client.get_admin(), new_admin);
    // Old admin can no longer act.
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    assert_eq!(
        client.try_register_org(&admin, &org, &owner),
        Err(Ok(Error::Unauthorized))
    );
}
