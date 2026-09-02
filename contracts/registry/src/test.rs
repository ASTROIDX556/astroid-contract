#![cfg(test)]
extern crate std;

use crate::{RegistryContract, RegistryContractClient, Role};
use astroid_interfaces::version::Version;
use astroid_shared::errors::Error;
use astroid_shared::types::ModuleKind;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{testutils::Events, Address, Env, IntoVal, String, Symbol, Val, Vec};

/// Assert that the canonical `ContractEvent` with the given variant symbol was
/// published during the test (single-topic event = the variant name).
fn assert_event(env: &Env, variant: &str) {
    let want: Val = Symbol::new(env, variant).into_val(env);
    let found = env
        .events()
        .all()
        .iter()
        .any(|(_contract_id, topics, _data)| topics.contains(want));
    assert!(found, "expected ContractEvent::{} to be emitted", variant);
}

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
fn batch_register_modules_updates_multiple_entries_atomically() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);

    let wallet = Address::generate(&env);
    let treasury = Address::generate(&env);
    let policy = Address::generate(&env);
    let kinds = Vec::from_array(
        &env,
        [ModuleKind::Wallet, ModuleKind::Treasury, ModuleKind::Policy],
    );
    let addrs = Vec::from_array(&env, [wallet.clone(), treasury.clone(), policy.clone()]);

    client.batch_register_modules(&owner, &org, &kinds, &addrs);
    assert_eq!(client.lookup(&org, &ModuleKind::Wallet), wallet);
    assert_eq!(client.lookup(&org, &ModuleKind::Treasury), treasury);
    assert_eq!(client.lookup(&org, &ModuleKind::Policy), policy);
    assert_event(&env, "RegistryModuleBatchUpdated");
}

#[test]
fn batch_register_modules_rolls_back_on_invalid_input() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);

    let wallet = Address::generate(&env);
    let policy = Address::generate(&env);
    let kinds = Vec::from_array(
        &env,
        [ModuleKind::Wallet, ModuleKind::Policy, ModuleKind::Policy],
    );
    let addrs = Vec::from_array(&env, [wallet.clone(), policy.clone(), policy.clone()]);

    let res = client.try_batch_register_modules(&owner, &org, &kinds, &addrs);
    assert_eq!(res, Err(Ok(Error::InvalidInput)));
    assert_eq!(
        client.try_lookup(&org, &ModuleKind::Wallet),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(
        client.try_lookup(&org, &ModuleKind::Policy),
        Err(Ok(Error::NotFound))
    );
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
fn set_migration_target_guides_lookup() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    let v1 = Address::generate(&env);
    let v2 = Address::generate(&env);
    client.register_module(&owner, &org, &ModuleKind::Wallet, &v1);

    // No migration configured initially.
    assert_eq!(
        client.try_get_module_migration(&org, &ModuleKind::Wallet),
        Err(Ok(Error::NotFound))
    );

    // Deprecate the old implementation and point at its successor.
    client.deprecate_module(&admin, &org, &ModuleKind::Wallet);
    client.set_migration_target(&admin, &org, &ModuleKind::Wallet, &v2);

    // lookups reject the deprecated module while the migration target (and the
    // raw legacy address) remain readable.
    assert_eq!(
        client.try_lookup(&org, &ModuleKind::Wallet),
        Err(Ok(Error::ModuleDeprecated))
    );
    assert_eq!(client.get_module_migration(&org, &ModuleKind::Wallet), v2);
    assert_eq!(client.get_module_address(&org, &ModuleKind::Wallet), v1);

    // The composite view reports all three facts in one call.
    let info = client.get_module(&org, &ModuleKind::Wallet);
    assert_eq!(info.address, v1);
    assert!(info.deprecated);
    assert_eq!(info.migration_target, Some(v2));
}

#[test]
fn module_cannot_be_its_own_migration_target() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    let wallet = Address::generate(&env);
    client.register_module(&owner, &org, &ModuleKind::Wallet, &wallet);

    let res = client.try_set_migration_target(&admin, &org, &ModuleKind::Wallet, &wallet);
    assert_eq!(res, Err(Ok(Error::InvalidInput)));
    assert_eq!(
        client.try_get_module_migration(&org, &ModuleKind::Wallet),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn set_migration_target_is_admin_only() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    let v1 = Address::generate(&env);
    let v2 = Address::generate(&env);
    client.register_module(&owner, &org, &ModuleKind::Wallet, &v1);

    let intruder = Address::generate(&env);
    assert_eq!(
        client.try_set_migration_target(&intruder, &org, &ModuleKind::Wallet, &v2),
        Err(Ok(Error::Unauthorized))
    );
    // Even the org owner cannot set the migration target: admin-only.
    assert_eq!(
        client.try_set_migration_target(&owner, &org, &ModuleKind::Wallet, &v2),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(
        client.try_get_module_migration(&org, &ModuleKind::Wallet),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn set_migration_target_requires_registered_module() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    let successor = Address::generate(&env);

    let res = client.try_set_migration_target(&admin, &org, &ModuleKind::Wallet, &successor);
    assert_eq!(res, Err(Ok(Error::NotFound)));
}

#[test]
fn clear_migration_target_unlinks_successor() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    let v1 = Address::generate(&env);
    let v2 = Address::generate(&env);
    client.register_module(&owner, &org, &ModuleKind::Wallet, &v1);
    client.set_migration_target(&admin, &org, &ModuleKind::Wallet, &v2);
    assert_eq!(client.get_module_migration(&org, &ModuleKind::Wallet), v2);

    // Clearing removes the pointer (the deprecation status is preserved).
    client.deprecate_module(&admin, &org, &ModuleKind::Wallet);
    client.clear_migration_target(&admin, &org, &ModuleKind::Wallet);
    assert_eq!(
        client.try_get_module_migration(&org, &ModuleKind::Wallet),
        Err(Ok(Error::NotFound))
    );
    assert!(client.is_module_deprecated(&org, &ModuleKind::Wallet));

    // Clearing again fails explicitly.
    assert_eq!(
        client.try_clear_migration_target(&admin, &org, &ModuleKind::Wallet),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn set_migration_target_is_admin_only_clear() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    let v1 = Address::generate(&env);
    let v2 = Address::generate(&env);
    client.register_module(&owner, &org, &ModuleKind::Wallet, &v1);
    client.set_migration_target(&admin, &org, &ModuleKind::Wallet, &v2);

    let intruder = Address::generate(&env);
    assert_eq!(
        client.try_clear_migration_target(&intruder, &org, &ModuleKind::Wallet),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(client.get_module_migration(&org, &ModuleKind::Wallet), v2);
}

#[test]
fn re_registration_clears_migration_target() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    let v1 = Address::generate(&env);
    let v2 = Address::generate(&env);
    client.register_module(&owner, &org, &ModuleKind::Wallet, &v1);
    client.deprecate_module(&admin, &org, &ModuleKind::Wallet);
    client.set_migration_target(&admin, &org, &ModuleKind::Wallet, &v2);

    // Re-pointing the module clears both the deprecation flag and its
    // migration target so the fresh address is immediately routable.
    let v3 = Address::generate(&env);
    client.register_module(&owner, &org, &ModuleKind::Wallet, &v3);
    assert!(!client.is_module_deprecated(&org, &ModuleKind::Wallet));
    assert_eq!(
        client.try_get_module_migration(&org, &ModuleKind::Wallet),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(client.lookup(&org, &ModuleKind::Wallet), v3);
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

#[test]
fn standard_events_emitted() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);

    let wallet = Address::generate(&env);
    client.register_module(&owner, &org, &ModuleKind::Wallet, &wallet);
    assert_event(&env, "RegistryModuleUpdated");

    let new_owner = Address::generate(&env);
    client.set_org_owner(&owner, &org, &new_owner);
    assert_event(&env, "OrgOwnerChanged");

    client.freeze(&new_owner, &org);
    assert_event(&env, "RegistryFrozen");
}

#[test]
fn module_manager_can_register_module() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);

    // Grant module manager role to a different address
    let module_mgr = Address::generate(&env);
    client.grant_role(&owner, &org, &module_mgr, &Role::ModuleManager);

    // Module manager can register modules
    let wallet = Address::generate(&env);
    client.register_module(&module_mgr, &org, &ModuleKind::Wallet, &wallet);
    assert_eq!(client.lookup(&org, &ModuleKind::Wallet), wallet);
}

#[test]
fn module_manager_can_remove_module() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);

    let wallet = Address::generate(&env);
    client.register_module(&owner, &org, &ModuleKind::Wallet, &wallet);

    // Grant module manager role
    let module_mgr = Address::generate(&env);
    client.grant_role(&owner, &org, &module_mgr, &Role::ModuleManager);

    // Module manager can remove modules
    client.remove_module(&module_mgr, &org, &ModuleKind::Wallet);
    assert_eq!(
        client.try_lookup(&org, &ModuleKind::Wallet),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn unauthorized_user_cannot_register_module() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);

    // User without any role
    let stranger = Address::generate(&env);
    let wallet = Address::generate(&env);
    let res = client.try_register_module(&stranger, &org, &ModuleKind::Wallet, &wallet);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
}

#[test]
fn grant_and_revoke_role_work() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);

    let user = Address::generate(&env);
    // Grant role
    client.grant_role(&owner, &org, &user, &Role::ModuleManager);
    assert_eq!(client.get_role(&org, &user), Some(Role::ModuleManager));
    // Revoke role
    client.revoke_role(&owner, &org, &user);
    assert_eq!(client.get_role(&org, &user), None);
}

#[test]
fn revoke_nonexistent_role_fails() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);

    let user = Address::generate(&env);
    let res = client.try_revoke_role(&owner, &org, &user);
    assert_eq!(res, Err(Ok(Error::NotFound)));
}

#[test]
fn org_owner_cannot_grant_admin_role() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);

    let user = Address::generate(&env);
    // Org owner cannot grant Admin role
    let res = client.try_grant_role(&owner, &org, &user, &Role::Admin);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
}

#[test]
fn admin_can_grant_admin_role() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);

    let user = Address::generate(&env);
    // Admin can grant Admin role
    client.grant_role(&admin, &org, &user, &Role::Admin);
    assert_eq!(client.get_role(&org, &user), Some(Role::Admin));
}

#[test]
fn register_module_with_version_compatible_update() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);

    // Organization requires at least Wallet interface 1.0.
    client.set_min_interface_version(&admin, &org, &ModuleKind::Wallet, &Version::new(1, 0));

    let wallet = Address::generate(&env);
    // A compatible update (same major, newer minor) is accepted.
    client.register_module_with_version(
        &owner,
        &org,
        &ModuleKind::Wallet,
        &wallet,
        &Version::new(1, 2),
    );
    assert_eq!(client.lookup(&org, &ModuleKind::Wallet), wallet);
    assert_eq!(
        client.get_module_interface_version(&org, &ModuleKind::Wallet),
        Version::new(1, 2)
    );
    assert_eq!(
        client.check_interface_compatibility(&org, &ModuleKind::Wallet),
        Version::new(1, 2)
    );
}

#[test]
fn register_module_with_version_rejects_incompatible() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    client.set_min_interface_version(&admin, &org, &ModuleKind::Wallet, &Version::new(1, 2));

    let wallet = Address::generate(&env);
    // An older minor violates the bound and is refused before any state is written.
    let res = client.try_register_module_with_version(
        &owner,
        &org,
        &ModuleKind::Wallet,
        &wallet,
        &Version::new(1, 1),
    );
    assert_eq!(res, Err(Ok(Error::InterfaceVersionIncompatible)));
    assert_eq!(
        client.try_lookup(&org, &ModuleKind::Wallet),
        Err(Ok(Error::NotFound))
    );

    // A different major (breaking change) is likewise refused.
    let res = client.try_register_module_with_version(
        &owner,
        &org,
        &ModuleKind::Wallet,
        &wallet,
        &Version::new(2, 0),
    );
    assert_eq!(res, Err(Ok(Error::InterfaceVersionIncompatible)));
    assert_eq!(
        client.try_lookup(&org, &ModuleKind::Wallet),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn lookup_rejects_legacy_module_once_bound_raised() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    let wallet = Address::generate(&env);
    // A legacy registration (no explicit interface version) speaks CURRENT_VERSION.
    client.register_module(&owner, &org, &ModuleKind::Wallet, &wallet);
    assert_eq!(client.lookup(&org, &ModuleKind::Wallet), wallet);

    // Raising the bound above the current interface version blocks routing.
    client.set_min_interface_version(&admin, &org, &ModuleKind::Wallet, &Version::new(1, 2));
    assert_eq!(
        client.try_lookup(&org, &ModuleKind::Wallet),
        Err(Ok(Error::InterfaceVersionIncompatible))
    );
    assert_eq!(
        client.try_check_interface_compatibility(&org, &ModuleKind::Wallet),
        Err(Ok(Error::InterfaceVersionIncompatible))
    );

    // Clearing the bound restores routing.
    client.clear_min_interface_version(&admin, &org, &ModuleKind::Wallet);
    assert_eq!(client.lookup(&org, &ModuleKind::Wallet), wallet);
}

#[test]
fn bound_raise_blocks_then_in_band_upgrade_restores_routing() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);

    // Register a v1.1 module, then raise the bound to v1.2.
    let wallet = Address::generate(&env);
    client.register_module_with_version(
        &owner,
        &org,
        &ModuleKind::Wallet,
        &wallet,
        &Version::new(1, 1),
    );
    client.set_min_interface_version(&admin, &org, &ModuleKind::Wallet, &Version::new(1, 2));
    assert_eq!(
        client.try_lookup(&org, &ModuleKind::Wallet),
        Err(Ok(Error::InterfaceVersionIncompatible))
    );

    // An in-band upgrade to v1.3 restores routing.
    let upgraded = Address::generate(&env);
    client.register_module_with_version(
        &owner,
        &org,
        &ModuleKind::Wallet,
        &upgraded,
        &Version::new(1, 3),
    );
    assert_eq!(client.lookup(&org, &ModuleKind::Wallet), upgraded);
}

#[test]
fn min_interface_version_is_admin_gated() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);

    let stranger = Address::generate(&env);
    assert_eq!(
        client.try_set_min_interface_version(
            &stranger,
            &org,
            &ModuleKind::Wallet,
            &Version::new(1, 0)
        ),
        Err(Ok(Error::Unauthorized))
    );
    // Even the org owner cannot set the bound: admin-only.
    assert_eq!(
        client.try_set_min_interface_version(
            &owner,
            &org,
            &ModuleKind::Wallet,
            &Version::new(1, 0)
        ),
        Err(Ok(Error::Unauthorized))
    );
    // ...and no bound was recorded.
    assert_eq!(
        client.try_get_min_interface_version(&org, &ModuleKind::Wallet),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn min_interface_version_requires_existing_org() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    assert_eq!(
        client.try_set_min_interface_version(
            &admin,
            &org,
            &ModuleKind::Wallet,
            &Version::new(1, 0)
        ),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn clear_min_interface_version_roundtrip() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);

    // No bound recorded yet.
    assert_eq!(
        client.try_get_min_interface_version(&org, &ModuleKind::Wallet),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(
        client.try_clear_min_interface_version(&admin, &org, &ModuleKind::Wallet),
        Err(Ok(Error::NotFound))
    );

    client.set_min_interface_version(&admin, &org, &ModuleKind::Wallet, &Version::new(1, 1));
    assert_eq!(
        client.get_min_interface_version(&org, &ModuleKind::Wallet),
        Version::new(1, 1)
    );

    client.clear_min_interface_version(&admin, &org, &ModuleKind::Wallet);
    assert_eq!(
        client.try_get_min_interface_version(&org, &ModuleKind::Wallet),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn check_interface_compatibility_requires_registered_module() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);

    assert_eq!(
        client.try_check_interface_compatibility(&org, &ModuleKind::Wallet),
        Err(Ok(Error::NotFound))
    );
}
