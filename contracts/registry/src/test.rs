#![cfg(test)]
extern crate std;

use crate::{RegistryContract, RegistryContractClient};
use astroid_shared::errors::Error;
use astroid_shared::types::ModuleKind;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{testutils::Events, Address, Env, IntoVal, String, Symbol, Val};

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

// ── Deprecation and migration ──────────────────────────────────────────

#[test]
fn deprecate_module_marks_deprecated_and_blocks_new_bindings() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);

    let v1 = Address::generate(&env);
    client.register_module(&owner, &org, &ModuleKind::Policy, &v1);
    assert!(!client.is_deprecated(&org, &ModuleKind::Policy));
    assert_eq!(client.lookup(&org, &ModuleKind::Policy), v1);

    // Deprecate via admin (also works via owner).
    client.deprecate_module(&admin, &org, &ModuleKind::Policy);
    assert!(client.is_deprecated(&org, &ModuleKind::Policy));
    // Direct reads still succeed (orderly read).
    assert_eq!(client.get_module(&org, &ModuleKind::Policy).address, v1);
    assert_eq!(
        client.get_module(&org, &ModuleKind::Policy).deprecated,
        true
    );

    // New bindings to same slot are rejected.
    let v2 = Address::generate(&env);
    let res = client.try_register_module(&owner, &org, &ModuleKind::Policy, &v2);
    assert_eq!(res, Err(Ok(Error::InvalidState)));
    // Even admin cannot re-bind.
    let res = client.try_register_module(&admin, &org, &ModuleKind::Policy, &v2);
    assert_eq!(res, Err(Ok(Error::InvalidState)));

    // Lookup still returns original until migration is set (graceful).
    assert_eq!(client.lookup(&org, &ModuleKind::Policy), v1);
}

#[test]
fn deprecation_emits_events() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    let wallet = Address::generate(&env);
    client.register_module(&owner, &org, &ModuleKind::Wallet, &wallet);

    client.deprecate_module(&owner, &org, &ModuleKind::Wallet);
    // Should emit RegistryModuleUpdated + module/deprecate + registry/deprecate
    assert_event(&env, "RegistryModuleUpdated");
    let want: Val = Symbol::new(&env, "deprecate").into_val(&env);
    let has_deprecate = env
        .events()
        .all()
        .iter()
        .any(|(_id, topics, _data)| topics.contains(&want));
    assert!(has_deprecate, "expected deprecate event");
}

#[test]
fn set_migration_target_and_lookup_returns_migration() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);

    let old = Address::generate(&env);
    let new = Address::generate(&env);
    client.register_module(&owner, &org, &ModuleKind::Budget, &old);
    client.deprecate_module(&admin, &org, &ModuleKind::Budget);
    // Before migration, lookup returns original.
    assert_eq!(client.lookup(&org, &ModuleKind::Budget), old);

    client.set_migration_target(&owner, &org, &ModuleKind::Budget, &new);
    assert_eq!(client.get_migration_target(&org, &ModuleKind::Budget), new);
    let rec = client.get_module(&org, &ModuleKind::Budget);
    assert_eq!(rec.migration_target, Some(new.clone()));

    // After migration, lookup is guided to successor.
    assert_eq!(client.lookup(&org, &ModuleKind::Budget), new);

    // Migration event emitted.
    let want: Val = Symbol::new(&env, "migrate").into_val(&env);
    let has_migrate = env
        .events()
        .all()
        .iter()
        .any(|(_id, topics, _data)| topics.contains(&want));
    assert!(has_migrate, "expected migrate event");
}

#[test]
fn deprecate_requires_existing_module() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    let res = client.try_deprecate_module(&admin, &org, &ModuleKind::Escrow);
    assert_eq!(res, Err(Ok(Error::NotFound)));
}

#[test]
fn cannot_deprecate_twice() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    let w = Address::generate(&env);
    client.register_module(&owner, &org, &ModuleKind::Wallet, &w);
    client.deprecate_module(&admin, &org, &ModuleKind::Wallet);
    let res = client.try_deprecate_module(&admin, &org, &ModuleKind::Wallet);
    assert_eq!(res, Err(Ok(Error::AlreadyExists)));
}

#[test]
fn set_migration_requires_deprecated() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    let w = Address::generate(&env);
    let new = Address::generate(&env);
    client.register_module(&owner, &org, &ModuleKind::Wallet, &w);
    // Not yet deprecated -> InvalidState.
    let res = client.try_set_migration_target(&admin, &org, &ModuleKind::Wallet, &new);
    assert_eq!(res, Err(Ok(Error::InvalidState)));
}

#[test]
fn migration_target_not_found_when_unset() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    let w = Address::generate(&env);
    client.register_module(&owner, &org, &ModuleKind::Wallet, &w);
    client.deprecate_module(&admin, &org, &ModuleKind::Wallet);
    let res = client.try_get_migration_target(&org, &ModuleKind::Wallet);
    assert_eq!(res, Err(Ok(Error::NotFound)));
}

#[test]
fn non_admin_cannot_deprecate_or_migrate() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    let stranger = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    let w = Address::generate(&env);
    client.register_module(&owner, &org, &ModuleKind::Wallet, &w);

    let res = client.try_deprecate_module(&stranger, &org, &ModuleKind::Wallet);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));

    client.deprecate_module(&owner, &org, &ModuleKind::Wallet);
    let new = Address::generate(&env);
    let res = client.try_set_migration_target(&stranger, &org, &ModuleKind::Wallet, &new);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
}

#[test]
fn remove_cleans_deprecation_and_migration() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    let old = Address::generate(&env);
    let new = Address::generate(&env);
    client.register_module(&owner, &org, &ModuleKind::Policy, &old);
    client.deprecate_module(&admin, &org, &ModuleKind::Policy);
    client.set_migration_target(&admin, &org, &ModuleKind::Policy, &new);
    assert!(client.is_deprecated(&org, &ModuleKind::Policy));

    client.remove_module(&owner, &org, &ModuleKind::Policy);
    assert!(!client.is_deprecated(&org, &ModuleKind::Policy));
    assert_eq!(
        client.try_get_migration_target(&org, &ModuleKind::Policy),
        Err(Ok(Error::NotFound))
    );
    // Re-register after removal is allowed (slot no longer deprecated).
    let fresh = Address::generate(&env);
    client.register_module(&owner, &org, &ModuleKind::Policy, &fresh);
    assert_eq!(client.lookup(&org, &ModuleKind::Policy), fresh);
    assert!(!client.is_deprecated(&org, &ModuleKind::Policy));
}

#[test]
fn get_module_returns_full_record() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    let addr = Address::generate(&env);
    client.register_module(&owner, &org, &ModuleKind::Treasury, &addr);

    let rec = client.get_module(&org, &ModuleKind::Treasury);
    assert_eq!(rec.address, addr);
    assert!(!rec.deprecated);
    assert_eq!(rec.migration_target, None);

    client.deprecate_module(&admin, &org, &ModuleKind::Treasury);
    let new = Address::generate(&env);
    client.set_migration_target(&admin, &org, &ModuleKind::Treasury, &new);

    let rec2 = client.get_module(&org, &ModuleKind::Treasury);
    assert_eq!(rec2.address, addr);
    assert!(rec2.deprecated);
    assert_eq!(rec2.migration_target, Some(new));
}
