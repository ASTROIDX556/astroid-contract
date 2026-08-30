#![cfg(test)]
extern crate std;

use crate::{RegistryContract, RegistryContractClient, RegistryRole};
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

// ---------------------------------------------------------------------------
// Deprecation and migration
// ---------------------------------------------------------------------------

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
fn stranger_cannot_deprecate_module() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    let wallet = Address::generate(&env);
    client.register_module(&owner, &org, &ModuleKind::Wallet, &wallet);
    // A stranger may not deprecate; the org owner (or admin) may.
    let intruder = Address::generate(&env);
    assert_eq!(
        client.try_deprecate_module(&intruder, &org, &ModuleKind::Wallet),
        Err(Ok(Error::Unauthorized))
    );
    assert!(!client.is_module_deprecated(&org, &ModuleKind::Wallet));

    client.deprecate_module(&owner, &org, &ModuleKind::Wallet);
    assert!(client.is_module_deprecated(&org, &ModuleKind::Wallet));
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
fn re_registration_while_deprecated_is_blocked() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    let v1 = Address::generate(&env);
    let v2 = Address::generate(&env);
    client.register_module(&owner, &org, &ModuleKind::Wallet, &v1);
    client.deprecate_module(&admin, &org, &ModuleKind::Wallet);

    // A deprecated slot cannot be silently re-bound...
    assert_eq!(
        client.try_register_module(&owner, &org, &ModuleKind::Wallet, &v2),
        Err(Ok(Error::InvalidState))
    );
    assert!(client.is_module_deprecated(&org, &ModuleKind::Wallet));

    // ...until it is explicitly reactivated.
    client.reactivate_module(&admin, &org, &ModuleKind::Wallet);
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
fn deprecate_module_marks_deprecated_and_blocks_new_bindings() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);

    let v1 = Address::generate(&env);
    client.register_module(&owner, &org, &ModuleKind::Policy, &v1);
    assert!(!client.is_module_deprecated(&org, &ModuleKind::Policy));
    assert_eq!(client.lookup(&org, &ModuleKind::Policy), v1);

    // Deprecate via admin (also works via owner).
    client.deprecate_module(&admin, &org, &ModuleKind::Policy);
    assert!(client.is_module_deprecated(&org, &ModuleKind::Policy));
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

    // Without a migration target, lookup rejects the deprecated module.
    assert_eq!(
        client.try_lookup(&org, &ModuleKind::Policy),
        Err(Ok(Error::ModuleDeprecated))
    );
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
    // Before migration, lookup rejects the deprecated module.
    assert_eq!(
        client.try_lookup(&org, &ModuleKind::Budget),
        Err(Ok(Error::ModuleDeprecated))
    );

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
    assert!(client.is_module_deprecated(&org, &ModuleKind::Policy));

    client.remove_module(&owner, &org, &ModuleKind::Policy);
    assert!(!client.is_module_deprecated(&org, &ModuleKind::Policy));
    assert_eq!(
        client.try_get_migration_target(&org, &ModuleKind::Policy),
        Err(Ok(Error::NotFound))
    );
    // Re-register after removal is allowed (slot no longer deprecated).
    let fresh = Address::generate(&env);
    client.register_module(&owner, &org, &ModuleKind::Policy, &fresh);
    assert_eq!(client.lookup(&org, &ModuleKind::Policy), fresh);
    assert!(!client.is_module_deprecated(&org, &ModuleKind::Policy));
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

// ---------------------------------------------------------------------------
// Role-based permission delegation
// ---------------------------------------------------------------------------

/// A registry with one registered organization, returning the org slug and its
/// owner alongside the usual handles.
fn setup_org() -> (
    Env,
    RegistryContractClient<'static>,
    Address,
    String,
    Address,
) {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    (env, client, admin, org, owner)
}

#[test]
fn owner_is_implicitly_owner_role() {
    let (env, client, _admin, org, owner) = setup_org();
    assert_eq!(client.get_role(&org, &owner), Some(RegistryRole::Owner));
    assert!(client.can_manage_module(&org, &owner, &ModuleKind::Policy));
    assert!(client.can_manage_module(&org, &owner, &ModuleKind::Treasury));

    let stranger = Address::generate(&env);
    assert_eq!(client.get_role(&org, &stranger), None);
    assert!(!client.can_manage_module(&org, &stranger, &ModuleKind::Policy));
}

#[test]
fn granted_role_is_readable_and_revocable() {
    let (env, client, _admin, org, owner) = setup_org();
    let delegate = Address::generate(&env);

    client.grant_role(&owner, &org, &delegate, &RegistryRole::PolicyManager);
    assert_eq!(
        client.get_role(&org, &delegate),
        Some(RegistryRole::PolicyManager)
    );

    // Re-granting replaces rather than stacks.
    client.grant_role(&owner, &org, &delegate, &RegistryRole::TreasuryOperator);
    assert_eq!(
        client.get_role(&org, &delegate),
        Some(RegistryRole::TreasuryOperator)
    );

    client.revoke_role(&owner, &org, &delegate);
    assert_eq!(client.get_role(&org, &delegate), None);

    // Revoking again is an explicit failure, not a silent no-op.
    assert_eq!(
        client.try_revoke_role(&owner, &org, &delegate),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn policy_manager_reaches_only_the_policy_module() {
    let (env, client, _admin, org, owner) = setup_org();
    let delegate = Address::generate(&env);
    let addr = Address::generate(&env);
    client.grant_role(&owner, &org, &delegate, &RegistryRole::PolicyManager);

    client.register_module(&delegate, &org, &ModuleKind::Policy, &addr);
    assert_eq!(client.lookup(&org, &ModuleKind::Policy), addr);

    for kind in [ModuleKind::Treasury, ModuleKind::Wallet, ModuleKind::Budget] {
        assert!(!client.can_manage_module(&org, &delegate, &kind));
        assert_eq!(
            client.try_register_module(&delegate, &org, &kind, &addr),
            Err(Ok(Error::Unauthorized))
        );
        assert_eq!(client.try_lookup(&org, &kind), Err(Ok(Error::NotFound)));
    }
}

#[test]
fn treasury_operator_reaches_the_value_custody_modules() {
    let (env, client, _admin, org, owner) = setup_org();
    let delegate = Address::generate(&env);
    let addr = Address::generate(&env);
    client.grant_role(&owner, &org, &delegate, &RegistryRole::TreasuryOperator);

    for kind in [ModuleKind::Treasury, ModuleKind::Budget, ModuleKind::Escrow] {
        assert!(client.can_manage_module(&org, &delegate, &kind));
        client.register_module(&delegate, &org, &kind, &addr);
        assert_eq!(client.lookup(&org, &kind), addr);
    }

    // ...but not the policy that governs them.
    assert!(!client.can_manage_module(&org, &delegate, &ModuleKind::Policy));
    assert_eq!(
        client.try_register_module(&delegate, &org, &ModuleKind::Policy, &addr),
        Err(Ok(Error::Unauthorized))
    );
}

#[test]
fn module_upgrader_may_repoint_any_module() {
    let (env, client, _admin, org, owner) = setup_org();
    let delegate = Address::generate(&env);
    let v1 = Address::generate(&env);
    let v2 = Address::generate(&env);
    client.register_module(&owner, &org, &ModuleKind::Wallet, &v1);
    client.grant_role(&owner, &org, &delegate, &RegistryRole::ModuleUpgrader);

    client.register_module(&delegate, &org, &ModuleKind::Wallet, &v2);
    assert_eq!(client.lookup(&org, &ModuleKind::Wallet), v2);
    client.register_module(&delegate, &org, &ModuleKind::Policy, &v2);
    assert_eq!(client.lookup(&org, &ModuleKind::Policy), v2);
}

#[test]
fn delegated_owner_reaches_every_module_kind() {
    let (env, client, _admin, org, owner) = setup_org();
    let delegate = Address::generate(&env);
    let addr = Address::generate(&env);
    client.grant_role(&owner, &org, &delegate, &RegistryRole::Owner);

    for kind in [
        ModuleKind::Wallet,
        ModuleKind::Treasury,
        ModuleKind::Policy,
        ModuleKind::Escrow,
    ] {
        client.register_module(&delegate, &org, &kind, &addr);
        assert_eq!(client.lookup(&org, &kind), addr);
    }
}

#[test]
fn delegates_may_remove_modules_they_may_register() {
    let (env, client, _admin, org, owner) = setup_org();
    let delegate = Address::generate(&env);
    let addr = Address::generate(&env);
    client.register_module(&owner, &org, &ModuleKind::Policy, &addr);
    client.register_module(&owner, &org, &ModuleKind::Treasury, &addr);
    client.grant_role(&owner, &org, &delegate, &RegistryRole::PolicyManager);

    client.remove_module(&delegate, &org, &ModuleKind::Policy);
    assert_eq!(
        client.try_lookup(&org, &ModuleKind::Policy),
        Err(Ok(Error::NotFound))
    );
    // The removal gate matches the registration gate exactly.
    assert_eq!(
        client.try_remove_module(&delegate, &org, &ModuleKind::Treasury),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(client.lookup(&org, &ModuleKind::Treasury), addr);
}

#[test]
fn unauthorized_accounts_are_rejected() {
    let (env, client, _admin, org, _owner) = setup_org();
    let stranger = Address::generate(&env);
    let addr = Address::generate(&env);

    assert_eq!(
        client.try_register_module(&stranger, &org, &ModuleKind::Wallet, &addr),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(
        client.try_remove_module(&stranger, &org, &ModuleKind::Wallet),
        Err(Ok(Error::Unauthorized))
    );
}

#[test]
fn delegates_cannot_administer_roles_or_ownership() {
    let (env, client, _admin, org, owner) = setup_org();
    let delegate = Address::generate(&env);
    let accomplice = Address::generate(&env);
    client.grant_role(&owner, &org, &delegate, &RegistryRole::Owner);

    // Even the broadest delegated role cannot mint further delegations...
    assert_eq!(
        client.try_grant_role(&delegate, &org, &accomplice, &RegistryRole::Owner),
        Err(Ok(Error::Unauthorized))
    );
    // ...revoke its way around the owner...
    assert_eq!(
        client.try_revoke_role(&delegate, &org, &delegate),
        Err(Ok(Error::Unauthorized))
    );
    // ...or escalate into ownership.
    assert_eq!(
        client.try_set_org_owner(&delegate, &org, &delegate),
        Err(Ok(Error::Unauthorized))
    );

    assert_eq!(client.get_role(&org, &accomplice), None);
    assert_eq!(client.get_org_owner(&org), owner);
}

#[test]
fn protocol_admin_may_administer_roles() {
    let (env, client, admin, org, _owner) = setup_org();
    let delegate = Address::generate(&env);

    client.grant_role(&admin, &org, &delegate, &RegistryRole::ModuleUpgrader);
    assert_eq!(
        client.get_role(&org, &delegate),
        Some(RegistryRole::ModuleUpgrader)
    );
    client.revoke_role(&admin, &org, &delegate);
    assert_eq!(client.get_role(&org, &delegate), None);
}

#[test]
fn revoked_delegate_loses_access_immediately() {
    let (env, client, _admin, org, owner) = setup_org();
    let delegate = Address::generate(&env);
    let addr = Address::generate(&env);
    client.grant_role(&owner, &org, &delegate, &RegistryRole::PolicyManager);
    client.register_module(&delegate, &org, &ModuleKind::Policy, &addr);

    client.revoke_role(&owner, &org, &delegate);
    assert_eq!(
        client.try_register_module(&delegate, &org, &ModuleKind::Policy, &addr),
        Err(Ok(Error::Unauthorized))
    );
}

#[test]
fn roles_do_not_leak_between_organizations() {
    let (env, client, admin, org_a, owner_a) = setup_org();
    let org_b = String::from_str(&env, "globex");
    let owner_b = Address::generate(&env);
    client.register_org(&admin, &org_b, &owner_b);

    let delegate = Address::generate(&env);
    let addr = Address::generate(&env);
    client.grant_role(&owner_a, &org_a, &delegate, &RegistryRole::PolicyManager);

    client.register_module(&delegate, &org_a, &ModuleKind::Policy, &addr);
    assert_eq!(client.get_role(&org_b, &delegate), None);
    assert_eq!(
        client.try_register_module(&delegate, &org_b, &ModuleKind::Policy, &addr),
        Err(Ok(Error::Unauthorized))
    );
}

#[test]
fn owner_cannot_be_assigned_a_role() {
    let (_env, client, _admin, org, owner) = setup_org();
    // The owner already reaches every kind; recording a narrower role for them
    // would be misleading rather than restrictive.
    assert_eq!(
        client.try_grant_role(&owner, &org, &owner, &RegistryRole::PolicyManager),
        Err(Ok(Error::InvalidInput))
    );
    assert_eq!(client.get_role(&org, &owner), Some(RegistryRole::Owner));
}

#[test]
fn role_administration_on_an_unknown_org_fails() {
    let (env, client, admin, _org, _owner) = setup_org();
    let ghost = String::from_str(&env, "nowhere");
    let account = Address::generate(&env);

    assert_eq!(
        client.try_grant_role(&admin, &ghost, &account, &RegistryRole::Owner),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(
        client.try_revoke_role(&admin, &ghost, &account),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(client.get_role(&ghost, &account), None);
}

#[test]
fn frozen_registry_blocks_grants_and_delegated_writes() {
    let (env, client, _admin, org, owner) = setup_org();
    let delegate = Address::generate(&env);
    let other = Address::generate(&env);
    let addr = Address::generate(&env);
    client.grant_role(&owner, &org, &delegate, &RegistryRole::Owner);
    client.freeze(&owner, &org);

    assert_eq!(
        client.try_register_module(&delegate, &org, &ModuleKind::Wallet, &addr),
        Err(Ok(Error::RegistryFrozen))
    );
    assert_eq!(
        client.try_grant_role(&owner, &org, &other, &RegistryRole::Owner),
        Err(Ok(Error::RegistryFrozen))
    );

    // Revocation stays available while frozen so an owner can always withdraw
    // access during an incident.
    client.revoke_role(&owner, &org, &delegate);
    assert_eq!(client.get_role(&org, &delegate), None);
}
