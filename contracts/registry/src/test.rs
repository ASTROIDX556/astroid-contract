#![cfg(test)]
extern crate std;

use crate::{RegistryContract, RegistryContractClient};
use astroid_interfaces::upgrade;
use crate::{RegistryContract, RegistryContractClient, RegistryRole};
use astroid_shared::errors::Error;
use astroid_shared::types::ModuleKind;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{
    contract, contractimpl, testutils::Events, Address, BytesN, Env, IntoVal, String, Symbol, Val,
};

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

// --- upgrade authorization ---

/// A stand-in member contract wired exactly like the real ones: it delegates
/// its upgrade surface to `astroid_interfaces::upgrade`, so these tests exercise
/// the real cross-contract path against the real registry.
#[contract]
pub struct UpgradeMember;

#[contractimpl]
impl UpgradeMember {
    pub fn set_upgrade_authority(
        env: Env,
        caller: Address,
        admin: Address,
        registry: Address,
    ) -> Result<(), Error> {
        upgrade::set_authority(&env, &caller, &admin, &registry)
    }

    pub fn check_upgrade(
        env: Env,
        caller: Address,
        new_wasm_hash: BytesN<32>,
    ) -> Result<u32, Error> {
        upgrade::check(&env, &caller, ModuleKind::Wallet, &new_wasm_hash)
    }

    pub fn upgrade(env: Env, caller: Address, new_wasm_hash: BytesN<32>) -> Result<u32, Error> {
        upgrade::perform(&env, &caller, ModuleKind::Wallet, new_wasm_hash)
    }
}

fn hash(env: &Env, byte: u8) -> BytesN<32> {
    BytesN::from_array(env, &[byte; 32])
}

/// Registry + a member contract whose upgrade admin is `admin`.
fn upgrade_setup() -> (
    Env,
    RegistryContractClient<'static>,
    UpgradeMemberClient<'static>,
    Address,
) {
    let (env, registry, admin) = setup();
    let member_id = env.register_contract(None, UpgradeMember);
    let member = UpgradeMemberClient::new(&env, &member_id);
    member.set_upgrade_authority(&admin, &admin, &registry.address);
    (env, registry, member, admin)
}

#[test]
fn register_wasm_hash_records_both_directions() {
    let (env, client, admin) = setup();
    let h = hash(&env, 1);
    client.register_wasm_hash(&admin, &ModuleKind::Wallet, &2, &h);

    assert_eq!(client.get_wasm_hash(&ModuleKind::Wallet, &2), h);
    assert_eq!(client.is_upgrade_approved(&ModuleKind::Wallet, &h), 2);
    // Registering a hash also advances the latest-version pointer.
    assert_eq!(client.get_wasm_hash(&ModuleKind::Wallet, &2), h);
}

#[test]
fn unregistered_hash_is_not_approved() {
    let (env, client, admin) = setup();
    client.register_wasm_hash(&admin, &ModuleKind::Wallet, &1, &hash(&env, 1));

    // A hash that was never registered.
    assert_eq!(
        client.try_is_upgrade_approved(&ModuleKind::Wallet, &hash(&env, 9)),
        Err(Ok(Error::UnauthorizedUpgrade))
    );
    // The right hash under the wrong module kind.
    assert_eq!(
        client.try_is_upgrade_approved(&ModuleKind::Treasury, &hash(&env, 1)),
        Err(Ok(Error::UnauthorizedUpgrade))
    );
}

#[test]
fn revoked_hash_stops_being_approved() {
    let (env, client, admin) = setup();
    let h = hash(&env, 4);
    client.register_wasm_hash(&admin, &ModuleKind::Budget, &1, &h);
    assert_eq!(client.is_upgrade_approved(&ModuleKind::Budget, &h), 1);

    client.revoke_wasm_hash(&admin, &ModuleKind::Budget, &1);
    assert_eq!(
        client.try_is_upgrade_approved(&ModuleKind::Budget, &h),
        Err(Ok(Error::UnauthorizedUpgrade))
    );
    assert_eq!(
        client.try_get_wasm_hash(&ModuleKind::Budget, &1),
        Err(Ok(Error::NotFound))
    );
    // Revoking twice is a no-op error, not a silent success.
    assert_eq!(
        client.try_revoke_wasm_hash(&admin, &ModuleKind::Budget, &1),
        Err(Ok(Error::NotFound))
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
fn replacing_a_version_revokes_the_superseded_hash() {
    let (env, client, admin) = setup();
    let old = hash(&env, 5);
    let new = hash(&env, 6);
    client.register_wasm_hash(&admin, &ModuleKind::Wallet, &1, &old);
    client.register_wasm_hash(&admin, &ModuleKind::Wallet, &1, &new);

    assert_eq!(client.is_upgrade_approved(&ModuleKind::Wallet, &new), 1);
    assert_eq!(
        client.try_is_upgrade_approved(&ModuleKind::Wallet, &old),
        Err(Ok(Error::UnauthorizedUpgrade))
    );
    // Re-registering the same hash for the same version is refused.
    assert_eq!(
        client.try_register_wasm_hash(&admin, &ModuleKind::Wallet, &1, &new),
        Err(Ok(Error::AlreadyExists))
    );
}

#[test]
fn only_the_admin_can_manage_approved_hashes() {
    let (env, client, admin) = setup();
    let stranger = Address::generate(&env);
    let h = hash(&env, 7);
    assert_eq!(
        client.try_register_wasm_hash(&stranger, &ModuleKind::Wallet, &1, &h),
        Err(Ok(Error::Unauthorized))
    );
    client.register_wasm_hash(&admin, &ModuleKind::Wallet, &1, &h);
    assert_eq!(
        client.try_revoke_wasm_hash(&stranger, &ModuleKind::Wallet, &1),
        Err(Ok(Error::Unauthorized))
    );
    // Version 0 is not a valid implementation version.
    assert_eq!(
        client.try_register_wasm_hash(&admin, &ModuleKind::Wallet, &0, &h),
        Err(Ok(Error::InvalidInput))
    );
}

#[test]
fn freezing_the_registry_halts_upgrade_authorization() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    let h = hash(&env, 8);
    client.register_wasm_hash(&admin, &ModuleKind::Policy, &1, &h);

    client.freeze(&owner, &org);
    assert_eq!(
        client.try_is_upgrade_approved(&ModuleKind::Policy, &h),
        Err(Ok(Error::RegistryFrozen))
    );

    client.unfreeze(&owner, &org);
    assert_eq!(client.is_upgrade_approved(&ModuleKind::Policy, &h), 1);
}

#[test]
fn member_upgrade_is_authorized_against_the_registry() {
    let (env, registry, member, admin) = upgrade_setup();
    let approved = hash(&env, 11);
    registry.register_wasm_hash(&admin, &ModuleKind::Wallet, &3, &approved);

    // The member resolves the hash through the registry and gets its version.
    assert_eq!(member.check_upgrade(&admin, &approved), 3);
}

#[test]
fn member_upgrade_to_unapproved_hash_is_refused() {
    let (env, registry, member, admin) = upgrade_setup();
    registry.register_wasm_hash(&admin, &ModuleKind::Wallet, &1, &hash(&env, 11));
    let rogue = hash(&env, 12);

    // Neither the dry run nor the real upgrade may proceed, so the member keeps
    // running its current code.
    assert_eq!(
        member.try_check_upgrade(&admin, &rogue),
        Err(Ok(Error::UnauthorizedUpgrade))
    );
    assert_eq!(
        member.try_upgrade(&admin, &rogue),
        Err(Ok(Error::UnauthorizedUpgrade))
    );
}

#[test]
fn member_upgrade_rejects_a_hash_approved_for_another_module() {
    let (env, registry, member, admin) = upgrade_setup();
    // Approved as a Treasury implementation, not a Wallet one.
    let other = hash(&env, 13);
    registry.register_wasm_hash(&admin, &ModuleKind::Treasury, &1, &other);
    assert_eq!(
        member.try_check_upgrade(&admin, &other),
        Err(Ok(Error::UnauthorizedUpgrade))
    );
}

#[test]
fn member_upgrade_requires_the_upgrade_admin() {
    let (env, registry, member, admin) = upgrade_setup();
    let approved = hash(&env, 14);
    registry.register_wasm_hash(&admin, &ModuleKind::Wallet, &1, &approved);
    let stranger = Address::generate(&env);

    assert_eq!(
        member.try_check_upgrade(&stranger, &approved),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(
        member.try_upgrade(&stranger, &approved),
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
fn member_upgrade_needs_a_configured_authority() {
    let (env, _registry, _member, _admin) = upgrade_setup();
    // A member that never had its authority bootstrapped cannot upgrade at all.
    let bare_id = env.register_contract(None, UpgradeMember);
    let bare = UpgradeMemberClient::new(&env, &bare_id);
    assert_eq!(
        bare.try_check_upgrade(&Address::generate(&env), &hash(&env, 15)),
        Err(Ok(Error::NotInitialized))
    );
}

#[test]
fn upgrade_authority_rotation_is_admin_gated() {
    let (env, registry, member, admin) = upgrade_setup();
    let stranger = Address::generate(&env);
    let new_admin = Address::generate(&env);

    // Only the current upgrade admin may rotate the authority.
    assert_eq!(
        member.try_set_upgrade_authority(&stranger, &stranger, &registry.address),
        Err(Ok(Error::Unauthorized))
    );
    member.set_upgrade_authority(&admin, &new_admin, &registry.address);

    let approved = hash(&env, 16);
    registry.register_wasm_hash(&admin, &ModuleKind::Wallet, &1, &approved);
    assert_eq!(member.check_upgrade(&new_admin, &approved), 1);
    assert_eq!(
        member.try_check_upgrade(&admin, &approved),
        Err(Ok(Error::Unauthorized))
    );
}

#[test]
fn frozen_registry_blocks_member_upgrades() {
    let (env, registry, member, admin) = upgrade_setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    registry.register_org(&admin, &org, &owner);
    let approved = hash(&env, 17);
    registry.register_wasm_hash(&admin, &ModuleKind::Wallet, &1, &approved);
    registry.freeze(&owner, &org);

    // The freeze reaches all the way through to the member contract.
    assert_eq!(
        member.try_check_upgrade(&admin, &approved),
        Err(Ok(Error::RegistryFrozen))
    );
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
