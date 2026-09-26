#![cfg(test)]
extern crate std;

use crate::{
    DataKey, RegistryContract, RegistryContractClient, RegistryRole, UpgradeAction,
    UpgradeAuditRecord,
};
use astroid_shared::constants::{
    MAX_REGISTRY_BATCH, MAX_UPGRADE_AUDIT_ENTRIES, PERSISTENT_BUMP_AMOUNT,
};
use astroid_shared::errors::Error;
use astroid_shared::types::{ModuleId, ModuleInfo, ModuleKind};
use soroban_sdk::testutils::{storage::Persistent as _, Address as _, AuthorizedFunction, Ledger};
use soroban_sdk::{
    symbol_short, testutils::Events, vec, Address, BytesN, Env, IntoVal, String, Symbol, Val, Vec,
};

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

/// Count canonical `ContractEvent` emissions of the given variant symbol so
/// tests can also assert that an event did *not* fire.
fn count_events(env: &Env, variant: &str) -> usize {
    let want: Val = Symbol::new(env, variant).into_val(env);
    env.events()
        .all()
        .iter()
        .filter(|(_contract_id, topics, _data)| topics.contains(want))
        .count()
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
    let h1 = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 1);
    let h2 = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 2);
    client.register_version(&admin, &ModuleKind::Wallet, &1, &v1, &h1);
    client.register_version(&admin, &ModuleKind::Wallet, &2, &v2, &h2);
    assert_eq!(client.get_version(&ModuleKind::Wallet, &1), v1);
    assert_eq!(client.get_version(&ModuleKind::Wallet, &2), v2);
    // Latest points at the highest registered version.
    assert_eq!(client.get_latest(&ModuleKind::Wallet), v2);
}

#[test]
fn register_version_zero_fails() {
    let (env, client, admin) = setup();
    let addr = Address::generate(&env);
    let h = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 1);
    let res = client.try_register_version(&admin, &ModuleKind::Wallet, &0, &addr, &h);
    assert_eq!(res, Err(Ok(Error::InvalidInput)));
}

// --- Version registration: auth, hash integrity, immutability (Issue #217) ---

/// Approve `[seed; 32]` for `kind` and return it.
fn approved_hash(
    env: &Env,
    client: &RegistryContractClient,
    admin: &Address,
    kind: ModuleKind,
    seed: u8,
) -> BytesN<32> {
    let h = BytesN::from_array(env, &[seed; 32]);
    client.add_approved_wasm(admin, &kind, &h);
    h
}

#[test]
fn register_version_binds_hash_and_is_retrievable() {
    let (env, client, admin) = setup();
    let addr = Address::generate(&env);
    let h = approved_hash(&env, &client, &admin, ModuleKind::Policy, 7);

    client.register_version(&admin, &ModuleKind::Policy, &3, &addr, &h);

    assert_eq!(client.get_version(&ModuleKind::Policy, &3), addr);
    assert_eq!(client.get_version_wasm(&ModuleKind::Policy, &3), h);
    assert_eq!(client.get_latest(&ModuleKind::Policy), addr);
    assert_eq!(client.verify_version(&ModuleKind::Policy, &3, &h), addr);
}

#[test]
fn register_version_demands_the_admin_signature() {
    let (env, client, admin) = setup();
    let addr = Address::generate(&env);
    let h = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 1);

    client.register_version(&admin, &ModuleKind::Wallet, &1, &addr, &h);

    // The admin's signature was required for exactly this invocation.
    let auths = env.auths();
    assert_eq!(auths.len(), 1);
    let (signer, invocation) = &auths[0];
    assert_eq!(signer, &admin);
    match &invocation.function {
        AuthorizedFunction::Contract((contract, function, _args)) => {
            assert_eq!(contract, &client.address);
            assert_eq!(function, &Symbol::new(&env, "register_version"));
        }
        _ => panic!("expected a contract invocation"),
    }
}

#[test]
fn register_version_without_any_signature_is_rejected() {
    let env = Env::default();
    let contract_id = env.register_contract(None, RegistryContract);
    let client = RegistryContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin);
    let h = BytesN::from_array(&env, &[1; 32]);
    let addr = Address::generate(&env);

    // Approving and registering both need the admin's auth; with no auth
    // mocked the host refuses before anything is written.
    assert!(client
        .try_add_approved_wasm(&admin, &ModuleKind::Wallet, &h)
        .is_err());
    assert!(client
        .try_register_version(&admin, &ModuleKind::Wallet, &1, &addr, &h)
        .is_err());
    assert_eq!(
        client.try_get_version(&ModuleKind::Wallet, &1),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn non_admin_cannot_register_version() {
    let (env, client, admin, org, owner) = setup_org();
    let addr = Address::generate(&env);
    let h = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 1);
    let stranger = Address::generate(&env);
    let upgrader = Address::generate(&env);
    client.grant_role(&owner, &org, &upgrader, &RegistryRole::ModuleUpgrader);

    // Neither a stranger, an org owner, nor an org-scoped ModuleUpgrader may
    // write the global version map: it is protocol-admin only.
    for caller in [&stranger, &owner, &upgrader] {
        assert_eq!(
            client.try_register_version(caller, &ModuleKind::Wallet, &1, &addr, &h),
            Err(Ok(Error::Unauthorized))
        );
    }
    assert_eq!(
        client.try_get_version(&ModuleKind::Wallet, &1),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(
        client.try_get_latest(&ModuleKind::Wallet),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn non_admin_cannot_approve_wasm() {
    let (env, client, admin) = setup();
    let stranger = Address::generate(&env);
    let h = BytesN::from_array(&env, &[9; 32]);
    assert_eq!(
        client.try_add_approved_wasm(&stranger, &ModuleKind::Wallet, &h),
        Err(Ok(Error::Unauthorized))
    );
    assert!(!client.is_wasm_approved(&ModuleKind::Wallet, &h));

    client.add_approved_wasm(&admin, &ModuleKind::Wallet, &h);
    assert_eq!(
        client.try_remove_approved_wasm(&stranger, &ModuleKind::Wallet, &h),
        Err(Ok(Error::Unauthorized))
    );
    assert!(client.is_wasm_approved(&ModuleKind::Wallet, &h));
}

#[test]
fn register_version_rejects_unapproved_hash() {
    let (env, client, admin) = setup();
    let addr = Address::generate(&env);
    let unapproved = BytesN::from_array(&env, &[42; 32]);

    assert_eq!(
        client.try_register_version(&admin, &ModuleKind::Wallet, &1, &addr, &unapproved),
        Err(Ok(Error::Unauthorized))
    );
    // A rejected registration writes nothing, including the latest pointer.
    assert_eq!(
        client.try_get_version(&ModuleKind::Wallet, &1),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(
        client.try_get_version_wasm(&ModuleKind::Wallet, &1),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(
        client.try_get_latest(&ModuleKind::Wallet),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn register_version_rejects_hash_approved_for_another_kind() {
    let (env, client, admin) = setup();
    let addr = Address::generate(&env);
    let treasury_code = approved_hash(&env, &client, &admin, ModuleKind::Treasury, 5);

    assert_eq!(
        client.try_register_version(&admin, &ModuleKind::Wallet, &1, &addr, &treasury_code),
        Err(Ok(Error::Unauthorized))
    );
}

#[test]
fn register_version_rejects_revoked_hash() {
    let (env, client, admin) = setup();
    let addr = Address::generate(&env);
    let h = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 1);
    client.remove_approved_wasm(&admin, &ModuleKind::Wallet, &h);

    assert_eq!(
        client.try_register_version(&admin, &ModuleKind::Wallet, &1, &addr, &h),
        Err(Ok(Error::Unauthorized))
    );
}

#[test]
fn registered_version_cannot_be_repointed() {
    let (env, client, admin) = setup();
    let original = Address::generate(&env);
    let hijack = Address::generate(&env);
    let h1 = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 1);
    let h2 = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 2);
    client.register_version(&admin, &ModuleKind::Wallet, &1, &original, &h1);

    // Even the admin with an approved hash cannot overwrite a published
    // version, so a consumer pinned to v1 keeps getting v1.
    assert_eq!(
        client.try_register_version(&admin, &ModuleKind::Wallet, &1, &hijack, &h2),
        Err(Ok(Error::AlreadyExists))
    );
    assert_eq!(client.get_version(&ModuleKind::Wallet, &1), original);
    assert_eq!(client.get_version_wasm(&ModuleKind::Wallet, &1), h1);
}

#[test]
fn same_version_number_is_independent_per_kind() {
    let (env, client, admin) = setup();
    let wallet_v1 = Address::generate(&env);
    let policy_v1 = Address::generate(&env);
    let hw = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 1);
    let hp = approved_hash(&env, &client, &admin, ModuleKind::Policy, 2);

    client.register_version(&admin, &ModuleKind::Wallet, &1, &wallet_v1, &hw);
    client.register_version(&admin, &ModuleKind::Policy, &1, &policy_v1, &hp);
    assert_eq!(client.get_version(&ModuleKind::Wallet, &1), wallet_v1);
    assert_eq!(client.get_version(&ModuleKind::Policy, &1), policy_v1);
}

#[test]
fn backfilled_older_version_does_not_move_latest() {
    let (env, client, admin) = setup();
    let v1 = Address::generate(&env);
    let v5 = Address::generate(&env);
    let h1 = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 1);
    let h5 = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 5);

    client.register_version(&admin, &ModuleKind::Wallet, &5, &v5, &h5);
    client.register_version(&admin, &ModuleKind::Wallet, &1, &v1, &h1);
    assert_eq!(client.get_latest(&ModuleKind::Wallet), v5);
    assert_eq!(client.get_version(&ModuleKind::Wallet, &1), v1);
}

#[test]
fn frozen_registry_blocks_version_registration() {
    let (env, client, admin, org, owner) = setup_org();
    let addr = Address::generate(&env);
    let h = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 1);
    client.freeze(&owner, &org);

    assert_eq!(
        client.try_register_version(&admin, &ModuleKind::Wallet, &1, &addr, &h),
        Err(Ok(Error::RegistryFrozen))
    );
    client.unfreeze(&owner, &org);
    client.register_version(&admin, &ModuleKind::Wallet, &1, &addr, &h);
    assert_eq!(client.get_version(&ModuleKind::Wallet, &1), addr);
}

#[test]
fn unknown_version_keys_fail_with_not_found() {
    let (env, client, admin) = setup();
    let h = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 1);

    assert_eq!(
        client.try_get_version(&ModuleKind::Wallet, &1),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(
        client.try_get_version_wasm(&ModuleKind::Wallet, &1),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(
        client.try_get_latest(&ModuleKind::Wallet),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(
        client.try_verify_version(&ModuleKind::Wallet, &1, &h),
        Err(Ok(Error::NotFound))
    );

    // A registered kind still reports NotFound for a version it lacks.
    let addr = Address::generate(&env);
    client.register_version(&admin, &ModuleKind::Wallet, &1, &addr, &h);
    assert_eq!(
        client.try_get_version(&ModuleKind::Wallet, &2),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(
        client.try_verify_version(&ModuleKind::Wallet, &2, &h),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn verify_version_rejects_mismatched_hash() {
    let (env, client, admin) = setup();
    let addr = Address::generate(&env);
    let h1 = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 1);
    let other = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 2);
    client.register_version(&admin, &ModuleKind::Wallet, &1, &addr, &h1);

    // Approved, but not the code v1 was registered with.
    assert_eq!(
        client.try_verify_version(&ModuleKind::Wallet, &1, &other),
        Err(Ok(Error::InvalidInput))
    );
    assert_eq!(client.verify_version(&ModuleKind::Wallet, &1, &h1), addr);
}

#[test]
fn verify_version_fails_once_the_bound_hash_is_revoked() {
    let (env, client, admin) = setup();
    let addr = Address::generate(&env);
    let h = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 1);
    client.register_version(&admin, &ModuleKind::Wallet, &1, &addr, &h);
    client.remove_approved_wasm(&admin, &ModuleKind::Wallet, &h);

    assert_eq!(
        client.try_verify_version(&ModuleKind::Wallet, &1, &h),
        Err(Ok(Error::Unauthorized))
    );
    // The record itself is untouched; only its verification now fails.
    assert_eq!(client.get_version(&ModuleKind::Wallet, &1), addr);
}

#[test]
fn legacy_version_without_bound_hash_never_verifies() {
    let (env, client, admin) = setup();
    let addr = Address::generate(&env);
    let h = approved_hash(&env, &client, &admin, ModuleKind::Wallet, 1);
    // A record written before hashes were bound: address only.
    env.as_contract(&client.address, || {
        env.storage()
            .persistent()
            .set(&DataKey::Version(ModuleKind::Wallet, 1), &addr);
    });

    assert_eq!(client.get_version(&ModuleKind::Wallet, &1), addr);
    assert_eq!(
        client.try_get_version_wasm(&ModuleKind::Wallet, &1),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(
        client.try_verify_version(&ModuleKind::Wallet, &1, &h),
        Err(Ok(Error::InvalidInput))
    );
}

#[test]
fn version_registration_emits_structured_event() {
    let (env, client, admin) = setup();
    let addr = Address::generate(&env);
    let h = approved_hash(&env, &client, &admin, ModuleKind::Escrow, 3);

    client.register_version(&admin, &ModuleKind::Escrow, &4, &addr, &h);

    let want_topic: Val = Symbol::new(&env, "RegistryVersionRegistered").into_val(&env);
    let event = env
        .events()
        .all()
        .iter()
        .find(|(_id, topics, _data)| topics.contains(want_topic))
        .expect("RegistryVersionRegistered must be emitted");
    assert_eq!(event.0, client.address);
    let data: (ModuleKind, u32, Address, BytesN<32>) = event.2.into_val(&env);
    assert_eq!(data, (ModuleKind::Escrow, 4, addr.clone(), h));

    // The legacy tuple-topic event is still published for existing consumers.
    let legacy: Vec<Val> = (
        symbol_short!("version"),
        symbol_short!("register"),
        ModuleKind::Escrow,
        4u32,
    )
        .into_val(&env);
    assert!(env
        .events()
        .all()
        .iter()
        .any(|(_id, topics, _data)| topics == legacy));
}

#[test]
fn rejected_registration_emits_no_version_event() {
    let (env, client, admin) = setup();
    let addr = Address::generate(&env);
    let unapproved = BytesN::from_array(&env, &[1; 32]);
    let _ = client.try_register_version(&admin, &ModuleKind::Wallet, &1, &addr, &unapproved);

    let want_topic: Val = Symbol::new(&env, "RegistryVersionRegistered").into_val(&env);
    assert!(!env
        .events()
        .all()
        .iter()
        .any(|(_id, topics, _data)| topics.contains(want_topic)));
}

#[test]
fn register_version_rejects_downgrades_and_repeats() {
    let (env, client, admin) = setup();
    let v1 = Address::generate(&env);
    let v2 = Address::generate(&env);
    client.register_version(&admin, &ModuleKind::Wallet, &1, &v1);
    client.register_version(&admin, &ModuleKind::Wallet, &2, &v2);

    // The version table is monotonic per kind: the admin escape hatch may
    // never lower or repeat the latest version, mirroring the propose/commit
    // flow's downgrade protection (Issue #304).
    let addr = Address::generate(&env);
    assert_eq!(
        client.try_register_version(&admin, &ModuleKind::Wallet, &2, &addr),
        Err(Ok(Error::InvalidState))
    );
    assert_eq!(
        client.try_register_version(&admin, &ModuleKind::Wallet, &1, &addr),
        Err(Ok(Error::InvalidState))
    );
    // Strictly newer versions still land.
    let v3 = Address::generate(&env);
    client.register_version(&admin, &ModuleKind::Wallet, &3, &v3);
    assert_eq!(client.get_latest(&ModuleKind::Wallet), v3);
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

// --- registry-gated upgrades ---

/// Two independent registry instances: `registry` plays the protocol registry
/// that authorizes implementations, `member` plays a contract being upgraded
/// (every member contract carries the same three upgrade entrypoints).
struct UpgradeHarness {
    env: Env,
    registry: RegistryContractClient<'static>,
    registry_id: Address,
    member: RegistryContractClient<'static>,
    admin: Address,
}

fn setup_upgrade() -> UpgradeHarness {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);

    let registry_id = env.register_contract(None, RegistryContract);
    let registry = RegistryContractClient::new(&env, &registry_id);
    registry.initialize(&admin);

    let member_id = env.register_contract(None, RegistryContract);
    let member = RegistryContractClient::new(&env, &member_id);
    member.initialize(&admin);

    UpgradeHarness {
        env,
        registry,
        registry_id,
        member,
        admin,
    }
}

fn hash(env: &Env, seed: u8) -> soroban_sdk::BytesN<32> {
    soroban_sdk::BytesN::from_array(env, &[seed; 32])
}

#[test]
fn upgrade_authority_is_recorded_and_readable() {
    let h = setup_upgrade();
    h.member
        .set_upgrade_authority(&h.admin, &h.admin, &h.registry_id);
    let authority = h.member.get_upgrade_authority();
    assert_eq!(authority.admin, h.admin);
    assert_eq!(authority.registry, h.registry_id);
}

#[test]
fn upgrade_needs_a_configured_authority() {
    let h = setup_upgrade();
    assert_eq!(
        h.member.try_upgrade(&h.admin, &hash(&h.env, 1)),
        Err(Ok(Error::NotInitialized))
    );
}

#[test]
fn upgrade_to_an_unapproved_hash_is_refused() {
    let h = setup_upgrade();
    h.member
        .set_upgrade_authority(&h.admin, &h.admin, &h.registry_id);
    // Nothing has been approved for this kind, so the registry says no.
    assert_eq!(
        h.member.try_upgrade(&h.admin, &hash(&h.env, 1)),
        Err(Ok(Error::Unauthorized))
    );
}

#[test]
fn upgrade_requires_the_recorded_admin() {
    let h = setup_upgrade();
    let stranger = Address::generate(&h.env);
    h.member
        .set_upgrade_authority(&h.admin, &h.admin, &h.registry_id);
    // Approved in the registry, but the caller is not the upgrade admin.
    h.registry
        .add_approved_wasm(&h.admin, &ModuleKind::Organization, &hash(&h.env, 1));
    assert_eq!(
        h.member.try_upgrade(&stranger, &hash(&h.env, 1)),
        Err(Ok(Error::Unauthorized))
    );
}

#[test]
fn approval_is_scoped_to_the_module_kind() {
    let h = setup_upgrade();
    h.member
        .set_upgrade_authority(&h.admin, &h.admin, &h.registry_id);
    // Approved for a different kind than the member reports, so it must not
    // satisfy this member's gate.
    h.registry
        .add_approved_wasm(&h.admin, &ModuleKind::Wallet, &hash(&h.env, 1));
    assert!(h
        .registry
        .is_wasm_approved(&ModuleKind::Wallet, &hash(&h.env, 1)));
    assert!(!h
        .registry
        .is_wasm_approved(&ModuleKind::Organization, &hash(&h.env, 1)));
    assert_eq!(
        h.member.try_upgrade(&h.admin, &hash(&h.env, 1)),
        Err(Ok(Error::Unauthorized))
    );
}

#[test]
fn a_revoked_hash_stops_authorizing_upgrades() {
    let h = setup_upgrade();
    h.member
        .set_upgrade_authority(&h.admin, &h.admin, &h.registry_id);
    h.registry
        .add_approved_wasm(&h.admin, &ModuleKind::Organization, &hash(&h.env, 1));
    h.registry
        .remove_approved_wasm(&h.admin, &ModuleKind::Organization, &hash(&h.env, 1));
    assert_eq!(
        h.member.try_upgrade(&h.admin, &hash(&h.env, 1)),
        Err(Ok(Error::Unauthorized))
    );
}

#[test]
fn only_the_current_admin_can_rotate_the_authority() {
    let h = setup_upgrade();
    let stranger = Address::generate(&h.env);
    h.member
        .set_upgrade_authority(&h.admin, &h.admin, &h.registry_id);
    assert_eq!(
        h.member
            .try_set_upgrade_authority(&stranger, &stranger, &h.registry_id),
        Err(Ok(Error::Unauthorized))
    );
    // The incumbent may hand the role over.
    h.member
        .set_upgrade_authority(&h.admin, &stranger, &h.registry_id);
    assert_eq!(h.member.get_upgrade_authority().admin, stranger);
}

#[test]
fn only_the_registry_admin_can_bootstrap_the_upgrade_authority() {
    let h = setup_upgrade();
    let squatter = Address::generate(&h.env);
    // Before bootstrap, a stranger cannot claim upgrade rights over the
    // registry by getting to `set_upgrade_authority` first.
    assert_eq!(
        h.member
            .try_set_upgrade_authority(&squatter, &squatter, &h.registry_id),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(
        h.member.try_get_upgrade_authority(),
        Err(Ok(Error::NotInitialized))
    );

    h.member
        .set_upgrade_authority(&h.admin, &h.admin, &h.registry_id);
    assert_eq!(h.member.get_upgrade_authority().admin, h.admin);
}

#[test]
fn uninitialized_registry_cannot_bootstrap_the_upgrade_authority() {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register_contract(None, RegistryContract);
    let client = RegistryContractClient::new(&env, &id);
    let anyone = Address::generate(&env);
    assert_eq!(
        client.try_set_upgrade_authority(&anyone, &anyone, &id),
        Err(Ok(Error::Unauthorized))
    );
}

// --- Batch lookup (Issue #228) ---

fn module_id(env: &Env, org: &str, kind: ModuleKind) -> ModuleId {
    ModuleId {
        org: String::from_str(env, org),
        kind,
    }
}

fn live(address: &Address) -> Option<ModuleInfo> {
    Some(ModuleInfo {
        address: address.clone(),
        deprecated: false,
    })
}

/// Register org "acme" with Wallet, Treasury and Policy modules; returns the
/// three module addresses in that order.
fn setup_acme(env: &Env, client: &RegistryContractClient, admin: &Address) -> [Address; 3] {
    let org = String::from_str(env, "acme");
    let owner = Address::generate(env);
    client.register_org(admin, &org, &owner);
    let modules = [
        Address::generate(env),
        Address::generate(env),
        Address::generate(env),
    ];
    let kinds = [ModuleKind::Wallet, ModuleKind::Treasury, ModuleKind::Policy];
    for (kind, address) in kinds.iter().zip(modules.iter()) {
        client.register_module(&owner, &org, kind, address);
    }
    modules
}

#[test]
fn batch_returns_every_registered_module_in_request_order() {
    let (env, client, admin) = setup();
    let [wallet, treasury, policy] = setup_acme(&env, &client, &admin);

    // Deliberately not in registration order.
    let ids = vec![
        &env,
        module_id(&env, "acme", ModuleKind::Policy),
        module_id(&env, "acme", ModuleKind::Wallet),
        module_id(&env, "acme", ModuleKind::Treasury),
    ];
    assert_eq!(
        client.get_modules_batch(&ids),
        vec![&env, live(&policy), live(&wallet), live(&treasury)]
    );
}

#[test]
fn batch_reports_missing_modules_as_none_in_place() {
    let (env, client, admin) = setup();
    let [wallet, _treasury, policy] = setup_acme(&env, &client, &admin);

    let ids = vec![
        &env,
        module_id(&env, "acme", ModuleKind::Escrow), // kind never registered
        module_id(&env, "acme", ModuleKind::Wallet),
        module_id(&env, "ghost", ModuleKind::Wallet), // org never registered
        module_id(&env, "acme", ModuleKind::Policy),
    ];
    assert_eq!(
        client.get_modules_batch(&ids),
        vec![&env, None, live(&wallet), None, live(&policy)]
    );
}

#[test]
fn batch_of_only_missing_modules_is_all_none() {
    let (env, client, _admin) = setup();
    let ids = vec![
        &env,
        module_id(&env, "ghost", ModuleKind::Wallet),
        module_id(&env, "ghost", ModuleKind::Budget),
    ];
    assert_eq!(client.get_modules_batch(&ids), vec![&env, None, None]);
}

#[test]
fn empty_batch_returns_empty_list() {
    let (env, client, _admin) = setup();
    assert_eq!(client.get_modules_batch(&Vec::new(&env)), Vec::new(&env));
}

#[test]
fn batch_at_the_size_limit_succeeds() {
    let (env, client, admin) = setup();
    let [wallet, _treasury, _policy] = setup_acme(&env, &client, &admin);

    let mut ids = Vec::new(&env);
    for _ in 0..MAX_REGISTRY_BATCH {
        ids.push_back(module_id(&env, "acme", ModuleKind::Wallet));
    }
    let result = client.get_modules_batch(&ids);
    assert_eq!(result.len(), MAX_REGISTRY_BATCH);
    assert!(result.iter().all(|m| m == live(&wallet)));
}

#[test]
fn batch_over_the_size_limit_is_rejected() {
    let (env, client, admin) = setup();
    setup_acme(&env, &client, &admin);

    let mut ids = Vec::new(&env);
    for _ in 0..=MAX_REGISTRY_BATCH {
        ids.push_back(module_id(&env, "acme", ModuleKind::Wallet));
    }
    assert_eq!(
        client.try_get_modules_batch(&ids),
        Err(Ok(Error::InvalidInput))
    );
}

#[test]
fn batch_size_is_checked_before_any_storage_read() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    client.register_org(&admin, &org, &Address::generate(&env));
    client.freeze(&admin, &org);

    let mut ids = Vec::new(&env);
    for _ in 0..=MAX_REGISTRY_BATCH {
        ids.push_back(module_id(&env, "acme", ModuleKind::Wallet));
    }
    // The freeze flag is itself a storage read; an oversized batch is refused
    // on its length alone, before the freeze flag is consulted.
    assert_eq!(
        client.try_get_modules_batch(&ids),
        Err(Ok(Error::InvalidInput))
    );
    let one = vec![&env, module_id(&env, "acme", ModuleKind::Wallet)];
    assert_eq!(
        client.try_get_modules_batch(&one),
        Err(Ok(Error::RegistryFrozen))
    );
}

#[test]
fn batch_answers_duplicate_ids_at_every_position() {
    let (env, client, admin) = setup();
    let [wallet, treasury, _policy] = setup_acme(&env, &client, &admin);

    let ids = vec![
        &env,
        module_id(&env, "acme", ModuleKind::Wallet),
        module_id(&env, "acme", ModuleKind::Treasury),
        module_id(&env, "acme", ModuleKind::Wallet),
        module_id(&env, "ghost", ModuleKind::Wallet),
        module_id(&env, "ghost", ModuleKind::Wallet),
    ];
    assert_eq!(
        client.get_modules_batch(&ids),
        vec![
            &env,
            live(&wallet),
            live(&treasury),
            live(&wallet),
            None,
            None
        ]
    );
}

#[test]
fn batch_agrees_with_the_single_lookups() {
    let (env, client, admin) = setup();
    setup_acme(&env, &client, &admin);
    let org = String::from_str(&env, "acme");
    client.deprecate_module(&admin, &org, &ModuleKind::Treasury);

    let kinds = [
        ModuleKind::Wallet,
        ModuleKind::Treasury, // deprecated
        ModuleKind::Policy,
        ModuleKind::Escrow, // missing
    ];
    let mut ids = Vec::new(&env);
    for kind in kinds {
        ids.push_back(ModuleId {
            org: org.clone(),
            kind,
        });
    }
    let batch = client.get_modules_batch(&ids);
    assert_eq!(batch.len(), ids.len());

    for (id, entry) in ids.iter().zip(batch.iter()) {
        let raw = client.try_get_module_address(&id.org, &id.kind);
        let routed = client.try_lookup(&id.org, &id.kind);
        match entry {
            None => {
                assert_eq!(raw, Err(Ok(Error::NotFound)));
                assert_eq!(routed, Err(Ok(Error::NotFound)));
            }
            Some(info) => {
                assert_eq!(raw, Ok(Ok(info.address.clone())));
                assert_eq!(
                    info.deprecated,
                    client.is_module_deprecated(&id.org, &id.kind)
                );
                if info.deprecated {
                    assert_eq!(routed, Err(Ok(Error::ModuleDeprecated)));
                } else {
                    assert_eq!(routed, Ok(Ok(info.address)));
                }
            }
        }
    }
}

#[test]
fn batch_reports_deprecated_modules_without_failing() {
    let (env, client, admin) = setup();
    let [wallet, treasury, _policy] = setup_acme(&env, &client, &admin);
    let org = String::from_str(&env, "acme");
    client.deprecate_module(&admin, &org, &ModuleKind::Wallet);

    let ids = vec![
        &env,
        module_id(&env, "acme", ModuleKind::Wallet),
        module_id(&env, "acme", ModuleKind::Treasury),
    ];
    assert_eq!(
        client.get_modules_batch(&ids),
        vec![
            &env,
            Some(ModuleInfo {
                address: wallet,
                deprecated: true,
            }),
            live(&treasury),
        ]
    );
}

#[test]
fn batch_extends_ttl_exactly_like_lookup() {
    let (env, client, admin) = setup();
    setup_acme(&env, &client, &admin);
    let org = String::from_str(&env, "acme");
    client.deprecate_module(&admin, &org, &ModuleKind::Treasury);

    let ttl = |kind: ModuleKind| {
        env.as_contract(&client.address, || {
            env.storage()
                .persistent()
                .get_ttl(&DataKey::Module(org.clone(), kind))
        })
    };
    // Age the records past the bump threshold so a read would extend them.
    env.ledger().with_mut(|l| l.sequence_number += 2 * 17_280);
    let aged = ttl(ModuleKind::Wallet);
    assert!(aged < PERSISTENT_BUMP_AMOUNT);
    assert_eq!(ttl(ModuleKind::Treasury), aged);

    let ids = vec![
        &env,
        module_id(&env, "acme", ModuleKind::Wallet),
        module_id(&env, "acme", ModuleKind::Treasury),
    ];
    client.get_modules_batch(&ids);
    // A live record is extended, as a successful `lookup` extends it; a
    // deprecated one is left alone, as `lookup` (which refuses it) does.
    assert_eq!(ttl(ModuleKind::Wallet), PERSISTENT_BUMP_AMOUNT);
    assert_eq!(ttl(ModuleKind::Treasury), aged);

    // `lookup` on the policy record produces the same extension.
    client.lookup(&org, &ModuleKind::Policy);
    assert_eq!(ttl(ModuleKind::Policy), PERSISTENT_BUMP_AMOUNT);
}

// --- version upgrade validation (Issue #304) ---

/// Bundled addresses for an org with a delegated module upgrader, so the
/// upgrade-validation tests can exercise the whole authorization matrix.
struct UpgradeFlow {
    env: Env,
    client: RegistryContractClient<'static>,
    admin: Address,
    owner: Address,
    upgrader: Address,
    stranger: Address,
}

fn setup_upgrade_flow(org: &str) -> UpgradeFlow {
    let (env, client, admin) = setup();
    let owner = Address::generate(&env);
    let upgrader = Address::generate(&env);
    let stranger = Address::generate(&env);
    let org = String::from_str(&env, org);
    client.register_org(&admin, &org, &owner);
    client.grant_role(&owner, &org, &upgrader, &RegistryRole::ModuleUpgrader);
    UpgradeFlow {
        env,
        client,
        admin,
        owner,
        upgrader,
        stranger,
    }
}

fn upgrade_args(
    h: &UpgradeFlow,
    version: u32,
    seed: u8,
) -> (String, ModuleKind, u32, BytesN<32>, Address) {
    (
        String::from_str(&h.env, "acme"),
        ModuleKind::Wallet,
        version,
        hash(&h.env, seed),
        Address::generate(&h.env),
    )
}

#[test]
fn propose_and_commit_a_valid_upgrade() {
    let h = setup_upgrade_flow("acme");
    let (org, kind, version, wasm, addr) = upgrade_args(&h, 1, 1);

    h.client
        .propose_upgrade(&h.owner, &org, &kind, &version, &wasm, &addr);
    let pending = h.client.get_upgrade_proposal(&kind).unwrap();
    assert_eq!(pending.version, 1);
    assert_eq!(pending.wasm_hash, wasm);
    assert_eq!(pending.address, addr);
    assert_eq!(pending.proposer, h.owner);
    assert!(pending.expires_at > h.env.ledger().timestamp());

    let (committed_version, committed_addr) = h.client.commit_upgrade(&h.admin, &kind);
    assert_eq!(
        (committed_version, committed_addr.clone()),
        (version, addr.clone())
    );
    // The version table and the wasm approval both advanced.
    assert_eq!(h.client.get_version(&kind, &1), addr);
    assert_eq!(h.client.get_latest(&kind), addr);
    assert!(h.client.is_wasm_approved(&kind, &wasm));
    // The pending record is consumed.
    assert_eq!(h.client.get_upgrade_proposal(&kind), None);

    assert_event(&h.env, "UpgradeProposed");
    assert_event(&h.env, "UpgradeCommitted");
}

#[test]
fn stranger_and_delegated_non_upgrader_cannot_propose() {
    let h = setup_upgrade_flow("acme");
    let policy_manager = Address::generate(&h.env);
    h.client.grant_role(
        &h.owner,
        &String::from_str(&h.env, "acme"),
        &policy_manager,
        &RegistryRole::PolicyManager,
    );

    // A stranger targeting an unknown org learns only NotFound.
    let (org, kind, version, wasm, addr) = upgrade_args(&h, 1, 1);
    assert_eq!(
        h.client.try_propose_upgrade(
            &h.stranger,
            &String::from_str(&h.env, "ghost"),
            &kind,
            &version,
            &wasm,
            &addr
        ),
        Err(Ok(Error::NotFound))
    );
    #[allow(clippy::needless_borrows_for_generic_args)]
    let _ = (&org, &version, &wasm, &addr);
    // A stranger on a real org is Unauthorized.
    assert_eq!(
        h.client
            .try_propose_upgrade(&h.stranger, &org, &kind, &version, &wasm, &addr),
        Err(Ok(Error::Unauthorized))
    );
    // A delegated role that cannot manage modules is Unauthorized too.
    assert_eq!(
        h.client
            .try_propose_upgrade(&policy_manager, &org, &kind, &version, &wasm, &addr),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(h.client.get_upgrade_proposal(&kind), None);
    let events_after_failures = count_events(&h.env, "UpgradeProposed");
    assert_eq!(events_after_failures, 0);
}

#[test]
fn org_owner_module_upgrader_and_admin_can_propose() {
    let h = setup_upgrade_flow("acme");
    let (org, kind, version, wasm, addr) = upgrade_args(&h, 1, 1);
    h.client
        .propose_upgrade(&h.upgrader, &org, &kind, &version, &wasm, &addr);
    assert!(h.client.get_upgrade_proposal(&kind).is_some());
    h.client.reject_upgrade(&h.admin, &kind);

    // The owner may propose the next slot.
    let (org2, kind2, v2, wasm2, addr2) = upgrade_args(&h, 2, 2);
    h.client
        .propose_upgrade(&h.owner, &org2, &kind2, &v2, &wasm2, &addr2);
    assert!(h.client.get_upgrade_proposal(&kind2).is_some());
    h.client.reject_upgrade(&h.admin, &kind2);

    // The admin may propose directly.
    let (org3, kind3, v3, wasm3, addr3) = upgrade_args(&h, 3, 3);
    h.client
        .propose_upgrade(&h.admin, &org3, &kind3, &v3, &wasm3, &addr3);
    assert!(h.client.get_upgrade_proposal(&kind3).is_some());
}

#[test]
fn zero_version_proposal_fails() {
    let h = setup_upgrade_flow("acme");
    let (org, kind, _, wasm, addr) = upgrade_args(&h, 1, 1);
    assert_eq!(
        h.client
            .try_propose_upgrade(&h.owner, &org, &kind, &0, &wasm, &addr),
        Err(Ok(Error::InvalidInput))
    );
}

#[test]
fn zero_wasm_hash_proposal_fails() {
    let h = setup_upgrade_flow("acme");
    let org = String::from_str(&h.env, "acme");
    let zero = BytesN::from_array(&h.env, &[0u8; 32]);
    assert_eq!(
        h.client.try_propose_upgrade(
            &h.owner,
            &org,
            &ModuleKind::Wallet,
            &1,
            &zero,
            &Address::generate(&h.env)
        ),
        Err(Ok(Error::InvalidInput))
    );
    // add_approved_wasm applies the same format gate.
    assert_eq!(
        h.client
            .try_add_approved_wasm(&h.admin, &ModuleKind::Wallet, &zero),
        Err(Ok(Error::InvalidInput))
    );
}

#[test]
fn downgrade_proposal_fails() {
    let h = setup_upgrade_flow("acme");
    // Commit v2 first.
    let (org, kind, version, wasm, addr) = upgrade_args(&h, 2, 1);
    h.client
        .propose_upgrade(&h.owner, &org, &kind, &version, &wasm, &addr);
    h.client.commit_upgrade(&h.admin, &kind);

    // Proposing v2 again (equal) is a downgrade.
    let (_, _, _, wasm_eq, addr_eq) = upgrade_args(&h, 2, 5);
    assert_eq!(
        h.client
            .try_propose_upgrade(&h.owner, &org, &kind, &2, &wasm_eq, &addr_eq),
        Err(Ok(Error::InvalidState))
    );
    // Proposing v1 (lower) is a downgrade.
    let (_, _, _, wasm_lo, addr_lo) = upgrade_args(&h, 1, 6);
    assert_eq!(
        h.client
            .try_propose_upgrade(&h.owner, &org, &kind, &1, &wasm_lo, &addr_lo),
        Err(Ok(Error::InvalidState))
    );
}

#[test]
fn duplicate_proposal_fails_until_resolved() {
    let h = setup_upgrade_flow("acme");
    let (org, kind, version, wasm, addr) = upgrade_args(&h, 1, 1);
    h.client
        .propose_upgrade(&h.owner, &org, &kind, &version, &wasm, &addr);
    let (_, _, _, wasm2, addr2) = upgrade_args(&h, 2, 2);
    assert_eq!(
        h.client
            .try_propose_upgrade(&h.owner, &org, &kind, &2, &wasm2, &addr2),
        Err(Ok(Error::InvalidState))
    );
    // After rejection the slot is free again.
    h.client.reject_upgrade(&h.owner, &kind);
    h.client
        .propose_upgrade(&h.owner, &org, &kind, &2, &wasm2, &addr2);
    assert!(h.client.get_upgrade_proposal(&kind).is_some());
}

#[test]
fn proposing_an_already_approved_hash_fails() {
    let h = setup_upgrade_flow("acme");
    let (org, kind, version, wasm, addr) = upgrade_args(&h, 1, 1);
    h.client.add_approved_wasm(&h.admin, &kind, &wasm);
    assert_eq!(
        h.client
            .try_propose_upgrade(&h.owner, &org, &kind, &version, &wasm, &addr),
        Err(Ok(Error::InvalidInput))
    );
}

#[test]
fn commit_is_admin_gated() {
    let h = setup_upgrade_flow("acme");
    let (org, kind, version, wasm, addr) = upgrade_args(&h, 1, 1);
    h.client
        .propose_upgrade(&h.owner, &org, &kind, &version, &wasm, &addr);
    assert_eq!(
        h.client.try_commit_upgrade(&h.owner, &kind),
        Err(Ok(Error::Unauthorized))
    );
    // The admin can still commit afterwards.
    h.client.commit_upgrade(&h.admin, &kind);
    assert_eq!(h.client.get_latest(&kind), addr);
}

#[test]
fn commit_without_proposal_fails() {
    let h = setup_upgrade_flow("acme");
    assert_eq!(
        h.client.try_commit_upgrade(&h.admin, &ModuleKind::Wallet),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn expired_proposal_cannot_be_committed() {
    let h = setup_upgrade_flow("acme");
    let (org, kind, version, wasm, addr) = upgrade_args(&h, 1, 1);
    h.client
        .propose_upgrade(&h.owner, &org, &kind, &version, &wasm, &addr);
    let expires_at = h.client.get_upgrade_proposal(&kind).unwrap().expires_at;

    // Advance past expiry, leaving a one-second margin.
    h.env.ledger().set_timestamp(expires_at + 1);
    assert_eq!(
        h.client.try_commit_upgrade(&h.admin, &kind),
        Err(Ok(Error::NotFound))
    );
    // The refused commit reverted atomically, so the stale record itself is
    // untouched — but it stays refuseable on every retry.
    let stale = h.client.get_upgrade_proposal(&kind).unwrap();
    assert_eq!(stale.version, 1);
    assert_eq!(
        h.client.try_commit_upgrade(&h.admin, &kind),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn stale_proposal_cannot_shadow_a_committed_version() {
    let h = setup_upgrade_flow("acme");
    // Proposal A: version 2.
    let (org, kind, _, wasm, addr) = upgrade_args(&h, 2, 1);
    h.client
        .propose_upgrade(&h.owner, &org, &kind, &2, &wasm, &addr);
    // While A is pending, version 3 is committed through a rejected-then
    // re-proposed path: reject A, commit v3, re-propose A → downgrade now.
    h.client.reject_upgrade(&h.owner, &kind);
    let (_, _, _, wasm3, addr3) = upgrade_args(&h, 3, 3);
    h.client
        .propose_upgrade(&h.admin, &org, &kind, &3, &wasm3, &addr3);
    h.client.commit_upgrade(&h.admin, &kind);
    assert_eq!(h.client.get_latest(&kind), addr3);

    // The stale v2 proposal is gone; re-proposing it is refused as a downgrade.
    assert_eq!(h.client.get_upgrade_proposal(&kind), None);
    assert_eq!(
        h.client
            .try_propose_upgrade(&h.owner, &org, &kind, &2, &wasm, &addr),
        Err(Ok(Error::InvalidState))
    );
}

#[test]
fn conflicting_approval_blocked_while_proposal_pending() {
    let h = setup_upgrade_flow("acme");
    let (org, kind, version, wasm, addr) = upgrade_args(&h, 1, 1);
    h.client
        .propose_upgrade(&h.owner, &org, &kind, &version, &wasm, &addr);
    // Approving a different hash while the proposal is open is refused.
    let other = hash(&h.env, 9);
    assert_eq!(
        h.client.try_add_approved_wasm(&h.admin, &kind, &other),
        Err(Ok(Error::InvalidState))
    );
    // Approving the proposed hash itself is allowed (it is what commit does).
    h.client.add_approved_wasm(&h.admin, &kind, &wasm);
    // Commit still works.
    h.client.commit_upgrade(&h.admin, &kind);
    assert_eq!(h.client.get_latest(&kind), addr);
}

#[test]
fn reject_requires_proposer_admin_or_org_owner() {
    let h = setup_upgrade_flow("acme");
    let (org, kind, version, wasm, addr) = upgrade_args(&h, 1, 1);
    h.client
        .propose_upgrade(&h.upgrader, &org, &kind, &version, &wasm, &addr);
    let proposal = h.client.get_upgrade_proposal(&kind).unwrap();

    // A stranger cannot reject.
    assert_eq!(
        h.client.try_reject_upgrade(&h.stranger, &kind),
        Err(Ok(Error::Unauthorized))
    );
    // The org owner (not the proposer) can reject.
    h.client.reject_upgrade(&h.owner, &kind);
    assert_eq!(h.client.get_upgrade_proposal(&kind), None);
    assert_event(&h.env, "UpgradeRejected");
    assert_eq!(proposal.proposer, h.upgrader);

    // Rejecting an empty slot is NotFound, not a silent no-op.
    assert_eq!(
        h.client.try_reject_upgrade(&h.admin, &kind),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn proposer_can_withdraw_their_own_proposal() {
    let h = setup_upgrade_flow("acme");
    let (org, kind, version, wasm, addr) = upgrade_args(&h, 1, 1);
    h.client
        .propose_upgrade(&h.upgrader, &org, &kind, &version, &wasm, &addr);
    h.client.reject_upgrade(&h.upgrader, &kind);
    assert_eq!(h.client.get_upgrade_proposal(&kind), None);
    assert_event(&h.env, "UpgradeRejected");
}

// ---------------------------------------------------------------------------
// Version upgrade audit logging (Issue #300)
// ---------------------------------------------------------------------------

#[test]
fn audit_log_records_propose_commit_and_reject() {
    let h = setup_upgrade_flow("acme");
    let (org, kind, version, wasm, addr) = upgrade_args(&h, 1, 1);
    let before = h.env.ledger().timestamp();

    h.client
        .propose_upgrade(&h.owner, &org, &kind, &version, &wasm, &addr);
    h.client.commit_upgrade(&h.admin, &kind);

    // The two successful lifecycle actions are recorded newest-first with a
    // full audit payload: who, what, when.
    let history = h.client.get_upgrade_history();
    assert_eq!(history.len(), 2);
    let commit = &history.get(0).unwrap();
    assert_eq!(commit.action, UpgradeAction::Committed);
    assert_eq!(commit.audit.kind, ModuleKind::Wallet);
    assert_eq!(commit.audit.version, 1);
    assert_eq!(commit.audit.wasm_hash, wasm);
    assert_eq!(commit.audit.org, org);
    assert_eq!(commit.audit.actor, h.admin);
    assert!(commit.audit.recorded_at >= before);
    let propose = &history.get(1).unwrap();
    assert_eq!(propose.action, UpgradeAction::Proposed);
    assert_eq!(propose.audit.actor, h.owner);
    assert_eq!(propose.audit.version, 1);

    // A rejection is logged too.
    let (org, kind, version, wasm, addr) = upgrade_args(&h, 2, 2);
    h.client
        .propose_upgrade(&h.owner, &org, &kind, &version, &wasm, &addr);
    h.client.reject_upgrade(&h.owner, &kind);
    let history = h.client.get_upgrade_history();
    assert_eq!(history.len(), 4);
    assert_eq!(history.get(0).unwrap().action, UpgradeAction::Rejected);
    assert_eq!(history.get(0).unwrap().audit.actor, h.owner);
    assert_eq!(history.get(1).unwrap().action, UpgradeAction::Proposed);
    assert_eq!(h.client.get_upgrade_history_len(), 4);
}

#[test]
fn audit_log_is_immutable_and_retained_in_instance_storage() {
    let h = setup_upgrade_flow("acme");
    let (org, kind, version, wasm, addr) = upgrade_args(&h, 1, 1);
    h.client
        .propose_upgrade(&h.owner, &org, &kind, &version, &wasm, &addr);
    h.client.commit_upgrade(&h.admin, &kind);
    let before = h.client.get_upgrade_history();

    // The audit log lives in instance storage: it survives without any
    // per-entry TTL bump, and reading it does not mutate what is stored.
    let snapshot = h.env.as_contract(&h.client.address, || {
        h.env
            .storage()
            .instance()
            .get::<_, Vec<UpgradeAuditRecord>>(&DataKey::UpgradeAuditLog)
            .expect("audit log stored in instance storage")
    });
    assert_eq!(snapshot.len(), before.len());
    assert_eq!(snapshot.get(0).unwrap(), before.get(0).unwrap());

    // Later lifecycle actions prepend (the log is newest first) and the
    // earlier entries are never rewritten — they shift down by exactly the
    // number of new entries, byte for byte.
    let (org, kind, version, wasm, addr) = upgrade_args(&h, 2, 2);
    h.client
        .propose_upgrade(&h.owner, &org, &kind, &version, &wasm, &addr);
    h.client.reject_upgrade(&h.owner, &kind);
    let after = h.client.get_upgrade_history();
    assert_eq!(after.len(), before.len() + 2);
    assert_eq!(after.get(0).unwrap().action, UpgradeAction::Rejected);
    assert_eq!(after.get(1).unwrap().action, UpgradeAction::Proposed);
    for i in 0..before.len() as u32 {
        assert_eq!(after.get(i + 2).unwrap(), before.get(i).unwrap());
    }
}

#[test]
fn refused_upgrades_leave_no_audit_entries() {
    let h = setup_upgrade_flow("acme");
    let kind = ModuleKind::Wallet;
    let (org, _, version, wasm, addr) = upgrade_args(&h, 1, 1);
    h.client
        .propose_upgrade(&h.owner, &org, &kind, &version, &wasm, &addr);
    h.client.commit_upgrade(&h.admin, &kind);
    assert_eq!(h.client.get_upgrade_history_len(), 2);

    // Soroban invocations are atomic: a refused call has every storage write
    // and event rolled back, so no on-revert "attempt" entry could ever be
    // observed on-chain. Verify the refusals below leave the trail untouched.
    let stranger = Address::generate(&h.env);
    assert_eq!(
        h.client.try_propose_upgrade(
            &stranger,
            &org,
            &kind,
            &2,
            &hash(&h.env, 7),
            &Address::generate(&h.env)
        ),
        Err(Ok(Error::Unauthorized))
    );
    // Identical-WASM edge case from Issue #300: re-proposing already-approved
    // bytecode is refused...
    assert_eq!(
        h.client
            .try_propose_upgrade(&h.owner, &org, &kind, &2, &wasm, &Address::generate(&h.env)),
        Err(Ok(Error::InvalidInput))
    );
    // ...and so is a downgrade.
    assert_eq!(
        h.client.try_propose_upgrade(
            &h.owner,
            &org,
            &kind,
            &1,
            &hash(&h.env, 5),
            &Address::generate(&h.env)
        ),
        Err(Ok(Error::InvalidState))
    );
    assert_eq!(h.client.get_upgrade_history_len(), 2);
    assert_eq!(
        h.client.get_upgrade_history().get(0).unwrap().action,
        UpgradeAction::Committed
    );
    // The kind is still free for the next, honest proposal.
    assert_eq!(h.client.get_upgrade_proposal(&kind), None);
}

#[test]
fn audit_log_rings_out_the_oldest_entries_at_the_cap() {
    let h = setup_upgrade_flow("acme");

    // Fill the ring buffer with propose→commit pairs (audit entries grow by
    // two per cycle) and confirm the cap is respected, oldest dropped first.
    for v in 1..=(MAX_UPGRADE_AUDIT_ENTRIES / 2 + 2) {
        let (org, kind, version, wasm, addr) = upgrade_args(&h, v, (v % 251) as u8);
        h.client
            .propose_upgrade(&h.owner, &org, &kind, &version, &wasm, &addr);
        h.client.commit_upgrade(&h.admin, &kind);
    }
    assert_eq!(
        h.client.get_upgrade_history_len(),
        MAX_UPGRADE_AUDIT_ENTRIES
    );

    // The most recent commit is still present; the earliest proposals are
    // gone, proving the buffer rings instead of growing unbounded.
    let history = h.client.get_upgrade_history();
    assert_eq!(history.get(0).unwrap().action, UpgradeAction::Committed);
    assert_eq!(
        history.get(0).unwrap().audit.version,
        MAX_UPGRADE_AUDIT_ENTRIES / 2 + 2
    );
    assert_eq!(history.get(1).unwrap().action, UpgradeAction::Proposed);
    assert_eq!(
        history.get(1).unwrap().audit.version,
        MAX_UPGRADE_AUDIT_ENTRIES / 2 + 2
    );
    let oldest = history.get(MAX_UPGRADE_AUDIT_ENTRIES - 1).unwrap();
    assert_eq!(oldest.action, UpgradeAction::Proposed);
    assert_eq!(oldest.audit.version, 3);
    // Versions 1 and 2's entries were the first things evicted.
    assert!(!history
        .iter()
        .any(|r| r.audit.version <= 2 || r.action == UpgradeAction::Rejected));
}

#[test]
fn audit_log_ring_buffer_ordering_holds_after_rejections() {
    let h = setup_upgrade_flow("acme");
    let kind = ModuleKind::Wallet;

    // Propose → reject, then propose → commit: the log stays newest-first
    // across a mixed sequence of lifecycle actions.
    let (org, _, v1, w1, a1) = upgrade_args(&h, 1, 1);
    h.client
        .propose_upgrade(&h.owner, &org, &kind, &v1, &w1, &a1);
    h.client.reject_upgrade(&h.owner, &kind);

    let (org2, _, v2, w2, a2) = upgrade_args(&h, 2, 2);
    h.client
        .propose_upgrade(&h.owner, &org2, &kind, &v2, &w2, &a2);
    h.client.commit_upgrade(&h.admin, &kind);

    let history = h.client.get_upgrade_history();
    assert_eq!(history.len(), 4);
    assert_eq!(history.get(0).unwrap().action, UpgradeAction::Committed);
    assert_eq!(history.get(0).unwrap().audit.version, 2);
    assert_eq!(history.get(1).unwrap().action, UpgradeAction::Proposed);
    assert_eq!(history.get(1).unwrap().audit.version, 2);
    assert_eq!(history.get(2).unwrap().action, UpgradeAction::Rejected);
    assert_eq!(history.get(2).unwrap().audit.version, 1);
    assert_eq!(history.get(3).unwrap().action, UpgradeAction::Proposed);
    assert_eq!(history.get(3).unwrap().audit.version, 1);
    assert_eq!(h.client.get_upgrade_history_len(), 4);
}

#[test]
fn unauthorized_and_ghost_org_proposals_are_refused_without_a_trace() {
    let h = setup_upgrade_flow("acme");
    let kind = ModuleKind::Wallet;
    let (org, _, version, wasm, addr) = upgrade_args(&h, 1, 1);

    // A stranger (not admin/owner/upgrader) on a real org is Unauthorized.
    assert_eq!(
        h.client
            .try_propose_upgrade(&h.stranger, &org, &kind, &version, &wasm, &addr),
        Err(Ok(Error::Unauthorized))
    );
    // A stranger on an unknown org learns only NotFound.
    assert_eq!(
        h.client.try_propose_upgrade(
            &h.stranger,
            &String::from_str(&h.env, "ghost"),
            &kind,
            &version,
            &wasm,
            &addr
        ),
        Err(Ok(Error::NotFound))
    );
    // Admin-gated commit with no proposal: NotFound.
    assert_eq!(
        h.client.try_commit_upgrade(&h.admin, &kind),
        Err(Ok(Error::NotFound))
    );
    // Every refusal above reverted atomically: no audit entries, no events.
    assert_eq!(h.client.get_upgrade_history_len(), 0);
    assert_eq!(count_events(&h.env, "UpgradeProposed"), 0);
    assert_eq!(count_events(&h.env, "UpgradeCommitted"), 0);
    assert_eq!(count_events(&h.env, "UpgradeRejected"), 0);
}

#[test]
fn audit_log_is_empty_before_any_upgrade_activity() {
    let h = setup_upgrade_flow("acme");
    assert_eq!(h.client.get_upgrade_history_len(), 0);
    assert_eq!(h.client.get_upgrade_history().len(), 0);
}
