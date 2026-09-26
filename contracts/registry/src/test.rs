#![cfg(test)]
extern crate std;

use crate::{DataKey, RegistryContract, RegistryContractClient, RegistryRole};
use astroid_shared::constants::{MAX_REGISTRY_BATCH, PERSISTENT_BUMP_AMOUNT};
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

// ---------------------------------------------------------------------------
// Deterministic error codes
//
// Every failure below must surface as a specific `Error` variant, never as a
// generic code and never as a host trap, so an off-chain consumer can branch on
// it. The three groups mirror the classes the protocol promises to keep
// distinct: out-of-bounds / invalid input, unauthorized callers, and frozen
// (lifecycle) refusals.
// ---------------------------------------------------------------------------

/// A registry that was registered but never `initialize`d, so the guards that
/// read instance storage report `NotInitialized` instead of panicking.
fn uninitialized() -> (Env, RegistryContractClient<'static>) {
    let env = Env::default();
    env.mock_all_auths();
    let contract_id = env.register_contract(None, RegistryContract);
    let client = RegistryContractClient::new(&env, &contract_id);
    (env, client)
}

#[test]
fn uninitialized_registry_reports_not_initialized() {
    let (env, client) = uninitialized();
    let admin = Address::generate(&env);
    let org = String::from_str(&env, "acme");

    assert_eq!(client.try_get_admin(), Err(Ok(Error::NotInitialized)));
    assert_eq!(
        client.try_register_org(&admin, &org, &Address::generate(&env)),
        Err(Ok(Error::NotInitialized))
    );
    assert_eq!(
        client.try_deprecate_module(&admin, &org, &ModuleKind::Wallet),
        Err(Ok(Error::NotInitialized))
    );
    assert_eq!(
        client.try_set_admin(&admin, &Address::generate(&env)),
        Err(Ok(Error::NotInitialized))
    );
}

#[test]
fn out_of_bounds_lookups_report_not_found() {
    let (env, client, _admin) = setup();
    let ghost = String::from_str(&env, "ghost");
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&_admin, &org, &owner);

    // A key that was never written must not read as a default value.
    assert_eq!(client.try_get_org_owner(&ghost), Err(Ok(Error::NotFound)));
    assert_eq!(
        client.try_get_module_address(&org, &ModuleKind::Wallet),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(
        client.try_verify_owner(&ghost, &owner),
        Err(Ok(Error::NotFound))
    );
    // No version has been registered, and version 0 can never be registered.
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
fn empty_org_slug_is_rejected_as_invalid_input() {
    let (env, client, admin) = setup();
    // An empty string is a valid `String` but not a valid org identifier; it
    // must be refused with `InvalidInput` rather than stored.
    let res = client.try_register_org(
        &admin,
        &String::from_str(&env, ""),
        &Address::generate(&env),
    );
    assert_eq!(res, Err(Ok(Error::InvalidInput)));
    assert_eq!(
        client.try_get_org_owner(&String::from_str(&env, "")),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn unknown_org_is_not_found_for_every_owner_gated_call() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    let ghost = String::from_str(&env, "ghost");
    let new_owner = Address::generate(&env);

    // A real owner naming an organization that does not exist gets `NotFound`,
    // not a permission failure — the two are different diagnoses.
    assert_eq!(
        client.try_set_org_owner(&owner, &ghost, &new_owner),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(
        client.try_register_module(
            &owner,
            &ghost,
            &ModuleKind::Wallet,
            &Address::generate(&env)
        ),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(
        client.try_remove_module(&owner, &ghost, &ModuleKind::Wallet),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(client.try_freeze(&owner, &ghost), Err(Ok(Error::NotFound)));
    assert_eq!(
        client.try_unfreeze(&owner, &ghost),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn unauthorized_callers_are_refused_by_the_protocol_admin() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    let intruder = Address::generate(&env);
    let intruder_org = String::from_str(&env, "evil");
    client.register_org(&admin, &intruder_org, &intruder);

    // A stranger must never seize the protocol admin, approve Wasm, or record a
    // version, even while holding ownership of an organization of their own.
    assert_eq!(
        client.try_set_admin(&intruder, &intruder),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(
        client.try_add_approved_wasm(&intruder, &ModuleKind::Wallet, &hash(&env, 1)),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(
        client.try_remove_approved_wasm(&intruder, &ModuleKind::Wallet, &hash(&env, 1)),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(
        client.try_register_version(
            &intruder,
            &ModuleKind::Wallet,
            &1,
            &Address::generate(&env),
            &hash(&env, 1)
        ),
        Err(Ok(Error::Unauthorized))
    );
    // The admin is unchanged.
    assert_eq!(client.get_admin(), admin);
}

#[test]
fn freeze_and_unfreeze_require_the_owner_or_admin() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    let intruder = Address::generate(&env);

    assert_eq!(
        client.try_freeze(&intruder, &org),
        Err(Ok(Error::Unauthorized))
    );
    client.freeze(&owner, &org);
    assert_eq!(
        client.try_unfreeze(&intruder, &org),
        Err(Ok(Error::Unauthorized))
    );
    // Only the owner or the protocol admin may lift the breaker.
    client.unfreeze(&owner, &org);
    client.freeze(&admin, &org);
    client.unfreeze(&admin, &org);
}

#[test]
fn frozen_registry_refuses_every_organization_scoped_write() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    let wallet = Address::generate(&env);
    client.register_module(&owner, &org, &ModuleKind::Wallet, &wallet);
    client.freeze(&owner, &org);

    // Every write that would change routing for this org must report the single
    // dedicated `RegistryFrozen` code — never a generic `Unauthorized`.
    for res in [
        client.try_register_module(&owner, &org, &ModuleKind::Policy, &Address::generate(&env)),
        client.try_remove_module(&owner, &org, &ModuleKind::Wallet),
        client.try_set_org_owner(&owner, &org, &Address::generate(&env)),
        client.try_deprecate_module(&owner, &org, &ModuleKind::Wallet),
        client.try_reactivate_module(&owner, &org, &ModuleKind::Wallet),
        client.try_register_org(&admin, &String::from_str(&env, "other"), &owner),
        client.try_grant_role(
            &owner,
            &org,
            &Address::generate(&env),
            &RegistryRole::PolicyManager,
        ),
    ] {
        assert_eq!(res, Err(Ok(Error::RegistryFrozen)));
    }

    // Routing is frozen too, so a live module reports the same dedicated code
    // rather than being served; the legacy getter stays open for recovery.
    assert_eq!(
        client.try_lookup(&org, &ModuleKind::Wallet),
        Err(Ok(Error::RegistryFrozen))
    );
    assert_eq!(client.get_module_address(&org, &ModuleKind::Wallet), wallet);
    client.unfreeze(&owner, &org);
    client.register_module(&owner, &org, &ModuleKind::Policy, &Address::generate(&env));
}

#[test]
fn deprecated_module_reports_module_deprecated_not_not_found() {
    let (env, client, admin) = setup();
    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    client.register_org(&admin, &org, &owner);
    let wallet = Address::generate(&env);
    client.register_module(&owner, &org, &ModuleKind::Wallet, &wallet);
    // Deprecation is protocol-admin gated; the org owner is refused.
    assert_eq!(
        client.try_deprecate_module(&owner, &org, &ModuleKind::Wallet),
        Err(Ok(Error::Unauthorized))
    );
    client.deprecate_module(&admin, &org, &ModuleKind::Wallet);

    // The record still exists for the legacy getter, but routing must report the
    // dedicated deprecation code so callers can distinguish it from a missing
    // module.
    assert_eq!(client.get_module_address(&org, &ModuleKind::Wallet), wallet);
    assert_eq!(
        client.try_lookup(&org, &ModuleKind::Wallet),
        Err(Ok(Error::ModuleDeprecated))
    );
    // A module that was never registered is `NotFound`, not deprecated.
    assert_eq!(
        client.try_lookup(&org, &ModuleKind::Policy),
        Err(Ok(Error::NotFound))
    );
    // Reactivating restores routing and clears the code.
    client.reactivate_module(&admin, &org, &ModuleKind::Wallet);
    assert_eq!(client.lookup(&org, &ModuleKind::Wallet), wallet);
}

#[test]
fn unapproved_wasm_cannot_be_removed() {
    let (env, client, admin) = setup();
    // Revoking a hash that was never approved is `NotFound`, not a silent no-op.
    let res = client.try_remove_approved_wasm(&admin, &ModuleKind::Wallet, &hash(&env, 7));
    assert_eq!(res, Err(Ok(Error::NotFound)));
}
