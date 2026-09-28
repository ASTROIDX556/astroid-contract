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

// ---------------------------------------------------------------------------
// The registry's own upgrade map and module registration (Issue #206).
//
// Everything above drives a *member* contract's upgrade. These drive the
// registry's: a registry that is its own upgrade authority validates its own
// upgrade map before replacing its own code, and gates its module records on
// the org they claim to belong to.
// ---------------------------------------------------------------------------

/// Test-only consumer of the registry's self-upgrade surface, the way a
/// deployment pipeline would check a target before proposing it.
#[contract]
pub struct SelfUpgradePlanner;

#[contractimpl]
impl SelfUpgradePlanner {
    /// The published version `wasm_hash` would move the registry to, or the
    /// registry's own error code unchanged.
    pub fn plan(env: Env, registry: Address, wasm_hash: BytesN<32>) -> Result<u32, Error> {
        match RegistryContractClient::new(&env, &registry).try_validate_registry_upgrade(&wasm_hash)
        {
            Ok(Ok(version)) => Ok(version),
            Err(Ok(error)) => Err(error),
            _ => panic!("registry returned an undecodable result"),
        }
    }
}

/// A registry that authorizes its own upgrades — the deployment the shared
/// cross-call gate cannot serve, because the host forbids a contract calling
/// itself — with `v1..=v3` published for `Organization`, each bound to its own
/// approved code.
struct SelfHarness<'a> {
    env: Env,
    admin: Address,
    registry: RegistryContractClient<'a>,
    planner: SelfUpgradePlannerClient<'a>,
    v1: BytesN<32>,
    v2: BytesN<32>,
    v3: BytesN<32>,
}

fn setup_self() -> SelfHarness<'static> {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);

    let registry_id = env.register_contract(None, RegistryContract);
    let registry = RegistryContractClient::new(&env, &registry_id);
    registry.initialize(&admin);
    // The registry is its own upgrade authority: nobody else's approval list
    // gets a vote on what code this contract runs.
    registry.set_upgrade_authority(&admin, &admin, &registry_id);

    fn publish(
        env: &Env,
        registry: &RegistryContractClient,
        admin: &Address,
        seed: u8,
    ) -> BytesN<32> {
        let code = hash(env, seed);
        registry.add_approved_wasm(admin, &ModuleKind::Organization, &code);
        registry.register_version(
            admin,
            &ModuleKind::Organization,
            &seed.into(),
            &env.register_contract(None, RegistryContract),
            &code,
        );
        code
    }
    let v1 = publish(&env, &registry, &admin, 1);
    let v2 = publish(&env, &registry, &admin, 2);
    let v3 = publish(&env, &registry, &admin, 3);

    let planner_id = env.register_contract(None, SelfUpgradePlanner);
    let planner = SelfUpgradePlannerClient::new(&env, &planner_id);

    SelfHarness {
        env,
        admin,
        registry,
        planner,
        v1,
        v2,
        v3,
    }
}

#[test]
fn a_self_authorizing_registry_resolves_its_own_upgrade_target() {
    let h = setup_self();

    // A consumer contract can ask the registry what a hash would do before
    // anyone signs a proposal, and gets the version back, not just an "ok".
    assert_eq!(h.planner.plan(&h.registry.address, &h.v3), 3);
    assert_eq!(h.planner.plan(&h.registry.address, &h.v2), 2);
    assert_eq!(h.registry.validate_registry_upgrade(&h.v1), 1);
    // The registry starts at nothing and reads as such.
    assert_eq!(h.registry.get_registry_version(), 0);
    // Planning is a read: it cannot have moved anything.
    assert_eq!(h.registry.get_registry_version(), 0);
}

#[test]
fn a_self_upgrade_target_the_map_does_not_publish_is_refused() {
    let h = setup_self();
    // Approved, so it clears the approval gate, and named by no published
    // version, so it has no version to be ordered against.
    let unpublished = hash(&h.env, 40);
    h.registry
        .add_approved_wasm(&h.admin, &ModuleKind::Organization, &unpublished);

    assert_eq!(
        h.planner.try_plan(&h.registry.address, &unpublished),
        Err(Ok(Error::NotFound))
    );
    // The write path agrees with the dry run, rather than swapping code the map
    // cannot vouch for.
    assert_eq!(
        h.registry.try_upgrade(&h.admin, &unpublished),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(h.registry.get_registry_version(), 0);
}

#[test]
fn a_self_upgrade_record_naming_an_account_is_refused() {
    let h = setup_self();
    // A published `Organization` version is a deployment of the registry, so its
    // record has to name a contract. An account is not one.
    let bogus = Address::from_string(&soroban_sdk::String::from_str(
        &h.env,
        "GAEQSCIJBEEQSCIJBEEQSCIJBEEQSCIJBEEQSCIJBEEQSCIJBEEQSH7S",
    ));
    h.registry
        .register_version(&h.admin, &ModuleKind::Organization, &4, &bogus, &h.v1);

    assert_eq!(
        h.planner.try_plan(&h.registry.address, &h.v1),
        Err(Ok(Error::InvalidInput))
    );
}

#[test]
fn a_stranger_cannot_replace_the_registrys_own_code() {
    let h = setup_self();
    let stranger = Address::generate(&h.env);

    // The hash is a perfectly valid forward target, which is what makes this a
    // test of the caller: the only thing wrong with it is who is asking.
    assert_eq!(h.planner.plan(&h.registry.address, &h.v3), 3);
    assert_eq!(
        h.registry.try_upgrade(&stranger, &h.v3),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(h.registry.get_registry_version(), 0);
}

#[test]
fn the_registry_will_not_swap_in_code_it_never_approved() {
    let h = setup_self();
    let other_kind = hash(&h.env, 41);
    h.registry
        .add_approved_wasm(&h.admin, &ModuleKind::Wallet, &other_kind);
    // Publishing it for `Organization` is refused outright: the registry does
    // not let unapproved code enter its own upgrade map in the first place, so
    // there is no way to reach a state where a published version carries code
    // that `upgrade` would then have to reject.
    assert_eq!(
        h.registry.try_register_version(
            &h.admin,
            &ModuleKind::Organization,
            &4,
            &h.env.register_contract(None, RegistryContract),
            &other_kind
        ),
        Err(Ok(Error::Unauthorized))
    );
    // And approval for another kind is not approval for this one: the registry
    // runs `Organization` code and is gated as one.
    assert_eq!(
        h.registry.try_upgrade(&h.admin, &other_kind),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(h.registry.get_registry_version(), 0);
}

#[test]
fn a_module_cannot_be_registered_for_an_org_that_does_not_exist() {
    let h = setup_self();
    let org = soroban_sdk::String::from_str(&h.env, "ghost");
    let module = Address::generate(&h.env);
    let stranger = Address::generate(&h.env);

    // A record for an org that was never registered names an owner that does
    // not exist, so there is nobody whose signature could authorize it — not
    // even the protocol admin's.
    for caller in [&h.admin, &stranger] {
        assert_eq!(
            h.registry
                .try_register_module(caller, &org, &ModuleKind::Wallet, &module),
            Err(Ok(Error::NotFound))
        );
    }
    assert_eq!(
        h.registry.try_get_module_address(&org, &ModuleKind::Wallet),
        Err(Ok(Error::NotFound))
    );
    // The same is true of the other way a module record is written, and of the
    // read a caller would use to route on it.
    assert_eq!(
        h.registry
            .try_remove_module(&h.admin, &org, &ModuleKind::Wallet),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn a_modules_own_org_can_register_it_and_noone_else_can() {
    use soroban_sdk::testutils::AuthorizedFunction;

    let h = setup_self();
    let org = soroban_sdk::String::from_str(&h.env, "acme");
    let owner = Address::generate(&h.env);
    let module = Address::generate(&h.env);
    h.registry.register_org(&h.admin, &org, &owner);

    // The org's owner registers its own module.
    h.registry
        .register_module(&owner, &org, &ModuleKind::Wallet, &module);
    // `auths()` reports the most recent frame, so it is read here rather than
    // after the reads below — a call that needs no signature leaves an empty
    // frame in its place.
    let auths = h.env.auths();
    assert_eq!(
        h.registry.get_module_address(&org, &ModuleKind::Wallet),
        module
    );
    // The registry demanded that owner's signature for exactly this
    // invocation, not the protocol admin's.
    let (signer, invocation) = auths.last().expect("module writes need auth");
    assert_eq!(*signer, owner);
    match &invocation.function {
        AuthorizedFunction::Contract((contract, function, _args)) => {
            assert_eq!(contract, &h.registry.address);
            assert_eq!(
                function,
                &soroban_sdk::Symbol::new(&h.env, "register_module")
            );
        }
        _ => panic!("expected a contract invocation"),
    }

    // A stranger cannot displace it.
    let impostor = Address::generate(&h.env);
    assert_eq!(
        h.registry
            .try_register_module(&impostor, &org, &ModuleKind::Wallet, &impostor),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(
        h.registry.get_module_address(&org, &ModuleKind::Wallet),
        module
    );

    // The protocol admin is a superuser over module records for orgs that
    // exist, which is how they get bootstrapped and repaired. It is not one for
    // an org that does not — the check in the test above runs ahead of the
    // admin short circuit, so an admin cannot conjure one into existence
    // either.
    h.registry
        .remove_module(&h.admin, &org, &ModuleKind::Wallet);
    assert_eq!(
        h.registry.try_get_module_address(&org, &ModuleKind::Wallet),
        Err(Ok(Error::NotFound))
    );
}
