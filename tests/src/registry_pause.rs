//! Cross-contract emergency circuit breaker for the Registry (Issue #335).
//!
//! A consumer contract observes the registry's pause through the generated
//! [`RegistryClient`] from `astroid-interfaces` — the same typed surface a
//! production contract uses — while the registry's own client drives the
//! admin `pause`/`unpause` controls and the rejected modifications.

use astroid_interfaces::RegistryClient;
use astroid_registry::{RegistryContract, RegistryContractClient};
use astroid_shared::errors::Error;
use astroid_shared::types::ModuleKind;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{contract, contractimpl, Address, Env, String};

/// Test-only consumer: asks the registry whether its circuit breaker is
/// engaged, through the shared interface client rather than the registry's
/// own generated client.
#[contract]
pub struct PauseProbe;

#[contractimpl]
impl PauseProbe {
    /// Forward the pause query to the registry it is given.
    pub fn paused(env: Env, registry: Address) -> bool {
        RegistryClient::new(&env, &registry).is_paused()
    }
}

struct Harness<'a> {
    env: Env,
    registry: RegistryContractClient<'a>,
    probe: PauseProbeClient<'a>,
    admin: Address,
    org: String,
    owner: Address,
}

fn setup() -> Harness<'static> {
    let env = Env::default();
    env.mock_all_auths();

    let registry_id = env.register_contract(None, RegistryContract);
    let registry = RegistryContractClient::new(&env, &registry_id);
    let admin = Address::generate(&env);
    registry.initialize(&admin);

    let org = String::from_str(&env, "acme");
    let owner = Address::generate(&env);
    registry.register_org(&admin, &org, &owner);

    let probe_id = env.register_contract(None, PauseProbe);
    let probe = PauseProbeClient::new(&env, &probe_id);

    Harness {
        env,
        registry,
        probe,
        admin,
        org,
        owner,
    }
}

#[test]
fn consumer_observes_pause_and_registry_rejects_modifications() {
    let h = setup();

    // Released: a modification succeeds and the consumer sees no pause.
    let wallet = Address::generate(&h.env);
    h.registry
        .register_module(&h.owner, &h.org, &ModuleKind::Wallet, &wallet);
    assert!(!h.probe.paused(&h.registry.address));

    h.registry.pause(&h.admin);
    assert!(h.probe.paused(&h.registry.address));

    // With the breaker engaged, modifications are refused with the designated
    // code even when everything else about the caller is valid.
    let other = Address::generate(&h.env);
    assert_eq!(
        h.registry
            .try_register_module(&h.owner, &h.org, &ModuleKind::Treasury, &other),
        Err(Ok(Error::RegistryPaused))
    );
    assert_eq!(
        h.registry
            .try_remove_module(&h.owner, &h.org, &ModuleKind::Wallet),
        Err(Ok(Error::RegistryPaused))
    );

    // ...but the registrations that already exist stay readable for incident
    // inspection.
    assert_eq!(h.registry.lookup(&h.org, &ModuleKind::Wallet), wallet);
}

#[test]
fn unpause_restores_cross_contract_observability_and_writes() {
    let h = setup();

    h.registry.pause(&h.admin);
    assert!(h.probe.paused(&h.registry.address));

    h.registry.unpause(&h.admin);
    assert!(!h.probe.paused(&h.registry.address));

    let policy = Address::generate(&h.env);
    h.registry
        .register_module(&h.owner, &h.org, &ModuleKind::Policy, &policy);
    assert_eq!(h.registry.lookup(&h.org, &ModuleKind::Policy), policy);
}
