//! Cross-contract batch reads against the Registry.
//!
//! A consumer contract resolves several of an organization's modules through
//! the generated [`RegistryClient`] from `astroid-interfaces` — the same typed
//! surface a production contract would use — rather than through the
//! registry's own test client.

use astroid_interfaces::RegistryClient;
use astroid_registry::{RegistryContract, RegistryContractClient};
use astroid_shared::constants::MAX_REGISTRY_BATCH;
use astroid_shared::errors::Error;
use astroid_shared::types::{ModuleId, ModuleInfo, ModuleKind};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{contract, contractimpl, vec, Address, Env, String, Vec};

/// Test-only consumer: forwards a batch lookup to the registry it is given.
#[contract]
pub struct ModuleResolver;

#[contractimpl]
impl ModuleResolver {
    /// Resolve `ids` with one cross-contract call. A registry error aborts
    /// this invocation too, so it surfaces to our caller unchanged.
    pub fn resolve(env: Env, registry: Address, ids: Vec<ModuleId>) -> Vec<Option<ModuleInfo>> {
        RegistryClient::new(&env, &registry).get_modules_batch(&ids)
    }

    /// Resolve `ids`, handling a registry error in this contract instead of
    /// aborting: returns the error code the registry reported.
    pub fn resolve_checked(
        env: Env,
        registry: Address,
        ids: Vec<ModuleId>,
    ) -> Result<Vec<Option<ModuleInfo>>, Error> {
        match RegistryClient::new(&env, &registry).try_get_modules_batch(&ids) {
            Ok(Ok(modules)) => Ok(modules),
            Err(Ok(error)) => Err(error),
            _ => panic!("registry returned an undecodable result"),
        }
    }
}

struct Harness<'a> {
    env: Env,
    registry: RegistryContractClient<'a>,
    resolver: ModuleResolverClient<'a>,
    wallet: Address,
    treasury: Address,
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
    let wallet = Address::generate(&env);
    let treasury = Address::generate(&env);
    registry.register_module(&owner, &org, &ModuleKind::Wallet, &wallet);
    registry.register_module(&owner, &org, &ModuleKind::Treasury, &treasury);

    let resolver_id = env.register_contract(None, ModuleResolver);
    let resolver = ModuleResolverClient::new(&env, &resolver_id);

    Harness {
        env,
        registry,
        resolver,
        wallet,
        treasury,
    }
}

fn id(env: &Env, kind: ModuleKind) -> ModuleId {
    ModuleId {
        org: String::from_str(env, "acme"),
        kind,
    }
}

fn live(address: &Address) -> Option<ModuleInfo> {
    Some(ModuleInfo {
        address: address.clone(),
        deprecated: false,
    })
}

#[test]
fn contract_resolves_a_partial_batch_across_contracts() {
    let h = setup();
    let ids = vec![
        &h.env,
        id(&h.env, ModuleKind::Treasury),
        id(&h.env, ModuleKind::Policy), // not registered
        id(&h.env, ModuleKind::Wallet),
    ];

    let expected = vec![&h.env, live(&h.treasury), None, live(&h.wallet)];
    assert_eq!(h.resolver.resolve(&h.registry.address, &ids), expected);
    assert_eq!(
        h.resolver.resolve_checked(&h.registry.address, &ids),
        expected
    );
}

#[test]
fn oversized_batch_error_propagates_across_contracts() {
    let h = setup();
    let mut ids = Vec::new(&h.env);
    for _ in 0..=MAX_REGISTRY_BATCH {
        ids.push_back(id(&h.env, ModuleKind::Wallet));
    }

    // Unhandled: the registry's error aborts the consumer with the same code.
    assert_eq!(
        h.resolver.try_resolve(&h.registry.address, &ids),
        Err(Ok(soroban_sdk::Error::from_contract_error(
            Error::InvalidInput as u32
        )))
    );
    // Handled: the consumer receives the registry's code and returns it.
    assert_eq!(
        h.resolver.try_resolve_checked(&h.registry.address, &ids),
        Err(Ok(Error::InvalidInput))
    );
}
