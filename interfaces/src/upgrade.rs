//! Registry-gated contract upgrades.
//!
//! Soroban lets a contract replace its own code with
//! [`soroban_sdk::deploy::Deployer::update_current_contract_wasm`]. On its own
//! that is an unconditional power: whoever the contract accepts as an admin can
//! point it at *any* uploaded Wasm. Astroid's upgrade strategy (PRD Doc 7
//! §Upgrade Strategy) instead makes the registry the single source of truth for
//! which implementations exist, so this module routes every member contract's
//! upgrade through it:
//!
//! ```text
//! caller ──auth──▶ member contract ──registry.is_upgrade_approved(kind, hash)──▶ registry
//!                        │                                    approved version │
//!                        └──── update_current_contract_wasm(hash) ◀────────────┘
//! ```
//!
//! Both gates must pass: the caller must be the contract's recorded upgrade
//! admin, and the new Wasm hash must be registered for that [`ModuleKind`] in
//! the registry's version map. Anything else fails with
//! [`Error::UnauthorizedUpgrade`] and the contract keeps running its current
//! code.
//!
//! The helpers live here rather than in `astroid-shared` because they need the
//! generated [`RegistryClient`], and here rather than in each contract because
//! every member contract must enforce the identical rule.

use crate::RegistryClient;
use astroid_shared::constants::{INSTANCE_BUMP_AMOUNT, INSTANCE_LIFETIME_THRESHOLD};
use astroid_shared::errors::Error;
use astroid_shared::types::ModuleKind;
use soroban_sdk::{contracttype, symbol_short, Address, BytesN, Env};

/// Instance-storage key for the upgrade authority. Namespaced under its own
/// type so it can never collide with a contract's own `DataKey`.
#[contracttype]
#[derive(Clone)]
enum UpgradeKey {
    Authority,
}

/// Who may upgrade a contract, and which registry authorizes the new code.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpgradeAuthority {
    /// The only address allowed to request an upgrade.
    pub admin: Address,
    /// Registry contract consulted for the approved version map.
    pub registry: Address,
}

/// Record (or rotate) the upgrade authority.
///
/// The first call bootstraps it and should be made by the deployer in the same
/// transaction as the contract's own `initialize`, exactly like the other
/// first-come initializers in this workspace. Afterwards only the current admin
/// may rotate it, and the call is authenticated either way.
pub fn set_authority(
    env: &Env,
    caller: &Address,
    admin: &Address,
    registry: &Address,
) -> Result<(), Error> {
    caller.require_auth();
    if let Some(current) = stored(env) {
        if &current.admin != caller {
            return Err(Error::Unauthorized);
        }
    }
    env.storage().instance().set(
        &UpgradeKey::Authority,
        &UpgradeAuthority {
            admin: admin.clone(),
            registry: registry.clone(),
        },
    );
    env.storage()
        .instance()
        .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
    env.events().publish(
        (symbol_short!("upgrade"), symbol_short!("auth")),
        (admin.clone(), registry.clone()),
    );
    Ok(())
}

/// Read the recorded upgrade authority.
pub fn get_authority(env: &Env) -> Result<UpgradeAuthority, Error> {
    stored(env).ok_or(Error::NotInitialized)
}

/// Authorize an upgrade without performing it: authenticate `caller` as the
/// upgrade admin and resolve `wasm_hash` in the registry's version map for
/// `kind`. Returns the version the hash is registered under.
///
/// Exposed on its own so an upgrade can be validated (by a keeper, a dry run or
/// a test) without swapping any code.
pub fn check(
    env: &Env,
    caller: &Address,
    kind: ModuleKind,
    wasm_hash: &BytesN<32>,
) -> Result<u32, Error> {
    caller.require_auth();
    let authority = get_authority(env)?;
    if &authority.admin != caller {
        return Err(Error::Unauthorized);
    }
    let registry = RegistryClient::new(env, &authority.registry);
    match registry.try_is_upgrade_approved(&kind, wasm_hash) {
        Ok(Ok(version)) => Ok(version),
        // The registry returned something that is not a version.
        Ok(Err(_)) => Err(Error::UnauthorizedUpgrade),
        // The registry rejected the hash (or is frozen) — surface its reason.
        Err(Ok(e)) => Err(e),
        // System-level failure: fail closed rather than upgrade.
        Err(Err(_)) => Err(Error::UnauthorizedUpgrade),
    }
}

/// Authorize and then perform the upgrade: on success the contract's code is
/// replaced with `wasm_hash` and the approved version is returned.
///
/// [`check`] runs first, so an unauthorized caller or an unregistered hash
/// aborts before `update_current_contract_wasm` is ever reached. The new code
/// takes effect after the current invocation completes.
pub fn perform(
    env: &Env,
    caller: &Address,
    kind: ModuleKind,
    wasm_hash: BytesN<32>,
) -> Result<u32, Error> {
    let version = check(env, caller, kind, &wasm_hash)?;
    env.deployer()
        .update_current_contract_wasm(wasm_hash.clone());
    env.events().publish(
        (symbol_short!("upgrade"), symbol_short!("applied")),
        (kind, version, wasm_hash),
    );
    Ok(version)
}

fn stored(env: &Env) -> Option<UpgradeAuthority> {
    env.storage().instance().get(&UpgradeKey::Authority)
}
