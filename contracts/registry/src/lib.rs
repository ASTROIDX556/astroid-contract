#![no_std]
#![allow(clippy::too_many_arguments)]
//! # Astroid Registry Contract
//!
//! The backbone of the protocol and its single source of truth. The registry
//! records, per organization:
//! - the **owner** of the organization,
//! - the **module address** for each [`ModuleKind`] (wallet, treasury, policy…),
//!
//! and, globally, a **version → address** table used by the upgrade strategy so
//! new contract versions (e.g. Wallet v1 → v2 → v3) can be introduced without
//! breaking consumers (PRD Doc 7 §Upgrade Strategy).
//!
//! The version map also records the **approved Wasm hash** of each version.
//! Member contracts consult it through [`RegistryInterface::is_upgrade_approved`]
//! before replacing their own code, so an implementation must exist in this
//! table before any contract can upgrade to it; anything else is refused with
//! [`Error::UnauthorizedUpgrade`]. Registering and revoking hashes is
//! admin-gated, which makes the registry the single authorization point for the
//! whole protocol's upgradeability.
//!
//! Security model (PRD Doc 10): validate caller → ownership → inputs →
//! permissions → fail safely → emit events. All mutating calls are admin- or
//! owner-gated and require Soroban auth.

use astroid_interfaces::RegistryInterface;
use astroid_shared::constants::{PERSISTENT_BUMP_AMOUNT, PERSISTENT_LIFETIME_THRESHOLD};
use astroid_shared::errors::Error;
use astroid_shared::events::ContractEvent;
use astroid_shared::types::ModuleKind;
use astroid_shared::validation::require_non_empty;
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, Address, BytesN, Env, String,
};

/// Storage keys. `Admin` lives in instance storage; everything else is keyed
/// per organization/module in persistent storage.
#[contracttype]
#[derive(Clone)]
enum DataKey {
    /// Protocol admin (instance).
    Admin,
    /// Organization owner: org slug -> owner address.
    Org(String),
    /// Module address: (org slug, kind) -> contract address.
    Module(String, ModuleKind),
    /// Version table: (kind, version) -> contract address (global upgrade map).
    Version(ModuleKind, u32),
    /// Latest known version number for a kind.
    LatestVersion(ModuleKind),
    /// Approved implementation hash: (kind, version) -> Wasm hash.
    WasmHash(ModuleKind, u32),
    /// Reverse index of the above: (kind, Wasm hash) -> version. Lets an
    /// upgrade check resolve a hash in one read instead of scanning versions.
    ApprovedWasm(ModuleKind, BytesN<32>),
    /// Emergency freeze status (instance).
    Frozen,
}

#[contract]
pub struct RegistryContract;

// ---------------------------------------------------------------------------
// Administration & registration (inherent surface).
// ---------------------------------------------------------------------------
#[contractimpl]
impl RegistryContract {
    /// Initialize the registry with its administrator. Callable once.
    pub fn initialize(env: Env, admin: Address) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .instance()
            .extend_ttl(PERSISTENT_LIFETIME_THRESHOLD, PERSISTENT_BUMP_AMOUNT);
        env.events()
            .publish((symbol_short!("registry"), symbol_short!("init")), admin);
        Ok(())
    }

    /// Register an organization and its owner. Admin-gated.
    pub fn register_org(
        env: Env,
        caller: Address,
        org: String,
        owner: Address,
    ) -> Result<(), Error> {
        Self::check_frozen(&env)?;
        require_non_empty(&org)?;
        Self::require_admin(&env, &caller)?;
        let key = DataKey::Org(org.clone());
        if env.storage().persistent().has(&key) {
            return Err(Error::AlreadyExists);
        }
        env.storage().persistent().set(&key, &owner);
        Self::bump(&env, &key);
        env.events().publish(
            (symbol_short!("org"), symbol_short!("register"), org.clone()),
            owner,
        );
        Ok(())
    }

    /// Transfer ownership of an organization. Only the current owner or the
    /// admin may reassign it.
    pub fn set_org_owner(
        env: Env,
        caller: Address,
        org: String,
        new_owner: Address,
    ) -> Result<(), Error> {
        Self::check_frozen(&env)?;
        caller.require_auth();
        let key = DataKey::Org(org.clone());
        let current: Address = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(Error::NotFound)?;
        if caller != current && !Self::is_admin(&env, &caller) {
            return Err(Error::Unauthorized);
        }
        env.storage().persistent().set(&key, &new_owner);
        Self::bump(&env, &key);
        astroid_shared::events::publish(
            &env,
            ContractEvent::OrgOwnerChanged {
                org: org.clone(),
                new_owner: new_owner.clone(),
            },
        );
        env.events().publish(
            (symbol_short!("org"), symbol_short!("owner"), org.clone()),
            new_owner,
        );
        Ok(())
    }

    /// Register (or update) a module address for an organization. Callable by
    /// the admin or the organization owner.
    pub fn register_module(
        env: Env,
        caller: Address,
        org: String,
        kind: ModuleKind,
        address: Address,
    ) -> Result<(), Error> {
        Self::check_frozen(&env)?;
        caller.require_auth();
        Self::require_admin_or_org_owner(&env, &caller, &org)?;
        let key = DataKey::Module(org.clone(), kind);
        env.storage().persistent().set(&key, &address);
        Self::bump(&env, &key);
        astroid_shared::events::publish(
            &env,
            ContractEvent::RegistryModuleUpdated {
                org: org.clone(),
                kind,
                address: address.clone(),
            },
        );
        env.events().publish(
            (
                symbol_short!("module"),
                symbol_short!("register"),
                org.clone(),
                kind,
            ),
            address,
        );
        Ok(())
    }

    /// Remove a module registration. Admin or org owner.
    pub fn remove_module(
        env: Env,
        caller: Address,
        org: String,
        kind: ModuleKind,
    ) -> Result<(), Error> {
        Self::check_frozen(&env)?;
        caller.require_auth();
        Self::require_admin_or_org_owner(&env, &caller, &org)?;
        let key = DataKey::Module(org.clone(), kind);
        if !env.storage().persistent().has(&key) {
            return Err(Error::NotFound);
        }
        env.storage().persistent().remove(&key);
        env.events().publish(
            (
                symbol_short!("module"),
                symbol_short!("remove"),
                org.clone(),
                kind,
            ),
            (),
        );
        Ok(())
    }

    /// Record a contract implementation address for a `(kind, version)` pair and
    /// advance the latest-version pointer if newer. Admin-gated; this is what
    /// powers the version-lookup upgrade strategy.
    pub fn register_version(
        env: Env,
        caller: Address,
        kind: ModuleKind,
        version: u32,
        address: Address,
    ) -> Result<(), Error> {
        Self::require_admin(&env, &caller)?;
        if version == 0 {
            return Err(Error::InvalidInput);
        }
        let vkey = DataKey::Version(kind, version);
        env.storage().persistent().set(&vkey, &address);
        Self::bump(&env, &vkey);

        let lkey = DataKey::LatestVersion(kind);
        let latest: u32 = env.storage().persistent().get(&lkey).unwrap_or(0);
        if version > latest {
            env.storage().persistent().set(&lkey, &version);
            Self::bump(&env, &lkey);
        }
        env.events().publish(
            (
                symbol_short!("version"),
                symbol_short!("register"),
                kind,
                version,
            ),
            address,
        );
        Ok(())
    }

    /// Approve a Wasm hash as the implementation of `(kind, version)`.
    /// Admin-gated. This is the only way an upgrade path enters the protocol:
    /// a member contract will not swap to a hash that is not recorded here.
    ///
    /// Re-registering a version replaces its hash and revokes the previous one,
    /// so a superseded implementation stops being an allowed upgrade target.
    pub fn register_wasm_hash(
        env: Env,
        caller: Address,
        kind: ModuleKind,
        version: u32,
        wasm_hash: BytesN<32>,
    ) -> Result<(), Error> {
        Self::check_frozen(&env)?;
        Self::require_admin(&env, &caller)?;
        if version == 0 {
            return Err(Error::InvalidInput);
        }
        let hkey = DataKey::WasmHash(kind, version);
        if let Some(previous) = env.storage().persistent().get::<_, BytesN<32>>(&hkey) {
            if previous == wasm_hash {
                return Err(Error::AlreadyExists);
            }
            env.storage()
                .persistent()
                .remove(&DataKey::ApprovedWasm(kind, previous));
        }
        env.storage().persistent().set(&hkey, &wasm_hash);
        Self::bump(&env, &hkey);
        let akey = DataKey::ApprovedWasm(kind, wasm_hash.clone());
        env.storage().persistent().set(&akey, &version);
        Self::bump(&env, &akey);

        let lkey = DataKey::LatestVersion(kind);
        let latest: u32 = env.storage().persistent().get(&lkey).unwrap_or(0);
        if version > latest {
            env.storage().persistent().set(&lkey, &version);
            Self::bump(&env, &lkey);
        }
        env.events().publish(
            (symbol_short!("wasm"), symbol_short!("approved")),
            (kind, version, wasm_hash),
        );
        Ok(())
    }

    /// Revoke an approved implementation hash. Admin-gated. Once revoked no
    /// contract can upgrade to that code any more; contracts already running it
    /// are unaffected.
    pub fn revoke_wasm_hash(
        env: Env,
        caller: Address,
        kind: ModuleKind,
        version: u32,
    ) -> Result<(), Error> {
        Self::require_admin(&env, &caller)?;
        let hkey = DataKey::WasmHash(kind, version);
        let wasm_hash: BytesN<32> = env
            .storage()
            .persistent()
            .get(&hkey)
            .ok_or(Error::NotFound)?;
        env.storage().persistent().remove(&hkey);
        env.storage()
            .persistent()
            .remove(&DataKey::ApprovedWasm(kind, wasm_hash.clone()));
        env.events().publish(
            (symbol_short!("wasm"), symbol_short!("revoked")),
            (kind, version, wasm_hash),
        );
        Ok(())
    }

    /// Read the approved Wasm hash of `(kind, version)`.
    pub fn get_wasm_hash(env: Env, kind: ModuleKind, version: u32) -> Result<BytesN<32>, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::WasmHash(kind, version))
            .ok_or(Error::NotFound)
    }

    /// Look up a specific implementation version.
    pub fn get_version(env: Env, kind: ModuleKind, version: u32) -> Result<Address, Error> {
        let key = DataKey::Version(kind, version);
        let val = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(Error::NotFound)?;
        Self::bump(&env, &key);
        Ok(val)
    }

    /// Look up the latest implementation address for a kind.
    pub fn get_latest(env: Env, kind: ModuleKind) -> Result<Address, Error> {
        let key = DataKey::LatestVersion(kind);
        let latest: u32 = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(Error::NotFound)?;
        Self::bump(&env, &key);
        Self::get_version(env, kind, latest)
    }

    /// Read the recorded owner of an organization.
    pub fn get_org_owner(env: Env, org: String) -> Result<Address, Error> {
        let key = DataKey::Org(org);
        let val = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(Error::NotFound)?;
        Self::bump(&env, &key);
        Ok(val)
    }

    /// Read the current admin.
    pub fn get_admin(env: Env) -> Result<Address, Error> {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)
    }

    /// Rotate the admin. Only the current admin may do this.
    pub fn set_admin(env: Env, caller: Address, new_admin: Address) -> Result<(), Error> {
        Self::require_admin(&env, &caller)?;
        env.storage().instance().set(&DataKey::Admin, &new_admin);
        env.storage()
            .instance()
            .extend_ttl(PERSISTENT_LIFETIME_THRESHOLD, PERSISTENT_BUMP_AMOUNT);
        env.events().publish(
            (symbol_short!("registry"), symbol_short!("setadmin")),
            new_admin,
        );
        Ok(())
    }

    /// Emergency freeze - only registered org owners can freeze.
    pub fn freeze(env: Env, caller: Address, org: String) -> Result<(), Error> {
        caller.require_auth();
        let owner: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Org(org.clone()))
            .ok_or(Error::NotFound)?;
        if owner != caller && !Self::is_admin(&env, &caller) {
            return Err(Error::Unauthorized);
        }
        env.storage().instance().set(&DataKey::Frozen, &true);
        astroid_shared::events::publish(
            &env,
            ContractEvent::RegistryFrozen {
                org: org.clone(),
                frozen: true,
            },
        );
        env.events()
            .publish((symbol_short!("registry"), symbol_short!("frozen")), org);
        Ok(())
    }

    /// Unfreeze - only registered org owners can unfreeze (works even when frozen).
    pub fn unfreeze(env: Env, caller: Address, org: String) -> Result<(), Error> {
        caller.require_auth();
        // Bypass frozen check - unfreeze must work even when frozen
        let owner: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Org(org.clone()))
            .ok_or(Error::NotFound)?;
        if owner != caller && !Self::is_admin(&env, &caller) {
            return Err(Error::Unauthorized);
        }
        env.storage().instance().set(&DataKey::Frozen, &false);
        astroid_shared::events::publish(
            &env,
            ContractEvent::RegistryFrozen {
                org: org.clone(),
                frozen: false,
            },
        );
        env.events()
            .publish((symbol_short!("registry"), symbol_short!("unfrozen")), org);
        Ok(())
    }

    // --- internal helpers ---

    fn check_frozen(env: &Env) -> Result<(), Error> {
        if env
            .storage()
            .instance()
            .get::<_, bool>(&DataKey::Frozen)
            .unwrap_or(false)
        {
            return Err(Error::RegistryFrozen);
        }
        Ok(())
    }

    fn is_admin(env: &Env, who: &Address) -> bool {
        match env.storage().instance().get::<_, Address>(&DataKey::Admin) {
            Some(admin) => &admin == who,
            None => false,
        }
    }

    fn require_admin(env: &Env, caller: &Address) -> Result<(), Error> {
        caller.require_auth();
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        if &admin != caller {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }

    fn require_admin_or_org_owner(env: &Env, caller: &Address, org: &String) -> Result<(), Error> {
        if Self::is_admin(env, caller) {
            return Ok(());
        }
        let owner: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Org(org.clone()))
            .ok_or(Error::NotFound)?;
        if &owner != caller {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }

    fn bump(env: &Env, key: &DataKey) {
        env.storage().persistent().extend_ttl(
            key,
            PERSISTENT_LIFETIME_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
    }
}

// ---------------------------------------------------------------------------
// Shared interface implementation. Guarantees the on-chain signatures match the
// generated `RegistryClient` used by other contracts.
// ---------------------------------------------------------------------------
#[contractimpl]
impl RegistryInterface for RegistryContract {
    fn lookup(env: Env, org: String, kind: ModuleKind) -> Result<Address, Error> {
        Self::check_frozen(&env)?;
        let key = DataKey::Module(org, kind);
        let val = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(Error::NotFound)?;
        Self::bump(&env, &key);
        Ok(val)
    }

    fn verify_owner(env: Env, org: String, owner: Address) -> Result<bool, Error> {
        Self::check_frozen(&env)?;
        let key = DataKey::Org(org);
        let recorded: Address = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(Error::NotFound)?;
        Self::bump(&env, &key);
        Ok(recorded == owner)
    }

    /// Resolve `wasm_hash` in the version map for `kind`, returning the version
    /// it is approved as. An unknown or revoked hash is refused with
    /// [`Error::UnauthorizedUpgrade`], and while the registry is frozen no
    /// upgrade is authorized at all, which makes the emergency freeze an
    /// effective protocol-wide upgrade halt.
    fn is_upgrade_approved(
        env: Env,
        kind: ModuleKind,
        wasm_hash: BytesN<32>,
    ) -> Result<u32, Error> {
        Self::check_frozen(&env)?;
        env.storage()
            .persistent()
            .get(&DataKey::ApprovedWasm(kind, wasm_hash))
            .ok_or(Error::UnauthorizedUpgrade)
    }
}

#[cfg(test)]
mod test;
