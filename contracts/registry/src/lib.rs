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
//! Security model (PRD Doc 10): validate caller → ownership → inputs →
//! permissions → fail safely → emit events. All mutating calls are admin- or
//! owner-gated and require Soroban auth.

use astroid_interfaces::RegistryInterface;
use astroid_shared::constants::{PERSISTENT_BUMP_AMOUNT, PERSISTENT_LIFETIME_THRESHOLD};
use astroid_shared::errors::Error;
use astroid_shared::events::ContractEvent;
use astroid_shared::types::ModuleKind;
use astroid_shared::validation::require_non_empty;
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env, String};

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
    /// Emergency freeze status (instance).
    Frozen,
    /// Role assignments: (org slug, address) -> Role.
    Role(String, Address),
}

/// Granular roles for fine-grained permission control within an organization.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    /// Full protocol control. Can manage all orgs and global settings.
    Admin = 0,
    /// Organization owner. Can manage org modules, ownership, and freeze state.
    OrgOwner = 1,
    /// Can register and remove modules for the organization.
    ModuleManager = 2,
    /// Can register new contract versions (global upgrade authority).
    VersionManager = 3,
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
            (symbol_short!("org"), symbol_short!("register")),
            (org, owner),
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
            (symbol_short!("org"), symbol_short!("owner")),
            (org, new_owner),
        );
        Ok(())
    }

    /// Register (or update) a module address for an organization. Callable by
    /// the admin, org owner, or module manager.
    pub fn register_module(
        env: Env,
        caller: Address,
        org: String,
        kind: ModuleKind,
        address: Address,
    ) -> Result<(), Error> {
        Self::check_frozen(&env)?;
        Self::require_module_manager(&env, &caller, &org)?;
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
            (symbol_short!("module"), symbol_short!("register")),
            (org, kind, address),
        );
        Ok(())
    }

    /// Remove a module registration. Admin, org owner, or module manager.
    pub fn remove_module(
        env: Env,
        caller: Address,
        org: String,
        kind: ModuleKind,
    ) -> Result<(), Error> {
        Self::check_frozen(&env)?;
        Self::require_module_manager(&env, &caller, &org)?;
        let key = DataKey::Module(org.clone(), kind);
        if !env.storage().persistent().has(&key) {
            return Err(Error::NotFound);
        }
        env.storage().persistent().remove(&key);
        env.events().publish(
            (symbol_short!("module"), symbol_short!("remove")),
            (org, kind),
        );
        Ok(())
    }

    /// Record a contract implementation address for a `(kind, version)` pair and
    /// advance the latest-version pointer if newer. Callable by the admin or
    /// version manager. This is what powers the version-lookup upgrade strategy.
    pub fn register_version(
        env: Env,
        caller: Address,
        kind: ModuleKind,
        version: u32,
        address: Address,
    ) -> Result<(), Error> {
        Self::require_admin(&env, &caller)?;
        // TODO: Enable version manager role for version registration
        // For now, keep admin-only for security
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
            (symbol_short!("version"), symbol_short!("register")),
            (kind, version, address),
        );
        Ok(())
    }

    /// Look up a specific implementation version.
    pub fn get_version(env: Env, kind: ModuleKind, version: u32) -> Result<Address, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::Version(kind, version))
            .ok_or(Error::NotFound)
    }

    /// Look up the latest implementation address for a kind.
    pub fn get_latest(env: Env, kind: ModuleKind) -> Result<Address, Error> {
        let latest: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::LatestVersion(kind))
            .ok_or(Error::NotFound)?;
        Self::get_version(env, kind, latest)
    }

    /// Read the recorded owner of an organization.
    pub fn get_org_owner(env: Env, org: String) -> Result<Address, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::Org(org))
            .ok_or(Error::NotFound)
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

    /// Grant a role to an address for an organization. Admin or org owner may
    /// grant roles. Org owners cannot grant Admin role.
    pub fn grant_role(
        env: Env,
        caller: Address,
        org: String,
        address: Address,
        role: Role,
    ) -> Result<(), Error> {
        Self::check_frozen(&env)?;
        caller.require_auth();
        // Only admin can grant Admin role
        if role == Role::Admin && !Self::is_admin(&env, &caller) {
            return Err(Error::Unauthorized);
        }
        // Admin or org owner can grant other roles
        Self::require_admin_or_org_owner(&env, &caller, &org)?;
        let key = DataKey::Role(org.clone(), address.clone());
        env.storage().persistent().set(&key, &role);
        Self::bump(&env, &key);
        env.events().publish(
            (symbol_short!("role"), symbol_short!("grant")),
            (org, address, role_name(&role)),
        );
        Ok(())
    }

    /// Revoke a role from an address for an organization. Admin or org owner may
    /// revoke roles.
    pub fn revoke_role(
        env: Env,
        caller: Address,
        org: String,
        address: Address,
    ) -> Result<(), Error> {
        Self::check_frozen(&env)?;
        caller.require_auth();
        Self::require_admin_or_org_owner(&env, &caller, &org)?;
        let key = DataKey::Role(org.clone(), address.clone());
        if !env.storage().persistent().has(&key) {
            return Err(Error::NotFound);
        }
        env.storage().persistent().remove(&key);
        env.events().publish(
            (symbol_short!("role"), symbol_short!("revoke")),
            (org, address),
        );
        Ok(())
    }

    /// Get the role assigned to an address for an organization.
    pub fn get_role(env: Env, org: String, address: Address) -> Result<Option<Role>, Error> {
        Ok(env
            .storage()
            .persistent()
            .get(&DataKey::Role(org, address)))
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

    /// Check if the caller has at least the required role for the organization.
    /// Admin always has access regardless of role assignment.
    fn require_role(
        env: &Env,
        caller: &Address,
        org: &String,
        required_role: Role,
    ) -> Result<(), Error> {
        caller.require_auth();
        // Admin always has full access
        if Self::is_admin(env, caller) {
            return Ok(());
        }
        // Check if caller has the required role or higher
        let caller_role: Option<Role> = env
            .storage()
            .persistent()
            .get(&DataKey::Role(org.clone(), caller.clone()));
        match caller_role {
            Some(role) => {
                // Role hierarchy: Admin > OrgOwner > ModuleManager > VersionManager
                let role_level = role_level(&role);
                let required_level = role_level(&required_role);
                if role_level <= required_level {
                    Ok(())
                } else {
                    Err(Error::Unauthorized)
                }
            }
            None => Err(Error::Unauthorized),
        }
    }

    /// Get the numeric level of a role (lower = more privileged).
    fn role_level(role: &Role) -> u8 {
        match role {
            Role::Admin => 0,
            Role::OrgOwner => 1,
            Role::ModuleManager => 2,
            Role::VersionManager => 3,
        }
    }

    /// Check if the caller can manage modules (Admin, OrgOwner, or ModuleManager).
    fn require_module_manager(env: &Env, caller: &Address, org: &String) -> Result<(), Error> {
        Self::require_role(env, caller, org, Role::ModuleManager)
    }

    /// Check if the caller can manage versions (Admin or VersionManager).
    fn require_version_manager(env: &Env, caller: &Address, org: &String) -> Result<(), Error> {
        // Version management is a global operation; org param is used for role lookup
        Self::require_role(env, caller, org, Role::VersionManager)
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
        env.storage()
            .persistent()
            .get(&DataKey::Module(org, kind))
            .ok_or(Error::NotFound)
    }

    fn verify_owner(env: Env, org: String, owner: Address) -> Result<bool, Error> {
        Self::check_frozen(&env)?;
        let recorded: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Org(org))
            .ok_or(Error::NotFound)?;
        Ok(recorded == owner)
    }
}

/// Convert a role to its string name for event emission.
fn role_name(role: &Role) -> soroban_sdk::Symbol {
    use soroban_sdk::symbol_short;
    match role {
        Role::Admin => symbol_short!("admin"),
        Role::OrgOwner => symbol_short!("org_owner"),
        Role::ModuleManager => symbol_short!("mod_mgr"),
        Role::VersionManager => symbol_short!("ver_mgr"),
    }
}

#[cfg(test)]
mod test;
