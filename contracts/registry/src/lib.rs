#![no_std]
#![allow(clippy::too_many_arguments)]
//! # Astroid Registry Contract
//!
//! The backbone of the protocol and its single source of truth. The registry
//! records, per organization:
//! - the **owner** of the organization,
//! - the **module address** for each [`ModuleKind`] (wallet, treasury, policy…),
//! - optional **deprecation** flags and **migration targets**, so a superseded
//!   module is blocked from new interactions (`Error::ModuleDeprecated`) while
//!   clients are pointed at its replacement,
//!
//! and, globally, a **version → address** table used by the upgrade strategy so
//! new contract versions (e.g. Wallet v1 → v2 → v3) can be introduced without
//! breaking consumers (PRD Doc 7 §Upgrade Strategy).
//!
//! ## Interface version compatibility
//!
//! Because contracts upgrade independently, the registry also validates the
//! *shared interface* version a registered module advertises against the
//! minimum compatibility bound the organization declares for that module kind.
//! Before a module is routed to (`lookup`) or re-pointed at a newer
//! implementation (`register_module_with_version`), the implementation's
//! [`Version`] must satisfy the organization's bound — otherwise the call is
//! rejected with the deterministic [`Error::InterfaceVersionIncompatible`].
//! See [`astroid_interfaces::version`] for the versioning rules.
//!
//! Security model (PRD Doc 10): validate caller → ownership → inputs →
//! permissions → fail safely → emit events. All mutating calls are admin- or
//! owner-gated and require Soroban auth.
//!
//! ## Permission delegation
//!
//! Requiring the root owner's key for every registry edit does not survive
//! contact with a real organization: the people who rotate a policy contract
//! are usually not the people who hold ultimate ownership, and handing them the
//! root key to do it defeats the point of having one. The registry therefore
//! records a [`Role`] per `(organization, account)` and checks it on the
//! org-scoped modifications, so an owner can delegate narrow administrative
//! powers to sub-accounts or secondary operational keys without transferring
//! ownership:
//!
//! | Role             | May register/remove modules of kind                    |
//! |------------------|-------------------------------------------------------|
//! | `Admin`          | anything (protocol-wide administration)               |
//! | `OrgOwner`       | anything for their own organization                   |
//! | `ModuleManager`  | any kind (repointing modules at new versions)         |
//! | `VersionManager` | reserved for the global version table                  |
//!
//! Roles are totally ordered by privilege (lower rank = more privileged), so a
//! guard for `ModuleManager` is also satisfied by `OrgOwner` and `Admin`.
//! Delegation is deliberately bounded: only the recorded org owner or the
//! protocol admin may grant or revoke, and the root actions (ownership
//! transfer, emergency freeze, role administration) stay with them as well.

use astroid_interfaces::version::{require_compatible, Version, CURRENT_VERSION};
use astroid_interfaces::RegistryInterface;
use astroid_shared::constants::{PERSISTENT_BUMP_AMOUNT, PERSISTENT_LIFETIME_THRESHOLD};
use astroid_shared::ensure;
use astroid_shared::errors::Error;
use astroid_shared::events::ContractEvent;
use astroid_shared::storage::key_of_string;
use astroid_shared::types::ModuleKind;
use astroid_shared::validation::require_non_empty;
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, Address, BytesN, Env, String, Vec,
};

/// Storage keys. `Admin` lives in instance storage; everything else is keyed
/// per organization/module in persistent storage.
///
/// Org-slug components are pre-hashed to a fixed-size [`BytesN<32>`] via
/// [`key_of_string`] so key serialization cost is constant regardless of
/// identifier length (gas-sensitive on hot lookups). Each module's routing
/// records are consolidated into a single [`ModuleRecord`] under one `DataKey`
/// so a lookup touches one rent line instead of several.
#[contracttype]
#[derive(Clone)]
enum DataKey {
    /// Protocol admin (instance).
    Admin,
    /// Organization owner: hashed org slug -> owner address.
    Org(BytesN<32>),
    /// Consolidated module record: (hashed org slug, kind) -> ModuleRecord.
    Module(BytesN<32>, ModuleKind),
    /// Delegated role: (hashed org slug, account) -> Role.
    Role(BytesN<32>, Address),
    /// Version table: (kind, version) -> contract address (global upgrade map).
    Version(ModuleKind, u32),
    /// Latest known version number for a kind.
    LatestVersion(ModuleKind),
    /// Emergency freeze status (instance).
    Frozen,
    /// System-wide pause status (instance).
    Paused,
    /// Interface version a registered module implementation advertises:
    /// (hashed org slug, kind) -> Version.
    MinInterfaceVersion(BytesN<32>, ModuleKind),
}

/// The full routing state for one registered module, stored under a single
/// `Module` key to keep lookups on one rent line.
///
/// The interface version is kept as two scalar `u32`s (rather than nesting the
/// `Version` UDT) so the record can be a plain `contracttype` struct; a zero
/// `interface_major`/`interface_minor` pair signals "no explicit version".
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModuleRecord {
    /// The currently registered implementation address.
    pub address: Address,
    /// Whether the module is deprecated and `lookup` rejects new interactions.
    pub deprecated: bool,
    /// The successor implementation to migrate to, when one is configured.
    pub migration_target: Option<Address>,
    /// The interface version the implementation advertises (0,0 = unset).
    /// Stored as scalars to avoid nesting a cross-crate UDT inside the record.
    pub interface_major: u32,
    pub interface_minor: u32,
}

impl ModuleRecord {
    /// A fresh, unregistered record pointed at `address`.
    fn new(address: Address) -> Self {
        Self {
            address,
            deprecated: false,
            migration_target: None,
            interface_major: 0,
            interface_minor: 0,
        }
    }

    /// The recorded interface version, when one was explicitly registered.
    fn interface_version(&self) -> Option<Version> {
        if self.interface_major == 0 && self.interface_minor == 0 {
            None
        } else {
            Some(Version::new(self.interface_major, self.interface_minor))
        }
    }

    /// Set the recorded interface version.
    fn set_interface_version(&mut self, v: Version) {
        self.interface_major = v.major;
        self.interface_minor = v.minor;
    }
}

/// Granular roles for fine-grained permission control within an organization.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryRole {
    /// Delegated co-owner of the organization's module records. Reaches every
    /// module kind, but not the root actions (ownership transfer, freeze, role
    /// administration), which stay with the recorded owner.
    Owner = 0,
    /// May manage the organization's `Policy` module registration.
    PolicyManager = 1,
    /// May manage the organization's `Treasury`, `Budget` and `Escrow` module
    /// registrations — the value-custody side of the protocol.
    TreasuryOperator = 2,
    /// May repoint any of the organization's modules, which is what rolling a
    /// module forward to a new implementation version amounts to.
    ModuleUpgrader = 3,
}

/// Organization-scoped operational roles.
///
/// Discriminants are part of the public ABI and MUST NOT be reordered once
/// released. Lower rank means more privilege, so an `OrgOwner` satisfies a
/// `ModuleManager` guard.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    /// Protocol-wide administrator. Satisfies every guard.
    Admin = 0,
    /// Recorded organization owner.
    OrgOwner = 1,
    /// May register/remove/rotate modules for the organization.
    ModuleManager = 2,
    /// Reserved for managing the global version table.
    VersionManager = 3,
}

/// A composite view of a registered module returned by [`RegistryContract::get_module`].
/// Lets a client resolve, in one call, the current address, whether the module is
/// deprecated, and where to migrate to (if one has been configured).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModuleInfo {
    /// The currently registered (possibly deprecated) implementation address.
    pub address: Address,
    /// Whether the module is deprecated and `lookup` rejects new interactions.
    pub deprecated: bool,
    /// The successor implementation to migrate to, when one is configured.
    pub migration_target: Option<Address>,
}

impl RegistryRole {
    /// Whether this role may register or remove the module of `kind` for the
    /// organization it was granted on.
    pub fn may_manage(self, kind: ModuleKind) -> bool {
        match self {
            RegistryRole::Owner | RegistryRole::ModuleUpgrader => true,
            RegistryRole::PolicyManager => matches!(kind, ModuleKind::Policy),
            RegistryRole::TreasuryOperator => matches!(
                kind,
                ModuleKind::Treasury | ModuleKind::Budget | ModuleKind::Escrow
            ),
        }
    }
}

#[contract]
pub struct RegistryContract;

// ---------------------------------------------------------------------------
// Administration & registration (inherent surface).
// ---------------------------------------------------------------------------
#[contractimpl]
impl RegistryContract {
    // --- registry-gated upgrades ---

    /// Record (or rotate) who may upgrade this contract and which registry
    /// authorizes the new code. Bootstrapped by the deployer alongside
    /// `initialize`; afterwards only the current upgrade admin may rotate it.
    pub fn set_upgrade_authority(
        env: soroban_sdk::Env,
        caller: soroban_sdk::Address,
        admin: soroban_sdk::Address,
        registry: soroban_sdk::Address,
    ) -> Result<(), astroid_shared::errors::Error> {
        Self::check_paused(&env)?;
        astroid_interfaces::upgrade::set_authority(&env, &caller, &admin, &registry)
    }

    /// Read the recorded upgrade authority.
    pub fn get_upgrade_authority(
        env: soroban_sdk::Env,
    ) -> Result<astroid_interfaces::upgrade::UpgradeAuthority, astroid_shared::errors::Error> {
        astroid_interfaces::upgrade::get_authority(&env)
    }

    /// Replace this contract's code with `wasm_hash`.
    ///
    /// Two gates must pass: `caller` must be the recorded upgrade admin, and
    /// `wasm_hash` must be approved for [`ModuleKind::Organization`] in the registry. Any
    /// other outcome leaves the contract running its current code.
    pub fn upgrade(
        env: soroban_sdk::Env,
        caller: soroban_sdk::Address,
        wasm_hash: soroban_sdk::BytesN<32>,
    ) -> Result<(), astroid_shared::errors::Error> {
        Self::check_paused(&env)?;
        astroid_interfaces::upgrade::perform(
            &env,
            &caller,
            astroid_shared::types::ModuleKind::Organization,
            wasm_hash,
        )
    }
    /// Initialize the registry with its administrator. Callable once.
    pub fn initialize(env: Env, admin: Address) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .instance()
            .extend_ttl(PERSISTENT_LIFETIME_THRESHOLD, PERSISTENT_BUMP_AMOUNT);
        astroid_shared::events::registry_initialized(&env, &admin);
        Ok(())
    }

    /// Register an organization and its owner. Admin-gated.
    pub fn register_org(
        env: Env,
        caller: Address,
        org: String,
        owner: Address,
    ) -> Result<(), Error> {
        Self::check_paused(&env)?;
        Self::check_frozen(&env)?;
        require_non_empty(&org)?;
        Self::require_admin(&env, &caller)?;
        let key = DataKey::Org(org_key(&env, &org));
        if env.storage().persistent().has(&key) {
            return Err(Error::AlreadyExists);
        }
        env.storage().persistent().set(&key, &owner);
        Self::bump(&env, &key);
        astroid_shared::events::registry_org_registered(&env, &org, &owner);
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
        Self::check_paused(&env)?;
        Self::check_frozen(&env)?;
        caller.require_auth();
        let key = DataKey::Org(org_key(&env, &org));
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
        astroid_shared::events::registry_org_owner(&env, &org, &new_owner);
        Ok(())
    }

    /// Register (or update) a module address for an organization. Callable by
    /// the admin, org owner, or module manager.
    ///
    /// This is the convenience path that assumes the implementation speaks the
    /// protocol's current interface ([`CURRENT_VERSION`]). Use
    /// [`Self::register_module_with_version`] to declare a specific interface
    /// version and have it validated against the organization's minimum bound.
    pub fn register_module(
        env: Env,
        caller: Address,
        org: String,
        kind: ModuleKind,
        address: Address,
    ) -> Result<(), Error> {
        Self::check_paused(&env)?;
        Self::check_frozen(&env)?;
        Self::require_module_manager(&env, &caller, &org)?;
        let key = DataKey::Module(org_key(&env, &org), kind);
        // A (re)registration points at a fresh implementation, so any prior
        // deprecation flag, migration target and recorded interface version must
        // not carry over and block or misdirect lookups of the new address.
        env.storage()
            .persistent()
            .set(&key, &ModuleRecord::new(address.clone()));
        Self::bump(&env, &key);
        astroid_shared::events::publish(
            &env,
            ContractEvent::RegistryModuleUpdated {
                org: org.clone(),
                kind,
                address: address.clone(),
            },
        );
        astroid_shared::events::registry_module_registered(&env, &org, kind, &address);
        Ok(())
    }

    /// Register (or update) a module address together with the **interface
    /// version** the implementation advertises.
    ///
    /// This is the upgrade-aware registration path: `version` is validated
    /// against the organization's minimum compatibility bound for `kind` (see
    /// [`Self::set_min_interface_version`]) *before* the module is recorded, so
    /// a newer implementation that does not meet — or a rollback that violates —
    /// the bound is rejected with [`Error::InterfaceVersionIncompatible`] and no
    /// state is written.
    ///
    /// Callable by the admin, org owner, or module manager.
    pub fn register_module_with_version(
        env: Env,
        caller: Address,
        org: String,
        kind: ModuleKind,
        address: Address,
        version: Version,
    ) -> Result<(), Error> {
        Self::check_paused(&env)?;
        Self::check_frozen(&env)?;
        Self::require_module_manager(&env, &caller, &org)?;
        let ok = org_key(&env, &org);
        // Registration-time compatibility gate: an org that declares a minimum
        // compatible interface version must not be pointed at an implementation
        // that violates it.
        if let Some(min) = env
            .storage()
            .persistent()
            .get(&DataKey::MinInterfaceVersion(ok.clone(), kind))
        {
            require_compatible(version, min)?;
        }
        let mut record = ModuleRecord::new(address.clone());
        record.set_interface_version(version);
        let key = DataKey::Module(ok, kind);
        env.storage().persistent().set(&key, &record);
        Self::bump(&env, &key);
        astroid_shared::events::publish(
            &env,
            ContractEvent::RegistryModuleUpdated {
                org: org.clone(),
                kind,
                address: address.clone(),
            },
        );
        astroid_shared::events::registry_module_registered(&env, &org, kind, &address);
        env.events().publish(
            (
                symbol_short!("interface"),
                symbol_short!("version"),
                org,
                kind,
            ),
            version,
        );
        Ok(())
    }

    /// Atomically register (or update) several module addresses for an
    /// organization in a single call. Callable by the admin, org owner, or
    /// module manager.
    ///
    /// All lists must be non-empty and of equal length, and no `kind` may
    /// appear twice — otherwise the whole batch is rejected with
    /// [`Error::InvalidInput`] *before* any state is written, so a partial
    /// registration can never occur.
    pub fn batch_register_modules(
        env: Env,
        caller: Address,
        org: String,
        kinds: Vec<ModuleKind>,
        addresses: Vec<Address>,
    ) -> Result<(), Error> {
        Self::check_paused(&env)?;
        Self::check_frozen(&env)?;
        Self::require_module_manager(&env, &caller, &org)?;
        if kinds.is_empty() || kinds.len() != addresses.len() {
            return Err(Error::InvalidInput);
        }
        // Reject duplicate kinds up-front so an invalid batch never partially
        // writes module records.
        for i in 0..kinds.len() {
            for j in (i + 1)..kinds.len() {
                if kinds.get(i).unwrap() == kinds.get(j).unwrap() {
                    return Err(Error::InvalidInput);
                }
            }
        }
        for i in 0..kinds.len() {
            let kind = kinds.get(i).unwrap();
            let address = addresses.get(i).unwrap();
            let key = DataKey::Module(org_key(&env, &org), kind);
            env.storage()
                .persistent()
                .set(&key, &ModuleRecord::new(address));
            Self::bump(&env, &key);
        }
        astroid_shared::events::publish(
            &env,
            ContractEvent::RegistryModuleBatchUpdated {
                org: org.clone(),
                kinds,
                addresses,
            },
        );
        Ok(())
    }

    /// Mark a registered module as deprecated. Admin-gated. Once flagged,
    /// [`Self::lookup`] rejects new interactions with [`Error::ModuleDeprecated`]
    /// while the raw address remains readable through [`Self::get_module_address`]
    /// so legacy migrations can still reach the old implementation.
    pub fn deprecate_module(
        env: Env,
        caller: Address,
        org: String,
        kind: ModuleKind,
    ) -> Result<(), Error> {
        Self::check_frozen(&env)?;
        Self::require_admin(&env, &caller)?;
        let mkey = DataKey::Module(org_key(&env, &org), kind);
        let mut record: ModuleRecord = env
            .storage()
            .persistent()
            .get(&mkey)
            .ok_or(Error::NotFound)?;
        record.deprecated = true;
        env.storage().persistent().set(&mkey, &record);
        Self::bump(&env, &mkey);
        astroid_shared::events::registry_module_deprecated(&env, &org, kind);
        Ok(())
    }

    /// Clear a module's deprecation flag, restoring normal routing. Admin-gated.
    pub fn reactivate_module(
        env: Env,
        caller: Address,
        org: String,
        kind: ModuleKind,
    ) -> Result<(), Error> {
        Self::check_frozen(&env)?;
        Self::require_admin(&env, &caller)?;
        let mkey = DataKey::Module(org_key(&env, &org), kind);
        let mut record: ModuleRecord = env
            .storage()
            .persistent()
            .get(&mkey)
            .ok_or(Error::NotFound)?;
        record.deprecated = false;
        env.storage().persistent().set(&mkey, &record);
        Self::bump(&env, &mkey);
        astroid_shared::events::registry_module_restored(&env, &org, kind);
        Ok(())
    }

    /// Read a module's deprecation status (false when never flagged).
    pub fn is_module_deprecated(env: Env, org: String, kind: ModuleKind) -> bool {
        env.storage()
            .persistent()
            .get::<_, ModuleRecord>(&DataKey::Module(org_key(&env, &org), kind))
            .map(|r| r.deprecated)
            .unwrap_or(false)
    }

    /// Read a registered module address bypassing the deprecation guard.
    /// Intended for legacy migrations and admin tooling that must still reach a
    /// deprecated implementation.
    pub fn get_module_address(env: Env, org: String, kind: ModuleKind) -> Result<Address, Error> {
        let key = DataKey::Module(org_key(&env, &org), kind);
        let record: ModuleRecord = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(Error::NotFound)?;
        Self::bump(&env, &key);
        Ok(record.address)
    }

    /// Link a registered module to its successor implementation. Admin-gated.
    ///
    /// This is the formal migration pointer: once set, consumers can read it via
    /// [`Self::get_module_migration`] (or [`Self::get_module`]) to be guided from
    /// a deprecated module to the up-to-date replacement. The target must exist
    /// as a registered module of the same kind and must differ from the module it
    /// would replace (a module cannot be its own successor).
    pub fn set_migration_target(
        env: Env,
        caller: Address,
        org: String,
        kind: ModuleKind,
        successor: Address,
    ) -> Result<(), Error> {
        Self::check_frozen(&env)?;
        Self::require_admin(&env, &caller)?;
        let mkey = DataKey::Module(org_key(&env, &org), kind);
        let mut record: ModuleRecord = env
            .storage()
            .persistent()
            .get(&mkey)
            .ok_or(Error::NotFound)?;
        if successor == record.address {
            return Err(Error::InvalidInput);
        }
        record.migration_target = Some(successor.clone());
        env.storage().persistent().set(&mkey, &record);
        Self::bump(&env, &mkey);
        env.events().publish(
            (
                symbol_short!("module"),
                symbol_short!("migrate"),
                org.clone(),
                kind,
            ),
            successor,
        );
        Ok(())
    }

    /// Clear a module's migration target, un-linking it from any successor.
    /// Admin-gated. The module keeps its existing deprecation status.
    pub fn clear_migration_target(
        env: Env,
        caller: Address,
        org: String,
        kind: ModuleKind,
    ) -> Result<(), Error> {
        Self::check_frozen(&env)?;
        Self::require_admin(&env, &caller)?;
        let mkey = DataKey::Module(org_key(&env, &org), kind);
        let mut record: ModuleRecord = env
            .storage()
            .persistent()
            .get(&mkey)
            .ok_or(Error::NotFound)?;
        if record.migration_target.is_none() {
            return Err(Error::NotFound);
        }
        record.migration_target = None;
        env.storage().persistent().set(&mkey, &record);
        Self::bump(&env, &mkey);
        env.events().publish(
            (symbol_short!("module"), symbol_short!("mig_clear")),
            (org, kind),
        );
        Ok(())
    }

    /// Read the migration target configured for a module, or [`Error::NotFound`]
    /// when none has been set.
    pub fn get_module_migration(env: Env, org: String, kind: ModuleKind) -> Result<Address, Error> {
        let gkey = DataKey::Module(org_key(&env, &org), kind);
        let record: ModuleRecord = env
            .storage()
            .persistent()
            .get(&gkey)
            .ok_or(Error::NotFound)?;
        Self::bump(&env, &gkey);
        record.migration_target.ok_or(Error::NotFound)
    }

    /// Composite view of a registered module: its address, deprecated status and
    /// configured migration target. Returns [`Error::NotFound`] when the module
    /// is not registered.
    pub fn get_module(env: Env, org: String, kind: ModuleKind) -> Result<ModuleInfo, Error> {
        let mkey = DataKey::Module(org_key(&env, &org), kind);
        let record: ModuleRecord = env
            .storage()
            .persistent()
            .get(&mkey)
            .ok_or(Error::NotFound)?;
        Self::bump(&env, &mkey);
        Ok(ModuleInfo {
            address: record.address,
            deprecated: record.deprecated,
            migration_target: record.migration_target,
        })
    }

    /// Remove a module registration. Same gate as `register_module`: admin, org
    /// owner, or a delegated role that reaches this [`ModuleKind`].
    pub fn remove_module(
        env: Env,
        caller: Address,
        org: String,
        kind: ModuleKind,
    ) -> Result<(), Error> {
        Self::check_paused(&env)?;
        Self::check_frozen(&env)?;
        Self::require_module_manager(&env, &caller, &org)?;
        let key = DataKey::Module(org_key(&env, &org), kind);
        ensure!(env.storage().persistent().has(&key), Error::NotFound);
        env.storage().persistent().remove(&key);
        // The consolidated ModuleRecord holds the deprecation flag, migration
        // target and interface version, so removing it drops every piece of the
        // routing state together and a later re-registration starts clean.
        env.events().publish(
            (
                symbol_short!("module"),
                symbol_short!("remove"),
                org.clone(),
                kind,
            ),
            (),
        );
        astroid_shared::events::registry_module_removed(&env, &org, kind);
        Ok(())
    }

    /// Delegate `role` over `org` to `account`, replacing any role it already
    /// held. Only the recorded organization owner or the protocol admin may
    /// grant, so a delegated role can never be used to widen its own reach or
    /// to mint further delegations.
    ///
    /// Org owners cannot be granted the `Admin` role; that is reserved for the
    /// protocol admin.
    pub fn grant_role(
        env: Env,
        caller: Address,
        org: String,
        address: Address,
        role: Role,
    ) -> Result<(), Error> {
        Self::check_frozen(&env)?;
        // Only admin can grant Admin role
        if role == Role::Admin && !Self::is_admin(&env, &caller) {
            return Err(Error::Unauthorized);
        }
        // Admin or org owner can grant other roles
        Self::require_admin_or_org_owner(&env, &caller, &org)?;
        let key = DataKey::Role(org_key(&env, &org), address.clone());
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
        Self::require_admin_or_org_owner(&env, &caller, &org)?;
        let key = DataKey::Role(org_key(&env, &org), address.clone());
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
            .get(&DataKey::Role(org_key(&env, &org), address)))
    }

    /// Whether `account` may register or remove the `kind` module for `org` —
    /// the same question the entrypoint guard asks, exposed for off-chain use.
    pub fn can_manage_module(env: Env, org: String, account: Address, kind: ModuleKind) -> bool {
        if Self::is_admin(&env, &account) {
            return true;
        }
        Self::effective_role(&env, &org, &account)
            .map(|role| role.may_manage(kind))
            .unwrap_or(false)
    }

    // --- interface version compatibility ---

    /// Declare the **minimum compatible interface version** the organization
    /// requires for a module kind. Admin-gated.
    ///
    /// Once set, this bound is enforced in two places:
    /// - [`Self::register_module_with_version`] rejects any implementation whose
    ///   advertised [`Version`] is not compatible with the bound, and
    /// - [`Self::lookup`] (and [`Self::check_interface_compatibility`]) refuses
    ///   to route to a registered module whose interface version violates it.
    ///
    /// The organization must already exist (otherwise [`Error::NotFound`]).
    pub fn set_min_interface_version(
        env: Env,
        caller: Address,
        org: String,
        kind: ModuleKind,
        min: Version,
    ) -> Result<(), Error> {
        Self::check_paused(&env)?;
        Self::check_frozen(&env)?;
        Self::require_admin(&env, &caller)?;
        ensure!(
            env.storage()
                .persistent()
                .has(&DataKey::Org(org_key(&env, &org))),
            Error::NotFound
        );
        let key = DataKey::MinInterfaceVersion(org_key(&env, &org), kind);
        env.storage().persistent().set(&key, &min);
        Self::bump(&env, &key);
        Ok(())
    }

    /// Clear the minimum compatible interface version bound for a module kind.
    /// Admin-gated. Fails with [`Error::NotFound`] when no bound is set.
    pub fn clear_min_interface_version(
        env: Env,
        caller: Address,
        org: String,
        kind: ModuleKind,
    ) -> Result<(), Error> {
        Self::check_paused(&env)?;
        Self::check_frozen(&env)?;
        Self::require_admin(&env, &caller)?;
        let key = DataKey::MinInterfaceVersion(org_key(&env, &org), kind);
        if !env.storage().persistent().has(&key) {
            return Err(Error::NotFound);
        }
        env.storage().persistent().remove(&key);
        Ok(())
    }

    /// Read the minimum compatible interface version bound for a module kind,
    /// or [`Error::NotFound`] when none has been set.
    pub fn get_min_interface_version(
        env: Env,
        org: String,
        kind: ModuleKind,
    ) -> Result<Version, Error> {
        let key = DataKey::MinInterfaceVersion(org_key(&env, &org), kind);
        let val = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(Error::NotFound)?;
        Self::bump(&env, &key);
        Ok(val)
    }

    /// Read the interface version recorded for a registered module, or
    /// [`Error::NotFound`] when the module is not registered or was registered
    /// without an explicit version.
    pub fn get_module_interface_version(
        env: Env,
        org: String,
        kind: ModuleKind,
    ) -> Result<Version, Error> {
        let key = DataKey::Module(org_key(&env, &org), kind);
        let record: ModuleRecord = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(Error::NotFound)?;
        Self::bump(&env, &key);
        record.interface_version().ok_or(Error::NotFound)
    }

    /// Verify a registered module against the organization's minimum
    /// compatibility bound, returning the module's effective interface version.
    ///
    /// - [`Err(Error::NotFound)`] when the module is not registered,
    /// - [`Err(Error::InterfaceVersionIncompatible)`] when the module's
    ///   interface version does not satisfy the bound,
    /// - [`Ok(version)`] otherwise. Modules registered through the plain
    ///   [`Self::register_module`] path are presumed to implement
    ///   [`CURRENT_VERSION`].
    pub fn check_interface_compatibility(
        env: Env,
        org: String,
        kind: ModuleKind,
    ) -> Result<Version, Error> {
        let key = DataKey::Module(org_key(&env, &org), kind);
        if !env.storage().persistent().has(&key) {
            return Err(Error::NotFound);
        }
        Self::bump(&env, &key);
        let actual = Self::effective_interface_version(&env, &org, kind)?;
        let min: Option<Version> = env
            .storage()
            .persistent()
            .get(&DataKey::MinInterfaceVersion(org_key(&env, &org), kind));
        match min {
            Some(min) => {
                require_compatible(actual, min)?;
                Ok(actual)
            }
            None => Ok(actual),
        }
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
        Self::check_paused(&env)?;
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
        astroid_shared::events::registry_version_registered(&env, kind, version, &address);
        Ok(())
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
        let key = DataKey::Org(org_key(&env, &org));
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
        Self::check_paused(&env)?;
        Self::require_admin(&env, &caller)?;
        env.storage().instance().set(&DataKey::Admin, &new_admin);
        env.storage()
            .instance()
            .extend_ttl(PERSISTENT_LIFETIME_THRESHOLD, PERSISTENT_BUMP_AMOUNT);
        astroid_shared::events::registry_set_admin(&env, &new_admin);
        Ok(())
    }

    /// Emergency freeze - only registered org owners can freeze.
    pub fn freeze(env: Env, caller: Address, org: String) -> Result<(), Error> {
        caller.require_auth();
        let owner: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Org(org_key(&env, &org)))
            .ok_or(Error::NotFound)?;
        ensure!(
            owner == caller || Self::is_admin(&env, &caller),
            Error::Unauthorized
        );
        env.storage().instance().set(&DataKey::Frozen, &true);
        astroid_shared::events::publish(
            &env,
            ContractEvent::RegistryFrozen {
                org: org.clone(),
                frozen: true,
            },
        );
        astroid_shared::events::registry_frozen(&env, &org);
        Ok(())
    }

    /// Unfreeze - only registered org owners can unfreeze (works even when frozen).
    pub fn unfreeze(env: Env, caller: Address, org: String) -> Result<(), Error> {
        caller.require_auth();
        // Bypass frozen check - unfreeze must work even when frozen
        let owner: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Org(org_key(&env, &org)))
            .ok_or(Error::NotFound)?;
        ensure!(
            owner == caller || Self::is_admin(&env, &caller),
            Error::Unauthorized
        );
        env.storage().instance().set(&DataKey::Frozen, &false);
        astroid_shared::events::publish(
            &env,
            ContractEvent::RegistryFrozen {
                org: org.clone(),
                frozen: false,
            },
        );
        astroid_shared::events::registry_unfrozen(&env, &org);
        Ok(())
    }

    // --- internal helpers ---

    fn check_frozen(env: &Env) -> Result<(), Error> {
        ensure!(
            !env.storage()
                .instance()
                .get::<_, bool>(&DataKey::Frozen)
                .unwrap_or(false),
            Error::RegistryFrozen
        );
        Ok(())
    }

    fn check_paused(env: &Env) -> Result<(), Error> {
        ensure!(
            !env.storage()
                .instance()
                .get::<_, bool>(&DataKey::Paused)
                .unwrap_or(false),
            Error::ContractPaused
        );
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
        ensure!(&admin == caller, Error::Unauthorized);
        Ok(())
    }

    /// Require the caller to be the protocol admin or the recorded organization
    /// owner.
    fn require_admin_or_org_owner(env: &Env, caller: &Address, org: &String) -> Result<(), Error> {
        caller.require_auth();
        if Self::is_admin(env, caller) {
            return Ok(());
        }
        let owner: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Org(org_key(env, org)))
            .ok_or(Error::NotFound)?;
        ensure!(&owner == caller, Error::Unauthorized);
        Ok(())
    }

    /// Resolve the role `account` effectively holds over `org`, treating the
    /// recorded owner as an implicit [`RegistryRole::Owner`]. Returns `None`
    /// for an unknown organization, which the callers report as
    /// [`Error::Unauthorized`] — a stranger asking about a non-existent org
    /// learns nothing either way.
    fn effective_role(env: &Env, org: &String, account: &Address) -> Option<RegistryRole> {
        let ok = org_key(env, org);
        let owner: Option<Address> = env.storage().persistent().get(&DataKey::Org(ok.clone()));
        if owner.as_ref() == Some(account) {
            return Some(RegistryRole::Owner);
        }
        // Roles are stored as the protocol `Role` under one shared key; map the
        // surviving `RegistryRole` vocabulary onto it for the delegated-role
        // surface used by `can_manage_module`.
        let role: Option<Role> = env
            .storage()
            .persistent()
            .get(&DataKey::Role(ok, account.clone()));
        role.map(|r| match r {
            Role::Admin => RegistryRole::Owner,
            Role::OrgOwner => RegistryRole::Owner,
            Role::ModuleManager => RegistryRole::ModuleUpgrader,
            Role::VersionManager => RegistryRole::ModuleUpgrader,
        })
    }

    /// The interface version a registered module effectively speaks: the
    /// explicitly recorded one when present, otherwise the protocol's current
    /// interface version.
    fn effective_interface_version(
        env: &Env,
        org: &String,
        kind: ModuleKind,
    ) -> Result<Version, Error> {
        Ok(env
            .storage()
            .persistent()
            .get::<_, ModuleRecord>(&DataKey::Module(org_key(env, org), kind))
            .and_then(|r| r.interface_version())
            .unwrap_or(CURRENT_VERSION))
    }

    /// Check if the caller has at least the required role for the organization.
    /// Admin always has access regardless of role assignment. The recorded org
    /// owner is treated as an implicit [`Role::OrgOwner`].
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
        // Check if caller has the required role or higher; the recorded org
        // owner implicitly holds OrgOwner even though no record is stored.
        let caller_role: Option<Role> = env
            .storage()
            .persistent()
            .get(&DataKey::Role(org_key(env, org), caller.clone()));
        let granted = match caller_role {
            Some(role) => role,
            None => {
                let owner: Option<Address> = env
                    .storage()
                    .persistent()
                    .get(&DataKey::Org(org_key(env, org)));
                if owner.as_ref() == Some(caller) {
                    Role::OrgOwner
                } else {
                    return Err(Error::Unauthorized);
                }
            }
        };
        // Role hierarchy: Admin > OrgOwner > ModuleManager > VersionManager
        if Self::role_level(&granted) <= Self::role_level(&required_role) {
            Ok(())
        } else {
            Err(Error::Unauthorized)
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
        Self::check_paused(&env)?;
        Self::check_frozen(&env)?;
        let key = DataKey::Module(org_key(&env, &org), kind);
        let record: ModuleRecord = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(Error::NotFound)?;
        // Routing guard: reject new interactions targeting deprecated modules.
        if record.deprecated {
            return Err(Error::ModuleDeprecated);
        }
        // Interface-version routing guard: when the organization declares a
        // minimum compatible interface version for this module kind, calls must
        // not be routed to an implementation that violates it.
        if let Some(min) = env
            .storage()
            .persistent()
            .get::<_, Version>(&DataKey::MinInterfaceVersion(org_key(&env, &org), kind))
        {
            let actual = Self::effective_interface_version(&env, &org, kind)?;
            require_compatible(actual, min)?;
        }
        Self::bump(&env, &key);
        Ok(record.address)
    }

    fn verify_owner(env: Env, org: String, owner: Address) -> Result<bool, Error> {
        Self::check_paused(&env)?;
        Self::check_frozen(&env)?;
        let key = DataKey::Org(org_key(&env, &org));
        let recorded: Address = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(Error::NotFound)?;
        Self::bump(&env, &key);
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

/// Hash an org slug into the fixed-size `BytesN<32>` used across the registry's
/// org-scoped storage keys, keeping key serialization cost constant regardless
/// of slug length.
fn org_key(env: &Env, org: &String) -> BytesN<32> {
    key_of_string(env, org)
}

#[cfg(test)]
mod test;
