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
//!
//! ## Permission delegation
//!
//! Requiring the root owner's key for every registry edit does not survive
//! contact with a real organization: the people who rotate a policy contract
//! are usually not the people who hold ultimate ownership, and handing them the
//! root key to do it defeats the point of having one. The registry therefore
//! records a [`RegistryRole`] per `(organization, account)` and checks it on the
//! org-scoped modifications, so an owner can delegate narrow administrative
//! powers to sub-accounts or secondary operational keys without transferring
//! ownership:
//!
//! | Role               | May register/remove modules of kind                |
//! |--------------------|----------------------------------------------------|
//! | `Owner`            | any kind (a delegated co-owner for module records) |
//! | `ModuleUpgrader`   | any kind (repointing modules at new versions)      |
//! | `PolicyManager`    | `Policy`                                           |
//! | `TreasuryOperator` | `Treasury`, `Budget`, `Escrow`                     |
//!
//! Delegation is deliberately bounded. Root actions — transferring ownership,
//! the emergency freeze, and administering roles themselves — stay with the
//! recorded org owner and the protocol admin, so no grant can be used to
//! escalate into ownership or to widen its own reach.
//!
//! ## Upgrade paths
//!
//! [`RegistryContract::register_version`] publishes immutable `(kind, version)`
//! records, but a published version is only *reachable* once some organization's
//! module is moved onto it. [`RegistryContract::upgrade_module`] is that move,
//! and it never takes an address or a WASM hash from the caller: it resolves
//! both from the version record itself, so the code a module ends up running is
//! always code the protocol admin published *and* approved. The validations it
//! runs before touching the pointer are, in order:
//!
//! | Check                                              | Refusal                |
//!|----------------------------------------------------|------------------------|
//! | the registry is not frozen                          | `RegistryFrozen`       |
//! | `caller` holds a role that reaches this `kind`      | `Unauthorized`         |
//! | the module is already registered                    | `NotFound`             |
//! | `target_version` is non-zero                        | `InvalidInput`         |
//! | `target_version` is newer than the module's pin     | `CircularUpgrade`      |
//! | the target version exists                           | `NotFound`             |
//! | the target is bound to a WASM hash                  | `InvalidInput`         |
//! | that hash is still approved for this `kind`         | `Unauthorized`         |
//! | the target address is a contract                    | `InvalidInput`         |
//! | the target address is not the one already in use    | `CircularUpgrade`      |
//!
//! [`RegistryContract::register_module_version`] applies the same checks when a
//! module is *registered* rather than moved: it resolves the address and the
//! WASM hash from the version record and advances the pin in the same write, so a
//! versioned deployment (`v1` straight from the registry) is validated at
//! creation time, and a repoint driven through registration cannot walk backwards
//! either.
//!
//! The pin is a high-water mark and version records are immutable, so a module's
//! version sequence is strictly increasing: no upgrade can re-enter a version a
//! module has already left, which is the cycle a rolling deployment must never
//! make. The address check closes the remaining degenerate case, a "move" onto
//! the contract the module already runs. Note what this is and is not: the pin
//! orders the upgrade path, it does not vet the pointer itself.
//! [`RegistryContract::register_module`] remains the unvalidated path that lets
//! an owner or delegate route their own organization's module anywhere, behind
//! the same permission gate as always — resetting the pin is not a new
//! capability, it just keeps the validated path's ordering honest about the
//! code the module is actually running.

use astroid_interfaces::{RegistryInterface, UpgradeableInterface};
use astroid_shared::constants::{
    MAX_REGISTRY_BATCH, PERSISTENT_BUMP_AMOUNT, PERSISTENT_LIFETIME_THRESHOLD,
};
use astroid_shared::ensure;
use astroid_shared::errors::Error;
use astroid_shared::events::ContractEvent;
use astroid_shared::types::{ModuleId, ModuleInfo, ModuleKind};
use astroid_shared::validation::require_non_empty;
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, Address, BytesN, Env, String, Vec,
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
    /// Module deprecation flag: (org slug, kind) -> bool. When set, the routing
    /// surface (`lookup`) rejects new interactions with [`Error::ModuleDeprecated`]
    /// while the raw address stays readable for legacy migrations.
    ModuleDeprecated(String, ModuleKind),
    /// Version pin: (org slug, kind) -> the version the module currently runs.
    ///
    /// The high-water mark of that module's upgrade path. Absent for every
    /// module registered before validated upgrades existed — those read as `0`
    /// (unpinned) rather than failing, which is what lets an organization
    /// upgrade a module that predates this key without a migration. Cleared by
    /// [`RegistryContract::register_module`] and
    /// [`RegistryContract::remove_module`] together with the record it belongs
    /// to, because both mean "the previous upgrade path describes code this
    /// module no longer runs".
    ModuleVersion(String, ModuleKind),
    /// Delegated role: (org slug, account) -> RegistryRole.
    OrgRole(String, Address),
    /// Legacy version table: (kind, version) -> contract address. Superseded by
    /// [`DataKey::VersionRecord`]; still written by nothing and read only as a
    /// fallback by [`RegistryContract::read_version`], so entries published
    /// before the consolidation keep resolving.
    Version(ModuleKind, u32),
    /// Consolidated version record: (kind, version) -> address + bound WASM
    /// hash. Replaces the former `Version` + `VersionWasm` pair; `Version` is
    /// retained as the legacy layout (see [`RegistryContract::read_version`]).
    VersionRecord(ModuleKind, u32),
    /// Latest known version number for a kind.
    LatestVersion(ModuleKind),
    /// Emergency freeze status (instance).
    Frozen,
    /// Approved WASM hashes: (kind, hash) -> bool.
    ApprovedWasm(ModuleKind, BytesN<32>),
}

/// A delegated administrative role over one organization's registry records.
///
/// One role per account keeps the ledger footprint to a single small entry per
/// delegation. Roles are capability-scoped rather than ranked: `PolicyManager`
/// is not "less" than `TreasuryOperator`, it simply reaches different module
/// kinds. Discriminants are part of the public ABI and MUST NOT be reordered or
/// reused once released.
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

/// Key for a single version lookup in the global upgrade map.
///
/// Mirrors [`ModuleId`] for the module-address map. Used by
/// [`RegistryContract::get_versions_batch`] so a batch can carry several
/// `(kind, version)` pairs in one invocation while preserving order and
/// duplicates, just as the module batch does. Keeps the lookup surface
/// uniform across both maps.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionId {
    pub kind: ModuleKind,
    pub version: u32,
}

// ---------------------------------------------------------------------------
// Upgrade-map lookup helpers — cached, minimal ledger access.
// ---------------------------------------------------------------------------
/// Per-invocation cache for the global version upgrade map.
///
/// Persistent storage reads dominate gas. When a caller resolves many versions
/// (e.g. a batch verification or upgrade-path walk) the same
/// `(kind, version)` is often requested repeatedly. Re-reading it would pay
/// the ledger cost each time. The cache keeps the first result — including
/// `None` for a missing key — and serves duplicates by a linear scan over an
/// in-memory `Vec` bounded by `MAX_REGISTRY_BATCH`, so only comparisons are
/// paid after the first hit.
///
/// Mirrors `VelocityGate` in the wallet contract and `RuleEvaluationContext`
/// in the policy contract: reuse a ledger record within one invocation
/// rather than re-reading it.
struct VersionLookupCache {
    env: Env,
    entries: Vec<(ModuleKind, u32, Option<VersionRecord>)>,
}

impl VersionLookupCache {
    fn new(env: &Env) -> Self {
        Self {
            env: env.clone(),
            entries: Vec::new(env),
        }
    }

    /// Return the cached record for `(kind, version)`, loading it once on a miss
    /// and extending TTL only when the record exists and only once per distinct
    /// key in this invocation (matching `get_version` policy).
    fn get(&mut self, kind: ModuleKind, version: u32) -> Option<VersionRecord> {
        for i in 0..self.entries.len() {
            let (k, v, rec) = self.entries.get(i).unwrap();
            if k == kind && v == version {
                return rec.clone();
            }
        }
        let rec = RegistryContract::read_version(&self.env, kind, version);
        self.entries.push_back((kind, version, rec.clone()));
        rec
    }
}

#[contract]
pub struct RegistryContract;

/// The WASM hash a version is bound to, or the fact that it is not bound to
/// one.
///
/// Modelled as a sum type rather than an `Option` because `#[contracttype]`
/// cannot encode `Option<BytesN<32>>` — the SDK's `Option` conversion needs an
/// infallible `From<&T> for ScVal`, and `BytesN` only offers a fallible
/// `TryFrom`. The distinction is also worth making explicit on-chain: "bound to
/// this hash" and "published before hashes were bound" are different states,
/// not the presence or absence of a field.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BoundHash {
    /// Bound to this hash, which `get_version_wasm` reports and `verify_version`
    /// requires to match.
    Bound(BytesN<32>),
    /// Published before hashes were bound, so there is no hash to report or
    /// match — exactly the position such a version occupied when the hash lived
    /// in a separate entry that was simply absent.
    Unbound,
}

/// A registered implementation version: the address it resolves to together
/// with the WASM hash that address is bound to.
///
/// `Version` (address) and `VersionWasm` (hash) used to be two persistent
/// entries per version. Folding them into one record halves the entries a
/// populated registry holds for the upgrade map, removes one write from every
/// [`RegistryContract::register_version`], and lets
/// [`RegistryContract::verify_version`] answer from a single read where it
/// previously needed two.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionRecord {
    /// The implementation this version resolves to.
    pub address: Address,
    /// The hash this version is bound to, if any.
    pub hash: BoundHash,
}

/// A validated upgrade: where a module is now and where [`RegistryContract::upgrade_module`]
/// would take it.
///
/// Internal, so it is deliberately not a `#[contracttype]`: it never crosses the
/// contract boundary. The entrypoints return the version number and the address
/// instead, which is all a caller — or the event log — needs.
struct UpgradePlan {
    /// The version the module runs today, or `0` when it was registered by
    /// address and has never been upgraded.
    from_version: u32,
    /// The version being moved onto.
    to_version: u32,
    /// The contract that version resolves to.
    address: Address,
    /// The approved WASM hash that contract is bound to.
    hash: BytesN<32>,
}

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
    /// the protocol admin, the organization owner, or an account holding a
    /// delegated [`RegistryRole`] that reaches this [`ModuleKind`].
    pub fn register_module(
        env: Env,
        caller: Address,
        org: String,
        kind: ModuleKind,
        address: Address,
    ) -> Result<(), Error> {
        Self::check_frozen(&env)?;
        caller.require_auth();
        Self::require_module_permission(&env, &caller, &org, kind)?;
        let key = DataKey::Module(org.clone(), kind);
        env.storage().persistent().set(&key, &address);
        Self::bump(&env, &key);
        // A (re)registration points at a fresh implementation, so any prior
        // deprecation flag must not carry over and block the new address, and
        // the module's version pin starts over: the recorded upgrade path
        // describes code this module is no longer running.
        let dkey = DataKey::ModuleDeprecated(org.clone(), kind);
        if env.storage().persistent().has(&dkey) {
            env.storage().persistent().remove(&dkey);
        }
        Self::clear_module_version(&env, &org, kind);
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
        let mkey = DataKey::Module(org.clone(), kind);
        if !env.storage().persistent().has(&mkey) {
            return Err(Error::NotFound);
        }
        let dkey = DataKey::ModuleDeprecated(org.clone(), kind);
        env.storage().persistent().set(&dkey, &true);
        Self::bump(&env, &dkey);
        env.events().publish(
            (symbol_short!("module"), symbol_short!("deprecate")),
            (org, kind),
        );
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
        let mkey = DataKey::Module(org.clone(), kind);
        if !env.storage().persistent().has(&mkey) {
            return Err(Error::NotFound);
        }
        let dkey = DataKey::ModuleDeprecated(org.clone(), kind);
        env.storage().persistent().set(&dkey, &false);
        Self::bump(&env, &dkey);
        env.events().publish(
            (symbol_short!("module"), symbol_short!("restore")),
            (org, kind),
        );
        Ok(())
    }

    /// Read a module's deprecation status (false when never flagged).
    pub fn is_module_deprecated(env: Env, org: String, kind: ModuleKind) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::ModuleDeprecated(org, kind))
            .unwrap_or(false)
    }

    /// Read a registered module address bypassing the deprecation guard.
    /// Intended for legacy migrations and admin tooling that must still reach a
    /// deprecated implementation.
    pub fn get_module_address(env: Env, org: String, kind: ModuleKind) -> Result<Address, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::Module(org, kind))
            .ok_or(Error::NotFound)
    }

    /// Remove a module registration. Same gate as `register_module`: admin, org
    /// owner, or a delegated role that reaches this [`ModuleKind`].
    pub fn remove_module(
        env: Env,
        caller: Address,
        org: String,
        kind: ModuleKind,
    ) -> Result<(), Error> {
        Self::check_frozen(&env)?;
        caller.require_auth();
        Self::require_module_permission(&env, &caller, &org, kind)?;
        let key = DataKey::Module(org.clone(), kind);
        ensure!(env.storage().persistent().has(&key), Error::NotFound);
        env.storage().persistent().remove(&key);
        // Drop the deprecation flag together with the record so a later
        // re-registration starts clean and lookups report NotFound, not
        // ModuleDeprecated, for a removed module. The version pin goes with it:
        // the removed module's upgrade path is history, and keeping it would
        // make the re-registered module refuse versions it never ran.
        let dkey = DataKey::ModuleDeprecated(org.clone(), kind);
        if env.storage().persistent().has(&dkey) {
            env.storage().persistent().remove(&dkey);
        }
        Self::clear_module_version(&env, &org, kind);
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

    /// Delegate `role` over `org` to `account`, replacing any role it already
    /// held. Only the recorded organization owner or the protocol admin may
    /// grant, so a delegated role can never be used to widen its own reach or
    /// to mint further delegations.
    ///
    /// Granting to the org owner is refused: the owner already reaches every
    /// module kind, so the record would be redundant and could only mislead
    /// anyone reading the delegation list.
    pub fn grant_role(
        env: Env,
        caller: Address,
        org: String,
        account: Address,
        role: RegistryRole,
    ) -> Result<(), Error> {
        Self::check_frozen(&env)?;
        caller.require_auth();
        let owner = Self::require_root_owner(&env, &caller, &org)?;
        if account == owner {
            return Err(Error::InvalidInput);
        }
        let key = DataKey::OrgRole(org.clone(), account.clone());
        env.storage().persistent().set(&key, &role);
        Self::bump(&env, &key);
        env.events().publish(
            (symbol_short!("role"), symbol_short!("granted")),
            (org, account, role),
        );
        Ok(())
    }

    /// Revoke whatever role `account` holds over `org`. Only the recorded
    /// organization owner or the protocol admin may revoke.
    ///
    /// Fails with [`Error::NotFound`] when the account holds no delegated role,
    /// so a revocation is never silently a no-op — an owner who believes they
    /// have withdrawn access has actually withdrawn it.
    pub fn revoke_role(
        env: Env,
        caller: Address,
        org: String,
        account: Address,
    ) -> Result<(), Error> {
        caller.require_auth();
        Self::require_root_owner(&env, &caller, &org)?;
        let key = DataKey::OrgRole(org.clone(), account.clone());
        if !env.storage().persistent().has(&key) {
            return Err(Error::NotFound);
        }
        env.storage().persistent().remove(&key);
        env.events().publish(
            (symbol_short!("role"), symbol_short!("revoked")),
            (org, account),
        );
        Ok(())
    }

    /// Read the role `account` holds over `org`, or `None` if it holds none.
    ///
    /// The org owner is reported as [`RegistryRole::Owner`] even though no
    /// record is stored for them, so callers see the effective permission
    /// rather than a storage detail.
    pub fn get_role(env: Env, org: String, account: Address) -> Option<RegistryRole> {
        Self::effective_role(&env, &org, &account)
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

    /// Record a contract implementation for a `(kind, version)` pair, bound to
    /// the WASM hash it runs, and advance the latest-version pointer if newer.
    /// This is what powers the version-lookup upgrade strategy.
    ///
    /// Checks, in order: the registry is not frozen ([`Error::RegistryFrozen`]);
    /// `caller` is the protocol admin and signed ([`Error::Unauthorized`]);
    /// `version` is non-zero ([`Error::InvalidInput`]); the pair is not already
    /// registered ([`Error::AlreadyExists`]); `wasm_hash` is approved for `kind`
    /// via [`Self::add_approved_wasm`] ([`Error::Unauthorized`], the same code
    /// the upgrade gate reports for unapproved code). Nothing is written unless
    /// every check passes.
    ///
    /// Version records are immutable: a published version can never be
    /// repointed at different code, so a consumer pinned to it keeps getting
    /// what it pinned. Rolling forward means registering a new version.
    pub fn register_version(
        env: Env,
        caller: Address,
        kind: ModuleKind,
        version: u32,
        address: Address,
        wasm_hash: BytesN<32>,
    ) -> Result<(), Error> {
        Self::check_frozen(&env)?;
        Self::require_admin(&env, &caller)?;
        ensure!(version != 0, Error::InvalidInput);
        // A pair is taken if either layout already holds it. The common case is
        // a single existence check; the legacy key is only consulted when the
        // consolidated one is free, so a fresh registration still pays one read.
        ensure!(
            !env.storage()
                .persistent()
                .has(&DataKey::VersionRecord(kind, version))
                && !env
                    .storage()
                    .persistent()
                    .has(&DataKey::Version(kind, version)),
            Error::AlreadyExists
        );
        ensure!(
            Self::is_wasm_approved(env.clone(), kind, wasm_hash.clone()),
            Error::Unauthorized
        );
        // One write for the whole record, where the address and the hash used to
        // be two separate entries and two writes.
        let vkey = DataKey::VersionRecord(kind, version);
        env.storage().persistent().set(
            &vkey,
            &VersionRecord {
                address: address.clone(),
                hash: BoundHash::Bound(wasm_hash.clone()),
            },
        );
        Self::bump(&env, &vkey);

        let lkey = DataKey::LatestVersion(kind);
        let latest: u32 = env.storage().persistent().get(&lkey).unwrap_or(0);
        if version > latest {
            env.storage().persistent().set(&lkey, &version);
            Self::bump(&env, &lkey);
        }
        astroid_shared::events::publish(
            &env,
            ContractEvent::RegistryVersionRegistered {
                kind,
                version,
                address: address.clone(),
                wasm_hash,
            },
        );
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

    /// Look up a specific implementation version.
    pub fn get_version(env: Env, kind: ModuleKind, version: u32) -> Result<Address, Error> {
        Ok(Self::read_version(&env, kind, version)
            .ok_or(Error::NotFound)?
            .address)
    }

    /// Read the WASM hash a registered version is bound to. Fails with
    /// [`Error::NotFound`] for an unknown `(kind, version)`, and for a version
    /// registered before hashes were bound (it has no hash to report).
    pub fn get_version_wasm(env: Env, kind: ModuleKind, version: u32) -> Result<BytesN<32>, Error> {
        match Self::read_version(&env, kind, version).map(|rec| rec.hash) {
            Some(BoundHash::Bound(hash)) => Ok(hash),
            _ => Err(Error::NotFound),
        }
    }

    /// Verify that `(kind, version)` is registered, runs exactly `wasm_hash`,
    /// and that the hash is still approved; on success return the version's
    /// address. Read-only, so a deployer or consumer can check an upgrade
    /// target before acting on it.
    ///
    /// Errors: [`Error::NotFound`] for an unknown version;
    /// [`Error::InvalidInput`] when `wasm_hash` differs from the bound hash (or
    /// the version predates hash binding and so has none to match);
    /// [`Error::Unauthorized`] when the bound hash has since been removed from
    /// the approved list.
    pub fn verify_version(
        env: Env,
        kind: ModuleKind,
        version: u32,
        wasm_hash: BytesN<32>,
    ) -> Result<Address, Error> {
        // One read for the address and its bound hash together; the split
        // layout needed a second read for the hash.
        let record = Self::read_version(&env, kind, version).ok_or(Error::NotFound)?;
        ensure!(
            matches!(record.hash, BoundHash::Bound(ref bound) if bound == &wasm_hash),
            Error::InvalidInput
        );
        ensure!(
            Self::is_wasm_approved(env, kind, wasm_hash),
            Error::Unauthorized
        );
        Ok(record.address)
    }

    /// Move `org`'s `kind` module onto the implementation registered at
    /// `target_version` for that same kind, after checking the whole upgrade
    /// path. Returns the version the module now runs.
    ///
    /// The address and the WASM hash are resolved from the version record, never
    /// taken from the caller, so there is no way to point a module at a contract
    /// the protocol admin did not publish for its kind or at code whose hash is
    /// not approved. See the crate-level "Upgrade paths" section for the full
    /// order of checks; the short version is:
    ///
    /// 1. the registry is not frozen — [`Error::RegistryFrozen`];
    /// 2. `caller` is signed and may manage this `kind` for `org` —
    ///    [`Error::Unauthorized`] (or [`Error::NotFound`] for an unknown org);
    /// 3. the module is already registered — [`Error::NotFound`];
    /// 4. `target_version` is non-zero — [`Error::InvalidInput`];
    /// 5. `target_version` is strictly newer than the module's current pin —
    ///    [`Error::CircularUpgrade`], which is what stops the path from
    ///    revisiting or reversing;
    /// 6. the target version exists for this kind — [`Error::NotFound`];
    /// 7. the target is bound to a WASM hash — [`Error::InvalidInput`] for a
    ///    version published before hashes were bound, so there is nothing to
    ///    verify;
    /// 8. that hash is still approved for this kind — [`Error::Unauthorized`]
    ///    for code that was never approved or has since been revoked;
    /// 9. the target address is a contract — [`Error::InvalidInput`], so the
    ///    module can never be routed to an account;
    /// 10. the target is not the contract the module already runs —
    ///     [`Error::CircularUpgrade`].
    ///
    /// On success the module pointer moves, the deprecation flag is cleared (the
    /// module is running a live implementation again) and the pin advances to
    /// `target_version`. Nothing is written unless every check passes, so a
    /// refusal leaves the module exactly where it was.
    ///
    /// A `0` pin (see [`Self::get_module_version`]) means the module was
    /// registered by address and has never been upgraded, so it accepts any
    /// registered version as its first step.
    pub fn upgrade_module(
        env: Env,
        caller: Address,
        org: String,
        kind: ModuleKind,
        target_version: u32,
    ) -> Result<u32, Error> {
        Self::check_frozen(&env)?;
        require_non_empty(&org)?;
        caller.require_auth();
        Self::require_module_permission(&env, &caller, &org, kind)?;
        let plan = Self::plan_upgrade(&env, &org, kind, target_version)?;

        // Past this line every check has passed; only writes remain.
        let key = DataKey::Module(org.clone(), kind);
        env.storage().persistent().set(&key, &plan.address);
        Self::bump(&env, &key);
        let vkey = DataKey::ModuleVersion(org.clone(), kind);
        env.storage().persistent().set(&vkey, &plan.to_version);
        Self::bump(&env, &vkey);
        // The module runs a registered implementation again, so a deprecation
        // flag left by the implementation it just left must not keep the new
        // address unroutable.
        let dkey = DataKey::ModuleDeprecated(org.clone(), kind);
        if env.storage().persistent().has(&dkey) {
            env.storage().persistent().remove(&dkey);
        }

        astroid_shared::events::publish(
            &env,
            ContractEvent::RegistryModuleUpgraded {
                org: org.clone(),
                kind,
                from_version: plan.from_version,
                to_version: plan.to_version,
                address: plan.address.clone(),
                wasm_hash: plan.hash.clone(),
            },
        );
        env.events().publish(
            (symbol_short!("module"), symbol_short!("upgrade")),
            (org, kind, plan.to_version),
        );
        Ok(plan.to_version)
    }

    /// Register `org`'s `kind` module onto a published implementation version,
    /// resolving the address from the registry instead of taking one from the
    /// caller.
    ///
    /// [`Self::register_module`] accepts whatever address the caller names, so
    /// that path can point a module at code the registry never published or
    /// approved. This entrypoint closes the gap for versioned deployments: both
    /// the address and the WASM hash come from the immutable `(kind, version)`
    /// record, and the module's version pin advances to `version`.
    ///
    /// The validations are exactly [`Self::upgrade_module`]'s (see the
    /// crate-level "Upgrade paths" section), which is what makes the upgrade
    /// path monotonic even when it is driven through registration:
    ///
    /// - `version` is non-zero and strictly newer than the module's existing pin
    ///   — [`Error::CircularUpgrade`] for a version the module has already left,
    ///   or for the one it already runs;
    /// - the target version exists for this `kind` — [`Error::NotFound`];
    /// - the target is bound to a WASM hash — [`Error::InvalidInput`];
    /// - that hash is still approved for this `kind` — [`Error::Unauthorized`];
    /// - the resolved address is a contract — [`Error::InvalidInput`].
    ///
    /// Registering a module that was never registered is legal and starts its
    /// path; registering over an existing one is a validated repoint, and any
    /// deprecation flag is cleared because the module runs a live implementation
    /// again. On success the pointer, the pin and the events match what
    /// [`Self::upgrade_module`] would have produced for the same target, so an
    /// indexer sees one upgrade path whichever entrypoint drove it. Returns the
    /// version the module now runs.
    pub fn register_module_version(
        env: Env,
        caller: Address,
        org: String,
        kind: ModuleKind,
        version: u32,
    ) -> Result<u32, Error> {
        Self::check_frozen(&env)?;
        require_non_empty(&org)?;
        caller.require_auth();
        Self::require_module_permission(&env, &caller, &org, kind)?;
        // Registration may create the record or replace one; either way the
        // version path is validated against the current pointer when there is
        // one, so a repoint can never walk backwards.
        let current: Option<Address> = env
            .storage()
            .persistent()
            .get(&DataKey::Module(org.clone(), kind));
        let existed = current.is_some();
        let plan = Self::resolve_upgrade_target(&env, &org, kind, version, current)?;

        let key = DataKey::Module(org.clone(), kind);
        env.storage().persistent().set(&key, &plan.address);
        Self::bump(&env, &key);
        let vkey = DataKey::ModuleVersion(org.clone(), kind);
        env.storage().persistent().set(&vkey, &plan.to_version);
        Self::bump(&env, &vkey);
        let dkey = DataKey::ModuleDeprecated(org.clone(), kind);
        if env.storage().persistent().has(&dkey) {
            env.storage().persistent().remove(&dkey);
        }

        astroid_shared::events::publish(
            &env,
            ContractEvent::RegistryModuleUpdated {
                org: org.clone(),
                kind,
                address: plan.address.clone(),
            },
        );
        env.events().publish(
            (
                symbol_short!("module"),
                symbol_short!("register"),
                org.clone(),
                kind,
            ),
            plan.address.clone(),
        );
        // A repoint moves an existing module, so it is reported as an upgrade
        // too: consumers that only track `RegistryModuleUpgraded` see the same
        // history as they would have through `upgrade_module`.
        if existed {
            astroid_shared::events::publish(
                &env,
                ContractEvent::RegistryModuleUpgraded {
                    org: org.clone(),
                    kind,
                    from_version: plan.from_version,
                    to_version: plan.to_version,
                    address: plan.address.clone(),
                    wasm_hash: plan.hash.clone(),
                },
            );
            env.events().publish(
                (symbol_short!("module"), symbol_short!("upgrade")),
                (org, kind, plan.to_version),
            );
        }
        Ok(plan.to_version)
    }

    /// Run every check [`Self::upgrade_module`] would run and return the address
    /// the module would be moved to, writing nothing.
    ///
    /// A keeper, a deployment script or a test can confirm that a target is
    /// reachable — version published, hash approved, path not circular — before
    /// asking for the migration. The checks, and the order they fire in, are
    /// identical to the write path's, so a successful validation predicts a
    /// successful upgrade (and a refusal carries the same code the upgrade
    /// would have reported).
    ///
    /// Read-only: it moves no pointer and writes no pin, and it needs no auth.
    /// The one ledger write it may cause is the version record's TTL extension,
    /// which any read of that record already pays for. It does consult the
    /// freeze flag, like [`Self::lookup`], so a pre-flight run does not approve
    /// an upgrade the registry would refuse to record.
    pub fn validate_upgrade(
        env: Env,
        org: String,
        kind: ModuleKind,
        target_version: u32,
    ) -> Result<Address, Error> {
        Self::check_frozen(&env)?;
        require_non_empty(&org)?;
        Ok(Self::plan_upgrade(&env, &org, kind, target_version)?.address)
    }

    /// The version `org`'s `kind` module is currently pinned to.
    ///
    /// `0` means the module is registered by address and has never been moved by
    /// [`Self::upgrade_module`] — which is the state of every module registered
    /// before that entrypoint existed, so those need no migration to take part in
    /// validated upgrades. [`Error::NotFound`] is reserved for "no such module",
    /// keeping the two apart: `Ok(0)` is a module with an upgrade path ahead of
    /// it, `NotFound` is not a module at all.
    pub fn get_module_version(env: Env, org: String, kind: ModuleKind) -> Result<u32, Error> {
        let key = DataKey::Module(org.clone(), kind);
        ensure!(env.storage().persistent().has(&key), Error::NotFound);
        Ok(env
            .storage()
            .persistent()
            .get(&DataKey::ModuleVersion(org, kind))
            .unwrap_or(0))
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

    /// Batch counterpart of [`Self::get_version`]: resolve up to
    /// [`MAX_REGISTRY_BATCH`] version addresses in one invocation.
    ///
    /// - `result[i]` answers `ids[i]`; length and order are preserved and
    ///   duplicate ids are answered at every position.
    /// - An unregistered id yields `None` instead of failing the batch, so one
    ///   missing version does not hide the others.
    /// - A mix of registered and missing ids is handled per entry.
    /// - An empty `ids` returns an empty list.
    ///
    /// Errors: [`Error::InvalidInput`] when more than [`MAX_REGISTRY_BATCH`] ids
    /// are requested (checked before any storage is read). Read-only: no auth
    /// is required and the frozen flag is not consulted, matching
    /// [`Self::get_version`].
    ///
    /// Gas optimization: a per-invocation [`VersionLookupCache`] keeps the first
    /// ledger read for each distinct `(kind, version)` — including `None` for a
    /// missing key — and serves duplicates from an in-memory `Vec` bounded by
    /// [`MAX_REGISTRY_BATCH`]. A batch with duplicates therefore pays one
    /// persistent read and one TTL bump per distinct key, not per entry, while
    /// preserving order and duplicates exactly like [`Self::get_modules_batch`].
    pub fn get_versions_batch(
        env: Env,
        ids: Vec<VersionId>,
    ) -> Result<Vec<Option<Address>>, Error> {
        ensure!(ids.len() <= MAX_REGISTRY_BATCH, Error::InvalidInput);
        let mut cache = VersionLookupCache::new(&env);
        let mut results = Vec::new(&env);
        for vid in ids.iter() {
            results.push_back(cache.get(vid.kind, vid.version).map(|rec| rec.address));
        }
        Ok(results)
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
        env.events()
            .publish((symbol_short!("registry"), symbol_short!("unfrozen")), org);
        Ok(())
    }

    /// Record an approved WASM hash for a specific module kind.
    pub fn add_approved_wasm(
        env: Env,
        caller: Address,
        kind: ModuleKind,
        wasm_hash: BytesN<32>,
    ) -> Result<(), Error> {
        Self::require_admin(&env, &caller)?;
        let key = DataKey::ApprovedWasm(kind, wasm_hash.clone());
        env.storage().persistent().set(&key, &true);
        Self::bump(&env, &key);
        env.events().publish(
            (symbol_short!("wasm"), symbol_short!("approved")),
            (kind, wasm_hash),
        );
        Ok(())
    }

    /// Remove/deprecate a previously approved WASM hash.
    pub fn remove_approved_wasm(
        env: Env,
        caller: Address,
        kind: ModuleKind,
        wasm_hash: BytesN<32>,
    ) -> Result<(), Error> {
        Self::require_admin(&env, &caller)?;
        let key = DataKey::ApprovedWasm(kind, wasm_hash.clone());
        if !env.storage().persistent().has(&key) {
            return Err(Error::NotFound);
        }
        env.storage().persistent().remove(&key);
        env.events().publish(
            (symbol_short!("wasm"), symbol_short!("removed")),
            (kind, wasm_hash),
        );
        Ok(())
    }

    /// Read-only check to see if a WASM hash is approved for a given kind.
    pub fn is_wasm_approved(env: Env, kind: ModuleKind, wasm_hash: BytesN<32>) -> bool {
        let key = DataKey::ApprovedWasm(kind, wasm_hash);
        env.storage().persistent().get(&key).unwrap_or(false)
    }

    // --- internal helpers ---

    /// Validate the upgrade of `org`'s `kind` module to `target_version` and
    /// return everything the caller needs to carry it out. Moves nothing, so
    /// [`Self::validate_upgrade`] and [`Self::upgrade_module`] reach identical
    /// conclusions and report identical codes.
    ///
    /// The target is resolved from the immutable version record rather than from
    /// the caller's arguments, which is what makes an unverified hash
    /// unrepresentable here: there is no way to name code the registry has not
    /// published and approved for this `kind`.
    fn plan_upgrade(
        env: &Env,
        org: &String,
        kind: ModuleKind,
        target_version: u32,
    ) -> Result<UpgradePlan, Error> {
        // An upgrade moves an existing registration, so there must be one. The
        // address is read for the "already running this contract" check below,
        // which makes the extra read pay for itself.
        let current: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Module(org.clone(), kind))
            .ok_or(Error::NotFound)?;
        Self::resolve_upgrade_target(env, org, kind, target_version, Some(current))
    }

    /// The version-path checks shared by [`Self::upgrade_module`] and
    /// [`Self::register_module_version`].
    ///
    /// `current` is the address the module runs today, or `None` when the record
    /// does not exist yet (a versioned registration). Everything else — the
    /// non-zero target, the monotonic ordering against the pin, the published
    /// version record, its bound-and-approved hash and the contract-address
    /// check — is identical on both paths, so the two entrypoints can never
    /// disagree about whether a target is reachable.
    fn resolve_upgrade_target(
        env: &Env,
        org: &String,
        kind: ModuleKind,
        target_version: u32,
        current: Option<Address>,
    ) -> Result<UpgradePlan, Error> {
        // Version `0` is never a valid record (`register_version` refuses it), so
        // it can only be an uninitialized read.
        ensure!(target_version != 0, Error::InvalidInput);

        // Version ordering. The pin is a high-water mark, so this is the check
        // that makes an upgrade path acyclic: a module can never re-enter a
        // version it has already left, and never move backwards onto one. An
        // unpinned module (0) is at the start of its path, so any version is
        // forward of it.
        let from_version: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::ModuleVersion(org.clone(), kind))
            .unwrap_or(0);
        ensure!(target_version > from_version, Error::CircularUpgrade);

        // Existence, then integrity: the target must be a published version of
        // *this* kind, bound to code that is still approved for it.
        let record = Self::read_version(env, kind, target_version).ok_or(Error::NotFound)?;
        let hash = match record.hash {
            BoundHash::Bound(hash) => hash,
            // A version published before hashes were bound has nothing to
            // verify, so it cannot be moved onto: the point of this path is that
            // the code behind a module is known.
            BoundHash::Unbound => return Err(Error::InvalidInput),
        };
        ensure!(
            Self::is_wasm_approved(env.clone(), kind, hash.clone()),
            Error::Unauthorized
        );
        // A module must be routable, and only a contract can be called. Without
        // this, a version record naming an account would leave the module
        // permanently unroutable.
        ensure!(
            Self::is_contract_address(&record.address),
            Error::InvalidInput
        );
        // A "move" onto the contract the module already runs is the degenerate
        // cycle: it changes no code and no routing, so it is refused rather than
        // silently recorded as progress. A versioned registration of a module
        // that does not exist yet has nothing to compare against.
        if let Some(current) = current {
            ensure!(record.address != current, Error::CircularUpgrade);
        }

        Ok(UpgradePlan {
            from_version,
            to_version: target_version,
            address: record.address,
            hash,
        })
    }

    /// Whether `address` is a contract principal rather than an account.
    ///
    /// SDK 21 exposes no `is_contract`, so this reads the type byte off the
    /// address's canonical strkey encoding: `C` marks a contract ID, `G` an
    /// ed25519 account. Strkeys are always 56 characters, so anything else is
    /// treated as not-a-contract. Same check as the treasury's
    /// `is_contract_address`, kept local so the registry does not depend on a
    /// member contract.
    fn is_contract_address(address: &Address) -> bool {
        let strkey = address.to_string();
        let mut buf = [0u8; 56];
        if strkey.len() as usize != buf.len() {
            return false;
        }
        strkey.copy_into_slice(&mut buf);
        buf[0] == b'C'
    }

    /// Forget a module's version pin. Called from the two paths that replace or
    /// remove the registration itself, so a pin can never outlive the record it
    /// describes. Absent keys are left alone rather than written as `0`, keeping
    /// the entry table no larger than it needs to be.
    fn clear_module_version(env: &Env, org: &String, kind: ModuleKind) {
        let key = DataKey::ModuleVersion(org.clone(), kind);
        if env.storage().persistent().has(&key) {
            env.storage().persistent().remove(&key);
        }
    }

    /// Resolve `(kind, version)` to its record, or `None` when unregistered.
    ///
    /// A single read on the current layout. Versions published before the record
    /// was consolidated stored only their address under [`DataKey::Version`], so
    /// that key is consulted second and such a version still resolves — with no
    /// bound hash, which is precisely how it behaved when the hash lived in a
    /// separate entry that was simply absent. An already-registered version
    /// therefore keeps answering every query across the layout change.
    ///
    /// The fallback is the only extra read in this function, and it costs a miss
    /// (an absent key deserializes nothing). Entries written after the
    /// consolidation never reach it.
    fn read_version(env: &Env, kind: ModuleKind, version: u32) -> Option<VersionRecord> {
        let key = DataKey::VersionRecord(kind, version);
        if let Some(record) = env.storage().persistent().get::<_, VersionRecord>(&key) {
            Self::bump(env, &key);
            return Some(record);
        }
        let legacy = DataKey::Version(kind, version);
        let address: Option<Address> = env.storage().persistent().get(&legacy);
        if address.is_some() {
            Self::bump(env, &legacy);
        }
        address.map(|address| VersionRecord {
            address,
            hash: BoundHash::Unbound,
        })
    }

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

    /// Require the caller to be the *recorded* organization owner (or the
    /// protocol admin) and return that owner. Used for the root actions that
    /// are deliberately not delegable, so a delegated role can never administer
    /// roles or otherwise escalate.
    fn require_root_owner(env: &Env, caller: &Address, org: &String) -> Result<Address, Error> {
        let owner: Address = env
            .storage()
            .persistent()
            .get(&DataKey::Org(org.clone()))
            .ok_or(Error::NotFound)?;
        if &owner != caller && !Self::is_admin(env, caller) {
            return Err(Error::Unauthorized);
        }
        Ok(owner)
    }

    /// Resolve the role `account` effectively holds over `org`, treating the
    /// recorded owner as an implicit [`RegistryRole::Owner`]. Returns `None`
    /// for an unknown organization, which the callers report as
    /// [`Error::Unauthorized`] — a stranger asking about a non-existent org
    /// learns nothing either way.
    fn effective_role(env: &Env, org: &String, account: &Address) -> Option<RegistryRole> {
        let owner: Option<Address> = env.storage().persistent().get(&DataKey::Org(org.clone()));
        if owner.as_ref() == Some(account) {
            return Some(RegistryRole::Owner);
        }
        env.storage()
            .persistent()
            .get(&DataKey::OrgRole(org.clone(), account.clone()))
    }

    /// Permission guard for the org-scoped module registrations: the protocol
    /// admin, the org owner, or a delegated role that reaches `kind`.
    fn require_module_permission(
        env: &Env,
        caller: &Address,
        org: &String,
        kind: ModuleKind,
    ) -> Result<(), Error> {
        if Self::is_admin(env, caller) {
            return Ok(());
        }
        // An unknown organization has no owner and no roles, so it reports
        // NotFound rather than a permission failure.
        if !env.storage().persistent().has(&DataKey::Org(org.clone())) {
            return Err(Error::NotFound);
        }
        match Self::effective_role(env, org, caller) {
            Some(role) if role.may_manage(kind) => Ok(()),
            _ => Err(Error::Unauthorized),
        }
    }

    /// Read one module record together with its deprecation flag, or `None`
    /// when `(org, kind)` is not registered. Shared by [`Self::lookup`] and
    /// [`Self::get_modules_batch`] so both read a record identically: the TTL is
    /// extended only for a live (non-deprecated) record, as routing has always
    /// done.
    fn read_module(env: &Env, org: String, kind: ModuleKind) -> Option<ModuleInfo> {
        let key = DataKey::Module(org.clone(), kind);
        let address: Address = env.storage().persistent().get(&key)?;
        let deprecated = env
            .storage()
            .persistent()
            .get::<_, bool>(&DataKey::ModuleDeprecated(org, kind))
            .unwrap_or(false);
        if !deprecated {
            Self::bump(env, &key);
        }
        Some(ModuleInfo {
            address,
            deprecated,
        })
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
        let module = Self::read_module(&env, org, kind).ok_or(Error::NotFound)?;
        // Routing guard: reject new interactions targeting deprecated modules.
        if module.deprecated {
            return Err(Error::ModuleDeprecated);
        }
        Ok(module.address)
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

    /// Batch counterpart of [`Self::lookup`]: resolve up to
    /// [`MAX_REGISTRY_BATCH`] module registrations in a single invocation.
    ///
    /// - `result[i]` answers `ids[i]`; length and order are preserved and
    ///   duplicate ids are answered at every position.
    /// - An unregistered id yields `None` instead of failing the batch, so one
    ///   missing module does not hide the others.
    /// - A deprecated module is returned with `deprecated: true` rather than
    ///   [`Error::ModuleDeprecated`]; callers routing to it should refuse it.
    /// - An empty `ids` returns an empty list.
    ///
    /// Errors: [`Error::InvalidInput`] when more than [`MAX_REGISTRY_BATCH`] ids
    /// are requested (checked before any storage is read), and
    /// [`Error::RegistryFrozen`] while the registry is frozen, like every
    /// other lookup on this interface. Read-only: no auth is required.
    fn get_modules_batch(env: Env, ids: Vec<ModuleId>) -> Result<Vec<Option<ModuleInfo>>, Error> {
        ensure!(ids.len() <= MAX_REGISTRY_BATCH, Error::InvalidInput);
        Self::check_frozen(&env)?;
        let mut modules = Vec::new(&env);
        for id in ids.iter() {
            modules.push_back(Self::read_module(&env, id.org, id.kind));
        }
        Ok(modules)
    }
}

// ---------------------------------------------------------------------------
// Registry-gated upgrades, exposed through the shared `UpgradeableInterface`.
// ---------------------------------------------------------------------------
#[contractimpl]
impl UpgradeableInterface for RegistryContract {
    /// Record (or rotate) who may upgrade this contract and which registry
    /// authorizes the new code. The first call must come from the registry's
    /// protocol admin, so nobody can claim upgrade rights over the source of
    /// truth between deployment and bootstrap; afterwards only the current
    /// upgrade admin may rotate it.
    fn set_upgrade_authority(
        env: Env,
        caller: Address,
        admin: Address,
        registry: Address,
    ) -> Result<(), Error> {
        if astroid_interfaces::upgrade::get_authority(&env).is_err() {
            // `set_authority` performs the `require_auth`; checking identity
            // here without a second auth keeps a single signature per call.
            ensure!(Self::is_admin(&env, &caller), Error::Unauthorized);
        }
        astroid_interfaces::upgrade::set_authority(&env, &caller, &admin, &registry)
    }

    /// Read the recorded upgrade authority.
    fn get_upgrade_authority(
        env: Env,
    ) -> Result<astroid_interfaces::upgrade::UpgradeAuthority, Error> {
        astroid_interfaces::upgrade::get_authority(&env)
    }

    /// Replace this contract's code with `wasm_hash`.
    ///
    /// Two gates must pass: `caller` must be the recorded upgrade admin, and
    /// `wasm_hash` must be approved for `ModuleKind::Organization` in the registry.
    /// Any other outcome leaves the contract running its current code.
    fn upgrade(env: Env, caller: Address, wasm_hash: soroban_sdk::BytesN<32>) -> Result<(), Error> {
        astroid_interfaces::upgrade::perform(
            &env,
            &caller,
            astroid_shared::types::ModuleKind::Organization,
            wasm_hash,
        )
    }
}

#[cfg(test)]
mod test;
