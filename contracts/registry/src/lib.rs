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

use astroid_interfaces::{RegistryInterface, UpgradeableInterface};
use astroid_shared::constants::{
    MAX_REGISTRY_BATCH, MAX_UPGRADE_AUDIT_ENTRIES, PERSISTENT_BUMP_AMOUNT,
    PERSISTENT_LIFETIME_THRESHOLD, UPGRADE_PROPOSAL_EXPIRY,
};
use astroid_shared::ensure;
use astroid_shared::errors::Error;
use astroid_shared::events::{self, ContractEvent, UpgradeAudit};
use astroid_shared::types::{ModuleId, ModuleInfo, ModuleKind};
use astroid_shared::validation::{require_non_empty, require_valid_wasm_hash};
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, vec, Address, BytesN, Env, String, Vec,
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
    /// Delegated role: (org slug, account) -> RegistryRole.
    OrgRole(String, Address),
    /// Version table: (kind, version) -> contract address (global upgrade map).
    Version(ModuleKind, u32),
    /// Latest known version number for a kind.
    LatestVersion(ModuleKind),
    /// Emergency freeze status (instance).
    Frozen,
    /// Approved WASM hashes: (kind, hash) -> bool.
    ApprovedWasm(ModuleKind, BytesN<32>),
    /// Pending version-upgrade proposal: kind -> UpgradeProposal.
    UpgradeProposal(ModuleKind),
    /// Immutable historical log of upgrade-lifecycle actions (instance).
    UpgradeAuditLog,
}

/// A pending version-upgrade proposal for one [`ModuleKind`]: the `(version,
/// wasm_hash, address)` triple an authorized caller wants committed into the
/// version table, plus who proposed it and when it expires.
///
/// The record is keyed by kind alone — one proposal per kind at a time — so a
/// kind's upgrade path is always unambiguous and a hostile proposal cannot hide
/// behind a second, conflicting one.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpgradeProposal {
    /// The version number this proposal would occupy in the version table.
    pub version: u32,
    /// The Wasm hash of the proposed implementation.
    pub wasm_hash: BytesN<32>,
    /// The contract address the implementation is expected to be deployed at.
    pub address: Address,
    /// The organization the proposal was made under. Recorded so the org's
    /// owner can reject (or withdraw via the proposer) a proposal they no
    /// longer want without relying on the protocol admin.
    pub org: String,
    /// Who proposed the upgrade (an org owner or the protocol admin).
    pub proposer: Address,
    /// Unix timestamp after which the proposal can no longer be committed.
    pub expires_at: u64,
}

/// What kind of upgrade-lifecycle action an [`UpgradeAuditRecord`] captures.
/// Discriminants are part of the public ABI and MUST NOT be reordered or
/// reused once released.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpgradeAction {
    /// A `(version, wasm_hash, address)` triple was proposed for a kind.
    Proposed = 0,
    /// A pending proposal was committed into the version table.
    Committed = 1,
    /// A pending proposal was rejected or withdrawn by its proposer.
    Rejected = 2,
}
// NOTE: refused upgrade attempts (unauthorized actor, downgrade, identical-WASM
// re-proposal, …) are deliberately *not* logged. A Soroban invocation is
// atomic: every storage write and event of a call that returns an error is
// rolled back, so an audit entry written on the failure path could never be
// observed on-chain. Refusals stay visible off-chain as reverted transactions
// carrying their error code; the on-chain trail records successful lifecycle
// actions only.

/// One immutable entry in the registry's historical upgrade log (Issue #300):
/// who did what to which version of a module kind, and when. Records are
/// appended on every successful propose/commit/reject and never edited or
/// removed; refused attempts revert atomically (see [`UpgradeAction`]) so the
/// log only ever contains actions that took effect. The log itself is a ring
/// buffer capped at [`MAX_UPGRADE_AUDIT_ENTRIES`] entries of instance storage.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpgradeAuditRecord {
    /// Which lifecycle action was taken.
    pub action: UpgradeAction,
    /// The typed audit payload shared with the emitted event.
    pub audit: UpgradeAudit,
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
        // deprecation flag must not carry over and block the new address.
        let dkey = DataKey::ModuleDeprecated(org.clone(), kind);
        if env.storage().persistent().has(&dkey) {
            env.storage().persistent().remove(&dkey);
        }
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
        // ModuleDeprecated, for a removed module.
        let dkey = DataKey::ModuleDeprecated(org.clone(), kind);
        if env.storage().persistent().has(&dkey) {
            env.storage().persistent().remove(&dkey);
        }
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
        ensure!(version != 0, Error::InvalidInput);
        // Downgrade protection: the version table is monotonic per kind, so a
        // registration may never lower or repeat the latest version. Direct
        // registration is the admin escape hatch and carries the same guard as
        // the propose/commit flow.
        let latest: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::LatestVersion(kind))
            .unwrap_or(0);
        ensure!(version > latest, Error::InvalidState);
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

    // --- Version upgrade validation (Issue #304) ---

    /// Propose a version upgrade for a module kind: record a pending
    /// `(version, wasm_hash, address)` triple that a protocol admin can later
    /// commit ([`Self::commit_upgrade`]) or reject
    /// ([`Self::reject_upgrade`]).
    ///
    /// Validation performed:
    /// - `caller` must be the protocol admin, the recorded owner of `org`, or
    ///   an account holding a delegated [`RegistryRole::ModuleUpgrader`] over
    ///   `org` — proposals are exactly the act of rolling a module forward, so
    ///   the module-management gate is the right one.
    /// - the registry must not be frozen and `org` must be registered.
    /// - `version` must be non-zero and strictly greater than the latest
    ///   registered version for the kind, so a proposal can never be a
    ///   downgrade (downgrade-attack prevention).
    /// - `wasm_hash` must pass [`require_valid_wasm_hash`] and must not already
    ///   be approved for the kind (a re-proposal of deployed bytecode is
    ///   meaningless and usually a mistake — Issue #300's identical-WASM edge
    ///   case).
    /// - the kind must have no pending proposal ([`Error::InvalidState`]),
    ///   so the upgrade path stays unambiguous.
    ///
    /// On success the proposal is stored, `UpgradeProposed` is emitted (both
    /// the canonical and the tuple-topic form) and the action is appended to
    /// the immutable upgrade audit log ([`Self::get_upgrade_history`]). A
    /// refused proposal reverts atomically — Soroban rolls back every storage
    /// write and event of a failed invocation — so only successful lifecycle
    /// actions are ever recorded; the refusal itself remains visible off-chain
    /// as a reverted transaction.
    pub fn propose_upgrade(
        env: Env,
        caller: Address,
        org: String,
        kind: ModuleKind,
        version: u32,
        wasm_hash: BytesN<32>,
        address: Address,
    ) -> Result<(), Error> {
        Self::check_frozen(&env)?;
        require_non_empty(&org)?;
        caller.require_auth();
        // Authorization: org owners and delegated module upgraders may propose;
        // everyone else — including holders of unrelated delegated roles — is
        // rejected with the canonical Unauthorized. An unknown org is reported
        // as NotFound so callers can tell a typo from a permission failure.
        if !Self::is_admin(&env, &caller) {
            match Self::effective_role(&env, &org, &caller) {
                Some(RegistryRole::ModuleUpgrader) | Some(RegistryRole::Owner) => {}
                _ => {
                    if !env.storage().persistent().has(&DataKey::Org(org.clone())) {
                        return Err(Error::NotFound);
                    }
                    return Err(Error::Unauthorized);
                }
            }
        }
        // Input validation, including the identical-WASM edge case from
        // Issue #300: re-proposing bytecode that is already approved for the
        // kind fails rather than laundering a no-op through the flow.
        ensure!(version != 0, Error::InvalidInput);
        require_valid_wasm_hash(&env, &wasm_hash)?;

        // Downgrade protection: strictly newer versions only.
        let latest: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::LatestVersion(kind))
            .unwrap_or(0);
        ensure!(version > latest, Error::InvalidState);

        // One open proposal per kind keeps the upgrade path unambiguous.
        let pkey = DataKey::UpgradeProposal(kind);
        ensure!(!env.storage().persistent().has(&pkey), Error::InvalidState);

        // The hash must not already be approved for the kind: proposals exist
        // to introduce new bytecode, not to re-commit something deployed.
        ensure!(
            !env.storage()
                .persistent()
                .get::<_, bool>(&DataKey::ApprovedWasm(kind, wasm_hash.clone()))
                .unwrap_or(false),
            Error::InvalidInput
        );

        let proposal = UpgradeProposal {
            version,
            wasm_hash: wasm_hash.clone(),
            address: address.clone(),
            org: org.clone(),
            proposer: caller.clone(),
            expires_at: env.ledger().timestamp() + UPGRADE_PROPOSAL_EXPIRY,
        };
        env.storage().persistent().set(&pkey, &proposal);
        Self::bump(&env, &pkey);

        let audit_log = UpgradeAudit {
            kind,
            version,
            wasm_hash: wasm_hash.clone(),
            org: org.clone(),
            actor: caller,
            recorded_at: env.ledger().timestamp(),
        };
        Self::append_audit(&env, UpgradeAction::Proposed, &audit_log);
        events::upgrade_proposed(&env, kind, version, &wasm_hash);
        events::publish(&env, ContractEvent::UpgradeProposed { audit: audit_log });
        Ok(())
    }

    /// Commit a pending upgrade proposal: record the proposed address in the
    /// version table, approve the proposed Wasm hash for the kind, clear the
    /// pending record and emit `UpgradeCommitted`.
    ///
    /// Committing is the higher-bar side of the flow and is admin-gated. All of
    /// the proposal's validation is re-checked at commit time so nothing that
    /// became invalid while the proposal was pending can slip through:
    /// - the proposal must exist for the kind ([`Error::NotFound`]) and must
    ///   not have expired (a matured proposal stays refuseable forever);
    /// - `version` must still be strictly greater than the latest registered
    ///   version (nothing was committed in the meantime);
    /// - `wasm_hash` must still be well-formed.
    ///
    /// A successful commit appends `Committed` to the audit log and emits
    /// `UpgradeCommitted` (canonical and tuple-topic form); any refusal reverts
    /// atomically, so refused commits never touch the trail.
    pub fn commit_upgrade(
        env: Env,
        caller: Address,
        kind: ModuleKind,
    ) -> Result<(u32, Address), Error> {
        Self::check_frozen(&env)?;
        Self::require_admin(&env, &caller)?;

        let pkey = DataKey::UpgradeProposal(kind);
        let proposal: UpgradeProposal = env
            .storage()
            .persistent()
            .get(&pkey)
            .ok_or(Error::NotFound)?;

        // Expiry: a matured proposal is dropped once and for all — committing
        // it is refused forever after (the check re-runs on every attempt).
        if env.ledger().timestamp() > proposal.expires_at {
            return Err(Error::NotFound);
        }

        // Re-validate everything the proposal asserted at propose time; the
        // world may have moved underneath it while it was pending.
        require_valid_wasm_hash(&env, &proposal.wasm_hash)?;
        let latest: u32 = env
            .storage()
            .persistent()
            .get(&DataKey::LatestVersion(kind))
            .unwrap_or(0);
        ensure!(proposal.version > latest, Error::InvalidState);

        // Commit: version table + wasm approval, then clear the pending record.
        let vkey = DataKey::Version(kind, proposal.version);
        env.storage().persistent().set(&vkey, &proposal.address);
        Self::bump(&env, &vkey);
        let lkey = DataKey::LatestVersion(kind);
        env.storage().persistent().set(&lkey, &proposal.version);
        Self::bump(&env, &lkey);
        let akey = DataKey::ApprovedWasm(kind, proposal.wasm_hash.clone());
        env.storage().persistent().set(&akey, &true);
        Self::bump(&env, &akey);
        env.storage().persistent().remove(&pkey);

        let version = proposal.version;
        let address = proposal.address.clone();
        let wasm_hash = proposal.wasm_hash.clone();

        let audit_log = UpgradeAudit {
            kind,
            version,
            wasm_hash: wasm_hash.clone(),
            org: proposal.org,
            actor: caller,
            recorded_at: env.ledger().timestamp(),
        };
        Self::append_audit(&env, UpgradeAction::Committed, &audit_log);
        events::upgrade_committed(&env, kind, version, &wasm_hash, &address);
        events::publish(
            &env,
            ContractEvent::UpgradeCommitted {
                audit: audit_log,
                address: address.clone(),
            },
        );
        // Same payload as the canonical event, keeping the legacy
        // ("version", "register") topic consumers working.
        env.events().publish(
            (
                symbol_short!("version"),
                symbol_short!("register"),
                kind,
                version,
            ),
            address.clone(),
        );
        Ok((version, address))
    }

    /// Reject (or withdraw) a pending upgrade proposal: clear the pending
    /// record and emit `UpgradeRejected`.
    ///
    /// The proposer may withdraw their own proposal; the protocol admin may
    /// reject any proposal. An org owner may also reject a proposal targeting
    /// their organization's module kind, so an owner can always stop an
    /// upgrade they no longer want even if they did not propose it. Deleting a
    /// non-existent proposal fails with [`Error::NotFound`], so a rejection is
    /// never silently a no-op.
    ///
    /// A successful rejection appends `Rejected` to the audit log and emits
    /// `UpgradeRejected` (canonical and tuple-topic form); any refusal reverts
    /// atomically, so refused rejections never touch the trail.
    pub fn reject_upgrade(env: Env, caller: Address, kind: ModuleKind) -> Result<(), Error> {
        Self::check_frozen(&env)?;
        caller.require_auth();

        let pkey = DataKey::UpgradeProposal(kind);
        let proposal: UpgradeProposal = env
            .storage()
            .persistent()
            .get(&pkey)
            .ok_or(Error::NotFound)?;

        let authorized = Self::is_admin(&env, &caller)
            || proposal.proposer == caller
            || env
                .storage()
                .persistent()
                .get::<_, Address>(&DataKey::Org(proposal.org.clone()))
                .map(|owner| owner == caller)
                .unwrap_or(false);
        ensure!(authorized, Error::Unauthorized);

        env.storage().persistent().remove(&pkey);
        let audit_log = UpgradeAudit {
            kind,
            version: proposal.version,
            wasm_hash: proposal.wasm_hash.clone(),
            org: proposal.org,
            actor: caller,
            recorded_at: env.ledger().timestamp(),
        };
        Self::append_audit(&env, UpgradeAction::Rejected, &audit_log);
        events::upgrade_rejected(&env, kind, proposal.version, &proposal.wasm_hash);
        events::publish(&env, ContractEvent::UpgradeRejected { audit: audit_log });
        Ok(())
    }

    /// The immutable historical upgrade log (Issue #300): every successful
    /// propose, commit and reject, most recent entry first. Records are never
    /// edited or removed; the log is a ring buffer capped at
    /// [`MAX_UPGRADE_AUDIT_ENTRIES`] entries.
    pub fn get_upgrade_history(env: Env) -> Vec<UpgradeAuditRecord> {
        env.storage()
            .instance()
            .get(&DataKey::UpgradeAuditLog)
            .unwrap_or_else(|| Vec::new(&env))
    }

    /// Number of upgrade audit entries currently retained.
    pub fn get_upgrade_history_len(env: Env) -> u32 {
        Self::upgrade_log(&env).len()
    }

    /// Read the pending upgrade proposal for a kind, if any.
    pub fn get_upgrade_proposal(env: Env, kind: ModuleKind) -> Option<UpgradeProposal> {
        Self::pending_proposal(&env, &kind)
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
    ///
    /// The hash must be well-formed ([`require_valid_wasm_hash`]) and must not
    /// conflict with a pending upgrade proposal for the kind: while a proposal
    /// is open, an approval of a *different* hash would let the proposal be
    /// committed against bytecode the proposers never saw, so it is refused
    /// with [`Error::InvalidState`] until the proposal is committed or
    /// rejected.
    pub fn add_approved_wasm(
        env: Env,
        caller: Address,
        kind: ModuleKind,
        wasm_hash: BytesN<32>,
    ) -> Result<(), Error> {
        Self::require_admin(&env, &caller)?;
        require_valid_wasm_hash(&env, &wasm_hash)?;
        if let Some(pending) = Self::pending_proposal(&env, &kind) {
            ensure!(pending.wasm_hash == wasm_hash, Error::InvalidState);
        }
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

    // --- upgrade audit trail (Issue #300) ---

    /// Read the audit log (most recent entry first).
    fn upgrade_log(env: &Env) -> Vec<UpgradeAuditRecord> {
        env.storage()
            .instance()
            .get(&DataKey::UpgradeAuditLog)
            .unwrap_or_else(|| vec![env])
    }

    /// Append `record` to the immutable audit log, newest first, dropping the
    /// oldest entry once the ring buffer reaches [`MAX_UPGRADE_AUDIT_ENTRIES`].
    ///
    /// Only called on the success paths of the upgrade lifecycle; a Soroban
    /// invocation is atomic, so had the surrounding call failed this write
    /// would be rolled back along with everything else it did.
    fn append_audit(env: &Env, action: UpgradeAction, audit: &UpgradeAudit) {
        let mut log = Self::upgrade_log(env);
        log.push_front(UpgradeAuditRecord {
            action,
            audit: audit.clone(),
        });
        while log.len() > MAX_UPGRADE_AUDIT_ENTRIES {
            log.pop_back();
        }
        env.storage()
            .instance()
            .set(&DataKey::UpgradeAuditLog, &log);
    }

    /// Read the pending upgrade proposal for `kind`, if one is stored. The
    /// only consumer of the raw record besides the upgrade flow itself, so the
    /// expiry check lives at the flow's commit path rather than here.
    fn pending_proposal(env: &Env, kind: &ModuleKind) -> Option<UpgradeProposal> {
        env.storage()
            .persistent()
            .get(&DataKey::UpgradeProposal(*kind))
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
    /// authorizes the new code. Bootstrapped by the deployer alongside
    /// `initialize`; afterwards only the current upgrade admin may rotate it.
    fn set_upgrade_authority(
        env: Env,
        caller: Address,
        admin: Address,
        registry: Address,
    ) -> Result<(), Error> {
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
