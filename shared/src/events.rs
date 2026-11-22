//! Standardized cross-cutting events.
//!
//! Per PRD Doc 7 the backend subscribes to a fixed set of protocol events to
//! drive analytics, notifications and audit logs. These helpers publish those
//! events with a consistent topic/data schema so that every contract emits them
//! identically. Contracts may also publish additional, contract-specific events
//! directly; these are the shared "standard" set.
//!
//! Two layers are provided:
//!
//! 1. **Typed [`ContractEvent`]** — a single `ContractEvent` enum that is the
//!    canonical, structured schema consumed by off-chain indexers. Each variant
//!    publishes under one topic equal to the variant symbol (e.g. `WalletCreated`)
//!    with a strongly-typed payload, so consumers get stable, self-describing
//!    events across every contract.
//! 2. **Tuple-topic helpers** — convenience functions publishing the legacy
//!    `(Symbol category, Symbol action)` tuple topics, retained for backwards
//!    compatibility with existing dashboards.
//!
//! The two layers are emitted together on key state transitions so neither
//! existing nor new consumers break.
//!
//! ## Topic naming convention (Issue #493)
//!
//! Every tuple-topic event published by an Astroid contract follows one shape:
//!
//! ```text
//! (category, action)            -- e.g. ("budget", "consumed")
//! (category, action, subject)   -- e.g. ("org", "register", org_id)
//! ```
//!
//! * `category` is one of the constants in [`topic`] — the noun naming the
//!   contract domain or resource the event concerns (`budget`, `policy`,
//!   `proposal`, ...). Contracts never spell a category inline, so a typo can
//!   no longer split one stream into two.
//! * `action` is a lower-case `symbol_short!` verb or past participle of at
//!   most nine characters (`created`, `approved`, `win_roll`, ...).
//! * `subject`, when present, is the identifier an indexer filters on without
//!   decoding the payload (an org id, an escrow id).
//!
//! Payloads carry identifiers and amounts only — never secrets, signatures or
//! off-chain configuration. Contracts publish through [`emit`] /
//! [`emit_for`] (or a named helper below built on them) rather than calling
//! `env.events().publish` directly, so every event in the protocol goes
//! through one audited builder.

use crate::types::{AssetAmount, ModuleKind};
use soroban_sdk::{
    contracttype, symbol_short, Address, BytesN, Env, IntoVal, String, Symbol, Val, Vec,
};

/// Canonical topic categories (Issue #493).
///
/// The first topic of every tuple-topic event is one of these symbols. They
/// are `symbol_short!` constants, so using them costs nothing at runtime and
/// keeps the on-wire encoding identical to the previous inline spellings.
pub mod topic {
    use soroban_sdk::{symbol_short, Symbol};

    /// Registry contract lifecycle (`init`, `setadmin`, `frozen`, ...).
    pub const REGISTRY: Symbol = symbol_short!("registry");
    /// Organization records held by the registry.
    pub const ORG: Symbol = symbol_short!("org");
    /// Module bindings held by the registry.
    pub const MODULE: Symbol = symbol_short!("module");
    /// Role grants held by the registry.
    pub const ROLE: Symbol = symbol_short!("role");
    /// Module version table / upgrade lifecycle.
    pub const VERSION: Symbol = symbol_short!("version");
    /// Registry administrators.
    pub const ADMIN: Symbol = symbol_short!("admin");
    /// Approved Wasm hashes.
    pub const WASM: Symbol = symbol_short!("wasm");
    /// Agent wallets.
    pub const WALLET: Symbol = symbol_short!("wallet");
    /// Multisig signer set.
    pub const SIGNER: Symbol = symbol_short!("signer");
    /// Multisig threshold.
    pub const THRESHOLD: Symbol = symbol_short!("threshold");
    /// Time-locked multisig governance changes.
    pub const GOVCHANGE: Symbol = symbol_short!("govchange");
    /// Emergency lock.
    pub const EMERGENCY: Symbol = symbol_short!("emergency");
    /// Batched multisig calls.
    pub const BATCH: Symbol = symbol_short!("batch");
    /// Time-locked operations (multisig delay, treasury queue).
    pub const TIMELOCK: Symbol = symbol_short!("timelock");
    /// Proposal lifecycle.
    pub const PROPOSAL: Symbol = symbol_short!("proposal");
    /// Treasury custody and configuration.
    pub const TREASURY: Symbol = symbol_short!("treasury");
    /// Treasury milestone disbursements.
    pub const MILESTONE: Symbol = symbol_short!("milestone");
    /// Budget allocations and spending windows.
    pub const BUDGET: Symbol = symbol_short!("budget");
    /// Policy configuration and evaluation.
    pub const POLICY: Symbol = symbol_short!("policy");
    /// Escrow lifecycle.
    pub const ESCROW: Symbol = symbol_short!("escrow");
    /// Value transfers.
    pub const TRANSFER: Symbol = symbol_short!("transfer");
}

/// Publish a standardized `(category, action)` event (Issue #493).
///
/// `category` should be one of the [`topic`] constants. This is the single
/// builder behind every two-topic event in the protocol.
pub fn emit<D>(env: &Env, category: Symbol, action: Symbol, data: D)
where
    D: IntoVal<Env, Val>,
{
    env.events().publish((category, action), data);
}

/// Publish a standardized `(category, action, subject)` event (Issue #493).
///
/// The third topic is the identifier subscribers filter on without decoding
/// the payload (an org id, an escrow id, a proposal id).
pub fn emit_for<S, D>(env: &Env, category: Symbol, action: Symbol, subject: S, data: D)
where
    S: IntoVal<Env, Val>,
    D: IntoVal<Env, Val>,
{
    env.events().publish((category, action, subject), data);
}

/// Publish a standardized `(category, action, subject, qualifier)` event
/// (Issue #493) — used where an identifier alone is ambiguous, e.g. a module
/// binding keyed by `(org, kind)` or a version keyed by `(kind, version)`.
pub fn emit_for_pair<S, Q, D>(
    env: &Env,
    category: Symbol,
    action: Symbol,
    subject: S,
    qualifier: Q,
    data: D,
) where
    S: IntoVal<Env, Val>,
    Q: IntoVal<Env, Val>,
    D: IntoVal<Env, Val>,
{
    env.events()
        .publish((category, action, subject, qualifier), data);
}

/// Typed payload of the upgrade audit trail: who did what to which version of
/// a module kind, and when. Emitted as part of every upgrade-lifecycle event
/// (`UpgradeProposed`, `UpgradeCommitted`, `UpgradeRejected`) and stored
/// on-chain as an immutable historical log by the registry, so off-chain
/// indexers and on-chain readers see one identical audit schema.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpgradeAudit {
    /// The module kind whose upgrade path this record concerns.
    pub kind: ModuleKind,
    /// The version number involved in the action.
    pub version: u32,
    /// The Wasm hash involved in the action.
    pub wasm_hash: BytesN<32>,
    /// The organization the action was taken under.
    pub org: String,
    /// The account that performed the action (proposer, committing admin,
    /// or rejecting actor).
    pub actor: Address,
    /// Unix timestamp of the action.
    pub recorded_at: u64,
}

/// Typed payload of [`ContractEvent::EscrowExpired`].
///
/// Published when an escrow reaches its expiration deadline or when a keeper
/// reclaims an expired escrow's remaining custody. `amount` is the value still
/// held for the sender at that instant; `expired_at` is the ledger timestamp
/// that made the escrow expire.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EscrowExpiration {
    pub escrow_id: u64,
    pub sender: Address,
    pub amount: i128,
    pub expired_at: u64,
}

/// Typed payload of [`ContractEvent::DepositRecorded`].
///
/// A compact, self-describing record of value entering protocol custody: who
/// sent it, which asset and amount actually arrived, the custodian's recorded
/// balance afterwards, and the ledger timestamp that made the deposit final.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DepositRecorded {
    pub org: String,
    pub from: Address,
    pub asset: Address,
    pub amount: i128,
    pub balance: i128,
    pub recorded_at: u64,
}

/// Canonical, structured event schema emitted by every Astroid contract.
///
/// Publish with `events::publish(env, ContractEvent::Variant { .. })`. Each
/// variant becomes a single-topic event (the variant symbol) carrying a typed
/// payload, giving off-chain indexers one stable schema to track state changes
/// such as module updates, wallet/registry state changes, treasury
/// configuration, budget allocations and policy violations.
#[derive(Clone)]
pub enum ContractEvent {
    /// A module was registered or updated in the registry.
    RegistryModuleUpdated {
        org: String,
        kind: ModuleKind,
        address: Address,
    },
    /// An organization's owner changed.
    OrgOwnerChanged { org: String, new_owner: Address },
    /// The registry was frozen (`frozen = true`) or unfrozen (`frozen = false`).
    RegistryFrozen { org: String, frozen: bool },
    /// A contract implementation upgrade was proposed for a module kind.
    /// Carries the audit payload ([`UpgradeAudit`]) written to the registry's
    /// historical upgrade log at the same moment.
    UpgradeProposed { audit: UpgradeAudit },
    /// A proposed upgrade was rejected or withdrawn.
    UpgradeRejected { audit: UpgradeAudit },
    /// A proposed upgrade was committed: the implementation address was
    /// recorded in the version table and its Wasm hash approved for the kind.
    UpgradeCommitted {
        audit: UpgradeAudit,
        address: Address,
    },
    // NOTE: there is deliberately no "upgrade attempt rejected" event. A
    // Soroban invocation is atomic: every event and storage write of a call
    // that returns an error is rolled back, so an event published on a failure
    // path could never be observed on-chain. Refused upgrade attempts (an
    // unauthorized actor, a re-proposal of already-approved bytecode, …) stay
    // visible off-chain as reverted transactions carrying their error code;
    // the UpgradeProposed/UpgradeCommitted/UpgradeRejected events and the
    // registry's on-chain audit log cover the actions that took effect.
    /// A contract implementation version was registered in the global upgrade
    /// map, bound to the approved WASM hash it runs.
    RegistryVersionRegistered {
        kind: ModuleKind,
        version: u32,
        address: Address,
        wasm_hash: BytesN<32>,
    },
    /// An organization's module was moved onto a newer registered implementation
    /// through the validated upgrade path (Issue #249).
    ///
    /// `from_version` is `0` when the module was registered by address and had
    /// not been upgraded before, so a consumer reading the log can tell a first
    /// validated step apart from a later one. `wasm_hash` is the approved hash
    /// `address` is bound to in the version map — never a caller-supplied one.
    RegistryModuleUpgraded {
        org: String,
        kind: ModuleKind,
        from_version: u32,
        to_version: u32,
        address: Address,
        wasm_hash: BytesN<32>,
    },
    /// The registry replaced its own code with a newer published implementation
    /// (Issue #206).
    ///
    /// `from_version` is `0` for a registry that was deployed before the upgrade
    /// map was tracking its own version, so a consumer can tell the first
    /// validated self-upgrade apart from a later one. `to_version` is the
    /// published `Organization` version the target hash is bound to — the
    /// registry resolved it from its upgrade map, it was never caller-supplied,
    /// and it is strictly greater than `from_version`, so this event is the
    /// audit trail that the registry's own version never went backwards.
    RegistryUpgraded {
        from_version: u32,
        to_version: u32,
        wasm_hash: BytesN<32>,
    },
    /// A wallet was created.
    WalletCreated { wallet_id: u64, owner: Address },
    /// A wallet changed lifecycle state (`state` is e.g. `frozen`/`paused`/...).
    WalletStateChanged { wallet_id: u64, state: Symbol },
    /// The wallet contract's circuit breaker was tripped by `by`.
    WalletPaused { by: Address },
    /// The wallet contract's circuit breaker was reset by `by`.
    WalletUnpaused { by: Address },
    /// Value was deposited into a wallet's internal balance.
    ///
    /// Distinct from [`ContractEvent::TransferExecuted`]: that reports the token
    /// leg (custody in, recipient out), this attributes it to the wallet it
    /// credited.
    WalletFunded {
        wallet_id: u64,
        from: Address,
        asset: Address,
        amount: i128,
    },
    /// Value left a wallet for its owner.
    WalletWithdrawn {
        wallet_id: u64,
        to: Address,
        asset: Address,
        amount: i128,
    },
    /// A spend cleared the wallet's policy gate. Emitted only on the passing
    /// path: a denial reverts the invocation, so the policy contract's own
    /// [`ContractEvent::PolicyViolation`] is what reports a refusal, and this
    /// event is the record that the gate was consulted and allowed the spend.
    WalletPolicyChecked {
        wallet_id: u64,
        asset: Address,
        amount: i128,
    },
    /// The wallet's policy gate was wired to a policy contract.
    WalletPolicyConfigured { policy: Address },
    /// The wallet's policy gate was removed; subsequent spends run ungated.
    WalletPolicyCleared,
    /// A wallet was granted or revoked an exemption from the policy gate.
    WalletPolicyBypassChanged { wallet_id: u64, bypass: bool },
    /// A per-asset velocity ceiling was set on a wallet.
    WalletVelocityLimitSet {
        wallet_id: u64,
        asset: Address,
        max_amount: i128,
        window_seconds: u64,
    },
    /// A per-asset velocity ceiling was removed from a wallet.
    WalletVelocityLimitCleared { wallet_id: u64, asset: Address },
    /// A per-wallet rate limit was set. A `window_seconds` of `0` reports that
    /// the limit was disabled and its usage cleared; a `0` cap means that
    /// dimension is unlimited.
    WalletRateLimitSet {
        wallet_id: u64,
        max_volume: i128,
        max_count: u32,
        window_seconds: u64,
    },
    /// A wallet's rate limit was removed.
    WalletRateLimitCleared { wallet_id: u64 },
    /// The wallet's emergency guardian was (re)designated.
    WalletGuardianChanged { guardian: Address },
    /// A supporting module was wired into the wallet (`module` is e.g.
    /// `budget`/`registry`), replacing any previous address.
    WalletModuleWired { module: Symbol, address: Address },
    /// A per-asset budget envelope was bound to the wallet.
    WalletAssetBudgetSet { asset: Address, budget_id: String },
    /// A role on a wallet changed. `role` is the role granted, and is `None` on
    /// a revocation, where the account simply holds nothing.
    WalletRoleChanged {
        wallet_id: u64,
        account: Address,
        role: Option<Symbol>,
        action: Symbol,
    },
    /// A batch passed policy, velocity and budget validation and was executed
    /// atomically. One event for the whole batch, so the log stays concise;
    /// the individual token transfers remain visible as SAC events.
    WalletBatchValidated {
        wallet_id: u64,
        executed: u32,
        total_amount: i128,
        budget_remaining: i128,
    },
    /// Value moved out of a contract to a recipient.
    TransferExecuted {
        from: Address,
        to: Address,
        asset: Address,
        amount: i128,
    },
    /// Value moved out of a contract to several recipients in one atomic batch.
    /// Emitted once per batch (not once per leg) to keep the log concise; the
    /// individual token transfers remain visible as SAC events.
    BatchTransferExecuted {
        from: Address,
        asset: Address,
        count: u32,
        total: i128,
    },
    /// A treasury configuration field was updated (`action` is e.g. `policy`).
    TreasuryConfigUpdated { org: String, action: Symbol },
    /// A treasury was frozen by the multisig.
    TreasuryFrozen { org: String },
    /// A treasury was unfrozen by the multisig.
    TreasuryUnfrozen { org: String },
    /// Value was deposited into a treasury. `amount` is what actually
    /// arrived in custody (a fee-on-transfer token delivers less than was
    /// requested), and `balance` is the treasury's recorded balance of
    /// `asset` after the deposit.
    TreasuryDeposited {
        org: String,
        from: Address,
        asset: Address,
        amount: i128,
        balance: i128,
    },
    /// A deposit was recorded by any protocol custodian (treasury, wallet or
    /// escrow). Carries [`DepositRecorded`], one stable schema across all of
    /// them (Issue #520).
    DepositRecorded { record: DepositRecorded },
    /// Value was withdrawn from a treasury. `balance` is the treasury's
    /// recorded balance of `asset` after the withdrawal.
    TreasuryWithdrawn {
        org: String,
        to: Address,
        asset: Address,
        amount: i128,
        balance: i128,
    },
    /// Audit trail for a treasury outflow: who invoked the withdrawal, who
    /// received it, and whether the registry verified that caller as the
    /// organization's recorded governance module.
    TreasuryWithdrawalAudit {
        org: String,
        caller: Address,
        to: Address,
        asset: Address,
        amount: i128,
        registry_verified: bool,
        recorded_at: u64,
    },
    /// A budget was allocated, consumed or rolled over (`action` describes which).
    BudgetUpdated {
        budget_id: String,
        action: Symbol,
        amount: i128,
    },
    /// A policy rejected a transfer.
    PolicyViolation { policy_id: String, reason: Symbol },
    /// An escrow was created and funded: custody of the listed assets moved
    /// from the sender to the contract (Issue #292).
    EscrowCreated {
        escrow_id: u64,
        sender: Address,
        recipient: Address,
        assets: Vec<AssetAmount>,
        deadline: u64,
    },
    /// An escrow's held assets were released to its recipient, whether via the
    /// standard arbiter path or a signature-based manual override.
    EscrowReleased {
        escrow_id: u64,
        recipient: Address,
        assets: Vec<AssetAmount>,
    },
    /// An escrow's remaining custody balance was returned to its sender,
    /// whether via the timed-out refund paths or a pre-deadline cancellation
    /// (Issue #292).
    EscrowRefunded {
        escrow_id: u64,
        sender: Address,
        assets: Vec<AssetAmount>,
    },
    /// An escrow reached its expiration deadline, or an expired escrow's
    /// remaining custody was reclaimed and its storage entries removed
    /// (Issue #521). Carries [`EscrowExpiration`].
    EscrowExpired { expiration: EscrowExpiration },
    /// Gas usage telemetry for a single operation execution.
    GasTelemetry {
        operation: Symbol,
        gas_used: u64,
        storage_bytes: u64,
    },
    /// Cumulative resource usage summary for an entire transaction.
    TransactionSummary {
        total_gas: u64,
        total_cpu: u64,
        total_storage: u64,
        operation_count: u32,
    },
}

/// Publish a [`ContractEvent`] using the canonical schema.
///
/// Each variant is emitted under a single topic equal to the variant symbol
/// (e.g. `WalletCreated`) carrying the variant's fields as a typed payload, so
/// off-chain indexers get one stable, self-describing schema per event.
pub fn publish(env: &Env, event: ContractEvent) {
    match event {
        ContractEvent::RegistryModuleUpdated { org, kind, address } => {
            env.events().publish(
                (Symbol::new(env, "RegistryModuleUpdated"),),
                (org, kind, address),
            );
        }
        ContractEvent::OrgOwnerChanged { org, new_owner } => {
            env.events()
                .publish((Symbol::new(env, "OrgOwnerChanged"),), (org, new_owner));
        }
        ContractEvent::RegistryFrozen { org, frozen } => {
            env.events()
                .publish((Symbol::new(env, "RegistryFrozen"),), (org, frozen));
        }
        ContractEvent::UpgradeProposed { audit } => {
            env.events()
                .publish((Symbol::new(env, "UpgradeProposed"),), audit);
        }
        ContractEvent::UpgradeRejected { audit } => {
            env.events()
                .publish((Symbol::new(env, "UpgradeRejected"),), audit);
        }
        ContractEvent::UpgradeCommitted { audit, address } => {
            env.events()
                .publish((Symbol::new(env, "UpgradeCommitted"),), (audit, address));
        }
        ContractEvent::RegistryVersionRegistered {
            kind,
            version,
            address,
            wasm_hash,
        } => {
            env.events().publish(
                (Symbol::new(env, "RegistryVersionRegistered"),),
                (kind, version, address, wasm_hash),
            );
        }
        ContractEvent::RegistryModuleUpgraded {
            org,
            kind,
            from_version,
            to_version,
            address,
            wasm_hash,
        } => {
            env.events().publish(
                (Symbol::new(env, "RegistryModuleUpgraded"),),
                (org, kind, from_version, to_version, address, wasm_hash),
            );
        }
        ContractEvent::RegistryUpgraded {
            from_version,
            to_version,
            wasm_hash,
        } => {
            env.events().publish(
                (Symbol::new(env, "RegistryUpgraded"),),
                (from_version, to_version, wasm_hash),
            );
        }
        ContractEvent::WalletCreated { wallet_id, owner } => {
            env.events()
                .publish((Symbol::new(env, "WalletCreated"),), (wallet_id, owner));
        }
        ContractEvent::WalletPaused { by } => {
            env.events()
                .publish((Symbol::new(env, "WalletPaused"),), by);
        }
        ContractEvent::WalletUnpaused { by } => {
            env.events()
                .publish((Symbol::new(env, "WalletUnpaused"),), by);
        }
        ContractEvent::WalletStateChanged { wallet_id, state } => {
            env.events().publish(
                (Symbol::new(env, "WalletStateChanged"),),
                (wallet_id, state),
            );
        }
        ContractEvent::WalletFunded {
            wallet_id,
            from,
            asset,
            amount,
        } => {
            env.events().publish(
                (Symbol::new(env, "WalletFunded"),),
                (wallet_id, from, asset, amount),
            );
        }
        ContractEvent::WalletWithdrawn {
            wallet_id,
            to,
            asset,
            amount,
        } => {
            env.events().publish(
                (Symbol::new(env, "WalletWithdrawn"),),
                (wallet_id, to, asset, amount),
            );
        }
        ContractEvent::WalletPolicyChecked {
            wallet_id,
            asset,
            amount,
        } => {
            env.events().publish(
                (Symbol::new(env, "WalletPolicyChecked"),),
                (wallet_id, asset, amount),
            );
        }
        ContractEvent::WalletPolicyConfigured { policy } => {
            env.events()
                .publish((Symbol::new(env, "WalletPolicyConfigured"),), (policy,));
        }
        ContractEvent::WalletPolicyCleared => {
            env.events()
                .publish((Symbol::new(env, "WalletPolicyCleared"),), ());
        }
        ContractEvent::WalletPolicyBypassChanged { wallet_id, bypass } => {
            env.events().publish(
                (Symbol::new(env, "WalletPolicyBypassChanged"),),
                (wallet_id, bypass),
            );
        }
        ContractEvent::WalletVelocityLimitSet {
            wallet_id,
            asset,
            max_amount,
            window_seconds,
        } => {
            env.events().publish(
                (Symbol::new(env, "WalletVelocityLimitSet"),),
                (wallet_id, asset, max_amount, window_seconds),
            );
        }
        ContractEvent::WalletVelocityLimitCleared { wallet_id, asset } => {
            env.events().publish(
                (Symbol::new(env, "WalletVelocityLimitCleared"),),
                (wallet_id, asset),
            );
        }
        ContractEvent::WalletRateLimitSet {
            wallet_id,
            max_volume,
            max_count,
            window_seconds,
        } => {
            env.events().publish(
                (Symbol::new(env, "WalletRateLimitSet"),),
                (wallet_id, max_volume, max_count, window_seconds),
            );
        }
        ContractEvent::WalletRateLimitCleared { wallet_id } => {
            env.events()
                .publish((Symbol::new(env, "WalletRateLimitCleared"),), (wallet_id,));
        }
        ContractEvent::WalletGuardianChanged { guardian } => {
            env.events()
                .publish((Symbol::new(env, "WalletGuardianChanged"),), (guardian,));
        }
        ContractEvent::WalletModuleWired { module, address } => {
            env.events()
                .publish((Symbol::new(env, "WalletModuleWired"),), (module, address));
        }
        ContractEvent::WalletAssetBudgetSet { asset, budget_id } => {
            env.events().publish(
                (Symbol::new(env, "WalletAssetBudgetSet"),),
                (asset, budget_id),
            );
        }
        ContractEvent::WalletRoleChanged {
            wallet_id,
            account,
            role,
            action,
        } => {
            env.events().publish(
                (Symbol::new(env, "WalletRoleChanged"),),
                (wallet_id, account, role, action),
            );
        }
        ContractEvent::WalletBatchValidated {
            wallet_id,
            executed,
            total_amount,
            budget_remaining,
        } => {
            env.events().publish(
                (Symbol::new(env, "WalletBatchValidated"),),
                (wallet_id, executed, total_amount, budget_remaining),
            );
        }
        ContractEvent::TransferExecuted {
            from,
            to,
            asset,
            amount,
        } => {
            env.events().publish(
                (Symbol::new(env, "TransferExecuted"),),
                (from, to, asset, amount),
            );
        }
        ContractEvent::BatchTransferExecuted {
            from,
            asset,
            count,
            total,
        } => {
            env.events().publish(
                (Symbol::new(env, "BatchTransferExecuted"),),
                (from, asset, count, total),
            );
        }
        ContractEvent::TreasuryConfigUpdated { org, action } => {
            env.events()
                .publish((Symbol::new(env, "TreasuryConfigUpdated"),), (org, action));
        }
        ContractEvent::BudgetUpdated {
            budget_id,
            action,
            amount,
        } => {
            env.events().publish(
                (Symbol::new(env, "BudgetUpdated"),),
                (budget_id, action, amount),
            );
        }
        ContractEvent::PolicyViolation { policy_id, reason } => {
            env.events()
                .publish((Symbol::new(env, "PolicyViolation"),), (policy_id, reason));
        }
        ContractEvent::TreasuryFrozen { org } => {
            env.events()
                .publish((Symbol::new(env, "TreasuryFrozen"),), org);
        }
        ContractEvent::TreasuryUnfrozen { org } => {
            env.events()
                .publish((Symbol::new(env, "TreasuryUnfrozen"),), org);
        }
        ContractEvent::TreasuryDeposited {
            org,
            from,
            asset,
            amount,
            balance,
        } => {
            env.events().publish(
                (Symbol::new(env, "TreasuryDeposited"),),
                (org, from, asset, amount, balance),
            );
        }
        ContractEvent::DepositRecorded { record } => {
            env.events()
                .publish((Symbol::new(env, "DepositRecorded"),), record);
        }
        ContractEvent::TreasuryWithdrawn {
            org,
            to,
            asset,
            amount,
            balance,
        } => {
            env.events().publish(
                (Symbol::new(env, "TreasuryWithdrawn"),),
                (org, to, asset, amount, balance),
            );
        }
        ContractEvent::TreasuryWithdrawalAudit {
            org,
            caller,
            to,
            asset,
            amount,
            registry_verified,
            recorded_at,
        } => {
            env.events().publish(
                (Symbol::new(env, "TreasuryWithdrawalAudit"),),
                (
                    org,
                    caller,
                    to,
                    asset,
                    amount,
                    registry_verified,
                    recorded_at,
                ),
            );
        }
        ContractEvent::EscrowCreated {
            escrow_id,
            sender,
            recipient,
            assets,
            deadline,
        } => {
            env.events().publish(
                (Symbol::new(env, "EscrowCreated"),),
                (escrow_id, sender, recipient, assets, deadline),
            );
        }
        ContractEvent::EscrowReleased {
            escrow_id,
            recipient,
            assets,
        } => {
            env.events().publish(
                (Symbol::new(env, "EscrowReleased"),),
                (escrow_id, recipient, assets),
            );
        }
        ContractEvent::EscrowRefunded {
            escrow_id,
            sender,
            assets,
        } => {
            env.events().publish(
                (Symbol::new(env, "EscrowRefunded"),),
                (escrow_id, sender, assets),
            );
        }
        ContractEvent::EscrowExpired { expiration } => {
            env.events()
                .publish((Symbol::new(env, "EscrowExpired"),), expiration);
        }
        ContractEvent::GasTelemetry {
            operation,
            gas_used,
            storage_bytes,
        } => {
            env.events().publish(
                (Symbol::new(env, "GasTelemetry"),),
                (operation, gas_used, storage_bytes),
            );
        }
        ContractEvent::TransactionSummary {
            total_gas,
            total_cpu,
            total_storage,
            operation_count,
        } => {
            env.events().publish(
                (Symbol::new(env, "TransactionSummary"),),
                (total_gas, total_cpu, total_storage, operation_count),
            );
        }
    }
}

/// `TransferExecuted` — topic `("transfer", "executed")`.
pub fn transfer_executed(env: &Env, from: &Address, to: &Address, asset: &Address, amount: i128) {
    emit(
        env,
        topic::TRANSFER,
        symbol_short!("executed"),
        (from.clone(), to.clone(), asset.clone(), amount),
    );
}

/// Typed payload of the standardized escrow settlement events (Issue #536).
///
/// Shared by [`escrow_funds_released`] and [`escrow_funds_refunded`] so an
/// indexer decodes one schema for both outcomes of an escrow:
///
/// * `escrow_id` — the escrow that settled (also carried as the third topic,
///   so a subscriber can filter one escrow without decoding payloads);
/// * `recipient` — the account the funds moved to: the escrow's recipient on
///   a release, its sender on a refund;
/// * `amount` — the custody value this call moved, summed across every
///   asset the escrow holds (the same unit as `Escrow::funded_amount`);
/// * `timestamp` — the ledger timestamp of the settlement, following the
///   payload-ends-with-timestamp convention from Issue #222.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EscrowSettlement {
    pub escrow_id: u64,
    pub recipient: Address,
    pub amount: i128,
    pub timestamp: u64,
}

/// Topic action symbol of [`escrow_funds_released`].
pub const ESCROW_FUNDS_RELEASED: Symbol = symbol_short!("fund_rel");
/// Topic action symbol of [`escrow_funds_refunded`].
pub const ESCROW_FUNDS_REFUNDED: Symbol = symbol_short!("fund_ref");

/// `EscrowFundsReleased` — topic `("escrow", "fund_rel", escrow_id)`, data
/// [`EscrowSettlement`].
///
/// Published on every path that pays an escrow's held funds out to its
/// recipient (arbiter release and signature-override release).
pub fn escrow_funds_released(env: &Env, escrow_id: u64, recipient: &Address, amount: i128) {
    publish_escrow_settlement(env, ESCROW_FUNDS_RELEASED, escrow_id, recipient, amount);
}

/// `EscrowFundsRefunded` — topic `("escrow", "fund_ref", escrow_id)`, data
/// [`EscrowSettlement`].
///
/// Published on every path that returns an escrow's held funds to its sender
/// (timed-out refund, time-lock refund, pre-deadline cancel and post-grace
/// reclaim).
pub fn escrow_funds_refunded(env: &Env, escrow_id: u64, recipient: &Address, amount: i128) {
    publish_escrow_settlement(env, ESCROW_FUNDS_REFUNDED, escrow_id, recipient, amount);
}

/// `EscrowExpired` — topic `("EscrowExpired",)`, data [`EscrowExpiration`].
///
/// Published by `escrow::expire` when a keeper marks a timed-out escrow and by
/// `escrow::cleanup_expired` when the remaining custody is refunded and the
/// escrow's ledger entries are removed (Issue #521).
pub fn escrow_expired(env: &Env, escrow_id: u64, sender: &Address, amount: i128) {
    publish(
        env,
        ContractEvent::EscrowExpired {
            expiration: EscrowExpiration {
                escrow_id,
                sender: sender.clone(),
                amount,
                expired_at: env.ledger().timestamp(),
            },
        },
    );
}

fn publish_escrow_settlement(
    env: &Env,
    action: Symbol,
    escrow_id: u64,
    recipient: &Address,
    amount: i128,
) {
    emit_for(
        env,
        topic::ESCROW,
        action,
        escrow_id,
        EscrowSettlement {
            escrow_id,
            recipient: recipient.clone(),
            amount,
            timestamp: env.ledger().timestamp(),
        },
    );
}

/// `ProposalCreated` — topic `("proposal", "created")`.
pub fn proposal_created(env: &Env, proposal_id: u64, proposer: &Address) {
    emit(
        env,
        topic::PROPOSAL,
        symbol_short!("created"),
        (proposal_id, proposer.clone()),
    );
}

/// `ProposalApproved` — topic `("proposal", "approved")`.
pub fn proposal_approved(env: &Env, proposal_id: u64, approver: &Address, approvals: u32) {
    emit(
        env,
        topic::PROPOSAL,
        symbol_short!("approved"),
        (proposal_id, approver.clone(), approvals),
    );
}

/// `ProposalExecuted` — topic `("proposal", "executed")`.
///
/// Published once a proposal's approval weight met the threshold and it was
/// marked executed. The proposal id is the whole payload: execution is
/// terminal and the id is never reused, so it is also the replay marker.
pub fn proposal_executed(env: &Env, proposal_id: u64) {
    emit(env, topic::PROPOSAL, symbol_short!("executed"), proposal_id);
}

/// `BudgetExceeded` — topic `("budget", "exceeded")`.
pub fn budget_exceeded(env: &Env, budget_id: &String, requested: i128, remaining: i128) {
    emit(
        env,
        topic::BUDGET,
        symbol_short!("exceeded"),
        (budget_id.clone(), requested, remaining),
    );
}

/// `BudgetExhausted` — topic `("budget", "exhausted")`.
///
/// Published by a *successful* spend that leaves the current period with no
/// headroom (`remaining <= 0`). Unlike [`budget_exceeded`], which accompanies a
/// refused spend whose invocation reverts (and whose events are therefore
/// discarded by the host), this event is durable: an indexer sees the moment a
/// budget ran dry. `token` is `None` for the budget-level allowance and
/// `Some(asset)` for a per-asset limit.
pub fn budget_exhausted(
    env: &Env,
    budget_id: &String,
    token: Option<Address>,
    spent: i128,
    capacity: i128,
) {
    emit(
        env,
        topic::BUDGET,
        symbol_short!("exhausted"),
        (budget_id.clone(), token, spent, capacity),
    );
}

/// `BudgetReplenished` — topic `("budget", "replenish")`.
///
/// Published whenever fresh allowance becomes spendable: a period rollover
/// that re-arms the window, or an explicit owner top-up. `available` is the
/// headroom the budget (or per-asset limit, when `token` is `Some`) holds
/// immediately afterwards.
pub fn budget_replenished(env: &Env, budget_id: &String, token: Option<Address>, available: i128) {
    emit(
        env,
        topic::BUDGET,
        symbol_short!("replenish"),
        (budget_id.clone(), token, available),
    );
}

/// `PolicyViolation` — topic `("policy", "violation")`.
pub fn policy_violation(env: &Env, policy_id: &String, reason: Symbol) {
    emit(
        env,
        topic::POLICY,
        symbol_short!("violation"),
        (policy_id.clone(), reason),
    );
}

/// `TreasuryCreated` — topic `("treasury", "created")`.
pub fn treasury_created(env: &Env, org: &String, admin: &Address) {
    emit(
        env,
        topic::TREASURY,
        symbol_short!("created"),
        (org.clone(), admin.clone()),
    );
}

/// `AllowanceSet` — topic `("treasury", "allow_set")`.
///
/// Published when a withdrawal allowance is created or replaced. The payload
/// ends with the ledger timestamp — the convention standardized for treasury
/// and policy events in Issue #222 — so an indexer can order allowance
/// changes without correlating ledger metadata (the same convention is used
/// by [`allowance_consumed`] and [`allowance_removed`]).
pub fn allowance_set(
    env: &Env,
    agent: &Address,
    recipient: &Address,
    asset: &Address,
    limit: i128,
    expires_at: u64,
) {
    emit(
        env,
        topic::TREASURY,
        symbol_short!("allow_set"),
        (
            agent.clone(),
            recipient.clone(),
            asset.clone(),
            limit,
            expires_at,
            env.ledger().timestamp(),
        ),
    );
}

/// `AllowanceConsumed` — topic `("treasury", "allow_use")`.
///
/// Published when a spend consumes part of a withdrawal allowance: `amount` is
/// what this movement consumed, and the payload ends with the ledger
/// timestamp (Issue #222).
pub fn allowance_consumed(
    env: &Env,
    agent: &Address,
    recipient: &Address,
    asset: &Address,
    amount: i128,
) {
    emit(
        env,
        topic::TREASURY,
        symbol_short!("allow_use"),
        (
            agent.clone(),
            recipient.clone(),
            asset.clone(),
            amount,
            env.ledger().timestamp(),
        ),
    );
}

/// `AllowanceRemoved` — topic `("treasury", "allow_rem")`.
///
/// Published when a withdrawal allowance is revoked, mirroring the policy
/// contract's `allow_rem` topic and ending with the ledger timestamp
/// (Issue #222).
pub fn allowance_removed(env: &Env, agent: &Address, recipient: &Address, asset: &Address) {
    emit(
        env,
        topic::TREASURY,
        symbol_short!("allow_rem"),
        (
            agent.clone(),
            recipient.clone(),
            asset.clone(),
            env.ledger().timestamp(),
        ),
    );
}

/// Construct a `Symbol` reason code from a static name (used as event payloads
/// for policy/budget violations) so all call sites share one construction path.
pub fn reason(env: &Env, name: &str) -> Symbol {
    Symbol::new(env, name)
}

/// `UpgradeProposed` — topic `("version", "proposed")`. Published when an
/// org owner or admin proposes a version upgrade for a module kind.
pub fn upgrade_proposed(env: &Env, kind: ModuleKind, version: u32, wasm_hash: &BytesN<32>) {
    emit(
        env,
        topic::VERSION,
        symbol_short!("proposed"),
        (kind, version, wasm_hash.clone()),
    );
}

/// `UpgradeRejected` — topic `("version", "rejected")`. Published when a
/// pending upgrade proposal is rejected (or withdrawn by its proposer).
pub fn upgrade_rejected(env: &Env, kind: ModuleKind, version: u32, wasm_hash: &BytesN<32>) {
    emit(
        env,
        topic::VERSION,
        symbol_short!("rejected"),
        (kind, version, wasm_hash.clone()),
    );
}

/// `UpgradeCommitted` — topic `("version", "committed")`. Published when a
/// proposed upgrade is committed into the version table.
pub fn upgrade_committed(
    env: &Env,
    kind: ModuleKind,
    version: u32,
    wasm_hash: &BytesN<32>,
    address: &Address,
) {
    emit(
        env,
        topic::VERSION,
        symbol_short!("committed"),
        (kind, version, wasm_hash.clone(), address.clone()),
    );
}

/// `WalletBatchExecuted` — topic `("wallet", "batch")`.
pub fn wallet_batch_executed(env: &Env, wallet_id: u64, call_count: u32) {
    emit(
        env,
        topic::WALLET,
        symbol_short!("batch"),
        (wallet_id, call_count),
    );
}

/// Topic action of [`budget_window_rolled`].
pub const BUDGET_WINDOW_ROLLED: Symbol = symbol_short!("win_roll");

/// Typed payload of [`budget_window_rolled`] (Issue #495).
///
/// * `budget_id` — the budget whose spending window rolled over;
/// * `periods` — whole windows settled by this rollover (`> 1` when the
///   budget sat idle across several windows);
/// * `previous_spent` — the spend counter of the window that just closed,
///   reset to zero by the rollover;
/// * `window_start` / `window_end` — the new active window, half-open
///   `[window_start, window_end)`;
/// * `timestamp` — ledger time of the rollover (payload-ends-with-timestamp
///   convention from Issue #222).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BudgetWindowRollover {
    pub budget_id: String,
    pub periods: u64,
    pub previous_spent: i128,
    pub window_start: u64,
    pub window_end: u64,
    pub timestamp: u64,
}

/// `BudgetWindowRolled` — topic `("budget", "win_roll")`, data
/// [`BudgetWindowRollover`] (Issue #495).
///
/// Published whenever a recurring budget's spending window lapses and its
/// counters reset for the new window — lazily, by the first spend or keeper
/// call that observes the boundary.
pub fn budget_window_rolled(
    env: &Env,
    budget_id: &String,
    periods: u64,
    previous_spent: i128,
    window_start: u64,
    window_end: u64,
) {
    emit(
        env,
        topic::BUDGET,
        BUDGET_WINDOW_ROLLED,
        BudgetWindowRollover {
            budget_id: budget_id.clone(),
            periods,
            previous_spent,
            window_start,
            window_end,
            timestamp: env.ledger().timestamp(),
        },
    );
}

/// Topic action of [`proposal_state_changed`].
pub const PROPOSAL_STATE_CHANGED: Symbol = symbol_short!("state");

/// Typed payload of [`proposal_state_changed`] (Issue #497).
///
/// `from` / `to` are the `u32` discriminants of the proposal lifecycle enum
/// (`astroid_interfaces::proposal::ProposalState`), which this crate cannot
/// name without a dependency cycle.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposalTransition {
    pub proposal_id: u64,
    pub from: u32,
    pub to: u32,
    pub timestamp: u64,
}

/// `ProposalStateChanged` — topic `("proposal", "state", proposal_id)`, data
/// [`ProposalTransition`] (Issue #497).
///
/// Published on every lifecycle transition of a proposal, alongside the
/// transition-specific event (`approved`, `executed`, ...), so an indexer can
/// follow the state machine from one stream.
pub fn proposal_state_changed(env: &Env, proposal_id: u64, from: u32, to: u32) {
    emit_for(
        env,
        topic::PROPOSAL,
        PROPOSAL_STATE_CHANGED,
        proposal_id,
        ProposalTransition {
            proposal_id,
            from,
            to,
            timestamp: env.ledger().timestamp(),
        },
    );
}

/// Topic action of [`policy_rule_denied`].
pub const POLICY_RULE_DENIED: Symbol = symbol_short!("rule_deny");

/// `PolicyRuleDenied` — topic `("policy", "rule_deny", policy_id)`, data
/// `(rule_index, leaf_op, sub_reason)` (Issue #494).
///
/// Published when a composite policy rule refuses a transaction, naming which
/// rule (`u32::MAX` for the policy's single composite tree, otherwise the
/// rule-stack index), the `u32` discriminant of the leaf that decided it, and
/// a stable sub-reason symbol.
pub fn policy_rule_denied(
    env: &Env,
    policy_id: &String,
    rule_index: u32,
    leaf_op: u32,
    sub_reason: Symbol,
) {
    emit_for(
        env,
        topic::POLICY,
        POLICY_RULE_DENIED,
        policy_id.clone(),
        (rule_index, leaf_op, sub_reason),
    );
}

// ---------------------------------------------------------------------------
// Wallet policy evaluation failures (Issue #504)
// ---------------------------------------------------------------------------

/// Typed payload of the standardized wallet policy-failure event (Issue #504).
///
/// Published by the wallet whenever its pre-execution policy gate refuses an
/// outbound movement, so off-chain monitoring sees one concise, uniform record
/// per refusal regardless of which rule fired:
///
/// * `agent` — the account that attempted the movement (the AI agent's key;
///   also carried as the third topic so a subscriber can follow one agent
///   without decoding payloads);
/// * `wallet_id` — the wallet the movement would have debited;
/// * `policy_id` — the policy envelope that was evaluated (`"active"` for the
///   wallet's standing gate, or a batch action's own `policy_id`);
/// * `reason` — the `UPPER_SNAKE_CASE` wire name of the refusal
///   ([`crate::errors::Error::wire_name`]), e.g. `POLICY_DENIED`, or
///   `POLICY_UNAVAILABLE` when the policy contract could not be invoked;
/// * `code` — the numeric contract error code matching `reason`;
/// * `timestamp` — the ledger timestamp, following the
///   payload-ends-with-timestamp convention from Issue #222.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyViolationEvent {
    pub agent: Address,
    pub wallet_id: u64,
    pub policy_id: String,
    pub reason: Symbol,
    pub code: u32,
    pub timestamp: u64,
}

/// Topic category symbol of [`wallet_policy_violation`].
pub const WALLET_TOPIC: Symbol = symbol_short!("wallet");
/// Topic action symbol of [`wallet_policy_violation`].
pub const POLICY_VIOLATION_ACTION: Symbol = symbol_short!("pol_viol");

/// `WalletPolicyViolation` — topic `("wallet", "pol_viol", agent)`, data
/// [`PolicyViolationEvent`].
///
/// Note on durability: Soroban rolls back every event of an invocation that
/// returns an error. The wallet therefore publishes this both on its reverting
/// spend paths (visible in simulation / diagnostic traces) and on the
/// non-reverting `evaluate_policy` pre-flight entrypoint, whose event is
/// committed on-chain.
pub fn wallet_policy_violation(env: &Env, event: &PolicyViolationEvent) {
    env.events().publish(
        (WALLET_TOPIC, POLICY_VIOLATION_ACTION, event.agent.clone()),
        event.clone(),
    );
}

// ---------------------------------------------------------------------------
// Multisig batch confirmations (Issue #501)
// ---------------------------------------------------------------------------

/// `ProposalBatchApproved` — topic `("proposal", "batch_apr")`, data
/// `(approvals, proposal_ids, timestamp)`.
///
/// One concise event per batched confirmation call: `approvals` is the number
/// of (signer, proposal) confirmations recorded and `proposal_ids` lists the
/// proposals they touched, in batch order (duplicates collapsed). Per-proposal
/// `("proposal", "approved")` events are still published so existing indexers
/// keep their running tallies.
pub fn proposal_batch_approved(env: &Env, approvals: u32, proposal_ids: Vec<u64>) {
    let topics = (symbol_short!("proposal"), symbol_short!("batch_apr"));
    env.events()
        .publish(topics, (approvals, proposal_ids, env.ledger().timestamp()));
}

// ---------------------------------------------------------------------------
// Treasury sub-allocations and emergency sweep (Issue #502)
// ---------------------------------------------------------------------------

/// `AllocationLimitSet` — topic `("treasury", "alloc_cap")`, data
/// `(category, asset, max_amount, timestamp)`.
pub fn treasury_allocation_limit_set(env: &Env, category: &Symbol, asset: &Address, max: i128) {
    let topics = (symbol_short!("treasury"), symbol_short!("alloc_cap"));
    env.events().publish(
        topics,
        (
            category.clone(),
            asset.clone(),
            max,
            env.ledger().timestamp(),
        ),
    );
}

/// `AllocationChanged` — topic `("treasury", action)` where `action` is
/// `alloc` (reserve) or `dealloc` (release), data
/// `(category, asset, amount, reserved_after, timestamp)`.
pub fn treasury_allocation_changed(
    env: &Env,
    action: Symbol,
    category: &Symbol,
    asset: &Address,
    amount: i128,
    reserved_after: i128,
) {
    let topics = (symbol_short!("treasury"), action);
    env.events().publish(
        topics,
        (
            category.clone(),
            asset.clone(),
            amount,
            reserved_after,
            env.ledger().timestamp(),
        ),
    );
}

/// `RecoveryAddressSet` — topic `("treasury", "recov_set")`, data
/// `(recovery, actor, timestamp)`.
pub fn treasury_recovery_set(env: &Env, recovery: &Address, actor: &Address) {
    let topics = (symbol_short!("treasury"), symbol_short!("recov_set"));
    env.events().publish(
        topics,
        (recovery.clone(), actor.clone(), env.ledger().timestamp()),
    );
}

/// `EmergencySweep` — topic `("treasury", "em_sweep", asset)`, data
/// `(actor, recovery, amount, timestamp)`. Published once per swept asset.
pub fn treasury_emergency_sweep(
    env: &Env,
    actor: &Address,
    recovery: &Address,
    asset: &Address,
    amount: i128,
) {
    let topics = (
        symbol_short!("treasury"),
        symbol_short!("em_sweep"),
        asset.clone(),
    );
    env.events().publish(
        topics,
        (
            actor.clone(),
            recovery.clone(),
            amount,
            env.ledger().timestamp(),
        ),
    );
}

// ---------------------------------------------------------------------------
// Deposit tracking (Issue #520)
// ---------------------------------------------------------------------------

/// `DepositRecorded` — typed topic `("DepositRecorded",)` carrying a
/// [`DepositRecorded`] payload, plus the legacy tuple topic
/// `("treasury", "deposit")` with `(org, from, asset, amount, balance,
/// timestamp)` for dashboards that predate the typed layer.
///
/// Both use the standard Soroban event encoding: topics are symbols, the data
/// tuple is a single `contracttype`-compatible value, and the timestamp comes
/// from the deterministic ledger clock rather than the caller.
pub fn deposit_recorded(
    env: &Env,
    org: &String,
    from: &Address,
    asset: &Address,
    amount: i128,
    balance: i128,
) {
    let recorded_at = env.ledger().timestamp();
    let record = DepositRecorded {
        org: org.clone(),
        from: from.clone(),
        asset: asset.clone(),
        amount,
        balance,
        recorded_at,
    };
    publish(env, ContractEvent::DepositRecorded { record });
    env.events().publish(
        (symbol_short!("treasury"), symbol_short!("deposit")),
        (
            org.clone(),
            from.clone(),
            asset.clone(),
            amount,
            balance,
            recorded_at,
        ),
    );
}
