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

use crate::types::{AssetAmount, ModuleKind};
use soroban_sdk::{contracttype, symbol_short, Address, BytesN, Env, String, Symbol, Vec};

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
    /// Registry WASM was updated after an approved, authorized request.
    RegistryUpgraded {
        sequence: u32,
        caller: Address,
        wasm_hash: BytesN<32>,
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
    /// Value was deposited into a treasury. `balance` is the treasury's
    /// recorded balance of `asset` after the deposit.
    TreasuryDeposited {
        org: String,
        from: Address,
        asset: Address,
        amount: i128,
        balance: i128,
    },
    /// Value was withdrawn from a treasury. `balance` is the treasury's
    /// recorded balance of `asset` after the withdrawal.
    TreasuryWithdrawn {
        org: String,
        to: Address,
        asset: Address,
        amount: i128,
        balance: i128,
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
        ContractEvent::RegistryUpgraded {
            sequence,
            caller,
            wasm_hash,
        } => {
            env.events().publish(
                (Symbol::new(env, "RegistryUpgraded"),),
                (sequence, caller, wasm_hash),
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
    let topics = (symbol_short!("transfer"), symbol_short!("executed"));
    env.events()
        .publish(topics, (from.clone(), to.clone(), asset.clone(), amount));
}

/// `ProposalCreated` — topic `("proposal", "created")`.
pub fn proposal_created(env: &Env, proposal_id: u64, proposer: &Address) {
    let topics = (symbol_short!("proposal"), symbol_short!("created"));
    env.events()
        .publish(topics, (proposal_id, proposer.clone()));
}

/// `ProposalApproved` — topic `("proposal", "approved")`.
pub fn proposal_approved(env: &Env, proposal_id: u64, approver: &Address, approvals: u32) {
    let topics = (symbol_short!("proposal"), symbol_short!("approved"));
    env.events()
        .publish(topics, (proposal_id, approver.clone(), approvals));
}

/// `BudgetExceeded` — topic `("budget", "exceeded")`.
pub fn budget_exceeded(env: &Env, budget_id: &String, requested: i128, remaining: i128) {
    let topics = (symbol_short!("budget"), symbol_short!("exceeded"));
    env.events()
        .publish(topics, (budget_id.clone(), requested, remaining));
}

/// `PolicyViolation` — topic `("policy", "violation")`.
pub fn policy_violation(env: &Env, policy_id: &String, reason: Symbol) {
    let topics = (symbol_short!("policy"), symbol_short!("violation"));
    env.events().publish(topics, (policy_id.clone(), reason));
}

/// `TreasuryCreated` — topic `("treasury", "created")`.
pub fn treasury_created(env: &Env, org: &String, admin: &Address) {
    let topics = (symbol_short!("treasury"), symbol_short!("created"));
    env.events().publish(topics, (org.clone(), admin.clone()));
}

/// `AllowanceSet` — topic `("treasury", "allow_set")`.
pub fn allowance_set(env: &Env, agent: &Address, asset: &Address, amount: i128) {
    let topics = (symbol_short!("treasury"), symbol_short!("allow_set"));
    env.events()
        .publish(topics, (agent.clone(), asset.clone(), amount));
}

/// `AllowanceConsumed` — topic `("treasury", "allow_use")`.
pub fn allowance_consumed(env: &Env, agent: &Address, asset: &Address, amount: i128) {
    let topics = (symbol_short!("treasury"), symbol_short!("allow_use"));
    env.events()
        .publish(topics, (agent.clone(), asset.clone(), amount));
}

/// Construct a `Symbol` reason code from a static name (used as event payloads
/// for policy/budget violations) so all call sites share one construction path.
pub fn reason(env: &Env, name: &str) -> Symbol {
    Symbol::new(env, name)
}

/// `UpgradeProposed` — topic `("version", "proposed")`. Published when an
/// org owner or admin proposes a version upgrade for a module kind.
pub fn upgrade_proposed(env: &Env, kind: ModuleKind, version: u32, wasm_hash: &BytesN<32>) {
    let topics = (symbol_short!("version"), symbol_short!("proposed"));
    env.events()
        .publish(topics, (kind, version, wasm_hash.clone()));
}

/// `UpgradeRejected` — topic `("version", "rejected")`. Published when a
/// pending upgrade proposal is rejected (or withdrawn by its proposer).
pub fn upgrade_rejected(env: &Env, kind: ModuleKind, version: u32, wasm_hash: &BytesN<32>) {
    let topics = (symbol_short!("version"), symbol_short!("rejected"));
    env.events()
        .publish(topics, (kind, version, wasm_hash.clone()));
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
    let topics = (symbol_short!("version"), symbol_short!("committed"));
    env.events()
        .publish(topics, (kind, version, wasm_hash.clone(), address.clone()));
}

/// `WalletBatchExecuted` — topic `("wallet", "batch")`.
pub fn wallet_batch_executed(env: &Env, wallet_id: u64, call_count: u32) {
    let topics = (symbol_short!("wallet"), symbol_short!("batch"));
    env.events().publish(topics, (wallet_id, call_count));
}
