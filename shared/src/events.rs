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
use soroban_sdk::{symbol_short, Address, BytesN, Env, String, Symbol, Vec};

// ---------------------------------------------------------------------------
// Wallet domain helpers
// ---------------------------------------------------------------------------

/// Wallet guardian was set.
pub fn wallet_guardian(env: &Env, guardian: &Address) {
    env.events().publish(
        (symbol_short!("wallet"), symbol_short!("guardian")),
        guardian,
    );
}

/// Tokens deposited into a wallet.
pub fn wallet_deposit(env: &Env, wallet_id: u64, asset: &Address, amount: i128) {
    env.events().publish(
        (symbol_short!("wallet"), symbol_short!("deposit")),
        (wallet_id, asset.clone(), amount),
    );
}

/// Tokens withdrawn from a wallet.
pub fn wallet_withdraw(env: &Env, wallet_id: u64, asset: &Address, amount: i128) {
    env.events().publish(
        (symbol_short!("wallet"), symbol_short!("withdraw")),
        (wallet_id, asset.clone(), amount),
    );
}

/// A role was granted on a wallet.
pub fn wallet_role_granted(env: &Env, wallet_id: u64, account: &Address, role: Symbol) {
    env.events().publish(
        (symbol_short!("role"), symbol_short!("granted")),
        (wallet_id, account.clone(), role),
    );
}

/// A role was revoked on a wallet.
pub fn wallet_role_revoked(env: &Env, wallet_id: u64, account: &Address) {
    env.events().publish(
        (symbol_short!("role"), symbol_short!("revoked")),
        (wallet_id, account.clone()),
    );
}

// ---------------------------------------------------------------------------
// Multisig domain helpers
// ---------------------------------------------------------------------------

/// A signer was added to the multisig.
pub fn multisig_signer_added(env: &Env, signer: &Address, weight: u32) {
    env.events().publish(
        (symbol_short!("signer"), symbol_short!("added")),
        (signer.clone(), weight),
    );
}

/// A signer's weight was changed.
pub fn multisig_signer_weight(env: &Env, signer: &Address, weight: u32) {
    env.events().publish(
        (symbol_short!("signer"), symbol_short!("weight")),
        (signer.clone(), weight),
    );
}

/// A signer was removed from the multisig.
pub fn multisig_signer_removed(env: &Env, signer: &Address) {
    env.events().publish(
        (symbol_short!("signer"), symbol_short!("removed")),
        signer.clone(),
    );
}

/// A timelock delay was changed.
pub fn multisig_timelock_changed(env: &Env, delay: u64) {
    env.events()
        .publish((symbol_short!("timelock"), symbol_short!("changed")), delay);
}

/// A threshold change was proposed (pending timelock).
pub fn multisig_threshold_pending(env: &Env, threshold: u32, sequence: u32) {
    env.events().publish(
        (symbol_short!("threshold"), symbol_short!("pending")),
        (threshold, sequence),
    );
}

/// A threshold change was finalized.
pub fn multisig_threshold_changed(env: &Env, threshold: u32) {
    env.events().publish(
        (symbol_short!("threshold"), symbol_short!("changed")),
        threshold,
    );
}

/// A governance change was executed.
pub fn multisig_govchange_executed(env: &Env, proposal_id: u64, caller: &Address, kind: Symbol) {
    env.events().publish(
        (symbol_short!("govchange"), symbol_short!("executed")),
        (proposal_id, caller.clone(), kind),
    );
}

/// A governance change was cancelled.
pub fn multisig_govchange_cancelled(env: &Env, proposal_id: u64, caller: &Address, kind: Symbol) {
    env.events().publish(
        (symbol_short!("govchange"), symbol_short!("cancelled")),
        (proposal_id, caller.clone(), kind),
    );
}

/// A governance change was proposed.
pub fn multisig_govchange_proposed(env: &Env, id: u64, caller: &Address, kind: Symbol, eta: u64) {
    env.events().publish(
        (symbol_short!("govchange"), symbol_short!("proposed")),
        (id, caller.clone(), kind, eta),
    );
}

/// A multisig batch was executed.
pub fn multisig_batch_executed(env: &Env, nonce: u32, caller: &Address, call_count: u32) {
    env.events().publish(
        (symbol_short!("batch"), symbol_short!("executed")),
        (nonce, caller.clone(), call_count),
    );
}

/// A multisig proposal was executed.
pub fn multisig_proposal_executed(env: &Env, proposal_id: u64) {
    env.events().publish(
        (symbol_short!("proposal"), symbol_short!("executed")),
        proposal_id,
    );
}

// ---------------------------------------------------------------------------
// Proposal domain helpers
// ---------------------------------------------------------------------------

/// A proposal was rejected.
pub fn proposal_rejected(env: &Env, proposal_id: u64, approver: &Address) {
    env.events().publish(
        (symbol_short!("proposal"), symbol_short!("rejected")),
        (proposal_id, approver.clone()),
    );
}

// ---------------------------------------------------------------------------
// Treasury domain helpers
// ---------------------------------------------------------------------------

/// Tokens were deposited into the treasury.
pub fn treasury_deposited(env: &Env, asset: &Address, amount: i128) {
    env.events().publish(
        (symbol_short!("treasury"), symbol_short!("deposited")),
        (asset.clone(), amount),
    );
}

/// A batch payment was executed.
pub fn treasury_batchpay(env: &Env, asset: &Address, count: u32, total: i128) {
    env.events().publish(
        (symbol_short!("treasury"), symbol_short!("batchpay")),
        (asset.clone(), count, total),
    );
}

/// Milestone payment was initialized.
pub fn treasury_milestone_init(env: &Env, count: u32, total: i128, milestones: u32) {
    env.events().publish(
        (symbol_short!("milestone"), symbol_short!("init")),
        (count, total, milestones),
    );
}

/// A milestone payment was disbursed.
pub fn treasury_milestone_disbursed(env: &Env, milestone_id: u32, disbursed: i128, amount: i128) {
    env.events().publish(
        (symbol_short!("milestone"), symbol_short!("disbursed")),
        (milestone_id, disbursed, amount),
    );
}

// ---------------------------------------------------------------------------
// Budget domain helpers
// ---------------------------------------------------------------------------

/// A budget was allocated.
pub fn budget_allocated(env: &Env, budget_id: &String, owner: &Address, limit: i128) {
    env.events().publish(
        (symbol_short!("budget"), symbol_short!("allocated")),
        (budget_id.clone(), owner.clone(), limit),
    );
}

/// A budget was made recurring.
pub fn budget_recurring(
    env: &Env,
    budget_id: &String,
    period: Symbol,
    period_seconds: u64,
    rollover_cap: i128,
) {
    env.events().publish(
        (symbol_short!("budget"), symbol_short!("recurring")),
        (budget_id.clone(), period, period_seconds, rollover_cap),
    );
}

/// A budget limit was changed.
pub fn budget_setlimit(env: &Env, budget_id: &String, new_limit: i128) {
    env.events().publish(
        (symbol_short!("budget"), symbol_short!("setlimit")),
        (budget_id.clone(), new_limit),
    );
}

/// A budget was frozen.
pub fn budget_frozen(env: &Env, budget_id: &String) {
    env.events().publish(
        (symbol_short!("budget"), symbol_short!("frozen")),
        budget_id.clone(),
    );
}

/// A budget was unfrozen.
pub fn budget_unfrozen(env: &Env, budget_id: &String) {
    env.events().publish(
        (symbol_short!("budget"), symbol_short!("unfrozen")),
        budget_id.clone(),
    );
}

/// A budget was archived.
pub fn budget_archived(env: &Env, budget_id: &String) {
    env.events().publish(
        (symbol_short!("budget"), symbol_short!("archived")),
        budget_id.clone(),
    );
}

/// Funds were reallocated between budgets.
pub fn budget_realloc(env: &Env, from_id: &String, to_id: &String, amount: i128) {
    env.events().publish(
        (symbol_short!("budget"), symbol_short!("realloc")),
        (from_id.clone(), to_id.clone(), amount),
    );
}

/// An asset limit was set on a budget.
pub fn budget_set_asset(env: &Env, budget_id: &String, token: &Address, limit: i128) {
    env.events().publish(
        (symbol_short!("budget"), symbol_short!("set_ast")),
        (budget_id.clone(), token.clone(), limit),
    );
}

/// An asset limit was spent against.
pub fn budget_asset_spend(env: &Env, budget_id: &String, token: &Address, amount: i128) {
    env.events().publish(
        (symbol_short!("budget"), symbol_short!("ast_spend")),
        (budget_id.clone(), token.clone(), amount),
    );
}

/// An asset limit was reset.
pub fn budget_asset_reset(env: &Env, budget_id: &String, token: &Address, limit: i128) {
    env.events().publish(
        (symbol_short!("budget"), symbol_short!("ast_reset")),
        (budget_id.clone(), token.clone(), limit),
    );
}

/// A budget period expired.
pub fn budget_expired(env: &Env, budget_id: &String) {
    env.events().publish(
        (symbol_short!("budget"), symbol_short!("expired")),
        budget_id.clone(),
    );
}

/// Budget consumption (generic action).
pub fn budget_action(env: &Env, budget_id: &String, action: Symbol, amount: i128) {
    env.events().publish(
        (symbol_short!("budget"), action),
        (budget_id.clone(), amount),
    );
}

/// Budget consumed (generic).
pub fn budget_consumed(env: &Env, budget_id: &String, amount: i128, remaining: i128) {
    env.events().publish(
        (symbol_short!("budget"), symbol_short!("consumed")),
        (budget_id.clone(), amount, remaining),
    );
}

// ---------------------------------------------------------------------------
// Policy domain helpers
// ---------------------------------------------------------------------------

/// A policy was registered.
pub fn policy_registered(env: &Env, policy_id: &String) {
    env.events().publish(
        (symbol_short!("policy"), symbol_short!("registd")),
        policy_id.clone(),
    );
}

/// A policy was rotated.
pub fn policy_rotated(env: &Env, policy_id: &String) {
    env.events().publish(
        (symbol_short!("policy"), symbol_short!("rotated")),
        policy_id.clone(),
    );
}

/// An asset was added to a policy whitelist.
pub fn policy_asset_added(env: &Env, policy_id: &String, asset: &Address) {
    env.events().publish(
        (symbol_short!("policy"), symbol_short!("asset_add")),
        (policy_id.clone(), asset.clone()),
    );
}

/// An asset was removed from a policy whitelist.
pub fn policy_asset_removed(env: &Env, policy_id: &String, asset: &Address) {
    env.events().publish(
        (symbol_short!("policy"), symbol_short!("asset_rem")),
        (policy_id.clone(), asset.clone()),
    );
}

/// An asset was added to a policy blocklist.
pub fn policy_asset_blocked(env: &Env, policy_id: &String, asset: &Address) {
    env.events().publish(
        (symbol_short!("policy"), symbol_short!("ablk_add")),
        (policy_id.clone(), asset.clone()),
    );
}

/// An asset was removed from a policy blocklist.
pub fn policy_asset_unblocked(env: &Env, policy_id: &String, asset: &Address) {
    env.events().publish(
        (symbol_short!("policy"), symbol_short!("ablk_rem")),
        (policy_id.clone(), asset.clone()),
    );
}

/// An address was added to a policy blocklist.
pub fn policy_blocked(env: &Env, policy_id: &String, address: &Address) {
    env.events().publish(
        (symbol_short!("policy"), symbol_short!("blk_add")),
        (policy_id.clone(), address.clone()),
    );
}

/// An address was removed from a policy blocklist.
pub fn policy_unblocked(env: &Env, policy_id: &String, address: &Address) {
    env.events().publish(
        (symbol_short!("policy"), symbol_short!("blk_rem")),
        (policy_id.clone(), address.clone()),
    );
}

/// A merchant was added to a policy blocklist.
pub fn policy_merchant_blocked(env: &Env, policy_id: &String, merchant: &Address) {
    env.events().publish(
        (symbol_short!("policy"), symbol_short!("merch_add")),
        (policy_id.clone(), merchant.clone()),
    );
}

/// A merchant was removed from a policy blocklist.
pub fn policy_merchant_unblocked(env: &Env, policy_id: &String, merchant: &Address) {
    env.events().publish(
        (symbol_short!("policy"), symbol_short!("merch_rem")),
        (policy_id.clone(), merchant.clone()),
    );
}

/// A category was added to a policy blocklist.
pub fn policy_category_blocked(env: &Env, policy_id: &String, category: &String) {
    env.events().publish(
        (symbol_short!("policy"), symbol_short!("cat_add")),
        (policy_id.clone(), category.clone()),
    );
}

/// A category was removed from a policy blocklist.
pub fn policy_category_unblocked(env: &Env, policy_id: &String, category: &String) {
    env.events().publish(
        (symbol_short!("policy"), symbol_short!("cat_rem")),
        (policy_id.clone(), category.clone()),
    );
}

/// A spending allowance was set.
pub fn policy_allowance_set(env: &Env, policy_id: &String, asset: &Address, limit: i128) {
    env.events().publish(
        (symbol_short!("policy"), symbol_short!("allow_set")),
        (policy_id.clone(), asset.clone(), limit),
    );
}

/// A spending allowance was removed.
pub fn policy_allowance_removed(env: &Env, policy_id: &String, asset: &Address) {
    env.events().publish(
        (symbol_short!("policy"), symbol_short!("allow_rem")),
        (policy_id.clone(), asset.clone()),
    );
}

/// A spending allowance was consumed.
pub fn policy_allowance_used(
    env: &Env,
    policy_id: &String,
    asset: &Address,
    amount: i128,
    spent: i128,
) {
    env.events().publish(
        (symbol_short!("policy"), symbol_short!("allow_use")),
        (policy_id.clone(), asset.clone(), amount, spent),
    );
}

/// A rule tree was set on a policy.
pub fn policy_rule_set(env: &Env, policy_id: &String) {
    env.events().publish(
        (symbol_short!("policy"), symbol_short!("rule_set")),
        policy_id.clone(),
    );
}

/// A rule tree was cleared on a policy.
pub fn policy_rule_cleared(env: &Env, policy_id: &String) {
    env.events().publish(
        (symbol_short!("policy"), symbol_short!("rule_clr")),
        policy_id.clone(),
    );
}

// ---------------------------------------------------------------------------
// Registry domain helpers
// ---------------------------------------------------------------------------

/// An organization was registered.
pub fn registry_org_registered(env: &Env, org: &String, owner: &Address) {
    env.events().publish(
        (symbol_short!("org"), symbol_short!("register"), org.clone()),
        owner.clone(),
    );
}

/// An organization's owner changed.
pub fn registry_org_owner(env: &Env, org: &String, new_owner: &Address) {
    env.events().publish(
        (symbol_short!("org"), symbol_short!("owner"), org.clone()),
        new_owner.clone(),
    );
}

/// A module was registered.
pub fn registry_module_registered(env: &Env, org: &String, kind: ModuleKind, address: &Address) {
    env.events().publish(
        (
            symbol_short!("module"),
            symbol_short!("register"),
            org.clone(),
        ),
        (kind, address.clone()),
    );
}

/// A module was deprecated.
pub fn registry_module_deprecated(env: &Env, org: &String, kind: ModuleKind) {
    env.events().publish(
        (symbol_short!("module"), symbol_short!("deprecate")),
        (org.clone(), kind),
    );
}

/// A module was restored.
pub fn registry_module_restored(env: &Env, org: &String, kind: ModuleKind) {
    env.events().publish(
        (symbol_short!("module"), symbol_short!("restore")),
        (org.clone(), kind),
    );
}

/// A module was removed.
pub fn registry_module_removed(env: &Env, org: &String, kind: ModuleKind) {
    env.events().publish(
        (symbol_short!("module"), symbol_short!("remove")),
        (org.clone(), kind),
    );
}

/// A version was registered.
pub fn registry_version_registered(env: &Env, kind: ModuleKind, version: u32, address: &Address) {
    env.events().publish(
        (
            symbol_short!("version"),
            symbol_short!("register"),
            kind,
            version,
        ),
        address.clone(),
    );
}

/// A role was granted in the registry.
pub fn registry_role_granted(env: &Env, org: &String, account: &Address, role: Symbol) {
    env.events().publish(
        (symbol_short!("role"), symbol_short!("granted")),
        (org.clone(), account.clone(), role),
    );
}

/// A role was revoked in the registry.
pub fn registry_role_revoked(env: &Env, org: &String, account: &Address) {
    env.events().publish(
        (symbol_short!("role"), symbol_short!("revoked")),
        (org.clone(), account.clone()),
    );
}

/// The registry was initialized.
pub fn registry_initialized(env: &Env, admin: &Address) {
    env.events().publish(
        (symbol_short!("registry"), symbol_short!("init")),
        admin.clone(),
    );
}

/// The registry admin was changed.
pub fn registry_set_admin(env: &Env, new_admin: &Address) {
    env.events().publish(
        (symbol_short!("registry"), symbol_short!("setadmin")),
        new_admin.clone(),
    );
}

/// The registry was frozen.
pub fn registry_frozen(env: &Env, org: &String) {
    env.events().publish(
        (symbol_short!("registry"), symbol_short!("frozen")),
        org.clone(),
    );
}

/// The registry was unfrozen.
pub fn registry_unfrozen(env: &Env, org: &String) {
    env.events().publish(
        (symbol_short!("registry"), symbol_short!("unfrozen")),
        org.clone(),
    );
}

/// A WASM hash was approved.
pub fn registry_wasm_approved(env: &Env, kind: ModuleKind, wasm_hash: &BytesN<32>) {
    env.events().publish(
        (symbol_short!("wasm"), symbol_short!("approved")),
        (kind, wasm_hash.clone()),
    );
}

/// A WASM hash was removed.
pub fn registry_wasm_removed(env: &Env, kind: ModuleKind, wasm_hash: &BytesN<32>) {
    env.events().publish(
        (symbol_short!("wasm"), symbol_short!("removed")),
        (kind, wasm_hash.clone()),
    );
}

// ---------------------------------------------------------------------------
// Escrow domain helpers
// ---------------------------------------------------------------------------

/// An escrow was funded.
pub fn escrow_funded(
    env: &Env,
    id: u64,
    sender: &Address,
    recipient: &Address,
    assets: &Vec<AssetAmount>,
) {
    env.events().publish(
        (symbol_short!("escrow"), symbol_short!("funded")),
        (id, sender.clone(), recipient.clone(), assets.clone()),
    );
}

/// A timelocked escrow was initialized.
pub fn escrow_init_timelock(
    env: &Env,
    id: u64,
    sender: &Address,
    recipient: &Address,
    assets: &Vec<AssetAmount>,
    unlock_time: u64,
) {
    env.events().publish(
        (symbol_short!("escrow"), symbol_short!("init_tl")),
        (
            id,
            sender.clone(),
            recipient.clone(),
            assets.clone(),
            unlock_time,
        ),
    );
}

/// A scheduled escrow was initialized.
pub fn escrow_init_scheduled(
    env: &Env,
    id: u64,
    sender: &Address,
    recipient: &Address,
    assets: &Vec<AssetAmount>,
    funded_amount: i128,
    start_time: u64,
    end_time: u64,
) {
    env.events().publish(
        (symbol_short!("escrow"), symbol_short!("sched")),
        (
            id,
            sender.clone(),
            recipient.clone(),
            assets.clone(),
            funded_amount,
            start_time,
            end_time,
        ),
    );
}

/// An escrow was withdrawn.
pub fn escrow_withdrawn(env: &Env, id: u64, caller: &Address, amount: i128, released: i128) {
    env.events().publish(
        (symbol_short!("escrow"), symbol_short!("withdraw")),
        (id, caller.clone(), amount, released),
    );
}

/// An escrow was claimed.
pub fn escrow_claimed(env: &Env, id: u64, caller: &Address, claimable: i128) {
    env.events().publish(
        (symbol_short!("escrow"), symbol_short!("claimed")),
        (id, caller.clone(), claimable),
    );
}

/// An escrow was released by arbiter.
pub fn escrow_released(env: &Env, id: u64, arbiter: &Address, amount: i128) {
    env.events().publish(
        (symbol_short!("escrow"), symbol_short!("released")),
        (id, arbiter.clone(), amount),
    );
}

/// An escrow override was executed.
pub fn escrow_override(env: &Env, id: u64, nonce: u32) {
    env.events().publish(
        (symbol_short!("escrow"), symbol_short!("override")),
        (id, nonce),
    );
}

/// An escrow was refunded.
pub fn escrow_refunded(env: &Env, id: u64, caller: &Address) {
    env.events().publish(
        (symbol_short!("escrow"), symbol_short!("refunded")),
        (id, caller.clone()),
    );
}

/// A timelocked escrow refund was executed.
pub fn escrow_refund_timelock(env: &Env, id: u64, caller: &Address) {
    env.events().publish(
        (symbol_short!("escrow"), symbol_short!("ref_tl")),
        (id, caller.clone()),
    );
}

/// An escrow was cancelled.
pub fn escrow_cancelled(env: &Env, id: u64, caller: &Address) {
    env.events().publish(
        (symbol_short!("escrow"), symbol_short!("cancelled")),
        (id, caller.clone()),
    );
}

/// An escrow was reclaimed by sender.
pub fn escrow_reclaimed(env: &Env, id: u64, caller: &Address) {
    env.events().publish(
        (symbol_short!("escrow"), symbol_short!("reclaimed")),
        (id, caller.clone()),
    );
}

/// A milestone escrow was created.
pub fn escrow_milestone(
    env: &Env,
    id: u64,
    sender: &Address,
    recipient: &Address,
    asset: &Address,
    amount: i128,
) {
    env.events().publish(
        (symbol_short!("escrow"), symbol_short!("milestone")),
        (id, sender.clone(), recipient.clone(), asset.clone(), amount),
    );
}

/// A milestone payout was released.
pub fn escrow_milestone_release(env: &Env, id: u64, caller: &Address, index: u32, payout: i128) {
    env.events().publish(
        (symbol_short!("escrow"), symbol_short!("ms_rel")),
        (id, caller.clone(), index, payout),
    );
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
    /// Several modules were registered or updated atomically in one batch.
    RegistryModuleBatchUpdated {
        org: String,
        kinds: Vec<ModuleKind>,
        addresses: Vec<Address>,
    },
    /// An organization's owner changed.
    OrgOwnerChanged { org: String, new_owner: Address },
    /// The registry was frozen (`frozen = true`) or unfrozen (`frozen = false`).
    RegistryFrozen { org: String, frozen: bool },
    /// The contract was paused (`paused = true`) or unpaused (`paused = false`)
    /// via the system-wide emergency circuit breaker.
    ContractPaused { paused: bool },
    /// A wallet was created.
    WalletCreated { wallet_id: u64, owner: Address },
    /// A wallet changed lifecycle state (`state` is e.g. `frozen`/`paused`/...).
    WalletStateChanged { wallet_id: u64, state: Symbol },
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
    /// A budget was allocated, consumed or rolled over (`action` describes which).
    BudgetUpdated {
        budget_id: String,
        action: Symbol,
        amount: i128,
    },
    /// A policy rejected a transfer.
    PolicyViolation { policy_id: String, reason: Symbol },
    /// An escrow's held assets were released to its recipient, whether via the
    /// standard arbiter path or a signature-based manual override.
    EscrowReleased {
        escrow_id: u64,
        recipient: Address,
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
        ContractEvent::RegistryModuleBatchUpdated {
            org,
            kinds,
            addresses,
        } => {
            env.events().publish(
                (Symbol::new(env, "RegistryModuleBatchUpdated"),),
                (org, kinds, addresses),
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
        ContractEvent::ContractPaused { paused } => {
            env.events()
                .publish((Symbol::new(env, "ContractPaused"),), paused);
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

/// `WalletCreated` — topic `("wallet", "created")`.
pub fn wallet_created(env: &Env, wallet_id: u64, owner: &Address) {
    let topics = (symbol_short!("wallet"), symbol_short!("created"));
    env.events().publish(topics, (wallet_id, owner.clone()));
}

/// `WalletFrozen` — topic `("wallet", "frozen")`.
pub fn wallet_frozen(env: &Env, wallet_id: u64, by: &Address) {
    let topics = (symbol_short!("wallet"), symbol_short!("frozen"));
    env.events().publish(topics, (wallet_id, by.clone()));
}

/// `TransferExecuted` — topic `("transfer", "executed")`.
pub fn transfer_executed(env: &Env, from: &Address, to: &Address, asset: &Address, amount: i128) {
    let topics = (symbol_short!("transfer"), symbol_short!("executed"));
    env.events()
        .publish(topics, (from.clone(), to.clone(), asset.clone(), amount));
}

// --- Escrow-specific events -------------------------------------------------
//
// These mirror the standardized shared-event convention (`(category, action)`)
// so the Astroid backend can subscribe to escrow lifecycle transitions with the
// same topic schema used everywhere else in the protocol.

/// `EscrowFunded` — topic `("escrow", "funded")`. Emitted when an escrow is
/// created and the funds are pulled into the contract's custody.
pub fn escrow_funded(
    env: &Env,
    id: u64,
    sender: &Address,
    recipient: &Address,
    asset: &Address,
    amount: i128,
) {
    let topics = (symbol_short!("escrow"), symbol_short!("funded"));
    env.events().publish(
        topics,
        (id, sender.clone(), recipient.clone(), asset.clone(), amount),
    );
}

/// `EscrowReleased` — topic `("escrow", "released")`. Emitted when the arbiter
/// releases the escrowed funds to the recipient (fulfillment).
pub fn escrow_released(env: &Env, id: u64, by: &Address) {
    let topics = (symbol_short!("escrow"), symbol_short!("released"));
    env.events().publish(topics, (id, by.clone()));
}

/// `EscrowClaimed` — topic `("escrow", "claimed")`. Emitted when a recipient
/// claims from a time-locked escrow after the unlock time (fulfillment).
pub fn escrow_claimed(env: &Env, id: u64, by: &Address) {
    let topics = (symbol_short!("escrow"), symbol_short!("claimed"));
    env.events().publish(topics, (id, by.clone()));
}

/// `EscrowExpired` — topic `("escrow", "expired")`. Emitted when an escrow's
/// deadline passes and it is marked expired (auto-cancellation marker).
pub fn escrow_expired(env: &Env, id: u64) {
    let topics = (symbol_short!("escrow"), symbol_short!("expired"));
    env.events().publish(topics, id);
}

/// `EscrowRefunded` — topic `("escrow", "refunded")`. Emitted when expired (or
/// cancelled) escrow funds are returned to the original depositor.
pub fn escrow_refunded(env: &Env, id: u64, to: &Address) {
    let topics = (symbol_short!("escrow"), symbol_short!("refunded"));
    env.events().publish(topics, (id, to.clone()));
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

/// `WalletBatchExecuted` — topic `("wallet", "batch")`.
pub fn wallet_batch_executed(env: &Env, wallet_id: u64, call_count: u32) {
    let topics = (symbol_short!("wallet"), symbol_short!("batch"));
    env.events().publish(topics, (wallet_id, call_count));
}

/// `WalletBatchValidated` — topic `("wallet", "batch_validated")`. Published by
/// the wallet after a policy- and budget-validated batch run completes.
pub fn wallet_batch_validated(
    env: &Env,
    wallet_id: u64,
    executed: u32,
    total_amount: i128,
    budget_remaining: i128,
) {
    let topics = (symbol_short!("wallet"), Symbol::new(env, "batch_validated"));
    env.events().publish(
        topics,
        (wallet_id, executed, total_amount, budget_remaining),
    );
}
