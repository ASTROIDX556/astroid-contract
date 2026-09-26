//! Gas usage telemetry and execution cost tracking helpers.
//!
//! This module provides utilities for contracts to log resource consumption
//! metrics that off-chain components and AI agents can use to estimate
//! transaction expenses prior to submitting Soroban transactions.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use astroid_shared::telemetry::log_execution_cost;
//!
//! // At the start of a function
//! let start = env.ledger().timestamp();
//!
//! // ... do work ...
//!
//! // At the end, log the cost
//! log_execution_cost(&env, "transfer", 150, 1024);
//! ```

use soroban_sdk::{contracttype, Env, Symbol};

/// Resource consumption metrics for a single execution step.
///
/// Captures the gas consumed, CPU instructions (when available), and
/// memory/storage footprint so off-chain estimators can predict costs.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionCost {
    /// The name of the operation being measured (e.g. "transfer", "mint").
    pub operation: Symbol,
    /// Gas units consumed during the operation.
    pub gas_used: u64,
    /// CPU instructions consumed (0 when unavailable).
    pub cpu_instructions: u64,
    /// Bytes of storage read or written during the operation.
    pub storage_bytes: u64,
    /// Timestamp (ledger close time) when the measurement was taken.
    pub timestamp: u64,
}

/// Cumulative resource usage summary for an entire transaction.
///
/// Aggregates individual `ExecutionCost` entries into totals that can be
/// compared against Soroban resource limits and used for budget estimation.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionSummary {
    /// Total gas consumed across all operations in the transaction.
    pub total_gas: u64,
    /// Total CPU instructions consumed.
    pub total_cpu: u64,
    /// Total storage bytes read or written.
    pub total_storage: u64,
    /// Number of individual operations tracked.
    pub operation_count: u32,
    /// Whether any operation approached the resource limit (>90%).
    pub near_limit: bool,
}

/// Log an execution cost event for a single operation.
///
/// Publishes a Soroban event with topic `"ExecCost"` containing the
/// operation name and metrics. Off-chain indexers can subscribe to this
/// topic to build real-time gas estimation models.
///
/// # Arguments
///
/// * `env` - The Soroban environment
/// * `operation` - Human-readable operation name
/// * `gas_used` - Gas units consumed
/// * `storage_bytes` - Bytes of storage accessed
pub fn log_execution_cost(env: &Env, operation: &str, gas_used: u64, storage_bytes: u64) {
    let timestamp = env.ledger().timestamp();
    let cost = ExecutionCost {
        operation: Symbol::new(env, operation),
        gas_used,
        cpu_instructions: 0,
        storage_bytes,
        timestamp,
    };
    env.events().publish((Symbol::new(env, "ExecCost"),), cost);
}

/// Log an execution cost event with full CPU metrics.
///
/// Variant of [`log_execution_cost`] that includes CPU instruction counts
/// for operations where this metric is available.
pub fn log_execution_cost_full(
    env: &Env,
    operation: &str,
    gas_used: u64,
    cpu_instructions: u64,
    storage_bytes: u64,
) {
    let timestamp = env.ledger().timestamp();
    let cost = ExecutionCost {
        operation: Symbol::new(env, operation),
        gas_used,
        cpu_instructions,
        storage_bytes,
        timestamp,
    };
    env.events()
        .publish((Symbol::new(env, "ExecCostFull"),), cost);
}

/// Log a transaction summary event aggregating all operation costs.
///
/// Publishes a Soroban event with topic `"TxSummary"` containing totals
/// that can be used for end-of-transaction cost reporting and limit checking.
pub fn log_transaction_summary(
    env: &Env,
    total_gas: u64,
    total_cpu: u64,
    total_storage: u64,
    operation_count: u32,
    near_limit: bool,
) {
    let summary = TransactionSummary {
        total_gas,
        total_cpu,
        total_storage,
        operation_count,
        near_limit,
    };
    env.events()
        .publish((Symbol::new(env, "TxSummary"),), summary);
}

/// Estimate the gas cost for a hypothetical operation based on historical data.
///
/// Returns a rough estimate of gas units needed, useful for pre-flight checks
/// and budget planning. This is a simple heuristic that can be refined with
/// real on-chain data.
pub fn estimate_gas(operation: &str, storage_bytes: u64) -> u64 {
    // Base cost per operation category
    let base = match operation {
        "transfer" | "mint" | "burn" => 100,
        "approve" | "allowance" => 80,
        "balance" | "balance_of" => 60,
        "transfer_from" => 150,
        "write" | "store" => 200,
        _ => 100,
    };
    // Add storage overhead: ~10 gas per KB
    base + (storage_bytes / 1024) * 10
}

/// Check whether a gas usage value is approaching the Soroban resource limit.
///
/// Returns `true` if `gas_used` exceeds 90% of the default Soroban contract
/// call budget (currently 100,000,000 gas units). Contracts can use this to
/// emit warnings before hitting hard limits.
pub fn is_near_gas_limit(gas_used: u64) -> bool {
    const SOROBAN_GAS_LIMIT: u64 = 100_000_000;
    const NEAR_LIMIT_THRESHOLD: u64 = 90; // 90%
    (gas_used * 100) / SOROBAN_GAS_LIMIT >= NEAR_LIMIT_THRESHOLD
}
