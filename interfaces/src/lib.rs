#![no_std]
//! # astroid-interfaces
//!
//! Shared interface traits for the Astroid protocol. Each trait is annotated
//! with [`soroban_sdk::contractclient`], which generates a strongly-typed
//! cross-contract client (e.g. `PolicyClient`, `BudgetClient`, `RegistryClient`).
//!
//! - The **caller** side (e.g. the Treasury contract) imports the generated
//!   client to invoke another contract with compile-checked signatures.
//! - On the **callee** side, a contract may implement the trait inside its
//!   `#[contractimpl]` block or expose matching entrypoints from an existing
//!   `#[contractimpl]` block.
//!
//! This is how Astroid keeps the dependency graph acyclic — `Registry → others`
//! and `Treasury → {Policy, Budget}` — without any contract crate depending on
//! another contract crate at compile time.
//!
//! ## Which contract implements which trait
//!
//! | Trait                      | Served by                | Generated client     |
//! |----------------------------|--------------------------|----------------------|
//! | [`RegistryInterface`]      | `astroid-registry`       | `RegistryClient`     |
//! | [`WalletInterface`]        | `astroid-wallet`         | `WalletClient`       |
//! | [`PolicyInterface`]        | `astroid-policy`         | `PolicyClient`       |
//! | [`BudgetInterface`]        | `astroid-budget`         | `BudgetClient`       |
//! | [`TreasuryInterface`]      | `astroid-treasury`       | `TreasuryClient`     |
//! | [`MultisigInterface`]      | `astroid-multisig`       | `MultisigClient`     |
//! | [`ProposalInterface`]      | `astroid-proposal`       | `ProposalClient`     |
//! | [`EscrowInterface`]        | `astroid-escrow`         | `EscrowClient`       |
//! | [`UpgradeableInterface`]   | all eight contracts      | `UpgradeableClient`  |
//!
//! Every fallible method returns the canonical [`Error`] so a cross-contract
//! `try_*` call always decodes into the same stable `u32` code table. The
//! integration crate (`tests/src/interface_compliance.rs`) asserts each row of
//! this table at compile time (trait bounds) and at runtime (every deployed
//! contract answers through the shared client).

pub mod proposal;
pub mod upgrade;

pub use proposal::{ProposalClient, ProposalInterface, ProposalState};

#[cfg(test)]
mod test;

use astroid_shared::errors::{BudgetError, Error};
use astroid_shared::types::{ModuleId, ModuleInfo, ModuleKind, WalletData};
use soroban_sdk::{contractclient, Address, Bytes, BytesN, Env, String, Vec};

/// Version of the interface surface declared in this crate. Bump it whenever a
/// trait gains, loses or changes a method — or a new trait is declared, as
/// [`EscrowInterface`] was (Issue #293) — so off-chain clients built against an
/// older definition can detect the drift.
pub const INTERFACE_VERSION: u32 = 3;

/// Wallet operations and views available to cross-contract callers.
#[contractclient(name = "WalletClient")]
pub trait WalletInterface {
    /// Create a wallet owned by `owner` and return its identifier.
    fn create_wallet(env: Env, owner: Address) -> Result<u64, Error>;

    /// Deposit `amount` of `asset` from `from` into `wallet_id`.
    fn deposit(
        env: Env,
        wallet_id: u64,
        from: Address,
        asset: Address,
        amount: i128,
    ) -> Result<(), Error>;

    /// Transfer `amount` of `asset` from `wallet_id` to `to`.
    fn transfer(
        env: Env,
        caller: Address,
        wallet_id: u64,
        to: Address,
        asset: Address,
        amount: i128,
    ) -> Result<(), Error>;

    /// Withdraw `amount` of `asset` from `wallet_id` to its owner.
    fn withdraw(
        env: Env,
        caller: Address,
        wallet_id: u64,
        asset: Address,
        amount: i128,
    ) -> Result<(), Error>;

    /// Read a wallet's owner and lifecycle state.
    fn get_wallet(env: Env, wallet_id: u64) -> Result<WalletData, Error>;

    /// Read the wallet's internal balance for `asset`.
    fn balance(env: Env, wallet_id: u64, asset: Address) -> i128;

    /// Whether the wallet contract's emergency circuit breaker is engaged.
    fn is_paused(env: Env) -> bool;
}

/// Registry lookup surface. The registry is the protocol's source of truth for
/// where each module/contract lives and who owns it (PRD Doc 7 §Registry).
#[contractclient(name = "RegistryClient")]
pub trait RegistryInterface {
    /// Resolve a registered module address by organization + kind.
    fn lookup(env: Env, org: String, kind: ModuleKind) -> Result<Address, Error>;

    /// Verify that `owner` is the recorded owner of `org`.
    fn verify_owner(env: Env, org: String, owner: Address) -> Result<bool, Error>;

    /// Resolve several module registrations in one call.
    ///
    /// `result[i]` answers `ids[i]`: the output has the input's length and
    /// order, duplicates included. An unregistered id yields `None` rather than
    /// failing the batch; a deprecated one is reported with `deprecated: true`.
    /// At most `MAX_REGISTRY_BATCH` ids may be requested; a longer list fails
    /// with `InvalidInput` before any record is read. An empty list returns an
    /// empty list.
    fn get_modules_batch(env: Env, ids: Vec<ModuleId>) -> Result<Vec<Option<ModuleInfo>>, Error>;

    /// Whether the registry's emergency circuit breaker is engaged.
    ///
    /// While `true`, every state-mutating registry entrypoint fails with
    /// `Error::RegistryPaused`; read-only lookups stay available for incident
    /// inspection. Cross-contract upgrades observe the pause too, because
    /// `is_wasm_approved` reports no hash as approved while paused.
    fn is_paused(env: Env) -> bool;
}

/// Policy verification surface. Contracts call `check_transfer` to have a spend
/// validated against the active, hash-verified policy (PRD Doc 7 §Policy).
#[contractclient(name = "PolicyClient")]
pub trait PolicyInterface {
    /// Returns `Ok(())` if a transfer of `amount` of `asset` to `recipient` is
    /// permitted by the policy identified by `policy_id`, else a policy error.
    fn check_transfer(
        env: Env,
        policy_id: String,
        asset: Address,
        recipient: Address,
        amount: i128,
    ) -> Result<(), Error>;
}

/// Budget enforcement surface. Contracts call `consume` to atomically debit a
/// remaining allocation, which reverts with `BudgetExceeded` when insufficient
/// (PRD Doc 7 §Budget).
#[contractclient(name = "BudgetClient")]
pub trait BudgetInterface {
    /// Debit `amount` from the budget's remaining allocation. `caller` must be
    /// the authorized consumer (the treasury/owner). Returns the new remaining.
    fn consume(
        env: Env,
        caller: Address,
        budget_id: String,
        amount: i128,
    ) -> Result<i128, BudgetError>;

    /// Credit `amount` back to the budget (e.g. a refunded or cancelled spend).
    /// `caller` must be the budget owner and `amount` may not exceed what has
    /// been spent. Returns the new remaining allocation.
    fn release(env: Env, caller: Address, budget_id: String, amount: i128) -> Result<i128, Error>;

    /// Read the remaining allocation for a budget.
    fn remaining(env: Env, budget_id: String) -> Result<i128, Error>;
}

/// Gas usage telemetry surface. Contracts may implement this trait to expose
/// resource consumption metrics for off-chain cost estimation and monitoring.
///
/// The telemetry interface is optional — contracts that do not implement it
/// still function normally, but callers can use these view methods to read
/// accumulated cost data for budgeting and pre-flight checks.
#[contractclient(name = "TelemetryClient")]
pub trait TelemetryInterface {
    /// Record gas consumption for a named operation.
    ///
    /// # Arguments
    /// * `operation` - Human-readable name (e.g. "transfer", "mint")
    /// * `gas_used` - Gas units consumed during the operation
    /// * `storage_bytes` - Bytes of storage read/written during the operation
    fn record_cost(
        env: Env,
        operation: String,
        gas_used: u64,
        storage_bytes: u64,
    ) -> Result<(), Error>;

    /// Estimate the gas cost for a hypothetical operation.
    ///
    /// Returns the estimated gas units needed, useful for pre-flight checks
    /// and budget planning before submitting a transaction.
    fn estimate_cost(env: Env, operation: String, storage_bytes: u64) -> Result<u64, Error>;

    /// Read whether the cumulative gas usage is approaching the Soroban limit.
    ///
    /// Returns `true` if recent operations have consumed more than 90% of the
    /// available gas budget, signaling that subsequent operations may fail.
    fn is_near_limit(env: Env) -> Result<bool, Error>;
}

/// Treasury read surface. Lets wallets, proposals and off-chain services query
/// treasury holdings and routing state without depending on the treasury crate
/// (PRD Doc 7 §Treasury).
#[contractclient(name = "TreasuryClient")]
pub trait TreasuryInterface {
    /// Live on-chain balance the treasury holds of `asset`. Fails with
    /// [`Error::AssetNotAuthorized`] when `asset` is not on the approved list.
    fn balance(env: Env, asset: Address) -> Result<i128, Error>;

    /// Whether `asset` is currently approved for routing through the treasury.
    fn is_approved_asset(env: Env, asset: Address) -> bool;

    /// Whether the treasury's emergency circuit breaker is engaged.
    fn is_paused(env: Env) -> bool;
}

/// Multisig verification surface. Other contracts (e.g. the proposal flow) use
/// it to check that a signer set meets the organization's quorum before acting
/// (PRD Doc 7 §Multisig).
#[contractclient(name = "MultisigClient")]
pub trait MultisigInterface {
    /// Verify that `signatories` (each authorizing `payload`) together with
    /// `caller` meet the weighted threshold. Returns the accumulated weight.
    fn verify_threshold(
        env: Env,
        caller: Address,
        signatories: Vec<Address>,
        payload: Bytes,
    ) -> Result<u32, Error>;

    /// Whether `who` is a registered signer.
    fn is_signer(env: Env, who: Address) -> bool;

    /// Voting weight of `who`, or `0` when it is not a registered signer.
    fn get_signer_weight(env: Env, who: Address) -> u32;

    /// The weighted approval threshold currently in force.
    fn get_threshold(env: Env) -> Result<u32, Error>;
}

/// Escrow lifecycle read surface. An escrow holds one party's funds until a
/// release condition, schedule or refund rule is met, so wallets, budgets and
/// off-chain monitors need to ask the escrow contract what it may still pay out
/// without depending on the escrow crate (PRD Doc 7 §Escrow).
///
/// Only primitive answers cross this boundary. An escrow's full record carries
/// the escrow crate's own `#[contracttype]`s, whereas a caller deciding whether
/// to fund, claim, reclaim or merely display an escrow needs the amounts and the
/// state predicates below — so those, and not the record, are what the shared
/// client is for.
#[contractclient(name = "EscrowClient")]
pub trait EscrowInterface {
    /// Number of escrows created so far, i.e. the id the next `create` takes.
    fn escrow_count(env: Env) -> u64;

    /// Timestamp at which the escrow's refund window closes, or `0` when the
    /// window has no upper bound.
    fn refund_window_closes_at(env: Env, id: u64) -> Result<u64, Error>;

    /// Whether the escrow's funds may be reclaimed at the current ledger time:
    /// still held, grace elapsed and refund window still open.
    fn is_refundable(env: Env, id: u64) -> Result<bool, Error>;

    /// Amount claimable right now under the escrow's release schedule.
    fn get_claimable_amount(env: Env, id: u64) -> Result<i128, Error>;

    /// Amount vested so far under the escrow's release schedule.
    fn get_vested_amount(env: Env, id: u64) -> Result<i128, Error>;

    /// Whether the release schedule has matured at the current ledger time.
    fn is_unlocked(env: Env, id: u64) -> Result<bool, Error>;
}

/// Registry-gated upgrade surface shared by every member contract. The
/// behaviour lives in [`upgrade`]; this trait pins the entrypoint signatures so
/// operators can drive an upgrade of any contract through one client.
#[contractclient(name = "UpgradeableClient")]
pub trait UpgradeableInterface {
    /// Runtime version of the shared contract interface.
    fn get_interface_version(env: Env) -> u32;

    /// Record (or rotate) who may upgrade the contract and which registry
    /// authorizes the new code. See [`upgrade::set_authority`].
    fn set_upgrade_authority(
        env: Env,
        caller: Address,
        admin: Address,
        registry: Address,
    ) -> Result<(), Error>;

    /// Read the recorded upgrade authority, or [`Error::NotInitialized`].
    fn get_upgrade_authority(env: Env) -> Result<upgrade::UpgradeAuthority, Error>;

    /// Replace the contract's code with `wasm_hash` once the caller and the
    /// registry approval both check out. See [`upgrade::perform`].
    fn upgrade(env: Env, caller: Address, wasm_hash: BytesN<32>) -> Result<(), Error>;
}
