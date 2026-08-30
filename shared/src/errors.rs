//! Deterministic, protocol-wide error codes.
//!
//! Every contract returns variants of this single enum so that off-chain
//! consumers (the Astroid API, SDK and dashboard) can map a stable `u32` code
//! to a meaningful message. Numeric values are grouped by domain and MUST NOT
//! be reordered or reused once released — they are part of the public ABI.

use soroban_sdk::contracterror;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    // --- Generic / lifecycle (1-9) ---
    NotFound = 1,
    AlreadyExists = 2,
    Unauthorized = 3,
    InvalidInput = 4,
    NotInitialized = 5,
    AlreadyInitialized = 6,

    // --- Value / arithmetic (10-19) ---
    InsufficientFunds = 7,
    Overflow = 8,
    Underflow = 9,
    InvalidAmount = 10,

    // --- Policy (20-29) ---
    PolicyDenied = 11,
    EmergencyLock = 12,
    PolicyRecipientRestricted = 13,
    PolicyMerchantBlocked = 14,
    PolicyCategoryRestricted = 15,
    /// The asset is not in the organization's whitelist.
    AssetNotWhitelisted = 16,
    /// A conditional policy rule denied the transaction.
    RuleDenied = 17,

    // --- Registry (30-39) ---
    RegistryFrozen = 20,
    ModuleDeprecated = 21,

    // --- Budget (40-49) ---
    BudgetExceeded = 22,
    BudgetFrozen = 23,
    BudgetArchived = 24,
    AssetNotAuthorized = 25,
    BudgetExpired = 26,

    // --- Wallet (50-59) ---
    WalletFrozen = 27,
    WalletArchived = 28,
    WalletPaused = 29,
    InvalidState = 30,

    // --- Multisig / approvals (60-69) ---
    ThresholdNotMet = 31,
    AlreadySigned = 32,
    NotASigner = 33,
    InvalidThreshold = 34,
    TimeLocked = 35,
    TooManySigners = 36,
    /// A sub-call within a batch failed; the entire batch reverted atomically.
    BatchCallFailed = 37,
    /// Batch nonce is not strictly greater than the last used nonce (replay).
    InvalidNonce = 38,
    /// A signer with zero (or otherwise invalid) voting weight was supplied.
    InvalidSignerWeight = 39,
    /// Accumulated approval weight is below the configured threshold.
    InsufficientWeight = 40,

    // --- Proposal (70-79) ---
    ProposalExpired = 41,
    InvalidProposalState = 42,
    ProposalNotApproved = 43,
    NotAnApprover = 44,
    CancellationWindowClosed = 45,
    MathOverflow = 46,
    DivisionByZero = 47,

    // --- Escrow (80-89) ---
    EscrowExpired = 48,
    TimeLockActive = 49,

    // --- Dependency tracking ---
    /// A prerequisite proposal has not executed, so the dependent proposal may
    /// not execute yet.
    PrerequisiteNotMet = 50,
    /// A declared dependency would close a cycle in the dependency graph.
    CircularDependencyDetected = 51,

    // --- Interface versioning (95-99) ---
    /// The remote contract's interface version is older than the minimum
    /// required by the caller, or otherwise incompatible.
    InterfaceVersionMismatch = 95,
}
