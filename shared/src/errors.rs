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
    PolicyHashMismatch = 12,
    EmergencyLock = 13,
    PolicyRecipientRestricted = 14,
    PolicyMerchantBlocked = 15,
    PolicyCategoryRestricted = 16,
    /// The asset is not in the organization's whitelist.
    AssetNotWhitelisted = 17,
    FeeLimitExceeded = 18,

    // --- Registry (30-39) ---
    RegistryFrozen = 19,
    ModuleDeprecated = 20,

    // --- Budget (40-49) ---
    BudgetExceeded = 21,
    BudgetFrozen = 22,
    BudgetArchived = 23,
    AssetNotAuthorized = 24,
    BudgetExpired = 25,

    // --- Wallet (50-59) ---
    WalletFrozen = 26,
    WalletArchived = 27,
    WalletPaused = 28,
    InvalidState = 29,

    // --- Multisig / approvals (60-69) ---
    ThresholdNotMet = 30,
    AlreadySigned = 31,
    NotASigner = 32,
    InvalidThreshold = 33,
    TimeLocked = 34,
    TooManySigners = 35,
    /// A sub-call within a batch failed; the entire batch reverted atomically.
    BatchCallFailed = 36,
    /// Batch nonce is not strictly greater than the last used nonce (replay).
    InvalidNonce = 37,
    /// A signer with zero (or otherwise invalid) voting weight was supplied.
    InvalidSignerWeight = 38,
    /// Accumulated approval weight is below the configured threshold.
    InsufficientWeight = 39,

    // --- Proposal (70-79) ---
    ProposalExpired = 70,
    InvalidProposalState = 71,
    ProposalNotApproved = 72,
    NotAnApprover = 73,
    /// A prerequisite proposal has not executed, so the dependent proposal may
    /// not execute yet.
    PrerequisiteNotMet = 74,
    /// A declared dependency would close a cycle in the dependency graph.
    CircularDependencyDetected = 75,
    CancellationWindowClosed = 74,
    MathOverflow = 75,
    DivisionByZero = 76,
    ProposalExpired = 39,
    InvalidProposalState = 40,
    ProposalNotApproved = 41,
    NotAnApprover = 42,
    CancellationWindowClosed = 43,
    MathOverflow = 44,
    DivisionByZero = 45,

    // --- Escrow (80-89) ---
    EscrowExpired = 47,
    TimeLockActive = 48,

    // --- Interface versioning (95-99) ---
    /// The remote contract's interface version is older than the minimum
    /// required by the caller, or otherwise incompatible.
    InterfaceVersionMismatch = 95,
}
