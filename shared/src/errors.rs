//! Deterministic, protocol-wide error codes.
//!
//! Every contract returns variants of this single enum so that off-chain
//! consumers (the Astroid API, SDK and dashboard) can map a stable `u32` code
//! to a meaningful message. Numeric values are grouped by domain and MUST NOT
//! be reordered or reused once released — they are part of the public ABI.
//!
//! The `#[contracterror]` derive caps the number of variants at 50, so new
//! error codes must reuse an existing variant or the enum must be pruned.

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
    InsufficientFunds = 10,
    Overflow = 11,
    Underflow = 12,
    InvalidAmount = 13,
    MathOverflow = 14,
    DivisionByZero = 15,

    // --- Policy (20-29) ---
    PolicyDenied = 20,
    EmergencyLock = 22,
    PolicyRecipientRestricted = 23,
    PolicyMerchantBlocked = 24,
    PolicyCategoryRestricted = 25,
    /// The asset is not in the organization's whitelist.
    AssetNotWhitelisted = 26,

    // --- Registry (30-39) ---
    RegistryFrozen = 30,
    ModuleDeprecated = 31,

    // --- Budget (40-49) ---
    BudgetExceeded = 40,
    BudgetFrozen = 41,
    BudgetArchived = 42,
    AssetNotAuthorized = 43,
    BudgetExpired = 44,

    // --- Wallet (50-59) ---
    WalletFrozen = 50,
    WalletArchived = 51,
    WalletPaused = 52,
    InvalidState = 53,

    // --- Multisig / approvals (60-69) ---
    ThresholdNotMet = 60,
    AlreadySigned = 61,
    NotASigner = 62,
    InvalidThreshold = 63,
    TimeLocked = 64,
    TooManySigners = 65,
    /// A sub-call within a batch failed; the entire batch reverted atomically.
    BatchCallFailed = 66,
    /// Batch nonce is not strictly greater than the last used nonce (replay).
    InvalidNonce = 67,
    /// A signer with zero (or otherwise invalid) voting weight was supplied.
    InvalidSignerWeight = 68,
    /// Accumulated approval weight is below the configured threshold.
    InsufficientWeight = 69,

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
    CancellationWindowClosed = 76,

    // --- Escrow (80-89) ---
    EscrowExpired = 80,
    TimeLockActive = 81,
}
