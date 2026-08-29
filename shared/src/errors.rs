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
    FeeLimitExceeded = 14,
    PolicyMerchantBlocked = 15,
    PolicyCategoryRestricted = 16,

    // --- Registry (30-39) ---
    RegistryFrozen = 17,

    // --- Budget (40-49) ---
    BudgetExceeded = 18,
    BudgetFrozen = 19,
    BudgetArchived = 20,
    AssetNotAuthorized = 21,
    BudgetExpired = 22,

    // --- Wallet (50-59) ---
    WalletFrozen = 23,
    WalletArchived = 24,
    WalletPaused = 25,
    InvalidState = 26,

    // --- Multisig / approvals (60-69) ---
    ThresholdNotMet = 27,
    AlreadySigned = 28,
    NotASigner = 29,
    InvalidThreshold = 30,
    TimeLocked = 31,
    TooManySigners = 32,
    /// A sub-call within a batch failed; the entire batch reverted atomically.
    BatchCallFailed = 33,
    /// Batch nonce is not strictly greater than the last used nonce (replay).
    InvalidNonce = 34,
    /// A signer with zero (or otherwise invalid) voting weight was supplied.
    InvalidSignerWeight = 35,
    /// Accumulated approval weight is below the configured threshold.
    InsufficientWeight = 36,

    // --- Proposal (70-79) ---
    ProposalExpired = 37,
    InvalidProposalState = 38,
    ProposalNotApproved = 39,
    NotAnApprover = 40,
    CancellationWindowClosed = 41,
    MathOverflow = 42,
    DivisionByZero = 43,

    // --- Escrow (80-89) ---
    EscrowExpired = 44,
    TimeLockActive = 45,
}
