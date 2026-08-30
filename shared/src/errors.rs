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

    // --- Budget (40-49) ---
    BudgetExceeded = 20,
    BudgetFrozen = 21,
    BudgetArchived = 22,
    AssetNotAuthorized = 23,
    BudgetExpired = 24,

    // --- Wallet (50-59) ---
    WalletFrozen = 25,
    WalletArchived = 26,
    WalletPaused = 27,
    InvalidState = 28,

    // --- Multisig / approvals (60-69) ---
    ThresholdNotMet = 29,
    AlreadySigned = 30,
    NotASigner = 31,
    InvalidThreshold = 32,
    TimeLocked = 33,
    TooManySigners = 34,
    /// A sub-call within a batch failed; the entire batch reverted atomically.
    BatchCallFailed = 35,
    /// Batch nonce is not strictly greater than the last used nonce (replay).
    InvalidNonce = 68,
    /// A signer weight outside `[1, MAX_SIGNER_WEIGHT]` was supplied.
    InvalidSignerWeight = 69,
    InvalidNonce = 36,
    /// A signer with zero (or otherwise invalid) voting weight was supplied.
    InvalidSignerWeight = 37,
    /// Accumulated approval weight is below the configured threshold.
    InsufficientWeight = 38,

    // --- Proposal (70-79) ---
    ProposalExpired = 39,
    InvalidProposalState = 40,
    ProposalNotApproved = 41,
    NotAnApprover = 42,
    CancellationWindowClosed = 43,
    MathOverflow = 44,
    DivisionByZero = 45,

    // --- Escrow (80-89) ---
    EscrowExpired = 46,
    TimeLockActive = 47,
}
