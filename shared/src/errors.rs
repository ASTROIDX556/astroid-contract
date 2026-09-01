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
    // --- Generic / lifecycle (1-6) ---
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
    // --- Value / arithmetic (10-12) ---
    InsufficientFunds = 10,
    Overflow = 11,
    InvalidAmount = 12,

    // --- Policy (20-27) ---
    PolicyDenied = 20,
    EmergencyLock = 21,
    PolicyRecipientRestricted = 22,
    PolicyMerchantBlocked = 23,
    PolicyCategoryRestricted = 24,
    /// The asset is not in the organization's whitelist.
    AssetNotWhitelisted = 25,
    AssetNotWhitelisted = 25,
    /// A proposed spend would breach a per-asset spending allowance.
    PolicyAllowanceExceeded = 26,

    // --- Registry (30-39) ---
    RegistryFrozen = 30,
    ModuleDeprecated = 31,
    /// System-wide emergency pause: all critical registry operations are halted.
    ContractPaused = 32,

    // --- Budget (40-49) ---
    // --- Budget (40-44) ---
    BudgetExceeded = 40,
    BudgetFrozen = 41,
    BudgetArchived = 42,
    AssetNotAuthorized = 43,
    BudgetExpired = 44,
    VelocityExceeded = 45,

    // --- Treasury (91-99) ---
    PayoutScheduleViolated = 91,

    // --- Wallet (50-59) ---
    // --- Wallet (50-53) ---
    WalletFrozen = 50,
    WalletArchived = 51,
    WalletPaused = 52,
    InvalidState = 53,
    AllowanceExceeded = 54,

    // --- Multisig / approvals (60-69) ---
    InvalidSignature = 60,
    // --- Multisig / approvals (61-69, 90-92) ---
    ThresholdNotMet = 61,
    AlreadySigned = 62,
    NotASigner = 63,
    InvalidThreshold = 64,
    TimeLocked = 65,
    TooManySigners = 66,
    /// A sub-call within a batch failed; the entire batch reverted atomically.
    BatchCallFailed = 67,
    /// Batch nonce is not strictly greater than the last used nonce (replay).
    InvalidNonce = 68,
    /// A signer with zero (or otherwise invalid) voting weight was supplied.
    InvalidSignerWeight = 69,
    /// Accumulated approval weight is below the configured threshold.
    InsufficientWeight = 70,
    InsufficientWeight = 90,
    /// A timelocked governance change was executed before its delay elapsed.
    TimelockNotExpired = 91,
    /// A caller without governance rights attempted to modify signers,
    /// weights or the threshold.
    UnauthorizedModification = 92,

    // --- Proposal (71-79) ---
    ProposalExpired = 71,
    InvalidProposalState = 72,
    ProposalNotApproved = 73,
    NotAnApprover = 74,
    /// The aggregated count of verified approver signatures did not reach the
    /// configured threshold at execution time.
    QuorumNotMet = 75,
    CancellationWindowClosed = 76,

    // --- Escrow (80-89) ---
    ConditionNotMet = 80,
    EscrowNotFunded = 81,
    EscrowExpired = 82,
    InvalidCondition = 83,
    TimeLockActive = 84,

    // --- Treasury (90-99) ---
    /// Accumulated approval weight is below the configured threshold.
    InsufficientWeight = 90,
    /// Treasury is under emergency pause — all operations blocked.
    EmergencyPaused = 91,
    /// Asset is not on the treasury whitelist.
    AssetNotWhitelisted = 92,
}
