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
    // --- Generic / lifecycle (1-6) ---
    NotFound = 1,
    AlreadyExists = 2,
    Unauthorized = 3,
    InvalidInput = 4,
    NotInitialized = 5,
    AlreadyInitialized = 6,

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
    PolicyPaused = 26,

    // --- Registry (30-39) ---
    RegistryFrozen = 30,
    ModuleDeprecated = 31,

    // --- Budget (40-44) ---
    BudgetExceeded = 40,
    BudgetFrozen = 41,
    BudgetArchived = 42,
    AssetNotAuthorized = 43,
    BudgetExpired = 44,

    // --- Wallet (50-53) ---
    WalletFrozen = 50,
    WalletArchived = 51,
    WalletPaused = 52,
    InvalidState = 53,

    // --- Multisig / approvals (61-71) ---
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
    /// Accumulated approval weight is below the configured threshold, or a
    /// signer was supplied with an invalid (zero) voting weight.
    InsufficientWeight = 69,
    /// A timelocked governance change was executed before its delay elapsed.
    TimelockNotExpired = 70,
    /// A caller without governance rights attempted to modify signers,
    /// weights or the threshold.
    UnauthorizedModification = 71,

    // --- Proposal (72-79) ---
    ProposalExpired = 72,
    InvalidProposalState = 73,
    ProposalNotApproved = 74,
    NotAnApprover = 75,
    CancellationWindowClosed = 76,
    /// A prerequisite proposal has not executed, so the dependent proposal may
    /// not execute yet.
    PrerequisiteNotMet = 77,
    /// A declared dependency would close a cycle in the dependency graph.
    CircularDependencyDetected = 78,

    // --- Escrow (80-81) ---
    EscrowExpired = 80,
    TimeLockActive = 81,

    // --- Treasury allowances (83-85) ---
    AllowanceExceeded = 83,
    AllowanceExpired = 84,
    AllowanceNotFound = 85,
}
