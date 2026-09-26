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
    // 25 (`AssetNotWhitelisted`) retired: it meant the same thing as
    // `AssetNotAuthorized` (43) and was consolidated into it, freeing a slot
    // for `TreasuryPaused`. The value is never reused.
    // 26 (`PolicyAllowanceExceeded`) retired: it meant the same thing as
    // `AllowanceExceeded` (83) — a spend would breach a per-asset allowance —
    // and was consolidated into it, freeing a slot for
    // `VelocityLimitExceeded`. The value is never reused.
    /// VELOCITY_LIMIT_EXCEEDED: an outbound spend would push the volume moved
    /// out of a wallet within its rolling velocity window past the configured
    /// ceiling. Nothing moves; the spend may succeed once older volume ages
    /// out of the window.
    VelocityLimitExceeded = 27,

    // --- Registry (30-39) ---
    RegistryFrozen = 30,
    ModuleDeprecated = 31,

    // --- Budget (40-44) ---
    BudgetExceeded = 40,
    BudgetFrozen = 41,
    BudgetArchived = 42,
    /// The named token contract is not on the organization's approved-asset
    /// list. The canonical "asset not approved" code: consulted by the
    /// treasury whitelist, the budget's asset registry and the policy
    /// contract's per-policy asset whitelist alike (it also covers the value
    /// formerly reported as `AssetNotWhitelisted`).
    AssetNotAuthorized = 43,
    BudgetExpired = 44,

    // --- Wallet (50-53) ---
    WalletFrozen = 50,
    WalletArchived = 51,
    WalletPaused = 52,
    InvalidState = 53,

    // --- Multisig / approvals (61-69, 90-92) ---
    ThresholdNotMet = 61,
    AlreadySigned = 62,
    NotASigner = 63,
    InvalidThreshold = 64,
    TooManySigners = 66,
    /// A sub-call within a batch failed; the entire batch reverted atomically.
    BatchCallFailed = 67,
    /// Batch nonce is not strictly greater than the last used nonce (replay).
    InvalidNonce = 68,
    /// A signer with zero (or otherwise invalid) voting weight was supplied.
    InvalidSignerWeight = 69,
    /// Accumulated approval weight is below the configured threshold.
    InsufficientWeight = 90,
    /// A timelocked action was executed before its delay elapsed. Reported by
    /// the multisig when a governance change runs ahead of its delay, and by
    /// the escrow (Issue #332) when a release attempt fires before the
    /// escrow's own release clock — the ledger timestamp is still short of the
    /// `cliff_time`, or on a linear schedule the requested amount exceeds what
    /// has vested so far. This is the distinct early-release code: the
    /// beneficiary-facing `withdraw` / `claim` paths report
    /// [`Error::TimeLockActive`] instead. (A dedicated new variant is not
    /// possible: this table is already at the 50-case spec limit.)
    TimelockNotExpired = 91,
    /// A caller without governance rights attempted to modify signers,
    /// weights or the threshold.
    UnauthorizedModification = 92,

    // --- Proposal (71-79) ---
    ProposalExpired = 71,
    InvalidProposalState = 72,
    ProposalNotApproved = 73,
    NotAnApprover = 74,
    CancellationWindowClosed = 75,
    /// A prerequisite proposal has not executed, so the dependent proposal may
    /// not execute yet.
    PrerequisiteNotMet = 78,
    /// A declared dependency would close a cycle in the dependency graph.
    CircularDependencyDetected = 79,

    // --- Escrow (80-82) ---
    EscrowExpired = 80,
    TimeLockActive = 81,
    GraceActive = 82,

    // --- Treasury (83-85) ---
    /// A spend would breach a per-asset allowance: the treasury's per-agent
    /// withdrawal allowance or a policy's per-asset spending allowance.
    AllowanceExceeded = 83,
    AllowanceExpired = 84,
    /// The treasury's emergency circuit breaker is engaged
    /// (TREASURY_PAUSED): every outbound disbursement or transfer is refused
    /// with this code until the guardian or multisig unpauses it. Inbound
    /// deposits deliberately stay open so recovery funding can still arrive.
    TreasuryPaused = 85,
}

/// Budget spend errors, kept separate from the protocol-wide error enum so
/// budget-specific timing errors do not exceed Soroban's 50-variant limit.
/// Existing codes match [`Error`] exactly; code 45 is the new scheduled-start
/// denial.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum BudgetError {
    NotFound = 1,
    Unauthorized = 3,
    InvalidInput = 4,
    Overflow = 11,
    InvalidAmount = 12,
    BudgetExceeded = 40,
    BudgetFrozen = 41,
    BudgetArchived = 42,
    AssetNotAuthorized = 43,
    BudgetExpired = 44,
    BudgetNotActive = 45,
}

impl From<Error> for BudgetError {
    fn from(error: Error) -> Self {
        match error {
            Error::NotFound => Self::NotFound,
            Error::Unauthorized => Self::Unauthorized,
            Error::InvalidInput => Self::InvalidInput,
            Error::Overflow => Self::Overflow,
            Error::InvalidAmount => Self::InvalidAmount,
            Error::BudgetExceeded => Self::BudgetExceeded,
            Error::BudgetFrozen => Self::BudgetFrozen,
            Error::BudgetArchived => Self::BudgetArchived,
            Error::AssetNotAuthorized => Self::AssetNotAuthorized,
            Error::BudgetExpired => Self::BudgetExpired,
            Error::InvalidState => Self::InvalidInput,
            _ => Self::InvalidInput,
        }
    }
}

impl From<BudgetError> for Error {
    fn from(error: BudgetError) -> Self {
        match error {
            BudgetError::NotFound => Self::NotFound,
            BudgetError::Unauthorized => Self::Unauthorized,
            BudgetError::InvalidInput => Self::InvalidInput,
            BudgetError::Overflow => Self::Overflow,
            BudgetError::InvalidAmount => Self::InvalidAmount,
            BudgetError::BudgetExceeded => Self::BudgetExceeded,
            BudgetError::BudgetFrozen => Self::BudgetFrozen,
            BudgetError::BudgetArchived => Self::BudgetArchived,
            BudgetError::AssetNotAuthorized => Self::AssetNotAuthorized,
            BudgetError::BudgetExpired | BudgetError::BudgetNotActive => Self::BudgetExpired,
        }
    }
}
