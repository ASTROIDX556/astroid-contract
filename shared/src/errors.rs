//! Deterministic, protocol-wide error codes.
//!
//! Every contract returns variants of this single enum so that off-chain
//! consumers (the Astroid API, SDK and dashboard) can map a stable `u32` code
//! to a meaningful message. Numeric values are grouped by domain and MUST NOT
//! be reordered or reused once released — they are part of the public ABI.
//!
//! Because all eight contracts share this one enum, "which code does a given
//! contract return" is a single lookup with no per-contract overrides to drift.
//! Three invariants keep the mapping deterministic, and each is enforced by a
//! test in `shared/src/test.rs`:
//!
//! 1. **Explicit and unique** — every variant carries a hand-written
//!    discriminant, and no two variants share a code.
//! 2. **Non-overlapping domains** — each contract's codes occupy a distinct
//!    numeric range, so a code can be attributed to exactly one contract.
//! 3. **Never reused** — a retired code stays empty forever, so a stale
//!    integrator can never decode a fresh failure as a retired meaning.
//!
//! The protocol-wide table deliberately holds more cases than Soroban's
//! `#[contracterror]` spec admits (`VecM<.., 50>`), so the enum is annotated
//! `#[contracterror(export = false)]` to skip only the optional `contractspecv0`
//! metadata section; every code, its name and its numeric value are unaffected,
//! and the conversions to [`soroban_sdk::Error`] remain derived. Contract-specific
//! codes that do not belong in the shared numeric bands live in their own tables
//! ([`BudgetError`], [`MilestoneError`]).

use soroban_sdk::contracterror;

// `export = false`: the spec XDR for an error enum is limited to 50 cases
// (`ScSpecUdtErrorEnumV0.cases: VecM<_, 50>`), while the workspace references
// more than 50 distinct codes, so spec generation would not compile. Only the
// optional `contractspecv0` metadata section is skipped — every code, its
// name and its numeric value are unaffected.
#[contracterror(export = false)]
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
    /// CIRCULAR_UPGRADE: a module upgrade would move a module's pointer onto
    /// the implementation it already runs, or back onto one it has already left
    /// — closing a loop in the upgrade path instead of advancing it (Issue #249).
    /// Distinct from [`Error::InvalidInput`] so deployment tooling that walks
    /// upgrade paths can tell a cycle apart from a malformed request and stop
    /// walking rather than retrying.
    CircularUpgrade = 32,

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

    // --- Wallet (50-54) ---
    WalletFrozen = 50,
    WalletArchived = 51,
    WalletPaused = 52,
    InvalidState = 53,
    /// RATE_LIMIT_EXCEEDED: an outbound transaction would exceed the wallet's
    /// configured rate limit (maximum outbound volume and/or transaction count
    /// within the active sliding window). Nothing moves; the spend may succeed
    /// once earlier activity ages out of the window.
    RateLimitExceeded = 54,

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
    // 70 is unassigned: the multisig block resumes at 90 for the weights the
    // governance flow reports separately.
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

impl Error {
    /// Every variant the protocol can report, in the order the enum declares
    /// them. The audit walks this list, so a variant added to (or removed from)
    /// the enum without a matching entry fails `error_code_table_is_frozen`.
    pub const ALL: [Error; 52] = [
        // --- Generic / lifecycle (1-6) ---
        Error::NotFound,
        Error::AlreadyExists,
        Error::Unauthorized,
        Error::InvalidInput,
        Error::NotInitialized,
        Error::AlreadyInitialized,
        // --- Value / arithmetic (10-12) ---
        Error::InsufficientFunds,
        Error::Overflow,
        Error::InvalidAmount,
        // --- Policy (20-29) ---
        Error::PolicyDenied,
        Error::EmergencyLock,
        Error::PolicyRecipientRestricted,
        Error::PolicyMerchantBlocked,
        Error::PolicyCategoryRestricted,
        Error::VelocityLimitExceeded,
        // --- Registry (30-39) ---
        Error::RegistryFrozen,
        Error::ModuleDeprecated,
        Error::CircularUpgrade,
        // --- Budget (40-44) ---
        Error::BudgetExceeded,
        Error::BudgetFrozen,
        Error::BudgetArchived,
        Error::AssetNotAuthorized,
        Error::BudgetExpired,
        // --- Wallet (50-54) ---
        Error::WalletFrozen,
        Error::WalletArchived,
        Error::WalletPaused,
        Error::InvalidState,
        Error::RateLimitExceeded,
        // --- Multisig / approvals (61-69, 90-92) ---
        Error::ThresholdNotMet,
        Error::AlreadySigned,
        Error::NotASigner,
        Error::InvalidThreshold,
        Error::TooManySigners,
        Error::BatchCallFailed,
        Error::InvalidNonce,
        Error::InvalidSignerWeight,
        Error::InsufficientWeight,
        Error::TimelockNotExpired,
        Error::UnauthorizedModification,
        // --- Proposal (71-79) ---
        Error::ProposalExpired,
        Error::InvalidProposalState,
        Error::ProposalNotApproved,
        Error::NotAnApprover,
        Error::CancellationWindowClosed,
        Error::PrerequisiteNotMet,
        Error::CircularDependencyDetected,
        // --- Escrow (80-82) ---
        Error::EscrowExpired,
        Error::TimeLockActive,
        Error::GraceActive,
        // --- Treasury (83-85) ---
        Error::AllowanceExceeded,
        Error::AllowanceExpired,
        Error::TreasuryPaused,
    ];

    /// The `u32` code this variant carries on the wire.
    ///
    /// Equivalent to the `#[repr(u32)]` discriminant and to the code embedded
    /// in the [`soroban_sdk::Error`] produced by `From<Error>`, so this is the
    /// exact value an off-chain consumer sees. Note that `0` is reserved: the
    /// host reports a contract error of `0` as "no error", so no variant may
    /// ever take that value.
    pub const fn code(self) -> u32 {
        self as u32
    }
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

/// Milestone-approval errors, kept separate from the protocol-wide [`Error`]
/// enum so the escrow's milestone state machine can report dedicated,
/// deterministic codes without pushing the canonical table past Soroban's
/// 50-variant ceiling (the same reason [`BudgetError`] exists).
///
/// Codes that already belong to the canonical table are mirrored here with
/// their exact wire value, so a milestone refusal that is really a generic
/// failure — an unknown escrow, a non-arbiter approving, a terminal escrow —
/// still decodes to the number an off-chain consumer already knows. Only
/// [`MilestoneError::InvalidMilestone`] (86) and
/// [`MilestoneError::MilestoneAlreadyCompleted`] (87) extend the escrow band
/// (80-82); `86`/`87` are the next free slots and are never reused.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum MilestoneError {
    /// The referenced escrow does not exist, or the escrow has no milestone
    /// schedule (agent passed a plain escrow to a milestone entrypoint).
    NotFound = 1,
    /// A caller without milestone-review rights attempted an approval, a
    /// dispute or a resolution.
    Unauthorized = 3,
    /// A malformed milestone request (e.g. an unknown index in a call that
    /// does not reach the state machine).
    InvalidInput = 4,
    /// Checked arithmetic on milestone amounts overflowed or divided by zero.
    Overflow = 11,
    /// A milestone payout amount was not strictly positive.
    InvalidAmount = 12,
    /// The escrow is not in a state that permits this milestone transition
    /// (for example it has already been refunded, or the whole schedule was
    /// cancelled).
    InvalidState = 53,
    /// INVALID_MILESTONE: the requested milestone does not exist on the escrow,
    /// the index was not found, or the milestone is currently disputed and
    /// cannot be approved.
    InvalidMilestone = 86,
    /// MILESTONE_ALREADY_COMPLETED: the milestone has already been approved and
    /// paid out; it cannot be approved a second time.
    MilestoneAlreadyCompleted = 87,
}

impl MilestoneError {
    /// The `u32` code this variant carries on the wire, identical to the value
    /// an off-chain consumer reads from a failed transaction.
    pub const fn code(self) -> u32 {
        self as u32
    }
}

/// Every code the milestone-specific [`MilestoneError`] table can report, in
/// declaration order. Kept as a literal so a renumber or a reissued slot is
/// caught by `milestone_error_codes_are_frozen` rather than passing silently.
pub const MILESTONE_ERROR_CODES: [u32; 8] = [1, 3, 4, 11, 12, 53, 86, 87];

impl From<Error> for MilestoneError {
    fn from(error: Error) -> Self {
        match error {
            Error::NotFound => Self::NotFound,
            Error::Unauthorized => Self::Unauthorized,
            Error::InvalidInput => Self::InvalidInput,
            Error::Overflow => Self::Overflow,
            Error::InvalidAmount => Self::InvalidAmount,
            Error::InvalidState => Self::InvalidState,
            _ => Self::InvalidInput,
        }
    }
}

impl From<MilestoneError> for Error {
    fn from(error: MilestoneError) -> Self {
        match error {
            MilestoneError::NotFound => Self::NotFound,
            MilestoneError::Unauthorized => Self::Unauthorized,
            MilestoneError::InvalidInput => Self::InvalidInput,
            MilestoneError::Overflow => Self::Overflow,
            MilestoneError::InvalidAmount => Self::InvalidAmount,
            MilestoneError::InvalidState => Self::InvalidState,
            // The two milestone-specific codes have no canonical equivalent, so
            // they collapse onto the closest generic failure when a caller asks
            // for the protocol-wide error.
            MilestoneError::InvalidMilestone => Self::InvalidInput,
            MilestoneError::MilestoneAlreadyCompleted => Self::InvalidState,
        }
    }
}
