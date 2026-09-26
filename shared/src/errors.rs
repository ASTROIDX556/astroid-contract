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
//!    discriminant (the `#[contracterror]` expansion rejects implicit ones), and
//!    no two variants share a code.
//! 2. **Non-overlapping domains** — each contract's codes occupy a distinct
//!    numeric range, so a code can be attributed to exactly one contract.
//! 3. **Never reused** — a retired code stays empty forever, so a stale
//!    integrator can never decode a fresh failure as a retired meaning.

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
    /// A proposed spend would breach a per-asset spending allowance.
    PolicyAllowanceExceeded = 26,
    // 27-29 are unassigned: the policy block stops at 26, and 30 starts the
    // registry block.

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
    // 70 is unassigned: the multisig block resumes at 90 for the weights the
    // governance flow reports separately.
    /// Accumulated approval weight is below the configured threshold.
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
    AllowanceExceeded = 83,
    AllowanceExpired = 84,
    /// The treasury's emergency circuit breaker is engaged
    /// (TREASURY_PAUSED): every outbound disbursement or transfer is refused
    /// with this code until the guardian or multisig unpauses it. Inbound
    /// deposits deliberately stay open so recovery funding can still arrive.
    TreasuryPaused = 85,
}

impl Error {
    /// Every variant of the table, grouped by domain in the same order as the
    /// enum itself.
    ///
    /// This is the enumeration the error-code audit in `shared/src/test.rs`
    /// walks. **A newly added variant must also be appended to its block here**
    /// — the audit can only check what it can reach. The bands are not globally
    /// sorted (the multisig approvals band, 90-92, is declared before the
    /// proposal band, 71-79, to match the enum), but each block is ascending.
    pub const ALL: [Error; 50] = [
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
        // --- Policy (20-27) ---
        Error::PolicyDenied,
        Error::EmergencyLock,
        Error::PolicyRecipientRestricted,
        Error::PolicyMerchantBlocked,
        Error::PolicyCategoryRestricted,
        Error::PolicyAllowanceExceeded,
        // --- Registry (30-39) ---
        Error::RegistryFrozen,
        Error::ModuleDeprecated,
        // --- Budget (40-44) ---
        Error::BudgetExceeded,
        Error::BudgetFrozen,
        Error::BudgetArchived,
        Error::AssetNotAuthorized,
        Error::BudgetExpired,
        // --- Wallet (50-53) ---
        Error::WalletFrozen,
        Error::WalletArchived,
        Error::WalletPaused,
        Error::InvalidState,
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
