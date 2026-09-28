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
    /// A proposed spend would breach a per-asset spending allowance.
    PolicyAllowanceExceeded = 26,

    // --- Registry (30-39) ---
    /// The registry's emergency circuit breaker is engaged (REGISTRY_PAUSED).
    /// Every state-mutating registry interaction — module registration and
    /// removal, role administration, version records, WASM approvals, and
    /// registry-gated upgrades — short-circuits with this code until a protocol
    /// administrator unpauses it. Read-only lookups deliberately stay available
    /// so operators can inspect protocol state during an incident. Use the
    /// [`Error::RegistryPaused`] alias when reporting the circuit breaker; the
    /// legacy name is retained so existing clients keep decoding code 30.
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
    /// The registry's designated emergency-circuit-breaker code.
    ///
    /// This is an alias for [`Error::RegistryFrozen`], not a distinct variant:
    /// the protocol's error table already sits at Stellar's hard limit of 50
    /// `ScSpecUdtUnionCaseV0` entries, so the registry's single halt code (30)
    /// serves both the organization freeze and the new admin pause. Exposing it
    /// under the pause name lets contracts and clients speak in the circuit
    /// breaker's terms while off-chain decoders keep seeing the stable code 30.
    #[allow(non_upper_case_globals)]
    pub const RegistryPaused: Error = Error::RegistryFrozen;
}
