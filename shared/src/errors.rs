//! Deterministic, protocol-wide error codes.
//!
//! Every contract returns variants of this single enum so that off-chain
//! consumers (the Astroid API, SDK and dashboard) can map a stable `u32` code
//! to a meaningful message. Numeric values are grouped by domain and MUST NOT
//! be reordered or reused once released — they are part of the public ABI.
//!
//! Because all eight contracts share this one enum, "which code does a given
//! contract return" is a single lookup with no per-contract overrides to drift.
//! Four invariants keep the mapping deterministic, and each is enforced by a
//! test in `shared/src/test.rs`:
//!
//! 1. **Explicit and unique** — every variant carries a hand-written
//!    discriminant, and no two variants share a code.
//! 2. **Non-overlapping domains** — each contract's codes occupy a distinct
//!    numeric range, so a code can be attributed to exactly one contract.
//! 3. **Never reused** — a retired code stays empty forever, so a stale
//!    integrator can never decode a fresh failure as a retired meaning.
//! 4. **Documented and named by convention** — every variant of every error
//!    enum here carries a doc comment explaining what triggers it, and its
//!    published `wire_name()` is `UPPER_SNAKE_CASE` and unique within its
//!    table, which is the form off-chain consumers key their catalogues off.
//!    This one is checked by reading this file's own source at test time
//!    (`error_variants_are_documented`) and by walking each table
//!    (`error_wire_names_are_upper_snake_case_and_unique`), because a missing
//!    doc comment or a mis-spelled name is otherwise invisible to the compiler.
//!
//! The protocol-wide table deliberately holds more cases than Soroban's
//! `#[contracterror]` spec admits (`VecM<.., 50>`), so the enum is annotated
//! `#[contracterror(export = false)]` to skip only the optional `contractspecv0`
//! metadata section; every code, its name and its numeric value are unaffected,
//! and the conversions to [`soroban_sdk::Error`] remain derived. Contract-specific
//! codes that do not belong in the shared numeric bands live in their own tables
//! ([`BudgetError`], [`MilestoneError`]), which are held to the same
//! documentation, naming and uniqueness rules.

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
    /// The record the call refers to does not exist: an unknown escrow, budget,
    /// wallet, policy, proposal, organization, module or version key — or an
    /// operation that revokes or removes something that was never set. Nothing
    /// is created as a side effect of the lookup.
    NotFound = 1,
    /// A create call would overwrite a record that already exists: a duplicate
    /// registration, a re-registered organization, module or policy, a
    /// re-added approver, signer or asset, or a second escrow for an id already
    /// in use. The existing record is left untouched.
    AlreadyExists = 2,
    /// The caller is not the party authorized for this record and did not sign
    /// the required authorization. This is the single role-check code for the
    /// whole protocol: only the owner may spend a budget, only the admin may
    /// register a module, only a listed approver may act on a proposal.
    Unauthorized = 3,
    /// An argument failed validation: a malformed parameter, an empty
    /// identifier, a structurally invalid rule tree or recipient list, or a
    /// value outside the range the entrypoint accepts. The call is rejected
    /// before any state is read or written.
    InvalidInput = 4,
    /// `initialize` has not run, so the instance state this entrypoint needs
    /// (admin, signer set, timelock or guardian) is absent. The contract must
    /// be initialized before the call can be served.
    NotInitialized = 5,
    /// `initialize` was called on a contract that already holds instance
    /// state. Initialization is one-shot: the repeat is refused rather than
    /// silently overwriting the existing admin, signers or configuration.
    AlreadyInitialized = 6,

    // --- Value / arithmetic (10-12) ---
    /// The operation would move more than the source holds: a debit larger than
    /// the recorded balance, a transfer the payer cannot fund, or a release the
    /// escrow, budget or treasury cannot cover. No funds move and no balance
    /// is debited.
    InsufficientFunds = 10,
    /// A checked arithmetic step left the representable range (an `i128`/`u64`
    /// result that wraps, or a narrowing cast that does not fit), so the result
    /// cannot be encoded. Reported instead of wrapping — the release profile
    /// keeps `overflow-checks` on, and all value math goes through the checked
    /// helpers in [`math`](crate::math) rather than panicking.
    Overflow = 11,
    /// The amount is not usable: zero where a strictly positive value is
    /// required, a negative value anywhere, or a payout larger than the balance
    /// or vested schedule that remains. Rejected before the token is called.
    InvalidAmount = 12,

    // --- Policy (20-27) ---
    /// The wallet's active policy refused the spend: the policy is disabled,
    /// the asset is blacklisted, no rule matches, a whitelist misses, or the
    /// amount exceeds the policy's per-transaction `max_amount`. The spend does
    /// not proceed — an agent cannot override its own policy.
    PolicyDenied = 20,
    /// The multisig's emergency lock is engaged, so changes to the member set
    /// and other governance state are refused until the lock is released.
    /// Outbound spends are not blocked by this lock.
    EmergencyLock = 21,
    /// The recipient appears on the policy's restricted (blocklisted) list, so
    /// the transfer is refused before the token is called.
    PolicyRecipientRestricted = 22,
    /// The merchant appears on the policy's blocked-merchant list, so the
    /// spend is refused.
    PolicyMerchantBlocked = 23,
    /// The spend's category appears on the policy's restricted-category list,
    /// so the spend is refused.
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
    /// The protocol registry is frozen: every mutating registry entrypoint
    /// (module registration, version pointers, role changes, upgrades)
    /// aborts. Read paths stay available so integrators can still inspect the
    /// registry during an incident.
    RegistryFrozen = 30,
    /// Routing was asked for a module version that is flagged deprecated.
    /// Deprecated modules are not selectable for new traffic — the caller must
    /// route to the successor version, or use the explicit legacy-read path.
    ModuleDeprecated = 31,
    /// CIRCULAR_UPGRADE: a module upgrade would move a module's pointer onto
    /// the implementation it already runs, or back onto one it has already left
    /// — closing a loop in the upgrade path instead of advancing it (Issue #249).
    /// Distinct from [`Error::InvalidInput`] so deployment tooling that walks
    /// upgrade paths can tell a cycle apart from a malformed request and stop
    /// walking rather than retrying.
    CircularUpgrade = 32,

    // --- Budget (40-44) ---
    /// The spend would breach the budget: the per-asset limit for this token,
    /// or the aggregate ceiling for the period once rollover and any deficit
    /// carry-forward have been applied. Nothing is spent and the recorded
    /// utilization is unchanged.
    BudgetExceeded = 40,
    /// The budget is frozen, so no spend, release or limit change is permitted
    /// while the freeze holds.
    BudgetFrozen = 41,
    /// The budget is archived — a terminal state. It can no longer be spent,
    /// topped up or reconfigured; only archival bookkeeping remains available.
    BudgetArchived = 42,
    /// The named token contract is not on the organization's approved-asset
    /// list. The canonical "asset not approved" code: consulted by the
    /// treasury whitelist, the budget's asset registry and the policy
    /// contract's per-policy asset whitelist alike (it also covers the value
    /// formerly reported as `AssetNotWhitelisted`).
    AssetNotAuthorized = 43,
    /// The budget's window has closed: the ledger timestamp is at or past
    /// `expires_at`, or the active period has lapsed. The budget no longer
    /// authorizes spend. Distinct from
    /// [`BudgetError::BudgetNotActive`], which is the *not yet started* case.
    BudgetExpired = 44,

    // --- Wallet (50-54) ---
    /// The wallet is frozen by its guardian, so configuration changes are
    /// refused until it is thawed.
    WalletFrozen = 50,
    /// The wallet is archived — a terminal state. New configuration, role
    /// grants and spends are all refused.
    WalletArchived = 51,
    /// The wallet's circuit breaker is engaged, so every mutating path is
    /// refused. Read paths stay available.
    WalletPaused = 52,
    /// The record is in a state that cannot serve this request: a spend
    /// attempted while the wallet, budget or treasury is paused, a reentrancy
    /// lock is already held, an escrow has reached a terminal state, or an
    /// allowance has been revoked. Distinct from [`Error::Unauthorized`]: the
    /// caller may be perfectly entitled, the record simply cannot move right
    /// now.
    InvalidState = 53,
    /// RATE_LIMIT_EXCEEDED: an outbound transaction would exceed the wallet's
    /// configured rate limit (maximum outbound volume and/or transaction count
    /// within the active sliding window). Nothing moves; the spend may succeed
    /// once earlier activity ages out of the window.
    RateLimitExceeded = 54,

    // --- Multisig / approvals (61-69, 90-92) ---
    /// The accumulated approvals are below the configured threshold: too few
    /// distinct signers, a tally that has not reached the required quorum or
    /// majority, or a vote that has not yet collected enough weight for the
    /// action being attempted.
    ThresholdNotMet = 61,
    /// This caller has already signed or approved this record. A signature is
    /// recorded once, so a repeat is refused rather than counted twice.
    AlreadySigned = 62,
    /// The caller is not in the multisig's signer set (and, for a proposal, not
    /// in its approver allow-list), so their approval is not accepted.
    NotASigner = 63,
    /// The requested threshold is unusable: zero approvals, or more approvals
    /// than the signer set can ever supply. Rejected at configuration time,
    /// before a single vote is cast.
    InvalidThreshold = 64,
    /// The proposed signer set is larger than
    /// [`MAX_SIGNERS`](crate::constants::MAX_SIGNERS), the protocol cap that
    /// bounds the storage and iteration cost of a signer set.
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
    /// The proposal's deadline has passed, so it can no longer be approved,
    /// executed or cancelled. Expiry is measured against the ledger timestamp,
    /// never wall-clock time.
    ProposalExpired = 71,
    /// The operation is not legal for the proposal's current state: approving
    /// or executing one that is already executed, cancelled or closed, or
    /// sweeping up a record that is not pending.
    InvalidProposalState = 72,
    /// `execute` was called before the proposal reached `Approved`: the
    /// threshold, the quorum and any prerequisite chain have not all been
    /// satisfied yet.
    ProposalNotApproved = 73,
    /// The caller is not in the approver allow-list configured for this
    /// proposal, so their approval is not counted.
    NotAnApprover = 74,
    /// The proposer attempted to cancel after the cancellation window (grace
    /// period) closed. Only the executor or governance may proceed from here.
    CancellationWindowClosed = 75,
    /// A prerequisite proposal has not executed, so the dependent proposal may
    /// not execute yet.
    PrerequisiteNotMet = 78,
    /// A declared dependency would close a cycle in the dependency graph.
    CircularDependencyDetected = 79,

    // --- Escrow (80-82) ---
    /// The ledger timestamp is at or past the escrow's deadline, so the
    /// beneficiary release path is closed and the funds are no longer
    /// releasable to the beneficiary.
    EscrowExpired = 80,
    /// The escrow's own release clock has not elapsed: the timestamp is still
    /// short of the `cliff_time`/`unlock_time`, or a linear schedule has not
    /// yet vested the requested amount. This is what the beneficiary-facing
    /// `withdraw`/`claim` paths report; the privileged early-release paths
    /// report [`Error::TimelockNotExpired`] instead.
    TimeLockActive = 81,
    /// A milestone is still inside its dispute grace period, so settlement is
    /// not final and the release is held until the window closes.
    GraceActive = 82,

    // --- Treasury (83-85) ---
    /// A spend would breach a per-asset allowance: the treasury's per-agent
    /// withdrawal allowance or a policy's per-asset spending allowance.
    AllowanceExceeded = 83,
    /// The allowance has passed its `expires_at`, so the draw is refused. An
    /// expired allowance is never treated as a standing grant — it must be
    /// re-granted.
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

    /// The canonical `UPPER_SNAKE_CASE` name for this variant — the identifier
    /// an off-chain consumer (the Astroid API, SDK and dashboard) keys its
    /// message catalogue off, alongside [`Error::code`].
    ///
    /// The name is a stable part of the published error contract, exactly like
    /// the number, and is held to the same rules: `UPPER_SNAKE_CASE`, and unique
    /// within the table. Both are enforced by the tests in
    /// `shared/src/test.rs`.
    ///
    /// The Rust variant keeps its `CamelCase` spelling on purpose. Renaming the
    /// variants would break every call site in the workspace, every downstream
    /// crate that imports `astroid_shared`, and the SDK's generated bindings,
    /// all to change a spelling no on-chain consumer can see. The wire name is
    /// the published contract; this is the single place it is written down.
    pub const fn wire_name(self) -> &'static str {
        match self {
            // --- Generic / lifecycle (1-6) ---
            Error::NotFound => "NOT_FOUND",
            Error::AlreadyExists => "ALREADY_EXISTS",
            Error::Unauthorized => "UNAUTHORIZED",
            Error::InvalidInput => "INVALID_INPUT",
            Error::NotInitialized => "NOT_INITIALIZED",
            Error::AlreadyInitialized => "ALREADY_INITIALIZED",
            // --- Value / arithmetic (10-12) ---
            Error::InsufficientFunds => "INSUFFICIENT_FUNDS",
            Error::Overflow => "OVERFLOW",
            Error::InvalidAmount => "INVALID_AMOUNT",
            // --- Policy (20-29) ---
            Error::PolicyDenied => "POLICY_DENIED",
            Error::EmergencyLock => "EMERGENCY_LOCK",
            Error::PolicyRecipientRestricted => "POLICY_RECIPIENT_RESTRICTED",
            Error::PolicyMerchantBlocked => "POLICY_MERCHANT_BLOCKED",
            Error::PolicyCategoryRestricted => "POLICY_CATEGORY_RESTRICTED",
            Error::VelocityLimitExceeded => "VELOCITY_LIMIT_EXCEEDED",
            // --- Registry (30-39) ---
            Error::RegistryFrozen => "REGISTRY_FROZEN",
            Error::ModuleDeprecated => "MODULE_DEPRECATED",
            // --- Budget (40-44) ---
            Error::BudgetExceeded => "BUDGET_EXCEEDED",
            Error::BudgetFrozen => "BUDGET_FROZEN",
            Error::BudgetArchived => "BUDGET_ARCHIVED",
            Error::AssetNotAuthorized => "ASSET_NOT_AUTHORIZED",
            Error::BudgetExpired => "BUDGET_EXPIRED",
            // --- Wallet (50-54) ---
            Error::WalletFrozen => "WALLET_FROZEN",
            Error::WalletArchived => "WALLET_ARCHIVED",
            Error::WalletPaused => "WALLET_PAUSED",
            Error::InvalidState => "INVALID_STATE",
            Error::RateLimitExceeded => "RATE_LIMIT_EXCEEDED",
            // --- Multisig / approvals (61-69, 90-92) ---
            Error::ThresholdNotMet => "THRESHOLD_NOT_MET",
            Error::AlreadySigned => "ALREADY_SIGNED",
            Error::NotASigner => "NOT_A_SIGNER",
            Error::InvalidThreshold => "INVALID_THRESHOLD",
            Error::TooManySigners => "TOO_MANY_SIGNERS",
            Error::BatchCallFailed => "BATCH_CALL_FAILED",
            Error::InvalidNonce => "INVALID_NONCE",
            Error::InvalidSignerWeight => "INVALID_SIGNER_WEIGHT",
            Error::InsufficientWeight => "INSUFFICIENT_WEIGHT",
            Error::TimelockNotExpired => "TIMELOCK_NOT_EXPIRED",
            Error::UnauthorizedModification => "UNAUTHORIZED_MODIFICATION",
            // --- Proposal (71-79) ---
            Error::ProposalExpired => "PROPOSAL_EXPIRED",
            Error::InvalidProposalState => "INVALID_PROPOSAL_STATE",
            Error::ProposalNotApproved => "PROPOSAL_NOT_APPROVED",
            Error::NotAnApprover => "NOT_AN_APPROVER",
            Error::CancellationWindowClosed => "CANCELLATION_WINDOW_CLOSED",
            Error::PrerequisiteNotMet => "PREREQUISITE_NOT_MET",
            Error::CircularDependencyDetected => "CIRCULAR_DEPENDENCY_DETECTED",
            // --- Escrow (80-82) ---
            Error::EscrowExpired => "ESCROW_EXPIRED",
            Error::TimeLockActive => "TIME_LOCK_ACTIVE",
            Error::GraceActive => "GRACE_ACTIVE",
            // --- Treasury (83-85) ---
            Error::AllowanceExceeded => "ALLOWANCE_EXCEEDED",
            Error::AllowanceExpired => "ALLOWANCE_EXPIRED",
            Error::TreasuryPaused => "TREASURY_PAUSED",
        }
    }
}

/// Budget spend errors, kept separate from the protocol-wide error enum so
/// budget-specific timing errors do not exceed Soroban's 50-variant limit.
/// Existing codes match [`Error`] exactly; code 45 is the new scheduled-start
/// denial.
///
/// This table backs the budget's public spend-decision entrypoints
/// (`check_and_record_spend` and `consume`) and the private `require_started`
/// guard. Every variant except [`BudgetError::BudgetExceeded`] and
/// [`BudgetError::BudgetNotActive`] is reached through [`From<Error>`], so the
/// generic refusals the budget's shared helpers produce keep the exact wire
/// value an off-chain consumer already decodes.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum BudgetError {
    /// No budget record exists for the requested id. Wire-compatible with
    /// [`Error::NotFound`], so a consumer's existing handler still matches.
    NotFound = 1,
    /// The caller is not the budget's owner/controller and did not authorize
    /// the spend. Wire-compatible with [`Error::Unauthorized`].
    Unauthorized = 3,
    /// An argument failed validation. This is also where
    /// [`Error::InvalidState`] and any failure the [`From<Error>`] conversion
    /// does not name specifically land, so a budget refusal reported as
    /// `InvalidInput` means "malformed argument, or a state failure with no
    /// budget-specific code".
    InvalidInput = 4,
    /// A checked arithmetic step left the representable range while accumulating
    /// the spend, so the new total cannot be encoded. Wire-compatible with
    /// [`Error::Overflow`].
    Overflow = 11,
    /// The requested spend is not strictly positive. Rejected before the
    /// budget's utilization is touched. Wire-compatible with
    /// [`Error::InvalidAmount`].
    InvalidAmount = 12,
    /// The spend would breach the budget: the per-asset limit for this token,
    /// or the aggregate ceiling for the period after rollover and deficit
    /// carry-forward are applied. Nothing is spent.
    BudgetExceeded = 40,
    /// The budget is frozen, so no spend is permitted while the freeze holds.
    /// Wire-compatible with [`Error::BudgetFrozen`].
    BudgetFrozen = 41,
    /// The budget is archived and terminal: it can no longer be spent. Also
    /// reported when a lifecycle guard finds the budget archived. Wire-
    /// compatible with [`Error::BudgetArchived`].
    BudgetArchived = 42,
    /// The token has no per-asset budget record, i.e. it is not an approved
    /// spendable asset for this budget. Wire-compatible with
    /// [`Error::AssetNotAuthorized`].
    AssetNotAuthorized = 43,
    /// The budget's window has closed: the ledger timestamp is at or past
    /// `expires_at`. Wire-compatible with [`Error::BudgetExpired`].
    BudgetExpired = 44,
    /// BUDGET_NOT_ACTIVE: the budget has not started yet — the ledger timestamp
    /// is before `starts_at` — so nothing may be spent. The "not yet begun"
    /// counterpart to [`BudgetError::BudgetExpired`] ("already over"), and the
    /// one code with no canonical [`Error`] equivalent: converting a
    /// `BudgetError` back into an `Error` folds it onto
    /// [`Error::BudgetExpired`], so a consumer that wants to tell the two apart
    /// must decode this table directly.
    BudgetNotActive = 45,
}

impl BudgetError {
    /// Every variant the budget spend table can report, in the order the enum
    /// declares them. The audit walks this list, so a variant added to (or
    /// removed from) the enum without a matching entry fails
    /// `budget_error_table_is_frozen`.
    pub const ALL: [BudgetError; 11] = [
        BudgetError::NotFound,
        BudgetError::Unauthorized,
        BudgetError::InvalidInput,
        BudgetError::Overflow,
        BudgetError::InvalidAmount,
        BudgetError::BudgetExceeded,
        BudgetError::BudgetFrozen,
        BudgetError::BudgetArchived,
        BudgetError::AssetNotAuthorized,
        BudgetError::BudgetExpired,
        BudgetError::BudgetNotActive,
    ];

    /// The `u32` code this variant carries on the wire, identical to the value
    /// an off-chain consumer reads from a failed transaction. As in [`Error`],
    /// `0` is reserved and may not be used.
    pub const fn code(self) -> u32 {
        self as u32
    }

    /// The canonical `UPPER_SNAKE_CASE` name for this variant, held to the same
    /// rules as [`Error::wire_name`]. The ten mirrored variants deliberately
    /// share their canonical name with [`Error`], because they share its number:
    /// one off-chain catalogue covers both tables.
    pub const fn wire_name(self) -> &'static str {
        match self {
            BudgetError::NotFound => "NOT_FOUND",
            BudgetError::Unauthorized => "UNAUTHORIZED",
            BudgetError::InvalidInput => "INVALID_INPUT",
            BudgetError::Overflow => "OVERFLOW",
            BudgetError::InvalidAmount => "INVALID_AMOUNT",
            BudgetError::BudgetExceeded => "BUDGET_EXCEEDED",
            BudgetError::BudgetFrozen => "BUDGET_FROZEN",
            BudgetError::BudgetArchived => "BUDGET_ARCHIVED",
            BudgetError::AssetNotAuthorized => "ASSET_NOT_AUTHORIZED",
            BudgetError::BudgetExpired => "BUDGET_EXPIRED",
            BudgetError::BudgetNotActive => "BUDGET_NOT_ACTIVE",
        }
    }
}

/// Every code the budget-specific [`BudgetError`] table can report, in
/// declaration order. Kept as a literal so a renumber or a reissued slot is
/// caught by `budget_error_codes_are_frozen_and_unique` rather than passing
/// silently.
pub const BUDGET_ERROR_CODES: [u32; 11] = [1, 3, 4, 11, 12, 40, 41, 42, 43, 44, 45];

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
    /// Every variant the milestone table can report, in the order the enum
    /// declares them. The audit walks this list, so a variant added to (or
    /// removed from) the enum without a matching entry in
    /// [`MILESTONE_ERROR_CODES`] fails the milestone audit rather than slipping
    /// an undocumented code onto the wire.
    pub const ALL: [MilestoneError; 8] = [
        MilestoneError::NotFound,
        MilestoneError::Unauthorized,
        MilestoneError::InvalidInput,
        MilestoneError::Overflow,
        MilestoneError::InvalidAmount,
        MilestoneError::InvalidState,
        MilestoneError::InvalidMilestone,
        MilestoneError::MilestoneAlreadyCompleted,
    ];

    /// The `u32` code this variant carries on the wire, identical to the value
    /// an off-chain consumer reads from a failed transaction.
    pub const fn code(self) -> u32 {
        self as u32
    }

    /// The canonical `UPPER_SNAKE_CASE` name for this variant, held to the same
    /// rules as [`Error::wire_name`]. The six mirrored variants share their
    /// canonical name with [`Error`] because they share its number; only
    /// `INVALID_MILESTONE` and `MILESTONE_ALREADY_COMPLETED` are milestone-only.
    pub const fn wire_name(self) -> &'static str {
        match self {
            MilestoneError::NotFound => "NOT_FOUND",
            MilestoneError::Unauthorized => "UNAUTHORIZED",
            MilestoneError::InvalidInput => "INVALID_INPUT",
            MilestoneError::Overflow => "OVERFLOW",
            MilestoneError::InvalidAmount => "INVALID_AMOUNT",
            MilestoneError::InvalidState => "INVALID_STATE",
            MilestoneError::InvalidMilestone => "INVALID_MILESTONE",
            MilestoneError::MilestoneAlreadyCompleted => "MILESTONE_ALREADY_COMPLETED",
        }
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
