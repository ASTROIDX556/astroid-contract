//! Deterministic, protocol-wide error codes.
//!
//! Every contract returns variants of this single enum so that off-chain
//! consumers (the Astroid API, SDK and dashboard) can map a stable `u32` code
//! to a meaningful message. Numeric values are grouped by domain and MUST NOT
//! be reordered or reused once released — they are part of the public ABI.
//!
//! This table is the single, authoritative union of every error code surfaced
//! by the workspace contracts. New variants must be allocated in the free slot
//! of the matching domain group and must never reuse an existing discriminant.
//!
//! The conversions to [`soroban_sdk::Error`] are written by hand because the
//! protocol XDR for an error-enum spec caps the number of cases at 50
//! (`VecM<ScSpecUdtErrorEnumCaseV0, 50>`), while the protocol-wide code table
//! exceeds that limit, so `#[contracterror]` cannot be used here.

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
    /// A proposed spend would breach a per-asset spending allowance.
    PolicyAllowanceExceeded = 26,
    /// A conditional policy rule evaluated to a hard deny.
    RuleDenied = 27,

    // --- Registry (30-39) ---
    RegistryFrozen = 30,
    ModuleDeprecated = 31,
    /// System-wide emergency pause: all critical registry operations are halted.
    ContractPaused = 32,
    /// A registered interface version does not meet the organization's minimum
    /// compatibility bound for that module kind. Deterministic error constant
    /// for incompatible interface version attempts.
    InterfaceVersionIncompatible = 33,

    // --- Budget (40-49) ---
    BudgetExceeded = 40,
    BudgetFrozen = 41,
    BudgetArchived = 42,
    AssetNotAuthorized = 43,
    BudgetExpired = 44,
    VelocityExceeded = 45,

    // --- Wallet (50-59) ---
    WalletFrozen = 50,
    WalletArchived = 51,
    WalletPaused = 52,
    InvalidState = 53,
    RateLimitExceeded = 54,
    /// A caller attempted an action its role does not allow.
    UnauthorizedDispatch = 55,

    // --- Multisig / approvals (60-69, 90-92) ---
    InvalidSignature = 60,
    ThresholdNotMet = 61,
    AlreadySigned = 62,
    NotASigner = 63,
    InvalidThreshold = 64,
    /// Accumulated voting weight is below the configured tier threshold.
    InsufficientTierWeight = 65,
    TooManySigners = 66,
    /// A sub-call within a batch failed; the entire batch reverted atomically.
    BatchCallFailed = 67,
    /// Batch nonce is not strictly greater than the last used nonce (replay).
    InvalidNonce = 68,
    /// A signer with zero (or otherwise invalid) voting weight was supplied.
    InvalidSignerWeight = 69,

    // --- Proposal (70-79) ---
    /// A declared delegation path exceeds the maximum allowed depth.
    DelegationDepthExceeded = 70,
    ProposalExpired = 71,
    InvalidProposalState = 72,
    ProposalNotApproved = 73,
    NotAnApprover = 74,
    CancellationWindowClosed = 75,
    /// The aggregated count of verified approver signatures did not reach the
    /// configured threshold at execution time.
    QuorumNotMet = 76,
    /// A declared delegation would close a cycle in the delegation graph.
    CircularDelegation = 77,
    /// A prerequisite proposal has not executed, so the dependent proposal may
    /// not execute yet.
    PrerequisiteNotMet = 78,
    /// A declared dependency would close a cycle in the dependency graph.
    CircularDependencyDetected = 79,

    // --- Escrow (80-82) ---
    EscrowExpired = 80,
    TimeLockActive = 81,
    GraceActive = 82,

    // --- Treasury (83-86) ---
    AllowanceExceeded = 83,
    AllowanceExpired = 84,
    /// A scheduled payout violated its milestone schedule.
    PayoutScheduleViolated = 85,
    /// The treasury is under an emergency stop that halts all payouts.
    EmergencyPaused = 86,

    // --- Multisig governance (90-92) ---
    /// Accumulated approval weight is below the configured threshold.
    InsufficientWeight = 90,
    /// A timelocked governance change was executed before its delay elapsed.
    TimelockNotExpired = 91,
    /// A caller without governance rights attempted to modify signers,
    /// weights or the threshold.
    UnauthorizedModification = 92,
}

impl Error {
    /// Returns the deterministic `u32` code for this error variant.
    pub const fn code(self) -> u32 {
        match self {
            Error::NotFound => 1,
            Error::AlreadyExists => 2,
            Error::Unauthorized => 3,
            Error::InvalidInput => 4,
            Error::NotInitialized => 5,
            Error::AlreadyInitialized => 6,
            Error::InsufficientFunds => 10,
            Error::Overflow => 11,
            Error::InvalidAmount => 12,
            Error::PolicyDenied => 20,
            Error::EmergencyLock => 21,
            Error::PolicyRecipientRestricted => 22,
            Error::PolicyMerchantBlocked => 23,
            Error::PolicyCategoryRestricted => 24,
            Error::AssetNotWhitelisted => 25,
            Error::PolicyAllowanceExceeded => 26,
            Error::RuleDenied => 27,
            Error::RegistryFrozen => 30,
            Error::ModuleDeprecated => 31,
            Error::ContractPaused => 32,
            Error::InterfaceVersionIncompatible => 33,
            Error::BudgetExceeded => 40,
            Error::BudgetFrozen => 41,
            Error::BudgetArchived => 42,
            Error::AssetNotAuthorized => 43,
            Error::BudgetExpired => 44,
            Error::VelocityExceeded => 45,
            Error::WalletFrozen => 50,
            Error::WalletArchived => 51,
            Error::WalletPaused => 52,
            Error::InvalidState => 53,
            Error::RateLimitExceeded => 54,
            Error::UnauthorizedDispatch => 55,
            Error::InvalidSignature => 60,
            Error::ThresholdNotMet => 61,
            Error::AlreadySigned => 62,
            Error::NotASigner => 63,
            Error::InvalidThreshold => 64,
            Error::InsufficientTierWeight => 65,
            Error::TooManySigners => 66,
            Error::BatchCallFailed => 67,
            Error::InvalidNonce => 68,
            Error::InvalidSignerWeight => 69,
            Error::DelegationDepthExceeded => 70,
            Error::ProposalExpired => 71,
            Error::InvalidProposalState => 72,
            Error::ProposalNotApproved => 73,
            Error::NotAnApprover => 74,
            Error::CancellationWindowClosed => 75,
            Error::QuorumNotMet => 76,
            Error::CircularDelegation => 77,
            Error::PrerequisiteNotMet => 78,
            Error::CircularDependencyDetected => 79,
            Error::EscrowExpired => 80,
            Error::TimeLockActive => 81,
            Error::GraceActive => 82,
            Error::AllowanceExceeded => 83,
            Error::AllowanceExpired => 84,
            Error::PayoutScheduleViolated => 85,
            Error::EmergencyPaused => 86,
            Error::InsufficientWeight => 90,
            Error::TimelockNotExpired => 91,
            Error::UnauthorizedModification => 92,
        }
    }
}

impl TryFrom<soroban_sdk::Error> for Error {
    type Error = soroban_sdk::Error;
    #[inline(always)]
    fn try_from(error: soroban_sdk::Error) -> Result<Self, soroban_sdk::Error> {
        if error.is_type(soroban_sdk::xdr::ScErrorType::Contract) {
            let discriminant = error.get_code();
            Ok(match discriminant {
                1 => Self::NotFound,
                2 => Self::AlreadyExists,
                3 => Self::Unauthorized,
                4 => Self::InvalidInput,
                5 => Self::NotInitialized,
                6 => Self::AlreadyInitialized,
                10 => Self::InsufficientFunds,
                11 => Self::Overflow,
                12 => Self::InvalidAmount,
                20 => Self::PolicyDenied,
                21 => Self::EmergencyLock,
                22 => Self::PolicyRecipientRestricted,
                23 => Self::PolicyMerchantBlocked,
                24 => Self::PolicyCategoryRestricted,
                25 => Self::AssetNotWhitelisted,
                26 => Self::PolicyAllowanceExceeded,
                27 => Self::RuleDenied,
                30 => Self::RegistryFrozen,
                31 => Self::ModuleDeprecated,
                32 => Self::ContractPaused,
                33 => Self::InterfaceVersionIncompatible,
                40 => Self::BudgetExceeded,
                41 => Self::BudgetFrozen,
                42 => Self::BudgetArchived,
                43 => Self::AssetNotAuthorized,
                44 => Self::BudgetExpired,
                45 => Self::VelocityExceeded,
                50 => Self::WalletFrozen,
                51 => Self::WalletArchived,
                52 => Self::WalletPaused,
                53 => Self::InvalidState,
                54 => Self::RateLimitExceeded,
                55 => Self::UnauthorizedDispatch,
                60 => Self::InvalidSignature,
                61 => Self::ThresholdNotMet,
                62 => Self::AlreadySigned,
                63 => Self::NotASigner,
                64 => Self::InvalidThreshold,
                65 => Self::InsufficientTierWeight,
                66 => Self::TooManySigners,
                67 => Self::BatchCallFailed,
                68 => Self::InvalidNonce,
                69 => Self::InvalidSignerWeight,
                70 => Self::DelegationDepthExceeded,
                71 => Self::ProposalExpired,
                72 => Self::InvalidProposalState,
                73 => Self::ProposalNotApproved,
                74 => Self::NotAnApprover,
                75 => Self::CancellationWindowClosed,
                76 => Self::QuorumNotMet,
                77 => Self::CircularDelegation,
                78 => Self::PrerequisiteNotMet,
                79 => Self::CircularDependencyDetected,
                80 => Self::EscrowExpired,
                81 => Self::TimeLockActive,
                82 => Self::GraceActive,
                83 => Self::AllowanceExceeded,
                84 => Self::AllowanceExpired,
                85 => Self::PayoutScheduleViolated,
                86 => Self::EmergencyPaused,
                90 => Self::InsufficientWeight,
                91 => Self::TimelockNotExpired,
                92 => Self::UnauthorizedModification,
                _ => return Err(error),
            })
        } else {
            Err(error)
        }
    }
}

impl TryFrom<&soroban_sdk::Error> for Error {
    type Error = soroban_sdk::Error;
    #[inline(always)]
    fn try_from(error: &soroban_sdk::Error) -> Result<Self, soroban_sdk::Error> {
        <_ as TryFrom<soroban_sdk::Error>>::try_from(*error)
    }
}

impl From<Error> for soroban_sdk::Error {
    #[inline(always)]
    fn from(val: Error) -> soroban_sdk::Error {
        soroban_sdk::Error::from_contract_error(val.code())
    }
}

impl From<&Error> for soroban_sdk::Error {
    #[inline(always)]
    fn from(val: &Error) -> soroban_sdk::Error {
        <_ as From<Error>>::from(*val)
    }
}

impl TryFrom<soroban_sdk::InvokeError> for Error {
    type Error = soroban_sdk::InvokeError;
    #[inline(always)]
    fn try_from(error: soroban_sdk::InvokeError) -> Result<Self, soroban_sdk::InvokeError> {
        match error {
            soroban_sdk::InvokeError::Abort => Err(error),
            soroban_sdk::InvokeError::Contract(code) => Ok(match code {
                1 => Self::NotFound,
                2 => Self::AlreadyExists,
                3 => Self::Unauthorized,
                4 => Self::InvalidInput,
                5 => Self::NotInitialized,
                6 => Self::AlreadyInitialized,
                10 => Self::InsufficientFunds,
                11 => Self::Overflow,
                12 => Self::InvalidAmount,
                20 => Self::PolicyDenied,
                21 => Self::EmergencyLock,
                22 => Self::PolicyRecipientRestricted,
                23 => Self::PolicyMerchantBlocked,
                24 => Self::PolicyCategoryRestricted,
                25 => Self::AssetNotWhitelisted,
                26 => Self::PolicyAllowanceExceeded,
                27 => Self::RuleDenied,
                30 => Self::RegistryFrozen,
                31 => Self::ModuleDeprecated,
                32 => Self::ContractPaused,
                33 => Self::InterfaceVersionIncompatible,
                40 => Self::BudgetExceeded,
                41 => Self::BudgetFrozen,
                42 => Self::BudgetArchived,
                43 => Self::AssetNotAuthorized,
                44 => Self::BudgetExpired,
                45 => Self::VelocityExceeded,
                50 => Self::WalletFrozen,
                51 => Self::WalletArchived,
                52 => Self::WalletPaused,
                53 => Self::InvalidState,
                54 => Self::RateLimitExceeded,
                55 => Self::UnauthorizedDispatch,
                60 => Self::InvalidSignature,
                61 => Self::ThresholdNotMet,
                62 => Self::AlreadySigned,
                63 => Self::NotASigner,
                64 => Self::InvalidThreshold,
                65 => Self::InsufficientTierWeight,
                66 => Self::TooManySigners,
                67 => Self::BatchCallFailed,
                68 => Self::InvalidNonce,
                69 => Self::InvalidSignerWeight,
                70 => Self::DelegationDepthExceeded,
                71 => Self::ProposalExpired,
                72 => Self::InvalidProposalState,
                73 => Self::ProposalNotApproved,
                74 => Self::NotAnApprover,
                75 => Self::CancellationWindowClosed,
                76 => Self::QuorumNotMet,
                77 => Self::CircularDelegation,
                78 => Self::PrerequisiteNotMet,
                79 => Self::CircularDependencyDetected,
                80 => Self::EscrowExpired,
                81 => Self::TimeLockActive,
                82 => Self::GraceActive,
                83 => Self::AllowanceExceeded,
                84 => Self::AllowanceExpired,
                85 => Self::PayoutScheduleViolated,
                86 => Self::EmergencyPaused,
                90 => Self::InsufficientWeight,
                91 => Self::TimelockNotExpired,
                92 => Self::UnauthorizedModification,
                _ => return Err(error),
            }),
        }
    }
}

impl TryFrom<&soroban_sdk::InvokeError> for Error {
    type Error = soroban_sdk::InvokeError;
    #[inline(always)]
    fn try_from(error: &soroban_sdk::InvokeError) -> Result<Self, soroban_sdk::InvokeError> {
        <_ as TryFrom<soroban_sdk::InvokeError>>::try_from(*error)
    }
}

impl From<Error> for soroban_sdk::InvokeError {
    #[inline(always)]
    fn from(val: Error) -> soroban_sdk::InvokeError {
        soroban_sdk::InvokeError::Contract(val.code())
    }
}

impl From<&Error> for soroban_sdk::InvokeError {
    #[inline(always)]
    fn from(val: &Error) -> soroban_sdk::InvokeError {
        <_ as From<Error>>::from(*val)
    }
}

impl soroban_sdk::TryFromVal<soroban_sdk::Env, soroban_sdk::Val> for Error {
    type Error = soroban_sdk::ConversionError;
    #[inline(always)]
    fn try_from_val(
        env: &soroban_sdk::Env,
        val: &soroban_sdk::Val,
    ) -> Result<Self, soroban_sdk::ConversionError> {
        use soroban_sdk::TryIntoVal;
        let error: soroban_sdk::Error = val.try_into_val(env)?;
        error.try_into().map_err(|_| soroban_sdk::ConversionError)
    }
}

impl soroban_sdk::TryFromVal<soroban_sdk::Env, Error> for soroban_sdk::Val {
    type Error = soroban_sdk::ConversionError;
    #[inline(always)]
    fn try_from_val(
        _env: &soroban_sdk::Env,
        val: &Error,
    ) -> Result<Self, soroban_sdk::ConversionError> {
        let error: soroban_sdk::Error = val.into();
        Ok(error.into())
    }
}
