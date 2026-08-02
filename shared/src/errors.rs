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
    InsufficientFunds = 10,
    Overflow = 11,
    Underflow = 12,
    InvalidAmount = 13,

    // --- Policy (20-29) ---
    PolicyDenied = 20,
    PolicyHashMismatch = 21,
    EmergencyLock = 22,

    // --- Budget (30-39) ---
    BudgetExceeded = 30,
    BudgetFrozen = 31,
    BudgetArchived = 32,

    // --- Wallet (40-49) ---
    WalletFrozen = 40,
    WalletArchived = 41,
    WalletPaused = 42,
    InvalidState = 43,

    // --- Multisig / approvals (50-59) ---
    InvalidSignature = 50,
    ThresholdNotMet = 51,
    AlreadySigned = 52,
    NotASigner = 53,
    InvalidThreshold = 54,
    TimeLocked = 55,
    TooManySigners = 56,

    // --- Proposal (60-69) ---
    ProposalExpired = 60,
    InvalidProposalState = 61,
    ProposalNotApproved = 62,
    NotAnApprover = 63,

    // --- Escrow (70-79) ---
    ConditionNotMet = 70,
    EscrowNotFunded = 71,
    EscrowExpired = 72,
    InvalidCondition = 73,
}
