//! Small, reusable validation guards.
//!
//! Each returns `Ok(())` when the invariant holds and a specific contract
//! [`Error`] otherwise, so callers can `?`-propagate. Keeping these here means
//! every contract validates inputs identically.

use crate::errors::Error;
use soroban_sdk::{Address, BytesN, Env, String};

/// Require a syntactically valid Wasm hash.
///
/// A Wasm code hash on Stellar is the 32-byte SHA-256 of the deployed Wasm
/// blob. The [`BytesN<32>`] parameter pins the width — a shorter payload can
/// never decode into it — so what remains to check here is the degenerate
/// value: the all-zero hash is refused because no real contract code hashes to
/// zeros, and accepting it would let a proposal launder a meaningless hash
/// into the approval table. Reports [`Error::InvalidInput`] — the shared
/// error table is already at the 50-case spec limit, so no dedicated variant
/// can be added.
pub fn require_valid_wasm_hash(env: &Env, hash: &BytesN<32>) -> Result<(), Error> {
    if hash == &BytesN::from_array(env, &[0u8; 32]) {
        return Err(Error::InvalidInput);
    }
    Ok(())
}

/// Require a strictly positive amount (typical for transfers / deposits).
pub fn require_positive_amount(amount: i128) -> Result<(), Error> {
    if amount <= 0 {
        return Err(Error::InvalidAmount);
    }
    Ok(())
}

/// Require a non-negative amount (allows zero, e.g. a zero-limit budget).
pub fn require_non_negative_amount(amount: i128) -> Result<(), Error> {
    if amount < 0 {
        return Err(Error::InvalidAmount);
    }
    Ok(())
}

/// Require a non-empty string (names, ids, org slugs).
pub fn require_non_empty(value: &String) -> Result<(), Error> {
    if value.is_empty() {
        return Err(Error::InvalidInput);
    }
    Ok(())
}

/// Require that `expiry` (a unix timestamp in seconds) is still in the future
/// relative to the current ledger time.
pub fn require_not_expired(env: &Env, expiry: u64) -> Result<(), Error> {
    if env.ledger().timestamp() >= expiry {
        return Err(Error::ProposalExpired);
    }
    Ok(())
}

/// Require that the current ledger time has reached `unlock_at` (time locks).
pub fn require_time_reached(env: &Env, unlock_at: u64) -> Result<(), Error> {
    if env.ledger().timestamp() < unlock_at {
        return Err(Error::TimelockNotExpired);
    }
    Ok(())
}

/// Require that `value` falls within an inclusive `[min, max]` window. Passing
/// `max == 0` is treated as "no upper bound".
pub fn require_within_amount_bounds(value: i128, min: i128, max: i128) -> Result<(), Error> {
    if value < min {
        return Err(Error::PolicyDenied);
    }
    if max != 0 && value > max {
        return Err(Error::PolicyDenied);
    }
    Ok(())
}

/// Verify multi-signer quorum approvals against configured signer weights and threshold.
///
/// This is the slice-based form of the shared threshold helper: the weight
/// accumulation, duplicate detection, zero-weight handling and comparison all
/// live in [`crate::auth`], so this function and the contracts that use the
/// helper directly can never disagree about the same tally.
///
/// Validates:
/// - `threshold` is strictly positive (`Error::InvalidThreshold`).
/// - `signers` and `weights` have equal non-zero length (`Error::InvalidInput`).
/// - `signers` contains no duplicate addresses (`Error::InvalidInput`).
/// - `approvals` contains no duplicate signers (`Error::AlreadySigned`).
/// - Every address in `approvals` is present in `signers` (`Error::NotASigner`).
/// - Accumulated weight summation does not overflow `u32::MAX` (`Error::Overflow`).
/// - Total accumulated approval weight meets or exceeds `threshold` (`Error::QUORUM_NOT_MET`).
pub fn verify_quorum(
    signers: &[Address],
    weights: &[u32],
    approvals: &[Address],
    threshold: u32,
) -> Result<(), Error> {
    crate::auth::verify_approvals(
        signers,
        weights,
        approvals,
        threshold,
        Error::QUORUM_NOT_MET,
    )
    .map(|_| ())
}
