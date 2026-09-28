//! Small, reusable validation guards.
//!
//! Each returns `Ok(())` when the invariant holds and a specific contract
//! [`Error`] otherwise, so callers can `?`-propagate. Keeping these here means
//! every contract validates inputs identically.

use crate::errors::Error;
use soroban_sdk::{Address, Env, String};

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
/// Validates:
/// - `signers` and `weights` have equal non-zero length (`Error::InvalidInput`).
/// - `threshold` is strictly positive (`Error::InvalidThreshold`).
/// - `signers` contains no duplicate addresses (`Error::InvalidInput`).
/// - `approvals` contains no duplicate signers (`Error::AlreadySigned`).
/// - Every address in `approvals` is present in `signers` (`Error::NotASigner`).
/// - Accumulated weight summation does not overflow `u32::MAX` (`Error::Overflow`).
/// - Total accumulated approval weight meets or exceeds `threshold` (`Error::ThresholdNotMet`).
pub fn verify_quorum(
    signers: &[Address],
    weights: &[u32],
    approvals: &[Address],
    threshold: u32,
) -> Result<(), Error> {
    if signers.len() != weights.len() || signers.is_empty() {
        return Err(Error::InvalidInput);
    }
    if threshold == 0 {
        return Err(Error::InvalidThreshold);
    }

    for i in 0..signers.len() {
        for j in (i + 1)..signers.len() {
            if signers[i] == signers[j] {
                return Err(Error::InvalidInput);
            }
        }
    }

    for i in 0..approvals.len() {
        for j in (i + 1)..approvals.len() {
            if approvals[i] == approvals[j] {
                return Err(Error::AlreadySigned);
            }
        }
    }

    let mut total_weight: u64 = 0;

    for app in approvals.iter() {
        let mut found = false;
        for (idx, signer) in signers.iter().enumerate() {
            if app == signer {
                found = true;
                total_weight = total_weight
                    .checked_add(weights[idx] as u64)
                    .ok_or(Error::Overflow)?;
                if total_weight > u32::MAX as u64 {
                    return Err(Error::Overflow);
                }
                break;
            }
        }
        if !found {
            return Err(Error::NotASigner);
        }
    }

    if total_weight < threshold as u64 {
        return Err(Error::ThresholdNotMet);
    }

    Ok(())
}
