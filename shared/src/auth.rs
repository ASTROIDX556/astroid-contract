//! Shared multi-signature threshold verification (Issue #450).
//!
//! Both the multisig and the proposal contract decide whether a collection of
//! approvals meets the required approval weight. Keeping the arithmetic and
//! the comparison here — instead of in each contract — guarantees the two can
//! never disagree about the same tally, and gives every caller one place to
//! get the edge cases right:
//!
//! * **Overflow.** Every accumulation goes through [`crate::math::checked_add`]
//!   and is narrowed back to `u32` only by [`narrow_weight`], so an
//!   unrepresentable sum is [`Error::Overflow`] rather than a wrap into a
//!   smaller number that could silently fail (or falsely satisfy) a quorum.
//! * **Duplicates.** An address may appear once in a signer set
//!   ([`Error::InvalidInput`] on a repeat) and once in an approval list
//!   ([`Error::AlreadySigned`] on a repeat), so one key can never stack its
//!   weight twice.
//! * **Zero-weight / inactive signers.** A signer with weight `0` contributes
//!   nothing and is not counted as an approver; a signer who is not in the set
//!   at all is [`Error::NotASigner`]. Neither can manufacture a quorum.
//!
//! The threshold comparison is `weight >= threshold`: an exact match is
//! enough, and exceeding the threshold is never a failure.

use crate::errors::Error;
use crate::math::checked_add;
use soroban_sdk::{Address, Env, TryFromVal, Val, Vec};

/// One member of a weighted signer set. Implemented by each contract's own
/// signer record so the helper never depends on a contract-specific layout.
pub trait WeightedSigner {
    /// This signer's voting weight.
    fn weight(&self) -> u32;
}

/// Checked accumulation of one signer's weight into a running total.
///
/// The sum is carried in `i128` — wider than any `u32` weight — so the only
/// possible failure is a true `i128` overflow, reported as
/// [`Error::Overflow`]. [`narrow_weight`] is the single place the running
/// total is narrowed back to `u32`.
pub fn add_weight(total: i128, weight: u32) -> Result<i128, Error> {
    checked_add(total, weight as i128)
}

/// Narrow an accumulated `i128` weight back to `u32`, refusing to truncate.
///
/// Any total outside `0..=u32::MAX` is [`Error::Overflow`] instead of a
/// wrapped value that could wrongly satisfy or fail a threshold.
pub fn narrow_weight(total: i128) -> Result<u32, Error> {
    if total < 0 || total > u32::MAX as i128 {
        return Err(Error::Overflow);
    }
    Ok(total as u32)
}

/// Whether `weight` meets or exceeds `threshold`.
///
/// The one threshold predicate shared by every contract: `>=`, so an exact
/// match is sufficient and excess weight is never a problem.
pub fn meets_threshold(weight: u32, threshold: u32) -> bool {
    weight >= threshold
}

/// Weight still required before the threshold is met, saturating at `0` so a
/// tally that already exceeds the threshold reports nothing outstanding.
pub fn remaining_weight(weight: u32, threshold: u32) -> u32 {
    threshold.saturating_sub(weight)
}

/// Require `weight` to meet `threshold`, reporting `shortfall` otherwise.
///
/// `shortfall` lets each caller keep its own deterministic error code (for
/// example [`Error::InsufficientWeight`] for approval progress or
/// [`Error::QUORUM_NOT_MET`] for a verified signature quorum) while sharing
/// the comparison itself.
pub fn require_threshold(weight: u32, threshold: u32, shortfall: Error) -> Result<(), Error> {
    if meets_threshold(weight, threshold) {
        Ok(())
    } else {
        Err(shortfall)
    }
}

/// Accumulate the weights of the signers selected by `is_selected`, and count
/// how many of them carry a non-zero weight.
///
/// The signer set stores one entry per address, so iterating it cannot count
/// one key twice. Zero-weight signers add nothing and are not counted as
/// approvers, so an inactive signer can neither contribute weight nor inflate
/// the participation count. Every addition goes through [`add_weight`] and the
/// result through [`narrow_weight`], so an unrepresentable sum is refused
/// rather than truncated.
pub fn accumulate_selected<T>(
    signers: &Vec<T>,
    is_selected: &dyn Fn(&T) -> bool,
) -> Result<(u32, u32), Error>
where
    T: WeightedSigner + Clone + TryFromVal<Env, Val>,
    Val: TryFromVal<Env, T>,
{
    let mut total: i128 = 0;
    let mut approvers: u32 = 0;
    for s in signers.iter() {
        if !is_selected(&s) {
            continue;
        }
        let weight = s.weight();
        total = add_weight(total, weight)?;
        if weight > 0 {
            approvers = approvers.checked_add(1).ok_or(Error::Overflow)?;
        }
    }
    Ok((narrow_weight(total)?, approvers))
}

/// Accumulate selected signer weights and verify the total against `threshold`
/// in one fail-closed step.
///
/// Returns the verified `(weight, approvers)` tally on success — an exact match
/// and any excess weight both pass — or `shortfall` when the tally is below the
/// threshold. An unrepresentable sum surfaces as [`Error::Overflow`] before any
/// comparison is made.
pub fn verify_selected<T>(
    signers: &Vec<T>,
    is_selected: &dyn Fn(&T) -> bool,
    threshold: u32,
    shortfall: Error,
) -> Result<(u32, u32), Error>
where
    T: WeightedSigner + Clone + TryFromVal<Env, Val>,
    Val: TryFromVal<Env, T>,
{
    let tally = accumulate_selected(signers, is_selected)?;
    require_threshold(tally.0, threshold, shortfall)?;
    Ok(tally)
}

/// Sum the weights of the approvals in `approvals` against an explicit signer
/// set and weight list, rejecting duplicates and non-signers.
///
/// * `signers.len() != weights.len()` or an empty signer set —
///   [`Error::InvalidInput`].
/// * An address repeated in `signers` — [`Error::InvalidInput`].
/// * An address repeated in `approvals` — [`Error::AlreadySigned`].
/// * An approval that is not a signer — [`Error::NotASigner`].
/// * A sum outside `u32` — [`Error::Overflow`].
///
/// A zero-weight signer is accepted but contributes nothing, so it can never
/// help reach a threshold. Returns the verified total weight.
pub fn tally_approvals(
    signers: &[Address],
    weights: &[u32],
    approvals: &[Address],
) -> Result<u32, Error> {
    if signers.len() != weights.len() || signers.is_empty() {
        return Err(Error::InvalidInput);
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

    let mut total: i128 = 0;
    for approval in approvals.iter() {
        let mut found = false;
        for (idx, signer) in signers.iter().enumerate() {
            if approval == signer {
                found = true;
                total = add_weight(total, weights[idx])?;
                break;
            }
        }
        if !found {
            return Err(Error::NotASigner);
        }
    }

    narrow_weight(total)
}

/// Verify that `approvals` carries at least `threshold` weight in the given
/// signer set, reporting `shortfall` when it does not.
///
/// A zero threshold is refused with [`Error::InvalidThreshold`] before any
/// tally is taken, so an empty approval list can never authorize an action.
/// All the duplicate, non-signer, zero-weight and overflow semantics of
/// [`tally_approvals`] apply. Returns the verified total weight.
pub fn verify_approvals(
    signers: &[Address],
    weights: &[u32],
    approvals: &[Address],
    threshold: u32,
    shortfall: Error,
) -> Result<u32, Error> {
    if threshold == 0 {
        return Err(Error::InvalidThreshold);
    }
    let total = tally_approvals(signers, weights, approvals)?;
    require_threshold(total, threshold, shortfall)?;
    Ok(total)
}
