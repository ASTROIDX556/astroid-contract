//! Version comparison and upgrade-transition validation for the registry
//! (Issue #445).
//!
//! The registry is the protocol's single source of truth for module addresses
//! and upgrade paths. A module's version pin is a high-water mark: every move
//! must be strictly forward. The helpers here are the pure, side-effect-free
//! core of that rule so the comparison itself can be unit-tested without a
//! Soroban host and shared by every entrypoint that plans an upgrade.
//!
//! Versions are the monotonic `u32` numbers published by
//! [`crate::RegistryContract::register_version`]. `0` is reserved for "not
//! pinned yet" — a module registered by address before validated upgrades — so
//! it can be the start of a path but never a target.

use core::cmp::Ordering;

use astroid_shared::errors::Error;

/// The largest forward step a standalone pre-flight may approve.
///
/// Deployment tooling that walks a path one release at a time can use this as a
/// typo guard: a jump of sixteen or more versions between neighbouring
/// deployments is almost certainly a misconfigured module replacement rather
/// than an intentional upgrade. The on-chain upgrade path itself is bounded by
/// the published version records, not by this constant; this limit applies to
/// [`validate_upgrade_step`].
pub const MAX_FORWARD_STEP: u32 = 16;

/// Order two versions. Kept as a helper rather than an inline `cmp` so every
/// caller agrees on what "newer" means and a future change to the version
/// representation has exactly one place to land.
pub fn compare_versions(current: u32, target: u32) -> Ordering {
    current.cmp(&target)
}

/// Whether `target` is a strict forward step from `current`.
///
/// Equality is deliberately *not* forward: repointing a module at the version
/// it already runs changes neither code nor routing and would let a caller
/// fake progress in the upgrade path.
pub fn is_strictly_newer(current: u32, target: u32) -> bool {
    matches!(compare_versions(current, target), Ordering::Less)
}

/// Validate a version transition with the deterministic registry error codes.
///
/// - `target == 0` is an uninitialized read, never a published version:
///   [`Error::InvalidInput`].
/// - a target at or behind the current pin would roll the module back or repeat
///   its current version: [`Error::VersionNotMonotonic`].
/// - a strictly forward target is accepted.
///
/// This is the single definition of "monotonic" used by both the read-only
/// pre-flight and the write path, so the two can never disagree about whether
/// a version transition is legal.
pub fn validate_transition(current: u32, target: u32) -> Result<(), Error> {
    if target == 0 {
        return Err(Error::InvalidInput);
    }
    if !is_strictly_newer(current, target) {
        return Err(Error::VersionNotMonotonic);
    }
    Ok(())
}

/// Validate a transition and additionally cap how far forward it may jump.
///
/// Used by the owner-facing pre-flight entrypoint to reject an obviously
/// misconfigured target (e.g. `v1 → v200`) before any deployment is attempted.
/// The ordering check runs first, so a backwards jump still reports
/// [`Error::VersionNotMonotonic`] rather than the jump error.
pub fn validate_upgrade_step(current: u32, target: u32) -> Result<(), Error> {
    validate_transition(current, target)?;
    let step = target
        .checked_sub(current)
        .ok_or(Error::VersionNotMonotonic)?;
    if step > MAX_FORWARD_STEP {
        return Err(Error::InvalidInput);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comparison_orders_versions_strictly() {
        assert_eq!(compare_versions(1, 2), Ordering::Less);
        assert_eq!(compare_versions(2, 2), Ordering::Equal);
        assert_eq!(compare_versions(3, 2), Ordering::Greater);
    }

    #[test]
    fn only_a_strictly_newer_version_is_forward() {
        assert!(is_strictly_newer(0, 1));
        assert!(is_strictly_newer(2, 3));
        assert!(!is_strictly_newer(2, 2));
        assert!(!is_strictly_newer(3, 2));
    }

    #[test]
    fn transition_accepts_sequential_and_forward_steps() {
        assert_eq!(validate_transition(0, 1), Ok(()));
        assert_eq!(validate_transition(1, 2), Ok(()));
        assert_eq!(validate_transition(2, 5), Ok(()));
    }

    #[test]
    fn transition_rejects_downgrade_repeat_and_zero() {
        assert_eq!(validate_transition(3, 2), Err(Error::VersionNotMonotonic));
        assert_eq!(validate_transition(2, 2), Err(Error::VersionNotMonotonic));
        assert_eq!(validate_transition(0, 0), Err(Error::InvalidInput));
        assert_eq!(validate_transition(3, 0), Err(Error::InvalidInput));
    }

    #[test]
    fn bounded_step_rejects_an_oversized_jump() {
        assert_eq!(validate_upgrade_step(1, 1 + MAX_FORWARD_STEP), Ok(()));
        assert_eq!(
            validate_upgrade_step(1, 2 + MAX_FORWARD_STEP),
            Err(Error::InvalidInput)
        );
        // Ordering wins over the jump guard so a rollback keeps its own code.
        assert_eq!(
            validate_upgrade_step(100, 2),
            Err(Error::VersionNotMonotonic)
        );
    }
}
