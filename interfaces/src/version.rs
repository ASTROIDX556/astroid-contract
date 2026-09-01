//! Interface version negotiation helpers.
//!
//! Astroid contracts upgrade independently. Before making or accepting
//! cross-contract calls, a callee and caller may need to verify that they
//! speak compatible versions of the *shared interface* (the trait signatures
//! defined in this crate). This module provides the primitives for that check.
//!
//! # What a version represents
//!
//! A [`Version`] is a `(major, minor)` pair that tracks the **interface**
//! contract — the set of function signatures, return types and error semantics
//! defined by a trait in this crate — *not* the implementation details of any
//! particular on-chain deployment. Two contracts that advertise the same
//! interface version agree on the shape of calls they can make to each other;
//! they may still differ in internal state, gas usage or business logic.
//!
//! # Versioning rules
//!
//! | Change kind                                     | Bump         |
//! |-------------------------------------------------|--------------|
//! | Added optional field / new optional trait method | `minor += 1` |
//! | Removed method, changed signature, changed error set | `major += 1`, `minor = 0` |
//!
//! A **breaking** interface change (method removed, parameter type changed,
//! return type changed, new *required* method added) increments `major` and
//! resets `minor` to 0. A **backward-compatible** addition (new optional
//! method, new return field) increments `minor` only.
//!
//! # How consumers should use this
//!
//! 1. Each contract stores (or hard-codes) the [`CURRENT_VERSION`] of every
//!    shared interface it *implements*.
//! 2. Before calling a remote contract the caller passes its own
//!    [`CURRENT_VERSION`] and the remote contract's advertised version to
//!    [`require_compatible`]. If the call returns `Err`, the caller must not
//!    proceed.
//! 3. The callee can perform the symmetric check on entry.
//!
//! [`require_compatible`] returns [`Ok(())`] when `actual` ≥ `minimum` (same
//! major, minor ≥ required). Any incompatibility produces
//! [`Error::InvalidInput`].

use astroid_shared::errors::Error;
use soroban_sdk::contracttype;

/// The current shared interface version. Bump this when *any* trait in this
/// crate receives a breaking change. New contracts should reference this
/// constant (rather than literal values) so the version stays in sync with the
/// compiled trait definitions.
pub const CURRENT_VERSION: Version = Version { major: 1, minor: 0 };

/// A simple `(major, minor)` interface version.
///
/// - `major` — breaking interface change counter (reset on bump).
/// - `minor` — backward-compatible addition counter (reset when `major` bumps).
///
/// Two versions are **compatible** when they share the same `major` and the
/// actual `minor` is greater than or equal to the required minimum.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
}

impl Version {
    /// Create a new version.
    pub const fn new(major: u32, minor: u32) -> Self {
        Self { major, minor }
    }

    /// Return `true` when `self` satisfies the `minimum` requirement:
    /// same major and `self.minor >= minimum.minor`.
    pub const fn is_compatible_with(self, minimum: Self) -> bool {
        self.major == minimum.major && self.minor >= minimum.minor
    }
}

/// Check whether `actual` is compatible with `minimum`.
///
/// Returns [`Ok(())`] when `actual` has the same `major` as `minimum` and its
/// `minor` is greater than or equal to the required `minor`.
///
/// Returns [`Err(Error::InvalidInput)`] when the versions are
/// incompatible — callers **must not** proceed with the cross-contract call.
///
/// # Examples
///
/// ```ignore
/// // Same version — compatible.
/// require_compatible(Version::new(1, 0), Version::new(1, 0))?;
///
/// // Newer minor — compatible.
/// require_compatible(Version::new(1, 2), Version::new(1, 0))?;
///
/// // Different major — incompatible.
/// require_compatible(Version::new(2, 0), Version::new(1, 0))?; // Err
/// ```
pub fn require_compatible(actual: Version, minimum: Version) -> Result<(), Error> {
    if actual.is_compatible_with(minimum) {
        Ok(())
    } else {
        Err(Error::InvalidInput)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // Same version
    // ------------------------------------------------------------------

    #[test]
    fn same_version_is_compatible() {
        let v = Version::new(1, 0);
        assert_eq!(require_compatible(v, v), Ok(()));
    }

    #[test]
    fn same_version_minor_nonzero() {
        let v = Version::new(1, 5);
        assert_eq!(require_compatible(v, v), Ok(()));
    }

    // ------------------------------------------------------------------
    // Newer compatible version satisfies older minimum
    // ------------------------------------------------------------------

    #[test]
    fn newer_minor_satisfies_older_minimum() {
        assert_eq!(
            require_compatible(Version::new(1, 3), Version::new(1, 0)),
            Ok(())
        );
    }

    #[test]
    fn newer_minor_satisfies_exact_minimum() {
        assert_eq!(
            require_compatible(Version::new(1, 5), Version::new(1, 5)),
            Ok(())
        );
    }

    // ------------------------------------------------------------------
    // Older version fails against newer requirement
    // ------------------------------------------------------------------

    #[test]
    fn older_minor_fails_against_newer_minimum() {
        assert_eq!(
            require_compatible(Version::new(1, 0), Version::new(1, 3)),
            Err(Error::InvalidInput)
        );
    }

    #[test]
    fn older_major_fails() {
        assert_eq!(
            require_compatible(Version::new(0, 9), Version::new(1, 0)),
            Err(Error::InvalidInput)
        );
    }

    // ------------------------------------------------------------------
    // Boundary versions
    // ------------------------------------------------------------------

    #[test]
    fn boundary_major_mismatch() {
        // Same minor but different major — incompatible.
        assert_eq!(
            require_compatible(Version::new(2, 0), Version::new(1, 0)),
            Err(Error::InvalidInput)
        );
    }

    #[test]
    fn boundary_minor_exactly_one_less() {
        assert_eq!(
            require_compatible(Version::new(1, 4), Version::new(1, 5)),
            Err(Error::InvalidInput)
        );
    }

    #[test]
    fn boundary_minor_exactly_one_more() {
        assert_eq!(
            require_compatible(Version::new(1, 6), Version::new(1, 5)),
            Ok(())
        );
    }

    #[test]
    fn zero_versions_compatible() {
        assert_eq!(
            require_compatible(Version::new(0, 0), Version::new(0, 0)),
            Ok(())
        );
    }

    #[test]
    fn zero_major_with_higher_minor() {
        assert_eq!(
            require_compatible(Version::new(0, 5), Version::new(0, 2)),
            Ok(())
        );
    }

    // ------------------------------------------------------------------
    // Structured error
    // ------------------------------------------------------------------

    #[test]
    fn incompatible_returns_structured_error() {
        let result = require_compatible(Version::new(1, 0), Version::new(2, 0));
        assert_eq!(result, Err(Error::InvalidInput));
        // Verify the error code is 4.
        assert_eq!(result.unwrap_err() as u32, 4);
    }

    // ------------------------------------------------------------------
    // is_compatible_with (const)
    // ------------------------------------------------------------------

    #[test]
    fn is_compatible_with_reflects_semantics() {
        assert!(Version::new(1, 5).is_compatible_with(Version::new(1, 0)));
        assert!(!Version::new(1, 0).is_compatible_with(Version::new(1, 5)));
        assert!(!Version::new(2, 0).is_compatible_with(Version::new(1, 0)));
        assert!(Version::new(0, 0).is_compatible_with(Version::new(0, 0)));
    }

    // ------------------------------------------------------------------
    // CURRENT_VERSION sanity
    // ------------------------------------------------------------------

    #[test]
    fn current_version_is_compatible_with_itself() {
        assert_eq!(require_compatible(CURRENT_VERSION, CURRENT_VERSION), Ok(()));
    }

    #[test]
    fn current_version_major_is_positive() {
        const _: () = assert!(CURRENT_VERSION.major >= 1);
    }
}
