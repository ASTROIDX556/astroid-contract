//! Consolidated, deterministic error codes for the Astroid protocol.
//!
//! This module re-exports the canonical [`Error`] enum from `astroid_shared`
//! so that all contracts and client SDKs depend on a single, stable error
//! surface. Every variant carries an explicit `u32` discriminant that is part
//! of the public ABI and MUST NOT be reordered or reused once released.

pub use astroid_shared::errors::Error;

#[cfg(test)]
mod test {
    extern crate alloc;

    use super::*;
    use alloc::{format, string::String};
    use soroban_sdk::xdr::{Limits, ReadXdr, ScErrorType, ScSpecEntry, ScSpecUdtErrorEnumV0};
    use soroban_sdk::{testutils::Ledger, Env, InvokeError};

    /// Every variant of the consolidated error enum, grouped by domain.
    /// All per-variant tests iterate this table. When introducing a new
    /// variant, add it here with its assigned code — the stability, uniqueness
    /// and serialization tests will then cover it automatically.
    const ALL_VARIANTS: &[(Error, u32)] = &[
        // Generic / lifecycle (1-6)
        (Error::NotFound, 1),
        (Error::AlreadyExists, 2),
        (Error::Unauthorized, 3),
        (Error::InvalidInput, 4),
        (Error::NotInitialized, 5),
        (Error::AlreadyInitialized, 6),
        // Value / arithmetic (10-12)
        (Error::InsufficientFunds, 10),
        (Error::Overflow, 11),
        (Error::InvalidAmount, 12),
        // Policy (20-27; 25 retired, never reused)
        (Error::PolicyDenied, 20),
        (Error::EmergencyLock, 21),
        (Error::PolicyRecipientRestricted, 22),
        (Error::PolicyMerchantBlocked, 23),
        (Error::PolicyCategoryRestricted, 24),
        (Error::PolicyAllowanceExceeded, 26),
        // Registry (30-39)
        (Error::RegistryFrozen, 30),
        (Error::ModuleDeprecated, 31),
        // Budget (40-44)
        (Error::BudgetExceeded, 40),
        (Error::BudgetFrozen, 41),
        (Error::BudgetArchived, 42),
        (Error::AssetNotAuthorized, 43),
        (Error::BudgetExpired, 44),
        // Wallet (50-53)
        (Error::WalletFrozen, 50),
        (Error::WalletArchived, 51),
        (Error::WalletPaused, 52),
        (Error::InvalidState, 53),
        // Multisig / approvals (61-69, 90-92)
        (Error::ThresholdNotMet, 61),
        (Error::AlreadySigned, 62),
        (Error::NotASigner, 63),
        (Error::InvalidThreshold, 64),
        (Error::TooManySigners, 66),
        (Error::BatchCallFailed, 67),
        (Error::InvalidNonce, 68),
        (Error::InvalidSignerWeight, 69),
        (Error::InsufficientWeight, 90),
        (Error::TimelockNotExpired, 91),
        (Error::UnauthorizedModification, 92),
        // Proposal (71-79)
        (Error::ProposalExpired, 71),
        (Error::InvalidProposalState, 72),
        (Error::ProposalNotApproved, 73),
        (Error::NotAnApprover, 74),
        (Error::CancellationWindowClosed, 75),
        (Error::PrerequisiteNotMet, 78),
        (Error::CircularDependencyDetected, 79),
        // Escrow (80-82)
        (Error::EscrowExpired, 80),
        (Error::TimeLockActive, 81),
        (Error::GraceActive, 82),
        // Treasury (83-85)
        (Error::AllowanceExceeded, 83),
        (Error::AllowanceExpired, 84),
        (Error::TreasuryPaused, 85),
    ];

    /// Verify that every Error variant has a stable, explicit u32 discriminant.
    /// These values are part of the public ABI and must never change.
    #[test]
    fn error_discriminants_are_stable() {
        for (variant, code) in ALL_VARIANTS {
            assert_eq!(
                *variant as u32, *code,
                "discriminant of {variant:?} changed"
            );
        }
    }

    /// Verify no duplicate discriminants exist (critical for ABI stability).
    #[test]
    fn error_discriminants_are_unique() {
        for (i, (_, code_a)) in ALL_VARIANTS.iter().enumerate() {
            for (variant_b, code_b) in ALL_VARIANTS.iter().skip(i + 1) {
                assert_ne!(
                    code_a, code_b,
                    "duplicate discriminant {code_a}: {:?} vs {:?}",
                    ALL_VARIANTS[i].0, variant_b,
                );
            }
        }
    }

    /// Verify that Error implements the required traits for Soroban SDK
    /// compatibility (`#[contracterror]` requires `Copy`).
    #[test]
    fn error_implements_required_traits() {
        fn assert_contracterror_traits<T: Copy + Clone + core::fmt::Debug + Eq + PartialEq>() {}
        assert_contracterror_traits::<Error>();
    }

    /// Verify Error can be used as a contract error return type.
    #[test]
    fn error_as_contract_return() {
        let env = Env::default();
        env.ledger().set_timestamp(1_000);

        fn returns_error() -> Result<(), Error> {
            Err(Error::PolicyDenied)
        }

        let result = returns_error();
        assert_eq!(result, Err(Error::PolicyDenied));

        // Verify the error code is accessible
        assert_eq!(result.unwrap_err() as u32, 20);
    }

    /// Verify that Error can be constructed from its discriminant (for
    /// off-chain SDKs).
    #[test]
    fn error_from_discriminant() {
        for (variant, code) in ALL_VARIANTS {
            // SAFETY: Error is a fieldless enum with `#[repr(u32)]`-style
            // explicit discriminants, so `transmute` from a valid discriminant
            // round-trips to the matching variant.
            let round_tripped: Error = unsafe { core::mem::transmute(*code) };
            assert_eq!(round_tripped, *variant, "discriminant {code} mismatch");
        }
    }

    /// Verify the generated interface spec is present and valid: it must
    /// deserialize as a `ScSpecEntry::UdtErrorEnumV0` whose cases carry the
    /// exact variant names and codes client SDKs generate bindings from.
    #[test]
    fn error_spec_xdr_deserializes_with_all_variants() {
        let spec_bytes = Error::spec_xdr();
        let entry = ScSpecEntry::from_xdr(spec_bytes, Limits::none())
            .expect("generated spec XDR must deserialize");

        let ScSpecEntry::UdtErrorEnumV0(ScSpecUdtErrorEnumV0 {
            name,
            doc: _,
            lib: _,
            cases,
        }) = entry
        else {
            panic!("spec entry must be a UdtErrorEnumV0");
        };
        assert_eq!(
            String::from_utf8_lossy(&name),
            "Error",
            "spec type name must match the enum name"
        );

        assert_eq!(
            cases.len(),
            ALL_VARIANTS.len(),
            "spec must expose exactly one case per variant"
        );
        for (case, (variant, code)) in cases.iter().zip(ALL_VARIANTS.iter()) {
            assert_eq!(
                case.value,
                *code,
                "spec case {:?} carries wrong code",
                String::from_utf8_lossy(&case.name)
            );
            assert_eq!(
                String::from_utf8_lossy(&case.name),
                format!("{variant:?}"),
                "spec case name must match the Rust variant name"
            );
        }
    }

    /// Verify every variant converts losslessly into the SDK's host error
    /// (`Into<soroban_sdk::Error>`, what `panic_with_error!` raises on-chain)
    /// and preserves its code and Contract error type.
    #[test]
    fn error_converts_into_sdk_error_preserving_code() {
        for (variant, code) in ALL_VARIANTS {
            let host_error: soroban_sdk::Error = (*variant).into();
            assert!(
                host_error.is_type(ScErrorType::Contract),
                "{variant:?} must map to a Contract-type host error"
            );
            assert_eq!(
                host_error.get_code(),
                *code,
                "{variant:?} must preserve its discriminant in the host error"
            );
        }
    }

    /// Verify the inverse conversion: an SDK host error built from a known
    /// code converts back via `TryFrom` to the exact protocol variant, and
    /// that codes outside the enum do not fabricate a variant (fail closed).
    #[test]
    fn error_try_from_sdk_error_round_trips() {
        for (variant, code) in ALL_VARIANTS {
            let host_error = soroban_sdk::Error::from_contract_error(*code);
            let round_tripped = Error::try_from(host_error)
                .unwrap_or_else(|_| panic!("code {code} must convert back to {variant:?}"));
            assert_eq!(round_tripped, *variant);

            // The same conversion via the InvokeError representation.
            let invoke: InvokeError = (*variant).into();
            assert_eq!(invoke, InvokeError::Contract(*code));
            assert_eq!(
                Error::try_from(invoke).expect("InvokeError::Contract must convert back"),
                *variant
            );
        }

        // A Contract-type code this enum does not define must fail conversion
        // rather than invent a variant.
        let unassigned = soroban_sdk::Error::from_contract_error(999);
        assert!(Error::try_from(unassigned).is_err());
    }

    /// Verify the ScVal wire representation: on the Soroban host a contract
    /// error enum is serialized as `ScVal::Error(ScError::Contract(code))`,
    /// so a variant → host error → ScVal round trip must carry the exact
    /// discriminant client SDKs decode.
    #[test]
    fn error_scval_serialization_round_trips() {
        use soroban_sdk::xdr::{ScError, ScVal};
        use soroban_sdk::TryFromVal;

        for (variant, code) in ALL_VARIANTS {
            let env = Env::default();
            // The macro generates `TryFromVal<Env, Error> for Val` (what
            // `panic_with_error!` raises) but no bare `From<Error> for Val`,
            // so route through the SDK host error.
            let host: soroban_sdk::Error = (*variant).into();
            let val: soroban_sdk::Val = host.into();
            // On-wire representation seen by off-chain decoders.
            let sc_val =
                ScVal::try_from_val(&env, &val).expect("contract error must serialize to an ScVal");
            assert_eq!(
                sc_val,
                ScVal::Error(ScError::Contract(*code)),
                "{variant:?} must serialize as ScVal::Error(Contract({code}))"
            );

            // And the wire bytes decode back to the exact variant.
            let round_tripped = Error::try_from_val(&env, &val)
                .expect("serialized error must convert back to the enum");
            assert_eq!(round_tripped, *variant);
        }
    }

    /// Smoke-test the crate-root re-export path SDK consumers rely on
    /// (`astroid_interfaces::Error`): it must be one and the same type as the
    /// canonical shared error, so client code written against the interfaces
    /// crate interoperates with every member contract's `Result<_, Error>`.
    #[test]
    fn crate_root_reexport_is_the_canonical_error() {
        fn assert_same_type<T>(_: T, _: T) {}
        assert_same_type(Error::NotFound, astroid_shared::errors::Error::NotFound);
    }
}
