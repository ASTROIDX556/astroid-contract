//! Consolidated, deterministic error codes for the Astroid protocol.
//!
//! This module re-exports the canonical [`Error`] enum from `astroid_shared`
//! so that all contracts and client SDKs depend on a single, stable error
//! surface. Every variant carries an explicit `u32` discriminant that is part
//! of the public ABI and MUST NOT be reordered or reused once released.

pub use astroid_shared::errors::Error;

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::{testutils::Ledger, Env};

    /// Verify that every Error variant has a stable, explicit u32 discriminant.
    /// These values are part of the public ABI and must never change.
    #[test]
    fn error_discriminants_are_stable() {
        // Generic / lifecycle (1-6)
        assert_eq!(Error::NotFound as u32, 1);
        assert_eq!(Error::AlreadyExists as u32, 2);
        assert_eq!(Error::Unauthorized as u32, 3);
        assert_eq!(Error::InvalidInput as u32, 4);
        assert_eq!(Error::NotInitialized as u32, 5);
        assert_eq!(Error::AlreadyInitialized as u32, 6);

        // Value / arithmetic (10-12)
        assert_eq!(Error::InsufficientFunds as u32, 10);
        assert_eq!(Error::Overflow as u32, 11);
        assert_eq!(Error::InvalidAmount as u32, 12);

        // Policy (20-27)
        assert_eq!(Error::PolicyDenied as u32, 20);
        assert_eq!(Error::EmergencyLock as u32, 21);
        assert_eq!(Error::PolicyRecipientRestricted as u32, 22);
        assert_eq!(Error::PolicyMerchantBlocked as u32, 23);
        assert_eq!(Error::PolicyCategoryRestricted as u32, 24);
        assert_eq!(Error::AssetNotWhitelisted as u32, 25);
        assert_eq!(Error::PolicyAllowanceExceeded as u32, 26);

        // Registry (30-39)
        assert_eq!(Error::RegistryFrozen as u32, 30);
        assert_eq!(Error::ModuleDeprecated as u32, 31);

        // Budget (40-44)
        assert_eq!(Error::BudgetExceeded as u32, 40);
        assert_eq!(Error::BudgetFrozen as u32, 41);
        assert_eq!(Error::BudgetArchived as u32, 42);
        assert_eq!(Error::AssetNotAuthorized as u32, 43);
        assert_eq!(Error::BudgetExpired as u32, 44);

        // Wallet (50-53)
        assert_eq!(Error::WalletFrozen as u32, 50);
        assert_eq!(Error::WalletArchived as u32, 51);
        assert_eq!(Error::WalletPaused as u32, 52);
        assert_eq!(Error::InvalidState as u32, 53);

        // Multisig / approvals (61-69, 90-92)
        assert_eq!(Error::ThresholdNotMet as u32, 61);
        assert_eq!(Error::AlreadySigned as u32, 62);
        assert_eq!(Error::NotASigner as u32, 63);
        assert_eq!(Error::InvalidThreshold as u32, 64);
        assert_eq!(Error::TooManySigners as u32, 66);
        assert_eq!(Error::BatchCallFailed as u32, 67);
        assert_eq!(Error::InvalidNonce as u32, 68);
        assert_eq!(Error::InvalidSignerWeight as u32, 69);
        assert_eq!(Error::InsufficientWeight as u32, 90);
        assert_eq!(Error::TimelockNotExpired as u32, 91);
        assert_eq!(Error::UnauthorizedModification as u32, 92);

        // Proposal (71-79)
        assert_eq!(Error::ProposalExpired as u32, 71);
        assert_eq!(Error::InvalidProposalState as u32, 72);
        assert_eq!(Error::ProposalNotApproved as u32, 73);
        assert_eq!(Error::NotAnApprover as u32, 74);
        assert_eq!(Error::CancellationWindowClosed as u32, 75);
        assert_eq!(Error::PrerequisiteNotMet as u32, 78);
        assert_eq!(Error::CircularDependencyDetected as u32, 79);

        // Escrow (80-82)
        assert_eq!(Error::EscrowExpired as u32, 80);
        assert_eq!(Error::TimeLockActive as u32, 81);
        assert_eq!(Error::GraceActive as u32, 82);

        // Treasury allowances (83-84)
        assert_eq!(Error::AllowanceExceeded as u32, 83);
        assert_eq!(Error::AllowanceExpired as u32, 84);
    }

    /// Verify that Error implements the required traits for Soroban SDK compatibility.
    #[test]
    fn error_implements_required_traits() {
        fn assert_copy_clone_debug_eq_partial_eq<
            T: Copy + Clone + core::fmt::Debug + Eq + PartialEq,
        >() {
        }
        assert_copy_clone_debug_eq_partial_eq::<Error>();
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

    /// Verify that Error can be constructed from its discriminant (for off-chain SDKs).
    #[test]
    fn error_from_discriminant() {
        // This tests that the discriminant values match what off-chain SDKs expect
        // Off-chain consumers can map u32 codes to Error variants
        let code_to_variant = [
            (1u32, Error::NotFound),
            (3u32, Error::Unauthorized),
            (10u32, Error::InsufficientFunds),
            (20u32, Error::PolicyDenied),
            (40u32, Error::BudgetExceeded),
            (50u32, Error::WalletFrozen),
            (61u32, Error::ThresholdNotMet),
            (71u32, Error::ProposalExpired),
            (80u32, Error::EscrowExpired),
            (83u32, Error::AllowanceExceeded),
        ];

        for (code, expected) in code_to_variant {
            // Verify we can match by discriminant
            let variant: Error = unsafe { core::mem::transmute(code) };
            assert_eq!(variant, expected, "discriminant {} mismatch", code);
        }
    }

    /// Verify no duplicate discriminants exist (critical for ABI stability).
    #[test]
    fn error_discriminants_are_unique() {
        // Simple O(n^2) check since we have a fixed, small number of variants
        let variants = [
            Error::NotFound,
            Error::AlreadyExists,
            Error::Unauthorized,
            Error::InvalidInput,
            Error::NotInitialized,
            Error::AlreadyInitialized,
            Error::InsufficientFunds,
            Error::Overflow,
            Error::InvalidAmount,
            Error::PolicyDenied,
            Error::EmergencyLock,
            Error::PolicyRecipientRestricted,
            Error::PolicyMerchantBlocked,
            Error::PolicyCategoryRestricted,
            Error::AssetNotWhitelisted,
            Error::PolicyAllowanceExceeded,
            Error::RegistryFrozen,
            Error::ModuleDeprecated,
            Error::BudgetExceeded,
            Error::BudgetFrozen,
            Error::BudgetArchived,
            Error::AssetNotAuthorized,
            Error::BudgetExpired,
            Error::WalletFrozen,
            Error::WalletArchived,
            Error::WalletPaused,
            Error::InvalidState,
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
            Error::ProposalExpired,
            Error::InvalidProposalState,
            Error::ProposalNotApproved,
            Error::NotAnApprover,
            Error::CancellationWindowClosed,
            Error::PrerequisiteNotMet,
            Error::CircularDependencyDetected,
            Error::EscrowExpired,
            Error::TimeLockActive,
            Error::GraceActive,
            Error::AllowanceExceeded,
            Error::AllowanceExpired,
        ];

        for i in 0..variants.len() {
            for j in (i + 1)..variants.len() {
                assert_ne!(
                    variants[i] as u32, variants[j] as u32,
                    "Duplicate discriminant for {:?} and {:?}",
                    variants[i], variants[j]
                );
            }
        }
    }
}
