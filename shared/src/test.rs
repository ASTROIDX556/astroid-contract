#![cfg(test)]
//! Unit tests for the shared math, validation and constant helpers.

use crate::constants::{INSTANCE_BUMP_AMOUNT, INSTANCE_LIFETIME_THRESHOLD, MAX_SIGNERS};
use crate::errors::Error;
use crate::math::{
    checked_abs, checked_add, checked_div, checked_mul, checked_neg, checked_rem, checked_sub,
};
use crate::validation::{
    require_non_negative_amount, require_not_expired, require_positive_amount,
    require_time_reached, require_within_amount_bounds,
};
use soroban_sdk::testutils::Ledger;
use soroban_sdk::Env;

// ---------------------------------------------------------------------------
// checked_add
// ---------------------------------------------------------------------------

#[test]
fn add_happy_path() {
    assert_eq!(checked_add(0, 0), Ok(0));
    assert_eq!(checked_add(2, 3), Ok(5));
    assert_eq!(checked_add(-2, -3), Ok(-5));
    assert_eq!(checked_add(-5, 5), Ok(0));
    assert_eq!(checked_add(5, -5), Ok(0));
}

#[test]
fn add_identity() {
    assert_eq!(checked_add(42, 0), Ok(42));
    assert_eq!(checked_add(0, 42), Ok(42));
    assert_eq!(checked_add(-42, 0), Ok(-42));
}

#[test]
fn add_overflow() {
    assert_eq!(checked_add(i128::MAX, 1), Err(Error::Overflow));
    assert_eq!(checked_sub(i128::MIN, 1), Err(Error::Overflow));
    assert_eq!(checked_mul(i128::MAX, 2), Err(Error::Overflow));
    assert_eq!(checked_mul(i128::MAX, i128::MAX), Err(Error::Overflow));
    assert_eq!(checked_mul(i128::MAX, 100), Err(Error::Overflow));
}

#[test]
fn mul_underflow() {
    // i128::MIN * 2 overflows because |i128::MIN| > i128::MAX.
    assert_eq!(checked_mul(i128::MIN, 2), Err(Error::Overflow));
    // i128::MIN * -1 overflows because -i128::MIN cannot be represented.
    assert_eq!(checked_mul(i128::MIN, -1), Err(Error::Overflow));
}

#[test]
fn mul_large_values() {
    // Both large positive — still fits.
    assert_eq!(checked_mul(1_000_000, 1_000_000), Ok(1_000_000_000_000));
    // True overflow: max * 2 wraps past the upper bound.
    assert_eq!(checked_mul(i128::MAX, 2), Err(Error::Overflow));
    // Large negative * large positive — fits in i128 (order 10^24).
    assert_eq!(
        checked_mul(-1_000_000_000_000i128, 1_000_000_000_000i128),
        Ok(-1_000_000_000_000_000_000_000_000i128)
    );
}

// ---------------------------------------------------------------------------
// checked_div
// ---------------------------------------------------------------------------

#[test]
fn div_happy_path() {
    assert_eq!(checked_div(20, 5), Ok(4));
    assert_eq!(checked_div(-20, 5), Ok(-4));
    assert_eq!(checked_div(20, -5), Ok(-4));
    assert_eq!(checked_div(-20, -5), Ok(4));
}

#[test]
fn div_identity() {
    assert_eq!(checked_div(42, 1), Ok(42));
    assert_eq!(checked_div(-42, 1), Ok(-42));
    assert_eq!(checked_div(42, -1), Ok(-42));
}

#[test]
fn div_zero_dividend() {
    assert_eq!(checked_div(0, 5), Ok(0));
    assert_eq!(checked_div(0, -5), Ok(0));
}

#[test]
fn div_by_zero() {
    assert_eq!(checked_div(0, 0), Err(Error::InvalidInput));
    assert_eq!(checked_div(42, 0), Err(Error::InvalidInput));
    assert_eq!(checked_div(-42, 0), Err(Error::InvalidInput));
}

#[test]
fn div_truncation() {
    // Integer division truncates toward zero.
    assert_eq!(checked_div(7, 2), Ok(3));
    assert_eq!(checked_div(-7, 2), Ok(-3));
    assert_eq!(checked_div(7, -2), Ok(-3));
}

#[test]
fn div_overflow() {
    // i128::MIN / -1 cannot be represented.
    assert_eq!(checked_div(i128::MIN, -1), Err(Error::Overflow));
}

// ---------------------------------------------------------------------------
// checked_rem
// ---------------------------------------------------------------------------

#[test]
fn rem_happy_path() {
    assert_eq!(checked_rem(7, 3), Ok(1));
    assert_eq!(checked_rem(-7, 3), Ok(-1));
    assert_eq!(checked_rem(7, -3), Ok(1));
    assert_eq!(checked_rem(-7, -3), Ok(-1));
}

#[test]
fn rem_zero_dividend() {
    assert_eq!(checked_rem(0, 5), Ok(0));
    assert_eq!(checked_rem(0, -5), Ok(0));
}

#[test]
fn rem_by_zero() {
    assert_eq!(checked_rem(42, 0), Err(Error::InvalidInput));
    assert_eq!(checked_rem(0, 0), Err(Error::InvalidInput));
}

#[test]
fn rem_exact_division() {
    assert_eq!(checked_rem(10, 5), Ok(0));
    assert_eq!(checked_rem(-10, 5), Ok(0));
}

// ---------------------------------------------------------------------------
// checked_neg
// ---------------------------------------------------------------------------

#[test]
fn neg_happy_path() {
    assert_eq!(checked_neg(0), Ok(0));
    assert_eq!(checked_neg(42), Ok(-42));
    assert_eq!(checked_neg(-42), Ok(42));
}

#[test]
fn neg_overflow() {
    // -i128::MIN cannot be represented as i128.
    assert_eq!(checked_neg(i128::MIN), Err(Error::Overflow));
}

#[test]
fn neg_extremes() {
    assert_eq!(checked_neg(i128::MAX), Ok(-i128::MAX));
    assert_eq!(checked_neg(-i128::MAX), Ok(i128::MAX));
}

// ---------------------------------------------------------------------------
// checked_abs
// ---------------------------------------------------------------------------

#[test]
fn abs_happy_path() {
    assert_eq!(checked_abs(0), Ok(0));
    assert_eq!(checked_abs(42), Ok(42));
    assert_eq!(checked_abs(-42), Ok(42));
}

#[test]
fn abs_overflow() {
    // |i128::MIN| cannot be represented as i128.
    assert_eq!(checked_abs(i128::MIN), Err(Error::Overflow));
}

#[test]
fn abs_extremes() {
    assert_eq!(checked_abs(i128::MAX), Ok(i128::MAX));
    assert_eq!(checked_abs(-i128::MAX), Ok(i128::MAX));
}

#[test]
fn math_additional_edge_cases() {
    // Underflow only when the result drops below the minimum value. All wraps
    // are reported as Overflow by the checked helpers.
    assert_eq!(checked_sub(0, 1), Ok(-1));
    assert_eq!(checked_sub(i128::MIN, 1), Err(Error::Overflow));
    assert_eq!(checked_add(i128::MIN, -1), Err(Error::Overflow));
    // Multiplication overflow on the extreme negative bound.
    assert_eq!(checked_mul(i128::MIN, -1), Err(Error::Overflow));
    assert_eq!(checked_mul(i128::MIN, 2), Err(Error::Overflow));
    // Division by zero is rejected before any arithmetic is attempted.
    assert_eq!(checked_div(0, 0), Err(Error::InvalidInput));
    assert_eq!(checked_div(-7, 0), Err(Error::InvalidInput));
    // The one division that overflows: MIN / -1 has no representable result.
    assert_eq!(checked_div(i128::MIN, -1), Err(Error::Overflow));
    // Zero and identity operations stay exact.
    assert_eq!(checked_add(i128::MAX, 0), Ok(i128::MAX));
    assert_eq!(checked_mul(0, i128::MAX), Ok(0));
    assert_eq!(checked_div(i128::MIN, 1), Ok(i128::MIN));
}

#[test]
fn amount_validation() {
    assert_eq!(require_positive_amount(1), Ok(()));
    assert_eq!(require_positive_amount(0), Err(Error::InvalidAmount));
    assert_eq!(require_positive_amount(-1), Err(Error::InvalidAmount));
    assert_eq!(require_non_negative_amount(0), Ok(()));
    assert_eq!(require_non_negative_amount(-5), Err(Error::InvalidAmount));
}

#[test]
fn amount_bounds() {
    // Within [10, 100].
    assert_eq!(require_within_amount_bounds(50, 10, 100), Ok(()));
    // Below min.
    assert_eq!(
        require_within_amount_bounds(5, 10, 100),
        Err(Error::PolicyDenied)
    );
    // Above max.
    assert_eq!(
        require_within_amount_bounds(150, 10, 100),
        Err(Error::PolicyDenied)
    );
    // max == 0 means unbounded above.
    assert_eq!(require_within_amount_bounds(10_000, 10, 0), Ok(()));
}

#[test]
fn time_validation() {
    let env = Env::default();
    env.ledger().set_timestamp(1_000);

    // Expiry in the future is fine; in the past/now is expired.
    assert_eq!(require_not_expired(&env, 2_000), Ok(()));
    assert_eq!(
        require_not_expired(&env, 1_000),
        Err(Error::ProposalExpired)
    );
    assert_eq!(require_not_expired(&env, 500), Err(Error::ProposalExpired));

    // Time lock: reached only once timestamp >= unlock_at.
    assert_eq!(require_time_reached(&env, 500), Ok(()));
    assert_eq!(require_time_reached(&env, 1_000), Ok(()));
    assert_eq!(
        require_time_reached(&env, 2_000),
        Err(Error::TimelockNotExpired)
    );
}

#[test]
fn constants_are_sane() {
    const _: () = {
        assert!(INSTANCE_LIFETIME_THRESHOLD < INSTANCE_BUMP_AMOUNT);
    };
    const _: () = {
        assert!(MAX_SIGNERS >= 1);
    };
    const _: () = {
        assert!(INSTANCE_LIFETIME_THRESHOLD < INSTANCE_BUMP_AMOUNT);
    };
    const _: () = {
        assert!(MAX_SIGNERS >= 1);
    };
}

// ---------------------------------------------------------------------------
// Telemetry helpers
// ---------------------------------------------------------------------------

use crate::telemetry::{estimate_gas, is_near_gas_limit, ExecutionCost, TransactionSummary};

#[test]
fn telemetry_estimate_gas_transfer() {
    // Transfer operations have a base cost of 100 gas.
    assert_eq!(estimate_gas("transfer", 0), 100);
    assert_eq!(estimate_gas("transfer", 1024), 110);
    assert_eq!(estimate_gas("transfer", 10240), 200);
}

#[test]
fn telemetry_estimate_gas_mint() {
    // Mint operations share the same base cost as transfer.
    assert_eq!(estimate_gas("mint", 0), 100);
    assert_eq!(estimate_gas("mint", 2048), 120);
}

#[test]
fn telemetry_estimate_gas_balance() {
    // Read-only operations are cheaper.
    assert_eq!(estimate_gas("balance", 0), 60);
    assert_eq!(estimate_gas("balance_of", 0), 60);
}

#[test]
fn telemetry_estimate_gas_approve() {
    // Approve operations have a base cost of 80 gas.
    assert_eq!(estimate_gas("approve", 0), 80);
    assert_eq!(estimate_gas("allowance", 0), 80);
}

#[test]
fn telemetry_estimate_gas_unknown_operation() {
    // Unknown operations default to 100 gas.
    assert_eq!(estimate_gas("unknown_op", 0), 100);
    assert_eq!(estimate_gas("some_custom_fn", 512), 100);
}

#[test]
fn telemetry_is_near_gas_limit() {
    // Below 90% is not near limit.
    assert!(!is_near_gas_limit(0));
    assert!(!is_near_gas_limit(50_000_000));
    assert!(!is_near_gas_limit(89_999_999));

    // At or above 90% is near limit.
    assert!(is_near_gas_limit(90_000_000));
    assert!(is_near_gas_limit(100_000_000));
    assert!(is_near_gas_limit(150_000_000));
}

#[test]
fn execution_cost_struct_fields() {
    let env = Env::default();
    let cost = ExecutionCost {
        operation: soroban_sdk::Symbol::new(&env, "transfer"),
        gas_used: 150,
        cpu_instructions: 0,
        storage_bytes: 1024,
        timestamp: 1_000_000,
    };

    assert_eq!(cost.operation, soroban_sdk::Symbol::new(&env, "transfer"));
    assert_eq!(cost.gas_used, 150);
    assert_eq!(cost.cpu_instructions, 0);
    assert_eq!(cost.storage_bytes, 1024);
    assert_eq!(cost.timestamp, 1_000_000);
}

#[test]
fn transaction_summary_struct_fields() {
    let summary = TransactionSummary {
        total_gas: 500,
        total_cpu: 10_000,
        total_storage: 4096,
        operation_count: 3,
        near_limit: false,
    };

    assert_eq!(summary.total_gas, 500);
    assert_eq!(summary.total_cpu, 10_000);
    assert_eq!(summary.total_storage, 4096);
    assert_eq!(summary.operation_count, 3);
    assert!(!summary.near_limit);
}

#[test]
fn telemetry_event_emission() {
    use crate::telemetry::log_execution_cost;

    let env = Env::default();

    // Publish a telemetry event — should not panic.
    log_execution_cost(&env, "transfer", 150, 1024);
}

#[test]
fn telemetry_full_event_emission() {
    use crate::telemetry::log_execution_cost_full;

    let env = Env::default();

    // Publish a full telemetry event — should not panic.
    log_execution_cost_full(&env, "transfer", 150, 500, 1024);
}

#[test]
fn telemetry_summary_event_emission() {
    use crate::telemetry::log_transaction_summary;

    let env = Env::default();

    // Publish a transaction summary event — should not panic.
    log_transaction_summary(&env, 500, 10_000, 4096, 3, false);
}

#[test]
fn contract_event_gas_telemetry_variant() {
    use crate::events::{publish, ContractEvent};
    use soroban_sdk::Symbol;

    let env = Env::default();

    let event = ContractEvent::GasTelemetry {
        operation: Symbol::new(&env, "transfer"),
        gas_used: 150,
        storage_bytes: 1024,
    };

    publish(&env, event);
}

#[test]
fn contract_event_transaction_summary_variant() {
    use crate::events::{publish, ContractEvent};

    let env = Env::default();

    let event = ContractEvent::TransactionSummary {
        total_gas: 500,
        total_cpu: 10_000,
        total_storage: 4096,
        operation_count: 3,
    };

    publish(&env, event);
}

// ---------------------------------------------------------------------------
// Error-code audit
//
// The code table is the public ABI shared by all eight contracts, so these
// tests are the guard rail that keeps it deterministic. They are deliberately
// exhaustive rather than sampled: a single renumbered or duplicated code
// silently breaks every off-chain consumer, and no runtime test of a business
// rule would notice.
// ---------------------------------------------------------------------------

/// Codes that were once assigned to a variant and have been retired. They must
/// stay empty forever so a stale integrator can never decode a fresh failure
/// as a retired meaning.
const RETIRED_CODES: [u32; 2] = [25, 65];

/// The frozen `(variant, code)` table. This is the assertion that actually
/// protects the ABI: it fails loudly if a variant is renumbered, moved across
/// domain blocks, or dropped.
const EXPECTED_CODES: [(Error, u32); 50] = [
    // --- Generic / lifecycle (1-6) ---
    (Error::NotFound, 1),
    (Error::AlreadyExists, 2),
    (Error::Unauthorized, 3),
    (Error::InvalidInput, 4),
    (Error::NotInitialized, 5),
    (Error::AlreadyInitialized, 6),
    // --- Value / arithmetic (10-12) ---
    (Error::InsufficientFunds, 10),
    (Error::Overflow, 11),
    (Error::InvalidAmount, 12),
    // --- Policy (20-29) ---
    (Error::PolicyDenied, 20),
    (Error::EmergencyLock, 21),
    (Error::PolicyRecipientRestricted, 22),
    (Error::PolicyMerchantBlocked, 23),
    (Error::PolicyCategoryRestricted, 24),
    (Error::PolicyAllowanceExceeded, 26),
    // --- Registry (30-39) ---
    (Error::RegistryFrozen, 30),
    (Error::ModuleDeprecated, 31),
    // --- Budget (40-44) ---
    (Error::BudgetExceeded, 40),
    (Error::BudgetFrozen, 41),
    (Error::BudgetArchived, 42),
    (Error::AssetNotAuthorized, 43),
    (Error::BudgetExpired, 44),
    // --- Wallet (50-53) ---
    (Error::WalletFrozen, 50),
    (Error::WalletArchived, 51),
    (Error::WalletPaused, 52),
    (Error::InvalidState, 53),
    // --- Multisig / approvals (61-69, 90-92) ---
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
    // --- Proposal (71-79) ---
    (Error::ProposalExpired, 71),
    (Error::InvalidProposalState, 72),
    (Error::ProposalNotApproved, 73),
    (Error::NotAnApprover, 74),
    (Error::CancellationWindowClosed, 75),
    (Error::PrerequisiteNotMet, 78),
    (Error::CircularDependencyDetected, 79),
    // --- Escrow (80-82) ---
    (Error::EscrowExpired, 80),
    (Error::TimeLockActive, 81),
    (Error::GraceActive, 82),
    // --- Treasury (83-85) ---
    (Error::AllowanceExceeded, 83),
    (Error::AllowanceExpired, 84),
    (Error::TreasuryPaused, 85),
];

#[test]
fn error_code_table_is_frozen() {
    // Every reachable variant is accounted for: `ALL` is the enumeration the
    // audit walks, so a mismatch here means a variant was added to (or removed
    // from) the enum without updating the audited table.
    assert_eq!(Error::ALL.len(), EXPECTED_CODES.len());
    for (variant, expected) in EXPECTED_CODES {
        assert_eq!(
            variant.code(),
            expected,
            "{:?} must keep its published code",
            variant
        );
    }
}

#[test]
fn error_codes_are_unique_and_never_overlap() {
    for (i, variant) in Error::ALL.iter().enumerate() {
        let code = variant.code();
        assert_ne!(code, 0, "{:?} may not take the reserved code 0", variant);
        // Compare against every later variant: two variants sharing a code is
        // the failure mode that makes a failure unattributable off chain.
        for other in &Error::ALL[i + 1..] {
            assert_ne!(
                other.code(),
                code,
                "code {} is claimed by both {:?} and {:?}",
                code,
                variant,
                other
            );
        }
    }
}

#[test]
fn error_code_bands_are_ascending() {
    // Each contract's band is declared ascending, so a variant dropped into the
    // wrong block — the usual symptom of an accidental renumber — shows up as
    // a non-ascending band rather than passing silently.
    let bands: [(u32, u32); 9] = [
        (1, 6),
        (10, 12),
        (20, 29),
        (30, 39),
        (40, 44),
        (50, 53),
        (60, 69),
        (70, 79),
        (90, 92),
    ];
    for (low, high) in bands {
        let mut previous: Option<u32> = None;
        for variant in Error::ALL {
            if variant.code() < low || variant.code() > high {
                continue;
            }
            if let Some(prev) = previous {
                assert!(
                    prev < variant.code(),
                    "band {low}-{high} is not ascending: {prev} then {}",
                    variant.code()
                );
            }
            previous = Some(variant.code());
        }
    }
}

#[test]
fn retired_error_codes_are_never_reused() {
    for (variant, code) in EXPECTED_CODES {
        assert!(
            !RETIRED_CODES.contains(&code),
            "{:?} was assigned retired code {}",
            variant,
            code
        );
    }
}

#[test]
fn error_domains_do_not_overlap() {
    // Each contract's codes live in their own numeric band, so a code observed
    // on chain attributes to exactly one contract. The generic 1-6 and value
    // 10-12 bands are shared by design and excluded.
    let registry = Error::ALL
        .iter()
        .filter(|e| (30..40).contains(&e.code()))
        .count();
    let budget = Error::ALL
        .iter()
        .filter(|e| (40..45).contains(&e.code()))
        .count();
    let wallet = Error::ALL
        .iter()
        .filter(|e| (50..54).contains(&e.code()))
        .count();
    let multisig = Error::ALL
        .iter()
        .filter(|e| (60..70).contains(&e.code()) || (90..93).contains(&e.code()))
        .count();
    let proposal = Error::ALL
        .iter()
        .filter(|e| (70..80).contains(&e.code()))
        .count();
    let escrow = Error::ALL
        .iter()
        .filter(|e| (80..83).contains(&e.code()))
        .count();
    let treasury = Error::ALL
        .iter()
        .filter(|e| (83..86).contains(&e.code()))
        .count();
    let policy = Error::ALL
        .iter()
        .filter(|e| (20..30).contains(&e.code()))
        .count();

    assert_eq!(registry, 2, "registry band 30-39");
    assert_eq!(budget, 5, "budget band 40-44");
    assert_eq!(wallet, 4, "wallet band 50-53");
    assert_eq!(multisig, 11, "multisig bands 61-69 and 90-92");
    assert_eq!(proposal, 7, "proposal band 71-79");
    assert_eq!(escrow, 3, "escrow band 80-82");
    assert_eq!(treasury, 3, "treasury band 83-85");
    assert_eq!(policy, 6, "policy band 20-29");
}

#[test]
fn error_codes_round_trip_through_the_host_error() {
    // A contract returning `Err(Error::X)` reaches the caller as a
    // `soroban_sdk::Error` carrying `X.code()`. The generated `TryFrom` must
    // map every code back to its variant, otherwise the consumer sees a code it
    // cannot attribute.
    for variant in Error::ALL {
        let host = soroban_sdk::Error::from(variant);
        assert_eq!(host.get_code(), variant.code());
        assert_eq!(Error::try_from(host), Ok(variant));
    }
}

#[test]
fn unknown_error_codes_are_never_decoded() {
    // A code outside the table (e.g. emitted by a future contract version an
    // old consumer has not learned yet) must stay an opaque error rather than
    // being guessed at.
    let unknown = soroban_sdk::Error::from_contract_error(4_294_967_295);
    assert!(Error::try_from(unknown).is_err());
}
