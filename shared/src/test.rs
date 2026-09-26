#![cfg(test)]
//! Unit tests for the shared math, validation and constant helpers.

use crate::constants::{INSTANCE_BUMP_AMOUNT, INSTANCE_LIFETIME_THRESHOLD, MAX_SIGNERS};
use crate::errors::Error;
use crate::math::{
    checked_abs, checked_add, checked_add_u64, checked_balance_add, checked_balance_sub,
    checked_div, checked_div_u64, checked_mul, checked_mul_u64, checked_neg, checked_rem,
    checked_sub, checked_sub_u64, validate_sufficient_balance, CheckedOptionExt, SafeAdd,
    SafeBalance, SafeDiv, SafeMul, SafeSub,
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

// ---------------------------------------------------------------------------
// u64 checked helpers
// ---------------------------------------------------------------------------

#[test]
fn u64_add_happy_path() {
    assert_eq!(checked_add_u64(0, 0), Ok(0));
    assert_eq!(checked_add_u64(2, 3), Ok(5));
    assert_eq!(checked_add_u64(u64::MAX, 0), Ok(u64::MAX));
    assert_eq!(checked_add_u64(0, u64::MAX), Ok(u64::MAX));
}

#[test]
fn u64_add_overflow() {
    assert_eq!(checked_add_u64(u64::MAX, 1), Err(Error::Overflow));
    assert_eq!(checked_add_u64(1, u64::MAX), Err(Error::Overflow));
    assert_eq!(checked_add_u64(u64::MAX, u64::MAX), Err(Error::Overflow));
}

#[test]
fn u64_sub_happy_path() {
    assert_eq!(checked_sub_u64(5, 3), Ok(2));
    assert_eq!(checked_sub_u64(0, 0), Ok(0));
    assert_eq!(checked_sub_u64(u64::MAX, u64::MAX), Ok(0));
    assert_eq!(checked_sub_u64(u64::MAX, 1), Ok(u64::MAX - 1));
}

#[test]
fn u64_sub_underflow() {
    assert_eq!(checked_sub_u64(0, 1), Err(Error::Overflow));
    assert_eq!(checked_sub_u64(3, 5), Err(Error::Overflow));
    assert_eq!(checked_sub_u64(1, u64::MAX), Err(Error::Overflow));
}

#[test]
fn u64_mul_happy_path() {
    assert_eq!(checked_mul_u64(0, u64::MAX), Ok(0));
    assert_eq!(checked_mul_u64(6, 7), Ok(42));
    assert_eq!(checked_mul_u64(u64::MAX, 1), Ok(u64::MAX));
}

#[test]
fn u64_mul_overflow() {
    assert_eq!(checked_mul_u64(u64::MAX, 2), Err(Error::Overflow));
    assert_eq!(checked_mul_u64(u64::MAX, u64::MAX), Err(Error::Overflow));
    assert_eq!(
        checked_mul_u64(1u64 << 32, 1u64 << 32),
        Err(Error::Overflow)
    );
}

#[test]
fn u64_div_happy_path() {
    assert_eq!(checked_div_u64(20, 5), Ok(4));
    assert_eq!(checked_div_u64(0, 5), Ok(0));
    assert_eq!(checked_div_u64(u64::MAX, 1), Ok(u64::MAX));
}

#[test]
fn u64_div_by_zero() {
    assert_eq!(checked_div_u64(0, 0), Err(Error::InvalidInput));
    assert_eq!(checked_div_u64(42, 0), Err(Error::InvalidInput));
    assert_eq!(checked_div_u64(u64::MAX, 0), Err(Error::InvalidInput));
}

#[test]
fn u64_traits_match_free_functions() {
    // The `Safe*` traits and the free helpers must agree on every edge case.
    assert_eq!(2u64.safe_add(3), Ok(5));
    assert_eq!(u64::MAX.safe_add(1), Err(Error::Overflow));
    assert_eq!(5u64.safe_sub(3), Ok(2));
    assert_eq!(0u64.safe_sub(1), Err(Error::Overflow));
    assert_eq!(6u64.safe_mul(7), Ok(42));
    assert_eq!(u64::MAX.safe_mul(2), Err(Error::Overflow));
    assert_eq!(20u64.safe_div(5), Ok(4));
    assert_eq!(1u64.safe_div(0), Err(Error::InvalidInput));
}

// ---------------------------------------------------------------------------
// Unified error mapping
// ---------------------------------------------------------------------------

#[test]
fn checked_option_maps_none_to_contract_errors() {
    assert_eq!(Some(5i128).or_overflow(), Ok(5));
    assert_eq!(None::<i128>.or_overflow(), Err(Error::Overflow));
    assert_eq!(Some(5i128).or_invalid_input(), Ok(5));
    assert_eq!(None::<i128>.or_invalid_input(), Err(Error::InvalidInput));

    assert_eq!(Some(5u64).or_overflow(), Ok(5));
    assert_eq!(None::<u64>.or_overflow(), Err(Error::Overflow));
    assert_eq!(None::<u64>.or_invalid_input(), Err(Error::InvalidInput));
}

// ---------------------------------------------------------------------------
// Balance validation
// ---------------------------------------------------------------------------

#[test]
fn sufficient_balance_happy_path() {
    // A balance larger than the amount, and the exact-balance boundary, both pass.
    assert_eq!(validate_sufficient_balance(100, 30), Ok(()));
    assert_eq!(validate_sufficient_balance(30, 30), Ok(()));
    assert_eq!(validate_sufficient_balance(i128::MAX, i128::MAX), Ok(()));
    assert_eq!(validate_sufficient_balance(i128::MAX, 1), Ok(()));
}

#[test]
fn sufficient_balance_zero_values() {
    // Zero is a legal balance and a zero-amount transfer is a no-op.
    assert_eq!(validate_sufficient_balance(0, 0), Ok(()));
    assert_eq!(validate_sufficient_balance(1, 0), Ok(()));
    assert_eq!(validate_sufficient_balance(i128::MAX, 0), Ok(()));
    // An empty balance cannot fund any positive transfer.
    assert_eq!(
        validate_sufficient_balance(0, 1),
        Err(Error::InsufficientFunds)
    );
    assert_eq!(
        validate_sufficient_balance(0, i128::MAX),
        Err(Error::InsufficientFunds)
    );
}

#[test]
fn sufficient_balance_insufficient() {
    assert_eq!(
        validate_sufficient_balance(29, 30),
        Err(Error::InsufficientFunds)
    );
    assert_eq!(
        validate_sufficient_balance(i128::MAX - 1, i128::MAX),
        Err(Error::InsufficientFunds)
    );
}

#[test]
fn sufficient_balance_rejects_negatives() {
    // Negative balances/amounts are malformed input, never a valid transfer.
    assert_eq!(
        validate_sufficient_balance(-1, 0),
        Err(Error::InvalidAmount)
    );
    assert_eq!(
        validate_sufficient_balance(0, -1),
        Err(Error::InvalidAmount)
    );
    assert_eq!(
        validate_sufficient_balance(-5, -5),
        Err(Error::InvalidAmount)
    );
    assert_eq!(
        validate_sufficient_balance(i128::MIN, 0),
        Err(Error::InvalidAmount)
    );
    assert_eq!(
        validate_sufficient_balance(i128::MIN, i128::MIN),
        Err(Error::InvalidAmount)
    );
}

#[test]
fn balance_sub_happy_path() {
    assert_eq!(checked_balance_sub(100, 30), Ok(70));
    assert_eq!(checked_balance_sub(30, 30), Ok(0));
    assert_eq!(checked_balance_sub(0, 0), Ok(0));
    assert_eq!(checked_balance_sub(i128::MAX, i128::MAX), Ok(0));
    assert_eq!(checked_balance_sub(i128::MAX, 0), Ok(i128::MAX));
}

#[test]
fn balance_sub_insufficient() {
    // The subtraction is guarded, so an over-draw returns a deterministic error
    // instead of wrapping to a huge positive balance.
    assert_eq!(checked_balance_sub(5, 6), Err(Error::InsufficientFunds));
    assert_eq!(
        checked_balance_sub(0, i128::MAX),
        Err(Error::InsufficientFunds)
    );
}

#[test]
fn balance_sub_negative_operands() {
    assert_eq!(checked_balance_sub(-5, 1), Err(Error::InvalidAmount));
    assert_eq!(checked_balance_sub(10, -1), Err(Error::InvalidAmount));
    assert_eq!(checked_balance_sub(i128::MIN, 1), Err(Error::InvalidAmount));
}

#[test]
fn balance_add_happy_path() {
    assert_eq!(checked_balance_add(0, 0), Ok(0));
    assert_eq!(checked_balance_add(5, 5), Ok(10));
    assert_eq!(checked_balance_add(i128::MAX, 0), Ok(i128::MAX));
    assert_eq!(checked_balance_add(0, i128::MAX), Ok(i128::MAX));
}

#[test]
fn balance_add_overflow() {
    assert_eq!(checked_balance_add(i128::MAX, 1), Err(Error::Overflow));
    assert_eq!(checked_balance_add(1, i128::MAX), Err(Error::Overflow));
    assert_eq!(
        checked_balance_add(i128::MAX, i128::MAX),
        Err(Error::Overflow)
    );
}

#[test]
fn balance_add_negative_operands() {
    assert_eq!(checked_balance_add(-1, 0), Err(Error::InvalidAmount));
    assert_eq!(checked_balance_add(0, -1), Err(Error::InvalidAmount));
    assert_eq!(checked_balance_add(-1, -1), Err(Error::InvalidAmount));
}

#[test]
fn safe_balance_trait_delegates() {
    // `safe_debit`/`safe_credit` mirror the free-function guarantees.
    assert_eq!(100i128.safe_debit(30), Ok(70));
    assert_eq!(30i128.safe_debit(30), Ok(0));
    assert_eq!(30i128.safe_debit(100), Err(Error::InsufficientFunds));
    assert_eq!(30i128.safe_debit(-1), Err(Error::InvalidAmount));

    assert_eq!(100i128.safe_credit(30), Ok(130));
    assert_eq!(i128::MAX.safe_credit(0), Ok(i128::MAX));
    assert_eq!(i128::MAX.safe_credit(1), Err(Error::Overflow));
    assert_eq!(1i128.safe_credit(-1), Err(Error::InvalidAmount));
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
