#![cfg(test)]
#![allow(clippy::cloned_ref_to_slice_refs)]
//! Unit tests for the shared math, validation and constant helpers.

use crate::auth::{
    accumulate_selected, add_weight, meets_threshold, narrow_weight, remaining_weight,
    require_threshold, tally_approvals, verify_approvals, verify_selected, WeightedSigner,
};
use crate::constants::{INSTANCE_BUMP_AMOUNT, INSTANCE_LIFETIME_THRESHOLD, MAX_SIGNERS};
use crate::errors::{
    BudgetError, Error, MilestoneError, BUDGET_ERROR_CODES, MILESTONE_ERROR_CODES,
};
use crate::math::{
    calculate_budget_rollover, calculate_rollover_allowance, checked_abs, checked_add,
    checked_add_u128, checked_add_u64, checked_balance_add, checked_balance_sub,
    checked_batch_allowance, checked_batch_calculation, checked_batch_calculation_with_multipliers,
    checked_div, checked_div_u128, checked_div_u64, checked_mul, checked_mul_u128, checked_mul_u64,
    checked_neg, checked_rem, checked_sub, checked_sub_u128, checked_sub_u64,
    compute_budget_rollover, validate_batch_allowance, validate_sufficient_balance,
    verify_batch_allowance, verify_batch_allowance_aggregate, verify_batch_allowance_iter,
    verify_batch_allowance_pairs, verify_batch_allowance_with_multipliers, BatchAmount,
    CheckedOptionExt, ContractError, SafeAdd, SafeBalance, SafeDiv, SafeMul, SafeSub,
};
use crate::validation::{
    require_non_negative_amount, require_not_expired, require_positive_amount,
    require_time_reached, require_within_amount_bounds, verify_quorum,
};
use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::{Address, Env};

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

// ---------------------------------------------------------------------------
// Batch allowance verification
// ---------------------------------------------------------------------------

#[test]
fn batch_allowance_suite_in_test_module() {
    // ContractError alias is usable and equal to Error
    let err: ContractError = Error::AllowanceExceeded;
    assert_eq!(err, ContractError::AllowanceExceeded);

    // BatchAmount trait constants and methods
    assert_eq!(<i128 as BatchAmount>::ZERO, 0);
    assert_eq!(<u128 as BatchAmount>::ZERO, 0);
    assert!((-1i128).is_negative());
    assert!(!0i128.is_negative());
    assert!(!0u128.is_negative());

    // u128 checked arithmetic helpers
    assert_eq!(checked_add_u128(1, 2), Ok(3));
    assert_eq!(checked_sub_u128(3, 1), Ok(2));
    assert_eq!(checked_mul_u128(2, 3), Ok(6));
    assert_eq!(checked_div_u128(6, 2), Ok(3));

    // Single limit verification
    let amounts = [50i128, 75, 125];
    assert_eq!(verify_batch_allowance(&amounts, &[250i128]), Ok(250));
    assert_eq!(checked_batch_allowance(&amounts, &[250i128]), Ok(250));
    assert_eq!(checked_batch_calculation(&amounts, &[250i128]), Ok(250));
    assert_eq!(validate_batch_allowance(&amounts, &[250i128]), Ok(()));

    // Exceeded single limit
    assert_eq!(
        verify_batch_allowance(&amounts, &[249i128]),
        Err(Error::AllowanceExceeded)
    );

    // Pairwise verification
    let limits = [50i128, 100, 150];
    assert_eq!(verify_batch_allowance(&amounts, &limits), Ok(250));
    assert_eq!(
        verify_batch_allowance(&[51i128, 75, 125], &limits),
        Err(Error::AllowanceExceeded)
    );

    // Multipliers
    let unit_prices = [10i128, 25];
    let quantities = [4i128, 2]; // 40 + 50 = 90
    assert_eq!(
        verify_batch_allowance_with_multipliers(&unit_prices, &quantities, &[90i128]),
        Ok(90)
    );
    assert_eq!(
        checked_batch_calculation_with_multipliers(&unit_prices, &quantities, &[90i128]),
        Ok(90)
    );
    assert_eq!(
        verify_batch_allowance_with_multipliers(&unit_prices, &quantities, &[89i128]),
        Err(Error::AllowanceExceeded)
    );

    // Overflow protection
    assert_eq!(
        verify_batch_allowance(&[i128::MAX, 1], &[i128::MAX]),
        Err(Error::Overflow)
    );
    assert_eq!(
        verify_batch_allowance_with_multipliers(&[i128::MAX], &[2], &[i128::MAX]),
        Err(Error::Overflow)
    );

    // Iterators
    let pairs = [(10i128, 20i128), (30, 40)];
    assert_eq!(verify_batch_allowance_pairs(pairs), Ok(40));
    assert_eq!(
        verify_batch_allowance_aggregate([10i128, 20, 30], 60),
        Ok(60)
    );
    assert_eq!(
        verify_batch_allowance_iter([10i128, 20], [10i128, 20]),
        Ok(30)
    );
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
fn quorum_validation_helper_tests() {
    let env = Env::default();
    let s1 = Address::generate(&env);
    let s2 = Address::generate(&env);
    let s3 = Address::generate(&env);

    // 1. Exact threshold met
    assert_eq!(
        verify_quorum(
            &[s1.clone(), s2.clone()],
            &[2, 3],
            &[s1.clone(), s2.clone()],
            5
        ),
        Ok(())
    );

    // 2. Exceeding threshold met
    assert_eq!(
        verify_quorum(
            &[s1.clone(), s2.clone()],
            &[2, 4],
            &[s1.clone(), s2.clone()],
            5
        ),
        Ok(())
    );

    // 3. Threshold not met
    assert_eq!(
        verify_quorum(&[s1.clone(), s2.clone()], &[2, 2], &[s1.clone()], 3),
        Err(Error::QUORUM_NOT_MET)
    );

    // 4. Duplicate signers in approval list rejected
    assert_eq!(
        verify_quorum(
            &[s1.clone(), s2.clone()],
            &[2, 3],
            &[s1.clone(), s1.clone()],
            4
        ),
        Err(Error::AlreadySigned)
    );

    // 5. Duplicate signers in signer set rejected
    assert_eq!(
        verify_quorum(&[s1.clone(), s1.clone()], &[2, 3], &[s1.clone()], 2),
        Err(Error::InvalidInput)
    );

    // 6. Empty signers or empty approvals with threshold > 0
    assert_eq!(
        verify_quorum(&[], &[], &[s1.clone()], 1),
        Err(Error::InvalidInput)
    );
    assert_eq!(
        verify_quorum(&[s1.clone()], &[1], &[], 1),
        Err(Error::QUORUM_NOT_MET)
    );

    // 7. Mismatched signers and weights lengths
    assert_eq!(
        verify_quorum(&[s1.clone(), s2.clone()], &[2], &[s1.clone()], 1),
        Err(Error::InvalidInput)
    );

    // 8. Zero threshold rejected
    assert_eq!(
        verify_quorum(&[s1.clone()], &[2], &[s1.clone()], 0),
        Err(Error::InvalidThreshold)
    );

    // 9. Non-signer in approval list
    assert_eq!(
        verify_quorum(&[s1.clone()], &[2], &[s3.clone()], 1),
        Err(Error::NotASigner)
    );

    // 10. Weight overflow prevention
    assert_eq!(
        verify_quorum(
            &[s1.clone(), s2.clone()],
            &[u32::MAX, 1],
            &[s1.clone(), s2.clone()],
            u32::MAX
        ),
        Err(Error::Overflow)
    );
}

/// Minimal `WeightedSigner` for the shared helper's tests. `contracttype`
/// gives it the conversion traits a Soroban `Vec` element needs.
#[soroban_sdk::contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
struct TestSigner {
    address: Address,
    weight: u32,
}

impl WeightedSigner for TestSigner {
    fn weight(&self) -> u32 {
        self.weight
    }
}

#[test]
fn auth_weight_arithmetic_is_checked() {
    assert_eq!(add_weight(0, 0), Ok(0));
    assert_eq!(add_weight(0, 5), Ok(5));
    assert_eq!(add_weight(5, 3), Ok(8));

    assert_eq!(narrow_weight(0), Ok(0));
    assert_eq!(narrow_weight(u32::MAX as i128), Ok(u32::MAX));
    assert_eq!(narrow_weight(u32::MAX as i128 + 1), Err(Error::Overflow));
    assert_eq!(narrow_weight(-1), Err(Error::Overflow));

    assert!(!meets_threshold(9, 10));
    assert!(meets_threshold(10, 10));
    assert!(meets_threshold(11, 10));
    assert_eq!(remaining_weight(9, 10), 1);
    assert_eq!(remaining_weight(11, 10), 0);

    assert_eq!(
        require_threshold(9, 10, Error::QUORUM_NOT_MET),
        Err(Error::QUORUM_NOT_MET)
    );
    assert_eq!(require_threshold(10, 10, Error::QUORUM_NOT_MET), Ok(()));
}

#[test]
fn auth_accumulates_selected_weights() {
    let env = Env::default();
    let a = Address::generate(&env);
    let b = Address::generate(&env);
    let c = Address::generate(&env);
    let signers = soroban_sdk::vec![
        &env,
        TestSigner {
            address: a.clone(),
            weight: 3,
        },
        TestSigner {
            address: b.clone(),
            weight: 2,
        },
        TestSigner {
            address: c.clone(),
            weight: 0,
        },
    ];

    // Exact threshold: 3 + 2 == 5.
    assert_eq!(
        verify_selected(&signers, &|_| true, 5, Error::InsufficientWeight),
        Ok((5, 2))
    );
    // Exceeding it is fine.
    assert_eq!(
        verify_selected(&signers, &|_| true, 4, Error::InsufficientWeight),
        Ok((5, 2))
    );
    // Below threshold.
    assert_eq!(
        verify_selected(&signers, &|_| true, 6, Error::InsufficientWeight),
        Err(Error::InsufficientWeight)
    );

    // A zero-weight signer contributes nothing and is not counted as an
    // approver, even though it is selected.
    let (weight, approvers) = accumulate_selected(&signers, &|s| s.address == c).unwrap();
    assert_eq!((weight, approvers), (0, 0));

    // Selection is exact: only `a` is selected here.
    assert_eq!(
        verify_selected(&signers, &|s| s.address == a, 3, Error::QUORUM_NOT_MET),
        Ok((3, 1))
    );
    assert_eq!(
        verify_selected(&signers, &|s| s.address == a, 4, Error::QUORUM_NOT_MET),
        Err(Error::QUORUM_NOT_MET)
    );
}

#[test]
fn auth_tallies_approvals_with_edge_cases() {
    let env = Env::default();
    let s1 = Address::generate(&env);
    let s2 = Address::generate(&env);
    let s3 = Address::generate(&env);
    let signers = [s1.clone(), s2.clone(), s3.clone()];
    let weights = [2u32, 3, 0];

    // Exact threshold (2 + 3 == 5).
    assert_eq!(
        verify_approvals(
            &signers,
            &weights,
            &[s1.clone(), s2.clone()],
            5,
            Error::QUORUM_NOT_MET
        ),
        Ok(5)
    );

    // Below threshold.
    assert_eq!(
        verify_approvals(&signers, &weights, &[s1.clone()], 3, Error::QUORUM_NOT_MET),
        Err(Error::QUORUM_NOT_MET)
    );

    // Empty approvals can never clear a positive threshold.
    assert_eq!(
        verify_approvals(&signers, &weights, &[], 1, Error::QUORUM_NOT_MET),
        Err(Error::QUORUM_NOT_MET)
    );

    // A duplicate approver is rejected rather than double-counted.
    assert_eq!(
        tally_approvals(&signers, &weights, &[s1.clone(), s1.clone()]),
        Err(Error::AlreadySigned)
    );

    // A duplicate signer in the set is malformed input.
    assert_eq!(
        tally_approvals(&[s1.clone(), s1.clone()], &[1, 1], &[s1.clone()]),
        Err(Error::InvalidInput)
    );

    // Non-signers cannot contribute weight.
    let outsider = Address::generate(&env);
    assert_eq!(
        tally_approvals(&signers, &weights, &[outsider]),
        Err(Error::NotASigner)
    );

    // A zero-weight signer is accepted but adds nothing.
    assert_eq!(
        verify_approvals(&signers, &weights, &[s3.clone()], 1, Error::QUORUM_NOT_MET),
        Err(Error::QUORUM_NOT_MET)
    );

    // Mismatched signer/weight lengths and empty sets are invalid input.
    assert_eq!(
        tally_approvals(&signers, &[2, 3], &[s1.clone()]),
        Err(Error::InvalidInput)
    );
    assert_eq!(tally_approvals(&[], &[], &[]), Err(Error::InvalidInput));

    // A zero threshold is refused before any tally is taken.
    assert_eq!(
        verify_approvals(&signers, &weights, &[s1.clone()], 0, Error::QUORUM_NOT_MET),
        Err(Error::InvalidThreshold)
    );

    // An unrepresentable weight sum fails closed.
    assert_eq!(
        tally_approvals(&signers, &[u32::MAX, 1, 0], &[s1.clone(), s2.clone()]),
        Err(Error::Overflow)
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
// Token transfer wrappers (Issue #204)
// ---------------------------------------------------------------------------

mod token_wrappers {
    use crate::errors::Error;
    use crate::token::{
        checked_transfer_total, map_token_error, safe_transfer, safe_transfer_tracked,
        token_balance, validate_transfer_amount,
    };
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::token::{StellarAssetClient, TokenClient};
    use soroban_sdk::xdr::{ScErrorCode, ScErrorType};
    use soroban_sdk::{contract, contractimpl, Address, Env};

    /// A contract paying out of its own token balance, the way wallets,
    /// treasuries and escrows use the wrapper.
    #[contract]
    pub struct Vault;

    #[contractimpl]
    impl Vault {
        pub fn pay(env: Env, token: Address, to: Address, amount: i128) -> Result<(), Error> {
            safe_transfer(&env, &token, &env.current_contract_address(), &to, amount)
        }
    }

    struct Setup {
        env: Env,
        token: Address,
        alice: Address,
        bob: Address,
    }

    fn setup() -> Setup {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let token = env.register_stellar_asset_contract_v2(admin).address();
        let alice = Address::generate(&env);
        let bob = Address::generate(&env);
        Setup {
            env,
            token,
            alice,
            bob,
        }
    }

    fn mint(env: &Env, token: &Address, to: &Address, amount: i128) {
        StellarAssetClient::new(env, token).mint(to, &amount);
    }

    fn balance(env: &Env, token: &Address, who: &Address) -> i128 {
        TokenClient::new(env, token).balance(who)
    }

    #[test]
    fn transfer_amount_must_be_strictly_positive() {
        assert_eq!(validate_transfer_amount(1), Ok(()));
        assert_eq!(validate_transfer_amount(i128::MAX), Ok(()));
        assert_eq!(validate_transfer_amount(0), Err(Error::InvalidAmount));
        assert_eq!(validate_transfer_amount(-1), Err(Error::InvalidAmount));
        assert_eq!(
            validate_transfer_amount(i128::MIN),
            Err(Error::InvalidAmount)
        );
    }

    #[test]
    fn successful_transfer_moves_exact_amount() {
        let s = setup();
        mint(&s.env, &s.token, &s.alice, 1_000);
        safe_transfer(&s.env, &s.token, &s.alice, &s.bob, 400).unwrap();
        assert_eq!(balance(&s.env, &s.token, &s.alice), 600);
        assert_eq!(balance(&s.env, &s.token, &s.bob), 400);
    }

    #[test]
    fn transferring_the_entire_balance_succeeds() {
        let s = setup();
        mint(&s.env, &s.token, &s.alice, 250);
        safe_transfer(&s.env, &s.token, &s.alice, &s.bob, 250).unwrap();
        assert_eq!(balance(&s.env, &s.token, &s.alice), 0);
        assert_eq!(balance(&s.env, &s.token, &s.bob), 250);
    }

    #[test]
    fn zero_and_negative_amounts_are_rejected_without_moving_funds() {
        let s = setup();
        mint(&s.env, &s.token, &s.alice, 100);
        for amount in [0, -1, i128::MIN] {
            assert_eq!(
                safe_transfer(&s.env, &s.token, &s.alice, &s.bob, amount),
                Err(Error::InvalidAmount)
            );
        }
        assert_eq!(balance(&s.env, &s.token, &s.alice), 100);
        assert_eq!(balance(&s.env, &s.token, &s.bob), 0);
    }

    #[test]
    fn insufficient_funds_is_distinct_from_invalid_amount() {
        let s = setup();
        mint(&s.env, &s.token, &s.alice, 99);
        assert_eq!(
            safe_transfer(&s.env, &s.token, &s.alice, &s.bob, 100),
            Err(Error::InsufficientFunds)
        );
        // An empty sender is insufficient, not invalid.
        assert_eq!(
            safe_transfer(&s.env, &s.token, &s.bob, &s.alice, 1),
            Err(Error::InsufficientFunds)
        );
        assert_eq!(balance(&s.env, &s.token, &s.alice), 99);
    }

    #[test]
    fn recipient_overflow_is_rejected_before_the_token_is_called() {
        let s = setup();
        mint(&s.env, &s.token, &s.bob, i128::MAX);
        mint(&s.env, &s.token, &s.alice, 1);
        assert_eq!(
            safe_transfer(&s.env, &s.token, &s.alice, &s.bob, 1),
            Err(Error::Overflow)
        );
        assert_eq!(balance(&s.env, &s.token, &s.alice), 1);
        assert_eq!(balance(&s.env, &s.token, &s.bob), i128::MAX);
    }

    #[test]
    fn maximum_representable_amount_transfers() {
        let s = setup();
        mint(&s.env, &s.token, &s.alice, i128::MAX);
        safe_transfer(&s.env, &s.token, &s.alice, &s.bob, i128::MAX).unwrap();
        assert_eq!(balance(&s.env, &s.token, &s.bob), i128::MAX);
        assert_eq!(balance(&s.env, &s.token, &s.alice), 0);
    }

    #[test]
    fn recipient_filled_to_exactly_max_succeeds() {
        let s = setup();
        mint(&s.env, &s.token, &s.bob, i128::MAX - 5);
        mint(&s.env, &s.token, &s.alice, 5);
        safe_transfer(&s.env, &s.token, &s.alice, &s.bob, 5).unwrap();
        assert_eq!(balance(&s.env, &s.token, &s.bob), i128::MAX);
    }

    #[test]
    fn self_transfer_at_max_balance_does_not_report_overflow() {
        let s = setup();
        mint(&s.env, &s.token, &s.alice, i128::MAX);
        safe_transfer(&s.env, &s.token, &s.alice, &s.alice, i128::MAX).unwrap();
        assert_eq!(balance(&s.env, &s.token, &s.alice), i128::MAX);
    }

    #[test]
    fn missing_authorization_is_an_error_not_a_trap() {
        let s = setup();
        mint(&s.env, &s.token, &s.alice, 10);
        // Drop the blanket mock: alice has now authorized nothing. The host
        // hides the token's auth failure behind a context error, so the
        // wrapper reports it as InvalidState instead of trapping.
        s.env.set_auths(&[]);
        assert_eq!(
            safe_transfer(&s.env, &s.token, &s.alice, &s.bob, 10),
            Err(Error::InvalidState)
        );
        assert_eq!(balance(&s.env, &s.token, &s.alice), 10);
        assert_eq!(balance(&s.env, &s.token, &s.bob), 0);
    }

    #[test]
    fn token_address_that_is_not_a_contract_fails_closed() {
        let s = setup();
        let not_a_token = Address::generate(&s.env);
        assert_eq!(
            token_balance(&s.env, &not_a_token, &s.alice),
            Err(Error::InvalidState)
        );
        assert_eq!(
            safe_transfer(&s.env, &not_a_token, &s.alice, &s.bob, 1),
            Err(Error::InvalidState)
        );
    }

    #[test]
    fn token_refusal_codes_reach_the_caller_mapped() {
        // A raw SAC refusal (bypassing the wrapper's pre-checks) arrives as
        // the SAC's contract code, which the wrapper maps.
        let s = setup();
        mint(&s.env, &s.token, &s.alice, 10);
        let raw = TokenClient::new(&s.env, &s.token).try_transfer(&s.alice, &s.bob, &11);
        match raw {
            Err(Ok(err)) => assert_eq!(map_token_error(err), Error::InsufficientFunds),
            other => panic!("expected a token contract error, got {:?}", other),
        }
    }

    #[test]
    fn contract_pays_from_its_own_balance_and_surfaces_codes() {
        let s = setup();
        let vault_id = s.env.register_contract(None, Vault);
        let vault = VaultClient::new(&s.env, &vault_id);
        mint(&s.env, &s.token, &vault_id, 50);

        vault.pay(&s.token, &s.bob, &20);
        assert_eq!(balance(&s.env, &s.token, &s.bob), 20);
        assert_eq!(balance(&s.env, &s.token, &vault_id), 30);

        // Failures reach the caller as contract error codes, not host traps.
        assert_eq!(
            vault.try_pay(&s.token, &s.bob, &31),
            Err(Ok(Error::InsufficientFunds))
        );
        assert_eq!(
            vault.try_pay(&s.token, &s.bob, &0),
            Err(Ok(Error::InvalidAmount))
        );
        assert_eq!(balance(&s.env, &s.token, &vault_id), 30);
    }

    #[test]
    fn tracked_transfer_debits_the_internal_ledger() {
        let s = setup();
        mint(&s.env, &s.token, &s.alice, 1_000);
        let remaining = safe_transfer_tracked(&s.env, &s.token, &s.alice, &s.bob, 300, 120);
        assert_eq!(remaining, Ok(180));
        assert_eq!(balance(&s.env, &s.token, &s.bob), 120);
    }

    #[test]
    fn tracked_transfer_checks_the_ledger_before_the_token() {
        let s = setup();
        // The token balance would cover it; the internal ledger does not.
        mint(&s.env, &s.token, &s.alice, 1_000);
        assert_eq!(
            safe_transfer_tracked(&s.env, &s.token, &s.alice, &s.bob, 100, 101),
            Err(Error::InsufficientFunds)
        );
        assert_eq!(
            safe_transfer_tracked(&s.env, &s.token, &s.alice, &s.bob, -1, 1),
            Err(Error::InvalidAmount)
        );
        assert_eq!(
            safe_transfer_tracked(&s.env, &s.token, &s.alice, &s.bob, 100, 0),
            Err(Error::InvalidAmount)
        );
        assert_eq!(balance(&s.env, &s.token, &s.bob), 0);
    }

    #[test]
    fn tracked_transfer_fails_when_the_token_balance_is_short() {
        let s = setup();
        // The ledger says 500 is spendable but only 10 tokens are held.
        mint(&s.env, &s.token, &s.alice, 10);
        assert_eq!(
            safe_transfer_tracked(&s.env, &s.token, &s.alice, &s.bob, 500, 50),
            Err(Error::InsufficientFunds)
        );
    }

    #[test]
    fn batch_total_is_checked() {
        assert_eq!(checked_transfer_total([]), Ok(0));
        assert_eq!(checked_transfer_total([1, 2, 3]), Ok(6));
        assert_eq!(checked_transfer_total([i128::MAX]), Ok(i128::MAX));
        assert_eq!(checked_transfer_total([i128::MAX - 1, 1]), Ok(i128::MAX));
        assert_eq!(checked_transfer_total([i128::MAX, 1]), Err(Error::Overflow));
        assert_eq!(checked_transfer_total([5, 0, 5]), Err(Error::InvalidAmount));
        assert_eq!(checked_transfer_total([5, -5]), Err(Error::InvalidAmount));
    }

    #[test]
    fn token_balance_reads_without_trapping() {
        let s = setup();
        assert_eq!(token_balance(&s.env, &s.token, &s.alice), Ok(0));
        mint(&s.env, &s.token, &s.alice, 7);
        assert_eq!(token_balance(&s.env, &s.token, &s.alice), Ok(7));
    }

    #[test]
    fn token_errors_map_deterministically() {
        let c = soroban_sdk::Error::from_contract_error;
        assert_eq!(map_token_error(c(10)), Error::InsufficientFunds);
        assert_eq!(map_token_error(c(8)), Error::InvalidAmount);
        assert_eq!(map_token_error(c(12)), Error::Overflow);
        for code in [4, 5, 6, 11, 13] {
            assert_eq!(map_token_error(c(code)), Error::Unauthorized);
        }
        for code in [1, 2, 3, 7, 9, 99] {
            assert_eq!(map_token_error(c(code)), Error::InvalidState);
        }
        let auth =
            soroban_sdk::Error::from_type_and_code(ScErrorType::Auth, ScErrorCode::InvalidAction);
        assert_eq!(map_token_error(auth), Error::Unauthorized);
        let budget =
            soroban_sdk::Error::from_type_and_code(ScErrorType::Budget, ScErrorCode::ExceededLimit);
        assert_eq!(map_token_error(budget), Error::InvalidState);
    }
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
const RETIRED_CODES: [u32; 0] = [];

/// The published code for every variant, written out by hand. This is the
/// audit record: it is deliberately *not* derived from the enum, because a
/// table derived from the thing it is meant to police cannot detect a
/// renumbering.
const EXPECTED_CODES: [(Error, u32); 77] = [
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
    (Error::PolicyExpired, 25),
    (Error::PolicyUnauthorizedSigner, 26),
    (Error::VelocityLimitExceeded, 27),
    (Error::PolicyConstraintUnmet, 28),
    (Error::PolicyMaxAmountExceeded, 29),
    // --- Registry (30-39) ---
    (Error::RegistryFrozen, 30),
    (Error::ModuleDeprecated, 31),
    (Error::CircularUpgrade, 32),
    (Error::InvalidUpgradeAddress, 33),
    (Error::VersionNotMonotonic, 34),
    (Error::InvalidUpgradePath, 35),
    (Error::VersionAlreadyExists, 36),
    // --- Budget (40-47) ---
    (Error::BudgetExceeded, 40),
    (Error::BudgetFrozen, 41),
    (Error::BudgetArchived, 42),
    (Error::AssetNotAuthorized, 43),
    (Error::BudgetExpired, 44),
    (Error::InvalidTimeWindow, 46),
    (Error::InvalidRolloverConfig, 47),
    // --- Budget continued (48-49) ---
    (Error::BudgetOverflow, 48),
    (Error::BudgetLimitExceeded, 49),
    // --- Wallet (50-55) ---
    (Error::WalletFrozen, 50),
    (Error::WalletArchived, 51),
    (Error::WalletPaused, 52),
    (Error::InvalidState, 53),
    (Error::RateLimitExceeded, 54),
    (Error::UnauthorizedWalletAccess, 55),
    (Error::UnsupportedAsset, 56),
    // --- Multisig / approvals (61-69, 70, 90-93) ---
    (Error::ThresholdNotMet, 61),
    (Error::AlreadySigned, 62),
    (Error::NotASigner, 63),
    (Error::InvalidThreshold, 64),
    (Error::InvalidSignerCount, 65),
    (Error::TooManySigners, 66),
    (Error::BatchCallFailed, 67),
    (Error::InvalidNonce, 68),
    (Error::InvalidSignerWeight, 69),
    (Error::ThresholdExceeded, 70),
    (Error::InsufficientWeight, 90),
    (Error::TimelockNotExpired, 91),
    (Error::UnauthorizedModification, 92),
    (Error::DuplicateSigner, 93),
    (Error::QuorumNotMet, 94),
    // --- Proposal (71-79) ---
    (Error::ProposalExpired, 71),
    (Error::InvalidProposalState, 72),
    (Error::ProposalNotApproved, 73),
    (Error::NotAnApprover, 74),
    (Error::CancellationWindowClosed, 75),
    (Error::ProposalDefeated, 76),
    (Error::PrerequisiteNotMet, 78),
    (Error::CircularDependencyDetected, 79),
    // --- Escrow (80-82, 86-87) ---
    (Error::EscrowExpired, 80),
    (Error::TimeLockActive, 81),
    (Error::GraceActive, 82),
    (Error::EscrowNotExpired, 86),
    (Error::EscrowAlreadySettled, 87),
    // --- Treasury (83-85) ---
    (Error::AllowanceExceeded, 83),
    (Error::AllowanceExpired, 84),
    (Error::TreasuryPaused, 85),
    (Error::AllocationLimitExceeded, 88),
    (Error::EmergencySweepUnauthorized, 89),
    // --- Escrow continuation (95-99) ---
    (Error::UnauthorizedCancellation, 95),
    // --- Budget rollover (96) ---
    (Error::BudgetRolloverExceeded, 96),
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
fn budget_error_aliases_keep_their_deterministic_codes() {
    // Issue #519: BUDGET_EXCEEDED, BUDGET_NOT_FOUND and INVALID_ALLOCATION must
    // be nameable from the shared error table by both budget and wallet. They
    // are aliases, so the published wire codes stay exactly as they were.
    assert_eq!(Error::BudgetExceeded.code(), 40);
    assert_eq!(Error::BudgetExceeded.wire_name(), "BUDGET_EXCEEDED");
    assert_eq!(Error::BudgetNotFound, Error::NotFound);
    assert_eq!(Error::BudgetNotFound.code(), 1);
    assert_eq!(Error::InvalidAllocation, Error::InvalidInput);
    assert_eq!(Error::InvalidAllocation.code(), 4);
    assert_eq!(BudgetError::InvalidAllocation, BudgetError::InvalidInput);
    assert_eq!(BudgetError::InvalidAllocation.code(), 4);
}

#[test]
fn named_budget_and_quorum_codes_are_wire_stable() {
    // Issues #459 and #463: the failure modes get their own published names and
    // numbers. The mirrored budget codes stay identical in both tables, and a
    // quorum shortfall is distinguishable from a generic threshold failure.
    assert_eq!(Error::BUDGET_OVERFLOW, Error::BudgetOverflow);
    assert_eq!(Error::BUDGET_OVERFLOW.code(), 48);
    assert_eq!(Error::BUDGET_OVERFLOW.wire_name(), "BUDGET_OVERFLOW");
    assert_eq!(Error::BUDGET_LIMIT_EXCEEDED, Error::BudgetLimitExceeded);
    assert_eq!(Error::BUDGET_LIMIT_EXCEEDED.code(), 49);
    assert_eq!(
        Error::BUDGET_LIMIT_EXCEEDED.wire_name(),
        "BUDGET_LIMIT_EXCEEDED"
    );
    assert_eq!(BudgetError::BUDGET_OVERFLOW, BudgetError::BudgetOverflow);
    assert_eq!(BudgetError::BUDGET_OVERFLOW.code(), 48);
    assert_eq!(
        BudgetError::BUDGET_LIMIT_EXCEEDED.code(),
        Error::BUDGET_LIMIT_EXCEEDED.code()
    );
    assert_eq!(
        BudgetError::from(Error::BUDGET_OVERFLOW),
        BudgetError::BudgetOverflow
    );
    assert_eq!(
        Error::from(BudgetError::BUDGET_LIMIT_EXCEEDED),
        Error::BUDGET_LIMIT_EXCEEDED
    );
    assert_eq!(Error::QUORUM_NOT_MET, Error::QuorumNotMet);
    assert_eq!(Error::QUORUM_NOT_MET.code(), 94);
    assert_eq!(Error::QUORUM_NOT_MET.wire_name(), "QUORUM_NOT_MET");
    assert_ne!(Error::QUORUM_NOT_MET, Error::ThresholdNotMet);
    assert_ne!(Error::QUORUM_NOT_MET, Error::InsufficientWeight);
}

#[test]
fn budget_rollover_exceeded_has_a_stable_named_code() {
    // Issue #447: the explicit name and its canonical code are part of the
    // published ABI. Both error tables must decode the same number, and the
    // dedicated code must be distinguishable from the general config error.
    assert_eq!(
        Error::BUDGET_ROLLOVER_EXCEEDED,
        Error::BudgetRolloverExceeded
    );
    assert_eq!(Error::BUDGET_ROLLOVER_EXCEEDED.code(), 96);
    assert_eq!(
        Error::BUDGET_ROLLOVER_EXCEEDED.wire_name(),
        "BUDGET_ROLLOVER_EXCEEDED"
    );
    assert_eq!(
        BudgetError::BUDGET_ROLLOVER_EXCEEDED,
        BudgetError::BudgetRolloverExceeded
    );
    assert_eq!(BudgetError::BUDGET_ROLLOVER_EXCEEDED.code(), 96);
    assert_eq!(
        BudgetError::from(Error::BUDGET_ROLLOVER_EXCEEDED),
        BudgetError::BudgetRolloverExceeded
    );
    assert_eq!(
        Error::from(BudgetError::BUDGET_ROLLOVER_EXCEEDED),
        Error::BudgetRolloverExceeded
    );
    assert_ne!(Error::BudgetRolloverExceeded, Error::InvalidRolloverConfig);
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
    let bands: [(u32, u32); 12] = [
        (1, 6),
        (10, 12),
        (20, 29),
        (30, 39),
        (40, 49),
        (50, 56),
        (60, 70),
        (71, 79),
        (80, 87),
        (88, 89),
        (90, 94),
        (95, 95),
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
        .filter(|e| (40..50).contains(&e.code()))
        .count();
    let wallet = Error::ALL
        .iter()
        .filter(|e| (50..57).contains(&e.code()))
        .count();
    let multisig = Error::ALL
        .iter()
        .filter(|e| (60..71).contains(&e.code()) || (90..95).contains(&e.code()))
        .count();
    let proposal = Error::ALL
        .iter()
        .filter(|e| (71..80).contains(&e.code()))
        .count();
    let escrow = Error::ALL
        .iter()
        .filter(|e| matches!(e.code(), 80..=82 | 86..=87 | 95))
        .count();
    let treasury = Error::ALL
        .iter()
        .filter(|e| (83..86).contains(&e.code()) || (88..90).contains(&e.code()))
        .count();
    let policy = Error::ALL
        .iter()
        .filter(|e| (20..30).contains(&e.code()))
        .count();

    assert_eq!(registry, 7, "registry band 30-39");
    assert_eq!(budget, 9, "budget band 40-49");
    assert_eq!(wallet, 7, "wallet band 50-56");
    assert_eq!(multisig, 15, "multisig bands 61-70 and 90-94");
    assert_eq!(proposal, 8, "proposal band 71-79");
    assert_eq!(escrow, 6, "escrow band 80-82, 86-87 and 95");
    assert_eq!(treasury, 5, "treasury bands 83-85 and 88-89");
    assert_eq!(policy, 10, "policy band 20-29");
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

#[test]
fn milestone_error_codes_are_frozen_and_unique() {
    // A milestone refusal that is really a generic failure must decode to the
    // exact canonical number, so a consumer's existing handler still matches.
    assert_eq!(MilestoneError::NotFound.code(), Error::NotFound.code());
    assert_eq!(
        MilestoneError::Unauthorized.code(),
        Error::Unauthorized.code()
    );
    assert_eq!(
        MilestoneError::InvalidInput.code(),
        Error::InvalidInput.code()
    );
    assert_eq!(MilestoneError::Overflow.code(), Error::Overflow.code());
    assert_eq!(
        MilestoneError::InvalidAmount.code(),
        Error::InvalidAmount.code()
    );
    assert_eq!(
        MilestoneError::InvalidState.code(),
        Error::InvalidState.code()
    );
    // The two milestone-only codes are the next free slots after the escrow
    // band (80-82) and must never be reassigned.
    assert_eq!(MilestoneError::InvalidMilestone.code(), 86);
    assert_eq!(MilestoneError::MilestoneAlreadyCompleted.code(), 87);

    assert_eq!(MilestoneError::ALL.len(), MILESTONE_ERROR_CODES.len());
    for (variant, code) in MilestoneError::ALL.iter().zip(MILESTONE_ERROR_CODES) {
        assert_eq!(variant.code(), code, "{:?} must keep its code", variant);
        assert_ne!(code, 0, "{:?} may not take the reserved code 0", variant);
        assert!(
            !RETIRED_CODES.contains(&code),
            "{:?} was assigned retired code {}",
            variant,
            code
        );
    }
    // Every code is unique, so a failure is attributable to one variant.
    for (i, code) in MILESTONE_ERROR_CODES.iter().enumerate() {
        assert!(
            !MILESTONE_ERROR_CODES[i + 1..].contains(code),
            "duplicate milestone code {}",
            code
        );
    }
    // A contract returning any variant round-trips as that exact number.
    for variant in MilestoneError::ALL {
        let host = soroban_sdk::Error::from(variant);
        assert_eq!(host.get_code(), variant.code());
        assert_eq!(MilestoneError::try_from(host), Ok(variant));
    }
}

#[test]
fn budget_error_table_is_frozen() {
    // `ALL` is the enumeration this audit walks, so a variant added to (or
    // removed from) the enum without a matching entry in `BUDGET_ERROR_CODES`
    // fails here instead of slipping an undocumented code onto the wire.
    assert_eq!(BudgetError::ALL.len(), BUDGET_ERROR_CODES.len());
    for (variant, expected) in BudgetError::ALL.iter().zip(BUDGET_ERROR_CODES) {
        assert_eq!(
            variant.code(),
            expected,
            "{:?} must keep its published code",
            variant
        );
    }
}

#[test]
fn budget_error_codes_are_frozen_and_unique() {
    for (i, code) in BUDGET_ERROR_CODES.iter().enumerate() {
        // The host reports a contract error of `0` as "no error", so no variant
        // may ever take that value.
        assert_ne!(*code, 0, "code 0 is reserved by the host");
        // Compare against every later code: a duplicate makes a budget refusal
        // unattributable off chain, and `BudgetError` has a distinct code (45)
        // that nothing else may shadow.
        for other in &BUDGET_ERROR_CODES[i + 1..] {
            assert_ne!(
                other, code,
                "code {} is claimed twice in the budget table",
                code
            );
        }
        assert!(
            !RETIRED_CODES.contains(code),
            "retired code {} reissued in the budget table",
            code
        );
    }

    // A contract returning any variant round-trips as that exact number, so an
    // off-chain consumer decodes it back to the same variant.
    for variant in BudgetError::ALL {
        let host = soroban_sdk::Error::from(variant);
        assert_eq!(host.get_code(), variant.code());
        assert_eq!(BudgetError::try_from(host), Ok(variant));
    }

    // The ten mirrored codes are wire-compatible with the canonical table, so a
    // consumer's existing `Error` handler still fires. `BudgetNotActive` (45) is
    // the one budget-only code, and it folds onto `Error::BudgetExpired` on the
    // way back — asserted here so that lossy conversion is deliberate rather
    // than accidental.
    for variant in BudgetError::ALL {
        let canonical = Error::from(variant);
        match variant {
            BudgetError::BudgetNotActive => {
                assert_eq!(canonical, Error::BudgetExpired);
            }
            BudgetError::BudgetLimitExceeded => {
                assert_eq!(canonical, Error::BudgetLimitExceeded);
            }
            BudgetError::InvalidTimeWindow => {
                assert_eq!(canonical, Error::InvalidTimeWindow);
            }
            BudgetError::InvalidRolloverConfig => {
                assert_eq!(canonical, Error::InvalidRolloverConfig);
            }
            BudgetError::BudgetOverflow => {
                assert_eq!(canonical, Error::BudgetOverflow);
            }
            _ => {
                assert_eq!(
                    canonical.code(),
                    variant.code(),
                    "{:?} must decode to the same number in the canonical table",
                    variant
                );
            }
        }
    }
}

/// Every variant the three error tables expose must carry a code that is
/// non-zero, not a retired slot, and — within its own table — claimed by no
/// other variant. Uniqueness is per table on purpose: the budget and milestone
/// tables deliberately mirror canonical codes, so a code shared *between*
/// tables is the wire compatibility the protocol relies on, whereas a code
/// shared *within* a table is a failure nothing can attribute.
#[test]
fn every_public_error_variant_has_a_unique_code() {
    // Canonical table.
    assert_unique_codes(Error::ALL.iter().map(|e| e.code()));
    // Budget table.
    assert_unique_codes(BudgetError::ALL.iter().map(|e| e.code()));
    // Milestone table.
    assert_unique_codes(MilestoneError::ALL.iter().map(|e| e.code()));

    // No variant of any table may take a retired slot, and no table may claim
    // the reserved code 0.
    for code in Error::ALL
        .iter()
        .map(|e| e.code())
        .chain(BudgetError::ALL.iter().map(|e| e.code()))
        .chain(MilestoneError::ALL.iter().map(|e| e.code()))
    {
        assert_ne!(code, 0, "code 0 is reserved by the host");
        assert!(
            !RETIRED_CODES.contains(&code),
            "retired code {} was reissued",
            code
        );
    }
}

/// Walk one table's codes, asserting each is non-zero and not already claimed by
/// an earlier entry in the same table.
fn assert_unique_codes<I: Iterator<Item = u32>>(codes: I) {
    // The tables are small and fixed-size, so an O(n^2) walk over the
    // accumulated codes is cheaper than allocating a set.
    let mut seen = [0u32; MAX_AUDITED_CODES];
    for (count, code) in codes.enumerate() {
        assert_ne!(code, 0, "code 0 is reserved by the host");
        for previous in &seen[..count] {
            assert_ne!(
                *previous, code,
                "code {} is claimed by more than one error variant",
                code
            );
        }
        assert!(
            count < seen.len(),
            "error table grew past the audit's capacity"
        );
        seen[count] = code;
    }
}

// ---------------------------------------------------------------------------
// Error-table lint (Issue #244)
//
// A missing doc comment, a wire name that drifts out of `UPPER_SNAKE_CASE`, or a
// discriminant left implicit is invisible to the compiler: the crate still
// builds, the tests still pass, and the codes are still as deterministic as they
// were. The only thing that catches them is reading the source, so the routine
// below parses `errors.rs` at test time and enforces the documentation and
// naming conventions on every variant of every error table in the crate.
// ---------------------------------------------------------------------------

/// This file, verbatim. Reading the source is what makes the documentation rule
/// enforceable; the compiler cannot see a missing doc comment.
const ERROR_SOURCE: &str = include_str!("errors.rs");

/// The upper bound on the codes and wire names the audits below can remember.
/// The largest table declares 51 variants; the slack keeps an in-progress table
/// from failing on capacity alone.
const MAX_AUDITED_CODES: usize = 100;

/// The upper bound on the `#[contracterror]` tables the scan tracks. Three exist
/// today; the slack means a new one is reported as "extend the audit" rather
/// than as a capacity failure.
const MAX_ERROR_TABLES: usize = 8;

/// A `#[contracterror]` variant exactly as `errors.rs` declares it.
#[derive(Clone, Copy)]
struct DeclaredVariant {
    /// The table it belongs to: `Error`, `BudgetError` or `MilestoneError`.
    table: &'static str,
    /// The variant's Rust name, as written in the source. Used in failure
    /// messages; the published name is the variant's `wire_name()`, which is
    /// checked separately because it is a method, not a declaration.
    name: &'static str,
    /// The discriminant, as written in the source.
    code: u32,
    /// 1-based line number, so a failure points at the declaration.
    line: usize,
    /// Whether a `///` doc comment precedes the declaration.
    documented: bool,
}

/// `UPPER_SNAKE_CASE`: ASCII capitals, digits and underscores, starting with a
/// capital and free of leading, trailing or doubled underscores. This is the
/// form the Astroid SDK, API and dashboard key their message catalogues off, so
/// a variant whose wire name is `NotFound` instead of `NOT_FOUND` is a silent
/// mismatch for every consumer of that catalogue.
fn is_upper_snake_case(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) if first.is_ascii_uppercase() => {}
        _ => return false,
    }
    if name.starts_with('_') || name.ends_with('_') || name.contains("__") {
        return false;
    }
    name.chars()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// Walk every `#[contracterror]` table in `errors.rs`, in source order, calling
/// `on_variant` once per declared variant and `on_table` once per table with the
/// number of variants that table declares.
///
/// The scan is deliberately literal rather than clever: it recognises exactly
/// the layout `errors.rs` uses — one `Name = <decimal>,` per line, with
/// attributes and `//` / `///` comments on their own lines — and panics with a
/// pointed message on anything else, so a reformat shows up as an actionable
/// failure instead of silently skipping a variant.
fn scan_error_tables(
    on_variant: &mut impl FnMut(DeclaredVariant),
    on_table: &mut impl FnMut(&'static str, usize),
) {
    // 1. Find the `#[contracterror]` enums. The attribute may carry arguments
    //    (`#[contracterror(export = false)]`), so match on the prefix only. The
    //    `#[derive]` / `#[repr]` lines in between belong to the same item and
    //    must not end the search.
    let mut tables: [(&'static str, usize); MAX_ERROR_TABLES] = [("", 0); MAX_ERROR_TABLES];
    let mut table_count = 0usize;
    let mut awaiting_contracterror = false;
    for (index, line) in ERROR_SOURCE.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("#[contracterror") {
            awaiting_contracterror = true;
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("pub enum ") {
            if awaiting_contracterror {
                assert!(
                    table_count < tables.len(),
                    "more error tables than this audit knows about — extend it"
                );
                tables[table_count] = (rest.trim_end_matches('{').trim(), index + 1);
                table_count += 1;
            }
            // The attribute never carries over to the next item.
            awaiting_contracterror = false;
            continue;
        }
        if awaiting_contracterror
            && !(trimmed.is_empty() || trimmed.starts_with("///") || trimmed.starts_with("#["))
        {
            awaiting_contracterror = false;
        }
    }
    assert!(
        table_count > 0,
        "the scan found no #[contracterror] table in errors.rs — the source layout \
         this audit depends on has changed"
    );

    // 2. Walk each table's body. A table's variants are the lines between its
    //    `pub enum` and the first line that is exactly `}`: these enums hold no
    //    nested items, so that brace is unambiguous.
    for (table, header_line) in &tables[..table_count] {
        let mut documented = false;
        let mut variants = 0usize;
        for (offset, line) in ERROR_SOURCE.lines().skip(*header_line).enumerate() {
            let line_number = header_line + offset + 1;
            let trimmed = line.trim();
            if line == "}" {
                break;
            }
            if trimmed.is_empty() {
                // A blank line ends a doc run: a `///` block above a blank line
                // documents that block, not the variant below it.
                documented = false;
                continue;
            }
            if trimmed.starts_with("///") {
                documented = true;
                continue;
            }
            if trimmed.starts_with("//") || trimmed.starts_with("#[") {
                // Plain and attribute lines do not interrupt a doc run.
                continue;
            }
            // Whatever is left is a variant declaration: `Name = <decimal>,`.
            let declaration = trimmed.strip_suffix(',').unwrap_or_else(|| {
                panic!(
                    "errors.rs:{line_number}: expected `Name = <code>,` inside \
                     `{table}`, found `{trimmed}`"
                )
            });
            let (name, code) = declaration.split_once('=').unwrap_or_else(|| {
                panic!(
                    "errors.rs:{line_number}: `{trimmed}` has no explicit discriminant \
                     in `{table}` — write `{trimmed} = <code>,` so the wire value is \
                     hand-written and reviewable"
                )
            });
            let name = name.trim();
            let code = code.trim();
            let parsed: u32 = code.parse().unwrap_or_else(|_| {
                panic!(
                    "errors.rs:{line_number}: `{name}` must carry a plain decimal \
                     discriminant, found `{code}`"
                )
            });
            variants += 1;
            on_variant(DeclaredVariant {
                table,
                name,
                code: parsed,
                line: line_number,
                documented,
            });
            documented = false;
        }
        assert!(
            variants > 0,
            "`{table}` declares no variants this audit could read — the source \
             layout this audit depends on has changed"
        );
        on_table(table, variants);
    }
}

#[test]
fn error_variants_are_documented() {
    // The point of the exercise: an off-chain consumer decodes a `u32` and a
    // name, never a Rust doc comment, so this comment *is* the specification of
    // when the code is emitted. An undocumented variant is a code nobody can
    // explain.
    let mut checked = 0usize;
    scan_error_tables(
        &mut |variant| {
            assert!(
                variant.documented,
                "errors.rs:{}: `{}::{}` has no doc comment — say what triggers it",
                variant.line, variant.table, variant.name
            );
            assert_ne!(
                variant.code, 0,
                "errors.rs:{}: `{}::{}` takes the reserved code 0; the host reports a \
                 contract error of 0 as \"no error\"",
                variant.line, variant.table, variant.name
            );
            checked += 1;
        },
        &mut |_, _| {},
    );
    // Every table declared three variants or more, so a scan that visited
    // nothing cannot pass.
    assert!(
        checked > 0,
        "the documentation scan visited no variants at all"
    );
}

#[test]
fn error_tables_declared_in_source_match_the_audited_tables() {
    // `on_table` is called once per table, so this compares per table: a new
    // variant in one table cannot hide behind the grand total staying stable.
    let expected = [
        ("Error", Error::ALL.len()),
        ("BudgetError", BudgetError::ALL.len()),
        ("MilestoneError", MILESTONE_ERROR_CODES.len()),
    ];
    let mut seen: [&str; MAX_ERROR_TABLES] = [""; MAX_ERROR_TABLES];
    let mut seen_count = 0usize;
    scan_error_tables(&mut |_| {}, &mut |table, declared| {
        assert!(
            seen_count < seen.len(),
            "more error tables than this audit knows about — extend it"
        );
        seen[seen_count] = table;
        seen_count += 1;
        let audited = expected
            .iter()
            .find(|(name, _)| *name == table)
            .unwrap_or_else(|| {
                panic!(
                    "`{table}` is a new #[contracterror] table in errors.rs — add \
                         it to this audit and give it an `ALL`/code constant of its own"
                )
            });
        assert_eq!(
            declared, audited.1,
            "`{table}` declares {declared} variants in errors.rs but the audited \
                 table enumerates {} — update both in the same change",
            audited.1
        );
    });
    assert_eq!(
        seen_count,
        expected.len(),
        "this audit covers {} tables but errors.rs has {}: {:?}",
        expected.len(),
        seen_count,
        &seen[..seen_count]
    );
}

#[test]
fn error_wire_names_are_upper_snake_case_and_unique() {
    // The published name must be UPPER_SNAKE_CASE and must identify exactly one
    // variant within its table, so an off-chain message catalogue keyed on it
    // cannot be ambiguous.
    fn assert_wire_names<I: Iterator<Item = &'static str>>(table: &str, names: I) {
        let mut seen = [""; MAX_AUDITED_CODES];
        for (count, name) in names.enumerate() {
            assert!(
                is_upper_snake_case(name),
                "{table}: wire name `{name}` is not UPPER_SNAKE_CASE"
            );
            assert!(
                !seen[..count].contains(&name),
                "{table}: wire name `{name}` is used by more than one variant"
            );
            assert!(count < seen.len(), "{table}: too many variants to audit");
            seen[count] = name;
        }
    }

    assert_wire_names("Error", Error::ALL.iter().map(|e| e.wire_name()));
    assert_wire_names(
        "BudgetError",
        BudgetError::ALL.iter().map(|e| e.wire_name()),
    );
    assert_wire_names(
        "MilestoneError",
        MilestoneError::ALL.iter().map(|e| e.wire_name()),
    );
}

#[test]
fn mirrored_tables_share_the_canonical_wire_names() {
    // A variant that mirrors a canonical code must also mirror its name, or the
    // two tables would decode one number to two different identifiers.
    for variant in BudgetError::ALL {
        let canonical = Error::from(variant);
        if variant == BudgetError::BudgetNotActive {
            // The one budget-only code: it has no canonical counterpart.
            assert_eq!(variant.wire_name(), "BUDGET_NOT_ACTIVE");
            continue;
        }
        assert_eq!(
            variant.wire_name(),
            canonical.wire_name(),
            "{:?} mirrors its canonical code but not its wire name",
            variant
        );
    }

    for variant in MilestoneError::ALL {
        if matches!(
            variant,
            MilestoneError::InvalidMilestone | MilestoneError::MilestoneAlreadyCompleted
        ) {
            // The two milestone-only codes have no canonical counterpart.
            continue;
        }
        let canonical = Error::from(variant);
        assert_eq!(
            variant.code(),
            canonical.code(),
            "{:?} must mirror its canonical code",
            variant
        );
        assert_eq!(
            variant.wire_name(),
            canonical.wire_name(),
            "{:?} must mirror its canonical wire name",
            variant
        );
    }
}

#[test]
fn error_enums_implement_the_traits_the_sdk_requires() {
    // A `#[contracterror]` enum is only usable across a contract boundary if it is
    // `Copy`/`Clone` (passed by value through `Result`), `Debug` (for the
    // `panic!` messages and test output), `Eq`/`PartialEq` (for the `assert_eq!`
    // the whole suite is built on) and convertible from `soroban_sdk::Error`
    // (the generated `TryFrom`, which is how a wire code is decoded back into a
    // variant). `Ord`/`PartialOrd` keep the tables orderable for the off-chain
    // catalogues. Asserting the bounds here turns a dropped `#[derive]` into a
    // compile error in this module rather than a surprise at the first call site
    // that happens to need it.
    fn assert_contracterror_traits<T>()
    where
        T: Copy
            + Clone
            + core::fmt::Debug
            + Eq
            + PartialEq
            + PartialOrd
            + Ord
            + TryFrom<soroban_sdk::Error>,
    {
    }

    assert_contracterror_traits::<Error>();
    assert_contracterror_traits::<BudgetError>();
    assert_contracterror_traits::<MilestoneError>();
}

// ---------------------------------------------------------------------------
// calculate_budget_rollover & calculate_rollover_allowance
// ---------------------------------------------------------------------------

#[test]
fn budget_rollover_happy_path() {
    // 50% rollover (5_000 bps) of 1_000 unspent without cap
    assert_eq!(calculate_budget_rollover(1_000, 5_000, 0), Ok(500));
    // 25% rollover (2_500 bps) of 1_000 unspent without cap
    assert_eq!(calculate_budget_rollover(1_000, 2_500, 0), Ok(250));
    // 100% rollover (10_000 bps) of 1_000 unspent without cap
    assert_eq!(calculate_budget_rollover(1_000, 10_000, 0), Ok(1_000));
    // 0 bps => 0 rollover
    assert_eq!(calculate_budget_rollover(1_000, 0, 0), Ok(0));
    // 0 unspent => 0 rollover
    assert_eq!(calculate_budget_rollover(0, 5_000, 1_000), Ok(0));
    // Alias compute_budget_rollover matches
    assert_eq!(compute_budget_rollover(1_000, 5_000, 0), Ok(500));
}

#[test]
fn budget_rollover_cap_clamping() {
    // Calculated rollover = 500, cap = 300 => clamped to 300
    assert_eq!(calculate_budget_rollover(1_000, 5_000, 300), Ok(300));
    // Calculated rollover = 500, cap = 600 => uncapped at 500
    assert_eq!(calculate_budget_rollover(1_000, 5_000, 600), Ok(500));
    // Calculated rollover = 1_000, cap = 400 => clamped to 400
    assert_eq!(calculate_budget_rollover(1_000, 10_000, 400), Ok(400));
}

#[test]
fn budget_rollover_input_validation() {
    // Negative unspent is rejected
    assert_eq!(
        calculate_budget_rollover(-1, 5_000, 1_000),
        Err(Error::InvalidAmount)
    );
    // Negative bps is rejected
    assert_eq!(
        calculate_budget_rollover(1_000, -1, 1_000),
        Err(Error::InvalidAmount)
    );
    // Negative cap is rejected
    assert_eq!(
        calculate_budget_rollover(1_000, 5_000, -1),
        Err(Error::InvalidAmount)
    );
    // bps > 10_000 is rejected
    assert_eq!(
        calculate_budget_rollover(1_000, 10_001, 1_000),
        Err(Error::InvalidInput)
    );
}

#[test]
fn budget_rollover_large_values_no_overflow() {
    // i128::MAX with 10_000 bps (100%) does not overflow
    assert_eq!(
        calculate_budget_rollover(i128::MAX, 10_000, 0),
        Ok(i128::MAX)
    );
    // i128::MAX with 5_000 bps (50%) does not overflow
    assert_eq!(
        calculate_budget_rollover(i128::MAX, 5_000, 0),
        Ok(i128::MAX / 2)
    );
    // i128::MAX clamped by cap
    assert_eq!(
        calculate_budget_rollover(i128::MAX, 10_000, 50_000),
        Ok(50_000)
    );
}

#[test]
fn rollover_allowance_calculation() {
    // base_limit = 1_000, unspent = 1_000, 50% rollover capped at 300 => 1_000 + 300 = 1_300
    assert_eq!(
        calculate_rollover_allowance(1_000, 1_000, 5_000, 300),
        Ok(1_300)
    );
    // Negative base limit is rejected
    assert_eq!(
        calculate_rollover_allowance(-1, 1_000, 5_000, 300),
        Err(Error::InvalidAmount)
    );
    // Overflow when adding to i128::MAX
    assert_eq!(
        calculate_rollover_allowance(i128::MAX, 1_000, 5_000, 300),
        Err(Error::Overflow)
    );
}

// ---------------------------------------------------------------------------
// Issue #520: standardized deposit event emission
// ---------------------------------------------------------------------------

mod deposit_events {
    use crate::events::{self, DepositRecorded};
    use soroban_sdk::testutils::{Address as _, Events, Ledger};
    use soroban_sdk::{contract, contractimpl, Address, Env, IntoVal, String, TryFromVal};

    #[contract]
    pub struct DepositRecorder;

    #[contractimpl]
    impl DepositRecorder {
        pub fn record(
            env: Env,
            org: String,
            from: Address,
            asset: Address,
            amount: i128,
            balance: i128,
        ) {
            events::deposit_recorded(&env, &org, &from, &asset, amount, balance);
        }
    }

    #[test]
    fn deposit_recorded_emits_typed_and_legacy_events() {
        use soroban_sdk::testutils::Events;
        use soroban_sdk::{IntoVal, Symbol, TryFromVal, Val};

        let env = Env::default();
        env.ledger().set_timestamp(1_234);
        let org = String::from_str(&env, "acme");
        let from = Address::generate(&env);
        let asset = Address::generate(&env);
        let id = env.register_contract(None, DepositRecorder);

        DepositRecorderClient::new(&env, &id).record(&org, &from, &asset, &50, &500);

        let typed_topic: Val = Symbol::new(&env, "DepositRecorded").into_val(&env);
        let treasury_topic: Val = Symbol::new(&env, "treasury").into_val(&env);
        let deposit_topic: Val = Symbol::new(&env, "deposit").into_val(&env);
        let mut typed = 0;
        let mut legacy = 0;
        for (emitter, topics, data) in env.events().all().iter() {
            if emitter != id.clone() {
                continue;
            }
            if topics.contains(typed_topic) {
                typed += 1;
                let record = DepositRecorded::try_from_val(&env, &data).unwrap();
                assert_eq!(record.org, org);
                assert_eq!(record.from, from);
                assert_eq!(record.asset, asset);
                assert_eq!(record.amount, 50);
                assert_eq!(record.balance, 500);
                assert_eq!(record.recorded_at, 1_234);
            }
            if topics.contains(treasury_topic) && topics.contains(deposit_topic) {
                legacy += 1;
                let payload: (String, Address, Address, i128, i128, u64) =
                    TryFromVal::try_from_val(&env, &data).unwrap();
                assert_eq!(payload.0, org);
                assert_eq!(payload.1, from);
                assert_eq!(payload.2, asset);
                assert_eq!(payload.3, 50);
                assert_eq!(payload.4, 500);
                assert_eq!(payload.5, 1_234);
            }
        }
        assert_eq!(typed, 1);
        assert_eq!(legacy, 1);
    }

    #[contract]
    pub struct EventTester;

    #[contractimpl]
    impl EventTester {
        pub fn emit_all(env: Env, from: Address, to: Address, asset: Address) {
            events::emit_deposit(&env, &from, &asset, 100, 500);
            events::emit_withdraw(&env, &to, &asset, 50, 450);
            events::emit_release(&env, 1, &to, 200);
            events::emit_refund(&env, 1, &from, 300);
        }
    }

    #[test]
    fn test_standardized_event_helpers() {
        let env = Env::default();
        let from = Address::generate(&env);
        let to = Address::generate(&env);
        let asset = Address::generate(&env);
        let id = env.register_contract(None, EventTester);

        EventTesterClient::new(&env, &id).emit_all(&from, &to, &asset);

        let deposit_topic: soroban_sdk::Val = soroban_sdk::symbol_short!("deposit").into_val(&env);
        let withdraw_topic: soroban_sdk::Val =
            soroban_sdk::symbol_short!("withdraw").into_val(&env);
        let release_topic: soroban_sdk::Val = soroban_sdk::symbol_short!("release").into_val(&env);
        let refund_topic: soroban_sdk::Val = soroban_sdk::symbol_short!("refund").into_val(&env);

        let mut dep_count = 0;
        let mut with_count = 0;
        let mut rel_count = 0;
        let mut ref_count = 0;

        for (emitter, topics, data) in env.events().all().iter() {
            if emitter != id.clone() {
                continue;
            }
            if topics.contains(deposit_topic) {
                dep_count += 1;
                let ev = events::StandardDepositEvent::try_from_val(&env, &data).unwrap();
                assert_eq!(ev.from, from);
                assert_eq!(ev.asset, asset);
                assert_eq!(ev.amount, 100);
                assert_eq!(ev.balance, 500);
            }
            if topics.contains(withdraw_topic) {
                with_count += 1;
                let ev = events::StandardWithdrawEvent::try_from_val(&env, &data).unwrap();
                assert_eq!(ev.to, to);
                assert_eq!(ev.asset, asset);
                assert_eq!(ev.amount, 50);
                assert_eq!(ev.balance, 450);
            }
            if topics.contains(release_topic) {
                rel_count += 1;
                let ev = events::StandardReleaseEvent::try_from_val(&env, &data).unwrap();
                assert_eq!(ev.id, 1);
                assert_eq!(ev.recipient, to);
                assert_eq!(ev.amount, 200);
            }
            if topics.contains(refund_topic) {
                ref_count += 1;
                let ev = events::StandardRefundEvent::try_from_val(&env, &data).unwrap();
                assert_eq!(ev.id, 1);
                assert_eq!(ev.recipient, from);
                assert_eq!(ev.amount, 300);
            }
        }
        assert_eq!(dep_count, 1);
        assert_eq!(with_count, 1);
        assert_eq!(rel_count, 1);
        assert_eq!(ref_count, 1);
    }
}

// ---------------------------------------------------------------------------
// Issue #493 — centralized event builders and topic constants.
// ---------------------------------------------------------------------------

mod event_builders {
    use crate::events::{self, topic};
    use soroban_sdk::testutils::{Address as _, Events};
    use soroban_sdk::{
        contract, symbol_short, Address, Env, IntoVal, String, Symbol, TryFromVal, Val,
    };

    #[contract]
    struct Emitter;

    #[test]
    fn topic_constants_match_their_wire_spelling() {
        let env = Env::default();
        let pairs: [(Symbol, &str); 21] = [
            (topic::REGISTRY, "registry"),
            (topic::ORG, "org"),
            (topic::MODULE, "module"),
            (topic::ROLE, "role"),
            (topic::VERSION, "version"),
            (topic::ADMIN, "admin"),
            (topic::WASM, "wasm"),
            (topic::WALLET, "wallet"),
            (topic::SIGNER, "signer"),
            (topic::THRESHOLD, "threshold"),
            (topic::GOVCHANGE, "govchange"),
            (topic::EMERGENCY, "emergency"),
            (topic::BATCH, "batch"),
            (topic::TIMELOCK, "timelock"),
            (topic::PROPOSAL, "proposal"),
            (topic::TREASURY, "treasury"),
            (topic::MILESTONE, "milestone"),
            (topic::BUDGET, "budget"),
            (topic::POLICY, "policy"),
            (topic::ESCROW, "escrow"),
            (topic::TRANSFER, "transfer"),
        ];
        for (constant, spelling) in pairs {
            assert_eq!(constant, Symbol::new(&env, spelling), "{spelling}");
        }
    }

    #[test]
    fn emit_builders_publish_two_three_and_four_topic_events() {
        let env = Env::default();
        let id = env.register_contract(None, Emitter);
        let who = Address::generate(&env);
        env.as_contract(&id, || {
            events::emit(&env, topic::BUDGET, symbol_short!("consumed"), 7i128);
            events::emit_for(
                &env,
                topic::ESCROW,
                symbol_short!("funded"),
                9u64,
                who.clone(),
            );
            events::emit_for_pair(
                &env,
                topic::MODULE,
                symbol_short!("register"),
                String::from_str(&env, "acme"),
                3u32,
                who.clone(),
            );
        });
        let all = env.events().all();
        assert_eq!(all.len(), 3);

        let (_, t0, d0) = all.get(0).unwrap();
        assert_eq!(t0.len(), 2);
        assert_eq!(
            Symbol::try_from_val(&env, &t0.get(0).unwrap()).unwrap(),
            topic::BUDGET
        );
        assert_eq!(i128::try_from_val(&env, &d0).unwrap(), 7);

        let (_, t1, d1) = all.get(1).unwrap();
        assert_eq!(t1.len(), 3);
        assert_eq!(u64::try_from_val(&env, &t1.get(2).unwrap()).unwrap(), 9);
        assert_eq!(Address::try_from_val(&env, &d1).unwrap(), who);

        let (_, t2, _) = all.get(2).unwrap();
        assert_eq!(t2.len(), 4);
        assert_eq!(u32::try_from_val(&env, &t2.get(3).unwrap()).unwrap(), 3);
    }

    #[test]
    fn standard_rollover_transition_and_rule_events_carry_identifiers() {
        let env = Env::default();
        let id = env.register_contract(None, Emitter);
        let bid = String::from_str(&env, "eng");
        env.as_contract(&id, || {
            events::budget_window_rolled(&env, &bid, 2, 40, 200, 300);
            events::proposal_state_changed(&env, 5, 1, 2);
            events::policy_rule_denied(&env, &bid, 1, 10, Symbol::new(&env, "rule_velocity"));
        });
        let all = env.events().all();
        assert_eq!(all.len(), 3);

        let roll =
            events::BudgetWindowRollover::try_from_val(&env, &all.get(0).unwrap().2).unwrap();
        assert_eq!((roll.periods, roll.previous_spent), (2, 40));
        assert_eq!((roll.window_start, roll.window_end), (200, 300));

        let (_, topics, data) = all.get(1).unwrap();
        assert_eq!(u64::try_from_val(&env, &topics.get(2).unwrap()).unwrap(), 5);
        let t = events::ProposalTransition::try_from_val(&env, &data).unwrap();
        assert_eq!((t.proposal_id, t.from, t.to), (5, 1, 2));

        let (_, topics, data) = all.get(2).unwrap();
        let act: Val = events::POLICY_RULE_DENIED.into_val(&env);
        assert!(topics.get(1).unwrap().shallow_eq(&act));
        let (index, leaf, reason) = <(u32, u32, Symbol)>::try_from_val(&env, &data).unwrap();
        assert_eq!((index, leaf), (1, 10));
        assert_eq!(reason, Symbol::new(&env, "rule_velocity"));
    }
}
