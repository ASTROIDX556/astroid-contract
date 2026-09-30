//! Overflow-safe `i128`, `u128`, and `u64` arithmetic, balance validation, and batch allowance checks.
//!
//! Financial contracts must never rely on wrapping arithmetic. Every value
//! computation routes through these helpers, which return a contract [`Error`]
//! instead of panicking so callers can fail safely and deterministically.

pub use crate::errors::ContractError;
use crate::errors::Error;

/// Map the `None` produced by a primitive `checked_*` operation onto the
/// shared, deterministic [`Error`] table.
///
/// This is the single conversion point for arithmetic failures across the
/// workspace: the checked `add`/`sub`/`mul` families return `None` on overflow
/// (or underflow) and `checked_div` returns `None` on division by zero.
/// Routing every `None` through this trait keeps each crate mapping the same
/// failure to the same contract error code.
pub trait CheckedOptionExt<T> {
    /// Convert `None` into [`Error::Overflow`].
    fn or_overflow(self) -> Result<T, Error>;

    /// Convert `None` into [`Error::InvalidInput`].
    fn or_invalid_input(self) -> Result<T, Error>;
}

impl<T> CheckedOptionExt<T> for Option<T> {
    fn or_overflow(self) -> Result<T, Error> {
        self.ok_or(Error::Overflow)
    }

    fn or_invalid_input(self) -> Result<T, Error> {
        self.ok_or(Error::InvalidInput)
    }
}

pub trait SafeAdd {
    fn safe_add(self, other: Self) -> Result<Self, Error>
    where
        Self: Sized;
}

pub trait SafeSub {
    fn safe_sub(self, other: Self) -> Result<Self, Error>
    where
        Self: Sized;
}

pub trait SafeMul {
    fn safe_mul(self, other: Self) -> Result<Self, Error>
    where
        Self: Sized;
}

pub trait SafeDiv {
    fn safe_div(self, other: Self) -> Result<Self, Error>
    where
        Self: Sized;
}

impl SafeAdd for i128 {
    fn safe_add(self, other: i128) -> Result<i128, Error> {
        self.checked_add(other).or_overflow()
    }
}

impl SafeSub for i128 {
    fn safe_sub(self, other: i128) -> Result<i128, Error> {
        self.checked_sub(other).or_overflow()
    }
}

impl SafeMul for i128 {
    fn safe_mul(self, other: i128) -> Result<i128, Error> {
        self.checked_mul(other).or_overflow()
    }
}

impl SafeDiv for i128 {
    fn safe_div(self, other: i128) -> Result<i128, Error> {
        if other == 0 {
            return Err(Error::InvalidInput);
        }
        self.checked_div(other).or_overflow()
    }
}

// `u64` is the type of ledger counters, timestamps and telemetry values. It
// shares the exact same failure semantics as `i128` so a wrapping count or a
// zero-denominator division can never panic the Wasm runtime.
impl SafeAdd for u64 {
    fn safe_add(self, other: u64) -> Result<u64, Error> {
        self.checked_add(other).or_overflow()
    }
}

impl SafeSub for u64 {
    fn safe_sub(self, other: u64) -> Result<u64, Error> {
        self.checked_sub(other).or_overflow()
    }
}

impl SafeMul for u64 {
    fn safe_mul(self, other: u64) -> Result<u64, Error> {
        self.checked_mul(other).or_overflow()
    }
}

impl SafeDiv for u64 {
    fn safe_div(self, other: u64) -> Result<u64, Error> {
        if other == 0 {
            return Err(Error::InvalidInput);
        }
        self.checked_div(other).or_overflow()
    }
}

// `u128` safe math for large unsigned aggregates and batch computations.
impl SafeAdd for u128 {
    fn safe_add(self, other: u128) -> Result<u128, Error> {
        self.checked_add(other).or_overflow()
    }
}

impl SafeSub for u128 {
    fn safe_sub(self, other: u128) -> Result<u128, Error> {
        self.checked_sub(other).or_overflow()
    }
}

impl SafeMul for u128 {
    fn safe_mul(self, other: u128) -> Result<u128, Error> {
        self.checked_mul(other).or_overflow()
    }
}

impl SafeDiv for u128 {
    fn safe_div(self, other: u128) -> Result<u128, Error> {
        if other == 0 {
            return Err(Error::InvalidInput);
        }
        self.checked_div(other).or_overflow()
    }
}

// Keep the old functions for backwards compatibility in other contracts,
// but delegate to the traits
pub fn checked_add(a: i128, b: i128) -> Result<i128, Error> {
    a.safe_add(b)
}

pub fn checked_sub(a: i128, b: i128) -> Result<i128, Error> {
    a.safe_sub(b)
}

pub fn checked_mul(a: i128, b: i128) -> Result<i128, Error> {
    a.safe_mul(b)
}

pub fn checked_div(a: i128, b: i128) -> Result<i128, Error> {
    a.safe_div(b)
}

/// Checked remainder. Returns [`Error::InvalidInput`] on divide-by-zero.
pub fn checked_rem(a: i128, b: i128) -> Result<i128, Error> {
    if b == 0 {
        return Err(Error::InvalidInput);
    }
    a.checked_rem(b).ok_or(Error::Overflow)
}

/// Checked negation. Returns [`Error::Overflow`] when the result cannot be
/// represented (only `i128::MIN`).
pub fn checked_neg(a: i128) -> Result<i128, Error> {
    a.checked_neg().ok_or(Error::Overflow)
}

/// Checked absolute value. Returns [`Error::Overflow`] when the result
/// cannot be represented (only `i128::MIN`).
pub fn checked_abs(a: i128) -> Result<i128, Error> {
    a.checked_abs().ok_or(Error::Overflow)
}

// ---------------------------------------------------------------------------
// `u64` checked helpers
// ---------------------------------------------------------------------------
//
// Ledger counters, timestamps and telemetry values are `u64`. They go through
// the same checked path as `i128` so an overflowing count or a zero-denominator
// division surfaces as a contract error rather than a Wasm panic.

/// Checked `u64` addition. Returns [`Error::Overflow`] on overflow.
pub fn checked_add_u64(a: u64, b: u64) -> Result<u64, Error> {
    a.safe_add(b)
}

/// Checked `u64` subtraction. Returns [`Error::Overflow`] on underflow.
pub fn checked_sub_u64(a: u64, b: u64) -> Result<u64, Error> {
    a.safe_sub(b)
}

/// Checked `u64` multiplication. Returns [`Error::Overflow`] on overflow.
pub fn checked_mul_u64(a: u64, b: u64) -> Result<u64, Error> {
    a.safe_mul(b)
}

/// Checked `u64` division. Returns [`Error::InvalidInput`] on division by zero.
pub fn checked_div_u64(a: u64, b: u64) -> Result<u64, Error> {
    a.safe_div(b)
}

// ---------------------------------------------------------------------------
// `u128` checked helpers
// ---------------------------------------------------------------------------

/// Checked `u128` addition. Returns [`Error::Overflow`] on overflow.
pub fn checked_add_u128(a: u128, b: u128) -> Result<u128, Error> {
    a.safe_add(b)
}

/// Checked `u128` subtraction. Returns [`Error::Overflow`] on underflow.
pub fn checked_sub_u128(a: u128, b: u128) -> Result<u128, Error> {
    a.safe_sub(b)
}

/// Checked `u128` multiplication. Returns [`Error::Overflow`] on overflow.
pub fn checked_mul_u128(a: u128, b: u128) -> Result<u128, Error> {
    a.safe_mul(b)
}

/// Checked `u128` division. Returns [`Error::InvalidInput`] on division by zero.
pub fn checked_div_u128(a: u128, b: u128) -> Result<u128, Error> {
    a.safe_div(b)
}

// ---------------------------------------------------------------------------
// Balance validation
// ---------------------------------------------------------------------------
//
// Token balances are tracked as `i128`. Before invoking an external Soroban
// token contract every transfer must prove that the tracked balance covers the
// requested amount, otherwise a wrapping subtraction could silently mint value.
// These helpers centralize that check so wallets, treasuries and escrows all
// fail with the same deterministic error codes.

/// Verify that `balance` is large enough to cover `amount`.
///
/// Negative balances or amounts are treated as malformed input and rejected
/// with [`Error::InvalidAmount`], since neither is ever legitimate for a token
/// transfer. A zero `amount` is allowed (a no-op transfer) and only succeeds
/// when `balance` is also non-negative. When `balance < amount` the call fails
/// with [`Error::InsufficientFunds`].
///
/// The comparison is pure — no arithmetic is performed — so it cannot overflow,
/// even at the `i128` boundaries.
pub fn validate_sufficient_balance(balance: i128, amount: i128) -> Result<(), Error> {
    if balance < 0 || amount < 0 {
        return Err(Error::InvalidAmount);
    }
    if balance < amount {
        return Err(Error::InsufficientFunds);
    }
    Ok(())
}

/// Debit `amount` from `balance` after proving the balance is sufficient.
///
/// Returns the remaining balance. Fails with [`Error::InvalidAmount`] for
/// negative operands and [`Error::InsufficientFunds`] when `balance < amount`,
/// so the subtraction can never underflow.
pub fn checked_balance_sub(balance: i128, amount: i128) -> Result<i128, Error> {
    validate_sufficient_balance(balance, amount)?;
    balance.checked_sub(amount).ok_or(Error::Overflow)
}

/// Credit `amount` onto `balance`, returning the new balance.
///
/// Fails with [`Error::InvalidAmount`] for negative operands and
/// [`Error::Overflow`] when the sum cannot be represented as an `i128`.
pub fn checked_balance_add(balance: i128, amount: i128) -> Result<i128, Error> {
    if balance < 0 || amount < 0 {
        return Err(Error::InvalidAmount);
    }
    balance.checked_add(amount).ok_or(Error::Overflow)
}

/// Balance-aware arithmetic on `i128`.
///
/// Mirrors the [`SafeAdd`] family but models a ledger balance: debits verify
/// sufficiency ([`Error::InsufficientFunds`]) instead of allowing an underflow,
/// and credits reject overflow ([`Error::Overflow`]). Both reject negative
/// operands with [`Error::InvalidAmount`].
pub trait SafeBalance {
    /// Subtract a transfer amount, verifying the balance is sufficient.
    fn safe_debit(self, amount: i128) -> Result<i128, Error>;

    /// Add a deposit amount, verifying the result does not overflow.
    fn safe_credit(self, amount: i128) -> Result<i128, Error>;
}

impl SafeBalance for i128 {
    fn safe_debit(self, amount: i128) -> Result<i128, Error> {
        checked_balance_sub(self, amount)
    }

    fn safe_credit(self, amount: i128) -> Result<i128, Error> {
        checked_balance_add(self, amount)
    }
}

// ---------------------------------------------------------------------------
// Batch allowance and expenditure verification
// ---------------------------------------------------------------------------
//
// Financial arithmetic across the Astroid protocol requires strict overflow
// checks. When evaluating complex multi-signature proposals, batch payouts,
// or multi-token budgets, verifying limits individually causes unnecessary gas
// consumption and repetitive boilerplate. These helpers evaluate multiple
// token expenditure constraints in a single gas-efficient step without risking
// integer overflow or redundant storage lookups.

/// Trait for numeric types supported by batch allowance verification.
pub trait BatchAmount: Copy + PartialOrd + SafeAdd + SafeMul + 'static {
    /// Zero representation for the type.
    const ZERO: Self;

    /// Returns `true` if the value is negative. Unsigned types always return `false`.
    fn is_negative(&self) -> bool;
}

impl BatchAmount for i128 {
    const ZERO: Self = 0;

    fn is_negative(&self) -> bool {
        *self < 0
    }
}

impl BatchAmount for u128 {
    const ZERO: Self = 0;

    fn is_negative(&self) -> bool {
        false
    }
}

impl BatchAmount for u64 {
    const ZERO: Self = 0;

    fn is_negative(&self) -> bool {
        false
    }
}

/// Verify a batch of expenditure amounts against spending limits or allowances.
///
/// This helper allows contracts like treasury, wallet, and budget to verify multiple
/// token expenditure constraints in a single gas-efficient step with strict overflow protection.
///
/// Supports two evaluation modes:
/// 1. **Aggregate limit**: When `limits` contains a single limit (`limits.len() == 1`),
///    all elements of `amounts` are summed using checked arithmetic and verified against
///    that single aggregate allowance (`sum <= limit`).
/// 2. **Pairwise limits**: When `amounts` and `limits` have the same length
///    (`amounts.len() == limits.len()`), each `amount[i]` is verified against its
///    corresponding `limit[i]` (`amount[i] <= limit[i]`), and the total expenditure
///    is accumulated with checked arithmetic.
///
/// Both `amounts` and `limits` must be non-negative. Zero amounts are treated as valid
/// no-op expenditures.
///
/// # Errors
/// - [`Error::InvalidAmount`]: Any `amount < 0` or `limit < 0`.
/// - [`Error::AllowanceExceeded`]: Any individual amount exceeds its limit (pairwise),
///   or cumulative expenditure exceeds the aggregate limit.
/// - [`Error::Overflow`]: Cumulative total exceeds the representable range of `T`.
/// - [`Error::InvalidInput`]: `limits` is empty while `amounts` is non-empty,
///   or `limits.len() != 1` and `limits.len() != amounts.len()`.
///
/// # Returns
/// The total verified expenditure amount (`Ok(total)`).
pub fn verify_batch_allowance<T: BatchAmount>(amounts: &[T], limits: &[T]) -> Result<T, Error> {
    if amounts.is_empty() {
        if limits.is_empty() {
            return Ok(T::ZERO);
        }
        if limits.len() == 1 {
            if limits[0].is_negative() {
                return Err(Error::InvalidAmount);
            }
            return Ok(T::ZERO);
        }
        return Err(Error::InvalidInput);
    }

    if limits.is_empty() {
        return Err(Error::InvalidInput);
    }

    if limits.len() == 1 {
        let limit = limits[0];
        if limit.is_negative() {
            return Err(Error::InvalidAmount);
        }
        let mut total = T::ZERO;
        for &amount in amounts {
            if amount.is_negative() {
                return Err(Error::InvalidAmount);
            }
            total = total.safe_add(amount)?;
        }
        if total > limit {
            return Err(Error::AllowanceExceeded);
        }
        Ok(total)
    } else if limits.len() == amounts.len() {
        let mut total = T::ZERO;
        for (&amount, &limit) in amounts.iter().zip(limits.iter()) {
            if amount.is_negative() || limit.is_negative() {
                return Err(Error::InvalidAmount);
            }
            if amount > limit {
                return Err(Error::AllowanceExceeded);
            }
            total = total.safe_add(amount)?;
        }
        Ok(total)
    } else {
        Err(Error::InvalidInput)
    }
}

/// Verify a batch of expenditure constraints with quantities/multipliers against spending limits.
///
/// For each item `i`, the expenditure is computed as `amount[i].safe_mul(multipliers[i])`.
/// The resulting expenditures are verified against `limits` using checked arithmetic.
///
/// Passing an empty `multipliers` slice defaults all multipliers to 1 (standard 1:1 expenditure).
///
/// # Errors
/// - [`Error::InvalidAmount`]: Any `amount < 0`, `multiplier < 0`, or `limit < 0`.
/// - [`Error::AllowanceExceeded`]: Any computed expenditure exceeds its limit (pairwise),
///   or cumulative expenditure exceeds the aggregate limit.
/// - [`Error::Overflow`]: An item's multiplication or the cumulative total overflows `T`.
/// - [`Error::InvalidInput`]: Slice lengths mismatch (`multipliers` non-empty and
///   `multipliers.len() != amounts.len()`, or invalid `limits` length).
///
/// # Returns
/// The total verified expenditure amount (`Ok(total)`).
pub fn verify_batch_allowance_with_multipliers<T: BatchAmount>(
    amounts: &[T],
    multipliers: &[T],
    limits: &[T],
) -> Result<T, Error> {
    if multipliers.is_empty() {
        return verify_batch_allowance(amounts, limits);
    }
    if multipliers.len() != amounts.len() {
        return Err(Error::InvalidInput);
    }
    if amounts.is_empty() {
        return verify_batch_allowance(amounts, limits);
    }
    if limits.is_empty() {
        return Err(Error::InvalidInput);
    }

    if limits.len() == 1 {
        let limit = limits[0];
        if limit.is_negative() {
            return Err(Error::InvalidAmount);
        }
        let mut total = T::ZERO;
        for (&amount, &multiplier) in amounts.iter().zip(multipliers.iter()) {
            if amount.is_negative() || multiplier.is_negative() {
                return Err(Error::InvalidAmount);
            }
            let cost = amount.safe_mul(multiplier)?;
            total = total.safe_add(cost)?;
        }
        if total > limit {
            return Err(Error::AllowanceExceeded);
        }
        Ok(total)
    } else if limits.len() == amounts.len() {
        let mut total = T::ZERO;
        for ((&amount, &multiplier), &limit) in
            amounts.iter().zip(multipliers.iter()).zip(limits.iter())
        {
            if amount.is_negative() || multiplier.is_negative() || limit.is_negative() {
                return Err(Error::InvalidAmount);
            }
            let cost = amount.safe_mul(multiplier)?;
            if cost > limit {
                return Err(Error::AllowanceExceeded);
            }
            total = total.safe_add(cost)?;
        }
        Ok(total)
    } else {
        Err(Error::InvalidInput)
    }
}

/// Checked batch allowance calculation helper.
///
/// Mirrors [`verify_batch_allowance`] to provide checked batch verification across contracts.
#[inline]
pub fn checked_batch_allowance<T: BatchAmount>(amounts: &[T], limits: &[T]) -> Result<T, Error> {
    verify_batch_allowance(amounts, limits)
}

/// Checked batch calculation helper for multi-token budgets and proposals.
///
/// Evaluates batch expenditure constraints against spending limits, returning
/// the checked total or a deterministic [`Error`].
#[inline]
pub fn checked_batch_calculation<T: BatchAmount>(amounts: &[T], limits: &[T]) -> Result<T, Error> {
    verify_batch_allowance(amounts, limits)
}

/// Checked batch calculation with multipliers for quantity-based expenditures.
#[inline]
pub fn checked_batch_calculation_with_multipliers<T: BatchAmount>(
    amounts: &[T],
    multipliers: &[T],
    limits: &[T],
) -> Result<T, Error> {
    verify_batch_allowance_with_multipliers(amounts, multipliers, limits)
}

/// Boolean-equivalent batch allowance validator returning `Ok(())` on success.
#[inline]
pub fn validate_batch_allowance<T: BatchAmount>(amounts: &[T], limits: &[T]) -> Result<(), Error> {
    verify_batch_allowance(amounts, limits).map(|_| ())
}

/// Verify an iterator of `(amount, limit)` pairs.
///
/// Zero-allocation streaming validator that verifies each `amount <= limit` and
/// accumulates total expenditure safely.
///
/// # Errors
/// - [`Error::InvalidAmount`]: Any `amount < 0` or `limit < 0`.
/// - [`Error::AllowanceExceeded`]: Any `amount > limit`.
/// - [`Error::Overflow`]: Cumulative total overflows `T`.
pub fn verify_batch_allowance_pairs<T, I>(items: I) -> Result<T, Error>
where
    T: BatchAmount,
    I: IntoIterator<Item = (T, T)>,
{
    let mut total = T::ZERO;
    for (amount, limit) in items {
        if amount.is_negative() || limit.is_negative() {
            return Err(Error::InvalidAmount);
        }
        if amount > limit {
            return Err(Error::AllowanceExceeded);
        }
        total = total.safe_add(amount)?;
    }
    Ok(total)
}

/// Verify an iterator of expenditure amounts against a single aggregate limit.
///
/// Zero-allocation streaming validator that sums all amounts with overflow protection
/// and verifies the sum does not exceed `limit`.
///
/// # Errors
/// - [`Error::InvalidAmount`]: Any `amount < 0` or `limit < 0`.
/// - [`Error::AllowanceExceeded`]: Cumulative total exceeds `limit`.
/// - [`Error::Overflow`]: Cumulative total overflows `T`.
pub fn verify_batch_allowance_aggregate<T, I>(amounts: I, limit: T) -> Result<T, Error>
where
    T: BatchAmount,
    I: IntoIterator<Item = T>,
{
    if limit.is_negative() {
        return Err(Error::InvalidAmount);
    }
    let mut total = T::ZERO;
    for amount in amounts {
        if amount.is_negative() {
            return Err(Error::InvalidAmount);
        }
        total = total.safe_add(amount)?;
    }
    if total > limit {
        return Err(Error::AllowanceExceeded);
    }
    Ok(total)
}

/// Stream-verify two iterators of amounts and limits.
///
/// If `limits` yields a single item, evaluates all amounts against that aggregate limit.
/// If `limits` yields multiple items, evaluates amounts and limits pairwise.
///
/// # Errors
/// - [`Error::InvalidAmount`]: Any negative amount or limit.
/// - [`Error::AllowanceExceeded`]: Any limit breach.
/// - [`Error::Overflow`]: Arithmetic overflow.
/// - [`Error::InvalidInput`]: Iterator length mismatch or empty limits for non-empty amounts.
pub fn verify_batch_allowance_iter<T, A, L>(amounts: A, limits: L) -> Result<T, Error>
where
    T: BatchAmount,
    A: IntoIterator<Item = T>,
    L: IntoIterator<Item = T>,
{
    let mut amounts_iter = amounts.into_iter();
    let mut limits_iter = limits.into_iter();

    let first_limit = match limits_iter.next() {
        Some(l) => l,
        None => {
            if amounts_iter.next().is_none() {
                return Ok(T::ZERO);
            }
            return Err(Error::InvalidInput);
        }
    };

    let second_limit = limits_iter.next();
    match second_limit {
        None => {
            if first_limit.is_negative() {
                return Err(Error::InvalidAmount);
            }
            let mut total = T::ZERO;
            for amount in amounts_iter {
                if amount.is_negative() {
                    return Err(Error::InvalidAmount);
                }
                total = total.safe_add(amount)?;
            }
            if total > first_limit {
                return Err(Error::AllowanceExceeded);
            }
            Ok(total)
        }
        Some(second_limit_val) => {
            let first_amount = match amounts_iter.next() {
                Some(a) => a,
                None => return Err(Error::InvalidInput),
            };
            if first_amount.is_negative() || first_limit.is_negative() {
                return Err(Error::InvalidAmount);
            }
            if first_amount > first_limit {
                return Err(Error::AllowanceExceeded);
            }
            let mut total = first_amount;

            let second_amount = match amounts_iter.next() {
                Some(a) => a,
                None => return Err(Error::InvalidInput),
            };
            if second_amount.is_negative() || second_limit_val.is_negative() {
                return Err(Error::InvalidAmount);
            }
            if second_amount > second_limit_val {
                return Err(Error::AllowanceExceeded);
            }
            total = total.safe_add(second_amount)?;

            loop {
                match (amounts_iter.next(), limits_iter.next()) {
                    (Some(amount), Some(limit)) => {
                        if amount.is_negative() || limit.is_negative() {
                            return Err(Error::InvalidAmount);
                        }
                        if amount > limit {
                            return Err(Error::AllowanceExceeded);
                        }
                        total = total.safe_add(amount)?;
                    }
                    (None, None) => return Ok(total),
                    _ => return Err(Error::InvalidInput),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Budget rollover calculations
// ---------------------------------------------------------------------------

/// Calculate the rollover allowance for a budget period using basis points
/// and an optional upper cap.
///
/// Computes `floor(unspent * rollover_bps / 10_000)` safely without `i128` overflow.
/// If `max_rollover_cap > 0`, clamps the result to `min(credit, max_rollover_cap)`.
/// If `max_rollover_cap == 0`, the rollover is uncapped.
///
/// # Errors
/// - [`Error::InvalidAmount`] if `unspent < 0`, `rollover_bps < 0`, or `max_rollover_cap < 0`.
/// - [`Error::InvalidInput`] if `rollover_bps > BPS_DENOMINATOR` (10_000).
/// - [`Error::Overflow`] if intermediate arithmetic overflows.
pub fn calculate_budget_rollover(
    unspent: i128,
    rollover_bps: i128,
    max_rollover_cap: i128,
) -> Result<i128, Error> {
    if unspent < 0 || rollover_bps < 0 || max_rollover_cap < 0 {
        return Err(Error::InvalidAmount);
    }
    if rollover_bps > crate::constants::BPS_DENOMINATOR {
        return Err(Error::InvalidInput);
    }
    if unspent == 0 || rollover_bps == 0 {
        return Ok(0);
    }

    // Split unspent into quotient and remainder with BPS_DENOMINATOR (10_000)
    // to guarantee no i128 intermediate overflow even if unspent == i128::MAX.
    let q = unspent.safe_div(crate::constants::BPS_DENOMINATOR)?;
    let r = checked_rem(unspent, crate::constants::BPS_DENOMINATOR)?;
    let whole = q.safe_mul(rollover_bps)?;
    let part = (r.safe_mul(rollover_bps)?).safe_div(crate::constants::BPS_DENOMINATOR)?;
    let credit = whole.safe_add(part)?;

    if max_rollover_cap > 0 && credit > max_rollover_cap {
        Ok(max_rollover_cap)
    } else {
        Ok(credit)
    }
}

/// Alias for [`calculate_budget_rollover`].
pub fn compute_budget_rollover(
    unspent: i128,
    rollover_bps: i128,
    max_rollover_cap: i128,
) -> Result<i128, Error> {
    calculate_budget_rollover(unspent, rollover_bps, max_rollover_cap)
}

/// Compute the new period allowance by adding the rolled-over credit to the fresh period's base limit.
///
/// Verifies `base_limit >= 0` and uses checked arithmetic to prevent overflow.
pub fn calculate_rollover_allowance(
    base_limit: i128,
    unspent: i128,
    rollover_bps: i128,
    max_rollover_cap: i128,
) -> Result<i128, Error> {
    if base_limit < 0 {
        return Err(Error::InvalidAmount);
    }
    let credit = calculate_budget_rollover(unspent, rollover_bps, max_rollover_cap)?;
    base_limit.safe_add(credit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_allowance_single_limit_happy_path() {
        let amounts = [100i128, 200, 300];
        let limits = [600i128]; // Exact boundary
        assert_eq!(verify_batch_allowance(&amounts, &limits), Ok(600));
        assert_eq!(checked_batch_allowance(&amounts, &limits), Ok(600));
        assert_eq!(checked_batch_calculation(&amounts, &limits), Ok(600));
        assert_eq!(validate_batch_allowance(&amounts, &limits), Ok(()));
    }

    #[test]
    fn batch_allowance_pairwise_happy_path() {
        let amounts = [100i128, 200, 300];
        let limits = [100i128, 250, 300]; // Mixed exact and headroom
        assert_eq!(verify_batch_allowance(&amounts, &limits), Ok(600));
        assert_eq!(checked_batch_allowance(&amounts, &limits), Ok(600));
        assert_eq!(checked_batch_calculation(&amounts, &limits), Ok(600));
    }

    #[test]
    fn batch_allowance_u128_happy_path() {
        let amounts = [50u128, 150u128];
        let limits = [200u128];
        assert_eq!(verify_batch_allowance(&amounts, &limits), Ok(200));
        assert_eq!(checked_batch_calculation(&amounts, &limits), Ok(200));
    }

    #[test]
    fn batch_allowance_zero_values() {
        // Zero amounts and limits
        assert_eq!(verify_batch_allowance(&[0i128, 0], &[0i128]), Ok(0));
        assert_eq!(verify_batch_allowance(&[0i128, 0], &[0i128, 0]), Ok(0));
        assert_eq!(verify_batch_allowance(&[0i128], &[100i128]), Ok(0));

        // Empty amounts and limits
        let empty: [i128; 0] = [];
        assert_eq!(verify_batch_allowance(&empty, &empty), Ok(0));
        assert_eq!(verify_batch_allowance(&empty, &[100i128]), Ok(0));
        assert_eq!(verify_batch_allowance(&empty, &[0i128]), Ok(0));
    }

    #[test]
    fn batch_allowance_exact_boundary_and_breach() {
        // Single limit exact boundary
        assert_eq!(verify_batch_allowance(&[500i128], &[500i128]), Ok(500));
        // Single limit breach by 1
        assert_eq!(
            verify_batch_allowance(&[501i128], &[500i128]),
            Err(Error::AllowanceExceeded)
        );

        // Aggregate limit exact boundary
        assert_eq!(verify_batch_allowance(&[250i128, 250], &[500i128]), Ok(500));
        // Aggregate limit breach by 1
        assert_eq!(
            verify_batch_allowance(&[250i128, 251], &[500i128]),
            Err(Error::AllowanceExceeded)
        );

        // Pairwise exact boundary
        assert_eq!(
            verify_batch_allowance(&[100i128, 200], &[100i128, 200]),
            Ok(300)
        );
        // Pairwise breach on first element
        assert_eq!(
            verify_batch_allowance(&[101i128, 200], &[100i128, 200]),
            Err(Error::AllowanceExceeded)
        );
        // Pairwise breach on second element
        assert_eq!(
            verify_batch_allowance(&[100i128, 201], &[100i128, 200]),
            Err(Error::AllowanceExceeded)
        );
    }

    #[test]
    fn batch_allowance_overflow_scenarios() {
        // Addition overflow with i128::MAX in aggregate limit mode
        assert_eq!(
            verify_batch_allowance(&[i128::MAX, 1], &[i128::MAX]),
            Err(Error::Overflow)
        );

        // Addition overflow in pairwise mode (each within limit, but sum overflows)
        assert_eq!(
            verify_batch_allowance(&[i128::MAX, i128::MAX], &[i128::MAX, i128::MAX]),
            Err(Error::Overflow)
        );

        // Max representable amount at limit succeeds
        assert_eq!(
            verify_batch_allowance(&[i128::MAX], &[i128::MAX]),
            Ok(i128::MAX)
        );

        // u128 addition overflow
        assert_eq!(
            verify_batch_allowance(&[u128::MAX, 1], &[u128::MAX]),
            Err(Error::Overflow)
        );
    }

    #[test]
    fn batch_allowance_negative_and_invalid_inputs() {
        // Negative amount
        assert_eq!(
            verify_batch_allowance(&[-1i128, 10], &[100i128]),
            Err(Error::InvalidAmount)
        );
        assert_eq!(
            verify_batch_allowance(&[10i128, -1], &[100i128]),
            Err(Error::InvalidAmount)
        );
        assert_eq!(
            verify_batch_allowance(&[-1i128], &[-1i128]),
            Err(Error::InvalidAmount)
        );

        // Negative limit
        assert_eq!(
            verify_batch_allowance(&[10i128], &[-50i128]),
            Err(Error::InvalidAmount)
        );
        assert_eq!(
            verify_batch_allowance(&[], &[-50i128]),
            Err(Error::InvalidAmount)
        );

        // Non-empty amounts with empty limits
        assert_eq!(
            verify_batch_allowance(&[100i128], &[]),
            Err(Error::InvalidInput)
        );

        // Mismatched lengths (3 amounts, 2 limits)
        assert_eq!(
            verify_batch_allowance(&[10i128, 20, 30], &[50i128, 50]),
            Err(Error::InvalidInput)
        );

        // Empty amounts with >1 limits
        let empty: [i128; 0] = [];
        assert_eq!(
            verify_batch_allowance(&empty, &[100i128, 200]),
            Err(Error::InvalidInput)
        );
    }

    #[test]
    fn batch_allowance_with_multipliers_tests() {
        let amounts = [10i128, 20, 30];
        let multipliers = [5i128, 2, 1]; // 50, 40, 30 -> total 120
        let limits = [120i128]; // Exact boundary

        assert_eq!(
            verify_batch_allowance_with_multipliers(&amounts, &multipliers, &limits),
            Ok(120)
        );
        assert_eq!(
            checked_batch_calculation_with_multipliers(&amounts, &multipliers, &limits),
            Ok(120)
        );

        // Breach by 1
        assert_eq!(
            verify_batch_allowance_with_multipliers(&amounts, &multipliers, &[119i128]),
            Err(Error::AllowanceExceeded)
        );

        // Pairwise with multipliers
        assert_eq!(
            verify_batch_allowance_with_multipliers(&amounts, &multipliers, &[50i128, 40, 30]),
            Ok(120)
        );
        assert_eq!(
            verify_batch_allowance_with_multipliers(&amounts, &multipliers, &[50i128, 39, 30]),
            Err(Error::AllowanceExceeded)
        );

        // Multiplication overflow
        assert_eq!(
            verify_batch_allowance_with_multipliers(&[i128::MAX], &[2], &[i128::MAX]),
            Err(Error::Overflow)
        );

        // Negative multiplier
        assert_eq!(
            verify_batch_allowance_with_multipliers(&[10i128], &[-1], &[100i128]),
            Err(Error::InvalidAmount)
        );

        // Length mismatch
        assert_eq!(
            verify_batch_allowance_with_multipliers(&[10i128, 20], &[1], &[100i128]),
            Err(Error::InvalidInput)
        );

        // Empty multipliers defaults to standard batch allowance
        assert_eq!(
            verify_batch_allowance_with_multipliers(&[10i128, 20], &[], &[30i128]),
            Ok(30)
        );
    }

    #[test]
    fn batch_allowance_iterator_helpers() {
        // verify_batch_allowance_pairs
        let pairs = [(100i128, 150i128), (200, 200), (50, 100)];
        assert_eq!(verify_batch_allowance_pairs(pairs), Ok(350));

        let breach_pairs = [(100i128, 150i128), (201, 200)];
        assert_eq!(
            verify_batch_allowance_pairs(breach_pairs),
            Err(Error::AllowanceExceeded)
        );

        // verify_batch_allowance_aggregate
        let items = [100i128, 200, 300];
        assert_eq!(verify_batch_allowance_aggregate(items, 600), Ok(600));
        assert_eq!(
            verify_batch_allowance_aggregate(items, 599),
            Err(Error::AllowanceExceeded)
        );

        // verify_batch_allowance_iter single limit
        assert_eq!(
            verify_batch_allowance_iter([100i128, 200, 300], [600i128]),
            Ok(600)
        );
        // verify_batch_allowance_iter pairwise
        assert_eq!(
            verify_batch_allowance_iter([100i128, 200], [100i128, 250]),
            Ok(300)
        );
        // verify_batch_allowance_iter length mismatch
        assert_eq!(
            verify_batch_allowance_iter([100i128, 200, 300], [100i128, 200]),
            Err(Error::InvalidInput)
        );
    }

    #[test]
    fn u128_safe_arithmetic() {
        assert_eq!(checked_add_u128(10, 20), Ok(30));
        assert_eq!(checked_add_u128(u128::MAX, 1), Err(Error::Overflow));

        assert_eq!(checked_sub_u128(20, 10), Ok(10));
        assert_eq!(checked_sub_u128(10, 20), Err(Error::Overflow));

        assert_eq!(checked_mul_u128(10, 20), Ok(200));
        assert_eq!(checked_mul_u128(u128::MAX, 2), Err(Error::Overflow));

        assert_eq!(checked_div_u128(20, 10), Ok(2));
        assert_eq!(checked_div_u128(20, 0), Err(Error::InvalidInput));
    }
}
