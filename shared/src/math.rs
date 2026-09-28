//! Overflow-safe `i128` and `u64` arithmetic.
//!
//! Financial contracts must never rely on wrapping arithmetic. Every value
//! computation routes through these helpers, which return a contract [`Error`]
//! instead of panicking so callers can fail safely and deterministically.

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
