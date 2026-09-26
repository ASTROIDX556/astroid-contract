//! Overflow-safe `i128` arithmetic.
//!
//! Financial contracts must never rely on wrapping arithmetic. Every value
//! computation routes through these helpers, which return a contract [`Error`]
//! instead of panicking so callers can fail safely and deterministically.

use crate::errors::Error;

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
        self.checked_add(other).ok_or(Error::Overflow)
    }
}

impl SafeSub for i128 {
    fn safe_sub(self, other: i128) -> Result<i128, Error> {
        self.checked_sub(other).ok_or(Error::Overflow)
    }
}

impl SafeMul for i128 {
    fn safe_mul(self, other: i128) -> Result<i128, Error> {
        self.checked_mul(other).ok_or(Error::Overflow)
    }
}

impl SafeDiv for i128 {
    fn safe_div(self, other: i128) -> Result<i128, Error> {
        if other == 0 {
            return Err(Error::InvalidInput);
        }
        self.checked_div(other).ok_or(Error::Overflow)
    }
}

// Keep the old functions for backwards compatibility in other contracts,
// but delegate to the traits
pub fn checked_add(a: i128, b: i128) -> Result<i128, Error> {
    a.safe_add(b).map_err(|_| Error::Overflow) // mapping back for old code
}

pub fn checked_sub(a: i128, b: i128) -> Result<i128, Error> {
    a.safe_sub(b)
}

pub fn checked_mul(a: i128, b: i128) -> Result<i128, Error> {
    a.safe_mul(b).map_err(|_| Error::Overflow)
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
