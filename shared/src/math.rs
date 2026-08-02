//! Overflow-safe `i128` arithmetic.
//!
//! Financial contracts must never rely on wrapping arithmetic. Every value
//! computation routes through these helpers, which return a contract [`Error`]
//! instead of panicking so callers can fail safely and deterministically.

use crate::errors::Error;

/// Checked addition. Returns [`Error::Overflow`] on wrap.
pub fn checked_add(a: i128, b: i128) -> Result<i128, Error> {
    a.checked_add(b).ok_or(Error::Overflow)
}

/// Checked subtraction. Returns [`Error::Underflow`] on wrap.
pub fn checked_sub(a: i128, b: i128) -> Result<i128, Error> {
    a.checked_sub(b).ok_or(Error::Underflow)
}

/// Checked multiplication. Returns [`Error::Overflow`] on wrap.
pub fn checked_mul(a: i128, b: i128) -> Result<i128, Error> {
    a.checked_mul(b).ok_or(Error::Overflow)
}

/// Checked division. Returns [`Error::InvalidInput`] on divide-by-zero.
pub fn checked_div(a: i128, b: i128) -> Result<i128, Error> {
    if b == 0 {
        return Err(Error::InvalidInput);
    }
    a.checked_div(b).ok_or(Error::Overflow)
}
