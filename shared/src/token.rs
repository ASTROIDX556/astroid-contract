//! Overflow-safe token transfer wrappers.
//!
//! A raw `token::TokenClient::transfer` traps the whole invocation when the
//! token contract refuses (insufficient balance, overflowing recipient,
//! missing auth, deauthorized trustline, ...), so the caller cannot tell the
//! Astroid backend *why* a payment failed. These wrappers validate everything
//! the protocol can check up front and then invoke the token through
//! `try_transfer`, so every failure surfaces as a deterministic [`Error`]:
//!
//! | Condition                                   | Error                      |
//! |---------------------------------------------|----------------------------|
//! | `amount <= 0`                               | [`Error::InvalidAmount`]   |
//! | sender's token balance `< amount`           | [`Error::InsufficientFunds`] |
//! | recipient balance `+ amount` exceeds `i128` | [`Error::Overflow`]        |
//! | batch total exceeds `i128`                  | [`Error::Overflow`]        |
//! | token refuses: trustline / account problems | [`Error::Unauthorized`]    |
//! | token refuses for any other reason          | [`Error::InvalidState`]    |
//!
//! Token-side refusals are decoded with the Stellar Asset Contract's error
//! table (see [`map_token_error`]); a custom token that reuses those codes
//! maps the same way, and anything unrecognised fails closed as
//! [`Error::InvalidState`]. Nothing is ever clamped or silently skipped: a
//! wrapper either moves exactly `amount` or returns an error.
//!
//! Host-level failures inside the token (most commonly `from` not having
//! authorized the transfer, or `token` not being a contract) reach the caller
//! only as a sanitized `Error(Context, InvalidAction)`: the host deliberately
//! hides the callee's cause. They therefore surface as
//! [`Error::InvalidState`] rather than a guessed, possibly wrong, code.

use crate::errors::Error;
use crate::math::{checked_balance_add, checked_balance_sub, validate_sufficient_balance};
use crate::validation::require_positive_amount;
use soroban_sdk::xdr::ScErrorType;
use soroban_sdk::{token::TokenClient, Address, Env};

// Stellar Asset Contract error codes (soroban-env-host `ContractError`).
const SAC_UNAUTHORIZED: u32 = 4;
const SAC_AUTHENTICATION: u32 = 5;
const SAC_ACCOUNT_MISSING: u32 = 6;
const SAC_NEGATIVE_AMOUNT: u32 = 8;
const SAC_BALANCE: u32 = 10;
const SAC_BALANCE_DEAUTHORIZED: u32 = 11;
const SAC_OVERFLOW: u32 = 12;
const SAC_TRUSTLINE_MISSING: u32 = 13;

/// Require a transferable amount: strictly positive. Zero and negative
/// amounts fail with [`Error::InvalidAmount`].
pub fn validate_transfer_amount(amount: i128) -> Result<(), Error> {
    require_positive_amount(amount)
}

/// Sum the legs of a batch payout. Every leg must be a valid transfer amount
/// ([`Error::InvalidAmount`]) and the total must fit in an `i128`
/// ([`Error::Overflow`]). An empty batch totals zero.
pub fn checked_transfer_total<I>(amounts: I) -> Result<i128, Error>
where
    I: IntoIterator<Item = i128>,
{
    let mut total: i128 = 0;
    for amount in amounts {
        validate_transfer_amount(amount)?;
        total = checked_balance_add(total, amount)?;
    }
    Ok(total)
}

/// Translate an error raised by a token contract into the shared table.
pub fn map_token_error(err: soroban_sdk::Error) -> Error {
    if err.is_type(ScErrorType::Contract) {
        return match err.get_code() {
            SAC_BALANCE => Error::InsufficientFunds,
            SAC_NEGATIVE_AMOUNT => Error::InvalidAmount,
            SAC_OVERFLOW => Error::Overflow,
            SAC_UNAUTHORIZED
            | SAC_AUTHENTICATION
            | SAC_ACCOUNT_MISSING
            | SAC_BALANCE_DEAUTHORIZED
            | SAC_TRUSTLINE_MISSING => Error::Unauthorized,
            _ => Error::InvalidState,
        };
    }
    if err.is_type(ScErrorType::Auth) {
        return Error::Unauthorized;
    }
    Error::InvalidState
}

/// Read `who`'s balance of `token` without trapping. A token that cannot be
/// queried, or reports a negative balance, fails closed.
pub fn token_balance(env: &Env, token: &Address, who: &Address) -> Result<i128, Error> {
    match TokenClient::new(env, token).try_balance(who) {
        Ok(Ok(balance)) if balance >= 0 => Ok(balance),
        Ok(Ok(_)) => Err(Error::InvalidState),
        Ok(Err(_)) => Err(Error::InvalidState),
        Err(Ok(err)) => Err(map_token_error(err)),
        Err(Err(_)) => Err(Error::InvalidState),
    }
}

/// Move exactly `amount` of `token` from `from` to `to`.
///
/// Checks, in order: the amount is valid, `from` holds at least `amount`,
/// and crediting `to` cannot overflow; only then is the token invoked. `from`
/// must authorize the transfer exactly as with a direct token call (a
/// contract paying out of its own balance authorizes implicitly).
pub fn safe_transfer(
    env: &Env,
    token: &Address,
    from: &Address,
    to: &Address,
    amount: i128,
) -> Result<(), Error> {
    validate_transfer_amount(amount)?;
    validate_sufficient_balance(token_balance(env, token, from)?, amount)?;
    if from != to {
        checked_balance_add(token_balance(env, token, to)?, amount)?;
    }
    match TokenClient::new(env, token).try_transfer(from, to, &amount) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) => Err(Error::InvalidState),
        Err(Ok(err)) => Err(map_token_error(err)),
        Err(Err(_)) => Err(Error::InvalidState),
    }
}

/// [`safe_transfer`] for contracts that also keep an internal ledger of what
/// `from` may spend (e.g. a wallet's tracked balance).
///
/// The debit is validated against `tracked_balance` first
/// ([`Error::InvalidAmount`] / [`Error::InsufficientFunds`]), so the internal
/// ledger can never underflow, and the new tracked balance is returned only
/// after the token transfer succeeded. The caller persists it.
pub fn safe_transfer_tracked(
    env: &Env,
    token: &Address,
    from: &Address,
    to: &Address,
    tracked_balance: i128,
    amount: i128,
) -> Result<i128, Error> {
    validate_transfer_amount(amount)?;
    let remaining = checked_balance_sub(tracked_balance, amount)?;
    safe_transfer(env, token, from, to, amount)?;
    Ok(remaining)
}
