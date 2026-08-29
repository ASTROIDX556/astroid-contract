#![no_std]
//! # Astroid Escrow Contract
//!
//! Temporary custody: `Sender → Escrow → (conditions) → Recipient`.
//! Escrows are used for milestone payments, freelancer work, and agent-to-agent
//! settlements (PRD Doc 7 §Escrow). The escrow contract itself never decides
//! whether work was satisfactory — a designated arbiter signs release; a
//! deadline provides a default outcome. This keeps the contract small and
//! trustless while the richer policy logic lives off-chain.
//!
//! On `create` the sender's funds are pulled into the contract's own custody and
//! only leave through one of two settlement paths:
//!
//! ```text
//! Funded ──(arbiter, before deadline)──▶ Released ─▶ recipient ─▶ Closed
//! Funded ──(after deadline)────────────▶ Refunded ─▶ sender    ─▶ Closed
//!    └────(after deadline, marker)─────▶ Expired ──(refund)──▶ Refunded
//! ```
//!
//! `Expired` is a permissionless status marker (a keeper/UI may set it once the
//! deadline passes); funds stay in custody until `refund` returns them to the
//! sender, so no escrow can be `Closed` with money still locked.
//!
//! ## Refund window
//!
//! Refunds are only valid inside an explicit window that opens at the escrow's
//! `deadline` and — when a non-zero `refund_window` was configured — closes
//! `refund_window` seconds later:
//!
//! ```text
//! ── funded ──┤ deadline ├── refund window (open) ──┤ closes_at ├── expired ──▶
//!   too early                    refundable                    too late
//! ```
//!
//! Attempting a refund outside that window fails deterministically with
//! [`Error::RefundWindowNotOpen`] (before the deadline — the counterparty still
//! owns its guaranteed release window) or [`Error::RefundWindowClosed`] (after
//! the window elapsed). A `refund_window` of `0` means "no upper bound", which
//! is what [`EscrowContract::create`] configures so existing behaviour is
//! unchanged; use [`EscrowContract::create_with_refund_window`] to bound it.

use astroid_shared::constants::{
    INSTANCE_BUMP_AMOUNT, INSTANCE_LIFETIME_THRESHOLD, PERSISTENT_BUMP_AMOUNT,
    PERSISTENT_LIFETIME_THRESHOLD,
};
use astroid_shared::errors::Error;
use astroid_shared::events;
use astroid_shared::math::checked_add;
use astroid_shared::validation::require_positive_amount;
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, token, Address, Env, String,
};

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EscrowState {
    Created = 0,
    Funded = 1,
    Released = 2,
    Refunded = 3,
    Expired = 4,
    Closed = 5,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Escrow {
    pub sender: Address,
    pub recipient: Address,
    pub arbiter: Address,
    pub asset: Address,
    pub amount: i128,
    pub state: EscrowState,
    pub deadline: u64,
    /// Seconds after `deadline` during which a refund may be claimed.
    /// `0` means the refund window never closes.
    pub refund_window: u64,
    pub funded_amount: i128,
    pub memo: String,
}

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Count,
    Escrow(u64),
}

#[contract]
pub struct EscrowContract;

#[contractimpl]
impl EscrowContract {
    pub fn initialize(env: Env) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Count) {
            return Err(Error::AlreadyInitialized);
        }
        env.storage().instance().set(&DataKey::Count, &0u64);
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
        Ok(())
    }

    /// Create + fund an escrow in one call. `sender` locks `amount` of `asset`
    /// until `deadline` and names a `recipient` and an `arbiter`. The real tokens
    /// are moved into the contract's custody here — the escrow always reflects
    /// funds actually held.
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        env: Env,
        sender: Address,
        recipient: Address,
        arbiter: Address,
        asset: Address,
        amount: i128,
        deadline: u64,
        memo: String,
    ) -> Result<u64, Error> {
        Self::create_with_refund_window(
            env, sender, recipient, arbiter, asset, amount, deadline, 0, memo,
        )
    }

    /// Create + fund an escrow with a bounded refund window. Identical to
    /// [`Self::create`] except that the sender may only reclaim the funds during
    /// `[deadline, deadline + refund_window)`; passing `0` leaves the window open
    /// forever. A bounded window lets settlement logic treat an un-refunded,
    /// timed-out escrow as final.
    #[allow(clippy::too_many_arguments)]
    pub fn create_with_refund_window(
        env: Env,
        sender: Address,
        recipient: Address,
        arbiter: Address,
        asset: Address,
        amount: i128,
        deadline: u64,
        refund_window: u64,
        memo: String,
    ) -> Result<u64, Error> {
        // `sender` commits the funds.
        sender.require_auth();
        require_positive_amount(amount)?;
        if recipient == sender {
            return Err(Error::InvalidInput);
        }
        // A live release window is required — a past/zero deadline would make the
        // escrow un-releasable and instantly refundable.
        if deadline <= env.ledger().timestamp() {
            return Err(Error::InvalidInput);
        }

        let mut count: u64 = env.storage().instance().get(&DataKey::Count).unwrap_or(0);
        count = checked_add(count as i128, 1)? as u64;
        let id = count;

        // Pull the funds into the escrow's own custody. If the sender lacks the
        // balance this panics and the whole invocation (including the id bump)
        // rolls back.
        token::TokenClient::new(&env, &asset).transfer(
            &sender,
            &env.current_contract_address(),
            &amount,
        );

        let escrow = Escrow {
            sender: sender.clone(),
            recipient: recipient.clone(),
            arbiter,
            asset: asset.clone(),
            amount,
            state: EscrowState::Funded,
            deadline,
            refund_window,
            funded_amount: amount,
            memo,
        };
        env.storage()
            .persistent()
            .set(&DataKey::Escrow(id), &escrow);
        Self::bump(&env, id);
        env.storage().instance().set(&DataKey::Count, &count);

        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("funded")),
            (id, sender, recipient, asset, amount),
        );
        Ok(id)
    }

    /// Initialize an escrow with time-lock (unfunded version).
    #[allow(clippy::too_many_arguments)]
    pub fn initialize_timelock(
        env: Env,
        sender: Address,
        recipient: Address,
        arbiter: Address,
        asset: Address,
        amount: i128,
        unlock_time: u64,
        memo: String,
    ) -> Result<u64, Error> {
        sender.require_auth();
        require_positive_amount(amount)?;
        if recipient == sender {
            return Err(Error::InvalidInput);
        }
        if unlock_time <= env.ledger().timestamp() {
            return Err(Error::InvalidInput);
        }

        let mut count: u64 = env.storage().instance().get(&DataKey::Count).unwrap_or(0);
        count = checked_add(count as i128, 1)? as u64;
        let id = count;

        let escrow = Escrow {
            sender: sender.clone(),
            recipient: recipient.clone(),
            arbiter,
            asset: asset.clone(),
            amount,
            state: EscrowState::Created,
            deadline: unlock_time,
            // Time-locked escrows have no upper refund bound.
            refund_window: 0,
            funded_amount: 0,
            memo,
        };
        env.storage()
            .persistent()
            .set(&DataKey::Escrow(id), &escrow);
        Self::bump(&env, id);
        env.storage().instance().set(&DataKey::Count, &count);

        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("init_tl")),
            (id, sender, recipient, asset, amount, unlock_time),
        );
        Ok(id)
    }

    /// Claim funds from time-locked escrow after unlock_time.
    pub fn claim(env: Env, caller: Address, id: u64) -> Result<(), Error> {
        caller.require_auth();
        let mut escrow = Self::load(&env, id)?;
        if escrow.recipient != caller {
            return Err(Error::Unauthorized);
        }
        if !matches!(escrow.state, EscrowState::Created) {
            return Err(Error::InvalidState);
        }
        if env.ledger().timestamp() < escrow.deadline {
            return Err(Error::TimeLockActive);
        }

        escrow.state = EscrowState::Released;
        Self::store(&env, id, &escrow);
        token::TokenClient::new(&env, &escrow.asset).transfer(
            &env.current_contract_address(),
            &escrow.recipient,
            &escrow.amount,
        );
        events::transfer_executed(
            &env,
            &escrow.sender,
            &escrow.recipient,
            &escrow.asset,
            escrow.amount,
        );
        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("claimed")),
            (id, caller),
        );
        Ok(())
    }

    /// Release the escrowed funds to the recipient. Only the arbiter may call,
    /// and only before the deadline — afterward the sender reclaims via `refund`.
    pub fn release(env: Env, arbiter: Address, id: u64) -> Result<(), Error> {
        arbiter.require_auth();
        let mut escrow = Self::load(&env, id)?;
        if escrow.arbiter != arbiter {
            return Err(Error::Unauthorized);
        }
        if !matches!(escrow.state, EscrowState::Funded) {
            return Err(Error::InvalidState);
        }
        if env.ledger().timestamp() >= escrow.deadline {
            // Past the deadline the arbiter can no longer release. We do NOT persist
            // an `Expired` transition here: returning `Err` rolls back every storage
            // write, so the marker is set through the permissionless `expire`
            // entrypoint and the funds are reclaimed via `refund`.
            return Err(Error::EscrowExpired);
        }

        escrow.state = EscrowState::Released;
        Self::store(&env, id, &escrow);
        // Move the real tokens out of custody to the recipient.
        token::TokenClient::new(&env, &escrow.asset).transfer(
            &env.current_contract_address(),
            &escrow.recipient,
            &escrow.funded_amount,
        );
        events::transfer_executed(
            &env,
            &escrow.sender,
            &escrow.recipient,
            &escrow.asset,
            escrow.funded_amount,
        );
        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("released")),
            (id, arbiter),
        );
        Ok(())
    }

    /// Mark a timed-out escrow `Expired` once its deadline has passed.
    /// Permissionless status transition (a keeper or UI may call it). Funds are
    /// NOT moved here — they remain in custody until the sender reclaims them via
    /// `refund`, which also accepts the `Expired` state.
    pub fn expire(env: Env, id: u64) -> Result<(), Error> {
        let mut escrow = Self::load(&env, id)?;
        if !matches!(escrow.state, EscrowState::Funded) {
            return Err(Error::InvalidState);
        }
        if env.ledger().timestamp() < escrow.deadline {
            return Err(Error::InvalidState);
        }
        escrow.state = EscrowState::Expired;
        Self::store(&env, id, &escrow);
        env.events()
            .publish((symbol_short!("escrow"), symbol_short!("expired")), id);
        Ok(())
    }

    /// Refund the escrow back to the sender after the deadline (permissionless
    /// settlement path used when the escrow was never released — either still
    /// `Funded` past its deadline, or already marked `Expired`). Returns the real
    /// tokens to the sender.
    ///
    /// The refund window is enforced here: the call fails with
    /// [`Error::RefundWindowNotOpen`] before the deadline and with
    /// [`Error::RefundWindowClosed`] once a bounded window has elapsed.
    pub fn refund(env: Env, caller: Address, id: u64) -> Result<(), Error> {
        caller.require_auth();
        let mut escrow = Self::load(&env, id)?;
        if !matches!(escrow.state, EscrowState::Funded | EscrowState::Expired) {
            return Err(Error::InvalidState);
        }
        Self::check_refund_window(&env, &escrow, Error::RefundWindowNotOpen)?;
        escrow.state = EscrowState::Refunded;
        Self::store(&env, id, &escrow);
        // Return the real tokens to the sender.
        token::TokenClient::new(&env, &escrow.asset).transfer(
            &env.current_contract_address(),
            &escrow.sender,
            &escrow.funded_amount,
        );
        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("refunded")),
            (id, caller),
        );
        Ok(())
    }

    /// Refund time-locked escrow after unlock_time has elapsed. The same refund
    /// window applies; before the unlock time the historical
    /// [`Error::TimeLockActive`] is kept, since for this path the deadline *is*
    /// the time lock.
    pub fn refund_timelock(env: Env, caller: Address, id: u64) -> Result<(), Error> {
        caller.require_auth();
        let mut escrow = Self::load(&env, id)?;
        if escrow.sender != caller {
            return Err(Error::Unauthorized);
        }
        if !matches!(escrow.state, EscrowState::Created) {
            return Err(Error::InvalidState);
        }
        Self::check_refund_window(&env, &escrow, Error::TimeLockActive)?;

        escrow.state = EscrowState::Refunded;
        Self::store(&env, id, &escrow);
        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("ref_tl")),
            (id, caller),
        );
        Ok(())
    }

    /// Close a settled escrow (terminal). Callable only once the funds have
    /// actually moved — i.e. from `Released` or `Refunded`. An `Expired` escrow
    /// must be `refund`ed first so custody is emptied before it can be closed;
    /// this prevents closing over still-locked funds.
    pub fn close(env: Env, caller: Address, id: u64) -> Result<(), Error> {
        caller.require_auth();
        let mut escrow = Self::load(&env, id)?;
        if !matches!(escrow.state, EscrowState::Released | EscrowState::Refunded) {
            return Err(Error::InvalidState);
        }
        if caller != escrow.sender && caller != escrow.recipient && caller != escrow.arbiter {
            return Err(Error::Unauthorized);
        }
        escrow.state = EscrowState::Closed;
        Self::store(&env, id, &escrow);
        Ok(())
    }

    // --- views ---

    pub fn get(env: Env, id: u64) -> Result<Escrow, Error> {
        Self::load(&env, id)
    }

    /// Timestamp at which the escrow's refund window closes, or `0` when the
    /// window has no upper bound. Lets clients show a countdown without
    /// recomputing the window rule off-chain.
    pub fn refund_window_closes_at(env: Env, id: u64) -> Result<u64, Error> {
        let escrow = Self::load(&env, id)?;
        Ok(Self::closes_at(&escrow))
    }

    /// Whether a refund may be claimed for `id` at the current ledger time.
    pub fn is_refundable(env: Env, id: u64) -> Result<bool, Error> {
        let escrow = Self::load(&env, id)?;
        if !matches!(
            escrow.state,
            EscrowState::Created | EscrowState::Funded | EscrowState::Expired
        ) {
            return Ok(false);
        }
        Ok(Self::check_refund_window(&env, &escrow, Error::RefundWindowNotOpen).is_ok())
    }

    // --- internals ---

    /// Timestamp the refund window closes at (`0` = never). `saturating_add`
    /// keeps an absurd `refund_window` from overflowing into a closed window.
    fn closes_at(escrow: &Escrow) -> u64 {
        if escrow.refund_window == 0 {
            0
        } else {
            escrow.deadline.saturating_add(escrow.refund_window)
        }
    }

    /// Enforce that the current ledger time falls inside the escrow's refund
    /// window `[deadline, closes_at)`. `not_open` lets each settlement path keep
    /// its own error for "too early" while sharing one window rule. The escrow
    /// record is passed in so the check adds no extra storage reads.
    fn check_refund_window(env: &Env, escrow: &Escrow, not_open: Error) -> Result<(), Error> {
        let now = env.ledger().timestamp();
        if now < escrow.deadline {
            return Err(not_open);
        }
        let closes_at = Self::closes_at(escrow);
        if closes_at != 0 && now >= closes_at {
            return Err(Error::RefundWindowClosed);
        }
        Ok(())
    }

    fn load(env: &Env, id: u64) -> Result<Escrow, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::Escrow(id))
            .ok_or(Error::NotFound)
    }

    fn store(env: &Env, id: u64, escrow: &Escrow) {
        env.storage().persistent().set(&DataKey::Escrow(id), escrow);
        Self::bump(env, id);
    }

    fn bump(env: &Env, id: u64) {
        env.storage().persistent().extend_ttl(
            &DataKey::Escrow(id),
            PERSISTENT_LIFETIME_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
    }
}

#[cfg(test)]
mod test;
