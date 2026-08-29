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

use astroid_shared::constants::{
    HOUR_IN_LEDGERS, INSTANCE_BUMP_AMOUNT, INSTANCE_LIFETIME_THRESHOLD, PERSISTENT_BUMP_AMOUNT,
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
    pub funded_amount: i128,
    pub memo: String,
    /// Pending beneficiary replacement address (None = no proposal active).
    pub proposed_beneficiary: Option<Address>,
    /// Ledger sequence at which the beneficiary proposal was created.
    pub proposed_at_seq: u32,
}

/// Mandatory number of ledger sequences that must elapse between a beneficiary
/// proposal and when it may be claimed. ~1 hour on Stellar.
pub const BENEFICIARY_TIMELEDGER_DELTA: u32 = HOUR_IN_LEDGERS;

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
            funded_amount: amount,
            memo,
            proposed_beneficiary: None,
            proposed_at_seq: 0,
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
            funded_amount: 0,
            memo,
            proposed_beneficiary: None,
            proposed_at_seq: 0,
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
    pub fn refund(env: Env, caller: Address, id: u64) -> Result<(), Error> {
        caller.require_auth();
        let mut escrow = Self::load(&env, id)?;
        if !matches!(escrow.state, EscrowState::Funded | EscrowState::Expired) {
            return Err(Error::InvalidState);
        }
        if env.ledger().timestamp() < escrow.deadline {
            return Err(Error::InvalidState);
        }
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

    /// Refund time-locked escrow after unlock_time has elapsed.
    pub fn refund_timelock(env: Env, caller: Address, id: u64) -> Result<(), Error> {
        caller.require_auth();
        let mut escrow = Self::load(&env, id)?;
        if escrow.sender != caller {
            return Err(Error::Unauthorized);
        }
        if !matches!(escrow.state, EscrowState::Created) {
            return Err(Error::InvalidState);
        }
        if env.ledger().timestamp() < escrow.deadline {
            return Err(Error::TimeLockActive);
        }

        escrow.state = EscrowState::Refunded;
        Self::store(&env, id, &escrow);
        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("ref_tl")),
            (id, caller),
        );
        Ok(())
    }

    /// Propose a new beneficiary for this escrow. Only the sender or arbiter may
    /// call. A mandatory ledger-sequence timelock must elapse before the proposal
    /// can be claimed via [`claim_beneficiary`]. Submitting a new proposal while
    /// one already exists replaces it (resets the timelock).
    pub fn propose_beneficiary(
        env: Env,
        caller: Address,
        id: u64,
        new_beneficiary: Address,
    ) -> Result<(), Error> {
        caller.require_auth();
        let mut escrow = Self::load(&env, id)?;
        if caller != escrow.sender && caller != escrow.arbiter {
            return Err(Error::Unauthorized);
        }
        if !matches!(escrow.state, EscrowState::Created | EscrowState::Funded) {
            return Err(Error::InvalidState);
        }
        if new_beneficiary == escrow.recipient {
            return Err(Error::InvalidInput);
        }
        if new_beneficiary == escrow.sender {
            return Err(Error::InvalidInput);
        }
        if new_beneficiary == escrow.arbiter {
            return Err(Error::InvalidInput);
        }
        // Reject the zero address as a beneficiary.
        if is_zero_address(&env, &new_beneficiary) {
            return Err(Error::InvalidInput);
        }

        let current_seq = env.ledger().sequence();
        escrow.proposed_beneficiary = Some(new_beneficiary.clone());
        escrow.proposed_at_seq = current_seq;
        Self::store(&env, id, &escrow);
        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("bene_prp")),
            (id, caller, new_beneficiary, current_seq),
        );
        Ok(())
    }

    /// Claim a previously proposed beneficiary change. Callable only by the
    /// proposed beneficiary and only after [`BENEFICIARY_TIMELEDGER_DELTA`]
    /// ledgers have elapsed since the proposal was created. On success the
    /// escrow's `recipient` is updated and the proposal is cleared.
    pub fn claim_beneficiary(env: Env, caller: Address, id: u64) -> Result<(), Error> {
        caller.require_auth();
        let mut escrow = Self::load(&env, id)?;
        if !matches!(escrow.state, EscrowState::Created | EscrowState::Funded) {
            return Err(Error::InvalidState);
        }
        let proposed = escrow
            .proposed_beneficiary
            .as_ref()
            .ok_or(Error::InvalidState)?;
        if *proposed != caller {
            return Err(Error::Unauthorized);
        }

        let current_seq = env.ledger().sequence();
        let required_seq = escrow
            .proposed_at_seq
            .checked_add(BENEFICIARY_TIMELEDGER_DELTA)
            .ok_or(Error::Overflow)?;
        if current_seq < required_seq {
            return Err(Error::TimeLockActive);
        }

        escrow.recipient = proposed.clone();
        escrow.proposed_beneficiary = None;
        escrow.proposed_at_seq = 0;
        Self::store(&env, id, &escrow);
        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("bene_clm")),
            (id, caller, escrow.recipient),
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

    // --- internals ---

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

/// Returns `true` if `addr` is the zero public key (all 32 bytes zero).
fn is_zero_address(_env: &Env, addr: &Address) -> bool {
    let s = addr.to_string();
    let len = s.len() as usize;
    let mut buf = [0u8; 64];
    s.copy_into_slice(&mut buf[..len]);
    buf[..len].iter().all(|&b| b == 0)
}

#[cfg(test)]
mod test;
