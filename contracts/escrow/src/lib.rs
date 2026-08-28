#![no_std]
//! # Astroid Escrow Contract
//!
//! Temporary custody: `Sender → Escrow → (conditions) → Recipient`.
//! Escrows are used for milestone payments, freelancer work, agent-to-agent
//! settlements, and time-locked / gradual linear release schedules (PRD Doc 7 §Escrow).
//!
//! Release schedules support:
//! - Bullet / Cliff time-locks (`ReleaseType::Cliff`): 100% unlocked at maturity.
//! - Linear release schedules (`ReleaseType::Linear`): Continuous linear vesting
//!   from start_time to end_time with optional cliff_time.
//! - Partial and multiple gradual withdrawals by the beneficiary.
//! - Deterministic `Error::EscrowLocked` when withdrawing before maturity or cliff.
//! - Arbiter-governed releases before deadline and permissionless refunds after deadline.

pub mod storage;

pub use storage::{
    bump_escrow, get_count, increment_count, load_escrow, store_escrow, DataKey, Escrow,
    EscrowState, ReleaseSchedule, ReleaseType,
};

use astroid_shared::constants::{INSTANCE_BUMP_AMOUNT, INSTANCE_LIFETIME_THRESHOLD};
use astroid_shared::errors::Error;
use astroid_shared::events;
use astroid_shared::math::{checked_add, checked_div, checked_mul, checked_sub};
use astroid_shared::validation::require_positive_amount;
use soroban_sdk::{contract, contractimpl, symbol_short, token, Address, Env, String};

/// Calculate vested amount according to a ReleaseSchedule at a given ledger timestamp.
pub fn calculate_vested_amount(
    amount: i128,
    schedule: &ReleaseSchedule,
    current_time: u64,
) -> Result<i128, Error> {
    match schedule.release_type {
        ReleaseType::None => Ok(0),
        ReleaseType::Cliff => {
            if schedule.end_time < schedule.start_time
                || schedule.cliff_time < schedule.start_time
                || schedule.cliff_time > schedule.end_time
            {
                return Err(Error::InvalidInput);
            }
            if current_time < schedule.cliff_time || current_time < schedule.start_time {
                return Ok(0);
            }
            if current_time >= schedule.end_time {
                Ok(amount)
            } else {
                Ok(0)
            }
        }
        ReleaseType::Linear => {
            if schedule.end_time <= schedule.start_time
                || schedule.cliff_time < schedule.start_time
                || schedule.cliff_time > schedule.end_time
            {
                return Err(Error::InvalidInput);
            }
            if current_time < schedule.cliff_time || current_time < schedule.start_time {
                return Ok(0);
            }
            if current_time >= schedule.end_time {
                return Ok(amount);
            }
            let total_duration = (schedule.end_time - schedule.start_time) as i128;
            if total_duration == 0 {
                return Ok(amount);
            }
            let elapsed = (current_time - schedule.start_time) as i128;
            let vested = checked_div(checked_mul(amount, elapsed)?, total_duration)?;
            Ok(vested)
        }
    }
}

/// Calculate currently claimable (vested minus already released) amount for an escrow.
pub fn calculate_claimable_amount(escrow: &Escrow, current_time: u64) -> Result<i128, Error> {
    if matches!(
        escrow.schedule.release_type,
        ReleaseType::Cliff | ReleaseType::Linear
    ) {
        let vested = calculate_vested_amount(escrow.funded_amount, &escrow.schedule, current_time)?;
        let claimable = checked_sub(vested, escrow.released_amount)?;
        if claimable < 0 {
            return Ok(0);
        }
        Ok(claimable)
    } else {
        Ok(0)
    }
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

    /// Create + fund an arbiter-governed escrow in one call. `sender` locks `amount` of `asset`
    /// until `deadline` and names a `recipient` and an `arbiter`. The real tokens
    /// are moved into the contract's custody here.
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
        sender.require_auth();
        require_positive_amount(amount)?;
        if recipient == sender {
            return Err(Error::InvalidInput);
        }
        if deadline <= env.ledger().timestamp() {
            return Err(Error::InvalidInput);
        }

        let id = increment_count(&env)?;

        // Pull the funds into the escrow's custody.
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
            schedule: ReleaseSchedule::none(),
            released_amount: 0,
        };
        store_escrow(&env, id, &escrow);

        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("funded")),
            (id, sender, recipient, asset, amount),
        );
        Ok(id)
    }

    /// Create a funded time-locked escrow with bullet cliff release at `unlock_time`.
    #[allow(clippy::too_many_arguments)]
    pub fn create_timelock(
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
        let now = env.ledger().timestamp();
        if unlock_time <= now {
            return Err(Error::InvalidInput);
        }

        let id = increment_count(&env)?;

        token::TokenClient::new(&env, &asset).transfer(
            &sender,
            &env.current_contract_address(),
            &amount,
        );

        let schedule = ReleaseSchedule {
            release_type: ReleaseType::Cliff,
            start_time: now,
            cliff_time: unlock_time,
            end_time: unlock_time,
        };

        let escrow = Escrow {
            sender: sender.clone(),
            recipient: recipient.clone(),
            arbiter,
            asset: asset.clone(),
            amount,
            state: EscrowState::Funded,
            deadline: unlock_time,
            funded_amount: amount,
            memo,
            schedule,
            released_amount: 0,
        };
        store_escrow(&env, id, &escrow);

        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("funded")),
            (id, sender.clone(), recipient.clone(), asset.clone(), amount),
        );
        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("init_tl")),
            (id, sender, recipient, asset, amount, unlock_time),
        );
        Ok(id)
    }

    /// Create a funded escrow with configurable release schedule (Cliff or Linear).
    #[allow(clippy::too_many_arguments)]
    pub fn create_scheduled(
        env: Env,
        sender: Address,
        recipient: Address,
        arbiter: Address,
        asset: Address,
        amount: i128,
        schedule: ReleaseSchedule,
        deadline: u64,
        memo: String,
    ) -> Result<u64, Error> {
        sender.require_auth();
        require_positive_amount(amount)?;
        if recipient == sender {
            return Err(Error::InvalidInput);
        }
        if schedule.start_time > schedule.cliff_time
            || schedule.cliff_time > schedule.end_time
            || schedule.end_time <= schedule.start_time
        {
            return Err(Error::InvalidInput);
        }
        if schedule.end_time <= env.ledger().timestamp() {
            return Err(Error::InvalidInput);
        }
        let effective_deadline = if deadline == 0 {
            schedule.end_time
        } else {
            deadline
        };
        if effective_deadline < schedule.end_time {
            return Err(Error::InvalidInput);
        }

        let id = increment_count(&env)?;

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
            deadline: effective_deadline,
            funded_amount: amount,
            memo,
            schedule: schedule.clone(),
            released_amount: 0,
        };
        store_escrow(&env, id, &escrow);

        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("funded")),
            (id, sender.clone(), recipient.clone(), asset.clone(), amount),
        );
        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("sched")),
            (
                id,
                sender,
                recipient,
                asset,
                amount,
                schedule.start_time,
                schedule.end_time,
            ),
        );
        Ok(id)
    }

    /// Initialize an unfunded escrow with time-lock schedule.
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
        let now = env.ledger().timestamp();
        if unlock_time <= now {
            return Err(Error::InvalidInput);
        }

        let id = increment_count(&env)?;

        let schedule = ReleaseSchedule {
            release_type: ReleaseType::Cliff,
            start_time: now,
            cliff_time: unlock_time,
            end_time: unlock_time,
        };

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
            schedule,
            released_amount: 0,
        };
        store_escrow(&env, id, &escrow);

        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("init_tl")),
            (id, sender, recipient, asset, amount, unlock_time),
        );
        Ok(id)
    }

    /// Fund an initialized escrow.
    pub fn fund(env: Env, sender: Address, id: u64) -> Result<(), Error> {
        sender.require_auth();
        let mut escrow = load_escrow(&env, id)?;
        if escrow.sender != sender {
            return Err(Error::Unauthorized);
        }
        if !matches!(escrow.state, EscrowState::Created) {
            return Err(Error::InvalidState);
        }

        token::TokenClient::new(&env, &escrow.asset).transfer(
            &sender,
            &env.current_contract_address(),
            &escrow.amount,
        );

        escrow.funded_amount = escrow.amount;
        escrow.state = EscrowState::Funded;
        store_escrow(&env, id, &escrow);

        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("funded")),
            (
                id,
                escrow.sender,
                escrow.recipient,
                escrow.asset,
                escrow.amount,
            ),
        );
        Ok(())
    }

    /// Beneficiary partial or full withdrawal according to release schedule.
    pub fn withdraw(env: Env, caller: Address, id: u64, amount: i128) -> Result<i128, Error> {
        caller.require_auth();
        require_positive_amount(amount)?;
        let mut escrow = load_escrow(&env, id)?;
        if escrow.recipient != caller {
            return Err(Error::Unauthorized);
        }
        if !matches!(escrow.state, EscrowState::Funded) {
            return Err(Error::InvalidState);
        }

        let now = env.ledger().timestamp();
        let claimable = calculate_claimable_amount(&escrow, now)?;
        if claimable <= 0 {
            return Err(Error::EscrowLocked);
        }
        if amount > claimable {
            return Err(Error::InsufficientFunds);
        }

        escrow.released_amount = checked_add(escrow.released_amount, amount)?;
        if escrow.released_amount == escrow.funded_amount {
            escrow.state = EscrowState::Released;
        }
        store_escrow(&env, id, &escrow);

        token::TokenClient::new(&env, &escrow.asset).transfer(
            &env.current_contract_address(),
            &escrow.recipient,
            &amount,
        );
        events::transfer_executed(
            &env,
            &escrow.sender,
            &escrow.recipient,
            &escrow.asset,
            amount,
        );
        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("withdraw")),
            (id, caller, amount, escrow.released_amount),
        );
        Ok(escrow.released_amount)
    }

    /// Claim all currently available funds from time-locked or scheduled escrow.
    pub fn claim(env: Env, caller: Address, id: u64) -> Result<i128, Error> {
        caller.require_auth();
        let mut escrow = load_escrow(&env, id)?;
        if escrow.recipient != caller {
            return Err(Error::Unauthorized);
        }

        let now = env.ledger().timestamp();

        if matches!(escrow.state, EscrowState::Funded) {
            let claimable = if matches!(
                escrow.schedule.release_type,
                ReleaseType::Cliff | ReleaseType::Linear
            ) {
                calculate_claimable_amount(&escrow, now)?
            } else {
                if now < escrow.deadline {
                    return Err(Error::EscrowLocked);
                }
                checked_sub(escrow.funded_amount, escrow.released_amount)?
            };

            if claimable <= 0 {
                return Err(Error::EscrowLocked);
            }

            escrow.released_amount = checked_add(escrow.released_amount, claimable)?;
            if escrow.released_amount == escrow.funded_amount {
                escrow.state = EscrowState::Released;
            }
            store_escrow(&env, id, &escrow);

            token::TokenClient::new(&env, &escrow.asset).transfer(
                &env.current_contract_address(),
                &escrow.recipient,
                &claimable,
            );
            events::transfer_executed(
                &env,
                &escrow.sender,
                &escrow.recipient,
                &escrow.asset,
                claimable,
            );
            env.events().publish(
                (symbol_short!("escrow"), symbol_short!("claimed")),
                (id, caller, claimable),
            );
            Ok(claimable)
        } else if matches!(escrow.state, EscrowState::Created) {
            if now < escrow.deadline {
                return Err(Error::EscrowLocked);
            }
            escrow.state = EscrowState::Released;
            store_escrow(&env, id, &escrow);
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
                (id, caller, escrow.amount),
            );
            Ok(escrow.amount)
        } else {
            Err(Error::InvalidState)
        }
    }

    /// Release the escrowed funds to the recipient. Only the arbiter may call,
    /// and only before the deadline.
    pub fn release(env: Env, arbiter: Address, id: u64) -> Result<(), Error> {
        arbiter.require_auth();
        let mut escrow = load_escrow(&env, id)?;
        if escrow.arbiter != arbiter {
            return Err(Error::Unauthorized);
        }
        if !matches!(escrow.state, EscrowState::Funded) {
            return Err(Error::InvalidState);
        }
        if env.ledger().timestamp() >= escrow.deadline {
            return Err(Error::EscrowExpired);
        }

        let remaining = checked_sub(escrow.funded_amount, escrow.released_amount)?;
        escrow.released_amount = escrow.funded_amount;
        escrow.state = EscrowState::Released;
        store_escrow(&env, id, &escrow);

        token::TokenClient::new(&env, &escrow.asset).transfer(
            &env.current_contract_address(),
            &escrow.recipient,
            &remaining,
        );
        events::transfer_executed(
            &env,
            &escrow.sender,
            &escrow.recipient,
            &escrow.asset,
            remaining,
        );
        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("released")),
            (id, arbiter),
        );
        Ok(())
    }

    /// Mark a timed-out escrow `Expired` once its deadline has passed.
    pub fn expire(env: Env, id: u64) -> Result<(), Error> {
        let mut escrow = load_escrow(&env, id)?;
        if !matches!(escrow.state, EscrowState::Funded) {
            return Err(Error::InvalidState);
        }
        if env.ledger().timestamp() < escrow.deadline {
            return Err(Error::InvalidState);
        }
        escrow.state = EscrowState::Expired;
        store_escrow(&env, id, &escrow);
        env.events()
            .publish((symbol_short!("escrow"), symbol_short!("expired")), id);
        Ok(())
    }

    /// Refund remaining funds back to the sender after the deadline.
    pub fn refund(env: Env, caller: Address, id: u64) -> Result<(), Error> {
        caller.require_auth();
        let mut escrow = load_escrow(&env, id)?;
        if !matches!(escrow.state, EscrowState::Funded | EscrowState::Expired) {
            return Err(Error::InvalidState);
        }
        if env.ledger().timestamp() < escrow.deadline {
            return Err(Error::InvalidState);
        }

        let remaining = checked_sub(escrow.funded_amount, escrow.released_amount)?;
        escrow.state = EscrowState::Refunded;
        store_escrow(&env, id, &escrow);

        if remaining > 0 {
            token::TokenClient::new(&env, &escrow.asset).transfer(
                &env.current_contract_address(),
                &escrow.sender,
                &remaining,
            );
        }
        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("refunded")),
            (id, caller),
        );
        Ok(())
    }

    /// Refund time-locked escrow after unlock_time / deadline has elapsed.
    pub fn refund_timelock(env: Env, caller: Address, id: u64) -> Result<(), Error> {
        caller.require_auth();
        let mut escrow = load_escrow(&env, id)?;
        if escrow.sender != caller {
            return Err(Error::Unauthorized);
        }
        if !matches!(
            escrow.state,
            EscrowState::Created | EscrowState::Funded | EscrowState::Expired
        ) {
            return Err(Error::InvalidState);
        }
        if env.ledger().timestamp() < escrow.deadline {
            return Err(Error::EscrowLocked);
        }

        let remaining = checked_sub(escrow.funded_amount, escrow.released_amount)?;
        escrow.state = EscrowState::Refunded;
        store_escrow(&env, id, &escrow);

        if remaining > 0 {
            token::TokenClient::new(&env, &escrow.asset).transfer(
                &env.current_contract_address(),
                &escrow.sender,
                &remaining,
            );
        }
        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("ref_tl")),
            (id, caller),
        );
        Ok(())
    }

    /// Close a settled escrow (terminal).
    pub fn close(env: Env, caller: Address, id: u64) -> Result<(), Error> {
        caller.require_auth();
        let mut escrow = load_escrow(&env, id)?;
        if !matches!(escrow.state, EscrowState::Released | EscrowState::Refunded) {
            return Err(Error::InvalidState);
        }
        if caller != escrow.sender && caller != escrow.recipient && caller != escrow.arbiter {
            return Err(Error::Unauthorized);
        }
        escrow.state = EscrowState::Closed;
        store_escrow(&env, id, &escrow);
        Ok(())
    }

    // --- views ---

    pub fn get(env: Env, id: u64) -> Result<Escrow, Error> {
        load_escrow(&env, id)
    }

    pub fn get_claimable_amount(env: Env, id: u64) -> Result<i128, Error> {
        let escrow = load_escrow(&env, id)?;
        calculate_claimable_amount(&escrow, env.ledger().timestamp())
    }

    pub fn get_vested_amount(env: Env, id: u64) -> Result<i128, Error> {
        let escrow = load_escrow(&env, id)?;
        calculate_vested_amount(
            escrow.funded_amount,
            &escrow.schedule,
            env.ledger().timestamp(),
        )
    }

    pub fn get_schedule(env: Env, id: u64) -> Result<ReleaseSchedule, Error> {
        let escrow = load_escrow(&env, id)?;
        Ok(escrow.schedule)
    }
}

#[cfg(test)]
mod test;
