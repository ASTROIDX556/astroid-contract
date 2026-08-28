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
    INSTANCE_BUMP_AMOUNT, INSTANCE_LIFETIME_THRESHOLD, PERSISTENT_BUMP_AMOUNT,
    PERSISTENT_LIFETIME_THRESHOLD,
};
use astroid_shared::errors::Error;
use astroid_shared::events;
use astroid_shared::math::{checked_add, checked_div, checked_mul, checked_sub};
use astroid_shared::validation::require_positive_amount;
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, token, Address, Env, String, Vec,
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
}

/// A single milestone within a milestone-based escrow. `release_bps` is the
/// proportion of the total escrow amount (in basis points, 10_000 = 100%) that
/// is disbursed to the recipient when this milestone is approved.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Milestone {
    pub index: u32,
    pub description: String,
    pub release_bps: u32,
    pub released: bool,
}

/// Input describing a milestone when the escrow is created.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MilestoneSpec {
    pub description: String,
    pub release_bps: u32,
}

/// Aggregate milestone state for an escrow: the ordered milestones and the total
/// amount disbursed so far (used to compute the final, dust-free payout).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MilestoneSet {
    pub milestones: Vec<Milestone>,
    pub released_amount: i128,
}

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Count,
    Escrow(u64),
    Milestones(u64),
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
        // Milestone-based escrows must be settled via `release_milestone`.
        if env.storage().persistent().has(&DataKey::Milestones(id)) {
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

    /// Create + fund a milestone-based escrow in one call. Unlike `create`, the
    /// locked `amount` is disbursed progressively as the named `arbiter` approves
    /// each milestone via `release_milestone`. `milestones` must sum to exactly
    /// 10_000 basis points (100%). The real tokens are pulled into custody here.
    #[allow(clippy::too_many_arguments)]
    pub fn deposit_with_milestones(
        env: Env,
        sender: Address,
        recipient: Address,
        arbiter: Address,
        asset: Address,
        amount: i128,
        deadline: u64,
        memo: String,
        milestones: Vec<MilestoneSpec>,
    ) -> Result<u64, Error> {
        sender.require_auth();
        require_positive_amount(amount)?;
        if recipient == sender {
            return Err(Error::InvalidInput);
        }
        if deadline <= env.ledger().timestamp() {
            return Err(Error::InvalidInput);
        }
        if milestones.is_empty() {
            return Err(Error::InvalidInput);
        }

        // Basis points across all milestones must total exactly 100%.
        let mut total_bps: u32 = 0;
        for spec in milestones.iter() {
            total_bps = total_bps
                .checked_add(spec.release_bps)
                .ok_or(Error::Overflow)?;
        }
        if total_bps != 10_000 {
            return Err(Error::InvalidInput);
        }

        let mut count: u64 = env.storage().instance().get(&DataKey::Count).unwrap_or(0);
        count = checked_add(count as i128, 1)? as u64;
        let id = count;

        // Pull the funds into the escrow's own custody.
        token::TokenClient::new(&env, &asset).transfer(
            &sender,
            &env.current_contract_address(),
            &amount,
        );

        let mut items: Vec<Milestone> = Vec::new(&env);
        for (i, spec) in milestones.iter().enumerate() {
            items.push_back(Milestone {
                index: i as u32,
                description: spec.description.clone(),
                release_bps: spec.release_bps,
                released: false,
            });
        }
        let set = MilestoneSet {
            milestones: items,
            released_amount: 0,
        };
        env.storage()
            .persistent()
            .set(&DataKey::Milestones(id), &set);

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
        };
        env.storage()
            .persistent()
            .set(&DataKey::Escrow(id), &escrow);
        env.storage().persistent().extend_ttl(
            &DataKey::Milestones(id),
            PERSISTENT_LIFETIME_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
        Self::bump(&env, id);
        env.storage().instance().set(&DataKey::Count, &count);

        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("milestone")),
            (id, sender, recipient, asset, amount),
        );
        Ok(id)
    }

    /// Approve and release a single milestone's proportional payout to the
    /// recipient. Only the `arbiter` may approve (unauthorized approvals are
    /// rejected). When the final milestone is approved, the escrow transitions
    /// to `Released`. Checked math prevents over/under-disbursement.
    pub fn release_milestone(env: Env, caller: Address, id: u64, index: u32) -> Result<(), Error> {
        caller.require_auth();
        let mut escrow = Self::load(&env, id)?;
        if escrow.arbiter != caller {
            return Err(Error::Unauthorized);
        }
        if !matches!(escrow.state, EscrowState::Funded | EscrowState::Released) {
            return Err(Error::InvalidState);
        }

        let mut set: MilestoneSet = env
            .storage()
            .persistent()
            .get(&DataKey::Milestones(id))
            .ok_or(Error::NotFound)?;

        // Locate the requested milestone and ensure it is still pending.
        let mut found_idx: usize = 0;
        let mut target: Option<Milestone> = None;
        for (i, m) in set.milestones.iter().enumerate() {
            if m.index == index {
                found_idx = i;
                target = Some(m.clone());
            }
        }
        let milestone = target.ok_or(Error::InvalidInput)?;
        if milestone.released {
            return Err(Error::InvalidState);
        }

        // Only one milestone still unreleased → pay the dust-free remainder so the
        // recipient receives the full escrow amount despite basis-point rounding.
        let mut unreleased: u32 = 0;
        for m in set.milestones.iter() {
            if !m.released {
                unreleased = unreleased.saturating_add(1);
            }
        }
        let gross = checked_div(
            checked_mul(escrow.amount, milestone.release_bps as i128)?,
            10_000,
        )?;
        let remaining = checked_sub(escrow.amount, set.released_amount)?;
        let payout = if unreleased == 1 { remaining } else { gross };

        // Move the milestone's portion out of custody to the recipient.
        token::TokenClient::new(&env, &escrow.asset).transfer(
            &env.current_contract_address(),
            &escrow.recipient,
            &payout,
        );
        events::transfer_executed(
            &env,
            &escrow.sender,
            &escrow.recipient,
            &escrow.asset,
            payout,
        );

        set.released_amount = checked_add(set.released_amount, payout)?;
        let updated = Milestone {
            index: milestone.index,
            description: milestone.description,
            release_bps: milestone.release_bps,
            released: true,
        };
        set.milestones.set(found_idx as u32, updated);
        env.storage()
            .persistent()
            .set(&DataKey::Milestones(id), &set);

        // When every milestone is released, the escrow is fully settled.
        let all_released = set.milestones.iter().all(|m| m.released);
        if all_released {
            escrow.state = EscrowState::Released;
            Self::store(&env, id, &escrow);
        }

        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("ms_rel")),
            (id, caller, index, payout),
        );
        Ok(())
    }

    /// Read the milestone state for an escrow.
    pub fn milestones(env: Env, id: u64) -> Result<MilestoneSet, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::Milestones(id))
            .ok_or(Error::NotFound)
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

#[cfg(test)]
mod test;
