#![no_std]
//! # Astroid Escrow Contract
//!
//! Temporary custody: `Sender → Escrow → (conditions) → Recipient`.
//! Escrows are used for milestone payments, freelancer work, agent-to-agent
//! settlements, and time-locked / gradual linear release schedules (PRD Doc 7 §Escrow).
//!
//! A single escrow agreement may hold several distinct Stellar asset tokens at
//! once (e.g. a milestone payout mixing USDC and XLM) — `Escrow::assets` is a
//! list of `(asset, amount)` pairs rather than a single token/amount.
//!
//! On `create` the sender's funds are pulled into the contract's own custody and
//! only leave through one of three settlement paths:
//!
//! ```text
//! Funded ──(arbiter, before deadline+grace)─────▶ Released ─▶ recipient ─▶ Closed
//! Funded ──(signature override, before deadline)▶ Released ─▶ recipient ─▶ Closed
//! Funded ──(cancel, before deadline)────────────▶ Refunded ─▶ sender    ─▶ Closed
//! Funded ──(after deadline+grace, no release)───▶ reclaim  ─▶ sender    ─▶ Closed
//!    └────(after deadline+grace, marker)────────▶ Expired ──(refund)──▶ Refunded
//! ```
//!
//! `Expired` is a permissionless status marker (a keeper/UI may set it once the
//! deadline *and* grace period have passed, i.e. from `refund_opens_at`
//! onwards); funds stay in custody until `refund` or `reclaim` returns them to
//! the sender, so no escrow can be `Closed` with money still locked.
//!
//! ## Bounded refund window
//!
//! `grace_period` says when the sender's reclaim paths *open*; `refund_window`
//! optionally says when they *close*. An escrow created through
//! [`EscrowContract::create_with_refund_window`] may only be reclaimed during
//! `[deadline + grace_period, deadline + grace_period + refund_window)`, after
//! which `refund`, `refund_timelock` and `reclaim` all fail with
//! [`Error::EscrowExpired`]. `refund_window == 0` — what plain
//! [`EscrowContract::create`] stores — leaves the window open forever and
//! preserves the previous behaviour exactly.
//!
//! The window is measured from the moment refunds open rather than from the
//! deadline, so it can never close before it opens.
//! [`EscrowContract::refund_window_closes_at`] and
//! [`EscrowContract::is_refundable`] expose the rule so clients need not
//! recompute it off-chain.
//!
//! ## Reclaim rules
//!
//! The reclaim boundary is computed in exactly one place — the internal
//! `grace_end` helper, exposed to clients as
//! [`EscrowContract::refund_opens_at`] — i.e. `deadline.saturating_add(grace_period)`.
//! Every entrypoint that settles an escrow reads it from there instead of
//! re-deriving `deadline + grace_period` inline. Because the helper saturates,
//! creation rejects a `grace_period` that would push the boundary past the
//! largest representable instant with [`Error::InvalidInput`]; such an escrow
//! could otherwise saturate into a state whose reclaim path never opens
//! (permanent lockup).
//!
//! Every reclaim path is gated on the escrow's own parties: [`EscrowContract::refund`],
//! [`EscrowContract::refund_timelock`] and [`EscrowContract::reclaim`] are
//! sender-only (the sender is the only party whose funds are being returned),
//! while a pre-deadline [`EscrowContract::cancel`] may be triggered by either
//! the sender or the arbiter. All four — and the recipient-facing settlement
//! paths [`EscrowContract::release`] and [`EscrowContract::override_release`]
//! — move **only the un-released remainder**, pro-rated per asset as
//! `(funded_amount - released_amount) / funded_amount`. A recipient that has
//! already withdrawn part of a vested escrow keeps what it took, and a reclaim
//! can never reach into another escrow's custody.
//!
//! ## Signature-based release override
//!
//! Besides the single named `arbiter`, an escrow may name a set of
//! pre-configured ed25519 public keys (`override_signers`) and a threshold
//! (`override_threshold`). Anyone may call [`EscrowContract::override_release`]
//! with a `(nonce, signatures)` pair; the escrow releases early once enough of
//! the supplied signatures verify against the escrow's pre-configured keys.
//! This is independent of Soroban account auth — the cryptographic signatures
//! themselves are the authorization, which lets off-chain systems (or keys not
//! registered as Soroban accounts) approve a release.
//!
//! Every signature must cover a deterministic payload — the contract address,
//! the network id, the escrow id and the caller-supplied `nonce` — hashed with
//! SHA-256. The escrow tracks the last-used nonce and only accepts a strictly
//! greater one, which makes a captured signature unusable a second time
//! (replay protection).
//!
//! ## Milestone-based progressive release
//!
//! An escrow may optionally be funded via [`EscrowContract::deposit_with_milestones`]
//! with a list of basis-point-weighted milestones. Instead of a single arbiter
//! release, the arbiter approves each milestone individually via
//! [`EscrowContract::release_milestone`], disbursing funds proportionally. The
//! final milestone pays the dust-free remainder so the full amount is disbursed.
//! Plain `release` is blocked on milestone escrows to enforce phased settlement.
//!
//! ## Time-lock release schedules
//!
//! Escrows support configurable time-locks and gradual release schedules:
//! - Bullet / Cliff time-locks (`ReleaseType::Cliff`): 100% unlocked at maturity.
//! - Linear release schedules (`ReleaseType::Linear`): Continuous linear vesting
//!   from start_time to end_time with optional cliff_time.
//! - Partial and multiple gradual withdrawals by the beneficiary.
//! - Deterministic `Error::TimeLockActive` when withdrawing before maturity or cliff.

pub mod storage;

pub use storage::{
    bump_escrow, get_count, increment_count, load_escrow, store_escrow, DataKey, Escrow,
    EscrowState, ReleaseSchedule, ReleaseType,
};

use astroid_shared::constants::{
    INSTANCE_BUMP_AMOUNT, INSTANCE_LIFETIME_THRESHOLD, MAX_ESCROW_ASSETS, MAX_SIGNERS,
    PERSISTENT_BUMP_AMOUNT, PERSISTENT_LIFETIME_THRESHOLD,
};
use astroid_shared::errors::Error;
use astroid_shared::events::{self, ContractEvent};
use astroid_shared::math::{checked_add, checked_div, checked_mul, checked_sub};
use astroid_shared::types::AssetAmount;
use astroid_shared::validation::require_positive_amount;
use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, token, vec, Address, Bytes, BytesN, Env,
    String, Vec,
};

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

/// One signer's ed25519 signature over an [`EscrowContract::override_release`]
/// payload.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OverrideSignature {
    pub public_key: BytesN<32>,
    pub signature: BytesN<64>,
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

#[contract]
pub struct EscrowContract;

#[contractimpl]
impl EscrowContract {
    // --- registry-gated upgrades ---

    /// Record (or rotate) who may upgrade this contract and which registry
    /// authorizes the new code. Bootstrapped by the deployer alongside
    /// `initialize`; afterwards only the current upgrade admin may rotate it.
    pub fn set_upgrade_authority(
        env: soroban_sdk::Env,
        caller: soroban_sdk::Address,
        admin: soroban_sdk::Address,
        registry: soroban_sdk::Address,
    ) -> Result<(), astroid_shared::errors::Error> {
        astroid_interfaces::upgrade::set_authority(&env, &caller, &admin, &registry)
    }

    /// Read the recorded upgrade authority.
    pub fn get_upgrade_authority(
        env: soroban_sdk::Env,
    ) -> Result<astroid_interfaces::upgrade::UpgradeAuthority, astroid_shared::errors::Error> {
        astroid_interfaces::upgrade::get_authority(&env)
    }

    /// Replace this contract's code with `wasm_hash`.
    ///
    /// Two gates must pass: `caller` must be the recorded upgrade admin, and
    /// `wasm_hash` must be approved for [`ModuleKind::Escrow`] in the registry. Any
    /// other outcome leaves the contract running its current code.
    pub fn upgrade(
        env: soroban_sdk::Env,
        caller: soroban_sdk::Address,
        wasm_hash: soroban_sdk::BytesN<32>,
    ) -> Result<(), astroid_shared::errors::Error> {
        astroid_interfaces::upgrade::perform(
            &env,
            &caller,
            astroid_shared::types::ModuleKind::Escrow,
            wasm_hash,
        )
    }
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

    /// Create + fund an escrow in one call. `sender` locks every listed asset
    /// amount until `deadline` and names a `recipient` and an `arbiter`. The
    /// real tokens are moved into the contract's custody here — the escrow
    /// always reflects funds actually held.
    ///
    /// `release_signers`/`release_threshold` optionally configure the manual
    /// signature-override mechanism (see module docs); pass an empty
    /// `release_signers` and a `0` threshold to disable it for this escrow.
    /// `grace_period` extends the settlement window past the deadline: the
    /// arbiter may still release during the grace, but the sender may only
    /// reclaim the funds once the grace has fully elapsed without fulfillment.
    /// Either party (sender or arbiter) may cancel before the deadline.
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        env: Env,
        sender: Address,
        recipient: Address,
        arbiter: Address,
        assets: Vec<AssetAmount>,
        deadline: u64,
        grace_period: u64,
        memo: String,
        release_signers: Vec<BytesN<32>>,
        release_threshold: u32,
    ) -> Result<u64, Error> {
        Self::create_with_refund_window(
            env,
            sender,
            recipient,
            arbiter,
            assets,
            deadline,
            grace_period,
            0,
            memo,
            release_signers,
            release_threshold,
        )
    }

    /// Create + fund an escrow with a bounded refund window. Identical to
    /// [`Self::create`] except that the sender may only reclaim the funds during
    /// `[deadline + grace_period, deadline + grace_period + refund_window)`;
    /// passing `0` leaves the window open forever.
    ///
    /// Refunds do not open until the grace period has elapsed, so the window is
    /// measured from the moment they open rather than from the deadline — a
    /// window can therefore never close before it opens.
    #[allow(clippy::too_many_arguments)]
    pub fn create_with_refund_window(
        env: Env,
        sender: Address,
        recipient: Address,
        arbiter: Address,
        assets: Vec<AssetAmount>,
        deadline: u64,
        grace_period: u64,
        refund_window: u64,
        memo: String,
        release_signers: Vec<BytesN<32>>,
        release_threshold: u32,
    ) -> Result<u64, Error> {
        sender.require_auth();
        if recipient == sender {
            return Err(Error::InvalidInput);
        }
        if deadline <= env.ledger().timestamp() {
            return Err(Error::InvalidInput);
        }
        // The reclaim boundary must be a representable instant. `grace_end`
        // saturates, so a grace period that overflows it would create an escrow
        // whose reclaim path never opens — permanent lockup. Refuse it here.
        deadline
            .checked_add(grace_period)
            .ok_or(Error::InvalidInput)?;
        Self::validate_assets(&assets)?;
        Self::validate_override_config(&release_signers, release_threshold)?;

        let id = increment_count(&env)?;

        let mut funded_amount: i128 = 0;
        for a in assets.iter() {
            token::TokenClient::new(&env, &a.asset).transfer(
                &sender,
                &env.current_contract_address(),
                &a.amount,
            );
            funded_amount = checked_add(funded_amount, a.amount)?;
        }

        let escrow = Escrow {
            sender: sender.clone(),
            recipient: recipient.clone(),
            arbiter,
            assets: assets.clone(),
            state: EscrowState::Funded,
            deadline,
            grace_period,
            refund_window,
            funded_amount,
            memo,
            schedule: ReleaseSchedule::none(),
            released_amount: 0,
            override_signers: release_signers,
            override_threshold: release_threshold,
            override_nonce: 0,
        };
        store_escrow(&env, id, &escrow);

        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("funded")),
            (id, sender, recipient, assets),
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
        assets: Vec<AssetAmount>,
        unlock_time: u64,
        memo: String,
    ) -> Result<u64, Error> {
        sender.require_auth();
        if recipient == sender {
            return Err(Error::InvalidInput);
        }
        let now = env.ledger().timestamp();
        if unlock_time <= now {
            return Err(Error::InvalidInput);
        }
        Self::validate_assets(&assets)?;

        let id = increment_count(&env)?;

        let mut funded_amount: i128 = 0;
        for a in assets.iter() {
            token::TokenClient::new(&env, &a.asset).transfer(
                &sender,
                &env.current_contract_address(),
                &a.amount,
            );
            funded_amount = checked_add(funded_amount, a.amount)?;
        }

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
            assets: assets.clone(),
            state: EscrowState::Funded,
            deadline: unlock_time,
            grace_period: 0,
            refund_window: 0,
            funded_amount,
            memo,
            schedule,
            released_amount: 0,
            override_signers: Vec::new(&env),
            override_threshold: 0,
            override_nonce: 0,
        };
        store_escrow(&env, id, &escrow);

        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("funded")),
            (id, sender.clone(), recipient.clone(), assets.clone()),
        );
        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("init_tl")),
            (id, sender, recipient, assets, unlock_time),
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
        assets: Vec<AssetAmount>,
        schedule: ReleaseSchedule,
        deadline: u64,
        memo: String,
    ) -> Result<u64, Error> {
        sender.require_auth();
        if recipient == sender {
            return Err(Error::InvalidInput);
        }
        Self::validate_assets(&assets)?;
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

        let mut funded_amount: i128 = 0;
        for a in assets.iter() {
            token::TokenClient::new(&env, &a.asset).transfer(
                &sender,
                &env.current_contract_address(),
                &a.amount,
            );
            funded_amount = checked_add(funded_amount, a.amount)?;
        }

        let escrow = Escrow {
            sender: sender.clone(),
            recipient: recipient.clone(),
            arbiter,
            assets: assets.clone(),
            state: EscrowState::Funded,
            deadline: effective_deadline,
            grace_period: 0,
            refund_window: 0,
            funded_amount,
            memo,
            schedule: schedule.clone(),
            released_amount: 0,
            override_signers: Vec::new(&env),
            override_threshold: 0,
            override_nonce: 0,
        };
        store_escrow(&env, id, &escrow);

        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("funded")),
            (id, sender.clone(), recipient.clone(), assets.clone()),
        );
        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("sched")),
            (
                id,
                sender,
                recipient,
                assets,
                funded_amount,
                schedule.start_time,
                schedule.end_time,
            ),
        );
        Ok(id)
    }

    /// Initialize an escrow with time-lock (unfunded version). Manual
    /// signature override is not available on this path (empty signer set).
    /// `grace_period` extends the settlement window past `unlock_time`.
    #[allow(clippy::too_many_arguments)]
    pub fn initialize_timelock(
        env: Env,
        sender: Address,
        recipient: Address,
        arbiter: Address,
        assets: Vec<AssetAmount>,
        unlock_time: u64,
        grace_period: u64,
        memo: String,
    ) -> Result<u64, Error> {
        sender.require_auth();
        if recipient == sender {
            return Err(Error::InvalidInput);
        }
        let now = env.ledger().timestamp();
        if unlock_time <= now {
            return Err(Error::InvalidInput);
        }
        // Same representability guard as `create_with_refund_window`: a grace
        // period that saturates the reclaim boundary would leave an escrow
        // whose refund/reclaim path can never open.
        unlock_time
            .checked_add(grace_period)
            .ok_or(Error::InvalidInput)?;
        Self::validate_assets(&assets)?;

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
            assets: assets.clone(),
            state: EscrowState::Created,
            deadline: unlock_time,
            grace_period,
            refund_window: 0,
            funded_amount: 0,
            memo,
            schedule,
            released_amount: 0,
            override_signers: Vec::new(&env),
            override_threshold: 0,
            override_nonce: 0,
        };
        store_escrow(&env, id, &escrow);

        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("init_tl")),
            (id, sender, recipient, assets, unlock_time),
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

        let mut total: i128 = 0;
        for a in escrow.assets.iter() {
            token::TokenClient::new(&env, &a.asset).transfer(
                &sender,
                &env.current_contract_address(),
                &a.amount,
            );
            total = checked_add(total, a.amount)?;
        }

        escrow.funded_amount = total;
        escrow.state = EscrowState::Funded;
        store_escrow(&env, id, &escrow);

        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("funded")),
            (id, escrow.sender, escrow.recipient, escrow.assets),
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
            return Err(Error::TimeLockActive);
        }
        if amount > claimable {
            return Err(Error::InsufficientFunds);
        }

        escrow.released_amount = checked_add(escrow.released_amount, amount)?;
        if escrow.released_amount == escrow.funded_amount {
            escrow.state = EscrowState::Released;
        }
        store_escrow(&env, id, &escrow);

        for a in escrow.assets.iter() {
            let send_amount = checked_div(checked_mul(a.amount, amount)?, escrow.funded_amount)?;
            if send_amount > 0 {
                token::TokenClient::new(&env, &a.asset).transfer(
                    &env.current_contract_address(),
                    &escrow.recipient,
                    &send_amount,
                );
                events::transfer_executed(
                    &env,
                    &escrow.sender,
                    &escrow.recipient,
                    &a.asset,
                    send_amount,
                );
            }
        }
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
                if now < Self::grace_end(&escrow) {
                    return Err(Error::TimeLockActive);
                }
                checked_sub(escrow.funded_amount, escrow.released_amount)?
            };

            if claimable <= 0 {
                return Err(Error::TimeLockActive);
            }

            escrow.released_amount = checked_add(escrow.released_amount, claimable)?;
            if escrow.released_amount == escrow.funded_amount {
                escrow.state = EscrowState::Released;
            }
            store_escrow(&env, id, &escrow);

            for a in escrow.assets.iter() {
                let send_amount =
                    checked_div(checked_mul(a.amount, claimable)?, escrow.funded_amount)?;
                if send_amount > 0 {
                    token::TokenClient::new(&env, &a.asset).transfer(
                        &env.current_contract_address(),
                        &escrow.recipient,
                        &send_amount,
                    );
                    events::transfer_executed(
                        &env,
                        &escrow.sender,
                        &escrow.recipient,
                        &a.asset,
                        send_amount,
                    );
                }
            }
            env.events().publish(
                (symbol_short!("escrow"), symbol_short!("claimed")),
                (id, caller, claimable),
            );
            Ok(claimable)
        } else if matches!(escrow.state, EscrowState::Created) {
            if now < Self::grace_end(&escrow) {
                return Err(Error::TimeLockActive);
            }
            // A `Created` escrow that was never funded holds nothing: there is
            // nothing to claim, and attempting a transfer the contract cannot
            // cover would trap. Refuse cleanly instead.
            if escrow.funded_amount <= 0 {
                return Err(Error::InvalidState);
            }
            escrow.state = EscrowState::Released;
            Self::disburse_remainder(&env, &escrow, &escrow.recipient)?;
            escrow.released_amount = escrow.funded_amount;
            store_escrow(&env, id, &escrow);
            env.events().publish(
                (symbol_short!("escrow"), symbol_short!("claimed")),
                (id, caller, escrow.funded_amount),
            );
            Ok(escrow.funded_amount)
        } else {
            Err(Error::InvalidState)
        }
    }

    /// Release the escrowed assets to the recipient. Only the arbiter may call,
    /// and only until the reclaim boundary ([`Self::refund_opens_at`]) is
    /// reached — afterward the sender reclaims via `refund`.
    ///
    /// `release_amount` is an upper bound on this call: it must not exceed
    /// what the escrow still holds (`funded_amount - released_amount`), and the
    /// whole outstanding remainder is paid out — the cumulative
    /// `released_amount` is brought up to `funded_amount` and the escrow moves
    /// to `Released`. Whatever the recipient already withdrew through
    /// `withdraw`/`claim` stays with it; only the remainder leaves custody.
    pub fn release(env: Env, arbiter: Address, id: u64, release_amount: i128) -> Result<(), Error> {
        arbiter.require_auth();
        let mut escrow = load_escrow(&env, id)?;
        if escrow.arbiter != arbiter {
            return Err(Error::Unauthorized);
        }
        if !matches!(escrow.state, EscrowState::Funded) {
            return Err(Error::InvalidState);
        }
        if env.storage().persistent().has(&DataKey::Milestones(id)) {
            return Err(Error::InvalidState);
        }
        if env.ledger().timestamp() >= Self::grace_end(&escrow) {
            // Past the grace window the arbiter can no longer release. We do NOT
            // persist an `Expired` transition here: returning `Err` rolls back every
            // storage write, so the marker is set through the permissionless `expire`
            // entrypoint and the funds are reclaimed via `refund` / `reclaim`.
            return Err(Error::EscrowExpired);
        }
        let remaining = escrow
            .funded_amount
            .checked_sub(escrow.released_amount)
            .ok_or(Error::Overflow)?;
        if release_amount > remaining {
            return Err(Error::InvalidAmount);
        }

        escrow.state = EscrowState::Released;
        // Move the real tokens out of custody to the recipient — only what
        // this escrow still holds. Anything the recipient already withdrew
        // stays with it, and no other escrow's custody is touched. The
        // remainder must be computed against the *pre-release*
        // `released_amount`, so the record is updated afterwards.
        Self::disburse_remainder(&env, &escrow, &escrow.recipient)?;
        escrow.released_amount = escrow.funded_amount;
        store_escrow(&env, id, &escrow);
        events::publish(
            &env,
            ContractEvent::EscrowReleased {
                escrow_id: id,
                recipient: escrow.recipient.clone(),
                assets: escrow.assets.clone(),
            },
        );
        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("released")),
            (id, arbiter, release_amount),
        );
        Ok(())
    }

    /// Release the escrowed assets to the recipient via the manual signature
    /// override instead of the named arbiter. Requires at least
    /// `override_threshold` distinct, valid ed25519 signatures from the
    /// escrow's pre-configured `override_signers`, each covering a
    /// deterministic payload built from the contract address, network id,
    /// escrow id and `nonce`. `nonce` must be strictly greater than the last
    /// nonce this escrow consumed, which makes a captured signature set
    /// unusable a second time.
    ///
    /// Permissionless by design: the cryptographic signatures are the
    /// authorization, so any relayer may submit them.
    pub fn override_release(
        env: Env,
        id: u64,
        nonce: u64,
        signatures: Vec<OverrideSignature>,
    ) -> Result<(), Error> {
        let mut escrow = load_escrow(&env, id)?;
        if escrow.override_signers.is_empty() || escrow.override_threshold == 0 {
            return Err(Error::Unauthorized);
        }
        if !matches!(escrow.state, EscrowState::Funded) {
            return Err(Error::InvalidState);
        }
        if env.ledger().timestamp() >= escrow.deadline {
            return Err(Error::EscrowExpired);
        }
        if nonce <= escrow.override_nonce {
            return Err(Error::InvalidNonce);
        }
        if signatures.len() < escrow.override_threshold {
            return Err(Error::ThresholdNotMet);
        }

        let payload = Self::override_payload(&env, id, nonce);
        let digest: Bytes = env.crypto().sha256(&payload).into();

        // Every signer must be a distinct, pre-configured key, and every
        // signature must verify against the deterministic payload. Any single
        // invalid signature (unknown key, reused key, bad signature) fails the
        // whole call — signatures are never "partially" honored.
        let mut seen: Vec<BytesN<32>> = Vec::new(&env);
        for sig in signatures.iter() {
            if !escrow.override_signers.contains(&sig.public_key) {
                return Err(Error::NotASigner);
            }
            if seen.contains(&sig.public_key) {
                return Err(Error::AlreadySigned);
            }
            // Panics (aborting the whole invocation) if the signature is invalid.
            env.crypto()
                .ed25519_verify(&sig.public_key, &digest, &sig.signature);
            seen.push_back(sig.public_key.clone());
        }
        if seen.len() < escrow.override_threshold {
            return Err(Error::ThresholdNotMet);
        }

        escrow.override_nonce = nonce;
        escrow.state = EscrowState::Released;
        // Same remainder rule as `release`: pay out only what this escrow
        // still holds — computed against the pre-release `released_amount` —
        // then record it as fully released so the accounting field never goes
        // stale on a `Released` record.
        Self::disburse_remainder(&env, &escrow, &escrow.recipient)?;
        escrow.released_amount = escrow.funded_amount;
        store_escrow(&env, id, &escrow);
        events::publish(
            &env,
            ContractEvent::EscrowReleased {
                escrow_id: id,
                recipient: escrow.recipient.clone(),
                assets: escrow.assets.clone(),
            },
        );
        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("override")),
            (id, nonce),
        );
        Ok(())
    }

    /// Mark a timed-out escrow `Expired` once its deadline has passed.
    pub fn expire(env: Env, id: u64) -> Result<(), Error> {
        let mut escrow = load_escrow(&env, id)?;
        if !matches!(escrow.state, EscrowState::Funded) {
            return Err(Error::InvalidState);
        }
        if env.ledger().timestamp() < Self::grace_end(&escrow) {
            // The grace window is still open — the arbiter may still release, so the
            // escrow cannot be marked expired yet.
            return Err(Error::InvalidState);
        }
        escrow.state = EscrowState::Expired;
        store_escrow(&env, id, &escrow);
        env.events()
            .publish((symbol_short!("escrow"), symbol_short!("expired")), id);
        Ok(())
    }

    /// Refund the un-released remainder back to the sender once the reclaim
    /// boundary ([`Self::refund_opens_at`]) has been reached.
    ///
    /// Sender-only: the value returns to the escrow's depositor, so only that
    /// depositor may force the transition — a third party (recipient, arbiter
    /// or stranger) is refused with [`Error::Unauthorized`], exactly like
    /// [`Self::refund_timelock`] and [`Self::reclaim`]. Only the remainder is
    /// returned, so anything the recipient already withdrew stays with it.
    pub fn refund(env: Env, caller: Address, id: u64) -> Result<(), Error> {
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
        let now = env.ledger().timestamp();
        if now < escrow.deadline {
            // Before the fulfillment deadline the escrow is still live.
            return Err(Error::InvalidState);
        }
        if now < Self::grace_end(&escrow) {
            // During the grace window the counterparty may still fulfill, so funds
            // may not yet be reclaimed via refund. Use `reclaim` after grace expiry.
            return Err(Error::GraceActive);
        }
        Self::require_refund_window_open(&env, &escrow)?;

        escrow.state = EscrowState::Refunded;
        store_escrow(&env, id, &escrow);
        Self::disburse_remainder(&env, &escrow, &escrow.sender)?;
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
        if env.ledger().timestamp() < Self::grace_end(&escrow) {
            return Err(Error::TimeLockActive);
        }
        Self::require_refund_window_open(&env, &escrow)?;

        escrow.state = EscrowState::Refunded;
        store_escrow(&env, id, &escrow);
        Self::disburse_remainder(&env, &escrow, &escrow.sender)?;
        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("ref_tl")),
            (id, caller),
        );
        Ok(())
    }

    /// Cancel an escrow before its fulfillment `deadline` and return the
    /// un-released remainder to the sender. Either the `sender` or the
    /// `arbiter` may cancel, but only while the escrow is still
    /// `Funded`/`Created` and before the deadline has been reached — this is
    /// the pre-fulfillment dispute exit.
    ///
    /// Only the remainder moves: a recipient that already withdrew part of a
    /// vested escrow keeps it, and an unfunded `Created` escrow (nothing in
    /// custody) transitions without attempting a transfer it cannot cover.
    pub fn cancel(env: Env, caller: Address, id: u64) -> Result<(), Error> {
        caller.require_auth();
        let mut escrow = load_escrow(&env, id)?;
        if escrow.sender != caller && escrow.arbiter != caller {
            return Err(Error::Unauthorized);
        }
        if !matches!(escrow.state, EscrowState::Funded | EscrowState::Created) {
            return Err(Error::InvalidState);
        }
        // Cancellation is only permitted before the fulfillment deadline.
        if env.ledger().timestamp() >= escrow.deadline {
            return Err(Error::InvalidState);
        }

        escrow.state = EscrowState::Refunded;
        store_escrow(&env, id, &escrow);
        Self::disburse_remainder(&env, &escrow, &escrow.sender)?;
        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("cancelled")),
            (id, caller),
        );
        Ok(())
    }

    /// Reclaim the escrowed funds to the sender after the grace period has fully
    /// elapsed without counterparty fulfillment. Only the `sender` may reclaim,
    /// and only once `now >= refund_opens_at` (the shared
    /// `deadline + grace_period` boundary). This is the post-dispute
    /// safe-settlement path that guarantees funds cannot be stranded or
    /// double-spent while a dispute is unresolved: only the un-released
    /// remainder is returned, so a recipient that already withdrew part of the
    /// escrow keeps it and the contract is never asked to move more than this
    /// escrow still holds.
    pub fn reclaim(env: Env, caller: Address, id: u64) -> Result<(), Error> {
        caller.require_auth();
        let mut escrow = load_escrow(&env, id)?;
        // Only the sender may reclaim post-grace.
        if escrow.sender != caller {
            return Err(Error::Unauthorized);
        }
        if !matches!(
            escrow.state,
            EscrowState::Created | EscrowState::Funded | EscrowState::Expired
        ) {
            return Err(Error::InvalidState);
        }
        // The grace window must have fully elapsed without fulfillment.
        if env.ledger().timestamp() < Self::grace_end(&escrow) {
            return Err(Error::GraceActive);
        }
        Self::require_refund_window_open(&env, &escrow)?;

        escrow.state = EscrowState::Refunded;
        store_escrow(&env, id, &escrow);
        Self::disburse_remainder(&env, &escrow, &escrow.sender)?;
        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("reclaimed")),
            (id, caller),
        );
        Ok(())
    }

    /// Close a settled escrow (terminal). Only the three parties may do it, and
    /// only from a terminal settlement state (`Released` or `Refunded`), so an
    /// escrow is never closed while funds are still in custody.
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

    /// Fund an escrow with a milestone-based progressive release schedule.
    /// `milestones` is an ordered list of basis-point-weighted milestones whose
    /// weights must sum to exactly 10_000 (100%). The arbiter approves each
    /// milestone individually via [`EscrowContract::release_milestone`]; plain
    /// `release` is blocked on milestone escrows to enforce phased settlement.
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

        let mut total_bps: u32 = 0;
        for spec in milestones.iter() {
            total_bps = total_bps
                .checked_add(spec.release_bps)
                .ok_or(Error::Overflow)?;
        }
        if total_bps != 10_000 {
            return Err(Error::InvalidInput);
        }

        let id = increment_count(&env)?;

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
        env.storage().persistent().extend_ttl(
            &DataKey::Milestones(id),
            PERSISTENT_LIFETIME_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );

        let asset_amounts = vec![
            &env,
            AssetAmount {
                asset: asset.clone(),
                amount,
            },
        ];

        let escrow = Escrow {
            sender: sender.clone(),
            recipient: recipient.clone(),
            arbiter,
            assets: asset_amounts,
            state: EscrowState::Funded,
            deadline,
            grace_period: 0,
            refund_window: 0,
            funded_amount: amount,
            memo,
            schedule: ReleaseSchedule::none(),
            released_amount: 0,
            override_signers: Vec::new(&env),
            override_threshold: 0,
            override_nonce: 0,
        };
        store_escrow(&env, id, &escrow);

        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("milestone")),
            (id, sender, recipient, asset, amount),
        );
        Ok(id)
    }

    /// Approve and release a single milestone's proportional payout. Only the
    /// arbiter may approve; a milestone may be released at most once. The final
    /// milestone pays the dust-free remainder so the full amount is disbursed.
    pub fn release_milestone(env: Env, caller: Address, id: u64, index: u32) -> Result<(), Error> {
        caller.require_auth();
        let mut escrow = load_escrow(&env, id)?;
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

        let total_amount = Self::total_amount(&escrow.assets);
        let mut unreleased: u32 = 0;
        for m in set.milestones.iter() {
            if !m.released {
                unreleased = unreleased.saturating_add(1);
            }
        }
        let gross = checked_div(
            checked_mul(total_amount, milestone.release_bps as i128)?,
            10_000,
        )?;
        let remaining = checked_sub(total_amount, set.released_amount)?;
        let payout = if unreleased == 1 { remaining } else { gross };

        let primary_asset = &escrow.assets.get_unchecked(0).asset;
        token::TokenClient::new(&env, primary_asset).transfer(
            &env.current_contract_address(),
            &escrow.recipient,
            &payout,
        );
        events::transfer_executed(
            &env,
            &escrow.sender,
            &escrow.recipient,
            primary_asset,
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

        // Mirror the milestone bookkeeping onto the escrow record so
        // `funded_amount - released_amount` keeps meaning "what this escrow
        // still holds" for every later reclaim (`reclaim`, `refund`, `cancel`).
        // Without this a partially released milestone escrow would look
        // untouched and a reclaim could ask the contract for more than this
        // escrow still has in custody.
        escrow.released_amount = set.released_amount;
        let all_released = set.milestones.iter().all(|m| m.released);
        if all_released {
            escrow.state = EscrowState::Released;
        }
        store_escrow(&env, id, &escrow);

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

    // --- views ---

    pub fn get(env: Env, id: u64) -> Result<Escrow, Error> {
        load_escrow(&env, id)
    }

    /// Timestamp at which the sender's refund and reclaim paths open for `id`:
    /// the escrow's `deadline + grace_period`, saturating at `u64::MAX`.
    ///
    /// This is the one boundary every settlement entrypoint reads, so clients
    /// can render a countdown without recomputing the rule off-chain. For a
    /// bounded window it is always `<=` [`Self::refund_window_closes_at`]
    /// (which measures the window from here); an unbounded window reports `0`.
    pub fn refund_opens_at(env: Env, id: u64) -> Result<u64, Error> {
        Ok(Self::grace_end(&load_escrow(&env, id)?))
    }

    /// Timestamp at which the escrow's refund window closes, or `0` when the
    /// window has no upper bound. Lets clients show a countdown without
    /// recomputing the window rule off-chain.
    pub fn refund_window_closes_at(env: Env, id: u64) -> Result<u64, Error> {
        Ok(Self::closes_at(&load_escrow(&env, id)?))
    }

    /// Whether the funds may be reclaimed for `id` at the current ledger time —
    /// the escrow still holds them, the grace period has elapsed, and the refund
    /// window has not closed.
    pub fn is_refundable(env: Env, id: u64) -> Result<bool, Error> {
        let escrow = load_escrow(&env, id)?;
        if !matches!(
            escrow.state,
            EscrowState::Created | EscrowState::Funded | EscrowState::Expired
        ) {
            return Ok(false);
        }
        let now = env.ledger().timestamp();
        if now < Self::grace_end(&escrow) {
            return Ok(false);
        }
        Ok(Self::require_refund_window_open(&env, &escrow).is_ok())
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

    /// Sum the amounts across every listed asset (single-asset milestone
    /// escrows simply return that asset's amount).
    fn total_amount(assets: &Vec<AssetAmount>) -> i128 {
        let mut total: i128 = 0;
        for a in assets.iter() {
            total += a.amount;
        }
        total
    }

    /// Timestamp the refund window closes at (`0` = never). Refunds open at
    /// [`Self::grace_end`], so the window is measured from there.
    /// `saturating_add` keeps an absurd `refund_window` from wrapping around
    /// into an already-closed window.
    fn closes_at(escrow: &Escrow) -> u64 {
        if escrow.refund_window == 0 {
            return 0;
        }
        Self::grace_end(escrow).saturating_add(escrow.refund_window)
    }

    /// The single reclaim boundary: the instant at which the sender's `refund`,
    /// `refund_timelock` and `reclaim` paths open, i.e. `deadline +
    /// grace_period`.
    ///
    /// Saturating on purpose. `grace_period` is caller-supplied, so a raw `+`
    /// would panic on an overflowing sum and a truncating cast would wrap it
    /// back to a past instant (letting a reclaim fire while the arbiter could
    /// still release). Saturation pushes the boundary as late as possible, and
    /// `create_with_refund_window` / `initialize_timelock` reject such inputs
    /// up front, so no escrow can end up with a boundary that never opens.
    fn grace_end(escrow: &Escrow) -> u64 {
        escrow.deadline.saturating_add(escrow.grace_period)
    }

    /// Move this escrow's un-released remainder out of custody to `to`,
    /// pro-rating each listed asset as `amount * remaining / funded_amount`
    /// and emitting the shared `transfer`/`executed` event for every amount
    /// actually moved.
    ///
    /// Every path that empties an escrow goes through here, which is what
    /// guarantees the two invariants the reclaim paths rely on: an escrow
    /// never moves more than `funded_amount - released_amount` (so a partially
    /// released escrow can never reach into another escrow's balance), and an
    /// unfunded record (`funded_amount == 0`) moves nothing instead of
    /// dividing by zero or transferring tokens the contract does not hold.
    fn disburse_remainder(env: &Env, escrow: &Escrow, to: &Address) -> Result<(), Error> {
        let remaining = checked_sub(escrow.funded_amount, escrow.released_amount)?;
        if remaining <= 0 {
            return Ok(());
        }
        for a in escrow.assets.iter() {
            let amount = checked_div(checked_mul(a.amount, remaining)?, escrow.funded_amount)?;
            if amount > 0 {
                token::TokenClient::new(env, &a.asset).transfer(
                    &env.current_contract_address(),
                    to,
                    &amount,
                );
                events::transfer_executed(env, &escrow.sender, to, &a.asset, amount);
            }
        }
        Ok(())
    }

    /// Refuse a reclaim once a bounded refund window has elapsed, so an
    /// un-refunded, timed-out escrow can be treated as final. An unbounded
    /// window (`refund_window == 0`) never closes.
    fn require_refund_window_open(env: &Env, escrow: &Escrow) -> Result<(), Error> {
        let closes_at = Self::closes_at(escrow);
        if closes_at != 0 && env.ledger().timestamp() >= closes_at {
            return Err(Error::EscrowExpired);
        }
        Ok(())
    }

    /// Validate a multi-asset list: non-empty, within the size cap, every
    /// amount strictly positive, and no asset listed more than once.
    fn validate_assets(assets: &Vec<AssetAmount>) -> Result<(), Error> {
        if assets.is_empty() || assets.len() > MAX_ESCROW_ASSETS {
            return Err(Error::InvalidInput);
        }
        for i in 0..assets.len() {
            let a = assets.get_unchecked(i);
            require_positive_amount(a.amount)?;
            for j in (i + 1)..assets.len() {
                if assets.get_unchecked(j).asset == a.asset {
                    return Err(Error::InvalidInput);
                }
            }
        }
        Ok(())
    }

    /// Validate an override signer set + threshold: either both empty/zero
    /// (override disabled), or a non-empty, size-capped, duplicate-free signer
    /// set with a threshold in `[1, signers.len()]`.
    fn validate_override_config(signers: &Vec<BytesN<32>>, threshold: u32) -> Result<(), Error> {
        if signers.is_empty() {
            if threshold != 0 {
                return Err(Error::InvalidThreshold);
            }
            return Ok(());
        }
        if signers.len() > MAX_SIGNERS {
            return Err(Error::TooManySigners);
        }
        if threshold == 0 || threshold > signers.len() {
            return Err(Error::InvalidThreshold);
        }
        for i in 0..signers.len() {
            let s = signers.get_unchecked(i);
            for j in (i + 1)..signers.len() {
                if signers.get_unchecked(j) == s {
                    return Err(Error::InvalidInput);
                }
            }
        }
        Ok(())
    }

    /// Build the deterministic payload signed by override signers: the
    /// contract address, the network id (derived from the network
    /// passphrase), the escrow id and the nonce. Binding the contract address
    /// and network id prevents a signature from one deployment/network being
    /// replayed on another; binding the escrow id prevents cross-escrow
    /// replay; the strictly-increasing nonce prevents same-escrow replay.
    pub(crate) fn override_payload(env: &Env, id: u64, nonce: u64) -> Bytes {
        let mut payload = env.current_contract_address().to_xdr(env);
        payload.append(&Bytes::from_array(
            env,
            &env.ledger().network_id().to_array(),
        ));
        payload.append(&Bytes::from_array(env, &id.to_be_bytes()));
        payload.append(&Bytes::from_array(env, &nonce.to_be_bytes()));
        payload
    }
}

#[cfg(test)]
mod test;
