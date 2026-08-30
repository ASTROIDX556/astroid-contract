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
//! Funded ──(arbiter, before deadline)──────────▶ Released ─▶ recipient ─▶ Closed
//! Funded ──(signature override, before deadline)▶ Released ─▶ recipient ─▶ Closed
//! Funded ──(after deadline)────────────────────▶ Refunded ─▶ sender    ─▶ Closed
//!    └────(after deadline, marker)─────────────▶ Expired ──(refund)──▶ Refunded
//! ```
//!
//! `Expired` is a permissionless status marker (a keeper/UI may set it once the
//! deadline passes); funds stay in custody until `refund` returns them to the
//! sender, so no escrow can be `Closed` with money still locked.
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
};
use astroid_shared::errors::Error;
use astroid_shared::events::{self, ContractEvent};
use astroid_shared::math::{checked_add, checked_div, checked_mul, checked_sub};
use astroid_shared::types::AssetAmount;
use astroid_shared::validation::require_positive_amount;
use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, token, Address, Bytes, BytesN, Env, String,
    Vec,
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

    /// Create + fund an escrow in one call. `sender` locks every listed asset
    /// amount until `deadline` and names a `recipient` and an `arbiter`. The
    /// real tokens are moved into the contract's custody here — the escrow
    /// always reflects funds actually held.
    ///
    /// `release_signers`/`release_threshold` optionally configure the manual
    /// signature-override mechanism (see module docs); pass an empty
    /// `release_signers` and a `0` threshold to disable it for this escrow.
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        env: Env,
        sender: Address,
        recipient: Address,
        arbiter: Address,
        assets: Vec<AssetAmount>,
        deadline: u64,
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
    #[allow(clippy::too_many_arguments)]
    pub fn initialize_timelock(
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
                if now < escrow.deadline {
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
            if now < escrow.deadline {
                return Err(Error::TimeLockActive);
            }
            escrow.state = EscrowState::Released;
            store_escrow(&env, id, &escrow);
            Self::transfer_all(&env, &escrow, &escrow.recipient);
            for a in escrow.assets.iter() {
                events::transfer_executed(
                    &env,
                    &escrow.sender,
                    &escrow.recipient,
                    &a.asset,
                    a.amount,
                );
            }
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
    /// and only before the deadline — afterward the sender reclaims via `refund`.
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

        escrow.released_amount = escrow.funded_amount;
        escrow.state = EscrowState::Released;
        store_escrow(&env, id, &escrow);
        // Move the real tokens out of custody to the recipient.
        Self::transfer_all(&env, &escrow, &escrow.recipient);
        for a in escrow.assets.iter() {
            events::transfer_executed(&env, &escrow.sender, &escrow.recipient, &a.asset, a.amount);
        }
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
            (id, arbiter),
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
        store_escrow(&env, id, &escrow);
        Self::transfer_all(&env, &escrow, &escrow.recipient);
        for a in escrow.assets.iter() {
            events::transfer_executed(&env, &escrow.sender, &escrow.recipient, &a.asset, a.amount);
        }
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
            for a in escrow.assets.iter() {
                let return_amount =
                    checked_div(checked_mul(a.amount, remaining)?, escrow.funded_amount)?;
                if return_amount > 0 {
                    token::TokenClient::new(&env, &a.asset).transfer(
                        &env.current_contract_address(),
                        &escrow.sender,
                        &return_amount,
                    );
                }
            }
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
            return Err(Error::TimeLockActive);
        }

        let remaining = checked_sub(escrow.funded_amount, escrow.released_amount)?;
        escrow.state = EscrowState::Refunded;
        store_escrow(&env, id, &escrow);

        if remaining > 0 {
            for a in escrow.assets.iter() {
                let return_amount =
                    checked_div(checked_mul(a.amount, remaining)?, escrow.funded_amount)?;
                if return_amount > 0 {
                    token::TokenClient::new(&env, &a.asset).transfer(
                        &env.current_contract_address(),
                        &escrow.sender,
                        &return_amount,
                    );
                }
            }
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

    /// Move every listed asset amount out of the contract's custody to `to`.
    fn transfer_all(env: &Env, escrow: &Escrow, to: &Address) {
        for a in escrow.assets.iter() {
            token::TokenClient::new(env, &a.asset).transfer(
                &env.current_contract_address(),
                to,
                &a.amount,
            );
        }
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
