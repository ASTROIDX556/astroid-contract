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
//! An escrow may hold a **list** of assets (each a distinct Stellar token
//! contract with its own amount) so a single agreement can bundle multiple
//! currencies/tokens rather than being limited to one.
//!
//! On `create` the sender's funds are pulled into the contract's own custody and
//! only leave through one of three settlement paths:
//!
//! ```text
//! Funded ──(arbiter, before deadline)──────────▶ Released ─▶ recipient ─▶ Closed
//! Funded ──(M-of-N override signatures)────────▶ Released ─▶ recipient ─▶ Closed
//! Funded ──(after deadline)────────────────────▶ Refunded ─▶ sender    ─▶ Closed
//!    └────(after deadline, marker)─────────────▶ Expired ──(refund)───▶ Refunded
//! ```
//!
//! `Expired` is a permissionless status marker (a keeper/UI may set it once the
//! deadline passes); funds stay in custody until `refund` returns them to the
//! sender, so no escrow can be `Closed` with money still locked.
//!
//! ## Manual release override
//!
//! An escrow may optionally configure a set of Ed25519 public keys and an
//! `M`-of-`N` threshold at `create` time. Holders of those keys can jointly
//! authorize `release_with_signatures` to release the escrow to the recipient
//! ahead of (or regardless of) the arbiter/deadline path — e.g. an off-chain
//! dispute-resolution quorum. Each signature is verified on-chain with
//! `env.crypto().ed25519_verify` (the host's `verify_sig_ed25519` function)
//! over a payload that binds the escrow id and a caller-chosen nonce; the
//! nonce is recorded per-escrow the moment release succeeds so the same
//! signed payload can never be replayed.

use astroid_shared::constants::{
    INSTANCE_BUMP_AMOUNT, INSTANCE_LIFETIME_THRESHOLD, MAX_ESCROW_ASSETS, MAX_RELEASE_SIGNERS,
    MIN_THRESHOLD, PERSISTENT_BUMP_AMOUNT, PERSISTENT_LIFETIME_THRESHOLD,
};
use astroid_shared::errors::Error;
use astroid_shared::events;
use astroid_shared::math::checked_add;
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

/// One Ed25519 public key's signature over the release payload for a specific
/// escrow + nonce (see [`EscrowContract::release_with_signatures`]).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseSignature {
    pub signer: BytesN<32>,
    pub signature: BytesN<64>,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Escrow {
    pub sender: Address,
    pub recipient: Address,
    pub arbiter: Address,
    pub assets: Vec<AssetAmount>,
    pub state: EscrowState,
    pub deadline: u64,
    pub memo: String,
    /// Pre-configured Ed25519 public keys eligible to co-sign a manual release
    /// override. Empty means the override path is disabled for this escrow.
    pub release_signers: Vec<BytesN<32>>,
    /// Number of distinct `release_signers` signatures required to release via
    /// `release_with_signatures`. `0` when `release_signers` is empty.
    pub release_threshold: u32,
}

/// A single milestone within a milestone-based escrow. `release_bps` is the
/// proportion of the total escrow amount (in basis points, 10_000 = 100%) that
/// is disbursed to the recipient when this milestone is approved.
#[contracttype]
#[derive(Clone)]
enum DataKey {
    Count,
    Escrow(u64),
    /// Marks a (escrow id, nonce) pair as consumed by a successful override
    /// release, so the signed payload can never authorize a second release.
    UsedNonce(u64, u64),
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

    /// Create + fund an escrow in one call. `sender` locks each `(asset, amount)`
    /// pair in `assets` until `deadline` and names a `recipient` and an
    /// `arbiter`. The real tokens are moved into the contract's custody here —
    /// the escrow always reflects funds actually held.
    ///
    /// `release_signers`/`release_threshold` configure the optional manual
    /// override path: pass an empty `release_signers` (and `0` threshold) to
    /// disable it, or a non-empty set plus an `M`-of-`N` threshold to enable
    /// `release_with_signatures`.
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
        if milestones.is_empty() {
            return Err(Error::InvalidInput);
        }

        let n_assets = assets.len();
        if n_assets == 0 || n_assets > MAX_ESCROW_ASSETS {
            return Err(Error::InvalidInput);
        }
        for a in assets.iter() {
            require_positive_amount(a.amount)?;
        }
        Self::assert_unique_assets(&assets)?;

        if release_signers.len() > MAX_RELEASE_SIGNERS {
            return Err(Error::TooManySigners);
        }
        Self::assert_unique_signers(&release_signers)?;
        Self::validate_release_threshold(release_threshold, release_signers.len())?;

        let mut count: u64 = env.storage().instance().get(&DataKey::Count).unwrap_or(0);
        count = checked_add(count as i128, 1)? as u64;
        let id = count;

        // Pull the funds into the escrow's own custody. If the sender lacks the
        // balance this panics and the whole invocation (including the id bump)
        // rolls back.
        for a in assets.iter() {
            token::TokenClient::new(&env, &a.asset).transfer(
                &sender,
                &env.current_contract_address(),
                &a.amount,
            );
        }

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
            assets: assets.clone(),
            state: EscrowState::Funded,
            deadline,
            memo,
            release_signers,
            release_threshold,
        };
        store_escrow(&env, id, &escrow);

        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("funded")),
            (id, sender, recipient, assets),
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

        let all_released = set.milestones.iter().all(|m| m.released);
        if all_released {
            escrow.state = EscrowState::Released;
            store_escrow(&env, id, &escrow);
        }

        events::escrow_milestone_release(&env, id, &caller, index, payout);
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
        Self::transfer_assets(&env, &escrow, &escrow.recipient);
        Self::emit_transfer_events(&env, &escrow);
        Self::emit_released(&env, id, &escrow, symbol_short!("arbiter"));
        Ok(())
    }

    /// Manual release override: releases the escrow to the recipient once at
    /// least `release_threshold` of the escrow's configured `release_signers`
    /// have produced a valid Ed25519 signature over the escrow id + `nonce`.
    /// Works regardless of the deadline, so a quorum can override a stalled or
    /// disputed arbiter decision. `caller` is just the transaction submitter
    /// (any account may relay the collected signatures); the signatures
    /// themselves are what authorizes the release.
    ///
    /// Each `(escrow id, nonce)` pair may only ever be consumed once — replaying
    /// a previously successful signature bundle is rejected with
    /// [`Error::AlreadySigned`].
    pub fn release_with_signatures(
        env: Env,
        caller: Address,
        id: u64,
        nonce: u64,
        signatures: Vec<ReleaseSignature>,
    ) -> Result<(), Error> {
        caller.require_auth();
        let mut escrow = Self::load(&env, id)?;
        if escrow.release_signers.is_empty() {
            // Override path not configured for this escrow.
            return Err(Error::InvalidInput);
        }

        // Checked ahead of the state guard so a replayed (id, nonce) is always
        // reported as `AlreadySigned` — the authoritative replay signal — even
        // once the escrow itself has moved past `Funded`.
        let nonce_key = DataKey::UsedNonce(id, nonce);
        if env.storage().persistent().has(&nonce_key) {
            return Err(Error::AlreadySigned);
        }
        if !matches!(escrow.state, EscrowState::Funded) {
            return Err(Error::InvalidState);
        }

        // The payload binds the escrow id and the nonce, so a signature can
        // neither be replayed against a different escrow nor reused once its
        // nonce is consumed below.
        let payload = Self::release_payload(&env, id, nonce);
        let mut counted: Vec<BytesN<32>> = Vec::new(&env);
        for entry in signatures.iter() {
            if !escrow.release_signers.contains(&entry.signer) {
                return Err(Error::NotASigner);
            }
            if counted.contains(&entry.signer) {
                return Err(Error::AlreadySigned);
            }
            // Traps (aborts the whole invocation) if the signature is invalid —
            // there is no partial-credit path for a bad signature. This calls the
            // host's `verify_sig_ed25519` function (exposed by soroban-sdk 21.x as
            // `Crypto::ed25519_verify`).
            env.crypto()
                .ed25519_verify(&entry.signer, &payload, &entry.signature);
            counted.push_back(entry.signer.clone());
        }
        if counted.len() < escrow.release_threshold {
            return Err(Error::ThresholdNotMet);
        }

        env.storage().persistent().set(&nonce_key, &true);
        env.storage().persistent().extend_ttl(
            &nonce_key,
            PERSISTENT_LIFETIME_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );

        escrow.state = EscrowState::Released;
        Self::store(&env, id, &escrow);
        Self::transfer_assets(&env, &escrow, &escrow.recipient);
        Self::emit_transfer_events(&env, &escrow);
        Self::emit_released(&env, id, &escrow, symbol_short!("sigs"));
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
        Self::transfer_assets(&env, &escrow, &escrow.sender);
        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("refunded")),
            (id, caller, escrow.assets.clone()),
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
        load_escrow(&env, id)
    }

    /// Whether `(id, nonce)` has already been consumed by a successful
    /// `release_with_signatures` call.
    pub fn nonce_used(env: Env, id: u64, nonce: u64) -> bool {
        env.storage()
            .persistent()
            .has(&DataKey::UsedNonce(id, nonce))
    }

    // --- internals ---

    fn load(env: &Env, id: u64) -> Result<Escrow, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::Escrow(id))
            .ok_or(Error::NotFound)
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
        if now < escrow.deadline + escrow.grace_period {
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

    /// Sum the amounts across every listed asset (single-asset milestone
    /// escrows simply return that asset's amount).
    fn total_amount(assets: &Vec<AssetAmount>) -> i128 {
        let mut total: i128 = 0;
        for a in assets.iter() {
            total += a.amount;
        }
        total
    }

    /// Validate a multi-asset list: non-empty, within the size cap, every
    /// amount strictly positive, and no asset listed more than once.
    /// Timestamp the refund window closes at (`0` = never). Refunds open at
    /// `deadline + grace_period`, so the window is measured from there.
    /// `saturating_add` keeps an absurd `refund_window` from wrapping around
    /// into an already-closed window.
    fn closes_at(escrow: &Escrow) -> u64 {
        if escrow.refund_window == 0 {
            return 0;
        }
        escrow
            .deadline
            .saturating_add(escrow.grace_period)
            .saturating_add(escrow.refund_window)
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

    /// Move every configured asset out of the escrow's custody to `to`.
    fn transfer_assets(env: &Env, escrow: &Escrow, to: &Address) {
        for a in escrow.assets.iter() {
            token::TokenClient::new(env, &a.asset).transfer(
                &env.current_contract_address(),
                to,
                &a.amount,
            );
        }
    }

    fn emit_transfer_events(env: &Env, escrow: &Escrow) {
        for a in escrow.assets.iter() {
            events::transfer_executed(env, &escrow.sender, &escrow.recipient, &a.asset, a.amount);
        }
    }

    /// `EscrowReleased` — topic `("escrow", "released")`. Details every asset
    /// transferred to the recipient and which release path authorized it
    /// (`"arbiter"` or `"sigs"`).
    fn emit_released(env: &Env, id: u64, escrow: &Escrow, via: Symbol) {
        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("released")),
            (id, escrow.recipient.clone(), escrow.assets.clone(), via),
        );
    }

    /// The payload signed by each override-release key: the escrow id followed
    /// by the nonce, both as big-endian bytes. Binding the id prevents a
    /// signature from one escrow authorizing release of another; binding the
    /// nonce (tracked per-escrow in [`DataKey::UsedNonce`]) prevents the same
    /// signature bundle from ever being replayed once it succeeds.
    fn release_payload(env: &Env, id: u64, nonce: u64) -> Bytes {
        let mut payload = Bytes::new(env);
        payload.extend_from_array(&id.to_be_bytes());
        payload.extend_from_array(&nonce.to_be_bytes());
        payload
    }

    fn assert_unique_assets(assets: &Vec<AssetAmount>) -> Result<(), Error> {
        let len = assets.len();
        let mut i = 0;
        while i < len {
            let a = assets.get(i).unwrap();
            let mut j = i + 1;
            while j < len {
                if a.asset == assets.get(j).unwrap().asset {
                    return Err(Error::InvalidInput);
                }
                j += 1;
            }
            i += 1;
        }
        Ok(())
    }

    fn assert_unique_signers(signers: &Vec<BytesN<32>>) -> Result<(), Error> {
        let len = signers.len();
        let mut i = 0;
        while i < len {
            let a = signers.get(i).unwrap();
            let mut j = i + 1;
            while j < len {
                if a == signers.get(j).unwrap() {
                    return Err(Error::InvalidInput);
                }
                j += 1;
            }
            i += 1;
        }
        Ok(())
    }

    /// `release_signers.len() == 0` requires `threshold == 0` (override
    /// disabled); otherwise the threshold must be within `[MIN_THRESHOLD, n]`.
    fn validate_release_threshold(threshold: u32, n: u32) -> Result<(), Error> {
        if n == 0 {
            if threshold != 0 {
                return Err(Error::InvalidThreshold);
            }
            return Ok(());
        }
        if threshold < MIN_THRESHOLD || threshold > n {
            return Err(Error::InvalidThreshold);
        }
        Ok(())
    }
}

#[cfg(test)]
mod test;
