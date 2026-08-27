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
        // `sender` commits the funds.
        sender.require_auth();
        if recipient == sender {
            return Err(Error::InvalidInput);
        }
        // A live release window is required — a past/zero deadline would make the
        // escrow un-releasable and instantly refundable.
        if deadline <= env.ledger().timestamp() {
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
        env.storage()
            .persistent()
            .set(&DataKey::Escrow(id), &escrow);
        Self::bump(&env, id);
        env.storage().instance().set(&DataKey::Count, &count);

        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("funded")),
            (id, sender, recipient, assets),
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
        Self::load(&env, id)
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
