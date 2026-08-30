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
//! ## Milestone-based progressive release
//!
//! An escrow may optionally be funded via [`EscrowContract::deposit_with_milestones`]
//! with a list of basis-point-weighted milestones. Instead of a single arbiter
//! release, the arbiter approves each milestone individually via
//! [`EscrowContract::release_milestone`], disbursing funds proportionally. The
//! final milestone pays the dust-free remainder so the full amount is disbursed.
//! Plain `release` is blocked on milestone escrows to enforce phased settlement.

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
    /// The assets (and per-asset amounts) held by this escrow. Populated at
    /// creation time; `create` pulls every listed amount into custody
    /// atomically, so this always reflects funds actually held once `state`
    /// is `Funded`.
    pub assets: Vec<AssetAmount>,
    pub state: EscrowState,
    pub deadline: u64,
    pub memo: String,
    /// Pre-configured ed25519 public keys allowed to co-sign a manual release
    /// override. Empty disables the override mechanism for this escrow.
    pub override_signers: Vec<BytesN<32>>,
    /// Minimum number of distinct, valid signatures (from `override_signers`)
    /// required to release via [`EscrowContract::override_release`].
    pub override_threshold: u32,
    /// The last nonce consumed by a successful override release. A subsequent
    /// override call must supply a strictly greater nonce.
    pub override_nonce: u64,
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

        let mut count: u64 = env.storage().instance().get(&DataKey::Count).unwrap_or(0);
        count = checked_add(count as i128, 1)? as u64;
        let id = count;

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
            override_signers: release_signers,
            override_threshold: release_threshold,
            override_nonce: 0,
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

    /// Initialize an escrow with time-lock (unfunded version). Manual
    /// signature override is not available on this path (empty signer set).
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
        if unlock_time <= env.ledger().timestamp() {
            return Err(Error::InvalidInput);
        }
        Self::validate_assets(&assets)?;

        let mut count: u64 = env.storage().instance().get(&DataKey::Count).unwrap_or(0);
        count = checked_add(count as i128, 1)? as u64;
        let id = count;

        let escrow = Escrow {
            sender: sender.clone(),
            recipient: recipient.clone(),
            arbiter,
            assets: assets.clone(),
            state: EscrowState::Created,
            deadline: unlock_time,
            memo,
            override_signers: Vec::new(&env),
            override_threshold: 0,
            override_nonce: 0,
        };
        env.storage()
            .persistent()
            .set(&DataKey::Escrow(id), &escrow);
        Self::bump(&env, id);
        env.storage().instance().set(&DataKey::Count, &count);

        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("init_tl")),
            (id, sender, recipient, assets, unlock_time),
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
        Self::transfer_all(&env, &escrow, &escrow.recipient);
        for a in escrow.assets.iter() {
            events::transfer_executed(&env, &escrow.sender, &escrow.recipient, &a.asset, a.amount);
        }
        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("claimed")),
            (id, caller),
        );
        Ok(())
    }

    /// Release the escrowed assets to the recipient. Only the arbiter may call,
    /// and only before the deadline — afterward the sender reclaims via `refund`.
    /// Rejected on milestone-based escrows (use `release_milestone` instead).
    pub fn release(env: Env, arbiter: Address, id: u64) -> Result<(), Error> {
        arbiter.require_auth();
        let mut escrow = Self::load(&env, id)?;
        if escrow.arbiter != arbiter {
            return Err(Error::Unauthorized);
        }
        if !matches!(escrow.state, EscrowState::Funded) {
            return Err(Error::InvalidState);
        }
        if env.storage().persistent().has(&DataKey::Milestones(id)) {
            return Err(Error::InvalidState);
        }
        if env.ledger().timestamp() >= escrow.deadline {
            return Err(Error::EscrowExpired);
        }

        escrow.state = EscrowState::Released;
        Self::store(&env, id, &escrow);
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
    /// override instead of the named arbiter.
    pub fn override_release(
        env: Env,
        id: u64,
        nonce: u64,
        signatures: Vec<OverrideSignature>,
    ) -> Result<(), Error> {
        let mut escrow = Self::load(&env, id)?;
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

        let mut seen: Vec<BytesN<32>> = Vec::new(&env);
        for sig in signatures.iter() {
            if !escrow.override_signers.contains(&sig.public_key) {
                return Err(Error::NotASigner);
            }
            if seen.contains(&sig.public_key) {
                return Err(Error::AlreadySigned);
            }
            env.crypto()
                .ed25519_verify(&sig.public_key, &digest, &sig.signature);
            seen.push_back(sig.public_key.clone());
        }
        if seen.len() < escrow.override_threshold {
            return Err(Error::ThresholdNotMet);
        }

        escrow.override_nonce = nonce;
        escrow.state = EscrowState::Released;
        Self::store(&env, id, &escrow);
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

    /// Create + fund a milestone-based escrow in one call. Unlike `create`, the
    /// locked amount is disbursed progressively as the named `arbiter` approves
    /// each milestone via `release_milestone`. `milestones` must sum to exactly
    /// 10_000 basis points (100%). Uses a single asset.
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

        let mut count: u64 = env.storage().instance().get(&DataKey::Count).unwrap_or(0);
        count = checked_add(count as i128, 1)? as u64;
        let id = count;

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
            memo,
            override_signers: Vec::new(&env),
            override_threshold: 0,
            override_nonce: 0,
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

    /// Approve and release a single milestone's proportional payout.
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

    /// Refund the escrow back to the sender after the deadline.
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
        Self::transfer_all(&env, &escrow, &escrow.sender);
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

    /// Close a settled escrow (terminal).
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

    fn transfer_all(env: &Env, escrow: &Escrow, to: &Address) {
        for a in escrow.assets.iter() {
            token::TokenClient::new(env, &a.asset).transfer(
                &env.current_contract_address(),
                to,
                &a.amount,
            );
        }
    }

    fn total_amount(assets: &Vec<AssetAmount>) -> i128 {
        let mut total: i128 = 0;
        for a in assets.iter() {
            total += a.amount;
        }
        total
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
