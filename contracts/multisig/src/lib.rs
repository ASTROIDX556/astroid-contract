#![no_std]
#![allow(clippy::too_many_arguments)]
//! # Astroid MultiSig Contract
//!
//! Prevents unilateral spending by requiring an approval **weight** threshold
//! before an action executes (PRD Doc 7 §MultiSig). Each signer is assigned a
//! positive voting weight and the contract tracks the accumulated weight of
//! approvals against a configurable `threshold` (expressed in weight units,
//! not raw signer count). This lets organizations give different administrative
//! keys or partner entities proportionally larger influence.
//!
//! The contract owns a dynamic weighted signer set and a threshold, and manages
//! internal proposals through an approve → execute flow with an optional
//! per-proposal time lock and a global emergency lock.
//!
//! [`MultiSigContract::execute_batch`] additionally supports bundling multiple
//! discrete contract calls into one transaction: each contributing signer's
//! signature is verified (by the Soroban host) over the exact batch payload
//! `(nonce, calls)`, the aggregate signature weight must meet the threshold, and
//! the nonce makes batches replay-proof. Execution is atomic — if any sub-call
//! fails the whole batch reverts with [`Error::BatchCallFailed`] or the callee's
//! error.
//!
//! ## Weighted threshold verification
//!
//! Authorization is measured in **signature weight**, not signer count. Every
//! signer carries [`DEFAULT_SIGNER_WEIGHT`] until an explicit weight is recorded
//! for it, so an unweighted multisig behaves exactly like a plain N-of-M one,
//! and an organization can give a treasurer or a recovery key more say without
//! adding signers. A transaction executes only when the accumulated weight of
//! the verified signatures reaches the threshold; short of it, every path fails
//! with [`Error::ThresholdNotMet`] and emits a `ThresholdNotMet` event.
//!
//! [`MultiSigContract::verify_threshold`] exposes that check on its own: it
//! verifies a collection of signatures over an exact payload (the Soroban host
//! performs the cryptographic verification through
//! [`Address::require_auth_for_args`]), accumulates the weight of the distinct,
//! registered signers behind them, and returns the total or
//! [`Error::ThresholdNotMet`]. Duplicated signatories count once, so a single
//! key can never reach the threshold on its own.
//!
//! Events: `SignerAdded`, `SignerRemoved`, `SignerWeightChanged`,
//! `ThresholdChanged`, `ThresholdNotMet`, `ProposalApproved`,
//! `ProposalExecuted`, `BatchExecuted`, `EmergencyLock`.
//!
//! Events: `SignerAdded`, `SignerRemoved`, `SignerWeightUpdated`,
//! `ThresholdChanged`, `ProposalApproved`, `ProposalExecuted`,
//! `EmergencyLock`.
//!
//! Execution below the weight threshold is rejected with
//! [`Error::InsufficientWeight`].

use astroid_shared::constants::{
    DEFAULT_SIGNER_WEIGHT, INSTANCE_BUMP_AMOUNT, INSTANCE_LIFETIME_THRESHOLD, MAX_BATCH_CALLS,
    MAX_SIGNERS, MAX_SIGNER_WEIGHT, MIN_THRESHOLD, PERSISTENT_BUMP_AMOUNT,
    PERSISTENT_LIFETIME_THRESHOLD,
};
use astroid_shared::errors::Error;
use astroid_shared::math::{checked_add, checked_sub};
use astroid_shared::validation::require_time_reached;
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, vec, Address, Bytes, Env, IntoVal, Map,
    Symbol, Val, Vec,
};

#[contracttype]
#[derive(Clone)]
enum DataKey {
    /// Config: current weighted signer set (instance).
    Signers,
    /// Config: current approval weight threshold (instance).
    Threshold,
    /// State: global emergency lock flag (instance).
    EmergencyLock,
    /// State: monotonic proposal id counter (instance).
    ProposalCount,
    /// State: proposal record by id (persistent).
    Proposal(u64),
    /// Relationship: whether a signer approved a proposal (persistent).
    Approval(u64, Address),
    /// State: last used batch nonce (instance); batches must use a greater one.
    LastBatchNonce,
    /// Config: explicit per-signer voting weights (instance). Signers absent
    /// from the map carry `DEFAULT_SIGNER_WEIGHT`.
    Weights,
}

/// A registered signer and its positive voting weight.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignerWeight {
    pub address: Address,
    pub weight: u32,
}

/// Internal multisig proposal. `action`/`payload` describe the intended change
/// or call; the multisig only records weighted approvals and marks it executed
/// once the accumulated weight meets the threshold. Actual value movement is
/// delegated to the calling context (e.g. the Treasury) which checks
/// `is_executed`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MsProposal {
    pub proposer: Address,
    /// A short action tag, e.g. `payment`, `config`.
    pub action: Symbol,
    /// Opaque payload (e.g. serialized transfer intent / hash).
    pub payload: Bytes,
    /// Accumulated signature weight of everyone who approved so far, compared
    /// against the threshold at execution time.
    pub approvals: u32,
    /// Accumulated approval weight (sum of approver weights).
    pub approval_weight: u32,
    pub executed: bool,
    /// Earliest timestamp at which execution is allowed (time lock; 0 = none).
    pub unlock_at: u64,
}

/// A single discrete contract call inside a batch. `args` are raw Soroban
/// values, so any contract function can be targeted.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchCall {
    /// Contract to invoke.
    pub contract: Address,
    /// Function to invoke on the target contract.
    pub func: Symbol,
    /// Arguments passed to the target function.
    pub args: Vec<Val>,
}

#[contract]
pub struct MultiSigContract;

#[contractimpl]
impl MultiSigContract {
    /// Initialize with an initial signer set and threshold. Every initial signer
    /// carries [`DEFAULT_SIGNER_WEIGHT`], so `threshold` must be within
    /// `[MIN_THRESHOLD, signers.len()]` and signers within `MAX_SIGNERS`.
    /// Weights are adjusted afterwards with
    /// [`MultiSigContract::set_signer_weight`].
    pub fn initialize(env: Env, signers: Vec<Address>, threshold: u32) -> Result<(), Error> {
    /// Initialize with an initial weighted signer set and a weight threshold.
    /// `threshold` must be within `[MIN_THRESHOLD, total_weight]` and the signer
    /// set within `MAX_SIGNERS`, with all weights positive and addresses unique.
    pub fn initialize(env: Env, signers: Vec<SignerWeight>, threshold: u32) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Threshold) {
            return Err(Error::AlreadyInitialized);
        }
        let n = signers.len();
        if n == 0 || n > MAX_SIGNERS {
            return Err(Error::InvalidInput);
        }
        for s in signers.iter() {
            if s.weight == 0 {
                return Err(Error::InvalidSignerWeight);
            }
        }
        let total = Self::total_weight(&signers)?;
        Self::validate_threshold(threshold, total)?;
        Self::assert_unique(&signers)?;

        env.storage().instance().set(&DataKey::Signers, &signers);
        env.storage()
            .instance()
            .set(&DataKey::Threshold, &threshold);
        env.storage()
            .instance()
            .set(&DataKey::EmergencyLock, &false);
        env.storage().instance().set(&DataKey::ProposalCount, &0u64);
        env.storage()
            .instance()
            .set(&DataKey::LastBatchNonce, &0u64);
        Self::bump_instance(&env);
        Ok(())
    }

    /// Add a signer carrying [`DEFAULT_SIGNER_WEIGHT`]. Signer-gated. Rejects
    /// duplicates and over-capacity sets.
    pub fn add_signer(env: Env, caller: Address, signer: Address) -> Result<(), Error> {
        Self::add_signer_with_weight(env, caller, signer, DEFAULT_SIGNER_WEIGHT)
    }

    /// Add a signer with an explicit voting weight in
    /// `[1, MAX_SIGNER_WEIGHT]`. Signer-gated.
    pub fn add_signer_with_weight(
    /// Add a signer with a positive weight. Signer-gated. Rejects duplicates and
    /// over-capacity sets, and weights below 1.
    pub fn add_signer(
        env: Env,
        caller: Address,
        signer: Address,
        weight: u32,
    ) -> Result<(), Error> {
        Self::require_signer(&env, &caller)?;
        Self::validate_weight(weight)?;
        if weight == 0 {
            return Err(Error::InvalidSignerWeight);
        }
        let mut signers = Self::signers(&env)?;
        if signers.iter().any(|s| s.address == signer) {
            return Err(Error::AlreadyExists);
        }
        if signers.len() >= MAX_SIGNERS {
            return Err(Error::TooManySigners);
        }
        signers.push_back(SignerWeight {
            address: signer.clone(),
            weight,
        });
        env.storage().instance().set(&DataKey::Signers, &signers);
        Self::store_weight(&env, &signer, weight);
        Self::bump_instance(&env);
        env.events().publish(
            (symbol_short!("signer"), symbol_short!("added")),
            (signer, weight),
        );
        Ok(())
    }

    /// Change a signer's voting weight. Signer-gated. The change is refused when
    /// it would leave the remaining aggregate weight below the threshold, so the
    /// multisig can never be weighted into a state it cannot authorize.
    pub fn set_signer_weight(
        env: Env,
        caller: Address,
        signer: Address,
        weight: u32,
    ) -> Result<(), Error> {
        Self::require_signer(&env, &caller)?;
        Self::validate_weight(weight)?;
        let signers = Self::signers(&env)?;
        if !signers.contains(&signer) {
            return Err(Error::NotASigner);
        }
        let weights = Self::weights(&env);
        let current = Self::weight_of(&weights, &signer);
        let total = Self::sum_weights(&signers, &weights)?;
        let updated = checked_add(checked_sub(total as i128, current as i128)?, weight as i128)?;
        if (updated as u32) < Self::threshold(&env)? {
            return Err(Error::InvalidThreshold);
        }
        Self::store_weight(&env, &signer, weight);
        Self::bump_instance(&env);
        env.events().publish(
            (symbol_short!("signer"), symbol_short!("weight")),
            (signer, weight),
        );
        Ok(())
    }

    /// Remove a signer. Signer-gated. Refuses to drop the remaining total weight
    /// below the threshold, so the multisig can never become unusable.
    pub fn remove_signer(env: Env, caller: Address, signer: Address) -> Result<(), Error> {
        Self::require_signer(&env, &caller)?;
        let mut signers = Self::signers(&env)?;
        let idx: u32 = signers
            .iter()
            .position(|s| s.address == signer)
            .ok_or(Error::NotASigner)? as u32;
        let removed_weight = signers.get(idx).unwrap().weight;
        let remaining = checked_add(
            Self::total_weight(&signers)? as i128 - removed_weight as i128,
            0,
        )? as u32;
        let threshold = Self::threshold(&env)?;
        let idx = signers.first_index_of(&signer).ok_or(Error::NotASigner)?;
        let mut weights = Self::weights(&env);
        // Removing a signer removes its weight too; the rest must still be able
        // to reach the threshold on their own.
        let remaining = checked_sub(
            Self::sum_weights(&signers, &weights)? as i128,
            Self::weight_of(&weights, &signer) as i128,
        )?;
        if (remaining as u32) < threshold {
        if remaining < threshold {
            return Err(Error::InvalidThreshold);
        }
        signers.remove(idx);
        env.storage().instance().set(&DataKey::Signers, &signers);
        weights.remove(signer.clone());
        env.storage().instance().set(&DataKey::Weights, &weights);
        Self::bump_instance(&env);
        env.events()
            .publish((symbol_short!("signer"), symbol_short!("removed")), signer);
        Ok(())
    }

    /// Update the approval threshold. Signer-gated. Must stay within
    /// `[MIN_THRESHOLD, aggregate signer weight]`, so a reachable threshold is
    /// an invariant of the configuration.
    pub fn set_threshold(env: Env, caller: Address, threshold: u32) -> Result<(), Error> {
        Self::require_signer(&env, &caller)?;
        let signers = Self::signers(&env)?;
        Self::validate_threshold(threshold, Self::total_weight(&env, &signers)?)?;
    /// Update the voting weight of an existing signer. Signer-gated. The new
    /// weight must keep the total at or above the configured threshold; weights
    /// of 0 are rejected.
    pub fn set_signer_weight(
        env: Env,
        caller: Address,
        signer: Address,
        weight: u32,
    ) -> Result<(), Error> {
        Self::require_signer(&env, &caller)?;
        if weight == 0 {
            return Err(Error::InvalidSignerWeight);
        }
        let mut signers = Self::signers(&env)?;
        let idx: u32 = signers
            .iter()
            .position(|s| s.address == signer)
            .ok_or(Error::NotASigner)? as u32;
        let old_weight = signers.get(idx).unwrap().weight;
        let total = Self::total_weight(&signers)?;
        let new_total = checked_add(total as i128 - old_weight as i128 + weight as i128, 0)? as u32;
        let threshold = Self::threshold(&env)?;
        if new_total < threshold {
            return Err(Error::InvalidThreshold);
        }
        let mut updated = signers.get(idx).unwrap();
        updated.weight = weight;
        signers.set(idx, updated);
        env.storage().instance().set(&DataKey::Signers, &signers);
        Self::bump_instance(&env);
        env.events().publish(
            (symbol_short!("signer"), symbol_short!("weight")),
            (signer, weight),
        );
        Ok(())
    }

    /// Update the approval weight threshold. Signer-gated. Must stay within
    /// `[MIN_THRESHOLD, total_weight]`.
    pub fn set_threshold(env: Env, caller: Address, threshold: u32) -> Result<(), Error> {
        Self::require_signer(&env, &caller)?;
        let signers = Self::signers(&env)?;
        Self::validate_threshold(threshold, Self::total_weight(&signers)?)?;
        env.storage()
            .instance()
            .set(&DataKey::Threshold, &threshold);
        Self::bump_instance(&env);
        env.events().publish(
            (symbol_short!("threshold"), symbol_short!("changed")),
            threshold,
        );
        Ok(())
    }

    /// Toggle the global emergency lock (signer-gated). While locked, proposals
    /// cannot be created, approved or executed.
    pub fn set_emergency_lock(env: Env, caller: Address, locked: bool) -> Result<(), Error> {
        Self::require_signer(&env, &caller)?;
        env.storage()
            .instance()
            .set(&DataKey::EmergencyLock, &locked);
        Self::bump_instance(&env);
        env.events()
            .publish((symbol_short!("emergency"), symbol_short!("lock")), locked);
        Ok(())
    }

    /// Create a proposal. Only a signer may propose. `unlock_at` sets an optional
    /// time lock (0 = immediately executable once threshold met). The proposer's
    /// weight is counted automatically.
    pub fn propose(
        env: Env,
        proposer: Address,
        action: Symbol,
        payload: Bytes,
        unlock_at: u64,
    ) -> Result<u64, Error> {
        Self::require_not_locked(&env)?;
        Self::require_signer(&env, &proposer)?;

        let mut count: u64 = env
            .storage()
            .instance()
            .get(&DataKey::ProposalCount)
            .ok_or(Error::NotInitialized)?;
        count = checked_add(count as i128, 1)? as u64;
        let id = count;

        let proposer_weight = Self::weight_of(&env, &proposer)?;
        let proposal = MsProposal {
            proposer: proposer.clone(),
            action,
            payload,
            // The proposer's approval is counted at its own weight.
            approvals: Self::weight_of(&Self::weights(&env), &proposer),
            approval_weight: proposer_weight,
            executed: false,
            unlock_at,
        };
        env.storage()
            .persistent()
            .set(&DataKey::Proposal(id), &proposal);
        env.storage()
            .persistent()
            .set(&DataKey::Approval(id, proposer.clone()), &true);
        Self::bump_proposal(&env, id);
        env.storage()
            .instance()
            .set(&DataKey::ProposalCount, &count);
        Self::bump_instance(&env);

        env.events().publish(
            (symbol_short!("proposal"), symbol_short!("created")),
            (id, proposer),
        );
        Ok(id)
    }

    /// Approve a proposal. Only signers may approve, once each. The caller's
    /// voting weight is added to the proposal's accumulated weight. Emits
    /// `ProposalApproved` with the running total.
    /// Approve a proposal. Only signers may approve, once each. Their weight is
    /// added to the accumulated total. Emits `ProposalApproved` with the running
    /// weight.
    pub fn approve(env: Env, caller: Address, proposal_id: u64) -> Result<u32, Error> {
        Self::require_not_locked(&env)?;
        Self::require_signer(&env, &caller)?;
        let mut proposal = Self::load_proposal(&env, proposal_id)?;
        if proposal.executed {
            return Err(Error::InvalidProposalState);
        }
        let akey = DataKey::Approval(proposal_id, caller.clone());
        if env.storage().persistent().get(&akey).unwrap_or(false) {
            return Err(Error::AlreadySigned);
        }
        let weight = Self::weight_of(&env, &caller)?;
        env.storage().persistent().set(&akey, &true);
        let weight = Self::weight_of(&Self::weights(&env), &caller);
        proposal.approvals = checked_add(proposal.approvals as i128, weight as i128)? as u32;
        proposal.approval_weight =
            checked_add(proposal.approval_weight as i128, weight as i128)? as u32;
        env.storage()
            .persistent()
            .set(&DataKey::Proposal(proposal_id), &proposal);
        Self::bump_proposal(&env, proposal_id);
        env.events().publish(
            (symbol_short!("proposal"), symbol_short!("approved")),
            (proposal_id, caller, proposal.approval_weight),
        );
        Ok(proposal.approval_weight)
    }

    /// Execute a proposal once the accumulated approval weight meets the
    /// threshold and any time lock has elapsed. Marks it executed and emits
    /// `ProposalExecuted`. Rejects with [`Error::InsufficientWeight`] when the
    /// accumulated weight is below the threshold.
    pub fn execute(env: Env, caller: Address, proposal_id: u64) -> Result<(), Error> {
        Self::require_not_locked(&env)?;
        Self::require_signer(&env, &caller)?;
        let mut proposal = Self::load_proposal(&env, proposal_id)?;
        if proposal.executed {
            return Err(Error::InvalidProposalState);
        }
        let threshold = Self::threshold(&env)?;
        if proposal.approvals < threshold {
            Self::emit_threshold_not_met(&env, proposal.approvals, threshold);
            return Err(Error::ThresholdNotMet);
        if proposal.approval_weight < threshold {
            return Err(Error::InsufficientWeight);
        }
        if proposal.unlock_at != 0 {
            require_time_reached(&env, proposal.unlock_at)?;
        }
        proposal.executed = true;
        env.storage()
            .persistent()
            .set(&DataKey::Proposal(proposal_id), &proposal);
        Self::bump_proposal(&env, proposal_id);
        env.events().publish(
            (symbol_short!("proposal"), symbol_short!("executed")),
            proposal_id,
        );
        Ok(())
    }

    /// Execute a batch of discrete contract calls under a single threshold
    /// verification. Bundling several calls into one transaction reduces fees
    /// and makes multi-step administrative operations atomic.
    ///
    /// - `caller` must be a current signer. Its signature is verified against
    ///   the batch payload itself and counts toward the threshold (mirroring
    ///   how a proposer auto-approves in the proposal flow), so every
    ///   contributing signer signs the exact same payload.
    /// - `nonce` must be strictly greater than the last used batch nonce, which
    ///   makes batches replay-proof; the nonce is part of the signed payload.
    /// - `calls` must be non-empty and within [`MAX_BATCH_CALLS`].
    /// - `approvers` lists any additional signers backing the batch. Every
    ///   listed approver must be a current signer and must authorize the exact
    ///   payload `(nonce, calls)`; the host cryptographically verifies each
    ///   signature and enforces replay prevention via
    ///   [`Address::require_auth_for_args`]. Duplicate entries (including the
    ///   caller) only count once. Each signer carries weight 1, so the number
    ///   of distinct signers — caller plus approvers — must meet the threshold.
    ///
    /// Execution is atomic: each call runs inside a Soroban error-handling
    /// boundary ([`Env::try_invoke_contract`]); if any sub-call fails the whole
    /// batch reverts (including the nonce), so no partial state is committed.
    /// A failing sub-call surfaces its own contract error when known, otherwise
    /// [`Error::BatchCallFailed`].
    pub fn execute_batch(
        env: Env,
        caller: Address,
        nonce: u64,
        calls: Vec<BatchCall>,
        approvers: Vec<Address>,
    ) -> Result<(), Error> {
        Self::require_not_locked(&env)?;
        let signers = Self::signers(&env)?;
        let threshold = Self::threshold(&env)?;
        if !signers.iter().any(|s| s.address == caller) {
            return Err(Error::NotASigner);
        }

        if calls.is_empty() || calls.len() > MAX_BATCH_CALLS {
            return Err(Error::InvalidInput);
        }
        // A list longer than the maximum signer set can only hold duplicates or
        // non-signers; reject it up front (gas safety).
        if approvers.len() > MAX_SIGNERS {
            return Err(Error::InvalidInput);
        }

        // Replay protection: batch nonces must be strictly increasing.
        let last_nonce: u64 = env
            .storage()
            .instance()
            .get(&DataKey::LastBatchNonce)
            .unwrap_or(0);
        if nonce <= last_nonce {
            return Err(Error::InvalidNonce);
        }

        // Aggregate signature verification over the entire batch payload: the
        // caller plus every distinct approver must be a signer and must have
        // authorized `(nonce, calls)`. Each contributes its own voting weight.
        let payload = Self::batch_payload(&env, nonce, &calls);
        let mut signatories = vec![&env, caller.clone()];
        for approver in approvers.iter() {
            signatories.push_back(approver);
            if !signers.iter().any(|s| s.address == approver) {
                return Err(Error::NotASigner);
            }
            if seen.contains(&approver) {
                continue;
            }
            seen.push_back(approver.clone());
            approver.require_auth_for_args(payload.clone());
            weight = checked_add(weight as i128, 1)? as u32;
        }
        let weight = Self::accumulate_weight(&env, &signers, &signatories, &payload)?;
        if weight < threshold {
            Self::emit_threshold_not_met(&env, weight, threshold);
            return Err(Error::ThresholdNotMet);
        }

        env.storage()
            .instance()
            .set(&DataKey::LastBatchNonce, &nonce);

        // Execute every call atomically; any failure reverts the whole batch.
        for call in calls.iter() {
            Self::execute_call(&env, &call)?;
        }

        Self::bump_instance(&env);
        env.events().publish(
            (symbol_short!("batch"), symbol_short!("executed")),
            (nonce, caller, calls.len()),
        );
        Ok(())
    }

    /// Verify that a collection of signatures over `payload` carries at least
    /// the configured threshold of voting weight.
    ///
    /// Every entry in `signatories` must be a registered signer and must have
    /// authorized this exact call - the Soroban host performs the cryptographic
    /// signature verification via [`Address::require_auth_for_args`], and
    /// binding the check to `payload` means a signature collected for one
    /// operation can never be replayed against another. Repeated signatories
    /// count once, so a single key cannot stack its own weight.
    ///
    /// Returns the accumulated weight on success, [`Error::NotASigner`] when an
    /// unregistered address is presented, and [`Error::ThresholdNotMet`] (plus a
    /// `ThresholdNotMet` event) when the verified weight falls short.
    pub fn verify_threshold(
        env: Env,
        signatories: Vec<Address>,
        payload: Bytes,
    ) -> Result<u32, Error> {
        Self::require_not_locked(&env)?;
        if signatories.is_empty() || signatories.len() > MAX_SIGNERS {
            return Err(Error::InvalidInput);
        }
        let signers = Self::signers(&env)?;
        let threshold = Self::threshold(&env)?;
        let args = vec![&env, payload.to_val()];
        let weight = Self::accumulate_weight(&env, &signers, &signatories, &args)?;
        if weight < threshold {
            Self::emit_threshold_not_met(&env, weight, threshold);
            return Err(Error::ThresholdNotMet);
        }
        Ok(weight)
    }

    // --- views ---

    /// Voting weight of `who` (0 when it is not a signer).
    pub fn get_signer_weight(env: Env, who: Address) -> u32 {
        match Self::signers(&env) {
            Ok(signers) if signers.contains(&who) => Self::weight_of(&Self::weights(&env), &who),
            _ => 0,
        }
    }

    /// Aggregate voting weight of the whole signer set.
    pub fn get_total_weight(env: Env) -> Result<u32, Error> {
        let signers = Self::signers(&env)?;
        Self::total_weight(&env, &signers)
    }

    pub fn get_proposal(env: Env, proposal_id: u64) -> Result<MsProposal, Error> {
        Self::load_proposal(&env, proposal_id)
    }

    /// Last used batch nonce. The next `execute_batch` call must pass a strictly
    /// greater nonce.
    pub fn get_last_batch_nonce(env: Env) -> u64 {
        env.storage()
            .instance()
            .get(&DataKey::LastBatchNonce)
            .unwrap_or(0)
    }

    pub fn get_signers(env: Env) -> Vec<SignerWeight> {
        Self::signers(&env).unwrap_or_else(|_| Vec::new(&env))
    }

    pub fn get_threshold(env: Env) -> Result<u32, Error> {
        Self::threshold(&env)
    }

    pub fn is_signer(env: Env, who: Address) -> bool {
        Self::signers(&env)
            .map(|s| s.iter().any(|sw| sw.address == who))
            .unwrap_or(false)
    }

    pub fn is_locked(env: Env) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::EmergencyLock)
            .unwrap_or(false)
    }

    // --- internal helpers ---

    fn signers(env: &Env) -> Result<Vec<SignerWeight>, Error> {
        env.storage()
            .instance()
            .get(&DataKey::Signers)
            .ok_or(Error::NotInitialized)
    }

    fn total_weight(signers: &Vec<SignerWeight>) -> Result<u32, Error> {
        let mut total: i128 = 0;
        let len = signers.len();
        let mut i = 0;
        while i < len {
            let w = signers.get(i).unwrap().weight;
            total = checked_add(total, w as i128)?;
            i += 1;
        }
        Ok(total as u32)
    }

    fn weight_of(env: &Env, who: &Address) -> Result<u32, Error> {
        let signers = Self::signers(env)?;
        signers
            .iter()
            .find(|s| &s.address == who)
            .map(|s| s.weight)
            .ok_or(Error::NotASigner)
    }

    fn threshold(env: &Env) -> Result<u32, Error> {
        env.storage()
            .instance()
            .get(&DataKey::Threshold)
            .ok_or(Error::NotInitialized)
    }

    fn load_proposal(env: &Env, id: u64) -> Result<MsProposal, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::Proposal(id))
            .ok_or(Error::NotFound)
    }

    fn require_signer(env: &Env, caller: &Address) -> Result<(), Error> {
        caller.require_auth();
        let signers = Self::signers(env)?;
        if !signers.iter().any(|s| &s.address == caller) {
            return Err(Error::NotASigner);
        }
        Ok(())
    }

    fn require_not_locked(env: &Env) -> Result<(), Error> {
        let locked: bool = env
            .storage()
            .instance()
            .get(&DataKey::EmergencyLock)
            .unwrap_or(false);
        if locked {
            return Err(Error::EmergencyLock);
        }
        Ok(())
    }

    /// Build the deterministic payload `(nonce, calls)` that every approver's
    /// signature must cover, so a signature can never be replayed against a
    /// different batch or a reused nonce.
    fn batch_payload(env: &Env, nonce: u64, calls: &Vec<BatchCall>) -> Vec<Val> {
        let nonce_val: Val = nonce.into_val(env);
        let calls_val: Val = calls.to_val();
        vec![env, nonce_val, calls_val]
    }

    /// Invoke a single batch call inside a Soroban error-handling boundary so a
    /// failure can be caught and the whole batch reverted atomically instead of
    /// aborting with an opaque trap. Returns the callee's own contract error
    /// when it is one of ours, otherwise [`Error::BatchCallFailed`].
    fn execute_call(env: &Env, call: &BatchCall) -> Result<(), Error> {
        match env.try_invoke_contract::<Val, Error>(&call.contract, &call.func, call.args.clone()) {
            Ok(Ok(_)) => Ok(()),
            // A raw `Val` always decodes, so this arm is unreachable in
            // practice; kept for exhaustiveness.
            Ok(Err(_)) => Err(Error::BatchCallFailed),
            // The callee exited with a contract error — surface it precisely.
            Err(Ok(e)) => Err(e),
            // System-level failure (panic / abort / unknown error code).
            Err(Err(_)) => Err(Error::BatchCallFailed),
        }
    }

    fn validate_threshold(threshold: u32, total_weight: u32) -> Result<(), Error> {
        if threshold < MIN_THRESHOLD || threshold > total_weight {
            return Err(Error::InvalidThreshold);
        }
        Ok(())
    }

    fn validate_weight(weight: u32) -> Result<(), Error> {
        if !(DEFAULT_SIGNER_WEIGHT..=MAX_SIGNER_WEIGHT).contains(&weight) {
            return Err(Error::InvalidSignerWeight);
        }
        Ok(())
    }

    /// Explicit weight overrides. Signers absent from the map carry
    /// [`DEFAULT_SIGNER_WEIGHT`], so an unweighted multisig stores nothing.
    fn weights(env: &Env) -> Map<Address, u32> {
        env.storage()
            .instance()
            .get(&DataKey::Weights)
            .unwrap_or_else(|| Map::new(env))
    }

    fn weight_of(weights: &Map<Address, u32>, who: &Address) -> u32 {
        weights.get(who.clone()).unwrap_or(DEFAULT_SIGNER_WEIGHT)
    }

    /// Record `weight` for `signer`, dropping the entry when it is the default
    /// so the stored map only ever holds real overrides.
    fn store_weight(env: &Env, signer: &Address, weight: u32) {
        let mut weights = Self::weights(env);
        if weight == DEFAULT_SIGNER_WEIGHT {
            weights.remove(signer.clone());
        } else {
            weights.set(signer.clone(), weight);
        }
        env.storage().instance().set(&DataKey::Weights, &weights);
    }

    fn total_weight(env: &Env, signers: &Vec<Address>) -> Result<u32, Error> {
        Self::sum_weights(signers, &Self::weights(env))
    }

    /// Sum the weights of `signers` against an already-loaded override map, so
    /// callers that need several weight reads pay for one storage read.
    fn sum_weights(signers: &Vec<Address>, weights: &Map<Address, u32>) -> Result<u32, Error> {
        let mut total: i128 = 0;
        for signer in signers.iter() {
            total = checked_add(total, Self::weight_of(weights, &signer) as i128)?;
        }
        Ok(total as u32)
    }

    /// Verify each distinct signatory's signature over `args` and accumulate the
    /// voting weight behind them. Every signatory must be a registered signer;
    /// repeated entries are verified once and counted once, so no key can stack
    /// its own weight. The host performs the cryptographic verification.
    fn accumulate_weight(
        env: &Env,
        signers: &Vec<Address>,
        signatories: &Vec<Address>,
        args: &Vec<Val>,
    ) -> Result<u32, Error> {
        let weights = Self::weights(env);
        let mut seen: Vec<Address> = Vec::new(env);
        let mut total: i128 = 0;
        for who in signatories.iter() {
            if !signers.contains(&who) {
                return Err(Error::NotASigner);
            }
            if seen.contains(&who) {
                continue;
            }
            seen.push_back(who.clone());
            who.require_auth_for_args(args.clone());
            total = checked_add(total, Self::weight_of(&weights, &who) as i128)?;
        }
        Ok(total as u32)
    }

    /// Announce a failed threshold check so off-chain monitors can alert on
    /// under-authorized attempts.
    fn emit_threshold_not_met(env: &Env, weight: u32, threshold: u32) {
        env.events().publish(
            (symbol_short!("threshold"), symbol_short!("notmet")),
            (weight, threshold),
        );
    }

    fn assert_unique(signers: &Vec<Address>) -> Result<(), Error> {
    fn assert_unique(signers: &Vec<SignerWeight>) -> Result<(), Error> {
        let len = signers.len();
        let mut i = 0;
        while i < len {
            let a = signers.get(i).unwrap().address.clone();
            let mut j = i + 1;
            while j < len {
                if a == signers.get(j).unwrap().address {
                    return Err(Error::InvalidInput);
                }
                j += 1;
            }
            i += 1;
        }
        Ok(())
    }

    fn bump_proposal(env: &Env, id: u64) {
        env.storage().persistent().extend_ttl(
            &DataKey::Proposal(id),
            PERSISTENT_LIFETIME_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
    }

    fn bump_instance(env: &Env) {
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
    }
}

#[cfg(test)]
mod test;
