#![no_std]
//! # Astroid Proposal Contract
//!
//! Represents an action awaiting approval and drives it through the lifecycle
//! (PRD Doc 7 §Proposal):
//!
//! ```text
//! Created ─▶ Pending ─▶ Approved ─▶ Executed
//!    │          │           │
//!    ▼          ▼           ▼
//!  Cancelled  Rejected    Closed
//!            / Expired
//! ```
//!
//! A proposal links off-chain context — `wallet`, `policy`, `org` and a `tx_ref`
//! transaction reference — so the backend can reconstruct why money moved. The
//! contract records an explicit approver allow-list and an approval threshold;
//! reaching the threshold moves the proposal to `Approved`, after which it may
//! be `Executed` (marked done) and finally `Closed`.
//!
//! Functions: `create`, `approve`, `reject`, `cancel`, `expire`, `execute`,
//! `close`.

use astroid_shared::constants::{
    INSTANCE_BUMP_AMOUNT, INSTANCE_LIFETIME_THRESHOLD, MAX_APPROVERS, PERSISTENT_BUMP_AMOUNT,
    PERSISTENT_LIFETIME_THRESHOLD,
};
use astroid_shared::errors::Error;
use astroid_shared::math::checked_add;
use astroid_shared::validation::require_non_empty;
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env, String, Vec};

/// Proposal lifecycle state.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProposalState {
    Created = 0,
    Pending = 1,
    Approved = 2,
    Executed = 3,
    Closed = 4,
    Rejected = 5,
    Cancelled = 6,
    Expired = 7,
}

/// Stored proposal record. `approvers` is the allow-list of addresses eligible
/// to approve; `threshold` approvals move it to `Approved`. Execution also
/// requires `quorum` participating approvers.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proposal {
    pub proposer: Address,
    pub org: String,
    /// Links (opaque references owned by the backend / other contracts).
    pub wallet: String,
    pub policy: String,
    pub tx_ref: String,
    pub approvers: Vec<Address>,
    pub threshold: u32,
    pub quorum: u32,
    pub approvals: u32,
    pub state: ProposalState,
    pub expires_at: u64,
}

#[contracttype]
#[derive(Clone)]
enum DataKey {
    ProposalCount,
    Proposal(u64),
    Approval(u64, Address),
}

#[contract]
pub struct ProposalContract;

#[contractimpl]
impl ProposalContract {
    /// Initialize the id counter. Idempotent-guarded.
    pub fn initialize(env: Env) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::ProposalCount) {
            return Err(Error::AlreadyInitialized);
        }
        env.storage().instance().set(&DataKey::ProposalCount, &0u64);
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
        Ok(())
    }

    /// Create a proposal in `Pending` state. `proposer` must authorize. The
    /// approver allow-list must be non-empty and `threshold` within its size.
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        env: Env,
        proposer: Address,
        org: String,
        wallet: String,
        policy: String,
        tx_ref: String,
        approvers: Vec<Address>,
        threshold: u32,
        expires_at: u64,
    ) -> Result<u64, Error> {
        Self::create_proposal(
            env,
            proposer,
            org,
            wallet,
            policy,
            tx_ref,
            approvers,
            threshold,
            threshold,
            expires_at,
        )
    }

    /// Create a proposal with separate approval and participation thresholds.
    /// Quorum is the minimum number of eligible approvers that must participate
    /// before an approved proposal can execute.
    #[allow(clippy::too_many_arguments)]
    pub fn create_with_quorum(
        env: Env,
        proposer: Address,
        org: String,
        wallet: String,
        policy: String,
        tx_ref: String,
        approvers: Vec<Address>,
        threshold: u32,
        quorum: u32,
        expires_at: u64,
    ) -> Result<u64, Error> {
        Self::create_proposal(
            env,
            proposer,
            org,
            wallet,
            policy,
            tx_ref,
            approvers,
            threshold,
            quorum,
            expires_at,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn create_proposal(
        env: Env,
        proposer: Address,
        org: String,
        wallet: String,
        policy: String,
        tx_ref: String,
        approvers: Vec<Address>,
        threshold: u32,
        quorum: u32,
        expires_at: u64,
    ) -> Result<u64, Error> {
        proposer.require_auth();
        require_non_empty(&org)?;
        let n = approvers.len();
        if n == 0 || n > MAX_APPROVERS {
            return Err(Error::InvalidInput);
        }
        if threshold == 0 || threshold > n {
            return Err(Error::InvalidThreshold);
        }
        if quorum == 0 || quorum > n {
            return Err(Error::InvalidThreshold);
        }
        if expires_at != 0 && expires_at <= env.ledger().timestamp() {
            return Err(Error::InvalidInput);
        }

        let mut count: u64 = env
            .storage()
            .instance()
            .get(&DataKey::ProposalCount)
            .ok_or(Error::NotInitialized)?;
        count = checked_add(count as i128, 1)? as u64;
        let id = count;

        let proposal = Proposal {
            proposer: proposer.clone(),
            org,
            wallet,
            policy,
            tx_ref,
            approvers,
            threshold,
            quorum,
            approvals: 0,
            state: ProposalState::Pending,
            expires_at,
        };
        env.storage()
            .persistent()
            .set(&DataKey::Proposal(id), &proposal);
        Self::bump(&env, id);
        env.storage()
            .instance()
            .set(&DataKey::ProposalCount, &count);
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);

        env.events().publish(
            (symbol_short!("proposal"), symbol_short!("created")),
            (id, proposer),
        );
        Ok(id)
    }

    /// Approve a proposal. Caller must be on the approver allow-list and may
    /// approve only once. Reaching `threshold` transitions to `Approved`.
    pub fn approve(env: Env, caller: Address, id: u64) -> Result<u32, Error> {
        caller.require_auth();
        let mut proposal = Self::load(&env, id)?;
        Self::ensure_not_expired(&env, &proposal)?;
        if proposal.state != ProposalState::Pending {
            return Err(Error::InvalidProposalState);
        }
        if !proposal.approvers.contains(&caller) {
            return Err(Error::NotAnApprover);
        }
        let akey = DataKey::Approval(id, caller.clone());
        if env.storage().persistent().get(&akey).unwrap_or(false) {
            return Err(Error::AlreadySigned);
        }
        env.storage().persistent().set(&akey, &true);
        proposal.approvals = checked_add(proposal.approvals as i128, 1)? as u32;
        if proposal.approvals >= proposal.threshold {
            proposal.state = ProposalState::Approved;
        }
        Self::store(&env, id, &proposal);
        env.events().publish(
            (symbol_short!("proposal"), symbol_short!("approved")),
            (id, caller, proposal.approvals),
        );
        Ok(proposal.approvals)
    }

    /// Reject a proposal. Any approver may reject a pending proposal, which
    /// moves it to the terminal `Rejected` state.
    pub fn reject(env: Env, caller: Address, id: u64) -> Result<(), Error> {
        caller.require_auth();
        let mut proposal = Self::load(&env, id)?;
        if proposal.state != ProposalState::Pending {
            return Err(Error::InvalidProposalState);
        }
        if !proposal.approvers.contains(&caller) {
            return Err(Error::NotAnApprover);
        }
        proposal.state = ProposalState::Rejected;
        Self::store(&env, id, &proposal);
        env.events().publish(
            (symbol_short!("proposal"), symbol_short!("rejected")),
            (id, caller),
        );
        Ok(())
    }

    /// Cancel a proposal. Only the original proposer may cancel, and only before
    /// it is executed/closed.
    pub fn cancel(env: Env, caller: Address, id: u64) -> Result<(), Error> {
        caller.require_auth();
        let mut proposal = Self::load(&env, id)?;
        if caller != proposal.proposer {
            return Err(Error::Unauthorized);
        }
        if matches!(
            proposal.state,
            ProposalState::Executed | ProposalState::Closed | ProposalState::Cancelled
        ) {
            return Err(Error::InvalidProposalState);
        }
        proposal.state = ProposalState::Cancelled;
        Self::store(&env, id, &proposal);
        env.events()
            .publish((symbol_short!("proposal"), symbol_short!("cancelled")), id);
        Ok(())
    }

    /// Mark a proposal expired if its deadline has passed. Permissionless
    /// (anyone may trigger the transition; state gate protects correctness).
    pub fn expire(env: Env, id: u64) -> Result<(), Error> {
        let mut proposal = Self::load(&env, id)?;
        if !matches!(
            proposal.state,
            ProposalState::Pending | ProposalState::Approved
        ) {
            return Err(Error::InvalidProposalState);
        }
        if proposal.expires_at == 0 || env.ledger().timestamp() < proposal.expires_at {
            return Err(Error::InvalidProposalState);
        }
        proposal.state = ProposalState::Expired;
        Self::store(&env, id, &proposal);
        env.events()
            .publish((symbol_short!("proposal"), symbol_short!("expired")), id);
        Ok(())
    }

    /// Execute an approved proposal. Only the proposer may execute (the actual
    /// value movement happens in the wallet/treasury; this records completion).
    pub fn execute(env: Env, caller: Address, id: u64) -> Result<(), Error> {
        caller.require_auth();
        let mut proposal = Self::load(&env, id)?;
        Self::ensure_not_expired(&env, &proposal)?;
        if caller != proposal.proposer {
            return Err(Error::Unauthorized);
        }
        if proposal.state != ProposalState::Approved {
            return Err(Error::ProposalNotApproved);
        }
        if proposal.approvals < proposal.quorum {
            return Err(Error::QuorumNotMet);
        }
        proposal.state = ProposalState::Executed;
        Self::store(&env, id, &proposal);
        env.events()
            .publish((symbol_short!("proposal"), symbol_short!("executed")), id);
        Ok(())
    }

    /// Close an executed proposal (terminal). Only the proposer may close.
    pub fn close(env: Env, caller: Address, id: u64) -> Result<(), Error> {
        caller.require_auth();
        let mut proposal = Self::load(&env, id)?;
        if caller != proposal.proposer {
            return Err(Error::Unauthorized);
        }
        if proposal.state != ProposalState::Executed {
            return Err(Error::InvalidProposalState);
        }
        proposal.state = ProposalState::Closed;
        Self::store(&env, id, &proposal);
        env.events()
            .publish((symbol_short!("proposal"), symbol_short!("closed")), id);
        Ok(())
    }

    // --- views ---

    pub fn get(env: Env, id: u64) -> Result<Proposal, Error> {
        Self::load(&env, id)
    }

    pub fn state(env: Env, id: u64) -> Result<ProposalState, Error> {
        Ok(Self::load(&env, id)?.state)
    }

    // --- internal helpers ---

    fn load(env: &Env, id: u64) -> Result<Proposal, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::Proposal(id))
            .ok_or(Error::NotFound)
    }

    fn store(env: &Env, id: u64, proposal: &Proposal) {
        env.storage()
            .persistent()
            .set(&DataKey::Proposal(id), proposal);
        Self::bump(env, id);
    }

    /// Surface [`Error::ProposalExpired`] when the deadline has passed so callers
    /// fail safely. This deliberately does NOT persist the `Expired` state: on the
    /// Soroban host, returning `Err` rolls back every storage write from the
    /// invocation, so the terminal transition is recorded only through the
    /// permissionless [`ProposalContract::expire`] entrypoint (which returns `Ok`).
    fn ensure_not_expired(env: &Env, proposal: &Proposal) -> Result<(), Error> {
        if proposal.expires_at != 0 && env.ledger().timestamp() >= proposal.expires_at {
            return Err(Error::ProposalExpired);
        }
        Ok(())
    }

    fn bump(env: &Env, id: u64) {
        env.storage().persistent().extend_ttl(
            &DataKey::Proposal(id),
            PERSISTENT_LIFETIME_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
    }
}

#[cfg(test)]
mod test;
