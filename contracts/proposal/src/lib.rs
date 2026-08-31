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
//! A proposal links off-chain context — `wallet`, `policy` and `org` — so the
//! backend can reconstruct why money moved. The
//! contract records an explicit approver allow-list and an approval threshold;
//! reaching the threshold moves the proposal to `Approved`. Execution is
//! additionally gated on a **cryptographically verified quorum**: [`execute`]
//! requires the approver signatures over the exact execution payload to be
//! verified by the Soroban host (via [`Address::require_auth_for_args`]) and to
//! aggregate to at least the threshold, so a proposal cannot be forged into an
//! executed state without the genuine signer set. After `Executed` it may be
//! `Closed`. An already-executed proposal can never be executed again.
//!
//! Functions: `create`, `approve`, `reject`, `cancel`, `expire`, `execute`,
//! `close`.

use astroid_shared::constants::{
    INSTANCE_BUMP_AMOUNT, INSTANCE_LIFETIME_THRESHOLD, MAX_APPROVERS, PERSISTENT_BUMP_AMOUNT,
    PERSISTENT_LIFETIME_THRESHOLD,
};
use astroid_shared::errors::Error;
use astroid_shared::math::checked_add;
use astroid_shared::types::AssetAmount;
use astroid_shared::validation::require_non_empty;
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, token::TokenClient, vec, Address, Env,
    IntoVal, String, Vec,
};

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
/// to approve; `threshold` approvals move it to `Approved`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proposal {
    pub proposer: Address,
    pub org: String,
    /// Links (opaque references owned by the backend / other contracts).
    pub wallet: String,
    pub policy: String,
    pub approvers: Vec<Address>,
    pub threshold: u32,
    pub approvals: u32,
    pub state: ProposalState,
    pub created_at: u64,
    pub deposit: Vec<AssetAmount>,
    pub expires_at: u64,
    pub grace_period: u64,
}

impl Proposal {
    pub fn is_expired(&self, env: &Env) -> bool {
        self.expires_at != 0 && env.ledger().timestamp() >= self.expires_at
    }

    pub fn is_active(&self, env: &Env) -> bool {
        !self.is_expired(env)
            && matches!(self.state, ProposalState::Pending | ProposalState::Approved)
    }

    pub fn can_execute(&self, env: &Env) -> bool {
        self.is_active(env) && self.state == ProposalState::Approved
    }
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
        approvers: Vec<Address>,
        threshold: u32,
        deposit: Vec<AssetAmount>,
        expires_at: u64,
        grace_period: u64,
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
        if let Some(dep) = deposit.first() {
            if dep.amount <= 0 {
                return Err(Error::InvalidAmount);
            }
            TokenClient::new(&env, &dep.asset).transfer(
                &proposer,
                &env.current_contract_address(),
                &dep.amount,
            );
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
            approvers,
            threshold,
            approvals: 0,
            deposit,
            state: ProposalState::Pending,
            created_at: env.ledger().timestamp(),
            expires_at,
            grace_period,
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
        if proposal.is_expired(&env) {
            return Err(Error::ProposalExpired);
        }
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
        if let Some(dep) = proposal.deposit.first() {
            TokenClient::new(&env, &dep.asset).transfer(
                &env.current_contract_address(),
                &proposal.proposer,
                &dep.amount,
            );
        }
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
        if proposal.grace_period != 0
            && env.ledger().timestamp() > proposal.created_at + proposal.grace_period
        {
            return Err(Error::CancellationWindowClosed);
        }
        proposal.state = ProposalState::Cancelled;
        if let Some(dep) = proposal.deposit.first() {
            TokenClient::new(&env, &dep.asset).transfer(
                &env.current_contract_address(),
                &proposal.proposer,
                &dep.amount,
            );
        }
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
        if !proposal.is_expired(&env) {
            return Err(Error::InvalidProposalState);
        }
        proposal.state = ProposalState::Expired;
        if let Some(dep) = proposal.deposit.first() {
            TokenClient::new(&env, &dep.asset).transfer(
                &env.current_contract_address(),
                &proposal.proposer,
                &dep.amount,
            );
        }
        Self::store(&env, id, &proposal);
        env.events()
            .publish((symbol_short!("proposal"), symbol_short!("expired")), id);
        Ok(())
    }

    /// Execute an approved proposal, gated on a **cryptographically verified
    /// quorum of approver signatures**.
    ///
    /// `caller` relays the invocation; the actual authorization is the genuine
    /// signer set, not the relayer's identity. Every address in `signers` must be
    /// a registered approver and must have authorized the exact execution payload
    /// `(proposal_id, execution_id)` — the Soroban host verifies each signature
    /// and enforces replay prevention through [`Address::require_auth_for_args`].
    /// Signatures are aggregated by distinct approver (duplicates count once);
    /// if the aggregate is below the proposal's `threshold` the execution is
    /// rejected with [`Error::QuorumNotMet`]. An unregistered signer is rejected
    /// with [`Error::InvalidSignature`].
    ///
    /// The proposal must already be in `Approved` state (on-chain approvals met
    /// the threshold). Anything else — including `Executed`/`Closed` — is
    /// rejected, which **prevents double-execution**. The emitted event carries
    /// `execution_id` so off-chain consumers can correlate each execution.
    pub fn execute(
        env: Env,
        caller: Address,
        id: u64,
        execution_id: u64,
        signers: Vec<Address>,
    ) -> Result<(), Error> {
        caller.require_auth();
        let mut proposal = Self::load(&env, id)?;
        if proposal.is_expired(&env) {
            return Err(Error::ProposalExpired);
        }
        // Double-execution guard: only `Approved` may transition to `Executed`;
        // an `Executed`/`Closed`/`Rejected`/... proposal never qualifies again.
        if proposal.state != ProposalState::Approved {
            return Err(Error::ProposalNotApproved);
        }

        // Aggregate and verify approver signatures over the exact execution
        // payload, mirroring the multisig batch-signature scheme. Each distinct
        // registered approver contributes one verified signature toward the
        // threshold; duplicates are ignored to prevent weight inflation.
        let payload = vec![&env, id.into_val(&env), execution_id.into_val(&env)];
        let mut seen = Vec::new(&env);
        let mut aggregate: u32 = 0;
        for signer in signers.iter() {
            if !proposal.approvers.contains(&signer) {
                return Err(Error::InvalidSignature);
            }
            if seen.contains(&signer) {
                continue;
            }
            seen.push_back(signer.clone());
            // Soroban host cryptographically verifies the signer's authorization
            // over the exact payload and enforces replay prevention.
            signer.require_auth_for_args(payload.clone());
            aggregate = checked_add(aggregate as i128, 1)? as u32;
        }
        if aggregate < proposal.threshold {
            return Err(Error::QuorumNotMet);
        }

        proposal.state = ProposalState::Executed;
        if let Some(dep) = proposal.deposit.first() {
            TokenClient::new(&env, &dep.asset).transfer(
                &env.current_contract_address(),
                &proposal.proposer,
                &dep.amount,
            );
        }
        Self::store(&env, id, &proposal);
        env.events().publish(
            (symbol_short!("proposal"), symbol_short!("executed")),
            (id, execution_id, caller),
        );
        Ok(())
    }

    /// Purge an expired proposal from storage to reclaim space.
    pub fn cleanup_expired(env: Env, id: u64) -> Result<(), Error> {
        let proposal = Self::load(&env, id)?;
        if proposal.expires_at == 0 || env.ledger().timestamp() < proposal.expires_at {
            return Err(Error::InvalidProposalState);
        }
        env.storage().persistent().remove(&DataKey::Proposal(id));
        env.events()
            .publish((symbol_short!("proposal"), symbol_short!("cleaned")), id);
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

    /// Require that every prerequisite proposal has executed.
    ///
    /// Dependencies are deduplicated at creation time and each entry is one
    /// storage read, so a check costs exactly as many reads as the proposal has
    /// distinct prerequisites — and short-circuits on the first unmet one. A
    /// prerequisite that has been cancelled, rejected, expired or explicitly
    /// marked `Failed` can never become executed, but it is reported the same
    /// way: the dependent proposal simply cannot run.
    fn ensure_dependencies_met(env: &Env, proposal: &Proposal) -> Result<(), Error> {
        for dep in proposal.dependencies.iter() {
            let prerequisite = Self::load(env, dep)?;
            if !prerequisite.state.has_executed() {
                return Err(Error::PrerequisiteNotMet);
            }
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
