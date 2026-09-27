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
//! reaching the threshold moves the proposal to `Approved`, after which it may
//! be `Executed` (marked done) and finally `Closed`. An approved proposal whose
//! off-chain action did not go through is marked `Failed`, a terminal state.
//!
//! ## Timelock
//!
//! Executing an approved proposal immediately lets a sudden takeover spend the
//! mandate before it is even visible. The contract therefore enforces a
//! mandatory minimum delay — the configured `timelock` (seconds) stored at
//! [`ProposalContract::initialize`] — between approval and execution. The
//! approval timestamp is recorded the moment the proposal reaches `Approved`,
//! and `execute` refuses with [`Error::TimelockNotExpired`] until
//! `approved_at + timelock` has passed. The `can_execute` view evaluates that
//! same gate, so it never advertises a proposal as executable while its delay
//! is still running.
//!
//! ## Quorum and majority
//!
//! A bare approval threshold can be gamed — `threshold = 1` on a ten-person
//! allow-list would execute on a single signature — so `execute` re-validates
//! the tally against two further bars before anything fires:
//!
//! * **Quorum (participation).** At least [`PROPOSAL_QUORUM_PERCENT`]% of the
//!   approver allow-list must have voted. The requirement is computed with
//!   integer scaling only — `ceil(approvers * percent / 100)`, never
//!   floating point — and rounded *up* so a partial vote can never round the
//!   bar away.
//! * **Majority (the vote itself).** The approvals must form a *strict*
//!   majority of the allow-list: `approvals > approvers / 2`. An exact tie is
//!   not a majority.
//!
//! The proposal's own configured `threshold` is re-checked as well — behind
//! the `Approved` state gate, which already guarantees it — as defence in
//! depth against a tally that somehow slipped below the bar it declared.
//!
//! Every shortfall reports the protocol-wide [`Error::ThresholdNotMet`]: a
//! missed quorum *is* a missed threshold (the participation bar was not
//! crossed), and the shared error enum already sits at the Stellar spec's
//! 50-case cap for contract errors, so there is no room for a dedicated
//! quorum code.
//!
//! ```text
//! approvals < threshold              ──▶ ProposalNotApproved (state gate)
//! approvals < quorum(allow-list)     ──▶ Error::ThresholdNotMet
//! approvals <= allow-list / 2 (tie)  ──▶ Error::ThresholdNotMet
//! otherwise                          ──▶ timelock / dependency gates, then run
//! ```
//!
//! All three bars are re-derived from the stored record on every call rather
//! than cached, so the verdict is a pure function of on-chain state and every
//! node agrees on it. The maths lives in [`VoteBars`] — the quorum
//! calculation and majority check helpers ([`VoteBars::quorum_required`],
//! [`VoteBars::majority_required`], [`VoteBars::has_majority`]) composed by
//! [`VoteBars::for_proposal`] and applied by [`VoteBars::ensure_met`] — and
//! the very same numbers are readable on-chain through the `vote_bars` view,
//! so a client can report *which* bar a tally missed instead of only that
//! execution was refused.
//!
//! ## Dependency chaining
//!
//! A proposal may declare prerequisite proposals it depends on. `execute` then
//! refuses to run until every prerequisite has executed, which is what lets a
//! multi-step protocol upgrade or a staged asset allocation be sequenced
//! correctly: each step is its own proposal, approved on its own merits, but
//! the steps can only fire in order.
//!
//! ```text
//! #1 fund escrow ──▶ #2 migrate balances ──▶ #3 retire old module
//!                    (depends on #1)          (depends on #2)
//! ```
//!
//! The graph is acyclic by construction — see [`ProposalContract::create`] —
//! and a dependency that would close a cycle is rejected at creation time with
//! [`Error::CircularDependencyDetected`].
//!
//! ## Expiration gating
//!
//! A proposal may declare `expires_at`, a deadline after which its approval
//! window is closed. The deadline is compared against the deterministic ledger
//! clock (`env.ledger().timestamp()`), so every node evaluating the same ledger
//! agrees on whether the proposal is stale. `expires_at == 0` means the
//! proposal never expires.
//!
//! The deadline is re-evaluated against the current ledger on every call. A
//! Any invocation that encounters a stale proposal lazily records the terminal
//! `Expired` state, refunds the deposit, and emits an expiry event. The
//! permissionless [`ProposalContract::expire`] remains available to settle an
//! untouched stale proposal, and [`ProposalContract::cleanup_expired`] can
//! purge it afterwards.
//!
//! ```text
//! live (timestamp < expires_at) ──approve/execute/…──▶ normal transition
//! stale ──any interaction──────────▶ Expired (deposit refunded, event emitted)
//! Expired ──later interaction──────▶ no-op
//! Expired ──cleanup_expired()──────▶ purged
//! ```
//!
//! Functions: `create`, `approve`, `reject`, `cancel`, `expire`, `execute`,
//! `fail`, `close`, `cleanup_expired`, plus the `get`, `state`, `is_expired`,
//! `dependencies`, `dependencies_met`, `vote_bars` and `can_execute` views.
//! `initialize` also stores the mandatory per-proposal timelock.

use astroid_interfaces::{ProposalInterface, UpgradeableInterface};
// The lifecycle vocabulary lives in the interfaces crate so the multisig, the
// wallet and off-chain consumers all decode the same `u32` discriminants. The
// contract consumes the shared definition and re-exports it under its old name,
// so existing callers keep working against a single source of truth.
pub use astroid_interfaces::proposal::ProposalState;
use astroid_shared::constants::{
    INSTANCE_BUMP_AMOUNT, INSTANCE_LIFETIME_THRESHOLD, MAX_APPROVERS, MAX_DEPENDENCIES,
    PERSISTENT_BUMP_AMOUNT, PERSISTENT_LIFETIME_THRESHOLD, PROPOSAL_QUORUM_PERCENT,
};
use astroid_shared::errors::Error;
use astroid_shared::math::checked_add;
use astroid_shared::types::AssetAmount;
use astroid_shared::validation::{require_non_empty, require_time_reached};
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, token::TokenClient, Address, Env, String,
    Vec,
};

/// Stored proposal record. `approvers` is the allow-list of addresses eligible
/// to approve; `threshold` approvals move it to `Approved`. `dependencies` are
/// the ids of proposals that must have executed before this one may execute.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proposal {
    pub proposer: Address,
    pub org: String,
    /// Links (opaque references owned by the backend / other contracts).
    pub wallet: String,
    pub policy: String,
    pub approvers: Vec<Address>,
    /// Prerequisite proposal ids, deduplicated and each strictly less than this
    /// proposal's own id. Empty for a proposal with no dependencies.
    pub dependencies: Vec<u64>,
    pub threshold: u32,
    pub approvals: u32,
    pub state: ProposalState,
    pub created_at: u64,
    /// Ledger timestamp at which the proposal reached `Approved`; `0` until
    /// then. `execute` refuses to run until `approved_at + timelock` has
    /// passed, so an approved proposal cannot be executed the moment it is
    /// approved.
    pub approved_at: u64,
    pub deposit: Vec<AssetAmount>,
    pub expires_at: u64,
    pub grace_period: u64,
}

impl Proposal {
    /// Whether the proposal's deadline has been reached on the current ledger.
    ///
    /// Evaluated against `env.ledger().timestamp()` — the deterministic clock
    /// the host fixes for the whole invocation — so the answer is identical for
    /// every read of the same ledger. `expires_at == 0` encodes "no deadline"
    /// and never expires. The boundary is inclusive: `now == expires_at` is
    /// already expired.
    pub fn is_expired(&self, env: &Env) -> bool {
        self.expires_at != 0 && env.ledger().timestamp() >= self.expires_at
    }

    /// Whether the proposal may still change state: it has not gone stale and
    /// sits in one of the two live states.
    pub fn is_active(&self, env: &Env) -> bool {
        !self.is_expired(env)
            && matches!(self.state, ProposalState::Pending | ProposalState::Approved)
    }

    /// Whether `execute` would accept this proposal on the current ledger: it
    /// is live, sits in `Approved`, and the mandatory delay between approval
    /// and execution has elapsed.
    ///
    /// The last term is the same gate [`ProposalContract::execute`] applies,
    /// evaluated through [`require_timelock_elapsed`], so a client that
    /// pre-checks this view can never get an answer the entrypoint would then
    /// contradict — in particular it never reports a prematurely executable
    /// proposal while its timelock is still running. The check reads this
    /// contract's instance storage (the configured timelock), so it must be
    /// evaluated in the proposal contract's own context;
    /// [`ProposalContract::can_execute`] is the entrypoint form of the question.
    pub fn can_execute(&self, env: &Env) -> bool {
        self.is_active(env)
            && self.state == ProposalState::Approved
            && require_timelock_elapsed(env, self).is_ok()
    }
}

/// The three vote bars a tally must clear before [`ProposalContract::execute`]
/// may fire, derived from the proposal's allow-list, its configured
/// `threshold` and the protocol quorum percentage — see the module-level
/// *Quorum and majority* notes.
///
/// Every bar is recomputed from the stored record on each check rather than
/// cached, so the verdict is a pure function of on-chain state and every node
/// agrees on it. The struct is a [`contracttype`] so the same bars can be
/// read back through the [`ProposalContract::vote_bars`] view, letting a
/// client report *which* bar a tally missed instead of only that execution
/// was refused.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VoteBars {
    /// The approval threshold the proposal declared at creation.
    pub threshold: u32,
    /// Participation quorum: [`PROPOSAL_QUORUM_PERCENT`]% of the approver
    /// allow-list, rounded **up** so a partial vote can never round the bar
    /// away.
    pub quorum: u32,
    /// Strict majority: one past half of the approver allow-list. An exact
    /// tie never reaches it.
    pub majority: u32,
}

impl VoteBars {
    /// All three bars for `proposal`, re-derived from its allow-list size.
    pub fn for_proposal(proposal: &Proposal) -> Self {
        let eligible = proposal.approvers.len();
        Self {
            threshold: proposal.threshold,
            quorum: Self::quorum_required(eligible, PROPOSAL_QUORUM_PERCENT),
            majority: Self::majority_required(eligible),
        }
    }

    /// Quorum calculation helper: the number of approvals that makes a vote
    /// among `eligible` voters quorate — `percent`% of the approver
    /// allow-list, rounded **up**.
    ///
    /// Integer scaling only — `ceil(eligible * percent / 100)` computed with
    /// [`u64::div_ceil`] — never floating point, so every node derives the
    /// identical integer. `percent` is clamped to 100, so a misconfigured
    /// percentage can never demand more than the whole allow-list.
    pub fn quorum_required(eligible: u32, percent: u32) -> u32 {
        let percent = percent.min(100);
        ((eligible as u64) * (percent as u64)).div_ceil(100) as u32
    }

    /// Majority check helper: the smallest number of approvals that exceeds
    /// half the allow-list — a strict majority. An exact tie (exactly half)
    /// never reaches it.
    pub fn majority_required(eligible: u32) -> u32 {
        eligible / 2 + 1
    }

    /// Whether `approvals` forms a strict majority of the `eligible` voters.
    pub fn has_majority(approvals: u32, eligible: u32) -> bool {
        approvals >= Self::majority_required(eligible)
    }

    /// Whether a tally of `approvals` clears *every* bar — the configured
    /// threshold, the participation quorum and the strict majority.
    pub fn met_by(&self, approvals: u32) -> bool {
        approvals >= self.threshold && approvals >= self.quorum && approvals >= self.majority
    }

    /// Refuse a tally that misses any bar with the protocol-wide
    /// [`Error::ThresholdNotMet`]; a missed quorum *is* a missed threshold,
    /// and the shared error enum is at the Stellar spec's 50-case cap, so one
    /// code covers all three bars.
    pub fn ensure_met(&self, approvals: u32) -> Result<(), Error> {
        if self.met_by(approvals) {
            Ok(())
        } else {
            Err(Error::ThresholdNotMet)
        }
    }
}

#[contracttype]
#[derive(Clone)]
enum DataKey {
    ProposalCount,
    /// Mandatory minimum delay in seconds between approval and execution,
    /// applied to every proposal (configured once at [initialize]).
    Timelock,
    Proposal(u64),
    Approval(u64, Address),
}

#[contract]
pub struct ProposalContract;

#[contractimpl]
impl ProposalContract {
    /// Initialize the id counter and the mandatory per-proposal timelock.
    /// Idempotent-guarded. `timelock` is the minimum number of seconds that
    /// must pass between a proposal's approval and its execution; `0` disables
    /// the delay.
    pub fn initialize(env: Env, timelock: u64) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::ProposalCount) {
            return Err(Error::AlreadyInitialized);
        }
        env.storage().instance().set(&DataKey::ProposalCount, &0u64);
        env.storage().instance().set(&DataKey::Timelock, &timelock);
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
        Ok(())
    }

    /// Create a proposal in `Pending` state. `proposer` must authorize. The
    /// approver allow-list must be non-empty and `threshold` within its size.
    ///
    /// `dependencies` lists prerequisite proposals that must have executed
    /// before this one may execute; pass an empty vector for an independent
    /// proposal. Each entry must name an existing proposal, and duplicates are
    /// collapsed so a prerequisite is read exactly once at execution time.
    ///
    /// **Acyclicity.** Proposal ids are assigned from a monotonic counter, and a
    /// dependency must name a proposal that already exists — so every edge in
    /// the graph points from a higher id to a strictly lower one, and a cycle
    /// would require an edge pointing forward. That is exactly what the
    /// `dependency >= id` check rejects, with
    /// [`Error::CircularDependencyDetected`]. Self-reference is the degenerate
    /// case of the same check. Because every edge strictly decreases the id,
    /// no sequence of edges can return to its starting proposal, so the graph
    /// is a DAG by construction and no traversal is needed.
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        env: Env,
        proposer: Address,
        org: String,
        wallet: String,
        policy: String,
        approvers: Vec<Address>,
        dependencies: Vec<u64>,
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

        if dependencies.len() > MAX_DEPENDENCIES {
            return Err(Error::InvalidInput);
        }

        let mut count: u64 = env
            .storage()
            .instance()
            .get(&DataKey::ProposalCount)
            .ok_or(Error::NotInitialized)?;
        count = checked_add(count as i128, 1)? as u64;
        let id = count;

        // Validate the declared prerequisites and collapse duplicates, so that
        // `execute` reads each prerequisite exactly once.
        let mut deps: Vec<u64> = Vec::new(&env);
        for dep in dependencies.iter() {
            // Any edge that does not point strictly backwards would close a
            // cycle (or be a self-reference); see the acyclicity note above.
            if dep >= id {
                return Err(Error::CircularDependencyDetected);
            }
            if !env.storage().persistent().has(&DataKey::Proposal(dep)) {
                return Err(Error::NotFound);
            }
            if !deps.contains(dep) {
                deps.push_back(dep);
            }
        }

        let proposal = Proposal {
            proposer: proposer.clone(),
            org,
            wallet,
            policy,
            approvers,
            dependencies: deps,
            threshold,
            approvals: 0,
            deposit,
            state: ProposalState::Pending,
            created_at: env.ledger().timestamp(),
            approved_at: 0,
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
    ///
    /// If the deadline has passed, records `Expired`, refunds the deposit and
    /// emits the expiry event without recording this vote. The unchanged
    /// approval count is returned because returning an error would roll back
    /// the expiry transition and its event.
    pub fn approve(env: Env, caller: Address, id: u64) -> Result<u32, Error> {
        caller.require_auth();
        let mut proposal = Self::load(&env, id)?;
        if Self::expire_if_due(&env, id, &mut proposal)? {
            return Ok(proposal.approvals);
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
            // Record the moment of approval: the timelock only starts counting
            // once, when the threshold is reached, and is re-applied verbatim
            // (approval signatures cannot be retracted).
            proposal.approved_at = env.ledger().timestamp();
        }
        Self::store(&env, id, &proposal);
        env.events().publish(
            (symbol_short!("proposal"), symbol_short!("approved")),
            (id, caller, proposal.approvals),
        );
        Ok(proposal.approvals)
    }

    /// Reject a proposal. Any approver may reject a pending proposal, which
    /// moves it to the terminal `Rejected` state and refunds the deposit.
    ///
    /// A stale proposal may not be rejected — it has left the approval window,
    /// so it is settled through [`ProposalContract::expire`] instead; the
    /// deposit is returned on either path.
    pub fn reject(env: Env, caller: Address, id: u64) -> Result<(), Error> {
        caller.require_auth();
        let mut proposal = Self::load(&env, id)?;
        if Self::expire_if_due(&env, id, &mut proposal)? {
            return Ok(());
        }
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
    ///
    /// A proposal that has already gone stale is out of the cancellation
    /// window regardless of the grace period: cancelling is a live-proposal
    /// action and fails with [`Error::ProposalExpired`], leaving the deposit
    /// to be returned by [`ProposalContract::expire`].
    pub fn cancel(env: Env, caller: Address, id: u64) -> Result<(), Error> {
        caller.require_auth();
        let mut proposal = Self::load(&env, id)?;
        if Self::expire_if_due(&env, id, &mut proposal)? {
            return Ok(());
        }
        if caller != proposal.proposer {
            return Err(Error::Unauthorized);
        }
        if matches!(
            proposal.state,
            ProposalState::Executed | ProposalState::Closed | ProposalState::Cancelled
        ) {
            return Err(Error::InvalidProposalState);
        }
        if proposal.grace_period != 0 {
            // Saturating end-of-window: `created_at + grace_period` that does
            // not fit a ledger timestamp describes a window so long it never
            // closes, which must not wrap into the past (and trap) — the
            // deadline above still bounds how long it can be relied on.
            let grace_end = proposal.created_at.saturating_add(proposal.grace_period);
            if env.ledger().timestamp() > grace_end {
                return Err(Error::CancellationWindowClosed);
            }
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
    ///
    /// This is a permissionless way to settle an untouched stale proposal. The
    /// deadline is re-read from `env.ledger().timestamp()` here rather than
    /// trusted from the caller: calling it before the deadline has passed
    /// fails with [`Error::InvalidProposalState`]. Recording the transition
    /// refunds the proposer's deposit and closes the proposal permanently.
    pub fn expire(env: Env, id: u64) -> Result<(), Error> {
        let mut proposal = Self::load(&env, id)?;
        if !Self::expire_if_due(&env, id, &mut proposal)? {
            return Err(Error::InvalidProposalState);
        }
        Ok(())
    }

    /// Purge an expired proposal from storage to reclaim space.
    ///
    /// Two gates, both re-read from the ledger, and both reported as
    /// [`Error::InvalidProposalState`]: the deadline must have passed (a
    /// proposal with no deadline at all can never be purged), and the proposal
    /// must be in a state that has already settled its deposit. Purging a
    /// still-live proposal would delete the record while the contract still
    /// holds the proposer's funds, so a stale pending or approved proposal is
    /// first settled through the same expiry transition. The proposal's
    /// approval flags are purged along with it.
    pub fn cleanup_expired(env: Env, id: u64) -> Result<(), Error> {
        let mut proposal = Self::load(&env, id)?;
        Self::expire_if_due(&env, id, &mut proposal)?;
        if !proposal.is_expired(&env) {
            return Err(Error::InvalidProposalState);
        }
        if !proposal.state.deposit_settled() {
            return Err(Error::InvalidProposalState);
        }
        env.storage().persistent().remove(&DataKey::Proposal(id));
        for approver in proposal.approvers.iter() {
            env.storage()
                .persistent()
                .remove(&DataKey::Approval(id, approver));
        }
        env.events()
            .publish((symbol_short!("proposal"), symbol_short!("cleaned")), id);
        Ok(())
    }

    /// Execute an approved proposal. Only the proposer may execute (the actual
    /// value movement happens in the wallet/treasury; this records completion).
    ///
    /// Immediately after the state gate the tally itself is re-validated: the
    /// participation quorum, the configured `threshold` and a strict majority
    /// of the approver allow-list must all hold, or the call is refused with
    /// [`Error::ThresholdNotMet`] (see the module-level *Quorum and majority*
    /// notes). Reaching `Approved` once is therefore not a licence forever —
    /// an under-supported or merely-tied tally can never fire.
    ///
    /// Every declared prerequisite must have executed first, otherwise the call
    /// fails with [`Error::PrerequisiteNotMet`] and nothing changes. This is
    /// checked after the timelock so that a proposal blocked only by its chain
    /// reports the dependency rather than a less specific error.
    ///
    /// The expiry gate runs first: a proposal whose deadline passed before it
    /// was executed never fires. The call settles it instead — it records the
    /// terminal `Expired` state, refunds the deposit and emits the `expired`
    /// event — and returns `Ok(())` without executing, because returning an
    /// error would roll that settlement back. Callers tell the two outcomes
    /// apart through `state`, `is_executed` or the `expired` event; repeat
    /// calls are no-ops. Then the mandatory timelock applies — execution is refused with
    /// [`Error::TimelockNotExpired`] until `timelock` seconds have passed
    /// since approval — and only then is the dependency chain resolved. The
    /// ordering means a premature attempt is reported as a scheduling error
    /// rather than a (still accurate) dependency failure.
    pub fn execute(env: Env, caller: Address, id: u64) -> Result<(), Error> {
        caller.require_auth();
        let mut proposal = Self::load(&env, id)?;
        if Self::expire_if_due(&env, id, &mut proposal)? {
            return Ok(());
        }
        if caller != proposal.proposer {
            return Err(Error::Unauthorized);
        }
        if proposal.state != ProposalState::Approved {
            return Err(Error::ProposalNotApproved);
        }
        // Re-check the tally that earned `Approved` — quorum participation,
        // the configured threshold and a strict majority — so execution can
        // never out-run the votes that authorised it.
        Self::ensure_vote_valid(&proposal)?;
        // Mandatory timelock: an approved proposal may not be executed until
        // `timelock` seconds have elapsed since it was approved. Guards against
        // a sudden takeover executing freshly-approved proposals before honest
        // members can withdraw support, reporting the protocol-wide
        // [`Error::TimelockNotExpired`] constant for premature attempts. A `0`
        // timelock (disabled) has no effect. The same gate backs
        // [`Proposal::can_execute`], so the view and the entrypoint agree.
        require_timelock_elapsed(&env, &proposal)?;
        Self::ensure_dependencies_met(&env, id, &proposal)?;
        proposal.state = ProposalState::Executed;
        if let Some(dep) = proposal.deposit.first() {
            TokenClient::new(&env, &dep.asset).transfer(
                &env.current_contract_address(),
                &proposal.proposer,
                &dep.amount,
            );
        }
        Self::store(&env, id, &proposal);
        env.events()
            .publish((symbol_short!("proposal"), symbol_short!("executed")), id);
        Ok(())
    }

    /// Mark an approved proposal as `Failed` (terminal). Only the proposer may
    /// do so. Recording the failure explicitly keeps a broken step visible to
    /// anything that depends on it: a `Failed` prerequisite never satisfies a
    /// dependent proposal, so the chain stops instead of silently continuing.
    ///
    /// A proposal that has gone stale before being executed or failed is
    /// reported as [`Error::ProposalExpired`], not `Failed`: the deadline, not
    /// the action, is what ended it, and the deposit is returned by
    /// [`ProposalContract::expire`].
    pub fn fail(env: Env, caller: Address, id: u64) -> Result<(), Error> {
        caller.require_auth();
        let mut proposal = Self::load(&env, id)?;
        if Self::expire_if_due(&env, id, &mut proposal)? {
            return Ok(());
        }
        if caller != proposal.proposer {
            return Err(Error::Unauthorized);
        }
        if proposal.state != ProposalState::Approved {
            return Err(Error::ProposalNotApproved);
        }
        proposal.state = ProposalState::Failed;
        Self::store(&env, id, &proposal);
        env.events()
            .publish((symbol_short!("proposal"), symbol_short!("failed")), id);
        Ok(())
    }

    /// Close an executed proposal (terminal). Only the proposer may close.
    ///
    /// Deliberately *not* gated on the deadline: by the time this runs the
    /// proposal has already executed, so the approval window is moot and
    /// refusing the tidy-up after `expires_at` would only strand the record in
    /// `Executed`. The expiry gates guard transitions that still let a stale
    /// proposal influence the outcome.
    pub fn close(env: Env, caller: Address, id: u64) -> Result<(), Error> {
        caller.require_auth();
        let mut proposal = Self::load(&env, id)?;
        if Self::expire_if_due(&env, id, &mut proposal)? {
            return Ok(());
        }
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
        let mut proposal = Self::load(&env, id)?;
        Self::expire_if_due(&env, id, &mut proposal)?;
        Ok(proposal)
    }

    /// The vote bars this proposal's tally must clear before `execute` will
    /// run: its configured `threshold`, the participation quorum
    /// ([`PROPOSAL_QUORUM_PERCENT`]% of the approver allow-list, integer
    /// scaled and rounded up) and a strict majority of that allow-list.
    ///
    /// The bars themselves never depend on the clock, but the record is read
    /// through the same settle-first path as every other view, so the answer
    /// is derived from exactly what `execute` would see: a client that only
    /// gets [`Error::ThresholdNotMet`] back can use this view to tell the
    /// caller *which* bar its tally missed.
    pub fn vote_bars(env: Env, id: u64) -> Result<VoteBars, Error> {
        let mut proposal = Self::load(&env, id)?;
        Self::expire_if_due(&env, id, &mut proposal)?;
        Ok(VoteBars::for_proposal(&proposal))
    }

    // --- internal helpers ---

    /// Materialize expiry when an interaction observes a stale or already
    /// expired proposal. Returning success commits the transition, refund and
    /// event together and makes subsequent interactions idempotent.
    fn expire_if_due(env: &Env, id: u64, proposal: &mut Proposal) -> Result<bool, Error> {
        if proposal.state == ProposalState::Expired {
            return Ok(true);
        }
        if !matches!(
            proposal.state,
            ProposalState::Pending | ProposalState::Approved
        ) || !proposal.is_expired(env)
        {
            return Ok(false);
        }

        proposal.state = ProposalState::Expired;
        if let Some(dep) = proposal.deposit.first() {
            TokenClient::new(env, &dep.asset).transfer(
                &env.current_contract_address(),
                &proposal.proposer,
                &dep.amount,
            );
        }
        Self::store(env, id, proposal);
        env.events()
            .publish((symbol_short!("proposal"), symbol_short!("expired")), id);
        Ok(true)
    }

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

    /// Refuse to execute a proposal whose tally does not clear every vote bar.
    ///
    /// The bars are derived afresh from the stored record on each call —
    /// nothing is cached — by [`VoteBars::for_proposal`], and checked in
    /// order of increasing strictness:
    ///
    /// 1. the proposal's configured `threshold` (defence in depth: the
    ///    `Approved` state gate in `execute` already guarantees it);
    /// 2. the participation quorum — at least [`PROPOSAL_QUORUM_PERCENT`]% of
    ///    the allow-list must have voted, rounded up;
    /// 3. a strict majority of the allow-list (an exact tie is not a
    ///    majority).
    ///
    /// Every shortfall reports [`Error::ThresholdNotMet`] (see
    /// [`VoteBars::ensure_met`]).
    ///
    /// Nothing is mutated: a refusal leaves the proposal `Approved` and free
    /// to be re-attempted, failed or cancelled.
    fn ensure_vote_valid(proposal: &Proposal) -> Result<(), Error> {
        VoteBars::for_proposal(proposal).ensure_met(proposal.approvals)
    }

    /// Require that every prerequisite proposal has executed.
    ///
    /// Dependencies are deduplicated at creation time and each entry is one
    /// storage read, so a check costs exactly as many reads as the proposal has
    /// distinct prerequisites — and short-circuits on the first unmet one. A
    /// prerequisite that has been cancelled, rejected, expired or explicitly
    /// marked `Failed` can never become executed, but it is reported the same
    /// way: the dependent proposal simply cannot run.
    ///
    /// Dependency resolution is observable: validation publishes
    /// `("proposal", "dep_ok")` when the whole chain is satisfied, or
    /// `("proposal", "dep_fail")` carrying the id of the first unmet
    /// prerequisite when it is not.
    fn ensure_dependencies_met(env: &Env, id: u64, proposal: &Proposal) -> Result<(), Error> {
        for dep in proposal.dependencies.iter() {
            let prerequisite = Self::load(env, dep)?;
            if !prerequisite.state.has_executed() {
                env.events().publish(
                    (symbol_short!("proposal"), symbol_short!("dep_fail")),
                    (id, dep),
                );
                return Err(Error::PrerequisiteNotMet);
            }
        }
        env.events().publish(
            (symbol_short!("proposal"), symbol_short!("dep_ok")),
            (id, proposal.dependencies.clone()),
        );
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

/// Refuse to release a proposal until the mandatory delay between approval and
/// execution has elapsed on the current ledger.
///
/// The delay is the protocol-wide `timelock` (seconds) stored once by
/// [`ProposalContract::initialize`]; `0` disables it, and a record stamped
/// before any delay applied (`approved_at == 0`) has nothing to wait for.
/// Otherwise the release instant `approved_at + timelock` is computed with the
/// shared checked helpers and *must* be representable as a ledger timestamp:
/// an unrepresentable instant fails closed with [`Error::Overflow`] instead of
/// truncating into the past, which would otherwise let a proposal execute the
/// moment it is approved. [`Proposal::can_execute`] runs the very same gate.
fn require_timelock_elapsed(env: &Env, proposal: &Proposal) -> Result<(), Error> {
    let timelock: u64 = env
        .storage()
        .instance()
        .get(&DataKey::Timelock)
        .unwrap_or(0);
    if timelock == 0 || proposal.approved_at == 0 {
        return Ok(());
    }
    let release_at = checked_add(proposal.approved_at as i128, timelock as i128)?;
    let release_at = u64::try_from(release_at).map_err(|_| Error::Overflow)?;
    require_time_reached(env, release_at)
}

// ---------------------------------------------------------------------------
// Status surface, exposed through the shared `ProposalInterface`.
//
// Declaring these in the trait impl (rather than an inherent one) is what makes
// the contract's entrypoints provably match the cross-contract client other
// contracts are generated against. Each read settles a stale proposal first,
// so the answer always reflects the deterministic ledger clock.
// ---------------------------------------------------------------------------
#[contractimpl]
impl ProposalInterface for ProposalContract {
    /// Current lifecycle state of proposal `id`.
    fn state(env: Env, id: u64) -> Result<ProposalState, Error> {
        let mut proposal = Self::load(&env, id)?;
        Self::expire_if_due(&env, id, &mut proposal)?;
        Ok(proposal.state)
    }

    /// Whether the proposal's deadline has been reached on the current ledger
    /// (and it therefore has a deadline at all). Lets a client check before
    /// spending a transaction on a stale proposal.
    fn is_expired(env: Env, id: u64) -> Result<bool, Error> {
        let mut proposal = Self::load(&env, id)?;
        Self::expire_if_due(&env, id, &mut proposal)?;
        Ok(proposal.state == ProposalState::Expired || proposal.is_expired(&env))
    }

    /// Whether the proposal has completed its action — `Executed` or `Closed`
    /// (the only terminal states reachable from a successful run). This is the
    /// completion check downstream contracts should read before chaining onto a
    /// proposal, so dependency resolution needs no private state.
    fn is_executed(env: Env, id: u64) -> Result<bool, Error> {
        let mut proposal = Self::load(&env, id)?;
        Self::expire_if_due(&env, id, &mut proposal)?;
        Ok(proposal.state.has_executed())
    }

    /// The prerequisite proposal ids this proposal declares.
    fn dependencies(env: Env, id: u64) -> Result<Vec<u64>, Error> {
        let mut proposal = Self::load(&env, id)?;
        Self::expire_if_due(&env, id, &mut proposal)?;
        Ok(proposal.dependencies)
    }

    /// Whether every prerequisite has executed — the same question `execute`
    /// asks, exposed so callers can check before spending a transaction on it.
    fn dependencies_met(env: Env, id: u64) -> Result<bool, Error> {
        let mut proposal = Self::load(&env, id)?;
        Self::expire_if_due(&env, id, &mut proposal)?;
        Ok(Self::ensure_dependencies_met(&env, id, &proposal).is_ok())
    }

    /// Whether `execute` would accept this proposal on the current ledger:
    /// live (not past its deadline), `Approved`, the tally still clearing the
    /// quorum / threshold / majority bars, the mandatory delay since approval
    /// elapsed, and every prerequisite executed. The conjunction of exactly
    /// the gates `execute` applies, in the order it applies them, so a client
    /// can check before spending a transaction on it and never get an answer
    /// the entrypoint would then contradict.
    fn can_execute(env: Env, id: u64) -> Result<bool, Error> {
        let mut proposal = Self::load(&env, id)?;
        Self::expire_if_due(&env, id, &mut proposal)?;
        if !proposal.can_execute(&env) {
            return Ok(false);
        }
        if Self::ensure_vote_valid(&proposal).is_err() {
            return Ok(false);
        }
        Ok(Self::ensure_dependencies_met(&env, id, &proposal).is_ok())
    }
}

// ---------------------------------------------------------------------------
// Registry-gated upgrades, exposed through the shared `UpgradeableInterface`.
// ---------------------------------------------------------------------------
#[contractimpl]
impl UpgradeableInterface for ProposalContract {
    /// Record (or rotate) who may upgrade this contract and which registry
    /// authorizes the new code. Bootstrapped by the deployer alongside
    /// `initialize`; afterwards only the current upgrade admin may rotate it.
    fn set_upgrade_authority(
        env: Env,
        caller: Address,
        admin: Address,
        registry: Address,
    ) -> Result<(), Error> {
        astroid_interfaces::upgrade::set_authority(&env, &caller, &admin, &registry)
    }

    /// Read the recorded upgrade authority.
    fn get_upgrade_authority(
        env: Env,
    ) -> Result<astroid_interfaces::upgrade::UpgradeAuthority, Error> {
        astroid_interfaces::upgrade::get_authority(&env)
    }

    /// Replace this contract's code with `wasm_hash`.
    ///
    /// Two gates must pass: `caller` must be the recorded upgrade admin, and
    /// `wasm_hash` must be approved for `ModuleKind::Proposal` in the registry.
    /// Any other outcome leaves the contract running its current code.
    fn upgrade(env: Env, caller: Address, wasm_hash: soroban_sdk::BytesN<32>) -> Result<(), Error> {
        astroid_interfaces::upgrade::perform(
            &env,
            &caller,
            astroid_shared::types::ModuleKind::Proposal,
            wasm_hash,
        )
    }
}

#[cfg(test)]
mod test;
