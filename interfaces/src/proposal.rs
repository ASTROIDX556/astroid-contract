//! Proposal lifecycle interface: the canonical state enum and status-query
//! trait shared by the `proposal`, `multisig` and `wallet` contracts.
//!
//! The proposal contract owns the lifecycle, but the states themselves are
//! protocol vocabulary: the multisig verifies the quorum that authorizes a
//! proposal, and the wallet executes the resulting value movement. Defining the
//! state here — rather than letting each contract grow its own copy — keeps one
//! source of truth for the on-chain encoding, so off-chain indexers and the
//! Astroid backend decode the same `u32` discriminant no matter who answers.
//!
//! ## Lifecycle
//!
//! ```text
//! Created ─▶ Pending ─▶ Approved ─▶ Executed ─▶ Closed
//!    │          │           │
//!    ▼          ▼           ▼
//! Cancelled  Rejected     Failed
//!             / Expired
//! ```
//!
//! ## Deterministic encoding
//!
//! [`ProposalState`] is a `#[contracttype]`, so it serializes through the
//! canonical Soroban conversion rules as an `ScVal::U32` carrying the
//! discriminant. The numeric values below are part of the public ABI and MUST
//! NOT be reordered or reused once released. They map onto the protocol-wide
//! [`Error`] codes as follows:
//!
//! | Condition reached                                | Error                     |
//! |--------------------------------------------------|---------------------------|
//! | Interaction with a proposal in the wrong state   | [`Error::InvalidProposalState`] |
//! | Execution attempted before `Approved`            | [`Error::ProposalNotApproved`]  |
//! | Deadline passed before the action ran            | [`Error::ProposalExpired`]      |
//! | A prerequisite proposal has not executed         | [`Error::PrerequisiteNotMet`]   |

use astroid_shared::errors::Error;
use soroban_sdk::{contractclient, contracttype, Env, Vec};

/// Canonical lifecycle state of an Astroid proposal.
///
/// Discriminants are explicit and stable: they are the `ScVal::U32` value the
/// contract stores and every cross-contract client decodes. Adding a state is
/// an interface-version bump; renumbering an existing one is a breaking ABI
/// change.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProposalState {
    /// Recorded but not yet opened for voting.
    Created = 0,
    /// Open for approvals and rejections.
    Pending = 1,
    /// The approval threshold was reached; awaiting the timelock and execution.
    Approved = 2,
    /// The authorized action ran to completion. Terminal.
    Executed = 3,
    /// An executed proposal that has been tidied away. Terminal, and still
    /// counts as executed for dependency resolution.
    Closed = 4,
    /// An approver rejected the proposal. Terminal.
    Rejected = 5,
    /// The proposer cancelled the proposal. Terminal.
    Cancelled = 6,
    /// The approval window closed before the action ran. Terminal.
    Expired = 7,
    /// Approved, but the action it authorized did not go through. Terminal, and
    /// deliberately distinct from [`ProposalState::Executed`] so a dependent
    /// proposal stays blocked rather than inheriting a broken prerequisite.
    Failed = 8,
}

impl ProposalState {
    /// Whether a proposal in this state has carried out its action, and so can
    /// satisfy a dependent proposal's prerequisite.
    ///
    /// [`ProposalState::Closed`] counts: it is only reachable from
    /// [`ProposalState::Executed`], and tidying an executed proposal away must
    /// not retroactively block its dependents.
    pub fn has_executed(self) -> bool {
        matches!(self, ProposalState::Executed | ProposalState::Closed)
    }

    /// Whether a proposal in this state has already returned its deposit (or
    /// never held one), and so may be purged from storage.
    ///
    /// [`ProposalState::Pending`] and [`ProposalState::Approved`] are excluded:
    /// a stale proposal in either state still holds the proposer's deposit, and
    /// deleting the record would strand it. Those states must first pass
    /// through the expiry transition, which refunds the deposit as it records
    /// the change. [`ProposalState::Failed`] is excluded for the same custody
    /// reason — its deposit has not been returned by any transition, so the
    /// record is kept.
    pub fn deposit_settled(self) -> bool {
        matches!(
            self,
            ProposalState::Expired
                | ProposalState::Rejected
                | ProposalState::Cancelled
                | ProposalState::Executed
                | ProposalState::Closed
        )
    }

    /// Whether the proposal may still change state — it sits in one of the two
    /// live states. The deadline gate is applied by the contract against the
    /// deterministic ledger clock; this is the pure, stateless part of that
    /// question and is safe to evaluate off-chain.
    pub fn is_live(self) -> bool {
        matches!(self, ProposalState::Pending | ProposalState::Approved)
    }

    /// Whether the state is final: no further transition is possible. Useful
    /// for callers that want to stop polling a proposal.
    pub fn is_terminal(self) -> bool {
        !self.is_live() && self != ProposalState::Created
    }
}

/// Proposal status-query surface. Other contracts (and the Astroid backend)
/// use it to drive a proposal through its lifecycle without depending on the
/// proposal crate at compile time.
///
/// Every method is fallible and reports the canonical protocol-wide [`Error`],
/// so a cross-contract `try_*` call always decodes into the same stable `u32`
/// code table:
///
/// * `NotFound` — no proposal with that id;
/// * [`Error::InvalidProposalState`] — the query itself is not applicable;
/// * and, for [`ProposalInterface::can_execute`], the gates are folded into a
///   `bool` rather than surfacing individually, matching the on-chain view.
#[contractclient(name = "ProposalClient")]
pub trait ProposalInterface {
    /// Current lifecycle state of proposal `id`.
    ///
    /// A stale proposal is settled to [`ProposalState::Expired`] by this read,
    /// so the answer always reflects the deterministic ledger clock.
    fn state(env: Env, id: u64) -> Result<ProposalState, Error>;

    /// Whether the proposal's deadline has been reached on the current ledger
    /// (and it therefore has a deadline at all).
    fn is_expired(env: Env, id: u64) -> Result<bool, Error>;

    /// Whether the proposal has completed its action — [`ProposalState::Executed`]
    /// or [`ProposalState::Closed`]. The completion check downstream contracts
    /// read before chaining onto a proposal.
    fn is_executed(env: Env, id: u64) -> Result<bool, Error>;

    /// The prerequisite proposal ids this proposal declares.
    fn dependencies(env: Env, id: u64) -> Result<Vec<u64>, Error>;

    /// Whether every prerequisite has executed.
    fn dependencies_met(env: Env, id: u64) -> Result<bool, Error>;

    /// Whether execution would be accepted on the current ledger: live,
    /// `Approved`, the tally still clearing every vote bar, the mandatory
    /// timelock elapsed, and every prerequisite executed.
    fn can_execute(env: Env, id: u64) -> Result<bool, Error>;
}
