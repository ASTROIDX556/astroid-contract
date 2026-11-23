# Proposal Contract

## Overview

The proposal contract coordinates execution flows between multisig approvals and contract calls. It represents an action awaiting approval and drives it through the lifecycle defined in PRD Doc 7 §Proposal:

```
Created ─▶ Pending ─▶ Approved ─▶ Executed
   │          │           │
   ▼          ▼           ▼
 Cancelled  Rejected    Closed
            / Expired
```

A proposal links off-chain context — `wallet`, `policy` and `org` — so the backend can reconstruct why money moved. The contract records an explicit approver allow-list and an approval threshold; reaching the threshold moves the proposal to `Approved`, after which it may be `Executed` (marked done) and finally `Closed`. An approved proposal whose off-chain action did not go through is marked `Failed`, a terminal state.

## Lifecycle States

| State       | Description                                                            |
|-------------|------------------------------------------------------------------------|
| `Pending`   | Awaiting approvals                                                     |
| `Approved` | Threshold met, waiting for timelock to elapse                          |
| `Executed` | Proposal executed, deposit transferred to proposer                     |
| `Closed`    | Execution tidied away                                                  |
| `Cancelled` | Proposer cancelled before execution                                    |
| `Rejected`  | Approvers rejected the proposal                                        |
| `Expired`   | Deadline passed without action                                         |
| `Failed`    | Explicit failure recorded by proposer                                  |

## Core Arithmetic and Safety

All value math goes through the shared checked helpers in `astroid-shared` (`math.rs`), which return deterministic `Error` codes instead of panicking on overflow:

- `checked_add`, `checked_sub`, `checked_mul`, `checked_div` for `i128` and `u128`
- `checked_add_u64`, `checked_sub_u64`, `checked_mul_u64`, `checked_div_u64` for `u64`
- `validate_sufficient_balance` — verify balance covers amount before transfer
- `checked_balance_add` / `checked_balance_sub` — credit/debit with underflow/overflow protection
- `SafeAdd`/`SafeSub`/`SafeMul`/`SafeDiv` traits
- `SafeBalance` trait for ledger-aware debit/credit
- `verify_batch_allowance` — batch expenditure verification with aggregate or pairwise limits
- `checked_batch_allowance`, `checked_batch_calculation` — checked variants
- `calculate_budget_rollover` / `calculate_rollover_allowance` — basis-point rollover math

The release profile keeps `overflow-checks` ON; all value math must go through these helpers.

## Key Types

### `Proposal`

```rust
pub struct Proposal {
    pub proposer: Address,
    pub org: String,
    pub wallet: String,
    pub policy: String,
    pub approvers: Vec<Address>,
    pub dependencies: Vec<u64>,
    pub threshold: u32,
    pub approvals: u32,
    pub approval_weight: u32,
    pub state: ProposalState,
    pub created_at: u64,
    pub approved_at: u64,
    pub expires_at: u64,
    pub grace_period: u64,
}
```

### `VoteBars`

The three vote bars a tally must clear before execution:

- **threshold** — the proposal's configured approval threshold
- **quorum** — `ceil(approvers * PROPOSAL_QUORUM_PERCENT / 100)`, integer-scaled, rounded up
- **majority** — `floor(approvers / 2) + 1`, a strict majority (exact tie fails)

### `ProposalTally`

```rust
pub struct ProposalTally {
    pub approvals: u32,
    pub approval_weight: u32,
    pub outstanding: u32,
    pub bars: VoteBars,
    pub quorum_reached: bool,
    pub majority_reached: bool,
    pub threshold_reached: bool,
    pub passed: bool,
    pub defeated: bool,
}
```

## Functions

### `initialize(env, timelock, multisig)`

Idempotent-guarded initialization. Sets the mandatory per-proposal timelock (seconds between approval and execution). `0` disables the delay.

### `create`

Creates a proposal in `Pending` state. Requires:

- `proposer` authorization
- Non-empty org
- Approver allow-list non-empty and ≤ `MAX_APPROVERS`
- Each approver must be a multisig signer
- Declared prerequisites must exist and be acyclic (no circular dependencies)
- If deposit specified, proposer transfers `DEPOSIT` to the contract
- `expires_at` must be either `0` (never) or a future ledger timestamp

Emits [`events::proposal_created`].

### `approve`

An authorized multisig signer may approve. Moves the proposal to `Approved` once the threshold is reached. Records `approved_at` timestamp. Emits [`events::proposal_approved`].

### `execute`

Only the proposer may execute. Re-validates all bars (threshold, quorum, majority) against the live multisig state (emergency lock, signer weight). Applies the mandatory timelock. Checks all prerequisites have executed. Transitions to `Executed` and transfers the deposit to the proposer. Emits [`events::proposal_executed`].

### `finalize`

Permissionless settlement: a live proposal that can no longer pass moves to `Defeated`, deposits are refunded. Emits [`events::proposal_defeated`].

### `expire`

Permissionless expiry: if `expires_at` has passed, the proposal transitions to `Expired`, deposit is refunded. Emits [`events::expired`].

### `reject`

Any approver may reject a `Pending` proposal → `Rejected`. Deposit is refunded to proposer. Emits [`events::rejected`].

### `cancel`

Only the proposer may cancel, before execution or expiry. If a `grace_period` is configured, cancellation is allowed while `now <= created_at + grace_period`. Emits [`events::cancelled`].

### `fail`

Only the proposer may mark an `Approved` proposal as `Failed` (terminal). Emits [`events::failed`].

### `close`

Only the proposer may close an `Executed` proposal → `Closed`. Emits [`events::closed`].

### `prune_expired`, `prune_expired_batch`, `prune_expired_range`

Crank helpers: purge expired proposals with settled deposits to reclaim storage.

## Views

- `get(id)` — returns the current proposal record
- `state(id)` — returns the current `ProposalState`
- `vote_bars(id)` — returns the `VoteBars` (threshold, quorum, majority)
- `timelock()` — the configured delay in seconds
- `release_at(id)` — the release instant (`approved_at + timelock`)
- `can_execute(id)` — whether execution is allowed on the current ledger
- `is_expired(id)` — whether the deadline has been reached
- `tally(id)` — the full `ProposalTally`

## Error Codes

All errors are from the shared `astroid-shared::errors::Error` enum. Proposal-specific codes:

| Code | Wire Name               | Trigger                                                  |
|------|-------------------------|----------------------------------------------------------|
| 71   | `PROPOSAL_EXPIRED`      | Deadline passed                                          |
| 72   | `INVALID_PROPOSAL_STATE`| Illegal state transition                                 |
| 73   | `PROPOSAL_NOT_APPROVED` | Proposal not in `Approved` state                         |
| 74   | `NOT_AN_APPROVER`       | Caller not in approver allow-list                        |
| 75   | `CANCELLATION_WINDOW_CLOSED` | Grace period elapsed                               |
| 76   | `PROPOSAL_DEFEATED`     | Tally can no longer clear bars                           |
| 78   | `PREREQUISITE_NOT_MET`  | A declared prerequisite has not executed                 |
| 79   | `CIRCULAR_DEPENDENCY_DETECTED` | Dependency would close a cycle                     |

## Events

All events are published through the shared `astroid-shared::events` module, ensuring a consistent schema across all Astroid contracts.

| Event                      | Topic                              | Payload                                                        |
|----------------------------|------------------------------------|----------------------------------------------------------------|
| `proposal_created`         | `("proposal", "created")`          | `(proposal_id, proposer)`                                      |
| `proposal_approved`        | `("proposal", "approved")`         | `(proposal_id, approver, approvals)`                          |
| `proposal_executed`        | `("proposal", "executed")`         | `(proposal_id)`                                                |
| `proposal_defeated`        | `("proposal", "defeated")`         | `(proposal_id, approvals, required)`                           |
| `proposal_cancelled`       | `("proposal", "cancelled")`        | `(proposal_id)`                                                |
| `proposal_failed`          | `("proposal", "failed")`           | `(proposal_id)`                                                |
| `proposal_expired`         | `("proposal", "expired")`          | (implicit from transition)                                     |
| `weightok`                 | `("proposal", "weightok")`         | `(proposal_id, caller, approval_weight)`                       |
| `pruned_b`                 | `("proposal", "pruned_b")`         | `(count)`                                                      |
| `pruned_r`                 | `("proposal", "pruned_r")`         | `(count)`                                                      |

See [`shared/src/events.rs`](shared/src/events.rs) for the full event catalog and helper signatures.

## Storage Layout

Keys are instance-scoped (persist across upgrades) or persistent (survive upgrades with TTL):

| Key               | Type           | Scope       |
|-------------------|----------------|-------------|
| `ProposalCount`   | `u64`          | instance    |
| `Timelock`        | `u64`          | instance    |
| `Multisig`        | `Address`      | instance    |
| `Proposal(u64)`   | `Proposal`     | persistent  |
| `Approval(u64, Address)` | `bool` | persistent  |

Instance keys are bump-limited via `INSTANCE_LIFETIME_THRESHOLD` / `INSTANCE_BUMP_AMOUNT`. Persistent keys extend TTL via `PERSISTENT_LIFETIME_THRESHOLD` / `PERSISTENT_BUMP_AMOUNT`.

## Error Code Bands

Proposal errors occupy codes 71–79 in the shared `Error` enum, adjacent to the multisig/approval band (61–70) and the escrow band (80–82). This contiguous range was chosen to keep related codes near each other in the wire catalog.

## Dependencies and Acyclicity

A proposal may declare prerequisite proposals it depends on. `execute` then refuses to run until every prerequisite has executed. The graph is acyclic by construction — a dependency must name a proposal with a strictly lower ID, and the `dependency >= id` check at creation rejects cycles. This lets multi-step protocols (e.g., fund escrow → migrate balances → retire module) sequence correctly.

## Quorum and Majority

- **Quorum**: at least `PROPOSAL_QUORUM_PERCENT`% of the approver allow-list must have voted. Computed as `ceil(approvers * percent / 100)` using checked `u64` arithmetic.
- **Majority**: approvals must form a strict majority: `approvals > approvers / 2`. An exact tie never reaches it.

Both are re-derived from the stored record on every call, so the verdict is a pure function of on-chain state.

## Timelock

Executing an approved proposal immediately would let a sudden takeover spend the mandate before it is visible. The contract enforces a mandatory minimum delay — the configured `timelock` (seconds) set at [`initialize`]. The approval timestamp is recorded when the proposal reaches `Approved`, and `execute` refuses with [`Error::TimelockNotExpired`] until `approved_at + timelock` has passed.

The release instant is computed with checked arithmetic (`timelock::release_at`) so an unrepresentable deadline fails closed with [`Error::Overflow`] instead of wrapping into the past. The boundary is inclusive: `now == release_at` is already released, one second earlier is not.

## API Reference (Key Signatures)

```rust
// Initialization
pub fn initialize(env: Env, timelock: u64, multisig: Address) -> Result<(), Error>

// Creation
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
) -> Result<u64, Error> // returns proposal id

// Approval
pub fn approve(env: Env, caller: Address, id: u64) -> Result<u32, Error> // returns approval count

// Execution
pub fn execute(env: Env, caller: Address, id: u64) -> Result<(), Error>

// Settlement
pub fn finalize(env: Env, id: u64) -> Result<ProposalState, Error>
pub fn fail(env: Env, caller: Address, id: u64) -> Result<(), Error>
pub fn close(env: Env, caller: Address, id: u64) -> Result<(), Error>

// Lifecycle queries
pub fn state(env: Env, id: u64) -> ProposalState
pub fn vote_bars(env: Env, id: u64) -> VoteBars
pub fn can_execute(env: Env, id: u64) -> bool
pub fn is_expired(env: Env, id: u64) -> bool
pub fn tally(env: Env, id: u64) -> Result<ProposalTally, Error>

// Expiration and cancellation
pub fn expire(env: Env, id: u64) -> Result<(), Error>
pub fn reject(env: Env, caller: Address, id: u64) -> Result<(), Error>
pub fn cancel(env: Env, caller: Address, id: u64) -> Result<(), Error>
```

## Testing

All proposal functionality is tested in `contracts/proposal/src/test.rs`. The test harness (`Harness`) sets up a mock environment with a multisig, proposer, and approvers. Key test categories:

- Lifecycle transitions (create → approve → execute → close)
- Timelock gating and expiry boundaries
- Dependency chaining and ordering
- Quorum and majority calculations (rounding, ties, thresholds)
- Weighted multisig thresholds
- Cancellation grace windows
- Error code correctness (threshold not met, proposal expired, etc.)
- Event emission verification

Run proposal tests with:

```bash
cargo test -p astroid-contract -- proposal
```

The full workspace test suite (`cargo test --workspace`) also exercises the proposal contract through integration tests in other crates (wallet, multisig, treasury, budget).

## Further Reading

- [PRD Doc 7](https://prd.astroid.dev/7) — authoritative smart‑contract architecture
- [`astroid-shared::math`] — checked arithmetic helpers
- [`astroid-shared::events`] — standardized event emission
- [`astroid-shared::errors`] — deterministic error code table
- [`astroid-interfaces::proposal::ProposalInterface`] — the interface definition