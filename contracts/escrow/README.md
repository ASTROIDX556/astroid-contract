# astroid-escrow

Escrow contract — temporary custody until a designated arbiter resolves the
release condition. A single agreement can hold several distinct Stellar
assets, and can optionally require multi-party sign-off before the recipient is
paid, and/or be released early by a set of pre-configured ed25519 signers
instead of the named arbiter.

```text
funder ──► create(sender, recipient, arbiter, assets[], deadline, memo,
                   release_signers[], release_threshold) ──► Escrow-Funded
       │
       └─► create_with_release_condition(config{participants[],
                                    approval_threshold})  ──► Escrow-Funded
              │
              ├─► participant.approve_release(id)  (x N) ──► threshold met
              │
              ├─► arbiter.release(id)                     ──► Released ──► assets move
              ├─► override_release(id, nonce, signatures) ──► Released ──► assets move
              ├─► sender.refund(id)                       ──► Refunded   (after deadline)
              └─► sender.cancel / refund_timelock / reclaim (never gated)
```

## Contents

- [Deployment](#deployment)
- [State machine](#state-machine)
- [Public interface](#public-interface)
- [Events](#events)
- [Error codes](#error-codes)
- [Storage layout](#storage-layout)
- [TTL management](#ttl-management)
- [Time-lock release schedules](#time-lock-release-schedules)
- [Multi-party release conditions](#multi-party-release-conditions)
- [Invariants](#invariants)
- [Use-cases](#use-cases)

## Deployment

The escrow is a standalone contract: it has no constructor dependencies on
the other Astroid modules, so it can be deployed at any point after the
registry. Build and test it from the workspace root:

```bash
stellar contract build                 # → target/wasm32v1-none/release/astroid_escrow.wasm
cargo test -p astroid-escrow           # unit tests (src/test.rs)
cargo test -p astroid-integration-tests escrow   # cross-contract scenarios
```

Deploy and initialize on testnet (replace `alice` with your funded identity):

```bash
# 1. Deploy the Wasm and record the contract id.
ESCROW=$(stellar contract deploy \
  --wasm target/wasm32v1-none/release/astroid_escrow.wasm \
  --source alice --network testnet)

# 2. Initialize once. `admin` manages the token whitelist.
stellar contract invoke --id "$ESCROW" --source alice --network testnet \
  -- initialize --admin "$(stellar keys address alice)"

# 3. Whitelist every token contract that may be escrowed (admin only).
stellar contract invoke --id "$ESCROW" --source alice --network testnet \
  -- approve_token --caller "$(stellar keys address alice)" --token <TOKEN_CONTRACT_ID>

# 4. (Optional) Bind registry-gated upgrades.
stellar contract invoke --id "$ESCROW" --source alice --network testnet \
  -- set_upgrade_authority --caller <ADMIN> --admin <ADMIN> --registry <REGISTRY_ID>
```

`initialize` can only run once (`AlreadyInitialized`, 6). Every creation path
refuses tokens that are not whitelisted with `AssetNotAuthorized` (43).

## State machine

`Created → Funded → (Released | Refunded | Expired) → Closed`

- `create` funds immediately (atomic in a single call), pulling every listed
  `(asset, amount)` pair into custody.
- `release` requires the arbiter and a live deadline.
- `override_release` requires at least `release_threshold` distinct, valid
  ed25519 signatures from `release_signers`, each over a deterministic
  payload (contract address, network id, escrow id, nonce), and a live
  deadline. It is permissionless — the signatures are the authorization, so
  any relayer may submit them. Pass an empty signer set (and threshold `0`)
  at `create` time to disable this path for an escrow.
- `refund` requires the recorded sender and opens once the escrow has timed
  out: before `deadline` it fails with `TimeLockActive` (81), during the
  grace period with `GraceActive` (82), and from `deadline + grace_period`
  (inclusive, by ledger timestamp) it returns the funds to the sender. That is
  the same instant `release` starts failing with `EscrowExpired` (80), so the
  release and refund windows never overlap.
- `close` (terminal) requires one of the three roles once the escrow is final.

## Public interface

All amounts are `i128` in the token's smallest unit; all times are ledger
timestamps (`u64`, seconds). Unless noted otherwise, entry points return
`Result<_, Error>` with the codes listed under [Error codes](#error-codes).
Types come from `src/storage.rs` (`Escrow`, `ReleaseSchedule`, …),
`src/lib.rs` (`OverrideSignature`, `ReleaseConditionConfig`) and
`shared/src/types.rs` (`AssetAmount`).

### Administration and token whitelist

| Function | Auth | Description |
|---|---|---|
| `initialize(admin: Address) -> Result<(), Error>` | — | One-time setup; records the whitelist admin. |
| `approve_token(caller: Address, token: Address) -> Result<(), Error>` | admin | Whitelist a token (max `MAX_ESCROW_TOKENS` = 32). |
| `revoke_token(caller: Address, token: Address) -> Result<(), Error>` | admin | Stop *new* escrows of a token; existing ones stay settleable. |
| `admin() -> Result<Address, Error>` | — | Whitelist admin. |
| `is_token_approved(token: Address) -> bool` | — | Whitelist membership. |
| `approved_tokens() -> Vec<Address>` | — | Whitelisted tokens, in approval order. |

### Creation and funding

| Function | Auth | Description |
|---|---|---|
| `create(sender, recipient, arbiter, assets: Vec<AssetAmount>, deadline: u64, grace_period: u64, memo: String, release_signers: Vec<BytesN<32>>, release_threshold: u32) -> Result<u64, Error>` | sender | Create and fund atomically; returns the escrow id. |
| `create_with_refund_window(sender, recipient, arbiter, assets, deadline, grace_period, refund_window: u64, memo, release_signers, release_threshold) -> Result<u64, Error>` | sender | As `create`, with a bounded refund window (`0` = open forever). |
| `create_with_release_condition(config: ReleaseConditionConfig) -> Result<u64, Error>` | sender | As `create_with_refund_window`, plus a multi-party `participants` / `approval_threshold` gate. |
| `create_timelock(sender, recipient, arbiter, assets, unlock_time: u64, memo) -> Result<u64, Error>` | sender | Funded `Cliff` escrow unlocking at `unlock_time`. |
| `create_scheduled(sender, recipient, arbiter, assets, schedule: ReleaseSchedule, deadline: u64, memo) -> Result<u64, Error>` | sender | Funded escrow with a `Cliff` or `Linear` schedule. |
| `initialize_timelock(sender, recipient, arbiter, assets, unlock_time: u64, grace_period: u64, memo) -> Result<u64, Error>` | sender | Record a time-locked escrow in `Created` without moving funds. |
| `fund(sender: Address, id: u64) -> Result<(), Error>` | sender | Fund an escrow created by `initialize_timelock`. |
| `deposit_with_milestones(sender, recipient, arbiter, asset: Address, amount: i128, deadline: u64, memo, milestones: Vec<MilestoneSpec>) -> Result<u64, Error>` | sender | Single-asset escrow paid out per milestone (`release_bps` must sum to 10 000). |

### Settlement

| Function | Auth | Description |
|---|---|---|
| `release(arbiter: Address, id: u64, release_amount: i128) -> Result<(), Error>` | arbiter | Pay the remaining balance to the recipient (schedule + condition gated). |
| `override_release(id: u64, nonce: u64, signatures: Vec<OverrideSignature>) -> Result<(), Error>` | signatures | Release with `release_threshold` ed25519 signatures; permissionless submitter. |
| `withdraw(caller: Address, id: u64, amount: i128) -> Result<i128, Error>` | recipient | Partial payout of the vested amount on a scheduled escrow. |
| `claim(caller: Address, id: u64) -> Result<i128, Error>` | recipient | Pay out everything currently claimable on a scheduled escrow. |
| `approve_release(caller: Address, id: u64) -> Result<u32, Error>` | participant | Record one multi-party sign-off; returns the running approval count. |
| `expire(id: u64) -> Result<(), Error>` | — | Mark a timed-out escrow `Expired` (keeper call). |
| `refund(caller: Address, id: u64) -> Result<(), Error>` | sender | Return funds from `deadline + grace_period`. |
| `refund_timelock(caller: Address, id: u64) -> Result<(), Error>` | sender | Return funds of a time-locked escrow after its unlock / grace end. |
| `cancel(caller: Address, id: u64) -> Result<(), Error>` | sender or arbiter | Pre-deadline exit; refunds the unreleased balance. |
| `reclaim(caller: Address, id: u64) -> Result<(), Error>` | sender | Post-grace safe-settlement path back to the sender. |
| `close(caller: Address, id: u64) -> Result<(), Error>` | sender, recipient or arbiter | Move a `Released` / `Refunded` escrow to terminal `Closed`. |

### Milestones

Milestone entry points return `Result<_, MilestoneError>` (see below).

| Function | Auth | Description |
|---|---|---|
| `release_milestone(caller: Address, id: u64, index: u32) -> Result<(), MilestoneError>` | arbiter | Approve a milestone and pay its share. |
| `dispute_milestone(caller: Address, id: u64, index: u32) -> Result<(), MilestoneError>` | arbiter | Mark a pending milestone `Disputed`. |
| `resolve_milestone(caller: Address, id: u64, index: u32) -> Result<(), MilestoneError>` | arbiter | Move a disputed milestone back to `Pending`. |
| `cancel_remaining_milestones(caller: Address, id: u64) -> Result<i128, Error>` | sender or arbiter | Refund every unreleased milestone; returns the refunded amount. |

### Views

| Function | Description |
|---|---|
| `get(id: u64) -> Result<Escrow, Error>` | Full escrow record. |
| `get_schedule(id: u64) -> Result<ReleaseSchedule, Error>` | Release schedule (`ReleaseType::None` for plain escrows). |
| `milestones(id: u64) -> Result<MilestoneSet, Error>` | Milestone schedule and progress. |
| `get_release_condition(id: u64) -> Result<ReleaseCondition, Error>` | Multi-party condition, or `NotFound`. |
| `release_approvals(id: u64) -> Result<Vec<Address>, Error>` | Participants that approved, in declaration order. |
| `escrow_count() -> u64` | Number of escrows created (`EscrowInterface`). |
| `refund_window_closes_at(id: u64) -> Result<u64, Error>` | When the refund window closes (`0` = the window never closes). |
| `is_refundable(id: u64) -> Result<bool, Error>` | Whether `refund` would succeed now. |
| `get_claimable_amount(id: u64) -> Result<i128, Error>` | Vested minus already released. |
| `get_vested_amount(id: u64) -> Result<i128, Error>` | Amount vested at the current ledger time. |
| `is_unlocked(id: u64) -> Result<bool, Error>` | Whether the schedule has matured. |

### Upgrades (`UpgradeableInterface`)

| Function | Description |
|---|---|
| `set_upgrade_authority(caller, admin, registry) -> Result<(), Error>` | Bind (or rotate) the upgrade admin and authorizing registry. |
| `get_upgrade_authority() -> Result<UpgradeAuthority, Error>` | Current upgrade binding. |
| `upgrade(caller, wasm_hash: BytesN<32>) -> Result<(), Error>` | Install registry-approved Wasm. |

## Events

Settlement is published through the shared schema in `shared/src/events.rs`
so indexers decode one format across contracts.

| Topic | Data | Emitted by |
|---|---|---|
| `("escrow", "fund_rel", escrow_id)` | `EscrowSettlement { escrow_id, recipient, amount, timestamp }` | `release`, `override_release` |
| `("escrow", "fund_ref", escrow_id)` | `EscrowSettlement { escrow_id, recipient, amount, timestamp }` | `refund`, `refund_timelock`, `cancel`, `reclaim` |
| `("EscrowCreated",)` | `(escrow_id, sender, recipient, assets, deadline)` | creation paths |
| `("EscrowReleased",)` | `(escrow_id, recipient, assets)` | `release`, `override_release` |
| `("EscrowRefunded",)` | `(escrow_id, sender, assets)` | refund / cancel / reclaim paths |
| `("transfer", "executed")` | `(from, to, asset, amount)` | `release`, `override_release`, `withdraw`, `claim`, `cancel`, `reclaim`, milestone payouts |
| `("escrow", "approval")` | `(id, caller, approvals, threshold)` | `approve_release` |
| `("escrow", "tok_add" \| "tok_rm")` | `token` | `approve_token` / `revoke_token` |

In the `fund_rel` / `fund_ref` payload, `recipient` is the account the funds
moved to: the escrow's recipient on a release, its sender on a refund.
`amount` is the custody value that call moved, summed across assets (the unit
of `Escrow::funded_amount`), and `timestamp` is the ledger timestamp. The
escrow id is also the third topic, so a subscriber can follow one escrow
without decoding payloads. The legacy `("escrow", "released" | "refunded" |
"ref_tl" | "cancelled" | "reclaimed" | "override" | "expired")` tuple events
are still emitted for existing dashboards.

## Error codes

Codes are the shared `astroid_shared::errors::Error` values, so they mean the
same thing in every contract.

| Code | Error | When the escrow returns it |
|---|---|---|
| 1 | `NotFound` | Unknown escrow id, no release condition, or revoking an unlisted token. |
| 2 | `AlreadyExists` | Re-approving an already whitelisted token. |
| 3 | `Unauthorized` | Caller is not the recorded sender / arbiter / recipient / admin; override release on an escrow with no signer set. |
| 4 | `InvalidInput` | Empty or duplicate assets, more than `MAX_ESCROW_ASSETS` (10), `recipient == sender`, unlock time in the past, duplicate participants, whitelist full. |
| 5 | `NotInitialized` | Whitelist admin not recorded yet. |
| 6 | `AlreadyInitialized` | `initialize` called twice. |
| 10 | `InsufficientFunds` | `withdraw` asks for more than is currently claimable. |
| 11 | `Overflow` | Checked arithmetic overflowed (amount sums, pro-rata splits, deadlines). |
| 12 | `InvalidAmount` | Non-positive amount, or a release larger than the remaining balance. |
| 43 | `AssetNotAuthorized` | Token is not on the whitelist. |
| 53 | `InvalidState` | Transition not allowed from the current state (e.g. release after refund, cancel after the deadline, `release` on a milestone escrow). |
| 61 | `ThresholdNotMet` | Too few override signatures, or too few multi-party approvals. |
| 62 | `AlreadySigned` | Duplicate override signer, or a participant approving twice. |
| 63 | `NotASigner` | Override key or approving caller is outside the configured set. |
| 64 | `InvalidThreshold` | Threshold outside `[1, signers]`, or non-zero with an empty set. |
| 66 | `TooManySigners` | More than `MAX_SIGNERS` (20) override signers or participants. |
| 68 | `InvalidNonce` | Override nonce not strictly greater than the last one used. |
| 80 | `EscrowExpired` | `release` at or after `deadline + grace_period`, or `override_release` at or after `deadline`. |
| 81 | `TimeLockActive` | Refund before `deadline`; withdraw / claim with nothing vested; cancel once value has vested. |
| 82 | `GraceActive` | Refund / reclaim during `[deadline, deadline + grace_period)`. |
| 91 | `TimelockNotExpired` (`Error::EscrowLocked`) | Release before the schedule's cliff, or of unvested value on a `Linear` schedule. |

Milestone entry points use the narrower `MilestoneError` table:

| Code | Error | Meaning |
|---|---|---|
| 1 | `NotFound` | Escrow missing or has no milestone schedule. |
| 3 | `Unauthorized` | Caller may not review milestones. |
| 4 | `InvalidInput` | Malformed request. |
| 11 | `Overflow` | Milestone arithmetic overflowed. |
| 12 | `InvalidAmount` | Non-positive milestone payout. |
| 53 | `InvalidState` | Escrow refunded / schedule cancelled. |
| 86 | `InvalidMilestone` | Unknown index, or the milestone is disputed. |
| 87 | `MilestoneAlreadyCompleted` | Milestone was already paid. |

## Storage layout

Keys are the `DataKey` enum in [`src/storage.rs`](src/storage.rs).

| Key | Storage | Value | Notes |
|---|---|---|---|
| `Count` | instance | `u64` | Last escrow id issued; ids start at 1. |
| `Admin` | instance | `Address` | Whitelist admin set by `initialize`. |
| `ApprovedTokenList` | instance | `Vec<Address>` | Enumerable whitelist (≤ 32 entries). |
| `ApprovedToken(Address)` | persistent | `bool` | O(1) whitelist membership check on every deposit. |
| `Escrow(u64)` | persistent | `Escrow` | The escrow record (parties, assets, state, deadlines, schedule, override signer set and nonce). |
| `Milestones(u64)` | persistent | `MilestoneSet` | Present only for `deposit_with_milestones` escrows. |
| `ReleaseCondition(u64)` | persistent | `ReleaseCondition` | Present only when a multi-party condition was configured. |
| `ReleaseApproval(u64, Address)` | persistent | `bool` | One entry per approving participant. |

The upgrade binding lives under its own key type in
`interfaces/src/upgrade.rs` (instance storage), so it can never collide with
`DataKey`.

Design choices:

- **Per-escrow records are persistent.** They must outlive arbitrary idle
  periods between creation and settlement, and they scale with the number of
  escrows, so they never sit in instance storage, which is loaded on every
  call.
- **Optional data has its own key.** Milestones, release conditions and
  approvals are stored beside the `Escrow` rather than inside it. A plain
  escrow neither reads nor writes them, and records written by an earlier
  deployment still deserialize after an upgrade adds a new optional key.
- **One approval, one entry.** Recording an approval writes a single small
  entry instead of rewriting the whole condition, and the per-participant key
  makes a double vote impossible to miss.

## TTL management

TTL constants come from `shared/src/constants.rs` (`DAY_IN_LEDGERS` =
17 280, about 5 s per ledger):

| Storage | Threshold | Extended to |
|---|---|---|
| instance | `INSTANCE_LIFETIME_THRESHOLD` (6 days) | `INSTANCE_BUMP_AMOUNT` (7 days) |
| persistent | `PERSISTENT_LIFETIME_THRESHOLD` (29 days) | `PERSISTENT_BUMP_AMOUNT` (30 days) |

- **Instance** storage is extended in `initialize`, each time the escrow
  counter is incremented (every creation), and whenever the whitelist changes.
- **`Escrow(id)`** is extended on every write via `store_escrow` → `bump_escrow`,
  so every state transition (fund, release, withdraw, refund, close, …)
  renews the record for another 30 days.
- **`Milestones(id)`** is extended via `bump_milestones` after every write
  (creation, approval, dispute, resolution, cancellation), so a long-running
  phased agreement cannot lose its schedule between approvals.
- **`ReleaseCondition(id)` / `ReleaseApproval(id, who)`** are extended when
  written.
- **`ApprovedToken(token)`** is extended on approval and removed on
  revocation.

An escrow left idle for more than 30 days without a state change has its
entries archived, not deleted. They must be restored (`stellar contract
restore` or a `RestoreFootprint` operation) before the next call. Keepers
running long-dated escrows (long schedules, long refund windows) should
extend the TTL of `Escrow(id)` and its optional keys before they lapse.

## Time-lock release schedules

Escrows created through `create_timelock`, `create_scheduled` or
`initialize_timelock` carry a release schedule that is enforced on the ledger
clock (`env.ledger().timestamp()`) on every value-leaving path:

- `Cliff` schedules unlock 100% at `cliff_time` (= `end_time`); `Linear`
  schedules vest continuously between `start_time` and `end_time`, with an
  optional cliff.
- `withdraw` / `claim` are the beneficiary's partial-payout paths: they pay
  exactly the amount vested minus already released, and fail with
  `TimeLockActive` (81) while nothing is claimable.
- The arbiter's `release` and the signature-override path settle the escrow
  in full, so they are refused with `TimeLockActive` (81) while the
  outstanding balance has not fully vested on a `Linear` schedule, and
  before `cliff_time` on either schedule kind.
- `cancel` cannot route around the lock either: a scheduled escrow may only
  be cancelled while nothing has vested.
- Settlement paths move the remaining custody balance (funded minus released)
  pro-rata across the assets, so a release following partial withdrawals
  never over-draws custody.
- `is_unlocked(id)` reports whether the schedule has matured at the current
  ledger time so clients need not recompute it off-chain.

## Multi-party release conditions

`create_with_release_condition` takes the full creation argument set plus two
extra fields, `participants` (an allow-list of `Address`es) and
`approval_threshold`, and stores them as a `ReleaseCondition` beside the
escrow. Each participant then signs off on its own Soroban account via
`approve_release(id)`, which returns the running approval count. Once
`approvals >= approval_threshold`, the recipient can be paid.

The condition is **additive, not substitutive**: it never replaces the arbiter
or the override signatures, so a caller has to clear both gates. It is checked
on every path that moves value *to the recipient* on an escrow that carries one —
`release`, `override_release`, `claim` and `withdraw` — and is always
the last check before the first state mutation, so it can only ever prevent a
payout that would otherwise have succeeded (it never masks a more specific
error such as an expired deadline, an active time lock, or a double release).
Milestone escrows come from `deposit_with_milestones`, which never records a
condition, so `release_milestone` needs no gate.

The sender side is deliberately **not** gated. `cancel`, `refund`,
`refund_timelock` and `reclaim` stay open regardless of the approval count, so
a multi-party escrow can delay a payout but can never lock up the funder's
money — a condition on a stale dispute always still resolves back to the
depositor.

- Approvals require the caller's own `require_auth`, so no relayer can vote on
  a participant's behalf, and only while the escrow is `Funded` — a settled
  escrow has nothing left to sign off on.
- Approvals are recorded one storage key per participant, so a repeat approval
  fails with `AlreadySigned` (62) and can never inflate the count.
- A caller outside the participant set fails with `NotASigner` (63); an
  unmet threshold fails the payout with `ThresholdNotMet` (61).
- Creating with more than `MAX_SIGNERS` participants fails with
  `TooManySigners` (66); a threshold outside `[1, participants.len()]`, or a
  non-zero threshold with no participants, fails with `InvalidThreshold` (64);
  repeated participants fail with `InvalidInput` (4). The set is validated
  *before* any tokens move.
- An empty participant list with a `0` threshold records no condition at all,
  so such an escrow behaves exactly like one from `create` and pays nothing for
  the extra key.
- `get_release_condition` returns the stored condition (or `NotFound`), and
  `release_approvals` returns the participants that have signed off, in
  declaration order. `approve_release` also emits an
  `("escrow", "approval")` event carrying `(id, caller, approvals, threshold)`.

Because the condition lives under its own storage key rather than inside the
`Escrow` struct, single-party escrows neither read nor write it, and escrows
written by an earlier deployment keep deserializing after an upgrade.

## Invariants

- Caller must be the recorded role for `release` / `refund` / `close`.
- Every asset amount must be positive (shared `require_positive_amount`), the
  asset list may not be empty, exceed `MAX_ESCROW_ASSETS`, or repeat an asset.
- Releasing after the deadline auto-marks the escrow `Expired` and aborts.
- Override signatures must come from distinct, pre-configured signers and
  meet the threshold; a nonce is only accepted once and must strictly
  increase per escrow, which makes a captured signature set unusable a
  second time (replay protection).
- No path to the recipient's balance skips an unmet release condition, and no
  sender-side exit is blocked by one.
- `EscrowReleased` is emitted (via the shared, structured event schema)
  detailing the escrow id, recipient and every asset transferred, on both the
  arbiter and signature-override release paths.
- Every release path emits exactly one `("escrow", "fund_rel", id)` event and
  every refund path exactly one `("escrow", "fund_ref", id)` event. A refused
  call emits neither, because the invocation rolls back.

## Use-cases

- Milestone payments between ON-CHAIN purchased services.
- Agent-to-agent micro-settlement with audit trail.
- Marketplace / freelance payouts where a human arbiter adjudicates.
- Settlement that needs several independent sign-offs (buyer agent, seller
  agent and a validator oracle) before the recipient is paid.
