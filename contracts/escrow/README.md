# astroid-escrow

Escrow contract — temporary custody until a designated arbiter resolves the
release condition. A single agreement can hold several distinct Stellar
assets, and can optionally be released early by a set of pre-configured
ed25519 signers instead of the named arbiter.

```text
funder ──► create(sender, recipient, arbiter, assets[], deadline, memo,
                   release_signers[], release_threshold) ──► Escrow-Funded
                      │
                      ├─► arbiter.release(id)                     ──► Released ──► assets move
                      ├─► override_release(id, nonce, signatures) ──► Released ──► assets move
                      └─► sender.refund(id)                       ──► Refunded   (after deadline)
```

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

## Invariants

- Caller must be the recorded role for `release` / `refund` / `close`.
- Every asset amount must be positive (shared `require_positive_amount`), the
  asset list may not be empty, exceed `MAX_ESCROW_ASSETS`, or repeat an asset.
- Releasing after the deadline auto-marks the escrow `Expired` and aborts.
- Override signatures must come from distinct, pre-configured signers and
  meet the threshold; a nonce is only accepted once and must strictly
  increase per escrow, which makes a captured signature set unusable a
  second time (replay protection).
- `EscrowReleased` is emitted (via the shared, structured event schema)
  detailing the escrow id, recipient and every asset transferred, on both the
  arbiter and signature-override release paths.

## Milestone-based release

`deposit_with_milestones(sender, recipient, arbiter, asset, amount, deadline,
  memo, milestones[])` funds a single-asset escrow against an ordered list of
basis-point-weighted milestones (`MilestoneSpec { description, release_bps }`)
whose weights must sum to exactly `10_000` (100%).

- The arbiter approves one milestone at a time with
  `release_milestone(arbiter, id, index)`, which disburses that milestone's
  proportional share and marks it released.
- Each milestone may be approved **at most once** (a repeat approval fails with
  `InvalidState`) and an out-of-range `index` fails with `InvalidInput`.
- The final milestone pays the exact remainder rather than its floored gross,
  so the disbursed amounts always sum to the funded amount with no dust left in
  custody.
- The escrow's own `released_amount` tracks the milestone total, so
  `refund` / `reclaim` / `cancel` only ever return the still-held remainder.
- Plain `release` is refused on a milestone escrow (`InvalidState`); settlement
  must go through the phased approvals.

## Use-cases

- Milestone payments between ON-CHAIN purchased services.
- Agent-to-agent micro-settlement with audit trail.
- Marketplace / freelance payouts where a human arbiter adjudicates.
