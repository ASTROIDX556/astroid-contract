# astroid-escrow

Escrow contract — temporary custody until a designated arbiter resolves the
release condition, or a pre-configured signer quorum overrides it.

```text
funder ──► create(sender, recipient, arbiter, assets[], deadline, memo,
                  release_signers[], release_threshold)      ──► Escrow-Funded
                      │
                      ├─► arbiter.release(id)                ──► Released ──► assets move
                      ├─► release_with_signatures(id, nonce,
                      │       signatures[])                  ──► Released ──► assets move
                      └─► sender.refund(id)                  ──► Refunded   (after deadline)
```

## Multi-asset

An escrow holds a **list** of `(asset, amount)` pairs (`Vec<AssetAmount>`,
shared type) instead of a single token, so one agreement can bundle several
Stellar assets. All configured assets are pulled into custody atomically on
`create` and move together on `release` / `refund`.

## Manual release override

`create` optionally takes a set of Ed25519 public keys (`release_signers`) and
an `M`-of-`N` threshold (`release_threshold`). Once configured, holders of
those keys can jointly authorize `release_with_signatures` to release the
escrow to the recipient regardless of the arbiter/deadline path — e.g. an
off-chain dispute-resolution quorum.

- Each signature is verified on-chain with `env.crypto().ed25519_verify`
  (the host's `verify_sig_ed25519` function) over a payload built from the
  escrow id and a caller-chosen `nonce` (big-endian `id || nonce`).
- Binding the id stops a signature from one escrow authorizing release of
  another; a per-escrow `(id, nonce)` usage record stops the same signed
  payload from ever being replayed.
- Pass an empty `release_signers` (and threshold `0`) to disable the override
  path for a given escrow.

## State machine

`Created → Funded → (Released | Refunded | Expired) → Closed`

- `create` funds immediately (atomic in a single call), pulling every listed
  `(asset, amount)` pair into custody.
- `release` requires the arbiter and a live deadline.
- `release_with_signatures` requires a threshold of override signatures and
  works regardless of the deadline.
- `refund` is permissionless after the deadline — a beneficiary that never
  claims and an absent arbiter default back to the funder.
- `close` (terminal) requires one of the three roles once the escrow is final.

## Invariants

- Caller must be the recorded role for `release` / `refund` / `close`.
- Amounts must be positive (shared `require_positive_amount`); the asset list
  must be non-empty, capped (`MAX_ESCROW_ASSETS`), and duplicate-free.
- `release_signers` must be duplicate-free and capped
  (`MAX_RELEASE_SIGNERS`); `release_threshold` must fall within
  `[MIN_THRESHOLD, release_signers.len()]`, or be `0` when no signers are
  configured.
- Releasing after the deadline auto-marks the escrow `Expired` and aborts.
- A given `(escrow id, nonce)` pair authorizes at most one
  `release_with_signatures` call, ever.
- `EscrowReleased` (topic `("escrow", "released")`) is emitted on every
  release, detailing the recipient, every asset transferred, and which path
  (`"arbiter"` or `"sigs"`) authorized it.

## Use-cases

- Milestone payments between ON-CHAIN purchased services.
- Agent-to-agent micro-settlement with audit trail.
- Marketplace / freelance payouts where a human arbiter adjudicates.
- Multi-currency settlements requiring an emergency signer-quorum override.
