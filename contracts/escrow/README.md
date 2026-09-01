# astroid-escrow

Escrow contract — temporary custody until a designated arbiter resolves the
release condition, or a pre-configured signer quorum overrides it.

```text
funder ──► create(sender, recipient, arbiter, assets[], deadline, memo,
                  release_signers[], release_threshold)      ──► Escrow-Funded
                      │
                      ├─► arbiter.release(id)      ──► Released ──▶ assets move
                      ├─► keeper.expire(id)        ──► Expired   (after deadline)
                      └─► anyone.cancel(id)         ──► Refunded  ──▶ back to sender (after deadline)
                          anyone.refund(id)        ──► Refunded  ──▶ back to sender (after deadline)
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
- `expire` is a permissionless status marker that flips a timed-out `Funded`
  escrow to `Expired` once the deadline passes (a keeper/UI may call it).
- `cancel` is the permissionless auto-cancellation path: after the deadline any
  caller may cancel the escrow, which auto-expires it (if still funded) and
  returns the locked funds to the original depositor — no arbiter or multi-party
  signature required.
- `refund` is permissionless after the deadline — a beneficiary that never
  claims and an absent arbiter default back to the funder.
- `close` (terminal) requires one of the three roles once the escrow is final.

## Invariants

- Caller must be the recorded role for `release` / `close`.
- Amounts must be positive (shared `require_positive_amount`).
- Releasing after the deadline is refused with `EscrowExpired`; the escrow is
  NOT auto-marked expired — a keeper/anyone calls `expire` or `cancel` instead.
- After the deadline, `cancel` / `refund` are permissionless: any caller may
  return the locked funds to the original depositor (auto-cancellation).

## Use-cases

- Milestone payments between ON-CHAIN purchased services.
- Agent-to-agent micro-settlement with audit trail.
- Marketplace / freelance payouts where a human arbiter adjudicates.
- Multi-currency settlements requiring an emergency signer-quorum override.
