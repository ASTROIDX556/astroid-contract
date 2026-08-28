# astroid-escrow

Escrow contract — temporary custody until a designated arbiter resolves the
release condition.

```text
funder ──► create(sender, recipient, arbiter, asset, amount, deadline) ──► Escrow-Funded
                      │
                      ├─► arbiter.release(id)      ──► Released ──▶ assets move
                      ├─► keeper.expire(id)        ──► Expired   (after deadline)
                      └─► anyone.cancel(id)         ──► Refunded  ──▶ back to sender (after deadline)
                          anyone.refund(id)        ──► Refunded  ──▶ back to sender (after deadline)
```

## State machine

`Created → Funded → (Released | Refunded | Expired) → Closed`

- `create` funds immediately (atomic in a single call).
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
