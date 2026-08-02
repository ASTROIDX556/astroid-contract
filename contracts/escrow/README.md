# astroid-escrow

Escrow contract — temporary custody until a designated arbiter resolves the
release condition.

```text
funder ──► create(sender, recipient, arbiter, asset, amount, deadline) ──► Escrow-Funded
                      │
                      ├─► arbiter.release(id)      ──► Released ──► assets move
                      └─► sender.refund(id)         ──► Refunded   (after deadline)
```

## State machine

`Created → Funded → (Released | Refunded | Expired) → Closed`

- `create` funds immediately (atomic in a single call).
- `release` requires the arbiter and a live deadline.
- `refund` is permissionless after the deadline — a beneficiary that never
  claims and an absent arbiter default back to the funder.
- `close` (terminal) requires one of the three roles once the escrow is final.

## Invariants

- Caller must be the recorded role for `release` / `refund` / `close`.
- Amounts must be positive (shared `require_positive_amount`).
- Releasing after the deadline auto-marks the escrow `Expired` and aborts.

## Use-cases

- Milestone payments between ON-CHAIN purchased services.
- Agent-to-agent micro-settlement with audit trail.
- Marketplace / freelance payouts where a human arbiter adjudicates.
