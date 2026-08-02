# astroid-policy

Policy contract — hash-verified enforcement of financial rules.

The backend manages human-readable policy JSON (e.g. `{ maxAmount: 25000, recipients: [...], window: {...} }`). This contract stores only:

- a SHA-256 `config_hash` of that JSON (tamper-evidence),
- a small set of scalar gates that are cheap to check on-chain (`max_amount`, `allowed_recipient`, `allowed_asset`, `expires_at`).

The [`check_transfer`](src/lib.rs) entry point evaluates a proposed transfer
against a named policy and returns [`Error::PolicyDenied`] when any gate fails.
Violations emit a `PolicyViolation` event so the backend's analytics / audit
modules can record the block.

## Why hash-verified?

Storing `config_hash` instead of the full JSON keeps storage cost minimal and
makes upgrades fast — the backend rotates the hash when a policy is updated.
Because the recorded max/timing gates live on-chain too, the verification path
stays fully deterministic and cheap.

## Operations

- `register_policy` — install a new policy.
- `rotate_policy` — replace hash + max threshold (owner-gated).
- `set_enabled` — disable (deny-all) or re-enable.
- `check_transfer` (via [`PolicyInterface`]) — called by treasury / wallet.

## Events

- `("policy", "registd")` on registration.
- `("policy", "rotated")` on rotation.
- `("policy", "violation")` on every denial, with a short `Symbol` reason.
