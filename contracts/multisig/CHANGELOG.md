# Changelog — multisig

## Threshold validation via shared events (Issue #472)

- `propose`, `approve` and `execute` publish the standard
  `proposal/created`, `proposal/approved` and `proposal/executed` events
  through `astroid_shared::events` (new `events::proposal_executed` helper).
  Topics and payloads are unchanged, so existing consumers see identical
  events. `proposal/approved` carries the aggregated signer weight that
  the threshold is measured against.
- Added the cross-contract integration suite `tests/src/multisig_integration.rs`.
  It covers weighted aggregation (3/2/1 against threshold 4), exact-threshold
  execution, duplicate and outsider approvals, the live tally after a signer is
  removed, replay protection for executed proposals and batch nonces,
  signature-verified batches that freeze and unfreeze the treasury and allocate
  a budget, `verify_threshold`, and the emergency lock.

Closes #472


- Implement dynamic signature threshold adjustment: proposals for threshold updates are validated against current signer weight, timelocked, re-validated at execution time, and emit `threshold/changed` on success.

Notes:
- Tests for threshold proposals, execution, cancellation, and bounds are present in `src/test.rs`.

Closes #118
