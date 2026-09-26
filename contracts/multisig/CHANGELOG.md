# Changelog — multisig

- Implement dynamic signature threshold adjustment: proposals for threshold updates are validated against current signer weight, timelocked, re-validated at execution time, and emit `threshold/changed` on success.

Notes:
- Tests for threshold proposals, execution, cancellation, and bounds are present in `src/test.rs`.

Closes #118

- Evaluate cumulative approval weight against the live threshold: `execute` now shares a single `evaluate_quorum` helper with a new read-only [`get_approval_weight`](src/lib.rs) view, so the weight callers observe is exactly what execution enforces. Approval weight still recomputes against the live signer set, so removed signers stop counting and duplicate ballots never stack.

Notes:
- Weighted quorum scenarios (e.g. weights 50/30/30 against threshold 80, exact-boundary, duplicate ballots, removed-approver reweighting) are covered in `src/test.rs`.

Closes #24
