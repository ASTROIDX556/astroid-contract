# Contributing to Astroid Contracts

Thanks for your interest in improving the smart contracts for Astroid — the
Financial Operating System for autonomous AI agents on Stellar. We develop in
the open and welcome issues, discussion, and pull requests.

## Getting started

```bash
git clone https://github.com/ASTROIDX556/astroid-contract.git
cd astroid-contract
cargo build                                     # build all contracts
cargo test                                      # run the test suites
stellar contract build                          # build optimized WASM
```

This is a **Cargo workspace** containing 8 core Soroban smart contracts plus
shared libraries and interface definitions.

## Ground rules

- **Minimize on-chain logic.** Only store what must be trusted by everyone.
  Never store AI reasoning, chat history, analytics, or UI state.
- **Verify, don't think.** Backend computes → Contract verifies → Execute.
  Contracts never make subjective decisions.
- **Deterministic error codes.** Every error type is a named constant
  (`INSUFFICIENT_FUNDS`, `POLICY_DENIED`, `BUDGET_EXCEEDED`, etc.).
- **Conventional Commits.** `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`.
- **Tests are required.** Unit, integration, and edge-case tests. Target 100%
  coverage for critical financial logic.
- **Gas optimization.** Minimize storage writes, reuse data structures, emit
  concise events, batch operations, avoid redundant lookups.

## Pull request checklist

1. `cargo build && cargo test` all pass.
2. New contracts include `README.md` explaining the purpose, interface, and storage layout.
3. Events follow the standard naming conventions in `shared/events.rs`.
4. Error codes are added to `shared/errors.rs`.

## Branch strategy

`main` is always releasable. Use `feature/*` and `fix/*` branches and open PRs
against `main`. See the PRD (Document 3) for the full branching model.

By contributing you agree that your contributions are licensed under the MIT License.
