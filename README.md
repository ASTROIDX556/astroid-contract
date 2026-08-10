# astroid-contract

> Soroban smart contracts — the **blockchain layer** of Astroid, the Financial Operating System for autonomous AI agents on Stellar.

These contracts are the on-chain enforcement point for Astroid's financial governance. Humans define policies, budgets, and approval rules off-chain; these contracts make the constraints that reach Stellar deterministic, tamper-evident, and auditable. Every large transfer is gated by policy checks, budget limits, and — where required — multisignature approval before it ever settles.

## Contracts

| Contract | Responsibility |
| --- | --- |
| `registry` | Directory of agents, wallets, and contract addresses; the on-chain source of truth for identity. |
| `wallet` | Per-agent smart wallet — balances, controlled transfers, freeze/archive lifecycle. |
| `policy` | Hash-verified spending rules; cheap on-chain gates (`max_amount`, allowed recipient/asset, expiry). |
| `budget` | Rolling spend limits with window accounting and enforcement. |
| `multisig` | M-of-N approval quorum for sensitive operations. |
| `proposal` | Proposal lifecycle (create → approve → execute / expire) with permissionless expiry. |
| `escrow` | Conditional release / refund for AI-to-AI settlement. |
| `treasury` | Organization-level custody and orchestrated payouts under policy + multisig. |

Shared code lives in [`shared/`](shared) (error codes, storage helpers, types) and the cross-contract call surface in [`interfaces/`](interfaces).

## Layout

```
contracts/     one crate per contract (registry, wallet, policy, budget, multisig, proposal, escrow, treasury)
shared/        astroid-shared — errors, storage keys, common types
interfaces/    astroid-interfaces — trait definitions for cross-contract calls
Cargo.toml     workspace manifest
```

## Prerequisites

- Rust `1.97+` with the `wasm32-unknown-unknown` target: `rustup target add wasm32-unknown-unknown`
- [Stellar CLI](https://developers.stellar.org/docs/tools/cli) `27.x` (`stellar contract …`) for deployment

## Build & test

```bash
# Run the full unit-test suite (native)
cargo test

# Build optimized, deployable WASM for every contract
cargo build --target wasm32-unknown-unknown --release
# → target/wasm32-unknown-unknown/release/astroid_*.wasm
```

## Deploy (testnet)

```bash
stellar contract deploy \
  --wasm target/wasm32-unknown-unknown/release/astroid_wallet.wasm \
  --network testnet \
  --source <your-key>
```

## Design notes

- **Errors roll back state.** Returning `Err` discards every storage write from that invocation. Terminal transitions that must persist (e.g. proposal expiry, escrow refund) are exposed as their own `Ok`-returning entrypoints rather than lazily applied on a failing read path.
- **Error codes are a frozen ABI.** Variant *names* are not stored on-chain — only numeric codes, grouped by domain in [`shared/src/errors.rs`](shared/src/errors.rs). Tests assert typed errors via the generated `client.try_<method>(…)` surface, not panic-string matching.
- **Policies are hash-verified.** The `policy` contract stores a SHA-256 hash of the human-readable rule JSON plus a few cheap scalar gates, keeping storage minimal and verification deterministic.

## License

MIT — see [LICENSE](LICENSE). Part of the [Astroid](https://github.com/ASTROIDX556) open-source platform.
