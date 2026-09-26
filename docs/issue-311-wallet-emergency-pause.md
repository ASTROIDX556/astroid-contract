# Wallet emergency pause circuit breaker

This branch tracks the wallet emergency pause work for the circuit-breaker mechanism described in issue #311.

## Scope
- Add a persistent contract-wide pause flag to the wallet.
- Restrict state toggling to authorized owners / guardians using the wallet's auth model.
- Refuse outgoing transfers and withdrawals while the wallet is paused.
- Emit pause state change events and keep recovery paths available once unpaused.
- Verify the pause/unpause lifecycle with wallet unit tests.

## Verification
The contract is validated with:

```bash
cargo test -p astroid-wallet
```

Current result in this environment: 51 passed, 0 failed.

Closes #311
