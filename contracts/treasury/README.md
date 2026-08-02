# astroid-treasury

Treasury contract — custody for organizational funds with policy + budget gates
on every outflow.

## Responsibilities

- `initialize(org, admin)` — DCP deploys the treasury for an org.
- `deposit(from, asset, amount)` — anyone can fund the pot.
- `withdraw(admin, asset, to, amount)` — policy + budget verified, then assets move.
- `set_policy(policy)` / `set_budget(budget)` — wire enforcement contracts.
- `freeze` / `unfreeze` — emergency stop on outflows.
- `allocate_budget(asset, budget_id)` — attach an envelope to an asset.

## Invariants

A withdrawal can only succeed when:
1. The caller is the recorded admin (`require_auth` gated).
2. The treasury is not frozen.
3. The policy contract's `check_transfer` passes (when wired).
4. The budget's `consume` does not return `BudgetExceeded` (when wired).
5. The treasury's tracked balance for the asset covers the request.

## Events

- `("treasury", "deposited")` on every deposit.
- `("transfer", "executed")` on successful withdrawals (shared standard).
- `("treasury", "policy")` / `("treasury", "budget")` when enforcement contracts are wired.

## Cross-contract flow

```text
Treasury.withdraw ──► PolicyClient (Policy contract)
                  ──► BudgetClient (Budget contract)
                  ──► events::transfer_executed
```

Both dependencies use the typed interfaces in `astroid-interfaces` so the
workspace graph stays acyclic.
