# astroid-budget

Budget contract — time-windowed spending limits with rollover, deficit carryforward, and per-asset allowances.

## Responsibilities

- `initialize(admin)` — protocol admin bootstraps the contract.
- `allocate(owner, budget_id, limit, period, rollover_enabled, expires_at)` — create a one-shot or recurring budget scoped to an owner.
- `allocate_with_deficit(..., allow_deficit)` — create a budget that permits spending beyond its limit, accumulating a deficit repaid in future periods.
- `allocate_scheduled(..., start_at, expires_at)` — create a budget that activates at a future timestamp.
- `allocate_with_rollover(..., rollover_bps, max_rollover_cap)` — create a budget with explicit rollover percentage and cap.
- `set_recurrence(budget_id, period, period_seconds, rollover_enabled, rollover_cap, rollover_max_bps)` — configure or change the recurring window and rollover policy.
- `set_rollover_config(budget_id, rollover_enabled, rollover_bps, max_rollover_cap)` — adjust rollover accounting mid-cycle.
- `consume(owner, budget_id, amount)` — debit the budget; reverts with `BudgetExceeded` when the effective ceiling (limit + rollover_credit − deficit) is breached.
- `check_and_record_spend(owner, budget_id, token, amount)` — atomic per-asset spend against a registered token allowance (Issue #294).
- `check_and_record_batch_spend(owner, budget_id, spends[])` — validate and record multi-token spends atomically; duplicate tokens rejected.
- `release(owner, budget_id, amount)` — credit amount back (refund/cancel); cannot exceed spent.
- `reset(owner, budget_id)` — zero spent and rollover_credit; re-anchor window to now.
- `rollover(owner, budget_id)` — force a period transition, applying rollover/deficit logic.
- `set_limit(owner, budget_id, new_limit)` — raise or lower the base limit (must be ≥ spent).
- `transfer_allocation(owner, from_id, to_id, amount)` — move unspent allocation between two budgets sharing the same owner.
- `freeze(owner, budget_id)` / `unfreeze(owner, budget_id)` — pause/resume consumption without archiving.
- `archive(owner, budget_id)` — terminal state; no further spends or config changes.
- `set_budget_limit(owner, budget_id, token, limit, window_seconds)` — register a per-asset recurring allowance.
- `set_budget_limit_with_rollover(..., rollover_enabled, rollover_bps, max_rollover_cap)` — register per-asset allowance with rollover.
- `set_asset_rollover_config(budget_id, token, rollover_enabled, rollover_bps, max_rollover_cap)` — adjust per-asset rollover.
- `remaining(budget_id)` — view current effective allowance (limit + rollover_credit − deficit − spent).
- `asset_remaining(budget_id, token)` — view per-asset allowance in current window.
- `get(budget_id)` — full budget record.
- `get_asset_budget(budget_id, token)` — full per-asset record (settles window first).
- `rollover_preview(budget_id)` — read-only preview of the next period transition (Issue #313).

## Invariants

A `consume` succeeds only when:

1. Caller is the recorded owner (`require_auth` gated).
2. Budget is `Active` (not `Frozen`, `Paused`, or `Archived`).
3. Ledger time ≥ `window_start` (scheduled budgets wait for activation).
4. Ledger time < `expires_at` (if set).
5. `amount > 0`.
6. `spent + amount ≤ limit + rollover_credit − deficit_amount`.

Period transitions are **lazy and catch-up correct**: every view or spend evaluates the transition hook first. If `n` whole windows elapsed since `window_start`, all `n` settle at once and `window_start` re-anchors to the period boundary — never to "now" — so windows never drift.

Rollover credit is **clamped to the effective cap** = `min(rollover_cap, limit × rollover_max_bps / 10_000)`. The closing balance **replaces** the carried credit rather than stacking, so an idle budget gains exactly one base limit per period.

Deficit carryforward (`allow_deficit`) requires a recurring period (`Daily`, `Weekly`, or `Monthly` with interval). The overspend becomes `deficit_amount` on transition, reducing next period's effective capacity by that amount.

Per-asset allowances (`set_budget_limit`) have independent windows. `check_and_record_batch_spend` validates all legs before persisting any; duplicate tokens are rejected to prevent cap bypass.

## Storage Layout

### Instance Storage

| Key | Type | Description |
|-----|------|-------------|
| `Admin` | `Address` | Protocol admin (initialize only; all operations owner-gated). |

### Persistent Storage

| Key | Type | Description |
|-----|------|-------------|
| `Budget(String)` | `Budget` | Main budget record keyed by `budget_id`. |
| `AssetBudget(String, Address)` | `AssetBudget` | Per-asset allowance record keyed by `(budget_id, token)`. |

### Budget Record Fields

- `owner: Address` — authorized consumer and administrator.
- `limit: i128` — base spending limit per period.
- `spent: i128` — cumulative spend in current window.
- `period: Period` — `None` (one-shot), `Daily`, `Weekly`, `Monthly`, or `Custom`.
- `period_seconds: u64` — interval for `Custom`; 0 otherwise.
- `window_start: u64` — start of current window (unix seconds); also scheduled activation time.
- `rollover_enabled: bool` — whether unspent carries forward.
- `rollover_credit: i128` — unspent carried from prior periods (clamped to effective cap).
- `rollover_cap: i128` — absolute cap on rollover_credit (0 = uncapped).
- `rollover_max_bps: i128` — protocol percentage ceiling on rollover (0 = uncapped).
- `rollover_bps: i128` — percentage of unspent to carry (basis points).
- `allow_deficit: bool` — whether overspend is permitted.
- `deficit_amount: i128` — overspend carried from prior periods.
- `expires_at: u64` — expiry timestamp (0 = never).
- `state: ResourceState` — `Active`, `Frozen`, `Paused`, `Archived`.

### AssetBudget Record Fields

- `limit: i128` — per-asset base limit.
- `spent: i128` — cumulative spend in current asset window.
- `window_seconds: u64` — asset window length (0 = one-shot).
- `window_start: u64` — start of current asset window.
- `rollover_enabled: bool` — whether unspent carries forward.
- `rollover_credit: i128` — unspent carried from prior asset periods.
- `rollover_bps: i128` — rollover percentage (basis points).
- `max_rollover_cap: i128` — absolute cap on asset rollover_credit.

## Error Codes

All errors use the shared [`Error`] enum from `astroid-shared` (re-exported as `BudgetError` for budget-specific codes):

| Condition | Error Code |
|-----------|------------|
| Spend/release/transfer amount ≤ 0 | `InvalidAmount` (12) |
| Negative limit or rollover cap | `InvalidAmount` (12) |
| Limit below spent, expiry passed, malformed period | `InvalidInput` (4) |
| Spend exceeds effective ceiling | `BudgetExceeded` (40) |
| Checked arithmetic overflow | `Overflow` (11) |
| Caller not budget owner | `Unauthorized` (3) |
| Budget frozen | `BudgetFrozen` (41) |
| Budget archived | `BudgetArchived` (42) |
| Budget expired (time) | `BudgetExpired` (44) |
| Budget not yet active (scheduled) | `BudgetNotActive` (45) — `BudgetError` only |
| Token not registered for per-asset spend | `AssetNotAuthorized` (43) |
| Duplicate token in batch spend | `InvalidInput` (4) |

Budget-specific codes (`BudgetError`) mirror the shared codes where applicable. `BudgetNotActive` (45) is unique to `BudgetError`; it folds to `BudgetExpired` when converted to the shared `Error`.

## Events

- `("budget", "allocated")` — `(budget_id, owner, limit)` on creation.
- `("budget", "recurring")` — `(budget_id, period, period_seconds, rollover_cap)` on `set_recurrence`.
- `("budget", "rollover")` — `(budget_id, rollover_bps, max_rollover_cap)` on `set_rollover_config`.
- `("budget", "reset")` — `budget_id` on manual reset.
- `("budget", "frozen")` / `("budget", "unfrozen")` / `("budget", "archived")` — lifecycle changes.
- `("budget", "setlimit")` — `(budget_id, new_limit)` on limit change.
- `("budget", "realloc")` — `(from_id, to_id, amount)` on `transfer_allocation`.
- `("budget", "set_ast")` — `(budget_id, token, limit)` on `set_budget_limit`.
- `("budget", "set_ast")` — same topic on `set_budget_limit_with_rollover`.
- `("budget", "ast_roll")` — `(budget_id, token, rollover_bps, max_rollover_cap)` on `set_asset_rollover_config`.
- `("budget", "ast_spend")` — `(budget_id, token, amount)` on per-asset spend.
- `BudgetUpdated` (canonical `ContractEvent`) — emitted on every state change.

## Cross-contract Flow

```text
Treasury.withdraw ──► BudgetClient.consume(caller, budget_id, amount)
                     ──► returns remaining or BudgetExceeded
```

The Treasury contract calls `BudgetClient::consume` before moving tokens. The budget debits atomically; if the spend would breach the ceiling the call reverts and no tokens move.

## Design Notes

- **No external cron**: Period transitions are evaluated lazily on every read/spend. A dormant budget catches up correctly when next accessed.
- **Half-open windows**: `[window_start, window_start + duration)`. The boundary timestamp belongs to the *next* period.
- **Rollover does not compound across gaps**: Idle periods contribute one base limit each; the prior window's remainder carries once. The effective cap prevents runaway accrual.
- **Deficit repayment**: On transition, `deficit_amount` is subtracted from the next period's effective capacity. The budget must "earn back" the overspend.
- **Scheduled activation**: `allocate_scheduled` with `start_at > now` blocks all spends until the ledger reaches that timestamp (`BudgetNotActive`).
- **Checked arithmetic everywhere**: All value math uses shared helpers that return `Error::Overflow` instead of panicking.
- **Per-asset atomicity**: `check_and_record_batch_spend` validates the full batch before writing any leg, so a partial failure leaves all allowances untouched.

## Constants

- `MAX_BATCH_TOKENS` — maximum tokens in a single `check_and_record_batch_spend` (bounds gas).
- `BPS_DENOMINATOR = 10_000` — basis point denominator for rollover percentages.
- `SECONDS_PER_DAY = 86_400`, `SECONDS_PER_WEEK = 604_800`, `SECONDS_PER_MONTH = 2_629_746`.

## Testing

Run the unit test suite:

```bash
cargo test -p astroid-budget
```

Key test modules cover:
- Basic allocation, consumption, reset, freeze, archive.
- Recurring windows: daily/weekly/monthly/custom, catch-up, drift prevention.
- Rollover: enabled/disabled, caps (absolute + percentage), credit replacement.
- Deficit carryforward: overspend, repayment, combined with rollover.
- Per-asset allowances: independent windows, batch atomicity, duplicate rejection.
- Boundary conditions: exact timestamps, expiry vs rollover, max values, overflow safety.
- Rollover preview: read-only equivalence with live transition.