# astroid-budget

Budget contract: spending envelopes that every outflow is debited against.

The treasury (or any contract holding a `BudgetClient`) calls
[`consume`](src/lib.rs) before value moves. A spend that would push the
budget past its ceiling reverts with `BudgetExceeded`, so an agent can never
spend more than the organization allocated, however many transactions it
sends.

## Responsibilities

- Hold one spending envelope per backend-owned `budget_id`, owned by the
  address that allocated it (normally the treasury admin or the org owner).
- Enforce `spent + amount <= limit + rollover_credit` on every debit, with
  checked `i128` math. The limit grows by `deficit_amount` instead when the
  budget allows a deficit.
- Reset recurring budgets lazily at period boundaries (`Daily`, `Weekly`,
  `Monthly`, or `Custom` seconds). This needs no cron or keeper.
- Optionally carry unspent allowance into the next period (rollover), bounded
  by an absolute cap and a percentage ceiling.
- Track independent per-token allowances under the same budget id, and debit
  several tokens atomically.
- Lifecycle controls: freeze / unfreeze, archive (terminal), expiry,
  scheduled start, and moving allocation between two budgets.

## Public interface

All mutating functions are owner-gated (`caller.require_auth()` plus an
owner match) unless noted.

### Setup and allocation

| Function | Description |
|---|---|
| `initialize(admin)` | One-time setup. Records a protocol admin; budget operations remain owner-gated. |
| `allocate(owner, budget_id, limit, period, rollover_enabled, expires_at)` | Create a budget. `expires_at = 0` means it never expires. |
| `allocate_with_deficit(owner, budget_id, limit, period, rollover_enabled, allow_deficit, expires_at)` | As `allocate`, optionally allowing overspend that is carried as a deficit into the next period. A deficit requires a `Daily` / `Weekly` / `Monthly` period. |
| `allocate_scheduled(owner, budget_id, limit, period, rollover_enabled, start_at, expires_at)` | Create a budget that only becomes spendable at `start_at`. |
| `allocate_with_rollover(owner, budget_id, limit, period, rollover_enabled, rollover_bps, max_rollover_cap, expires_at)` | Create a budget with explicit rollover percentage and cap. |

### Configuration

| Function | Description |
|---|---|
| `set_recurrence(caller, budget_id, period, period_seconds, rollover_enabled, rollover_cap, rollover_max_bps)` | Change cadence and rollover policy. Settles any transition already due, then re-anchors the window to now. |
| `set_rollover_config(caller, budget_id, rollover_enabled, rollover_bps, max_rollover_cap)` | Change rollover accounting only. |
| `set_limit(caller, budget_id, new_limit)` | Change the limit. It must stay `>=` the amount spent in the current window. |
| `transfer_allocation(caller, from_id, to_id, amount)` | Move unused allocation between two budgets with the same owner. |

### Spending (`BudgetInterface`)

| Function | Description |
|---|---|
| `consume(caller, budget_id, amount) -> i128` | Debit `amount` and return what remains. Applies any pending period transition first. |
| `release(caller, budget_id, amount) -> i128` | Credit back a refunded or cancelled spend. The amount cannot exceed what was spent this period. |
| `remaining(budget_id) -> i128` | Remaining allocation, read as of the current period. |

### Lifecycle

| Function | Description |
|---|---|
| `reset(caller, budget_id)` | Zero the spent counter and refresh the window. |
| `rollover(caller, budget_id)` | Force a period transition. This is the only manual rollover path. |
| `freeze` / `unfreeze(caller, budget_id)` | Block / restore consumption. |
| `archive(caller, budget_id)` | Terminal. The budget can no longer be spent. |

### Per-token allowances

| Function | Description |
|---|---|
| `set_budget_limit(caller, budget_id, token, limit, window_seconds)` | Register a per-token limit that recurs every `window_seconds`. `0` means it never resets. |
| `set_budget_limit_with_rollover(caller, budget_id, token, limit, window_seconds, rollover_enabled, rollover_bps, max_rollover_cap)` | As above, with rollover. |
| `set_asset_rollover_config(caller, budget_id, token, rollover_enabled, rollover_bps, max_rollover_cap)` | Change per-token rollover only. |
| `check_and_record_spend(caller, budget_id, token, amount)` | Debit one token's allowance. |
| `check_and_record_batch_spend(caller, budget_id, spends: Vec<AssetSpend>)` | All-or-nothing debit across up to `MAX_BATCH_TOKENS` distinct tokens. Duplicate tokens are rejected. |

### Views

| Function | Description |
|---|---|
| `get(budget_id) -> Budget` | Stored budget record. |
| `get_asset_budget(budget_id, token) -> AssetBudget` | Per-token record, with any due window reset applied. |
| `asset_remaining(budget_id, token) -> i128` | Remaining per-token allowance in the current window. |
| `rollover_preview(budget_id) -> RolloverOutcome` | Pure preview of what the next period boundary would carry over. |

### Upgrades (`UpgradeableInterface`)

`set_upgrade_authority`, `get_upgrade_authority`, and `upgrade(caller,
wasm_hash)`. An upgrade requires the recorded upgrade admin and a Wasm hash
the registry approved for `ModuleKind::Budget`.

## Period and rollover rules

- Windows are half-open: `[window_start, window_start + duration)`. A ledger
  timestamp equal to the window end already belongs to the next window.
- When `n` whole windows have elapsed, the transition settles all of them in
  one step and re-anchors `window_start` to the boundary, not to "now", so
  windows never drift.
- Rollover does not compound across idle windows. The carried credit is
  clamped to the effective cap, which is the smaller of `rollover_cap`
  (absolute, `0` means uncapped) and `rollover_max_bps` of the base limit
  (`0` means uncapped). A dormant budget therefore cannot build up several
  periods of allowance for an agent to drain at once.
- `Period` values: `None = 0`, `Daily = 1` (86 400 s), `Weekly = 2`
  (604 800 s), `Monthly = 3` (2 592 000 s), `Custom = 4` (`period_seconds`).

## Storage layout

| Key (`DataKey`) | Tier | Value |
|---|---|---|
| `Admin` | instance | `Address`: protocol admin set at `initialize`. |
| `Budget(budget_id: String)` | persistent | `Budget` record (below). |
| `AssetBudget(budget_id: String, token: Address)` | persistent | `AssetBudget` record (below). |

`Budget` fields: `owner`, `limit`, `spent`, `period`, `period_seconds`,
`window_start` (also the scheduled activation time), `rollover_enabled`,
`rollover_credit`, `rollover_cap`, `rollover_max_bps`, `rollover_bps`,
`allow_deficit`, `deficit_amount`, `expires_at`, `state: ResourceState`.

`AssetBudget` fields: `limit`, `spent`, `window_seconds`, `window_start`,
`rollover_enabled`, `rollover_credit`, `rollover_bps`, `max_rollover_cap`.

## Error codes

Codes come from the shared table in `shared/src/errors.rs`. `consume`,
`check_and_record_spend` and `check_and_record_batch_spend` return
`BudgetError`, which uses the same numeric codes plus `BudgetNotActive`.

| Code | Name | When |
|---|---|---|
| 1 | `NotFound` | Unknown `budget_id`. |
| 2 | `AlreadyExists` | `allocate*` with an id that is already in use. |
| 3 | `Unauthorized` | Caller is not the budget owner. |
| 4 | `InvalidInput` | Limit below spent, expiry in the past, malformed period, duplicate batch token, empty or oversized batch. |
| 6 | `AlreadyInitialized` | `initialize` called twice. |
| 11 | `Overflow` | Checked arithmetic would leave the `i128` range. |
| 12 | `InvalidAmount` | Spend, release, or transfer `<= 0`, or a negative limit or cap. |
| 40 | `BudgetExceeded` | The spend would pass the effective ceiling. Nothing is spent. |
| 41 | `BudgetFrozen` | Budget is frozen. |
| 42 | `BudgetArchived` | Budget is archived. |
| 43 | `AssetNotAuthorized` | Token has no per-asset allowance registered. |
| 44 | `BudgetExpired` | Ledger time is at or past `expires_at`. |
| 45 | `BudgetNotActive` | Ledger time is before a scheduled start (`BudgetError` only). |

## Events

Contract-local tuple topics, all under the `budget` category:

| Topic | Data |
|---|---|
| `("budget", "allocated")` | `(budget_id, owner, limit)` |
| `("budget", "recurring")` | `(budget_id, period, period_seconds, rollover_cap)` |
| `("budget", "rollover")` | `(budget_id, rollover_bps, max_rollover_cap)` on config change; `(budget_id, amount)` on a period transition |
| `("budget", "reset")` | `budget_id` (manual reset); `(budget_id, amount)` on a period transition |
| `("budget", "deficit")` | `(budget_id, amount)`: period transition that carried an overspend forward |
| `("budget", "expired")` | `budget_id` |
| `("budget", "setlimit")` | `(budget_id, new_limit)` |
| `("budget", "frozen")` / `("budget", "unfrozen")` / `("budget", "archived")` | `budget_id` |
| `("budget", "realloc")` | `(from_id, to_id, amount)` |
| `("budget", "consumed")` | `(budget_id, amount, remaining)` |
| `("budget", "set_ast")` / `("budget", "ast_roll")` | per-token limit / rollover config |
| `("budget", "ast_spend")` / `("budget", "ast_reset")` | per-token debit / window reset |

Standard events from `shared/src/events.rs`: `ContractEvent::BudgetUpdated` on
period transitions and per-token resets, and `budget_exceeded` (`("budget",
"exceeded")`) on the refusal path of `consume`. The refusal path returns an
error, so on-chain that event is rolled back together with the failed
invocation. It is visible in simulation, and the error code is the durable
signal.

## Testing

```sh
cargo test -p astroid-budget
```

The treasury → budget path is also covered end to end in
`tests/src/e2e_agent_spending.rs` and `tests/src/policy_workflow.rs`.
