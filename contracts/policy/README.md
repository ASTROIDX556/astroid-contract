# astroid-policy

Policy contract: hash-verified enforcement of the financial rules that AI
agents spend under.

The backend manages human-readable policy JSON (for example `{ maxAmount:
25000, recipients: [...], window: {...} }`). On-chain, this contract stores:

- a SHA-256 `config_hash` of that JSON, for tamper-evidence;
- a small set of scalar gates that are cheap to check on-chain: `max_amount`,
  `allowed_recipient`, `allowed_asset`, `expires_at`, and a daily operating
  time window;
- optional directories (recipient / asset whitelists, blocklists), per-asset
  allowances, per-agent spending limits, and composite rule trees.

The treasury and the wallet call [`check_transfer`](src/lib.rs) before any
value moves, under the policy id `"active"`. A refused transfer returns a
deterministic error code from `shared/src/errors.rs` and emits a
`PolicyViolation` event naming the rule that refused it.

## Why hash-verified?

Storing `config_hash` instead of the full JSON keeps storage cost low and
makes upgrades fast: the backend rotates the hash when a policy changes. The
max-amount and timing gates live on-chain too, so verification stays
deterministic and cheap.

## Rule structures

### `Policy` (one per `policy_id`)

| Field | Meaning |
|---|---|
| `owner: Address` | Controls the policy. Every mutating call is gated on it. |
| `config_hash: BytesN<32>` | SHA-256 of the off-chain policy JSON. |
| `max_amount: i128` | Single-transaction ceiling. |
| `allowed_recipient: Option<Address>` | Pins one recipient (`None` = any). |
| `allowed_asset: Option<Address>` | Pins one asset (`None` = any). |
| `expires_at: u64` | Policy deadline (`0` = never). |
| `enabled: bool` | `false` denies everything. |
| `rule_combination_strategy` | `All` (default) or `Any`, applied to stacked rule trees. |
| `window_start_time`, `window_end_time`, `window_days` | Daily operating window (`window_days == 0` = off). |

### `AgentSpendLimit` / `AgentDailySpend` (per policy, per agent)

| Field | Meaning |
|---|---|
| `per_tx_limit: i128` | Largest single spend for the agent (`0` = no cap). |
| `daily_limit: i128` | Largest cumulative spend per UTC day (`0` = no cap). |
| `day_start: u64` | UTC midnight that opened the current window. |
| `spent: i128` | Amount spent in that window. |

### `AssetAllowance` (per policy, per asset)

`limit`, `spent`, `expires_at`, `window_seconds` (`0` = cumulative), and
`window_start`.

### Composite rules

A `RuleTree` is a flattened `Vec<RuleNode>` with the root at index 0. Leaf
ops: `MaxAmount`, `AllowedRecipient`, `AllowedAsset`, `RecipientBlacklisted`,
`MerchantBlacklisted`. Branch ops: `And`, `Or`, `Not`, which reference their
children by an index range. Trees are validated when written and evaluated
to a maximum depth of 10. A policy has at most one composite rule
(`set_composite_rule`) plus a stack of up to 16 independent trees
(`add_policy_rule`). The stack combines under the policy's `All` / `Any`
strategy.

## Evaluation flow

`check_transfer(policy_id, asset, recipient, amount)` and the read-only
`evaluate_policy(policy_id, payload)` run the same rule walk in a fixed
order. The first rule that fails decides the outcome:

| # | Rule | `PolicyDenialReason` | Error from `check_transfer` |
|---|---|---|---|
| 0 | `amount <= 0` | none (input error) | `InvalidAmount` |
| 1 | policy disabled | `Disabled` | `PolicyDenied` |
| 2 | recipient on blocklist | `RecipientBlacklisted` | `PolicyRecipientRestricted` |
| 3 | recipient on merchant blocklist | `MerchantBlacklisted` | `PolicyMerchantBlocked` |
| 4 | recipient whitelist enforced, recipient not listed | `RecipientNotWhitelisted` | `PolicyDenied` |
| 5 | ledger time outside operating window | `OutsideTransferWindow` | `PolicyDenied` |
| 6 | policy expired | `Expired` | `PolicyDenied` |
| 7 | `amount > max_amount` | `AboveMaxTransactionLimit` | `PolicyDenied` |
| 8 | recipient differs from `allowed_recipient` | `RecipientNotAllowed` | `PolicyDenied` |
| 9 | asset differs from `allowed_asset` | `AssetNotAllowed` | `PolicyDenied` |
| 10 | asset on the policy's deny list | `AssetBlacklisted` | `PolicyDenied` |
| 11 | asset whitelist enforced, asset not listed | `AssetNotWhitelisted` | `AssetNotAuthorized` |
| 12 | per-asset allowance lapsed | `AllowanceExpired` | `AllowanceExpired` |
| 13 | per-asset allowance would be exceeded | `AllowanceExceeded` | `AllowanceExceeded` |
| 14 | composite rule tree is `false` | `CompositeRuleDenied` | `PolicyDenied` |
| 15 | rule stack is `false` | `RuleStackDenied` | `PolicyDenied` |

`evaluate_policy` returns the granular `PolicyDecision` and never returns an
`Err` for a refusal. It persists nothing, so it is safe to use for dry runs
and pre-flight screens.

Per-agent spending limits (next section) are a separate gate. A spend
executor calls `check_spending_limit` before the transfer and
`record_agent_spend` after it. `tests/src/policy_workflow.rs` shows that
pipeline running across wallet, treasury, and budget.

## Per-agent spending limits (Issue #471)

A runaway or compromised agent must not be able to drain the treasury. The
policy owner therefore gives each agent deterministic caps:

- `set_agent_spend_limit(caller, policy_id, agent, per_tx_limit, daily_limit)`
  (owner-gated). Either cap can be `0` to disable it. Negative caps are
  `InvalidAmount`. A per-transaction cap above a non-zero daily cap is
  `InvalidInput`.
- `check_spending_limit(policy_id, agent, amount) -> i128` (read-only).
  Returns the daily headroom left after the spend (`i128::MAX` with no daily
  cap).
- `record_agent_spend(caller, policy_id, agent, amount) -> i128`
  (owner-gated). Runs the same check, then adds the spend to the agent's
  daily total. A denied spend records nothing.
- `get_agent_spend_limit`, `get_agent_daily_spend`, and
  `remove_agent_spend_limit` (owner-gated; also clears the daily record).

Rules:

| Condition | Error |
|---|---|
| `amount <= 0` | `InvalidAmount` (12) |
| unknown `policy_id` | `NotFound` (1) |
| `amount > per_tx_limit` | `PolicyDenied` (20), checked first |
| today's spend + `amount` > `daily_limit` | `BudgetExceeded` (40) |
| running total overflows `i128` | `Overflow` (11) |

- Spending exactly the remaining daily headroom is allowed.
- The daily window is aligned to UTC midnight in ledger time
  (`env.ledger().timestamp()`, never caller input). It resets lazily: the
  first read or spend in a new day sees `spent == 0`. Midnight itself belongs
  to the new day. Unused days never accumulate.
- Spend is tracked even when an agent has no limit, so a limit introduced
  mid-day is enforced against the real running total. Tightening a limit
  mid-day keeps the spend already recorded.
- An agent with no configured limit is not restricted by this gate. The
  policy's own gates still apply through `check_transfer`.

## Recipient whitelist

A policy can own an on-chain directory of approved destinations. Entries are
stored per policy under `(policy_id, recipient)`:

- `set_recipient_whitelist_enabled` turns enforcement on or off (owner-gated).
- `add_recipient_to_whitelist` / `remove_recipient_from_whitelist` edit the
  directory (owner-gated). Duplicate or missing entries are rejected.
- `is_recipient_whitelisted` / `get_recipient_whitelist` query the directory.
- `evaluate_recipient_whitelist` is the evaluation entry point that
  `check_transfer` uses. It denies with `PolicyDenied` and a
  `not_whitelisted` violation.

While enforcement is on, the gate fails closed: an empty whitelist denies
every recipient. With enforcement off the gate does nothing.
`set_whitelist_enabled`, `add_whitelist`, and `remove_whitelist` are legacy
aliases.

## Transfer time windows

- `set_transfer_window(caller, policy_id, start_time, end_time, window_days)`
  (owner-gated) takes seconds since midnight UTC, repeating every
  `window_days` seconds. `window_days == 0` clears the window. The window may
  wrap past midnight (for example `22:00 → 06:00`). `window_days` is capped
  at one month.
- `get_transfer_window` returns `(start_time, end_time, window_days)`.

The start is inclusive and the end exclusive. A zero-length window
(`start == end`) fails closed. Time is always `env.ledger().timestamp()`.

## Asset rules and blocklists

- Asset deny list: `add_asset_blacklist`, `remove_asset_blacklist`,
  `is_asset_blacklisted`. Keyed per policy.
- Asset allow-list: `set_asset_whitelist_enabled`, `add_asset_to_whitelist`,
  `remove_asset_from_whitelist`, `validate_asset`. Keyed per policy.
- Recipient blocklist: `add_blacklist` / `remove_blacklist` (aliases
  `add_to_blocklist` / `remove_from_blocklist`). Gated on the owner of the
  given policy, but stored contract-wide by address.
- Merchant blocklist: `add_merchant_blacklist` /
  `remove_merchant_blacklist`. Contract-wide by address.
- Category blocklist: `add_category_blacklist` /
  `remove_category_blacklist`, checked through `check_category`
  (`PolicyCategoryRestricted`).

## Multi-asset and rate-limit rules

- `set_allowance` / `set_recurring_allowance`: per-(policy, asset)
  allowance. With `window_seconds > 0` it allows at most `limit` per fixed
  window. `remove_allowance`, `get_allowance`, `check_allowance` (read-only),
  and `update_allowance` (owner-gated, records the spend).
- `check_multi_asset_transfer` / `record_multi_asset_spend`: evaluate (and,
  owner-gated, record) one request that moves several assets to one
  recipient.
- Every amount must be strictly positive (`InvalidAmount`). A request holds
  1 to 10 entries (`InvalidInput`).
- Entries for the same asset are summed with checked math (`Overflow`) before
  any gate runs, so a spend cannot be split to slip under a limit.
- Each asset is checked only against its own gates and allowance. Amounts in
  different assets are never summed together.
- All-or-nothing: if any asset fails, nothing is recorded for any asset.
- Windows are fixed and anchored at `window_start`. With
  `k = (now - window_start) / window_seconds`, `k >= 1` resets `spent` and
  moves `window_start` forward by `k * window_seconds`.

## Public interface (summary)

| Area | Functions |
|---|---|
| Setup | `initialize`, `register_policy`, `rotate_policy`, `set_enabled`, `set_rule_combination_strategy`, `get` |
| Evaluation | `check_transfer` (`PolicyInterface`), `evaluate_policy`, `evaluate_recipient_whitelist`, `validate_asset`, `check_category` |
| Agent limits | `set_agent_spend_limit`, `remove_agent_spend_limit`, `get_agent_spend_limit`, `get_agent_daily_spend`, `check_spending_limit`, `record_agent_spend` |
| Allowances | `set_allowance`, `set_recurring_allowance`, `remove_allowance`, `get_allowance`, `check_allowance`, `update_allowance`, `check_multi_asset_transfer`, `record_multi_asset_spend` |
| Time window | `set_transfer_window`, `get_transfer_window` |
| Directories | recipient / asset whitelists, asset / recipient / merchant / category blocklists (see above) |
| Rule trees | `set_composite_rule`, `clear_composite_rule`, `get_composite_rule`, `evaluate_composite_rule`, `add_policy_rule`, `remove_policy_rule`, `clear_policy_rules`, `get_policy_rules`, `evaluate_policy_rules` |
| Upgrades | `set_upgrade_authority`, `get_upgrade_authority`, `upgrade` (`UpgradeableInterface`; registry-approved Wasm hash for `ModuleKind::Policy`) |

## Storage layout

| Key (`DataKey`) | Tier | Value |
|---|---|---|
| `Count` | instance | `u32` initialization marker |
| `Policy(policy_id)` | persistent | `Policy` |
| `Blacklist(address)` | persistent | recipient blocklist entry (stores the listing `policy_id`) |
| `MerchantBlacklist(address)` | persistent | merchant blocklist entry |
| `CategoryBlacklist(category)` | persistent | category blocklist entry |
| `AssetWhitelist(policy_id, asset)` | persistent | asset allow-list entry |
| `AssetBlacklist(policy_id, asset)` | persistent | asset deny-list entry |
| `AssetWhitelistEnabled(policy_id)` | persistent | `bool` |
| `RecipientWhitelist(policy_id, recipient)` | persistent | recipient whitelist entry |
| `RecipientWhitelistEnabled(policy_id)` | persistent | `bool` |
| `RecipientWhitelistIndex(policy_id)` | persistent | `Vec<Address>`, an enumerable mirror of the whitelist |
| `Allowance(policy_id, asset)` | persistent | `AssetAllowance` |
| `CompositeRule(policy_id)` | persistent | `RuleTree` |
| `PolicyRules(policy_id)` | persistent | `RuleStack` |
| `AgentLimit(policy_id, agent)` | persistent | `AgentSpendLimit` |
| `AgentDailySpend(policy_id, agent)` | persistent | `AgentDailySpend` |

## Error codes

All codes come from `shared/src/errors.rs`.

| Code | Name | Typical cause |
|---|---|---|
| 1 | `NotFound` | Unknown policy, or a missing whitelist / allowance / limit entry. |
| 2 | `AlreadyExists` | Duplicate policy id or directory entry. |
| 3 | `Unauthorized` | Caller is not the policy owner. |
| 4 | `InvalidInput` | Malformed rule tree, bad window bounds, empty id, multi-asset request size, `per_tx_limit > daily_limit`. |
| 6 | `AlreadyInitialized` | `initialize` called twice. |
| 11 | `Overflow` | Checked arithmetic overflow. |
| 12 | `InvalidAmount` | Non-positive transfer amount, or a negative limit. |
| 20 | `PolicyDenied` | A rule refused the transfer (table above), or the agent's per-transaction cap was exceeded. |
| 22 | `PolicyRecipientRestricted` | Recipient is blocklisted. |
| 23 | `PolicyMerchantBlocked` | Merchant is blocklisted. |
| 24 | `PolicyCategoryRestricted` | Category is blocklisted. |
| 40 | `BudgetExceeded` | The agent's daily spending limit would be exceeded. |
| 43 | `AssetNotAuthorized` | Asset whitelist enforced and asset not listed. |
| 83 | `AllowanceExceeded` | Per-asset allowance would be exceeded. |
| 84 | `AllowanceExpired` | Per-asset allowance has lapsed. |

## Events

- `("policy", "registd")` on registration and `("policy", "rotated")` on
  rotation.
- `("policy", "timewin")` on operating-window changes.
- `("policy", "wl_mode")`, `("policy", "wl_add")`, `("policy", "wl_rem")`
  on recipient whitelist edits.
- `("policy", "allow_set")`, `("policy", "allow_use")`,
  `("policy", "allow_rem")` for allowances.
- `("policy", "agt_limit")` `(policy_id, agent, per_tx_limit, daily_limit)`,
  `("policy", "agt_spend")` `(policy_id, agent, amount, spent_today)`, and
  `("policy", "agt_rem")` `(policy_id, agent)` for agent limits.
- `("policy", "violation")` plus the canonical
  `ContractEvent::PolicyViolation` on every denial, carrying a short reason
  symbol such as `above_max`, `not_whitelisted`, `outside_window`,
  `above_agent_tx_limit`, or `daily_limit_exceeded`.

## Testing

```sh
cargo test -p astroid-policy
```

Cross-contract coverage: `tests/src/policy_workflow.rs`,
`tests/src/policy_enforcement.rs`, and `tests/src/e2e_agent_spending.rs`.
