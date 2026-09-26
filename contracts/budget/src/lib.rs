#![no_std]
#![allow(clippy::too_many_arguments)]
//! # Astroid Budget Contract
//!
//! Enforces spending limits (PRD Doc 7 §Budget). Every spend calls
//! [`BudgetContract::consume`], which debits the remaining allocation and
//! reverts with [`Error::BudgetExceeded`] when a spend would push spending past
//! the limit. Budgets support periodic auto-reset windows (daily / weekly /
//! monthly), optional unspent-allowance rollover into the next period, an
//! expiration timestamp after which consumption is rejected, freezing,
//! archiving and moving allocation between two budgets.
//!
//! Budgets are keyed by a backend-owned string id and are scoped to an owner
//! address (the treasury or organization owner) which authorizes consumption
//! and administration. Budgets implement the shared [`BudgetInterface`] so other
//! contracts (e.g. Treasury) can debit them through a typed client.
//!
//! ## Recurring allowances
//!
//! A recurring budget is defined by a period (`Daily` / `Weekly` / `Monthly`,
//! or `Custom` with an explicit interval in seconds) and a rollover policy.
//! Period transitions are never driven by an external cron: every allowance
//! query ([`BudgetContract::remaining`]) and every disbursement
//! ([`BudgetContract::consume`]) evaluates the transition hook first, so an
//! agent reading its allowance always sees the current period even if nobody
//! touched the budget for several periods.
//!
//! The hook is catch-up correct. If `n` whole periods elapsed since the last
//! transition it settles all `n` of them at once and re-anchors `window_start`
//! to the period boundary rather than to "now", so windows never drift and a
//! dormant budget cannot be made to skip a reset.
//!
//! ## Window boundaries and gaps (Issue #246)
//!
//! A window is half-open: `[window_start, window_start + duration)`. The
//! **start timestamp is inclusive, the end timestamp is exclusive** — a ledger
//! timestamp exactly equal to the window end already belongs to the next
//! window, i.e. the period counts as expired at `now >= window_start +
//! duration`. [`BudgetContract::is_window_expired`] states this rule in one
//! place and every transition path routes through it.
//!
//! When several whole windows lapse with no activity in between (a multi-window
//! gap), the hook still settles in a single step. Rollover **does not compound
//! across lapsed windows**: only the immediately preceding window contributes
//! its unspent remainder; every fully idle window inside the gap contributes a
//! full base limit, and the accumulated total is clamped once to the budget's
//! effective rollover cap. Without that clamp a budget left dormant for `n`
//! windows could accrue roughly `n × limit`, letting an agent drain far more
//! than one period's worth of allowance in a single window — exactly what the
//! cap exists to prevent. (Deliberate design decision, see the PR for #246.)
//!
//! Rollover is bounded. When `rollover_enabled` is false the unspent remainder
//! is dropped and the next period starts from the base limit; when it is true
//! the remainder accumulates into `rollover_credit`, clamped to the **effective
//! cap** — the smaller of the owner-set absolute `rollover_cap` (0 = uncapped)
//! and the protocol percentage ceiling `rollover_max_bps` of the base limit
//! (0 = uncapped). The cap is what stops a budget that is left idle for a long
//! stretch from silently accruing a balance far larger than the limit it was
//! granted, which an agent could then drain in one period.
//!
//! Functions: `allocate`, `set_recurrence`, `consume`, `reset`, `rollover`,
//! `freeze`, `unfreeze`, `archive`, `transfer_allocation`.
//!
//! ## Error codes
//!
//! Every handler validates its inputs before touching storage and fails with a
//! stable code from the shared [`Error`] table rather than panicking:
//!
//! | Condition                                                   | Error                     |
//! |-------------------------------------------------------------|---------------------------|
//! | Spend / release / transfer amount `<= 0`                    | [`Error::InvalidAmount`]  |
//! | Negative limit or rollover cap                              | [`Error::InvalidAmount`]  |
//! | Limit below spent, expiry already passed, malformed period  | [`Error::InvalidInput`]   |
//! | Spend would exceed the effective ceiling                    | [`Error::BudgetExceeded`] |
//! | Checked arithmetic would overflow `i128`                    | [`Error::Overflow`]       |
//! | Caller is not the budget owner                              | [`Error::Unauthorized`]   |
//! | Budget is frozen / archived / expired                       | [`Error::BudgetFrozen`] / [`Error::BudgetArchived`] / [`Error::BudgetExpired`] |

use astroid_interfaces::{BudgetInterface, UpgradeableInterface};
use astroid_shared::constants::{
    BPS_DENOMINATOR, INSTANCE_BUMP_AMOUNT, INSTANCE_LIFETIME_THRESHOLD, PERSISTENT_BUMP_AMOUNT,
    PERSISTENT_LIFETIME_THRESHOLD,
};
use astroid_shared::errors::Error;
use astroid_shared::events::ContractEvent;
use astroid_shared::math::{checked_add, checked_div, checked_mul, checked_rem, checked_sub};
use astroid_shared::types::ResourceState;
use astroid_shared::validation::{require_non_empty, require_positive_amount};
use astroid_shared::{constants, events};
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, Address, Env, String, Symbol,
};

/// Reset period for a recurring budget. `None` means one-shot (no auto-reset).
///
/// `Custom` takes its interval from the budget's `period_seconds`, which lets
/// an organization define an arbitrary recurring window (an hourly agent
/// allowance, a fortnightly retainer) without adding a variant per cadence.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Period {
    None = 0,
    Daily = 1,
    Weekly = 2,
    Monthly = 3,
    Custom = 4,
}
/// Stored budget record.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Budget {
    pub owner: Address,
    pub limit: i128,
    pub spent: i128,
    pub period: Period,
    /// Window length in seconds when `period` is [`Period::Custom`]; ignored
    /// for the fixed cadences and 0 when unused.
    pub period_seconds: u64,
    /// Start of the current window (unix seconds). Used for auto-reset. Always
    /// sits on a period boundary once the budget has rolled at least once.
    pub window_start: u64,
    /// Whether unspent allowance carries into the next period on rollover.
    pub rollover_enabled: bool,
    /// Accumulated unspent allowance carried from prior periods (rollover).
    pub rollover_credit: i128,
    /// Upper bound on `rollover_credit` (0 = uncapped). Bounds how much idle
    /// allowance a recurring budget can accrue before it is spendable at once.
    pub rollover_cap: i128,
    /// Protocol-wide maximum rollover in basis points of the base limit
    /// (0 = uncapped, configured via `set_recurrence`). Applied in addition to
    /// [`Budget::rollover_cap`] — the effective cap is the smaller of the two.
    pub rollover_max_bps: i128,
    /// Whether the budget allows spending beyond its limit (deficit).
    pub allow_deficit: bool,
    /// Accumulated deficit carried from prior periods.
    pub deficit_amount: i128,
    /// Unix timestamp after which the budget is expired (0 = never expires).
    pub expires_at: u64,
    pub state: ResourceState,
}

/// Per-asset budget tracking. Recurs on its own fixed-length window so a
/// single budget can grant, say, a daily USDC allowance and a weekly XLM one.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssetBudget {
    pub limit: i128,
    pub spent: i128,
    /// Window length in seconds; 0 means the limit never auto-resets.
    pub window_seconds: u64,
    pub window_start: u64,
}
#[contracttype]
#[derive(Clone)]
enum DataKey {
    Admin,
    Budget(String),
    AssetBudget(String, Address),
}
#[contract]
pub struct BudgetContract;
#[contractimpl]
impl BudgetContract {
    /// Initialize with an admin (used only for protocol-level bookkeeping; all
    /// budget operations are owner-gated).
    pub fn initialize(env: Env, admin: Address) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
        Ok(())
    }
    /// Allocate (create) a budget with a spending `limit` and optional reset
    /// `period`. `owner` authorizes and becomes the budget's controller.
    /// `rollover_enabled` carries unspent allowance into the next period;
    /// `allow_deficit` permits spending beyond the limit, accumulating a
    /// deficit that carries into the next period; `expires_at` (unix seconds,
    /// 0 = never) marks the budget expired after a given time, after which
    /// consumption is rejected.
    pub fn allocate(
        env: Env,
        owner: Address,
        budget_id: String,
        limit: i128,
        period: Period,
        rollover_enabled: bool,
        expires_at: u64,
    ) -> Result<(), Error> {
        Self::allocate_with_deficit(
            env,
            owner,
            budget_id,
            limit,
            period,
            rollover_enabled,
            false,
            expires_at,
        )
    }
    /// Extended allocation with deficit support (Issue #35).
    pub fn allocate_with_deficit(
        env: Env,
        owner: Address,
        budget_id: String,
        limit: i128,
        period: Period,
        rollover_enabled: bool,
        allow_deficit: bool,
        expires_at: u64,
    ) -> Result<(), Error> {
        owner.require_auth();
        require_non_empty(&budget_id)?;
        Self::require_valid_limit(limit)?;
        // A budget that is already expired at creation could never be spent.
        if expires_at != 0 && expires_at <= env.ledger().timestamp() {
            return Err(Error::InvalidInput);
        }
        // Deficit carryforward only makes sense with a recurring period.
        if allow_deficit && period == Period::None {
            return Err(Error::InvalidInput);
        }
        let key = DataKey::Budget(budget_id.clone());
        if env.storage().persistent().has(&key) {
            return Err(Error::AlreadyExists);
        }
        let budget = Budget {
            owner: owner.clone(),
            limit,
            spent: 0,
            period,
            // Fixed cadences derive their window from `period`; a `Custom`
            // budget stays inert until `set_recurrence` supplies an interval.
            period_seconds: 0,
            window_start: env.ledger().timestamp(),
            rollover_enabled,
            rollover_credit: 0,
            rollover_cap: 0,
            rollover_max_bps: 0,
            allow_deficit,
            deficit_amount: 0,
            expires_at,
            state: ResourceState::Active,
        };
        env.storage().persistent().set(&key, &budget);
        Self::bump(&env, &budget_id);
        env.events().publish(
            (symbol_short!("budget"), symbol_short!("allocated")),
            (budget_id, owner, limit),
        );
        Ok(())
    }

    /// Configure the recurring allowance policy for a budget (owner-gated).
    ///
    /// `period` selects the cadence; `period_seconds` supplies the interval and
    /// is required (and only meaningful) for [`Period::Custom`].
    /// `rollover_enabled` decides whether an unspent remainder carries into the
    /// next period, and `rollover_cap` bounds how much may accumulate
    /// (0 = uncapped).
    ///
    /// `rollover_max_bps` is the maximum rollover as a percentage of the base
    /// `limit`, in basis points (0 = uncapped, 2_500 = 25%). It is a
    /// protocol-safety ceiling layered on top of the owner's absolute
    /// `rollover_cap`: the effective cap is the smaller of the two. A
    /// percentage of 100% or more is rejected with [`Error::InvalidInput`] so
    /// the cap can never loosen a bounded rollover, and `Self::effective_rollover_cap`
    /// applies it through the shared checked arithmetic.
    ///
    /// Any transition already due under the *previous* policy is settled first,
    /// so switching cadence can neither erase nor duplicate an owed reset. The
    /// window is then re-anchored to now, which is the boundary the new cadence
    /// counts from.
    pub fn set_recurrence(
        env: Env,
        caller: Address,
        budget_id: String,
        period: Period,
        period_seconds: u64,
        rollover_enabled: bool,
        rollover_cap: i128,
        rollover_max_bps: i128,
    ) -> Result<(), Error> {
        Self::require_valid_limit(rollover_cap)?;
        Self::require_valid_limit(rollover_max_bps)?;
        // A percentage cap of 100% or more would not bound anything.
        if rollover_max_bps >= BPS_DENOMINATOR {
            return Err(Error::InvalidInput);
        }
        if period == Period::Custom && period_seconds == 0 {
            return Err(Error::InvalidInput);
        }
        let mut budget = Self::require_owner(&env, &budget_id, &caller)?;
        Self::require_active(&budget)?;
        // Settle what the old policy already owes before adopting the new one.
        Self::window_transition(&env, &mut budget, &budget_id, true)?;

        budget.period = period;
        budget.period_seconds = if period == Period::Custom {
            period_seconds
        } else {
            0
        };
        budget.rollover_enabled = rollover_enabled;
        budget.rollover_cap = rollover_cap;
        budget.rollover_max_bps = rollover_max_bps;
        if !rollover_enabled {
            budget.rollover_credit = 0;
        } else if budget.rollover_credit > 0 {
            // Clamp the accrued credit to the *effective* (absolute ∩
            // percentage) ceiling the new policy implies, so an already
            // over-limit credit cannot outlive a tightening. A zero credit has
            // nothing to clamp, and skipping the computation there keeps
            // configuration deterministic even on limits whose percentage cap
            // itself cannot be represented (it then surfaces where the cap is
            // applied, at the transition).
            budget.rollover_credit = Self::apply_cap(
                budget.rollover_credit,
                Self::effective_rollover_cap(&budget)?,
            );
        }
        budget.window_start = env.ledger().timestamp();
        Self::store(&env, &budget_id, &budget);
        env.events().publish(
            (symbol_short!("budget"), symbol_short!("recurring")),
            (budget_id, period, period_seconds, rollover_cap),
        );
        Ok(())
    }

    /// Reset the spent counter to zero (owner-gated). Also refreshes the window.
    /// Rejects expired budgets.
    pub fn reset(env: Env, caller: Address, budget_id: String) -> Result<(), Error> {
        let mut budget = Self::require_owner(&env, &budget_id, &caller)?;
        Self::require_not_archived(&budget)?;
        Self::require_not_expired(&env, &budget)?;
        budget.spent = 0;
        budget.rollover_credit = 0;
        budget.window_start = env.ledger().timestamp();
        Self::store(&env, &budget_id, &budget);
        env.events()
            .publish((symbol_short!("budget"), symbol_short!("reset")), budget_id);
        Ok(())
    }
    /// Force a period transition for a budget (owner-gated). Rolls unspent
    /// allowance over into the next period when `rollover_enabled`, otherwise
    /// clears it. Carries forward any deficit. Rejects expired budgets. This is
    /// the only path that may trigger a rollover; ordinary consumption cannot do
    /// so on its own.
    pub fn rollover(env: Env, caller: Address, budget_id: String) -> Result<(), Error> {
        let mut budget = Self::require_owner(&env, &budget_id, &caller)?;
        Self::require_not_archived(&budget)?;
        Self::window_transition(&env, &mut budget, &budget_id, true)?;
        Self::store(&env, &budget_id, &budget);
        Ok(())
    }
    /// Change a budget's limit (owner-gated). New limit must be >= amount spent
    /// in the current window. Applies any pending period transition first.
    pub fn set_limit(
        env: Env,
        caller: Address,
        budget_id: String,
        new_limit: i128,
    ) -> Result<(), Error> {
        Self::require_valid_limit(new_limit)?;
        let mut budget = Self::require_owner(&env, &budget_id, &caller)?;
        Self::require_not_archived(&budget)?;
        Self::window_transition(&env, &mut budget, &budget_id, true)?;
        if new_limit < budget.spent {
            return Err(Error::InvalidInput);
        }
        budget.limit = new_limit;
        Self::store(&env, &budget_id, &budget);
        env.events().publish(
            (symbol_short!("budget"), symbol_short!("setlimit")),
            (budget_id, new_limit),
        );
        Ok(())
    }
    /// Freeze a budget (owner-gated). Frozen budgets reject consumption.
    pub fn freeze(env: Env, caller: Address, budget_id: String) -> Result<(), Error> {
        let mut budget = Self::require_owner(&env, &budget_id, &caller)?;
        if budget.state == ResourceState::Archived {
            return Err(Error::BudgetArchived);
        }
        budget.state = ResourceState::Frozen;
        Self::store(&env, &budget_id, &budget);
        env.events().publish(
            (symbol_short!("budget"), symbol_short!("frozen")),
            budget_id,
        );
        Ok(())
    }
    /// Unfreeze a budget back to active (owner-gated).
    pub fn unfreeze(env: Env, caller: Address, budget_id: String) -> Result<(), Error> {
        let mut budget = Self::require_owner(&env, &budget_id, &caller)?;
        if budget.state != ResourceState::Frozen {
            return Err(Error::InvalidState);
        }
        budget.state = ResourceState::Active;
        Self::store(&env, &budget_id, &budget);
        env.events().publish(
            (symbol_short!("budget"), symbol_short!("unfrozen")),
            budget_id,
        );
        Ok(())
    }
    /// Archive a budget (owner-gated, terminal). Rejects further consumption.
    pub fn archive(env: Env, caller: Address, budget_id: String) -> Result<(), Error> {
        let mut budget = Self::require_owner(&env, &budget_id, &caller)?;
        budget.state = ResourceState::Archived;
        Self::store(&env, &budget_id, &budget);
        env.events().publish(
            (symbol_short!("budget"), symbol_short!("archived")),
            budget_id,
        );
        Ok(())
    }
    /// Move unused allocation from one budget to another. Both must share the
    /// same owner, who authorizes. Reduces `from`'s limit and increases `to`'s.
    pub fn transfer_allocation(
        env: Env,
        caller: Address,
        from_id: String,
        to_id: String,
        amount: i128,
    ) -> Result<(), Error> {
        require_positive_amount(amount)?;
        if from_id == to_id {
            return Err(Error::InvalidInput);
        }
        let mut from = Self::require_owner(&env, &from_id, &caller)?;
        // `to` must exist and share the owner; caller already authorized above.
        let mut to = Self::load(&env, &to_id)?;
        if to.owner != caller {
            return Err(Error::Unauthorized);
        }
        Self::require_active(&from)?;
        Self::require_active(&to)?;
        Self::require_not_expired(&env, &from)?;
        Self::require_not_expired(&env, &to)?;
        // Only the unspent portion of `from` may be reallocated.
        let available = checked_sub(from.limit, from.spent)?;
        if amount > available {
            return Err(Error::BudgetExceeded);
        }
        from.limit = checked_sub(from.limit, amount)?;
        to.limit = checked_add(to.limit, amount)?;
        Self::store(&env, &from_id, &from);
        Self::store(&env, &to_id, &to);
        env.events().publish(
            (symbol_short!("budget"), symbol_short!("realloc")),
            (from_id, to_id, amount),
        );
        Ok(())
    }

    /// Set the recurring limit for a specific token (owner-gated).
    ///
    /// `window_seconds` makes the per-asset limit recur: the spent counter
    /// auto-resets every `window_seconds`, evaluated lazily on the next spend
    /// or query. Passing 0 keeps the limit one-shot.
    pub fn set_budget_limit(
        env: Env,
        caller: Address,
        budget_id: String,
        token: Address,
        limit: i128,
        window_seconds: u64,
    ) -> Result<(), Error> {
        Self::require_valid_limit(limit)?;
        let budget = Self::require_owner(&env, &budget_id, &caller)?;
        Self::require_active(&budget)?;
        Self::require_not_expired(&env, &budget)?;
        let key = DataKey::AssetBudget(budget_id.clone(), token.clone());
        let asset_budget = AssetBudget {
            limit,
            spent: 0,
            window_seconds,
            window_start: env.ledger().timestamp(),
        };
        env.storage().persistent().set(&key, &asset_budget);
        Self::bump_asset(&env, &budget_id, &token);
        env.events().publish(
            (symbol_short!("budget"), symbol_short!("set_ast")),
            (budget_id, token, limit),
        );
        Ok(())
    }
    /// Check and record spend for a specific token.
    pub fn check_and_record_spend(
        env: Env,
        caller: Address,
        budget_id: String,
        token: Address,
        amount: i128,
    ) -> Result<(), Error> {
        require_positive_amount(amount)?;
        let budget = Self::require_owner(&env, &budget_id, &caller)?;
        Self::require_active(&budget)?;
        Self::require_not_expired(&env, &budget)?;
        let key = DataKey::AssetBudget(budget_id.clone(), token.clone());
        let mut asset_budget: AssetBudget = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(Error::AssetNotAuthorized)?;
        // Recurring per-asset limits replenish lazily, on the spend itself.
        Self::asset_window_transition(&env, &mut asset_budget, &budget_id, &token, true);

        // Window rollover check
        let now = env.ledger().timestamp();
        if asset_budget.window_seconds > 0
            && now
                >= asset_budget
                    .window_start
                    .saturating_add(asset_budget.window_seconds)
        {
            asset_budget.spent = 0;
            asset_budget.window_start = now;
        }

        // Check if within limit
        let new_spent = checked_add(asset_budget.spent, amount)?;
        if new_spent > asset_budget.limit {
            return Err(Error::BudgetExceeded);
        }
        asset_budget.spent = new_spent;
        env.storage().persistent().set(&key, &asset_budget);
        Self::bump_asset(&env, &budget_id, &token);
        env.events().publish(
            (symbol_short!("budget"), symbol_short!("ast_spend")),
            (budget_id, token, amount),
        );
        Ok(())
    }
    // --- views ---
    pub fn get(env: Env, budget_id: String) -> Result<Budget, Error> {
        Self::load(&env, &budget_id)
    }

    /// Read a per-asset limit, settling any due window reset first so the
    /// record reflects the current period.
    pub fn get_asset_budget(
        env: Env,
        budget_id: String,
        token: Address,
    ) -> Result<AssetBudget, Error> {
        let mut asset_budget: AssetBudget = env
            .storage()
            .persistent()
            .get(&DataKey::AssetBudget(budget_id.clone(), token.clone()))
            .ok_or(Error::AssetNotAuthorized)?;
        Self::asset_window_transition(&env, &mut asset_budget, &budget_id, &token, false);
        Ok(asset_budget)
    }

    /// Remaining allowance for a specific token in the current window.
    pub fn asset_remaining(env: Env, budget_id: String, token: Address) -> Result<i128, Error> {
        let asset_budget = Self::get_asset_budget(env, budget_id, token)?;
        checked_sub(asset_budget.limit, asset_budget.spent)
    }

    // --- internal helpers ---
    fn load(env: &Env, id: &String) -> Result<Budget, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::Budget(id.clone()))
            .ok_or(Error::NotFound)
    }
    fn store(env: &Env, id: &String, budget: &Budget) {
        env.storage()
            .persistent()
            .set(&DataKey::Budget(id.clone()), budget);
        Self::bump(env, id);
    }
    fn require_owner(env: &Env, id: &String, caller: &Address) -> Result<Budget, Error> {
        caller.require_auth();
        let budget = Self::load(env, id)?;
        if &budget.owner != caller {
            return Err(Error::Unauthorized);
        }
        Ok(budget)
    }
    /// Limits and rollover caps are non-negative (0 is a valid, closed budget).
    fn require_valid_limit(limit: i128) -> Result<(), Error> {
        if limit < 0 {
            return Err(Error::InvalidAmount);
        }
        Ok(())
    }
    /// Archiving is terminal: no administrative change may revive a budget.
    fn require_not_archived(budget: &Budget) -> Result<(), Error> {
        if budget.state == ResourceState::Archived {
            return Err(Error::BudgetArchived);
        }
        Ok(())
    }
    /// Remaining allowance in the current period: base limit plus rollover
    /// credit, less any carried-forward deficit and what has been spent.
    fn effective_remaining(budget: &Budget) -> Result<i128, Error> {
        let capacity = checked_add(budget.limit, budget.rollover_credit)?;
        if budget.allow_deficit && budget.deficit_amount > 0 {
            let net = checked_sub(capacity, budget.deficit_amount)?;
            checked_sub(net, budget.spent)
        } else {
            checked_sub(capacity, budget.spent)
        }
    }
    fn require_active(budget: &Budget) -> Result<(), Error> {
        match budget.state {
            ResourceState::Active => Ok(()),
            ResourceState::Frozen | ResourceState::Paused => Err(Error::BudgetFrozen),
            ResourceState::Archived => Err(Error::BudgetArchived),
        }
    }

    /// The window length implied by a budget's period, or `None` when the
    /// budget does not recur (one-shot, or a `Custom` period with no interval
    /// configured yet).
    fn window_of(budget: &Budget) -> Option<u64> {
        match budget.period {
            Period::None => None,
            Period::Daily => Some(constants::SECONDS_PER_DAY),
            Period::Weekly => Some(constants::SECONDS_PER_WEEK),
            Period::Monthly => Some(constants::SECONDS_PER_MONTH),
            Period::Custom => {
                if budget.period_seconds == 0 {
                    None
                } else {
                    Some(budget.period_seconds)
                }
            }
        }
    }

    /// Clamp an accumulated rollover credit to its cap (0 = uncapped).
    fn apply_cap(credit: i128, cap: i128) -> i128 {
        if cap != 0 && credit > cap {
            cap
        } else {
            credit
        }
    }

    /// The two-layer rollover ceiling for a budget: the owner-configured
    /// absolute cap (0 = uncapped) intersected with the protocol-wide maximum
    /// rollover percentage of the base limit (see [`Budget::rollover_max_bps`]).
    /// The effective cap is the *smaller* of the two, so a percentage cap
    /// always wins over a more permissive absolute one and vice versa.
    ///
    /// The percentage side is computed by [`Self::percentage_of_limit`], which
    /// cannot overflow for any configuration `set_recurrence` accepts; the
    /// absolute side is used verbatim via [`Self::apply_cap`].
    fn effective_rollover_cap(budget: &Budget) -> Result<i128, Error> {
        let pct_cap = Self::percentage_of_limit(budget.limit, budget.rollover_max_bps)?;
        match (budget.rollover_cap, pct_cap) {
            // A recurring budget always carries one nonzero bound
            // (`set_recurrence` rejects percentages of 100% and more), so this
            // arm is defensive only.
            (0, 0) => Ok(0),
            (0, p) => Ok(p),
            (c, 0) => Ok(c),
            (c, p) => Ok(c.min(p)),
        }
    }

    /// `floor(limit * bps / 10_000)` — `bps` basis points of `limit` — without
    /// any intermediate that can overflow `i128`.
    ///
    /// `limit` is split into its 10_000-ary quotient and remainder:
    /// `limit * bps / 10_000 = q * bps + (r * bps) / 10_000`. Because
    /// `set_recurrence` rejects `bps >= 10_000` (100% and above), `q * bps <=
    /// limit` and `r * bps < 10^8`, so even a pathological `i128::MAX` limit
    /// yields an exact, representable cap rather than [`Error::Overflow`].
    /// Every step still routes through the shared checked arithmetic, so an
    /// out-of-band percentage (only possible if that bound were ever relaxed)
    /// degrades to [`Error::Overflow`], never a wrapped value.
    fn percentage_of_limit(limit: i128, bps: i128) -> Result<i128, Error> {
        if bps == 0 {
            return Ok(0);
        }
        let q = checked_div(limit, BPS_DENOMINATOR)?;
        let r = checked_rem(limit, BPS_DENOMINATOR)?;
        let whole = checked_mul(q, bps)?;
        let part = checked_div(checked_mul(r, bps)?, BPS_DENOMINATOR)?;
        checked_add(whole, part)
    }

    /// Whether the budget's current window has lapsed.
    ///
    /// A window is defined by its inclusive start (`window_start`) and its
    /// *exclusive* end (`window_start + window_seconds`). The boundary rule is
    /// therefore **half-open: `[start, end)` — the very first timestamp at or
    /// after `window_start + window_seconds` belongs to the *next* window**,
    /// i.e. a ledger timestamp exactly equal to the window end counts as
    /// expired. This matches the existing catch-up convention
    /// (`elapsed = now - window_start`, `elapsed >= window`) and the fixed
    /// cadences themselves (a daily budget re-arms at `start + 86_400`), and
    /// keeps `window_end` readable as "allowed until this instant, not
    /// including it".
    ///
    /// Returns `Ok(false)` for non-recurring budgets (`Period::None`, or a
    /// `Custom` period without an interval): their window never lapses.
    fn is_window_expired(env: &Env, budget: &Budget) -> Result<bool, Error> {
        let window = match Self::window_of(budget) {
            Some(w) => w,
            None => return Ok(false),
        };
        let now = env.ledger().timestamp();
        let end = budget
            .window_start
            .checked_add(window)
            .ok_or(Error::Overflow)?;
        Ok(now >= end)
    }

    /// The conditional execution hook for recurring allowances.
    ///
    /// Applies every period transition that is due (auto-reset / rollover) and
    /// checks expiration. Mutates `budget` in place. When `publish` is true,
    /// emits the `rollover`/`reset`/`expired` events. Returns
    /// [`Error::BudgetExpired`] if the budget has passed its expiration window.
    ///
    /// Window expiry is determined by [`Self::is_window_expired`] (half-open
    /// boundary: a timestamp equal to the window end belongs to the next
    /// window), and the rollover credit computed here is clamped to the
    /// effective cap — the smaller of the stored absolute `rollover_cap` and
    /// the percentage ceiling `rollover_max_bps` of the base limit.
    ///
    /// Settling *all* elapsed periods at once — rather than one per call — is
    /// what makes the hook safe to evaluate lazily: a budget nobody touched for
    /// five periods lands in exactly the state it would have had if it were
    /// visited every period.
    fn window_transition(
        env: &Env,
        budget: &mut Budget,
        budget_id: &String,
        publish: bool,
    ) -> Result<(), Error> {
        let now = env.ledger().timestamp();
        if budget.expires_at != 0 && now >= budget.expires_at {
            if publish {
                env.events().publish(
                    (symbol_short!("budget"), symbol_short!("expired")),
                    budget_id.clone(),
                );
            }
            return Err(Error::BudgetExpired);
        }
        let window = match Self::window_of(budget) {
            Some(w) => w,
            None => return Ok(()),
        };
        // The single place the period-lapse rule lives: half-open
        // [start, start + window), so a timestamp equal to the window end
        // already belongs to the next period (see `is_window_expired`).
        if !Self::is_window_expired(env, budget)? {
            return Ok(());
        }
        let elapsed = now.saturating_sub(budget.window_start);
        // Whole periods to settle. `window` is non-zero, so this is >= 1.
        let periods = (elapsed / window) as i128;

        // The current period's remainder, plus one full base limit for every
        // further period that came and went entirely untouched. `leftover`
        // already accounts for any credit carried into this window because the
        // period's capacity is `limit + rollover_credit`, so it is the base for
        // the next period's credit. Re-adding the old credit here would count
        // it a second time and let an agent that spent its whole rolled-over
        // allowance bank another period's worth of unearned capacity.
        let capacity = checked_add(budget.limit, budget.rollover_credit)?;
        let leftover = checked_sub(capacity, budget.spent)?;
        if budget.rollover_enabled {
            let mut credit = leftover;
            if periods > 1 {
                let idle = checked_sub(periods, 1)?;
                credit = Self::accrue_idle_periods(credit, budget, idle)?;
            }
            // Clamp to the effective cap = min(absolute `rollover_cap`,
            // percentage-of-limit `rollover_max_bps`); see
            // [`Self::effective_rollover_cap`].
            budget.rollover_credit = Self::apply_cap(credit, Self::effective_rollover_cap(budget)?);
        } else {
            budget.rollover_credit = 0;
        }
        let spent = budget.spent;
        // Deficit: spent exceeded capacity (base limit + rollover credit).
        // Track it so the next period's effective limit is reduced, and drop
        // any (negative) rollover credit computed above. `spent > capacity`
        // with `!allow_deficit` cannot happen — consume rejects it — but is
        // handled defensively by simply resetting the window.
        if spent > capacity && budget.allow_deficit {
            let deficit = checked_sub(spent, capacity)?;
            budget.deficit_amount = checked_add(budget.deficit_amount, deficit)?;
            budget.rollover_credit = 0; // No surplus to roll over
        }
        budget.spent = 0;
        // Re-anchor to the period boundary, not to `now`, so windows never
        // drift away from the schedule the budget was granted on.
        budget.window_start = budget
            .window_start
            .saturating_add((periods as u64).saturating_mul(window));
        if publish {
            let action = if budget.allow_deficit && spent > capacity {
                symbol_short!("deficit")
            } else if budget.rollover_enabled {
                symbol_short!("rollover")
            } else {
                symbol_short!("reset")
            };
            let amount = if budget.allow_deficit && spent > capacity {
                checked_sub(spent, capacity)?
            } else {
                checked_sub(capacity, spent)?
            };
            env.events().publish(
                (symbol_short!("budget"), action.clone()),
                (budget_id.clone(), amount),
            );
            events::publish(
                env,
                ContractEvent::BudgetUpdated {
                    budget_id: budget_id.clone(),
                    action,
                    amount: leftover,
                },
            );
        }
        Ok(())
    }

    /// Add the allowance of `idle` fully unspent periods to a rollover credit.
    ///
    /// A capped budget saturates instead of erroring: the total is clamped to
    /// the cap immediately afterwards, so a budget left dormant for a very long
    /// stretch settles at its cap rather than becoming permanently unusable.
    /// An uncapped budget uses checked math and surfaces [`Error::Overflow`].
    fn accrue_idle_periods(credit: i128, budget: &Budget, idle: i128) -> Result<i128, Error> {
        if budget.rollover_cap != 0 {
            return Ok(credit.saturating_add(budget.limit.saturating_mul(idle)));
        }
        checked_add(credit, checked_mul(budget.limit, idle)?)
    }

    /// Per-asset counterpart of [`Self::window_transition`]. Per-asset limits
    /// have no rollover: an unspent remainder is simply dropped when the window
    /// turns over. Persists and emits only when `publish` is set.
    fn asset_window_transition(
        env: &Env,
        asset_budget: &mut AssetBudget,
        budget_id: &String,
        token: &Address,
        publish: bool,
    ) {
        if asset_budget.window_seconds == 0 {
            return;
        }
        let now = env.ledger().timestamp();
        let elapsed = now.saturating_sub(asset_budget.window_start);
        if elapsed < asset_budget.window_seconds {
            return;
        }
        let periods = elapsed / asset_budget.window_seconds;
        asset_budget.spent = 0;
        asset_budget.window_start = asset_budget
            .window_start
            .saturating_add(periods.saturating_mul(asset_budget.window_seconds));
        env.storage().persistent().set(
            &DataKey::AssetBudget(budget_id.clone(), token.clone()),
            asset_budget,
        );
        Self::bump_asset(env, budget_id, token);
        if publish {
            Self::emit_asset_reset(env, budget_id, token, asset_budget.limit);
        }
    }

    fn emit_asset_reset(env: &Env, budget_id: &String, token: &Address, limit: i128) {
        env.events().publish(
            (symbol_short!("budget"), symbol_short!("ast_reset")),
            (budget_id.clone(), token.clone(), limit),
        );
        events::publish(
            env,
            ContractEvent::BudgetUpdated {
                budget_id: budget_id.clone(),
                action: Symbol::new(env, "asset_reset"),
                amount: limit,
            },
        );
    }

    /// Guard that rejects an expired budget.
    fn require_not_expired(env: &Env, budget: &Budget) -> Result<(), Error> {
        let now = env.ledger().timestamp();
        if budget.expires_at != 0 && now >= budget.expires_at {
            return Err(Error::BudgetExpired);
        }
        Ok(())
    }
    fn bump(env: &Env, id: &String) {
        env.storage().persistent().extend_ttl(
            &DataKey::Budget(id.clone()),
            PERSISTENT_LIFETIME_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
    }
    fn bump_asset(env: &Env, budget_id: &String, token: &Address) {
        env.storage().persistent().extend_ttl(
            &DataKey::AssetBudget(budget_id.clone(), token.clone()),
            PERSISTENT_LIFETIME_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
    }
}
// ---------------------------------------------------------------------------
// Shared interface implementation used by other contracts (e.g. Treasury).
// ---------------------------------------------------------------------------
#[contractimpl]
impl BudgetInterface for BudgetContract {
    /// Debit `amount` from the budget. Applies any pending period transition
    /// first, then enforces `spent + amount <= limit + rollover_credit`, else
    /// [`Error::BudgetExceeded`].
    fn consume(env: Env, caller: Address, budget_id: String, amount: i128) -> Result<i128, Error> {
        require_positive_amount(amount)?;
        let mut budget = Self::require_owner(&env, &budget_id, &caller)?;
        Self::require_active(&budget)?;
        Self::window_transition(&env, &mut budget, &budget_id, true)?;
        let capacity = checked_add(budget.limit, budget.rollover_credit)?;
        // When a deficit exists from prior periods, the effective spending
        // ceiling is reduced.  When no deficit exists yet, `allow_deficit`
        // lets the current period overspend (the excess becomes next-period
        // deficit).
        let ceiling = if budget.allow_deficit && budget.deficit_amount > 0 {
            checked_sub(capacity, budget.deficit_amount)?
        } else {
            capacity
        };
        let new_spent = checked_add(budget.spent, amount)?;
        if new_spent > ceiling {
            // With deficit allowed and no prior deficit, the first overspend is
            // permitted — it becomes the carried-forward deficit.
            if budget.allow_deficit && budget.deficit_amount == 0 {
                budget.spent = new_spent;
                Self::store(&env, &budget_id, &budget);
                // Checked: a genuine i128 overflow surfaces as [`Error::Overflow`]
                // instead of a panic; a negative result (deficit) is expected.
                let remaining = checked_sub(capacity, new_spent)?;
                env.events().publish(
                    (symbol_short!("budget"), symbol_short!("consumed")),
                    (budget_id, amount, remaining),
                );
                return Ok(remaining);
            }
            let remaining = checked_sub(ceiling, budget.spent)?;
            events::budget_exceeded(&env, &budget_id, amount, remaining);
            return Err(Error::BudgetExceeded);
        }
        budget.spent = new_spent;
        Self::store(&env, &budget_id, &budget);
        let remaining = checked_sub(ceiling, budget.spent)?;
        env.events().publish(
            (symbol_short!("budget"), symbol_short!("consumed")),
            (budget_id, amount, remaining),
        );
        Ok(remaining)
    }
    /// Credit `amount` back to the budget (a refunded or cancelled spend).
    /// Applies any pending period transition first, so an expired budget
    /// fails with [`Error::BudgetExpired`] instead of silently accepting the
    /// credit. Releasing more than has been spent in the current period fails
    /// with [`Error::InvalidAmount`]. Returns the new remaining allocation.
    fn release(env: Env, caller: Address, budget_id: String, amount: i128) -> Result<i128, Error> {
        require_positive_amount(amount)?;
        let mut budget = Self::require_owner(&env, &budget_id, &caller)?;
        Self::require_active(&budget)?;
        Self::window_transition(&env, &mut budget, &budget_id, true)?;
        if amount > budget.spent {
            return Err(Error::InvalidAmount);
        }
        budget.spent = checked_sub(budget.spent, amount)?;
        Self::store(&env, &budget_id, &budget);
        Self::effective_remaining(&budget)
    }

    /// Read remaining allocation, accounting for a pending period transition.
    fn remaining(env: Env, budget_id: String) -> Result<i128, Error> {
        let mut budget = Self::load(&env, &budget_id)?;
        // Don't emit events from a read-only view, but persist the period
        // transition so the rolled-over state is observable via `get`.
        if Self::window_transition(&env, &mut budget, &budget_id, false).is_ok() {
            Self::store(&env, &budget_id, &budget);
        } else {
            return Ok(0);
        }
        // Remaining is reduced by any carried-forward deficit. Checked at
        // every step: overflow returns [`Error::Overflow`], never wraps.
        Self::effective_remaining(&budget)
    }
}

// ---------------------------------------------------------------------------
// Registry-gated upgrades, exposed through the shared `UpgradeableInterface`.
// ---------------------------------------------------------------------------
#[contractimpl]
impl UpgradeableInterface for BudgetContract {
    /// Record (or rotate) who may upgrade this contract and which registry
    /// authorizes the new code. Bootstrapped by the deployer alongside
    /// `initialize`; afterwards only the current upgrade admin may rotate it.
    fn set_upgrade_authority(
        env: Env,
        caller: Address,
        admin: Address,
        registry: Address,
    ) -> Result<(), Error> {
        astroid_interfaces::upgrade::set_authority(&env, &caller, &admin, &registry)
    }

    /// Read the recorded upgrade authority.
    fn get_upgrade_authority(
        env: Env,
    ) -> Result<astroid_interfaces::upgrade::UpgradeAuthority, Error> {
        astroid_interfaces::upgrade::get_authority(&env)
    }

    /// Replace this contract's code with `wasm_hash`.
    ///
    /// Two gates must pass: `caller` must be the recorded upgrade admin, and
    /// `wasm_hash` must be approved for `ModuleKind::Budget` in the registry.
    /// Any other outcome leaves the contract running its current code.
    fn upgrade(env: Env, caller: Address, wasm_hash: soroban_sdk::BytesN<32>) -> Result<(), Error> {
        astroid_interfaces::upgrade::perform(
            &env,
            &caller,
            astroid_shared::types::ModuleKind::Budget,
            wasm_hash,
        )
    }
}

#[cfg(test)]
mod test;
