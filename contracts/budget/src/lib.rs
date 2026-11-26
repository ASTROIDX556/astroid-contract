#![no_std]
#![allow(clippy::too_many_arguments)]
//! # Astroid Budget Contract
//!
//! Enforces spending limits (PRD Doc 7 §Budget). Every spend calls
//! [`BudgetContract::consume`], which debits the remaining allocation and
//! reverts with [`Error::BudgetLimitReached`] when a spend would push spending past
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
//! (0 = uncapped). The closing balance *replaces* the credit carried into the
//! period instead of stacking on top of it, so an untouched budget gains
//! exactly one base limit per period and can never outrun the allowance it was
//! granted. The cap is what stops a budget that is left idle for a long stretch
//! from silently accruing a balance far larger than the limit it was granted,
//! which an agent could then drain in one period.
//!
//! ## Multi-token allowance validation (Issue #294)
//!
//! Alongside the token-agnostic [`BudgetContract::consume`], every token can
//! carry its own registered per-asset allowance
//! ([`BudgetContract::set_budget_limit`]) that recurs on a fixed window.
//! [`BudgetContract::check_and_record_batch_spend`] validates and records
//! spends across several tokens **atomically**: every leg is checked against
//! its registered allowance before anything is persisted, duplicate tokens are
//! rejected so a cap cannot be breached by splitting one spend into legs, and
//! unknown tokens fail with [`Error::AssetNotAuthorized`]. Batches are bounded
//! by [`MAX_BATCH_TOKENS`] to cap worst-case invocation cost.
//!
//! Functions: `allocate`, `set_recurrence`, `consume`, `reset`, `rollover`,
//! `freeze`, `unfreeze`, `archive`, `transfer_allocation`, plus the read-only
//! rollover calculation helper `rollover_preview`.
//!
//! ## Rollover calculation helper (Issue #313)
//!
//! [`BudgetContract::calculate_rollover`] is the pure function behind every
//! period transition: it reads the structured period record — the window
//! start (`window_start`), the window duration ([`Self::window_of`]), the
//! allocated amount (`limit`), the spent counter and the rollover flags —
//! and answers what the budget carries between periods, with no side
//! effects and no ledger dependency (the current time is a parameter).
//! [`BudgetContract::window_transition`] routes its carry computation
//! through it, and [`BudgetContract::rollover_preview`] exposes it as a
//! read-only view, so a preview and a transition can never disagree about
//! what a period boundary does. Rollover caps are enforced inside the
//! helper: the carry is always clamped to the effective cap — the smaller
//! of the owner's absolute `rollover_cap` and the protocol percentage
//! ceiling `rollover_max_bps` of the base limit — so no caller can obtain
//! an unclamped carry from the calculation.
//! `freeze`, `unfreeze`, `archive`, `transfer_allocation`,
//! `set_budget_limit`, `check_and_record_spend`,
//! `check_and_record_batch_spend`.
//!
//! ## Error codes
//!
//! Every handler validates its inputs before touching storage and fails with a
//! stable code from the shared [`Error`] table rather than panicking:
//!
//! Issue #503 gives the four budget-domain failures explicit names. Two are
//! named aliases that keep their published wire codes, so no consumer breaks:
//!
//! | Condition                                                   | Error                          | Code |
//! |-------------------------------------------------------------|--------------------------------|------|
//! | No budget exists for the id                                 | [`Error::BudgetNotFound`] (alias of `NotFound`) | 1 |
//! | Spend would exceed the effective ceiling / per-asset limit  | [`Error::ExceededSpendLimit`] (alias of `BudgetExceeded`) | 40 |
//! | Budget window has closed (`now >= expires_at`)              | [`Error::BudgetExpired`]       | 44 |
//! | Budget has not started yet (`now < starts_at`)              | [`BudgetError::BudgetNotActive`] | 45 |
//! | Expiry not after now/start, zero-length `Custom` interval, deficit on a non-recurring period | [`Error::InvalidTimeWindow`] | 46 |
//! | Spend / release / transfer amount `<= 0`                    | [`Error::InvalidAmount`]       | 12 |
//! | Negative limit or rollover cap                              | [`Error::InvalidAmount`]       | 12 |
//! | Limit below spent                                            | [`Error::InvalidInput`]        | 4  |
//! | Invalid rollover configuration                               | [`Error::InvalidRolloverConfig`] | 47 |
//! | Checked arithmetic in a spend/fund/allocate path overflowed  | [`Error::BUDGET_OVERFLOW`]     | 48 |
//! | Spend/consume would breach the effective ceiling            | [`Error::BUDGET_LIMIT_EXCEEDED`] | 49 |
//! | Rollover would settle more than `MAX_ROLLOVER_PERIODS`      | [`Error::BUDGET_ROLLOVER_EXCEEDED`] | 95 |
//! | Other checked arithmetic would overflow `i128`              | [`Error::Overflow`]            | 11 |
//! | Caller is not the budget owner                              | [`Error::Unauthorized`]        | 3  |
//! | Budget is frozen / archived                                 | [`Error::BudgetFrozen`] / [`Error::BudgetArchived`] | 41 / 42 |

use astroid_interfaces::{BudgetInterface, UpgradeableInterface};
use astroid_shared::constants::{
    BPS_DENOMINATOR, INSTANCE_BUMP_AMOUNT, INSTANCE_LIFETIME_THRESHOLD, MAX_BATCH_TOKENS,
    PERSISTENT_BUMP_AMOUNT, PERSISTENT_LIFETIME_THRESHOLD,
};
use astroid_shared::errors::{BudgetError, Error};
use astroid_shared::events::ContractEvent;
use astroid_shared::math::{
    calculate_budget_rollover, safe_add, safe_mul, safe_percentage, safe_sub,
};
use astroid_shared::types::ResourceState;
use astroid_shared::validation::{
    require_non_empty, require_non_negative_amount, require_positive_amount,
};
use astroid_shared::{constants, events};
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, Address, Env, String, Vec};

/// The largest number of whole periods a single rollover may settle (Issue
/// #447). A budget left dormant far longer than any protocol window would
/// otherwise force a catch-up over an unbounded number of periods; the rollover
/// is refused with [`Error::BUDGET_ROLLOVER_EXCEEDED`] instead, so a caller must
/// reconfigure the window or settle in bounded steps.
pub const MAX_ROLLOVER_PERIODS: u64 = 1024;

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
    /// Start of the current window (unix seconds). Also serves as the scheduled
    /// activation time until the budget first becomes active. Always sits on a
    /// period boundary once the budget has rolled at least once.
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
    /// Percentage of unspent allowance from period N to carry over into period N+1,
    /// in basis points (1 bp = 0.01%, 10_000 = 100%).
    pub rollover_bps: i128,
    /// Whether the budget allows spending beyond its limit (deficit).
    pub allow_deficit: bool,
    /// Accumulated deficit carried from prior periods.
    pub deficit_amount: i128,
    /// Unix timestamp after which the budget is expired (0 = never expires).
    pub expires_at: u64,
    pub state: ResourceState,
}

/// One leg of an atomic multi-token spend: `amount` of `token` against the
/// per-asset allowance registered for that token (see
/// [`BudgetContract::set_budget_limit`]).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssetSpend {
    pub token: Address,
    pub amount: i128,
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
    /// Whether unspent allowance carries into the next period on rollover.
    pub rollover_enabled: bool,
    /// Accumulated unspent allowance carried from prior periods (rollover).
    pub rollover_credit: i128,
    /// Percentage of unspent allowance to roll over, in basis points (1 bp = 0.01%, 10_000 = 100%).
    pub rollover_bps: i128,
    /// Upper bound on `rollover_credit` (0 = uncapped).
    pub max_rollover_cap: i128,
}
/// Result of the pure rollover calculation
/// ([`BudgetContract::calculate_rollover`]) for a budget at one instant.
///
/// A structured snapshot of the period transition the budget would take:
/// how many whole periods have elapsed, whether the current window has
/// lapsed, and what the budget carries between periods.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RolloverOutcome {
    /// The value carried between periods right now: with the window lapsed,
    /// the unspent remainder (clamped to the effective rollover cap) that
    /// moves into the next period — or, for a deficit budget, the over-spend
    /// that becomes a carried deficit. Before the boundary (or for a
    /// non-recurring budget) this is the credit already carried into the
    /// current period, and `deficit_amount` when the budget runs a deficit.
    pub carry_over: i128,
    /// Whole periods elapsed since `window_start` (0 before the boundary).
    pub periods: u64,
    /// Whether the current window has lapsed on the half-open
    /// `[window_start, window_start + duration)` rule — i.e. whether a
    /// transition is due.
    pub is_due: bool,
}

/// Snapshot of a budget's active spending window (Issue #495), returned by
/// [`BudgetContract::sync_window`] and [`BudgetContract::window_status`].
///
/// The window is half-open, `[window_start, window_end)`; `window_end` is `0`
/// for a budget that does not recur. `rolled_over` / `periods` report whether
/// the call settled (or, for the read-only view, would settle) a boundary and
/// how many whole windows that covered.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowStatus {
    pub window_start: u64,
    pub window_end: u64,
    pub spent: i128,
    pub remaining: i128,
    pub rolled_over: bool,
    pub periods: u64,
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
    ///
    /// `allow_deficit` requires a period that actually recurs — `Daily`,
    /// `Weekly` or `Monthly`. It is rejected for [`Period::None`] and for
    /// [`Period::Custom`], because a `Custom` budget has no interval until
    /// `set_recurrence` supplies one, so it has no next window for the
    /// overspend to be carried into and no way to repay it.
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
        let start_at = env.ledger().timestamp();
        Self::allocate_at(
            env,
            owner,
            budget_id,
            limit,
            period,
            rollover_enabled,
            allow_deficit,
            start_at,
            expires_at,
        )
    }

    /// Allocate a budget that becomes spendable at `start_at`.
    ///
    /// This additive entrypoint preserves the existing allocation signatures
    /// and stored [`Budget`] layout. A `start_at` at or before the current
    /// ledger timestamp is immediately active; a future start is enforced on
    /// every spend and allowance verification. `expires_at` must be zero
    /// (never) or later than both the current timestamp and `start_at`.
    pub fn allocate_scheduled(
        env: Env,
        owner: Address,
        budget_id: String,
        limit: i128,
        period: Period,
        rollover_enabled: bool,
        start_at: u64,
        expires_at: u64,
    ) -> Result<(), Error> {
        Self::allocate_at(
            env,
            owner,
            budget_id,
            limit,
            period,
            rollover_enabled,
            false,
            start_at,
            expires_at,
        )
    }

    /// Allocate a budget with an optional explicit rollover configuration (owner-gated).
    ///
    /// `rollover_bps` specifies the percentage (in basis points) of unspent funds
    /// to carry over into the next period (e.g. 5_000 for 50%).
    /// `max_rollover_cap` sets an upper bound on accumulated rollover credit (0 = uncapped).
    pub fn allocate_with_rollover(
        env: Env,
        owner: Address,
        budget_id: String,
        limit: i128,
        period: Period,
        rollover_enabled: bool,
        rollover_bps: i128,
        max_rollover_cap: i128,
        expires_at: u64,
    ) -> Result<(), Error> {
        Self::require_valid_limit(max_rollover_cap)?;
        Self::require_valid_limit(rollover_bps)?;
        if rollover_bps > BPS_DENOMINATOR {
            return Err(Error::InvalidRolloverConfig);
        }
        let start_at = env.ledger().timestamp();
        Self::allocate_internal(
            env,
            owner,
            budget_id,
            limit,
            period,
            rollover_enabled,
            rollover_bps,
            max_rollover_cap,
            false,
            start_at,
            expires_at,
        )
    }

    fn allocate_at(
        env: Env,
        owner: Address,
        budget_id: String,
        limit: i128,
        period: Period,
        rollover_enabled: bool,
        allow_deficit: bool,
        start_at: u64,
        expires_at: u64,
    ) -> Result<(), Error> {
        let rollover_bps = if rollover_enabled { BPS_DENOMINATOR } else { 0 };
        Self::allocate_internal(
            env,
            owner,
            budget_id,
            limit,
            period,
            rollover_enabled,
            rollover_bps,
            0,
            allow_deficit,
            start_at,
            expires_at,
        )
    }

    fn allocate_internal(
        env: Env,
        owner: Address,
        budget_id: String,
        limit: i128,
        period: Period,
        rollover_enabled: bool,
        rollover_bps: i128,
        rollover_cap: i128,
        allow_deficit: bool,
        start_at: u64,
        expires_at: u64,
    ) -> Result<(), Error> {
        owner.require_auth();
        require_non_empty(&budget_id)?;
        Self::require_valid_limit(limit)?;
        Self::require_valid_limit(rollover_cap)?;
        Self::require_valid_limit(rollover_bps)?;
        if rollover_bps > BPS_DENOMINATOR {
            return Err(Error::InvalidRolloverConfig);
        }
        let now = env.ledger().timestamp();
        // A budget that is already expired at creation, or expires before it
        // starts, could never be spent.
        if expires_at != 0 && (expires_at <= now || expires_at <= start_at) {
            return Err(Error::InvalidTimeWindow);
        }
        // Deficit carryforward only makes sense with a recurring period: the
        // overspend has to land in a *next* window to be repaid out of, and
        // `window_transition` is the only place that records it. So the test is
        // "does this budget recur?", asked through the same `window_of` the
        // state machine uses, not a match on `Period` alone.
        //
        // `Period::Custom` is the case that matters. Until `set_recurrence`
        // supplies an interval a `Custom` budget stores `period_seconds == 0`,
        // which makes it exactly as non-recurring as `Period::None` — yet
        // admitting it here let the first overspend run away. With no window to
        // roll over, `window_transition` returns before reaching its deficit
        // branch, so `deficit_amount` stayed 0 while `spent` ran past the
        // limit. `consume` grants the overspend on `allow_deficit &&
        // deficit_amount == 0`, so that stayed true forever: every further
        // `consume` was permitted and `remaining` fell without bound, with no
        // deficit ever booked to repay. Creation always stores
        // `period_seconds: 0`, so the interval argument is 0 here by
        // construction.
        if allow_deficit && Self::window_of(period, 0).is_none() {
            return Err(Error::InvalidTimeWindow);
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
            window_start: start_at,
            rollover_enabled,
            rollover_credit: 0,
            rollover_cap,
            rollover_max_bps: 0,
            rollover_bps,
            allow_deficit,
            deficit_amount: 0,
            expires_at,
            state: ResourceState::Active,
        };
        env.storage().persistent().set(&key, &budget);
        Self::bump(&env, &budget_id);
        events::budget_updated(
            &env,
            &budget_id,
            symbol_short!("allocated"),
            limit,
            (budget_id.clone(), owner, limit),
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
    /// percentage of 100% or more is rejected with [`Error::InvalidRolloverConfig`] so
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
            return Err(Error::InvalidRolloverConfig);
        }
        if period == Period::Custom && period_seconds == 0 {
            return Err(Error::InvalidTimeWindow);
        }
        let mut budget = Self::require_owner(&env, &budget_id, &caller)?;
        Self::require_active(&budget)?;
        let now = env.ledger().timestamp();
        let scheduled_for_future = now < budget.window_start;
        if scheduled_for_future {
            Self::require_not_expired(&env, &budget)?;
        } else {
            // Settle what the old policy already owes before adopting the new
            // one; preserve a future start when configuring a scheduled budget.
            Self::check_and_rollover_window(&env, &budget_id, &mut budget)?;
        }

        budget.period = period;
        budget.period_seconds = if period == Period::Custom {
            period_seconds
        } else {
            0
        };
        budget.rollover_enabled = rollover_enabled;
        budget.rollover_cap = rollover_cap;
        budget.rollover_max_bps = rollover_max_bps;
        if rollover_enabled && budget.rollover_bps == 0 {
            budget.rollover_bps = BPS_DENOMINATOR;
        } else if !rollover_enabled {
            budget.rollover_bps = 0;
        }
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
        if !scheduled_for_future {
            budget.window_start = now;
        }
        Self::store(&env, &budget_id, &budget);
        events::budget_updated(
            &env,
            &budget_id,
            symbol_short!("recurring"),
            rollover_cap,
            (budget_id.clone(), period, period_seconds, rollover_cap),
        );
        Ok(())
    }

    /// Configure rollover accounting parameters for a budget (owner-gated).
    pub fn set_rollover_config(
        env: Env,
        caller: Address,
        budget_id: String,
        rollover_enabled: bool,
        rollover_bps: i128,
        max_rollover_cap: i128,
    ) -> Result<(), Error> {
        Self::require_valid_limit(max_rollover_cap)?;
        Self::require_valid_limit(rollover_bps)?;
        if rollover_bps > BPS_DENOMINATOR {
            return Err(Error::InvalidRolloverConfig);
        }
        let mut budget = Self::require_owner(&env, &budget_id, &caller)?;
        Self::require_active(&budget)?;
        Self::require_not_expired(&env, &budget)?;
        // Settle pending transition if due
        Self::check_and_rollover_window(&env, &budget_id, &mut budget)?;

        budget.rollover_enabled = rollover_enabled;
        budget.rollover_bps = rollover_bps;
        budget.rollover_cap = max_rollover_cap;
        if !rollover_enabled {
            budget.rollover_credit = 0;
        } else if budget.rollover_credit > 0 {
            budget.rollover_credit = Self::apply_cap(
                budget.rollover_credit,
                Self::effective_rollover_cap(&budget)?,
            );
        }
        Self::store(&env, &budget_id, &budget);
        events::budget_updated(
            &env,
            &budget_id,
            symbol_short!("rollover"),
            max_rollover_cap,
            (budget_id.clone(), rollover_bps, max_rollover_cap),
        );
        Ok(())
    }

    /// Reset the spent counter to zero (owner-gated). Also refreshes the window.
    /// Rejects expired budgets.
    pub fn reset(env: Env, caller: Address, budget_id: String) -> Result<(), Error> {
        let mut budget = Self::require_owner(&env, &budget_id, &caller)?;
        Self::require_not_archived(&budget)?;
        Self::require_started(&env, &budget).map_err(Error::from)?;
        Self::require_not_expired(&env, &budget)?;
        budget.spent = 0;
        budget.rollover_credit = 0;
        budget.window_start = env.ledger().timestamp();
        Self::store(&env, &budget_id, &budget);
        events::budget_updated(
            &env,
            &budget_id,
            symbol_short!("reset"),
            0,
            budget_id.clone(),
        );
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
        Self::check_and_rollover_window(&env, &budget_id, &mut budget)?;
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
        Self::check_and_rollover_window(&env, &budget_id, &mut budget)?;
        if new_limit < budget.spent {
            return Err(Error::InvalidInput);
        }
        budget.limit = new_limit;
        Self::store(&env, &budget_id, &budget);
        events::budget_updated(
            &env,
            &budget_id,
            symbol_short!("setlimit"),
            new_limit,
            (budget_id.clone(), new_limit),
        );
        Ok(())
    }
    /// Fund (top up) a budget: raise its per-period `limit` by `amount`.
    ///
    /// Owner-gated, and refused on an archived budget. `amount` must be
    /// strictly positive and the new limit is computed with checked math, so
    /// a top-up can never wrap. Any pending period transition is applied
    /// first, so the extra allowance lands in the *current* window. Emits
    /// `("budget", "funded")`, the canonical `BudgetUpdated`, and
    /// `("budget", "replenish")` with the headroom now available. Returns the
    /// new limit.
    pub fn fund(env: Env, caller: Address, budget_id: String, amount: i128) -> Result<i128, Error> {
        require_positive_amount(amount)?;
        let mut budget = Self::require_owner(&env, &budget_id, &caller)?;
        Self::require_not_archived(&budget)?;
        Self::check_and_rollover_window(&env, &budget_id, &mut budget)?;
        budget.limit = safe_add(budget.limit, amount).map_err(|_| Error::BUDGET_OVERFLOW)?;
        Self::store(&env, &budget_id, &budget);
        events::budget_updated(
            &env,
            &budget_id,
            symbol_short!("funded"),
            amount,
            (budget_id.clone(), amount, budget.limit),
        );
        let available = Self::effective_remaining(&budget)
            .unwrap_or(i128::MAX)
            .max(0);
        events::budget_refilled(&env, &budget_id, None, available);
        Ok(budget.limit)
    }
    /// Freeze a budget (owner-gated). Frozen budgets reject consumption.
    pub fn freeze(env: Env, caller: Address, budget_id: String) -> Result<(), Error> {
        let mut budget = Self::require_owner(&env, &budget_id, &caller)?;
        if budget.state == ResourceState::Archived {
            return Err(Error::BudgetArchived);
        }
        budget.state = ResourceState::Frozen;
        Self::store(&env, &budget_id, &budget);
        events::budget_updated(
            &env,
            &budget_id,
            symbol_short!("frozen"),
            0,
            budget_id.clone(),
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
        events::budget_updated(
            &env,
            &budget_id,
            symbol_short!("unfrozen"),
            0,
            budget_id.clone(),
        );
        Ok(())
    }
    /// Archive a budget (owner-gated, terminal). Rejects further consumption.
    pub fn archive(env: Env, caller: Address, budget_id: String) -> Result<(), Error> {
        let mut budget = Self::require_owner(&env, &budget_id, &caller)?;
        budget.state = ResourceState::Archived;
        Self::store(&env, &budget_id, &budget);
        events::budget_updated(
            &env,
            &budget_id,
            symbol_short!("archived"),
            0,
            budget_id.clone(),
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
        let available = safe_sub(from.limit, from.spent).map_err(|_| Error::BUDGET_OVERFLOW)?;
        if amount > available {
            return Err(Error::BUDGET_LIMIT_EXCEEDED);
        }
        from.limit = safe_sub(from.limit, amount).map_err(|_| Error::BUDGET_OVERFLOW)?;
        to.limit = safe_add(to.limit, amount).map_err(|_| Error::BUDGET_OVERFLOW)?;
        Self::store(&env, &from_id, &from);
        Self::store(&env, &to_id, &to);
        events::budget_updated(
            &env,
            &from_id,
            symbol_short!("realloc"),
            amount,
            (from_id.clone(), to_id.clone(), amount),
        );
        events::publish(
            &env,
            ContractEvent::BudgetUpdated {
                budget_id: to_id.clone(),
                action: symbol_short!("realloc"),
                amount,
            },
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
            window_start: budget.window_start.max(env.ledger().timestamp()),
            rollover_enabled: false,
            rollover_credit: 0,
            rollover_bps: 0,
            max_rollover_cap: 0,
        };
        env.storage().persistent().set(&key, &asset_budget);
        Self::bump_asset(&env, &budget_id, &token);
        events::budget_updated(
            &env,
            &budget_id,
            symbol_short!("set_ast"),
            limit,
            (budget_id.clone(), token.clone(), limit),
        );
        Ok(())
    }

    /// Set the recurring limit and rollover configuration for a specific token (owner-gated).
    pub fn set_budget_limit_with_rollover(
        env: Env,
        caller: Address,
        budget_id: String,
        token: Address,
        limit: i128,
        window_seconds: u64,
        rollover_enabled: bool,
        rollover_bps: i128,
        max_rollover_cap: i128,
    ) -> Result<(), Error> {
        Self::require_valid_limit(limit)?;
        Self::require_valid_limit(max_rollover_cap)?;
        Self::require_valid_limit(rollover_bps)?;
        if rollover_bps > BPS_DENOMINATOR {
            return Err(Error::InvalidRolloverConfig);
        }
        let budget = Self::require_owner(&env, &budget_id, &caller)?;
        Self::require_active(&budget)?;
        Self::require_not_expired(&env, &budget)?;
        let key = DataKey::AssetBudget(budget_id.clone(), token.clone());
        let asset_budget = AssetBudget {
            limit,
            spent: 0,
            window_seconds,
            window_start: budget.window_start.max(env.ledger().timestamp()),
            rollover_enabled,
            rollover_credit: 0,
            rollover_bps,
            max_rollover_cap,
        };
        env.storage().persistent().set(&key, &asset_budget);
        Self::bump_asset(&env, &budget_id, &token);
        events::budget_updated(
            &env,
            &budget_id,
            symbol_short!("set_ast"),
            limit,
            (budget_id.clone(), token.clone(), limit),
        );
        Ok(())
    }

    /// Configure rollover accounting parameters for a specific token's budget (owner-gated).
    pub fn set_asset_rollover_config(
        env: Env,
        caller: Address,
        budget_id: String,
        token: Address,
        rollover_enabled: bool,
        rollover_bps: i128,
        max_rollover_cap: i128,
    ) -> Result<(), Error> {
        Self::require_valid_limit(max_rollover_cap)?;
        Self::require_valid_limit(rollover_bps)?;
        if rollover_bps > BPS_DENOMINATOR {
            return Err(Error::InvalidRolloverConfig);
        }
        let budget = Self::require_owner(&env, &budget_id, &caller)?;
        Self::require_active(&budget)?;
        Self::require_not_expired(&env, &budget)?;
        let key = DataKey::AssetBudget(budget_id.clone(), token.clone());
        let mut asset_budget: AssetBudget = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(Error::AssetNotAuthorized)?;
        Self::asset_window_transition(&env, &mut asset_budget, &budget_id, &token, true);

        asset_budget.rollover_enabled = rollover_enabled;
        asset_budget.rollover_bps = rollover_bps;
        asset_budget.max_rollover_cap = max_rollover_cap;
        if !rollover_enabled {
            asset_budget.rollover_credit = 0;
        } else if max_rollover_cap > 0 && asset_budget.rollover_credit > max_rollover_cap {
            asset_budget.rollover_credit = max_rollover_cap;
        }
        env.storage().persistent().set(&key, &asset_budget);
        Self::bump_asset(&env, &budget_id, &token);
        events::budget_updated(
            &env,
            &budget_id,
            symbol_short!("ast_roll"),
            max_rollover_cap,
            (
                budget_id.clone(),
                token.clone(),
                rollover_bps,
                max_rollover_cap,
            ),
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
    ) -> Result<(), BudgetError> {
        require_positive_amount(amount)?;
        let budget = Self::require_owner(&env, &budget_id, &caller)?;
        Self::require_active(&budget)?;
        Self::require_started(&env, &budget)?;
        Self::require_not_expired(&env, &budget)?;
        let key = DataKey::AssetBudget(budget_id.clone(), token.clone());
        let mut asset_budget: AssetBudget = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(Error::AssetNotAuthorized)?;
        // Recurring per-asset limits replenish lazily, on the spend itself.
        // The hook settles every elapsed window and re-anchors `window_start`
        // to the boundary, so the spend below always sees the current period
        // and no second reset (with a `now`-based anchor, which would drift
        // off the schedule) can fire afterwards.
        Self::asset_window_transition(&env, &mut asset_budget, &budget_id, &token, true);

        // Check if within limit (accounting for any rollover credit)
        let capacity = Self::asset_capacity(&asset_budget)?;
        let new_spent =
            safe_add(asset_budget.spent, amount).map_err(|_| BudgetError::BUDGET_OVERFLOW)?;
        if new_spent > capacity {
            return Err(BudgetError::BUDGET_LIMIT_EXCEEDED);
        }
        asset_budget.spent = new_spent;
        env.storage().persistent().set(&key, &asset_budget);
        Self::bump_asset(&env, &budget_id, &token);
        events::budget_updated(
            &env,
            &budget_id,
            symbol_short!("ast_spend"),
            amount,
            (budget_id.clone(), token.clone(), amount),
        );
        if new_spent >= capacity {
            events::budget_exhausted(&env, &budget_id, Some(token.clone()), new_spent, capacity);
        }
        Ok(())
    }

    /// Validate and record spends across multiple tokens atomically
    /// (Issue #294).
    ///
    /// Every `(token, amount)` leg is validated against its registered
    /// per-asset allowance **before** any spend is written: each token must
    /// have a limit registered via [`Self::set_budget_limit`] (otherwise
    /// [`Error::AssetNotAuthorized`]), amounts must be positive, duplicate
    /// tokens are rejected with [`Error::InvalidInput`] so a spend cannot be
    /// split into legs that individually fit but jointly breach the cap, and
    /// each leg's new spent total must stay within the token's current-window
    /// limit ([`Error::BudgetLimitReached`] otherwise). Only when every leg passes
    /// are all new spent totals persisted — a single breach rejects the whole
    /// batch and leaves every ledger untouched. Time-based window resets,
    /// lifecycle state and the scheduled-start gate are checked exactly as
    /// [`Self::check_and_record_spend`] does, and — like that entrypoint — the
    /// refusal is reported through [`BudgetError`] so a not-yet-started budget
    /// keeps its distinct `BudgetNotActive` code instead of folding onto the
    /// shared table.
    pub fn check_and_record_batch_spend(
        env: Env,
        caller: Address,
        budget_id: String,
        spends: Vec<AssetSpend>,
    ) -> Result<(), BudgetError> {
        if spends.is_empty() || spends.len() > MAX_BATCH_TOKENS {
            return Err(Error::InvalidInput.into());
        }
        let budget = Self::require_owner(&env, &budget_id, &caller)?;
        Self::require_active(&budget)?;
        // A scheduled budget blocks every spend path until its inclusive
        // start, batch included — without this gate the batch entrypoint was
        // the one way to spend an envelope before it activated.
        Self::require_started(&env, &budget)?;
        Self::require_not_expired(&env, &budget)?;

        // First pass: settle each token's window and simulate its leg without
        // persisting any spend, so a late failure cannot leave a partial
        // batch behind.
        let mut settled: Vec<AssetBudget> = Vec::new(&env);
        for i in 0..spends.len() {
            let spend = spends.get(i).unwrap();
            require_positive_amount(spend.amount)?;
            // A duplicate token would validate each leg against a stale
            // spent counter, letting the legs jointly exceed the cap.
            for j in 0..i {
                if spends.get(j).unwrap().token == spend.token {
                    return Err(Error::InvalidInput.into());
                }
            }
            let key = DataKey::AssetBudget(budget_id.clone(), spend.token.clone());
            let mut asset_budget: AssetBudget = env
                .storage()
                .persistent()
                .get(&key)
                .ok_or(Error::AssetNotAuthorized)?;
            Self::asset_window_transition(&env, &mut asset_budget, &budget_id, &spend.token, true);

            // Same ceiling as the single-leg path: the base limit plus any
            // rollover credit banked from earlier windows. Checking against
            // the bare limit refused spends `check_and_record_spend` accepts.
            let new_spent = safe_add(asset_budget.spent, spend.amount)
                .map_err(|_| BudgetError::BUDGET_OVERFLOW)?;
            if new_spent > Self::asset_capacity(&asset_budget)? {
                return Err(BudgetError::BUDGET_LIMIT_EXCEEDED);
            }
            asset_budget.spent = new_spent;
            settled.push_back(asset_budget);
        }

        // Second pass: every leg validated — record the batch atomically.
        for i in 0..spends.len() {
            let spend = spends.get(i).unwrap();
            env.storage().persistent().set(
                &DataKey::AssetBudget(budget_id.clone(), spend.token.clone()),
                &settled.get(i).unwrap(),
            );
            Self::bump_asset(&env, &budget_id, &spend.token);
            events::budget_updated(
                &env,
                &budget_id,
                symbol_short!("ast_spend"),
                spend.amount,
                (budget_id.clone(), spend.token.clone(), spend.amount),
            );
            let leg = settled.get(i).unwrap();
            let capacity = Self::asset_capacity(&leg)?;
            if leg.spent >= capacity {
                events::budget_exhausted(
                    &env,
                    &budget_id,
                    Some(spend.token.clone()),
                    leg.spent,
                    capacity,
                );
            }
        }
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
        let asset_budget = Self::get_asset_budget(env.clone(), budget_id.clone(), token)?;
        let budget = Self::load(&env, &budget_id)?;
        if env.ledger().timestamp() < budget.window_start {
            return Ok(0);
        }
        let capacity = if asset_budget.rollover_enabled {
            safe_add(asset_budget.limit, asset_budget.rollover_credit)?
        } else {
            asset_budget.limit
        };
        safe_sub(capacity, asset_budget.spent)
    }

    /// Settle a budget's spending window against the ledger clock
    /// (Issue #495). Permissionless: the outcome is a pure function of the
    /// stored record and `env.ledger().timestamp()`, so a keeper (or any
    /// client) may trigger it — exactly as every spend does lazily through
    /// [`Self::check_and_rollover_window`].
    ///
    /// When the current ledger timestamp is at or past the active window end
    /// (`window_start + duration`, half-open), every elapsed window is settled
    /// at once: the spend counter resets to zero, rollover credit is
    /// recomputed, `window_start` re-anchors to the boundary, and the
    /// `("budget", "win_roll")` event is published. The budget's parameters
    /// (limit, period, rollover and deficit configuration, expiry) are never
    /// touched. Before the boundary — or before a scheduled budget starts —
    /// nothing changes and `rolled_over` is `false`.
    ///
    /// Errors: [`Error::NotFound`], [`Error::BudgetArchived`],
    /// [`Error::BudgetExpired`] past `expires_at`, and
    /// [`Error::InvalidTimeWindow`] for a window record that cannot be
    /// settled deterministically.
    pub fn sync_window(env: Env, budget_id: String) -> Result<WindowStatus, Error> {
        let mut budget = Self::load(&env, &budget_id)?;
        Self::require_not_archived(&budget)?;
        if env.ledger().timestamp() < budget.window_start {
            return Self::window_status_of(&budget, 0);
        }
        let periods = Self::check_and_rollover_window(&env, &budget_id, &mut budget)?;
        if periods > 0 {
            Self::store(&env, &budget_id, &budget);
        }
        Self::window_status_of(&budget, periods)
    }

    /// Read-only counterpart of [`Self::sync_window`]: the window the budget
    /// is in right now, as it would be after settling any lapsed boundary.
    /// Persists and publishes nothing.
    pub fn window_status(env: Env, budget_id: String) -> Result<WindowStatus, Error> {
        let mut budget = Self::load(&env, &budget_id)?;
        if env.ledger().timestamp() < budget.window_start {
            return Self::window_status_of(&budget, 0);
        }
        Self::validate_window(&budget)?;
        let before = budget.window_start;
        Self::window_transition(&env, &mut budget, &budget_id, false)?;
        let periods = Self::periods_between(&budget, before);
        Self::window_status_of(&budget, periods)
    }

    /// Read-only preview of the rollover calculation for `budget_id`
    /// (Issue #313): the same [`RolloverOutcome`] a period transition would
    /// apply, without mutating anything.
    ///
    /// The evaluation is the pure calculation itself — no storage write, no
    /// event — so it is safe to call from any client that wants to know what
    /// a boundary will do before it happens. Because
    /// [`BudgetContract::window_transition`] routes its carry computation
    /// through [`Self::calculate_rollover`], a preview can never disagree
    /// with the transition it previews: both clamp the carry to the same
    /// effective cap.
    ///
    /// Errors mirror the transition paths: an unknown id reports
    /// [`Error::NotFound`]; an expired budget reports
    /// [`Error::BudgetExpired`] exactly as [`Self::window_transition`] would.
    /// A budget whose idle-period accrual (uncapped rollover across a long
    /// gap) would overflow `i128` reports [`Error::Overflow`] — the same
    /// failure the transition itself would hit.
    pub fn rollover_preview(env: Env, budget_id: String) -> Result<RolloverOutcome, Error> {
        let budget = Self::load(&env, &budget_id)?;
        let now = env.ledger().timestamp();
        if budget.expires_at != 0 && now >= budget.expires_at {
            return Err(Error::BudgetExpired);
        }
        Self::calculate_rollover(&budget, now)
    }

    // --- internal helpers ---
    fn load(env: &Env, id: &String) -> Result<Budget, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::Budget(id.clone()))
            .ok_or(Error::BudgetNotFound)
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
    ///
    /// Delegates to the shared guard so "non-negative" means the same thing
    /// here as in the policy contract, and so both return [`Error::InvalidAmount`]
    /// for the same input.
    fn require_valid_limit(limit: i128) -> Result<(), Error> {
        require_non_negative_amount(limit)
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
        let capacity = safe_add(budget.limit, budget.rollover_credit)?;
        if budget.allow_deficit && budget.deficit_amount > 0 {
            let net = safe_sub(capacity, budget.deficit_amount)?;
            safe_sub(net, budget.spent)
        } else {
            safe_sub(capacity, budget.spent)
        }
    }
    fn require_active(budget: &Budget) -> Result<(), Error> {
        match budget.state {
            ResourceState::Active => Ok(()),
            ResourceState::Frozen | ResourceState::Paused => Err(Error::BudgetFrozen),
            ResourceState::Archived => Err(Error::BudgetArchived),
        }
    }

    /// The window length implied by a period/interval pair, or `None` when the
    /// budget does not recur (one-shot, or a `Custom` period with no interval
    /// configured yet).
    ///
    /// Takes its cadence as arguments rather than a whole [`Budget`] so that
    /// creation-time validation can ask the *same* question the state machine
    /// asks at runtime — see [`Self::allocate_at`], which rejects a deficit
    /// policy on any period this returns `None` for. Deriving the guard from one
    /// predicate is what keeps "recurring enough to carry a deficit" from
    /// drifting away from "recurring enough for `window_transition` to fire".
    fn window_of(period: Period, period_seconds: u64) -> Option<u64> {
        match period {
            Period::None => None,
            Period::Daily => Some(constants::SECONDS_PER_DAY),
            Period::Weekly => Some(constants::SECONDS_PER_WEEK),
            Period::Monthly => Some(constants::SECONDS_PER_MONTH),
            Period::Custom => {
                if period_seconds == 0 {
                    None
                } else {
                    Some(period_seconds)
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
    /// The pure rollover calculation behind every period transition
    /// (Issue #313). Answers, for `now`, what a recurring budget carries
    /// between periods: how many whole periods have elapsed since the window
    /// started, whether the current window has lapsed, and the value moving
    /// across the boundary.
    ///
    /// **Pure.** No storage access, no event, no ledger read — `now` is the
    /// caller's instant, so the answer for a given `(budget, now)` pair is
    /// reproducible and both [`Self::window_transition`] and the read-only
    /// [`Self::rollover_preview`] view route through this one function. The
    /// structured period record ([`Budget`]) supplies everything else: the
    /// window start, the duration ([`Self::window_of`]), the allocated
    /// amount (`limit`), the spent counter and the rollover flags.
    ///
    /// **Caps enforced here.** The carry is clamped to the *effective* cap —
    /// the smaller of the owner's absolute `rollover_cap` and the protocol
    /// percentage ceiling `rollover_max_bps` of the base limit — via
    /// [`Self::effective_rollover_cap`], so no caller (present or future)
    /// can obtain an unclamped carry from this calculation.
    ///
    /// Semantics match the transition they back:
    ///
    /// - a non-recurring budget (or one whose window has not lapsed) reports
    ///   `periods = 0`, `is_due = false` and the credit already carried into
    ///   the current period;
    /// - when the window has lapsed with rollover **enabled**, the carry is
    ///   the `rollover_bps` percentage of the unspent remainder of
    ///   `limit + rollover_credit`, plus one full base limit per fully idle
    ///   period inside a multi-period gap, then clamped once more to the
    ///   effective cap. Rollover does not compound: only the immediately
    ///   preceding period contributes its remainder (the deliberate design
    ///   behind the cap);
    /// - with rollover **disabled** the carry is 0 — the unspent remainder
    ///   is dropped at the boundary;
    /// - a deficit budget whose `spent` exceeds capacity reports the over-
    ///   spend as a *negative* carry: at the boundary it becomes an added
    ///   carried deficit, and no surplus is banked.
    ///
    /// Every step uses the shared checked arithmetic, so an out-of-range
    /// value surfaces [`Error::Overflow`] rather than wrapping.
    fn calculate_rollover(budget: &Budget, now: u64) -> Result<RolloverOutcome, Error> {
        let window = match Self::window_of(budget.period, budget.period_seconds) {
            Some(w) => w,
            None => {
                return Ok(RolloverOutcome {
                    carry_over: budget.rollover_credit,
                    periods: 0,
                    is_due: false,
                })
            }
        };
        // The single place the period-lapse rule lives: half-open
        // [start, start + window), so a timestamp equal to the window end
        // already belongs to the next period.
        let is_due = Self::is_window_expired(budget, now)?;
        if !is_due {
            return Ok(RolloverOutcome {
                carry_over: budget.rollover_credit,
                periods: 0,
                is_due: false,
            });
        }
        let elapsed = now.saturating_sub(budget.window_start);
        // Whole periods to settle. `window` is non-zero, so this is >= 1.
        let periods = (elapsed / window) as i128;
        // Bounded catch-up (Issue #447). Refuse an unbounded gap with a
        // dedicated, deterministic code rather than walking an arbitrary number
        // of periods or silently clamping the accumulated allowance. Because
        // this runs before any write, the whole invocation reverts atomically.
        if periods > MAX_ROLLOVER_PERIODS as i128 {
            return Err(Error::BUDGET_ROLLOVER_EXCEEDED);
        }

        // The current period's remainder, plus one full base limit for every
        // further period that came and went entirely untouched. `leftover`
        // already accounts for any credit carried into this window because
        // the period's capacity is `limit + rollover_credit`. Re-adding the
        // old credit would count it a second time.
        let capacity = safe_add(budget.limit, budget.rollover_credit)?;
        let leftover = safe_sub(capacity, budget.spent)?;

        let carry = if budget.allow_deficit && budget.spent > capacity {
            // Deficit: spent exceeded capacity (base limit + rollover
            // credit). Track it as a negative carry so the boundary turns it
            // into next period's reduced effective limit, and no surplus is
            // banked. `spent > capacity` with `!allow_deficit` cannot happen
            // — consume rejects it — so it is handled defensively below.
            safe_sub(capacity, budget.spent)?
        } else if budget.rollover_enabled {
            // A negative closing balance (`spent` above `capacity`, reachable
            // when the owner tightens the cap mid-period through
            // `set_recurrence`) carries as zero: a shortfall is never an
            // allowance for the next window, and carrying it would pin the
            // budget to a permanently reduced ceiling. (`spent > capacity`
            // with `allow_deficit` is handled by the deficit arm above.)
            let unspent = if leftover > 0 { leftover } else { 0 };
            let cap = Self::effective_rollover_cap(budget)?;
            // The carry is the `rollover_bps` percentage of the unspent
            // remainder, clamped to the effective cap in the same step by the
            // shared calculation (mirroring `window_transition`).
            let mut credit = calculate_budget_rollover(unspent, budget.rollover_bps, cap)?;
            if periods > 1 {
                let idle = safe_sub(periods, 1)?;
                credit = Self::accrue_idle_periods(credit, budget, idle)?;
                credit = Self::apply_cap(credit, cap);
            }
            credit
        } else {
            // Rollover disabled: the unspent remainder is dropped.
            0
        };

        Ok(RolloverOutcome {
            carry_over: carry,
            periods: periods as u64,
            is_due: true,
        })
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
        safe_percentage(limit, bps)
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
    fn is_window_expired(budget: &Budget, now: u64) -> Result<bool, Error> {
        let window = match Self::window_of(budget.period, budget.period_seconds) {
            Some(w) => w,
            None => return Ok(false),
        };
        let end = budget
            .window_start
            .checked_add(window)
            .ok_or(Error::Overflow)?;
        Ok(now >= end)
    }

    /// Window rollover check invoked at the start of every spend validation
    /// (Issue #495).
    ///
    /// Validates that the window record can be settled deterministically,
    /// then applies [`Self::window_transition`]: when the ledger timestamp is
    /// at or past the active window end, every elapsed window is settled at
    /// once — spend counter reset to zero, rollover credit recomputed,
    /// `window_start` re-anchored to the boundary — and the rollover events
    /// (including the standard `("budget", "win_roll")`) are published. The
    /// budget's configured parameters are left untouched.
    ///
    /// Returns the number of whole windows rolled over (`0` when the current
    /// window is still open or the budget does not recur). Mutates `budget`
    /// in place; the caller persists it. Never panics: all time arithmetic is
    /// checked, and an abnormal record reports
    /// [`Error::InvalidTimeWindow`].
    fn check_and_rollover_window(
        env: &Env,
        budget_id: &String,
        budget: &mut Budget,
    ) -> Result<u64, Error> {
        Self::validate_window(budget)?;
        let before = budget.window_start;
        Self::window_transition(env, budget, budget_id, true)?;
        Ok(Self::periods_between(budget, before))
    }

    /// Reject a window record a rollover cannot settle deterministically: a
    /// window end that is not representable as a ledger timestamp, or a
    /// negative counter (neither is reachable through the public API, so
    /// either indicates corrupted state).
    fn validate_window(budget: &Budget) -> Result<(), Error> {
        if budget.spent < 0 || budget.limit < 0 || budget.rollover_credit < 0 {
            return Err(Error::InvalidTimeWindow);
        }
        if let Some(window) = Self::window_of(budget.period, budget.period_seconds) {
            budget
                .window_start
                .checked_add(window)
                .ok_or(Error::InvalidTimeWindow)?;
        }
        Ok(())
    }

    /// Whole windows between a previous `window_start` and the current one.
    fn periods_between(budget: &Budget, previous_start: u64) -> u64 {
        match Self::window_of(budget.period, budget.period_seconds) {
            Some(window) => budget.window_start.saturating_sub(previous_start) / window,
            None => 0,
        }
    }

    /// Build a [`WindowStatus`] for `budget` after `periods` rollovers.
    fn window_status_of(budget: &Budget, periods: u64) -> Result<WindowStatus, Error> {
        let window_end = match Self::window_of(budget.period, budget.period_seconds) {
            Some(window) => budget
                .window_start
                .checked_add(window)
                .ok_or(Error::InvalidTimeWindow)?,
            None => 0,
        };
        Ok(WindowStatus {
            window_start: budget.window_start,
            window_end,
            spent: budget.spent,
            remaining: Self::effective_remaining(budget)?,
            rolled_over: periods > 0,
            periods,
        })
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
    /// window), and the rollover credit applied here comes from the pure
    /// calculation [`Self::calculate_rollover`] — the same function the
    /// read-only [`Self::rollover_preview`] view reports, so a preview can
    /// never disagree with the transition it previews.
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
                events::budget_expired(env, budget_id);
            }
            return Err(Error::BudgetExpired);
        }
        let outcome = Self::calculate_rollover(budget, now)?;
        if !outcome.is_due {
            return Ok(());
        }
        let periods = outcome.periods as i128;
        let window = Self::window_of(budget.period, budget.period_seconds)
            .ok_or(Error::InvalidTimeWindow)?;
        let capacity = safe_add(budget.limit, budget.rollover_credit)?;
        let spent = budget.spent;
        let went_into_deficit = budget.allow_deficit && spent > capacity;

        // Apply the calculated carry. A deficit transition banks no credit
        // (the over-spend is carried as a deficit instead) and accumulates it
        // into the deficit counter; every other transition takes the credit
        // verbatim — including the 0 a rollover-disabled budget computes.
        budget.rollover_credit = if went_into_deficit {
            0
        } else {
            outcome.carry_over
        };
        if went_into_deficit {
            let deficit = safe_sub(spent, capacity)?;
            budget.deficit_amount = safe_add(budget.deficit_amount, deficit)?;
        }
        budget.spent = 0;
        // Re-anchor to the period boundary, not to `now`, so windows never
        // drift away from the schedule the budget was granted on.
        budget.window_start = budget
            .window_start
            .saturating_add((periods as u64).saturating_mul(window));
        if publish {
            let action = if went_into_deficit {
                symbol_short!("deficit")
            } else if budget.rollover_enabled {
                symbol_short!("rollover")
            } else {
                symbol_short!("reset")
            };
            let amount = if went_into_deficit {
                safe_sub(spent, capacity)?
            } else {
                safe_sub(capacity, spent)?
            };
            // The canonical amount is the unspent remainder that drove the
            // transition — what `calculate_rollover` started from as its carry
            // base. (A deficit transition over-drew, so this is negative; the
            // `deficit` event carries the positive over-spend.)
            events::budget_updated(
                env,
                budget_id,
                action,
                safe_sub(capacity, spent)?,
                (budget_id.clone(), amount),
            );
            // Emit dedicated BudgetRollover event when rollover occurs
            if budget.rollover_enabled && !went_into_deficit && outcome.carry_over != 0 {
                events::budget_rollover(
                    env,
                    budget_id,
                    outcome.periods,
                    outcome.carry_over,
                    budget.window_start,
                );
            }
            // The window re-armed: announce the headroom now spendable so a
            // consumer that saw `exhausted` knows the agent may spend again.
            // Informational only: a capacity beyond `i128::MAX` saturates
            // rather than failing the transition (the overflow is reported by
            // whichever spend or view actually needs the exact figure).
            let available = Self::effective_remaining(budget)
                .unwrap_or(i128::MAX)
                .max(0);
            events::budget_refilled(env, budget_id, None, available);
            // Issue #495 — the standard window-rollover event: how many
            // windows were settled, the closed window's spend, and the new
            // active window.
            events::budget_window_rolled(
                env,
                budget_id,
                periods as u64,
                spent,
                budget.window_start,
                budget.window_start.saturating_add(window),
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
        safe_add(credit, safe_mul(budget.limit, idle)?)
    }

    /// Per-asset counterpart of [`Self::window_transition`].
    /// Persists and emits only when `publish` is set.
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
        if asset_budget.rollover_enabled {
            let capacity = match safe_add(asset_budget.limit, asset_budget.rollover_credit) {
                Ok(c) => c,
                Err(_) => asset_budget.limit,
            };
            let unspent = capacity.saturating_sub(asset_budget.spent).max(0);
            let credit = calculate_budget_rollover(
                unspent,
                asset_budget.rollover_bps,
                asset_budget.max_rollover_cap,
            )
            .unwrap_or(0);
            asset_budget.rollover_credit = credit;
        } else {
            asset_budget.rollover_credit = 0;
        }
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
            let amount = if asset_budget.rollover_enabled {
                asset_budget
                    .limit
                    .saturating_add(asset_budget.rollover_credit)
            } else {
                asset_budget.limit
            };
            Self::emit_asset_reset(env, budget_id, token, amount);
            events::budget_refilled(env, budget_id, Some(token.clone()), amount);
        }
    }

    fn emit_asset_reset(env: &Env, budget_id: &String, token: &Address, limit: i128) {
        events::asset_budget_reset(env, budget_id, token, limit);
    }

    /// Guard that rejects an expired budget.
    fn require_not_expired(env: &Env, budget: &Budget) -> Result<(), Error> {
        let now = env.ledger().timestamp();
        if budget.expires_at != 0 && now >= budget.expires_at {
            return Err(Error::BudgetExpired);
        }
        Ok(())
    }
    /// Reject use of a scheduled budget before its inclusive start timestamp.
    fn require_started(env: &Env, budget: &Budget) -> Result<(), BudgetError> {
        if env.ledger().timestamp() < budget.window_start {
            return Err(BudgetError::BudgetNotActive);
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
    /// Spendable ceiling of a per-asset limit in its current window: the base
    /// limit plus banked rollover credit when rollover is enabled. Shared by
    /// the single and batch spend paths so they can never disagree.
    fn asset_capacity(asset_budget: &AssetBudget) -> Result<i128, Error> {
        if asset_budget.rollover_enabled {
            safe_add(asset_budget.limit, asset_budget.rollover_credit)
                .map_err(|_| Error::BUDGET_OVERFLOW)
        } else {
            Ok(asset_budget.limit)
        }
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
    /// [`Error::BudgetLimitReached`].
    fn consume(
        env: Env,
        caller: Address,
        budget_id: String,
        amount: i128,
    ) -> Result<i128, BudgetError> {
        require_positive_amount(amount)?;
        let mut budget = Self::require_owner(&env, &budget_id, &caller)?;
        Self::require_active(&budget)?;
        Self::require_started(&env, &budget)?;
        Self::check_and_rollover_window(&env, &budget_id, &mut budget)?;
        let capacity = safe_add(budget.limit, budget.rollover_credit)
            .map_err(|_| BudgetError::BUDGET_OVERFLOW)?;
        // When a deficit exists from prior periods, the effective spending
        // ceiling is reduced.  When no deficit exists yet, `allow_deficit`
        // lets the current period overspend (the excess becomes next-period
        // deficit).
        let ceiling = if budget.allow_deficit && budget.deficit_amount > 0 {
            safe_sub(capacity, budget.deficit_amount).map_err(|_| BudgetError::BUDGET_OVERFLOW)?
        } else {
            capacity
        };
        let new_spent = safe_add(budget.spent, amount).map_err(|_| BudgetError::BUDGET_OVERFLOW)?;
        if new_spent > ceiling {
            // With deficit allowed and no prior deficit, the first overspend is
            // permitted — it becomes the carried-forward deficit.
            if budget.allow_deficit && budget.deficit_amount == 0 {
                budget.spent = new_spent;
                Self::store(&env, &budget_id, &budget);
                // Checked: a genuine i128 overflow surfaces as [`Error::Overflow`]
                // instead of a panic; a negative result (deficit) is expected.
                let remaining =
                    safe_sub(capacity, new_spent).map_err(|_| BudgetError::BUDGET_OVERFLOW)?;
                events::budget_consumed(&env, &budget_id, amount, remaining);
                events::budget_exhausted(&env, &budget_id, None, new_spent, capacity);
                return Ok(remaining);
            }
            let remaining =
                safe_sub(ceiling, budget.spent).map_err(|_| BudgetError::BUDGET_OVERFLOW)?;
            events::budget_exceeded(&env, &budget_id, amount, remaining);
            return Err(BudgetError::BUDGET_LIMIT_EXCEEDED);
        }
        budget.spent = new_spent;
        Self::store(&env, &budget_id, &budget);
        let remaining =
            safe_sub(ceiling, budget.spent).map_err(|_| BudgetError::BUDGET_OVERFLOW)?;
        events::budget_consumed(&env, &budget_id, amount, remaining);
        if remaining <= 0 {
            events::budget_exhausted(&env, &budget_id, None, budget.spent, ceiling);
        }
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
        Self::check_and_rollover_window(&env, &budget_id, &mut budget)?;
        if amount > budget.spent {
            return Err(Error::InvalidAmount);
        }
        budget.spent = safe_sub(budget.spent, amount).map_err(|_| Error::BUDGET_OVERFLOW)?;
        Self::store(&env, &budget_id, &budget);
        Self::effective_remaining(&budget)
    }

    /// Read remaining allocation, accounting for a pending period transition.
    fn remaining(env: Env, budget_id: String) -> Result<i128, Error> {
        let mut budget = Self::load(&env, &budget_id)?;
        if env.ledger().timestamp() < budget.window_start {
            return Ok(0);
        }
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
