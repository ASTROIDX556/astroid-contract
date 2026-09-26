#![cfg(test)]
extern crate std;

use crate::{Budget, BudgetContract, BudgetContractClient, Period};
use astroid_shared::errors::Error;
use astroid_shared::types::ResourceState;
use soroban_sdk::testutils::Events;
use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::{Address, Env, IntoVal, String, Symbol, Val};

struct Harness {
    env: Env,
    client: BudgetContractClient<'static>,
    owner: Address,
}

fn setup() -> Harness {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000);
    let contract_id = env.register_contract(None, BudgetContract);
    let client = BudgetContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    client.initialize(&admin);
    let owner = Address::generate(&env);
    Harness { env, client, owner }
}

fn id(env: &Env, s: &str) -> String {
    String::from_str(env, s)
}

#[test]
fn allocate_creates_active_budget() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::None,
        &false,
        &0,
    );
    let b: Budget = h.client.get(&id(&h.env, "eng"));
    assert_eq!(b.limit, 1_000);
    assert_eq!(b.spent, 0);
    assert_eq!(b.state, ResourceState::Active);
    assert!(!b.rollover_enabled);
    assert_eq!(b.rollover_credit, 0);
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 1_000);
}

#[test]
fn duplicate_allocation_fails() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::None,
        &false,
        &0,
    );
    let res = h.client.try_allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &2_000,
        &Period::None,
        &false,
        &0,
    );
    assert_eq!(res, Err(Ok(Error::AlreadyExists)));
}

#[test]
fn consume_reduces_remaining() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::None,
        &false,
        &0,
    );
    let rem = h.client.consume(&h.owner, &id(&h.env, "eng"), &400);
    assert_eq!(rem, 600);
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 600);
    let b: Budget = h.client.get(&id(&h.env, "eng"));
    assert_eq!(b.spent, 400);
}

#[test]
fn over_budget_consume_fails_budget_exceeded() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::None,
        &false,
        &0,
    );
    h.client.consume(&h.owner, &id(&h.env, "eng"), &800);
    let res = h.client.try_consume(&h.owner, &id(&h.env, "eng"), &300);
    assert_eq!(res, Err(Ok(Error::BudgetExceeded)));
    // Spend up to the exact limit is allowed.
    let rem = h.client.consume(&h.owner, &id(&h.env, "eng"), &200);
    assert_eq!(rem, 0);
}

#[test]
fn consume_zero_or_negative_rejected() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::None,
        &false,
        &0,
    );
    let res = h.client.try_consume(&h.owner, &id(&h.env, "eng"), &0);
    assert_eq!(res, Err(Ok(Error::InvalidAmount)));
    let res = h.client.try_consume(&h.owner, &id(&h.env, "eng"), &-5);
    assert_eq!(res, Err(Ok(Error::InvalidAmount)));
}

#[test]
fn non_owner_cannot_consume() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::None,
        &false,
        &0,
    );
    let stranger = Address::generate(&h.env);
    let res = h.client.try_consume(&stranger, &id(&h.env, "eng"), &100);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
}

#[test]
fn reset_clears_spent() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::None,
        &false,
        &0,
    );
    h.client.consume(&h.owner, &id(&h.env, "eng"), &900);
    h.client.reset(&h.owner, &id(&h.env, "eng"));
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 1_000);
}

#[test]
fn frozen_budget_rejects_consume() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::None,
        &false,
        &0,
    );
    h.client.freeze(&h.owner, &id(&h.env, "eng"));
    let res = h.client.try_consume(&h.owner, &id(&h.env, "eng"), &100);
    assert_eq!(res, Err(Ok(Error::BudgetFrozen)));
    // Unfreeze restores spending.
    h.client.unfreeze(&h.owner, &id(&h.env, "eng"));
    let rem = h.client.consume(&h.owner, &id(&h.env, "eng"), &100);
    assert_eq!(rem, 900);
}

#[test]
fn archived_budget_rejects_consume() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::None,
        &false,
        &0,
    );
    h.client.archive(&h.owner, &id(&h.env, "eng"));
    let res = h.client.try_consume(&h.owner, &id(&h.env, "eng"), &100);
    assert_eq!(res, Err(Ok(Error::BudgetArchived)));
}

#[test]
fn daily_budget_auto_resets_after_window() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::Daily,
        &false,
        &0,
    );
    h.client.consume(&h.owner, &id(&h.env, "eng"), &1_000);
    // Exhausted within the window.
    let res = h.client.try_consume(&h.owner, &id(&h.env, "eng"), &1);
    assert_eq!(res, Err(Ok(Error::BudgetExceeded)));
    // Advance one full day; the window rolls over and spending resets.
    h.env.ledger().set_timestamp(1_000 + 86_400);
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 1_000);
    let rem = h.client.consume(&h.owner, &id(&h.env, "eng"), &250);
    assert_eq!(rem, 750);
}

#[test]
fn rollover_carries_unspent_into_next_period() {
    let h = setup();
    // Weekly budget with rollover enabled, starting at t=1_000.
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::Weekly,
        &true,
        &0,
    );
    h.client.consume(&h.owner, &id(&h.env, "eng"), &600);
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 400);
    // Advance past the weekly window; unspent (400) rolls over into the new period.
    h.env.ledger().set_timestamp(1_000 + 604_800);
    // New effective capacity = base limit (1000) + rollover credit (400) = 1400.
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 1_400);
    let b: Budget = h.client.get(&id(&h.env, "eng"));
    assert_eq!(b.rollover_credit, 400);
    assert_eq!(b.spent, 0);
    // Can now spend up to 1400.
    let rem = h.client.consume(&h.owner, &id(&h.env, "eng"), &1_400);
    assert_eq!(rem, 0);
}

#[test]
fn rollover_disabled_clears_unspent() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::Weekly,
        &false,
        &0,
    );
    h.client.consume(&h.owner, &id(&h.env, "eng"), &600);
    h.env.ledger().set_timestamp(1_000 + 604_800);
    // Rollover disabled: unspent is cleared, capacity stays at the base limit.
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 1_000);
    let b: Budget = h.client.get(&id(&h.env, "eng"));
    assert_eq!(b.rollover_credit, 0);
}

#[test]
fn explicit_rollover_requires_owner() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::Weekly,
        &true,
        &0,
    );
    h.client.consume(&h.owner, &id(&h.env, "eng"), &600);
    // Stranger cannot trigger rollover.
    let stranger = Address::generate(&h.env);
    let res = h.client.try_rollover(&stranger, &id(&h.env, "eng"));
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
    // Owner advances ledger and triggers rollover explicitly.
    h.env.ledger().set_timestamp(1_000 + 604_800);
    h.client.rollover(&h.owner, &id(&h.env, "eng"));
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 1_400);
}

#[test]
fn expired_budget_rejects_consume() {
    let h = setup();
    // Expires at t = 10_000.
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::None,
        &false,
        &10_000,
    );
    // Before expiry, spending works.
    let rem = h.client.consume(&h.owner, &id(&h.env, "eng"), &100);
    assert_eq!(rem, 900);
    // Past expiry, consumption is rejected.
    h.env.ledger().set_timestamp(20_000);
    let res = h.client.try_consume(&h.owner, &id(&h.env, "eng"), &100);
    assert_eq!(res, Err(Ok(Error::BudgetExpired)));
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 0);
}

#[test]
fn expired_budget_rejects_reset_and_set_limit() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::None,
        &false,
        &10_000,
    );
    h.env.ledger().set_timestamp(20_000);
    let res = h.client.try_reset(&h.owner, &id(&h.env, "eng"));
    assert_eq!(res, Err(Ok(Error::BudgetExpired)));
    let res = h.client.try_set_limit(&h.owner, &id(&h.env, "eng"), &2_000);
    assert_eq!(res, Err(Ok(Error::BudgetExpired)));
}

#[test]
fn set_limit_below_spent_rejected() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::None,
        &false,
        &0,
    );
    h.client.consume(&h.owner, &id(&h.env, "eng"), &600);
    let res = h.client.try_set_limit(&h.owner, &id(&h.env, "eng"), &500);
    assert_eq!(res, Err(Ok(Error::InvalidInput)));
    // Raising the limit works and increases remaining.
    h.client.set_limit(&h.owner, &id(&h.env, "eng"), &2_000);
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 1_400);
}

#[test]
fn transfer_allocation_moves_unspent_limit() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::None,
        &false,
        &0,
    );
    h.client.allocate(
        &h.owner,
        &id(&h.env, "ops"),
        &500,
        &Period::None,
        &false,
        &0,
    );
    h.client
        .transfer_allocation(&h.owner, &id(&h.env, "eng"), &id(&h.env, "ops"), &300);
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 700);
    assert_eq!(h.client.remaining(&id(&h.env, "ops")), 800);
}

#[test]
fn transfer_allocation_over_available_fails() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::None,
        &false,
        &0,
    );
    h.client.allocate(
        &h.owner,
        &id(&h.env, "ops"),
        &500,
        &Period::None,
        &false,
        &0,
    );
    h.client.consume(&h.owner, &id(&h.env, "eng"), &900);
    // Only 100 unspent remains in "eng".
    let res =
        h.client
            .try_transfer_allocation(&h.owner, &id(&h.env, "eng"), &id(&h.env, "ops"), &200);
    assert_eq!(res, Err(Ok(Error::BudgetExceeded)));
}

#[test]
fn get_missing_budget_fails_not_found() {
    let h = setup();
    let res = h.client.try_get(&id(&h.env, "nope"));
    assert_eq!(res, Err(Ok(Error::NotFound)));
}

// ---------------------------------------------------------------------------
// Recurring allowance hooks
// ---------------------------------------------------------------------------

const DAY: u64 = 86_400;
const WEEK: u64 = 604_800;

/// Assert that the canonical `ContractEvent` with the given variant symbol was
/// published during the test (single-topic event = the variant name).
fn assert_event(env: &Env, variant: &str) {
    let want: Val = Symbol::new(env, variant).into_val(env);
    let found = env
        .events()
        .all()
        .iter()
        .any(|(_contract_id, topics, _data)| topics.contains(&want));
    assert!(found, "expected ContractEvent::{} to be emitted", variant);
}

/// Allocate a budget under the harness owner with the common defaults.
fn allocate(h: &Harness, budget_id: &str, limit: i128, period: Period, rollover: bool) {
    h.client.allocate(
        &h.owner,
        &id(&h.env, budget_id),
        &limit,
        &period,
        &rollover,
        &0,
    );
}

#[test]
fn several_elapsed_periods_are_all_settled_at_once() {
    let h = setup();
    allocate(&h, "eng", 1_000, Period::Weekly, true);
    h.client.consume(&h.owner, &id(&h.env, "eng"), &600);

    // Nobody touches the budget for three whole weeks.
    h.env.ledger().set_timestamp(1_000 + 3 * WEEK);

    // Week 1 leaves 400 unspent; weeks 2 and 3 went by entirely unspent and
    // contribute a full base limit each: 400 + 1_000 + 1_000 = 2_400 credit.
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 1_000 + 2_400);
    let b: Budget = h.client.get(&id(&h.env, "eng"));
    assert_eq!(b.rollover_credit, 2_400);
    assert_eq!(b.spent, 0);
    // The window is re-anchored to the period boundary, not to "now".
    assert_eq!(b.window_start, 1_000 + 3 * WEEK);
}

#[test]
fn several_elapsed_periods_without_rollover_reset_once() {
    let h = setup();
    allocate(&h, "eng", 1_000, Period::Weekly, false);
    h.client.consume(&h.owner, &id(&h.env, "eng"), &600);

    h.env.ledger().set_timestamp(1_000 + 5 * WEEK);
    // No rollover: idle periods accrue nothing, the budget simply starts over.
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 1_000);
    let b: Budget = h.client.get(&id(&h.env, "eng"));
    assert_eq!(b.rollover_credit, 0);
    assert_eq!(b.window_start, 1_000 + 5 * WEEK);
}

#[test]
fn windows_do_not_drift_when_transitions_land_mid_period() {
    let h = setup();
    allocate(&h, "eng", 1_000, Period::Daily, false);

    // A query part-way through the second day settles day one only, and anchors
    // the window to the day boundary rather than to the moment of the query.
    h.env.ledger().set_timestamp(1_000 + DAY + 100);
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 1_000);
    assert_eq!(h.client.get(&id(&h.env, "eng")).window_start, 1_000 + DAY);

    // Because the anchor did not drift, the next reset still falls due on the
    // original schedule.
    h.env.ledger().set_timestamp(1_000 + 2 * DAY);
    h.client.consume(&h.owner, &id(&h.env, "eng"), &10);
    assert_eq!(
        h.client.get(&id(&h.env, "eng")).window_start,
        1_000 + 2 * DAY
    );
}

#[test]
fn rollover_credit_is_clamped_to_its_cap() {
    let h = setup();
    allocate(&h, "eng", 1_000, Period::Weekly, true);
    // Cap the accrual at 1_500 so a long idle stretch cannot build up a
    // balance the agent could drain in a single period.
    h.client.set_recurrence(
        &h.owner,
        &id(&h.env, "eng"),
        &Period::Weekly,
        &0,
        &true,
        &1_500,
    );

    h.env.ledger().set_timestamp(1_000 + 10 * WEEK);
    // Uncapped this would be 10_000; the cap holds it at 1_500.
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 1_000 + 1_500);
    assert_eq!(h.client.get(&id(&h.env, "eng")).rollover_credit, 1_500);
}

#[test]
fn custom_period_recurs_on_its_configured_interval() {
    let h = setup();
    allocate(&h, "agent", 1_000, Period::None, false);
    // An hourly agent allowance.
    h.client.set_recurrence(
        &h.owner,
        &id(&h.env, "agent"),
        &Period::Custom,
        &3_600,
        &false,
        &0,
    );
    let b: Budget = h.client.get(&id(&h.env, "agent"));
    assert_eq!(b.period, Period::Custom);
    assert_eq!(b.period_seconds, 3_600);

    h.client.consume(&h.owner, &id(&h.env, "agent"), &1_000);
    assert_eq!(h.client.remaining(&id(&h.env, "agent")), 0);

    // Just short of the hour the allowance is still exhausted.
    h.env.ledger().set_timestamp(1_000 + 3_599);
    assert_eq!(h.client.remaining(&id(&h.env, "agent")), 0);

    // On the hour it replenishes.
    h.env.ledger().set_timestamp(1_000 + 3_600);
    assert_eq!(h.client.remaining(&id(&h.env, "agent")), 1_000);
}

#[test]
fn custom_period_requires_an_interval() {
    let h = setup();
    allocate(&h, "agent", 1_000, Period::None, false);
    let res = h.client.try_set_recurrence(
        &h.owner,
        &id(&h.env, "agent"),
        &Period::Custom,
        &0,
        &false,
        &0,
    );
    assert_eq!(res, Err(Ok(Error::InvalidInput)));

    let res = h.client.try_set_recurrence(
        &h.owner,
        &id(&h.env, "agent"),
        &Period::Daily,
        &0,
        &true,
        &-1,
    );
    assert_eq!(res, Err(Ok(Error::InvalidAmount)));
}

#[test]
fn set_recurrence_settles_the_old_policy_before_switching() {
    let h = setup();
    allocate(&h, "eng", 1_000, Period::Daily, true);
    h.client.consume(&h.owner, &id(&h.env, "eng"), &400);

    // A day has already turned over when the cadence is changed to weekly.
    h.env.ledger().set_timestamp(1_000 + DAY);
    h.client
        .set_recurrence(&h.owner, &id(&h.env, "eng"), &Period::Weekly, &0, &true, &0);

    // The reset owed under the daily policy was applied, not discarded.
    let b: Budget = h.client.get(&id(&h.env, "eng"));
    assert_eq!(b.period, Period::Weekly);
    assert_eq!(b.spent, 0);
    assert_eq!(b.rollover_credit, 600);
    // ...and the new cadence counts from the switch.
    assert_eq!(b.window_start, 1_000 + DAY);
}

#[test]
fn set_recurrence_requires_the_owner() {
    let h = setup();
    allocate(&h, "eng", 1_000, Period::Daily, false);
    let stranger = Address::generate(&h.env);
    let res = h.client.try_set_recurrence(
        &stranger,
        &id(&h.env, "eng"),
        &Period::Weekly,
        &0,
        &false,
        &0,
    );
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
}

#[test]
fn disabling_rollover_drops_accrued_credit() {
    let h = setup();
    allocate(&h, "eng", 1_000, Period::Weekly, true);
    h.client.consume(&h.owner, &id(&h.env, "eng"), &200);
    h.env.ledger().set_timestamp(1_000 + WEEK);
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 1_800);

    h.client.set_recurrence(
        &h.owner,
        &id(&h.env, "eng"),
        &Period::Weekly,
        &0,
        &false,
        &0,
    );
    assert_eq!(h.client.get(&id(&h.env, "eng")).rollover_credit, 0);
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 1_000);
}

#[test]
fn consume_across_a_boundary_spends_the_replenished_allowance() {
    let h = setup();
    allocate(&h, "eng", 1_000, Period::Daily, false);
    h.client.consume(&h.owner, &id(&h.env, "eng"), &900);
    let res = h.client.try_consume(&h.owner, &id(&h.env, "eng"), &200);
    assert_eq!(res, Err(Ok(Error::BudgetExceeded)));

    // The disbursement itself evaluates the transition hook, so the very first
    // spend of the new period already sees the replenished allowance.
    h.env.ledger().set_timestamp(1_000 + DAY);
    let rem = h.client.consume(&h.owner, &id(&h.env, "eng"), &200);
    assert_eq!(rem, 800);
}

#[test]
fn rollover_and_reset_events_are_emitted() {
    let h = setup();
    allocate(&h, "eng", 1_000, Period::Weekly, true);
    h.client.consume(&h.owner, &id(&h.env, "eng"), &600);
    h.env.ledger().set_timestamp(1_000 + WEEK);
    h.client.consume(&h.owner, &id(&h.env, "eng"), &1);
    assert_event(&h.env, "BudgetUpdated");
}

// --- per-asset recurring limits ---

#[test]
fn per_asset_limit_replenishes_on_its_own_window() {
    let h = setup();
    allocate(&h, "eng", 10_000, Period::None, false);
    let token = Address::generate(&h.env);
    // 100 per hour for this token.
    h.client
        .set_budget_limit(&h.owner, &id(&h.env, "eng"), &token, &100, &3_600);

    h.client
        .check_and_record_spend(&h.owner, &id(&h.env, "eng"), &token, &80);
    assert_eq!(h.client.asset_remaining(&id(&h.env, "eng"), &token), 20);
    let res = h
        .client
        .try_check_and_record_spend(&h.owner, &id(&h.env, "eng"), &token, &30);
    assert_eq!(res, Err(Ok(Error::BudgetExceeded)));

    // The hour turns over and the per-asset allowance is whole again.
    h.env.ledger().set_timestamp(1_000 + 3_600);
    assert_eq!(h.client.asset_remaining(&id(&h.env, "eng"), &token), 100);
    h.client
        .check_and_record_spend(&h.owner, &id(&h.env, "eng"), &token, &100);
    assert_eq!(h.client.asset_remaining(&id(&h.env, "eng"), &token), 0);
    let b = h.client.get_asset_budget(&id(&h.env, "eng"), &token);
    assert_eq!(b.window_start, 1_000 + 3_600);
    assert_eq!(b.window_seconds, 3_600);
}

#[test]
fn per_asset_limit_without_a_window_never_resets() {
    let h = setup();
    allocate(&h, "eng", 10_000, Period::None, false);
    let token = Address::generate(&h.env);
    h.client
        .set_budget_limit(&h.owner, &id(&h.env, "eng"), &token, &100, &0);
    h.client
        .check_and_record_spend(&h.owner, &id(&h.env, "eng"), &token, &100);

    h.env.ledger().set_timestamp(1_000 + 10 * DAY);
    assert_eq!(h.client.asset_remaining(&id(&h.env, "eng"), &token), 0);
    let res = h
        .client
        .try_check_and_record_spend(&h.owner, &id(&h.env, "eng"), &token, &1);
    assert_eq!(res, Err(Ok(Error::BudgetExceeded)));
}

#[test]
fn per_asset_window_catches_up_across_many_periods() {
    let h = setup();
    allocate(&h, "eng", 10_000, Period::None, false);
    let token = Address::generate(&h.env);
    h.client
        .set_budget_limit(&h.owner, &id(&h.env, "eng"), &token, &100, &3_600);
    h.client
        .check_and_record_spend(&h.owner, &id(&h.env, "eng"), &token, &100);

    // Five hours later the allowance is one period's worth, not five.
    h.env.ledger().set_timestamp(1_000 + 5 * 3_600);
    assert_eq!(h.client.asset_remaining(&id(&h.env, "eng"), &token), 100);
    let b = h.client.get_asset_budget(&id(&h.env, "eng"), &token);
    assert_eq!(b.window_start, 1_000 + 5 * 3_600);
}

#[test]
fn unknown_asset_budget_is_rejected() {
    let h = setup();
    allocate(&h, "eng", 10_000, Period::None, false);
    let token = Address::generate(&h.env);
    let res = h.client.try_asset_remaining(&id(&h.env, "eng"), &token);
    assert_eq!(res, Err(Ok(Error::AssetNotAuthorized)));
}

#[test]
fn test_rollover_prevention() {
    let env = Env::default();
    env.mock_all_auths();

    let owner = Address::generate(&env);
    let contract_id = env.register_contract(None, BudgetContract);
    let client = BudgetContractClient::new(&env, &contract_id);

    let token = Address::generate(&env);
    let b_id = soroban_sdk::String::from_str(&env, "b1");

    client.allocate(&owner, &b_id, &1000, &crate::Period::None, &false, &0);
    client.set_budget_limit(&owner, &b_id, &token, &100, &3600); // 1 hour window

    env.ledger().set_timestamp(100);
    client.check_and_record_spend(&owner, &b_id, &token, &60);

    // if they spend 50 more in same window, it should fail
    let res = client.try_check_and_record_spend(&owner, &b_id, &token, &50);
    assert_eq!(res, Err(Ok(Error::BudgetExceeded)));

    // fast forward 1 hour (3600 seconds)
    env.ledger().set_timestamp(100 + 3600 + 1);

    // Now it should succeed because window resets!
    client.check_and_record_spend(&owner, &b_id, &token, &50);
}

// --- Issue #35: Deficit carryforward tests ---

#[test]
fn deficit_carryforward_allows_overspend() {
    let h = setup();
    h.client.allocate_with_deficit(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::Weekly,
        &true,
        &true, // allow_deficit
        &0,
    );
    // Spend beyond the limit — deficit allowed.
    let rem = h.client.consume(&h.owner, &id(&h.env, "eng"), &1_200);
    assert_eq!(rem, -200); // negative remaining = deficit
    let b: Budget = h.client.get(&id(&h.env, "eng"));
    assert!(b.allow_deficit);
    assert_eq!(b.spent, 1_200);
}

#[test]
fn deficit_carryforward_reduces_next_period() {
    let h = setup();
    h.client.allocate_with_deficit(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::Weekly,
        &true,
        &true, // allow_deficit
        &0,
    );
    // Spend 1200 (200 over limit)
    h.client.consume(&h.owner, &id(&h.env, "eng"), &1_200);
    // Advance past the weekly window
    h.env.ledger().set_timestamp(1_000 + 604_800);
    // Call remaining to trigger window transition and persist the rollover state
    // Use rollover to trigger the window transition explicitly
    h.client.rollover(&h.owner, &id(&h.env, "eng"));
    let b: Budget = h.client.get(&id(&h.env, "eng"));
    assert_eq!(b.window_start, 1_000 + 604_800);
    assert_eq!(b.deficit_amount, 200);
    assert_eq!(b.spent, 0);
    // effective_capacity = limit (1000) - deficit (200) = 800
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 800);
    // Can spend up to 800 (1000 - 200 deficit)
    let rem = h.client.consume(&h.owner, &id(&h.env, "eng"), &800);
    assert_eq!(rem, 0);
    // One more unit should fail since effective capacity is exhausted
    let res = h.client.try_consume(&h.owner, &id(&h.env, "eng"), &1);
    assert_eq!(res, Err(Ok(Error::BudgetExceeded)));
}

#[test]
fn deficit_not_allowed_rejects_overspend() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::Weekly,
        &true,
        &0,
    );
    // Spending beyond limit should fail without allow_deficit
    let res = h.client.try_consume(&h.owner, &id(&h.env, "eng"), &1_200);
    assert_eq!(res, Err(Ok(Error::BudgetExceeded)));
}

#[test]
fn deficit_without_period_rejected() {
    let h = setup();
    // Deficit carryforward requires a recurring period
    let res = h.client.try_allocate_with_deficit(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::None,
        &false,
        &true, // allow_deficit
        &0,
    );
    assert_eq!(res, Err(Ok(Error::InvalidInput)));
}

#[test]
fn deficit_surplus_rollover_combined() {
    let h = setup();
    h.client.allocate_with_deficit(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::Weekly,
        &true,
        &true, // allow_deficit
        &0,
    );
    // Spend only 600 — surplus of 400
    h.client.consume(&h.owner, &id(&h.env, "eng"), &600);
    h.env.ledger().set_timestamp(1_000 + 604_800);
    // Call remaining to trigger window transition and persist rollover state
    let rem = h.client.remaining(&id(&h.env, "eng"));
    assert_eq!(rem, 1_400);
    // After rollover: deficit=0, rollover_credit=400, spent=0
    let b: Budget = h.client.get(&id(&h.env, "eng"));
    assert_eq!(b.deficit_amount, 0);
    assert_eq!(b.rollover_credit, 400);
    assert_eq!(b.spent, 0);
}

// ---------------------------------------------------------------------------
// Issue #223: near-maximum boundary values. Every arithmetic path touching
// token balances / budget limits must go through the shared checked helpers
// and surface `Error::Overflow` instead of panicking or silently wrapping.
// ---------------------------------------------------------------------------

#[test]
fn allocate_accepts_maximum_limit() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &i128::MAX,
        &Period::None,
        &false,
        &0,
    );
    let b: Budget = h.client.get(&id(&h.env, "eng"));
    assert_eq!(b.limit, i128::MAX);
    // remaining = (limit + 0 credit) - 0 spent: fits exactly, no overflow.
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), i128::MAX);
}

#[test]
fn consume_up_to_max_capacity_succeeds() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &i128::MAX,
        &Period::None,
        &false,
        &0,
    );
    // spent = 0 + MAX and remaining = MAX - MAX: both fit exactly.
    let rem = h.client.consume(&h.owner, &id(&h.env, "eng"), &i128::MAX);
    assert_eq!(rem, 0);
}

#[test]
fn consume_beyond_max_capacity_returns_overflow() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &i128::MAX,
        &Period::None,
        &false,
        &0,
    );
    h.client.consume(&h.owner, &id(&h.env, "eng"), &i128::MAX);
    // spent + amount = MAX + 1 overflows i128: checked math returns the
    // contract error instead of a panic or a wrapped value.
    let res = h.client.try_consume(&h.owner, &id(&h.env, "eng"), &1);
    assert_eq!(res, Err(Ok(Error::Overflow)));
}

#[test]
fn release_refunds_the_full_maximum_spend() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &i128::MAX,
        &Period::None,
        &false,
        &0,
    );
    h.client.consume(&h.owner, &id(&h.env, "eng"), &i128::MAX);
    // Refund the whole period's spend: spent = MAX - MAX, remaining = MAX - 0.
    let rem = h.client.release(&h.owner, &id(&h.env, "eng"), &i128::MAX);
    assert_eq!(rem, i128::MAX);
}

#[test]
fn uncapped_rollover_accrual_past_max_returns_overflow() {
    let h = setup();
    // Three whole idle periods accrue 3 * limit, which overflows i128 when
    // limit is ~MAX/2. The uncapped path uses checked math on purpose.
    let limit = i128::MAX / 2;
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &limit,
        &Period::Weekly,
        &true, // rollover_enabled, uncapped (cap = 0)
        &0,
    );
    h.env.ledger().set_timestamp(1_000 + 3 * WEEK);
    let res = h.client.try_rollover(&h.owner, &id(&h.env, "eng"));
    assert_eq!(res, Err(Ok(Error::Overflow)));
}

#[test]
fn capped_rollover_accrual_saturates_instead_of_overflowing() {
    let h = setup();
    // Same near-max setup, but with a cap: the accrual saturates and the
    // credit is clamped to the cap, so the budget stays usable.
    let limit = i128::MAX / 2;
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &limit,
        &Period::Weekly,
        &true,
        &0,
    );
    h.client.set_recurrence(
        &h.owner,
        &id(&h.env, "eng"),
        &Period::Weekly,
        &0,
        &true,
        &limit, // rollover_cap
    );
    h.env.ledger().set_timestamp(1_000 + 3 * WEEK);
    h.client.rollover(&h.owner, &id(&h.env, "eng"));
    let b: Budget = h.client.get(&id(&h.env, "eng"));
    assert_eq!(b.rollover_credit, limit);
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 2 * limit);
}

#[test]
fn rollover_accrual_of_second_idle_period_overflows() {
    let h = setup();
    // Two whole idle periods accrue credit + limit = 2 * (MAX - 5), which
    // overflows i128 on the checked accrual path.
    let limit = i128::MAX - 5;
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &limit,
        &Period::Weekly,
        &true,
        &0,
    );
    h.env.ledger().set_timestamp(1_000 + 2 * WEEK);
    let res = h.client.try_rollover(&h.owner, &id(&h.env, "eng"));
    assert_eq!(res, Err(Ok(Error::Overflow)));
}

#[test]
fn remaining_with_max_limit_and_credit_returns_overflow() {
    let h = setup();
    // Rollover itself succeeds (credit = MAX - 10 fits), but the next
    // capacity computation limit + credit = MAX + (MAX - 10) overflows and
    // must surface as the contract error, not a wrapped value.
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &i128::MAX,
        &Period::Weekly,
        &true,
        &0,
    );
    h.client.consume(&h.owner, &id(&h.env, "eng"), &10);
    h.env.ledger().set_timestamp(1_000 + WEEK);
    h.client.rollover(&h.owner, &id(&h.env, "eng"));
    let res = h.client.try_remaining(&id(&h.env, "eng"));
    assert_eq!(res, Err(Ok(Error::Overflow)));
}

#[test]
fn deficit_remaining_near_max_stays_negative_and_checked() {
    let h = setup();
    let limit = i128::MAX - 1_000;
    h.client.allocate_with_deficit(
        &h.owner,
        &id(&h.env, "eng"),
        &limit,
        &Period::Weekly,
        &true,
        &true, // allow_deficit
        &0,
    );
    // Overspend into a deficit: remaining = (MAX - 1_000) - MAX = -1_000.
    let rem = h.client.consume(&h.owner, &id(&h.env, "eng"), &i128::MAX);
    assert_eq!(rem, -1_000);
    // The transition carries the deficit; next period's remaining is
    // (limit - deficit) - spent = (MAX - 1_000) - 1_000 - 0 = MAX - 2_000.
    h.env.ledger().set_timestamp(1_000 + WEEK);
    h.client.rollover(&h.owner, &id(&h.env, "eng"));
    let b: Budget = h.client.get(&id(&h.env, "eng"));
    assert_eq!(b.deficit_amount, 1_000);
    assert_eq!(b.spent, 0);
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), i128::MAX - 2_000);
}

#[test]
fn transfer_allocation_past_max_returns_overflow() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "src"),
        &(i128::MAX - 10),
        &Period::None,
        &false,
        &0,
    );
    h.client.allocate(
        &h.owner,
        &id(&h.env, "dst"),
        &(i128::MAX - 10),
        &Period::None,
        &false,
        &0,
    );
    // First hop fills dst exactly to i128::MAX.
    h.client
        .transfer_allocation(&h.owner, &id(&h.env, "src"), &id(&h.env, "dst"), &10);
    assert_eq!(h.client.remaining(&id(&h.env, "dst")), i128::MAX);
    // A further increase of dst.limit would overflow: checked math rejects it.
    let res =
        h.client
            .try_transfer_allocation(&h.owner, &id(&h.env, "src"), &id(&h.env, "dst"), &20);
    assert_eq!(res, Err(Ok(Error::Overflow)));
    // Atomic: dst is untouched by the failed transfer.
    assert_eq!(h.client.remaining(&id(&h.env, "dst")), i128::MAX);
    assert_eq!(h.client.remaining(&id(&h.env, "src")), i128::MAX - 20);
}

#[test]
fn per_asset_spend_past_max_returns_overflow() {
    let h = setup();
    allocate(&h, "eng", 10_000, Period::None, false);
    let token = Address::generate(&h.env);
    h.client
        .set_budget_limit(&h.owner, &id(&h.env, "eng"), &token, &i128::MAX, &0);
    h.client
        .check_and_record_spend(&h.owner, &id(&h.env, "eng"), &token, &i128::MAX);
    // spent + amount = MAX + 1 overflows the i128 spent counter.
    let res = h
        .client
        .try_check_and_record_spend(&h.owner, &id(&h.env, "eng"), &token, &1);
    assert_eq!(res, Err(Ok(Error::Overflow)));
    // The spend was not recorded.
    assert_eq!(h.client.asset_remaining(&id(&h.env, "eng"), &token), 0);
}

// ---------------------------------------------------------------------------
// Deterministic error codes
//
// A budget is a spending envelope, so the code has to distinguish "this asset
// was never authorized on this envelope" from "the envelope is out of room"
// from "the envelope is frozen" from "the envelope has lapsed". Collapsing any
// two of those would leave a caller unable to tell a fixable configuration
// problem from a genuinely exhausted allocation.
// ---------------------------------------------------------------------------

/// A budget owned by the harness, with `limit` and no period.
fn budget(h: &Harness, name: &str, limit: i128) -> String {
    let budget_id = id(&h.env, name);
    h.client
        .allocate(&h.owner, &budget_id, &limit, &Period::None, &false, &0);
    budget_id
}

#[test]
fn unknown_budget_ids_are_not_found() {
    let h = setup();
    let ghost = id(&h.env, "ghost");
    let token = Address::generate(&h.env);

    assert_eq!(h.client.try_get(&ghost), Err(Ok(Error::NotFound)));
    assert_eq!(h.client.try_remaining(&ghost), Err(Ok(Error::NotFound)));
    assert_eq!(
        h.client.try_reset(&h.owner, &ghost),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(
        h.client
            .try_check_and_record_spend(&h.owner, &ghost, &token, &1),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn empty_budget_id_is_invalid_input() {
    let h = setup();
    let blank = String::from_str(&h.env, "");
    assert_eq!(
        h.client
            .try_allocate(&h.owner, &blank, &100, &Period::None, &false, &0),
        Err(Ok(Error::InvalidInput))
    );
}

#[test]
fn negative_limits_are_invalid_amounts() {
    let h = setup();
    // `allocate` and `set_budget_limit` share the non-negative guard, and a
    // negative ceiling is a different mistake from a malformed id.
    assert_eq!(
        h.client
            .try_allocate(&h.owner, &id(&h.env, "eng"), &-1, &Period::None, &false, &0),
        Err(Ok(Error::InvalidAmount))
    );

    let b = budget(&h, "ops", 100);
    let token = Address::generate(&h.env);
    assert_eq!(
        h.client.try_set_budget_limit(&h.owner, &b, &token, &-1, &0),
        Err(Ok(Error::InvalidAmount))
    );
}

#[test]
fn deficit_without_a_recurring_period_is_invalid_input() {
    let h = setup();
    // A deficit has nothing to carry into a one-shot envelope, so this is a
    // configuration error rather than an allocation that happens to be odd.
    assert_eq!(
        h.client.try_allocate_with_deficit(
            &h.owner,
            &id(&h.env, "eng"),
            &1_000,
            &Period::None,
            &false,
            &true,
            &0
        ),
        Err(Ok(Error::InvalidInput))
    );
}

#[test]
fn duplicate_allocation_is_already_exists() {
    let h = setup();
    let b = budget(&h, "eng", 100);
    // Reusing an id must not silently reset the envelope.
    assert_eq!(
        h.client
            .try_allocate(&h.owner, &b, &999, &Period::None, &false, &0),
        Err(Ok(Error::AlreadyExists))
    );
    assert_eq!(h.client.get(&b).limit, 100);
}

#[test]
fn spend_on_an_unauthorized_asset_is_not_authorized() {
    let h = setup();
    let b = budget(&h, "eng", 1_000);
    let approved = Address::generate(&h.env);
    let stranger = Address::generate(&h.env);
    h.client
        .set_budget_limit(&h.owner, &b, &approved, &1_000, &0);

    // The envelope is funded and active; this asset simply is not on it. That
    // is a wiring problem, not an exhausted budget.
    assert_eq!(
        h.client
            .try_check_and_record_spend(&h.owner, &b, &stranger, &1),
        Err(Ok(Error::AssetNotAuthorized))
    );
    assert_eq!(h.client.remaining(&b), 1_000);
}

#[test]
fn exhausted_envelope_reports_budget_exceeded() {
    let h = setup();
    let b = budget(&h, "eng", 1_000);
    let token = Address::generate(&h.env);
    h.client.set_budget_limit(&h.owner, &b, &token, &1_000, &0);

    h.client
        .check_and_record_spend(&h.owner, &b, &token, &1_000);
    assert_eq!(
        h.client
            .try_check_and_record_spend(&h.owner, &b, &token, &1),
        Err(Ok(Error::BudgetExceeded))
    );
    // The refusal did not record the overspend.
    assert_eq!(h.client.asset_remaining(&b, &token), 0);

    // Exhausting the envelope says nothing about the owning budget's own total.
    let other = Address::generate(&h.env);
    h.client.set_budget_limit(&h.owner, &b, &other, &100, &0);
    assert_eq!(h.client.asset_remaining(&b, &other), 100);
}

#[test]
fn frozen_archived_and_lapsed_envelopes_have_distinct_codes() {
    let h = setup();
    let token = Address::generate(&h.env);

    let frozen = budget(&h, "frozen", 1_000);
    h.client
        .set_budget_limit(&h.owner, &frozen, &token, &1_000, &0);
    h.client.freeze(&h.owner, &frozen);
    assert_eq!(
        h.client
            .try_check_and_record_spend(&h.owner, &frozen, &token, &1),
        Err(Ok(Error::BudgetFrozen))
    );
    // Unfreezing a frozen envelope is a real transition; unfreezing an active
    // one is not, and must say so.
    h.client.unfreeze(&h.owner, &frozen);
    assert_eq!(
        h.client.try_unfreeze(&h.owner, &frozen),
        Err(Ok(Error::InvalidState))
    );

    let archived = budget(&h, "archived", 1_000);
    h.client
        .set_budget_limit(&h.owner, &archived, &token, &1_000, &0);
    h.client.freeze(&h.owner, &archived);
    h.client.archive(&h.owner, &archived);
    assert_eq!(
        h.client
            .try_check_and_record_spend(&h.owner, &archived, &token, &1),
        Err(Ok(Error::BudgetArchived))
    );
    // Re-freezing an archived envelope reports the terminal state.
    assert_eq!(
        h.client.try_freeze(&h.owner, &archived),
        Err(Ok(Error::BudgetArchived))
    );

    // A lapsed envelope reports expiry, not exhaustion: the remaining balance
    // was never spendable in the first place, and reviving it is the fix.
    let lapsed = id(&h.env, "lapsed");
    h.client
        .allocate(&h.owner, &lapsed, &1_000, &Period::None, &false, &1_500);
    h.env.ledger().set_timestamp(2_000);
    assert_eq!(
        h.client.try_reset(&h.owner, &lapsed),
        Err(Ok(Error::BudgetExpired))
    );
    // Clearing a lapsed envelope's history is what `reset` is for, so the
    // expiry guard has to fire before it writes anything.
    assert_eq!(h.client.get(&lapsed).spent, 0);
}

#[test]
fn spending_someone_elses_budget_is_unauthorized() {
    let h = setup();
    let b = budget(&h, "eng", 1_000);
    let token = Address::generate(&h.env);
    h.client.set_budget_limit(&h.owner, &b, &token, &1_000, &0);
    let stranger = Address::generate(&h.env);

    // An id that exists but is not the caller's is a permission failure, not a
    // missing one — the distinction tells an agent to stop, not to re-provision.
    assert_eq!(
        h.client
            .try_check_and_record_spend(&stranger, &b, &token, &1),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(
        h.client.try_set_budget_limit(&stranger, &b, &token, &1, &0),
        Err(Ok(Error::Unauthorized))
    );
    let dest = budget(&h, "dest", 100);
    assert_eq!(
        h.client.try_transfer_allocation(&stranger, &b, &dest, &1),
        Err(Ok(Error::Unauthorized))
    );
    // Moving between the caller's own envelopes is a different diagnosis.
    assert_eq!(
        h.client.try_transfer_allocation(&h.owner, &b, &b, &1),
        Err(Ok(Error::InvalidInput))
    );
    assert_eq!(h.client.remaining(&b), 1_000);
}
