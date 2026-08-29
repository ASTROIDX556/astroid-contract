#![cfg(test)]
extern crate std;

use crate::{Budget, BudgetContract, BudgetContractClient, Period};
use astroid_shared::errors::Error;
use astroid_shared::types::ResourceState;
use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::{Address, Env, String};

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

#[test]
fn rollover_enabled_without_period_fails() {
    let h = setup();
    let res = h.client.try_allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::None,
        &true,
        &0,
    );
    assert_eq!(res, Err(Ok(Error::InvalidPeriod)));
}

#[test]
fn multiple_daily_cycles_with_rollover() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::Daily,
        &true,
        &0,
    );
    // Day 1: spend 600, leave 400 unspent
    h.client.consume(&h.owner, &id(&h.env, "eng"), &600);
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 400);
    
    // Day 2: 400 rolls over, new capacity = 1000 + 400 = 1400
    h.env.ledger().set_timestamp(1_000 + 86_400);
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 1_400);
    h.client.consume(&h.owner, &id(&h.env, "eng"), &800);
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 600);
    
    // Day 3: 600 rolls over, new capacity = 1000 + 600 = 1600
    h.env.ledger().set_timestamp(1_000 + 2 * 86_400);
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 1_600);
    let b: Budget = h.client.get(&id(&h.env, "eng"));
    assert_eq!(b.rollover_credit, 600);
}

#[test]
fn multiple_daily_cycles_without_rollover() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "eng"),
        &1_000,
        &Period::Daily,
        &false,
        &0,
    );
    // Day 1: spend 600, leave 400 unspent
    h.client.consume(&h.owner, &id(&h.env, "eng"), &600);
    
    // Day 2: unspent cleared, capacity back to 1000
    h.env.ledger().set_timestamp(1_000 + 86_400);
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 1_000);
    h.client.consume(&h.owner, &id(&h.env, "eng"), &500);
    
    // Day 3: again unspent cleared, capacity back to 1000
    h.env.ledger().set_timestamp(1_000 + 2 * 86_400);
    assert_eq!(h.client.remaining(&id(&h.env, "eng")), 1_000);
    let b: Budget = h.client.get(&id(&h.env, "eng"));
    assert_eq!(b.rollover_credit, 0);
}

#[test]
fn weekly_cycles_across_multiple_weeks() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "marketing"),
        &5_000,
        &Period::Weekly,
        &true,
        &0,
    );
    // Week 1: spend 3000, leave 2000 unspent
    h.client.consume(&h.owner, &id(&h.env, "marketing"), &3_000);
    
    // Week 2: 2000 rolls over, capacity = 5000 + 2000 = 7000
    h.env.ledger().set_timestamp(1_000 + 604_800);
    assert_eq!(h.client.remaining(&id(&h.env, "marketing")), 7_000);
    h.client.consume(&h.owner, &id(&h.env, "marketing"), &4_000);
    
    // Week 3: 3000 rolls over, capacity = 5000 + 3000 = 8000
    h.env.ledger().set_timestamp(1_000 + 2 * 604_800);
    assert_eq!(h.client.remaining(&id(&h.env, "marketing")), 8_000);
    
    // Week 4: 8000 rolls over (since nothing spent in week 3), capacity = 5000 + 8000 = 13000
    h.env.ledger().set_timestamp(1_000 + 3 * 604_800);
    assert_eq!(h.client.remaining(&id(&h.env, "marketing")), 13_000);
}

#[test]
fn monthly_cycles_with_rollover() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "ops"),
        &10_000,
        &Period::Monthly,
        &true,
        &0,
    );
    // Month 1: spend 7000, leave 3000 unspent
    h.client.consume(&h.owner, &id(&h.env, "ops"), &7_000);
    
    // Month 2: 3000 rolls over, capacity = 10000 + 3000 = 13000
    h.env.ledger().set_timestamp(1_000 + 2_592_000);
    assert_eq!(h.client.remaining(&id(&h.env, "ops")), 13_000);
    h.client.consume(&h.owner, &id(&h.env, "ops"), &8_000);
    
    // Month 3: 5000 rolls over, capacity = 10000 + 5000 = 15000
    h.env.ledger().set_timestamp(1_000 + 2 * 2_592_000);
    assert_eq!(h.client.remaining(&id(&h.env, "ops")), 15_000);
}

#[test]
fn rollover_accumulates_across_periods() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "research"),
        &1_000,
        &Period::Daily,
        &true,
        &0,
    );
    // Day 1: spend 200, leave 800 unspent
    h.client.consume(&h.owner, &id(&h.env, "research"), &200);
    
    // Day 2: 800 rolls over, spend 100, leave 700 unspent + 800 rollover = 1500 total capacity
    h.env.ledger().set_timestamp(1_000 + 86_400);
    assert_eq!(h.client.remaining(&id(&h.env, "research")), 1_800);
    h.client.consume(&h.owner, &id(&h.env, "research"), &100);
    
    // Day 3: 1700 rolls over (1000 base + 800 previous rollover - 100 spent = 1700)
    h.env.ledger().set_timestamp(1_000 + 2 * 86_400);
    assert_eq!(h.client.remaining(&id(&h.env, "research")), 2_700);
    let b: Budget = h.client.get(&id(&h.env, "research"));
    assert_eq!(b.rollover_credit, 1_700);
}

#[test]
fn auto_reset_during_consumption() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "dev"),
        &1_000,
        &Period::Daily,
        &false,
        &0,
    );
    // Exhaust the budget
    h.client.consume(&h.owner, &id(&h.env, "dev"), &1_000);
    assert_eq!(h.client.remaining(&id(&h.env, "dev")), 0);
    
    // Advance past the daily window and consume - should auto-reset
    h.env.ledger().set_timestamp(1_000 + 86_400);
    let rem = h.client.consume(&h.owner, &id(&h.env, "dev"), &500);
    assert_eq!(rem, 500);
    
    let b: Budget = h.client.get(&id(&h.env, "dev"));
    assert_eq!(b.spent, 500);
    assert_eq!(b.window_start, 1_000 + 86_400);
}

#[test]
fn period_transition_with_pending_spend() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "qa"),
        &1_000,
        &Period::Weekly,
        &true,
        &0,
    );
    // Spend 600 in week 1
    h.client.consume(&h.owner, &id(&h.env, "qa"), &600);
    
    // Advance to week 2, then spend 900 (400 rollover + 500 from new limit)
    h.env.ledger().set_timestamp(1_000 + 604_800);
    let rem = h.client.consume(&h.owner, &id(&h.env, "qa"), &900);
    assert_eq!(rem, 500); // 1400 capacity - 900 spent = 500 remaining
    
    let b: Budget = h.client.get(&id(&h.env, "qa"));
    assert_eq!(b.spent, 900);
    assert_eq!(b.rollover_credit, 400);
}

#[test]
fn budget_window_start_advances_correctly() {
    let h = setup();
    h.client.allocate(
        &h.owner,
        &id(&h.env, "infra"),
        &1_000,
        &Period::Daily,
        &false,
        &0,
    );
    
    let b: Budget = h.client.get(&id(&h.env, "infra"));
    assert_eq!(b.window_start, 1_000);
    
    // Advance time by 2 days and trigger a transition
    h.env.ledger().set_timestamp(1_000 + 2 * 86_400);
    h.client.consume(&h.owner, &id(&h.env, "infra"), &100);
    
    let b: Budget = h.client.get(&id(&h.env, "infra"));
    assert_eq!(b.window_start, 1_000 + 2 * 86_400);
}
