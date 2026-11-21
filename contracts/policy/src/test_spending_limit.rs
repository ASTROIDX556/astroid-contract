//! Unit tests for the deterministic per-agent spending limit (Issue #471).
//!
//! Covers the per-transaction cap, daily cumulative tracking, the automatic
//! UTC-midnight window reset, the exact-boundary cases, owner gating, input
//! validation, and the shared error codes each refusal reports.

use astroid_shared::constants::SECONDS_PER_DAY;
use astroid_shared::errors::Error;
use soroban_sdk::{
    testutils::{Address as _, Ledger},
    Address, BytesN, Env, String,
};

use crate::{AgentDailySpend, AgentSpendLimit, PolicyContract, PolicyContractClient};

const POLICY: &str = "agents";
/// A ledger time in the middle of a UTC day (day 20_000 + 12h).
const NOON: u64 = 20_000 * SECONDS_PER_DAY + 43_200;
const PER_TX: i128 = 1_000;
const DAILY: i128 = 2_500;

struct T<'a> {
    env: Env,
    policy: PolicyContractClient<'a>,
    owner: Address,
    agent: Address,
}

impl<'a> T<'a> {
    fn id(&self) -> String {
        String::from_str(&self.env, POLICY)
    }

    fn set_time(&self, t: u64) {
        self.env.ledger().with_mut(|l| l.timestamp = t);
    }

    fn limit(&self, per_tx: i128, daily: i128) {
        self.policy
            .set_agent_spend_limit(&self.owner, &self.id(), &self.agent, &per_tx, &daily);
    }

    fn record(&self, amount: i128) -> Result<i128, Error> {
        match self
            .policy
            .try_record_agent_spend(&self.owner, &self.id(), &self.agent, &amount)
        {
            Ok(Ok(v)) => Ok(v),
            Err(Ok(e)) => Err(e),
            other => panic!("unexpected host result: {:?}", other),
        }
    }

    fn check(&self, amount: i128) -> Result<i128, Error> {
        match self
            .policy
            .try_check_spending_limit(&self.id(), &self.agent, &amount)
        {
            Ok(Ok(v)) => Ok(v),
            Err(Ok(e)) => Err(e),
            other => panic!("unexpected host result: {:?}", other),
        }
    }

    fn spent(&self) -> i128 {
        self.policy
            .get_agent_daily_spend(&self.id(), &self.agent)
            .spent
    }
}

fn setup<'a>() -> T<'a> {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().with_mut(|l| l.timestamp = NOON);
    let owner = Address::generate(&env);
    let agent = Address::generate(&env);
    let id = env.register_contract(None, PolicyContract);
    let policy = PolicyContractClient::new(&env, &id);
    policy.initialize();
    policy.register_policy(
        &owner,
        &String::from_str(&env, POLICY),
        &BytesN::from_array(&env, &[9u8; 32]),
        &1_000_000,
        &None,
        &None,
        &0,
        &None,
    );
    T {
        env,
        policy,
        owner,
        agent,
    }
}

// --- configuration ---------------------------------------------------------

#[test]
fn set_and_get_limit_round_trips() {
    let t = setup();
    t.limit(PER_TX, DAILY);
    assert_eq!(
        t.policy.get_agent_spend_limit(&t.id(), &t.agent),
        AgentSpendLimit {
            per_tx_limit: PER_TX,
            daily_limit: DAILY,
        }
    );
}

#[test]
fn unconfigured_limit_is_not_found() {
    let t = setup();
    assert_eq!(
        t.policy.try_get_agent_spend_limit(&t.id(), &t.agent),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn negative_caps_are_rejected() {
    let t = setup();
    assert_eq!(
        t.policy
            .try_set_agent_spend_limit(&t.owner, &t.id(), &t.agent, &-1, &DAILY),
        Err(Ok(Error::InvalidAmount))
    );
    assert_eq!(
        t.policy
            .try_set_agent_spend_limit(&t.owner, &t.id(), &t.agent, &PER_TX, &-1),
        Err(Ok(Error::InvalidAmount))
    );
}

#[test]
fn per_tx_cap_above_daily_cap_is_rejected() {
    let t = setup();
    assert_eq!(
        t.policy
            .try_set_agent_spend_limit(&t.owner, &t.id(), &t.agent, &(DAILY + 1), &DAILY),
        Err(Ok(Error::InvalidInput))
    );
    // Equal caps are coherent: one maximal spend uses the whole day.
    t.limit(DAILY, DAILY);
}

#[test]
fn only_the_policy_owner_can_configure_or_record() {
    let t = setup();
    let stranger = Address::generate(&t.env);
    assert_eq!(
        t.policy
            .try_set_agent_spend_limit(&stranger, &t.id(), &t.agent, &PER_TX, &DAILY),
        Err(Ok(Error::Unauthorized))
    );
    t.limit(PER_TX, DAILY);
    assert_eq!(
        t.policy
            .try_record_agent_spend(&stranger, &t.id(), &t.agent, &10),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(
        t.policy
            .try_remove_agent_spend_limit(&stranger, &t.id(), &t.agent),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(t.spent(), 0);
}

#[test]
fn unknown_policy_is_not_found() {
    let t = setup();
    let missing = String::from_str(&t.env, "missing");
    assert_eq!(
        t.policy
            .try_set_agent_spend_limit(&t.owner, &missing, &t.agent, &PER_TX, &DAILY),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(
        t.policy.try_check_spending_limit(&missing, &t.agent, &10),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn remove_clears_limit_and_spend() {
    let t = setup();
    t.limit(PER_TX, DAILY);
    t.record(PER_TX).unwrap();
    t.policy
        .remove_agent_spend_limit(&t.owner, &t.id(), &t.agent);
    assert_eq!(
        t.policy.try_get_agent_spend_limit(&t.id(), &t.agent),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(t.spent(), 0);
    assert_eq!(
        t.policy
            .try_remove_agent_spend_limit(&t.owner, &t.id(), &t.agent),
        Err(Ok(Error::NotFound))
    );
}

// --- per-transaction cap ----------------------------------------------------

#[test]
fn spend_at_per_tx_cap_is_allowed() {
    let t = setup();
    t.limit(PER_TX, DAILY);
    assert_eq!(t.check(PER_TX), Ok(DAILY - PER_TX));
    assert_eq!(t.record(PER_TX), Ok(DAILY - PER_TX));
    assert_eq!(t.spent(), PER_TX);
}

#[test]
fn spend_one_over_per_tx_cap_is_policy_denied_and_records_nothing() {
    let t = setup();
    t.limit(PER_TX, DAILY);
    assert_eq!(t.check(PER_TX + 1), Err(Error::PolicyDenied));
    assert_eq!(t.record(PER_TX + 1), Err(Error::PolicyDenied));
    assert_eq!(t.spent(), 0);
}

#[test]
fn per_tx_only_limit_never_caps_the_day() {
    let t = setup();
    t.limit(PER_TX, 0);
    for _ in 0..10 {
        assert_eq!(t.record(PER_TX), Ok(i128::MAX));
    }
    assert_eq!(t.spent(), 10 * PER_TX);
    assert_eq!(t.record(PER_TX + 1), Err(Error::PolicyDenied));
}

// --- daily cumulative cap ---------------------------------------------------

#[test]
fn daily_spend_accumulates_up_to_the_exact_cap() {
    let t = setup();
    t.limit(PER_TX, DAILY);
    assert_eq!(t.record(1_000), Ok(1_500));
    assert_eq!(t.record(1_000), Ok(500));
    // Exactly the remaining headroom is allowed and leaves zero.
    assert_eq!(t.record(500), Ok(0));
    assert_eq!(t.spent(), DAILY);
}

#[test]
fn spend_past_daily_cap_is_budget_exceeded_and_records_nothing() {
    let t = setup();
    t.limit(PER_TX, DAILY);
    t.record(1_000).unwrap();
    t.record(1_000).unwrap();
    assert_eq!(t.check(501), Err(Error::BudgetLimitReached));
    assert_eq!(t.record(501), Err(Error::BudgetLimitReached));
    assert_eq!(t.spent(), 2_000);
    // A smaller spend that fits still goes through.
    assert_eq!(t.record(500), Ok(0));
}

#[test]
fn per_tx_gate_is_checked_before_daily_gate() {
    let t = setup();
    t.limit(PER_TX, DAILY);
    t.record(1_000).unwrap();
    t.record(1_000).unwrap();
    // Breaches both caps: the per-transaction refusal wins, deterministically.
    assert_eq!(t.check(PER_TX + 1), Err(Error::PolicyDenied));
}

#[test]
fn check_is_read_only() {
    let t = setup();
    t.limit(PER_TX, DAILY);
    for _ in 0..5 {
        assert_eq!(t.check(PER_TX), Ok(DAILY - PER_TX));
    }
    assert_eq!(t.spent(), 0);
}

#[test]
fn tightening_mid_day_counts_spend_already_recorded() {
    let t = setup();
    t.limit(PER_TX, DAILY);
    t.record(1_000).unwrap();
    t.record(1_000).unwrap();
    t.limit(PER_TX, 2_000);
    assert_eq!(t.record(1), Err(Error::BudgetLimitReached));
}

#[test]
fn spend_without_a_limit_is_unrestricted_but_tracked() {
    let t = setup();
    assert_eq!(t.check(500_000), Ok(i128::MAX));
    assert_eq!(t.record(2_000), Ok(i128::MAX));
    assert_eq!(t.spent(), 2_000);
    // A limit introduced later the same day sees the real running total.
    t.limit(PER_TX, DAILY);
    assert_eq!(t.record(600), Err(Error::BudgetLimitReached));
    assert_eq!(t.record(500), Ok(0));
}

// --- automatic window reset -------------------------------------------------

#[test]
fn window_resets_at_utc_midnight() {
    let t = setup();
    t.limit(PER_TX, DAILY);
    t.record(1_000).unwrap();
    t.record(1_000).unwrap();
    t.record(500).unwrap();

    let midnight = (NOON / SECONDS_PER_DAY + 1) * SECONDS_PER_DAY;
    // One second before midnight is still the exhausted day.
    t.set_time(midnight - 1);
    assert_eq!(t.check(1), Err(Error::BudgetLimitReached));

    // Midnight itself opens the next window (start inclusive).
    t.set_time(midnight);
    assert_eq!(
        t.policy.get_agent_daily_spend(&t.id(), &t.agent),
        AgentDailySpend {
            day_start: midnight,
            spent: 0,
        }
    );
    assert_eq!(t.record(1_000), Ok(1_500));
}

#[test]
fn window_reset_after_multi_day_gap_does_not_accrue() {
    let t = setup();
    t.limit(PER_TX, DAILY);
    t.record(500).unwrap();
    // Idle for a week: the cap is per day, unused days never stack.
    t.set_time(NOON + 7 * SECONDS_PER_DAY);
    assert_eq!(t.spent(), 0);
    t.record(1_000).unwrap();
    t.record(1_000).unwrap();
    t.record(500).unwrap();
    assert_eq!(t.record(1), Err(Error::BudgetLimitReached));
}

#[test]
fn day_start_is_aligned_to_midnight() {
    let t = setup();
    let record = t.policy.get_agent_daily_spend(&t.id(), &t.agent);
    assert_eq!(record.day_start % SECONDS_PER_DAY, 0);
    assert!(record.day_start <= NOON && NOON < record.day_start + SECONDS_PER_DAY);
}

// --- input validation and arithmetic safety --------------------------------

#[test]
fn non_positive_amounts_are_invalid() {
    let t = setup();
    t.limit(PER_TX, DAILY);
    assert_eq!(t.check(0), Err(Error::InvalidAmount));
    assert_eq!(t.check(-5), Err(Error::InvalidAmount));
    assert_eq!(t.record(0), Err(Error::InvalidAmount));
}

#[test]
fn running_total_overflow_is_reported_not_wrapped() {
    let t = setup();
    // No limit: tracked but unrestricted, so only checked math can stop it.
    t.record(i128::MAX).unwrap();
    assert_eq!(t.check(1), Err(Error::Overflow));
    assert_eq!(t.record(1), Err(Error::Overflow));
    assert_eq!(t.spent(), i128::MAX);
}

#[test]
fn limits_are_scoped_per_agent_and_per_policy() {
    let t = setup();
    t.limit(PER_TX, DAILY);
    let other_agent = Address::generate(&t.env);
    // Another agent is untouched by this agent's limit and spend.
    t.record(1_000).unwrap();
    assert_eq!(
        t.policy
            .check_spending_limit(&t.id(), &other_agent, &500_000),
        i128::MAX
    );

    // The same agent under another policy has an independent ledger.
    let other = String::from_str(&t.env, "other");
    t.policy.register_policy(
        &t.owner,
        &other,
        &BytesN::from_array(&t.env, &[1u8; 32]),
        &1_000_000,
        &None,
        &None,
        &0,
        &None,
    );
    assert_eq!(t.policy.get_agent_daily_spend(&other, &t.agent).spent, 0);
}
