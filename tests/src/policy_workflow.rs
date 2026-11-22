//! Full policy enforcement workflow for an AI agent (Issue #469).
//!
//! Deploys registry, wallet, policy, budget and treasury into one `Env`,
//! resolves every module through the registry, configures the org's rules,
//! and runs permitted and blocked transactions through the whole stack:
//!
//! ```text
//!                 ┌───────────── registry (source of truth) ─────────────┐
//!                 ▼                    ▼                 ▼               ▼
//! admin ──withdraw──▶ treasury ──consume──▶ budget      policy ◀── wallet ◀── agent
//!                        │ └──check_transfer──────────────▲          │
//!                        └──▶ token ──▶ wallet custody    │          └──▶ token ──▶ merchant
//!                                                         │
//!                 per-agent limits: check_spending_limit / record_agent_spend
//! ```
//!
//! An agent spend goes through the same three steps a production executor
//! runs: the policy's per-agent spending limit is checked, the wallet transfer
//! is evaluated by the policy's `check_transfer` gates, and only then is the
//! spend recorded against the agent's daily total.
//!
//! For every blocked transaction the test asserts both the deterministic error
//! code (`PolicyDenied` for rule violations, `BudgetLimitReached` for exhausted
//! allowances) and that no balance, ledger, or counter moved.

use astroid_budget::{BudgetContract, BudgetContractClient, Period};
use astroid_policy::{PolicyContract, PolicyContractClient};
use astroid_registry::{RegistryContract, RegistryContractClient};
use astroid_shared::constants::SECONDS_PER_DAY;
use astroid_shared::errors::Error;
use astroid_shared::types::ModuleKind;
use astroid_treasury::{TreasuryContract, TreasuryContractClient};
use astroid_wallet::access::Role;
use astroid_wallet::{WalletContract, WalletContractClient};
use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::{token, Address, BytesN, Env, String};

const ORG: &str = "acme";
/// The treasury and wallet both evaluate spends against this policy id.
const POLICY_ID: &str = "active";
const BUDGET_ID: &str = "treasury-daily";
const TREASURY_FUNDS: i128 = 1_000_000;
/// Policy-wide single-transaction ceiling.
const POLICY_CAP: i128 = 50_000;
/// Treasury daily budget envelope.
const DAILY_BUDGET: i128 = 120_000;
/// Per-agent limits layered on the policy.
const AGENT_PER_TX: i128 = 5_000;
const AGENT_DAILY: i128 = 12_000;
/// 10:00 UTC on an arbitrary day.
const START: u64 = 19_000 * SECONDS_PER_DAY + 36_000;

struct Harness<'a> {
    env: Env,
    registry: RegistryContractClient<'a>,
    treasury: TreasuryContractClient<'a>,
    budget: BudgetContractClient<'a>,
    policy: PolicyContractClient<'a>,
    wallet: WalletContractClient<'a>,
    admin: Address,
    org_owner: Address,
    agent: Address,
    merchant: Address,
    asset: Address,
    wallet_id: u64,
}

impl<'a> Harness<'a> {
    fn s(&self, v: &str) -> String {
        String::from_str(&self.env, v)
    }

    fn pid(&self) -> String {
        self.s(POLICY_ID)
    }

    fn balance(&self, who: &Address) -> i128 {
        token::TokenClient::new(&self.env, &self.asset).balance(who)
    }

    fn set_time(&self, t: u64) {
        self.env.ledger().with_mut(|l| l.timestamp = t);
    }

    /// Every value the workflow can move, for "nothing moved" assertions.
    fn snapshot(&self) -> [i128; 8] {
        let holding = self.treasury.holding(&self.asset);
        [
            self.balance(&self.treasury.address),
            self.balance(&self.wallet.address),
            self.balance(&self.merchant),
            self.wallet.balance(&self.wallet_id, &self.asset),
            holding.total_out,
            self.budget.get(&self.s(BUDGET_ID)).spent,
            self.policy
                .get_agent_daily_spend(&self.pid(), &self.agent)
                .spent,
            self.balance(&self.org_owner),
        ]
    }

    /// Treasury → wallet funding: a policy- and budget-gated withdrawal to the
    /// org owner, who deposits it into the agent's wallet.
    fn fund_wallet(&self, amount: i128) -> Result<(), Error> {
        match self
            .treasury
            .try_withdraw(&self.admin, &self.asset, &self.org_owner, &amount)
        {
            Ok(Ok(())) => {}
            Err(Ok(e)) => return Err(e),
            other => panic!("unexpected host result: {:?}", other),
        }
        self.wallet
            .deposit(&self.wallet_id, &self.org_owner, &self.asset, &amount);
        Ok(())
    }

    /// One agent payment through the full pipeline: per-agent limit check →
    /// policy-gated wallet transfer → spend recorded against the daily total.
    /// Any refusal leaves every ledger untouched.
    fn agent_pay(&self, to: &Address, amount: i128) -> Result<(), Error> {
        match self
            .policy
            .try_check_spending_limit(&self.pid(), &self.agent, &amount)
        {
            Ok(Ok(_)) => {}
            Err(Ok(e)) => return Err(e),
            other => panic!("unexpected host result: {:?}", other),
        }
        match self
            .wallet
            .try_transfer(&self.agent, &self.wallet_id, to, &self.asset, &amount)
        {
            Ok(Ok(())) => {}
            Err(Ok(e)) => return Err(e),
            other => panic!("unexpected host result: {:?}", other),
        }
        self.policy
            .record_agent_spend(&self.admin, &self.pid(), &self.agent, &amount);
        Ok(())
    }
}

fn setup() -> Harness<'static> {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().with_mut(|l| l.timestamp = START);

    let admin = Address::generate(&env);
    let org_owner = Address::generate(&env);
    let agent = Address::generate(&env);
    let merchant = Address::generate(&env);
    let org = String::from_str(&env, ORG);

    // 1. Registry.
    let registry_id = env.register_contract(None, RegistryContract);
    let registry = RegistryContractClient::new(&env, &registry_id);
    registry.initialize(&admin);
    registry.register_org(&admin, &org, &org_owner);

    // 2. Deploy and register wallet, policy, budget, treasury.
    let wallet_addr = env.register_contract(None, WalletContract);
    let policy_addr = env.register_contract(None, PolicyContract);
    let budget_addr = env.register_contract(None, BudgetContract);
    let treasury_addr = env.register_contract(None, TreasuryContract);
    for (kind, addr) in [
        (ModuleKind::Wallet, &wallet_addr),
        (ModuleKind::Policy, &policy_addr),
        (ModuleKind::Budget, &budget_addr),
        (ModuleKind::Treasury, &treasury_addr),
    ] {
        registry.register_module(&org_owner, &org, &kind, addr);
    }

    // 3. From here on every module is reached through the registry.
    let wallet = WalletContractClient::new(&env, &registry.lookup(&org, &ModuleKind::Wallet));
    let policy = PolicyContractClient::new(&env, &registry.lookup(&org, &ModuleKind::Policy));
    let budget = BudgetContractClient::new(&env, &registry.lookup(&org, &ModuleKind::Budget));
    let treasury = TreasuryContractClient::new(&env, &registry.lookup(&org, &ModuleKind::Treasury));

    wallet.initialize(&admin);
    policy.initialize();
    budget.initialize(&admin);
    treasury.initialize(&org, &admin);

    // 4. Token + treasury funding.
    let token_admin = Address::generate(&env);
    let asset = env
        .register_stellar_asset_contract_v2(token_admin)
        .address();
    treasury.add_approved_asset(&admin, &asset);
    token::StellarAssetClient::new(&env, &asset).mint(&admin, &TREASURY_FUNDS);
    treasury.deposit(&admin, &asset, &TREASURY_FUNDS);

    // 5. Rules: org policy (cap + asset), per-agent limits, daily budget.
    policy.register_policy(
        &admin,
        &String::from_str(&env, POLICY_ID),
        &BytesN::from_array(&env, &[0x47; 32]),
        &POLICY_CAP,
        &None,
        &Some(asset.clone()),
        &0u64,
        &None,
    );
    policy.set_agent_spend_limit(
        &admin,
        &String::from_str(&env, POLICY_ID),
        &agent,
        &AGENT_PER_TX,
        &AGENT_DAILY,
    );
    budget.allocate(
        &admin,
        &String::from_str(&env, BUDGET_ID),
        &DAILY_BUDGET,
        &Period::Daily,
        &false,
        &0u64,
    );

    // 6. Wire the gates to the modules the registry resolves.
    let resolved_policy = registry.lookup(&org, &ModuleKind::Policy);
    treasury.set_policy(&admin, &resolved_policy);
    wallet.set_policy(&admin, &resolved_policy);
    treasury.set_budget(&admin, &registry.lookup(&org, &ModuleKind::Budget));
    treasury.allocate_budget(&admin, &asset, &String::from_str(&env, BUDGET_ID));

    // 7. Agent wallet.
    let wallet_id = wallet.create_wallet(&org_owner);
    wallet.grant_role(&org_owner, &wallet_id, &agent, &Role::Agent);

    Harness {
        env,
        registry,
        treasury,
        budget,
        policy,
        wallet,
        admin,
        org_owner,
        agent,
        merchant,
        asset,
        wallet_id,
    }
}

// --- wiring -----------------------------------------------------------------

#[test]
fn every_gate_is_wired_to_the_module_the_registry_resolves() {
    let h = setup();
    let org = h.s(ORG);
    let policy = h.registry.lookup(&org, &ModuleKind::Policy);
    assert_eq!(policy, h.policy.address);
    assert_eq!(h.wallet.get_policy(), Some(policy.clone()));
    let t = h.treasury.get();
    assert_eq!(t.policy, Some(policy));
    assert_eq!(t.budget, Some(h.registry.lookup(&org, &ModuleKind::Budget)));
}

// --- the full workflow: permitted vs blocked ---------------------------------

#[test]
fn compliant_and_violating_transactions_through_the_full_stack() {
    let h = setup();

    // Treasury funds the wallet: policy (≤ cap, right asset) and budget pass.
    h.fund_wallet(40_000).unwrap();
    assert_eq!(h.budget.get(&h.s(BUDGET_ID)).spent, 40_000);
    assert_eq!(h.wallet.balance(&h.wallet_id, &h.asset), 40_000);

    // Permitted: within every rule.
    h.agent_pay(&h.merchant, 4_000).unwrap();
    assert_eq!(h.balance(&h.merchant), 4_000);
    assert_eq!(
        h.policy.get_agent_daily_spend(&h.pid(), &h.agent).spent,
        4_000
    );

    // Blocked: above the agent's per-transaction limit.
    let before = h.snapshot();
    assert_eq!(
        h.agent_pay(&h.merchant, AGENT_PER_TX + 1),
        Err(Error::PolicyDenied)
    );
    assert_eq!(h.snapshot(), before);

    // Permitted again: the denial left no residue.
    h.agent_pay(&h.merchant, AGENT_PER_TX).unwrap();
    assert_eq!(h.balance(&h.merchant), 9_000);

    // Value is conserved across every holder.
    assert_eq!(
        h.balance(&h.treasury.address)
            + h.balance(&h.org_owner)
            + h.balance(&h.wallet.address)
            + h.balance(&h.merchant),
        TREASURY_FUNDS
    );
}

#[test]
fn wallet_transfer_over_policy_cap_is_policy_denied() {
    let h = setup();
    // Lift the agent limit so only the policy-wide cap stands in the way.
    h.policy
        .remove_agent_spend_limit(&h.admin, &h.pid(), &h.agent);
    h.fund_wallet(POLICY_CAP).unwrap();
    h.fund_wallet(POLICY_CAP).unwrap();
    let before = h.snapshot();
    assert_eq!(
        h.agent_pay(&h.merchant, POLICY_CAP + 1),
        Err(Error::PolicyDenied)
    );
    assert_eq!(h.snapshot(), before);
    // Exactly the cap is fine.
    h.agent_pay(&h.merchant, POLICY_CAP).unwrap();
    assert_eq!(h.balance(&h.merchant), POLICY_CAP);
}

#[test]
fn treasury_withdrawal_over_policy_cap_is_policy_denied_before_budget() {
    let h = setup();
    let before = h.snapshot();
    assert_eq!(h.fund_wallet(POLICY_CAP + 1), Err(Error::PolicyDenied));
    // The budget was never debited and no tokens left the treasury.
    assert_eq!(h.snapshot(), before);
}

#[test]
fn unlisted_recipient_is_policy_denied_once_whitelist_is_enforced() {
    let h = setup();
    h.fund_wallet(20_000).unwrap();
    let pid = h.pid();
    h.policy
        .add_recipient_to_whitelist(&h.admin, &pid, &h.org_owner);
    h.policy
        .add_recipient_to_whitelist(&h.admin, &pid, &h.merchant);
    h.policy
        .set_recipient_whitelist_enabled(&h.admin, &pid, &true);

    let stranger = Address::generate(&h.env);
    let before = h.snapshot();
    assert_eq!(h.agent_pay(&stranger, 1_000), Err(Error::PolicyDenied));
    assert_eq!(h.snapshot(), before);
    assert_eq!(h.balance(&stranger), 0);

    h.agent_pay(&h.merchant, 1_000).unwrap();
    assert_eq!(h.balance(&h.merchant), 1_000);
}

#[test]
fn spend_outside_operating_hours_is_policy_denied() {
    let h = setup();
    h.fund_wallet(20_000).unwrap();
    // Business hours 09:00–17:00 UTC.
    h.policy
        .set_transfer_window(&h.admin, &h.pid(), &32_400, &61_200, &SECONDS_PER_DAY);

    h.agent_pay(&h.merchant, 1_000).unwrap(); // 10:00 — open.

    let day = START - START % SECONDS_PER_DAY;
    h.set_time(day + 61_200); // 17:00 — end is exclusive.
    let before = h.snapshot();
    assert_eq!(h.agent_pay(&h.merchant, 1_000), Err(Error::PolicyDenied));
    assert_eq!(h.snapshot(), before);
}

#[test]
fn disabled_policy_halts_the_whole_workflow() {
    let h = setup();
    h.fund_wallet(10_000).unwrap();
    h.policy.set_enabled(&h.admin, &h.pid(), &false);
    let before = h.snapshot();
    assert_eq!(h.agent_pay(&h.merchant, 1_000), Err(Error::PolicyDenied));
    assert_eq!(h.fund_wallet(1_000), Err(Error::PolicyDenied));
    assert_eq!(h.snapshot(), before);

    h.policy.set_enabled(&h.admin, &h.pid(), &true);
    h.agent_pay(&h.merchant, 1_000).unwrap();
}

// --- cumulative limits -------------------------------------------------------

#[test]
fn agent_daily_limit_blocks_then_resets_next_day() {
    let h = setup();
    h.fund_wallet(40_000).unwrap();
    h.agent_pay(&h.merchant, 5_000).unwrap();
    h.agent_pay(&h.merchant, 5_000).unwrap();
    h.agent_pay(&h.merchant, 2_000).unwrap(); // exactly the daily limit.

    let before = h.snapshot();
    assert_eq!(h.agent_pay(&h.merchant, 1), Err(Error::BudgetLimitReached));
    assert_eq!(h.snapshot(), before);

    // Next UTC day: the window resets automatically.
    h.set_time(START + SECONDS_PER_DAY);
    h.agent_pay(&h.merchant, 5_000).unwrap();
    assert_eq!(h.balance(&h.merchant), AGENT_DAILY + 5_000);
}

#[test]
fn treasury_budget_exhaustion_is_budget_exceeded_even_when_policy_allows() {
    let h = setup();
    h.fund_wallet(POLICY_CAP).unwrap();
    h.fund_wallet(POLICY_CAP).unwrap();
    // 100_000 of 120_000 spent; 30_000 passes the policy cap but not the budget.
    let before = h.snapshot();
    assert_eq!(h.fund_wallet(30_000), Err(Error::BUDGET_LIMIT_EXCEEDED));
    assert_eq!(h.snapshot(), before);
    h.fund_wallet(20_000).unwrap();
    assert_eq!(h.budget.get(&h.s(BUDGET_ID)).spent, DAILY_BUDGET);
}

#[test]
fn unauthorized_caller_is_rejected_before_any_policy_evaluation() {
    let h = setup();
    h.fund_wallet(10_000).unwrap();
    let stranger = Address::generate(&h.env);
    let before = h.snapshot();
    assert!(h
        .wallet
        .try_transfer(&stranger, &h.wallet_id, &h.merchant, &h.asset, &100)
        .is_err());
    assert_eq!(
        h.policy
            .try_record_agent_spend(&stranger, &h.pid(), &h.agent, &100),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(h.snapshot(), before);
}
