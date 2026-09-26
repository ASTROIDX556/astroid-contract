//! End-to-end policy enforcement during wallet spending (Issue #227).
//!
//! Proves that the org's policy protects agent spending at the multi-contract
//! level, not just inside the policy contract's own unit tests:
//!
//! ```text
//! registry ──lookup──▶ treasury ──check_transfer──▶ policy
//!    │                    │ (funds the wallet)        ▲
//!    └──lookup──▶ wallet ─┴──── check_transfer ───────┘
//!                   │ (agent spend)
//!                   └──▶ token (SAC) ──▶ merchant
//! ```
//!
//! Every module address the gates use is resolved through the registry, the
//! single source of truth, so the test exercises the real wiring an org runs.
//! Both the treasury→wallet funding leg and the wallet→merchant agent spend are
//! gated by the same policy contract under the canonical `"active"` policy id.
//!
//! Every denial is checked end to end: the deterministic error the caller
//! receives, and that no token balance, treasury ledger, or wallet ledger
//! moved.

use astroid_policy::{PolicyContract, PolicyContractClient};
use astroid_registry::{RegistryContract, RegistryContractClient};
use astroid_shared::errors::Error;
use astroid_shared::types::ModuleKind;
use astroid_treasury::{TreasuryContract, TreasuryContractClient};
use astroid_wallet::access::Role;
use astroid_wallet::{WalletContract, WalletContractClient};
use soroban_sdk::testutils::{Address as _, Events};
use soroban_sdk::{token, Address, BytesN, Env, IntoVal, String, Symbol, Val, Vec};

const ORG: &str = "acme";
/// Both the treasury and the wallet evaluate spends against this policy id.
const POLICY_ID: &str = "active";
/// Tokens the admin deposits into the treasury.
const TREASURY_FUNDS: i128 = 500_000;
/// Per-spend ceiling of the org policy.
const CAP: i128 = 10_000;

struct Harness<'a> {
    env: Env,
    registry: RegistryContractClient<'a>,
    treasury: TreasuryContractClient<'a>,
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

    fn balance_of(&self, asset: &Address, who: &Address) -> i128 {
        token::TokenClient::new(&self.env, asset).balance(who)
    }

    fn balance(&self, who: &Address) -> i128 {
        self.balance_of(&self.asset, who)
    }

    /// Snapshot of every balance the flow can move, for "nothing moved"
    /// assertions after a denial.
    fn ledger(&self) -> [i128; 7] {
        let holding = self.treasury.holding(&self.asset);
        [
            self.balance(&self.treasury.address),
            self.balance(&self.wallet.address),
            self.balance(&self.merchant),
            self.balance(&self.org_owner),
            self.wallet.balance(&self.wallet_id, &self.asset),
            holding.total_in,
            holding.total_out,
        ]
    }

    /// Fund the agent wallet from the treasury: a policy-gated treasury payout
    /// to the org owner, who deposits it into the wallet. Each token moves
    /// exactly once, so balances stay conserved.
    fn fund_wallet(&self, amount: i128) {
        self.treasury
            .withdraw(&self.admin, &self.asset, &self.org_owner, &amount);
        self.wallet
            .deposit(&self.wallet_id, &self.org_owner, &self.asset, &amount);
    }
}

/// Deploy registry, treasury, policy and wallet; register them under the org;
/// wire the treasury's and wallet's policy gate to the policy the registry
/// resolves; register the org policy; fund the treasury; create the agent's
/// wallet.
fn setup() -> Harness<'static> {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let org_owner = Address::generate(&env);
    let agent = Address::generate(&env);
    let merchant = Address::generate(&env);
    let org = String::from_str(&env, ORG);

    let registry_id = env.register_contract(None, RegistryContract);
    let registry = RegistryContractClient::new(&env, &registry_id);
    registry.initialize(&admin);
    registry.register_org(&admin, &org, &org_owner);

    let treasury_id = env.register_contract(None, TreasuryContract);
    let policy_id = env.register_contract(None, PolicyContract);
    let wallet_id_addr = env.register_contract(None, WalletContract);
    for (kind, addr) in [
        (ModuleKind::Treasury, &treasury_id),
        (ModuleKind::Policy, &policy_id),
        (ModuleKind::Wallet, &wallet_id_addr),
    ] {
        registry.register_module(&org_owner, &org, &kind, addr);
    }

    // From here on, every module is reached through the registry.
    let treasury = TreasuryContractClient::new(&env, &registry.lookup(&org, &ModuleKind::Treasury));
    let policy = PolicyContractClient::new(&env, &registry.lookup(&org, &ModuleKind::Policy));
    let wallet = WalletContractClient::new(&env, &registry.lookup(&org, &ModuleKind::Wallet));

    treasury.initialize(&org, &admin);
    policy.initialize();
    wallet.initialize(&admin);

    let resolved_policy = registry.lookup(&org, &ModuleKind::Policy);
    treasury.set_policy(&admin, &resolved_policy);
    wallet.set_policy(&admin, &resolved_policy);

    let token_admin = Address::generate(&env);
    let asset = env
        .register_stellar_asset_contract_v2(token_admin)
        .address();
    treasury.add_approved_asset(&admin, &asset);

    // Org policy: at most CAP per spend, only in `asset`, any recipient (the
    // same policy gates the treasury→wallet leg, so it cannot pin a single
    // recipient).
    policy.register_policy(
        &admin,
        &String::from_str(&env, POLICY_ID),
        &BytesN::from_array(&env, &[7u8; 32]),
        &CAP,
        &None,
        &Some(asset.clone()),
        &0u64,
    );

    token::StellarAssetClient::new(&env, &asset).mint(&admin, &TREASURY_FUNDS);
    treasury.deposit(&admin, &asset, &TREASURY_FUNDS);

    let wallet_id = wallet.create_wallet(&org_owner);
    wallet.grant_role(&org_owner, &wallet_id, &agent, &Role::Agent);

    Harness {
        env,
        registry,
        treasury,
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

/// Whether `contract` published the `("transfer", "executed")` event.
fn transfer_event_from(h: &Harness, contract: &Address) -> bool {
    let want: Vec<Val> = (
        Symbol::new(&h.env, "transfer"),
        Symbol::new(&h.env, "executed"),
    )
        .into_val(&h.env);
    h.env
        .events()
        .all()
        .iter()
        .any(|(id, topics, _)| &id == contract && topics == want)
}

#[test]
fn gates_are_wired_to_the_policy_the_registry_resolves() {
    let h = setup();
    let org = h.s(ORG);
    let resolved = h.registry.lookup(&org, &ModuleKind::Policy);
    assert_eq!(resolved, h.policy.address);
    assert_eq!(h.wallet.get_policy(), Some(resolved.clone()));
    assert_eq!(h.treasury.get().policy, Some(resolved));
}

#[test]
fn permitted_spend_succeeds_through_treasury_wallet_and_policy() {
    let h = setup();

    // Treasury → wallet: a policy-gated withdrawal within the cap.
    h.fund_wallet(8_000);
    let holding = h.treasury.holding(&h.asset);
    assert_eq!(holding.total_out, 8_000);
    assert_eq!(h.balance(&h.treasury.address), TREASURY_FUNDS - 8_000);
    assert_eq!(h.balance(&h.wallet.address), 8_000);
    assert_eq!(h.balance(&h.org_owner), 0);
    assert_eq!(h.wallet.balance(&h.wallet_id, &h.asset), 8_000);

    // Wallet → merchant: the agent's spend, policy-gated again.
    h.wallet
        .transfer(&h.agent, &h.wallet_id, &h.merchant, &h.asset, &6_000);
    assert!(transfer_event_from(&h, &h.wallet.address));

    assert_eq!(h.balance(&h.merchant), 6_000);
    assert_eq!(h.balance(&h.wallet.address), 2_000);
    assert_eq!(h.wallet.balance(&h.wallet_id, &h.asset), 2_000);
    // Value is conserved: every token is accounted for across the holders.
    assert_eq!(
        h.balance(&h.treasury.address)
            + h.balance(&h.org_owner)
            + h.balance(&h.wallet.address)
            + h.balance(&h.merchant),
        TREASURY_FUNDS
    );
}

#[test]
fn spend_exactly_at_the_cap_is_permitted() {
    let h = setup();
    h.fund_wallet(CAP);
    h.wallet
        .transfer(&h.agent, &h.wallet_id, &h.merchant, &h.asset, &CAP);
    assert_eq!(h.balance(&h.merchant), CAP);
    assert_eq!(h.wallet.balance(&h.wallet_id, &h.asset), 0);
}

#[test]
fn over_cap_agent_spend_is_denied_and_moves_nothing() {
    let h = setup();
    h.fund_wallet(CAP);
    h.fund_wallet(CAP);
    let before = h.ledger();

    // Funded, active, agent-authorized: only the policy stands in the way.
    let res = h
        .wallet
        .try_transfer(&h.agent, &h.wallet_id, &h.merchant, &h.asset, &(CAP + 1));
    assert_eq!(res, Err(Ok(Error::PolicyDenied)));
    assert_eq!(h.ledger(), before);
    assert_eq!(h.balance(&h.merchant), 0);

    // The denial left no residue: a compliant spend still goes through.
    h.wallet
        .transfer(&h.agent, &h.wallet_id, &h.merchant, &h.asset, &CAP);
    assert_eq!(h.balance(&h.merchant), CAP);
    assert_eq!(h.wallet.balance(&h.wallet_id, &h.asset), CAP);
}

#[test]
fn over_cap_treasury_funding_is_denied_before_reaching_the_wallet() {
    let h = setup();
    let before = h.ledger();
    let res = h
        .treasury
        .try_withdraw(&h.admin, &h.asset, &h.org_owner, &(CAP + 1));
    assert_eq!(res, Err(Ok(Error::PolicyDenied)));
    assert_eq!(h.ledger(), before);
}

#[test]
fn spend_in_an_asset_outside_policy_is_denied() {
    let h = setup();
    h.fund_wallet(5_000);

    // A second token reaches the wallet by a direct (ungated) deposit.
    let other_admin = Address::generate(&h.env);
    let other = h
        .env
        .register_stellar_asset_contract_v2(other_admin)
        .address();
    let holder = Address::generate(&h.env);
    token::StellarAssetClient::new(&h.env, &other).mint(&holder, &1_000);
    h.wallet.deposit(&h.wallet_id, &holder, &other, &1_000);

    let res = h
        .wallet
        .try_transfer(&h.agent, &h.wallet_id, &h.merchant, &other, &100);
    assert_eq!(res, Err(Ok(Error::PolicyDenied)));
    assert_eq!(h.wallet.balance(&h.wallet_id, &other), 1_000);
    assert_eq!(h.balance_of(&other, &h.merchant), 0);
    // The permitted asset is unaffected.
    assert_eq!(h.wallet.balance(&h.wallet_id, &h.asset), 5_000);
}

#[test]
fn blacklisted_merchant_is_denied_at_both_gates() {
    let h = setup();
    h.fund_wallet(5_000);
    h.policy
        .add_blacklist(&h.admin, &h.s(POLICY_ID), &h.merchant);
    let before = h.ledger();

    // The wallet collapses every policy refusal into PolicyDenied.
    assert_eq!(
        h.wallet
            .try_transfer(&h.agent, &h.wallet_id, &h.merchant, &h.asset, &100),
        Err(Ok(Error::PolicyDenied))
    );
    // The treasury propagates the policy's specific code unchanged.
    assert_eq!(
        h.treasury
            .try_withdraw(&h.admin, &h.asset, &h.merchant, &100),
        Err(Ok(Error::PolicyRecipientRestricted))
    );
    assert_eq!(h.ledger(), before);
}

#[test]
fn disabling_the_policy_halts_all_spending_until_reenabled() {
    let h = setup();
    h.fund_wallet(5_000);
    h.policy.set_enabled(&h.admin, &h.s(POLICY_ID), &false);
    let before = h.ledger();

    assert_eq!(
        h.wallet
            .try_transfer(&h.agent, &h.wallet_id, &h.merchant, &h.asset, &1),
        Err(Ok(Error::PolicyDenied))
    );
    assert_eq!(
        h.treasury
            .try_withdraw(&h.admin, &h.asset, &h.org_owner, &1),
        Err(Ok(Error::PolicyDenied))
    );
    assert_eq!(h.ledger(), before);

    h.policy.set_enabled(&h.admin, &h.s(POLICY_ID), &true);
    h.wallet
        .transfer(&h.agent, &h.wallet_id, &h.merchant, &h.asset, &1);
    assert_eq!(h.balance(&h.merchant), 1);
}

#[test]
fn tightening_the_policy_takes_effect_on_the_next_spend() {
    let h = setup();
    h.fund_wallet(CAP);
    h.wallet
        .transfer(&h.agent, &h.wallet_id, &h.merchant, &h.asset, &3_000);

    // The owner lowers the cap; the very next identical spend is refused.
    h.policy.rotate_policy(
        &h.admin,
        &h.s(POLICY_ID),
        &BytesN::from_array(&h.env, &[8u8; 32]),
        &2_000,
    );
    assert_eq!(
        h.wallet
            .try_transfer(&h.agent, &h.wallet_id, &h.merchant, &h.asset, &3_000),
        Err(Ok(Error::PolicyDenied))
    );
    h.wallet
        .transfer(&h.agent, &h.wallet_id, &h.merchant, &h.asset, &2_000);
    assert_eq!(h.balance(&h.merchant), 5_000);
    assert_eq!(h.wallet.balance(&h.wallet_id, &h.asset), CAP - 5_000);
}

#[test]
fn unauthorized_caller_is_rejected_before_policy_evaluation() {
    let h = setup();
    h.fund_wallet(5_000);
    let before = h.ledger();
    let stranger = Address::generate(&h.env);
    // Within policy, but the caller holds no wallet role.
    assert_eq!(
        h.wallet
            .try_transfer(&stranger, &h.wallet_id, &h.merchant, &h.asset, &100),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(h.ledger(), before);
}
