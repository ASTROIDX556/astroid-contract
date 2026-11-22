//! Standardized wallet policy-failure telemetry (Issue #504).
//!
//! When an agent attempts a movement the org policy refuses, the wallet
//! publishes one [`PolicyViolationEvent`] under the Soroban topic
//! `("wallet", "pol_viol", agent)`. These tests deploy the real registry,
//! policy and wallet contracts and assert both halves of that contract — the
//! exact topic vector and the decoded payload (agent, wallet id, policy id,
//! reason code) — for:
//!
//! * the non-reverting `evaluate_policy` pre-flight, whose event is durable;
//! * the reverting `transfer` path, which still reports `PolicyDenied`;
//! * a validated batch action evaluated under its own `policy_id`.

use astroid_policy::{PolicyContract, PolicyContractClient};
use astroid_registry::{RegistryContract, RegistryContractClient};
use astroid_shared::errors::Error;
use astroid_shared::events::PolicyViolationEvent;
use astroid_shared::types::ModuleKind;
use astroid_wallet::access::Role;
use astroid_wallet::{BatchAction, ContractCall, WalletContract, WalletContractClient};
use soroban_sdk::testutils::{Address as _, Events};
use soroban_sdk::{
    token, vec, Address, BytesN, Env, IntoVal, String, Symbol, TryFromVal, Val, Vec,
};

const ORG: &str = "acme";
const POLICY_ID: &str = "active";
const CAP: i128 = 10_000;

struct Harness<'a> {
    env: Env,
    policy: PolicyContractClient<'a>,
    wallet: WalletContractClient<'a>,
    admin: Address,
    agent: Address,
    merchant: Address,
    asset: Address,
    wallet_id: u64,
}

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

    let policy_addr = env.register_contract(None, PolicyContract);
    let wallet_addr = env.register_contract(None, WalletContract);
    registry.register_module(&org_owner, &org, &ModuleKind::Policy, &policy_addr);
    registry.register_module(&org_owner, &org, &ModuleKind::Wallet, &wallet_addr);

    let policy = PolicyContractClient::new(&env, &registry.lookup(&org, &ModuleKind::Policy));
    let wallet = WalletContractClient::new(&env, &registry.lookup(&org, &ModuleKind::Wallet));
    policy.initialize();
    wallet.initialize(&admin);
    wallet.set_policy(&admin, &policy.address);

    let token_admin = Address::generate(&env);
    let asset = env
        .register_stellar_asset_contract_v2(token_admin)
        .address();
    policy.register_policy(
        &admin,
        &String::from_str(&env, POLICY_ID),
        &BytesN::from_array(&env, &[7u8; 32]),
        &CAP,
        &None,
        &Some(asset.clone()),
        &0u64,
        &None,
    );

    let wallet_id = wallet.create_wallet(&org_owner);
    wallet.grant_role(&org_owner, &wallet_id, &agent, &Role::Agent);
    token::StellarAssetClient::new(&env, &asset).mint(&org_owner, &(CAP * 4));
    wallet.deposit(&wallet_id, &org_owner, &asset, &(CAP * 4));

    Harness {
        env,
        policy,
        wallet,
        admin,
        agent,
        merchant,
        asset,
        wallet_id,
    }
}

/// The exact topic vector the wallet publishes a violation under.
fn violation_topics(env: &Env, agent: &Address) -> Vec<Val> {
    (
        Symbol::new(env, "wallet"),
        Symbol::new(env, "pol_viol"),
        agent.clone(),
    )
        .into_val(env)
}

/// Every `PolicyViolationEvent` the wallet contract published for `agent`.
fn violations(h: &Harness) -> std::vec::Vec<PolicyViolationEvent> {
    let want = violation_topics(&h.env, &h.agent);
    h.env
        .events()
        .all()
        .iter()
        .filter(|(id, topics, _)| *id == h.wallet.address && *topics == want)
        .map(|(_, _, data)| PolicyViolationEvent::try_from_val(&h.env, &data).unwrap())
        .collect()
}

/// What the policy contract itself reports for this spend, so the test pins
/// the wallet's `reason`/`code` to the real refusal rather than a constant.
fn policy_refusal(h: &Harness, asset: &Address, amount: i128) -> Error {
    match h.policy.try_check_transfer(
        &String::from_str(&h.env, POLICY_ID),
        asset,
        &h.merchant,
        &amount,
    ) {
        Err(Ok(e)) => e,
        other => panic!("expected a policy refusal, got {:?}", other),
    }
}

fn expected(h: &Harness, policy_id: &str, err: Error) -> PolicyViolationEvent {
    PolicyViolationEvent {
        agent: h.agent.clone(),
        wallet_id: h.wallet_id,
        policy_id: String::from_str(&h.env, policy_id),
        reason: Symbol::new(&h.env, err.wire_name()),
        code: err.code(),
        timestamp: h.env.ledger().timestamp(),
    }
}

#[test]
fn preflight_rejection_emits_the_standard_topic_and_payload() {
    let h = setup();
    let refusal = policy_refusal(&h, &h.asset, CAP + 1);

    let allowed =
        h.wallet
            .evaluate_policy(&h.agent, &h.wallet_id, &h.merchant, &h.asset, &(CAP + 1));
    assert!(!allowed);

    let got = violations(&h);
    assert_eq!(got.len(), 1, "exactly one violation event per refusal");
    assert_eq!(got[0], expected(&h, POLICY_ID, refusal));
    // Nothing moved: the pre-flight never touches custody.
    assert_eq!(h.wallet.balance(&h.wallet_id, &h.asset), CAP * 4);
}

#[test]
fn reason_code_names_the_rule_that_refused() {
    let h = setup();
    // A blacklisted recipient is refused for a different reason than an
    // over-cap amount; the event must carry that distinction.
    let over_cap = policy_refusal(&h, &h.asset, CAP + 1);
    h.policy
        .add_blacklist(&h.admin, &String::from_str(&h.env, POLICY_ID), &h.merchant);
    let refusal = policy_refusal(&h, &h.asset, 1);
    assert_eq!(refusal, Error::PolicyRecipientRestricted);
    assert_ne!(refusal, over_cap);

    assert!(!h
        .wallet
        .evaluate_policy(&h.agent, &h.wallet_id, &h.merchant, &h.asset, &1));
    let got = violations(&h);
    assert_eq!(got.len(), 1);
    assert_eq!(got[0].reason, Symbol::new(&h.env, refusal.wire_name()));
    assert_eq!(got[0].code, refusal.code());
}

#[test]
fn permitted_preflight_emits_no_violation() {
    let h = setup();
    assert!(h
        .wallet
        .evaluate_policy(&h.agent, &h.wallet_id, &h.merchant, &h.asset, &CAP));
    assert!(violations(&h).is_empty());
}

#[test]
fn preflight_requires_an_agent_role() {
    let h = setup();
    let stranger = Address::generate(&h.env);
    let res =
        h.wallet
            .try_evaluate_policy(&stranger, &h.wallet_id, &h.merchant, &h.asset, &(CAP + 1));
    assert!(res.is_err());
    assert!(violations(&h).is_empty());
}

#[test]
fn bypassed_wallet_preflight_skips_the_gate() {
    let h = setup();
    h.wallet.set_policy_bypass(&h.admin, &h.wallet_id, &true);
    assert!(h
        .wallet
        .evaluate_policy(&h.agent, &h.wallet_id, &h.merchant, &h.asset, &(CAP + 1)));
    assert!(violations(&h).is_empty());
}

#[test]
fn rejected_transfer_reports_policy_denied_and_moves_nothing() {
    let h = setup();
    let res = h
        .wallet
        .try_transfer(&h.agent, &h.wallet_id, &h.merchant, &h.asset, &(CAP + 1));
    assert_eq!(res, Err(Ok(Error::PolicyDenied)));
    assert_eq!(h.wallet.balance(&h.wallet_id, &h.asset), CAP * 4);
    assert_eq!(
        token::TokenClient::new(&h.env, &h.asset).balance(&h.merchant),
        0
    );
}

#[test]
fn unauthorized_signer_cannot_bypass_policy_constraints() {
    let h = setup();
    let rogue = Address::generate(&h.env);
    let owner = h.wallet.get_wallet(&h.wallet_id).owner;
    h.wallet
        .grant_role(&owner, &h.wallet_id, &rogue, &Role::Agent);
    h.policy
        .add_blacklist(&h.admin, &String::from_str(&h.env, POLICY_ID), &h.merchant);

    let before = h.wallet.balance(&h.wallet_id, &h.asset);
    let res = h
        .wallet
        .try_transfer(&rogue, &h.wallet_id, &h.merchant, &h.asset, &1);
    assert_eq!(res, Err(Ok(Error::PolicyDenied)));
    assert_eq!(h.wallet.balance(&h.wallet_id, &h.asset), before);
    assert_eq!(
        token::TokenClient::new(&h.env, &h.asset).balance(&h.merchant),
        0
    );
}

#[test]
fn rejected_batch_action_reports_its_own_policy_id() {
    let h = setup();
    let action = BatchAction {
        policy_id: String::from_str(&h.env, POLICY_ID),
        budget_id: String::from_str(&h.env, ""),
        asset: h.asset.clone(),
        recipient: h.merchant.clone(),
        amount: CAP + 1,
        // Never reached: the policy gate refuses the action in phase 1.
        call: ContractCall {
            contract_addr: h.asset.clone(),
            fn_name: Symbol::new(&h.env, "decimals"),
            args: Vec::new(&h.env),
        },
    };
    let res = h
        .wallet
        .try_batch_execute_validated(&h.agent, &h.wallet_id, &vec![&h.env, action]);
    assert_eq!(res, Err(Ok(Error::PolicyDenied)));
}
