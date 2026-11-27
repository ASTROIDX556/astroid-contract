//! End-to-end agent workflow: registry → wallet → treasury → policy → budget
//! (Issue #462).
//!
//! Every one of the eight workspace contracts is deployed into a single mock
//! [`Env`] in the architectural dependency order, wired through the registry,
//! and then driven through an agent's spending cycle:
//!
//! ```text
//! registry ──lookup──▶ wallet
//!     └─────lookup──▶ treasury ──check_transfer──▶ policy
//!                          └────────consume──────▶ budget
//!                          └────────token────────▶ recipient
//! ```
//!
//! The suite asserts three things the unit tests cannot: that the registry
//! resolves every module the flow touches, that policy and budget gates apply
//! to the *same* spend in sequence, and that the standardized events are
//! emitted only for the spend that actually settles. A constrained spend is
//! rejected with the gate's own deterministic error and moves nothing.

use astroid_budget::{BudgetContract, BudgetContractClient, Period};
use astroid_escrow::EscrowContract;
use astroid_multisig::{MultiSigContract, MultiSigContractClient, SignerWeight};
use astroid_policy::{PolicyContract, PolicyContractClient};
use astroid_proposal::{ProposalContract, ProposalContractClient};
use astroid_registry::{RegistryContract, RegistryContractClient};
use astroid_shared::errors::Error;
use astroid_shared::types::ModuleKind;
use astroid_treasury::{TreasuryContract, TreasuryContractClient};
use astroid_wallet::access::Role;
use astroid_wallet::{WalletContract, WalletContractClient};
use soroban_sdk::testutils::{Address as _, Events};
use soroban_sdk::{symbol_short, token, vec, Address, BytesN, Env, IntoVal, String, Symbol, Val};

const ORG: &str = "acme";
/// The treasury hard-codes the policy id `"active"` on every spend gate.
const POLICY_ID: &str = "active";
const BUDGET_ID: &str = "agent-daily";
const TREASURY_FUNDS: i128 = 100_000;
const POLICY_CAP: i128 = 10_000;
const BUDGET_LIMIT: i128 = 6_000;

struct Harness<'a> {
    env: Env,
    registry: RegistryContractClient<'a>,
    wallet: WalletContractClient<'a>,
    treasury: TreasuryContractClient<'a>,
    policy: PolicyContractClient<'a>,
    budget: BudgetContractClient<'a>,
    admin: Address,
    org_owner: Address,
    agent: Address,
    recipient: Address,
    wallet_contract: Address,
    wallet_num: u64,
    asset: Address,
}

impl<'a> Harness<'a> {
    fn s(&self, v: &str) -> String {
        String::from_str(&self.env, v)
    }

    fn balance(&self, who: &Address) -> i128 {
        token::TokenClient::new(&self.env, &self.asset).balance(who)
    }

    /// Whether a `(topic, tag)` event pair has been emitted so far — the shape
    /// every contract in the workspace publishes its tuple-topic events in.
    fn has_event(&self, topic: Symbol, tag: Symbol) -> bool {
        let topic: Val = topic.into_val(&self.env);
        let tag: Val = tag.into_val(&self.env);
        self.env
            .events()
            .all()
            .iter()
            .any(|(_, topics, _)| topics.contains(topic.clone()) && topics.contains(tag.clone()))
    }

    /// Register the org-wide `"active"` policy: at most `POLICY_CAP` per
    /// spend in `asset`, optionally restricted to `recipient` alone.
    fn register_active_policy(&self, recipient_only: bool) {
        self.policy.register_policy(
            &self.admin,
            &self.s(POLICY_ID),
            &BytesN::from_array(&self.env, &[0u8; 32]),
            &POLICY_CAP,
            &if recipient_only {
                Some(self.recipient.clone())
            } else {
                None
            },
            &Some(self.asset.clone()),
            &0u64,
            &None,
        );
    }
}

/// Deploy all eight contracts in dependency order, register the org's modules,
/// and wire the agent: wallet role, policy and budget.
///
/// The policy and budget are registered but the treasury is not yet wired to
/// them, so each test opts in to the gate it exercises.
fn setup() -> Harness<'static> {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let org_owner = Address::generate(&env);
    let agent = Address::generate(&env);
    let recipient = Address::generate(&env);
    let org = String::from_str(&env, ORG);

    // 1. Registry — source of truth for module addresses.
    let registry_id = env.register_contract(None, RegistryContract);
    let registry = RegistryContractClient::new(&env, &registry_id);
    registry.initialize(&admin);
    registry.register_org(&admin, &org, &org_owner);

    // 2. Wallet.
    let wallet_id = env.register_contract(None, WalletContract);
    let wallet = WalletContractClient::new(&env, &wallet_id);
    wallet.initialize(&admin);

    // 3. Treasury.
    let treasury_id = env.register_contract(None, TreasuryContract);
    let treasury = TreasuryContractClient::new(&env, &treasury_id);
    treasury.initialize(&org, &admin);

    // 4. Multisig — governance for treasury actions.
    let multisig_id = env.register_contract(None, MultiSigContract);
    let multisig = MultiSigContractClient::new(&env, &multisig_id);
    multisig.initialize(
        &vec![
            &env,
            SignerWeight {
                address: admin.clone(),
                weight: 1,
            },
            SignerWeight {
                address: org_owner.clone(),
                weight: 1,
            },
        ],
        &2,
    );
    treasury.set_multisig(&admin, &multisig_id);

    // 5. Proposal — approval lifecycle backed by the multisig.
    let proposal_id = env.register_contract(None, ProposalContract);
    let proposal = ProposalContractClient::new(&env, &proposal_id);
    proposal.initialize(&0u64, &multisig_id);

    // 6. Budget.
    let budget_id = env.register_contract(None, BudgetContract);
    let budget = BudgetContractClient::new(&env, &budget_id);
    budget.initialize(&admin);

    // 7. Policy.
    let policy_id = env.register_contract(None, PolicyContract);
    let policy = PolicyContractClient::new(&env, &policy_id);
    policy.initialize();

    // 8. Escrow — deployed so the order is complete; not used by this flow.
    let escrow_id = env.register_contract(None, EscrowContract);

    // Register every module under the organization.
    for (kind, addr) in [
        (ModuleKind::Wallet, &wallet_id),
        (ModuleKind::Treasury, &treasury_id),
        (ModuleKind::Multisig, &multisig_id),
        (ModuleKind::Proposal, &proposal_id),
        (ModuleKind::Budget, &budget_id),
        (ModuleKind::Policy, &policy_id),
        (ModuleKind::Escrow, &escrow_id),
    ] {
        registry.register_module(&admin, &org, &kind, addr);
    }

    // A real SAC token, approved by the treasury and funded by the admin.
    let token_admin = Address::generate(&env);
    let asset = env
        .register_stellar_asset_contract_v2(token_admin)
        .address();
    treasury.add_approved_asset(&admin, &asset);
    token::StellarAssetClient::new(&env, &asset).mint(&admin, &TREASURY_FUNDS);
    treasury.deposit(&admin, &asset, &TREASURY_FUNDS);

    // The agent's wallet, delegated to the agent.
    let wallet_num = wallet.create_wallet(&org_owner);
    wallet.grant_role(&org_owner, &wallet_num, &agent, &Role::Agent);

    Harness {
        env,
        registry,
        wallet,
        treasury,
        policy,
        budget,
        admin,
        org_owner,
        agent,
        recipient,
        wallet_contract: wallet_id,
        wallet_num,
        asset,
    }
}

/// The full happy path: resolve every module through the registry, then run a
/// spend through policy → budget → treasury, fund the agent wallet, and assert
/// the value movement and the events it emitted.
#[test]
fn agent_workflow_runs_through_registry_policy_budget_and_treasury() {
    let h = setup();

    // --- 1. Registry lookup: every address comes from the registry ----------
    let wallet_addr = h.registry.lookup(&h.s(ORG), &ModuleKind::Wallet);
    let treasury_addr = h.registry.lookup(&h.s(ORG), &ModuleKind::Treasury);
    let policy_addr = h.registry.lookup(&h.s(ORG), &ModuleKind::Policy);
    let budget_addr = h.registry.lookup(&h.s(ORG), &ModuleKind::Budget);
    assert_eq!(wallet_addr, h.wallet_contract);
    assert_eq!(treasury_addr, h.treasury.address);
    assert_eq!(policy_addr, h.policy.address);
    assert_eq!(budget_addr, h.budget.address);
    assert!(h.registry.verify_owner(&h.s(ORG), &h.org_owner));

    // --- 2. Policy + budget configured, then wired into the treasury --------
    // The policy allows any recipient here so the treasury can fund the
    // agent's wallet address as well as pay the recipient.
    h.register_active_policy(false);
    h.budget.allocate(
        &h.admin,
        &h.s(BUDGET_ID),
        &BUDGET_LIMIT,
        &Period::None,
        &false,
        &0u64,
    );
    h.treasury.set_policy(&h.admin, &policy_addr);
    h.treasury.set_budget(&h.admin, &budget_addr);
    h.treasury
        .allocate_budget(&h.admin, &h.asset, &h.s(BUDGET_ID));

    // The policy registration and the budget allocation are observable.
    assert!(h.has_event(symbol_short!("policy"), symbol_short!("registd")));
    assert!(h.has_event(symbol_short!("budget"), symbol_short!("allocated")));

    // --- 3. Policy check + budget consumption + treasury transfer -----------
    let events_before = h.env.events().all().len();
    let recipient_before = h.balance(&h.recipient);
    h.treasury
        .withdraw(&h.admin, &h.asset, &wallet_addr, &5_000);

    // The policy allowed it, the budget was debited, and tokens moved.
    assert_eq!(h.balance(&wallet_addr), 5_000);
    assert_eq!(h.balance(&h.recipient), recipient_before);
    let holding = h.treasury.holding(&h.asset);
    assert_eq!(holding.total_in, TREASURY_FUNDS - 5_000);
    assert_eq!(holding.total_out, 5_000);
    let budget = h.budget.get(&h.s(BUDGET_ID));
    assert_eq!(budget.limit, BUDGET_LIMIT);
    assert_eq!(budget.spent, 5_000);

    // The settlement emitted its event, and nothing else vanished.
    assert!(h.has_event(symbol_short!("treasury"), symbol_short!("withdrawn")));
    assert!(h.env.events().all().len() > events_before);

    // --- 4. Wallet → recipient keeps the sequence going end to end ----------
    assert_eq!(
        h.wallet.get_role(&h.wallet_num, &h.agent),
        Some(Role::Agent)
    );
    h.wallet
        .deposit(&h.wallet_num, &wallet_addr, &h.asset, &5_000);
    h.wallet
        .transfer(&h.agent, &h.wallet_num, &h.recipient, &h.asset, &2_000);
    assert_eq!(h.balance(&h.recipient), recipient_before + 2_000);
}

/// Constrained spending attempts are refused at the right gate, with the
/// contract's own error, and move nothing — no token balance, no treasury
/// ledger entry, no settlement event, and no budget consumption.
#[test]
fn constrained_spending_is_refused_without_moving_value() {
    let h = setup();

    h.register_active_policy(true);
    h.budget.allocate(
        &h.admin,
        &h.s(BUDGET_ID),
        &BUDGET_LIMIT,
        &Period::None,
        &false,
        &0u64,
    );
    h.treasury.set_policy(&h.admin, &h.policy.address);
    h.treasury.set_budget(&h.admin, &h.budget.address);
    h.treasury
        .allocate_budget(&h.admin, &h.asset, &h.s(BUDGET_ID));

    let before = [
        h.balance(&h.treasury.address),
        h.balance(&h.recipient),
        h.treasury.holding(&h.asset).total_in,
        h.treasury.holding(&h.asset).total_out,
        h.budget.get(&h.s(BUDGET_ID)).spent,
    ];

    // 1. Over the policy cap: the policy gate refuses before the budget is
    //    consulted.
    let res = h
        .treasury
        .try_withdraw(&h.admin, &h.asset, &h.recipient, &(POLICY_CAP + 1));
    assert_eq!(res, Err(Ok(Error::PolicyConstraintUnmet)));

    // 2. A recipient the policy does not allow is refused as well.
    let stranger = Address::generate(&h.env);
    let res = h
        .treasury
        .try_withdraw(&h.admin, &h.asset, &stranger, &1_000);
    assert_eq!(res, Err(Ok(Error::PolicyDenied)));

    // 3. Inside the policy but over the budget: the budget gate refuses.
    let res = h
        .treasury
        .try_withdraw(&h.admin, &h.asset, &h.recipient, &(BUDGET_LIMIT + 1));
    assert_eq!(res, Err(Ok(Error::BUDGET_LIMIT_EXCEEDED)));

    // 4. An unauthorized caller is stopped before any gate or transfer.
    let res = h
        .treasury
        .try_withdraw(&h.agent, &h.asset, &h.recipient, &1_000);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));

    // Nothing moved, and no settlement event was published.
    assert_eq!(
        [
            h.balance(&h.treasury.address),
            h.balance(&h.recipient),
            h.treasury.holding(&h.asset).total_in,
            h.treasury.holding(&h.asset).total_out,
            h.budget.get(&h.s(BUDGET_ID)).spent,
        ],
        before
    );
    assert!(!h.has_event(symbol_short!("treasury"), symbol_short!("withdrawn")));

    // A compliant spend still succeeds afterwards, proving the denials left
    // the gates usable rather than wedged.
    h.treasury
        .withdraw(&h.admin, &h.asset, &h.recipient, &1_000);
    assert_eq!(h.balance(&h.recipient), 1_000);
    assert_eq!(h.budget.get(&h.s(BUDGET_ID)).spent, 1_000);
}
