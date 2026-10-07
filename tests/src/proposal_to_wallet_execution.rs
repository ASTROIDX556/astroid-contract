//! Governed proposal → wallet execution: the full cross-contract lifecycle.
//!
//! Every other integration test in this crate starts *after* governance: the
//! registry is already configured, the modules are already wired, and the money
//! moves as a direct contract call. This module covers the stages those tests
//! take for granted, and proves the workspace still composes when a spend has
//! to earn its way out first:
//!
//! ```text
//! registry configuration
//!   → wallet creation + role delegation
//!     → proposal submission (deposit escrowed)
//!       → multisig weighted quorum over the action
//!         → proposal approval quorum + mandatory timelock
//!           → policy/budget validated wallet execution
//!             → proposal recorded Executed, then Closed
//! ```
//!
//! All eight workspace contracts are deployed into a single mock Soroban
//! [`Env`] and wired the way a real deployment wires them. Two details make the
//! composition real rather than incidental:
//!
//! * The wallet is pointed at the **registry** (`set_registry` + `set_org`), so
//!   every spend resolves its Policy and Budget addresses through
//!   `get_modules_batch` instead of instance-wired copies. The module
//!   registered in the registry is therefore the same module the wallet
//!   consults, and re-registering one is all it takes to change the gate.
//! * The **multisig owns the policy** — `register_policy` records the multisig
//!   contract address as the owner — so the rule engine that can abort an
//!   execution is itself under governance.
//!
//! The generated clients unwrap `Result`s and panic on error, so every aborted
//! path is driven through the `try_*` variants, asserted on the deterministic
//! [`Error`] code, and cross-checked against real token balances to prove
//! nothing moved.

use astroid_budget::{BudgetContract, BudgetContractClient, Period};
use astroid_escrow::{EscrowContract, EscrowContractClient};
use astroid_multisig::{BatchCall, MultiSigContract, MultiSigContractClient, SignerWeight};
use astroid_policy::{PolicyContract, PolicyContractClient};
use astroid_proposal::{ProposalContract, ProposalContractClient, ProposalState, VoteBars};
use astroid_registry::{RegistryContract, RegistryContractClient};
use astroid_shared::errors::Error;
use astroid_shared::types::{AssetAmount, ModuleKind, ResourceState};
use astroid_treasury::{TreasuryContract, TreasuryContractClient};
use astroid_wallet::access::Role;
use astroid_wallet::{WalletContract, WalletContractClient};
use soroban_sdk::{
    symbol_short,
    testutils::{Address as _, Ledger},
    token, vec, Address, Bytes, BytesN, Env, IntoVal, String, Val, Vec,
};

const START: u64 = 1_000;
const ORG: &str = "helios";
/// The treasury and the wallet both hard-code the policy id `"active"` on every
/// spend gate, so that is the envelope the org-wide rules live under.
const POLICY_ID: &str = "active";
const BUDGET_ID: &str = "ops-envelope";
/// Opaque off-chain reference the proposal record links to.
const WALLET_REF: &str = "wallet-1";

/// Per-spend ceiling the org's policy allows, in the asset's smallest unit.
const POLICY_MAX: i128 = 4_000;
/// Headroom of the budget envelope the wallet consumes from. Deliberately
/// larger than a single [`SPEND`], so "the policy forbade it" and "the envelope
/// was empty" are two distinguishable failure modes rather than one.
const BUDGET_LIMIT: i128 = 5_000;
const TREASURY_FUNDING: i128 = 500_000;
const WALLET_FUNDING: i128 = 100_000;
/// The authorized payout at the centre of the flow.
const SPEND: i128 = 4_000;
/// Stake the proposer locks in escrow while the proposal is live; refunded on
/// execution.
const DEPOSIT: i128 = 1_000;
/// Mandatory delay between a proposal reaching `Approved` and being allowed to
/// execute, in seconds.
const TIMELOCK: u64 = 3_600;

/// All eight workspace contracts deployed into one `Env`, configured and wired
/// exactly as a real deployment would have them.
struct Harness<'a> {
    env: Env,
    registry: RegistryContractClient<'a>,
    treasury: TreasuryContractClient<'a>,
    wallet: WalletContractClient<'a>,
    multisig: MultiSigContractClient<'a>,
    proposal: ProposalContractClient<'a>,
    policy: PolicyContractClient<'a>,
    budget: BudgetContractClient<'a>,
    escrow: EscrowContractClient<'a>,
    /// Protocol admin: initializes the registry and owns the org's contracts.
    admin: Address,
    /// Org owner, wallet owner, and the proposal's proposer/executor.
    org_owner: Address,
    /// Autonomous executor holding [`Role::Agent`] on the wallet.
    agent: Address,
    /// Multisig signers. Deliberately unequal weights, so quorum cannot be
    /// reached by a single key: `signer_a` alone holds 1 of the 2 required.
    signer_a: Address,
    signer_b: Address,
    /// The payee the policy approves.
    vendor: Address,
    /// A payee the policy does not approve.
    stranger: Address,
    asset: Address,
    /// The org's execution wallet, created and funded by [`setup`].
    wallet_id: u64,
}

fn setup() -> Harness<'static> {
    let env = Env::default();
    // This module exists to prove the contracts compose *across* contract
    // boundaries, so authorizations raised inside a sub-invocation (the wallet
    // requiring the agent's signature while the multisig drives it) have to be
    // honoured as well as those in the root invocation. Role, ownership and
    // permission checks are unaffected — only the Soroban auth tree is relaxed.
    env.mock_all_auths_allowing_non_root_auth();
    env.ledger().with_mut(|l| l.timestamp = START);

    let admin = Address::generate(&env);
    let org_owner = Address::generate(&env);
    let agent = Address::generate(&env);
    let signer_a = Address::generate(&env);
    let signer_b = Address::generate(&env);
    let vendor = Address::generate(&env);
    let stranger = Address::generate(&env);
    let org = String::from_str(&env, ORG);

    // --- Deploy every workspace contract -----------------------------------
    let registry_addr = env.register_contract(None, RegistryContract);
    let registry = RegistryContractClient::new(&env, &registry_addr);
    let treasury_addr = env.register_contract(None, TreasuryContract);
    let treasury = TreasuryContractClient::new(&env, &treasury_addr);
    let wallet_addr = env.register_contract(None, WalletContract);
    let wallet = WalletContractClient::new(&env, &wallet_addr);
    let multisig_addr = env.register_contract(None, MultiSigContract);
    let multisig = MultiSigContractClient::new(&env, &multisig_addr);
    let proposal_addr = env.register_contract(None, ProposalContract);
    let proposal = ProposalContractClient::new(&env, &proposal_addr);
    let policy_addr = env.register_contract(None, PolicyContract);
    let policy = PolicyContractClient::new(&env, &policy_addr);
    let budget_addr = env.register_contract(None, BudgetContract);
    let budget = BudgetContractClient::new(&env, &budget_addr);
    let escrow_addr = env.register_contract(None, EscrowContract);
    let escrow = EscrowContractClient::new(&env, &escrow_addr);

    // --- A real SAC token the whole flow moves around ----------------------
    let token_admin = Address::generate(&env);
    let asset = env
        .register_stellar_asset_contract_v2(token_admin)
        .address();

    // --- Registry configuration --------------------------------------------
    registry.initialize(&admin);
    registry.register_org(&admin, &org, &org_owner);
    for (kind, address) in [
        (ModuleKind::Treasury, treasury_addr.clone()),
        (ModuleKind::Wallet, wallet_addr.clone()),
        (ModuleKind::Multisig, multisig_addr.clone()),
        (ModuleKind::Proposal, proposal_addr.clone()),
        (ModuleKind::Policy, policy_addr.clone()),
        (ModuleKind::Budget, budget_addr.clone()),
        (ModuleKind::Escrow, escrow_addr.clone()),
    ] {
        registry.register_module(&admin, &org, &kind, &address);
    }

    // --- Governance: multisig and proposal ---------------------------------
    // Unequal weights, so reaching the threshold genuinely needs a second
    // signature rather than one key.
    multisig.initialize(
        &vec![
            &env,
            SignerWeight {
                address: signer_a.clone(),
                weight: 1,
            },
            SignerWeight {
                address: signer_b.clone(),
                weight: 2,
            },
        ],
        &2,
    );
    // The mandatory delay between approval and execution, in seconds.
    proposal.initialize(&TIMELOCK, &multisig_addr);

    // --- Policy -------------------------------------------------------------
    // The multisig contract itself owns the policy, so the rule engine that can
    // abort an execution is under the same governance as the proposal.
    policy.initialize();
    policy.register_policy(
        &multisig_addr,
        &String::from_str(&env, POLICY_ID),
        &BytesN::from_array(&env, &[0u8; 32]),
        &POLICY_MAX,
        &Some(vendor.clone()),
        &Some(asset.clone()),
        &0u64,
        &None,
    );

    // --- Budget -------------------------------------------------------------
    // The envelope is owned by the agent: the wallet forwards the *spending
    // caller* to `BudgetClient::consume`, so the consumer must be the owner.
    budget.initialize(&admin);
    budget.allocate(
        &agent,
        &String::from_str(&env, BUDGET_ID),
        &BUDGET_LIMIT,
        &Period::None,
        &false,
        &0u64,
    );

    // --- Treasury funding ---------------------------------------------------
    treasury.initialize(&org, &admin);
    treasury.set_multisig(&admin, &multisig_addr);
    treasury.add_approved_asset(&admin, &asset);
    token::StellarAssetClient::new(&env, &asset).mint(&admin, &1_000_000);
    treasury.deposit(&admin, &asset, &TREASURY_FUNDING);
    // The proposer escrows its stake at submission time.
    token::StellarAssetClient::new(&env, &asset).mint(&org_owner, &DEPOSIT);

    // --- Wallet creation, role delegation and funding ------------------------
    wallet.initialize(&admin);
    // Resolve Policy and Budget through the registry on every spend, so an
    // upgrade registered there takes effect without re-wiring the wallet.
    wallet.set_registry(&admin, &registry_addr);
    wallet.set_org(&admin, &org);
    wallet.set_default_budget_id(&admin, &String::from_str(&env, BUDGET_ID));
    let wallet_id = wallet.create_wallet(&org_owner);
    wallet.grant_role(&org_owner, &wallet_id, &agent, &Role::Agent);
    // Fund the wallet from the treasury as a single net movement: the
    // withdrawal lands on the org owner's account, which then funds the
    // wallet's custody, so the real tokens the wallet custodies end up equal to
    // the balances it has credited. The treasury's own policy/budget links are
    // deliberately left unwired, which keeps this leg ungated — the wallet's
    // gates are the only ones under test.
    treasury.withdraw(&admin, &asset, &org_owner, &WALLET_FUNDING);
    wallet.deposit(&wallet_id, &org_owner, &asset, &WALLET_FUNDING);

    Harness {
        env,
        registry,
        treasury,
        wallet,
        multisig,
        proposal,
        policy,
        budget,
        escrow,
        admin,
        org_owner,
        agent,
        signer_a,
        signer_b,
        vendor,
        stranger,
        asset,
        wallet_id,
    }
}

fn string(h: &Harness, s: &str) -> String {
    String::from_str(&h.env, s)
}

fn token_balance(h: &Harness, who: &Address) -> i128 {
    token::TokenClient::new(&h.env, &h.asset).balance(who)
}

/// The real tokens the wallet contract custodies for the org, which must always
/// match the sum of its internal per-wallet bookkeeping.
fn wallet_custody(h: &Harness) -> i128 {
    token::TokenClient::new(&h.env, &h.asset).balance(&h.wallet.address)
}

fn budget_id(h: &Harness) -> String {
    string(h, BUDGET_ID)
}

/// Submit the governed payout: a proposal by the org owner, escrowing
/// [`DEPOSIT`], that the two multisig signers must approve.
///
/// The approver allow-list is the signer set, and the threshold is the full
/// list — so a single key can never carry it, and the proposal also has to
/// clear the participation quorum and strict majority `execute` re-derives.
fn submit_proposal(h: &Harness) -> u64 {
    let approvers = vec![&h.env, h.signer_a.clone(), h.signer_b.clone()];
    let deposit: Vec<AssetAmount> = vec![
        &h.env,
        AssetAmount {
            asset: h.asset.clone(),
            amount: DEPOSIT,
        },
    ];
    let id = h.proposal.create(
        &h.org_owner,
        &string(h, ORG),
        &string(h, WALLET_REF),
        &string(h, POLICY_ID),
        &approvers,
        &vec![&h.env],
        &2,
        &deposit,
        &0u64,
        &0u64,
    );
    // The stake left the proposer and is now escrowed by the contract.
    assert_eq!(token_balance(h, &h.org_owner), 0);
    assert_eq!(token_balance(h, &h.proposal.address), DEPOSIT);
    id
}

/// Run the governance half of the lifecycle: the multisig's own weighted quorum
/// over the payout, then the proposal's approval quorum. The caller then has to
/// wait out the mandatory timelock with [`wait_out_timelock`].
fn authorize_proposal(h: &Harness, id: u64) {
    // --- Multisig weighted quorum over the action ---------------------------
    // The payload is the proposal id: the multisig's record stays opaque to the
    // contract but names exactly what it authorized.
    let ms_id = h.multisig.propose(
        &h.signer_a,
        &symbol_short!("payout"),
        &Bytes::from_slice(&h.env, &id.to_be_bytes()),
        &0u64,
    );
    // The proposer's own weight is credited automatically — 1, short of the 2
    // required, so quorum is genuinely still open.
    assert_eq!(h.multisig.get_proposal(&ms_id).approval_weight, 1);
    assert!(!h.multisig.get_proposal(&ms_id).executed);
    assert_eq!(
        h.multisig.try_execute(&h.signer_a, &ms_id),
        Err(Ok(Error::InsufficientWeight))
    );

    // The second signer's weight carries it over the threshold.
    assert_eq!(h.multisig.approve(&h.signer_b, &ms_id), 3);
    h.multisig.execute(&h.signer_b, &ms_id);
    assert!(h.multisig.get_proposal(&ms_id).executed);

    // --- Proposal approval quorum -------------------------------------------
    assert_eq!(h.proposal.approve(&h.signer_a, &id), 1);
    assert_eq!(h.proposal.state(&id), ProposalState::Pending);
    assert_eq!(h.proposal.approve(&h.signer_b, &id), 2);
    assert_eq!(h.proposal.state(&id), ProposalState::Approved);
    assert_eq!(h.proposal.get(&id).approved_at, START);
}

/// Advance the ledger past the proposal's mandatory approval→execution delay.
fn wait_out_timelock(h: &Harness) {
    h.env.ledger().with_mut(|l| l.timestamp = START + TIMELOCK);
}

/// The complete governed payout, from an unconfigured ledger to a settled
/// proposal. Asserts the cross-contract wiring and the value movement at every
/// stage.
#[test]
fn proposal_to_wallet_execution_end_to_end() {
    let h = setup();

    // --- Registry configuration resolved -----------------------------------
    for (kind, address) in [
        (ModuleKind::Treasury, h.treasury.address.clone()),
        (ModuleKind::Wallet, h.wallet.address.clone()),
        (ModuleKind::Multisig, h.multisig.address.clone()),
        (ModuleKind::Proposal, h.proposal.address.clone()),
        (ModuleKind::Policy, h.policy.address.clone()),
        (ModuleKind::Budget, h.budget.address.clone()),
        (ModuleKind::Escrow, h.escrow.address.clone()),
    ] {
        assert_eq!(h.registry.lookup(&string(&h, ORG), &kind), address);
    }
    assert!(h.registry.verify_owner(&string(&h, ORG), &h.org_owner));
    // The wallet resolves its gates through the registry, not through copies.
    assert_eq!(h.wallet.get_registry(), Some(h.registry.address.clone()));
    assert_eq!(h.wallet.get_org(), Some(string(&h, ORG)));
    assert_eq!(h.wallet.get_default_budget_id(), Some(budget_id(&h)));

    // --- Wallet creation and funding ---------------------------------------
    assert_eq!(h.wallet.get_wallet(&h.wallet_id).owner, h.org_owner);
    assert_eq!(
        h.wallet.get_wallet(&h.wallet_id).state,
        ResourceState::Active
    );
    assert_eq!(h.wallet.get_role(&h.wallet_id, &h.agent), Some(Role::Agent));
    assert_eq!(h.wallet.balance(&h.wallet_id, &h.asset), WALLET_FUNDING);
    assert_eq!(wallet_custody(&h), WALLET_FUNDING);

    // --- Proposal submission ------------------------------------------------
    let id = submit_proposal(&h);
    assert_eq!(h.proposal.state(&id), ProposalState::Pending);
    assert!(!h.proposal.is_executed(&id));
    assert!(h.proposal.dependencies_met(&id));
    // A pending proposal is never executable, whatever the tally.
    assert!(!h.proposal.can_execute(&id));
    // Two approvers: threshold 2, quorum ceil(2 * 50%) = 1, majority 2/2 + 1 = 2.
    assert_eq!(
        h.proposal.vote_bars(&id),
        VoteBars {
            threshold: 2,
            quorum: 1,
            majority: 2,
        }
    );

    // A stranger cannot lend an approval, and the tally stays where it was.
    let res = h.proposal.try_approve(&h.stranger, &id);
    assert_eq!(res, Err(Ok(Error::NotAnApprover)));
    assert_eq!(h.proposal.get(&id).approvals, 0);

    // --- Governance ---------------------------------------------------------
    authorize_proposal(&h, id);

    // The mandatory delay has not elapsed: the view and the entrypoint agree
    // that the payout may not fire yet.
    assert!(!h.proposal.can_execute(&id));
    let res = h.proposal.try_execute(&h.org_owner, &id);
    assert_eq!(res, Err(Ok(Error::TimelockNotExpired)));
    assert_eq!(h.proposal.state(&id), ProposalState::Approved);

    wait_out_timelock(&h);
    assert!(h.proposal.can_execute(&id));

    // --- Policy/budget validated execution ----------------------------------
    // The agent pays the vendor. The wallet consults the policy the *registry*
    // resolves, debits the envelope the *registry* resolves, debits its own
    // bookkeeping, and only then moves the real tokens.
    h.wallet
        .transfer(&h.agent, &h.wallet_id, &h.vendor, &h.asset, &SPEND);

    assert_eq!(token_balance(&h, &h.vendor), SPEND);
    assert_eq!(
        h.wallet.balance(&h.wallet_id, &h.asset),
        WALLET_FUNDING - SPEND
    );
    assert_eq!(wallet_custody(&h), WALLET_FUNDING - SPEND);
    // The envelope recorded exactly the authorized payout, once.
    let envelope = h.budget.get(&budget_id(&h));
    assert_eq!(envelope.limit, BUDGET_LIMIT);
    assert_eq!(envelope.spent, SPEND);
    assert_eq!(h.budget.remaining(&budget_id(&h)), BUDGET_LIMIT - SPEND);
    // The treasury's own accounting is untouched by the wallet's spend.
    assert_eq!(h.treasury.holding(&h.asset).total_out, WALLET_FUNDING);

    // --- The proposal records completion, then closes ------------------------
    h.proposal.execute(&h.org_owner, &id);
    assert_eq!(h.proposal.state(&id), ProposalState::Executed);
    assert!(h.proposal.is_executed(&id));
    // The escrowed stake is returned to the proposer.
    assert_eq!(token_balance(&h, &h.org_owner), DEPOSIT);
    assert_eq!(token_balance(&h, &h.proposal.address), 0);

    h.proposal.close(&h.org_owner, &id);
    assert_eq!(h.proposal.state(&id), ProposalState::Closed);
    assert!(h.proposal.is_executed(&id));
}

/// A policy violation aborts the execution path: the spend is refused with the
/// deterministic code, and neither the wallet's bookkeeping, the real tokens,
/// nor the budget envelope move.
#[test]
fn policy_violation_aborts_execution_path() {
    let h = setup();
    let id = submit_proposal(&h);
    authorize_proposal(&h, id);
    wait_out_timelock(&h);
    assert!(h.proposal.can_execute(&id));

    let wallet_id = h.wallet_id;
    let before = h.wallet.balance(&wallet_id, &h.asset);
    assert_eq!(before, WALLET_FUNDING);

    // 1. Above the policy's per-spend cap.
    let res = h
        .wallet
        .try_transfer(&h.agent, &wallet_id, &h.vendor, &h.asset, &(POLICY_MAX + 1));
    assert_eq!(res, Err(Ok(Error::PolicyDenied)));
    assert_eq!(h.wallet.balance(&wallet_id, &h.asset), before);
    assert_eq!(wallet_custody(&h), before);
    assert_eq!(token_balance(&h, &h.vendor), 0);
    // A refused spend consumes no budget allowance.
    assert_eq!(h.budget.get(&budget_id(&h)).spent, 0);

    // 2. To a payee the policy does not approve.
    let res = h
        .wallet
        .try_transfer(&h.agent, &wallet_id, &h.stranger, &h.asset, &1_000);
    assert_eq!(res, Err(Ok(Error::PolicyDenied)));
    assert_eq!(token_balance(&h, &h.stranger), 0);
    assert_eq!(h.wallet.balance(&wallet_id, &h.asset), before);
    assert_eq!(h.budget.get(&budget_id(&h)).spent, 0);

    // 3. A policy-compliant payout still runs — the gate above, not the setup,
    //    is what refused.
    h.wallet
        .transfer(&h.agent, &wallet_id, &h.vendor, &h.asset, &SPEND);
    assert_eq!(token_balance(&h, &h.vendor), SPEND);
    assert_eq!(h.wallet.balance(&wallet_id, &h.asset), before - SPEND);
    assert_eq!(h.budget.get(&budget_id(&h)).spent, SPEND);

    // 4. The budget is a separate, independently enforced ceiling: the last
    //    compliant-but-unfunded leg is refused with its own code.
    let res = h.wallet.try_transfer(
        &h.agent,
        &wallet_id,
        &h.vendor,
        &h.asset,
        &(BUDGET_LIMIT - SPEND + 1),
    );
    assert_eq!(res, Err(Ok(Error::BudgetExceeded)));
    assert_eq!(token_balance(&h, &h.vendor), SPEND);
    assert_eq!(h.wallet.balance(&wallet_id, &h.asset), before - SPEND);
    assert_eq!(h.budget.get(&budget_id(&h)).spent, SPEND);

    // The governance record is untouched by any of the refusals, and the value
    // that did move is exactly the amount the policy allowed — real custody and
    // internal bookkeeping still agree.
    assert_eq!(h.proposal.state(&id), ProposalState::Approved);
    assert!(h.proposal.can_execute(&id));
    assert_eq!(wallet_custody(&h), before - SPEND);
}

/// Governance can pull the execution path out from under the agent: the multisig
/// — which owns the policy — disables the org-wide policy, every spend is
/// refused, and re-enabling restores the exact payout that was blocked.
#[test]
fn governance_can_suspend_and_restore_the_execution_path() {
    let h = setup();
    let id = submit_proposal(&h);
    authorize_proposal(&h, id);
    wait_out_timelock(&h);

    // Baseline: the authorized payout works while the policy is live.
    h.wallet
        .transfer(&h.agent, &h.wallet_id, &h.vendor, &h.asset, &SPEND);
    assert_eq!(token_balance(&h, &h.vendor), SPEND);

    // The multisig owns the policy, so it — not the wallet admin — is the party
    // that can switch it off. An outsider cannot.
    let policy_id = string(&h, POLICY_ID);
    let res = h.policy.try_set_enabled(&h.admin, &policy_id, &false);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
    h.policy
        .set_enabled(&h.multisig.address, &policy_id, &false);
    assert!(!h.policy.get(&policy_id).enabled);

    // A fully approved proposal is still refused: a disabled policy denies
    // every spend before any amount or recipient is even evaluated.
    let res = h
        .wallet
        .try_transfer(&h.agent, &h.wallet_id, &h.vendor, &h.asset, &1_000);
    assert_eq!(res, Err(Ok(Error::PolicyDenied)));
    assert_eq!(token_balance(&h, &h.vendor), SPEND);
    assert_eq!(
        h.wallet.balance(&h.wallet_id, &h.asset),
        WALLET_FUNDING - SPEND
    );

    // Governance restores the policy and the very same payout goes through.
    h.policy.set_enabled(&h.multisig.address, &policy_id, &true);
    h.wallet
        .transfer(&h.agent, &h.wallet_id, &h.vendor, &h.asset, &1_000);
    assert_eq!(token_balance(&h, &h.vendor), SPEND + 1_000);
    assert_eq!(
        h.wallet.balance(&h.wallet_id, &h.asset),
        WALLET_FUNDING - SPEND - 1_000
    );
}

/// The multisig drives the wallet's policy-gated spend itself: `execute_batch`
/// verifies a threshold of signatures over the exact call payload and then
/// invokes the wallet across a contract boundary. A policy-violating leg
/// reverts the whole batch — including the nonce it would have consumed.
#[test]
fn multisig_batch_executes_the_wallet_spend_and_reverts_on_policy_violation() {
    let h = setup();
    let id = submit_proposal(&h);
    authorize_proposal(&h, id);
    wait_out_timelock(&h);

    // A batch whose second leg breaches the policy cap: the first leg is legal,
    // so only atomicity can stop the payee from keeping it.
    let batch = vec![
        &h.env,
        transfer_call(&h, &h.vendor, 1_000),
        transfer_call(&h, &h.vendor, POLICY_MAX + 1),
    ];
    let res =
        h.multisig
            .try_execute_batch(&h.signer_a, &1, &batch, &vec![&h.env, h.signer_b.clone()]);
    assert_eq!(res, Err(Ok(Error::PolicyDenied)));
    // Nothing moved, and the legal leg did not partially pay out.
    assert_eq!(token_balance(&h, &h.vendor), 0);
    assert_eq!(h.wallet.balance(&h.wallet_id, &h.asset), WALLET_FUNDING);
    assert_eq!(h.budget.get(&budget_id(&h)).spent, 0);
    // The failed batch reverted its nonce, so the number is still free.
    assert_eq!(h.multisig.get_last_batch_nonce(), 0);

    // A single compliant leg carries both signatures' weight (1 + 2 >= 2) and
    // executes the wallet spend across the contract boundary.
    let batch = vec![&h.env, transfer_call(&h, &h.vendor, SPEND)];
    h.multisig
        .execute_batch(&h.signer_a, &1, &batch, &vec![&h.env, h.signer_b.clone()]);
    assert_eq!(h.multisig.get_last_batch_nonce(), 1);
    assert_eq!(token_balance(&h, &h.vendor), SPEND);
    assert_eq!(
        h.wallet.balance(&h.wallet_id, &h.asset),
        WALLET_FUNDING - SPEND
    );
    assert_eq!(h.budget.get(&budget_id(&h)).spent, SPEND);
    // Wallet bookkeeping and real custody still agree after the batch path.
    assert_eq!(wallet_custody(&h), WALLET_FUNDING - SPEND);

    // Nonces are strictly increasing, so the spent one cannot be replayed.
    let res = h.multisig.try_execute_batch(
        &h.signer_a,
        &1,
        &vec![&h.env, transfer_call(&h, &h.vendor, 1_000)],
        &vec![&h.env, h.signer_b.clone()],
    );
    assert_eq!(res, Err(Ok(Error::InvalidNonce)));
    assert_eq!(token_balance(&h, &h.vendor), SPEND);
}

/// A `wallet.transfer` sub-call for the multisig's `execute_batch`.
fn transfer_call(h: &Harness, to: &Address, amount: i128) -> BatchCall {
    let mut args: Vec<Val> = Vec::new(&h.env);
    args.push_back(h.agent.clone().into_val(&h.env));
    args.push_back(h.wallet_id.into_val(&h.env));
    args.push_back(to.clone().into_val(&h.env));
    args.push_back(h.asset.clone().into_val(&h.env));
    args.push_back(amount.into_val(&h.env));
    BatchCall {
        contract: h.wallet.address.clone(),
        func: symbol_short!("transfer"),
        args,
    }
}
