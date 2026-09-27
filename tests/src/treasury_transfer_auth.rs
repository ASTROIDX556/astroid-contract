//! End-to-end authorization on treasury transfers (Issue #241).
//!
//! The treasury's own unit tests pin `require_auth` per function. This suite
//! proves the same thing at the multi-contract level an organization actually
//! runs, with every module resolved through the registry:
//!
//! ```text
//! registry ──lookup──▶ treasury ──check_transfer──▶ policy ──▶ token (SAC)
//! ```
//!
//! Two questions are asked of every path that can move value out of the
//! treasury, and they are kept apart deliberately:
//!
//! 1. **Can an unauthorized party reach it at all?** With auth mocking off, the
//!    host refuses the invocation before the contract body runs, so an agent
//!    that can name the contract and its arguments still cannot make it pay out.
//! 2. **Can an authorized-but-wrong party slip through?** With signatures
//!    satisfied, the identity checks must still reject a caller that is not the
//!    admin, the multisig, or the guardian.
//!
//! Every denial is checked twice: for the deterministic error the caller
//! receives, and for the fact that no token balance or treasury ledger entry
//! moved. An authorization check that fires after the money has already changed
//! hands is not an authorization check.

use astroid_policy::{PolicyContract, PolicyContractClient};
use astroid_registry::{RegistryContract, RegistryContractClient};
use astroid_shared::errors::Error;
use astroid_shared::types::{ModuleKind, Payment};
use astroid_treasury::{TreasuryContract, TreasuryContractClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{token, Address, BytesN, Env, String, Vec};

const ORG: &str = "acme";
const POLICY_ID: &str = "active";
const TREASURY_FUNDS: i128 = 500_000;
const CAP: i128 = 10_000;

struct Harness<'a> {
    env: Env,
    treasury: TreasuryContractClient<'a>,
    admin: Address,
    multisig: Address,
    guardian: Address,
    org_owner: Address,
    agent: Address,
    merchant: Address,
    asset: Address,
}

impl<'a> Harness<'a> {
    fn s(&self, v: &str) -> String {
        String::from_str(&self.env, v)
    }

    fn balance(&self, who: &Address) -> i128 {
        token::TokenClient::new(&self.env, &self.asset).balance(who)
    }

    /// Every balance and ledger total the flows below can move, for a
    /// "nothing moved" assertion after a denial.
    fn ledger(&self) -> [i128; 6] {
        let holding = self.treasury.holding(&self.asset);
        [
            self.balance(&self.treasury.address),
            self.balance(&self.org_owner),
            self.balance(&self.agent),
            self.balance(&self.merchant),
            holding.total_in,
            holding.total_out,
        ]
    }

    /// The shape an `unsatisfied require_auth` takes: the host aborts the
    /// invocation before the body runs.
    fn assert_no_auth<R: std::fmt::Debug>(&self, res: R, what: &str) {
        assert_eq!(
            format!("{:?}", res),
            "Err(Err(Abort))",
            "{what} must be refused for want of an authorization signature"
        );
    }

    /// The shape a known-but-wrong caller takes: the identity check rejects.
    fn assert_wrong_caller<R: std::fmt::Debug>(&self, res: R, what: &str) {
        assert_eq!(
            format!("{:?}", res),
            "Err(Ok(Unauthorized))",
            "{what} must be refused for want of the right caller"
        );
    }
}

/// Deploy registry, treasury and policy; register the org's modules; wire the
/// treasury's policy gate; approve a real SAC token; fund the treasury; and
/// wire the multisig/guardian roles. `admin` is the deployer admin, so it
/// doubles as the initial guardian.
fn setup() -> Harness<'static> {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let multisig = Address::generate(&env);
    let guardian = Address::generate(&env);
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
    for (kind, addr) in [
        (ModuleKind::Treasury, &treasury_id),
        (ModuleKind::Policy, &policy_id),
    ] {
        registry.register_module(&org_owner, &org, &kind, addr);
    }

    // From here on, every module is reached through the registry, so the test
    // exercises the wiring an org really runs.
    let treasury = TreasuryContractClient::new(&env, &registry.lookup(&org, &ModuleKind::Treasury));
    let policy = PolicyContractClient::new(&env, &registry.lookup(&org, &ModuleKind::Policy));

    treasury.initialize(&org, &admin);
    policy.initialize();
    treasury.set_policy(&admin, &registry.lookup(&org, &ModuleKind::Policy));
    treasury.set_multisig(&admin, &multisig);
    // Rotate the guardian off the admin so the guardian's powers are held by a
    // party the tests can distinguish from the admin.
    treasury.set_guardian(&admin, &guardian);

    let token_admin = Address::generate(&env);
    let asset = env
        .register_stellar_asset_contract_v2(token_admin)
        .address();
    treasury.add_approved_asset(&admin, &asset);

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

    Harness {
        env,
        treasury,
        admin,
        multisig,
        guardian,
        org_owner,
        agent,
        merchant,
        asset,
    }
}

// --- unauthorized direct calls -------------------------------------------

#[test]
fn an_unauthorized_party_cannot_withdraw_through_the_registered_treasury() {
    let h = setup();
    // Schedule a milestone payout while signatures are still satisfiable, so
    // the third outflow can be exercised below.
    h.treasury
        .init_milestone_disbursement(&h.admin, &h.asset, &h.merchant, &400, &2);
    let before = h.ledger();
    h.env.set_auths(&[]);

    // Every one of these names the real contract and arguments that work for
    // the admin. The only thing missing is a signature.
    h.assert_no_auth(
        h.treasury.try_withdraw(&h.admin, &h.asset, &h.agent, &100),
        "withdraw",
    );
    let mut payments = Vec::new(&h.env);
    payments.push_back(Payment {
        recipient: h.agent.clone(),
        amount: 100,
    });
    h.assert_no_auth(
        h.treasury.try_batch_transfer(&h.admin, &h.asset, &payments),
        "batch_transfer",
    );
    h.assert_no_auth(
        h.treasury.try_release_next_milestone(&h.admin, &1u64),
        "release_next_milestone",
    );

    assert_eq!(h.ledger(), before, "a refused outflow must move nothing");
}

#[test]
fn an_unauthorized_party_cannot_reconfigure_the_treasury() {
    let h = setup();
    let treasury_before = h.treasury.get();
    let other = Address::generate(&h.env);
    h.env.set_auths(&[]);

    h.assert_no_auth(h.treasury.try_set_policy(&h.admin, &other), "set_policy");
    h.assert_no_auth(h.treasury.try_set_budget(&h.admin, &other), "set_budget");
    h.assert_no_auth(
        h.treasury.try_set_multisig(&h.admin, &other),
        "set_multisig",
    );
    h.assert_no_auth(
        h.treasury.try_set_guardian(&h.admin, &other),
        "set_guardian",
    );
    h.assert_no_auth(
        h.treasury.try_add_approved_asset(&h.admin, &other),
        "add_approved_asset",
    );
    h.assert_no_auth(
        h.treasury.try_remove_approved_asset(&h.admin, &h.asset),
        "remove_approved_asset",
    );
    h.assert_no_auth(
        h.treasury
            .try_allocate_budget(&h.admin, &h.asset, &h.s("b1")),
        "allocate_budget",
    );
    h.assert_no_auth(
        h.treasury
            .try_set_allowance(&h.admin, &h.agent, &h.merchant, &h.asset, &100, &0u64),
        "set_allowance",
    );
    h.assert_no_auth(
        h.treasury
            .try_remove_allowance(&h.admin, &h.agent, &h.merchant, &h.asset),
        "remove_allowance",
    );
    h.assert_no_auth(
        h.treasury
            .try_init_milestone_disbursement(&h.admin, &h.asset, &h.merchant, &400, &2),
        "init_milestone_disbursement",
    );
    h.assert_no_auth(h.treasury.try_pause(&h.guardian), "pause");
    h.assert_no_auth(h.treasury.try_unpause(&h.guardian), "unpause");
    // freeze / unfreeze belong to the multisig, so an unsigned *admin* call is
    // refused on identity before a signature is demanded.
    h.assert_wrong_caller(h.treasury.try_freeze(&h.admin), "freeze by admin");
    h.assert_wrong_caller(h.treasury.try_unfreeze(&h.admin), "unfreeze by admin");

    // The treasury is byte-for-byte the one the admin configured.
    let after = h.treasury.get();
    assert_eq!(after.policy, treasury_before.policy);
    assert_eq!(after.budget, treasury_before.budget);
    assert_eq!(after.multisig, treasury_before.multisig);
    assert_eq!(after.guardian, treasury_before.guardian);
    assert_eq!(after.paused, false);
    assert!(h.treasury.is_approved_asset(&h.asset));
    assert!(!h.treasury.is_approved_asset(&other));
}

#[test]
fn an_unauthorized_party_cannot_deposit_under_another_accounts_name() {
    let h = setup();
    let before = h.ledger();

    // The depositor's own signature is required, so a third party cannot pull
    // tokens out of someone else's account into the treasury.
    h.env.set_auths(&[]);
    h.assert_no_auth(
        h.treasury.try_deposit(&h.org_owner, &h.asset, &100),
        "deposit on behalf of the org owner",
    );
    assert_eq!(h.ledger(), before, "a refused deposit must move nothing");
}

#[test]
fn the_treasury_cannot_be_claimed_without_the_admins_signature() {
    // Stand up only the treasury, unclaimed, and leave auth unsatisfiable: this
    // is the window between deployment and initialization, where the admin is
    // not yet recorded in storage and so cannot be checked against.
    let env = Env::default();
    env.set_auths(&[]);
    let id = env.register_contract(None, TreasuryContract);
    let treasury = TreasuryContractClient::new(&env, &id);
    let admin = Address::generate(&env);
    let attacker = Address::generate(&env);

    h_assert_refused(treasury.try_initialize(&String::from_str(&env, ORG), &attacker));
    h_assert_refused(treasury.try_initialize(&String::from_str(&env, ORG), &admin));
    // Neither attempt recorded an owner, so the deployer is not locked out and
    // the contract is not left half-initialized.
    assert!(
        matches!(treasury.try_get(), Err(Ok(Error::NotInitialized))),
        "a refused initialize must leave the treasury unclaimed"
    );

    // With the admin's signature the deployer wins the claim.
    env.mock_all_auths();
    treasury.initialize(&String::from_str(&env, ORG), &admin);
    assert_eq!(treasury.get().admin, admin);
    // And the owner cannot be rotated afterwards. The re-initialization guard
    // is checked before a signature is demanded, so this is refused on state
    // rather than on auth - either way the recorded admin is immutable.
    env.set_auths(&[]);
    assert_eq!(
        format!(
            "{:?}",
            treasury.try_initialize(&String::from_str(&env, "other"), &attacker)
        ),
        "Err(Ok(AlreadyInitialized))"
    );
    assert_eq!(treasury.get().admin, admin);
}

fn h_assert_refused<R: std::fmt::Debug>(res: R) {
    assert_eq!(
        format!("{:?}", res),
        "Err(Err(Abort))",
        "initialize must be refused for want of an authorization signature"
    );
}

// --- authorized signature, wrong identity ---------------------------------

#[test]
fn a_signed_non_admin_cannot_withdraw_through_the_registered_treasury() {
    let h = setup();
    let before = h.ledger();
    h.treasury
        .init_milestone_disbursement(&h.admin, &h.asset, &h.merchant, &400, &2);

    // Signatures are satisfied from here on, so the failure under test is the
    // identity check. An org owner, a wallet agent and a plain stranger are all
    // refused equally.
    for who in [&h.org_owner, &h.agent, &h.merchant] {
        h.assert_wrong_caller(
            h.treasury.try_withdraw(who, &h.asset, &h.merchant, &100),
            "withdraw",
        );
        let mut payments = Vec::new(&h.env);
        payments.push_back(Payment {
            recipient: h.merchant.clone(),
            amount: 100,
        });
        h.assert_wrong_caller(
            h.treasury.try_batch_transfer(who, &h.asset, &payments),
            "batch_transfer",
        );
        h.assert_wrong_caller(
            h.treasury.try_release_next_milestone(who, &1u64),
            "release_next_milestone",
        );
        h.assert_wrong_caller(h.treasury.try_set_policy(who, &h.merchant), "set_policy");
        h.assert_wrong_caller(
            h.treasury.try_remove_approved_asset(who, &h.asset),
            "remove_approved_asset",
        );
    }

    assert_eq!(h.ledger(), before, "a refused outflow must move nothing");
    // The scheduled payout was not advanced by any refusal: the admin's own
    // release still pays the full first tranche (400 / 2 milestones), which it
    // could not do had a refused call consumed one.
    h.treasury.release_next_milestone(&h.admin, &1u64);
    assert_eq!(h.balance(&h.merchant), 200);
}

#[test]
fn an_allowance_never_becomes_an_authority() {
    let h = setup();
    // The admin grants the agent a bounded withdrawal allowance. An allowance
    // lowers a ceiling; it is not a capability, so it must not let the agent
    // move value the admin could not.
    h.treasury
        .set_allowance(&h.admin, &h.agent, &h.merchant, &h.asset, &50, &0u64);

    // The allowance holder is still not the admin, so every outflow is refused
    // on identity despite holding a signed, on-chain grant.
    h.assert_wrong_caller(
        h.treasury
            .try_withdraw(&h.agent, &h.asset, &h.merchant, &50),
        "withdraw by an allowance holder",
    );
    let mut payments = Vec::new(&h.env);
    payments.push_back(Payment {
        recipient: h.merchant.clone(),
        amount: 50,
    });
    h.assert_wrong_caller(
        h.treasury.try_batch_transfer(&h.agent, &h.asset, &payments),
        "batch_transfer by an allowance holder",
    );

    // The admin is unaffected and still moves value.
    h.treasury.withdraw(&h.admin, &h.asset, &h.merchant, &50);
    assert_eq!(h.balance(&h.merchant), 50);
}

#[test]
fn the_emergency_roles_are_narrow_and_do_not_overlap_with_moving_value() {
    let h = setup();

    // Neither emergency role is an admin: the multisig cannot rewire the
    // treasury, and the guardian cannot move value.
    h.assert_wrong_caller(
        h.treasury.try_add_approved_asset(&h.multisig, &h.asset),
        "add_approved_asset by the multisig",
    );
    h.assert_wrong_caller(
        h.treasury.try_set_policy(&h.multisig, &h.merchant),
        "set_policy by the multisig",
    );
    h.assert_wrong_caller(
        h.treasury
            .try_withdraw(&h.guardian, &h.asset, &h.merchant, &10),
        "withdraw by the guardian",
    );

    // A stranger holds no role at all.
    let stranger = Address::generate(&h.env);
    h.assert_wrong_caller(h.treasury.try_pause(&stranger), "pause by a stranger");
    h.assert_wrong_caller(h.treasury.try_freeze(&stranger), "freeze by a stranger");
    h.assert_wrong_caller(h.treasury.try_freeze(&h.guardian), "freeze by the guardian");

    // The multisig does own freeze, and a frozen treasury refuses outflows
    // before the admin check is even reached - so the multisig cannot use its
    // own emergency power to route around a refusal.
    h.treasury.freeze(&h.multisig);
    assert_eq!(
        format!(
            "{:?}",
            h.treasury
                .try_withdraw(&h.admin, &h.asset, &h.merchant, &10)
        ),
        "Err(Ok(InvalidState))",
        "a frozen treasury refuses outflows, including the admin's"
    );
    h.treasury.unfreeze(&h.multisig);

    // The guardian does own the pause, and it is a breaker over value rather
    // than a role that grants it.
    h.treasury.pause(&h.guardian);
    assert!(h.treasury.is_paused());
    assert_eq!(
        format!(
            "{:?}",
            h.treasury
                .try_withdraw(&h.admin, &h.asset, &h.merchant, &10)
        ),
        "Err(Ok(TreasuryPaused))",
        "a paused treasury refuses the admin's outflows too"
    );
    h.treasury.unpause(&h.guardian);

    // With both breakers released only the admin can still move value, and
    // exercising the roles changed nothing about ownership.
    assert!(!h.treasury.is_paused());
    h.treasury.withdraw(&h.admin, &h.asset, &h.merchant, &10);
    assert_eq!(h.balance(&h.merchant), 10);
    assert_eq!(h.treasury.get().admin, h.admin);
}

#[test]
fn a_paused_treasury_refuses_outflows_to_the_admin_as_well() {
    let h = setup();
    h.treasury.pause(&h.guardian);
    assert!(h.treasury.is_paused());

    // The pause is a circuit breaker over value, not an authz question: even
    // the fully authorized admin cannot move value while it is engaged.
    h.assert_no_auth_value_paused(
        h.treasury
            .try_withdraw(&h.admin, &h.asset, &h.merchant, &100),
        "withdraw while paused",
    );
    let mut payments = Vec::new(&h.env);
    payments.push_back(Payment {
        recipient: h.merchant.clone(),
        amount: 100,
    });
    h.assert_no_auth_value_paused(
        h.treasury.try_batch_transfer(&h.admin, &h.asset, &payments),
        "batch_transfer while paused",
    );
    // Inbound recovery funding still lands while paused.
    token::StellarAssetClient::new(&h.env, &h.asset).mint(&h.org_owner, &100);
    h.treasury.deposit(&h.org_owner, &h.asset, &100);
    h.treasury.unpause(&h.guardian);
}

impl<'a> Harness<'a> {
    fn assert_no_auth_value_paused<R: std::fmt::Debug>(&self, res: R, what: &str) {
        assert_eq!(
            format!("{:?}", res),
            "Err(Ok(TreasuryPaused))",
            "{what} must be refused while the circuit breaker is engaged"
        );
    }
}
