//! End-to-end withdrawal time-lock on the treasury (Issue #321).
//!
//! The treasury is the one module where a compromised admin key is immediately
//! monetisable: whoever holds it can move the whole balance in one signed
//! transaction, and no policy, budget or multisig threshold can interpose if
//! that key is alone on the multisig. Policy and budget constrain *how much* and
//! *to whom*, but neither of them introduces a delay.
//!
//! This suite drives the cooling-off period at the multi-contract level an
//! organization actually runs, with every module resolved through the registry:
//!
//! ```text
//! registry ──lookup──▶ treasury ──check_transfer──▶ policy ──▶ token (SAC)
//! ```
//!
//! The cases below are grouped by what the time-lock has to guarantee:
//!
//! 1. **A premature execution fails loudly, with the designated code.** Every
//!    early attempt is asserted twice — for `Error::TimelockNotExpired`, the
//!    protocol's dedicated early-execution code, and for the fact that no token
//!    balance or ledger entry moved. A delay that reports the right error while
//!    the money has already changed hands is not a delay.
//! 2. **The fast path is untouched.** A treasury that never configures a lock,
//!    and payouts below the configured threshold, settle immediately — the
//!    control is aimed at draining the balance, not at ordinary agent spending.
//! 3. **Cancellation and lapse are clean.** A queued request can be dropped
//!    without waiting it out, and one left unexecuted past its grace period
//!    lapses instead of becoming a standing obligation.
//!
//! Timing is driven exclusively through `env.ledger().timestamp()`, which is
//! what the contract reads, so no case can accidentally pass by virtue of the
//! host clock happening to be slow.

use astroid_policy::{PolicyContract, PolicyContractClient};
use astroid_registry::{RegistryContract, RegistryContractClient};
use astroid_shared::constants::{GOVERNANCE_GRACE_PERIOD, MAX_TIMELOCK_DELAY, MIN_TIMELOCK_DELAY};
use astroid_shared::errors::Error;
use astroid_shared::types::{ModuleKind, Payment};
use astroid_treasury::{TreasuryContract, TreasuryContractClient};
use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::{token, Address, BytesN, Env, String, Vec};

const ORG: &str = "acme";
const POLICY_ID: &str = "active";
const TREASURY_FUNDS: i128 = 500_000;
/// Per-transaction ceiling the policy enforces. Set above every payout used
/// below so the cooling-off period, rather than the policy, is the binding
/// constraint; `parking_does_not_let_a_payout_escape_policy` covers the
/// interaction explicitly.
const CAP: i128 = 300_000;

/// The ledger instant every run starts from, so the boundary cases below are
/// stated as offsets from a known base rather than from an ambient clock.
const T0: u64 = 1_000_000;

/// Payouts at or above this amount are parked; anything smaller settles at once.
const THRESHOLD: i128 = 50_000;

struct Harness<'a> {
    env: Env,
    treasury: TreasuryContractClient<'a>,
    admin: Address,
    multisig: Address,
    guardian: Address,
    org_owner: Address,
    payee: Address,
    asset: Address,
}

impl<'a> Harness<'a> {
    fn balance(&self, who: &Address) -> i128 {
        token::TokenClient::new(&self.env, &self.asset).balance(who)
    }

    /// Every balance and ledger total the time-locked paths below can move, for
    /// a "nothing moved" assertion after a refusal.
    fn ledger(&self) -> [i128; 4] {
        let holding = self.treasury.holding(&self.asset);
        [
            self.balance(&self.treasury.address),
            self.balance(&self.payee),
            holding.total_in,
            holding.total_out,
        ]
    }

    /// Move the ledger to the absolute instant `ts`. Asserting the step is
    /// forward keeps a broken case from appearing to exercise the boundary it
    /// means to, and states every deadline as an offset from `T0` rather than
    /// from wherever the previous call happened to leave the clock.
    fn warp(&self, ts: u64) {
        let now = self.env.ledger().timestamp();
        assert!(ts > now, "a time-lock case must move the ledger forward");
        self.env.ledger().set_timestamp(ts);
    }

    /// A batch of `legs` identical payments to the payee.
    fn batch(&self, legs: u32, amount: i128) -> Vec<Payment> {
        let mut payments = Vec::new(&self.env);
        for _ in 0..legs {
            payments.push_back(Payment {
                recipient: self.payee.clone(),
                amount,
            });
        }
        payments
    }

    /// The shape a premature execution takes: the dedicated early-execution code.
    fn assert_too_early<R: std::fmt::Debug>(&self, res: R, what: &str) {
        assert_eq!(
            format!("{:?}", res),
            "Err(Ok(TimelockNotExpired))",
            "{what} must be refused while still inside its cooling-off period"
        );
    }
}

/// Deploy registry, treasury and policy; register the org's modules; wire the
/// treasury's policy gate; approve a real SAC token; and fund the treasury.
/// `admin` is the deployer admin, so it doubles as the initial guardian.
fn setup() -> Harness<'static> {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(T0);

    let admin = Address::generate(&env);
    let multisig = Address::generate(&env);
    let guardian = Address::generate(&env);
    let org_owner = Address::generate(&env);
    let payee = Address::generate(&env);
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

    // From here on, every module is reached through the registry, so the tests
    // exercise the wiring an org really runs.
    let treasury = TreasuryContractClient::new(&env, &registry.lookup(&org, &ModuleKind::Treasury));
    let policy = PolicyContractClient::new(&env, &registry.lookup(&org, &ModuleKind::Policy));

    treasury.initialize(&org, &admin);
    policy.initialize();
    treasury.set_policy(&admin, &registry.lookup(&org, &ModuleKind::Policy));
    treasury.set_multisig(&admin, &multisig);
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
        &None,
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
        payee,
        asset,
    }
}

/// Deploy the same wiring and engage the cooling-off period.
fn setup_timelocked(delay: u64, threshold: i128) -> Harness<'static> {
    let h = setup();
    h.treasury
        .set_withdrawal_time_lock(&h.admin, &delay, &threshold);
    h
}

// --- premature execution fails with the designated code -------------------

#[test]
fn an_early_execution_of_a_queued_withdrawal_fails_with_the_designated_code() {
    let h = setup_timelocked(MIN_TIMELOCK_DELAY, THRESHOLD);
    let before = h.ledger();

    // The request is parked, not paid: the whole point of the delay is that the
    // funds stay put while the organization has a chance to react.
    let id = h
        .treasury
        .queue_withdrawal(&h.admin, &h.asset, &h.payee, &100_000);
    let p = h.treasury.pending_withdrawal(&id);
    assert_eq!(p.amount, 100_000);
    assert_eq!(p.execute_after, T0 + MIN_TIMELOCK_DELAY);
    assert_eq!(h.ledger(), before, "queueing must move no value");

    // A quarter of the way in is still early, and the request survives the
    // refusal rather than being consumed by it.
    h.warp(T0 + MIN_TIMELOCK_DELAY / 4);
    h.assert_too_early(
        h.treasury.try_execute_withdrawal(&h.admin, &id),
        "execute_withdrawal a quarter of the way in",
    );
    assert!(h.treasury.pending_withdrawal(&id).is_pending());
    assert_eq!(h.ledger(), before);

    // And one second short of the deadline is still early too -- the boundary is
    // where the delay says it is, not somewhere near it.
    h.warp(T0 + MIN_TIMELOCK_DELAY - 1);
    h.assert_too_early(
        h.treasury.try_execute_withdrawal(&h.admin, &id),
        "execute_withdrawal one second early",
    );
    assert_eq!(h.ledger(), before, "a refused execution must move nothing");
    assert!(h.treasury.pending_withdrawal(&id).is_pending());
}

#[test]
fn a_high_value_withdrawal_cannot_settle_in_the_transaction_that_requests_it() {
    let h = setup_timelocked(MIN_TIMELOCK_DELAY, THRESHOLD);
    let before = h.ledger();

    // The direct path is refused outright, so a compromised admin key cannot
    // monetize itself in a single transaction — it has to go through the queue,
    // which leaves a visible, cancellable record behind.
    h.assert_too_early(
        h.treasury
            .try_withdraw(&h.admin, &h.asset, &h.payee, &100_000),
        "withdraw at or above the threshold",
    );
    h.assert_too_early(
        h.treasury
            .try_withdraw(&h.admin, &h.asset, &h.payee, &THRESHOLD),
        "withdraw exactly on the threshold",
    );
    assert_eq!(h.ledger(), before);
    assert_eq!(h.treasury.pending_withdrawal_count(), 0);
}

// --- parking does not become a policy escape hatch ------------------------

#[test]
fn parking_does_not_let_a_payout_escape_policy() {
    let h = setup_timelocked(MIN_TIMELOCK_DELAY, THRESHOLD);
    let before = h.ledger();

    // 400_000 is above the policy cap of 300_000. Queueing does not consult the
    // policy -- it moves nothing, so there is nothing yet to judge -- but the
    // request must not become a way around the cap once it comes due.
    let id = h
        .treasury
        .queue_withdrawal(&h.admin, &h.asset, &h.payee, &400_000);
    h.warp(T0 + MIN_TIMELOCK_DELAY);
    assert_eq!(
        h.treasury.try_execute_withdrawal(&h.admin, &id),
        Err(Ok(Error::PolicyDenied))
    );
    assert_eq!(h.ledger(), before, "a policy refusal must move nothing");

    // A queued request that reverts leaves no trace of having settled, so the
    // organization can correct it and queue a permitted amount instead.
    assert!(!h.treasury.pending_withdrawal(&id).executed);
    let permitted = h
        .treasury
        .queue_withdrawal(&h.admin, &h.asset, &h.payee, &100_000);
    let queued_at = h.env.ledger().timestamp();
    h.warp(queued_at + MIN_TIMELOCK_DELAY);
    h.treasury.execute_withdrawal(&h.admin, &permitted);
    assert_eq!(h.balance(&h.payee), 100_000);
}

#[test]
fn an_early_execution_of_a_queued_batch_fails_with_the_designated_code() {
    let h = setup_timelocked(MIN_TIMELOCK_DELAY, THRESHOLD);
    let before = h.ledger();

    // The lock measures the aggregate payout, so a large batch is parked whole:
    // splitting one movement across many legs cannot walk past the delay.
    let payments = h.batch(4, 40_000);
    let id = h
        .treasury
        .queue_batch_transfer(&h.admin, &h.asset, &payments);
    let p = h.treasury.pending_withdrawal(&id);
    assert_eq!(p.amount, 160_000);
    assert_eq!(p.payments.len(), 4);
    assert_eq!(h.ledger(), before);

    h.warp(T0 + MIN_TIMELOCK_DELAY - 1);
    h.assert_too_early(
        h.treasury.try_execute_withdrawal(&h.admin, &id),
        "execute_withdrawal of a queued batch, one second early",
    );
    assert_eq!(h.ledger(), before, "a refused batch must pay no leg at all");
}

#[test]
fn a_split_batch_cannot_walk_past_the_time_lock_on_the_direct_path() {
    let h = setup_timelocked(MIN_TIMELOCK_DELAY, THRESHOLD);
    let before = h.ledger();

    // Four legs of 30_000: every individual leg sits under the threshold, but
    // 120_000 leaves the treasury in aggregate. If the lock were measured per leg
    // this batch would settle instantly and the whole control would be advisory.
    let payments = h.batch(4, 30_000);
    h.assert_too_early(
        h.treasury.try_batch_transfer(&h.admin, &h.asset, &payments),
        "batch_transfer whose aggregate clears the threshold",
    );
    assert_eq!(h.ledger(), before, "no leg of a refused batch may be paid");
}

// --- the fast path is unaffected ------------------------------------------

#[test]
fn a_low_value_withdrawal_settles_immediately_under_a_configured_time_lock() {
    let h = setup_timelocked(MIN_TIMELOCK_DELAY, THRESHOLD);
    assert_eq!(h.treasury.withdrawal_time_lock().delay, MIN_TIMELOCK_DELAY);

    // One base unit under the bar settles at the same ledger instant, with no
    // queueing and no waiting: ordinary agent spending is not held hostage to a
    // governance control aimed at draining the whole balance.
    h.treasury
        .withdraw(&h.admin, &h.asset, &h.payee, &(THRESHOLD - 1));
    assert_eq!(h.balance(&h.payee), THRESHOLD - 1);
    assert_eq!(h.treasury.pending_withdrawal_count(), 0);

    // The same holds for a batch whose aggregate stays under the bar.
    h.treasury
        .batch_transfer(&h.admin, &h.asset, &h.batch(3, 1_000));
    assert_eq!(h.balance(&h.payee), THRESHOLD - 1 + 3_000);
    assert_eq!(h.treasury.pending_withdrawal_count(), 0);
}

#[test]
fn a_treasury_with_no_configured_time_lock_settles_cleanly() {
    let h = setup();

    // Never configured: the lock is off, so there is no queueing step at any
    // size and the outflow paths behave exactly as they did before the feature.
    let config = h.treasury.withdrawal_time_lock();
    assert_eq!(config.delay, 0);
    assert_eq!(config.threshold, 0);

    h.treasury.withdraw(&h.admin, &h.asset, &h.payee, &200_000);
    assert_eq!(h.balance(&h.payee), 200_000);
    h.treasury
        .batch_transfer(&h.admin, &h.asset, &h.batch(3, 1_000));
    assert_eq!(h.balance(&h.payee), 203_000);
    assert_eq!(h.treasury.holding(&h.asset).total_out, 203_000);
    assert_eq!(h.treasury.pending_withdrawal_count(), 0);
}

#[test]
fn a_zero_time_lock_settles_cleanly_and_captures_nothing() {
    let h = setup_timelocked(0, 0);

    // The zero configuration is the explicit "off" case, and behaves exactly
    // like never having configured one at any size.
    let config = h.treasury.withdrawal_time_lock();
    assert_eq!(config.delay, 0);
    assert_eq!(config.threshold, 0);

    h.treasury.withdraw(&h.admin, &h.asset, &h.payee, &200_000);
    assert_eq!(h.balance(&h.payee), 200_000);

    // Nothing can be parked, because nothing is ever captured -- queueing here
    // would impose a cooldown governance explicitly asked not to have.
    assert_eq!(
        h.treasury
            .try_queue_withdrawal(&h.admin, &h.asset, &h.payee, &200_000),
        Err(Ok(Error::InvalidInput))
    );
    assert_eq!(h.treasury.pending_withdrawal_count(), 0);
}

// --- cancellation and lapse -----------------------------------------------

#[test]
fn a_queued_withdrawal_can_be_cancelled_and_never_pays_out() {
    let h = setup_timelocked(MIN_TIMELOCK_DELAY, THRESHOLD);
    let before = h.ledger();
    let id = h
        .treasury
        .queue_withdrawal(&h.admin, &h.asset, &h.payee, &100_000);

    // Cancellation is the escape hatch that makes the delay safe to configure: a
    // request that turns out hostile can be dropped without waiting it out.
    h.treasury.cancel_withdrawal(&h.admin, &id);
    assert!(h.treasury.pending_withdrawal(&id).cancelled);

    // Cancelling twice is refused rather than silently idempotent...
    assert_eq!(
        h.treasury.try_cancel_withdrawal(&h.admin, &id),
        Err(Ok(Error::InvalidState))
    );
    assert_eq!(h.ledger(), before);

    // ...and a cancelled request stays dead well past its deadline, so the
    // cancellation cannot be raced by a later execution.
    h.warp(T0 + MIN_TIMELOCK_DELAY * 2);
    assert_eq!(
        h.treasury.try_execute_withdrawal(&h.admin, &id),
        Err(Ok(Error::InvalidState))
    );
    assert_eq!(h.ledger(), before);
    assert_eq!(h.balance(&h.payee), 0);
}

#[test]
fn a_stale_request_lapses_instead_of_paying_out_arbitrarily_late() {
    let h = setup_timelocked(MIN_TIMELOCK_DELAY, THRESHOLD);
    let before = h.ledger();
    let id = h
        .treasury
        .queue_withdrawal(&h.admin, &h.asset, &h.payee, &100_000);

    // The request matured long ago and was simply ignored. Cashing it in months
    // later, against a treasury whose balances have since changed entirely, is
    // refused: a lapsed request must be re-queued under fresh scrutiny.
    h.warp(T0 + MIN_TIMELOCK_DELAY + GOVERNANCE_GRACE_PERIOD);
    assert_eq!(
        h.treasury.try_execute_withdrawal(&h.admin, &id),
        Err(Ok(Error::ProposalExpired))
    );
    assert_eq!(h.ledger(), before);

    // Re-queueing is the sanctioned way to proceed, and starts a fresh clock on a
    // fresh id -- ids are never reused for a different request.
    let again = h
        .treasury
        .queue_withdrawal(&h.admin, &h.asset, &h.payee, &100_000);
    assert_ne!(again, id);
    let queued_at = h.env.ledger().timestamp();
    h.warp(queued_at + MIN_TIMELOCK_DELAY);
    h.treasury.execute_withdrawal(&h.admin, &again);
    assert_eq!(h.balance(&h.payee), 100_000);
}

// --- boundaries and authorization -----------------------------------------

#[test]
fn the_execution_boundary_is_inclusive_and_settles_once() {
    let h = setup_timelocked(MIN_TIMELOCK_DELAY, THRESHOLD);
    let id = h
        .treasury
        .queue_withdrawal(&h.admin, &h.asset, &h.payee, &100_000);

    // Exactly at the deadline the full delay has elapsed and not one second
    // less, so the payout settles.
    h.warp(T0 + MIN_TIMELOCK_DELAY);
    h.treasury.execute_withdrawal(&h.admin, &id);
    assert_eq!(h.balance(&h.payee), 100_000);
    assert_eq!(h.treasury.holding(&h.asset).total_out, 100_000);

    // The record is terminal in both directions: a second execution would be a
    // double payout, and cancelling a settled request would misreport the ledger.
    assert_eq!(
        h.treasury.try_execute_withdrawal(&h.admin, &id),
        Err(Ok(Error::InvalidState))
    );
    assert_eq!(
        h.treasury.try_cancel_withdrawal(&h.admin, &id),
        Err(Ok(Error::InvalidState))
    );
    assert_eq!(
        h.balance(&h.payee),
        100_000,
        "a request may settle only once"
    );
}

#[test]
fn the_time_lock_configuration_is_bounded_and_governed() {
    let h = setup();

    // Shorter than a governance change may be, and longer than one may be parked
    // behind, so the control can never be set to a value that makes it worthless
    // or a denial of service.
    assert_eq!(
        h.treasury
            .try_set_withdrawal_time_lock(&h.admin, &(MIN_TIMELOCK_DELAY - 1), &THRESHOLD),
        Err(Ok(Error::InvalidInput))
    );
    assert_eq!(
        h.treasury
            .try_set_withdrawal_time_lock(&h.admin, &(MAX_TIMELOCK_DELAY + 1), &THRESHOLD),
        Err(Ok(Error::InvalidInput))
    );
    // Both ends of the permitted window are accepted.
    h.treasury
        .set_withdrawal_time_lock(&h.admin, &MIN_TIMELOCK_DELAY, &THRESHOLD);
    assert_eq!(h.treasury.withdrawal_time_lock().delay, MIN_TIMELOCK_DELAY);
    h.treasury
        .set_withdrawal_time_lock(&h.admin, &MAX_TIMELOCK_DELAY, &THRESHOLD);
    assert_eq!(h.treasury.withdrawal_time_lock().delay, MAX_TIMELOCK_DELAY);

    // A zero or negative threshold would capture every payout, including dust.
    for bad in [0i128, -1] {
        assert_eq!(
            h.treasury
                .try_set_withdrawal_time_lock(&h.admin, &MIN_TIMELOCK_DELAY, &bad),
            Err(Ok(Error::InvalidAmount))
        );
    }
    // Every rejection left the previous configuration in force.
    assert_eq!(h.treasury.withdrawal_time_lock().delay, MAX_TIMELOCK_DELAY);
    assert_eq!(h.treasury.withdrawal_time_lock().threshold, THRESHOLD);
}

#[test]
fn only_governance_can_configure_or_drive_the_time_lock() {
    let h = setup_timelocked(MIN_TIMELOCK_DELAY, THRESHOLD);
    let before = h.ledger();

    // Neither the guardian, the multisig nor a stranger may set the control,
    // park a request, or cancel and execute one. The time-lock is a guard on the
    // admin, so its own levers have to be held more tightly than the thing they
    // guard -- otherwise disabling it is just one more way to drain the balance.
    for who in [&h.guardian, &h.multisig, &h.org_owner] {
        assert_eq!(
            h.treasury.try_set_withdrawal_time_lock(who, &0, &0),
            Err(Ok(Error::Unauthorized)),
            "only the admin may configure the time-lock"
        );
        assert_eq!(
            h.treasury
                .try_queue_withdrawal(who, &h.asset, &h.payee, &100_000),
            Err(Ok(Error::Unauthorized)),
            "only the admin may queue a withdrawal"
        );
    }

    let id = h
        .treasury
        .queue_withdrawal(&h.admin, &h.asset, &h.payee, &100_000);
    for who in [&h.guardian, &h.multisig, &h.org_owner] {
        assert_eq!(
            h.treasury.try_cancel_withdrawal(who, &id),
            Err(Ok(Error::Unauthorized))
        );
        assert_eq!(
            h.treasury.try_execute_withdrawal(who, &id),
            Err(Ok(Error::Unauthorized))
        );
    }
    assert_eq!(h.ledger(), before);
    assert!(h.treasury.pending_withdrawal(&id).is_pending());
    assert_eq!(h.treasury.withdrawal_time_lock().delay, MIN_TIMELOCK_DELAY);
}

#[test]
fn an_unknown_request_id_is_refused_deterministically() {
    let h = setup_timelocked(MIN_TIMELOCK_DELAY, THRESHOLD);
    let before = h.ledger();

    // Ids are allocated, never guessed.
    assert_eq!(
        h.treasury.try_pending_withdrawal(&7),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(
        h.treasury.try_execute_withdrawal(&h.admin, &7),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(
        h.treasury.try_cancel_withdrawal(&h.admin, &7),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(h.treasury.pending_withdrawal_count(), 0);
    assert_eq!(h.ledger(), before);
}

#[test]
fn a_paused_treasury_still_refuses_a_due_withdrawal() {
    let h = setup_timelocked(MIN_TIMELOCK_DELAY, THRESHOLD);
    let id = h
        .treasury
        .queue_withdrawal(&h.admin, &h.asset, &h.payee, &100_000);
    let before = h.ledger();

    // The circuit breaker and the cooling-off period are independent brakes: a
    // request that has served its full delay must still not pay out while the
    // treasury is paused.
    h.treasury.pause(&h.guardian);
    h.warp(T0 + MIN_TIMELOCK_DELAY);
    assert_eq!(
        h.treasury.try_execute_withdrawal(&h.admin, &id),
        Err(Ok(Error::TreasuryPaused))
    );
    assert_eq!(h.ledger(), before);
    assert!(h.treasury.pending_withdrawal(&id).is_pending());

    // Releasing the breaker lets it settle, with the original deadline honoured.
    h.treasury.unpause(&h.guardian);
    h.treasury.execute_withdrawal(&h.admin, &id);
    assert_eq!(h.balance(&h.payee), 100_000);
}
