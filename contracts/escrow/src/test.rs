use soroban_sdk::{
    testutils::{Address as _, Ledger},
    token, Address, Env, String,
};

use astroid_shared::errors::Error;

use crate::{EscrowContract, EscrowContractClient, EscrowState, ReleaseSchedule, ReleaseType};

const START: u64 = 1_000;

struct Harness<'a> {
    env: Env,
    client: EscrowContractClient<'a>,
    asset: Address,
    sender: Address,
    recipient: Address,
    arbiter: Address,
}

/// Register an escrow contract plus a test SAC token, and mint `funded` of the
/// asset to the sender so `create` moves real value into custody.
fn setup(funded: i128) -> Harness<'static> {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().with_mut(|l| l.timestamp = START);

    let id = env.register_contract(None, EscrowContract);
    let client = EscrowContractClient::new(&env, &id);
    client.initialize();

    let token_admin = Address::generate(&env);
    let asset = env
        .register_stellar_asset_contract_v2(token_admin)
        .address();

    let sender = Address::generate(&env);
    let recipient = Address::generate(&env);
    let arbiter = Address::generate(&env);
    if funded > 0 {
        token::StellarAssetClient::new(&env, &asset).mint(&sender, &funded);
    }

    Harness {
        env,
        client,
        asset,
        sender,
        recipient,
        arbiter,
    }
}

fn balance(h: &Harness, who: &Address) -> i128 {
    token::TokenClient::new(&h.env, &h.asset).balance(who)
}

fn create(h: &Harness, amount: i128, deadline: u64) -> u64 {
    h.client.create(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &h.asset,
        &amount,
        &deadline,
        &String::from_str(&h.env, "payment"),
    )
}

#[test]
fn full_cycle_create_release() {
    let h = setup(10_000);
    let id = create(&h, 10_000, START + 86_400);
    assert_eq!(id, 1);
    // Funds are now in the escrow's custody, out of the sender's account.
    assert_eq!(balance(&h, &h.sender), 0);
    assert_eq!(balance(&h, &h.client.address), 10_000);
    assert_eq!(h.client.get(&id).state, EscrowState::Funded);

    h.client.release(&h.arbiter, &id);
    assert_eq!(h.client.get(&id).state, EscrowState::Released);
    // The recipient received the real tokens; custody is empty.
    assert_eq!(balance(&h, &h.recipient), 10_000);
    assert_eq!(balance(&h, &h.client.address), 0);

    h.client.close(&h.sender, &id);
    assert_eq!(h.client.get(&id).state, EscrowState::Closed);
}

#[test]
fn non_arbiter_cannot_release() {
    let h = setup(5_000);
    let id = create(&h, 5_000, START + 100);
    let intruder = Address::generate(&h.env);

    let res = h.client.try_release(&intruder, &id);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
    // Nothing moved.
    assert_eq!(balance(&h, &h.client.address), 5_000);
    assert_eq!(balance(&h, &h.recipient), 0);
}

#[test]
fn release_after_deadline_is_refused() {
    let h = setup(5_000);
    let id = create(&h, 5_000, START + 100);

    // Releasing after the deadline is refused with EscrowExpired. The host rolls
    // back state on the returned error, so the escrow stays Funded and the sender
    // can still reclaim funds via the permissionless refund path.
    h.env.ledger().with_mut(|l| l.timestamp = START + 200);
    let res = h.client.try_release(&h.arbiter, &id);
    assert_eq!(res, Err(Ok(Error::EscrowExpired)));
    assert_eq!(h.client.get(&id).state, EscrowState::Funded);
    assert_eq!(balance(&h, &h.client.address), 5_000);
}

#[test]
fn refund_returns_funds_after_deadline() {
    let h = setup(5_000);
    let id = create(&h, 5_000, START + 100);

    h.env.ledger().with_mut(|l| l.timestamp = START + 200);
    h.client.refund(&h.sender, &id);
    assert_eq!(h.client.get(&id).state, EscrowState::Refunded);
    // The sender got the real tokens back; custody is empty.
    assert_eq!(balance(&h, &h.sender), 5_000);
    assert_eq!(balance(&h, &h.client.address), 0);
}

#[test]
fn refund_before_deadline_rejected() {
    let h = setup(5_000);
    let id = create(&h, 5_000, START + 100);

    let res = h.client.try_refund(&h.sender, &id);
    assert_eq!(res, Err(Ok(Error::InvalidState)));
    assert_eq!(balance(&h, &h.client.address), 5_000);
}

#[test]
fn expire_marks_then_refund_returns() {
    let h = setup(5_000);
    let id = create(&h, 5_000, START + 100);

    // Cannot expire before the deadline.
    let early = h.client.try_expire(&id);
    assert_eq!(early, Err(Ok(Error::InvalidState)));

    h.env.ledger().with_mut(|l| l.timestamp = START + 200);
    h.client.expire(&id);
    assert_eq!(h.client.get(&id).state, EscrowState::Expired);
    // Marking Expired must NOT move funds — they wait for refund.
    assert_eq!(balance(&h, &h.client.address), 5_000);
    assert_eq!(balance(&h, &h.sender), 0);

    h.client.refund(&h.sender, &id);
    assert_eq!(h.client.get(&id).state, EscrowState::Refunded);
    assert_eq!(balance(&h, &h.sender), 5_000);
    assert_eq!(balance(&h, &h.client.address), 0);
}

#[test]
fn released_escrow_cannot_be_refunded() {
    let h = setup(5_000);
    let id = create(&h, 5_000, START + 100);
    h.client.release(&h.arbiter, &id);

    // Even past the deadline, a released escrow cannot double-spend via refund.
    h.env.ledger().with_mut(|l| l.timestamp = START + 200);
    let res = h.client.try_refund(&h.sender, &id);
    assert_eq!(res, Err(Ok(Error::InvalidState)));
    assert_eq!(balance(&h, &h.recipient), 5_000);
    assert_eq!(balance(&h, &h.client.address), 0);
}

#[test]
fn cannot_close_while_expired() {
    let h = setup(5_000);
    let id = create(&h, 5_000, START + 100);
    h.env.ledger().with_mut(|l| l.timestamp = START + 200);
    h.client.expire(&id);

    // Closing an Expired escrow would strand its still-held funds — refused.
    let res = h.client.try_close(&h.sender, &id);
    assert_eq!(res, Err(Ok(Error::InvalidState)));
    assert_eq!(balance(&h, &h.client.address), 5_000);
}

#[test]
fn create_rejects_bad_input() {
    let h = setup(5_000);
    // recipient == sender
    let r1 = h.client.try_create(
        &h.sender,
        &h.sender,
        &h.arbiter,
        &h.asset,
        &1_000,
        &(START + 100),
        &String::from_str(&h.env, "x"),
    );
    assert_eq!(r1, Err(Ok(Error::InvalidInput)));
    // deadline in the past
    let r2 = h.client.try_create(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &h.asset,
        &1_000,
        &(START - 500),
        &String::from_str(&h.env, "x"),
    );
    assert_eq!(r2, Err(Ok(Error::InvalidInput)));
    // non-positive amount
    let r3 = h.client.try_create(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &h.asset,
        &0,
        &(START + 100),
        &String::from_str(&h.env, "x"),
    );
    assert_eq!(r3, Err(Ok(Error::InvalidAmount)));
    // No successful escrow was created, so the sender keeps every token.
    assert_eq!(balance(&h, &h.sender), 5_000);
}

#[test]
fn timelock_cliff_rejects_early_withdraw_and_claims_post_maturity() {
    let h = setup(10_000);
    let unlock_time = START + 1_000;

    let id = h.client.create_timelock(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &h.asset,
        &10_000,
        &unlock_time,
        &String::from_str(&h.env, "timelock cliff"),
    );
    assert_eq!(id, 1);
    assert_eq!(balance(&h, &h.sender), 0);
    assert_eq!(balance(&h, &h.client.address), 10_000);

    // Pre-maturity check: withdrawal and claim must fail with EscrowLocked
    h.env.ledger().with_mut(|l| l.timestamp = START + 500);
    assert_eq!(h.client.get_claimable_amount(&id), 0);
    assert_eq!(h.client.get_vested_amount(&id), 0);

    let early_claim = h.client.try_claim(&h.recipient, &id);
    assert_eq!(early_claim, Err(Ok(Error::EscrowLocked)));

    let early_withdraw = h.client.try_withdraw(&h.recipient, &id, &5_000);
    assert_eq!(early_withdraw, Err(Ok(Error::EscrowLocked)));

    // Post-maturity check: claim succeeds
    h.env.ledger().with_mut(|l| l.timestamp = unlock_time);
    assert_eq!(h.client.get_claimable_amount(&id), 10_000);
    assert_eq!(h.client.get_vested_amount(&id), 10_000);

    let claimed = h.client.claim(&h.recipient, &id);
    assert_eq!(claimed, 10_000);
    assert_eq!(balance(&h, &h.recipient), 10_000);
    assert_eq!(balance(&h, &h.client.address), 0);
    assert_eq!(h.client.get(&id).state, EscrowState::Released);
    assert_eq!(h.client.get_claimable_amount(&id), 0);
}

#[test]
fn timelock_linear_release_gradual_withdrawals() {
    let h = setup(10_000);
    let start_time = START;
    let cliff_time = START + 200;
    let end_time = START + 1_000;

    let schedule = ReleaseSchedule {
        release_type: ReleaseType::Linear,
        start_time,
        cliff_time,
        end_time,
    };

    let id = h.client.create_scheduled(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &h.asset,
        &10_000,
        &schedule,
        &end_time,
        &String::from_str(&h.env, "linear schedule"),
    );

    // 1. Before cliff (timestamp = START + 100): locked
    h.env.ledger().with_mut(|l| l.timestamp = START + 100);
    assert_eq!(h.client.get_claimable_amount(&id), 0);
    assert_eq!(h.client.get_vested_amount(&id), 0);
    let res = h.client.try_withdraw(&h.recipient, &id, &1_000);
    assert_eq!(res, Err(Ok(Error::EscrowLocked)));

    // 2. At 50% time (timestamp = START + 500, past cliff):
    // 50% of 10,000 = 5,000 vested.
    h.env.ledger().with_mut(|l| l.timestamp = START + 500);
    assert_eq!(h.client.get_vested_amount(&id), 5_000);
    assert_eq!(h.client.get_claimable_amount(&id), 5_000);

    // Partial withdrawal of 3,000
    let total_released = h.client.withdraw(&h.recipient, &id, &3_000);
    assert_eq!(total_released, 3_000);
    assert_eq!(balance(&h, &h.recipient), 3_000);
    assert_eq!(balance(&h, &h.client.address), 7_000);
    assert_eq!(h.client.get_claimable_amount(&id), 2_000);

    // Attempt to withdraw more than currently claimable (3,000 > 2,000)
    let over_withdraw = h.client.try_withdraw(&h.recipient, &id, &3_000);
    assert_eq!(over_withdraw, Err(Ok(Error::InsufficientFunds)));

    // 3. At 80% time (timestamp = START + 800):
    // 80% of 10,000 = 8,000 vested; already released 3,000 => claimable = 5,000.
    h.env.ledger().with_mut(|l| l.timestamp = START + 800);
    assert_eq!(h.client.get_vested_amount(&id), 8_000);
    assert_eq!(h.client.get_claimable_amount(&id), 5_000);

    let next_released = h.client.withdraw(&h.recipient, &id, &5_000);
    assert_eq!(next_released, 8_000);
    assert_eq!(balance(&h, &h.recipient), 8_000);
    assert_eq!(h.client.get_claimable_amount(&id), 0);

    // 4. At 100% maturity (timestamp = START + 1_000):
    // Total vested = 10,000; claimable = 2,000.
    h.env.ledger().with_mut(|l| l.timestamp = START + 1_000);
    assert_eq!(h.client.get_vested_amount(&id), 10_000);
    assert_eq!(h.client.get_claimable_amount(&id), 2_000);

    let claimed = h.client.claim(&h.recipient, &id);
    assert_eq!(claimed, 2_000);
    assert_eq!(balance(&h, &h.recipient), 10_000);
    assert_eq!(balance(&h, &h.client.address), 0);
    assert_eq!(h.client.get(&id).state, EscrowState::Released);
    assert_eq!(h.client.get_claimable_amount(&id), 0);
}

#[test]
fn scheduled_escrow_rejects_bad_schedule_inputs() {
    let h = setup(10_000);

    // start_time > cliff_time
    let s1 = ReleaseSchedule {
        release_type: ReleaseType::Linear,
        start_time: START + 500,
        cliff_time: START + 200,
        end_time: START + 1_000,
    };
    let r1 = h.client.try_create_scheduled(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &h.asset,
        &1_000,
        &s1,
        &(START + 1_000),
        &String::from_str(&h.env, "bad schedule"),
    );
    assert_eq!(r1, Err(Ok(Error::InvalidInput)));

    // cliff_time > end_time
    let s2 = ReleaseSchedule {
        release_type: ReleaseType::Linear,
        start_time: START,
        cliff_time: START + 1_200,
        end_time: START + 1_000,
    };
    let r2 = h.client.try_create_scheduled(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &h.asset,
        &1_000,
        &s2,
        &(START + 1_000),
        &String::from_str(&h.env, "bad schedule"),
    );
    assert_eq!(r2, Err(Ok(Error::InvalidInput)));

    // end_time <= start_time
    let s3 = ReleaseSchedule {
        release_type: ReleaseType::Linear,
        start_time: START + 500,
        cliff_time: START + 500,
        end_time: START + 500,
    };
    let r3 = h.client.try_create_scheduled(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &h.asset,
        &1_000,
        &s3,
        &(START + 500),
        &String::from_str(&h.env, "bad schedule"),
    );
    assert_eq!(r3, Err(Ok(Error::InvalidInput)));

    // deadline < end_time
    let s4 = ReleaseSchedule {
        release_type: ReleaseType::Linear,
        start_time: START,
        cliff_time: START + 100,
        end_time: START + 1_000,
    };
    let r4 = h.client.try_create_scheduled(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &h.asset,
        &1_000,
        &s4,
        &(START + 500),
        &String::from_str(&h.env, "bad schedule"),
    );
    assert_eq!(r4, Err(Ok(Error::InvalidInput)));
}

#[test]
fn timelock_unauthorized_claim_and_withdraw() {
    let h = setup(5_000);
    let id = h.client.create_timelock(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &h.asset,
        &5_000,
        &(START + 500),
        &String::from_str(&h.env, "timelock"),
    );

    let intruder = Address::generate(&h.env);
    h.env.ledger().with_mut(|l| l.timestamp = START + 600);

    let r1 = h.client.try_withdraw(&intruder, &id, &1_000);
    assert_eq!(r1, Err(Ok(Error::Unauthorized)));

    let r2 = h.client.try_claim(&intruder, &id);
    assert_eq!(r2, Err(Ok(Error::Unauthorized)));
}

#[test]
fn timelock_refund_rules() {
    let h = setup(5_000);
    let id = h.client.create_timelock(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &h.asset,
        &5_000,
        &(START + 500),
        &String::from_str(&h.env, "timelock"),
    );

    // Pre-deadline refund attempt fails
    h.env.ledger().with_mut(|l| l.timestamp = START + 200);
    let early = h.client.try_refund_timelock(&h.sender, &id);
    assert_eq!(early, Err(Ok(Error::EscrowLocked)));

    // Non-sender cannot refund
    let intruder = Address::generate(&h.env);
    let unauth = h.client.try_refund_timelock(&intruder, &id);
    assert_eq!(unauth, Err(Ok(Error::Unauthorized)));

    // Post-deadline refund succeeds
    h.env.ledger().with_mut(|l| l.timestamp = START + 600);
    h.client.refund_timelock(&h.sender, &id);
    assert_eq!(h.client.get(&id).state, EscrowState::Refunded);
    assert_eq!(balance(&h, &h.sender), 5_000);
    assert_eq!(balance(&h, &h.client.address), 0);
}

#[test]
fn initialize_and_fund_timelock_lifecycle() {
    let h = setup(5_000);
    let id = h.client.initialize_timelock(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &h.asset,
        &5_000,
        &(START + 500),
        &String::from_str(&h.env, "unfunded"),
    );
    assert_eq!(h.client.get(&id).state, EscrowState::Created);
    assert_eq!(balance(&h, &h.sender), 5_000);
    assert_eq!(balance(&h, &h.client.address), 0);

    // Intruder cannot fund
    let intruder = Address::generate(&h.env);
    let unauth_fund = h.client.try_fund(&intruder, &id);
    assert_eq!(unauth_fund, Err(Ok(Error::Unauthorized)));

    // Sender funds
    h.client.fund(&h.sender, &id);
    assert_eq!(h.client.get(&id).state, EscrowState::Funded);
    assert_eq!(balance(&h, &h.sender), 0);
    assert_eq!(balance(&h, &h.client.address), 5_000);

    // Pre-maturity claim fails
    h.env.ledger().with_mut(|l| l.timestamp = START + 200);
    let early = h.client.try_claim(&h.recipient, &id);
    assert_eq!(early, Err(Ok(Error::EscrowLocked)));

    // Post-maturity claim succeeds
    h.env.ledger().with_mut(|l| l.timestamp = START + 600);
    let claimed = h.client.claim(&h.recipient, &id);
    assert_eq!(claimed, 5_000);
    assert_eq!(balance(&h, &h.recipient), 5_000);
    assert_eq!(h.client.get(&id).state, EscrowState::Released);
}
