use soroban_sdk::{
    testutils::{Address as _, Ledger},
    Address, Env, String,
};

use crate::{EscrowContract, EscrowContractClient};

fn setup<'a>(env: &Env) -> EscrowContractClient<'a> {
    let id = env.register(EscrowContract, ());
    let client = EscrowContractClient::new(env, &id);
    client.initialize();
    client
}

#[test]
fn full_cycle_create_release() {
    let env = Env::default();
    env.mock_all_auths();
    let c = setup(&env);
    let sender = Address::generate(&env);
    let recipient = Address::generate(&env);
    let arbiter = Address::generate(&env);
    let asset = Address::generate(&env);

    let ledger_ts = 1_000u64;
    env.ledger().with_mut(|l| l.timestamp = ledger_ts);

    let id = c.create(
        &sender,
        &recipient,
        &arbiter,
        &asset,
        &10_000,
        &(ledger_ts + 86_400), // +1d deadline
        &String::from_str(&env, "payment"),
    );
    assert_eq!(id, 1);

    let escrow = c.get(&id);
    assert_eq!(escrow.amount, 10_000);
    assert_eq!(escrow.state as u32, crate::EscrowState::Funded as u32);

    c.release(&arbiter, &id);
    let escrow = c.get(&id);
    assert_eq!(escrow.state as u32, crate::EscrowState::Released as u32);

    c.close(&sender, &id);
    let escrow = c.get(&id);
    assert_eq!(escrow.state as u32, crate::EscrowState::Closed as u32);
}

#[test]
#[should_panic]
fn non_arbiter_can_not_release() {
    let env = Env::default();
    env.mock_all_auths();
    let c = setup(&env);
    let sender = Address::generate(&env);
    let recipient = Address::generate(&env);
    let arbiter = Address::generate(&env);
    let intruder = Address::generate(&env);
    let asset = Address::generate(&env);

    let ts = 1_000u64;
    env.ledger().with_mut(|l| l.timestamp = ts);
    let id = c.create(
        &sender,
        &recipient,
        &arbiter,
        &asset,
        &5_000,
        &(ts + 100),
        &String::from_str(&env, "m1"),
    );

    c.release(&intruder, &id);
}

#[test]
#[should_panic(expected = "EscrowExpired")]
fn release_after_deadline_expires_it() {
    let env = Env::default();
    env.mock_all_auths();
    let c = setup(&env);
    let sender = Address::generate(&env);
    let recipient = Address::generate(&env);
    let arbiter = Address::generate(&env);
    let asset = Address::generate(&env);

    let ts = 1_000u64;
    env.ledger().with_mut(|l| l.timestamp = ts);
    let id = c.create(
        &sender,
        &recipient,
        &arbiter,
        &asset,
        &5_000,
        &(ts + 100),
        &String::from_str(&env, "m1"),
    );

    env.ledger().with_mut(|l| l.timestamp = ts + 200);
    c.release(&arbiter, &id);
}

#[test]
fn refund_after_deadline_is_open_to_caller() {
    let env = Env::default();
    env.mock_all_auths();
    let c = setup(&env);
    let sender = Address::generate(&env);
    let recipient = Address::generate(&env);
    let arbiter = Address::generate(&env);
    let asset = Address::generate(&env);

    let ts = 1_000u64;
    env.ledger().with_mut(|l| l.timestamp = ts);
    let id = c.create(
        &sender,
        &recipient,
        &arbiter,
        &asset,
        &5_000,
        &(ts + 100),
        &String::from_str(&env, "m1"),
    );

    env.ledger().with_mut(|l| l.timestamp = ts + 200);
    c.refund(&sender, &id);
    let escrow = c.get(&id);
    assert_eq!(escrow.state as u32, crate::EscrowState::Refunded as u32);
}
