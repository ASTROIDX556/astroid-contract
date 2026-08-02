use soroban_sdk::{testutils::Address as _, Address, Env, String};

use crate::{TreasuryContract, TreasuryContractClient};

fn create_treasury<'a>(
    env: &Env,
    org: &str,
    admin: &Address,
) -> TreasuryContractClient<'a> {
    let id = env.register(TreasuryContract, ());
    let client = TreasuryContractClient::new(env, &id);
    client.initialize(&String::from_str(env, org), admin);
    client
}

#[test]
fn full_flow_deposit_allocate_withdraw() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let asset = Address::generate(&env);
    let recipient = Address::generate(&env);
    let t = create_treasury(&env, "vault", &admin);

    t.deposit(&admin, &asset, &1_000);
    assert_eq!(t.holding(&asset).total_in, 1_000);

    t.allocate_budget(&admin, &asset, &String::from_str(&env, "maint"));

    t.withdraw(&admin, &asset, &recipient, &400);
    let h = t.holding(&asset);
    assert_eq!(h.total_in, 600);
    assert_eq!(h.total_out, 400);
}

#[test]
#[should_panic]
fn withdraw_panics_when_not_admin() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let intruder = Address::generate(&env);
    let asset = Address::generate(&env);
    let t = create_treasury(&env, "vault", &admin);

    t.deposit(&admin, &asset, &500);
    // intruder is not the admin
    t.withdraw(&intruder, &asset, &Address::generate(&env), &100);
}

#[test]
#[should_panic(expected = "InsufficientFunds")]
fn withdraw_overdraws() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let asset = Address::generate(&env);
    let t = create_treasury(&env, "vault", &admin);

    t.deposit(&admin, &asset, &50);
    t.withdraw(&admin, &asset, &Address::generate(&env), &100);
}

#[test]
#[should_panic]
fn frozen_treasury_rejects_withdrawals() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let asset = Address::generate(&env);
    let t = create_treasury(&env, "vault", &admin);

    t.deposit(&admin, &asset, &1_000);
    t.freeze(&admin);
    t.withdraw(&admin, &asset, &Address::generate(&env), &10);
}

#[test]
fn prepare_holds_state() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let t = create_treasury(&env, "vault", &admin);
    let state = t.get();
    assert_eq!(state.org.to_string(), "vault");
}
