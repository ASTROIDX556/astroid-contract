use soroban_sdk::{testutils::Address as _, testutils::Ledger, Address, BytesN, Env, String};

use crate::{PolicyContract, PolicyContractClient};

fn setup<'a>(env: &Env, owner: &Address) -> PolicyContractClient<'a> {
    let id = env.register_contract(None, PolicyContract);
    let client = PolicyContractClient::new(env, &id);
    client.initialize(owner);
    client.register_policy(
        owner,
        &String::from_str(env, "max_txn"),
        &BytesN::from_array(env, &[42; 32]),
        &1_000_000,
        &None,
        &None,
        &0,
    );
    client
}

#[test]
fn allows_spend_below_max() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);
    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &recip, &999_999,)
        .is_ok());
}

#[test]
fn denies_spend_above_max() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);
    let r = p.try_check_transfer(
        &String::from_str(&env, "max_txn"),
        &asset,
        &recip,
        &1_000_001,
    );
    assert!(r.is_err());
}

#[test]
fn allowlist_recipient_enforced() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let allowed = Address::generate(&env);
    let blocked = Address::generate(&env);
    let asset = Address::generate(&env);
    let id = env.register_contract(None, PolicyContract);
    let client = PolicyContractClient::new(&env, &id);
    client.initialize(&owner);
    client.register_policy(
        &owner,
        &String::from_str(&env, "vendor_list"),
        &BytesN::from_array(&env, &[7; 32]),
        &0,
        &Some(allowed.clone()),
        &None,
        &0,
    );

    // Allowed recipient passes
    assert!(client
        .try_check_transfer(&String::from_str(&env, "vendor_list"), &asset, &allowed, &1,)
        .is_ok());

    // Other recipient denied
    assert!(client
        .try_check_transfer(&String::from_str(&env, "vendor_list"), &asset, &blocked, &1,)
        .is_err());
}

#[test]
fn disable_denies_everything() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    p.set_enabled(&owner, &String::from_str(&env, "max_txn"), &false);
    assert!(p
        .try_check_transfer(
            &String::from_str(&env, "max_txn"),
            &asset,
            &Address::generate(&env),
            &1,
        )
        .is_err());
}

#[test]
fn pause_blocks_evaluation_and_unpause_resumes() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000);
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    // Not paused initially: evaluation succeeds.
    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &recip, &1,)
        .is_ok());
    assert!(!p.paused());

    // Admin pauses for a bounded duration.
    p.pause(&owner, &500);
    assert!(p.paused());
    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &recip, &1,)
        .is_err());

    // After the pause window elapses, evaluations resume.
    env.ledger().set_timestamp(1_500);
    assert!(!p.paused());
    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &recip, &1,)
        .is_ok());
}

#[test]
fn indefinite_pause_requires_unpause() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(1_000);
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    let asset = Address::generate(&env);
    let recip = Address::generate(&env);

    // duration == 0 => indefinite pause.
    p.pause(&owner, &0);
    assert!(p.paused());
    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &recip, &1,)
        .is_err());

    // Time passing does not lift an indefinite pause.
    env.ledger().set_timestamp(1_000_000);
    assert!(p.paused());

    // Only an explicit unpause restores evaluation.
    p.unpause(&owner);
    assert!(!p.paused());
    assert!(p
        .try_check_transfer(&String::from_str(&env, "max_txn"), &asset, &recip, &1,)
        .is_ok());
}

#[test]
fn pause_duration_cap_enforced() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let p = setup(&env, &owner);
    // Exceeding MAX_PAUSE_DURATION (30 days) is rejected.
    let res = p.try_pause(&owner, &(2_592_000 + 1));
    assert!(res.is_err());
    assert!(!p.paused());
}

#[test]
fn only_admin_can_pause() {
    let env = Env::default();
    env.mock_all_auths();
    let owner = Address::generate(&env);
    let intruder = Address::generate(&env);
    let p = setup(&env, &owner);
    let res = p.try_pause(&intruder, &100);
    assert!(res.is_err());
    assert!(!p.paused());
}
