//! Expiration and storage cleanup of escrow contracts, observed from outside
//! the escrow crate (Issue #521).
//!
//! A timed-out escrow used to keep its record, milestone schedule, release
//! condition and participant approvals on the ledger indefinitely, with the
//! unclaimed custody still sitting in the contract. `cleanup_expired` reads the
//! ledger timestamp, refuses escrows that are still live, refunds the remainder
//! to the sender, removes every entry owned by the escrow and publishes the
//! shared `EscrowExpired` event.
//!
//! These tests deploy the escrow next to a real SAC token and verify the whole
//! behaviour a subscriber or keeper sees: the timestamp guards, the balance
//! movement, the freed storage (including release-condition metadata), the
//! typed event payload and the refusal to refund twice.

use astroid_escrow::{EscrowContract, EscrowContractClient, ReleaseConditionConfig};
use astroid_shared::errors::Error;
use astroid_shared::events::{EscrowExpiration, EscrowSettlement, ESCROW_FUNDS_REFUNDED};
use astroid_shared::types::AssetAmount;
use soroban_sdk::{
    testutils::{Address as _, Events as _, Ledger},
    token, vec, Address, Env, IntoVal, String, Symbol, TryFromVal, Val, Vec,
};

const START: u64 = 10_000;
const GRACE: u64 = 500;
const AMOUNT: i128 = 8_000;

struct Harness<'a> {
    env: Env,
    escrow: EscrowContractClient<'a>,
    sender: Address,
    recipient: Address,
    arbiter: Address,
    asset: Address,
}

fn setup() -> Harness<'static> {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().with_mut(|l| l.timestamp = START);

    let admin = Address::generate(&env);
    let escrow_id = env.register_contract(None, EscrowContract);
    let escrow = EscrowContractClient::new(&env, &escrow_id);
    escrow.initialize(&admin);

    let asset = env
        .register_stellar_asset_contract_v2(Address::generate(&env))
        .address();
    escrow.approve_token(&admin, &asset);

    let sender = Address::generate(&env);
    token::StellarAssetClient::new(&env, &asset).mint(&sender, &(AMOUNT * 4));
    let recipient = Address::generate(&env);
    let arbiter = Address::generate(&env);

    Harness {
        env,
        escrow,
        sender,
        recipient,
        arbiter,
        asset,
    }
}

fn assets(h: &Harness) -> Vec<AssetAmount> {
    vec![
        &h.env,
        AssetAmount {
            asset: h.asset.clone(),
            amount: AMOUNT,
        },
    ]
}

fn create(h: &Harness, deadline: u64, grace: u64, refund_window: u64) -> u64 {
    h.escrow.create_with_refund_window(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &assets(h),
        &deadline,
        &grace,
        &refund_window,
        &String::from_str(&h.env, "expiry-cleanup"),
        &Vec::new(&h.env),
        &0,
    )
}

fn create_with_condition(h: &Harness, deadline: u64) -> (u64, Address) {
    let participant = Address::generate(&h.env);
    let config = ReleaseConditionConfig {
        sender: h.sender.clone(),
        recipient: h.recipient.clone(),
        arbiter: h.arbiter.clone(),
        assets: assets(h),
        deadline,
        grace_period: GRACE,
        refund_window: 0,
        memo: String::from_str(&h.env, "conditioned"),
        override_signers: Vec::new(&h.env),
        override_threshold: 0,
        participants: vec![&h.env, participant.clone()],
        approval_threshold: 1,
    };
    (h.escrow.create_with_release_condition(&config), participant)
}

fn balance(h: &Harness, who: &Address) -> i128 {
    token::TokenClient::new(&h.env, &h.asset).balance(who)
}

fn expirations(h: &Harness) -> std::vec::Vec<EscrowExpiration> {
    let topic: Val = Symbol::new(&h.env, "EscrowExpired").into_val(&h.env);
    h.env
        .events()
        .all()
        .iter()
        .filter(|(contract, topics, _)| *contract == h.escrow.address && topics.contains(topic))
        .filter_map(|(_, _, data)| EscrowExpiration::try_from_val(&h.env, &data).ok())
        .collect()
}

fn refund_settlements(h: &Harness, id: u64) -> std::vec::Vec<EscrowSettlement> {
    let action: Val = ESCROW_FUNDS_REFUNDED.into_val(&h.env);
    let escrow_sym: Val = soroban_sdk::symbol_short!("escrow").into_val(&h.env);
    h.env
        .events()
        .all()
        .iter()
        .filter(|(contract, topics, _)| {
            *contract == h.escrow.address
                && topics.len() == 3
                && topics.get(0).unwrap().get_payload() == escrow_sym.get_payload()
                && topics.get(1).unwrap().get_payload() == action.get_payload()
        })
        .filter_map(|(_, topics, data)| {
            let event_id = u64::try_from_val(&h.env, &topics.get(2).unwrap()).ok()?;
            if event_id != id {
                return None;
            }
            EscrowSettlement::try_from_val(&h.env, &data).ok()
        })
        .collect()
}

#[test]
fn cleanup_expired_before_expiration_is_rejected() {
    let h = setup();
    let id = create(&h, START + 100, GRACE, 0);

    assert_eq!(
        h.escrow.try_cleanup_expired(&id),
        Err(Ok(Error::EscrowNotExpired))
    );
    assert_eq!(h.escrow.get(&id).state, astroid_escrow::EscrowState::Funded);
    assert_eq!(balance(&h, &h.sender), AMOUNT * 3);
    assert_eq!(balance(&h, &h.escrow.address), AMOUNT);
}

#[test]
fn cleanup_expired_during_grace_is_rejected() {
    let h = setup();
    let deadline = START + 100;
    let id = create(&h, deadline, GRACE, 0);

    h.env.ledger().with_mut(|l| l.timestamp = deadline + 1);
    assert_eq!(
        h.escrow.try_cleanup_expired(&id),
        Err(Ok(Error::GraceActive))
    );
    assert_eq!(h.escrow.get(&id).state, astroid_escrow::EscrowState::Funded);
    assert_eq!(balance(&h, &h.escrow.address), AMOUNT);
}

#[test]
fn cleanup_expired_refunds_unclaimed_funds_and_frees_storage() {
    let h = setup();
    let deadline = START + 100;
    let id = create(&h, deadline, GRACE, 0);

    h.env.ledger().with_mut(|l| l.timestamp = deadline + GRACE);

    h.escrow.cleanup_expired(&id);

    assert_eq!(balance(&h, &h.sender), AMOUNT * 4);
    assert_eq!(balance(&h, &h.escrow.address), 0);
    assert_eq!(h.escrow.try_get(&id), Err(Ok(Error::NotFound)));
    assert_eq!(
        h.escrow.try_cleanup_expired(&id),
        Err(Ok(Error::NotFound)),
        "a second cleanup cannot refund the same custody twice"
    );

    let expired = expirations(&h);
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].escrow_id, id);
    assert_eq!(expired[0].sender, h.sender);
    assert_eq!(expired[0].amount, AMOUNT);
    assert_eq!(expired[0].expired_at, deadline + GRACE);

    let refunds = refund_settlements(&h, id);
    assert_eq!(refunds.len(), 1);
    assert_eq!(refunds[0].recipient, h.sender);
    assert_eq!(refunds[0].amount, AMOUNT);
    assert_eq!(refunds[0].timestamp, deadline + GRACE);
}

#[test]
fn cleanup_expired_removes_release_condition_and_approval_entries() {
    let h = setup();
    let deadline = START + 100;
    let (id, participant) = create_with_condition(&h, deadline);
    h.escrow.approve_release(&participant, &id);
    assert_eq!(h.escrow.release_approvals(&id).len(), 1);

    h.env.ledger().with_mut(|l| l.timestamp = deadline + GRACE);
    h.escrow.cleanup_expired(&id);

    assert_eq!(
        h.escrow.try_get_release_condition(&id),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(
        h.escrow.try_release_approvals(&id),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(h.escrow.try_get(&id), Err(Ok(Error::NotFound)));
    assert_eq!(balance(&h, &h.sender), AMOUNT * 4);
}

#[test]
fn expire_then_cleanup_publishes_one_expiration_event() {
    let h = setup();
    let deadline = START + 100;
    let id = create(&h, deadline, GRACE, 0);

    h.env.ledger().with_mut(|l| l.timestamp = deadline + GRACE);
    h.escrow.expire(&id);
    assert_eq!(expirations(&h).len(), 1);

    h.escrow.cleanup_expired(&id);

    assert_eq!(expirations(&h).len(), 1, "expire already announced it");
    assert_eq!(h.escrow.try_get(&id), Err(Ok(Error::NotFound)));
    assert_eq!(balance(&h, &h.sender), AMOUNT * 4);
}

#[test]
fn cleanup_expired_respects_the_refund_window() {
    let h = setup();
    let deadline = START + 100;
    let window = 50;
    let id = create(&h, deadline, 0, window);

    h.env.ledger().with_mut(|l| l.timestamp = deadline + window);
    assert_eq!(
        h.escrow.try_cleanup_expired(&id),
        Err(Ok(Error::EscrowExpired))
    );
    assert_eq!(h.escrow.get(&id).state, astroid_escrow::EscrowState::Funded);
    assert_eq!(balance(&h, &h.escrow.address), AMOUNT);
}

#[test]
fn cleanup_expired_is_permissionless() {
    let h = setup();
    let deadline = START + 100;
    let id = create(&h, deadline, GRACE, 0);

    h.env.ledger().with_mut(|l| l.timestamp = deadline + GRACE);
    h.env.set_auths(&[]);
    h.escrow.cleanup_expired(&id);

    assert!(h.env.auths().is_empty());
    assert_eq!(balance(&h, &h.sender), AMOUNT * 4);
}
