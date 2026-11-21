//! Standardized escrow settlement events, observed from outside the crate
//! (Issue #536).
//!
//! Off-chain indexers and agent dashboards follow escrow settlement through
//! two events defined once in `shared/src/events.rs`:
//!
//! | Topic                              | Emitted by                                  |
//! |------------------------------------|---------------------------------------------|
//! | `("escrow", "fund_rel", escrow_id)` | `release`, `override_release`               |
//! | `("escrow", "fund_ref", escrow_id)` | `refund`, `refund_timelock`, `cancel`, `reclaim` |
//!
//! Both carry the same [`EscrowSettlement`] payload: escrow id, the account
//! the funds moved to, the custody value moved and the ledger timestamp.
//!
//! These scenarios deploy the escrow next to a real SAC token and check what
//! a subscriber actually sees: the exact topics and payload, the escrow id
//! in the topic so one escrow can be followed without decoding payloads, and
//! that the amount an event reports matches the tokens that moved.

use astroid_escrow::{EscrowContract, EscrowContractClient, EscrowState};
use astroid_shared::events::{EscrowSettlement, ESCROW_FUNDS_REFUNDED, ESCROW_FUNDS_RELEASED};
use astroid_shared::types::AssetAmount;
use soroban_sdk::{
    symbol_short,
    testutils::{Address as _, Events as _, Ledger},
    token, vec, Address, Env, IntoVal, String, Symbol, TryFromVal, Val, Vec,
};

const START: u64 = 10_000;
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

fn create(h: &Harness, amount: i128, deadline: u64) -> u64 {
    let assets: Vec<AssetAmount> = vec![
        &h.env,
        AssetAmount {
            asset: h.asset.clone(),
            amount,
        },
    ];
    h.escrow.create(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &assets,
        &deadline,
        &0,
        &String::from_str(&h.env, "settlement"),
        &Vec::new(&h.env),
        &0,
    )
}

fn balance(h: &Harness, who: &Address) -> i128 {
    token::TokenClient::new(&h.env, &h.asset).balance(who)
}

/// Every settlement event the escrow has published in this `Env`,
/// as `(action, escrow id from the topic, decoded payload)`.
fn settlements(h: &Harness) -> std::vec::Vec<(Symbol, u64, EscrowSettlement)> {
    let escrow_sym: Val = symbol_short!("escrow").into_val(&h.env);
    h.env
        .events()
        .all()
        .iter()
        .filter(|(contract, topics, _)| {
            *contract == h.escrow.address
                && topics.len() == 3
                && topics.get(0).unwrap().get_payload() == escrow_sym.get_payload()
        })
        .filter_map(|(_, topics, data)| {
            let action = Symbol::try_from_val(&h.env, &topics.get(1).unwrap()).ok()?;
            if action != ESCROW_FUNDS_RELEASED && action != ESCROW_FUNDS_REFUNDED {
                return None;
            }
            let id = u64::try_from_val(&h.env, &topics.get(2).unwrap()).ok()?;
            let payload = EscrowSettlement::try_from_val(&h.env, &data).ok()?;
            Some((action, id, payload))
        })
        .collect()
}

#[test]
fn release_publishes_indexed_fund_released_event_matching_the_payout() {
    let h = setup();
    let id = create(&h, AMOUNT, START + 1_000);

    h.env.ledger().with_mut(|l| l.timestamp = START + 10);
    h.escrow.release(&h.arbiter, &id, &AMOUNT);

    let events = settlements(&h);
    assert_eq!(events.len(), 1);
    let (action, topic_id, payload) = events[0].clone();
    assert_eq!(action, ESCROW_FUNDS_RELEASED);
    assert_eq!(topic_id, id);
    assert_eq!(
        payload,
        EscrowSettlement {
            escrow_id: id,
            recipient: h.recipient.clone(),
            amount: AMOUNT,
            timestamp: START + 10,
        }
    );
    // The reported amount is exactly what reached the recipient.
    assert_eq!(balance(&h, &h.recipient), payload.amount);
    assert_eq!(h.escrow.get(&id).state, EscrowState::Released);
}

#[test]
fn refund_publishes_indexed_fund_refunded_event_matching_the_return() {
    let h = setup();
    let id = create(&h, AMOUNT, START + 100);
    let before = balance(&h, &h.sender);

    h.env.ledger().with_mut(|l| l.timestamp = START + 100);
    h.escrow.refund(&h.sender, &id);

    let events = settlements(&h);
    assert_eq!(events.len(), 1);
    let (action, topic_id, payload) = events[0].clone();
    assert_eq!(action, ESCROW_FUNDS_REFUNDED);
    assert_eq!(topic_id, id);
    assert_eq!(
        payload,
        EscrowSettlement {
            escrow_id: id,
            recipient: h.sender.clone(),
            amount: AMOUNT,
            timestamp: START + 100,
        }
    );
    assert_eq!(balance(&h, &h.sender) - before, payload.amount);
    assert_eq!(h.escrow.get(&id).state, EscrowState::Refunded);
}

#[test]
fn settlement_topics_carry_the_escrow_id_so_escrows_can_be_followed_separately() {
    let h = setup();
    let first = create(&h, AMOUNT, START + 1_000);
    let second = create(&h, AMOUNT / 2, START + 1_000);

    // Settle the second escrow first: its event must name it, not the first.
    h.escrow.cancel(&h.sender, &second);
    let events = settlements(&h);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].0, ESCROW_FUNDS_REFUNDED);
    assert_eq!(events[0].1, second);
    assert_eq!(events[0].2.escrow_id, second);
    assert_eq!(events[0].2.amount, AMOUNT / 2);

    h.escrow.release(&h.arbiter, &first, &AMOUNT);
    // Filtering on the topic's escrow id isolates each escrow's history.
    let for_first: std::vec::Vec<_> = settlements(&h)
        .into_iter()
        .filter(|(_, topic_id, _)| *topic_id == first)
        .collect();
    assert_eq!(for_first.len(), 1);
    assert_eq!(for_first[0].0, ESCROW_FUNDS_RELEASED);
    assert_eq!(for_first[0].2.escrow_id, first);
    assert_eq!(for_first[0].2.amount, AMOUNT);
    assert!(settlements(&h)
        .iter()
        .filter(|(_, topic_id, _)| *topic_id == second)
        .all(|(action, _, _)| *action == ESCROW_FUNDS_REFUNDED));
}

#[test]
fn a_refused_settlement_publishes_nothing() {
    let h = setup();
    let id = create(&h, AMOUNT, START + 1_000);

    // Releasing past the deadline is refused; the invocation rolls back and
    // no settlement event reaches the log.
    h.env.ledger().with_mut(|l| l.timestamp = START + 2_000);
    assert!(h.escrow.try_release(&h.arbiter, &id, &AMOUNT).is_err());
    assert!(settlements(&h).is_empty());
    assert_eq!(balance(&h, &h.escrow.address), AMOUNT);
}
