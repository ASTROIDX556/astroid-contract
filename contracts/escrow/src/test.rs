use soroban_sdk::{
    testutils::{Address as _, Ledger},
    token, Address, Env, String,
};

use astroid_shared::constants::HOUR_IN_LEDGERS;
use astroid_shared::errors::Error;

use crate::{EscrowContract, EscrowContractClient, EscrowState};

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

// ── Beneficiary proposal helpers ───────────────────────────────────────

fn propose(h: &Harness, caller: &Address, id: u64, new_beneficiary: &Address) {
    h.client.propose_beneficiary(caller, &id, new_beneficiary);
}

fn try_propose(
    h: &Harness,
    caller: &Address,
    id: u64,
    new_beneficiary: &Address,
) -> Result<Result<(), soroban_sdk::ConversionError>, Result<Error, soroban_sdk::InvokeError>> {
    h.client
        .try_propose_beneficiary(caller, &id, new_beneficiary)
}

fn try_claim(
    h: &Harness,
    caller: &Address,
    id: u64,
) -> Result<Result<(), soroban_sdk::ConversionError>, Result<Error, soroban_sdk::InvokeError>> {
    h.client.try_claim_beneficiary(caller, &id)
}

fn advance_ledgers(h: &Harness, delta: u32) {
    h.env.ledger().with_mut(|l| l.sequence_number += delta);
}

// ── Beneficiary proposal tests ─────────────────────────────────────────

#[test]
fn successful_beneficiary_proposal() {
    let h = setup(5_000);
    let id = create(&h, 5_000, START + 100);
    let new_beneficiary = Address::generate(&h.env);

    propose(&h, &h.sender, id, &new_beneficiary);

    let escrow = h.client.get(&id);
    assert!(escrow.proposed_beneficiary.is_some());
    assert_eq!(escrow.proposed_beneficiary.unwrap(), new_beneficiary);
    assert_eq!(escrow.proposed_at_seq, h.env.ledger().sequence());
    // Recipient is unchanged until claim.
    assert_eq!(escrow.recipient, h.recipient);
}

#[test]
fn successful_beneficiary_claim_after_timelock() {
    let h = setup(5_000);
    let id = create(&h, 5_000, START + 100);
    let new_beneficiary = Address::generate(&h.env);

    propose(&h, &h.sender, id, &new_beneficiary);
    advance_ledgers(&h, HOUR_IN_LEDGERS);

    h.client.claim_beneficiary(&new_beneficiary, &id);

    let escrow = h.client.get(&id);
    assert_eq!(escrow.recipient, new_beneficiary);
    assert!(escrow.proposed_beneficiary.is_none());
    // Original recipient no longer has beneficiary rights.
    assert_eq!(h.client.get(&id).recipient, new_beneficiary);
}

#[test]
fn premature_claim_is_rejected() {
    let h = setup(5_000);
    let id = create(&h, 5_000, START + 100);
    let new_beneficiary = Address::generate(&h.env);

    propose(&h, &h.sender, id, &new_beneficiary);

    // Try to claim immediately — not enough ledgers have passed.
    let res = try_claim(&h, &new_beneficiary, id);
    assert_eq!(res, Err(Ok(Error::TimeLockActive)));
    // Recipient unchanged.
    assert_eq!(h.client.get(&id).recipient, h.recipient);
}

#[test]
fn claim_one_ledger_before_boundary_is_rejected() {
    let h = setup(5_000);
    let id = create(&h, 5_000, START + 100);
    let new_beneficiary = Address::generate(&h.env);

    propose(&h, &h.sender, id, &new_beneficiary);
    // Advance to exactly one ledger before the boundary.
    advance_ledgers(&h, HOUR_IN_LEDGERS - 1);

    let res = try_claim(&h, &new_beneficiary, id);
    assert_eq!(res, Err(Ok(Error::TimeLockActive)));
}

#[test]
fn claim_at_exact_boundary_succeeds() {
    let h = setup(5_000);
    let id = create(&h, 5_000, START + 100);
    let new_beneficiary = Address::generate(&h.env);

    propose(&h, &h.sender, id, &new_beneficiary);
    advance_ledgers(&h, HOUR_IN_LEDGERS);

    let res = try_claim(&h, &new_beneficiary, id);
    assert_eq!(res, Ok(Ok(())));
    assert_eq!(h.client.get(&id).recipient, new_beneficiary);
}

#[test]
fn unauthorized_proposal_is_rejected() {
    let h = setup(5_000);
    let id = create(&h, 5_000, START + 100);
    let stranger = Address::generate(&h.env);
    let new_beneficiary = Address::generate(&h.env);

    // Stranger (not sender or arbiter) cannot propose.
    let res = try_propose(&h, &stranger, id, &new_beneficiary);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
}

#[test]
fn unauthorized_claim_is_rejected() {
    let h = setup(5_000);
    let id = create(&h, 5_000, START + 100);
    let new_beneficiary = Address::generate(&h.env);
    let intruder = Address::generate(&h.env);

    propose(&h, &h.sender, id, &new_beneficiary);
    advance_ledgers(&h, HOUR_IN_LEDGERS);

    // Intruder (not the proposed beneficiary) cannot claim.
    let res = try_claim(&h, &intruder, id);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
}

#[test]
fn arbiter_can_propose_beneficiary() {
    let h = setup(5_000);
    let id = create(&h, 5_000, START + 100);
    let new_beneficiary = Address::generate(&h.env);

    propose(&h, &h.arbiter, id, &new_beneficiary);

    let escrow = h.client.get(&id);
    assert!(escrow.proposed_beneficiary.is_some());
    assert_eq!(escrow.proposed_beneficiary.unwrap(), new_beneficiary);
}

#[test]
fn original_beneficiary_retains_rights_before_timelock() {
    let h = setup(5_000);
    let id = create(&h, 5_000, START + 100);
    let new_beneficiary = Address::generate(&h.env);

    propose(&h, &h.sender, id, &new_beneficiary);
    advance_ledgers(&h, HOUR_IN_LEDGERS / 2);

    // Original recipient is still the beneficiary — release still works.
    h.client.release(&h.arbiter, &id);
    assert_eq!(h.client.get(&id).state, EscrowState::Released);
    assert_eq!(balance(&h, &h.recipient), 5_000);
}

#[test]
fn proposed_beneficiary_no_rights_before_timelock() {
    let h = setup(5_000);
    let id = create(&h, 5_000, START + 100);
    let new_beneficiary = Address::generate(&h.env);

    propose(&h, &h.sender, id, &new_beneficiary);

    // The proposed beneficiary cannot release (not the arbiter).
    let res = h.client.try_release(&new_beneficiary, &id);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
}

#[test]
fn proposal_state_cleared_after_claim() {
    let h = setup(5_000);
    let id = create(&h, 5_000, START + 100);
    let new_beneficiary = Address::generate(&h.env);

    propose(&h, &h.sender, id, &new_beneficiary);
    advance_ledgers(&h, HOUR_IN_LEDGERS);
    h.client.claim_beneficiary(&new_beneficiary, &id);

    let escrow = h.client.get(&id);
    assert!(escrow.proposed_beneficiary.is_none());
    assert_eq!(escrow.recipient, new_beneficiary);
}

#[test]
fn repeated_proposal_replaces_previous() {
    let h = setup(5_000);
    let id = create(&h, 5_000, START + 100);
    let first = Address::generate(&h.env);
    let second = Address::generate(&h.env);

    propose(&h, &h.sender, id, &first);
    let seq1 = h.client.get(&id).proposed_at_seq;

    advance_ledgers(&h, 10);
    propose(&h, &h.sender, id, &second);

    let escrow = h.client.get(&id);
    assert_eq!(escrow.proposed_beneficiary.unwrap(), second);
    assert_eq!(escrow.proposed_at_seq, seq1 + 10);
}

#[test]
fn propose_same_beneficiary_again_resets_timelock() {
    let h = setup(5_000);
    let id = create(&h, 5_000, START + 100);
    let new_beneficiary = Address::generate(&h.env);

    propose(&h, &h.sender, id, &new_beneficiary);
    advance_ledgers(&h, HOUR_IN_LEDGERS - 10);

    // Re-propose the same beneficiary — timelock resets.
    propose(&h, &h.sender, id, &new_beneficiary);

    // Advancing 10 more ledgers is no longer enough.
    let res = try_claim(&h, &new_beneficiary, id);
    assert_eq!(res, Err(Ok(Error::TimeLockActive)));
}

#[test]
fn propose_to_current_recipient_rejected() {
    let h = setup(5_000);
    let id = create(&h, 5_000, START + 100);

    // Proposing the current recipient as the new beneficiary is rejected.
    let res = try_propose(&h, &h.sender, id, &h.recipient);
    assert_eq!(res, Err(Ok(Error::InvalidInput)));
}

#[test]
fn propose_to_sender_rejected() {
    let h = setup(5_000);
    let id = create(&h, 5_000, START + 100);

    let res = try_propose(&h, &h.sender, id, &h.sender);
    assert_eq!(res, Err(Ok(Error::InvalidInput)));
}

#[test]
fn propose_to_arbiter_rejected() {
    let h = setup(5_000);
    let id = create(&h, 5_000, START + 100);

    let res = try_propose(&h, &h.sender, id, &h.arbiter);
    assert_eq!(res, Err(Ok(Error::InvalidInput)));
}

#[test]
fn propose_on_released_escrow_rejected() {
    let h = setup(5_000);
    let id = create(&h, 5_000, START + 100);
    let new_beneficiary = Address::generate(&h.env);

    h.client.release(&h.arbiter, &id);

    let res = try_propose(&h, &h.sender, id, &new_beneficiary);
    assert_eq!(res, Err(Ok(Error::InvalidState)));
}

#[test]
fn claim_on_released_escrow_rejected() {
    let h = setup(5_000);
    let id = create(&h, 5_000, START + 100);
    let new_beneficiary = Address::generate(&h.env);

    propose(&h, &h.sender, id, &new_beneficiary);
    advance_ledgers(&h, HOUR_IN_LEDGERS);
    h.client.release(&h.arbiter, &id);

    // Re-reading the released escrow — recipient is still the original
    // because release uses the pre-proposal recipient. Trying to claim after
    // release is rejected because state is no longer Created/Funded.
    let res = try_claim(&h, &new_beneficiary, id);
    assert_eq!(res, Err(Ok(Error::InvalidState)));
}

#[test]
fn claim_without_proposal_rejected() {
    let h = setup(5_000);
    let id = create(&h, 5_000, START + 100);
    let anyone = Address::generate(&h.env);

    advance_ledgers(&h, HOUR_IN_LEDGERS);
    let res = try_claim(&h, &anyone, id);
    assert_eq!(res, Err(Ok(Error::InvalidState)));
}

#[test]
fn proposal_on_timelock_escrow_works() {
    let h = setup(0);
    let new_beneficiary = Address::generate(&h.env);
    let unlock_time = START + 100;

    let id = h.client.initialize_timelock(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &h.asset,
        &5_000,
        &unlock_time,
        &String::from_str(&h.env, "locked"),
    );

    propose(&h, &h.sender, id, &new_beneficiary);
    let escrow = h.client.get(&id);
    assert!(escrow.proposed_beneficiary.is_some());
    assert_eq!(escrow.proposed_beneficiary.unwrap(), new_beneficiary);
}

#[test]
fn claim_on_timelock_escrow_after_timelock() {
    let h = setup(0);
    let new_beneficiary = Address::generate(&h.env);
    let unlock_time = START + 100;

    let id = h.client.initialize_timelock(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &h.asset,
        &5_000,
        &unlock_time,
        &String::from_str(&h.env, "locked"),
    );

    propose(&h, &h.sender, id, &new_beneficiary);
    advance_ledgers(&h, HOUR_IN_LEDGERS);

    h.client.claim_beneficiary(&new_beneficiary, &id);
    assert_eq!(h.client.get(&id).recipient, new_beneficiary);
}

#[test]
fn new_beneficiary_can_release_after_claim() {
    let h = setup(5_000);
    let id = create(&h, 5_000, START + 86_400);
    let new_beneficiary = Address::generate(&h.env);

    propose(&h, &h.sender, id, &new_beneficiary);
    advance_ledgers(&h, HOUR_IN_LEDGERS);
    h.client.claim_beneficiary(&new_beneficiary, &id);

    // The new beneficiary is now the recipient — arbiter releases to them.
    h.client.release(&h.arbiter, &id);
    assert_eq!(h.client.get(&id).state, EscrowState::Released);
    assert_eq!(balance(&h, &new_beneficiary), 5_000);
}

#[test]
fn propose_and_claim_event_emission() {
    let h = setup(5_000);
    let id = create(&h, 5_000, START + 100);
    let new_beneficiary = Address::generate(&h.env);

    propose(&h, &h.sender, id, &new_beneficiary);
    advance_ledgers(&h, HOUR_IN_LEDGERS);
    h.client.claim_beneficiary(&new_beneficiary, &id);

    // Verify final state is consistent.
    let escrow = h.client.get(&id);
    assert_eq!(escrow.recipient, new_beneficiary);
    assert!(escrow.proposed_beneficiary.is_none());
    assert_eq!(escrow.state, EscrowState::Funded);
}
