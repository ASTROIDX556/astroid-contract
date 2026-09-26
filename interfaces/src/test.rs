#![cfg(test)]
//! Unit tests for the proposal lifecycle interface.
//!
//! These pin the two guarantees cross-contract consumers depend on: the
//! `#[contracttype]` encoding round-trips through the Soroban conversion rules,
//! and every state's `u32` discriminant is frozen (it is the value stored
//! on-chain and decoded by every generated client).

use crate::proposal::{ProposalClient, ProposalState};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{vec, Env, IntoVal, TryFromVal, Val, Vec};

/// The full lifecycle, in discriminant order, so every test can sweep it.
const ALL_STATES: [ProposalState; 9] = [
    ProposalState::Created,
    ProposalState::Pending,
    ProposalState::Approved,
    ProposalState::Executed,
    ProposalState::Closed,
    ProposalState::Rejected,
    ProposalState::Cancelled,
    ProposalState::Expired,
    ProposalState::Failed,
];

// ---------------------------------------------------------------------------
// Deterministic discriminants
// ---------------------------------------------------------------------------

#[test]
fn discriminants_are_stable() {
    // These numbers are part of the public ABI: the contract stores them and
    // off-chain indexers decode them. Renumbering any of them is breaking.
    assert_eq!(ProposalState::Created as u32, 0);
    assert_eq!(ProposalState::Pending as u32, 1);
    assert_eq!(ProposalState::Approved as u32, 2);
    assert_eq!(ProposalState::Executed as u32, 3);
    assert_eq!(ProposalState::Closed as u32, 4);
    assert_eq!(ProposalState::Rejected as u32, 5);
    assert_eq!(ProposalState::Cancelled as u32, 6);
    assert_eq!(ProposalState::Expired as u32, 7);
    assert_eq!(ProposalState::Failed as u32, 8);
}

#[test]
fn discriminants_are_distinct() {
    // A duplicate discriminant would collapse two states into one on-chain
    // value and silently corrupt every status query.
    let mut seen: Vec<u32> = Vec::new(&Env::default());
    for state in ALL_STATES.iter() {
        let code = state.clone() as u32;
        assert!(!seen.contains(code), "duplicate discriminant {code}");
        seen.push_back(code);
    }
}

// ---------------------------------------------------------------------------
// Serialization / deserialization
// ---------------------------------------------------------------------------

#[test]
fn every_state_round_trips_through_soroban_encoding() {
    let env = Env::default();
    for state in ALL_STATES.iter() {
        let encoded: Val = state.clone().into_val(&env);
        let decoded = ProposalState::try_from_val(&env, &encoded).unwrap();
        assert_eq!(decoded, state.clone());
    }
}

#[test]
fn encoded_value_is_the_u32_discriminant() {
    let env = Env::default();
    // `#[contracttype]` unit enums encode as `ScVal::U32(discriminant)`; the
    // hand-built value must be indistinguishable from the derived one.
    for state in ALL_STATES.iter() {
        let encoded: Val = state.clone().into_val(&env);
        let code = u32::try_from_val(&env, &encoded).expect("unit enum encodes as a u32");
        assert_eq!(code, state.clone() as u32);
    }
}

#[test]
fn unknown_discriminant_is_rejected() {
    let env = Env::default();
    // Nothing in the table above sits at 9, so decoding it must fail rather
    // than silently inventing a tenth state.
    let unknown: Val = 9u32.into_val(&env);
    assert!(ProposalState::try_from_val(&env, &unknown).is_err());

    let far_out: Val = u32::MAX.into_val(&env);
    assert!(ProposalState::try_from_val(&env, &far_out).is_err());
}

#[test]
fn states_round_trip_inside_a_vec() {
    // Real payloads carry states in collections (e.g. a batch status read), so
    // the element encoding must survive the container round-trip too.
    let env = Env::default();
    let states = vec![
        &env,
        ProposalState::Pending,
        ProposalState::Approved,
        ProposalState::Executed,
        ProposalState::Failed,
    ];
    let encoded: Val = states.clone().into_val(&env);
    let decoded: soroban_sdk::Vec<ProposalState> =
        soroban_sdk::Vec::try_from_val(&env, &encoded).unwrap();
    assert_eq!(decoded, states);
}

#[test]
fn generated_client_compiles_against_the_env() {
    // Pins that `#[contractclient]` generated a usable client constructor for
    // the trait; the call itself is never executed.
    let env = Env::default();
    let id = soroban_sdk::Address::generate(&env);
    let _client = ProposalClient::new(&env, &id);
}

// ---------------------------------------------------------------------------
// Status helpers
// ---------------------------------------------------------------------------

#[test]
fn has_executed_covers_completion_states() {
    for state in ALL_STATES.iter() {
        let expected = matches!(state, ProposalState::Executed | ProposalState::Closed);
        assert_eq!(state.clone().has_executed(), expected);
    }
    // The two states downstream chaining cares about.
    assert!(ProposalState::Executed.has_executed());
    assert!(ProposalState::Closed.has_executed());
    assert!(!ProposalState::Approved.has_executed());
    assert!(!ProposalState::Failed.has_executed());
}

#[test]
fn deposit_settled_covers_refund_and_completion_states() {
    for state in ALL_STATES.iter() {
        let expected = matches!(
            state,
            ProposalState::Expired
                | ProposalState::Rejected
                | ProposalState::Cancelled
                | ProposalState::Executed
                | ProposalState::Closed
        );
        assert_eq!(state.clone().deposit_settled(), expected);
    }
    // Still holding the proposer's deposit: these may not be purged.
    assert!(!ProposalState::Pending.deposit_settled());
    assert!(!ProposalState::Approved.deposit_settled());
    assert!(!ProposalState::Failed.deposit_settled());
}

#[test]
fn live_and_terminal_partition_the_lifecycle() {
    for state in ALL_STATES.iter() {
        // `Created` is neither live nor terminal; every other state is one or
        // the other, never both.
        if state.clone() == ProposalState::Created {
            assert!(!state.clone().is_live());
            assert!(!state.clone().is_terminal());
            continue;
        }
        assert_ne!(state.clone().is_live(), state.clone().is_terminal());
    }
    assert!(ProposalState::Pending.is_live());
    assert!(ProposalState::Approved.is_live());
    assert!(ProposalState::Executed.is_terminal());
    assert!(ProposalState::Expired.is_terminal());
}
