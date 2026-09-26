//! Time-locked release verification across contract boundaries (Issue #332).
//!
//! The escrow's unit tests cover the full schedule matrix; these scenarios
//! drive the release paths through *deployed contract boundaries* from outside
//! the escrow crate, advancing the ledger clock step by step to prove that an
//! early release fails with the distinct `TimelockNotExpired` code
//! (`ERR_ESCROW_NOT_READY`) and succeeds only once the configured release time
//! has passed.

use astroid_escrow::{EscrowContract, EscrowContractClient, EscrowState};
use astroid_shared::errors::Error;
use astroid_shared::types::AssetAmount;
use soroban_sdk::testutils::{Address as _, Ledger};
use soroban_sdk::{token, vec, Address, Env, String, Vec};

const START: u64 = 1_000;

struct Harness {
    env: Env,
    escrow: EscrowContractClient<'static>,
    asset: Address,
    sender: Address,
    recipient: Address,
    arbiter: Address,
}

fn setup(amount: i128) -> Harness {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().with_mut(|l| l.timestamp = START);

    let escrow_id = env.register_contract(None, EscrowContract);
    let escrow = EscrowContractClient::new(&env, &escrow_id);
    escrow.initialize();

    let token_admin = Address::generate(&env);
    let asset = env
        .register_stellar_asset_contract_v2(token_admin)
        .address();
    let sender = Address::generate(&env);
    token::StellarAssetClient::new(&env, &asset).mint(&sender, &amount);

    Harness {
        env,
        escrow,
        asset,
        sender,
        recipient: Address::generate(&env),
        arbiter: Address::generate(&env),
    }
}

fn one_asset(h: &Harness, amount: i128) -> Vec<AssetAmount> {
    vec![
        &h.env,
        AssetAmount {
            asset: h.asset.clone(),
            amount,
        },
    ]
}

fn balance(h: &Harness, who: &Address) -> i128 {
    token::TokenClient::new(&h.env, &h.asset).balance(who)
}

#[test]
fn early_release_fails_with_the_distinct_code_until_the_release_time_passes() {
    let h = setup(10_000);
    let unlock_time = START + 1_000;

    let id = h.escrow.create_timelock(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &one_asset(&h, 10_000),
        &unlock_time,
        &String::from_str(&h.env, "vesting payout"),
    );
    assert_eq!(h.escrow.get(&id).state, EscrowState::Funded);

    // Advance the ledger clock step by step: every release attempt strictly
    // before the configured release time is refused with the distinct
    // early-release code, and no value ever moves early.
    for ts in [START + 100, START + 500, unlock_time - 2, unlock_time - 1] {
        h.env.ledger().with_mut(|l| l.timestamp = ts);
        assert_eq!(
            h.escrow.try_release(&h.arbiter, &id, &10_000),
            Err(Ok(Error::TimelockNotExpired)),
            "release at {ts} must be refused"
        );
        assert_eq!(h.escrow.get(&id).state, EscrowState::Funded);
        assert_eq!(balance(&h, &h.recipient), 0);
        assert_eq!(balance(&h, &h.escrow.address), 10_000);
    }

    // The code is the one the issue demands: distinct from both the
    // beneficiary's TimeLockActive (81) and EscrowExpired (80).
    assert_eq!(Error::TimelockNotExpired as u32, 91);

    // The beneficiary's own paths stay on the TimeLockActive code while
    // locked, so the two surfaces are observably different.
    h.env.ledger().with_mut(|l| l.timestamp = unlock_time - 1);
    assert_eq!(
        h.escrow.try_withdraw(&h.recipient, &id, &1_000),
        Err(Ok(Error::TimeLockActive))
    );

    // At maturity the beneficiary can claim the full amount through the
    // contract boundary.
    h.env.ledger().with_mut(|l| l.timestamp = unlock_time);
    let claimed = h.escrow.claim(&h.recipient, &id);
    assert_eq!(claimed, 10_000);
    assert_eq!(h.escrow.get(&id).state, EscrowState::Released);
    assert_eq!(balance(&h, &h.recipient), 10_000);
    assert_eq!(balance(&h, &h.escrow.address), 0);
}

#[test]
fn scheduled_release_verifies_the_clock_across_the_boundary() {
    // A scheduled escrow whose settlement deadline sits beyond the schedule
    // end: release flips from TimelockNotExpired to success exactly at the
    // configured release time, not before and not after it starts failing for
    // expiry.
    let h = setup(10_000);
    let schedule = astroid_escrow::ReleaseSchedule {
        release_type: astroid_escrow::ReleaseType::Cliff,
        start_time: START,
        cliff_time: START + 500,
        end_time: START + 500,
    };

    let id = h.escrow.create_scheduled(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &one_asset(&h, 10_000),
        &schedule,
        &(START + 2_000),
        &String::from_str(&h.env, "cliff release"),
    );

    // One second before the release time: refused, funds intact.
    h.env.ledger().with_mut(|l| l.timestamp = START + 499);
    assert_eq!(
        h.escrow.try_release(&h.arbiter, &id, &10_000),
        Err(Ok(Error::TimelockNotExpired))
    );
    assert_eq!(balance(&h, &h.escrow.address), 10_000);

    // Exactly at the release time: the arbiter may settle in full.
    h.env.ledger().with_mut(|l| l.timestamp = START + 500);
    h.escrow.release(&h.arbiter, &id, &10_000);
    assert_eq!(h.escrow.get(&id).state, EscrowState::Released);
    assert_eq!(balance(&h, &h.recipient), 10_000);
    assert_eq!(balance(&h, &h.escrow.address), 0);
}

#[test]
fn linear_schedule_release_cannot_exceed_the_vested_amount() {
    // On a linear schedule a partial release may not outrun vesting: the
    // over-vested portion is refused with the same early-release code until
    // enough time has passed.
    let h = setup(10_000);
    let schedule = astroid_escrow::ReleaseSchedule {
        release_type: astroid_escrow::ReleaseType::Linear,
        start_time: START,
        cliff_time: START + 200,
        end_time: START + 1_000,
    };

    let id = h.escrow.create_scheduled(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &one_asset(&h, 10_000),
        &schedule,
        &(START + 2_000),
        &String::from_str(&h.env, "linear release"),
    );

    // Halfway through the schedule only half has vested: releasing everything
    // is refused even though the cliff itself has passed.
    h.env.ledger().with_mut(|l| l.timestamp = START + 500);
    assert_eq!(h.escrow.get_vested_amount(&id), 5_000);
    assert_eq!(
        h.escrow.try_release(&h.arbiter, &id, &10_000),
        Err(Ok(Error::TimelockNotExpired))
    );

    // Releasing only the vested amount works mid-schedule.
    h.escrow.release(&h.arbiter, &id, &5_000);
    assert_eq!(h.escrow.get(&id).state, EscrowState::Released);
    assert_eq!(balance(&h, &h.recipient), 10_000);
}
