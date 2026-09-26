extern crate std;

use ed25519_dalek::{Signer, SigningKey};
use soroban_sdk::{
    testutils::{
        Address as _, AuthorizedFunction, AuthorizedInvocation, Ledger, MockAuth, MockAuthInvoke,
    },
    token, vec, Address, Bytes, BytesN, Env, IntoVal, String, Symbol, Vec,
};

use astroid_shared::errors::Error;
use astroid_shared::types::AssetAmount;

use crate::{
    EscrowContract, EscrowContractClient, EscrowState, MilestoneSpec, OverrideSignature,
    ReleaseSchedule, ReleaseType,
};

const START: u64 = 1_000;
const GRACE: u64 = 1_000;

struct Harness<'a> {
    env: Env,
    client: EscrowContractClient<'a>,
    asset_a: Address,
    asset_b: Address,
    sender: Address,
    recipient: Address,
    arbiter: Address,
}

fn setup(funded_a: i128, funded_b: i128) -> Harness<'static> {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().with_mut(|l| l.timestamp = START);

    let id = env.register_contract(None, EscrowContract);
    let client = EscrowContractClient::new(&env, &id);
    client.initialize();

    let token_admin_a = Address::generate(&env);
    let asset_a = env
        .register_stellar_asset_contract_v2(token_admin_a)
        .address();
    let token_admin_b = Address::generate(&env);
    let asset_b = env
        .register_stellar_asset_contract_v2(token_admin_b)
        .address();

    let sender = Address::generate(&env);
    let recipient = Address::generate(&env);
    let arbiter = Address::generate(&env);
    if funded_a > 0 {
        token::StellarAssetClient::new(&env, &asset_a).mint(&sender, &funded_a);
    }
    if funded_b > 0 {
        token::StellarAssetClient::new(&env, &asset_b).mint(&sender, &funded_b);
    }

    Harness {
        env,
        client,
        asset_a,
        asset_b,
        sender,
        recipient,
        arbiter,
    }
}

fn balance(h: &Harness, asset: &Address, who: &Address) -> i128 {
    token::TokenClient::new(&h.env, asset).balance(who)
}

fn one_asset(h: &Harness, amount: i128) -> Vec<AssetAmount> {
    vec![
        &h.env,
        AssetAmount {
            asset: h.asset_a.clone(),
            amount,
        },
    ]
}

fn two_assets(h: &Harness, amount_a: i128, amount_b: i128) -> Vec<AssetAmount> {
    vec![
        &h.env,
        AssetAmount {
            asset: h.asset_a.clone(),
            amount: amount_a,
        },
        AssetAmount {
            asset: h.asset_b.clone(),
            amount: amount_b,
        },
    ]
}

fn no_signers(h: &Harness) -> Vec<BytesN<32>> {
    Vec::new(&h.env)
}

fn create(h: &Harness, assets: &Vec<AssetAmount>, deadline: u64, grace_period: u64) -> u64 {
    h.client.create(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        assets,
        &deadline,
        &grace_period,
        &String::from_str(&h.env, "payment"),
        &no_signers(h),
        &0,
    )
}

fn keypair(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn public_key(env: &Env, kp: &SigningKey) -> BytesN<32> {
    BytesN::from_array(env, &kp.verifying_key().to_bytes())
}

fn sign_override(h: &Harness, kp: &SigningKey, id: u64, nonce: u64) -> OverrideSignature {
    let contract = h.client.address.clone();
    let digest: [u8; 32] = h.env.as_contract(&contract, || {
        let payload: Bytes = EscrowContract::override_payload(&h.env, id, nonce);
        h.env.crypto().sha256(&payload).to_array()
    });
    let signature = kp.sign(&digest).to_bytes();
    OverrideSignature {
        public_key: public_key(&h.env, kp),
        signature: BytesN::from_array(&h.env, &signature),
    }
}

fn milestone_spec(env: &Env, description: &str, bps: u32) -> MilestoneSpec {
    MilestoneSpec {
        description: String::from_str(env, description),
        release_bps: bps,
    }
}

// --- Core multi-asset tests ---

#[test]
fn full_cycle_create_release() {
    let h = setup(10_000, 5_000);
    let assets = two_assets(&h, 10_000, 5_000);
    let id = create(&h, &assets, START + 86_400, 0);
    assert_eq!(id, 1);
    assert_eq!(balance(&h, &h.asset_a, &h.sender), 0);
    assert_eq!(balance(&h, &h.asset_b, &h.sender), 0);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 10_000);
    assert_eq!(balance(&h, &h.asset_b, &h.client.address), 5_000);
    assert_eq!(h.client.get(&id).state, EscrowState::Funded);

    h.client.release(&h.arbiter, &id, &10_000);
    assert_eq!(h.client.get(&id).state, EscrowState::Released);
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 10_000);
    assert_eq!(balance(&h, &h.asset_b, &h.recipient), 5_000);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 0);
    assert_eq!(balance(&h, &h.asset_b, &h.client.address), 0);

    h.client.close(&h.sender, &id);
    assert_eq!(h.client.get(&id).state, EscrowState::Closed);
}

#[test]
fn non_arbiter_cannot_release() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), START + 100, 0);
    let intruder = Address::generate(&h.env);

    let res = h.client.try_release(&intruder, &id, &5_000);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 5_000);
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 0);
}

#[test]
fn release_after_deadline_is_refused() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), START + 100, 0);

    h.env.ledger().with_mut(|l| l.timestamp = START + 200);
    let res = h.client.try_release(&h.arbiter, &id, &5_000);
    assert_eq!(res, Err(Ok(Error::EscrowExpired)));
    assert_eq!(h.client.get(&id).state, EscrowState::Funded);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 5_000);
}

#[test]
fn refund_returns_funds_after_deadline() {
    let h = setup(5_000, 2_000);
    let id = create(&h, &two_assets(&h, 5_000, 2_000), START + 100, 0);

    h.env.ledger().with_mut(|l| l.timestamp = START + 200);
    h.client.refund(&h.sender, &id);
    assert_eq!(h.client.get(&id).state, EscrowState::Refunded);
    assert_eq!(balance(&h, &h.asset_a, &h.sender), 5_000);
    assert_eq!(balance(&h, &h.asset_b, &h.sender), 2_000);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 0);
    assert_eq!(balance(&h, &h.asset_b, &h.client.address), 0);
}

#[test]
fn refund_before_deadline_rejected() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), START + 100, 0);

    let res = h.client.try_refund(&h.sender, &id);
    assert_eq!(res, Err(Ok(Error::TimeLockActive)));
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 5_000);
}

#[test]
fn expire_marks_then_refund_returns() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), START + 100, 0);

    let early = h.client.try_expire(&id);
    assert_eq!(early, Err(Ok(Error::InvalidState)));

    h.env.ledger().with_mut(|l| l.timestamp = START + 200);
    h.client.expire(&id);
    assert_eq!(h.client.get(&id).state, EscrowState::Expired);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 5_000);
    assert_eq!(balance(&h, &h.asset_a, &h.sender), 0);

    h.client.refund(&h.sender, &id);
    assert_eq!(h.client.get(&id).state, EscrowState::Refunded);
    assert_eq!(balance(&h, &h.asset_a, &h.sender), 5_000);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 0);
}

#[test]
fn released_escrow_cannot_be_refunded() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), START + 100, 0);
    h.client.release(&h.arbiter, &id, &5_000);

    h.env.ledger().with_mut(|l| l.timestamp = START + 200);
    let res = h.client.try_refund(&h.sender, &id);
    assert_eq!(res, Err(Ok(Error::InvalidState)));
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 5_000);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 0);
}

#[test]
fn cannot_close_while_expired() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), START + 100, 0);
    h.env.ledger().with_mut(|l| l.timestamp = START + 200);
    h.client.expire(&id);

    let res = h.client.try_close(&h.sender, &id);
    assert_eq!(res, Err(Ok(Error::InvalidState)));
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 5_000);
}

#[test]
fn create_rejects_bad_input() {
    let h = setup(5_000, 0);
    let r1 = h.client.try_create(
        &h.sender,
        &h.sender,
        &h.arbiter,
        &one_asset(&h, 1_000),
        &(START + 100),
        &0,
        &String::from_str(&h.env, "x"),
        &no_signers(&h),
        &0,
    );
    assert_eq!(r1, Err(Ok(Error::InvalidInput)));
    let r2 = h.client.try_create(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &one_asset(&h, 1_000),
        &(START - 500),
        &0,
        &String::from_str(&h.env, "x"),
        &no_signers(&h),
        &0,
    );
    assert_eq!(r2, Err(Ok(Error::InvalidInput)));
    let r3 = h.client.try_create(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &one_asset(&h, 0),
        &(START + 100),
        &0,
        &String::from_str(&h.env, "x"),
        &no_signers(&h),
        &0,
    );
    assert_eq!(r3, Err(Ok(Error::InvalidAmount)));
    let r4 = h.client.try_create(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &Vec::new(&h.env),
        &(START + 100),
        &0,
        &String::from_str(&h.env, "x"),
        &no_signers(&h),
        &0,
    );
    assert_eq!(r4, Err(Ok(Error::InvalidInput)));
    let dup = vec![
        &h.env,
        AssetAmount {
            asset: h.asset_a.clone(),
            amount: 1_000,
        },
        AssetAmount {
            asset: h.asset_a.clone(),
            amount: 500,
        },
    ];
    let r5 = h.client.try_create(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &dup,
        &(START + 100),
        &0,
        &String::from_str(&h.env, "x"),
        &no_signers(&h),
        &0,
    );
    assert_eq!(r5, Err(Ok(Error::InvalidInput)));
    assert_eq!(balance(&h, &h.asset_a, &h.sender), 5_000);
}

#[test]
fn create_rejects_bad_override_config() {
    let h = setup(5_000, 0);
    let signer = public_key(&h.env, &keypair(1));
    let signers = vec![&h.env, signer];

    let r1 = h.client.try_create(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &one_asset(&h, 1_000),
        &(START + 100),
        &0,
        &String::from_str(&h.env, "x"),
        &signers,
        &0,
    );
    assert_eq!(r1, Err(Ok(Error::InvalidThreshold)));

    let r2 = h.client.try_create(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &one_asset(&h, 1_000),
        &(START + 100),
        &0,
        &String::from_str(&h.env, "x"),
        &signers,
        &2,
    );
    assert_eq!(r2, Err(Ok(Error::InvalidThreshold)));

    let r3 = h.client.try_create(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &one_asset(&h, 1_000),
        &(START + 100),
        &0,
        &String::from_str(&h.env, "x"),
        &Vec::new(&h.env),
        &1,
    );
    assert_eq!(r3, Err(Ok(Error::InvalidThreshold)));
}

// --- Override release tests ---

#[test]
fn override_release_with_threshold_signatures_releases_funds() {
    let h = setup(5_000, 1_000);
    let kp1 = keypair(1);
    let kp2 = keypair(2);
    let signers = vec![&h.env, public_key(&h.env, &kp1), public_key(&h.env, &kp2)];

    let id = h.client.create(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &two_assets(&h, 5_000, 1_000),
        &(START + 1_000),
        &0,
        &String::from_str(&h.env, "override"),
        &signers,
        &2,
    );

    let nonce = 1u64;
    let sig1 = sign_override(&h, &kp1, id, nonce);
    let sig2 = sign_override(&h, &kp2, id, nonce);
    let sigs = vec![&h.env, sig1, sig2];

    h.client.override_release(&id, &nonce, &sigs);

    assert_eq!(h.client.get(&id).state, EscrowState::Released);
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 5_000);
    assert_eq!(balance(&h, &h.asset_b, &h.recipient), 1_000);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 0);
}

#[test]
fn override_release_rejects_replayed_nonce() {
    let h = setup(5_000, 0);
    let kp1 = keypair(1);
    let signers = vec![&h.env, public_key(&h.env, &kp1)];

    let id = h.client.create(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &one_asset(&h, 5_000),
        &(START + 1_000),
        &0,
        &String::from_str(&h.env, "override"),
        &signers,
        &1,
    );

    let nonce = 1u64;
    let sig = sign_override(&h, &kp1, id, nonce);
    h.client
        .override_release(&id, &nonce, &vec![&h.env, sig.clone()]);
    assert_eq!(h.client.get(&id).state, EscrowState::Released);

    let res = h
        .client
        .try_override_release(&id, &nonce, &vec![&h.env, sig]);
    assert_eq!(res, Err(Ok(Error::InvalidState)));
}

#[test]
fn override_release_requires_strictly_increasing_nonce() {
    let h = setup(5_000, 0);
    let kp1 = keypair(1);
    let kp2 = keypair(2);
    let signers = vec![&h.env, public_key(&h.env, &kp1), public_key(&h.env, &kp2)];

    let id = h.client.create(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &one_asset(&h, 5_000),
        &(START + 1_000),
        &0,
        &String::from_str(&h.env, "override"),
        &signers,
        &2,
    );

    let sig1 = sign_override(&h, &kp1, id, 0);
    let sig2 = sign_override(&h, &kp2, id, 0);
    let res = h
        .client
        .try_override_release(&id, &0u64, &vec![&h.env, sig1, sig2]);
    assert_eq!(res, Err(Ok(Error::InvalidNonce)));
}

#[test]
fn override_release_rejects_insufficient_signatures() {
    let h = setup(5_000, 0);
    let kp1 = keypair(1);
    let kp2 = keypair(2);
    let signers = vec![&h.env, public_key(&h.env, &kp1), public_key(&h.env, &kp2)];

    let id = h.client.create(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &one_asset(&h, 5_000),
        &(START + 1_000),
        &0,
        &String::from_str(&h.env, "override"),
        &signers,
        &2,
    );

    let sig1 = sign_override(&h, &kp1, id, 1);
    let res = h
        .client
        .try_override_release(&id, &1u64, &vec![&h.env, sig1]);
    assert_eq!(res, Err(Ok(Error::ThresholdNotMet)));
    assert_eq!(h.client.get(&id).state, EscrowState::Funded);
}

#[test]
fn override_release_rejects_unknown_signer() {
    let h = setup(5_000, 0);
    let kp1 = keypair(1);
    let outsider = keypair(99);
    let signers = vec![&h.env, public_key(&h.env, &kp1)];

    let id = h.client.create(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &one_asset(&h, 5_000),
        &(START + 1_000),
        &0,
        &String::from_str(&h.env, "override"),
        &signers,
        &1,
    );

    let bad_sig = sign_override(&h, &outsider, id, 1);
    let res = h
        .client
        .try_override_release(&id, &1u64, &vec![&h.env, bad_sig]);
    assert_eq!(res, Err(Ok(Error::NotASigner)));
}

#[test]
fn override_release_rejects_duplicate_signer_in_one_call() {
    let h = setup(5_000, 0);
    let kp1 = keypair(1);
    let kp2 = keypair(2);
    let signers = vec![&h.env, public_key(&h.env, &kp1), public_key(&h.env, &kp2)];

    let id = h.client.create(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &one_asset(&h, 5_000),
        &(START + 1_000),
        &0,
        &String::from_str(&h.env, "override"),
        &signers,
        &2,
    );

    let sig1 = sign_override(&h, &kp1, id, 1);
    let res = h
        .client
        .try_override_release(&id, &1u64, &vec![&h.env, sig1.clone(), sig1]);
    assert_eq!(res, Err(Ok(Error::AlreadySigned)));
}

#[test]
fn override_release_disabled_without_configured_signers() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), START + 1_000, 0);

    let kp1 = keypair(1);
    let sig1 = sign_override(&h, &kp1, id, 1);
    let res = h
        .client
        .try_override_release(&id, &1u64, &vec![&h.env, sig1]);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
}

// --- Milestone tests ---

#[test]
fn milestone_partial_then_full_release() {
    let h = setup(10_000, 0);
    let specs = vec![
        &h.env,
        milestone_spec(&h.env, "design", 4_000),
        milestone_spec(&h.env, "build", 6_000),
    ];
    let id = h.client.deposit_with_milestones(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &h.asset_a,
        &10_000,
        &(START + 86_400),
        &String::from_str(&h.env, "project"),
        &specs,
    );
    assert_eq!(h.client.get(&id).state, EscrowState::Funded);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 10_000);

    h.client.release_milestone(&h.arbiter, &id, &0);
    let set = h.client.milestones(&id);
    assert!(set.milestones.get(0).unwrap().released);
    assert_eq!(set.released_amount, 4_000);
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 4_000);
    assert_eq!(h.client.get(&id).state, EscrowState::Funded);

    h.client.release_milestone(&h.arbiter, &id, &1);
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 10_000);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 0);
    assert_eq!(h.client.get(&id).state, EscrowState::Released);

    h.client.close(&h.arbiter, &id);
    assert_eq!(h.client.get(&id).state, EscrowState::Closed);
}

#[test]
fn milestone_unauthorized_approval_rejected() {
    let h = setup(10_000, 0);
    let specs = vec![&h.env, milestone_spec(&h.env, "m", 10_000)];
    let id = h.client.deposit_with_milestones(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &h.asset_a,
        &10_000,
        &(START + 86_400),
        &String::from_str(&h.env, "p"),
        &specs,
    );
    let res = h.client.try_release_milestone(&h.sender, &id, &0);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 0);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 10_000);
}

#[test]
fn milestone_double_release_rejected() {
    let h = setup(10_000, 0);
    let specs = vec![&h.env, milestone_spec(&h.env, "m", 10_000)];
    let id = h.client.deposit_with_milestones(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &h.asset_a,
        &10_000,
        &(START + 86_400),
        &String::from_str(&h.env, "p"),
        &specs,
    );
    h.client.release_milestone(&h.arbiter, &id, &0);
    let res = h.client.try_release_milestone(&h.arbiter, &id, &0);
    assert_eq!(res, Err(Ok(Error::InvalidState)));
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 10_000);
}

#[test]
fn milestone_bps_must_total_100() {
    let h = setup(10_000, 0);
    let specs = vec![
        &h.env,
        milestone_spec(&h.env, "a", 4_000),
        milestone_spec(&h.env, "b", 5_000),
    ];
    let res = h.client.try_deposit_with_milestones(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &h.asset_a,
        &10_000,
        &(START + 86_400),
        &String::from_str(&h.env, "p"),
        &specs,
    );
    assert_eq!(res, Err(Ok(Error::InvalidInput)));
    assert_eq!(balance(&h, &h.asset_a, &h.sender), 10_000);
}

#[test]
fn plain_release_blocked_on_milestone_escrow() {
    let h = setup(10_000, 0);
    let specs = vec![&h.env, milestone_spec(&h.env, "m", 10_000)];
    let id = h.client.deposit_with_milestones(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &h.asset_a,
        &10_000,
        &(START + 86_400),
        &String::from_str(&h.env, "p"),
        &specs,
    );
    let res = h.client.try_release(&h.arbiter, &id, &10_000);
    assert_eq!(res, Err(Ok(Error::InvalidState)));
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 0);
}

#[test]
fn timelock_cliff_rejects_early_withdraw_and_claims_post_maturity() {
    let h = setup(10_000, 0);
    let unlock_time = START + 1_000;

    let id = h.client.create_timelock(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &one_asset(&h, 10_000),
        &unlock_time,
        &String::from_str(&h.env, "timelock cliff"),
    );
    assert_eq!(id, 1);
    assert_eq!(balance(&h, &h.asset_a, &h.sender), 0);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 10_000);

    // Pre-maturity check: withdrawal and claim must fail with TimeLockActive
    h.env.ledger().with_mut(|l| l.timestamp = START + 500);
    assert_eq!(h.client.get_claimable_amount(&id), 0);
    assert_eq!(h.client.get_vested_amount(&id), 0);

    let early_claim = h.client.try_claim(&h.recipient, &id);
    assert_eq!(early_claim, Err(Ok(Error::TimeLockActive)));

    let early_withdraw = h.client.try_withdraw(&h.recipient, &id, &5_000);
    assert_eq!(early_withdraw, Err(Ok(Error::TimeLockActive)));

    // Post-maturity check: claim succeeds
    h.env.ledger().with_mut(|l| l.timestamp = unlock_time);
    assert_eq!(h.client.get_claimable_amount(&id), 10_000);
    assert_eq!(h.client.get_vested_amount(&id), 10_000);

    let claimed = h.client.claim(&h.recipient, &id);
    assert_eq!(claimed, 10_000);
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 10_000);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 0);
    assert_eq!(h.client.get(&id).state, EscrowState::Released);
    assert_eq!(h.client.get_claimable_amount(&id), 0);
}

#[test]
fn timelock_linear_release_gradual_withdrawals() {
    let h = setup(10_000, 0);
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
        &one_asset(&h, 10_000),
        &schedule,
        &end_time,
        &String::from_str(&h.env, "linear schedule"),
    );

    // 1. Before cliff (timestamp = START + 100): locked
    h.env.ledger().with_mut(|l| l.timestamp = START + 100);
    assert_eq!(h.client.get_claimable_amount(&id), 0);
    assert_eq!(h.client.get_vested_amount(&id), 0);
    let res = h.client.try_withdraw(&h.recipient, &id, &1_000);
    assert_eq!(res, Err(Ok(Error::TimeLockActive)));

    // 2. At 50% time (timestamp = START + 500, past cliff):
    // 50% of 10,000 = 5,000 vested.
    h.env.ledger().with_mut(|l| l.timestamp = START + 500);
    assert_eq!(h.client.get_vested_amount(&id), 5_000);
    assert_eq!(h.client.get_claimable_amount(&id), 5_000);

    // Partial withdrawal of 3,000
    let total_released = h.client.withdraw(&h.recipient, &id, &3_000);
    assert_eq!(total_released, 3_000);
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 3_000);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 7_000);
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
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 8_000);
    assert_eq!(h.client.get_claimable_amount(&id), 0);

    // 4. At 100% maturity (timestamp = START + 1_000):
    // Total vested = 10,000; claimable = 2,000.
    h.env.ledger().with_mut(|l| l.timestamp = START + 1_000);
    assert_eq!(h.client.get_vested_amount(&id), 10_000);
    assert_eq!(h.client.get_claimable_amount(&id), 2_000);

    let claimed = h.client.claim(&h.recipient, &id);
    assert_eq!(claimed, 2_000);
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 10_000);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 0);
    assert_eq!(h.client.get(&id).state, EscrowState::Released);
    assert_eq!(h.client.get_claimable_amount(&id), 0);
}

#[test]
fn scheduled_escrow_rejects_bad_schedule_inputs() {
    let h = setup(10_000, 0);

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
        &one_asset(&h, 1_000),
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
        &one_asset(&h, 1_000),
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
        &one_asset(&h, 1_000),
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
        &one_asset(&h, 1_000),
        &s4,
        &(START + 500),
        &String::from_str(&h.env, "bad schedule"),
    );
    assert_eq!(r4, Err(Ok(Error::InvalidInput)));
}

#[test]
fn timelock_unauthorized_claim_and_withdraw() {
    let h = setup(5_000, 0);
    let id = h.client.create_timelock(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &one_asset(&h, 5_000),
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
    let h = setup(5_000, 0);
    let id = h.client.create_timelock(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &one_asset(&h, 5_000),
        &(START + 500),
        &String::from_str(&h.env, "timelock"),
    );

    // Pre-deadline refund attempt fails
    h.env.ledger().with_mut(|l| l.timestamp = START + 200);
    let early = h.client.try_refund_timelock(&h.sender, &id);
    assert_eq!(early, Err(Ok(Error::TimeLockActive)));

    // Non-sender cannot refund
    let intruder = Address::generate(&h.env);
    let unauth = h.client.try_refund_timelock(&intruder, &id);
    assert_eq!(unauth, Err(Ok(Error::Unauthorized)));

    // Post-deadline refund succeeds
    h.env.ledger().with_mut(|l| l.timestamp = START + 600);
    h.client.refund_timelock(&h.sender, &id);
    assert_eq!(h.client.get(&id).state, EscrowState::Refunded);
    assert_eq!(balance(&h, &h.asset_a, &h.sender), 5_000);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 0);
}

#[test]
fn initialize_and_fund_timelock_lifecycle() {
    let h = setup(5_000, 0);
    let id = h.client.initialize_timelock(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &one_asset(&h, 5_000),
        &(START + 500),
        &0,
        &String::from_str(&h.env, "unfunded"),
    );
    assert_eq!(h.client.get(&id).state, EscrowState::Created);
    assert_eq!(balance(&h, &h.asset_a, &h.sender), 5_000);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 0);

    // Intruder cannot fund
    let intruder = Address::generate(&h.env);
    let unauth_fund = h.client.try_fund(&intruder, &id);
    assert_eq!(unauth_fund, Err(Ok(Error::Unauthorized)));

    // Sender funds
    h.client.fund(&h.sender, &id);
    assert_eq!(h.client.get(&id).state, EscrowState::Funded);
    assert_eq!(balance(&h, &h.asset_a, &h.sender), 0);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 5_000);

    // Pre-maturity claim fails
    h.env.ledger().with_mut(|l| l.timestamp = START + 200);
    let early = h.client.try_claim(&h.recipient, &id);
    assert_eq!(early, Err(Ok(Error::TimeLockActive)));

    // Post-maturity claim succeeds
    h.env.ledger().with_mut(|l| l.timestamp = START + 600);
    let claimed = h.client.claim(&h.recipient, &id);
    assert_eq!(claimed, 5_000);
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 5_000);
    assert_eq!(h.client.get(&id).state, EscrowState::Released);
}

// --- Grace period & cancellation (pr-137) ---

#[test]
fn release_after_grace_is_refused() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), START + 100, GRACE);

    h.env
        .ledger()
        .with_mut(|l| l.timestamp = START + 200 + GRACE);
    let res = h.client.try_release(&h.arbiter, &id, &5_000);
    assert_eq!(res, Err(Ok(Error::EscrowExpired)));
    assert_eq!(h.client.get(&id).state, EscrowState::Funded);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 5_000);
}

#[test]
fn release_allowed_during_grace() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), START + 100, GRACE);

    h.env.ledger().with_mut(|l| l.timestamp = START + 150);
    h.client.release(&h.arbiter, &id, &5_000);
    assert_eq!(h.client.get(&id).state, EscrowState::Released);
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 5_000);
}

#[test]
fn refund_returns_funds_after_grace() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), START + 100, GRACE);

    h.env.ledger().with_mut(|l| l.timestamp = START + 150);
    let early = h.client.try_refund(&h.sender, &id);
    assert_eq!(early, Err(Ok(Error::GraceActive)));
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 5_000);

    h.env
        .ledger()
        .with_mut(|l| l.timestamp = START + 200 + GRACE);
    h.client.refund(&h.sender, &id);
    assert_eq!(h.client.get(&id).state, EscrowState::Refunded);
    assert_eq!(balance(&h, &h.asset_a, &h.sender), 5_000);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 0);
}

#[test]
fn cancel_by_sender_before_deadline_returns_funds() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), START + 100, GRACE);

    h.client.cancel(&h.sender, &id);
    assert_eq!(h.client.get(&id).state, EscrowState::Refunded);
    assert_eq!(balance(&h, &h.asset_a, &h.sender), 5_000);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 0);
}

#[test]
fn arbiter_may_also_cancel_before_deadline() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), START + 100, GRACE);

    h.client.cancel(&h.arbiter, &id);
    assert_eq!(h.client.get(&id).state, EscrowState::Refunded);
    assert_eq!(balance(&h, &h.asset_a, &h.sender), 5_000);
}

#[test]
fn cancel_rejected_after_deadline() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), START + 100, GRACE);

    h.env.ledger().with_mut(|l| l.timestamp = START + 150);
    let res = h.client.try_cancel(&h.sender, &id);
    assert_eq!(res, Err(Ok(Error::InvalidState)));
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 5_000);
}

#[test]
fn cancel_rejected_for_non_party() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), START + 100, GRACE);
    let intruder = Address::generate(&h.env);

    let res = h.client.try_cancel(&intruder, &id);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 5_000);
}

#[test]
fn reclaim_after_grace_returns_funds() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), START + 100, GRACE);

    h.env.ledger().with_mut(|l| l.timestamp = START + 150);
    let early = h.client.try_reclaim(&h.sender, &id);
    assert_eq!(early, Err(Ok(Error::GraceActive)));
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 5_000);

    h.env
        .ledger()
        .with_mut(|l| l.timestamp = START + 200 + GRACE);
    h.client.reclaim(&h.sender, &id);
    assert_eq!(h.client.get(&id).state, EscrowState::Refunded);
    assert_eq!(balance(&h, &h.asset_a, &h.sender), 5_000);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 0);
}

#[test]
fn reclaim_rejected_for_non_sender() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), START + 100, GRACE);

    h.env
        .ledger()
        .with_mut(|l| l.timestamp = START + 200 + GRACE);
    let res = h.client.try_reclaim(&h.recipient, &id);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 5_000);
}

#[test]
fn reclaim_rejected_after_release() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), START + 100, GRACE);

    h.client.release(&h.arbiter, &id, &5_000);
    let res = h.client.try_reclaim(&h.sender, &id);
    assert_eq!(res, Err(Ok(Error::InvalidState)));
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 5_000);
}

// --- bounded refund window ---

/// Create a funded escrow whose refund window closes `refund_window` seconds
/// after refunds open at `deadline + grace_period`.
fn create_windowed(
    h: &Harness,
    assets: &Vec<AssetAmount>,
    deadline: u64,
    grace_period: u64,
    refund_window: u64,
) -> u64 {
    h.client.create_with_refund_window(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        assets,
        &deadline,
        &grace_period,
        &refund_window,
        &String::from_str(&h.env, "payment"),
        &no_signers(h),
        &0,
    )
}

fn at(h: &Harness, ts: u64) {
    h.env.ledger().with_mut(|l| l.timestamp = ts);
}

#[test]
fn unbounded_window_is_the_default() {
    let h = setup(1_000, 0);
    let id = create(&h, &one_asset(&h, 100), START + 100, 0);
    assert_eq!(h.client.refund_window_closes_at(&id), 0);
    // Far past the deadline the refund is still available.
    at(&h, START + 10_000_000);
    assert!(h.client.is_refundable(&id));
    h.client.refund(&h.sender, &id);
    assert_eq!(balance(&h, &h.asset_a, &h.sender), 1_000);
}

#[test]
fn refund_inside_the_window_succeeds() {
    let h = setup(1_000, 0);
    let id = create_windowed(&h, &one_asset(&h, 100), START + 100, 0, 50);
    assert_eq!(h.client.refund_window_closes_at(&id), START + 150);

    at(&h, START + 120);
    assert!(h.client.is_refundable(&id));
    h.client.refund(&h.sender, &id);
    assert_eq!(balance(&h, &h.asset_a, &h.sender), 1_000);
}

#[test]
fn refund_after_the_window_closes_is_rejected() {
    let h = setup(1_000, 0);
    let id = create_windowed(&h, &one_asset(&h, 100), START + 100, 0, 50);

    at(&h, START + 150);
    assert!(!h.client.is_refundable(&id));
    assert_eq!(
        h.client.try_refund(&h.sender, &id),
        Err(Ok(Error::EscrowExpired))
    );
    // The funds stay in the escrow's custody rather than moving anywhere.
    assert_eq!(balance(&h, &h.asset_a, &h.sender), 900);
}

#[test]
fn refund_at_the_last_second_of_the_window_succeeds() {
    let h = setup(1_000, 0);
    let id = create_windowed(&h, &one_asset(&h, 100), START + 100, 0, 50);
    // The window is half-open: it closes *at* START + 150.
    at(&h, START + 149);
    h.client.refund(&h.sender, &id);
    assert_eq!(balance(&h, &h.asset_a, &h.sender), 1_000);
}

#[test]
fn the_window_is_measured_from_the_end_of_the_grace_period() {
    let h = setup(1_000, 0);
    let id = create_windowed(&h, &one_asset(&h, 100), START + 100, 40, 50);
    // Refunds open at deadline + grace = START + 140, so the window closes at
    // START + 190 — never before it opens.
    assert_eq!(h.client.refund_window_closes_at(&id), START + 190);

    at(&h, START + 120);
    assert!(!h.client.is_refundable(&id));
    assert_eq!(
        h.client.try_refund(&h.sender, &id),
        Err(Ok(Error::GraceActive))
    );

    at(&h, START + 150);
    assert!(h.client.is_refundable(&id));
    h.client.refund(&h.sender, &id);
}

#[test]
fn reclaim_respects_the_window() {
    let h = setup(1_000, 0);
    let id = create_windowed(&h, &one_asset(&h, 100), START + 100, 0, 50);
    at(&h, START + 150);
    assert_eq!(
        h.client.try_reclaim(&h.sender, &id),
        Err(Ok(Error::EscrowExpired))
    );
}

#[test]
fn release_is_unaffected_by_the_refund_window() {
    let h = setup(1_000, 0);
    let id = create_windowed(&h, &one_asset(&h, 100), START + 100, 200, 50);
    // The arbiter may still release during the grace period, whatever the
    // refund window says.
    at(&h, START + 150);
    h.client.release(&h.arbiter, &id, &100);
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 100);
    // A settled escrow is never refundable.
    assert!(!h.client.is_refundable(&id));
}

#[test]
fn an_absurd_window_saturates_instead_of_overflowing() {
    let h = setup(1_000, 0);
    let id = create_windowed(&h, &one_asset(&h, 100), START + 100, 0, u64::MAX);
    assert_eq!(h.client.refund_window_closes_at(&id), u64::MAX);
    at(&h, START + 10_000_000);
    assert!(h.client.is_refundable(&id));
    h.client.refund(&h.sender, &id);
}

// --- Time-lock validation on `release` (Issue #238) ---

#[test]
fn release_before_cliff_maturity_is_refused_with_time_lock_active() {
    let h = setup(10_000, 0);
    let unlock_time = START + 1_000;

    let id = h.client.create_timelock(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &one_asset(&h, 10_000),
        &unlock_time,
        &String::from_str(&h.env, "premature release"),
    );

    // The settlement deadline is still far in the future, but the arbiter must
    // not be able to route around the time lock: the cliff has not matured.
    h.env.ledger().with_mut(|l| l.timestamp = START + 500);
    let res = h.client.try_release(&h.arbiter, &id, &10_000);
    assert_eq!(res, Err(Ok(Error::TimeLockActive)));
    // No funds moved and the escrow is still live.
    assert_eq!(h.client.get(&id).state, EscrowState::Funded);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 10_000);
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 0);

    // A release attempt at exactly the boundary before the cliff also fails.
    h.env.ledger().with_mut(|l| l.timestamp = unlock_time - 1);
    assert_eq!(
        h.client.try_release(&h.arbiter, &id, &10_000),
        Err(Ok(Error::TimeLockActive))
    );

    // At maturity the pre-existing settlement window rule takes over: a
    // timelock escrow's deadline equals its unlock time, so the release window
    // closes exactly at maturity and the arbiter is refused with
    // EscrowExpired. The recipient's path to the funds is `withdraw`/`claim`,
    // not the arbiter's `release`.
    h.env.ledger().with_mut(|l| l.timestamp = unlock_time);
    assert_eq!(
        h.client.try_release(&h.arbiter, &id, &10_000),
        Err(Ok(Error::EscrowExpired))
    );
    assert_eq!(h.client.get(&id).state, EscrowState::Funded);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 10_000);
}

#[test]
fn linear_release_cannot_exceed_vested_amount() {
    let h = setup(10_000, 0);
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
        &one_asset(&h, 10_000),
        &schedule,
        &end_time,
        &String::from_str(&h.env, "linear release gate"),
    );

    // Before the cliff nothing has vested: release must fail with
    // TimeLockActive even though the deadline is far away.
    h.env.ledger().with_mut(|l| l.timestamp = START + 100);
    assert_eq!(
        h.client.try_release(&h.arbiter, &id, &5_000),
        Err(Ok(Error::TimeLockActive))
    );

    // Halfway through the schedule only half has vested (50% of 10,000 =
    // 5,000), so releasing more than the vested amount is refused.
    h.env.ledger().with_mut(|l| l.timestamp = START + 500);
    assert_eq!(h.client.get_vested_amount(&id), 5_000);
    assert_eq!(
        h.client.try_release(&h.arbiter, &id, &10_000),
        Err(Ok(Error::TimeLockActive))
    );

    // Releasing the vested amount works — the escrow settles in full per the
    // arbiter's decision, but only once the schedule has vested that much.
    h.client.release(&h.arbiter, &id, &5_000);
    assert_eq!(h.client.get(&id).state, EscrowState::Released);
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 10_000);
}

// --- Release / timeout-refund lifecycle (Issue #248) ---
//
// Expiration is measured on the ledger clock against the stored `deadline` and
// `grace_period`. Refunds open at `deadline + grace_period` (inclusive), the
// same instant `release` closes, so the two windows never overlap.

const DEADLINE: u64 = START + 100;

/// Snapshot of `asset_a` balances: (sender, recipient, contract).
fn balances(h: &Harness) -> (i128, i128, i128) {
    (
        balance(h, &h.asset_a, &h.sender),
        balance(h, &h.asset_a, &h.recipient),
        balance(h, &h.asset_a, &h.client.address),
    )
}

#[test]
fn release_before_expiry_pays_the_beneficiary_exactly_once() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), DEADLINE, 0);
    assert_eq!(balances(&h), (0, 0, 5_000));

    at(&h, DEADLINE - 1);
    h.client.release(&h.arbiter, &id, &5_000);

    let escrow = h.client.get(&id);
    assert_eq!(escrow.state, EscrowState::Released);
    assert_eq!(escrow.released_amount, 5_000);
    assert_eq!(balances(&h), (0, 5_000, 0));
}

#[test]
fn refund_one_second_before_expiry_is_rejected() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), DEADLINE, 0);

    at(&h, DEADLINE - 1);
    assert_eq!(
        h.client.try_refund(&h.sender, &id),
        Err(Ok(Error::TimeLockActive))
    );
    assert_eq!(Error::TimeLockActive as u32, 81);
    assert_eq!(h.client.get(&id).state, EscrowState::Funded);
    assert_eq!(balances(&h), (0, 0, 5_000));
}

#[test]
fn refund_after_expiry_returns_funds_to_the_depositor() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), DEADLINE, 0);

    at(&h, DEADLINE + 1);
    h.client.refund(&h.sender, &id);

    assert_eq!(h.client.get(&id).state, EscrowState::Refunded);
    assert_eq!(balances(&h), (5_000, 0, 0));
}

#[test]
fn refund_at_exactly_the_expiry_instant_is_permitted() {
    // The boundary is inclusive (`now >= deadline + grace_period`), matching
    // `expire`, `reclaim`, `refund_timelock`, `claim` and `is_refundable`.
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), DEADLINE, 0);

    at(&h, DEADLINE);
    assert!(h.client.is_refundable(&id));
    h.client.refund(&h.sender, &id);
    assert_eq!(h.client.get(&id).state, EscrowState::Refunded);
    assert_eq!(balances(&h), (5_000, 0, 0));
}

#[test]
fn refund_boundaries_with_a_grace_period() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), DEADLINE, GRACE);

    // Before the deadline the escrow has not expired at all.
    at(&h, DEADLINE - 1);
    assert_eq!(
        h.client.try_refund(&h.sender, &id),
        Err(Ok(Error::TimeLockActive))
    );
    // From the deadline until the grace period ends, the arbiter may still
    // release, so the refund is refused as grace-active.
    at(&h, DEADLINE);
    assert_eq!(
        h.client.try_refund(&h.sender, &id),
        Err(Ok(Error::GraceActive))
    );
    at(&h, DEADLINE + GRACE - 1);
    assert_eq!(
        h.client.try_refund(&h.sender, &id),
        Err(Ok(Error::GraceActive))
    );
    assert_eq!(balances(&h), (0, 0, 5_000));

    // Refunds open exactly when the grace period ends.
    at(&h, DEADLINE + GRACE);
    h.client.refund(&h.sender, &id);
    assert_eq!(balances(&h), (5_000, 0, 0));
}

#[test]
fn reclaim_before_the_deadline_reports_time_lock_active() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), DEADLINE, GRACE);

    at(&h, DEADLINE - 1);
    assert_eq!(
        h.client.try_reclaim(&h.sender, &id),
        Err(Ok(Error::TimeLockActive))
    );
    at(&h, DEADLINE);
    assert_eq!(
        h.client.try_reclaim(&h.sender, &id),
        Err(Ok(Error::GraceActive))
    );
    assert_eq!(balances(&h), (0, 0, 5_000));
}

#[test]
fn release_closes_exactly_when_refunds_open() {
    let h = setup(10_000, 0);
    let early = create(&h, &one_asset(&h, 5_000), DEADLINE, GRACE);
    let late = create(&h, &one_asset(&h, 5_000), DEADLINE, GRACE);

    // Last second of the grace period: release still allowed.
    at(&h, DEADLINE + GRACE - 1);
    h.client.release(&h.arbiter, &early, &5_000);
    assert_eq!(h.client.get(&early).state, EscrowState::Released);

    // First second refunds are open: release is refused and funds stay put.
    at(&h, DEADLINE + GRACE);
    assert_eq!(
        h.client.try_release(&h.arbiter, &late, &5_000),
        Err(Ok(Error::EscrowExpired))
    );
    assert_eq!(h.client.get(&late).state, EscrowState::Funded);
    assert_eq!(balances(&h), (0, 5_000, 5_000));
}

#[test]
fn double_release_is_rejected_without_a_second_payout() {
    let h = setup(10_000, 0);
    // A second, independent escrow keeps funds in the contract so a duplicate
    // payout would have something to (wrongly) draw on.
    let id = create(&h, &one_asset(&h, 5_000), DEADLINE, 0);
    create(&h, &one_asset(&h, 5_000), DEADLINE, 0);

    h.client.release(&h.arbiter, &id, &5_000);
    assert_eq!(
        h.client.try_release(&h.arbiter, &id, &5_000),
        Err(Ok(Error::InvalidState))
    );
    assert_eq!(balances(&h), (0, 5_000, 5_000));
}

#[test]
fn double_refund_is_rejected_without_a_second_payout() {
    let h = setup(10_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), DEADLINE, 0);
    create(&h, &one_asset(&h, 5_000), DEADLINE, 0);

    at(&h, DEADLINE + 1);
    h.client.refund(&h.sender, &id);
    assert_eq!(
        h.client.try_refund(&h.sender, &id),
        Err(Ok(Error::InvalidState))
    );
    assert_eq!(
        h.client.try_reclaim(&h.sender, &id),
        Err(Ok(Error::InvalidState))
    );
    assert_eq!(balances(&h), (5_000, 0, 5_000));
}

#[test]
fn refund_after_release_is_rejected() {
    let h = setup(10_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), DEADLINE, 0);
    create(&h, &one_asset(&h, 5_000), DEADLINE, 0);

    h.client.release(&h.arbiter, &id, &5_000);
    at(&h, DEADLINE + 1);
    assert_eq!(
        h.client.try_refund(&h.sender, &id),
        Err(Ok(Error::InvalidState))
    );
    assert_eq!(h.client.get(&id).state, EscrowState::Released);
    assert_eq!(balances(&h), (0, 5_000, 5_000));
}

#[test]
fn release_after_refund_is_rejected() {
    let h = setup(10_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), DEADLINE, 0);
    create(&h, &one_asset(&h, 5_000), DEADLINE, 0);

    at(&h, DEADLINE + 1);
    h.client.refund(&h.sender, &id);
    // State is checked before time, so a settled escrow reports InvalidState
    // rather than EscrowExpired.
    assert_eq!(
        h.client.try_release(&h.arbiter, &id, &5_000),
        Err(Ok(Error::InvalidState))
    );
    assert_eq!(h.client.get(&id).state, EscrowState::Refunded);
    assert_eq!(balances(&h), (5_000, 0, 5_000));
}

#[test]
fn refund_rejected_for_anyone_but_the_depositor() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), DEADLINE, 0);
    let stranger = Address::generate(&h.env);

    at(&h, DEADLINE + 1);
    for caller in [&h.recipient, &h.arbiter, &stranger] {
        assert_eq!(
            h.client.try_refund(caller, &id),
            Err(Ok(Error::Unauthorized))
        );
    }
    assert_eq!(h.client.get(&id).state, EscrowState::Funded);
    assert_eq!(balances(&h), (0, 0, 5_000));
}

#[test]
fn release_rejected_for_anyone_but_the_arbiter() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), DEADLINE, 0);
    let stranger = Address::generate(&h.env);

    for caller in [&h.sender, &h.recipient, &stranger] {
        assert_eq!(
            h.client.try_release(caller, &id, &5_000),
            Err(Ok(Error::Unauthorized))
        );
    }
    assert_eq!(h.client.get(&id).state, EscrowState::Funded);
    assert_eq!(balances(&h), (0, 0, 5_000));
}

#[test]
fn refund_and_release_demand_auth_from_the_stored_party() {
    let h = setup(10_000, 0);
    let released = create(&h, &one_asset(&h, 5_000), DEADLINE, 0);
    let refunded = create(&h, &one_asset(&h, 5_000), DEADLINE, 0);

    h.client.release(&h.arbiter, &released, &5_000);
    assert_eq!(
        h.env.auths(),
        std::vec![(
            h.arbiter.clone(),
            AuthorizedInvocation {
                function: AuthorizedFunction::Contract((
                    h.client.address.clone(),
                    Symbol::new(&h.env, "release"),
                    (h.arbiter.clone(), released, 5_000_i128).into_val(&h.env),
                )),
                sub_invocations: std::vec![],
            }
        )]
    );

    at(&h, DEADLINE + 1);
    h.client.refund(&h.sender, &refunded);
    assert_eq!(
        h.env.auths(),
        std::vec![(
            h.sender.clone(),
            AuthorizedInvocation {
                function: AuthorizedFunction::Contract((
                    h.client.address.clone(),
                    Symbol::new(&h.env, "refund"),
                    (h.sender.clone(), refunded).into_val(&h.env),
                )),
                sub_invocations: std::vec![],
            }
        )]
    );
}

#[test]
fn refund_without_the_depositors_signature_fails() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), DEADLINE, 0);

    // Drop the blanket auth mock: nobody has signed anything now, so naming
    // the depositor as `caller` must not be enough to move the funds.
    h.env.set_auths(&[]);
    at(&h, DEADLINE + 1);
    // A failed `require_auth` aborts in the host (not a contract error code).
    assert!(matches!(h.client.try_refund(&h.sender, &id), Err(Err(_))));
    assert!(matches!(
        h.client.try_release(&h.arbiter, &id, &5_000),
        Err(Err(_))
    ));
    // A signature from someone other than the depositor does not help either.
    let stranger = Address::generate(&h.env);
    assert!(matches!(
        h.client
            .mock_auths(&[MockAuth {
                address: &stranger,
                invoke: &MockAuthInvoke {
                    contract: &h.client.address,
                    fn_name: "refund",
                    args: (h.sender.clone(), id).into_val(&h.env),
                    sub_invokes: &[],
                },
            }])
            .try_refund(&h.sender, &id),
        Err(Err(_))
    ));
    assert_eq!(h.client.get(&id).state, EscrowState::Funded);
    assert_eq!(balances(&h), (0, 0, 5_000));

    // Control: once the depositor signs exactly this invocation, it succeeds.
    h.client
        .mock_auths(&[MockAuth {
            address: &h.sender,
            invoke: &MockAuthInvoke {
                contract: &h.client.address,
                fn_name: "refund",
                args: (h.sender.clone(), id).into_val(&h.env),
                sub_invokes: &[],
            },
        }])
        .refund(&h.sender, &id);
    assert_eq!(balances(&h), (5_000, 0, 0));
}

#[test]
fn unknown_escrow_id_is_not_found() {
    let h = setup(5_000, 0);
    create(&h, &one_asset(&h, 5_000), DEADLINE, 0);

    at(&h, DEADLINE + 1);
    assert_eq!(
        h.client.try_refund(&h.sender, &99),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(
        h.client.try_reclaim(&h.sender, &99),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(
        h.client.try_release(&h.arbiter, &99, &5_000),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(h.client.try_get(&99), Err(Ok(Error::NotFound)));
    assert_eq!(balances(&h), (0, 0, 5_000));
}

#[test]
fn create_rejects_non_positive_amounts_and_non_future_expiry() {
    let h = setup(5_000, 0);
    let try_create = |assets: &Vec<AssetAmount>, deadline: u64| {
        h.client.try_create(
            &h.sender,
            &h.recipient,
            &h.arbiter,
            assets,
            &deadline,
            &0,
            &String::from_str(&h.env, "x"),
            &no_signers(&h),
            &0,
        )
    };

    assert_eq!(
        try_create(&one_asset(&h, 0), DEADLINE),
        Err(Ok(Error::InvalidAmount))
    );
    assert_eq!(
        try_create(&one_asset(&h, -1), DEADLINE),
        Err(Ok(Error::InvalidAmount))
    );
    // An expiration equal to "now" is already expired, so it is refused too.
    assert_eq!(
        try_create(&one_asset(&h, 1_000), START),
        Err(Ok(Error::InvalidInput))
    );
    assert_eq!(
        try_create(&one_asset(&h, 1_000), START - 1),
        Err(Ok(Error::InvalidInput))
    );
    assert_eq!(balances(&h), (5_000, 0, 0));
    assert_eq!(h.client.try_get(&1), Err(Ok(Error::NotFound)));
}

// ---------------------------------------------------------------------------
// Issue #216: Escrow release and refund conditions unit tests
// ---------------------------------------------------------------------------

#[test]
fn conditional_release_and_timeout_refund_lifecycle() {
    // 1. Test successful conditional release
    let h = setup(10_000, 0);
    let id1 = create(&h, &one_asset(&h, 4_000), START + 500, GRACE);

    // Beneficiary cannot claim directly before grace/schedule without arbiter
    assert_eq!(
        h.client.try_claim(&h.recipient, &id1),
        Err(Ok(Error::TimeLockActive))
    );

    // Arbiter releases successfully before deadline
    h.client.release(&h.arbiter, &id1, &4_000);
    assert_eq!(h.client.get(&id1).state, EscrowState::Released);
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 4_000);

    // 2. Test timeout refund path accessible only after expiry
    let id2 = create(&h, &one_asset(&h, 6_000), START + 500, GRACE);

    // Before deadline: refund fails with TimeLockActive
    assert_eq!(
        h.client.try_refund(&h.sender, &id2),
        Err(Ok(Error::TimeLockActive))
    );

    // During grace period (START + 500 to START + 1500): refund fails with GraceActive
    h.env.ledger().with_mut(|l| l.timestamp = START + 600);
    assert_eq!(
        h.client.try_refund(&h.sender, &id2),
        Err(Ok(Error::GraceActive))
    );

    // Unauthorized non-sender cannot refund
    let stranger = Address::generate(&h.env);
    assert_eq!(
        h.client.try_refund(&stranger, &id2),
        Err(Ok(Error::Unauthorized))
    );

    // After expiry (deadline + grace_period = START + 1500): refund succeeds
    h.env.ledger().with_mut(|l| l.timestamp = START + 1500);
    h.client.refund(&h.sender, &id2);
    assert_eq!(h.client.get(&id2).state, EscrowState::Refunded);
    assert_eq!(balance(&h, &h.asset_a, &h.sender), 6_000);
}

#[test]
fn mutual_consent_cancel_and_post_grace_reclaim() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), START + 1_000, GRACE);

    // Non-party cannot cancel
    let stranger = Address::generate(&h.env);
    assert_eq!(
        h.client.try_cancel(&stranger, &id),
        Err(Ok(Error::Unauthorized))
    );

    // Arbiter can cancel by mutual consent before deadline
    h.client.cancel(&h.arbiter, &id);
    assert_eq!(h.client.get(&id).state, EscrowState::Refunded);
    assert_eq!(balance(&h, &h.asset_a, &h.sender), 5_000);
}

