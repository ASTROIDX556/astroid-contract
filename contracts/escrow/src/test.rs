use ed25519_dalek::{Signer, SigningKey};
use soroban_sdk::{
    testutils::{Address as _, Ledger},
    token, vec, Address, Bytes, BytesN, Env, String, Vec,
};

use astroid_shared::errors::Error;
use astroid_shared::types::AssetAmount;

use crate::{
    EscrowContract, EscrowContractClient, EscrowState, MilestoneSpec, OverrideSignature,
};

const START: u64 = 1_000;

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

fn create(h: &Harness, assets: &Vec<AssetAmount>, deadline: u64) -> u64 {
    h.client.create(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        assets,
        &deadline,
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
    let id = create(&h, &assets, START + 86_400);
    assert_eq!(id, 1);
    assert_eq!(balance(&h, &h.asset_a, &h.sender), 0);
    assert_eq!(balance(&h, &h.asset_b, &h.sender), 0);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 10_000);
    assert_eq!(balance(&h, &h.asset_b, &h.client.address), 5_000);
    assert_eq!(h.client.get(&id).state, EscrowState::Funded);

    h.client.release(&h.arbiter, &id);
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
    let id = create(&h, &one_asset(&h, 5_000), START + 100);
    let intruder = Address::generate(&h.env);

    let res = h.client.try_release(&intruder, &id);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 5_000);
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 0);
}

#[test]
fn release_after_deadline_is_refused() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), START + 100);

    h.env.ledger().with_mut(|l| l.timestamp = START + 200);
    let res = h.client.try_release(&h.arbiter, &id);
    assert_eq!(res, Err(Ok(Error::EscrowExpired)));
    assert_eq!(h.client.get(&id).state, EscrowState::Funded);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 5_000);
}

#[test]
fn refund_returns_funds_after_deadline() {
    let h = setup(5_000, 2_000);
    let id = create(&h, &two_assets(&h, 5_000, 2_000), START + 100);

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
    let id = create(&h, &one_asset(&h, 5_000), START + 100);

    let res = h.client.try_refund(&h.sender, &id);
    assert_eq!(res, Err(Ok(Error::InvalidState)));
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 5_000);
}

#[test]
fn expire_marks_then_refund_returns() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), START + 100);

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
    let id = create(&h, &one_asset(&h, 5_000), START + 100);
    h.client.release(&h.arbiter, &id);

    h.env.ledger().with_mut(|l| l.timestamp = START + 200);
    let res = h.client.try_refund(&h.sender, &id);
    assert_eq!(res, Err(Ok(Error::InvalidState)));
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 5_000);
    assert_eq!(balance(&h, &h.asset_a, &h.client.address), 0);
}

#[test]
fn cannot_close_while_expired() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), START + 100);
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
    let id = create(&h, &one_asset(&h, 5_000), START + 1_000);

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
    let res = h.client.try_release(&h.arbiter, &id);
    assert_eq!(res, Err(Ok(Error::InvalidState)));
    assert_eq!(balance(&h, &h.asset_a, &h.recipient), 0);
}
