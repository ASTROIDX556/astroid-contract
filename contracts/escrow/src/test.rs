extern crate std;

use ed25519_dalek::{Signer, SigningKey};
use soroban_sdk::{
    testutils::{Address as _, Ledger},
    token, Address, BytesN, Env, String, Vec,
};

use astroid_shared::errors::Error;
use astroid_shared::types::AssetAmount;

use crate::{EscrowContract, EscrowContractClient, EscrowState, ReleaseSignature};

const START: u64 = 1_000;
const GRACE: u64 = 1_000;

struct Harness<'a> {
    env: Env,
    client: EscrowContractClient<'a>,
    asset: Address,
    asset2: Address,
    sender: Address,
    recipient: Address,
    arbiter: Address,
}

/// Register an escrow contract plus two test SAC tokens, and mint `funded` of
/// each asset to the sender so `create` moves real value into custody.
fn setup(funded: i128) -> Harness<'static> {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().with_mut(|l| l.timestamp = START);

    let id = env.register_contract(None, EscrowContract);
    let client = EscrowContractClient::new(&env, &id);
    client.initialize();

    let token_admin = Address::generate(&env);
    let asset = env
        .register_stellar_asset_contract_v2(token_admin.clone())
        .address();
    let asset2 = env
        .register_stellar_asset_contract_v2(token_admin)
        .address();

    let sender = Address::generate(&env);
    let recipient = Address::generate(&env);
    let arbiter = Address::generate(&env);
    if funded > 0 {
        token::StellarAssetClient::new(&env, &asset).mint(&sender, &funded);
        token::StellarAssetClient::new(&env, &asset2).mint(&sender, &funded);
    }

    Harness {
        env,
        client,
        asset,
        asset2,
        sender,
        recipient,
        arbiter,
    }
}

fn balance(h: &Harness, asset: &Address, who: &Address) -> i128 {
    token::TokenClient::new(&h.env, asset).balance(who)
}

fn assets_of(h: &Harness, amounts: &[i128]) -> Vec<AssetAmount> {
    let mut v = Vec::new(&h.env);
    let tokens = [&h.asset, &h.asset2];
    for (i, amount) in amounts.iter().enumerate() {
        v.push_back(AssetAmount {
            asset: tokens[i].clone(),
            amount: *amount,
        });
    }
    v
}

fn no_signers(h: &Harness) -> Vec<BytesN<32>> {
    Vec::new(&h.env)
}

fn create(
    h: &Harness,
    assets: &Vec<AssetAmount>,
    deadline: u64,
    release_signers: &Vec<BytesN<32>>,
    release_threshold: u32,
) -> u64 {
    h.client.create(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        assets,
        &deadline,
        &grace_period,
        &String::from_str(&h.env, "payment"),
        release_signers,
        &release_threshold,
    )
}

fn keypair(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn signer_public_key(h: &Harness, key: &SigningKey) -> BytesN<32> {
    BytesN::from_array(&h.env, &key.verifying_key().to_bytes())
}

/// Builds the exact payload `release_with_signatures` verifies against:
/// escrow id followed by nonce, both big-endian — matching
/// `EscrowContract::release_payload` byte-for-byte.
fn payload_bytes(id: u64, nonce: u64) -> [u8; 16] {
    let mut buf = [0u8; 16];
    buf[0..8].copy_from_slice(&id.to_be_bytes());
    buf[8..16].copy_from_slice(&nonce.to_be_bytes());
    buf
}

fn sign(h: &Harness, key: &SigningKey, id: u64, nonce: u64) -> ReleaseSignature {
    let sig = key.sign(&payload_bytes(id, nonce));
    ReleaseSignature {
        signer: signer_public_key(h, key),
        signature: BytesN::from_array(&h.env, &sig.to_bytes()),
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
fn full_cycle_create_release_multi_asset() {
    let h = setup(10_000);
    let assets = assets_of(&h, &[6_000, 4_000]);
    let signers = no_signers(&h);
    let id = create(&h, &assets, START + 86_400, &signers, 0);
    assert_eq!(id, 1);

    // Both assets moved into custody, out of the sender's account.
    assert_eq!(balance(&h, &h.asset, &h.sender), 4_000);
    assert_eq!(balance(&h, &h.asset2, &h.sender), 6_000);
    assert_eq!(balance(&h, &h.asset, &h.client.address), 6_000);
    assert_eq!(balance(&h, &h.asset2, &h.client.address), 4_000);
    assert_eq!(h.client.get(&id).state, EscrowState::Funded);
    assert_eq!(h.client.get(&id).assets.len(), 2);

    h.client.release(&h.arbiter, &id, &10_000);
    assert_eq!(h.client.get(&id).state, EscrowState::Released);
    assert_eq!(balance(&h, &h.asset, &h.recipient), 6_000);
    assert_eq!(balance(&h, &h.asset2, &h.recipient), 4_000);
    assert_eq!(balance(&h, &h.asset, &h.client.address), 0);
    assert_eq!(balance(&h, &h.asset2, &h.client.address), 0);

    h.client.close(&h.sender, &id);
    assert_eq!(h.client.get(&id).state, EscrowState::Closed);
}

#[test]
fn non_arbiter_cannot_release() {
    let h = setup(5_000);
    let assets = assets_of(&h, &[5_000]);
    let id = create(&h, &assets, START + 100, &no_signers(&h), 0);
    let intruder = Address::generate(&h.env);

    let res = h.client.try_release(&intruder, &id, &5_000);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
    assert_eq!(balance(&h, &h.asset, &h.client.address), 5_000);
    assert_eq!(balance(&h, &h.asset, &h.recipient), 0);
}

#[test]
fn release_after_deadline_is_refused() {
    let h = setup(5_000);
    let assets = assets_of(&h, &[5_000]);
    let id = create(&h, &assets, START + 100, &no_signers(&h), 0);

    h.env.ledger().with_mut(|l| l.timestamp = START + 200);
    let res = h.client.try_release(&h.arbiter, &id, &5_000);
    assert_eq!(res, Err(Ok(Error::InvalidState)));
    assert_eq!(h.client.get(&id).state, EscrowState::Funded);
    assert_eq!(balance(&h, &h.asset, &h.client.address), 5_000);
}

#[test]
fn refund_returns_funds_after_deadline() {
    let h = setup(5_000);
    let assets = assets_of(&h, &[5_000, 2_000]);
    let id = create(&h, &assets, START + 100, &no_signers(&h), 0);

    h.env.ledger().with_mut(|l| l.timestamp = START + 200);
    h.client.refund(&h.sender, &id);
    assert_eq!(h.client.get(&id).state, EscrowState::Refunded);
    assert_eq!(balance(&h, &h.asset, &h.sender), 5_000);
    assert_eq!(balance(&h, &h.asset2, &h.sender), 5_000);
    assert_eq!(balance(&h, &h.asset, &h.client.address), 0);
    assert_eq!(balance(&h, &h.asset2, &h.client.address), 0);
}

#[test]
fn refund_before_deadline_rejected() {
    let h = setup(5_000);
    let assets = assets_of(&h, &[5_000]);
    let id = create(&h, &assets, START + 100, &no_signers(&h), 0);

    let res = h.client.try_refund(&h.sender, &id);
    assert_eq!(res, Err(Ok(Error::InvalidState)));
    assert_eq!(balance(&h, &h.asset, &h.client.address), 5_000);
}

#[test]
fn expire_marks_then_refund_returns() {
    let h = setup(5_000);
    let assets = assets_of(&h, &[5_000]);
    let id = create(&h, &assets, START + 100, &no_signers(&h), 0);

    let early = h.client.try_expire(&id);
    assert_eq!(early, Err(Ok(Error::InvalidState)));

    h.env.ledger().with_mut(|l| l.timestamp = START + 200);
    h.client.expire(&id);
    assert_eq!(h.client.get(&id).state, EscrowState::Expired);
    assert_eq!(balance(&h, &h.asset, &h.client.address), 5_000);
    assert_eq!(balance(&h, &h.asset, &h.sender), 0);

    h.client.refund(&h.sender, &id);
    assert_eq!(h.client.get(&id).state, EscrowState::Refunded);
    assert_eq!(balance(&h, &h.asset, &h.sender), 5_000);
    assert_eq!(balance(&h, &h.asset, &h.client.address), 0);
}

#[test]
fn released_escrow_cannot_be_refunded() {
    let h = setup(5_000, 0);
    let id = create(&h, &one_asset(&h, 5_000), START + 100);
    h.client.release(&h.arbiter, &id);

    h.env.ledger().with_mut(|l| l.timestamp = START + 200);
    let res = h.client.try_refund(&h.sender, &id);
    assert_eq!(res, Err(Ok(Error::InvalidState)));
    assert_eq!(balance(&h, &h.asset, &h.recipient), 5_000);
    assert_eq!(balance(&h, &h.asset, &h.client.address), 0);
}

#[test]
fn cannot_close_while_expired() {
    let h = setup(5_000);
    let assets = assets_of(&h, &[5_000]);
    let id = create(&h, &assets, START + 100, &no_signers(&h), 0);
    h.env.ledger().with_mut(|l| l.timestamp = START + 200);
    h.client.expire(&id);

    let res = h.client.try_close(&h.sender, &id);
    assert_eq!(res, Err(Ok(Error::InvalidState)));
    assert_eq!(balance(&h, &h.asset, &h.client.address), 5_000);
}

#[test]
fn create_rejects_bad_input() {
    let h = setup(5_000);
    let signers = no_signers(&h);

    // recipient == sender
    let r1 = h.client.try_create(
        &h.sender,
        &h.sender,
        &h.arbiter,
        &assets_of(&h, &[1_000]),
        &(START + 100),
        &0,
        &String::from_str(&h.env, "x"),
        &signers,
        &0,
    );
    assert_eq!(r1, Err(Ok(Error::InvalidInput)));

    // deadline in the past
    let r2 = h.client.try_create(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &assets_of(&h, &[1_000]),
        &(START - 500),
        &0,
        &String::from_str(&h.env, "x"),
        &signers,
        &0,
    );
    assert_eq!(r2, Err(Ok(Error::InvalidInput)));

    // non-positive amount
    let r3 = h.client.try_create(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &assets_of(&h, &[0]),
        &(START + 100),
        &0,
        &String::from_str(&h.env, "x"),
        &signers,
        &0,
    );
    assert_eq!(r3, Err(Ok(Error::InvalidAmount)));

    // empty asset list
    let r4 = h.client.try_create(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &Vec::new(&h.env),
        &(START + 100),
        &String::from_str(&h.env, "x"),
        &signers,
        &0,
    );
    assert_eq!(r4, Err(Ok(Error::InvalidInput)));

    // duplicate asset in the list
    let dup = {
        let mut v = Vec::new(&h.env);
        v.push_back(AssetAmount {
            asset: h.asset.clone(),
            amount: 100,
        });
        v.push_back(AssetAmount {
            asset: h.asset.clone(),
            amount: 200,
        });
        v
    };
    let r5 = h.client.try_create(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &dup,
        &(START + 100),
        &String::from_str(&h.env, "x"),
        &signers,
        &0,
    );
    assert_eq!(r5, Err(Ok(Error::InvalidInput)));

    // No successful escrow was created, so the sender keeps every token.
    assert_eq!(balance(&h, &h.asset, &h.sender), 5_000);
}

#[test]
fn create_rejects_bad_release_signer_config() {
    let h = setup(5_000);
    let key1 = signer_key(1);
    let pk1 = signer_public_key(&h, &key1);
    let mut one_signer = Vec::new(&h.env);
    one_signer.push_back(pk1.clone());

    // threshold above signer count
    let r1 = h.client.try_create(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &assets_of(&h, &[1_000]),
        &(START + 100),
        &String::from_str(&h.env, "x"),
        &one_signer,
        &2,
    );
    assert_eq!(r1, Err(Ok(Error::InvalidThreshold)));

    // nonzero threshold with no signers configured
    let r2 = h.client.try_create(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &assets_of(&h, &[1_000]),
        &(START + 100),
        &String::from_str(&h.env, "x"),
        &no_signers(&h),
        &1,
    );
    assert_eq!(r2, Err(Ok(Error::InvalidThreshold)));

    // duplicate signer key
    let mut dup_signers = Vec::new(&h.env);
    dup_signers.push_back(pk1.clone());
    dup_signers.push_back(pk1);
    let r3 = h.client.try_create(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &assets_of(&h, &[1_000]),
        &(START + 100),
        &String::from_str(&h.env, "x"),
        &dup_signers,
        &1,
    );
    assert_eq!(r3, Err(Ok(Error::InvalidInput)));
}

#[test]
fn override_release_with_threshold_signatures_succeeds_before_deadline() {
    let h = setup(5_000);
    let key1 = signer_key(1);
    let key2 = signer_key(2);
    let key3 = signer_key(3);
    let mut signers = Vec::new(&h.env);
    signers.push_back(signer_public_key(&h, &key1));
    signers.push_back(signer_public_key(&h, &key2));
    signers.push_back(signer_public_key(&h, &key3));

    let assets = assets_of(&h, &[5_000]);
    // Deadline far in the future — the override must work despite it.
    let id = create(&h, &assets, START + 100_000, &signers, 2);

    let nonce = 42u64;
    let mut sigs = Vec::new(&h.env);
    sigs.push_back(sign(&h, &key1, id, nonce));
    sigs.push_back(sign(&h, &key2, id, nonce));

    let caller = Address::generate(&h.env);
    h.client
        .release_with_signatures(&caller, &id, &nonce, &sigs);

    assert_eq!(h.client.get(&id).state, EscrowState::Released);
    assert_eq!(balance(&h, &h.asset, &h.recipient), 5_000);
    assert!(h.client.nonce_used(&id, &nonce));
}

#[test]
fn override_release_below_threshold_rejected() {
    let h = setup(5_000);
    let key1 = signer_key(1);
    let key2 = signer_key(2);
    let mut signers = Vec::new(&h.env);
    signers.push_back(signer_public_key(&h, &key1));
    signers.push_back(signer_public_key(&h, &key2));

    let assets = assets_of(&h, &[5_000]);
    let id = create(&h, &assets, START + 100_000, &signers, 2);

    let nonce = 1u64;
    let mut sigs = Vec::new(&h.env);
    sigs.push_back(sign(&h, &key1, id, nonce));

    let caller = Address::generate(&h.env);
    let res = h
        .client
        .try_release_with_signatures(&caller, &id, &nonce, &sigs);
    assert_eq!(res, Err(Ok(Error::ThresholdNotMet)));
    assert_eq!(h.client.get(&id).state, EscrowState::Funded);
    assert!(!h.client.nonce_used(&id, &nonce));
}

#[test]
fn override_release_rejects_signer_not_in_set() {
    let h = setup(5_000);
    let key1 = signer_key(1);
    let outsider = signer_key(99);
    let mut signers = Vec::new(&h.env);
    signers.push_back(signer_public_key(&h, &key1));

    let assets = assets_of(&h, &[5_000]);
    let id = create(&h, &assets, START + 100_000, &signers, 1);

    let nonce = 1u64;
    let mut sigs = Vec::new(&h.env);
    sigs.push_back(sign(&h, &outsider, id, nonce));

    let caller = Address::generate(&h.env);
    let res = h
        .client
        .try_release_with_signatures(&caller, &id, &nonce, &sigs);
    assert_eq!(res, Err(Ok(Error::NotASigner)));
}

#[test]
fn override_release_rejects_duplicate_signer_in_submission() {
    let h = setup(5_000);
    let key1 = signer_key(1);
    let key2 = signer_key(2);
    let mut signers = Vec::new(&h.env);
    signers.push_back(signer_public_key(&h, &key1));
    signers.push_back(signer_public_key(&h, &key2));

    let assets = assets_of(&h, &[5_000]);
    let id = create(&h, &assets, START + 100_000, &signers, 2);

    let nonce = 1u64;
    let mut sigs = Vec::new(&h.env);
    let s1 = sign(&h, &key1, id, nonce);
    sigs.push_back(s1.clone());
    sigs.push_back(s1);

    let caller = Address::generate(&h.env);
    let res = h
        .client
        .try_release_with_signatures(&caller, &id, &nonce, &sigs);
    assert_eq!(res, Err(Ok(Error::AlreadySigned)));
}

#[test]
fn override_release_rejects_replayed_nonce() {
    let h = setup(5_000);
    let key1 = signer_key(1);
    let key2 = signer_key(2);
    let mut signers = Vec::new(&h.env);
    signers.push_back(signer_public_key(&h, &key1));
    signers.push_back(signer_public_key(&h, &key2));

    // Two escrows sharing the same override signer set.
    let id1 = create(
        &h,
        &assets_of(&h, &[2_000]),
        START + 100_000,
        &signers,
        2,
    );
    let id2 = create(
        &h,
        &assets_of(&h, &[3_000]),
        START + 100_000,
        &signers,
        2,
    );

    let nonce = 7u64;
    let mut sigs1 = Vec::new(&h.env);
    sigs1.push_back(sign(&h, &key1, id1, nonce));
    sigs1.push_back(sign(&h, &key2, id1, nonce));

    let caller = Address::generate(&h.env);
    h.client
        .release_with_signatures(&caller, &id1, &nonce, &sigs1);

    // Replaying the exact same (id, nonce, signatures) a second time must fail —
    // the nonce for id1 is already consumed.
    let replay = h
        .client
        .try_release_with_signatures(&caller, &id1, &nonce, &sigs1);
    assert_eq!(replay, Err(Ok(Error::AlreadySigned)));

    // Signatures minted for id1 must not authorize release of id2 — the payload
    // binds the escrow id, so verification itself fails (host trap).
    let cross_escrow = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        h.client
            .release_with_signatures(&caller, &id2, &nonce, &sigs1);
    }));
    assert!(cross_escrow.is_err());
    assert_eq!(h.client.get(&id2).state, EscrowState::Funded);
}

#[test]
fn override_release_without_configured_signers_rejected() {
    let h = setup(5_000);
    let assets = assets_of(&h, &[5_000]);
    let id = create(&h, &assets, START + 100_000, &no_signers(&h), 0);

    let caller = Address::generate(&h.env);
    let res = h
        .client
        .try_release_with_signatures(&caller, &id, &0u64, &Vec::new(&h.env));
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

// --- Clawback tests ---

#[test]
fn clawback_after_timeout_succeeds() {
    let h = setup(5_000);
    let id = create(&h, 5_000, START + 100);

    // Advance past the deadline.
    h.env.ledger().with_mut(|l| l.timestamp = START + 200);

    // Sender can clawback after timeout.
    h.client.clawback(&h.sender, &id);
    assert_eq!(h.client.get(&id).state, EscrowState::Refunded);
    // The sender got the real tokens back; custody is empty.
    assert_eq!(balance(&h, &h.sender), 5_000);
    assert_eq!(balance(&h, &h.client.address), 0);
}

#[test]
fn clawback_before_timeout_rejected() {
    let h = setup(5_000);
    let id = create(&h, 5_000, START + 100);

    // Cannot clawback before deadline without cancellation.
    let res = h.client.try_clawback(&h.sender, &id);
    assert_eq!(res, Err(Ok(Error::InvalidState)));
    assert_eq!(balance(&h, &h.client.address), 5_000);
}

#[test]
fn clawback_after_cancel_always_succeeds() {
    let h = setup(5_000);
    let id = create(&h, 5_000, START + 100_000);

    // Cancel the escrow (before deadline).
    h.client.cancel(&h.sender, &id);
    assert!(h.client.get(&id).cancelled);

    // Sender can immediately clawback because escrow is cancelled.
    h.client.clawback(&h.sender, &id);
    assert_eq!(h.client.get(&id).state, EscrowState::Refunded);
    assert_eq!(balance(&h, &h.sender), 5_000);
    assert_eq!(balance(&h, &h.client.address), 0);
}

#[test]
fn arbiter_can_cancel_for_clawback() {
    let h = setup(5_000);
    let id = create(&h, 5_000, START + 100_000);

    // Arbiter can cancel the escrow.
    h.client.cancel(&h.arbiter, &id);
    assert!(h.client.get(&id).cancelled);

    // Sender (organization) can now clawback.
    h.client.clawback(&h.sender, &id);
    assert_eq!(h.client.get(&id).state, EscrowState::Refunded);
    assert_eq!(balance(&h, &h.sender), 5_000);
}

#[test]
fn non_sender_cannot_clawback() {
    let h = setup(5_000);
    let id = create(&h, 5_000, START + 100);

    // Advance past the deadline.
    h.env.ledger().with_mut(|l| l.timestamp = START + 200);

    // Recipient or arbiter cannot clawback — only the sender.
    let res = h.client.try_clawback(&h.recipient, &id);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
}

#[test]
fn non_authorized_cannot_cancel() {
    let h = setup(5_000);
    let id = create(&h, 5_000, START + 100_000);

    let intruder = Address::generate(&h.env);
    let res = h.client.try_cancel(&intruder, &id);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
    assert!(!h.client.get(&id).cancelled);
}

#[test]
fn clawback_rejected_after_release() {
    let h = setup(5_000);
    let id = create(&h, 5_000, START + 100);

    // Release the escrow to the recipient.
    h.client.release(&h.arbiter, &id);
    assert_eq!(h.client.get(&id).state, EscrowState::Released);

    // Even past the deadline, clawback on a released escrow is invalid.
    h.env.ledger().with_mut(|l| l.timestamp = START + 200);
    let res = h.client.try_clawback(&h.sender, &id);
    assert_eq!(res, Err(Ok(Error::InvalidState)));
    // Funds already moved to recipient — nothing left.
    assert_eq!(balance(&h, &h.recipient), 5_000);
    assert_eq!(balance(&h, &h.client.address), 0);
}

#[test]
fn clawback_executes_successfully() {
    let h = setup(5_000);
    let id = create(&h, 5_000, START + 100);

    // Advance past the deadline.
    h.env.ledger().with_mut(|l| l.timestamp = START + 200);

    // Clawback should execute without error and transition state.
    h.client.clawback(&h.sender, &id);
    assert_eq!(h.client.get(&id).state, EscrowState::Refunded);
    // Verify funds were returned to sender.
    assert_eq!(balance(&h, &h.sender), 5_000);
    assert_eq!(balance(&h, &h.client.address), 0);
}

#[test]
fn cancel_and_clawback_time_lock_escrow() {
    let h = setup(5_000);
    let token_admin = Address::generate(&h.env);
    let asset = h
        .env
        .register_stellar_asset_contract_v2(token_admin)
        .address();
    token::StellarAssetClient::new(&h.env, &asset).mint(&h.sender, &3_000);

    let id = h.client.initialize_timelock(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &asset,
        &3_000,
        &(START + 100_000),
        &String::from_str(&h.env, "time-lock"),
    );
    assert_eq!(h.client.get(&id).state, EscrowState::Created);
    assert_eq!(h.client.get(&id).funded_amount, 0);

    // Cancel the time-locked escrow.
    h.client.cancel(&h.sender, &id);
    assert!(h.client.get(&id).cancelled);

    // Note: clawback requires state == Funded or Expired.
    // Created state is not supported for clawback — this is by design.
    let res = h.client.try_clawback(&h.sender, &id);
    assert_eq!(res, Err(Ok(Error::InvalidState)));
}
