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

/// A fixed, deterministic Ed25519 keypair for override-release signers, keyed
/// by a single seed byte so tests can cheaply mint distinct signers.
fn signer_key(seed: u8) -> SigningKey {
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
    let h = setup(5_000);
    let assets = assets_of(&h, &[5_000]);
    let id = create(&h, &assets, START + 100, &no_signers(&h), 0);
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
}
