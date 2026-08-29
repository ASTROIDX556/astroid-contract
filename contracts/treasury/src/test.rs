use soroban_sdk::{
    testutils::Address as _, testutils::Events, token, Address, Env, IntoVal, String, Symbol, Val,
};

use astroid_shared::errors::Error;

use crate::{TreasuryContract, TreasuryContractClient};

/// Assert that the canonical `ContractEvent` with the given variant symbol was
/// published during the test (single-topic event = the variant name).
fn assert_event(env: &Env, variant: &str) {
    let want: Val = Symbol::new(env, variant).into_val(env);
    let found = env
        .events()
        .all()
        .iter()
        .any(|(_contract_id, topics, _data)| topics.contains(&want));
    assert!(found, "expected ContractEvent::{} to be emitted", variant);
}

struct Harness<'a> {
    env: Env,
    client: TreasuryContractClient<'a>,
    admin: Address,
    asset: Address,
}

/// Register a treasury plus a test SAC token, approve that token for routing,
/// and mint `funded` of the asset to the admin so deposits move real value.
fn setup(org: &str, funded: i128) -> Harness<'static> {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);

    let id = env.register_contract(None, TreasuryContract);
    let client = TreasuryContractClient::new(&env, &id);
    client.initialize(&String::from_str(&env, org), &admin);

    let token_admin = Address::generate(&env);
    let asset = env
        .register_stellar_asset_contract_v2(token_admin)
        .address();
    if funded > 0 {
        token::StellarAssetClient::new(&env, &asset).mint(&admin, &funded);
    }
    client.add_approved_asset(&admin, &asset);

    Harness {
        env,
        client,
        admin,
        asset,
    }
}

fn token_balance(h: &Harness, who: &Address) -> i128 {
    token::TokenClient::new(&h.env, &h.asset).balance(who)
}

#[test]
fn full_flow_deposit_allocate_withdraw() {
    let h = setup("vault", 1_000);
    let recipient = Address::generate(&h.env);

    h.client.deposit(&h.admin, &h.asset, &1_000);
    // Internal accounting and real custody both reflect the deposit.
    assert_eq!(h.client.holding(&h.asset).total_in, 1_000);
    assert_eq!(token_balance(&h, &h.admin), 0);
    assert_eq!(token_balance(&h, &h.client.address), 1_000);

    h.client
        .allocate_budget(&h.admin, &h.asset, &String::from_str(&h.env, "maint"));

    h.client.withdraw(&h.admin, &h.asset, &recipient, &400);
    let holding = h.client.holding(&h.asset);
    assert_eq!(holding.total_in, 600);
    assert_eq!(holding.total_out, 400);
    // Real tokens left custody and reached the recipient.
    assert_eq!(token_balance(&h, &recipient), 400);
    assert_eq!(token_balance(&h, &h.client.address), 600);
}

#[test]
fn withdraw_rejected_when_not_admin() {
    let h = setup("vault", 500);
    let intruder = Address::generate(&h.env);
    h.client.deposit(&h.admin, &h.asset, &500);

    // intruder is not the admin — refused before any value moves.
    let res = h
        .client
        .try_withdraw(&intruder, &h.asset, &Address::generate(&h.env), &100);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
    assert_eq!(token_balance(&h, &h.client.address), 500);
}

#[test]
fn withdraw_overdraws() {
    let h = setup("vault", 50);
    h.client.deposit(&h.admin, &h.asset, &50);

    let res = h
        .client
        .try_withdraw(&h.admin, &h.asset, &Address::generate(&h.env), &100);
    assert_eq!(res, Err(Ok(Error::InsufficientFunds)));
    assert_eq!(token_balance(&h, &h.client.address), 50);
}

#[test]
fn frozen_treasury_rejects_withdrawals() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);
    h.client.freeze(&h.admin);

    let res = h
        .client
        .try_withdraw(&h.admin, &h.asset, &Address::generate(&h.env), &10);
    assert_eq!(res, Err(Ok(Error::InvalidState)));
    assert_eq!(token_balance(&h, &h.client.address), 1_000);
}

#[test]
fn deposit_into_frozen_treasury_rejected() {
    let h = setup("vault", 1_000);
    h.client.freeze(&h.admin);
    let res = h.client.try_deposit(&h.admin, &h.asset, &100);
    assert_eq!(res, Err(Ok(Error::InvalidState)));
    // No value moved on the rejected deposit.
    assert_eq!(token_balance(&h, &h.admin), 1_000);
}

#[test]
fn prepare_holds_state() {
    let h = setup("vault", 0);
    let state = h.client.get();
    assert_eq!(state.org, String::from_str(&h.env, "vault"));
}

#[test]
fn standard_events_emitted() {
    // Configuration changes publish a TreasuryConfigUpdated event. Setting a
    // (here placeholder) policy/budget address is enough to exercise the emit
    // path; we avoid a subsequent withdraw on this env because a real policy
    // gate is not wired up.
    let h = setup("vault", 0);
    h.client.set_policy(&h.admin, &h.admin);
    assert_event(&h.env, "TreasuryConfigUpdated");
    h.client.set_budget(&h.admin, &h.admin);
    assert_event(&h.env, "TreasuryConfigUpdated");

    // A successful withdraw (no policy/budget gates configured) publishes a
    // TransferExecuted event.
    let h2 = setup("vault", 1_000);
    let recipient = Address::generate(&h2.env);
    h2.client.deposit(&h2.admin, &h2.asset, &1_000);
    h2.client.withdraw(&h2.admin, &h2.asset, &recipient, &100);
    assert_event(&h2.env, "TransferExecuted");
}

// ---------------------------------------------------------------------------
// Multi-token asset whitelist and routing validation
// ---------------------------------------------------------------------------

/// Register a second SAC token that the treasury has *not* approved, minting
/// `funded` of it to the admin.
fn unapproved_token(h: &Harness, funded: i128) -> Address {
    let token_admin = Address::generate(&h.env);
    let asset = h
        .env
        .register_stellar_asset_contract_v2(token_admin)
        .address();
    if funded > 0 {
        token::StellarAssetClient::new(&h.env, &asset).mint(&h.admin, &funded);
    }
    asset
}

#[test]
fn governance_adds_and_removes_approved_assets() {
    let h = setup("vault", 100);
    // setup approved exactly one asset.
    assert!(h.client.is_approved_asset(&h.asset));
    assert_eq!(h.client.approved_asset_count(), 1);

    let other = unapproved_token(&h, 0);
    assert!(!h.client.is_approved_asset(&other));

    h.client.add_approved_asset(&h.admin, &other);
    assert!(h.client.is_approved_asset(&other));
    assert_eq!(h.client.approved_asset_count(), 2);

    h.client.remove_approved_asset(&h.admin, &other);
    assert!(!h.client.is_approved_asset(&other));
    assert_eq!(h.client.approved_asset_count(), 1);

    // With nothing approved, the treasury routes nothing at all — which is
    // also the state a freshly initialized treasury starts in.
    h.client.remove_approved_asset(&h.admin, &h.asset);
    assert_eq!(h.client.approved_asset_count(), 0);
    assert_eq!(
        h.client.try_deposit(&h.admin, &h.asset, &10),
        Err(Ok(Error::AssetNotAuthorized))
    );
}

#[test]
fn whitelist_changes_are_idempotency_checked() {
    let h = setup("vault", 0);
    assert_eq!(
        h.client.try_add_approved_asset(&h.admin, &h.asset),
        Err(Ok(Error::AlreadyExists))
    );
    let other = unapproved_token(&h, 0);
    assert_eq!(
        h.client.try_remove_approved_asset(&h.admin, &other),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn only_governance_can_change_the_whitelist() {
    let h = setup("vault", 0);
    let intruder = Address::generate(&h.env);
    let other = unapproved_token(&h, 0);

    assert_eq!(
        h.client.try_add_approved_asset(&intruder, &other),
        Err(Ok(Error::Unauthorized))
    );
    assert!(!h.client.is_approved_asset(&other));

    assert_eq!(
        h.client.try_remove_approved_asset(&intruder, &h.asset),
        Err(Ok(Error::Unauthorized))
    );
    assert!(h.client.is_approved_asset(&h.asset));
}

#[test]
fn deposit_of_an_unapproved_asset_is_refused() {
    let h = setup("vault", 0);
    let rogue = unapproved_token(&h, 1_000);

    let res = h.client.try_deposit(&h.admin, &rogue, &500);
    assert_eq!(res, Err(Ok(Error::AssetNotAuthorized)));
    // The rogue token contract was never invoked: no value moved.
    assert_eq!(
        token::TokenClient::new(&h.env, &rogue).balance(&h.admin),
        1_000
    );
    assert_eq!(h.client.holding(&rogue).total_in, 0);
}

#[test]
fn withdraw_of_an_unapproved_asset_is_refused() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);
    let recipient = Address::generate(&h.env);

    // Revoking approval closes the route without touching the accounting.
    h.client.remove_approved_asset(&h.admin, &h.asset);
    let res = h.client.try_withdraw(&h.admin, &h.asset, &recipient, &100);
    assert_eq!(res, Err(Ok(Error::AssetNotAuthorized)));
    assert_eq!(token_balance(&h, &recipient), 0);
    assert_eq!(token_balance(&h, &h.client.address), 1_000);
    assert_eq!(h.client.holding(&h.asset).total_in, 1_000);

    // Re-approving restores it.
    h.client.add_approved_asset(&h.admin, &h.asset);
    h.client.withdraw(&h.admin, &h.asset, &recipient, &100);
    assert_eq!(token_balance(&h, &recipient), 100);
}

#[test]
fn budget_envelopes_cannot_be_bound_to_unapproved_assets() {
    let h = setup("vault", 0);
    let rogue = unapproved_token(&h, 0);
    let res = h
        .client
        .try_allocate_budget(&h.admin, &rogue, &String::from_str(&h.env, "maint"));
    assert_eq!(res, Err(Ok(Error::AssetNotAuthorized)));
    assert_eq!(h.client.holding(&rogue).budget_id, None);
}

#[test]
fn multiple_approved_assets_route_independently() {
    let h = setup("vault", 1_000);
    let second = unapproved_token(&h, 500);
    h.client.add_approved_asset(&h.admin, &second);
    let recipient = Address::generate(&h.env);

    h.client.deposit(&h.admin, &h.asset, &1_000);
    h.client.deposit(&h.admin, &second, &500);
    h.client.withdraw(&h.admin, &h.asset, &recipient, &400);
    h.client.withdraw(&h.admin, &second, &recipient, &200);

    assert_eq!(h.client.holding(&h.asset).total_out, 400);
    assert_eq!(h.client.holding(&second).total_out, 200);
    assert_eq!(token_balance(&h, &recipient), 400);
    assert_eq!(
        token::TokenClient::new(&h.env, &second).balance(&recipient),
        200
    );

    // Revoking one asset leaves the other fully usable.
    h.client.remove_approved_asset(&h.admin, &second);
    assert_eq!(
        h.client.try_withdraw(&h.admin, &second, &recipient, &10),
        Err(Ok(Error::AssetNotAuthorized))
    );
    h.client.withdraw(&h.admin, &h.asset, &recipient, &100);
    assert_eq!(token_balance(&h, &recipient), 500);
}

#[test]
fn whitelist_changes_emit_events() {
    let h = setup("vault", 0);
    let other = unapproved_token(&h, 0);
    h.client.add_approved_asset(&h.admin, &other);
    assert_event(&h.env, "TreasuryConfigUpdated");
    h.client.remove_approved_asset(&h.admin, &other);
    assert_event(&h.env, "TreasuryConfigUpdated");
}
