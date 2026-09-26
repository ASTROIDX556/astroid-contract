#![cfg(test)]
extern crate std;

use soroban_sdk::{
    testutils::{Address as _, Events, Ledger},
    token, vec, Address, Env, IntoVal, String, Symbol, Val, Vec,
};

use astroid_shared::constants::MAX_BATCH_PAYMENTS;
use astroid_shared::errors::Error;
use astroid_shared::types::Payment;

use crate::{TreasuryContract, TreasuryContractClient};

/// Assert that the canonical `ContractEvent` with the given variant symbol was
/// published during the test (single-topic event = the variant name).
fn assert_event(env: &Env, variant: &str) {
    let want: Val = Symbol::new(env, variant).into_val(env);
    let found = env
        .events()
        .all()
        .iter()
        .any(|(_contract_id, topics, _data)| topics.contains(want));
    assert!(found, "expected ContractEvent::{} to be emitted", variant);
}

struct Harness<'a> {
    env: Env,
    client: TreasuryContractClient<'a>,
    admin: Address,
    multisig: Address,
    asset: Address,
}

/// Register a treasury plus a test SAC token, approve that token for routing,
/// and mint `funded` of the asset to the admin so deposits move real value.
fn setup(org: &str, funded: i128) -> Harness<'static> {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let multisig = Address::generate(&env);

    let id = env.register_contract(None, TreasuryContract);
    let client = TreasuryContractClient::new(&env, &id);
    client.initialize(&String::from_str(&env, org), &admin);
    client.set_multisig(&admin, &multisig);

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
        multisig,
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
    h.client.freeze(&h.multisig);

    let res = h
        .client
        .try_withdraw(&h.admin, &h.asset, &Address::generate(&h.env), &10);
    assert_eq!(res, Err(Ok(Error::InvalidState)));
    assert_eq!(token_balance(&h, &h.client.address), 1_000);
}

#[test]
fn deposit_into_frozen_treasury_allowed() {
    let h = setup("vault", 1_000);
    h.client.freeze(&h.multisig);
    // Deposits should be allowed even when frozen (only outbound transfers are blocked)
    h.client.deposit(&h.admin, &h.asset, &100);
    // Value moved into the treasury despite being frozen.
    assert_eq!(token_balance(&h, &h.admin), 900);
    assert_eq!(token_balance(&h, &h.client.address), 100);
}

#[test]
fn prepare_holds_state() {
    let h = setup("vault", 0);
    let state = h.client.get();
    assert_eq!(state.org, String::from_str(&h.env, "vault"));
}

#[test]
fn allowance_caps_withdrawal_and_accumulates() {
    let h = setup("vault", 1_000);
    let recipient = Address::generate(&h.env);
    h.client.deposit(&h.admin, &h.asset, &1_000);
    // Approve a 500 ceiling for admin -> recipient in this asset.
    h.client
        .set_allowance(&h.admin, &h.admin, &recipient, &h.asset, &500, &0);

    // First withdrawal within the ceiling succeeds and is deducted.
    h.client.withdraw(&h.admin, &h.asset, &recipient, &400);
    let al = h.client.allowance(&h.admin, &recipient, &h.asset);
    assert_eq!(al.spent, 400);
    assert_eq!(token_balance(&h, &recipient), 400);

    // Second withdrawal exceeds the remaining 100 -> rejected at the allowance gate.
    let res = h.client.try_withdraw(&h.admin, &h.asset, &recipient, &200);
    assert_eq!(res, Err(Ok(Error::AllowanceExceeded)));
    assert_eq!(token_balance(&h, &recipient), 400);

    // A different recipient is not under the allowance, so it is allowed.
    let other = Address::generate(&h.env);
    h.client.withdraw(&h.admin, &h.asset, &other, &100);
    assert_eq!(token_balance(&h, &other), 100);
}

#[test]
fn expired_allowance_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().set_timestamp(10_000);
    let admin = Address::generate(&env);
    let id = env.register_contract(None, TreasuryContract);
    let client = TreasuryContractClient::new(&env, &id);
    client.initialize(&String::from_str(&env, "vault"), &admin);
    let token_admin = Address::generate(&env);
    let asset = env
        .register_stellar_asset_contract_v2(token_admin)
        .address();
    token::StellarAssetClient::new(&env, &asset).mint(&admin, &1_000);
    client.add_approved_asset(&admin, &asset);
    client.deposit(&admin, &asset, &1_000);

    // Allowance already expired (expires_at in the past).
    let recipient = Address::generate(&env);
    client.set_allowance(&admin, &admin, &recipient, &asset, &500, &5_000);
    let res = client.try_withdraw(&admin, &asset, &recipient, &100);
    assert_eq!(res, Err(Ok(Error::AllowanceExpired)));
}

#[test]
fn remove_allowance_clears_cap() {
    let h = setup("vault", 1_000);
    let recipient = Address::generate(&h.env);
    h.client.deposit(&h.admin, &h.asset, &1_000);
    h.client
        .set_allowance(&h.admin, &h.admin, &recipient, &h.asset, &100, &0);
    h.client
        .remove_allowance(&h.admin, &h.admin, &recipient, &h.asset);
    // With no allowance in place the full balance may be withdrawn.
    h.client.withdraw(&h.admin, &h.asset, &recipient, &1_000);
    assert_eq!(token_balance(&h, &recipient), 1_000);
}

#[test]
fn test_milestone_releases() {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let contract_id = env.register_contract(None, TreasuryContract);
    let client = TreasuryContractClient::new(&env, &contract_id);
    client.initialize(&soroban_sdk::String::from_str(&env, "org"), &admin);

    let token = env
        .register_stellar_asset_contract_v2(admin.clone())
        .address();
    let token_admin = token::StellarAssetClient::new(&env, &token);
    let token_client = token::TokenClient::new(&env, &token);
    client.add_approved_asset(&admin, &token);

    let to = Address::generate(&env);

    let mid = client.init_milestone_disbursement(&admin, &token, &to, &1000, &3);
    assert_eq!(mid, 1);

    // Deposit 1000 into treasury so we have funds
    token_admin.mint(&admin, &1000);
    client.deposit(&admin, &token, &1000);

    // release milestone 1
    client.release_next_milestone(&admin, &mid);
    assert_eq!(token_client.balance(&to), 333); // 1000 / 3

    // release milestone 2
    client.release_next_milestone(&admin, &mid);
    assert_eq!(token_client.balance(&to), 666);

    // release milestone 3 (final, catches remainder)
    client.release_next_milestone(&admin, &mid);
    assert_eq!(token_client.balance(&to), 1000);

    // releasing beyond fails
    let res = client.try_release_next_milestone(&admin, &mid);
    assert!(res.is_err());
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
fn balance_reports_actual_custody_across_assets() {
    let h = setup("vault", 1_000);
    let second = unapproved_token(&h, 250);
    h.client.add_approved_asset(&h.admin, &second);
    h.client.deposit(&h.admin, &h.asset, &1_000);
    h.client.deposit(&h.admin, &second, &250);
    token::StellarAssetClient::new(&h.env, &h.asset).mint(&h.client.address, &7);

    assert_eq!(h.client.balance(&h.asset), 1_007);
    assert_eq!(h.client.balance(&second), 250);

    let assets: Vec<Address> = vec![&h.env, second.clone(), h.asset.clone()];
    let report = h.client.balances(&assets);
    assert_eq!(report.len(), 2);
    assert_eq!(report.get(0).unwrap().asset, second);
    assert_eq!(report.get(0).unwrap().balance, 250);
    assert_eq!(report.get(1).unwrap().asset, h.asset);
    assert_eq!(report.get(1).unwrap().balance, 1_007);
}

#[test]
fn balance_queries_require_approved_assets() {
    let h = setup("vault", 0);
    let rogue = unapproved_token(&h, 100);

    assert_eq!(
        h.client.try_balance(&rogue),
        Err(Ok(Error::AssetNotAuthorized))
    );
    let assets: Vec<Address> = vec![&h.env, rogue];
    assert_eq!(
        h.client.try_balances(&assets),
        Err(Ok(Error::AssetNotAuthorized))
    );
}

#[test]
fn balance_report_rejects_duplicate_assets() {
    let h = setup("vault", 0);
    let assets: Vec<Address> = vec![&h.env, h.asset.clone(), h.asset.clone()];

    assert_eq!(h.client.try_balances(&assets), Err(Ok(Error::InvalidInput)));
}

#[test]
fn balance_report_rejects_oversized_asset_lists() {
    let h = setup("vault", 0);
    let mut assets: Vec<Address> = Vec::new(&h.env);
    for _ in 0..33 {
        assets.push_back(Address::generate(&h.env));
    }

    assert_eq!(h.client.try_balances(&assets), Err(Ok(Error::InvalidInput)));
}

#[test]
fn balance_report_is_empty_for_no_assets() {
    let h = setup("vault", 0);
    let assets: Vec<Address> = Vec::new(&h.env);

    assert!(h.client.balances(&assets).is_empty());
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

/// Build one leg of a batch payout.
fn payment(recipient: &Address, amount: i128) -> Payment {
    Payment {
        recipient: recipient.clone(),
        amount,
    }
}

#[test]
fn batch_transfer_pays_every_recipient() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);

    let a = Address::generate(&h.env);
    let b = Address::generate(&h.env);
    let c = Address::generate(&h.env);
    let payments: Vec<Payment> = vec![&h.env, payment(&a, 100), payment(&b, 250), payment(&c, 50)];

    h.client.batch_transfer(&h.admin, &h.asset, &payments);

    assert_eq!(token_balance(&h, &a), 100);
    assert_eq!(token_balance(&h, &b), 250);
    assert_eq!(token_balance(&h, &c), 50);
    assert_eq!(token_balance(&h, &h.client.address), 600);

    // Internal accounting mirrors the aggregate payout exactly once.
    let holding = h.client.holding(&h.asset);
    assert_eq!(holding.total_in, 600);
    assert_eq!(holding.total_out, 400);

    assert_event(&h.env, "BatchTransferExecuted");
}

#[test]
fn batch_transfer_over_balance_pays_nobody() {
    let h = setup("vault", 300);
    h.client.deposit(&h.admin, &h.asset, &300);

    let a = Address::generate(&h.env);
    let b = Address::generate(&h.env);
    // Each leg fits on its own, but the cumulative total overdraws the treasury.
    let payments: Vec<Payment> = vec![&h.env, payment(&a, 200), payment(&b, 200)];

    let res = h.client.try_batch_transfer(&h.admin, &h.asset, &payments);
    assert_eq!(res, Err(Ok(Error::InsufficientFunds)));

    // Nothing partially executed: no recipient was paid and custody is intact.
    assert_eq!(token_balance(&h, &a), 0);
    assert_eq!(token_balance(&h, &b), 0);
    assert_eq!(token_balance(&h, &h.client.address), 300);
    let holding = h.client.holding(&h.asset);
    assert_eq!(holding.total_in, 300);
    assert_eq!(holding.total_out, 0);
}

#[test]
fn batch_transfer_rolls_back_when_one_leg_is_invalid() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);

    let a = Address::generate(&h.env);
    let b = Address::generate(&h.env);
    let c = Address::generate(&h.env);
    // The middle leg is a zero-amount payment, which invalidates the batch.
    let payments: Vec<Payment> = vec![&h.env, payment(&a, 100), payment(&b, 0), payment(&c, 100)];

    let res = h.client.try_batch_transfer(&h.admin, &h.asset, &payments);
    assert_eq!(res, Err(Ok(Error::InvalidAmount)));

    // The legs preceding the bad one are rolled back with the rest of the batch.
    assert_eq!(token_balance(&h, &a), 0);
    assert_eq!(token_balance(&h, &c), 0);
    assert_eq!(token_balance(&h, &h.client.address), 1_000);
    assert_eq!(h.client.holding(&h.asset).total_out, 0);
}

#[test]
fn batch_transfer_rejected_when_not_admin() {
    let h = setup("vault", 500);
    h.client.deposit(&h.admin, &h.asset, &500);

    let intruder = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    let payments: Vec<Payment> = vec![&h.env, payment(&recipient, 10)];

    let res = h.client.try_batch_transfer(&intruder, &h.asset, &payments);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
    assert_eq!(token_balance(&h, &h.client.address), 500);
}

#[test]
fn batch_transfer_rejected_when_frozen() {
    let h = setup("vault", 500);
    h.client.deposit(&h.admin, &h.asset, &500);
    h.client.freeze(&h.multisig);

    let recipient = Address::generate(&h.env);
    let payments: Vec<Payment> = vec![&h.env, payment(&recipient, 10)];

    let res = h.client.try_batch_transfer(&h.admin, &h.asset, &payments);
    assert_eq!(res, Err(Ok(Error::InvalidState)));
    assert_eq!(token_balance(&h, &recipient), 0);
}

#[test]
fn batch_transfer_rejects_empty_and_oversized_batches() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);

    let empty: Vec<Payment> = Vec::new(&h.env);
    assert_eq!(
        h.client.try_batch_transfer(&h.admin, &h.asset, &empty),
        Err(Ok(Error::InvalidInput))
    );

    let mut oversized: Vec<Payment> = Vec::new(&h.env);
    for _ in 0..(MAX_BATCH_PAYMENTS + 1) {
        let r = Address::generate(&h.env);
        oversized.push_back(payment(&r, 1));
    }
    assert_eq!(
        h.client.try_batch_transfer(&h.admin, &h.asset, &oversized),
        Err(Ok(Error::InvalidInput))
    );
    assert_eq!(token_balance(&h, &h.client.address), 1_000);
}

#[test]
fn batch_transfer_at_the_maximum_size_succeeds() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);

    let mut payments: Vec<Payment> = Vec::new(&h.env);
    let mut recipients = std::vec::Vec::new();
    for _ in 0..MAX_BATCH_PAYMENTS {
        let r = Address::generate(&h.env);
        payments.push_back(payment(&r, 5));
        recipients.push(r);
    }

    h.client.batch_transfer(&h.admin, &h.asset, &payments);

    for r in recipients.iter() {
        assert_eq!(token_balance(&h, r), 5);
    }
    let holding = h.client.holding(&h.asset);
    assert_eq!(holding.total_out, 5 * MAX_BATCH_PAYMENTS as i128);
    assert_eq!(holding.total_in, 1_000 - 5 * MAX_BATCH_PAYMENTS as i128);
}

#[test]
fn emergency_freeze_rejected_by_non_multisig() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);

    // Admin should not be able to freeze - only multisig
    let res = h.client.try_freeze(&h.admin);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));

    // Random address should also be rejected
    let intruder = Address::generate(&h.env);
    let res = h.client.try_freeze(&intruder);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));

    // Ensure transfers still work
    let recipient = Address::generate(&h.env);
    h.client.withdraw(&h.admin, &h.asset, &recipient, &100);
    assert_eq!(token_balance(&h, &recipient), 100);
}

#[test]
fn emergency_freeze_by_multisig_blocks_transfers() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);

    // Multisig can freeze
    h.client.freeze(&h.multisig);

    // All outbound transfers should be blocked
    let recipient = Address::generate(&h.env);
    let res = h.client.try_withdraw(&h.admin, &h.asset, &recipient, &100);
    assert_eq!(res, Err(Ok(Error::InvalidState)));

    let payments: Vec<Payment> = vec![&h.env, payment(&recipient, 50)];
    let res = h.client.try_batch_transfer(&h.admin, &h.asset, &payments);
    assert_eq!(res, Err(Ok(Error::InvalidState)));

    // Verify funds are still in treasury
    assert_eq!(token_balance(&h, &h.client.address), 1_000);
}

#[test]
fn emergency_unfreeze_restores_transfers() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);

    // Freeze with multisig
    h.client.freeze(&h.multisig);

    // Verify frozen state blocks transfers
    let recipient = Address::generate(&h.env);
    let res = h.client.try_withdraw(&h.admin, &h.asset, &recipient, &100);
    assert_eq!(res, Err(Ok(Error::InvalidState)));

    // Unfreeze with multisig
    h.client.unfreeze(&h.multisig);

    // Transfers should work again
    h.client.withdraw(&h.admin, &h.asset, &recipient, &100);
    assert_eq!(token_balance(&h, &recipient), 100);
    assert_eq!(token_balance(&h, &h.client.address), 900);
}

#[test]
fn emergency_unfreeze_rejected_by_non_multisig() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);

    // Freeze with multisig
    h.client.freeze(&h.multisig);

    // Admin should not be able to unfreeze
    let res = h.client.try_unfreeze(&h.admin);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));

    // Random address should also be rejected
    let intruder = Address::generate(&h.env);
    let res = h.client.try_unfreeze(&intruder);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));

    // Should still be frozen
    let recipient = Address::generate(&h.env);
    let res = h.client.try_withdraw(&h.admin, &h.asset, &recipient, &100);
    assert_eq!(res, Err(Ok(Error::InvalidState)));
}

#[test]
fn emergency_unfreeze_without_freeze_fails() {
    let h = setup("vault", 1_000);

    // Trying to unfreeze when not frozen should fail
    let res = h.client.try_unfreeze(&h.multisig);
    assert_eq!(res, Err(Ok(Error::InvalidState)));
}

#[test]
fn treasury_frozen_and_unfrozen_events_emitted() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);

    // Freeze should emit TreasuryFrozen event
    h.client.freeze(&h.multisig);
    assert_event(&h.env, "TreasuryFrozen");

    // Unfreeze should emit TreasuryUnfrozen event
    h.client.unfreeze(&h.multisig);
    assert_event(&h.env, "TreasuryUnfrozen");
}

#[test]
fn freeze_without_multisig_configured_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);

    let id = env.register_contract(None, TreasuryContract);
    let client = TreasuryContractClient::new(&env, &id);
    client.initialize(&String::from_str(&env, "vault"), &admin);

    // Try to freeze without setting multisig - should fail
    let res = client.try_freeze(&admin);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
}

// ---------------------------------------------------------------------------
// Emergency circuit breaker (pause / unpause)
// ---------------------------------------------------------------------------

#[test]
fn unauthorized_pause_attempts_are_rejected() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);
    let intruder = Address::generate(&h.env);

    // Neither direction is open to a stranger, and neither call mutates the
    // pause flag.
    assert_eq!(h.client.try_pause(&intruder), Err(Ok(Error::Unauthorized)));
    assert_eq!(
        h.client.try_unpause(&intruder),
        Err(Ok(Error::Unauthorized))
    );
    assert!(!h.client.is_paused());

    // Outflows still work, because the breaker never engaged.
    let recipient = Address::generate(&h.env);
    h.client.withdraw(&h.admin, &h.asset, &recipient, &100);
    assert_eq!(token_balance(&h, &recipient), 100);
}

#[test]
fn guardian_can_pause_and_unpause() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);

    // Bootstrap: the admin is recorded as the initial guardian, and a fresh
    // treasury starts with the breaker disengaged.
    assert_eq!(h.client.guardian(), h.admin);
    assert!(!h.client.is_paused());

    h.client.pause(&h.admin);
    assert!(h.client.is_paused());
    assert_event(&h.env, "TreasuryConfigUpdated");

    h.client.unpause(&h.admin);
    assert!(!h.client.is_paused());
    assert_event(&h.env, "TreasuryConfigUpdated");
}

#[test]
fn multisig_can_pause_and_unpause() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);

    // The organization's multisig holds the authority independently of the
    // guardian slot.
    h.client.pause(&h.multisig);
    assert!(h.client.is_paused());
    h.client.unpause(&h.multisig);
    assert!(!h.client.is_paused());
}

#[test]
fn pause_blocks_outflows_and_keeps_inflows_open() {
    // 1_500 minted so 1_000 can be deposited now and 500 more during the pause.
    let h = setup("vault", 1_500);
    h.client.deposit(&h.admin, &h.asset, &1_000);
    h.client.pause(&h.admin);

    let recipient = Address::generate(&h.env);

    // Single withdrawal refused with the dedicated code; nothing moved.
    let res = h.client.try_withdraw(&h.admin, &h.asset, &recipient, &100);
    assert_eq!(res, Err(Ok(Error::TreasuryPaused)));
    assert_eq!(token_balance(&h, &recipient), 0);

    // Batch payout refused with the same code; no leg is paid.
    let payments: Vec<Payment> = vec![&h.env, payment(&recipient, 50)];
    let res = h.client.try_batch_transfer(&h.admin, &h.asset, &payments);
    assert_eq!(res, Err(Ok(Error::TreasuryPaused)));
    assert_eq!(token_balance(&h, &recipient), 0);
    assert_eq!(h.client.holding(&h.asset).total_out, 0);

    // Inbound deposits stay open during a pause, so recovery funding arrives.
    h.client.deposit(&h.admin, &h.asset, &500);
    assert_eq!(token_balance(&h, &h.client.address), 1_500);
    assert_eq!(h.client.holding(&h.asset).total_in, 1_500);

    // Releasing the breaker restores every outflow.
    h.client.unpause(&h.admin);
    h.client.withdraw(&h.admin, &h.asset, &recipient, &100);
    assert_eq!(token_balance(&h, &recipient), 100);
    assert_eq!(token_balance(&h, &h.client.address), 1_400);
}

#[test]
fn pause_blocks_milestone_disbursement() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);
    let to = Address::generate(&h.env);
    let mid = h
        .client
        .init_milestone_disbursement(&h.admin, &h.asset, &to, &1_000, &3);

    h.client.pause(&h.admin);
    let res = h.client.try_release_next_milestone(&h.admin, &mid);
    assert_eq!(res, Err(Ok(Error::TreasuryPaused)));
    assert_eq!(token_balance(&h, &to), 0);

    h.client.unpause(&h.admin);
    h.client.release_next_milestone(&h.admin, &mid);
    assert_eq!(token_balance(&h, &to), 333);
}

#[test]
fn pause_toggle_is_idempotency_checked() {
    let h = setup("vault", 0);
    // Unpausing a treasury that was never paused is rejected.
    assert_eq!(h.client.try_unpause(&h.admin), Err(Ok(Error::InvalidState)));
    h.client.pause(&h.admin);
    // Pausing twice is rejected rather than silently accepted.
    assert_eq!(h.client.try_pause(&h.admin), Err(Ok(Error::InvalidState)));
    assert!(h.client.is_paused());
}

#[test]
fn pause_and_freeze_report_distinct_codes() {
    let h = setup("vault", 1_000);
    h.client.deposit(&h.admin, &h.asset, &1_000);
    let recipient = Address::generate(&h.env);

    // The multisig freeze is the structural stop and reports InvalidState.
    h.client.freeze(&h.multisig);
    assert_eq!(
        h.client.try_withdraw(&h.admin, &h.asset, &recipient, &10),
        Err(Ok(Error::InvalidState))
    );
    h.client.unfreeze(&h.multisig);

    // The guardian pause is the circuit breaker and reports TreasuryPaused.
    h.client.pause(&h.admin);
    assert_eq!(
        h.client.try_withdraw(&h.admin, &h.asset, &recipient, &10),
        Err(Ok(Error::TreasuryPaused))
    );
    assert_eq!(
        h.client
            .try_batch_transfer(&h.admin, &h.asset, &vec![&h.env, payment(&recipient, 10)]),
        Err(Ok(Error::TreasuryPaused))
    );
}

#[test]
fn set_guardian_rotates_pause_authority() {
    let h = setup("vault", 1_000);
    let new_guardian = Address::generate(&h.env);

    // Only the admin may rotate the guardian.
    let intruder = Address::generate(&h.env);
    assert_eq!(
        h.client.try_set_guardian(&intruder, &new_guardian),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(h.client.guardian(), h.admin);

    h.client.set_guardian(&h.admin, &new_guardian);
    assert_eq!(h.client.guardian(), new_guardian);

    // The superseded guardian has lost the authority; the new one holds it.
    assert_eq!(h.client.try_pause(&h.admin), Err(Ok(Error::Unauthorized)));
    h.client.pause(&new_guardian);
    assert!(h.client.is_paused());

    // The multisig keeps its own, independent authority throughout.
    h.client.unpause(&h.multisig);
    assert!(!h.client.is_paused());
}

// ---------------------------------------------------------------------------
// Deterministic error codes
//
// The treasury holds the protocol's working capital, so a refusal has to say
// which of the several distinct problems it was: a caller that is not the
// admin, an asset that was never whitelisted, an allowance that is spent or
// expired, or a balance that simply is not there.
// ---------------------------------------------------------------------------

/// A treasury that was never initialized, with no asset wired.
fn uninitialized() -> (Env, TreasuryContractClient<'static>) {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register_contract(None, TreasuryContract);
    let client = TreasuryContractClient::new(&env, &id);
    (env, client)
}

#[test]
fn uninitialized_treasury_reports_not_initialized_on_every_entry_point() {
    let (env, client) = uninitialized();
    let admin = Address::generate(&env);
    let asset = env
        .register_stellar_asset_contract_v2(Address::generate(&env))
        .address();
    let stranger = Address::generate(&env);

    // `load` used to unwrap, so each of these trapped the whole invocation with
    // an opaque host error instead of a code the caller could act on.
    assert_eq!(client.try_get(), Err(Ok(Error::NotInitialized)));
    assert_eq!(client.try_guardian(), Err(Ok(Error::NotInitialized)));
    assert_eq!(
        client.try_add_approved_asset(&admin, &asset),
        Err(Ok(Error::NotInitialized))
    );
    assert_eq!(
        client.try_deposit(&admin, &asset, &1),
        Err(Ok(Error::NotInitialized))
    );
    assert_eq!(
        client.try_withdraw(&admin, &asset, &stranger, &1),
        Err(Ok(Error::NotInitialized))
    );
    assert_eq!(client.try_pause(&admin), Err(Ok(Error::NotInitialized)));

    // "Not paused" must stay a readable question even with no record on file.
    assert!(!client.is_paused());
}

#[test]
fn initialize_twice_is_already_initialized() {
    let (env, client) = uninitialized();
    let admin = Address::generate(&env);
    client.initialize(&String::from_str(&env, "acme"), &admin);
    let other = Address::generate(&env);

    // A refused re-initialization must not reassign the admin.
    assert_eq!(
        client.try_initialize(&String::from_str(&env, "other"), &other),
        Err(Ok(Error::AlreadyInitialized))
    );
    assert_eq!(client.get().admin, admin);
    assert_eq!(client.get().org, String::from_str(&env, "acme"));
}

#[test]
fn non_positive_amounts_are_invalid_amount_on_the_treasury() {
    let h = setup("acme", 1_000);
    let recipient = Address::generate(&h.env);

    // The amount guard is its own diagnosis, shared by every value path here.
    for amount in [0, -1] {
        assert_eq!(
            h.client.try_deposit(&h.admin, &h.asset, &amount),
            Err(Ok(Error::InvalidAmount))
        );
        assert_eq!(
            h.client
                .try_withdraw(&h.admin, &h.asset, &recipient, &amount),
            Err(Ok(Error::InvalidAmount))
        );
        assert_eq!(
            h.client
                .try_set_allowance(&h.admin, &h.admin, &recipient, &h.asset, &amount, &0),
            Err(Ok(Error::InvalidAmount))
        );
    }
    // Nothing moved in either direction.
    assert_eq!(token_balance(&h, &h.client.address), 0);
    assert_eq!(h.client.balance(&h.asset), 0);
}

#[test]
fn withdrawal_beyond_custody_reports_insufficient_funds() {
    let h = setup("acme", 1_000);
    let recipient = Address::generate(&h.env);
    h.client.deposit(&h.admin, &h.asset, &1_000);

    // One unit past the recorded holding is refused, and the holding is intact.
    assert_eq!(
        h.client
            .try_withdraw(&h.admin, &h.asset, &recipient, &1_001),
        Err(Ok(Error::InsufficientFunds))
    );
    assert_eq!(h.client.balance(&h.asset), 1_000);
    assert_eq!(token_balance(&h, &recipient), 0);

    // Draining to exactly zero is allowed; only the next unit fails.
    h.client.withdraw(&h.admin, &h.asset, &recipient, &1_000);
    assert_eq!(h.client.balance(&h.asset), 0);
    assert_eq!(
        h.client.try_withdraw(&h.admin, &h.asset, &recipient, &1),
        Err(Ok(Error::InsufficientFunds))
    );
}

#[test]
fn exhausted_and_expired_allowances_have_their_own_codes() {
    let h = setup("acme", 1_000);
    let recipient = Address::generate(&h.env);
    h.client.deposit(&h.admin, &h.asset, &1_000);
    // `expires_at == 0` means the ceiling never lapses.
    h.client
        .set_allowance(&h.admin, &h.admin, &recipient, &h.asset, &100, &0);

    // Spending the whole cap is fine; the next request is over the limit, which
    // is a different diagnosis from the treasury itself being short.
    h.client.withdraw(&h.admin, &h.asset, &recipient, &100);
    assert_eq!(
        h.client.try_withdraw(&h.admin, &h.asset, &recipient, &1),
        Err(Ok(Error::AllowanceExceeded))
    );
    assert_eq!(token_balance(&h, &recipient), 100);

    // A lapsed ceiling is reported as expiry, never as exhaustion — the two
    // call for different responses from whoever holds the mandate.
    h.client
        .set_allowance(&h.admin, &h.admin, &recipient, &h.asset, &100, &1);
    h.env.ledger().set_timestamp(2);
    assert_eq!(
        h.client.try_withdraw(&h.admin, &h.asset, &recipient, &1),
        Err(Ok(Error::AllowanceExpired))
    );

    // A self-directed allowance would gate nothing.
    assert_eq!(
        h.client
            .try_set_allowance(&h.admin, &recipient, &recipient, &h.asset, &10, &0),
        Err(Ok(Error::InvalidInput))
    );
}

#[test]
fn non_admin_spends_are_unauthorized() {
    let h = setup("acme", 1_000);
    let recipient = Address::generate(&h.env);
    let stranger = Address::generate(&h.env);
    h.client.deposit(&h.admin, &h.asset, &1_000);

    // The treasury records exactly one admin; a stranger is not the multisig or
    // the guardian either, so nothing rescues the call.
    assert_eq!(
        h.client.try_withdraw(&stranger, &h.asset, &recipient, &1),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(h.client.try_pause(&stranger), Err(Ok(Error::Unauthorized)));
    assert_eq!(
        h.client
            .try_set_allowance(&stranger, &stranger, &recipient, &h.asset, &10, &0),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(h.client.balance(&h.asset), 1_000);
    assert_eq!(token_balance(&h, &recipient), 0);
}

#[test]
fn batch_payments_reject_malformed_input_before_any_leg_runs() {
    let h = setup("acme", 1_000);
    let a = Address::generate(&h.env);
    let b = Address::generate(&h.env);
    h.client.deposit(&h.admin, &h.asset, &1_000);

    // An empty batch is malformed input, not a successful no-op.
    let empty: Vec<Payment> = Vec::new(&h.env);
    assert_eq!(
        h.client.try_batch_transfer(&h.admin, &h.asset, &empty),
        Err(Ok(Error::InvalidInput))
    );

    // One leg past the cap is refused on size alone, before any amount check.
    let mut over: Vec<Payment> = Vec::new(&h.env);
    for _ in 0..=MAX_BATCH_PAYMENTS {
        over.push_back(payment(&a, 1));
    }
    assert_eq!(
        h.client.try_batch_transfer(&h.admin, &h.asset, &over),
        Err(Ok(Error::InvalidInput))
    );
    assert_eq!(token_balance(&h, &a), 0);

    // A batch whose total exceeds custody is refused as exhaustion, even though
    // every individual leg is well formed.
    let mut big: Vec<Payment> = Vec::new(&h.env);
    big.push_back(payment(&a, 600));
    big.push_back(payment(&b, 600));
    assert_eq!(
        h.client.try_batch_transfer(&h.admin, &h.asset, &big),
        Err(Ok(Error::InsufficientFunds))
    );
    assert_eq!(token_balance(&h, &a), 0);
    assert_eq!(token_balance(&h, &b), 0);
    assert_eq!(h.client.balance(&h.asset), 1_000);
}
