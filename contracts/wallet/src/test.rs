#![cfg(test)]
extern crate std;

use crate::access::Role;
use crate::{BatchAction, BatchReceipt, ContractCall, WalletContract, WalletContractClient};
use astroid_shared::errors::Error;
use astroid_shared::types::ResourceState;
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{
    contract, contractimpl, contracttype, testutils::Events, token, Address, Env, IntoVal, String,
    Symbol, Val, Vec,
};

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

struct Harness {
    env: Env,
    client: WalletContractClient<'static>,
    admin: Address,
    token: Address,
    contract_id: Address,
}

fn setup() -> Harness {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let contract_id = env.register_contract(None, WalletContract);
    let client = WalletContractClient::new(&env, &contract_id);
    client.initialize(&admin);

    // A test SAC token whose admin can mint funds to users.
    let token_admin = Address::generate(&env);
    let token = env
        .register_stellar_asset_contract_v2(token_admin.clone())
        .address();

    Harness {
        env,
        client,
        admin,
        token,
        contract_id,
    }
}

fn mint(h: &Harness, to: &Address, amount: i128) {
    let sac = token::StellarAssetClient::new(&h.env, &h.token);
    sac.mint(to, &amount);
}

fn token_balance(h: &Harness, who: &Address) -> i128 {
    token::TokenClient::new(&h.env, &h.token).balance(who)
}

#[test]
fn create_wallet_starts_active() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    let w = h.client.get_wallet(&id);
    assert_eq!(w.owner, owner);
    assert_eq!(w.state, ResourceState::Active);
}

#[test]
fn deposit_credits_internal_balance_and_moves_tokens() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    mint(&h, &owner, 1_000);

    h.client.deposit(&id, &owner, &h.token, &400);
    assert_eq!(h.client.balance(&id, &h.token), 400);
    assert_eq!(token_balance(&h, &owner), 600);
}

#[test]
fn transfer_moves_value_and_debits_wallet() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    mint(&h, &owner, 1_000);
    h.client.deposit(&id, &owner, &h.token, &1_000);

    h.client.transfer(&owner, &id, &recipient, &h.token, &250);
    assert_eq!(h.client.balance(&id, &h.token), 750);
    assert_eq!(token_balance(&h, &recipient), 250);
}

#[test]
fn withdraw_returns_to_owner() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    mint(&h, &owner, 1_000);
    h.client.deposit(&id, &owner, &h.token, &1_000);

    h.client.withdraw(&owner, &id, &h.token, &300);
    assert_eq!(h.client.balance(&id, &h.token), 700);
    assert_eq!(token_balance(&h, &owner), 300);
}

#[test]
fn transfer_more_than_balance_fails() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    mint(&h, &owner, 100);
    h.client.deposit(&id, &owner, &h.token, &100);

    let res = h
        .client
        .try_transfer(&owner, &id, &recipient, &h.token, &500);
    assert_eq!(res, Err(Ok(Error::InsufficientFunds)));
}

#[test]
fn non_owner_cannot_transfer() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let intruder = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    mint(&h, &owner, 100);
    h.client.deposit(&id, &owner, &h.token, &100);

    let res = h
        .client
        .try_transfer(&intruder, &id, &recipient, &h.token, &10);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
}

#[test]
fn transfer_while_frozen_fails_wallet_frozen() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    mint(&h, &owner, 100);
    h.client.deposit(&id, &owner, &h.token, &100);

    h.client.freeze(&owner, &id);
    assert_eq!(h.client.get_wallet(&id).state, ResourceState::Frozen);

    let res = h
        .client
        .try_transfer(&owner, &id, &recipient, &h.token, &10);
    assert_eq!(res, Err(Ok(Error::WalletFrozen)));
}

#[test]
fn admin_can_freeze_then_owner_unfreezes() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);

    // Owner freezes, then unfreezes back to Active.
    h.client.freeze(&owner, &id);
    h.client.unfreeze(&owner, &id);
    assert_eq!(h.client.get_wallet(&id).state, ResourceState::Active);
}

#[test]
fn transfer_while_paused_fails() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    mint(&h, &owner, 100);
    h.client.deposit(&id, &owner, &h.token, &100);

    h.client.pause(&owner, &id);
    let res = h
        .client
        .try_transfer(&owner, &id, &recipient, &h.token, &10);
    assert_eq!(res, Err(Ok(Error::WalletPaused)));

    h.client.unpause(&owner, &id);
    h.client.transfer(&owner, &id, &recipient, &h.token, &10);
    assert_eq!(token_balance(&h, &recipient), 10);
}

#[test]
fn archived_wallet_rejects_transfer_and_deposit() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    mint(&h, &owner, 100);
    h.client.deposit(&id, &owner, &h.token, &100);

    h.client.archive(&owner, &id);
    assert_eq!(h.client.get_wallet(&id).state, ResourceState::Archived);

    assert_eq!(
        h.client
            .try_transfer(&owner, &id, &recipient, &h.token, &10),
        Err(Ok(Error::WalletArchived))
    );
    mint(&h, &owner, 100);
    assert_eq!(
        h.client.try_deposit(&id, &owner, &h.token, &10),
        Err(Ok(Error::WalletArchived))
    );
}

#[test]
fn zero_amount_transfer_rejected() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    let res = h.client.try_transfer(&owner, &id, &recipient, &h.token, &0);
    assert_eq!(res, Err(Ok(Error::InvalidAmount)));
}

#[test]
fn unknown_wallet_fails_not_found() {
    let h = setup();
    let stranger = Address::generate(&h.env);
    let res = h.client.try_get_wallet(&999);
    assert_eq!(res, Err(Ok(Error::NotFound)));
    let res2 = h.client.try_freeze(&stranger, &999);
    assert_eq!(res2, Err(Ok(Error::NotFound)));
}

#[test]
fn standard_events_emitted() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    assert_event(&h.env, "WalletCreated");

    h.client.freeze(&owner, &id);
    assert_event(&h.env, "WalletStateChanged");
}

// ---------------------------------------------------------------------------
// Dispatch authorization tests
// ---------------------------------------------------------------------------

/// Helper: register a mock module in the registry for the test org.
fn register_mock_module(h: &Harness, kind: ModuleKind, addr: &Address) {
    // In tests the registry is a mock that always returns the registered address.
    // We store the mapping directly for the test harness.
    h.env.as_contract(&h.client.address, || {
        h.env
            .storage()
            .persistent()
            .set(&(kind.clone(), h.org.clone()), addr);
    });
}

#[test]
fn dispatch_owner_can_transfer() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    mint(&h, &owner, 1_000);
    h.client.deposit(&id, &owner, &h.token, &1_000);

    let action = WalletAction::Transfer {
        to: recipient.clone(),
        asset: h.token.clone(),
        amount: 250,
    };
    h.client.dispatch(&owner, &id, &action);

    assert_eq!(h.client.balance(&id, &h.token), 750);
    assert_eq!(token_balance(&h, &recipient), 250);
}

#[test]
fn dispatch_owner_can_freeze_and_unfreeze() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);

    h.client.dispatch(&owner, &id, &WalletAction::Freeze);
    assert_eq!(h.client.get_wallet(&id).state, ResourceState::Frozen);

    h.client.dispatch(&owner, &id, &WalletAction::Unfreeze);
    assert_eq!(h.client.get_wallet(&id).state, ResourceState::Active);
}

#[test]
fn dispatch_unregistered_caller_blocked() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let stranger = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    mint(&h, &owner, 1_000);
    h.client.deposit(&id, &owner, &h.token, &1_000);

    let action = WalletAction::Transfer {
        to: recipient.clone(),
        asset: h.token.clone(),
        amount: 100,
    };
    let res = h.client.try_dispatch(&stranger, &id, &action);
    assert_eq!(res, Err(Ok(Error::UnauthorizedDispatch)));
}

#[test]
fn dispatch_unregistered_cannot_freeze() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let stranger = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);

    let res = h.client.try_dispatch(&stranger, &id, &WalletAction::Freeze);
    assert_eq!(res, Err(Ok(Error::UnauthorizedDispatch)));
}

#[test]
fn dispatch_unregistered_cannot_withdraw() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let stranger = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    mint(&h, &owner, 1_000);
    h.client.deposit(&id, &owner, &h.token, &1_000);

    let action = WalletAction::Withdraw {
        asset: h.token.clone(),
        amount: 100,
    };
    let res = h.client.try_dispatch(&stranger, &id, &action);
    assert_eq!(res, Err(Ok(Error::UnauthorizedDispatch)));
}

#[test]
fn dispatch_frozen_wallet_blocks_transfer() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    mint(&h, &owner, 1_000);
    h.client.deposit(&id, &owner, &h.token, &1_000);

    h.client.freeze(&owner, &id);

    let action = WalletAction::Transfer {
        to: recipient.clone(),
        asset: h.token.clone(),
        amount: 100,
    };
    let res = h.client.try_dispatch(&owner, &id, &action);
    assert_eq!(res, Err(Ok(Error::WalletFrozen)));
}

#[test]
fn dispatch_zero_amount_transfer_rejected() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);

    let action = WalletAction::Transfer {
        to: recipient.clone(),
        asset: h.token.clone(),
        amount: 0,
    };
    let res = h.client.try_dispatch(&owner, &id, &action);
    assert_eq!(res, Err(Ok(Error::InvalidAmount)));
}

// ---------------------------------------------------------------------------
// Role-based access control
// ---------------------------------------------------------------------------

/// A wallet funded with `amount`, plus its owner.
fn funded_wallet(h: &Harness, amount: i128) -> (Address, u64) {
    let owner = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    mint(h, &owner, amount);
    h.client.deposit(&id, &owner, &h.token, &amount);
    (owner, id)
}

#[test]
fn breaker_starts_reset_and_guardian_defaults_to_admin() {
    let h = setup();
    assert!(!h.client.is_paused());
    assert_eq!(h.client.get_guardian(), h.admin);
}

#[test]
fn paused_wallet_contract_blocks_all_outgoing_value() {
    let h = setup();
    let (owner, id) = funded_wallet(&h, 1_000);
    let recipient = Address::generate(&h.env);

    h.client.emergency_pause(&h.admin);
    assert!(h.client.is_paused());

    assert_eq!(
        h.client
            .try_transfer(&owner, &id, &recipient, &h.token, &100),
        Err(Ok(Error::WalletPaused))
    );
    assert_eq!(
        h.client.try_withdraw(&owner, &id, &h.token, &100),
        Err(Ok(Error::WalletPaused))
    );
    // No value moved on any rejected path.
    assert_eq!(h.client.balance(&id, &h.token), 1_000);
    assert_eq!(token_balance(&h, &recipient), 0);
    assert_eq!(token_balance(&h, &h.client.address), 1_000);
}

#[test]
fn paused_wallet_contract_blocks_new_wallets() {
    let h = setup();
    h.client.emergency_pause(&h.admin);
    let owner = Address::generate(&h.env);
    assert_eq!(
        h.client.try_create_wallet(&owner),
        Err(Ok(Error::WalletPaused))
    );
}

#[test]
fn inspection_and_recovery_stay_available_while_paused() {
    let h = setup();
    let (owner, id) = funded_wallet(&h, 1_000);
    h.client.emergency_pause(&h.admin);

    // Read-only inspection is unaffected.
    assert_eq!(h.client.balance(&id, &h.token), 1_000);
    assert_eq!(h.client.get_wallet(&id).state, ResourceState::Active);
    assert!(h.client.is_paused());

    // Funding a wallet is inbound, so it stays open.
    mint(&h, &owner, 500);
    h.client.deposit(&id, &owner, &h.token, &500);
    assert_eq!(h.client.balance(&id, &h.token), 1_500);

    // Per-wallet quarantine still works, so an operator can act on a specific
    // compromised wallet while the breaker holds the line globally.
    h.client.freeze(&h.admin, &id);
    assert_eq!(h.client.get_wallet(&id).state, ResourceState::Frozen);
    h.client.unfreeze(&h.admin, &id);
    h.client.pause(&owner, &id);
    assert_eq!(h.client.get_wallet(&id).state, ResourceState::Paused);
}

#[test]
fn normal_operation_resumes_after_unpause() {
    let h = setup();
    let (owner, id) = funded_wallet(&h, 1_000);
    let recipient = Address::generate(&h.env);

    h.client.emergency_pause(&h.admin);
    h.client.emergency_unpause(&h.admin);
    assert!(!h.client.is_paused());

    h.client.transfer(&owner, &id, &recipient, &h.token, &400);
    assert_eq!(token_balance(&h, &recipient), 400);
    assert_eq!(h.client.balance(&id, &h.token), 600);
}

#[test]
fn designated_guardian_can_trip_but_not_reset_the_breaker() {
    let h = setup();
    let guardian = Address::generate(&h.env);
    h.client.set_guardian(&h.admin, &guardian);
    assert_eq!(h.client.get_guardian(), guardian);

    // Containment is fast: one guardian key is enough.
    h.client.emergency_pause(&guardian);
    assert!(h.client.is_paused());

    // Releasing funds back into motion is not.
    assert_eq!(
        h.client.try_emergency_unpause(&guardian),
        Err(Ok(Error::Unauthorized))
    );
    assert!(h.client.is_paused());

    h.client.emergency_unpause(&h.admin);
    assert!(!h.client.is_paused());
}

#[test]
fn strangers_cannot_touch_the_breaker() {
    let h = setup();
    let stranger = Address::generate(&h.env);
    let owner = Address::generate(&h.env);
    // Owning a wallet grants no emergency authority.
    h.client.create_wallet(&owner);

    assert_eq!(
        h.client.try_emergency_pause(&stranger),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(
        h.client.try_emergency_pause(&owner),
        Err(Ok(Error::Unauthorized))
    );
    assert!(!h.client.is_paused());

    h.client.emergency_pause(&h.admin);
    assert_eq!(
        h.client.try_emergency_unpause(&stranger),
        Err(Ok(Error::Unauthorized))
    );
    assert!(h.client.is_paused());
}

#[test]
fn only_the_admin_designates_the_guardian() {
    let h = setup();
    let stranger = Address::generate(&h.env);
    let res = h.client.try_set_guardian(&stranger, &stranger);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
    assert_eq!(h.client.get_guardian(), h.admin);
}

#[test]
fn redundant_breaker_transitions_are_rejected() {
    let h = setup();
    assert_eq!(
        h.client.try_emergency_unpause(&h.admin),
        Err(Ok(Error::InvalidState))
    );
    h.client.emergency_pause(&h.admin);
    assert_eq!(
        h.client.try_emergency_pause(&h.admin),
        Err(Ok(Error::InvalidState))
    );
}

#[test]
fn owner_is_implicitly_admin() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);

    assert_eq!(h.client.get_role(&id, &owner), Some(Role::Admin));
    assert!(h.client.has_role(&id, &owner, &Role::Admin));
    assert!(h.client.has_role(&id, &owner, &Role::Agent));

    // A stranger holds nothing at all.
    let stranger = Address::generate(&h.env);
    assert_eq!(h.client.get_role(&id, &stranger), None);
    assert!(!h.client.has_role(&id, &stranger, &Role::Auditor));
}

#[test]
fn granted_role_is_readable_and_revocable() {
    let h = setup();
    let (owner, id) = funded_wallet(&h, 100);
    let agent = Address::generate(&h.env);

    h.client.grant_role(&owner, &id, &agent, &Role::Agent);
    assert_eq!(h.client.get_role(&id, &agent), Some(Role::Agent));

    // Re-granting replaces the role rather than stacking.
    h.client.grant_role(&owner, &id, &agent, &Role::Auditor);
    assert_eq!(h.client.get_role(&id, &agent), Some(Role::Auditor));

    h.client.revoke_role(&owner, &id, &agent);
    assert_eq!(h.client.get_role(&id, &agent), None);

    // Revoking again is an explicit failure, not a silent no-op.
    assert_eq!(
        h.client.try_revoke_role(&owner, &id, &agent),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn agent_can_transfer_but_not_withdraw() {
    let h = setup();
    let (owner, id) = funded_wallet(&h, 1_000);
    let agent = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    h.client.grant_role(&owner, &id, &agent, &Role::Agent);

    // Routine operational spend: permitted.
    h.client.transfer(&agent, &id, &recipient, &h.token, &250);
    assert_eq!(token_balance(&h, &recipient), 250);
    assert_eq!(h.client.balance(&id, &h.token), 750);

    // Withdrawing funds to the owner is administrative: refused.
    assert_eq!(
        h.client.try_withdraw(&agent, &id, &h.token, &100),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(h.client.balance(&id, &h.token), 750);
}

#[test]
fn agent_cannot_administer_lifecycle_or_roles() {
    let h = setup();
    let (owner, id) = funded_wallet(&h, 100);
    let agent = Address::generate(&h.env);
    let outsider = Address::generate(&h.env);
    h.client.grant_role(&owner, &id, &agent, &Role::Agent);

    assert_eq!(
        h.client.try_pause(&agent, &id),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(
        h.client.try_archive(&agent, &id),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(
        h.client
            .try_grant_role(&agent, &id, &outsider, &Role::Agent),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(
        h.client.try_revoke_role(&agent, &id, &agent),
        Err(Ok(Error::Unauthorized))
    );

    // None of the rejected calls changed anything.
    assert_eq!(h.client.get_wallet(&id).state, ResourceState::Active);
    assert_eq!(h.client.get_role(&id, &outsider), None);
    assert_eq!(h.client.get_role(&id, &agent), Some(Role::Agent));
}

#[test]
fn agent_may_freeze_as_a_safety_action() {
    let h = setup();
    let (owner, id) = funded_wallet(&h, 100);
    let agent = Address::generate(&h.env);
    h.client.grant_role(&owner, &id, &agent, &Role::Agent);

    h.client.freeze(&agent, &id);
    assert_eq!(h.client.get_wallet(&id).state, ResourceState::Frozen);
    h.client.unfreeze(&agent, &id);
    assert_eq!(h.client.get_wallet(&id).state, ResourceState::Active);
}

#[test]
fn auditor_holds_no_mutating_power() {
    let h = setup();
    let (owner, id) = funded_wallet(&h, 1_000);
    let auditor = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    h.client.grant_role(&owner, &id, &auditor, &Role::Auditor);

    // The role is recorded and readable...
    assert_eq!(h.client.get_role(&id, &auditor), Some(Role::Auditor));
    assert!(h.client.has_role(&id, &auditor, &Role::Auditor));
    // ...but satisfies no guard on a mutating entrypoint.
    assert!(!h.client.has_role(&id, &auditor, &Role::Agent));
    assert_eq!(
        h.client
            .try_transfer(&auditor, &id, &recipient, &h.token, &10),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(
        h.client.try_withdraw(&auditor, &id, &h.token, &10),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(
        h.client.try_freeze(&auditor, &id),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(token_balance(&h, &recipient), 0);
    assert_eq!(h.client.balance(&id, &h.token), 1_000);
}

#[test]
fn delegated_admin_has_full_control() {
    let h = setup();
    let (owner, id) = funded_wallet(&h, 1_000);
    let manager = Address::generate(&h.env);
    let agent = Address::generate(&h.env);
    h.client.grant_role(&owner, &id, &manager, &Role::Admin);

    // A delegated admin may withdraw - and the funds still go to the owner.
    h.client.withdraw(&manager, &id, &h.token, &400);
    assert_eq!(token_balance(&h, &owner), 400);
    assert_eq!(h.client.balance(&id, &h.token), 600);

    // ...and may administer roles in turn.
    h.client.grant_role(&manager, &id, &agent, &Role::Agent);
    assert_eq!(h.client.get_role(&id, &agent), Some(Role::Agent));

    // ...and lifecycle.
    h.client.pause(&manager, &id);
    assert_eq!(h.client.get_wallet(&id).state, ResourceState::Paused);
}

#[test]
fn revoked_agent_loses_access_immediately() {
    let h = setup();
    let (owner, id) = funded_wallet(&h, 1_000);
    let agent = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    h.client.grant_role(&owner, &id, &agent, &Role::Agent);
    h.client.transfer(&agent, &id, &recipient, &h.token, &100);

    h.client.revoke_role(&owner, &id, &agent);
    assert_eq!(
        h.client
            .try_transfer(&agent, &id, &recipient, &h.token, &100),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(token_balance(&h, &recipient), 100);
}

#[test]
fn roles_do_not_leak_between_wallets() {
    let h = setup();
    let (owner_a, wallet_a) = funded_wallet(&h, 500);
    let (_owner_b, wallet_b) = funded_wallet(&h, 500);
    let agent = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);

    h.client
        .grant_role(&owner_a, &wallet_a, &agent, &Role::Agent);

    h.client
        .transfer(&agent, &wallet_a, &recipient, &h.token, &50);
    assert_eq!(
        h.client
            .try_transfer(&agent, &wallet_b, &recipient, &h.token, &50),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(h.client.get_role(&wallet_b, &agent), None);
}

#[test]
fn owner_cannot_be_assigned_a_role() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);

    // The owner is implicitly Admin; a demotion attempt is refused outright
    // rather than recorded and then ignored by the guards.
    assert_eq!(
        h.client.try_grant_role(&owner, &id, &owner, &Role::Auditor),
        Err(Ok(Error::InvalidInput))
    );
    assert_eq!(h.client.get_role(&id, &owner), Some(Role::Admin));
}

#[test]
fn role_checks_report_unknown_wallets_as_not_found() {
    let h = setup();
    let account = Address::generate(&h.env);
    assert_eq!(
        h.client.try_get_role(&999, &account),
        Err(Ok(Error::NotFound))
    );
    assert_eq!(
        h.client
            .try_grant_role(&account, &999, &account, &Role::Agent),
        Err(Ok(Error::NotFound))
    );
}

#[test]
fn breaker_events_are_emitted() {
    let h = setup();
    h.client.emergency_pause(&h.admin);
    assert_event(&h.env, "WalletPaused");
    h.client.emergency_unpause(&h.admin);
    assert_event(&h.env, "WalletUnpaused");
}

#[test]
fn granting_on_an_archived_wallet_is_refused() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    let agent = Address::generate(&h.env);
    h.client.grant_role(&owner, &id, &agent, &Role::Agent);
    h.client.archive(&owner, &id);

    let other = Address::generate(&h.env);
    assert_eq!(
        h.client.try_grant_role(&owner, &id, &other, &Role::Agent),
        Err(Ok(Error::WalletArchived))
    );
    // Revocation still works so stale grants can be cleaned up.
    h.client.revoke_role(&owner, &id, &agent);
    assert_eq!(h.client.get_role(&id, &agent), None);
}

// ---------------------------------------------------------------- stubs ----

/// Storage keys for the policy stub.
#[contracttype]
#[derive(Clone)]
enum PolicyKey {
    /// Approved value cap for a policy envelope id.
    Cap(String),
}

/// A configurable policy stub: every envelope id has a cap, and any check for
/// an amount above the cap is denied so tests can force a policy rejection.
#[contract]
pub struct TestPolicy;

#[contractimpl]
impl TestPolicy {
    /// Set the approved value cap for `policy_id`.
    pub fn set_cap(env: Env, policy_id: String, cap: i128) {
        env.storage()
            .persistent()
            .set(&PolicyKey::Cap(policy_id), &cap);
    }

    /// Mirrors `PolicyInterface::check_transfer`, denying spends above the
    /// envelope's approved cap.
    pub fn check_transfer(
        env: Env,
        policy_id: String,
        _asset: Address,
        _recipient: Address,
        amount: i128,
    ) -> Result<(), Error> {
        let cap: i128 = env
            .storage()
            .persistent()
            .get(&PolicyKey::Cap(policy_id))
            .unwrap_or(0);
        if amount > cap {
            return Err(Error::PolicyDenied);
        }
        Ok(())
    }
}

/// Storage keys for the budget stub.
#[contracttype]
#[derive(Clone)]
enum BudgetKey {
    /// Allocation still available for a budget envelope id.
    Remaining(String),
}

/// A budget stub with a top-up-able allocation: `consume` debits the remaining
/// allocation, returning `BudgetExceeded` when the batch asks for too much.
#[contract]
pub struct TestBudget;

#[contractimpl]
impl TestBudget {
    /// Credit `amount` to `budget_id`'s remaining allocation.
    pub fn top_up(env: Env, budget_id: String, amount: i128) {
        let key = BudgetKey::Remaining(budget_id.clone());
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(current + amount));
    }

    /// Mirrors `BudgetInterface::consume`, returning the new remaining balance
    /// and refusing when the requested amount exceeds what is left.
    pub fn consume(
        env: Env,
        _caller: Address,
        budget_id: String,
        amount: i128,
    ) -> Result<i128, Error> {
        let key = BudgetKey::Remaining(budget_id.clone());
        let remaining: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        if amount > remaining {
            return Err(Error::BudgetExceeded);
        }
        let new_remaining = remaining - amount;
        env.storage().persistent().set(&key, &new_remaining);
        Ok(new_remaining)
    }

    /// Read the allocation still available for `budget_id`.
    pub fn remaining(env: Env, budget_id: String) -> i128 {
        env.storage()
            .persistent()
            .get(&BudgetKey::Remaining(budget_id))
            .unwrap_or(0)
    }
}

// ------------------------------------------------------- validated batch ----

/// Register and wire the policy/budget stubs as the wallet's gates.
fn wire_gates(h: &Harness) -> (Address, Address) {
    let policy = h.env.register_contract(None, TestPolicy);
    let budget = h.env.register_contract(None, TestBudget);
    h.client.set_policy(&h.admin, &policy);
    h.client.set_budget(&h.admin, &budget);
    (policy, budget)
}

/// Build a validated `BatchAction` moving `amount` of `token` from the wallet
/// to `to`, checked against the given policy/budget envelopes (empty ids skip
/// the corresponding gate).
fn validated_action(
    env: &Env,
    token_addr: &Address,
    from: &Address,
    to: &Address,
    amount: i128,
    policy_id: &str,
    budget_id: &str,
) -> BatchAction {
    BatchAction {
        call: token_transfer_call(env, token_addr, from, to, amount),
        policy_id: String::from_str(env, policy_id),
        budget_id: String::from_str(env, budget_id),
        asset: token_addr.clone(),
        recipient: to.clone(),
        amount,
    }
}

#[test]
fn validated_batch_executes_and_reports_aggregates() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let r1 = Address::generate(&h.env);
    let r2 = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    mint(&h, &owner, 1_000);
    h.client.deposit(&id, &owner, &h.token, &1_000);

    let (policy, budget) = wire_gates(&h);
    TestPolicyClient::new(&h.env, &policy).set_cap(&String::from_str(&h.env, "p1"), &500);
    TestBudgetClient::new(&h.env, &budget).top_up(&String::from_str(&h.env, "b1"), &1_000);

    let mut actions: Vec<BatchAction> = Vec::new(&h.env);
    actions.push_back(validated_action(
        &h.env,
        &h.token,
        &h.contract_id,
        &r1,
        200,
        "p1",
        "b1",
    ));
    actions.push_back(validated_action(
        &h.env,
        &h.token,
        &h.contract_id,
        &r2,
        150,
        "p1",
        "b1",
    ));

    let receipt = h.client.batch_execute_validated(&owner, &id, &actions);
    assert_eq!(
        receipt,
        BatchReceipt {
            executed: 2,
            total_amount: 350,
            budget_remaining: 650,
        }
    );
    assert_eq!(token_balance(&h, &r1), 200);
    assert_eq!(token_balance(&h, &r2), 150);
    assert_eq!(token_balance(&h, &h.contract_id), 650);
    assert_eq!(
        TestBudgetClient::new(&h.env, &budget).remaining(&String::from_str(&h.env, "b1")),
        650
    );

    // The aggregated outcome is published as ("wallet", "batch_validated").
    let want: Val = Symbol::new(&h.env, "batch_validated").into_val(&h.env);
    let found = h
        .env
        .events()
        .all()
        .iter()
        .any(|(_contract_id, topics, _data)| topics.contains(want));
    assert!(found, "expected batch_validated event to be emitted");
}

#[test]
fn validated_batch_policy_denial_reverts_atomically() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let r1 = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    mint(&h, &owner, 1_000);
    h.client.deposit(&id, &owner, &h.token, &1_000);

    let (policy, budget) = wire_gates(&h);
    // Cap of 100: the first action passes, the second is denied by policy.
    TestPolicyClient::new(&h.env, &policy).set_cap(&String::from_str(&h.env, "p1"), &100);
    TestBudgetClient::new(&h.env, &budget).top_up(&String::from_str(&h.env, "b1"), &1_000);

    let mut actions: Vec<BatchAction> = Vec::new(&h.env);
    actions.push_back(validated_action(
        &h.env,
        &h.token,
        &h.contract_id,
        &r1,
        50,
        "p1",
        "b1",
    ));
    actions.push_back(validated_action(
        &h.env,
        &h.token,
        &h.contract_id,
        &r1,
        200,
        "p1",
        "b1",
    ));

    let res = h.client.try_batch_execute_validated(&owner, &id, &actions);
    assert_eq!(res, Err(Ok(Error::PolicyDenied)));

    // Nothing moved and the budget was never debited — full rollback.
    assert_eq!(token_balance(&h, &r1), 0);
    assert_eq!(token_balance(&h, &h.contract_id), 1_000);
    assert_eq!(
        TestBudgetClient::new(&h.env, &budget).remaining(&String::from_str(&h.env, "b1")),
        1_000
    );
}

#[test]
fn validated_batch_budget_insufficiency_reverts() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let r1 = Address::generate(&h.env);
    let r2 = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    mint(&h, &owner, 1_000);
    h.client.deposit(&id, &owner, &h.token, &1_000);

    let (policy, budget) = wire_gates(&h);
    TestPolicyClient::new(&h.env, &policy).set_cap(&String::from_str(&h.env, "p1"), &1_000);
    // Only 100 available: 80 fits, the second action's 60 does not.
    TestBudgetClient::new(&h.env, &budget).top_up(&String::from_str(&h.env, "b1"), &100);

    let mut actions: Vec<BatchAction> = Vec::new(&h.env);
    actions.push_back(validated_action(
        &h.env,
        &h.token,
        &h.contract_id,
        &r1,
        80,
        "p1",
        "b1",
    ));
    actions.push_back(validated_action(
        &h.env,
        &h.token,
        &h.contract_id,
        &r2,
        60,
        "p1",
        "b1",
    ));

    let res = h.client.try_batch_execute_validated(&owner, &id, &actions);
    assert_eq!(res, Err(Ok(Error::BudgetExceeded)));

    // Full rollback: no tokens moved, budget untouched.
    assert_eq!(token_balance(&h, &r1), 0);
    assert_eq!(token_balance(&h, &r2), 0);
    assert_eq!(token_balance(&h, &h.contract_id), 1_000);
    assert_eq!(
        TestBudgetClient::new(&h.env, &budget).remaining(&String::from_str(&h.env, "b1")),
        100
    );
}

#[test]
fn validated_batch_cumulative_overflow_reverts() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let r1 = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    mint(&h, &owner, i128::MAX);
    h.client.deposit(&id, &owner, &h.token, &i128::MAX);

    // The cumulative total exceeds i128 before any call executes. The checked
    // aggregate must abort the batch with Overflow, before any value moves.
    let mut actions: Vec<BatchAction> = Vec::new(&h.env);
    actions.push_back(validated_action(
        &h.env,
        &h.token,
        &h.contract_id,
        &r1,
        i128::MAX,
        "",
        "",
    ));
    actions.push_back(validated_action(
        &h.env,
        &h.token,
        &h.contract_id,
        &r1,
        1,
        "",
        "",
    ));

    let res = h.client.try_batch_execute_validated(&owner, &id, &actions);
    assert_eq!(res, Err(Ok(Error::Overflow)));
    assert_eq!(token_balance(&h, &r1), 0);
    assert_eq!(token_balance(&h, &h.contract_id), i128::MAX);
}

#[test]
fn validated_batch_unwired_gate_is_refused() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    mint(&h, &owner, 100);
    h.client.deposit(&id, &owner, &h.token, &100);

    // No policy contract wired, yet an action declares a policy envelope.
    let mut actions: Vec<BatchAction> = Vec::new(&h.env);
    actions.push_back(validated_action(
        &h.env,
        &h.token,
        &h.contract_id,
        &recipient,
        10,
        "p1",
        "",
    ));
    let res = h.client.try_batch_execute_validated(&owner, &id, &actions);
    assert_eq!(res, Err(Ok(Error::InvalidInput)));
    assert_eq!(token_balance(&h, &h.contract_id), 100);
}

#[test]
fn validated_batch_without_envelopes_passes_unwired() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    mint(&h, &owner, 100);
    h.client.deposit(&id, &owner, &h.token, &100);

    // No gates wired and no envelope ids: behaves like the raw path, but still
    // reports the aggregated totals.
    let mut actions: Vec<BatchAction> = Vec::new(&h.env);
    actions.push_back(validated_action(
        &h.env,
        &h.token,
        &h.contract_id,
        &recipient,
        40,
        "",
        "",
    ));
    actions.push_back(validated_action(
        &h.env,
        &h.token,
        &h.contract_id,
        &recipient,
        60,
        "",
        "",
    ));

    let receipt = h.client.batch_execute_validated(&owner, &id, &actions);
    assert_eq!(
        receipt,
        BatchReceipt {
            executed: 2,
            total_amount: 100,
            budget_remaining: 0,
        }
    );
    assert_eq!(token_balance(&h, &recipient), 100);
    assert_eq!(token_balance(&h, &h.contract_id), 0);
}

#[test]
fn validated_batch_mixed_assets_aggregate_total() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);

    let token_admin = Address::generate(&h.env);
    let token_b = h
        .env
        .register_stellar_asset_contract_v2(token_admin)
        .address();
    let sac_b = token::StellarAssetClient::new(&h.env, &token_b);
    sac_b.mint(&owner, &1_000);
    mint(&h, &owner, 1_000);
    h.client.deposit(&id, &owner, &h.token, &500);
    h.client.deposit(&id, &owner, &token_b, &500);

    // Cumulative value is aggregated across assets with checked math.
    let mut actions: Vec<BatchAction> = Vec::new(&h.env);
    actions.push_back(validated_action(
        &h.env,
        &h.token,
        &h.contract_id,
        &recipient,
        200,
        "",
        "",
    ));
    actions.push_back(validated_action(
        &h.env,
        &token_b,
        &h.contract_id,
        &recipient,
        100,
        "",
        "",
    ));

    let receipt = h.client.batch_execute_validated(&owner, &id, &actions);
    assert_eq!(
        receipt,
        BatchReceipt {
            executed: 2,
            total_amount: 300,
            budget_remaining: 0,
        }
    );
    assert_eq!(token_balance(&h, &recipient), 200);
    assert_eq!(
        token::TokenClient::new(&h.env, &token_b).balance(&recipient),
        100
    );
}

#[test]
fn validated_batch_empty_fails() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    let empty: Vec<BatchAction> = Vec::new(&h.env);
    let res = h.client.try_batch_execute_validated(&owner, &id, &empty);
    assert_eq!(res, Err(Ok(Error::InvalidInput)));
}

#[test]
fn validated_batch_non_agent_rejected() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let stranger = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);

    let mut actions: Vec<BatchAction> = Vec::new(&h.env);
    actions.push_back(validated_action(
        &h.env,
        &h.token,
        &h.contract_id,
        &recipient,
        50,
        "",
        "",
    ));
    let res = h
        .client
        .try_batch_execute_validated(&stranger, &id, &actions);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
}

#[test]
fn validated_batch_frozen_wallet_rejected() {
    let h = setup();
    let owner = Address::generate(&h.env);
    let recipient = Address::generate(&h.env);
    let id = h.client.create_wallet(&owner);
    mint(&h, &owner, 100);
    h.client.deposit(&id, &owner, &h.token, &100);
    h.client.freeze(&owner, &id);

    let mut actions: Vec<BatchAction> = Vec::new(&h.env);
    actions.push_back(validated_action(
        &h.env,
        &h.token,
        &h.contract_id,
        &recipient,
        10,
        "",
        "",
    ));
    let res = h.client.try_batch_execute_validated(&owner, &id, &actions);
    assert_eq!(res, Err(Ok(Error::WalletFrozen)));
}
