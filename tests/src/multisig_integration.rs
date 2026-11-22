//! Multi-signature threshold workflows across contract boundaries (Issue #472).
//!
//! Deploys the multisig next to the registry, treasury and budget contracts
//! and drives the workflows an organization relies on for high-value
//! operations:
//!
//! ```text
//! registry ──lookup──▶ multisig ──execute_batch──▶ treasury.freeze / unfreeze
//!                         │                    └─▶ budget.allocate
//!                         └── propose → approve → execute (weighted quorum)
//! ```
//!
//! Signers carry different voting weights (3 / 2 / 1) against a threshold of
//! 4, so every test exercises weight aggregation rather than a head count.
//! Each workflow checks the three guarantees the multisig exists for:
//!
//! * **Weight aggregation** — distinct signers' weights are summed, a repeat
//!   approval never stacks, and a removed signer stops counting.
//! * **Threshold enforcement** — nothing executes below the threshold; an exact
//!   match is enough.
//! * **Replay protection** — an executed proposal cannot execute again, and a
//!   batch nonce cannot be reused.
//!
//! The standard `proposal/created`, `proposal/approved` and
//! `proposal/executed` events from `shared/src/events.rs` are asserted with
//! their exact payloads.

use astroid_budget::{BudgetContract, BudgetContractClient, Period};
use astroid_multisig::{BatchCall, MultiSigContract, MultiSigContractClient, SignerWeight};
use astroid_registry::{RegistryContract, RegistryContractClient};
use astroid_shared::errors::Error;
use astroid_shared::types::ModuleKind;
use astroid_treasury::{TreasuryContract, TreasuryContractClient};
use soroban_sdk::testutils::{Address as _, Events};
use soroban_sdk::{
    symbol_short, token, vec, Address, Bytes, Env, IntoVal, String, Symbol, TryFromVal, Val, Vec,
};

const ORG: &str = "acme";
const THRESHOLD: u32 = 4;
const TREASURY_FUNDS: i128 = 100_000;

struct Harness<'a> {
    env: Env,
    registry: RegistryContractClient<'a>,
    multisig: MultiSigContractClient<'a>,
    treasury: TreasuryContractClient<'a>,
    budget: BudgetContractClient<'a>,
    admin: Address,
    /// Weight 3.
    alice: Address,
    /// Weight 2.
    bob: Address,
    /// Weight 1.
    carol: Address,
    asset: Address,
}

impl<'a> Harness<'a> {
    fn s(&self, v: &str) -> String {
        String::from_str(&self.env, v)
    }

    fn payload(&self, tag: &[u8]) -> Bytes {
        Bytes::from_slice(&self.env, tag)
    }

    fn signers(&self, who: &[&Address]) -> Vec<Address> {
        let mut v = Vec::new(&self.env);
        for a in who {
            v.push_back((*a).clone());
        }
        v
    }

    fn freeze_call(&self) -> BatchCall {
        BatchCall {
            contract: self.treasury.address.clone(),
            func: Symbol::new(&self.env, "freeze"),
            args: vec![&self.env, self.multisig.address.into_val(&self.env)],
        }
    }

    fn unfreeze_call(&self) -> BatchCall {
        BatchCall {
            contract: self.treasury.address.clone(),
            func: Symbol::new(&self.env, "unfreeze"),
            args: vec![&self.env, self.multisig.address.into_val(&self.env)],
        }
    }

    /// `budget.allocate(owner = multisig, id, limit, Period::None, false, 0)`:
    /// the multisig becomes the owner of a governance-controlled budget.
    fn allocate_call(&self, id: &str, limit: i128) -> BatchCall {
        let env = &self.env;
        BatchCall {
            contract: self.budget.address.clone(),
            func: Symbol::new(env, "allocate"),
            args: vec![
                env,
                self.multisig.address.into_val(env),
                self.s(id).into_val(env),
                limit.into_val(env),
                Period::None.into_val(env),
                false.into_val(env),
                0u64.into_val(env),
            ],
        }
    }

    fn token_balance(&self, who: &Address) -> i128 {
        token::TokenClient::new(&self.env, &self.asset).balance(who)
    }
}

fn setup() -> Harness<'static> {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let org_owner = Address::generate(&env);
    let alice = Address::generate(&env);
    let bob = Address::generate(&env);
    let carol = Address::generate(&env);
    let org = String::from_str(&env, ORG);

    let registry_id = env.register_contract(None, RegistryContract);
    let registry = RegistryContractClient::new(&env, &registry_id);
    registry.initialize(&admin);
    registry.register_org(&admin, &org, &org_owner);

    let multisig_id = env.register_contract(None, MultiSigContract);
    let treasury_id = env.register_contract(None, TreasuryContract);
    let budget_id = env.register_contract(None, BudgetContract);
    for (kind, addr) in [
        (ModuleKind::Multisig, &multisig_id),
        (ModuleKind::Treasury, &treasury_id),
        (ModuleKind::Budget, &budget_id),
    ] {
        registry.register_module(&org_owner, &org, &kind, addr);
    }

    // Every module is reached through the registry, as an org would.
    let multisig = MultiSigContractClient::new(&env, &registry.lookup(&org, &ModuleKind::Multisig));
    let treasury = TreasuryContractClient::new(&env, &registry.lookup(&org, &ModuleKind::Treasury));
    let budget = BudgetContractClient::new(&env, &registry.lookup(&org, &ModuleKind::Budget));

    multisig.initialize(
        &vec![
            &env,
            SignerWeight {
                address: alice.clone(),
                weight: 3,
            },
            SignerWeight {
                address: bob.clone(),
                weight: 2,
            },
            SignerWeight {
                address: carol.clone(),
                weight: 1,
            },
        ],
        &THRESHOLD,
    );
    treasury.initialize(&org, &admin);
    treasury.set_multisig(&admin, &multisig.address);
    budget.initialize(&admin);

    let token_admin = Address::generate(&env);
    let asset = env
        .register_stellar_asset_contract_v2(token_admin)
        .address();
    treasury.add_approved_asset(&admin, &asset);
    token::StellarAssetClient::new(&env, &asset).mint(&admin, &TREASURY_FUNDS);
    treasury.deposit(&admin, &asset, &TREASURY_FUNDS);

    Harness {
        env,
        registry,
        multisig,
        treasury,
        budget,
        admin,
        alice,
        bob,
        carol,
        asset,
    }
}

/// Payloads of every `(category, action)` event published by `contract`.
fn events_of(h: &Harness, contract: &Address, category: &str, action: &str) -> std::vec::Vec<Val> {
    let want: Vec<Val> =
        (Symbol::new(&h.env, category), Symbol::new(&h.env, action)).into_val(&h.env);
    h.env
        .events()
        .all()
        .iter()
        .filter(|(id, topics, _)| id == contract && *topics == want)
        .map(|(_, _, data)| data)
        .collect()
}

// --- wiring -----------------------------------------------------------------

#[test]
fn registry_resolves_the_multisig_the_treasury_trusts() {
    let h = setup();
    let org = h.s(ORG);
    assert_eq!(
        h.registry.lookup(&org, &ModuleKind::Multisig),
        h.multisig.address
    );
    assert_eq!(h.treasury.get().multisig, Some(h.multisig.address.clone()));
    assert_eq!(h.multisig.get_total_weight(), 6);
}

// --- weighted proposal workflow --------------------------------------------

#[test]
fn weighted_proposal_aggregates_to_threshold_and_executes_once() {
    let h = setup();
    let id = h.multisig.propose(
        &h.alice,
        &symbol_short!("payment"),
        &h.payload(b"pay-1"),
        &0,
    );

    // The proposer's weight (3) counts automatically but is short of 4.
    assert_eq!(h.multisig.get_proposal(&id).approval_weight, 3);
    assert_eq!(
        h.multisig.try_execute(&h.alice, &id),
        Err(Ok(Error::InsufficientWeight))
    );

    // Carol's weight 1 meets the threshold exactly: 3 + 1 == 4.
    assert_eq!(h.multisig.approve(&h.carol, &id), THRESHOLD);
    h.multisig.execute(&h.bob, &id);
    assert!(h.multisig.get_proposal(&id).executed);

    // Replay protection: the executed id is spent for good.
    assert_eq!(
        h.multisig.try_execute(&h.alice, &id),
        Err(Ok(Error::InvalidProposalState))
    );
    assert_eq!(
        h.multisig.try_approve(&h.bob, &id),
        Err(Ok(Error::InvalidProposalState))
    );
}

#[test]
fn lighter_signers_alone_cannot_reach_the_threshold() {
    let h = setup();
    // Bob (2) + Carol (1) = 3 < 4: two of three signers are not a quorum here.
    let id = h
        .multisig
        .propose(&h.bob, &symbol_short!("payment"), &h.payload(b"pay-2"), &0);
    assert_eq!(h.multisig.approve(&h.carol, &id), 3);
    assert_eq!(
        h.multisig.try_execute(&h.bob, &id),
        Err(Ok(Error::InsufficientWeight))
    );
    // Alice's approval lifts it past the threshold (6 >= 4).
    assert_eq!(h.multisig.approve(&h.alice, &id), 6);
    h.multisig.execute(&h.carol, &id);
}

#[test]
fn duplicate_and_outsider_approvals_never_add_weight() {
    let h = setup();
    let id = h
        .multisig
        .propose(&h.bob, &symbol_short!("payment"), &h.payload(b"pay-3"), &0);
    assert_eq!(
        h.multisig.try_approve(&h.bob, &id),
        Err(Ok(Error::AlreadySigned))
    );
    let outsider = Address::generate(&h.env);
    assert_eq!(
        h.multisig.try_approve(&outsider, &id),
        Err(Ok(Error::NotASigner))
    );
    assert_eq!(
        h.multisig.try_execute(&outsider, &id),
        Err(Ok(Error::NotASigner))
    );
    assert_eq!(h.multisig.get_proposal(&id).approval_weight, 2);
}

#[test]
fn removed_signer_approval_stops_counting_at_execution() {
    let h = setup();
    let id = h.multisig.propose(
        &h.alice,
        &symbol_short!("payment"),
        &h.payload(b"pay-4"),
        &0,
    );
    h.multisig.approve(&h.carol, &id); // 3 + 1 = 4: quorum.

    // Carol leaves; total weight 5 still covers the threshold, so removal is
    // allowed, but her approval no longer backs the proposal.
    h.multisig.remove_signer(&h.alice, &h.carol);
    assert_eq!(
        h.multisig.try_execute(&h.alice, &id),
        Err(Ok(Error::InsufficientWeight))
    );
    h.multisig.approve(&h.bob, &id); // 3 + 2 = 5.
    h.multisig.execute(&h.alice, &id);
}

#[test]
fn proposal_lifecycle_emits_the_standard_shared_events() {
    let h = setup();
    let ms = h.multisig.address.clone();
    let id = h.multisig.propose(
        &h.alice,
        &symbol_short!("payment"),
        &h.payload(b"pay-5"),
        &0,
    );
    h.multisig.approve(&h.carol, &id);
    h.multisig.execute(&h.bob, &id);

    // `events::proposal_created`: (proposal_id, proposer).
    let created = events_of(&h, &ms, "proposal", "created");
    assert_eq!(created.len(), 1);
    let (cid, proposer) = <(u64, Address)>::try_from_val(&h.env, &created[0]).unwrap();
    assert_eq!((cid, proposer), (id, h.alice.clone()));

    // `events::proposal_approved`: (proposal_id, approver, aggregated weight).
    let approved = events_of(&h, &ms, "proposal", "approved");
    assert_eq!(approved.len(), 1);
    let (aid, approver, weight) =
        <(u64, Address, u32)>::try_from_val(&h.env, &approved[0]).unwrap();
    assert_eq!((aid, approver, weight), (id, h.carol.clone(), THRESHOLD));

    // `events::proposal_executed`: proposal_id.
    let executed = events_of(&h, &ms, "proposal", "executed");
    assert_eq!(executed.len(), 1);
    assert_eq!(u64::try_from_val(&h.env, &executed[0]).unwrap(), id);

    // The threshold-met event fires once, on the approval that crossed it.
    assert_eq!(events_of(&h, &ms, "proposal", "quorum").len(), 1);
}

// --- signature-verified batch execution against other contracts ------------

#[test]
fn multisig_batch_freezes_and_unfreezes_the_treasury() {
    let h = setup();
    let recipient = Address::generate(&h.env);

    // Alice (3) + Carol (1) authorize the exact (nonce, calls) payload.
    h.multisig.execute_batch(
        &h.alice,
        &1,
        &vec![&h.env, h.freeze_call()],
        &h.signers(&[&h.carol]),
    );
    assert_eq!(
        h.treasury
            .try_withdraw(&h.admin, &h.asset, &recipient, &1_000),
        Err(Ok(Error::InvalidState))
    );
    assert_eq!(h.token_balance(&recipient), 0);

    // Bob (2) + Carol (1) = 3 cannot lift the freeze...
    assert_eq!(
        h.multisig.try_execute_batch(
            &h.bob,
            &2,
            &vec![&h.env, h.unfreeze_call()],
            &h.signers(&[&h.carol]),
        ),
        Err(Ok(Error::QUORUM_NOT_MET))
    );
    // ...and a failed batch does not burn its nonce.
    assert_eq!(h.multisig.get_last_batch_nonce(), 1);

    // Bob (2) + Alice (3) can.
    h.multisig.execute_batch(
        &h.bob,
        &2,
        &vec![&h.env, h.unfreeze_call()],
        &h.signers(&[&h.alice]),
    );
    h.treasury.withdraw(&h.admin, &h.asset, &recipient, &1_000);
    assert_eq!(h.token_balance(&recipient), 1_000);
}

#[test]
fn only_the_multisig_can_freeze_the_treasury() {
    let h = setup();
    // A single signer, however heavy, is not the multisig.
    assert_eq!(
        h.treasury.try_freeze(&h.alice),
        Err(Ok(Error::Unauthorized))
    );
}

#[test]
fn batch_nonce_cannot_be_replayed() {
    let h = setup();
    let calls = vec![&h.env, h.allocate_call("ops", 5_000)];
    h.multisig
        .execute_batch(&h.alice, &7, &calls, &h.signers(&[&h.bob]));
    let budget = h.budget.get(&h.s("ops"));
    assert_eq!(budget.owner, h.multisig.address);
    assert_eq!(budget.limit, 5_000);

    // Same nonce, and any lower nonce, are refused before anything runs.
    let again = vec![&h.env, h.allocate_call("ops-2", 1)];
    for nonce in [7u64, 3] {
        assert_eq!(
            h.multisig
                .try_execute_batch(&h.alice, &nonce, &again, &h.signers(&[&h.bob])),
            Err(Ok(Error::InvalidNonce))
        );
    }
    assert_eq!(h.budget.try_get(&h.s("ops-2")), Err(Ok(Error::NotFound)));
}

#[test]
fn batch_duplicate_signatories_count_once() {
    let h = setup();
    // Alice listed again as approver still contributes 3 once: 3 < 4.
    assert_eq!(
        h.multisig.try_execute_batch(
            &h.alice,
            &1,
            &vec![&h.env, h.allocate_call("dup", 1)],
            &h.signers(&[&h.alice, &h.alice]),
        ),
        Err(Ok(Error::QUORUM_NOT_MET))
    );
    assert_eq!(h.budget.try_get(&h.s("dup")), Err(Ok(Error::NotFound)));
}

#[test]
fn batch_requires_real_signatures_from_every_signatory() {
    let h = setup();
    // Drop the blanket auth mock: the host must now see a genuine signature
    // from each listed signer over the batch payload, and there is none.
    h.env.set_auths(&[]);
    let res = h.multisig.try_execute_batch(
        &h.alice,
        &1,
        &vec![&h.env, h.freeze_call()],
        &h.signers(&[&h.carol]),
    );
    assert!(res.is_err(), "batch must not run without signatures");
    assert_eq!(h.multisig.get_last_batch_nonce(), 0);
}

#[test]
fn verify_threshold_checks_a_signature_set_without_executing() {
    let h = setup();
    let payload = h.payload(b"treasury-rotation");
    assert_eq!(
        h.multisig
            .verify_threshold(&h.alice, &h.signers(&[&h.carol]), &payload),
        THRESHOLD
    );
    assert_eq!(
        h.multisig
            .try_verify_threshold(&h.bob, &h.signers(&[&h.carol]), &payload),
        Err(Ok(Error::QUORUM_NOT_MET))
    );
    let outsider = Address::generate(&h.env);
    assert_eq!(
        h.multisig
            .try_verify_threshold(&h.alice, &h.signers(&[&outsider]), &payload),
        Err(Ok(Error::NotASigner))
    );
}

#[test]
fn emergency_lock_blocks_every_multisig_path() {
    let h = setup();
    let id = h.multisig.propose(
        &h.alice,
        &symbol_short!("payment"),
        &h.payload(b"pay-6"),
        &0,
    );
    h.multisig.set_emergency_lock(&h.alice, &true);
    assert_eq!(
        h.multisig.try_approve(&h.carol, &id),
        Err(Ok(Error::EmergencyLock))
    );
    assert_eq!(
        h.multisig.try_execute_batch(
            &h.alice,
            &1,
            &vec![&h.env, h.freeze_call()],
            &h.signers(&[&h.carol]),
        ),
        Err(Ok(Error::EmergencyLock))
    );
    h.multisig.set_emergency_lock(&h.alice, &false);
    h.multisig.approve(&h.carol, &id);
    h.multisig.execute(&h.alice, &id);
}
