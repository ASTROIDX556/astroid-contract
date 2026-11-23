//! Registry → wallet → treasury integration workflow (Issue #454).
//!
//! The unit tests of each contract pin its own behaviour; this suite proves the
//! three foundation contracts work *together* the way an organization deploys
//! them:
//!
//! ```text
//! registry ──lookup──▶ treasury ──token──▶ wallet ──token──▶ recipient
//!     └──────lookup──▶ wallet
//! ```
//!
//! 1. The registry is the source of truth: every module address the flow uses
//!    is resolved through `lookup`, never hard-coded, and ownership is checked
//!    with `verify_owner`.
//! 2. The wallet is created and role-granted for an agent, funded from the
//!    treasury, and spends to a recipient.
//! 3. Every denial is checked twice — for the deterministic [`Error`] the
//!    caller receives across the contract boundary, and for the fact that no
//!    token balance or treasury ledger entry moved.

use astroid_registry::{RegistryContract, RegistryContractClient};
use astroid_shared::errors::Error;
use astroid_shared::types::ModuleKind;
use astroid_treasury::{TreasuryContract, TreasuryContractClient};
use astroid_wallet::access::Role;
use astroid_wallet::{WalletContract, WalletContractClient};
use soroban_sdk::testutils::Address as _;
use soroban_sdk::{token, Address, Env, String};

const ORG: &str = "acme";
const TREASURY_FUNDS: i128 = 100_000;

struct Harness<'a> {
    env: Env,
    registry: RegistryContractClient<'a>,
    treasury: TreasuryContractClient<'a>,
    admin: Address,
    org_owner: Address,
    agent: Address,
    recipient: Address,
    asset: Address,
}

impl<'a> Harness<'a> {
    fn s(&self, v: &str) -> String {
        String::from_str(&self.env, v)
    }

    fn balance(&self, who: &Address) -> i128 {
        token::TokenClient::new(&self.env, &self.asset).balance(who)
    }

    /// Everything the flows below can move, for a "nothing moved" assertion
    /// after a denial that crossed a contract boundary.
    fn ledger(&self) -> [i128; 5] {
        let holding = self.treasury.holding(&self.asset);
        [
            self.balance(&self.treasury.address),
            self.balance(&self.recipient),
            self.balance(&self.agent),
            holding.total_in,
            holding.total_out,
        ]
    }
}

/// Deploy registry, wallet and treasury; register the org and its module
/// addresses; approve and fund a real SAC token in the treasury.
fn setup() -> Harness<'static> {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let org_owner = Address::generate(&env);
    let agent = Address::generate(&env);
    let recipient = Address::generate(&env);
    let org = String::from_str(&env, ORG);

    let registry_id = env.register_contract(None, RegistryContract);
    let registry = RegistryContractClient::new(&env, &registry_id);
    registry.initialize(&admin);
    registry.register_org(&admin, &org, &org_owner);

    let wallet_id = env.register_contract(None, WalletContract);
    let wallet = WalletContractClient::new(&env, &wallet_id);
    wallet.initialize(&admin);

    let treasury_id = env.register_contract(None, TreasuryContract);
    let treasury = TreasuryContractClient::new(&env, &treasury_id);
    treasury.initialize(&org, &admin);

    registry.register_module(&admin, &org, &ModuleKind::Wallet, &wallet_id);
    registry.register_module(&admin, &org, &ModuleKind::Treasury, &treasury_id);

    // A real SAC token, approved by the treasury and funded by the admin.
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
        treasury,
        admin,
        org_owner,
        agent,
        recipient,
        asset,
    }
}

/// The registry is the only way the flow learns where each module lives:
/// lookups resolve the deployed contracts, ownership is verified, and an
/// unregistered module is reported as `NotFound` rather than silently routed.
#[test]
fn registry_lookup_resolves_the_deployed_modules() {
    let h = setup();

    let wallet_addr = h.registry.lookup(&h.s(ORG), &ModuleKind::Wallet);
    let treasury_addr = h.registry.lookup(&h.s(ORG), &ModuleKind::Treasury);

    // Resolving the modules is enough to build their clients: every call below
    // goes through the registry-provided address, not a locally captured one.
    let wallet = WalletContractClient::new(&h.env, &wallet_addr);
    let treasury = TreasuryContractClient::new(&h.env, &treasury_addr);

    assert_eq!(wallet.get_org(), None);
    assert_eq!(treasury.holding(&h.asset).total_in, TREASURY_FUNDS);
    assert_eq!(
        h.registry
            .get_module_address(&h.s(ORG), &ModuleKind::Wallet),
        wallet_addr
    );

    // Ownership checks across the boundary.
    assert!(h.registry.verify_owner(&h.s(ORG), &h.org_owner));
    assert!(!h.registry.verify_owner(&h.s(ORG), &h.agent));

    // A module the org never registered is a deterministic NotFound.
    let missing = h.registry.try_lookup(&h.s(ORG), &ModuleKind::Policy);
    assert_eq!(missing, Err(Ok(Error::NotFound)));
}

/// End-to-end happy path: resolve the modules, create the agent's wallet, fund
/// it from the treasury, and let the agent spend to a recipient.
#[test]
fn wallet_setup_and_treasury_transfer_work_end_to_end() {
    let h = setup();

    // Resolve both modules through the registry.
    let wallet_addr = h.registry.lookup(&h.s(ORG), &ModuleKind::Wallet);
    let treasury_addr = h.registry.lookup(&h.s(ORG), &ModuleKind::Treasury);
    let wallet = WalletContractClient::new(&h.env, &wallet_addr);
    let treasury = TreasuryContractClient::new(&h.env, &treasury_addr);

    // Wallet setup: owned by the org owner.
    let wallet_id = wallet.create_wallet(&h.org_owner);
    assert_eq!(wallet.get_wallet(&wallet_id).owner, h.org_owner);

    // The owner delegates spending to the agent.
    wallet.grant_role(&h.org_owner, &wallet_id, &h.agent, &Role::Agent);
    assert_eq!(wallet.get_role(&wallet_id, &h.agent), Some(Role::Agent));

    // Treasury → wallet funding moves real tokens into the wallet's custody
    // address; the deposit records them in the wallet's internal ledger.
    treasury.withdraw(&h.admin, &h.asset, &wallet_addr, &20_000);
    wallet.deposit(&wallet_id, &wallet_addr, &h.asset, &20_000);
    assert_eq!(wallet.balance(&wallet_id, &h.asset), 20_000);
    assert_eq!(h.balance(&wallet_addr), 20_000);

    let holding = treasury.holding(&h.asset);
    assert_eq!(holding.total_in, TREASURY_FUNDS - 20_000);
    assert_eq!(holding.total_out, 20_000);

    // Agent spend: wallet → recipient.
    wallet.transfer(&h.agent, &wallet_id, &h.recipient, &h.asset, &5_000);
    assert_eq!(h.balance(&h.recipient), 5_000);
    assert_eq!(h.balance(&wallet_addr), 15_000);
    assert_eq!(wallet.balance(&wallet_id, &h.asset), 15_000);
}

/// Authorization checks hold across the contract boundary, and a refusal
/// propagates the contract's own deterministic error without moving value.
#[test]
fn authorization_and_errors_propagate_across_contracts() {
    let h = setup();

    let wallet_addr = h.registry.lookup(&h.s(ORG), &ModuleKind::Wallet);
    let wallet = WalletContractClient::new(&h.env, &wallet_addr);
    let wallet_id = wallet.create_wallet(&h.org_owner);
    h.treasury
        .withdraw(&h.admin, &h.asset, &wallet_addr, &10_000);
    wallet.deposit(&wallet_id, &wallet_addr, &h.asset, &10_000);

    let before = h.ledger();
    let stranger = Address::generate(&h.env);

    // 1. A principal with no wallet role cannot transfer out.
    let res = wallet.try_transfer(&stranger, &wallet_id, &h.recipient, &h.asset, &500);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));

    // 2. The agent may transfer but may not withdraw to the owner.
    wallet.grant_role(&h.org_owner, &wallet_id, &h.agent, &Role::Agent);
    let res = wallet.try_withdraw(&h.agent, &wallet_id, &h.asset, &500);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));

    // 3. Only the treasury admin may move treasury funds.
    let res = h
        .treasury
        .try_withdraw(&h.agent, &h.asset, &h.recipient, &1_000);
    assert_eq!(res, Err(Ok(Error::Unauthorized)));

    // 4. An unapproved token is refused before any balance is touched.
    let rogue_token = h
        .env
        .register_stellar_asset_contract_v2(Address::generate(&h.env))
        .address();
    let res = h
        .treasury
        .try_withdraw(&h.admin, &rogue_token, &h.recipient, &1_000);
    assert_eq!(res, Err(Ok(Error::AssetNotAuthorized)));

    // 5. The treasury cannot pay out more than it holds.
    let res = h
        .treasury
        .try_withdraw(&h.admin, &h.asset, &h.recipient, &(TREASURY_FUNDS + 1));
    assert_eq!(res, Err(Ok(Error::InsufficientFunds)));

    // 6. Registry writes are owner-gated: a stranger cannot re-route a module.
    let res = h.registry.try_register_module(
        &stranger,
        &h.s(ORG),
        &ModuleKind::Wallet,
        &h.treasury.address,
    );
    assert_eq!(res, Err(Ok(Error::Unauthorized)));
    assert_eq!(
        h.registry.lookup(&h.s(ORG), &ModuleKind::Wallet),
        wallet_addr
    );

    // Nothing moved through any of the denials.
    assert_eq!(h.ledger(), before);
    assert_eq!(wallet.balance(&wallet_id, &h.asset), 10_000);
    assert_eq!(h.balance(&h.recipient), 0);
}
