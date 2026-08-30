#![no_std]
#![allow(clippy::too_many_arguments)]
//! # Astroid Wallet Contract
//!
//! Programmable, stateful custody wallets for AI agents. The contract is the
//! on-chain custodian: real assets (Stellar Asset Contract tokens) are held at
//! the wallet contract's own address, while per-wallet balances are tracked in
//! internal bookkeeping so an individual wallet can never spend more than it
//! holds.
//!
//! Lifecycle states (PRD Doc 7 §Wallet): `Active`, `Frozen`, `Paused`,
//! `Archived`. Outbound value movement is only permitted from an `Active`
//! wallet; every other state fails safely with a specific error.
//!
//! ## Emergency circuit breaker
//!
//! The per-wallet states above are the owner's tool: they act on one wallet at
//! a time and the owner must be in a position to use them. Compromised agent
//! keys and abnormal on-chain behaviour do not respect that granularity, so the
//! contract also carries a single contract-wide breaker.
//!
//! While tripped, every outbound path — `transfer`, `withdraw` — and the
//! creation of new wallets are refused with [`Error::WalletPaused`]. Everything
//! needed to inspect and recover stays live: all views, `deposit`, and the
//! per-wallet `freeze` / `pause` / `archive` transitions, so an operator can
//! quarantine individual wallets while the breaker holds the line globally.
//!
//! Authority is deliberately asymmetric. A designated guardian can *trip* the
//! breaker, so reacting to an incident is fast and needs only one key. Only the
//! admin can *reset* it — point `admin` at the organization's multisig and
//! resuming operations requires a threshold of signers.
//!
//! Functions: `create_wallet`, `deposit`, `transfer`, `withdraw`, `freeze`,
//! `unfreeze`, `pause`, `unpause`, `archive`, `batch_execute`,
//! `batch_execute_validated`, `set_policy`, `set_budget`,
//! `emergency_pause`, `emergency_unpause`, `set_guardian`.
//!
//! Events: `WalletCreated`, `WalletFrozen`, `TransferExecuted`, `WalletPaused`,
//! `WalletUnpaused` (shared schema) plus wallet-scoped state-change events.
//! Access control is role-based (see [`access`]). Every wallet has an owner,
//! who is implicitly [`Role::Admin`], and may delegate a role to any number of
//! other principals so that organization owners, human managers and autonomous
//! agent executors can share a wallet without sharing all of its powers:
//!
//! | Entrypoint                                   | Minimum role |
//! |----------------------------------------------|--------------|
//! | `withdraw`, `pause`, `unpause`, `archive`     | `Admin`      |
//! | `grant_role`, `revoke_role`                   | `Admin`      |
//! | `transfer`                                    | `Agent`      |
//! | `freeze`, `unfreeze`                          | `Agent`, or the contract admin |
//!
//! A caller whose role is below the requirement — including an `Auditor`, who
//! holds no mutating power at all — is rejected with [`Error::Unauthorized`].
//!
//! Functions: `create_wallet`, `deposit`, `transfer`, `withdraw`, `freeze`,
//! `unfreeze`, `pause`, `unpause`, `archive`, `grant_role`, `revoke_role`.
//!
//! Events: `WalletCreated`, `WalletFrozen`, `TransferExecuted` (shared schema)
//! plus wallet-scoped state-change and role-administration events.

use crate::access::Role;
use astroid_interfaces::{BudgetClient, PolicyClient};
use astroid_shared::constants::{INSTANCE_BUMP_AMOUNT, INSTANCE_LIFETIME_THRESHOLD};
use astroid_shared::ensure;
use astroid_shared::errors::Error;
use astroid_shared::math::{checked_add, checked_mul, checked_sub};
use astroid_shared::math::{SafeAdd, SafeSub};
use astroid_shared::types::ResourceState;
use astroid_shared::validation::require_positive_amount;
use astroid_shared::{constants, events};
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, token, Address, Env, String, Symbol, Val,
};

pub mod access;

#[contracttype]
#[derive(Clone)]
enum DataKey {
    /// Emergency/administrative address able to freeze any wallet (instance).
    Admin,
    /// Designated emergency guardian able to trip the breaker (instance).
    Guardian,
    /// Contract-wide emergency pause flag (instance).
    Paused,
    /// Monotonic wallet id counter (instance).
    WalletCount,
    /// Policy contract consulted when validating batch actions (instance).
    Policy,
    /// Budget contract consulted when consuming batch action value (instance).
    Budget,
    /// Wallet record: id -> WalletData.
    Wallet(u64),
    /// Per-wallet, per-asset balance: (id, asset) -> i128.
    Balance(u64, Address),
    /// Minimum collateral reserve ratio in basis points: (id, asset) -> u32.
    MinReserve(u64, Address),
}

/// A single sub-call to be executed as part of a batch. `contract_addr` is the
/// target contract, `fn_name` is the entry-point symbol, and `args` are the
/// serialized arguments. The batch executor invokes each sub-call sequentially;
/// if any fails the entire transaction is atomically reverted by the Soroban
/// runtime.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractCall {
    pub contract_addr: Address,
    pub fn_name: Symbol,
    pub args: soroban_sdk::Vec<soroban_sdk::Val>,
}

/// One policy- and budget-gated action of a validated batch. Carries the raw
/// [`ContractCall`] to execute plus the metadata the wallet needs to validate
/// the action before any value moves: the policy envelope and asset/recipient
/// the spend is checked against, and the budget envelope it is consumed from.
///
/// An empty `policy_id` skips the policy gate for that action; an empty
/// `budget_id` skips budget consumption — mirrors how the treasury wires each
/// holding to a specific envelope.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchAction {
    /// The external sub-call to execute.
    pub call: ContractCall,
    /// Policy envelope id validated against this action; empty = skip.
    pub policy_id: String,
    /// Budget envelope id consumed by this action; empty = skip.
    pub budget_id: String,
    /// Asset moved by this action, used by the policy check.
    pub asset: Address,
    /// Recipient of this action's value, used by the policy check.
    pub recipient: Address,
    /// Value moved by this action, checked against policy and budget.
    pub amount: i128,
}

/// Aggregated outcome of a validated batch execution.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchReceipt {
    /// Number of sub-calls executed.
    pub executed: u32,
    /// Cumulative value across the batch (checked-sum of all action amounts).
    pub total_amount: i128,
    /// Remaining allocation of the last budget envelope consumed; `0` when the
    /// batch touched no budget.
    pub budget_remaining: i128,
}

/// Stored wallet record. `owner` controls the wallet; `state` gates operations.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalletData {
    pub owner: Address,
    pub state: ResourceState,
}

/// Maximum enforceable collateral reserve ratio, in basis points (10000 = 100%).
pub const MAX_RESERVE_RATIO_BPS: u32 = 10_000;

#[contract]
pub struct WalletContract;

#[contractimpl]
impl WalletContract {
    /// Initialize the contract with an emergency admin (may freeze wallets).
    pub fn initialize(env: Env, admin: Address) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        env.storage().instance().set(&DataKey::Admin, &admin);
        // The admin is its own guardian until a dedicated one is designated.
        env.storage().instance().set(&DataKey::Guardian, &admin);
        env.storage().instance().set(&DataKey::WalletCount, &0u64);
        env.storage().instance().set(&DataKey::Paused, &false);
        Self::bump_instance(&env);
        Ok(())
    }

    /// Designate the emergency guardian allowed to trip the circuit breaker
    /// (admin only). Set it to a monitoring service or a partner key so an
    /// incident can be contained without waiting on the admin.
    pub fn set_guardian(env: Env, caller: Address, guardian: Address) -> Result<(), Error> {
        Self::require_admin(&env, &caller)?;
        env.storage().instance().set(&DataKey::Guardian, &guardian);
        Self::bump_instance(&env);
        env.events().publish(
            (symbol_short!("wallet"), symbol_short!("guardian")),
            guardian,
        );
        Ok(())
    }

    /// Trip the contract-wide circuit breaker (admin or guardian).
    ///
    /// Freezes every outbound movement and the creation of new wallets at once.
    /// Reads, deposits and the per-wallet recovery transitions stay available.
    pub fn emergency_pause(env: Env, caller: Address) -> Result<(), Error> {
        Self::require_guardian_or_admin(&env, &caller)?;
        if Self::paused(&env) {
            return Err(Error::InvalidState);
        }
        env.storage().instance().set(&DataKey::Paused, &true);
        Self::bump_instance(&env);
        env.events()
            .publish((Symbol::new(&env, "WalletPaused"),), caller);
        Ok(())
    }

    /// Reset the circuit breaker and resume normal operation.
    ///
    /// Admin only: tripping the breaker is a fast, low-privilege reaction, but
    /// releasing it puts funds back in motion and must clear the higher bar.
    pub fn emergency_unpause(env: Env, caller: Address) -> Result<(), Error> {
        Self::require_admin(&env, &caller)?;
        if !Self::paused(&env) {
            return Err(Error::InvalidState);
        }
        env.storage().instance().set(&DataKey::Paused, &false);
        Self::bump_instance(&env);
        env.events()
            .publish((Symbol::new(&env, "WalletUnpaused"),), caller);
        Ok(())
    }

    /// Create a new wallet owned by `owner`. Returns the new wallet id.
    pub fn create_wallet(env: Env, owner: Address) -> Result<u64, Error> {
        Self::when_not_paused(&env)?;
        owner.require_auth();
        let mut count: u64 = env
            .storage()
            .instance()
            .get(&DataKey::WalletCount)
            .ok_or(Error::NotInitialized)?;
        count = (count as i128).safe_add(1)? as u64;
        let id = count;
        let data = WalletData {
            owner: owner.clone(),
            state: ResourceState::Active,
        };
        env.storage().persistent().set(&DataKey::Wallet(id), &data);
        Self::bump_wallet(&env, id);
        env.storage().instance().set(&DataKey::WalletCount, &count);
        Self::bump_instance(&env);
        events::wallet_created(&env, id, &owner);
        events::publish(
            &env,
            events::ContractEvent::WalletCreated {
                wallet_id: id,
                owner: owner.clone(),
            },
        );
        Ok(id)
    }

    /// Fund a wallet: pulls `amount` of `asset` from `from` into custody and
    /// credits the wallet's internal balance. Requires `from` authorization.
    pub fn deposit(
        env: Env,
        wallet_id: u64,
        from: Address,
        asset: Address,
        amount: i128,
    ) -> Result<(), Error> {
        require_positive_amount(amount)?;
        from.require_auth();
        let wallet = Self::load_wallet(&env, wallet_id)?;
        // Deposits are refused into archived wallets; other states may receive.
        ensure!(
            wallet.state != ResourceState::Archived,
            Error::WalletArchived
        );
        // Move real tokens into the contract's custody, then credit internally.
        token::TokenClient::new(&env, &asset).transfer(
            &from,
            &env.current_contract_address(),
            &amount,
        );
        Self::credit(&env, wallet_id, &asset, amount)?;
        env.events().publish(
            (symbol_short!("wallet"), symbol_short!("deposit")),
            (wallet_id, asset, amount),
        );
        Ok(())
    }

    /// Pay `amount` of `asset` from a wallet to an arbitrary recipient. This is
    /// the routine operational spend, so [`Role::Agent`] is enough - an
    /// autonomous executor can pay without holding administrative power - and it
    /// is still only permitted while the wallet is `Active`.
    pub fn transfer(
        env: Env,
        caller: Address,
        wallet_id: u64,
        to: Address,
        asset: Address,
        amount: i128,
    ) -> Result<(), Error> {
        require_positive_amount(amount)?;
        Self::when_not_paused(&env)?;
        let wallet = Self::require_wallet_role(&env, wallet_id, &caller, Role::Agent)?;
        Self::require_active(&wallet)?;
        Self::require_reserve_ok(&env, wallet_id, &asset, amount)?;
        Self::debit(&env, wallet_id, &asset, amount)?;
        token::TokenClient::new(&env, &asset).transfer(
            &env.current_contract_address(),
            &to,
            &amount,
        );
        events::transfer_executed(&env, &env.current_contract_address(), &to, &asset, amount);
        Ok(())
    }

    /// Withdraw `amount` of `asset` from a wallet back to its owner. Funds
    /// leaving the wallet for its owner is an administrative action, so this
    /// requires [`Role::Admin`]; agents are deliberately excluded. Only
    /// permitted while the wallet is `Active`, and the destination is always
    /// the recorded owner regardless of who calls.
    pub fn withdraw(
        env: Env,
        caller: Address,
        wallet_id: u64,
        asset: Address,
        amount: i128,
    ) -> Result<(), Error> {
        require_positive_amount(amount)?;
        Self::when_not_paused(&env)?;
        let wallet = Self::require_wallet_role(&env, wallet_id, &caller, Role::Admin)?;
        Self::require_active(&wallet)?;
        Self::require_reserve_ok(&env, wallet_id, &asset, amount)?;
        Self::debit(&env, wallet_id, &asset, amount)?;
        token::TokenClient::new(&env, &asset).transfer(
            &env.current_contract_address(),
            &wallet.owner,
            &amount,
        );
        env.events().publish(
            (symbol_short!("wallet"), symbol_short!("withdraw")),
            (wallet_id, asset, amount),
        );
        Ok(())
    }

    /// Freeze a wallet. Blocks all outbound movement. Freezing is a safety
    /// action, so [`Role::Agent`] is enough - an agent that detects trouble can
    /// stop the bleeding - as is the contract-level emergency admin.
    pub fn freeze(env: Env, caller: Address, wallet_id: u64) -> Result<(), Error> {
        let mut wallet = Self::require_wallet_role_or_admin(&env, wallet_id, &caller, Role::Agent)?;
        if wallet.state == ResourceState::Archived {
            return Err(Error::WalletArchived);
        }

        wallet.state = ResourceState::Frozen;
        Self::store_wallet(&env, wallet_id, &wallet);
        events::wallet_frozen(&env, wallet_id, &caller);
        events::publish(
            &env,
            events::ContractEvent::WalletStateChanged {
                wallet_id,
                state: symbol_short!("frozen"),
            },
        );
        Ok(())
    }

    /// Unfreeze a wallet back to `Active`. Same gate as `freeze`.
    pub fn unfreeze(env: Env, caller: Address, wallet_id: u64) -> Result<(), Error> {
        let mut wallet = Self::require_wallet_role_or_admin(&env, wallet_id, &caller, Role::Agent)?;
        if wallet.state != ResourceState::Frozen {
            return Err(Error::InvalidState);
        }

        wallet.state = ResourceState::Active;
        Self::store_wallet(&env, wallet_id, &wallet);
        Self::emit_state(&env, wallet_id, symbol_short!("unfrozen"));
        Ok(())
    }

    /// Pause a wallet ([`Role::Admin`]). Temporarily blocks outbound movement.
    pub fn pause(env: Env, caller: Address, wallet_id: u64) -> Result<(), Error> {
        let mut wallet = Self::require_wallet_role(&env, wallet_id, &caller, Role::Admin)?;
        if wallet.state != ResourceState::Active {
            return Err(Error::InvalidState);
        }

        wallet.state = ResourceState::Paused;
        Self::store_wallet(&env, wallet_id, &wallet);
        Self::emit_state(&env, wallet_id, symbol_short!("paused"));
        Ok(())
    }

    /// Resume a paused wallet ([`Role::Admin`]).
    pub fn unpause(env: Env, caller: Address, wallet_id: u64) -> Result<(), Error> {
        let mut wallet = Self::require_wallet_role(&env, wallet_id, &caller, Role::Admin)?;
        if wallet.state != ResourceState::Paused {
            return Err(Error::InvalidState);
        }

        wallet.state = ResourceState::Active;
        Self::store_wallet(&env, wallet_id, &wallet);
        Self::emit_state(&env, wallet_id, symbol_short!("unpaused"));
        Ok(())
    }

    /// Execute a batch of sub-calls atomically. If any sub-call returns an
    /// error the Soroban runtime rolls back all state changes made during the
    /// entire batch, guaranteeing atomicity. The `caller` is the executing
    /// agent ([`Role::Agent`] is sufficient, matching `transfer`), and the
    /// contract-wide circuit breaker must be reset.
    pub fn batch_execute(
        env: Env,
        caller: Address,
        wallet_id: u64,
        calls: soroban_sdk::Vec<ContractCall>,
    ) -> Result<(), Error> {
        Self::when_not_paused(&env)?;
        let wallet = Self::require_wallet_role(&env, wallet_id, &caller, Role::Agent)?;
        Self::require_active(&wallet)?;

        if calls.is_empty() {
            return Err(Error::InvalidInput);
        }
        if calls.len() > constants::MAX_BATCH_CALLS {
            return Err(Error::InvalidInput);
        }

        let n = calls.len();
        for call in calls.into_iter() {
            Self::execute_call(&env, &call)?;
        }

        events::wallet_batch_executed(&env, wallet_id, n);
        Ok(())
    }

    /// Execute a batch of [`BatchAction`]s atomically, validating every action
    /// against the contract's policy and budget gates before any sub-call
    /// fires. Each action opts into the gates via `policy_id` / `budget_id`: a
    /// non-empty id requires the corresponding contract to be wired up
    /// (`set_policy` / `set_budget`) or the batch is refused, while an empty id
    /// skips that gate for the action.
    ///
    /// Phase 1 verifies every action and aggregates its value with checked math
    /// in a single pass (one budget consumption per envelope — no speculative
    /// pre-flights), then Phase 2 executes the sub-calls sequentially. Any
    /// failure — a policy denial, a budget overrun, a cumulative overflow, or a
    /// failing sub-call — reverts the entire transaction, so validation and
    /// execution are atomic. On success an aggregated [`BatchReceipt`] is
    /// returned.
    pub fn batch_execute_validated(
        env: Env,
        caller: Address,
        wallet_id: u64,
        actions: soroban_sdk::Vec<BatchAction>,
    ) -> Result<BatchReceipt, Error> {
        Self::when_not_paused(&env)?;
        let wallet = Self::require_wallet_role(&env, wallet_id, &caller, Role::Agent)?;
        Self::require_active(&wallet)?;

        if actions.is_empty() {
            return Err(Error::InvalidInput);
        }
        if actions.len() > constants::MAX_BATCH_CALLS {
            return Err(Error::InvalidInput);
        }

        let policy: Option<Address> = env.storage().instance().get(&DataKey::Policy);
        let budget: Option<Address> = env.storage().instance().get(&DataKey::Budget);

        // Phase 1 — verify every action and aggregate its value with checked
        // math so a cumulative overflow is caught before any value moves.
        let mut total_amount: i128 = 0;
        let mut budget_remaining: i128 = 0;
        for action in actions.iter() {
            require_positive_amount(action.amount)?;
            total_amount = checked_add(total_amount, action.amount)?;

            if !action.policy_id.is_empty() {
                let policy_addr = policy.as_ref().ok_or(Error::InvalidInput)?;
                PolicyClient::new(&env, policy_addr).check_transfer(
                    &action.policy_id,
                    &action.asset,
                    &action.recipient,
                    &action.amount,
                );
            }

            if !action.budget_id.is_empty() {
                let budget_addr = budget.as_ref().ok_or(Error::InvalidInput)?;
                budget_remaining = BudgetClient::new(&env, budget_addr).consume(
                    &caller,
                    &action.budget_id,
                    &action.amount,
                );
            }
        }

        // Phase 2 — execute every action sequentially; the runtime rolls the
        // whole batch back if any sub-call fails.
        let mut executed: u32 = 0;
        for action in actions.into_iter() {
            Self::execute_call(&env, &action.call)?;
            executed += 1;
        }

        events::wallet_batch_validated(&env, wallet_id, executed, total_amount, budget_remaining);
        Ok(BatchReceipt {
            executed,
            total_amount,
            budget_remaining,
        })
    }

    /// Wire the policy contract consulted when validating batch actions
    /// (contract admin only).
    pub fn set_policy(env: Env, caller: Address, policy: Address) -> Result<(), Error> {
        Self::require_admin(&env, &caller)?;
        env.storage().instance().set(&DataKey::Policy, &policy);
        Ok(())
    }

    /// Wire the budget contract batch actions consume from (contract admin
    /// only).
    pub fn set_budget(env: Env, caller: Address, budget: Address) -> Result<(), Error> {
        Self::require_admin(&env, &caller)?;
        env.storage().instance().set(&DataKey::Budget, &budget);
        Ok(())
    }

    /// Invoke a single batch call so a callee failure surfaces as its own
    /// contract error, reverting the whole batch atomically; system-level
    /// failures are reported as [`Error::BatchCallFailed`].
    fn execute_call(env: &Env, call: &ContractCall) -> Result<(), Error> {
        match env.try_invoke_contract::<Val, Error>(
            &call.contract_addr,
            &call.fn_name,
            call.args.clone(),
        ) {
            Ok(_) => Ok(()),
            // A raw `Val` always decodes, so this arm is unreachable in
            // practice; kept for exhaustiveness.
            Err(Ok(e)) => Err(e),
            // System-level failure (panic / abort / unknown error code).
            Err(Err(_)) => Err(Error::BatchCallFailed),
        }
    }

    /// Set the minimum collateral reserve ratio for a wallet/asset pair (owner
    /// only). `ratio_bps` is in basis points (0..=10000); 0 disables the check.
    /// Once set, every outbound transfer/withdrawal must leave at least
    /// `ratio_bps/10000` of the current balance behind, so organizations can
    /// enforce a mandatory backing ratio before high-risk agent transactions.
    pub fn set_reserve_ratio(
        env: Env,
        caller: Address,
        wallet_id: u64,
        asset: Address,
        ratio_bps: u32,
    ) -> Result<(), Error> {
        Self::require_wallet_role(&env, wallet_id, &caller, Role::Admin)?;
        if ratio_bps > MAX_RESERVE_RATIO_BPS {
            return Err(Error::InvalidInput);
        }
        let key = DataKey::MinReserve(wallet_id, asset.clone());
        if ratio_bps == 0 {
            env.storage().persistent().remove(&key);
        } else {
            env.storage().persistent().set(&key, &ratio_bps);
            env.storage().persistent().extend_ttl(
                &key,
                constants::PERSISTENT_LIFETIME_THRESHOLD,
                constants::PERSISTENT_BUMP_AMOUNT,
            );
        }
        env.events().publish(
            (symbol_short!("wallet"), symbol_short!("resv_set")),
            (wallet_id, asset, ratio_bps),
        );
        Ok(())
    }

    /// Archive a wallet (owner only). Terminal state; no further transactions.
    /// Archive a wallet ([`Role::Admin`]). Terminal state; no further
    /// transactions.
    pub fn archive(env: Env, caller: Address, wallet_id: u64) -> Result<(), Error> {
        let mut wallet = Self::require_wallet_role(&env, wallet_id, &caller, Role::Admin)?;
        if wallet.state == ResourceState::Archived {
            return Err(Error::WalletArchived);
        }

        wallet.state = ResourceState::Archived;
        Self::store_wallet(&env, wallet_id, &wallet);
        Self::emit_state(&env, wallet_id, symbol_short!("archived"));
        Ok(())
    }

    /// Delegate `role` on a wallet to `account`, replacing any role it already
    /// held. Requires [`Role::Admin`], so the owner (implicitly `Admin`) or an
    /// admin it has already delegated to may administer roles.
    ///
    /// Granting to the owner is refused: the owner is implicitly `Admin`, so the
    /// grant would either be redundant or an attempted demotion that the guards
    /// would ignore anyway. Refusing it keeps the stored roles honest.
    pub fn grant_role(
        env: Env,
        caller: Address,
        wallet_id: u64,
        account: Address,
        role: Role,
    ) -> Result<(), Error> {
        let wallet = Self::require_wallet_role(&env, wallet_id, &caller, Role::Admin)?;
        if wallet.state == ResourceState::Archived {
            return Err(Error::WalletArchived);
        }
        if account == wallet.owner {
            return Err(Error::InvalidInput);
        }
        access::set_role(&env, wallet_id, &account, role);
        env.events().publish(
            (symbol_short!("role"), symbol_short!("granted")),
            (wallet_id, account, role),
        );
        Ok(())
    }

    /// Revoke whatever role `account` holds on a wallet. Requires
    /// [`Role::Admin`]. Fails with [`Error::NotFound`] when the account holds no
    /// granted role, so a revocation is never silently a no-op.
    ///
    /// Permitted on an archived wallet so role records can still be cleaned up.
    pub fn revoke_role(
        env: Env,
        caller: Address,
        wallet_id: u64,
        account: Address,
    ) -> Result<(), Error> {
        Self::require_wallet_role(&env, wallet_id, &caller, Role::Admin)?;
        access::clear_role(&env, wallet_id, &account)?;
        env.events().publish(
            (symbol_short!("role"), symbol_short!("revoked")),
            (wallet_id, account),
        );
        Ok(())
    }

    // --- views ---

    /// Read the role `account` effectively holds on a wallet, or `None` if it
    /// holds none. The wallet owner always resolves to [`Role::Admin`].
    pub fn get_role(env: Env, wallet_id: u64, account: Address) -> Result<Option<Role>, Error> {
        let wallet = Self::load_wallet(&env, wallet_id)?;
        Ok(access::effective_role(
            &env,
            wallet_id,
            &wallet.owner,
            &account,
        ))
    }

    /// Whether `account` holds at least `role` on a wallet - the same question
    /// the entrypoint guards ask, exposed for off-chain callers.
    pub fn has_role(env: Env, wallet_id: u64, account: Address, role: Role) -> Result<bool, Error> {
        let wallet = Self::load_wallet(&env, wallet_id)?;
        Ok(access::require_role(&env, wallet_id, &wallet.owner, &account, role).is_ok())
    }

    /// Read a wallet's owner + state.
    pub fn get_wallet(env: Env, wallet_id: u64) -> Result<WalletData, Error> {
        Self::load_wallet(&env, wallet_id)
    }

    /// Read a wallet's internal balance for an asset (0 if none recorded).
    /// Stays available while the breaker is tripped.
    pub fn balance(env: Env, wallet_id: u64, asset: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(wallet_id, asset))
            .unwrap_or(0)
    }

    /// Read the configured minimum reserve ratio for a wallet/asset pair in
    /// basis points (0 when no reserve requirement is set).
    pub fn reserve_ratio(env: Env, wallet_id: u64, asset: Address) -> u32 {
        env.storage()
            .persistent()
            .get(&DataKey::MinReserve(wallet_id, asset))
            .unwrap_or(0)
    }

    /// Whether the contract-wide circuit breaker is currently tripped.
    pub fn is_paused(env: Env) -> bool {
        Self::paused(&env)
    }

    /// The address currently designated as emergency guardian.
    pub fn get_guardian(env: Env) -> Result<Address, Error> {
        env.storage()
            .instance()
            .get(&DataKey::Guardian)
            .ok_or(Error::NotInitialized)
    }

    // --- internal helpers ---

    fn load_wallet(env: &Env, id: u64) -> Result<WalletData, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::Wallet(id))
            .ok_or(Error::NotFound)
    }

    fn store_wallet(env: &Env, id: u64, data: &WalletData) {
        env.storage().persistent().set(&DataKey::Wallet(id), data);
        Self::bump_wallet(env, id);
    }

    /// Authenticate `caller`, then require it to hold at least `required` on the
    /// wallet. The wallet is loaded first so an unknown id reports
    /// [`Error::NotFound`] rather than an authorization failure.
    fn require_wallet_role(
        env: &Env,
        id: u64,
        caller: &Address,
        required: Role,
    ) -> Result<WalletData, Error> {
        caller.require_auth();
        let wallet = Self::load_wallet(env, id)?;
        access::require_role(env, id, &wallet.owner, caller, required)?;

        Ok(wallet)
    }

    /// As [`Self::require_wallet_role`], but the contract-level emergency admin
    /// also passes regardless of any per-wallet role.
    fn require_wallet_role_or_admin(
        env: &Env,
        id: u64,
        caller: &Address,
        required: Role,
    ) -> Result<WalletData, Error> {
        caller.require_auth();
        let wallet = Self::load_wallet(env, id)?;
        let admin: Option<Address> = env.storage().instance().get(&DataKey::Admin);
        if admin.map(|a| &a == caller).unwrap_or(false) {
            return Ok(wallet);
        }
        access::require_role(env, id, &wallet.owner, caller, required)?;

        Ok(wallet)
    }

    fn paused(env: &Env) -> bool {
        env.storage()
            .instance()
            .get(&DataKey::Paused)
            .unwrap_or(false)
    }

    /// The circuit breaker guard applied to every value-moving entrypoint.
    fn when_not_paused(env: &Env) -> Result<(), Error> {
        if Self::paused(env) {
            return Err(Error::WalletPaused);
        }
        Ok(())
    }

    fn require_admin(env: &Env, caller: &Address) -> Result<(), Error> {
        caller.require_auth();
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        if &admin != caller {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }

    fn require_guardian_or_admin(env: &Env, caller: &Address) -> Result<(), Error> {
        caller.require_auth();
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::NotInitialized)?;
        let guardian: Option<Address> = env.storage().instance().get(&DataKey::Guardian);
        let allowed = &admin == caller || guardian.map(|g| &g == caller).unwrap_or(false);
        if !allowed {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }

    fn require_active(wallet: &WalletData) -> Result<(), Error> {
        ensure!(wallet.state != ResourceState::Frozen, Error::WalletFrozen);
        ensure!(wallet.state != ResourceState::Paused, Error::WalletPaused);
        ensure!(
            wallet.state != ResourceState::Archived,
            Error::WalletArchived
        );
        Ok(())
    }

    fn credit(env: &Env, id: u64, asset: &Address, amount: i128) -> Result<(), Error> {
        let key = DataKey::Balance(id, asset.clone());
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        let updated = current.safe_add(amount)?;
        env.storage().persistent().set(&key, &updated);
        env.storage().persistent().extend_ttl(
            &key,
            constants::PERSISTENT_LIFETIME_THRESHOLD,
            constants::PERSISTENT_BUMP_AMOUNT,
        );
        Ok(())
    }

    /// Pre-execution reserve hook: verify that a planned outbound movement keeps
    /// the wallet's remaining balance at or above the configured minimum reserve
    /// ratio. Uses cross-multiplication (`projected * 10000 >= current * bps`)
    /// so no division is ever performed — division-by-zero is impossible even
    /// when the current balance is zero. Emits a precise event on failure.
    fn require_reserve_ok(env: &Env, id: u64, asset: &Address, amount: i128) -> Result<(), Error> {
        let key = DataKey::MinReserve(id, asset.clone());
        let ratio_bps: u32 = env.storage().persistent().get(&key).unwrap_or(0);
        if ratio_bps == 0 {
            return Ok(());
        }
        let current: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance(id, asset.clone()))
            .unwrap_or(0);
        if current < amount {
            return Err(Error::InsufficientFunds);
        }
        let projected = checked_sub(current, amount)?;
        if checked_mul(projected, 10_000)? < checked_mul(current, ratio_bps as i128)? {
            env.events().publish(
                (symbol_short!("wallet"), symbol_short!("resv_fail")),
                (id, asset.clone(), amount, ratio_bps),
            );
            return Err(Error::ReserveViolation);
        }
        Ok(())
    }

    fn debit(env: &Env, id: u64, asset: &Address, amount: i128) -> Result<(), Error> {
        let key = DataKey::Balance(id, asset.clone());
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        if current < amount {
            return Err(Error::InsufficientFunds);
        }
        let updated = current.safe_sub(amount)?;

        env.storage().persistent().set(&key, &updated);
        env.storage().persistent().extend_ttl(
            &key,
            constants::PERSISTENT_LIFETIME_THRESHOLD,
            constants::PERSISTENT_BUMP_AMOUNT,
        );
        Ok(())
    }

    fn emit_state(env: &Env, id: u64, action: soroban_sdk::Symbol) {
        env.events()
            .publish((symbol_short!("wallet"), action.clone()), id);
        events::publish(
            env,
            events::ContractEvent::WalletStateChanged {
                wallet_id: id,
                state: action,
            },
        );
    }

    fn bump_wallet(env: &Env, id: u64) {
        env.storage().persistent().extend_ttl(
            &DataKey::Wallet(id),
            constants::PERSISTENT_LIFETIME_THRESHOLD,
            constants::PERSISTENT_BUMP_AMOUNT,
        );
    }

    fn bump_instance(env: &Env) {
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
    }
}

#[cfg(test)]
mod test;
