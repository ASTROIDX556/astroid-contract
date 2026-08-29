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
//! Functions: `create_wallet`, `deposit`, `transfer`, `withdraw`, `freeze`,
//! `unfreeze`, `pause`, `unpause`, `archive`.
//!
//! Events: `WalletCreated`, `WalletFrozen`, `TransferExecuted` (shared schema)
//! plus wallet-scoped state-change events.

use astroid_shared::constants::{INSTANCE_BUMP_AMOUNT, INSTANCE_LIFETIME_THRESHOLD};
use astroid_shared::errors::Error;
use astroid_shared::math::{checked_add, checked_sub};
use astroid_shared::types::ResourceState;
use astroid_shared::validation::require_positive_amount;
use astroid_shared::{constants, events};
use soroban_sdk::{contract, contractimpl, contracttype, symbol_short, token, Address, Env};

#[contracttype]
#[derive(Clone)]
enum DataKey {
    /// Emergency/administrative address able to freeze any wallet (instance).
    Admin,
    /// Monotonic wallet id counter (instance).
    WalletCount,
    /// Wallet record: id -> WalletData.
    Wallet(u64),
    /// Per-wallet, per-asset balance: (id, asset) -> i128.
    Balance(u64, Address),
    /// Per-wallet, per-spender, per-asset allowance: (id, spender, asset) -> i128.
    Allowance(u64, Address, Address),
}

/// Stored wallet record. `owner` controls the wallet; `state` gates operations.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalletData {
    pub owner: Address,
    pub state: ResourceState,
}

/// Result of a dry-run simulation. Reports the projected balances that would
/// result from executing the operation.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SimResult {
    pub wallet_id: u64,
    pub from_balance: i128,
    pub to_balance: i128,
    pub asset: Address,
    pub amount: i128,
}

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
        env.storage().instance().set(&DataKey::WalletCount, &0u64);
        Self::bump_instance(&env);
        Ok(())
    }

    /// Create a new wallet owned by `owner`. Returns the new wallet id.
    pub fn create_wallet(env: Env, owner: Address) -> Result<u64, Error> {
        owner.require_auth();
        let mut count: u64 = env
            .storage()
            .instance()
            .get(&DataKey::WalletCount)
            .ok_or(Error::NotInitialized)?;
        count = checked_add(count as i128, 1)? as u64;
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
        if wallet.state == ResourceState::Archived {
            return Err(Error::WalletArchived);
        }
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

    /// Pay `amount` of `asset` from a wallet to an arbitrary recipient. Only the
    /// wallet owner may call, and only while the wallet is `Active`.
    pub fn transfer(
        env: Env,
        caller: Address,
        wallet_id: u64,
        to: Address,
        asset: Address,
        amount: i128,
    ) -> Result<(), Error> {
        require_positive_amount(amount)?;
        let wallet = Self::require_owner(&env, wallet_id, &caller)?;
        Self::require_active(&wallet)?;
        Self::debit(&env, wallet_id, &asset, amount)?;
        token::TokenClient::new(&env, &asset).transfer(
            &env.current_contract_address(),
            &to,
            &amount,
        );
        events::transfer_executed(&env, &env.current_contract_address(), &to, &asset, amount);
        Ok(())
    }

    /// Withdraw `amount` of `asset` from a wallet back to its owner. Only the
    /// owner may call, and only while the wallet is `Active`.
    pub fn withdraw(
        env: Env,
        caller: Address,
        wallet_id: u64,
        asset: Address,
        amount: i128,
    ) -> Result<(), Error> {
        require_positive_amount(amount)?;
        let wallet = Self::require_owner(&env, wallet_id, &caller)?;
        Self::require_active(&wallet)?;
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

    /// Freeze a wallet (owner or admin). Blocks all outbound movement.
    pub fn freeze(env: Env, caller: Address, wallet_id: u64) -> Result<(), Error> {
        let mut wallet = Self::require_owner_or_admin(&env, wallet_id, &caller)?;
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

    /// Unfreeze a wallet back to `Active` (owner or admin).
    pub fn unfreeze(env: Env, caller: Address, wallet_id: u64) -> Result<(), Error> {
        let mut wallet = Self::require_owner_or_admin(&env, wallet_id, &caller)?;
        if wallet.state != ResourceState::Frozen {
            return Err(Error::InvalidState);
        }
        wallet.state = ResourceState::Active;
        Self::store_wallet(&env, wallet_id, &wallet);
        Self::emit_state(&env, wallet_id, symbol_short!("unfrozen"));
        Ok(())
    }

    /// Pause a wallet (owner only). Temporarily blocks outbound movement.
    pub fn pause(env: Env, caller: Address, wallet_id: u64) -> Result<(), Error> {
        let mut wallet = Self::require_owner(&env, wallet_id, &caller)?;
        if wallet.state != ResourceState::Active {
            return Err(Error::InvalidState);
        }
        wallet.state = ResourceState::Paused;
        Self::store_wallet(&env, wallet_id, &wallet);
        Self::emit_state(&env, wallet_id, symbol_short!("paused"));
        Ok(())
    }

    /// Resume a paused wallet (owner only).
    pub fn unpause(env: Env, caller: Address, wallet_id: u64) -> Result<(), Error> {
        let mut wallet = Self::require_owner(&env, wallet_id, &caller)?;
        if wallet.state != ResourceState::Paused {
            return Err(Error::InvalidState);
        }
        wallet.state = ResourceState::Active;
        Self::store_wallet(&env, wallet_id, &wallet);
        Self::emit_state(&env, wallet_id, symbol_short!("unpaused"));
        Ok(())
    }

    /// Archive a wallet (owner only). Terminal state; no further transactions.
    pub fn archive(env: Env, caller: Address, wallet_id: u64) -> Result<(), Error> {
        let mut wallet = Self::require_owner(&env, wallet_id, &caller)?;
        if wallet.state == ResourceState::Archived {
            return Err(Error::WalletArchived);
        }
        wallet.state = ResourceState::Archived;
        Self::store_wallet(&env, wallet_id, &wallet);
        Self::emit_state(&env, wallet_id, symbol_short!("archived"));
        Ok(())
    }

    // --- dry-run simulation interface ---

    /// Simulate a transfer without mutating state. Validates ownership, wallet
    /// state, and balance, then returns the projected balances. Useful for UIs
    /// and off-chain callers to preview whether a transfer would succeed.
    pub fn simulate_transfer(
        env: Env,
        caller: Address,
        wallet_id: u64,
        to: Address,
        asset: Address,
        amount: i128,
    ) -> Result<SimResult, Error> {
        require_positive_amount(amount)?;
        let wallet = Self::require_owner(&env, wallet_id, &caller)?;
        Self::require_active(&wallet)?;
        let current: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance(wallet_id, asset.clone()))
            .unwrap_or(0);
        if current < amount {
            return Err(Error::InsufficientFunds);
        }
        Ok(SimResult {
            wallet_id,
            from_balance: checked_sub(current, amount)?,
            to_balance: amount,
            asset,
            amount,
        })
    }

    /// Simulate a withdrawal without mutating state. Validates ownership, wallet
    /// state, and balance, then returns the projected balances.
    pub fn simulate_withdraw(
        env: Env,
        caller: Address,
        wallet_id: u64,
        asset: Address,
        amount: i128,
    ) -> Result<SimResult, Error> {
        require_positive_amount(amount)?;
        let wallet = Self::require_owner(&env, wallet_id, &caller)?;
        Self::require_active(&wallet)?;
        let current: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Balance(wallet_id, asset.clone()))
            .unwrap_or(0);
        if current < amount {
            return Err(Error::InsufficientFunds);
        }
        Ok(SimResult {
            wallet_id,
            from_balance: checked_sub(current, amount)?,
            to_balance: amount,
            asset,
            amount,
        })
    }

    // --- multi-token allowance tracking ---

    /// Approve `spender` to spend up to `amount` of `asset` from a wallet.
    /// Only the wallet owner may call. Sets the allowance to `amount`.
    pub fn approve(
        env: Env,
        caller: Address,
        wallet_id: u64,
        spender: Address,
        asset: Address,
        amount: i128,
    ) -> Result<(), Error> {
        require_positive_amount(amount)?;
        let wallet = Self::require_owner(&env, wallet_id, &caller)?;
        if wallet.state == ResourceState::Archived {
            return Err(Error::WalletArchived);
        }
        env.storage()
            .persistent()
            .set(&DataKey::Allowance(wallet_id, spender.clone(), asset.clone()), &amount);
        env.storage().persistent().extend_ttl(
            &DataKey::Allowance(wallet_id, spender.clone(), asset.clone()),
            constants::PERSISTENT_LIFETIME_THRESHOLD,
            constants::PERSISTENT_BUMP_AMOUNT,
        );
        env.events().publish(
            (symbol_short!("wallet"), symbol_short!("approve")),
            (wallet_id, spender, asset, amount),
        );
        Ok(())
    }

    /// Increase a spender's allowance by `amount`. Only the wallet owner may call.
    pub fn increase_allowance(
        env: Env,
        caller: Address,
        wallet_id: u64,
        spender: Address,
        asset: Address,
        amount: i128,
    ) -> Result<(), Error> {
        require_positive_amount(amount)?;
        let wallet = Self::require_owner(&env, wallet_id, &caller)?;
        if wallet.state == ResourceState::Archived {
            return Err(Error::WalletArchived);
        }
        let current: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Allowance(wallet_id, spender.clone(), asset.clone()))
            .unwrap_or(0);
        let updated = checked_add(current, amount)?;
        env.storage()
            .persistent()
            .set(&DataKey::Allowance(wallet_id, spender.clone(), asset.clone()), &updated);
        env.storage().persistent().extend_ttl(
            &DataKey::Allowance(wallet_id, spender.clone(), asset.clone()),
            constants::PERSISTENT_LIFETIME_THRESHOLD,
            constants::PERSISTENT_BUMP_AMOUNT,
        );
        env.events().publish(
            (symbol_short!("wallet"), symbol_short!("inc_allw")),
            (wallet_id, spender, asset, updated),
        );
        Ok(())
    }

    /// Decrease a spender's allowance by `amount`. Only the wallet owner may call.
    /// Fails if the resulting allowance would be negative.
    pub fn decrease_allowance(
        env: Env,
        caller: Address,
        wallet_id: u64,
        spender: Address,
        asset: Address,
        amount: i128,
    ) -> Result<(), Error> {
        require_positive_amount(amount)?;
        let wallet = Self::require_owner(&env, wallet_id, &caller)?;
        if wallet.state == ResourceState::Archived {
            return Err(Error::WalletArchived);
        }
        let current: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Allowance(wallet_id, spender.clone(), asset.clone()))
            .unwrap_or(0);
        if current < amount {
            return Err(Error::AllowanceExceeded);
        }
        let updated = checked_sub(current, amount)?;
        env.storage()
            .persistent()
            .set(&DataKey::Allowance(wallet_id, spender.clone(), asset.clone()), &updated);
        env.storage().persistent().extend_ttl(
            &DataKey::Allowance(wallet_id, spender.clone(), asset.clone()),
            constants::PERSISTENT_LIFETIME_THRESHOLD,
            constants::PERSISTENT_BUMP_AMOUNT,
        );
        env.events().publish(
            (symbol_short!("wallet"), symbol_short!("dec_allw")),
            (wallet_id, spender, asset, updated),
        );
        Ok(())
    }

    /// Transfer `amount` of `asset` from a wallet to `to`, drawing on the
    /// caller's allowance. The caller must be an approved spender. Deducts the
    /// allowance, debits the wallet, and moves tokens.
    pub fn transfer_from(
        env: Env,
        caller: Address,
        wallet_id: u64,
        to: Address,
        asset: Address,
        amount: i128,
    ) -> Result<(), Error> {
        require_positive_amount(amount)?;
        caller.require_auth();
        let wallet = Self::load_wallet(&env, wallet_id)?;
        Self::require_active(&wallet)?;
        let allowance: i128 = env
            .storage()
            .persistent()
            .get(&DataKey::Allowance(wallet_id, caller.clone(), asset.clone()))
            .unwrap_or(0);
        if allowance < amount {
            return Err(Error::AllowanceExceeded);
        }
        Self::debit(&env, wallet_id, &asset, amount)?;
        // Decrease allowance after successful debit.
        let new_allowance = checked_sub(allowance, amount)?;
        env.storage().persistent().set(
            &DataKey::Allowance(wallet_id, caller.clone(), asset.clone()),
            &new_allowance,
        );
        env.storage().persistent().extend_ttl(
            &DataKey::Allowance(wallet_id, caller.clone(), asset.clone()),
            constants::PERSISTENT_LIFETIME_THRESHOLD,
            constants::PERSISTENT_BUMP_AMOUNT,
        );
        token::TokenClient::new(&env, &asset).transfer(
            &env.current_contract_address(),
            &to,
            &amount,
        );
        events::transfer_executed(&env, &env.current_contract_address(), &to, &asset, amount);
        Ok(())
    }

    // --- views ---

    /// Read a wallet's owner + state.
    pub fn get_wallet(env: Env, wallet_id: u64) -> Result<WalletData, Error> {
        Self::load_wallet(&env, wallet_id)
    }

    /// Read a wallet's internal balance for an asset (0 if none recorded).
    pub fn balance(env: Env, wallet_id: u64, asset: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(wallet_id, asset))
            .unwrap_or(0)
    }

    /// Read a spender's current allowance for a wallet's asset (0 if none).
    pub fn allowance(env: Env, wallet_id: u64, spender: Address, asset: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Allowance(wallet_id, spender, asset))
            .unwrap_or(0)
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

    fn require_owner(env: &Env, id: u64, caller: &Address) -> Result<WalletData, Error> {
        caller.require_auth();
        let wallet = Self::load_wallet(env, id)?;
        if &wallet.owner != caller {
            return Err(Error::Unauthorized);
        }
        Ok(wallet)
    }

    fn require_owner_or_admin(env: &Env, id: u64, caller: &Address) -> Result<WalletData, Error> {
        caller.require_auth();
        let wallet = Self::load_wallet(env, id)?;
        let admin: Option<Address> = env.storage().instance().get(&DataKey::Admin);
        let is_admin = admin.map(|a| &a == caller).unwrap_or(false);
        if &wallet.owner != caller && !is_admin {
            return Err(Error::Unauthorized);
        }
        Ok(wallet)
    }

    fn require_active(wallet: &WalletData) -> Result<(), Error> {
        match wallet.state {
            ResourceState::Active => Ok(()),
            ResourceState::Frozen => Err(Error::WalletFrozen),
            ResourceState::Paused => Err(Error::WalletPaused),
            ResourceState::Archived => Err(Error::WalletArchived),
        }
    }

    fn credit(env: &Env, id: u64, asset: &Address, amount: i128) -> Result<(), Error> {
        let key = DataKey::Balance(id, asset.clone());
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        let updated = checked_add(current, amount)?;
        env.storage().persistent().set(&key, &updated);
        env.storage().persistent().extend_ttl(
            &key,
            constants::PERSISTENT_LIFETIME_THRESHOLD,
            constants::PERSISTENT_BUMP_AMOUNT,
        );
        Ok(())
    }

    fn debit(env: &Env, id: u64, asset: &Address, amount: i128) -> Result<(), Error> {
        let key = DataKey::Balance(id, asset.clone());
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        if current < amount {
            return Err(Error::InsufficientFunds);
        }
        let updated = checked_sub(current, amount)?;
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
