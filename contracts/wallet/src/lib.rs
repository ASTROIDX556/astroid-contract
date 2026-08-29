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
//! Owners may also configure a per-wallet **rate limit** (max outbound volume
//! and transaction count per fixed epoch window, keyed off the ledger
//! timestamp) to blunt rapid-drain attacks and runaway agent loops. Outbound
//! transactions (`transfer`/`withdraw`) that would push a window past its
//! configured caps are rejected with [`Error::RateLimitExceeded`] before any
//! funds move.
//!
//! Functions: `create_wallet`, `deposit`, `transfer`, `withdraw`, `freeze`,
//! `unfreeze`, `pause`, `unpause`, `archive`, `set_rate_limit`.
//!
//! Events: `WalletCreated`, `WalletFrozen`, `TransferExecuted` (shared schema)
//! plus wallet-scoped state-change and rate-limit events.

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
    /// Rate-limit config per wallet: id -> RateLimitConfig.
    RateLimit(u64),
    /// Rate-limit usage per wallet and epoch window: (id, window_start) -> RateUsage.
    RateUsage(u64, u64),
}

/// Stored wallet record. `owner` controls the wallet; `state` gates operations.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalletData {
    pub owner: Address,
    pub state: ResourceState,
}

/// Per-wallet rate-limit configuration. Limits are enforced per fixed epoch
/// window of `window_seconds`, aligned to the ledger timestamp. A value of `0`
/// means "unlimited" for `max_volume`/`max_count`; `window_seconds == 0`
/// disables rate limiting entirely (the default for wallets without a config).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RateLimitConfig {
    /// Maximum cumulative outbound volume per window (0 = unlimited).
    pub max_volume: i128,
    /// Maximum outbound transactions per window (0 = unlimited).
    pub max_count: u32,
    /// Window size in seconds (0 = rate limiting disabled).
    pub window_seconds: u64,
}

/// Cumulative outbound usage recorded for a wallet within a single epoch window.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RateUsage {
    pub volume: i128,
    pub count: u32,
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
    /// wallet owner may call, and only while the wallet is `Active`. Subject to
    /// the wallet's configured rate limit.
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
        Self::enforce_rate_limit(&env, wallet_id, amount)?;
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
    /// owner may call, and only while the wallet is `Active`. Subject to the
    /// wallet's configured rate limit.
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
        Self::enforce_rate_limit(&env, wallet_id, amount)?;
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

    /// Configure a wallet's rate limit (owner only): maximum outbound volume
    /// and transaction count per fixed epoch window of `window_seconds`.
    /// `max_volume == 0` and `max_count == 0` mean unlimited for that dimension;
    /// `window_seconds == 0` disables rate limiting entirely.
    pub fn set_rate_limit(
        env: Env,
        caller: Address,
        wallet_id: u64,
        max_volume: i128,
        max_count: u32,
        window_seconds: u64,
    ) -> Result<(), Error> {
        Self::require_owner(&env, wallet_id, &caller)?;
        if max_volume < 0 {
            return Err(Error::InvalidInput);
        }
        let config = RateLimitConfig {
            max_volume,
            max_count,
            window_seconds,
        };
        env.storage()
            .instance()
            .set(&DataKey::RateLimit(wallet_id), &config);
        Self::bump_instance(&env);
        env.events().publish(
            (symbol_short!("wallet"), symbol_short!("ratelimit")),
            (wallet_id, max_volume, max_count, window_seconds),
        );
        Ok(())
    }

    // --- views ---

    /// Read a wallet's owner + state.
    pub fn get_wallet(env: Env, wallet_id: u64) -> Result<WalletData, Error> {
        Self::load_wallet(&env, wallet_id)
    }

    /// Read a wallet's rate-limit config (disabled defaults when unset).
    pub fn get_rate_limit(env: Env, wallet_id: u64) -> RateLimitConfig {
        env.storage()
            .instance()
            .get(&DataKey::RateLimit(wallet_id))
            .unwrap_or(RateLimitConfig {
                max_volume: 0,
                max_count: 0,
                window_seconds: 0,
            })
    }

    /// Read a wallet's outbound usage in the current epoch window (zeros when
    /// rate limiting is not configured).
    pub fn get_rate_usage(env: Env, wallet_id: u64) -> RateUsage {
        let config: RateLimitConfig =
            match env.storage().instance().get(&DataKey::RateLimit(wallet_id)) {
                Some(c) => c,
                None => {
                    return RateUsage {
                        volume: 0,
                        count: 0,
                    }
                }
            };
        if config.window_seconds == 0 {
            return RateUsage {
                volume: 0,
                count: 0,
            };
        }
        let ts = env.ledger().timestamp();
        let window = ts - (ts % config.window_seconds);
        env.storage()
            .persistent()
            .get(&DataKey::RateUsage(wallet_id, window))
            .unwrap_or(RateUsage {
                volume: 0,
                count: 0,
            })
    }

    /// Read a wallet's internal balance for an asset (0 if none recorded).
    pub fn balance(env: Env, wallet_id: u64, asset: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Balance(wallet_id, asset))
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

    /// Enforce a wallet's rate limit for an outbound transaction of `amount`
    /// and record it against the current epoch window. Returns
    /// [`Error::RateLimitExceeded`] when either the window volume or transaction
    /// count cap would be exceeded; the caller's whole invocation reverts on
    /// error, so no usage or balance change is committed for rejected transfers.
    fn enforce_rate_limit(env: &Env, wallet_id: u64, amount: i128) -> Result<(), Error> {
        let config: RateLimitConfig =
            match env.storage().instance().get(&DataKey::RateLimit(wallet_id)) {
                Some(c) => c,
                None => return Ok(()),
            };
        if config.window_seconds == 0 {
            return Ok(());
        }
        let ts = env.ledger().timestamp();
        let window = ts - (ts % config.window_seconds);
        let key = DataKey::RateUsage(wallet_id, window);
        let usage: RateUsage = env.storage().persistent().get(&key).unwrap_or(RateUsage {
            volume: 0,
            count: 0,
        });

        if config.max_count != 0 && usage.count >= config.max_count {
            return Err(Error::RateLimitExceeded);
        }
        let new_volume = checked_add(usage.volume, amount)?;
        if config.max_volume != 0 && new_volume > config.max_volume {
            return Err(Error::RateLimitExceeded);
        }

        let updated = RateUsage {
            volume: new_volume,
            count: checked_add(usage.count as i128, 1)? as u32,
        };
        env.storage().persistent().set(&key, &updated);
        env.storage().persistent().extend_ttl(
            &key,
            constants::PERSISTENT_LIFETIME_THRESHOLD,
            constants::PERSISTENT_BUMP_AMOUNT,
        );
        Ok(())
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
        env.events().publish((symbol_short!("wallet"), action), id);
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
