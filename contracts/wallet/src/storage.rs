//! Wallet storage layout and the low-level accessors over it (Issue #538).
//!
//! Every ledger read or write the wallet performs goes through this module,
//! so the access pattern of each entry point can be audited in one place and
//! kept to the minimum Soroban charges for:
//!
//! * **Instance** entries (`Admin`, `Guardian`, `Paused`, `WalletCount`,
//!   `Policy`, `Budget`, `Registry`, `Org`, `DefaultBudgetId`,
//!   `ReentrancyLock`) share one ledger entry and one TTL. It is extended
//!   once per value-moving invocation, when the re-entrancy lock is taken
//!   ([`acquire_lock`]); releasing the lock in the same invocation does not
//!   extend it a second time.
//! * **Persistent** entries (`Wallet`, `Balance`, `PolicyBypass`,
//!   `VelocityLimit`/`VelocityUsage`, `RateLimit`/`RateLimitUsage`,
//!   `AssetBudgetId`) each carry their own TTL, extended whenever the entry
//!   is written so a live wallet's state can never be archived mid-use.
//!
//! Callers read an entry once per invocation and pass the value along rather
//! than re-reading it: e.g. an outbound movement reads the tracked
//! `Balance(wallet, asset)` a single time to both verify and debit it.

use astroid_shared::constants::{
    INSTANCE_BUMP_AMOUNT, INSTANCE_LIFETIME_THRESHOLD, PERSISTENT_BUMP_AMOUNT,
    PERSISTENT_LIFETIME_THRESHOLD,
};
use astroid_shared::ensure;
use astroid_shared::errors::Error;
use astroid_shared::types::WalletData;
use soroban_sdk::{contracttype, Address, Env};

#[contracttype]
#[derive(Clone)]
pub(crate) enum DataKey {
    /// Emergency/administrative address able to freeze any wallet (instance).
    Admin,
    /// Designated emergency guardian able to trip the breaker (instance).
    Guardian,
    /// Contract-wide emergency pause flag (instance).
    Paused,
    /// Monotonic wallet id counter (instance).
    WalletCount,
    /// Budget contract consulted when consuming batch action value (instance).
    Budget,
    /// Wallet record: id -> WalletData.
    Wallet(u64),
    /// Per-wallet, per-asset balance: (id, asset) -> i128.
    Balance(u64, Address),
    /// Org-wide Policy contract consulted before every outbound movement
    /// (instance).
    Policy,
    /// Per-wallet opt-out from the policy gate: wallet id -> bool (persistent).
    /// Present + `true` means the wallet spends without policy evaluation.
    PolicyBypass(u64),
    /// Velocity ceiling: (wallet id, asset) -> VelocityLimit (persistent).
    VelocityLimit(u64, Address),
    /// Rolling velocity usage: (wallet id, asset) -> VelocityUsage
    /// (persistent). One fixed-size record per limited (wallet, asset), always
    /// overwritten in place, so usage never grows the ledger footprint.
    VelocityUsage(u64, Address),
    /// Rate-limit config: wallet id -> RateLimitConfig (persistent). A missing
    /// entry means rate limiting is off.
    RateLimit(u64),
    /// Rolling rate usage: wallet id -> RateUsage (persistent). One fixed-size
    /// record per limited wallet, always overwritten in place.
    RateLimitUsage(u64),
    /// Registry contract for dynamic policy/budget resolution (instance).
    Registry,
    /// Organization slug for registry lookups (instance).
    Org,
    /// Re-entrancy lock flag (instance).
    ReentrancyLock,
    /// Default budget envelope id for single transfers (instance).
    DefaultBudgetId,
    /// Per-asset budget envelope id: asset -> budget_id (persistent).
    AssetBudgetId(Address),
    /// Scheduled execution timelock: wallet id -> timestamp (persistent).
    Timelock(u64),
}

/// Extend the shared instance TTL.
pub(crate) fn bump_instance(env: &Env) {
    env.storage()
        .instance()
        .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
}

/// Extend the TTL of one persistent entry.
pub(crate) fn bump_persistent(env: &Env, key: &DataKey) {
    env.storage().persistent().extend_ttl(
        key,
        PERSISTENT_LIFETIME_THRESHOLD,
        PERSISTENT_BUMP_AMOUNT,
    );
}

/// Write a persistent entry and extend its TTL in one step.
fn set_persistent<V: soroban_sdk::IntoVal<Env, soroban_sdk::Val>>(
    env: &Env,
    key: &DataKey,
    value: &V,
) {
    env.storage().persistent().set(key, value);
    bump_persistent(env, key);
}

pub(crate) fn load_wallet(env: &Env, id: u64) -> Result<WalletData, Error> {
    env.storage()
        .persistent()
        .get(&DataKey::Wallet(id))
        .ok_or(Error::NotFound)
}

pub(crate) fn store_wallet(env: &Env, id: u64, data: &WalletData) {
    set_persistent(env, &DataKey::Wallet(id), data);
}

pub(crate) fn bump_wallet(env: &Env, id: u64) {
    bump_persistent(env, &DataKey::Wallet(id));
}

/// Tracked balance of `asset` held for wallet `id`; `0` when never funded.
pub(crate) fn read_balance(env: &Env, id: u64, asset: &Address) -> i128 {
    env.storage()
        .persistent()
        .get(&DataKey::Balance(id, asset.clone()))
        .unwrap_or(0)
}

/// Overwrite the tracked balance of `asset` for wallet `id`.
pub(crate) fn write_balance(env: &Env, id: u64, asset: &Address, amount: i128) {
    set_persistent(env, &DataKey::Balance(id, asset.clone()), &amount);
}

/// Contract-wide emergency pause flag.
pub(crate) fn is_paused(env: &Env) -> bool {
    env.storage()
        .instance()
        .get(&DataKey::Paused)
        .unwrap_or(false)
}

/// Whether wallet `id` is excused from the policy gate.
pub(crate) fn policy_bypass(env: &Env, id: u64) -> bool {
    env.storage()
        .persistent()
        .get(&DataKey::PolicyBypass(id))
        .unwrap_or(false)
}

/// Take the re-entrancy lock, refusing with [`Error::InvalidState`] if a
/// wallet entry point is already on the stack. Extends the instance TTL —
/// the one instance bump a value-moving invocation pays for.
pub(crate) fn acquire_lock(env: &Env) -> Result<(), Error> {
    let locked: bool = env
        .storage()
        .instance()
        .get(&DataKey::ReentrancyLock)
        .unwrap_or(false);
    ensure!(!locked, Error::InvalidState);
    env.storage()
        .instance()
        .set(&DataKey::ReentrancyLock, &true);
    bump_instance(env);
    Ok(())
}

/// Release the re-entrancy lock. The instance TTL was already extended by
/// [`acquire_lock`] in this same invocation, so it is not extended again.
pub(crate) fn release_lock(env: &Env) {
    env.storage()
        .instance()
        .set(&DataKey::ReentrancyLock, &false);
}

pub(crate) fn read_timelock(env: &Env, id: u64) -> u64 {
    env.storage()
        .persistent()
        .get(&DataKey::Timelock(id))
        .unwrap_or(0)
}

pub(crate) fn set_timelock(env: &Env, id: u64, unlock_time: u64) {
    set_persistent(env, &DataKey::Timelock(id), &unlock_time);
}

pub(crate) fn clear_timelock(env: &Env, id: u64) {
    env.storage().persistent().remove(&DataKey::Timelock(id));
}
