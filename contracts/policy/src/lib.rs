#![no_std]
#![allow(clippy::too_many_arguments)]
//! # Astroid Policy Contract
//!
//! Verifies that a proposed transfer complies with the ACTIVE policy
//! configuration (PRD Doc 7 §Policy). The Astroid backend owns the human-facing
//! policy graph; this contract stores only a cryptographic hash of the active
//! configuration and a small set of scalar gates so on-chain verification is
//! cheap, fast and tamper-evident (PRD "Policy Hash Verification" enhancement).
//!
//! ```text
//! off-chain policy.json → hash → store on-chain
//! transaction → recompute hash of ACTIVE config → compare → allow / deny
//! ```
//!
//! This contract answers: "may `amount` of `asset` flow to `recipient`
//! right now?" with a deterministic [`Error`] when it may not.
//!
//! Functions: `initialize`, `register_policy`, `rotate_policy`, `check_transfer`.

use astroid_interfaces::PolicyInterface;
use astroid_shared::constants::{PERSISTENT_BUMP_AMOUNT, PERSISTENT_LIFETIME_THRESHOLD};
use astroid_shared::errors::Error;
use astroid_shared::events::ContractEvent;
use astroid_shared::math::checked_sub;
use astroid_shared::validation::{require_non_empty, require_non_negative_amount};
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, Address, BytesN, Env, String,
};

/// On-chain representation of a registered policy.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Policy {
    /// Admin that controls this policy (typically the treasury/admin wallet).
    pub owner: Address,
    /// SHA-256 hash of the human-readable policy JSON managed off-chain.
    pub config_hash: BytesN<32>,
    /// Scalar gates baked in for cheap on-chain checks (so we don't need JSON).
    pub max_amount: i128,
    /// Allow-listed recipient (zero-length means "any" is allowed).
    pub allowed_recipient: Option<Address>,
    /// Asset contract address the spend must be in (None = any asset).
    pub allowed_asset: Option<Address>,
    /// Unix timestamp the policy is active until (0 = no expiry).
    pub expires_at: u64,
    /// Whether the policy is currently enabled.
    pub enabled: bool,
}

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Policy(String),
    Count,
    Blacklist(Address),
    Allowance(String, Address),
}

#[contract]
pub struct PolicyContract;

#[contractimpl]
impl PolicyContract {
    pub fn initialize(env: Env) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Count) {
            return Err(Error::AlreadyInitialized);
        }
        env.storage().instance().set(&DataKey::Count, &0u32);
        Ok(())
    }

    /// Register a policy. `owner` gates subsequent rotations. Cheap scalar gates
    /// are stored on-chain; the full configuration is hashed for tamper-evidence.
    pub fn register_policy(
        env: Env,
        owner: Address,
        policy_id: String,
        config_hash: BytesN<32>,
        max_amount: i128,
        allowed_recipient: Option<Address>,
        allowed_asset: Option<Address>,
        expires_at: u64,
    ) -> Result<(), Error> {
        owner.require_auth();
        require_non_empty(&policy_id)?;
        if env
            .storage()
            .persistent()
            .has(&DataKey::Policy(policy_id.clone()))
        {
            return Err(Error::AlreadyExists);
        }
        let policy = Policy {
            owner,
            config_hash,
            max_amount,
            allowed_recipient,
            allowed_asset,
            expires_at,
            enabled: true,
        };
        env.storage()
            .persistent()
            .set(&DataKey::Policy(policy_id.clone()), &policy);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("registd")),
            policy_id,
        );
        Ok(())
    }

    /// Rotate an existing policy hash — e.g. after the backend recomputes it.
    pub fn rotate_policy(
        env: Env,
        caller: Address,
        policy_id: String,
        new_hash: BytesN<32>,
        new_max: i128,
    ) -> Result<(), Error> {
        caller.require_auth();
        let mut policy = Self::load(&env, &policy_id)?;
        if policy.owner != caller {
            return Err(Error::Unauthorized);
        }
        policy.config_hash = new_hash;
        policy.max_amount = new_max;
        env.storage()
            .persistent()
            .set(&DataKey::Policy(policy_id.clone()), &policy);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("rotated")),
            policy_id,
        );
        Ok(())
    }

    /// Disable / enable a policy (owner only).
    pub fn set_enabled(
        env: Env,
        caller: Address,
        policy_id: String,
        enabled: bool,
    ) -> Result<(), Error> {
        caller.require_auth();
        let mut policy = Self::load(&env, &policy_id)?;
        if policy.owner != caller {
            return Err(Error::Unauthorized);
        }
        policy.enabled = enabled;
        env.storage()
            .persistent()
            .set(&DataKey::Policy(policy_id.clone()), &policy);
        Ok(())
    }

    /// Add an address to the restricted blacklist (owner only).
    pub fn add_blacklist(
        env: Env,
        caller: Address,
        policy_id: String,
        address: Address,
    ) -> Result<(), Error> {
        caller.require_auth();
        let policy = Self::load(&env, &policy_id)?;
        if policy.owner != caller {
            return Err(Error::Unauthorized);
        }
        let key = DataKey::Blacklist(address.clone());
        if env.storage().persistent().has(&key) {
            return Err(Error::AlreadyExists);
        }
        env.storage().persistent().set(&key, &policy_id);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("blk_add")),
            (policy_id, address),
        );
        Ok(())
    }

    /// Remove an address from the restricted blacklist (owner only).
    pub fn remove_blacklist(
        env: Env,
        caller: Address,
        policy_id: String,
        address: Address,
    ) -> Result<(), Error> {
        caller.require_auth();
        let policy = Self::load(&env, &policy_id)?;
        if policy.owner != caller {
            return Err(Error::Unauthorized);
        }
        let key = DataKey::Blacklist(address.clone());
        if !env.storage().persistent().has(&key) {
            return Err(Error::NotFound);
        }
        env.storage().persistent().remove(&key);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("blk_rem")),
            (policy_id, address),
        );
        Ok(())
    }

    /// Set per-asset allowance for a policy (owner only). Minimal storage write.
    pub fn set_allowance(
        env: Env,
        caller: Address,
        policy_id: String,
        asset: Address,
        amount: i128,
    ) -> Result<(), Error> {
        caller.require_auth();
        let policy = Self::load(&env, &policy_id)?;
        if policy.owner != caller {
            return Err(Error::Unauthorized);
        }
        require_non_negative_amount(amount)?;
        let key = DataKey::Allowance(policy_id.clone(), asset.clone());
        env.storage().persistent().set(&key, &amount);
        env.storage().persistent().extend_ttl(
            &key,
            PERSISTENT_LIFETIME_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("allow_set")),
            (policy_id, asset, amount),
        );
        Ok(())
    }

    /// Check if `amount` of `asset` is within the remaining allowance for `policy_id`.
    /// Returns `PolicyAllowanceExceeded` if breached, else `Ok(())`. Minimal read, no write.
    pub fn check_allowance(
        env: Env,
        policy_id: String,
        asset: Address,
        amount: i128,
    ) -> Result<(), Error> {
        let key = DataKey::Allowance(policy_id.clone(), asset.clone());
        if env.storage().persistent().has(&key) {
            let remaining: i128 = env.storage().persistent().get(&key).unwrap_or(0);
            if amount > remaining {
                events_policy_violation(&env, &policy_id, "allowance");
                return Err(Error::PolicyAllowanceExceeded);
            }
        }
        Ok(())
    }

    /// Atomically consume `amount` from the per-asset allowance. Owner-gated, uses checked math.
    pub fn update_allowance(
        env: Env,
        caller: Address,
        policy_id: String,
        asset: Address,
        amount: i128,
    ) -> Result<(), Error> {
        caller.require_auth();
        let policy = Self::load(&env, &policy_id)?;
        if policy.owner != caller {
            return Err(Error::Unauthorized);
        }
        if amount <= 0 {
            return Err(Error::InvalidAmount);
        }
        let key = DataKey::Allowance(policy_id.clone(), asset.clone());
        let current: i128 = env.storage().persistent().get(&key).unwrap_or(0);
        if amount > current {
            events_policy_violation(&env, &policy_id, "allowance");
            return Err(Error::PolicyAllowanceExceeded);
        }
        let new = checked_sub(current, amount)?;
        env.storage().persistent().set(&key, &new);
        env.storage().persistent().extend_ttl(
            &key,
            PERSISTENT_LIFETIME_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("allow_upd")),
            (policy_id, asset, amount, new),
        );
        Ok(())
    }

    /// Get remaining allowance for an asset under a policy. Returns 0 if not set.
    pub fn get_allowance(env: Env, policy_id: String, asset: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::Allowance(policy_id, asset))
            .unwrap_or(0)
    }

    // --- views ---

    pub fn get(env: Env, policy_id: String) -> Result<Policy, Error> {
        Self::load(&env, &policy_id)
    }

    // --- internels ---

    fn load(env: &Env, id: &String) -> Result<Policy, Error> {
        env.storage()
            .persistent()
            .get(&DataKey::Policy(id.clone()))
            .ok_or(Error::NotFound)
    }
}

/// Allow the interface trait to call `check_transfer` on this contract.
#[contractimpl]
impl PolicyInterface for PolicyContract {
    /// Evaluate a transfer request against the named policy. All gates must pass.
    fn check_transfer(
        env: Env,
        policy_id: String,
        asset: Address,
        recipient: Address,
        amount: i128,
    ) -> Result<(), Error> {
        let policy = Self::load(&env, &policy_id)?;
        // Disabled policies deny every spend.
        if !policy.enabled {
            events_policy_violation(&env, &policy_id, "disabled");
            return Err(Error::PolicyDenied);
        }
        if policy.expires_at != 0 && env.ledger().timestamp() >= policy.expires_at {
            events_policy_violation(&env, &policy_id, "expired");
            return Err(Error::PolicyDenied);
        }
        if policy.max_amount != 0 && amount > policy.max_amount {
            events_policy_violation(&env, &policy_id, "above_max");
            return Err(Error::PolicyDenied);
        }
        if let Some(allow_recip) = &policy.allowed_recipient {
            if allow_recip.clone() != recipient {
                events_policy_violation(&env, &policy_id, "bad_recipient");
                return Err(Error::PolicyDenied);
            }
        }
        if let Some(allow_asset) = &policy.allowed_asset {
            if allow_asset.clone() != asset {
                events_policy_violation(&env, &policy_id, "bad_asset");
                return Err(Error::PolicyDenied);
            }
        }
        // Check blacklist
        if env
            .storage()
            .persistent()
            .has(&DataKey::Blacklist(recipient.clone()))
        {
            events_policy_violation(&env, &policy_id, "blacklisted");
            return Err(Error::PolicyRecipientRestricted);
        }
        // Multi-token per-asset allowance check
        let allowance_key = DataKey::Allowance(policy_id.clone(), asset.clone());
        if env.storage().persistent().has(&allowance_key) {
            let remaining: i128 = env.storage().persistent().get(&allowance_key).unwrap_or(0);
            if amount > remaining {
                events_policy_violation(&env, &policy_id, "allowance");
                return Err(Error::PolicyAllowanceExceeded);
            }
        }
        Ok(())
    }
}

/// Emit a `PolicyViolation` event with a stable reason symbol, using both the
/// legacy tuple-topic helper and the canonical [`ContractEvent`] schema.
fn events_policy_violation(env: &Env, policy_id: &String, reason: &str) {
    let r = soroban_sdk::Symbol::new(env, reason);
    astroid_shared::events::policy_violation(env, policy_id, r.clone());
    astroid_shared::events::publish(
        env,
        ContractEvent::PolicyViolation {
            policy_id: policy_id.clone(),
            reason: r,
        },
    );
}

#[cfg(test)]
mod test;
