#![no_std]
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
//! Functions: `initialize`, `register_policy`, `rotate_policy`, `pause`,
//! `unpause`, `paused`, `check_transfer`.

use astroid_interfaces::PolicyInterface;
use astroid_shared::constants::MAX_PAUSE_DURATION;
use astroid_shared::errors::Error;
use astroid_shared::validation::require_non_empty;
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
    Admin,
    Pause,
}

#[contract]
pub struct PolicyContract;

#[contractimpl]
impl PolicyContract {
    /// Initialize the policy contract, registering `admin` as the only address
    /// authorized to rotate policies and to operate the emergency pause switch.
    pub fn initialize(env: Env, admin: Address) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Count) {
            return Err(Error::AlreadyInitialized);
        }
        admin.require_auth();
        env.storage().instance().set(&DataKey::Count, &0u32);
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Pause, &0u64);
        Ok(())
    }

    /// Activate the time-bound emergency pause. While paused, every
    /// `check_transfer` evaluation is rejected with `PolicyPaused`. `duration`
    /// is the number of seconds the pause lasts; it is capped by
    /// `MAX_PAUSE_DURATION` to prevent indefinite lockouts. Passing `duration ==
    /// 0` activates an indefinite pause that only an authorized admin can lift
    /// via `unpause`. Admin only.
    pub fn pause(env: Env, caller: Address, duration: u64) -> Result<(), Error> {
        Self::require_admin(&env, &caller)?;
        let paused_until: u64 = if duration == 0 {
            // Indefinite pause — lifted only by an explicit `unpause`.
            u64::MAX
        } else {
            if duration > MAX_PAUSE_DURATION {
                return Err(Error::PauseDurationExceeded);
            }
            env.ledger()
                .timestamp()
                .checked_add(duration)
                .ok_or(Error::Overflow)?
        };
        env.storage().instance().set(&DataKey::Pause, &paused_until);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("paused")),
            paused_until,
        );
        Ok(())
    }

    /// Lift an active emergency pause. Admin only. Returns evaluation to normal
    /// immediately regardless of any remaining duration.
    pub fn unpause(env: Env, caller: Address) -> Result<(), Error> {
        let _admin = Self::require_admin(&env, &caller)?;
        env.storage().instance().set(&DataKey::Pause, &0u64);
        env.events()
            .publish((symbol_short!("policy"), symbol_short!("resumed")), ());
        Ok(())
    }

    /// Whether the contract is currently paused (active pause window or
    /// indefinite pause).
    pub fn paused(env: Env) -> bool {
        let paused_until: u64 = env.storage().instance().get(&DataKey::Pause).unwrap_or(0);
        if paused_until == 0 {
            return false;
        }
        // Indefinite pause (u64::MAX) or a still-active time window.
        paused_until == u64::MAX || env.ledger().timestamp() < paused_until
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

    // --- views ---

    pub fn get(env: Env, policy_id: String) -> Result<Policy, Error> {
        Self::load(&env, &policy_id)
    }

    // --- internels ---

    fn require_admin(env: &Env, caller: &Address) -> Result<Address, Error> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .ok_or(Error::Unauthorized)?;
        if &admin != caller {
            return Err(Error::Unauthorized);
        }
        caller.require_auth();
        Ok(admin)
    }

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
        // Emergency pause: block all policy evaluations while active.
        if Self::paused(env.clone()) {
            events_policy_violation(&env, &policy_id, "paused");
            return Err(Error::PolicyPaused);
        }
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
        Ok(())
    }
}

/// Emit a `PolicyViolation` event with a stable reason symbol.
fn events_policy_violation(env: &Env, policy_id: &String, reason: &str) {
    astroid_shared::events::policy_violation(env, policy_id, soroban_sdk::Symbol::new(env, reason));
}

#[cfg(test)]
mod test;
