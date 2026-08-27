import re

with open("contracts/policy/src/lib.rs", "r") as f:
    text = f.read()

text = text.replace("use soroban_sdk::{", "use soroban_sdk::{\n    Vec,")

struct_old = """    /// Allow-listed recipient (zero-length means "any" is allowed).
    pub allowed_recipient: Option<Address>,
    /// Asset contract address the spend must be in (None = any asset).
    pub allowed_asset: Option<Address>,
    /// Unix timestamp the policy is active until (0 = no expiry).
    pub expires_at: u64,
    /// Whether the policy is currently enabled.
    pub enabled: bool,
}"""
struct_new = """    /// Allow-listed recipient (zero-length means "any" is allowed).
    pub allowed_recipient: Option<Address>,
    /// Asset contract addresses the spend must be in (empty = any asset).
    pub allowed_assets: Vec<Address>,
    /// Time window start (unix timestamp, 0 = no restriction).
    pub time_window_start: u64,
    /// Time window end (unix timestamp, 0 = no restriction).
    pub time_window_end: u64,
    /// Unix timestamp the policy is active until (0 = no expiry).
    pub expires_at: u64,
    /// Whether the policy is currently enabled.
    pub enabled: bool,
}"""
text = text.replace(struct_old, struct_new)

register_old = """    pub fn register_policy(
        env: Env,
        owner: Address,
        policy_id: String,
        config_hash: BytesN<32>,
        max_amount: i128,
        allowed_recipient: Option<Address>,
        allowed_asset: Option<Address>,
        expires_at: u64,
    ) -> Result<(), Error> {"""
register_new = """    pub fn register_policy(
        env: Env,
        owner: Address,
        policy_id: String,
        config_hash: BytesN<32>,
        max_amount: i128,
        allowed_recipient: Option<Address>,
        allowed_assets: Vec<Address>,
        time_window_start: u64,
        time_window_end: u64,
        expires_at: u64,
    ) -> Result<(), Error> {"""
text = text.replace(register_old, register_new)

text = text.replace("""        let policy = Policy {
            owner,
            config_hash,
            max_amount,
            allowed_recipient,
            allowed_asset,
            expires_at,
            enabled: true,
        };""", """        let policy = Policy {
            owner,
            config_hash,
            max_amount,
            allowed_recipient,
            allowed_assets,
            time_window_start,
            time_window_end,
            expires_at,
            enabled: true,
        };""")

eval_old = """        if policy.expires_at != 0 && env.ledger().timestamp() >= policy.expires_at {
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
        }"""
eval_new = """        let now = env.ledger().timestamp();
        if policy.expires_at != 0 && now >= policy.expires_at {
            events_policy_violation(&env, &policy_id, "expired");
            return Err(Error::PolicyDenied);
        }
        
        if policy.time_window_start != 0 && now < policy.time_window_start {
            events_policy_violation(&env, &policy_id, "too_early");
            return Err(Error::OutOfWindow);
        }
        if policy.time_window_end != 0 && now > policy.time_window_end {
            events_policy_violation(&env, &policy_id, "too_late");
            return Err(Error::OutOfWindow);
        }
        
        if policy.max_amount != 0 && amount > policy.max_amount {
            events_policy_violation(&env, &policy_id, "above_max");
            return Err(Error::LimitExceeded);
        }
        if let Some(allow_recip) = &policy.allowed_recipient {
            if allow_recip.clone() != recipient {
                events_policy_violation(&env, &policy_id, "bad_recipient");
                return Err(Error::PolicyDenied);
            }
        }
        if policy.allowed_assets.len() > 0 {
            let mut found = false;
            for a in policy.allowed_assets.iter() {
                if a == asset {
                    found = true;
                    break;
                }
            }
            if !found {
                events_policy_violation(&env, &policy_id, "bad_asset");
                return Err(Error::AssetRestricted);
            }
        }"""
text = text.replace(eval_old, eval_new)

with open("contracts/policy/src/lib.rs", "w") as f:
    f.write(text)
