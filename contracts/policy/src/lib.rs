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
//! Functions: `initialize`, `register_policy`, `rotate_policy`, `set_allowance`,
//! `get_allowance`, `check_allowance`, `update_allowance`, `check_transfer`.
//!
//! ## Multi-token allowances
//!
//! A policy can attach a per-asset spending allowance to any policy. Each
//! Stellar asset type (native XLM or a Soroban SAC token) is tracked under its
//! own `(policy_id, asset)` key, so evaluation is safe against overflow and
//! cheap (single persistent read/write).
//!
//! ## Asset deny list
//!
//! Agents source their token lists off-chain, so a policy also owns an on-chain
//! asset deny list keyed by `(policy_id, asset)` and managed by the policy owner
//! through `add_asset_blacklist` / `remove_asset_blacklist`. `check_transfer`
//! probes it once and denies a listed asset with [`Error::PolicyDenied`] and an
//! `asset_blacklisted` violation reason. The deny list is evaluated after the
//! allow gates and wins over them, so blacklisting an allow-listed or
//! whitelisted asset takes effect immediately.
//!
//! A dedicated `AssetBlacklisted` error code would read better here, but
//! [`Error`] already carries the 50 cases a Soroban error enum may declare, so
//! the deny list reuses [`Error::PolicyDenied`] and is distinguished by its
//! violation event reason.
//!
//! ## Multi-rule composition
//!
//! On top of the single composite tree set through `set_composite_rule`, a
//! policy can stack up to [`MAX_POLICY_RULES`] independent rule trees with
//! `add_policy_rule`. The stack is evaluated on every `check_transfer` and the
//! rules are combined conjunctively: **all** registered rules must pass. The
//! iteration short-circuits — the first rule that evaluates to `false` aborts
//! the loop immediately (gas-efficient) and the transfer is denied with
//! [`Error::PolicyDenied`]. `remove_policy_rule` / `clear_policy_rules` shrink
//! the stack again, so the governance team can retire a rule without touching
//! the remaining ones.
//!
//! ## Recipient whitelisting
//!
//! A policy can additionally own an on-chain *recipient whitelist* — the
//! organization's approved destination directory. Entries are stored per rule
//! set under `(policy_id, recipient)` and managed dynamically with
//! `add_recipient_to_whitelist` / `remove_recipient_from_whitelist`, while the
//! mode itself is a per-policy toggle (`set_recipient_whitelist_enabled`) so a
//! directory can be staged before it is enforced.
//!
//! While the mode is active every destination must be listed: an **empty**
//! whitelist denies every recipient (fail closed by default) and a miss is
//! rejected with [`Error::PolicyDenied`] plus a `not_whitelisted` violation
//! event. With the mode off the gate is a no-op, so existing policies keep
//! their behaviour until governance opts in.

use astroid_interfaces::{PolicyInterface, UpgradeableInterface};
use astroid_shared::errors::Error;
use astroid_shared::events::ContractEvent;
use astroid_shared::math::{checked_add, checked_sub};
use astroid_shared::validation::{require_non_empty, require_non_negative_amount};
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, Address, BytesN, Env, String,
};

/// Maximum recursion depth for composite rule evaluation to prevent stack
/// overflows and excessive gas consumption on-chain.
const MAX_RULE_DEPTH: u32 = 10;

/// Maximum number of independent rule trees a policy may stack. Bounds the
/// cost of the all-rules-must-pass evaluation loop so a policy owner cannot
/// register an unbounded amount of work for every transfer check.
const MAX_POLICY_RULES: u32 = 16;

/// A transaction payload submitted for policy evaluation.
///
/// This struct carries the essential fields of a proposed transfer so the
/// composite rule engine can assess it against the full policy tree.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionPayload {
    /// The Stellar asset contract address being transferred.
    pub asset: Address,
    /// The intended recipient of the transfer.
    pub recipient: Address,
    /// The amount being transferred (in base units).
    pub amount: i128,
}

/// The operation performed by a rule node.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum RuleOp {
    /// Leaf: transfer amount must be at most `value_i128`.
    MaxAmount = 0,
    /// Leaf: recipient must equal `value_address`.
    AllowedRecipient = 1,
    /// Leaf: asset must equal `value_address`.
    AllowedAsset = 2,
    /// Leaf: recipient must be on the on-chain blacklist.
    RecipientBlacklisted = 3,
    /// Leaf: recipient must be on the merchant blacklist.
    MerchantBlacklisted = 4,
    /// Branch: **all** children must evaluate to `true`.
    And = 5,
    /// Branch: **at least one** child must evaluate to `true`.
    Or = 6,
    /// Branch: negates the single child rule.
    Not = 7,
}

/// A single node in a flattened composite rule tree.
///
/// Branch nodes (`And`, `Or`, `Not`) reference their children by index range
/// into the enclosing [`RuleTree`] vector. Leaf nodes use
/// `children_start == children_end == 0`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuleNode {
    /// The operation this node performs.
    pub op: RuleOp,
    /// Payload for leaf nodes that carry an amount threshold.
    pub value_i128: i128,
    /// Payload for leaf nodes that carry an address.
    pub value_address: Address,
    /// Index of the first child in the tree vector (`0` = no children).
    pub children_start: u32,
    /// One past the last child index (`0` = no children).
    pub children_end: u32,
}

/// A flattened composite policy rule tree.
///
/// The root node is always at index **0**.  Children of a branch node at index
/// `i` occupy the contiguous range `[children_start, children_end)` in the
/// same vector.
///
/// **Gas safety:** Evaluation is depth-limited to [`MAX_RULE_DEPTH`].
pub type RuleTree = soroban_sdk::Vec<RuleNode>;

/// A stack of independently registered rule trees for one policy. Every entry
/// is an independent [`RuleTree`] and **all** of them must pass for a
/// transaction to be authorized.
pub type RuleStack = soroban_sdk::Vec<RuleTree>;

/// Reject a malformed [`RuleTree`] at write time.
///
/// The tree must contain a root node at index 0 and every branch node's child
/// range must resolve inside the tree (`children_start < children_end <= len`,
/// exactly one child for `Not`). Validating on registration keeps the
/// evaluation loop's iteration bounds safe: `evaluate_node` then only has to
/// walk ranges that are known to resolve.
fn validate_rule_tree(tree: &RuleTree) -> Result<(), Error> {
    if tree.is_empty() {
        return Err(Error::InvalidInput);
    }
    let len = tree.len();
    for i in 0..len {
        let node = tree.get(i).ok_or(Error::InvalidInput)?;
        // `checked_sub` keeps the range arithmetic panic-free: a crafted
        // `children_start > children_end` must yield `InvalidInput`, never an
        // overflow abort.
        let bad_children = match node.op {
            RuleOp::And | RuleOp::Or => {
                node.children_start >= node.children_end || node.children_end > len
            }
            RuleOp::Not => {
                node.children_end.checked_sub(node.children_start) != Some(1)
                    || node.children_end > len
            }
            // Leaves carry a payload instead of children.
            _ => false,
        };
        if bad_children {
            return Err(Error::InvalidInput);
        }
    }
    Ok(())
}

/// Cache blacklist membership for the recipient while evaluating a policy's
/// composite rule and rule stack.
#[derive(Default)]
struct RuleEvaluationContext {
    recipient_blacklisted: Option<bool>,
    merchant_blacklisted: Option<bool>,
}

impl RuleEvaluationContext {
    fn recipient_blacklisted(&mut self, env: &Env, recipient: &Address) -> bool {
        if let Some(is_blacklisted) = self.recipient_blacklisted {
            return is_blacklisted;
        }
        let is_blacklisted = env
            .storage()
            .persistent()
            .has(&DataKey::Blacklist(recipient.clone()));
        self.recipient_blacklisted = Some(is_blacklisted);
        is_blacklisted
    }

    fn merchant_blacklisted(&mut self, env: &Env, recipient: &Address) -> bool {
        if let Some(is_blacklisted) = self.merchant_blacklisted {
            return is_blacklisted;
        }
        let is_blacklisted = env
            .storage()
            .persistent()
            .has(&DataKey::MerchantBlacklist(recipient.clone()));
        self.merchant_blacklisted = Some(is_blacklisted);
        is_blacklisted
    }
}

/// Evaluate a node in a [`RuleTree`] against `payload`.
///
/// `depth` is decremented on every recursive call; returns
/// `Err(Error::InvalidInput)` when exhausted (stack/gas protection).
fn evaluate_node(
    env: &Env,
    tree: &RuleTree,
    node_idx: u32,
    payload: &TransactionPayload,
    depth: u32,
    context: &mut RuleEvaluationContext,
) -> Result<bool, Error> {
    if depth == 0 {
        return Err(Error::InvalidInput);
    }
    let remaining = depth - 1;
    let node = tree.get(node_idx).ok_or(Error::InvalidInput)?;
    match node.op {
        RuleOp::MaxAmount => Ok(payload.amount <= node.value_i128),
        RuleOp::AllowedRecipient => Ok(payload.recipient == node.value_address),
        RuleOp::AllowedAsset => Ok(payload.asset == node.value_address),
        RuleOp::RecipientBlacklisted => Ok(context.recipient_blacklisted(env, &payload.recipient)),
        RuleOp::MerchantBlacklisted => Ok(context.merchant_blacklisted(env, &payload.recipient)),
        RuleOp::And => {
            if node.children_start == node.children_end {
                return Err(Error::InvalidInput);
            }
            for i in node.children_start..node.children_end {
                if !evaluate_node(env, tree, i, payload, remaining, context)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        RuleOp::Or => {
            if node.children_start == node.children_end {
                return Err(Error::InvalidInput);
            }
            for i in node.children_start..node.children_end {
                if evaluate_node(env, tree, i, payload, remaining, context)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        RuleOp::Not => {
            // `checked_sub` keeps the range arithmetic panic-free: a crafted
            // `children_start == u32::MAX` must yield `InvalidInput`, never an
            // overflow abort. Exactly one child is required.
            if node.children_end.checked_sub(node.children_start) != Some(1) {
                return Err(Error::InvalidInput);
            }
            let result =
                evaluate_node(env, tree, node.children_start, payload, remaining, context)?;
            Ok(!result)
        }
    }
}

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
    MerchantBlacklist(Address),
    CategoryBlacklist(String),
    /// Per-policy asset whitelist: (policy_id, asset) -> true.
    AssetWhitelist(String, Address),
    /// Per-policy asset deny list: (policy_id, asset) -> (). Keyed by policy so
    /// each policy governs only its own assets.
    AssetBlacklist(String, Address),
    /// Whether an org uses a permissive (all-assets-allowed) or restrictive
    /// (whitelist-enforced) asset mode. Stored per policy_id.
    AssetWhitelistEnabled(String),
    /// Per-policy recipient whitelist: (policy_id, recipient) -> true. Keys the
    /// approved destination directory of one organization rule set.
    RecipientWhitelist(String, Address),
    /// Whether a policy enforces its recipient whitelist (default: off).
    RecipientWhitelistEnabled(String),
    /// Ordered index of the recipients listed under a policy. Soroban contract
    /// storage cannot be enumerated, so this vector is kept in sync with
    /// `RecipientWhitelist` to make the directory readable back to callers.
    RecipientWhitelistIndex(String),
    /// Per-(policy, asset) multi-token spending allowance.
    Allowance(String, Address),
    /// Composite rule tree for a policy (set via `set_composite_rule`).
    CompositeRule(String),
    /// Stack of independently registered rule trees for a policy (all must
    /// pass; managed through `add_policy_rule` / `remove_policy_rule`).
    PolicyRules(String),
}

/// A per-asset spending allowance attached to a policy.
///
/// Multiple Stellar asset types (native XLM and Soroban SAC tokens) are tracked
/// independently under the (policy_id, asset) key, so a policy can express a
/// granular quota per token rather than a single default denomination.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssetAllowance {
    /// The policy this allowance belongs to.
    pub policy_id: String,
    /// The asset contract address (SAC) or the native XLM contract.
    pub asset: Address,
    /// Cumulative spending limit for this asset. `0` means disabled.
    pub limit: i128,
    /// Amount already spent against the limit.
    pub spent: i128,
    /// Unix timestamp the allowance expires at (`0` = never).
    pub expires_at: u64,
}

#[contract]
pub struct PolicyContract;

#[contractimpl]
#[allow(clippy::too_many_arguments)]
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
    #[allow(clippy::too_many_arguments)]
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

    /// Add an asset to the policy's whitelist (owner only). When the asset
    /// whitelist is enabled for a policy, only whitelisted assets are permitted
    /// in `check_transfer`.
    pub fn add_asset_to_whitelist(
        env: Env,
        caller: Address,
        policy_id: String,
        asset: Address,
    ) -> Result<(), Error> {
        caller.require_auth();
        let policy = Self::load(&env, &policy_id)?;
        if policy.owner != caller {
            return Err(Error::Unauthorized);
        }
        let key = DataKey::AssetWhitelist(policy_id.clone(), asset.clone());
        if env.storage().persistent().has(&key) {
            return Err(Error::AlreadyExists);
        }
        env.storage().persistent().set(&key, &true);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("asset_add")),
            (policy_id, asset),
        );
        Ok(())
    }

    /// Remove an asset from the policy's whitelist (owner only).
    pub fn remove_asset_from_whitelist(
        env: Env,
        caller: Address,
        policy_id: String,
        asset: Address,
    ) -> Result<(), Error> {
        caller.require_auth();
        let policy = Self::load(&env, &policy_id)?;
        if policy.owner != caller {
            return Err(Error::Unauthorized);
        }
        let key = DataKey::AssetWhitelist(policy_id.clone(), asset.clone());
        if !env.storage().persistent().has(&key) {
            return Err(Error::NotFound);
        }
        env.storage().persistent().remove(&key);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("asset_rem")),
            (policy_id, asset),
        );
        Ok(())
    }

    /// Blacklist an asset for a policy (owner only). Once listed, no transfer
    /// evaluated against `policy_id` may move that token, whatever the policy's
    /// other asset gates say.
    pub fn add_asset_blacklist(
        env: Env,
        caller: Address,
        policy_id: String,
        asset: Address,
    ) -> Result<(), Error> {
        Self::require_policy_owner(&env, &caller, &policy_id)?;
        let key = DataKey::AssetBlacklist(policy_id.clone(), asset.clone());
        if env.storage().persistent().has(&key) {
            return Err(Error::AlreadyExists);
        }
        env.storage().persistent().set(&key, &());
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("ablk_add")),
            (policy_id, asset),
        );
        Ok(())
    }

    /// Remove an asset from a policy's blacklist (owner only).
    pub fn remove_asset_blacklist(
        env: Env,
        caller: Address,
        policy_id: String,
        asset: Address,
    ) -> Result<(), Error> {
        Self::require_policy_owner(&env, &caller, &policy_id)?;
        let key = DataKey::AssetBlacklist(policy_id.clone(), asset.clone());
        if !env.storage().persistent().has(&key) {
            return Err(Error::NotFound);
        }
        env.storage().persistent().remove(&key);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("ablk_rem")),
            (policy_id, asset),
        );
        Ok(())
    }

    /// Whether `asset` is blacklisted under `policy_id`.
    pub fn is_asset_blacklisted(env: Env, policy_id: String, asset: Address) -> bool {
        env.storage()
            .persistent()
            .has(&DataKey::AssetBlacklist(policy_id, asset))
    }

    /// Enable or disable the asset whitelist for a policy (owner only).
    /// When enabled, only assets explicitly added via `add_asset_to_whitelist`
    /// are permitted.
    pub fn set_asset_whitelist_enabled(
        env: Env,
        caller: Address,
        policy_id: String,
        enabled: bool,
    ) -> Result<(), Error> {
        caller.require_auth();
        let policy = Self::load(&env, &policy_id)?;
        if policy.owner != caller {
            return Err(Error::Unauthorized);
        }
        let key = DataKey::AssetWhitelistEnabled(policy_id);
        env.storage().persistent().set(&key, &enabled);
        Ok(())
    }

    /// Check whether an asset is whitelisted for a given policy.
    /// Returns Ok(()) if allowed, or AssetNotAuthorized if the whitelist is
    /// enabled and the asset is not present.
    pub fn validate_asset(env: Env, policy_id: String, asset: Address) -> Result<(), Error> {
        let enabled_key = DataKey::AssetWhitelistEnabled(policy_id.clone());
        let whitelist_enabled: bool = env
            .storage()
            .persistent()
            .get(&enabled_key)
            .unwrap_or(false);
        if !whitelist_enabled {
            return Ok(());
        }
        let key = DataKey::AssetWhitelist(policy_id.clone(), asset.clone());
        if !env.storage().persistent().has(&key) {
            events_policy_violation(&env, &policy_id, "asset_not_whitelisted");
            return Err(Error::AssetNotAuthorized);
        }
        Ok(())
    }

    /// Add an address to the restricted blacklist (owner only).
    pub fn add_blacklist(
        env: Env,
        caller: Address,
        policy_id: String,
        address: Address,
    ) -> Result<(), Error> {
        Self::require_policy_owner(&env, &caller, &policy_id)?;
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
        Self::require_policy_owner(&env, &caller, &policy_id)?;
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

    /// Add a merchant address to the merchant blacklist (owner only).
    pub fn add_merchant_blacklist(
        env: Env,
        caller: Address,
        policy_id: String,
        merchant_address: Address,
    ) -> Result<(), Error> {
        caller.require_auth();
        let policy = Self::load(&env, &policy_id)?;
        if policy.owner != caller {
            return Err(Error::Unauthorized);
        }
        let key = DataKey::MerchantBlacklist(merchant_address.clone());
        if env.storage().persistent().has(&key) {
            return Err(Error::AlreadyExists);
        }
        env.storage().persistent().set(&key, &policy_id);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("merch_add")),
            (policy_id, merchant_address),
        );
        Ok(())
    }

    /// Remove a merchant address from the merchant blacklist (owner only).
    pub fn remove_merchant_blacklist(
        env: Env,
        caller: Address,
        policy_id: String,
        merchant_address: Address,
    ) -> Result<(), Error> {
        caller.require_auth();
        let policy = Self::load(&env, &policy_id)?;
        if policy.owner != caller {
            return Err(Error::Unauthorized);
        }
        let key = DataKey::MerchantBlacklist(merchant_address.clone());
        if !env.storage().persistent().has(&key) {
            return Err(Error::NotFound);
        }
        env.storage().persistent().remove(&key);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("merch_rem")),
            (policy_id, merchant_address),
        );
        Ok(())
    }

    /// Add a spending category to the category blacklist (owner only).
    pub fn add_category_blacklist(
        env: Env,
        caller: Address,
        policy_id: String,
        category: String,
    ) -> Result<(), Error> {
        caller.require_auth();
        let policy = Self::load(&env, &policy_id)?;
        if policy.owner != caller {
            return Err(Error::Unauthorized);
        }
        require_non_empty(&category)?;
        let key = DataKey::CategoryBlacklist(category.clone());
        if env.storage().persistent().has(&key) {
            return Err(Error::AlreadyExists);
        }
        env.storage().persistent().set(&key, &policy_id);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("cat_add")),
            (policy_id, category),
        );
        Ok(())
    }

    /// Remove a spending category from the category blacklist (owner only).
    pub fn remove_category_blacklist(
        env: Env,
        caller: Address,
        policy_id: String,
        category: String,
    ) -> Result<(), Error> {
        caller.require_auth();
        let policy = Self::load(&env, &policy_id)?;
        if policy.owner != caller {
            return Err(Error::Unauthorized);
        }
        let key = DataKey::CategoryBlacklist(category.clone());
        if !env.storage().persistent().has(&key) {
            return Err(Error::NotFound);
        }
        env.storage().persistent().remove(&key);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("cat_rem")),
            (policy_id, category),
        );
        Ok(())
    }

    /// Add a recipient address to the blocklist (owner only). Blocked
    /// addresses are rejected immediately in `check_transfer` before any
    /// other policy gate is evaluated (Issue #32).
    pub fn add_to_blocklist(
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

    /// Remove a recipient address from the blocklist (owner only).
    pub fn remove_from_blocklist(
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

    // --- recipient whitelist ---

    /// Turn recipient whitelist mode on or off for a policy (owner only).
    ///
    /// While enabled, `check_transfer` only permits destinations listed in this
    /// policy's approved directory — an **empty** whitelist therefore denies
    /// every recipient (fail closed by default). Disabling restores the
    /// permissive behaviour without touching the stored entries, so a directory
    /// can be staged before it is enforced.
    pub fn set_recipient_whitelist_enabled(
        env: Env,
        caller: Address,
        policy_id: String,
        enabled: bool,
    ) -> Result<(), Error> {
        Self::require_policy_owner(&env, &caller, &policy_id)?;
        env.storage().persistent().set(
            &DataKey::RecipientWhitelistEnabled(policy_id.clone()),
            &enabled,
        );
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("wl_mode")),
            (policy_id, enabled),
        );
        Ok(())
    }

    /// Add a recipient to the policy's whitelist (owner only).
    ///
    /// Fails with [`Error::AlreadyExists`] when the address is already listed
    /// for this policy, so the directory stays duplicate-free.
    pub fn add_recipient_to_whitelist(
        env: Env,
        caller: Address,
        policy_id: String,
        recipient: Address,
    ) -> Result<(), Error> {
        Self::require_policy_owner(&env, &caller, &policy_id)?;
        let key = DataKey::RecipientWhitelist(policy_id.clone(), recipient.clone());
        if env.storage().persistent().has(&key) {
            return Err(Error::AlreadyExists);
        }
        env.storage().persistent().set(&key, &true);
        // Mirror the entry in the read index so the directory can be listed
        // back (Soroban offers no key enumeration).
        let index_key = DataKey::RecipientWhitelistIndex(policy_id.clone());
        let mut index: soroban_sdk::Vec<Address> = env
            .storage()
            .persistent()
            .get(&index_key)
            .unwrap_or_else(|| soroban_sdk::Vec::new(&env));
        index.push_back(recipient.clone());
        env.storage().persistent().set(&index_key, &index);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("wl_add")),
            (policy_id, recipient),
        );
        Ok(())
    }

    /// Remove a recipient from the policy's whitelist (owner only).
    ///
    /// Fails with [`Error::NotFound`] when the address was never listed (or
    /// was already removed), so a stale governance transaction cannot silently
    /// no-op. Dropping the last entry also drops the index key.
    pub fn remove_recipient_from_whitelist(
        env: Env,
        caller: Address,
        policy_id: String,
        recipient: Address,
    ) -> Result<(), Error> {
        Self::require_policy_owner(&env, &caller, &policy_id)?;
        let key = DataKey::RecipientWhitelist(policy_id.clone(), recipient.clone());
        if !env.storage().persistent().has(&key) {
            return Err(Error::NotFound);
        }
        env.storage().persistent().remove(&key);
        let index_key = DataKey::RecipientWhitelistIndex(policy_id.clone());
        let mut index: soroban_sdk::Vec<Address> = env
            .storage()
            .persistent()
            .get(&index_key)
            .unwrap_or_else(|| soroban_sdk::Vec::new(&env));
        if let Some(pos) = index.iter().position(|a| a == recipient) {
            // `position` reports a `usize`; convert without panicking so a
            // malformed index surfaces as an error rather than an abort.
            index.remove(u32::try_from(pos).map_err(|_| Error::InvalidInput)?);
        }
        if index.is_empty() {
            env.storage().persistent().remove(&index_key);
        } else {
            env.storage().persistent().set(&index_key, &index);
        }
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("wl_rem")),
            (policy_id, recipient),
        );
        Ok(())
    }

    /// Whether `recipient` is on `policy_id`'s approved destination directory.
    ///
    /// A pure membership probe: it reports the stored state regardless of
    /// whether whitelist mode is currently enforced, so callers can diff the
    /// directory against an off-chain list.
    pub fn is_recipient_whitelisted(env: Env, policy_id: String, recipient: Address) -> bool {
        env.storage()
            .persistent()
            .has(&DataKey::RecipientWhitelist(policy_id, recipient))
    }

    /// Read back every recipient whitelisted for `policy_id`, in insertion
    /// order. Returns an empty vector when the directory has no entries.
    pub fn get_recipient_whitelist(env: Env, policy_id: String) -> soroban_sdk::Vec<Address> {
        env.storage()
            .persistent()
            .get(&DataKey::RecipientWhitelistIndex(policy_id))
            .unwrap_or_else(|| soroban_sdk::Vec::new(&env))
    }

    /// Evaluate `payload` against the policy's active recipient whitelist.
    ///
    /// This is the whitelist's evaluation entry point: it is called by
    /// `check_transfer` for every proposed transfer and can also be invoked
    /// directly to dry-run a destination. Returns `Ok(())` when whitelist mode
    /// is off (gate not enforced) or when `payload.recipient` is listed, and
    /// [`Error::PolicyDenied`] — with a `not_whitelisted` violation event —
    /// when an untrusted destination is targeted while the mode is active.
    ///
    /// The policy itself is resolved by the caller (`check_transfer` loads it
    /// before any gate runs), so an unknown policy never reaches this probe.
    pub fn evaluate_recipient_whitelist(
        env: Env,
        policy_id: String,
        payload: TransactionPayload,
    ) -> Result<(), Error> {
        let enabled: bool = env
            .storage()
            .persistent()
            .get(&DataKey::RecipientWhitelistEnabled(policy_id.clone()))
            .unwrap_or(false);
        if !enabled {
            return Ok(());
        }
        if !env.storage().persistent().has(&DataKey::RecipientWhitelist(
            policy_id.clone(),
            payload.recipient,
        )) {
            events_policy_violation(&env, &policy_id, "not_whitelisted");
            return Err(Error::PolicyDenied);
        }
        Ok(())
    }

    /// Short alias of [`PolicyContract::set_recipient_whitelist_enabled`].
    pub fn set_whitelist_enabled(
        env: Env,
        caller: Address,
        policy_id: String,
        enabled: bool,
    ) -> Result<(), Error> {
        Self::set_recipient_whitelist_enabled(env, caller, policy_id, enabled)
    }

    /// Short alias of [`PolicyContract::add_recipient_to_whitelist`].
    pub fn add_whitelist(
        env: Env,
        caller: Address,
        policy_id: String,
        recipient: Address,
    ) -> Result<(), Error> {
        Self::add_recipient_to_whitelist(env, caller, policy_id, recipient)
    }

    /// Short alias of [`PolicyContract::remove_recipient_from_whitelist`].
    pub fn remove_whitelist(
        env: Env,
        caller: Address,
        policy_id: String,
        recipient: Address,
    ) -> Result<(), Error> {
        Self::remove_recipient_from_whitelist(env, caller, policy_id, recipient)
    }

    /// Check if a spending category is restricted. Returns Ok(()) if the category
    /// is allowed, or PolicyCategoryRestricted if it's blacklisted.
    pub fn check_category(env: Env, policy_id: String, category: String) -> Result<(), Error> {
        // Empty category is always allowed
        if category.is_empty() {
            return Ok(());
        }

        if env
            .storage()
            .persistent()
            .has(&DataKey::CategoryBlacklist(category.clone()))
        {
            events_policy_violation(&env, &policy_id, "category_restricted");
            return Err(Error::PolicyCategoryRestricted);
        }
        Ok(())
    }

    // --- multi-token allowances ---

    /// Create or update the spending allowance for `(policy_id, asset)`.
    /// `owner` only. Rejects a negative limit. `expires_at == 0` means never.
    pub fn set_allowance(
        env: Env,
        caller: Address,
        policy_id: String,
        asset: Address,
        limit: i128,
        expires_at: u64,
    ) -> Result<(), Error> {
        caller.require_auth();
        let policy = Self::load(&env, &policy_id)?;
        if policy.owner != caller {
            return Err(Error::Unauthorized);
        }
        require_non_negative_amount(limit)?;
        // Updating an allowance keeps existing spend so limits are enforced
        // cumulatively across updates.
        let mut allowance = Self::get_allowance(env.clone(), policy_id.clone(), asset.clone());
        allowance.limit = limit;
        allowance.expires_at = expires_at;
        allowance.policy_id = policy_id.clone();
        allowance.asset = asset.clone();
        env.storage().persistent().set(
            &DataKey::Allowance(policy_id.clone(), asset.clone()),
            &allowance,
        );
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("allow_set")),
            (policy_id, asset, limit),
        );
        Ok(())
    }

    /// Remove the spending allowance for `(policy_id, asset)`. `owner` only.
    pub fn remove_allowance(
        env: Env,
        caller: Address,
        policy_id: String,
        asset: Address,
    ) -> Result<(), Error> {
        caller.require_auth();
        let policy = Self::load(&env, &policy_id)?;
        if policy.owner != caller {
            return Err(Error::Unauthorized);
        }
        let key = DataKey::Allowance(policy_id.clone(), asset.clone());
        if !env.storage().persistent().has(&key) {
            return Err(Error::NotFound);
        }
        env.storage().persistent().remove(&key);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("allow_rem")),
            (policy_id, asset),
        );
        Ok(())
    }

    /// Read the current allowance for `(policy_id, asset)`. Returns the stored
    /// record, or a zeroed record when none has been configured (so callers can
    /// treat an unset allowance as "unrestricted").
    pub fn get_allowance(env: Env, policy_id: String, asset: Address) -> AssetAllowance {
        env.storage()
            .persistent()
            .get(&DataKey::Allowance(policy_id.clone(), asset.clone()))
            .unwrap_or(AssetAllowance {
                policy_id,
                asset,
                limit: 0,
                spent: 0,
                expires_at: 0,
            })
    }

    /// Check whether spending `amount` of `asset` under `policy_id` is within
    /// the configured allowance. Returns the remaining headroom after the spend
    /// (0 = the allowance would be fully consumed, which is permitted). An
    /// unset allowance is unrestricted. Returns
    /// [`Error::AllowanceExceeded`] when the spend would breach the
    /// allowance.
    pub fn check_allowance(
        env: Env,
        policy_id: String,
        asset: Address,
        amount: i128,
    ) -> Result<i128, Error> {
        require_non_negative_amount(amount)?;
        let allowance = Self::get_allowance(env.clone(), policy_id.clone(), asset.clone());
        // No configured allowance => unrestricted for this asset.
        if allowance.limit == 0 {
            return Ok(i128::MAX);
        }
        if allowance.expires_at != 0 && env.ledger().timestamp() >= allowance.expires_at {
            events_policy_violation(&env, &policy_id, "allowance_expired");
            // A lapsed envelope is not a rule denial: the operator's remedy is
            // to renew it, not to loosen the policy. `Error::AllowanceExpired`
            // keeps that distinct from `PolicyDenied` and from
            // `PolicyAllowanceExceeded`.
            return Err(Error::AllowanceExpired);
        }
        let headroom_after_spend = checked_sub(allowance.limit, allowance.spent)?;
        if amount > headroom_after_spend {
            events_policy_violation(&env, &policy_id, "allowance_exceeded");
            return Err(Error::AllowanceExceeded);
        }
        checked_sub(headroom_after_spend, amount)
    }

    /// Atomically consume `amount` against the `(policy_id, asset)` allowance.
    /// Returns `Ok(())` when the allowance was decremented, or
    /// [`Error::AllowanceExceeded`] when it would be breached.
    pub fn update_allowance(
        env: Env,
        caller: Address,
        policy_id: String,
        asset: Address,
        amount: i128,
    ) -> Result<(), Error> {
        caller.require_auth();
        require_non_negative_amount(amount)?;
        let mut allowance = Self::get_allowance(env.clone(), policy_id.clone(), asset.clone());
        // No configured allowance => nothing to enforce.
        if allowance.limit == 0 {
            return Ok(());
        }
        if allowance.expires_at != 0 && env.ledger().timestamp() >= allowance.expires_at {
            return Err(Error::AllowanceExpired);
        }
        let headroom_after_spend = checked_sub(allowance.limit, allowance.spent)?;
        if amount > headroom_after_spend {
            return Err(Error::AllowanceExceeded);
        }
        allowance.spent = checked_add(allowance.spent, amount)?;
        env.storage().persistent().set(
            &DataKey::Allowance(policy_id.clone(), asset.clone()),
            &allowance,
        );
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("allow_use")),
            (policy_id, asset, amount, allowance.spent),
        );
        Ok(())
    }

    // --- composite rules ---

    /// Register or replace the composite rule tree for a policy.
    ///
    /// The rule tree is evaluated during `check_transfer` **after** all the
    /// standard scalar gates (blocklist, max amount, recipient, asset, etc.)
    /// have passed. If the rule tree evaluates to `false`, the transfer is
    /// denied with [`Error::PolicyDenied`].
    ///
    /// `owner` only. The tree must contain at least one node with the root at
    /// index 0.
    pub fn set_composite_rule(
        env: Env,
        caller: Address,
        policy_id: String,
        rule_tree: RuleTree,
    ) -> Result<(), Error> {
        caller.require_auth();
        let policy = Self::load(&env, &policy_id)?;
        if policy.owner != caller {
            return Err(Error::Unauthorized);
        }
        if rule_tree.is_empty() {
            return Err(Error::InvalidInput);
        }
        let key = DataKey::CompositeRule(policy_id.clone());
        env.storage().persistent().set(&key, &rule_tree);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("rule_set")),
            policy_id,
        );
        Ok(())
    }

    /// Remove the composite rule tree for a policy (owner only).
    pub fn clear_composite_rule(env: Env, caller: Address, policy_id: String) -> Result<(), Error> {
        caller.require_auth();
        let policy = Self::load(&env, &policy_id)?;
        if policy.owner != caller {
            return Err(Error::Unauthorized);
        }
        let key = DataKey::CompositeRule(policy_id.clone());
        if !env.storage().persistent().has(&key) {
            return Err(Error::NotFound);
        }
        env.storage().persistent().remove(&key);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("rule_clr")),
            policy_id,
        );
        Ok(())
    }

    /// Read the composite rule tree for a policy, if one is set.
    pub fn get_composite_rule(env: Env, policy_id: String) -> Result<RuleTree, Error> {
        let key = DataKey::CompositeRule(policy_id.clone());
        env.storage().persistent().get(&key).ok_or(Error::NotFound)
    }

    /// Evaluate a composite rule tree against a transaction payload.
    ///
    /// Returns `Ok(true)` when the rule permits the transaction, or
    /// `Err(Error::PolicyDenied)` when it denies it. If no composite rule
    /// is registered for the policy the function returns `Ok(true)` (permissive
    /// default — standard scalar gates still apply).
    pub fn evaluate_composite_rule(
        env: Env,
        policy_id: String,
        payload: TransactionPayload,
    ) -> Result<bool, Error> {
        let mut context = RuleEvaluationContext::default();
        Self::evaluate_composite_rule_with_context(&env, &policy_id, &payload, &mut context)
    }

    fn evaluate_composite_rule_with_context(
        env: &Env,
        policy_id: &String,
        payload: &TransactionPayload,
        context: &mut RuleEvaluationContext,
    ) -> Result<bool, Error> {
        let key = DataKey::CompositeRule(policy_id.clone());
        let tree: RuleTree = match env.storage().persistent().get(&key) {
            Some(t) => t,
            None => return Ok(true),
        };
        if tree.is_empty() {
            return Ok(true);
        }
        evaluate_node(env, &tree, 0, payload, MAX_RULE_DEPTH, context)
    }

    // --- multi-rule composition ---

    /// Register an additional rule tree on the policy's rule stack.
    ///
    /// Every rule on the stack is evaluated during `check_transfer` and **all**
    /// of them must pass: the first rule that evaluates to `false`
    /// short-circuits the evaluation and the transfer is denied with
    /// [`Error::PolicyDenied`]. This is how a policy composes independent
    /// governance constraints — e.g. an allow-listed recipient *plus* a maximum
    /// amount — without folding them into a single hand-built tree.
    ///
    /// `owner` only. The tree must be non-empty and structurally sound (see
    /// [`validate_rule_tree`]) so a malformed rule is rejected at write time
    /// rather than aborting evaluation later. Returns the number of rules now
    /// registered for the policy and fails with [`Error::InvalidInput`] once
    /// [`MAX_POLICY_RULES`] rules are stacked.
    pub fn add_policy_rule(
        env: Env,
        caller: Address,
        policy_id: String,
        rule_tree: RuleTree,
    ) -> Result<u32, Error> {
        Self::require_policy_owner(&env, &caller, &policy_id)?;
        validate_rule_tree(&rule_tree)?;
        let key = DataKey::PolicyRules(policy_id.clone());
        let mut stack: RuleStack = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or_else(|| soroban_sdk::Vec::new(&env));
        if stack.len() >= MAX_POLICY_RULES {
            return Err(Error::InvalidInput);
        }
        stack.push_back(rule_tree);
        let count = stack.len();
        env.storage().persistent().set(&key, &stack);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("rule_add")),
            (policy_id, count),
        );
        Ok(count)
    }

    /// Remove the rule at `index` from the policy's rule stack (owner only).
    ///
    /// The index is bounds-checked against the current stack length, so an
    /// out-of-range removal fails with [`Error::InvalidInput`] instead of
    /// panicking. Removing the last rule drops the storage key entirely.
    pub fn remove_policy_rule(
        env: Env,
        caller: Address,
        policy_id: String,
        index: u32,
    ) -> Result<(), Error> {
        Self::require_policy_owner(&env, &caller, &policy_id)?;
        let key = DataKey::PolicyRules(policy_id.clone());
        let mut stack: RuleStack = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(Error::NotFound)?;
        if index >= stack.len() {
            return Err(Error::InvalidInput);
        }
        stack.remove(index);
        if stack.is_empty() {
            env.storage().persistent().remove(&key);
        } else {
            env.storage().persistent().set(&key, &stack);
        }
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("rule_rem")),
            (policy_id, index),
        );
        Ok(())
    }

    /// Drop every registered rule for a policy (owner only).
    pub fn clear_policy_rules(env: Env, caller: Address, policy_id: String) -> Result<(), Error> {
        Self::require_policy_owner(&env, &caller, &policy_id)?;
        let key = DataKey::PolicyRules(policy_id.clone());
        if !env.storage().persistent().has(&key) {
            return Err(Error::NotFound);
        }
        env.storage().persistent().remove(&key);
        env.events().publish(
            (symbol_short!("policy"), symbol_short!("rules_clr")),
            policy_id,
        );
        Ok(())
    }

    /// Read the whole rule stack for a policy. Returns an empty stack when no
    /// rule has been registered yet (permissive default).
    pub fn get_policy_rules(env: Env, policy_id: String) -> RuleStack {
        env.storage()
            .persistent()
            .get(&DataKey::PolicyRules(policy_id))
            .unwrap_or_else(|| soroban_sdk::Vec::new(&env))
    }

    /// Evaluate every registered rule against `payload`.
    ///
    /// Rules are combined conjunctively and walked in stack order; the loop
    /// returns `Ok(false)` — "denied" — as soon as one rule fails, so later
    /// rules are never paid for. An empty stack is permissive. Malformed trees
    /// surface as [`Error::InvalidInput`] (defensive: registration already
    /// validates the shape).
    pub fn evaluate_policy_rules(
        env: Env,
        policy_id: String,
        payload: TransactionPayload,
    ) -> Result<bool, Error> {
        let mut context = RuleEvaluationContext::default();
        Self::evaluate_policy_rules_with_context(&env, &policy_id, &payload, &mut context)
    }

    fn evaluate_policy_rules_with_context(
        env: &Env,
        policy_id: &String,
        payload: &TransactionPayload,
        context: &mut RuleEvaluationContext,
    ) -> Result<bool, Error> {
        let stack: RuleStack = env
            .storage()
            .persistent()
            .get(&DataKey::PolicyRules(policy_id.clone()))
            .unwrap_or_else(|| soroban_sdk::Vec::new(env));
        let count = stack.len();
        for i in 0..count {
            // `get` bounds-checks the index; a miss means the stack changed
            // under us, which storage cannot do mid-invocation — fail closed.
            let tree = stack.get(i).ok_or(Error::InvalidInput)?;
            if tree.is_empty() {
                continue;
            }
            if !evaluate_node(env, &tree, 0, payload, MAX_RULE_DEPTH, context)? {
                return Ok(false);
            }
        }
        Ok(true)
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

    /// Authenticate `caller` and require it to own `policy_id`.
    fn require_policy_owner(env: &Env, caller: &Address, policy_id: &String) -> Result<(), Error> {
        caller.require_auth();
        if Self::load(env, policy_id)?.owner != *caller {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
}

/// Allow the interface trait to call `check_transfer` on this contract.
#[contractimpl]
impl PolicyInterface for PolicyContract {
    /// Evaluate a transfer request against the named policy. All gates must pass.
    ///
    /// Blocklist checks run **first** so that compromised or malicious
    /// addresses are rejected immediately, before any allowance, asset or
    /// amount evaluation (Issue #32). The recipient whitelist gate follows in
    /// the same family: while a policy enforces its approved destination
    /// directory, an untrusted recipient is denied with
    /// [`Error::PolicyDenied`].
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
        // --- Blocklist checks (Issue #32) — evaluated first ---
        let recipient_blacklisted = env
            .storage()
            .persistent()
            .has(&DataKey::Blacklist(recipient.clone()));
        if recipient_blacklisted {
            events_policy_violation(&env, &policy_id, "blacklisted");
            return Err(Error::PolicyRecipientRestricted);
        }
        let merchant_blacklisted = env
            .storage()
            .persistent()
            .has(&DataKey::MerchantBlacklist(recipient.clone()));
        if merchant_blacklisted {
            events_policy_violation(&env, &policy_id, "merchant_blocked");
            return Err(Error::PolicyMerchantBlocked);
        }
        // --- Recipient whitelist: approved destinations only (Issue #63) ---
        // Runs with the other recipient gates and fails closed: an enabled
        // whitelist with no entries denies every destination.
        let payload = TransactionPayload {
            asset: asset.clone(),
            recipient: recipient.clone(),
            amount,
        };
        Self::evaluate_recipient_whitelist(env.clone(), policy_id.clone(), payload.clone())?;
        // --- Allowance / amount gates ---
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
        // The asset deny list wins over every allow gate, so blacklisting an
        // allow-listed or whitelisted asset takes effect immediately.
        if env
            .storage()
            .persistent()
            .has(&DataKey::AssetBlacklist(policy_id.clone(), asset.clone()))
        {
            events_policy_violation(&env, &policy_id, "asset_blacklisted");
            return Err(Error::PolicyDenied);
        }
        // Check asset whitelist (Issue #37)
        Self::validate_asset(env.clone(), policy_id.clone(), asset.clone())?;
        // Multi-token allowance gate: reject a spend that would breach the
        // per-(policy, asset) allowance. An unset allowance is unrestricted.
        Self::check_allowance(env.clone(), policy_id.clone(), asset.clone(), amount)?;
        // --- Composite rule evaluation ---
        // The blocklist results computed above seed the evaluation context so
        // `RecipientBlacklisted` / `MerchantBlacklisted` leaves reuse them
        // instead of re-reading storage on every node.
        let mut rule_context = RuleEvaluationContext {
            recipient_blacklisted: Some(recipient_blacklisted),
            merchant_blacklisted: Some(merchant_blacklisted),
        };
        let rule_result = Self::evaluate_composite_rule_with_context(
            &env,
            &policy_id,
            &payload,
            &mut rule_context,
        )?;
        if !rule_result {
            events_policy_violation(&env, &policy_id, "rule_denied");
            return Err(Error::PolicyDenied);
        }
        // --- Multi-rule stack: every registered rule must pass ---
        // The stack short-circuits on the first failing rule, so evaluation
        // stops (and the transfer is denied) as soon as one rule says no.
        if !Self::evaluate_policy_rules_with_context(&env, &policy_id, &payload, &mut rule_context)?
        {
            events_policy_violation(&env, &policy_id, "rules_denied");
            return Err(Error::PolicyDenied);
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

// ---------------------------------------------------------------------------
// Registry-gated upgrades, exposed through the shared `UpgradeableInterface`.
// ---------------------------------------------------------------------------
#[contractimpl]
impl UpgradeableInterface for PolicyContract {
    /// Record (or rotate) who may upgrade this contract and which registry
    /// authorizes the new code. Bootstrapped by the deployer alongside
    /// `initialize`; afterwards only the current upgrade admin may rotate it.
    fn set_upgrade_authority(
        env: Env,
        caller: Address,
        admin: Address,
        registry: Address,
    ) -> Result<(), Error> {
        astroid_interfaces::upgrade::set_authority(&env, &caller, &admin, &registry)
    }

    /// Read the recorded upgrade authority.
    fn get_upgrade_authority(
        env: Env,
    ) -> Result<astroid_interfaces::upgrade::UpgradeAuthority, Error> {
        astroid_interfaces::upgrade::get_authority(&env)
    }

    /// Replace this contract's code with `wasm_hash`.
    ///
    /// Two gates must pass: `caller` must be the recorded upgrade admin, and
    /// `wasm_hash` must be approved for `ModuleKind::Policy` in the registry.
    /// Any other outcome leaves the contract running its current code.
    fn upgrade(env: Env, caller: Address, wasm_hash: soroban_sdk::BytesN<32>) -> Result<(), Error> {
        astroid_interfaces::upgrade::perform(
            &env,
            &caller,
            astroid_shared::types::ModuleKind::Policy,
            wasm_hash,
        )
    }
}

#[cfg(test)]
mod test;
