//! Conditional policy rule types and evaluation engine.
//!
//! Rules layer on top of the scalar gates defined in [`super::Policy`] to
//! provide configurable, per-policy allow/deny logic for destination addresses
//! and asset identifiers.
//!
//! # Evaluation semantics
//!
//! Rules are evaluated in insertion order using a **first-match-wins**
//! strategy:
//!
//! 1. The first rule whose [`PolicyRule::matches`] returns `true` determines
//!    the outcome — [`RuleMatch::Allow`] permits the transfer,
//!    [`RuleMatch::Deny`] rejects it with [`Error::RuleDenied`].
//! 2. If *no* rule matches the transfer is **allowed** (backward-compatible
//!    with policies that have no conditional rules).
//!
//! # Wildcard destination matching
//!
//! When [`RuleTarget::Destination`] is used with a value ending in `*`, the
//! rule matches any address whose string representation starts with the prefix
//! before the `*`. For example `GABC*` matches `GABCDEF...` but not `GXYZ...`.
//! An exact-match destination rule (no `*`) compares the full address string.

use soroban_sdk::{contracttype, Address, Env, String};

use astroid_shared::errors::Error;

/// Maximum number of conditional rules a single policy may carry.
/// Keeps evaluation bounded and prevents unbounded storage growth.
pub const MAX_POLICY_RULES: u32 = 16;

/// Maximum byte length for pattern / candidate buffers used in wildcard
/// matching.  Stellar base32 addresses are 56 bytes; 128 leaves ample room.
const MAX_MATCH_LEN: usize = 128;

/// Whether a matching rule allows or denies the transaction.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleMatch {
    Allow = 0,
    Deny = 1,
}

/// Which transaction field a rule inspects.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuleTarget {
    /// Match against the transfer recipient address.
    Destination = 0,
    /// Match against the asset / token contract address.
    Asset = 1,
}

/// A single conditional rule attached to a policy.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyRule {
    /// Caller-supplied identifier (must be unique within a policy).
    pub id: String,
    /// Outcome when this rule matches.
    pub rule_match: RuleMatch,
    /// Which transaction field to inspect.
    pub target: RuleTarget,
    /// The value to match against. For [`RuleTarget::Destination`] a trailing
    /// `*` enables prefix / wildcard matching; for [`RuleTarget::Asset`] the
    /// full address must match exactly.
    pub value: String,
}

impl PolicyRule {
    /// Returns `true` when `self` applies to the given `(recipient, asset)`.
    pub fn matches(&self, env: &Env, recipient: &Address, asset: &Address) -> bool {
        let candidate = match self.target {
            RuleTarget::Destination => recipient.to_string(),
            RuleTarget::Asset => asset.to_string(),
        };
        matches_value(env, &self.value, &candidate)
    }
}

// ── Storage helpers ────────────────────────────────────────────────────

#[contracttype]
#[derive(Clone)]
pub(crate) enum RuleDataKey {
    Rules(String),
}

/// Load the rule vector for `policy_id`. Returns an empty vector when no rules
/// have been registered yet.
pub fn load_rules(env: &Env, policy_id: &String) -> soroban_sdk::Vec<PolicyRule> {
    env.storage()
        .persistent()
        .get(&RuleDataKey::Rules(policy_id.clone()))
        .unwrap_or_else(|| soroban_sdk::Vec::new(env))
}

fn store_rules(env: &Env, policy_id: &String, rules: &soroban_sdk::Vec<PolicyRule>) {
    env.storage()
        .persistent()
        .set(&RuleDataKey::Rules(policy_id.clone()), rules);
}

/// Append a rule to a policy. Returns [`Error::InvalidInput`] when the rule
/// limit would be exceeded, or [`Error::AlreadyExists`] when a rule with the
/// same id is already present.
pub fn add_rule(env: &Env, policy_id: &String, rule: PolicyRule) -> Result<(), Error> {
    let mut rules = load_rules(env, policy_id);
    if rules.len() >= MAX_POLICY_RULES {
        return Err(Error::InvalidInput);
    }
    for r in rules.iter() {
        if r.id == rule.id {
            return Err(Error::AlreadyExists);
        }
    }
    rules.push_back(rule);
    store_rules(env, policy_id, &rules);
    Ok(())
}

/// Remove a rule by id. Returns [`Error::NotFound`] when no such rule exists.
pub fn remove_rule(env: &Env, policy_id: &String, rule_id: &String) -> Result<(), Error> {
    let mut rules = load_rules(env, policy_id);
    for i in 0..rules.len() {
        if rules.get_unchecked(i).id == *rule_id {
            rules.remove(i);
            store_rules(env, policy_id, &rules);
            return Ok(());
        }
    }
    Err(Error::NotFound)
}

// ── Evaluation ─────────────────────────────────────────────────────────

/// Evaluate all conditional rules for `policy_id` against a transfer request.
///
/// * **First-match-wins:** the first rule whose [`PolicyRule::matches`] returns
///   `true` determines the result.
/// * An [`RuleMatch::Deny`] match returns [`Error::RuleDenied`].
/// * An [`RuleMatch::Allow`] match returns `Ok(())`.
/// * If no rule matches the transfer is **allowed** (backward-compatible
///   default — policies without conditional rules behave identically to
///   their pre-feature behaviour).
pub fn evaluate_rules(
    env: &Env,
    policy_id: &String,
    recipient: &Address,
    asset: &Address,
) -> Result<(), Error> {
    let rules = load_rules(env, policy_id);
    for rule in rules.iter() {
        if rule.matches(env, recipient, asset) {
            return match rule.rule_match {
                RuleMatch::Deny => Err(Error::RuleDenied),
                RuleMatch::Allow => Ok(()),
            };
        }
    }
    Ok(())
}

// ── Matching helpers ───────────────────────────────────────────────────

/// Core matching logic. If `pattern` ends with `*` a prefix match is
/// performed; otherwise the candidate must equal the pattern exactly.
fn matches_value(_env: &Env, pattern: &String, candidate: &String) -> bool {
    let p_len = pattern.len() as usize;
    let c_len = candidate.len() as usize;
    if p_len == 0 {
        return false;
    }

    let mut p_buf = [0u8; MAX_MATCH_LEN];
    let mut c_buf = [0u8; MAX_MATCH_LEN];
    let p_copy_len = p_len.min(MAX_MATCH_LEN);
    let c_copy_len = c_len.min(MAX_MATCH_LEN);
    pattern.copy_into_slice(&mut p_buf[..p_copy_len]);
    candidate.copy_into_slice(&mut c_buf[..c_copy_len]);

    if p_buf[p_copy_len - 1] == b'*' {
        // Wildcard: compare prefix bytes.
        let prefix_len = p_copy_len - 1;
        if prefix_len == 0 {
            // Pattern is just "*" — matches nothing.
            return false;
        }
        if c_len < prefix_len {
            return false;
        }
        p_buf[..prefix_len] == c_buf[..prefix_len]
    } else {
        // Exact: byte-level equality.
        p_len == c_len && p_buf[..p_copy_len] == c_buf[..c_copy_len]
    }
}
