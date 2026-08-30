import re
with open("contracts/policy/src/lib.rs", "r") as f:
    text = f.read()

replacement = """        // --- Blocklist checks (Issue #32) — evaluated first ---
        if env
            .storage()
            .persistent()
            .has(&DataKey::Blacklist(recipient.clone()))
        {
            events_policy_violation(&env, &policy_id, "blacklisted");
            return Err(Error::PolicyRecipientRestricted);
        }
        if env
            .storage()
            .persistent()
            .has(&DataKey::MerchantBlacklist(recipient.clone()))
        {
            events_policy_violation(&env, &policy_id, "merchant_blocked");
            return Err(Error::PolicyMerchantBlocked);
        }

        let now = env.ledger().timestamp();
        // --- Allowance / amount gates ---
        if policy.expires_at != 0 && now >= policy.expires_at {"""

text = re.sub(
    r"<<<<<<< HEAD\n([\s\S]*?)=======\n([\s\S]*?)>>>>>>> origin/main",
    replacement,
    text
)
with open("contracts/policy/src/lib.rs", "w") as f:
    f.write(text)

