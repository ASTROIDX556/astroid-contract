import re
with open("contracts/policy/src/lib.rs", "r") as f:
    text = f.read()

# Add max_fee to Policy
text = text.replace("    pub max_amount: i128,", "    pub max_amount: i128,\n    /// Maximum acceptable transaction fee.\n    pub max_fee: i128,")

# Update register_policy
text = text.replace("""        max_amount: i128,
        allowed_recipient: Option<Address>,""", """        max_amount: i128,
        max_fee: i128,
        allowed_recipient: Option<Address>,""")

text = text.replace("""        let policy = Policy {
            owner,
            config_hash,
            max_amount,
            allowed_recipient,""", """        let policy = Policy {
            owner,
            config_hash,
            max_amount,
            max_fee,
            allowed_recipient,""")

# Update rotate_policy
text = text.replace("""        new_hash: BytesN<32>,
        new_max: i128,
    ) -> Result<(), Error> {""", """        new_hash: BytesN<32>,
        new_max: i128,
        new_max_fee: i128,
    ) -> Result<(), Error> {""")
text = text.replace("policy.max_amount = new_max;", "policy.max_amount = new_max;\n        policy.max_fee = new_max_fee;")

# Add evaluate_policy method to PolicyContract
evaluate_policy = """    pub fn evaluate_policy(
        env: Env,
        policy_id: String,
        tx_fee: i128,
    ) -> Result<(), Error> {
        let policy = Self::load(&env, &policy_id)?;
        if !policy.enabled {
            events_policy_violation(&env, &policy_id, "disabled");
            return Err(Error::PolicyDenied);
        }
        if policy.max_fee != 0 && tx_fee > policy.max_fee {
            events_policy_violation(&env, &policy_id, "fee_high");
            return Err(Error::FeeLimitExceeded);
        }
        Ok(())
    }

    // --- views ---"""
text = text.replace("    // --- views ---", evaluate_policy)

with open("contracts/policy/src/lib.rs", "w") as f:
    f.write(text)
