import re
with open("contracts/policy/src/lib.rs", "r") as f:
    c = f.read()

# 1. Add to DataKey
c = c.replace("""    Policy(String),
    Count,
    Blacklist(Address),
}""", """    Policy(String),
    Count,
    Blacklist(Address),
    MerchantBlacklist(Address),
    CategoryBlacklist(String),
}""")

# 2. Add the blacklist functions right before `impl PolicyInterface for PolicyContract {`
functions = """
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
}
"""
c = c.replace("}\n\nimpl PolicyInterface for PolicyContract {", functions + "\nimpl PolicyInterface for PolicyContract {")

# 3. Add merchant block in validate_spend
block = """        // Check merchant blacklist
        if env
            .storage()
            .persistent()
            .has(&DataKey::MerchantBlacklist(recipient.clone()))
        {
            events_policy_violation(&env, &policy_id, "merchant_blocked");
            return Err(Error::PolicyMerchantBlocked);
        }
        Ok(())
    }
}"""
c = c.replace("        Ok(())\n    }\n}", block)

with open("contracts/policy/src/lib.rs", "w") as f:
    f.write(c)

