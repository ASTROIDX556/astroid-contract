import re
with open("contracts/treasury/src/lib.rs", "r") as f:
    text = f.read()

# Add ReentrancyLock to DataKey
text = text.replace("    Holding(Address),", "    Holding(Address),\n    ReentrancyLock,")

# Add reentrancy lock helper
lock_helpers = """    fn lock(env: &Env) -> Result<(), Error> {
        let is_locked: bool = env.storage().instance().get(&DataKey::ReentrancyLock).unwrap_or(false);
        if is_locked {
            return Err(Error::InvalidAction); // Or reentrancy error
        }
        env.storage().instance().set(&DataKey::ReentrancyLock, &true);
        Ok(())
    }

    fn unlock(env: &Env) {
        env.storage().instance().set(&DataKey::ReentrancyLock, &false);
    }

    fn load_holding"""
text = text.replace("    fn load_holding", lock_helpers)

# Fix deposit
deposit_old = """        // Pull tokens into the contract's own custody.
        token::TokenClient::new(&env, &asset).transfer(
            &from,
            &env.current_contract_address(),
            &amount,
        );
        let mut h = Self::load_holding(&env, &asset);
        h.total_in = checked_add(h.total_in, amount)?;
        Self::store_holding(&env, &asset, &h);
        env.events().publish(
            (symbol_short!("treasury"), symbol_short!("deposited")),
            (asset, amount),
        );
        Ok(())"""
deposit_new = """        Self::lock(&env)?;
        let mut h = Self::load_holding(&env, &asset);
        h.total_in = checked_add(h.total_in, amount)?;
        Self::store_holding(&env, &asset, &h);
        env.events().publish(
            (symbol_short!("treasury"), symbol_short!("deposited")),
            (asset.clone(), amount),
        );
        // Pull tokens into the contract's own custody.
        token::TokenClient::new(&env, &asset).transfer(
            &from,
            &env.current_contract_address(),
            &amount,
        );
        Self::unlock(&env);
        Ok(())"""
text = text.replace(deposit_old, deposit_new)

# Fix withdraw
withdraw_old = """        // 3. Debit the internal ledger, then move real tokens out of custody.
        if holding.total_in < amount {
            return Err(Error::InsufficientFunds);
        }
        holding.total_in = checked_sub(holding.total_in, amount)?;
        holding.total_out = checked_add(holding.total_out, amount)?;
        Self::store_holding(&env, &asset, &holding);
        token::TokenClient::new(&env, &asset).transfer(
            &env.current_contract_address(),
            &to,
            &amount,
        );
        events::transfer_executed(&env, &t.admin, &to, &asset, amount);
        Ok(())"""
withdraw_new = """        // 3. Debit the internal ledger, then move real tokens out of custody.
        Self::lock(&env)?;
        if holding.total_in < amount {
            Self::unlock(&env);
            return Err(Error::InsufficientFunds);
        }
        holding.total_in = checked_sub(holding.total_in, amount)?;
        holding.total_out = checked_add(holding.total_out, amount)?;
        Self::store_holding(&env, &asset, &holding);
        events::transfer_executed(&env, &t.admin, &to, &asset, amount);
        token::TokenClient::new(&env, &asset).transfer(
            &env.current_contract_address(),
            &to,
            &amount,
        );
        Self::unlock(&env);
        Ok(())"""
text = text.replace(withdraw_old, withdraw_new)

with open("contracts/treasury/src/lib.rs", "w") as f:
    f.write(text)
