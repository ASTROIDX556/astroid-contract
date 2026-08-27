import re

with open("contracts/treasury/src/lib.rs", "r") as f:
    text = f.read()

# Add MilestoneDisbursement struct
milestone_struct = """
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MilestoneDisbursement {
    pub total_amount: i128,
    pub milestones: u32,
    pub disbursed: u32,
    pub amount_per_milestone: i128,
    pub asset: Address,
    pub to: Address,
}
"""

text = text.replace("#[contracttype]\n#[derive(Clone, Debug, Eq, PartialEq)]\npub struct Holding {", milestone_struct + "\n#[contracttype]\n#[derive(Clone, Debug, Eq, PartialEq)]\npub struct Holding {")

# Add Milestone(u64) to DataKey
datakey_old = """enum DataKey {
    Treasury,
    Holding(Address),
}"""
datakey_new = """enum DataKey {
    Treasury,
    Holding(Address),
    Milestone(u64),
    MilestoneCount,
}"""
text = text.replace(datakey_old, datakey_new)

# Add milestone functions
milestone_funcs = """
    /// Initialize a milestone-based disbursement.
    pub fn initialize_milestone_disbursement(
        env: Env,
        caller: Address,
        asset: Address,
        to: Address,
        total_amount: i128,
        milestones: u32,
    ) -> Result<u64, Error> {
        let t = Self::require_admin(&env, &caller)?;
        require_positive_amount(total_amount)?;
        if milestones == 0 {
            return Err(Error::InvalidInput);
        }

        let amount_per_milestone = total_amount / (milestones as i128);
        
        let count_key = DataKey::MilestoneCount;
        let mut count: u64 = env.storage().instance().get(&count_key).unwrap_or(0);
        count += 1;
        
        let disbursement = MilestoneDisbursement {
            total_amount,
            milestones,
            disbursed: 0,
            amount_per_milestone,
            asset,
            to,
        };
        
        env.storage().persistent().set(&DataKey::Milestone(count), &disbursement);
        env.storage().persistent().extend_ttl(&DataKey::Milestone(count), PERSISTENT_LIFETIME_THRESHOLD, PERSISTENT_BUMP_AMOUNT);
        env.storage().instance().set(&count_key, &count);
        env.events().publish((symbol_short!("milestone"), symbol_short!("init")), (count, total_amount, milestones));
        Ok(count)
    }

    /// Release the next milestone payout.
    pub fn release_next_milestone(
        env: Env,
        caller: Address,
        milestone_id: u64,
    ) -> Result<(), Error> {
        let t = Self::require_admin(&env, &caller)?;
        let key = DataKey::Milestone(milestone_id);
        let mut d: MilestoneDisbursement = env.storage().persistent().get(&key).ok_or(Error::NotFound)?;
        
        if d.disbursed >= d.milestones {
            return Err(Error::InvalidState);
        }
        
        let mut amount = d.amount_per_milestone;
        if d.disbursed == d.milestones - 1 {
            let disbursed_so_far = (d.amount_per_milestone * (d.milestones - 1) as i128);
            amount = d.total_amount - disbursed_so_far;
        }
        
        d.disbursed += 1;
        env.storage().persistent().set(&key, &d);
        env.storage().persistent().extend_ttl(&key, PERSISTENT_LIFETIME_THRESHOLD, PERSISTENT_BUMP_AMOUNT);

        // Execute withdrawal logic
        let mut holding = Self::load_holding(&env, &d.asset);
        if let (Some(budget_addr), Some(budget_id)) = (&t.budget, &holding.budget_id) {
            astroid_interfaces::BudgetClient::new(&env, budget_addr)
                .consume(&caller, budget_id, &amount);
        }

        if holding.total_in < amount {
            return Err(Error::InsufficientFunds);
        }
        holding.total_in = checked_sub(holding.total_in, amount)?;
        holding.total_out = checked_add(holding.total_out, amount)?;
        Self::store_holding(&env, &d.asset, &holding);
        
        token::TokenClient::new(&env, &d.asset).transfer(
            &env.current_contract_address(),
            &d.to,
            &amount,
        );
        env.events().publish((symbol_short!("milestone"), symbol_short!("disbursed")), (milestone_id, d.disbursed, amount));
        Ok(())
    }
"""
text = text.replace("    pub fn get(env: Env) -> Treasury {", milestone_funcs + "\n    pub fn get(env: Env) -> Treasury {")

with open("contracts/treasury/src/lib.rs", "w") as f:
    f.write(text)
