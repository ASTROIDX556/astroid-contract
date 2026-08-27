import re

with open("contracts/budget/src/lib.rs", "r") as f:
    text = f.read()

# Add release function
release_func = """
    fn release(env: Env, caller: Address, budget_id: String, amount: i128) -> Result<i128, Error> {
        require_positive_amount(amount)?;
        let mut budget = Self::require_owner(&env, &budget_id, &caller)?;
        Self::require_active(&budget)?;
        // We only rollback if it doesn't underflow. If they try to release more than spent, it underflows.
        budget.spent = checked_sub(budget.spent, amount)?;
        Self::store(&env, &budget_id, &budget);
        
        env.events().publish(
            (symbol_short!("budget"), symbol_short!("rollback")),
            (budget_id, amount),
        );
        checked_sub(budget.limit, budget.spent)
    }

    /// Read remaining allocation, accounting for a pending auto-reset window.
"""

text = text.replace("    /// Read remaining allocation, accounting for a pending auto-reset window.\n", release_func)

with open("contracts/budget/src/lib.rs", "w") as f:
    f.write(text)
