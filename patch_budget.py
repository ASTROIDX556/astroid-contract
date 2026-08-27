import re

with open("contracts/budget/src/lib.rs", "r") as f:
    text = f.read()

# Add window_seconds to AssetBudget
text = text.replace(
    "pub struct AssetBudget {\n    pub limit: i128,\n    pub spent: i128,\n    pub window_start: u64,\n}",
    "pub struct AssetBudget {\n    pub limit: i128,\n    pub spent: i128,\n    pub window_start: u64,\n    pub window_seconds: u64,\n}"
)

# Update set_budget_limit
old_set = """    pub fn set_budget_limit(
        env: Env,
        caller: Address,
        budget_id: String,
        token: Address,
        limit: i128,
        _window_seconds: u64,
    ) -> Result<(), Error> {
        let budget = Self::require_owner(&env, &budget_id, &caller)?;
        Self::require_active(&budget)?;
        require_non_negative_amount(limit)?;

        let key = DataKey::AssetBudget(budget_id.clone(), token.clone());
        let asset_budget = AssetBudget {
            limit,
            spent: 0,
            window_start: env.ledger().timestamp(),
        };"""
new_set = """    pub fn set_budget_limit(
        env: Env,
        caller: Address,
        budget_id: String,
        token: Address,
        limit: i128,
        window_seconds: u64,
    ) -> Result<(), Error> {
        let budget = Self::require_owner(&env, &budget_id, &caller)?;
        Self::require_active(&budget)?;
        require_non_negative_amount(limit)?;

        let key = DataKey::AssetBudget(budget_id.clone(), token.clone());
        let asset_budget = AssetBudget {
            limit,
            spent: 0,
            window_start: env.ledger().timestamp(),
            window_seconds,
        };"""
text = text.replace(old_set, new_set)

# Update check_and_record_spend
old_check = """        // Check if within limit
        let new_spent = checked_add(asset_budget.spent, amount)?;
        if new_spent > asset_budget.limit {
            return Err(Error::BudgetExceeded);
        }

        asset_budget.spent = new_spent;"""
new_check = """        // Window rollover check
        let now = env.ledger().timestamp();
        if asset_budget.window_seconds > 0 && now >= asset_budget.window_start.saturating_add(asset_budget.window_seconds) {
            asset_budget.spent = 0;
            asset_budget.window_start = now;
        }

        // Check if within limit
        let new_spent = checked_add(asset_budget.spent, amount)?;
        if new_spent > asset_budget.limit {
            return Err(Error::BudgetExceeded);
        }

        asset_budget.spent = new_spent;"""
text = text.replace(old_check, new_check)

with open("contracts/budget/src/lib.rs", "w") as f:
    f.write(text)
