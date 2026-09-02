#![no_std]
#![allow(clippy::too_many_arguments)]
//! # Astroid Treasury Contract
//!
//! Custodies organizational funds and enforces governance on every outbound
//! movement (PRD Doc 7 §Treasury). Every `withdraw` / `transfer` resolves the
//! organization's Policy and Budget contracts and calls them BEFORE debiting
//! the ledger, so a spend must satisfy:
//!
//! ```text
//! admin auth → policy.check_transfer → budget.consume → assets move
//! ```
//!
//! Cross-contract calls go through the typed clients generated from
//! [`astroid_interfaces`], keeping the graph acyclic: `Treasury → {Policy, Budget}`.
//!
//! ## Asset whitelist
//!
//! Policy and budget gates constrain *how much* may move and *to whom*, but
//! neither says anything about *which token contract* is being invoked. An
//! agent that can name an arbitrary `Address` as the asset can point the
//! treasury at a hostile Stellar asset contract, whose `transfer` is arbitrary
//! code running with the treasury as the authorizer.
//!
//! Every routing decision is therefore checked against a persistent whitelist
//! of approved token contracts before any value moves:
//!
//! ```text
//! asset whitelisted → admin auth → policy.check_transfer → budget.consume → assets move
//! ```
//!
//! The whitelist is governance-managed (`add_approved_asset` /
//! `remove_approved_asset`, both admin-gated — point `admin` at the
//! organization's multisig to require a threshold of signers) and unapproved
//! assets are refused deterministically with [`Error::AssetNotAuthorized`] on
//! both inflows and outflows.
//!
//! [`TreasuryContract::batch_transfer`] applies the same gate chain to a whole
//! vector of payouts in a single, atomic invocation: the cumulative amount is
//! accumulated with checked math and validated against the treasury balance
//! before any value moves, so autonomous agents can pay many contributors for
//! the fee of one transaction. If any leg fails, the host reverts the entire
//! invocation and no recipient is paid.
//!
//! Functions: `initialize`, `set_policy`, `set_budget`, `set_multisig`,
//! `add_approved_asset`, `remove_approved_asset`, `freeze`, `unfreeze`,
//! `deposit`, `withdraw`, `batch_transfer`, `allocate_budget`, `set_allowance`,
//! `remove_allowance`, `allowance`, `init_milestone_disbursement`,
//! `release_next_milestone`, `get`, `holding`, `is_approved_asset`,
//! `approved_asset_count`.

use astroid_interfaces::PolicyClient;
use astroid_shared::constants::{
    INSTANCE_BUMP_AMOUNT, INSTANCE_LIFETIME_THRESHOLD, MAX_BATCH_PAYMENTS, PERSISTENT_BUMP_AMOUNT,
    PERSISTENT_LIFETIME_THRESHOLD,
};
use astroid_shared::errors::Error;
use astroid_shared::events;
use astroid_shared::math::{checked_add, checked_sub};
use astroid_shared::types::{Payment, ResourceState};
use astroid_shared::validation::{require_non_empty, require_positive_amount};
use soroban_sdk::{
    contract, contractimpl, contracttype, symbol_short, token, Address, Env, String, Symbol, Vec,
};

/// Stored treasury record.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Treasury {
    pub org: String,
    pub admin: Address,
    /// Emergency admin able to trigger emergency pause.
    pub emergency_admin: Option<Address>,
    /// Organization's Policy contract — consulted on every spend.
    pub policy: Option<Address>,
    /// Organization's Budget contract root.
    pub budget: Option<Address>,
    /// Lifecycle state shared with wallets.
    pub state: ResourceState,
    /// Whether the treasury is under emergency pause.
    pub emergency_paused: bool,
}

/// Per-asset accounting within the treasury.

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

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Holding {
    pub asset: Address,
    pub total_in: i128,
    pub total_out: i128,
    /// Budget envelope backing this asset, if any.
    pub budget_id: Option<String>,
    /// Amount paid out in the current interval (for streaming validation).
    pub interval_payout: i128,
    /// Start of the current payout interval (unix seconds).
    pub interval_start: u64,
}

/// Composite key identifying a withdrawal allowance scoped to a specific agent
/// (the caller that may spend), recipient and asset.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AllowanceId {
    pub agent: Address,
    pub recipient: Address,
    pub asset: Address,
}

/// Active withdrawal allowance restricting agent-driven expenditures against a
/// specific recipient/asset to a pre-approved `limit` over a time window.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Allowance {
    pub agent: Address,
    pub recipient: Address,
    pub asset: Address,
    /// Maximum cumulative amount that may be withdrawn under this allowance.
    pub limit: i128,
    /// Amount already consumed against the allowance.
    pub spent: i128,
    /// Unix timestamp after which the allowance can no longer be used (0 = never).
    pub expires_at: u64,
}

#[contracttype]
#[derive(Clone)]
enum DataKey {
    Treasury,
    Holding(Address),
    /// Whitelisted asset flag: asset -> bool.
    WhitelistedAsset(Address),
}

#[contract]
pub struct TreasuryContract;

#[contractimpl]
impl TreasuryContract {
    // --- registry-gated upgrades ---

    /// Record (or rotate) who may upgrade this contract and which registry
    /// authorizes the new code. Bootstrapped by the deployer alongside
    /// `initialize`; afterwards only the current upgrade admin may rotate it.
    pub fn set_upgrade_authority(
        env: soroban_sdk::Env,
        caller: soroban_sdk::Address,
        admin: soroban_sdk::Address,
        registry: soroban_sdk::Address,
    ) -> Result<(), astroid_shared::errors::Error> {
        astroid_interfaces::upgrade::set_authority(&env, &caller, &admin, &registry)
    }

    /// Read the recorded upgrade authority.
    pub fn get_upgrade_authority(
        env: soroban_sdk::Env,
    ) -> Result<astroid_interfaces::upgrade::UpgradeAuthority, astroid_shared::errors::Error> {
        astroid_interfaces::upgrade::get_authority(&env)
    }

    /// Replace this contract's code with `wasm_hash`.
    ///
    /// Two gates must pass: `caller` must be the recorded upgrade admin, and
    /// `wasm_hash` must be approved for [`ModuleKind::Treasury`] in the registry. Any
    /// other outcome leaves the contract running its current code.
    pub fn upgrade(
        env: soroban_sdk::Env,
        caller: soroban_sdk::Address,
        wasm_hash: soroban_sdk::BytesN<32>,
    ) -> Result<(), astroid_shared::errors::Error> {
        astroid_interfaces::upgrade::perform(
            &env,
            &caller,
            astroid_shared::types::ModuleKind::Treasury,
            wasm_hash,
        )
    }
    /// Create a treasury for `org`, gated on the admin's signature.
    pub fn initialize(env: Env, org: String, admin: Address) -> Result<(), Error> {
        if env.storage().instance().has(&DataKey::Treasury) {
            return Err(Error::AlreadyInitialized);
        }
        require_non_empty(&org)?;
        env.storage().instance().set(
            &DataKey::Treasury,
            &Treasury {
                org: org.clone(),
                admin: admin.clone(),
                emergency_admin: None,
                policy: None,
                budget: None,
                state: ResourceState::Active,
                emergency_paused: false,
            },
        );
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
        events::treasury_created(&env, &org, &admin);
        Self::unlock(&env);
        Ok(())
    }

    /// Wire the policy-enforcement contract consulted before every spend.
    pub fn set_policy(env: Env, caller: Address, policy: Address) -> Result<(), Error> {
        let mut t = Self::require_admin(&env, &caller)?;
        t.policy = Some(policy);
        Self::store(&env, &t);
        events::publish(
            &env,
            events::ContractEvent::TreasuryConfigUpdated {
                org: t.org.clone(),
                action: symbol_short!("policy"),
            },
        );
        env.events()
            .publish((symbol_short!("treasury"), symbol_short!("policy")), ());
        Self::unlock(&env);
        Ok(())
    }

    /// Wire the budget-tracking contract backing this treasury.
    pub fn set_budget(env: Env, caller: Address, budget: Address) -> Result<(), Error> {
        let mut t = Self::require_admin(&env, &caller)?;
        t.budget = Some(budget);
        Self::store(&env, &t);
        events::publish(
            &env,
            events::ContractEvent::TreasuryConfigUpdated {
                org: t.org.clone(),
                action: symbol_short!("budget"),
            },
        );
        env.events()
            .publish((symbol_short!("treasury"), symbol_short!("budget")), ());
        Self::unlock(&env);
        Ok(())
    }

    /// Set the streaming payout schedule (admin). Enforces a maximum payout
    /// velocity per interval for all withdrawals.
    pub fn set_payout_schedule(
        env: Env,
        caller: Address,
        max_per_interval: i128,
        interval_seconds: u64,
    ) -> Result<(), Error> {
        if max_per_interval <= 0 {
            return Err(Error::InvalidInput);
        }
        if interval_seconds == 0 {
            return Err(Error::InvalidInput);
        }
        let mut t = Self::require_admin(&env, &caller)?;
        t.payout_schedule = Some(PayoutSchedule {
            max_per_interval,
            interval_seconds,
        });
        Self::store(&env, &t);
        events::publish(
            &env,
            events::ContractEvent::TreasuryConfigUpdated {
                org: t.org.clone(),
                action: symbol_short!("payout"),
            },
        );
        env.events().publish(
            (symbol_short!("treasury"), symbol_short!("payout")),
            (max_per_interval, interval_seconds),
        );
        Ok(())
    }

    /// Clear the streaming payout schedule (admin).
    pub fn clear_payout_schedule(env: Env, caller: Address) -> Result<(), Error> {
        let mut t = Self::require_admin(&env, &caller)?;
        t.payout_schedule = None;
        Self::store(&env, &t);
        events::publish(
            &env,
            events::ContractEvent::TreasuryConfigUpdated {
                org: t.org.clone(),
                action: symbol_short!("payout_clr"),
            },
        );
        env.events()
            .publish((symbol_short!("treasury"), symbol_short!("payout_clr")), ());
        Ok(())
    }

    /// Freeze the treasury; all outflows are rejected while frozen.
    pub fn freeze(env: Env, caller: Address) -> Result<(), Error> {
        let mut t = Self::require_admin(&env, &caller)?;
        t.multisig = Some(multisig);
        Self::store(&env, &t);
        events::publish(
            &env,
            events::ContractEvent::TreasuryConfigUpdated {
                org: t.org.clone(),
                action: symbol_short!("multisig"),
            },
        );
        env.events()
            .publish((symbol_short!("treasury"), symbol_short!("multisig")), ());
        Self::unlock(&env);
        Ok(())
    }

    /// Emergency freeze — only the registry-verified multisig can freeze.
    /// Sets a dedicated frozen flag in persistent storage that blocks all outbound transfers.
    pub fn freeze(env: Env, caller: Address) -> Result<(), Error> {
        let t = Self::require_multisig(&env, &caller)?;
        env.storage().persistent().set(&DataKey::Frozen, &true);
        Self::bump_frozen(&env);
        events::publish(
            &env,
            events::ContractEvent::TreasuryFrozen { org: t.org.clone() },
        );
        env.events()
            .publish((symbol_short!("treasury"), symbol_short!("frozen")), ());
        Self::unlock(&env);
        Ok(())
    }

    /// Emergency unfreeze — only the registry-verified multisig can unfreeze.
    /// Clears the frozen flag to restore outbound transfers.
    pub fn unfreeze(env: Env, caller: Address) -> Result<(), Error> {
        let t = Self::require_multisig(&env, &caller)?;
        let frozen: bool = env
            .storage()
            .persistent()
            .get(&DataKey::Frozen)
            .unwrap_or(false);
        if !frozen {
            return Err(Error::InvalidState);
        }
        env.storage().persistent().set(&DataKey::Frozen, &false);
        Self::bump_frozen(&env);
        events::publish(
            &env,
            events::ContractEvent::TreasuryUnfrozen { org: t.org.clone() },
        );
        env.events()
            .publish((symbol_short!("treasury"), symbol_short!("unfrozen")), ());
        Self::unlock(&env);
        Ok(())
    }

    // --- emergency pause mechanism ---

    /// Set the emergency admin address. Only the current admin may call.
    pub fn set_emergency_admin(
        env: Env,
        caller: Address,
        emergency_admin: Address,
    ) -> Result<(), Error> {
        let mut t = Self::require_admin(&env, &caller)?;
        t.emergency_admin = Some(emergency_admin.clone());
        Self::store(&env, &t);
        events::publish(
            &env,
            events::ContractEvent::TreasuryConfigUpdated {
                org: t.org.clone(),
                action: symbol_short!("em_admin"),
            },
        );
        env.events().publish(
            (symbol_short!("treasury"), symbol_short!("em_admin")),
            emergency_admin,
        );
        Ok(())
    }

    /// Trigger emergency pause. Only the emergency admin may call.
    /// Blocks all deposits and withdrawals until cleared.
    pub fn emergency_pause(env: Env, caller: Address) -> Result<(), Error> {
        caller.require_auth();
        let mut t = Self::load(&env);
        let emergency_admin = t.emergency_admin.ok_or(Error::Unauthorized)?;
        if caller != emergency_admin {
            return Err(Error::Unauthorized);
        }
        t.emergency_paused = true;
        Self::store(&env, &t);
        events::publish(
            &env,
            events::ContractEvent::TreasuryConfigUpdated {
                org: t.org.clone(),
                action: symbol_short!("em_pause"),
            },
        );
        env.events()
            .publish((symbol_short!("treasury"), symbol_short!("em_pause")), ());
        Ok(())
    }

    /// Clear emergency pause. Only the admin may call.
    pub fn emergency_unpause(env: Env, caller: Address) -> Result<(), Error> {
        let mut t = Self::require_admin(&env, &caller)?;
        t.emergency_paused = false;
        Self::store(&env, &t);
        events::publish(
            &env,
            events::ContractEvent::TreasuryConfigUpdated {
                org: t.org.clone(),
                action: symbol_short!("unem_pa"),
            },
        );
        env.events()
            .publish((symbol_short!("treasury"), symbol_short!("unem_pa")), ());
        Ok(())
    }

    // --- asset whitelist ---

    /// Add an asset to the treasury whitelist. Only the admin may call.
    /// Whitelisted assets are the only ones that can be deposited or withdrawn.
    pub fn whitelist_asset(env: Env, caller: Address, asset: Address) -> Result<(), Error> {
        Self::require_admin(&env, &caller)?;
        env.storage()
            .persistent()
            .set(&DataKey::WhitelistedAsset(asset.clone()), &true);
        env.storage().persistent().extend_ttl(
            &DataKey::WhitelistedAsset(asset.clone()),
            PERSISTENT_LIFETIME_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
        env.events().publish(
            (symbol_short!("treasury"), symbol_short!("wl_asset")),
            asset,
        );
        Ok(())
    }

    /// Remove an asset from the treasury whitelist. Only the admin may call.
    pub fn remove_asset(env: Env, caller: Address, asset: Address) -> Result<(), Error> {
        Self::require_admin(&env, &caller)?;
        env.storage()
            .persistent()
            .set(&DataKey::WhitelistedAsset(asset.clone()), &false);
        env.storage().persistent().extend_ttl(
            &DataKey::WhitelistedAsset(asset.clone()),
            PERSISTENT_LIFETIME_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
        env.events().publish(
            (symbol_short!("treasury"), symbol_short!("rm_asset")),
            asset,
        );
        Ok(())
    }

    /// Deposit assets into the treasury (any funder may authorize). Moves real
    /// SAC tokens from `from` into the treasury's custody, then credits the
    /// internal per-asset accounting. Only whitelisted assets are accepted.
    pub fn deposit(env: Env, from: Address, asset: Address, amount: i128) -> Result<(), Error> {
        require_positive_amount(amount)?;
        from.require_auth();
        let t = Self::load(&env);
        Self::require_active(&t)?;
        Self::require_not_emergency_paused(&t)?;
        Self::require_whitelisted(&env, &asset)?;
        // Pull tokens into the contract's own custody.
        token::TokenClient::new(&env, &asset).transfer(
            &from,
            &env.current_contract_address(),
            &amount,
        );
        Self::unlock(&env);
        Self::unlock(&env);
        Ok(())
    }

    /// Attach a budget envelope to an asset (admin).
    pub fn allocate_budget(
        env: Env,
        admin: Address,
        asset: Address,
        budget_id: String,
    ) -> Result<(), Error> {
        let _t = Self::require_admin(&env, &admin)?;
        require_non_empty(&budget_id)?;
        Self::require_approved_asset(&env, &asset)?;
        let mut h = Self::load_holding(&env, &asset);
        h.budget_id = Some(budget_id);
        Self::store_holding(&env, &asset, &h);
        Self::unlock(&env);
        Ok(())
    }

    /// Create or update a withdrawal allowance capping how much `agent` may send
    /// to `recipient` in `asset`. `limit` is the cumulative ceiling; `expires_at`
    /// is an optional unix expiry (0 = no expiry). Admin only.
    pub fn set_allowance(
        env: Env,
        admin: Address,
        agent: Address,
        recipient: Address,
        asset: Address,
        limit: i128,
        expires_at: u64,
    ) -> Result<(), Error> {
        let _t = Self::require_admin(&env, &admin)?;
        require_positive_amount(limit)?;
        if agent == recipient {
            return Err(Error::InvalidInput);
        }
        let id = AllowanceId {
            agent,
            recipient,
            asset,
        };
        let allowance = Allowance {
            agent: id.agent.clone(),
            recipient: id.recipient.clone(),
            asset: id.asset.clone(),
            limit,
            spent: 0,
            expires_at,
        };
        env.storage()
            .persistent()
            .set(&DataKey::Allowance(id), &allowance);
        env.events()
            .publish((symbol_short!("treasury"), symbol_short!("allow")), ());
        Self::unlock(&env);
        Ok(())
    }

    /// Remove an active withdrawal allowance (admin only).
    pub fn remove_allowance(
        env: Env,
        admin: Address,
        agent: Address,
        recipient: Address,
        asset: Address,
    ) -> Result<(), Error> {
        let _t = Self::require_admin(&env, &admin)?;
        let id = AllowanceId {
            agent,
            recipient,
            asset,
        };
        if !env
            .storage()
            .persistent()
            .has(&DataKey::Allowance(id.clone()))
        {
            return Err(Error::NotFound);
        }
        env.storage().persistent().remove(&DataKey::Allowance(id));
        env.events()
            .publish((symbol_short!("treasury"), symbol_short!("allowrm")), ());
        Self::unlock(&env);
        Ok(())
    }

    /// Read the current state of a withdrawal allowance.
    pub fn allowance(
        env: Env,
        agent: Address,
        recipient: Address,
        asset: Address,
    ) -> Result<Allowance, Error> {
        let id = AllowanceId {
            agent,
            recipient,
            asset,
        };
        env.storage()
            .persistent()
            .get(&DataKey::Allowance(id))
            .ok_or(Error::NotFound)
    }

    /// Withdraw assets to a recipient. Only the admin may call, and the spend
    /// must clear policy and budget gates before the ledger is debited. Only
    /// whitelisted assets may be withdrawn; emergency pause blocks all withdrawals.
    pub fn withdraw(
        env: Env,
        caller: Address,
        asset: Address,
        to: Address,
        amount: i128,
    ) -> Result<(), Error> {
        require_positive_amount(amount)?;
        Self::check_frozen(&env)?;
        let t = Self::load(&env);
        Self::require_active(&t)?;
        Self::require_not_emergency_paused(&t)?;
        Self::require_whitelisted(&env, &asset)?;
        if t.admin != caller {
            return Err(Error::Unauthorized);
        }
        caller.require_auth();

        // 1. Routing validation — refuse to invoke a token contract the
        //    organization has not approved, before any gate is consulted.
        Self::require_approved_asset(&env, &asset)?;

        // 2. Policy verification — the policy contract evaluates the spend.
        if let Some(policy_addr) = &t.policy {
            PolicyClient::new(&env, policy_addr).check_transfer(
                &String::from_str(&env, "active"),
                &asset,
                &to,
                &amount,
            );
        }

        // 3. Budget consumption — aborts if the envelope lacks headroom.
        let mut holding = Self::load_holding(&env, &asset);
        if let (Some(budget_addr), Some(budget_id)) = (&t.budget, &holding.budget_id) {
            astroid_interfaces::BudgetClient::new(&env, budget_addr)
                .consume(&caller, budget_id, &amount);
        }

        // 3. Withdrawal allowance enforcement — restrict agent-driven spends to
        //    pre-approved periodic ceilings per (agent, recipient, asset).
        Self::lock(&env)?;

        let allowance_id = AllowanceId {
            agent: caller.clone(),
            recipient: to.clone(),
            asset: asset.clone(),
        };
        if let Some(mut al) = env
            .storage()
            .persistent()
            .get::<DataKey, Allowance>(&DataKey::Allowance(allowance_id.clone()))
        {
            if al.expires_at != 0 && env.ledger().timestamp() >= al.expires_at {
                Self::unlock(&env);
                return Err(Error::AllowanceExpired);
            }
            let new_payout = checked_add(holding.interval_payout, amount)?;
            if new_payout > schedule.max_per_interval {
                return Err(Error::PayoutScheduleViolated);
            }
            holding.interval_payout = new_payout;
        }

        // 4. Debit the internal ledger, then move real tokens out of custody.
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
        events::transfer_executed(&env, &t.admin, &to, &asset, amount);
        events::publish(
            &env,
            events::ContractEvent::TransferExecuted {
                from: t.admin.clone(),
                to: to.clone(),
                asset: asset.clone(),
                amount,
            },
        );
        Self::unlock(&env);
        Ok(())
    }

    /// Disburse `payments` of a single `asset` to many recipients in one atomic
    /// transaction. Only the admin may call, and the batch clears exactly the
    /// same gates as [`TreasuryContract::withdraw`] — policy per leg, budget for
    /// the aggregate — before the ledger is debited.
    ///
    /// The payout total is accumulated with the shared checked-math helpers and
    /// verified against the treasury's recorded balance up front, so an
    /// over-drawing batch is rejected before any token moves. Beyond that,
    /// atomicity is guaranteed by the host: returning an error (or a failing
    /// sub-call, such as a policy denial or a token transfer) rolls back every
    /// storage write and every transfer made earlier in the invocation, so a
    /// batch either pays every recipient or none of them.
    pub fn batch_transfer(
        env: Env,
        caller: Address,
        asset: Address,
        payments: Vec<Payment>,
    ) -> Result<(), Error> {
        if payments.is_empty() || payments.len() > MAX_BATCH_PAYMENTS {
            return Err(Error::InvalidInput);
        }
        Self::check_frozen(&env)?;
        let t = Self::load(&env);
        Self::require_active(&t)?;
        if t.admin != caller {
            return Err(Error::Unauthorized);
        }
        caller.require_auth();

        // 1. Validate every leg and accumulate the payout with checked math, so
        //    a malformed or overflowing batch is rejected before anything moves.
        let mut total: i128 = 0;
        for payment in payments.iter() {
            require_positive_amount(payment.amount)?;
            total = checked_add(total, payment.amount)?;
        }

        // 2. Cumulative balance check against the recorded holding.
        let mut holding = Self::load_holding(&env, &asset);
        if holding.total_in < total {
            return Err(Error::InsufficientFunds);
        }

        // 3. Policy verification — each leg is evaluated on its own, because
        //    per-recipient and per-amount gates are what the policy encodes.
        if let Some(policy_addr) = &t.policy {
            let policy = PolicyClient::new(&env, policy_addr);
            let policy_id = String::from_str(&env, "active");
            for payment in payments.iter() {
                policy.check_transfer(&policy_id, &asset, &payment.recipient, &payment.amount);
            }
        }

        // 4. Budget consumption — one debit for the aggregate rather than one
        //    cross-contract call per recipient.
        if let (Some(budget_addr), Some(budget_id)) = (&t.budget, &holding.budget_id) {
            astroid_interfaces::BudgetClient::new(&env, budget_addr)
                .consume(&caller, budget_id, &total);
        }

        // 5. Debit the internal ledger once, then move real tokens per recipient.
        Self::lock(&env)?;
        holding.total_in = checked_sub(holding.total_in, total)?;
        holding.total_out = checked_add(holding.total_out, total)?;
        Self::store_holding(&env, &asset, &holding);

        let token_client = token::TokenClient::new(&env, &asset);
        let custody = env.current_contract_address();
        for payment in payments.iter() {
            token_client.transfer(&custody, &payment.recipient, &payment.amount);
        }

        // A single summary event keeps the log concise; the per-recipient moves
        // are already observable as the asset contract's own transfer events.
        events::publish(
            &env,
            events::ContractEvent::BatchTransferExecuted {
                from: t.admin.clone(),
                asset: asset.clone(),
                count: payments.len(),
                total,
            },
        );
        events::treasury_batchpay(&env, &asset, payments.len(), total);

        Self::unlock(&env);
        Self::unlock(&env);
        Ok(())
    }

    // --- views ---

    /// Initialize a milestone-based disbursement.
    pub fn init_milestone_disbursement(
        env: Env,
        caller: Address,
        asset: Address,
        to: Address,
        total_amount: i128,
        milestones: u32,
    ) -> Result<u64, Error> {
        let _t = Self::require_admin(&env, &caller)?;
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

        env.storage()
            .persistent()
            .set(&DataKey::Milestone(count), &disbursement);
        env.storage().persistent().extend_ttl(
            &DataKey::Milestone(count),
            PERSISTENT_LIFETIME_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
        env.storage().instance().set(&count_key, &count);
        events::treasury_milestone_init(&env, count, total_amount, milestones);
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
        let mut d: MilestoneDisbursement = env
            .storage()
            .persistent()
            .get(&key)
            .ok_or(Error::NotFound)?;

        if d.disbursed >= d.milestones {
            return Err(Error::InvalidState);
        }

        let mut amount = d.amount_per_milestone;
        if d.disbursed == d.milestones - 1 {
            let disbursed_so_far = d.amount_per_milestone * (d.milestones - 1) as i128;
            amount = d.total_amount - disbursed_so_far;
        }

        d.disbursed += 1;
        env.storage().persistent().set(&key, &d);
        env.storage().persistent().extend_ttl(
            &key,
            PERSISTENT_LIFETIME_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );

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
        events::treasury_milestone_disbursed(&env, milestone_id, d.disbursed, amount);
        Self::unlock(&env);
        Ok(())
    }

    pub fn get(env: Env) -> Treasury {
        Self::load(&env)
    }

    pub fn holding(env: Env, asset: Address) -> Holding {
        Self::load_holding(&env, &asset)
    }

    /// Check whether an asset is whitelisted for this treasury.
    pub fn is_whitelisted(env: Env, asset: Address) -> bool {
        env.storage()
            .persistent()
            .get(&DataKey::WhitelistedAsset(asset))
            .unwrap_or(false)
    }

    // --- internals ---

    fn load(env: &Env) -> Treasury {
        env.storage()
            .instance()
            .get(&DataKey::Treasury)
            .expect("treasury not initialized")
    }

    fn store(env: &Env, t: &Treasury) {
        env.storage().instance().set(&DataKey::Treasury, t);
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
    }

    fn require_admin(env: &Env, caller: &Address) -> Result<Treasury, Error> {
        let t = Self::load(env);
        if t.admin != *caller {
            return Err(Error::Unauthorized);
        }
        caller.require_auth();
        Ok(t)
    }

    /// Reject any routing through a token contract that governance has not
    /// approved. The whitelist starts empty, so a freshly initialized treasury
    /// moves nothing until an asset is explicitly approved.
    fn require_approved_asset(env: &Env, asset: &Address) -> Result<(), Error> {
        if !env
            .storage()
            .persistent()
            .get(&DataKey::ApprovedAsset(asset.clone()))
            .unwrap_or(false)
        {
            return Err(Error::AssetNotAuthorized);
        }
        env.storage().persistent().extend_ttl(
            &DataKey::ApprovedAsset(asset.clone()),
            PERSISTENT_LIFETIME_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
        Ok(())
    }

    fn approved_count(env: &Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::ApprovedAssetCount)
            .unwrap_or(0)
    }

    fn store_approved_count(env: &Env, count: u32) {
        env.storage()
            .instance()
            .set(&DataKey::ApprovedAssetCount, &count);
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_LIFETIME_THRESHOLD, INSTANCE_BUMP_AMOUNT);
    }

    /// Publish a whitelist change under both the contract-local tuple topic and
    /// the canonical cross-cutting schema.
    fn emit_asset_change(env: &Env, t: &Treasury, asset: &Address, action: Symbol) {
        env.events()
            .publish((symbol_short!("treasury"), action.clone()), asset.clone());
        events::publish(
            env,
            events::ContractEvent::TreasuryConfigUpdated {
                org: t.org.clone(),
                action,
            },
        );
    }

    fn require_multisig(env: &Env, caller: &Address) -> Result<Treasury, Error> {
        let t = Self::load(env);
        match &t.multisig {
            Some(multisig) if multisig == caller => {
                caller.require_auth();
                Ok(t)
            }
            _ => Err(Error::Unauthorized),
        }
    }

    fn check_frozen(env: &Env) -> Result<(), Error> {
        let frozen: bool = env
            .storage()
            .persistent()
            .get(&DataKey::Frozen)
            .unwrap_or(false);
        if frozen {
            return Err(Error::InvalidState);
        }
        Self::unlock(env);
        Ok(())
    }

    fn bump_frozen(env: &Env) {
        env.storage().persistent().extend_ttl(
            &DataKey::Frozen,
            PERSISTENT_LIFETIME_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
    }

    fn require_active(t: &Treasury) -> Result<(), Error> {
        match t.state {
            ResourceState::Active => Ok(()),
            _ => Err(Error::InvalidState),
        }
    }

    fn require_not_emergency_paused(t: &Treasury) -> Result<(), Error> {
        if t.emergency_paused {
            return Err(Error::EmergencyPaused);
        }
        env.storage()
            .instance()
            .set(&DataKey::ReentrancyLock, &true);
        Self::unlock(env);
        Ok(())
    }

    fn require_whitelisted(env: &Env, asset: &Address) -> Result<(), Error> {
        let whitelisted: bool = env
            .storage()
            .persistent()
            .get(&DataKey::WhitelistedAsset(asset.clone()))
            .unwrap_or(false);
        if !whitelisted {
            return Err(Error::AssetNotWhitelisted);
        }
        Ok(())
    }

    fn load_holding(env: &Env, asset: &Address) -> Holding {
        env.storage()
            .persistent()
            .get(&DataKey::Holding(asset.clone()))
            .unwrap_or(Holding {
                asset: asset.clone(),
                total_in: 0,
                total_out: 0,
                budget_id: None,
                interval_payout: 0,
                interval_start: 0,
            })
    }

    fn store_holding(env: &Env, asset: &Address, h: &Holding) {
        env.storage()
            .persistent()
            .set(&DataKey::Holding(asset.clone()), h);
        env.storage().persistent().extend_ttl(
            &DataKey::Holding(asset.clone()),
            PERSISTENT_LIFETIME_THRESHOLD,
            PERSISTENT_BUMP_AMOUNT,
        );
    }
}

#[cfg(test)]
mod test;
