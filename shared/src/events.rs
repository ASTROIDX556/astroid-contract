//! Standardized cross-cutting events.
//!
//! Per PRD Doc 7 the backend subscribes to a fixed set of protocol events to
//! drive analytics, notifications and audit logs. These helpers publish those
//! events with a consistent topic/data schema so that every contract emits them
//! identically. Contracts may also publish additional, contract-specific events
//! directly; these are the shared "standard" set.
//!
//! Topic convention: `(Symbol category, Symbol action)` with a tuple data
//! payload. Symbols use [`symbol_short!`] (<= 9 chars) or [`Symbol::new`].

use soroban_sdk::{symbol_short, Address, Env, String, Symbol};

/// `WalletCreated` — topic `("wallet", "created")`.
pub fn wallet_created(env: &Env, wallet_id: u64, owner: &Address) {
    let topics = (symbol_short!("wallet"), symbol_short!("created"));
    env.events().publish(topics, (wallet_id, owner.clone()));
}

/// `WalletFrozen` — topic `("wallet", "frozen")`.
pub fn wallet_frozen(env: &Env, wallet_id: u64, by: &Address) {
    let topics = (symbol_short!("wallet"), symbol_short!("frozen"));
    env.events().publish(topics, (wallet_id, by.clone()));
}

/// `TransferExecuted` — topic `("transfer", "executed")`.
pub fn transfer_executed(env: &Env, from: &Address, to: &Address, asset: &Address, amount: i128) {
    let topics = (symbol_short!("transfer"), symbol_short!("executed"));
    env.events()
        .publish(topics, (from.clone(), to.clone(), asset.clone(), amount));
}

// --- Escrow-specific events -------------------------------------------------
//
// These mirror the standardized shared-event convention (`(category, action)`)
// so the Astroid backend can subscribe to escrow lifecycle transitions with the
// same topic schema used everywhere else in the protocol.

/// `EscrowFunded` — topic `("escrow", "funded")`. Emitted when an escrow is
/// created and the funds are pulled into the contract's custody.
pub fn escrow_funded(
    env: &Env,
    id: u64,
    sender: &Address,
    recipient: &Address,
    asset: &Address,
    amount: i128,
) {
    let topics = (symbol_short!("escrow"), symbol_short!("funded"));
    env.events().publish(
        topics,
        (id, sender.clone(), recipient.clone(), asset.clone(), amount),
    );
}

/// `EscrowReleased` — topic `("escrow", "released")`. Emitted when the arbiter
/// releases the escrowed funds to the recipient (fulfillment).
pub fn escrow_released(env: &Env, id: u64, by: &Address) {
    let topics = (symbol_short!("escrow"), symbol_short!("released"));
    env.events().publish(topics, (id, by.clone()));
}

/// `EscrowClaimed` — topic `("escrow", "claimed")`. Emitted when a recipient
/// claims from a time-locked escrow after the unlock time (fulfillment).
pub fn escrow_claimed(env: &Env, id: u64, by: &Address) {
    let topics = (symbol_short!("escrow"), symbol_short!("claimed"));
    env.events().publish(topics, (id, by.clone()));
}

/// `EscrowExpired` — topic `("escrow", "expired")`. Emitted when an escrow's
/// deadline passes and it is marked expired (auto-cancellation marker).
pub fn escrow_expired(env: &Env, id: u64) {
    let topics = (symbol_short!("escrow"), symbol_short!("expired"));
    env.events().publish(topics, id);
}

/// `EscrowRefunded` — topic `("escrow", "refunded")`. Emitted when expired (or
/// cancelled) escrow funds are returned to the original depositor.
pub fn escrow_refunded(env: &Env, id: u64, to: &Address) {
    let topics = (symbol_short!("escrow"), symbol_short!("refunded"));
    env.events().publish(topics, (id, to.clone()));
}

/// `ProposalCreated` — topic `("proposal", "created")`.
pub fn proposal_created(env: &Env, proposal_id: u64, proposer: &Address) {
    let topics = (symbol_short!("proposal"), symbol_short!("created"));
    env.events()
        .publish(topics, (proposal_id, proposer.clone()));
}

/// `ProposalApproved` — topic `("proposal", "approved")`.
pub fn proposal_approved(env: &Env, proposal_id: u64, approver: &Address, approvals: u32) {
    let topics = (symbol_short!("proposal"), symbol_short!("approved"));
    env.events()
        .publish(topics, (proposal_id, approver.clone(), approvals));
}

/// `BudgetExceeded` — topic `("budget", "exceeded")`.
pub fn budget_exceeded(env: &Env, budget_id: &String, requested: i128, remaining: i128) {
    let topics = (symbol_short!("budget"), symbol_short!("exceeded"));
    env.events()
        .publish(topics, (budget_id.clone(), requested, remaining));
}

/// `PolicyViolation` — topic `("policy", "violation")`.
pub fn policy_violation(env: &Env, policy_id: &String, reason: Symbol) {
    let topics = (symbol_short!("policy"), symbol_short!("violation"));
    env.events().publish(topics, (policy_id.clone(), reason));
}

/// `TreasuryCreated` — topic `("treasury", "created")`.
pub fn treasury_created(env: &Env, org: &String, admin: &Address) {
    let topics = (symbol_short!("treasury"), symbol_short!("created"));
    env.events().publish(topics, (org.clone(), admin.clone()));
}

/// Construct a `Symbol` reason code from a static name (used as event payloads
/// for policy/budget violations) so all call sites share one construction path.
pub fn reason(env: &Env, name: &str) -> Symbol {
    Symbol::new(env, name)
}
