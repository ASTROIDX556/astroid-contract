//! End-to-end integration tests for the Astroid contract workspace.
//!
//! Each test deploys all eight workspace contracts into a single mock Soroban
//! [`Env`] in dependency order and drives the full agent spending lifecycle
//! across them:
//!
//! ```text
//! registry → treasury → budget → policy → wallet → escrow
//! ```
//!
//! The harness deploys every contract with [`Env::register_contract`], links
//! the org's modules through the registry, mints a real SAC token, and funds
//! the treasury so the flow moves real value from deposit to escrow custody.

#[cfg(test)]
pub mod e2e_agent_spending;
#[cfg(test)]
pub mod interface_compliance;
#[cfg(test)]
pub mod policy_test;
#[cfg(test)]
pub mod registry_batch;
#[cfg(test)]
pub mod registry_upgrade;
