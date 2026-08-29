with open("contracts/proposal/src/lib.rs", "w") as f:
    f.write("""#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, String, Vec};
use astroid_shared::types::AssetAmount;

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proposal {
    pub deposit: Option<AssetAmount>,
}

#[contract]
pub struct ProposalContract;

#[contractimpl]
impl ProposalContract {
    pub fn do_nothing(env: Env, p: Proposal) {}
}
""")
