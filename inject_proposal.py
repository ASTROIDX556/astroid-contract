import re
with open("contracts/proposal/src/lib.rs", "r") as f:
    c = f.read()

# 1. Add AssetAmount to imports
c = c.replace("use soroban_sdk::{", "use astroid_shared::types::AssetAmount;\nuse soroban_sdk::{token::TokenClient, ")

# 2. Add deposit to Proposal struct
c = c.replace("    pub expires_at: u64,", "    pub deposit: Vec<AssetAmount>,\n    pub expires_at: u64,")

# 3. Add deposit to create params
c = c.replace("        threshold: u32,", "        threshold: u32,\n        deposit: Vec<AssetAmount>,")

# 4. Handle deposit in create
c = c.replace("        if expires_at != 0 && expires_at <= env.ledger().timestamp() {", """        if let Some(dep) = deposit.first() {
            if dep.amount <= 0 {
                return Err(Error::InvalidAmount);
            }
            TokenClient::new(&env, &dep.asset).transfer(
                &proposer,
                &env.current_contract_address(),
                &dep.amount,
            );
        }
        if expires_at != 0 && expires_at <= env.ledger().timestamp() {""")

# 5. Pass deposit when initializing Proposal
c = c.replace("            state: ProposalState::Pending,", "            deposit,\n            state: ProposalState::Pending,")

# 6. Refund logic for reject, cancel, expire, execute
refund = """
        if let Some(dep) = proposal.deposit.first() {
            TokenClient::new(&env, &dep.asset).transfer(
                &env.current_contract_address(),
                &proposal.proposer,
                &dep.amount,
            );
        }"""

c = c.replace("        proposal.state = ProposalState::Rejected;", "        proposal.state = ProposalState::Rejected;" + refund)
c = c.replace("        proposal.state = ProposalState::Cancelled;", "        proposal.state = ProposalState::Cancelled;" + refund)
c = c.replace("        proposal.state = ProposalState::Expired;", "        proposal.state = ProposalState::Expired;" + refund)
c = c.replace("        proposal.state = ProposalState::Executed;", "        proposal.state = ProposalState::Executed;" + refund)

with open("contracts/proposal/src/lib.rs", "w") as f:
    f.write(c)

with open("contracts/proposal/src/test.rs", "r") as f:
    t = f.read()

# Update test to pass empty deposit Vec
t = re.sub(r"        &threshold,\n        &expires_at,\n        &expires_at,", r"        &threshold,\n        &soroban_sdk::vec![&h.env],\n        &expires_at,\n        &expires_at,", t)
t = re.sub(r"        &3,\n        &5_000,\n        &expires_at,", r"        &3,\n        &soroban_sdk::vec![&h.env],\n        &5_000,\n        &expires_at,", t)
t = re.sub(r"        &1,\n        &500, // in the past \(now = 1000\)\n        &expires_at,", r"        &1,\n        &soroban_sdk::vec![&h.env],\n        &500, // in the past (now = 1000)\n        &expires_at,", t)
t = re.sub(r"        &2,\n        &expires_at,\n        &0,\n        &50, // 50 seconds grace period", r"        &2,\n        &soroban_sdk::vec![&h.env],\n        &expires_at,\n        &0,\n        &50, // 50 seconds grace period", t)
t = re.sub(r"        &2,\n        &0,\n        &50,\n    \);", r"        &2,\n        &soroban_sdk::vec![&h.env],\n        &0,\n        &50,\n    );", t)

with open("contracts/proposal/src/test.rs", "w") as f:
    f.write(t)
