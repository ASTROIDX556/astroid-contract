import re

with open("contracts/proposal/src/lib.rs", "r") as f:
    c = f.read()

c = c.replace("use soroban_sdk::{", "use astroid_shared::types::AssetAmount;\nuse soroban_sdk::{")

c = c.replace("    pub expires_at: u64,", "    pub deposit: Option<AssetAmount>,\n    pub expires_at: u64,")

c = c.replace("        threshold: u32,", "        threshold: u32,\n        deposit: Option<AssetAmount>,")

c = c.replace("        if expires_at != 0 && expires_at <= env.ledger().timestamp() {", """        if let Some(dep) = &deposit {
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

c = c.replace("            state: ProposalState::Pending,", "            deposit,\n            state: ProposalState::Pending,")

c = c.replace("        proposal.state = ProposalState::Rejected;", """        proposal.state = ProposalState::Rejected;
        if let Some(dep) = &proposal.deposit {
            TokenClient::new(&env, &dep.asset).transfer(
                &env.current_contract_address(),
                &proposal.proposer,
                &dep.amount,
            );
        }""")

c = c.replace("        proposal.state = ProposalState::Cancelled;", """        proposal.state = ProposalState::Cancelled;
        if let Some(dep) = &proposal.deposit {
            TokenClient::new(&env, &dep.asset).transfer(
                &env.current_contract_address(),
                &proposal.proposer,
                &dep.amount,
            );
        }""")

c = c.replace("        proposal.state = ProposalState::Expired;", """        proposal.state = ProposalState::Expired;
        if let Some(dep) = &proposal.deposit {
            TokenClient::new(&env, &dep.asset).transfer(
                &env.current_contract_address(),
                &proposal.proposer,
                &dep.amount,
            );
        }""")

c = c.replace("        proposal.state = ProposalState::Executed;", """        proposal.state = ProposalState::Executed;
        if let Some(dep) = &proposal.deposit {
            TokenClient::new(&env, &dep.asset).transfer(
                &env.current_contract_address(),
                &proposal.proposer,
                &dep.amount,
            );
        }""")

with open("contracts/proposal/src/lib.rs", "w") as f:
    f.write(c)

with open("contracts/proposal/src/test.rs", "r") as f:
    t = f.read()

t = re.sub(r"        &threshold,\n        &expires_at,\n        &expires_at,", r"        &threshold,\n        &None,\n        &expires_at,\n        &expires_at,", t)
t = re.sub(r"        &3,\n        &5_000,\n        &expires_at,", r"        &3,\n        &None,\n        &5_000,\n        &expires_at,", t)
t = re.sub(r"        &1,\n        &500, // in the past \(now = 1000\)\n        &expires_at,", r"        &1,\n        &None,\n        &500, // in the past (now = 1000)\n        &expires_at,", t)
t = re.sub(r"        &2,\n        &expires_at,\n        &0,\n        &50,", r"        &2,\n        &None,\n        &expires_at,\n        &0,\n        &50,", t)
t = re.sub(r"        &2,\n        &0,\n        &50,", r"        &2,\n        &None,\n        &0,\n        &50,", t)

with open("contracts/proposal/src/test.rs", "w") as f:
    f.write(t)

