import re

with open("contracts/proposal/src/lib.rs", "r") as f:
    text = f.read()

if "token::TokenClient" not in text:
    text = text.replace("use soroban_sdk::{", "use soroban_sdk::{token::TokenClient, ")

text = text.replace("pub expires_at: u64,", "pub deadline: u64,\n    pub deposit_asset: Option<Address>,\n    pub deposit_amount: i128,")
text = text.replace("expires_at: u64,", "deadline: u64,\n        deposit_asset: Option<Address>,\n        deposit_amount: i128,")
text = text.replace("if expires_at != 0 && expires_at <= env.ledger().timestamp() {", """if deadline != 0 && deadline <= env.ledger().timestamp() {
            return Err(Error::InvalidInput);
        }
        if let Some(asset) = &deposit_asset {
            if deposit_amount <= 0 { return Err(Error::InvalidAmount); }
            TokenClient::new(&env, asset).transfer(&proposer, &env.current_contract_address(), &deposit_amount);
        }
        if false {""")

text = text.replace("expires_at,", "deadline,\n            deposit_asset,\n            deposit_amount,")

# execute
text = text.replace("""        proposal.state = ProposalState::Executed;
        Self::store(&env, id, &proposal);""", """        proposal.state = ProposalState::Executed;
        if let Some(asset) = &proposal.deposit_asset {
            TokenClient::new(&env, asset).transfer(&env.current_contract_address(), &proposal.proposer, &proposal.deposit_amount);
        }
        Self::store(&env, id, &proposal);""")

# reject
text = text.replace("""        proposal.state = ProposalState::Rejected;
        Self::store(&env, id, &proposal);""", """        proposal.state = ProposalState::Rejected;
        if let Some(asset) = &proposal.deposit_asset {
            TokenClient::new(&env, asset).transfer(&env.current_contract_address(), &proposal.proposer, &proposal.deposit_amount);
        }
        Self::store(&env, id, &proposal);""")

# cancel
text = text.replace("""        proposal.state = ProposalState::Cancelled;
        Self::store(&env, id, &proposal);""", """        proposal.state = ProposalState::Cancelled;
        if let Some(asset) = &proposal.deposit_asset {
            TokenClient::new(&env, asset).transfer(&env.current_contract_address(), &proposal.proposer, &proposal.deposit_amount);
        }
        Self::store(&env, id, &proposal);""")

# claim_expired_refund
expire_method = """    /// Mark a proposal expired if its deadline has passed. Permissionless
    /// (anyone may trigger the transition; state gate protects correctness).
    pub fn expire(env: Env, id: u64) -> Result<(), Error> {
        let mut proposal = Self::load(&env, id)?;
        if !matches!(
            proposal.state,
            ProposalState::Pending | ProposalState::Approved
        ) {
            return Err(Error::InvalidProposalState);
        }
        if proposal.expires_at == 0 || env.ledger().timestamp() < proposal.expires_at {
            return Err(Error::InvalidProposalState);
        }
        proposal.state = ProposalState::Expired;
        Self::store(&env, id, &proposal);
        env.events()
            .publish((symbol_short!("proposal"), symbol_short!("expired")), id);
        Ok(())
    }"""
new_claim = """    /// Mark a proposal expired and claim refund.
    pub fn claim_expired_refund(env: Env, proposal_id: u64) -> Result<(), Error> {
        let mut proposal = Self::load(&env, proposal_id)?;
        if !matches!(
            proposal.state,
            ProposalState::Pending | ProposalState::Approved
        ) {
            return Err(Error::InvalidProposalState);
        }
        if proposal.deadline == 0 || env.ledger().timestamp() < proposal.deadline {
            return Err(Error::InvalidProposalState);
        }
        proposal.state = ProposalState::Expired;
        if let Some(asset) = &proposal.deposit_asset {
            TokenClient::new(&env, asset).transfer(&env.current_contract_address(), &proposal.proposer, &proposal.deposit_amount);
        }
        Self::store(&env, proposal_id, &proposal);
        env.events().publish((symbol_short!("proposal"), symbol_short!("refunded")), proposal_id);
        Ok(())
    }"""
text = text.replace(expire_method, new_claim)

text = text.replace("proposal.expires_at", "proposal.deadline")
text = text.replace("expire(", "claim_expired_refund(")

with open("contracts/proposal/src/lib.rs", "w") as f:
    f.write(text)
