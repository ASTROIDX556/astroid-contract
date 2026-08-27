import re

with open("contracts/proposal/src/lib.rs", "r") as f:
    text = f.read()

cleanup_func = """

    /// Purge an expired proposal from storage to reclaim space.
    pub fn cleanup_expired(env: Env, id: u64) -> Result<(), Error> {
        let proposal = Self::load(&env, id)?;
        if proposal.expires_at == 0 || env.ledger().timestamp() < proposal.expires_at {
            return Err(Error::InvalidProposalState);
        }
        env.storage().persistent().remove(&DataKey::Proposal(id));
        env.events()
            .publish((symbol_short!("proposal"), symbol_short!("cleaned")), id);
        Ok(())
    }"""

# Insert before execute
text = text.replace("    pub fn execute(env: Env, caller: Address, id: u64) -> Result<(), Error> {", cleanup_func + "\n\n    pub fn execute(env: Env, caller: Address, id: u64) -> Result<(), Error> {")

with open("contracts/proposal/src/lib.rs", "w") as f:
    f.write(text)
