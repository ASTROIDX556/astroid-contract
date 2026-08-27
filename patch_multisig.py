import re

with open("contracts/multisig/src/lib.rs", "r") as f:
    text = f.read()

# Add Map to imports
text = text.replace("Address, Bytes, Env, Symbol, Vec,", "Address, Bytes, Env, Symbol, Vec, Map,")

# Change initialize signature
text = text.replace("signers: Vec<Address>", "signers: Map<Address, u32>")

# Fix initialize logic
init_body_old = """        if env.storage().instance().has(&DataKey::Threshold) {
            return Err(Error::AlreadyInitialized);
        }
        let n = signers.len();
        if n == 0 || n > MAX_SIGNERS {
            return Err(Error::InvalidInput);
        }
        Self::validate_threshold(threshold, n)?;
        Self::assert_unique(&signers)?;"""
init_body_new = """        if env.storage().instance().has(&DataKey::Threshold) {
            return Err(Error::AlreadyInitialized);
        }
        let n = signers.len();
        if n == 0 || n > MAX_SIGNERS {
            return Err(Error::InvalidInput);
        }
        
        let mut total_weight: u32 = 0;
        for (_addr, weight) in signers.iter() {
            total_weight = total_weight.saturating_add(weight);
        }
        Self::validate_threshold(threshold, total_weight)?;"""

text = text.replace(init_body_old, init_body_new)

# Fix add_signer signature
text = text.replace("signer: Address)", "signer: Address, weight: u32)")
add_signer_old = """        let mut signers = Self::signers(&env)?;
        if signers.contains(&signer) {
            return Err(Error::AlreadyExists);
        }
        if signers.len() >= MAX_SIGNERS {
            return Err(Error::TooManySigners);
        }
        signers.push_back(signer.clone());"""
add_signer_new = """        let mut signers = Self::signers(&env)?;
        if signers.contains_key(signer.clone()) {
            return Err(Error::AlreadyExists);
        }
        if signers.len() >= MAX_SIGNERS {
            return Err(Error::TooManySigners);
        }
        signers.set(signer.clone(), weight);"""
text = text.replace(add_signer_old, add_signer_new)

# Fix remove_signer logic
remove_signer_old = """        let mut signers = Self::signers(&env)?;
        let threshold = Self::threshold(&env)?;
        let idx = signers.first_index_of(&signer).ok_or(Error::NotASigner)?;
        if signers.len() - 1 < threshold {
            return Err(Error::InvalidThreshold);
        }
        signers.remove(idx);"""
remove_signer_new = """        let mut signers = Self::signers(&env)?;
        let threshold = Self::threshold(&env)?;
        if !signers.contains_key(signer.clone()) {
            return Err(Error::NotASigner);
        }
        signers.remove(signer.clone());
        let mut total_weight: u32 = 0;
        for (_addr, weight) in signers.iter() {
            total_weight = total_weight.saturating_add(weight);
        }
        if total_weight < threshold {
            return Err(Error::InvalidThreshold);
        }"""
text = text.replace(remove_signer_old, remove_signer_new)

# Fix set_threshold logic
set_threshold_old = """        let signers = Self::signers(&env)?;
        Self::validate_threshold(threshold, signers.len())?;"""
set_threshold_new = """        let signers = Self::signers(&env)?;
        let mut total_weight: u32 = 0;
        for (_addr, weight) in signers.iter() {
            total_weight = total_weight.saturating_add(weight);
        }
        Self::validate_threshold(threshold, total_weight)?;"""
text = text.replace(set_threshold_old, set_threshold_new)

# Fix propose logic - "The proposer's approval is counted automatically" -> we no longer increment `approvals` as a simple counter. Let's just keep approvals = 1 for retrocompatibility, but we aggregate weight later!
# Actually, the issue says "aggregates the weight of all positive voters/signers associated with an active proposal" at execution.
# But wait, `approve` increments `approvals`. We can leave it as a count of approvals, and in `execute`, we do the weight check!

# Fix execute logic
execute_old = """        let threshold = Self::threshold(&env)?;
        if proposal.approvals < threshold {
            return Err(Error::ThresholdNotMet);
        }"""
execute_new = """        let threshold = Self::threshold(&env)?;
        let signers = Self::signers(&env)?;
        let mut total_weight: u32 = 0;
        for (addr, weight) in signers.iter() {
            let akey = DataKey::Approval(proposal_id, addr.clone());
            if env.storage().persistent().get(&akey).unwrap_or(false) {
                total_weight = total_weight.saturating_add(weight);
            }
        }
        if total_weight < threshold {
            return Err(Error::ThresholdNotMet);
        }"""
text = text.replace(execute_old, execute_new)

# Fix get_signers and signers and is_signer return types
text = text.replace("pub fn get_signers(env: Env) -> Result<Vec<Address>, Error>", "pub fn get_signers(env: Env) -> Result<Map<Address, u32>, Error>")
text = text.replace("fn signers(env: &Env) -> Result<Vec<Address>, Error>", "fn signers(env: &Env) -> Result<Map<Address, u32>, Error>")
is_signer_old = """    pub fn is_signer(env: Env, who: Address) -> bool {
        Self::signers(&env)
            .map(|s| s.contains(&who))
            .unwrap_or(false)
    }"""
is_signer_new = """    pub fn is_signer(env: Env, who: Address) -> bool {
        Self::signers(&env)
            .map(|s| s.contains_key(who.clone()))
            .unwrap_or(false)
    }"""
text = text.replace(is_signer_old, is_signer_new)

require_signer_old = """    fn require_signer(env: &Env, caller: &Address) -> Result<(), Error> {
        caller.require_auth();
        let signers = Self::signers(env)?;
        if !signers.contains(caller) {
            return Err(Error::NotASigner);
        }
        Ok(())
    }"""
require_signer_new = """    fn require_signer(env: &Env, caller: &Address) -> Result<(), Error> {
        caller.require_auth();
        let signers = Self::signers(env)?;
        if !signers.contains_key(caller.clone()) {
            return Err(Error::NotASigner);
        }
        Ok(())
    }"""
text = text.replace(require_signer_old, require_signer_new)

# Remove assert_unique as it's no longer used or useful for Maps
text = re.sub(r"    fn assert_unique\(signers: &Vec<Address>\) -> Result<\(\), Error> \{.*?    \}\n\n", "", text, flags=re.DOTALL)

with open("contracts/multisig/src/lib.rs", "w") as f:
    f.write(text)
