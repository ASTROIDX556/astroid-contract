import re

with open("contracts/escrow/src/lib.rs", "r") as f:
    text = f.read()

# Replace initialize_timelock
sig_old = """    pub fn initialize_timelock(
        env: Env,
        sender: Address,
        recipient: Address,
        arbiter: Address,
        asset: Address,
        amount: i128,
        unlock_time: u64,
        memo: String,
    ) -> Result<u64, Error> {"""
sig_new = """    pub fn initialize_timelock(
        env: Env,
        sender: Address,
        recipient: Address,
        arbiter: Address,
        balances: Map<Address, i128>,
        unlock_time: u64,
        memo: String,
    ) -> Result<u64, Error> {"""
text = text.replace(sig_old, sig_new)

text = text.replace("""        require_positive_amount(amount)?;
        if recipient == sender {""", """        if recipient == sender {""")

text = text.replace("""        if unlock_time <= env.ledger().timestamp() {
            return Err(Error::InvalidInput);
        }""", """        if unlock_time <= env.ledger().timestamp() {
            return Err(Error::InvalidInput);
        }
        if balances.is_empty() {
            return Err(Error::InvalidInput);
        }
        for (_, amount) in balances.iter() {
            require_positive_amount(amount)?;
        }""")

text = text.replace("""        let escrow = Escrow {
            sender: sender.clone(),
            recipient: recipient.clone(),
            arbiter,
            asset: asset.clone(),
            amount,
            state: EscrowState::Created,
            deadline: unlock_time,
            funded_amount: 0,
            memo,
        };""", """        let escrow = Escrow {
            sender: sender.clone(),
            recipient: recipient.clone(),
            arbiter,
            balances,
            state: EscrowState::Created,
            deadline: unlock_time,
            memo,
        };""")

text = text.replace("""            (symbol_short!("escrow"), symbol_short!("init_tl")),
            (id, sender, recipient, asset, amount, unlock_time),""", """            (symbol_short!("escrow"), symbol_short!("init_tl")),
            (id, sender, recipient, unlock_time),""")

# fix claim
claim_old = """        token::TokenClient::new(&env, &escrow.asset).transfer(
            &env.current_contract_address(),
            &escrow.recipient,
            &escrow.amount,
        );"""
claim_new = """        for (asset, amount) in escrow.balances.iter() {
            token::TokenClient::new(&env, &asset).transfer(
                &env.current_contract_address(),
                &escrow.recipient,
                &amount,
            );
        }"""
text = text.replace(claim_old, claim_new)

# fix claim event
text = text.replace("""            (symbol_short!("escrow"), symbol_short!("claimed")),
            (id, escrow.recipient, escrow.asset, escrow.amount),""", """            (symbol_short!("escrow"), symbol_short!("claimed")),
            (id, escrow.recipient),""")

# fix refund_timelock
rtl_old = """        token::TokenClient::new(&env, &escrow.asset).transfer(
            &env.current_contract_address(),
            &escrow.sender,
            &escrow.amount,
        );"""
rtl_new = """        for (asset, amount) in escrow.balances.iter() {
            token::TokenClient::new(&env, &asset).transfer(
                &env.current_contract_address(),
                &escrow.sender,
                &amount,
            );
        }"""
text = text.replace(rtl_old, rtl_new)

# fix refund_timelock event
text = text.replace("""            (symbol_short!("escrow"), symbol_short!("refunded")),
            (id, escrow.sender, escrow.asset, escrow.amount),""", """            (symbol_short!("escrow"), symbol_short!("refunded")),
            (id, escrow.sender),""")

with open("contracts/escrow/src/lib.rs", "w") as f:
    f.write(text)
