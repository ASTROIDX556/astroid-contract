import re
with open("contracts/escrow/src/lib.rs", "r") as f:
    text = f.read()

# Replace create signature
sig_old = """    pub fn create(
        env: Env,
        sender: Address,
        recipient: Address,
        arbiter: Address,
        asset: Address,
        amount: i128,
        deadline: u64,
        memo: String,
    ) -> Result<u64, Error> {"""
sig_new = """    pub fn create(
        env: Env,
        sender: Address,
        recipient: Address,
        arbiter: Address,
        balances: Map<Address, i128>,
        deadline: u64,
        memo: String,
    ) -> Result<u64, Error> {"""
text = text.replace(sig_old, sig_new)

# Replace checks
checks_old = """        // `sender` commits the funds.
        sender.require_auth();
        require_positive_amount(amount)?;
        if recipient == sender {
            return Err(Error::InvalidInput);
        }
        // A live release window is required — a past/zero deadline would make the
        // escrow un-releasable and instantly refundable.
        if deadline <= env.ledger().timestamp() {
            return Err(Error::InvalidInput);
        }"""
checks_new = """        sender.require_auth();
        if recipient == sender {
            return Err(Error::InvalidInput);
        }
        if deadline <= env.ledger().timestamp() {
            return Err(Error::InvalidInput);
        }
        if balances.is_empty() {
            return Err(Error::InvalidInput);
        }
        for (_, amount) in balances.iter() {
            require_positive_amount(amount)?;
        }"""
text = text.replace(checks_old, checks_new)

# Replace token transfer
transfer_old = """        // Pull the funds into the escrow's own custody. If the sender lacks the
        // balance this panics and the whole invocation (including the id bump)
        // rolls back.
        token::TokenClient::new(&env, &asset).transfer(
            &sender,
            &env.current_contract_address(),
            &amount,
        );"""
transfer_new = """        for (asset, amount) in balances.iter() {
            token::TokenClient::new(&env, &asset).transfer(
                &sender,
                &env.current_contract_address(),
                &amount,
            );
        }"""
text = text.replace(transfer_old, transfer_new)

# Replace escrow creation
escrow_old = """        let escrow = Escrow {
            sender,
            recipient,
            arbiter,
            asset: asset.clone(),
            amount,
            state: EscrowState::Funded,
            deadline,
            funded_amount: amount,
            memo,
        };"""
escrow_new = """        let escrow = Escrow {
            sender: sender.clone(),
            recipient: recipient.clone(),
            arbiter,
            balances,
            state: EscrowState::Funded,
            deadline,
            memo,
        };"""
text = text.replace(escrow_old, escrow_new)

# Replace create event
event_old = """env.events()
            .publish((symbol_short!("escrow"), symbol_short!("created")), (id, asset, amount));"""
event_new = """env.events()
            .publish((symbol_short!("escrow"), symbol_short!("created")), (id, sender, recipient));"""
text = text.replace(event_old, event_new)

with open("contracts/escrow/src/lib.rs", "w") as f:
    f.write(text)
