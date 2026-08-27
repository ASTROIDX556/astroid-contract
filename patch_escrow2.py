import re
with open("contracts/escrow/src/lib.rs", "r") as f:
    text = f.read()

# Fix release
rel_old = """        escrow.state = EscrowState::Released;
        Self::store(&env, id, &escrow);
        // Move the real tokens out of custody to the recipient.
        token::TokenClient::new(&env, &escrow.asset).transfer(
            &env.current_contract_address(),
            &escrow.recipient,
            &escrow.funded_amount,
        );
        events::transfer_executed(
            &env,
            &escrow.sender,
            &escrow.recipient,
            &escrow.asset,
            escrow.funded_amount,
        );"""
rel_new = """        escrow.state = EscrowState::Released;
        Self::store(&env, id, &escrow);
        for (asset, amount) in escrow.balances.iter() {
            token::TokenClient::new(&env, &asset).transfer(
                &env.current_contract_address(),
                &escrow.recipient,
                &amount,
            );
            events::transfer_executed(
                &env,
                &escrow.sender,
                &escrow.recipient,
                &asset,
                amount,
            );
        }"""
text = text.replace(rel_old, rel_new)

# Fix refund
ref_old = """        escrow.state = EscrowState::Refunded;
        Self::store(&env, id, &escrow);
        // Return the real tokens to the sender.
        token::TokenClient::new(&env, &escrow.asset).transfer(
            &env.current_contract_address(),
            &escrow.sender,
            &escrow.funded_amount,
        );
        events::transfer_executed(
            &env,
            &escrow.recipient,
            &escrow.sender,
            &escrow.asset,
            escrow.funded_amount,
        );"""
ref_new = """        escrow.state = EscrowState::Refunded;
        Self::store(&env, id, &escrow);
        for (asset, amount) in escrow.balances.iter() {
            token::TokenClient::new(&env, &asset).transfer(
                &env.current_contract_address(),
                &escrow.sender,
                &amount,
            );
            events::transfer_executed(
                &env,
                &escrow.recipient,
                &escrow.sender,
                &asset,
                amount,
            );
        }"""
text = text.replace(ref_old, ref_new)

with open("contracts/escrow/src/lib.rs", "w") as f:
    f.write(text)
