with open("contracts/escrow/src/lib.rs", "r") as f:
    text = f.read()

ref_old = """        escrow.state = EscrowState::Refunded;
        Self::store(&env, id, &escrow);
        // Return the real tokens to the sender.
        token::TokenClient::new(&env, &escrow.asset).transfer(
            &env.current_contract_address(),
            &escrow.sender,
            &escrow.funded_amount,
        );
        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("refunded")),
            (id, caller),
        );"""
ref_new = """        escrow.state = EscrowState::Refunded;
        Self::store(&env, id, &escrow);
        for (asset, amount) in escrow.balances.iter() {
            token::TokenClient::new(&env, &asset).transfer(
                &env.current_contract_address(),
                &escrow.sender,
                &amount,
            );
        }
        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("refunded")),
            (id, caller),
        );"""
text = text.replace(ref_old, ref_new)

with open("contracts/escrow/src/lib.rs", "w") as f:
    f.write(text)
