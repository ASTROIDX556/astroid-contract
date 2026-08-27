with open("contracts/escrow/src/lib.rs", "r") as f:
    text = f.read()

claim_old = """        for (asset, amount) in escrow.balances.iter() {
            token::TokenClient::new(&env, &asset).transfer(
                &env.current_contract_address(),
                &escrow.recipient,
                &amount,
            );
        }
        events::transfer_executed(
            &env,
            &escrow.sender,
            &escrow.recipient,
            &escrow.asset,
            escrow.amount,
        );"""
claim_new = """        for (asset, amount) in escrow.balances.iter() {
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
text = text.replace(claim_old, claim_new)

with open("contracts/escrow/src/lib.rs", "w") as f:
    f.write(text)
