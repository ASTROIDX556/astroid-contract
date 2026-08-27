with open("contracts/escrow/src/lib.rs", "r") as f:
    text = f.read()

escrow_old = """        let escrow = Escrow {
            sender: sender.clone(),
            recipient: recipient.clone(),
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

event_old = """        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("funded")),
            (id, sender, recipient, asset, amount),
        );"""
event_new = """        env.events().publish(
            (symbol_short!("escrow"), symbol_short!("funded")),
            (id, sender, recipient),
        );"""
text = text.replace(event_old, event_new)

with open("contracts/escrow/src/lib.rs", "w") as f:
    f.write(text)
