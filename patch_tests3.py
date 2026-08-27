with open("contracts/escrow/src/test.rs", "r") as f:
    text = f.read()

create_helper_old = """fn create(h: &Harness, amount: i128, deadline: u64) -> u64 {
    h.client.create(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &h.asset,
        &amount,
        &deadline,
        &String::from_str(&h.env, "payment"),
    )
}"""
create_helper_new = """fn create(h: &Harness, amount: i128, deadline: u64) -> u64 {
    let mut balances = Map::new(&h.env);
    balances.set(h.asset.clone(), amount);
    h.client.create(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &balances,
        &deadline,
        &String::from_str(&h.env, "payment"),
    )
}"""
text = text.replace(create_helper_old, create_helper_new)

rejects_old = """#[test]
fn create_rejects_bad_input() {
    let h = setup(5_000);
    // recipient == sender
    let r1 = h.client.try_create(
        &h.sender,
        &h.sender,
        &h.arbiter,
        &balances,
        &(START + 100),
        &String::from_str(&h.env, "x"),
    );
    assert_eq!(r1, Err(Ok(Error::InvalidInput)));
    // deadline in the past
    let r2 = h.client.try_create(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &balances,
        &(START - 500),
        &String::from_str(&h.env, "x"),
    );
    assert_eq!(r2, Err(Ok(Error::InvalidInput)));
    // non-positive amount
    let r3 = h.client.try_create(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &h.asset,
        &0,
        &(START + 100),
        &String::from_str(&h.env, "x"),
    );
    assert_eq!(r3, Err(Ok(Error::InvalidAmount)));
    // No successful escrow was created, so the sender keeps every token.
    assert_eq!(balance(&h, &h.sender), 5_000);
}"""
rejects_new = """#[test]
fn create_rejects_bad_input() {
    let h = setup(5_000);
    let mut balances = Map::new(&h.env);
    balances.set(h.asset.clone(), 5_000);
    
    // recipient == sender
    let r1 = h.client.try_create(
        &h.sender,
        &h.sender,
        &h.arbiter,
        &balances,
        &(START + 100),
        &String::from_str(&h.env, "x"),
    );
    assert_eq!(r1, Err(Ok(Error::InvalidInput)));
    // deadline in the past
    let r2 = h.client.try_create(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &balances,
        &(START - 500),
        &String::from_str(&h.env, "x"),
    );
    assert_eq!(r2, Err(Ok(Error::InvalidInput)));
    // non-positive amount
    let mut bad_balances = Map::new(&h.env);
    bad_balances.set(h.asset.clone(), 0);
    let r3 = h.client.try_create(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &bad_balances,
        &(START + 100),
        &String::from_str(&h.env, "x"),
    );
    assert_eq!(r3, Err(Ok(Error::InvalidAmount)));
    // No successful escrow was created, so the sender keeps every token.
    assert_eq!(balance(&h, &h.sender), 5_000);
}"""
text = text.replace(rejects_old, rejects_new)

with open("contracts/escrow/src/test.rs", "w") as f:
    f.write(text)
