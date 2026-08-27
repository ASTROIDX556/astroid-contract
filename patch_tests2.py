import re

with open("contracts/escrow/src/test.rs", "r") as f:
    text = f.read()

# Replace fund/create helpers
setup_func = """fn setup(funded: i128) -> Harness<'static> {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().with_mut(|l| l.timestamp = START);

    let id = env.register_contract(None, EscrowContract);
    let client = EscrowContractClient::new(&env, &id);
    client.initialize();"""
setup_new = """fn setup(funded: i128) -> Harness<'static> {
    let env = Env::default();
    env.mock_all_auths();
    env.ledger().with_mut(|l| l.timestamp = START);

    let id = env.register_contract(None, EscrowContract);
    let client = EscrowContractClient::new(&env, &id);
    client.initialize();"""
text = text.replace(setup_func, setup_new)

text = re.sub(
r"""    let mut balances = Map::new\(&env\);\n    balances\.set\(asset\.clone\(\), 1_000\);""",
"", text)

create_sig_old = """fn fund(h: &Harness, amount: i128) -> u64 {
    h.client.create(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &h.asset,
        &amount,
        &(START + 100),
        &String::from_str(&h.env, "test"),
    )
}"""
create_sig_new = """fn fund(h: &Harness, amount: i128) -> u64 {
    let mut balances = Map::new(&h.env);
    balances.set(h.asset.clone(), amount);
    h.client.create(
        &h.sender,
        &h.recipient,
        &h.arbiter,
        &balances,
        &(START + 100),
        &String::from_str(&h.env, "test"),
    )
}"""
text = text.replace(create_sig_old, create_sig_new)

create_call1 = """        &balances,
        &0,
        &(START + 100),"""
create_call1_new = """        &balances,
        &(START + 100),"""
text = text.replace(create_call1, create_call1_new)

create_call2 = """        &balances,
        &1_000,
        &(START),"""
create_call2_new = """        &balances,
        &(START),"""
text = text.replace(create_call2, create_call2_new)

create_call3 = """        &balances,
        &1_000,
        &(START + 100),"""
create_call3_new = """        &balances,
        &(START + 100),"""
text = text.replace(create_call3, create_call3_new)

with open("contracts/escrow/src/test.rs", "w") as f:
    f.write(text)
