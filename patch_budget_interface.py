with open("interfaces/src/lib.rs", "r") as f:
    text = f.read()

text = text.replace("fn consume(env: Env, caller: Address, budget_id: String, amount: i128) -> Result<i128, Error>;", "fn consume(env: Env, caller: Address, budget_id: String, amount: i128) -> Result<i128, Error>;\n    fn release(env: Env, caller: Address, budget_id: String, amount: i128) -> Result<i128, Error>;")

with open("interfaces/src/lib.rs", "w") as f:
    f.write(text)
