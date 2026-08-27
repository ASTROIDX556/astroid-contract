import re
with open("contracts/escrow/src/test.rs", "r") as f:
    text = f.read()

# Add Map to imports
if "use soroban_sdk::{Map" not in text:
    text = text.replace("use soroban_sdk::{", "use soroban_sdk::{Map, ")

# Update setup to create balances Map
setup_old = """    let mut client = EscrowContractClient::new(&env, &contract_id);
    client.initialize();"""
setup_new = """    let mut client = EscrowContractClient::new(&env, &contract_id);
    client.initialize();
    
    let mut balances = Map::new(&env);
    balances.set(asset.clone(), 1_000);"""
text = text.replace(setup_old, setup_new)

# In test.rs, they likely call create with: `asset.clone(), 1_000, deadline`
# Let's replace those calls:
text = text.replace("""            &h.asset,
            &1_000,""", """            &balances,""")
# sometimes it could be `&h.asset, &1_000`
text = re.sub(r"&h\.asset,\n\s*&1_000,", r"&balances,", text)

# Actually, let's just grep the file and do it precisely.
# Wait, let's write out the text to test.rs first and see.
with open("contracts/escrow/src/test.rs", "w") as f:
    f.write(text)
