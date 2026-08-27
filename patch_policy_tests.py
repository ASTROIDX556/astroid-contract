import re

with open("contracts/policy/src/test.rs", "r") as f:
    text = f.read()

text = text.replace("""    client.register_policy(
        owner,
        &String::from_str(env, "max_txn"),
        &BytesN::from_array(env, &[42; 32]),
        &1_000_000,
        &None,
        &None,
        &0,
    );""", """    client.register_policy(
        owner,
        &String::from_str(env, "max_txn"),
        &BytesN::from_array(env, &[42; 32]),
        &1_000_000,
        &None,
        &soroban_sdk::vec![env],
        &0,
        &0,
        &0,
    );""")

text = text.replace("""    client.register_policy(
        &owner,
        &String::from_str(&env, "vendor_list"),
        &BytesN::from_array(&env, &[7; 32]),
        &0,
        &Some(allowed.clone()),
        &None,
        &0,
    );""", """    client.register_policy(
        &owner,
        &String::from_str(&env, "vendor_list"),
        &BytesN::from_array(&env, &[7; 32]),
        &0,
        &Some(allowed.clone()),
        &soroban_sdk::vec![&env],
        &0,
        &0,
        &0,
    );""")

with open("contracts/policy/src/test.rs", "w") as f:
    f.write(text)
