import re
with open("contracts/proposal/src/test.rs", "r") as f:
    t = f.read()

# I will replace the function create in test.rs to take `deposit: Vec<AssetAmount>` and pass it properly!
t = re.sub(r"fn create\(h: &Harness, threshold: u32, expires_at: u64\) -> u64 \{[\s\S]*?&expires_at,\n    \)", 
"""fn create(h: &Harness, threshold: u32, expires_at: u64) -> u64 {
    h.client.create(
        &h.proposer,
        &String::from_str(&h.env, "acme"),
        &String::from_str(&h.env, "wallet-1"),
        &String::from_str(&h.env, "policy-1"),
        &String::from_str(&h.env, "tx-ref-1"),
        &approver_vec(h),
        &threshold,
        &soroban_sdk::vec![&h.env],
        &expires_at,
        &0,
    )""", t)

t = re.sub(r"    let res = h.client.try_create\([\s\S]*?&5_000,\n        &expires_at,\n    \);",
"""    let res = h.client.try_create(
        &h.proposer,
        &String::from_str(&h.env, "acme"),
        &String::from_str(&h.env, "wallet-1"),
        &String::from_str(&h.env, "policy-1"),
        &String::from_str(&h.env, "tx-ref-1"),
        &approver_vec(&h),
        &3,
        &soroban_sdk::vec![&h.env],
        &5_000,
        &0,
    );""", t)

t = re.sub(r"    let res = h.client.try_create\([\s\S]*?&500, // in the past \(now = 1000\)\n        &expires_at,\n    \);",
"""    let res = h.client.try_create(
        &h.proposer,
        &String::from_str(&h.env, "acme"),
        &String::from_str(&h.env, "wallet-1"),
        &String::from_str(&h.env, "policy-1"),
        &String::from_str(&h.env, "tx-ref-1"),
        &approver_vec(&h),
        &1,
        &soroban_sdk::vec![&h.env],
        &500, // in the past (now = 1000)
        &0,
    );""", t)

t = re.sub(r"    let id = h.client.create\([\s\S]*?&0,\n        &50,\n    \);",
"""    let id = h.client.create(
        &h.proposer,
        &String::from_str(&h.env, "org"),
        &String::from_str(&h.env, "w1"),
        &String::from_str(&h.env, "p1"),
        &String::from_str(&h.env, "tx1"),
        &approver_vec(&h),
        &2,
        &soroban_sdk::vec![&h.env],
        &0,
        &50,
    );""", t, count=1)

t = re.sub(r"    let id2 = h.client.create\([\s\S]*?&0,\n        &50,\n    \);",
"""    let id2 = h.client.create(
        &h.proposer,
        &String::from_str(&h.env, "org"),
        &String::from_str(&h.env, "w1"),
        &String::from_str(&h.env, "p1"),
        &String::from_str(&h.env, "tx1"),
        &approver_vec(&h),
        &2,
        &soroban_sdk::vec![&h.env],
        &0,
        &50,
    );""", t)

with open("contracts/proposal/src/test.rs", "w") as f:
    f.write(t)
