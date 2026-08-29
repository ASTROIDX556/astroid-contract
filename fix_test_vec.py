import re

with open("contracts/proposal/src/test.rs", "r") as f:
    t = f.read()

t = re.sub(r"        &threshold,\n        &expires_at,\n        &expires_at,", r"        &threshold,\n        &soroban_sdk::vec![&h.env],\n        &expires_at,\n        &expires_at,", t)
t = re.sub(r"        &3,\n        &5_000,\n        &expires_at,", r"        &3,\n        &soroban_sdk::vec![&h.env],\n        &5_000,\n        &expires_at,", t)
t = re.sub(r"        &1,\n        &500, // in the past \(now = 1000\)\n        &expires_at,", r"        &1,\n        &soroban_sdk::vec![&h.env],\n        &500, // in the past (now = 1000)\n        &expires_at,", t)
t = re.sub(r"        &2,\n        &expires_at,\n        &0,\n        &50,", r"        &2,\n        &soroban_sdk::vec![&h.env],\n        &expires_at,\n        &0,\n        &50,", t)
t = re.sub(r"        &2,\n        &0,\n        &50,", r"        &2,\n        &soroban_sdk::vec![&h.env],\n        &0,\n        &50,", t)

with open("contracts/proposal/src/test.rs", "w") as f:
    f.write(t)
