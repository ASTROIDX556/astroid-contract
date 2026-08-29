with open("contracts/proposal/src/test.rs", "r") as f:
    t = f.read()

t = t.replace("""        &threshold,
        &expires_at,
        &0,
    )""", """        &threshold,
        &soroban_sdk::vec![&h.env],
        &expires_at,
        &0,
    )""")

t = t.replace("""        &3,
        &5_000,
        &0,
    );""", """        &3,
        &soroban_sdk::vec![&h.env],
        &5_000,
        &0,
    );""")

t = t.replace("""        &1,
        &500, // in the past (now = 1000)
        &0,
    );""", """        &1,
        &soroban_sdk::vec![&h.env],
        &500, // in the past (now = 1000)
        &0,
    );""")

t = t.replace("""        &2,
        &0,
        &50, // 50 seconds grace period
    );""", """        &2,
        &soroban_sdk::vec![&h.env],
        &0,
        &50, // 50 seconds grace period
    );""")

t = t.replace("""        &2,
        &0,
        &50,
    );""", """        &2,
        &soroban_sdk::vec![&h.env],
        &0,
        &50,
    );""")

with open("contracts/proposal/src/test.rs", "w") as f:
    f.write(t)
