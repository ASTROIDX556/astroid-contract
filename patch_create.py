import re
with open("contracts/proposal/src/test.rs", "r") as f:
    text = f.read()

text = re.sub(
    r"(&expires_at,\n\s*\))",
    r"&expires_at,\n        &None,\n        &0,\n    )",
    text
)

text = re.sub(
    r"(&5_000,\n\s*\);)",
    r"&5_000,\n        &None,\n        &0,\n    );",
    text
)

text = re.sub(
    r"(&500, // in the past \(now = 1000\)\n\s*\);)",
    r"&500, // in the past (now = 1000)\n        &None,\n        &0,\n    );",
    text
)

with open("contracts/proposal/src/test.rs", "w") as f:
    f.write(text)
