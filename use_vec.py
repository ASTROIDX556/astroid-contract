with open("contracts/proposal/src/lib.rs", "r") as f:
    c = f.read()

import re
c = c.replace("Option<AssetAmount>", "Vec<AssetAmount>")
c = c.replace("token::TokenClient", "")
c = c.replace("use soroban_sdk::{", "use soroban_sdk::{token::TokenClient, ")
c = re.sub(r"if let Some\(dep\) = &deposit \{", r"if let Some(dep) = deposit.first() {", c)
c = re.sub(r"if let Some\(dep\) = &proposal.deposit \{", r"if let Some(dep) = proposal.deposit.first() {", c)

with open("contracts/proposal/src/lib.rs", "w") as f:
    f.write(c)

with open("contracts/proposal/src/test.rs", "r") as f:
    t = f.read()

t = t.replace("&None", "&soroban_sdk::vec![&h.env]")

with open("contracts/proposal/src/test.rs", "w") as f:
    f.write(t)
