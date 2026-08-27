import re

with open("contracts/budget/src/test.rs", "r") as f:
    text = f.read()

text = text.replace("client.allocate(&b_id, &owner, &1000, &astroid_shared::types::Period::None);", "client.allocate(&owner, &b_id, &1000, &astroid_shared::types::Period::None);")

with open("contracts/budget/src/test.rs", "w") as f:
    f.write(text)

with open("contracts/treasury/src/test.rs", "r") as f:
    text = f.read()

text = text.replace("let token = env.register_stellar_asset_contract(admin.clone());", "let token = env.register_stellar_asset_contract_v2(admin.clone()).address();")
text = text.replace("let token_client = token::TokenClient::new(&env, &token);", "let token_admin = token::StellarAssetClient::new(&env, &token);\n    let token_client = token::TokenClient::new(&env, &token);")
text = text.replace("token_client.mint(&admin, &1000);", "token_admin.mint(&admin, &1000);")

with open("contracts/treasury/src/test.rs", "w") as f:
    f.write(text)

