import re

with open("contracts/policy/src/test.rs", "r") as f:
    content = f.read()

# Fix imports
imports_pattern = r"<<<<<<< HEAD\nuse astroid_shared::errors::Error;\nuse soroban_sdk::testutils::Ledger;\nuse soroban_sdk::\{testutils::Address as _, Address, BytesN, Env, String\};\n=======\nuse soroban_sdk::\{\n    testutils::Address as _, testutils::Events, Address, BytesN, Env, IntoVal, String, Symbol, Val,\n\};\n>>>>>>> origin/main"
imports_repl = """use astroid_shared::errors::Error;
use soroban_sdk::testutils::Ledger;
use soroban_sdk::{
    testutils::Address as _, testutils::Events, Address, BytesN, Env, IntoVal, String, Symbol, Val,
};"""
content = re.sub(imports_pattern, imports_repl, content)

# Fix tests
tests_pattern = r"<<<<<<< HEAD\n(fn test_asset_and_window_restrictions\(\) \{.*?\n)\s*=======\n(fn standard_policy_violation_event_emitted\(\) \{.*?\n)>>>>>>> origin/main"
tests_repl = r"\1}\n\n#[test]\n\2"
content = re.sub(tests_pattern, tests_repl, content, flags=re.DOTALL)

with open("contracts/policy/src/test.rs", "w") as f:
    f.write(content)
