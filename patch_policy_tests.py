with open("contracts/policy/src/test.rs", "r") as f:
    text = f.read()

if "use astroid_shared::errors::Error;" not in text:
    text = text.replace("use soroban_sdk::{", "use astroid_shared::errors::Error;\nuse soroban_sdk::{")

with open("contracts/policy/src/test.rs", "w") as f:
    f.write(text)
