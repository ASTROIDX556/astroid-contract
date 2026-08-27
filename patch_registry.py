import re

with open("contracts/registry/src/lib.rs", "r") as f:
    text = f.read()

# Add BytesN to imports
if "BytesN" not in text:
    text = text.replace("Env, String", "BytesN, Env, String")

# Add ApprovedWasm to DataKey
datakey_old = """    /// Emergency freeze status (instance).
    Frozen,
}"""
datakey_new = """    /// Emergency freeze status (instance).
    Frozen,
    /// Approved WASM hashes: (kind, hash) -> bool.
    ApprovedWasm(ModuleKind, BytesN<32>),
}"""
text = text.replace(datakey_old, datakey_new)

# Add the 3 functions after unfreeze
unfreeze_func_end = """        env.events()
            .publish((symbol_short!("registry"), symbol_short!("unfrozen")), org);
        Ok(())
    }"""
wasm_funcs = """

    /// Record an approved WASM hash for a specific module kind.
    pub fn add_approved_wasm(
        env: Env,
        caller: Address,
        kind: ModuleKind,
        wasm_hash: BytesN<32>,
    ) -> Result<(), Error> {
        Self::require_admin(&env, &caller)?;
        let key = DataKey::ApprovedWasm(kind.clone(), wasm_hash.clone());
        env.storage().persistent().set(&key, &true);
        Self::bump(&env, &key);
        env.events().publish(
            (symbol_short!("wasm"), symbol_short!("approved")),
            (kind, wasm_hash),
        );
        Ok(())
    }

    /// Remove/deprecate a previously approved WASM hash.
    pub fn remove_approved_wasm(
        env: Env,
        caller: Address,
        kind: ModuleKind,
        wasm_hash: BytesN<32>,
    ) -> Result<(), Error> {
        Self::require_admin(&env, &caller)?;
        let key = DataKey::ApprovedWasm(kind.clone(), wasm_hash.clone());
        if !env.storage().persistent().has(&key) {
            return Err(Error::NotFound);
        }
        env.storage().persistent().remove(&key);
        env.events().publish(
            (symbol_short!("wasm"), symbol_short!("removed")),
            (kind, wasm_hash),
        );
        Ok(())
    }

    /// Read-only check to see if a WASM hash is approved for a given kind.
    pub fn is_wasm_approved(env: Env, kind: ModuleKind, wasm_hash: BytesN<32>) -> bool {
        let key = DataKey::ApprovedWasm(kind, wasm_hash);
        env.storage().persistent().get(&key).unwrap_or(false)
    }"""
text = text.replace(unfreeze_func_end, unfreeze_func_end + wasm_funcs)

with open("contracts/registry/src/lib.rs", "w") as f:
    f.write(text)
