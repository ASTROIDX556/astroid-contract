import re

def refactor_file(path):
    with open(path, "r") as f:
        text = f.read()

    # Add macro import
    if "astroid_shared::ensure" not in text:
        text = text.replace("use astroid_shared::errors::Error;", "use astroid_shared::errors::Error;\nuse astroid_shared::ensure;")
    
    # Replace single `if cond { return Err(...) }` with `ensure!(!cond, Err)`
    
    # Let's replace manually for safety!
    if "registry" in path:
        text = text.replace("""        if env
            .storage()
            .instance()
            .get::<_, bool>(&DataKey::Frozen)
            .unwrap_or(false)
        {
            return Err(Error::RegistryFrozen);
        }""", """        ensure!(!env
            .storage()
            .instance()
            .get::<_, bool>(&DataKey::Frozen)
            .unwrap_or(false), Error::RegistryFrozen);""")
        text = text.replace("""        if version == 0 {
            return Err(Error::InvalidInput);
        }""", "        ensure!(version != 0, Error::InvalidInput);")
        text = text.replace("""        if owner != caller && !Self::is_admin(&env, &caller) {
            return Err(Error::Unauthorized);
        }""", "        ensure!(owner == caller || Self::is_admin(&env, &caller), Error::Unauthorized);")
        text = text.replace("""        if &admin != caller {
            return Err(Error::Unauthorized);
        }""", "        ensure!(&admin == caller, Error::Unauthorized);")
        text = text.replace("""        if !env.storage().persistent().has(&key) {
            return Err(Error::NotFound);
        }""", "        ensure!(env.storage().persistent().has(&key), Error::NotFound);")
        
    elif "wallet" in path:
        text = text.replace("""        if amount <= 0 {
            return Err(Error::InvalidAmount);
        }""", "        ensure!(amount > 0, Error::InvalidAmount);")
        text = text.replace("""        if w.owner != caller {
            return Err(Error::Unauthorized);
        }""", "        ensure!(w.owner == caller, Error::Unauthorized);")
        text = text.replace("""        if amount > w.balances.get(token.clone()).unwrap_or(0) {
            return Err(Error::InsufficientFunds);
        }""", "        ensure!(amount <= w.balances.get(token.clone()).unwrap_or(0), Error::InsufficientFunds);")
        text = text.replace("""        if w.state != ResourceState::Frozen {
            return Err(Error::InvalidState);
        }""", "        ensure!(w.state == ResourceState::Frozen, Error::InvalidState);")

    with open(path, "w") as f:
        f.write(text)

refactor_file("contracts/registry/src/lib.rs")
refactor_file("contracts/wallet/src/lib.rs")
