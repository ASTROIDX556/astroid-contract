import re

def refactor_wallet(path):
    with open(path, "r") as f:
        text = f.read()

    # require_owner
    text = text.replace("""        if &wallet.owner != caller {
            return Err(Error::Unauthorized);
        }""", "        ensure!(&wallet.owner == caller, Error::Unauthorized);")

    # require_owner_or_admin
    text = text.replace("""        if &wallet.owner != caller && !is_admin {
            return Err(Error::Unauthorized);
        }""", "        ensure!(&wallet.owner == caller || is_admin, Error::Unauthorized);")

    # require_active
    text = text.replace("""    fn require_active(wallet: &WalletData) -> Result<(), Error> {
        match wallet.state {
            ResourceState::Active => Ok(()),
            ResourceState::Frozen => Err(Error::WalletFrozen),
            ResourceState::Paused => Err(Error::WalletPaused),
            ResourceState::Archived => Err(Error::WalletArchived),
        }
    }""", """    fn require_active(wallet: &WalletData) -> Result<(), Error> {
        ensure!(wallet.state != ResourceState::Frozen, Error::WalletFrozen);
        ensure!(wallet.state != ResourceState::Paused, Error::WalletPaused);
        ensure!(wallet.state != ResourceState::Archived, Error::WalletArchived);
        Ok(())
    }""")

    # deposit
    text = text.replace("""        if wallet.state == ResourceState::Archived {
            return Err(Error::WalletArchived);
        }""", "        ensure!(wallet.state != ResourceState::Archived, Error::WalletArchived);")

    # debit
    text = text.replace("""        if current < amount {
            return Err(Error::InsufficientFunds);
        }""", "        ensure!(current >= amount, Error::InsufficientFunds);")

    # unfreeze / unpause
    text = text.replace("""        if wallet.state != ResourceState::Frozen {
            return Err(Error::InvalidState);
        }""", "        ensure!(wallet.state == ResourceState::Frozen, Error::InvalidState);")

    text = text.replace("""        if wallet.state != ResourceState::Paused {
            return Err(Error::InvalidState);
        }""", "        ensure!(wallet.state == ResourceState::Paused, Error::InvalidState);")
        
    text = text.replace("""        if wallet.state != ResourceState::Active {
            return Err(Error::InvalidState);
        }""", "        ensure!(wallet.state == ResourceState::Active, Error::InvalidState);")

    text = text.replace("""        if wallet.state == ResourceState::Archived {
            return Err(Error::WalletArchived);
        }""", "        ensure!(wallet.state != ResourceState::Archived, Error::WalletArchived);")


    with open(path, "w") as f:
        f.write(text)


refactor_wallet("contracts/wallet/src/lib.rs")
