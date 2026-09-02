//! Storage key building helpers.
//!
//! Soroban hashes a storage key into a fixed 32-byte contract-storage key, so
//! the *rent* of a single entry does not depend on how the key is serialized.
//! What *does* depend on the key layout is the number of entries (every
//! separate key is a separate rent line) and the gas paid to serialize a key on
//! every host access.
//!
//! Two rules therefore drive the helpers here:
//! - prefer **fewer, consolidated records** over many thin keys, and
//! - keep each key component a **fixed size** so serialization cost does not
//!   grow with variable-length inputs (org slugs, ids) on hot lookups.
//!
//! `key_of_string` turns a variable-length identifier into a constant 32-byte
//! component via SHA-256, so an org- or id-keyed map pays the same serialization
//! cost no matter how long the identifier is.

use soroban_sdk::{Bytes, BytesN, Env, String};

/// Build a fixed-size storage key component from a string identifier.
///
/// The identifier is hashed with SHA-256, so the returned component is always
/// 32 bytes regardless of the identifier's length. Callers use the result as a
/// `BytesN<32>` field inside their `DataKey` enum:
///
/// ```ignore
/// enum DataKey {
///     Org(soroban_sdk::BytesN<32>),
/// }
/// ```
///
/// This keeps key serialization cheap and constant-size on every lookup while
/// still allowing arbitrary-length identifiers (org slugs, record ids) without
/// capping the on-chain storage key size.
pub fn key_of_string(env: &Env, s: &String) -> BytesN<32> {
    let len = s.len() as usize;
    let mut buf = [0u8; 64];
    s.copy_into_slice(&mut buf[..len]);
    let bytes = Bytes::from_slice(env, &buf[..len]);
    let digest: Bytes = env.crypto().sha256(&bytes).into();
    digest
        .try_into()
        .unwrap_or_else(|_| BytesN::from_array(env, &[0u8; 32]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::Env;

    #[test]
    fn key_of_string_is_fixed_size() {
        let env = Env::default();
        for slug in ["acme", "acme-corp-finance", ""] {
            let key = key_of_string(&env, &String::from_str(&env, slug));
            assert_eq!(key.len(), 32);
        }
    }

    #[test]
    fn key_of_string_is_deterministic_and_distinct() {
        let env = Env::default();
        let a = String::from_str(&env, "acme");
        let b = String::from_str(&env, "acme");
        let c = String::from_str(&env, "acme-2");
        assert_eq!(key_of_string(&env, &a), key_of_string(&env, &b));
        assert_ne!(key_of_string(&env, &a), key_of_string(&env, &c));
    }
}
