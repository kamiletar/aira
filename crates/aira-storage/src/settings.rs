//! App settings (TTL defaults, relay URL, transport mode, language, etc.).
//!
//! Key: string identifier (e.g., "ttl/default", "relay/url").
//! Value: postcard-serialized bytes, encrypted with storage key.

use crate::encrypted::{decrypt_value, encrypt_value};
use crate::{Storage, StorageError, SETTINGS};

/// Get a setting value by key.
///
/// Returns `None` if the key does not exist.
///
/// # Errors
///
/// Returns [`StorageError`] on database or decryption failure.
pub fn get(storage: &Storage, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
    let txn = storage.db().begin_read()?;
    let table = txn.open_table(SETTINGS)?;

    match table.get(key)? {
        Some(entry) => {
            let decrypted = decrypt_value(storage.key(), entry.value())?;
            Ok(Some(decrypted))
        }
        None => Ok(None),
    }
}

/// Set a setting value.
///
/// # Errors
///
/// Returns [`StorageError`] on database or encryption failure.
pub fn set(storage: &Storage, key: &str, value: &[u8]) -> Result<(), StorageError> {
    let encrypted = encrypt_value(storage.key(), value)?;

    let txn = storage.db().begin_write()?;
    {
        let mut table = txn.open_table(SETTINGS)?;
        table.insert(key, encrypted.as_slice())?;
    }
    txn.commit()?;
    Ok(())
}

/// Remove a setting.
///
/// # Errors
///
/// Returns [`StorageError`] on database failure.
pub fn remove(storage: &Storage, key: &str) -> Result<(), StorageError> {
    let txn = storage.db().begin_write()?;
    {
        let mut table = txn.open_table(SETTINGS)?;
        table.remove(key)?;
    }
    txn.commit()?;
    Ok(())
}

/// Get the disappearing message TTL for a contact.
///
/// Returns `None` if no per-contact TTL is set (use default).
/// The value is stored as a postcard-encoded `Option<u64>` (seconds).
///
/// # Errors
///
/// Returns [`StorageError`] on database or decryption failure.
pub fn get_ttl(storage: &Storage, contact_pubkey: &[u8]) -> Result<Option<u64>, StorageError> {
    let key = format!("ttl/{}", hex::encode(contact_pubkey));
    match get(storage, &key)? {
        Some(bytes) => {
            let ttl: Option<u64> = postcard::from_bytes(&bytes)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            Ok(ttl)
        }
        None => Ok(None),
    }
}

/// Set the disappearing message TTL for a contact.
///
/// Pass `None` to disable disappearing messages for this contact.
///
/// # Errors
///
/// Returns [`StorageError`] on database or encryption failure.
pub fn set_ttl(
    storage: &Storage,
    contact_pubkey: &[u8],
    ttl_secs: Option<u64>,
) -> Result<(), StorageError> {
    let key = format!("ttl/{}", hex::encode(contact_pubkey));
    let bytes =
        postcard::to_allocvec(&ttl_secs).map_err(|e| StorageError::Serialization(e.to_string()))?;
    set(storage, &key, &bytes)
}

/// Simple hex encoding (no external dependency needed).
mod hex {
    use std::fmt::Write;

    pub fn encode(data: &[u8]) -> String {
        let mut s = String::with_capacity(data.len() * 2);
        for b in data {
            let _ = write!(s, "{b:02x}");
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::temp_storage;

    #[test]
    fn get_nonexistent_returns_none() {
        let storage = temp_storage();
        assert!(get(&storage, "no-such-key").expect("get").is_none());
    }

    #[test]
    fn set_and_get() {
        let storage = temp_storage();
        set(&storage, "relay/url", b"https://relay.aira.dev").expect("set");
        let value = get(&storage, "relay/url").expect("get").expect("exists");
        assert_eq!(value, b"https://relay.aira.dev");
    }

    #[test]
    fn set_overwrites() {
        let storage = temp_storage();
        set(&storage, "key", b"old").expect("set 1");
        set(&storage, "key", b"new").expect("set 2");
        let value = get(&storage, "key").expect("get").expect("exists");
        assert_eq!(value, b"new");
    }

    #[test]
    fn remove_setting() {
        let storage = temp_storage();
        set(&storage, "temp", b"value").expect("set");
        remove(&storage, "temp").expect("remove");
        assert!(get(&storage, "temp").expect("get").is_none());
    }

    #[test]
    fn ttl_per_contact() {
        let storage = temp_storage();
        let pk = b"contact-pk-for-ttl-test";

        // No TTL set initially
        assert!(get_ttl(&storage, pk).expect("get ttl").is_none());

        // Set TTL to 1 hour
        set_ttl(&storage, pk, Some(3600)).expect("set ttl");
        assert_eq!(get_ttl(&storage, pk).expect("get ttl"), Some(3600));

        // Disable TTL
        set_ttl(&storage, pk, None).expect("set ttl none");
        // None TTL is stored as a serialized None, which is distinct from "not set"
        // Both return None from get_ttl, which is correct behavior
    }
}
