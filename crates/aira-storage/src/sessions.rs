//! Ratchet state persistence (encrypted with storage key).
//!
//! Ratchet states are critical secrets — encryption is mandatory.
//! Key: contact public key bytes.
//! Value: serialized ratchet snapshot, encrypted with storage key.

use redb::ReadableTable;

use crate::encrypted::{decrypt_value, encrypt_value};
use crate::{Storage, StorageError, SESSIONS};

/// Save a ratchet state for a contact.
///
/// The `snapshot_bytes` should be a postcard-serialized `RatchetSnapshot`.
/// It will be encrypted before storage.
///
/// # Errors
///
/// Returns [`StorageError`] on database or encryption failure.
pub fn save(
    storage: &Storage,
    contact_pubkey: &[u8],
    snapshot_bytes: &[u8],
) -> Result<(), StorageError> {
    let encrypted = encrypt_value(storage.key(), snapshot_bytes)?;

    let txn = storage.db().begin_write()?;
    {
        let mut table = txn.open_table(SESSIONS)?;
        table.insert(contact_pubkey, encrypted.as_slice())?;
    }
    txn.commit()?;
    Ok(())
}

/// Load a ratchet state for a contact.
///
/// Returns `None` if no session exists for this contact.
/// Returns raw decrypted bytes — caller deserializes to `RatchetSnapshot`.
///
/// # Errors
///
/// Returns [`StorageError`] on database or decryption failure.
pub fn load(storage: &Storage, contact_pubkey: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
    let txn = storage.db().begin_read()?;
    let table = txn.open_table(SESSIONS)?;

    match table.get(contact_pubkey)? {
        Some(entry) => {
            let decrypted = decrypt_value(storage.key(), entry.value())?;
            Ok(Some(decrypted))
        }
        None => Ok(None),
    }
}

/// Remove a ratchet state for a contact.
///
/// # Errors
///
/// Returns [`StorageError`] on database failure.
pub fn remove(storage: &Storage, contact_pubkey: &[u8]) -> Result<(), StorageError> {
    let txn = storage.db().begin_write()?;
    {
        let mut table = txn.open_table(SESSIONS)?;
        table.remove(contact_pubkey)?;
    }
    txn.commit()?;
    Ok(())
}

/// List all contact public keys that have saved sessions.
///
/// # Errors
///
/// Returns [`StorageError`] on database failure.
pub fn list_contacts(storage: &Storage) -> Result<Vec<Vec<u8>>, StorageError> {
    let txn = storage.db().begin_read()?;
    let table = txn.open_table(SESSIONS)?;

    let mut keys = Vec::new();
    for entry in table.iter()? {
        let (key, _) = entry?;
        keys.push(key.value().to_vec());
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::temp_storage;

    #[test]
    fn save_and_load_session() {
        let storage = temp_storage();
        let pk = b"contact-pubkey-for-session-test!";
        let snapshot = b"serialized-ratchet-snapshot-data";

        save(&storage, pk, snapshot).expect("save");
        let loaded = load(&storage, pk).expect("load");

        assert_eq!(loaded.as_deref(), Some(snapshot.as_slice()));
    }

    #[test]
    fn load_nonexistent_returns_none() {
        let storage = temp_storage();
        let loaded = load(&storage, b"no-such-contact").expect("load");
        assert!(loaded.is_none());
    }

    #[test]
    fn save_overwrites_existing() {
        let storage = temp_storage();
        let pk = b"contact-pubkey-overwrite-test!!!";

        save(&storage, pk, b"old-state").expect("save 1");
        save(&storage, pk, b"new-state").expect("save 2");

        let loaded = load(&storage, pk).expect("load");
        assert_eq!(loaded.as_deref(), Some(b"new-state".as_slice()));
    }

    #[test]
    fn remove_session() {
        let storage = temp_storage();
        let pk = b"contact-pubkey-remove-test-here!";

        save(&storage, pk, b"state").expect("save");
        remove(&storage, pk).expect("remove");

        let loaded = load(&storage, pk).expect("load");
        assert!(loaded.is_none());
    }

    #[test]
    fn list_session_contacts() {
        let storage = temp_storage();
        save(&storage, b"pk1-session-list-test-aaaa-12345", b"s1").expect("save");
        save(&storage, b"pk2-session-list-test-bbbb-67890", b"s2").expect("save");

        let contacts = list_contacts(&storage).expect("list");
        assert_eq!(contacts.len(), 2);
    }

    #[test]
    fn session_data_is_encrypted_at_rest() {
        let storage = temp_storage();
        let pk = b"pk-encryption-verification-test!";
        let snapshot = b"secret-ratchet-state-12345";

        save(&storage, pk, snapshot).expect("save");

        // Read raw value from DB — should NOT contain plaintext
        let txn = storage.db().begin_read().expect("read");
        let table = txn.open_table(crate::SESSIONS).expect("table");
        let raw = table.get(pk.as_slice()).expect("get").expect("exists");
        let raw_bytes = raw.value();

        // Raw bytes must not contain the plaintext
        assert!(!raw_bytes.windows(snapshot.len()).any(|w| w == snapshot));
    }
}
