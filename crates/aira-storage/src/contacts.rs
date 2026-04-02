//! Contact list CRUD operations.
//!
//! Key: ML-DSA public key bytes.
//! Value: `ContactInfo` serialized with postcard, then encrypted with storage key.

use redb::ReadableTable;

use crate::encrypted::{decrypt_value, encrypt_value};
use crate::types::ContactInfo;
use crate::{Storage, StorageError, CONTACTS};

/// Add a new contact.
///
/// # Errors
///
/// Returns [`StorageError`] on database or encryption failure.
pub fn add(storage: &Storage, pubkey: &[u8], alias: &str) -> Result<(), StorageError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let info = ContactInfo {
        pubkey: pubkey.to_vec(),
        alias: alias.to_string(),
        added_at: now,
        verified: false,
        blocked: false,
    };

    let serialized =
        postcard::to_allocvec(&info).map_err(|e| StorageError::Serialization(e.to_string()))?;
    let encrypted = encrypt_value(storage.key(), &serialized)?;

    let txn = storage.db().begin_write()?;
    {
        let mut table = txn.open_table(CONTACTS)?;
        table.insert(pubkey, encrypted.as_slice())?;
    }
    txn.commit()?;
    Ok(())
}

/// Get a contact by public key.
///
/// # Errors
///
/// Returns [`StorageError::ContactNotFound`] if the contact does not exist.
pub fn get(storage: &Storage, pubkey: &[u8]) -> Result<ContactInfo, StorageError> {
    let txn = storage.db().begin_read()?;
    let table = txn.open_table(CONTACTS)?;

    let entry = table.get(pubkey)?.ok_or(StorageError::ContactNotFound)?;

    let decrypted = decrypt_value(storage.key(), entry.value())?;
    postcard::from_bytes(&decrypted).map_err(|e| StorageError::Serialization(e.to_string()))
}

/// List all contacts.
///
/// # Errors
///
/// Returns [`StorageError`] on database or decryption failure.
pub fn list(storage: &Storage) -> Result<Vec<ContactInfo>, StorageError> {
    let txn = storage.db().begin_read()?;
    let table = txn.open_table(CONTACTS)?;

    let mut contacts = Vec::new();
    for entry in table.iter()? {
        let (_, value) = entry?;
        let decrypted = decrypt_value(storage.key(), value.value())?;
        let info: ContactInfo = postcard::from_bytes(&decrypted)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        contacts.push(info);
    }
    Ok(contacts)
}

/// Remove a contact by public key.
///
/// # Errors
///
/// Returns [`StorageError`] on database failure. No error if contact doesn't exist.
pub fn remove(storage: &Storage, pubkey: &[u8]) -> Result<(), StorageError> {
    let txn = storage.db().begin_write()?;
    {
        let mut table = txn.open_table(CONTACTS)?;
        table.remove(pubkey)?;
    }
    txn.commit()?;
    Ok(())
}

/// Update a contact's alias.
///
/// # Errors
///
/// Returns [`StorageError::ContactNotFound`] if the contact does not exist.
pub fn update_alias(storage: &Storage, pubkey: &[u8], alias: &str) -> Result<(), StorageError> {
    let mut info = get(storage, pubkey)?;
    info.alias = alias.to_string();

    let serialized =
        postcard::to_allocvec(&info).map_err(|e| StorageError::Serialization(e.to_string()))?;
    let encrypted = encrypt_value(storage.key(), &serialized)?;

    let txn = storage.db().begin_write()?;
    {
        let mut table = txn.open_table(CONTACTS)?;
        table.insert(pubkey, encrypted.as_slice())?;
    }
    txn.commit()?;
    Ok(())
}

/// Set a contact's verified status.
///
/// # Errors
///
/// Returns [`StorageError::ContactNotFound`] if the contact does not exist.
pub fn set_verified(storage: &Storage, pubkey: &[u8], verified: bool) -> Result<(), StorageError> {
    let mut info = get(storage, pubkey)?;
    info.verified = verified;

    let serialized =
        postcard::to_allocvec(&info).map_err(|e| StorageError::Serialization(e.to_string()))?;
    let encrypted = encrypt_value(storage.key(), &serialized)?;

    let txn = storage.db().begin_write()?;
    {
        let mut table = txn.open_table(CONTACTS)?;
        table.insert(pubkey, encrypted.as_slice())?;
    }
    txn.commit()?;
    Ok(())
}

/// Set a contact's blocked status.
///
/// # Errors
///
/// Returns [`StorageError::ContactNotFound`] if the contact does not exist.
pub fn set_blocked(storage: &Storage, pubkey: &[u8], blocked: bool) -> Result<(), StorageError> {
    let mut info = get(storage, pubkey)?;
    info.blocked = blocked;

    let serialized =
        postcard::to_allocvec(&info).map_err(|e| StorageError::Serialization(e.to_string()))?;
    let encrypted = encrypt_value(storage.key(), &serialized)?;

    let txn = storage.db().begin_write()?;
    {
        let mut table = txn.open_table(CONTACTS)?;
        table.insert(pubkey, encrypted.as_slice())?;
    }
    txn.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::temp_storage;

    #[test]
    fn add_and_get_contact() {
        let storage = temp_storage();
        let pk = b"alice-pubkey-bytes-here-32bytes!!";

        add(&storage, pk, "Alice").expect("add");
        let info = get(&storage, pk).expect("get");

        assert_eq!(info.alias, "Alice");
        assert!(!info.verified);
        assert!(!info.blocked);
        assert_eq!(info.pubkey, pk.to_vec());
    }

    #[test]
    fn get_nonexistent_returns_not_found() {
        let storage = temp_storage();
        let result = get(&storage, b"no-such-key");
        assert!(matches!(result, Err(StorageError::ContactNotFound)));
    }

    #[test]
    fn list_contacts() {
        let storage = temp_storage();
        add(&storage, b"pk1-aaaabbbbccccddddeeeeffffggg1", "Alice").expect("add");
        add(&storage, b"pk2-aaaabbbbccccddddeeeeffffggg2", "Bob").expect("add");

        let contacts = list(&storage).expect("list");
        assert_eq!(contacts.len(), 2);

        let aliases: Vec<&str> = contacts.iter().map(|c| c.alias.as_str()).collect();
        assert!(aliases.contains(&"Alice"));
        assert!(aliases.contains(&"Bob"));
    }

    #[test]
    fn remove_contact() {
        let storage = temp_storage();
        let pk = b"pk-to-remove-padded-32-bytes!!!!";
        add(&storage, pk, "ToRemove").expect("add");
        remove(&storage, pk).expect("remove");
        assert!(matches!(
            get(&storage, pk),
            Err(StorageError::ContactNotFound)
        ));
    }

    #[test]
    fn update_alias_works() {
        let storage = temp_storage();
        let pk = b"pk-alias-test-padded-32-bytes!!!";
        add(&storage, pk, "OldName").expect("add");
        update_alias(&storage, pk, "NewName").expect("update");
        let info = get(&storage, pk).expect("get");
        assert_eq!(info.alias, "NewName");
    }

    #[test]
    fn set_verified_works() {
        let storage = temp_storage();
        let pk = b"pk-verify-test-padded-32-bytes!!";
        add(&storage, pk, "Contact").expect("add");
        set_verified(&storage, pk, true).expect("set verified");
        let info = get(&storage, pk).expect("get");
        assert!(info.verified);
    }

    #[test]
    fn set_blocked_works() {
        let storage = temp_storage();
        let pk = b"pk-block-test-padded-32-bytesXX!";
        add(&storage, pk, "Contact").expect("add");
        set_blocked(&storage, pk, true).expect("set blocked");
        let info = get(&storage, pk).expect("get");
        assert!(info.blocked);
    }
}
