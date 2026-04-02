//! Export/import encrypted backup.
//!
//! Backup format: `AIRA` magic (4 bytes) + version (1 byte) + nonce (12 bytes) + ciphertext.
//! The ciphertext is a postcard-serialized `BackupData` encrypted with the storage key.
//!
//! The backup does NOT contain the seed phrase or master key.
//! See SPEC.md §6.10.

use std::path::Path;

use serde::{Deserialize, Serialize};

use redb::ReadableTable;

use crate::encrypted::{decrypt_value, encrypt_value};
use crate::types::{ContactInfo, StoredMessage};
use crate::{Storage, StorageError};

/// Magic bytes identifying an Aira backup file.
const MAGIC: &[u8; 4] = b"AIRA";

/// Current backup format version.
const VERSION: u8 = 1;

/// Contents of a backup file.
#[derive(Debug, Serialize, Deserialize)]
pub struct BackupData {
    /// All contacts.
    pub contacts: Vec<ContactInfo>,
    /// App settings as key-value pairs.
    pub settings: Vec<(String, Vec<u8>)>,
    /// Ratchet states: `(contact_pubkey, encrypted_snapshot_bytes)`.
    pub ratchet_states: Vec<(Vec<u8>, Vec<u8>)>,
    /// Message history (optional, can be large).
    pub messages: Vec<(u64, StoredMessage)>,
}

/// Export the database to an encrypted backup file.
///
/// # Arguments
///
/// * `storage` — database handle
/// * `path` — output file path (typically `*.aira.enc`)
/// * `include_messages` — whether to include message history
///
/// # Errors
///
/// Returns [`StorageError`] on database, encryption, or I/O failure.
pub fn export(storage: &Storage, path: &Path, include_messages: bool) -> Result<(), StorageError> {
    let contacts = crate::contacts::list(storage)?;

    // Collect settings
    let settings = {
        let txn = storage.db().begin_read()?;
        let table = txn.open_table(crate::SETTINGS)?;
        let mut pairs = Vec::new();
        for entry in table.iter()? {
            let (key, value) = entry?;
            // Store raw encrypted values — they'll be re-encrypted in the backup blob
            let decrypted = decrypt_value(storage.key(), value.value())?;
            pairs.push((key.value().to_string(), decrypted));
        }
        pairs
    };

    // Collect ratchet states (store as raw decrypted snapshots)
    let ratchet_states = {
        let txn = storage.db().begin_read()?;
        let table = txn.open_table(crate::SESSIONS)?;
        let mut states = Vec::new();
        for entry in table.iter()? {
            let (key, value) = entry?;
            let decrypted = decrypt_value(storage.key(), value.value())?;
            states.push((key.value().to_vec(), decrypted));
        }
        states
    };

    // Collect messages if requested
    let messages = if include_messages {
        let txn = storage.db().begin_read()?;
        let table = txn.open_table(crate::MESSAGES)?;
        let mut msgs = Vec::new();
        for entry in table.iter()? {
            let (key, value) = entry?;
            let (contact_id, _ts) = key.value();
            let decrypted = decrypt_value(storage.key(), value.value())?;
            let msg: StoredMessage = postcard::from_bytes(&decrypted)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            msgs.push((contact_id, msg));
        }
        msgs
    } else {
        Vec::new()
    };

    let data = BackupData {
        contacts,
        settings,
        ratchet_states,
        messages,
    };

    let serialized =
        postcard::to_allocvec(&data).map_err(|e| StorageError::Serialization(e.to_string()))?;
    let encrypted = encrypt_value(storage.key(), &serialized)?;

    // Write: MAGIC + VERSION + encrypted blob (which contains nonce + ciphertext)
    let mut file_data = Vec::with_capacity(5 + encrypted.len());
    file_data.extend_from_slice(MAGIC);
    file_data.push(VERSION);
    file_data.extend_from_slice(&encrypted);

    std::fs::write(path, &file_data)?;
    Ok(())
}

/// Import a backup file, returning the parsed data.
///
/// The caller must provide the storage key (derived from the seed phrase).
/// This function only reads and decrypts — it does NOT write to the database.
/// The caller is responsible for merging/replacing data.
///
/// # Errors
///
/// Returns [`StorageError::Backup`] if the file format is invalid.
/// Returns [`StorageError::Decryption`] if the key is wrong.
pub fn import(path: &Path, storage_key: &[u8; 32]) -> Result<BackupData, StorageError> {
    let file_data = std::fs::read(path)?;

    if file_data.len() < 5 {
        return Err(StorageError::Backup("file too short".into()));
    }

    if &file_data[..4] != MAGIC {
        return Err(StorageError::Backup("invalid magic bytes".into()));
    }

    if file_data[4] != VERSION {
        return Err(StorageError::Backup(format!(
            "unsupported version: {}",
            file_data[4]
        )));
    }

    let encrypted = &file_data[5..];
    let decrypted = decrypt_value(storage_key, encrypted)?;

    postcard::from_bytes(&decrypted).map_err(|e| StorageError::Serialization(e.to_string()))
}

/// Restore backup data into a storage instance.
///
/// This overwrites existing contacts, settings, and sessions.
/// Messages are appended (not deduplicated).
///
/// # Errors
///
/// Returns [`StorageError`] on database or encryption failure.
pub fn restore(storage: &Storage, data: &BackupData) -> Result<(), StorageError> {
    // Restore contacts
    for contact in &data.contacts {
        let serialized = postcard::to_allocvec(contact)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        let encrypted = encrypt_value(storage.key(), &serialized)?;

        let txn = storage.db().begin_write()?;
        {
            let mut table = txn.open_table(crate::CONTACTS)?;
            table.insert(contact.pubkey.as_slice(), encrypted.as_slice())?;
        }
        txn.commit()?;
    }

    // Restore settings
    for (key, value) in &data.settings {
        crate::settings::set(storage, key, value)?;
    }

    // Restore ratchet states
    for (pubkey, snapshot) in &data.ratchet_states {
        crate::sessions::save(storage, pubkey, snapshot)?;
    }

    // Restore messages
    for (contact_id, msg) in &data.messages {
        crate::messages::store(storage, *contact_id, msg)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::temp_storage;

    #[test]
    fn export_import_roundtrip() {
        let storage = temp_storage();

        // Add some data
        crate::contacts::add(&storage, b"pk-backup-test-alice-32-bytes!!!", "Alice").expect("add");
        crate::settings::set(&storage, "relay/url", b"https://relay.example.com").expect("set");
        crate::sessions::save(
            &storage,
            b"pk-backup-test-alice-32-bytes!!!",
            b"ratchet-snapshot",
        )
        .expect("save session");

        let msg = StoredMessage {
            id: [0x42; 16],
            sender_is_self: true,
            payload_bytes: b"hello".to_vec(),
            timestamp_micros: 1_000_000,
            ttl_secs: None,
            read_at: None,
            expires_at: None,
        };
        let cid = crate::types::contact_id(b"pk-backup-test-alice-32-bytes!!!");
        crate::messages::store(&storage, cid, &msg).expect("store message");

        // Export
        let backup_path = std::env::temp_dir().join(format!(
            "aira-backup-test-{}.aira.enc",
            rand::random::<u64>()
        ));
        export(&storage, &backup_path, true).expect("export");

        // Import
        let data = import(&backup_path, storage.key()).expect("import");
        assert_eq!(data.contacts.len(), 1);
        assert_eq!(data.contacts[0].alias, "Alice");
        assert_eq!(data.settings.len(), 1);
        assert_eq!(data.ratchet_states.len(), 1);
        assert_eq!(data.messages.len(), 1);
        assert_eq!(data.messages[0].1.id, [0x42; 16]);

        // Cleanup
        let _ = std::fs::remove_file(&backup_path);
    }

    #[test]
    fn export_without_messages() {
        let storage = temp_storage();
        crate::contacts::add(&storage, b"pk-no-msg-backup-test-32-bytes!", "Bob").expect("add");

        let msg = StoredMessage {
            id: [0x01; 16],
            sender_is_self: false,
            payload_bytes: b"msg".to_vec(),
            timestamp_micros: 1_000,
            ttl_secs: None,
            read_at: None,
            expires_at: None,
        };
        let cid = crate::types::contact_id(b"pk-no-msg-backup-test-32-bytes!");
        crate::messages::store(&storage, cid, &msg).expect("store");

        let backup_path =
            std::env::temp_dir().join(format!("aira-no-msg-{}.aira.enc", rand::random::<u64>()));
        export(&storage, &backup_path, false).expect("export");

        let data = import(&backup_path, storage.key()).expect("import");
        assert_eq!(data.contacts.len(), 1);
        assert!(data.messages.is_empty());

        let _ = std::fs::remove_file(&backup_path);
    }

    #[test]
    fn import_wrong_key_fails() {
        let storage = temp_storage();
        crate::contacts::add(&storage, b"pk-wrong-key-test-pad-32-bytes!", "Carol").expect("add");

        let backup_path =
            std::env::temp_dir().join(format!("aira-wrongkey-{}.aira.enc", rand::random::<u64>()));
        export(&storage, &backup_path, false).expect("export");

        let wrong_key = [0xFF; 32];
        assert!(import(&backup_path, &wrong_key).is_err());

        let _ = std::fs::remove_file(&backup_path);
    }

    #[test]
    fn import_invalid_file_fails() {
        let path =
            std::env::temp_dir().join(format!("aira-invalid-{}.aira.enc", rand::random::<u64>()));
        std::fs::write(&path, b"not a backup").expect("write");

        let key = [0x42; 32];
        assert!(import(&path, &key).is_err());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn restore_backup() {
        let storage1 = temp_storage();
        crate::contacts::add(&storage1, b"pk-restore-test-pad-to-32bytes!", "Dave").expect("add");
        crate::settings::set(&storage1, "lang", b"ru").expect("set");

        let backup_path =
            std::env::temp_dir().join(format!("aira-restore-{}.aira.enc", rand::random::<u64>()));
        export(&storage1, &backup_path, false).expect("export");

        // Import into a fresh storage
        let storage2 = temp_storage();
        let data = import(&backup_path, storage1.key()).expect("import");

        // Restore needs the same key — create storage2 with same key
        let dir2 = std::env::temp_dir().join(format!("aira-restore2-{}", rand::random::<u64>()));
        let storage2_same_key =
            Storage::open(&dir2, zeroize::Zeroizing::new(*storage1.key())).expect("open");
        restore(&storage2_same_key, &data).expect("restore");

        let contacts = crate::contacts::list(&storage2_same_key).expect("list");
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].alias, "Dave");

        let _ = std::fs::remove_file(&backup_path);
        drop(storage2);
    }
}
