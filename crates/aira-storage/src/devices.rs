//! Device persistence — CRUD for linked devices and sync log.
//!
//! Devices are stored encrypted in the `devices` table.
//! Sync log entries track synchronization history per device.

use redb::ReadableTable;

use crate::encrypted::{decrypt_value, encrypt_value};
use crate::types::device_id_hash;
use crate::{Storage, StorageError, DEVICES, SYNC_LOG};

// ─── Device CRUD ────────────────────────────────────────────────────────────

/// Save (or update) a device.
///
/// The `device_bytes` should be a postcard-serialized `DeviceInfo`.
/// It will be encrypted before storage.
///
/// # Errors
///
/// Returns [`StorageError`] on database or encryption failure.
pub fn save_device(
    storage: &Storage,
    device_id: &[u8; 32],
    device_bytes: &[u8],
) -> Result<(), StorageError> {
    let encrypted = encrypt_value(storage.key(), device_bytes)?;

    let txn = storage.db().begin_write()?;
    {
        let mut table = txn.open_table(DEVICES)?;
        table.insert(device_id.as_slice(), encrypted.as_slice())?;
    }
    txn.commit()?;
    Ok(())
}

/// Load a device by ID.
///
/// Returns `None` if no device exists with this ID.
///
/// # Errors
///
/// Returns [`StorageError`] on database or decryption failure.
pub fn load_device(
    storage: &Storage,
    device_id: &[u8; 32],
) -> Result<Option<Vec<u8>>, StorageError> {
    let txn = storage.db().begin_read()?;
    let table = txn.open_table(DEVICES)?;

    match table.get(device_id.as_slice())? {
        Some(entry) => {
            let decrypted = decrypt_value(storage.key(), entry.value())?;
            Ok(Some(decrypted))
        }
        None => Ok(None),
    }
}

/// List all stored device IDs.
///
/// # Errors
///
/// Returns [`StorageError`] on database failure.
pub fn list_device_ids(storage: &Storage) -> Result<Vec<[u8; 32]>, StorageError> {
    let txn = storage.db().begin_read()?;
    let table = txn.open_table(DEVICES)?;

    let mut ids = Vec::new();
    for entry in table.iter()? {
        let (key, _) = entry?;
        let bytes = key.value();
        if bytes.len() == 32 {
            let mut id = [0u8; 32];
            id.copy_from_slice(bytes);
            ids.push(id);
        }
    }
    Ok(ids)
}

/// A device entry: `(device_id, serialized_device_bytes)`.
pub type DeviceEntry = ([u8; 32], Vec<u8>);

/// Load all devices (decrypted bytes).
///
/// Returns a list of `(device_id, device_bytes)` tuples.
///
/// # Errors
///
/// Returns [`StorageError`] on database or decryption failure.
pub fn list_devices(storage: &Storage) -> Result<Vec<DeviceEntry>, StorageError> {
    let txn = storage.db().begin_read()?;
    let table = txn.open_table(DEVICES)?;

    let mut result = Vec::new();
    for entry in table.iter()? {
        let (key, val) = entry?;
        let bytes = key.value();
        if bytes.len() == 32 {
            let mut id = [0u8; 32];
            id.copy_from_slice(bytes);
            let decrypted = decrypt_value(storage.key(), val.value())?;
            result.push((id, decrypted));
        }
    }
    Ok(result)
}

/// Remove a device by ID.
///
/// # Errors
///
/// Returns [`StorageError`] on database failure.
pub fn remove_device(storage: &Storage, device_id: &[u8; 32]) -> Result<(), StorageError> {
    let txn = storage.db().begin_write()?;
    {
        let mut table = txn.open_table(DEVICES)?;
        table.remove(device_id.as_slice())?;
    }
    txn.commit()?;
    Ok(())
}

// ─── Sync log ───────────────────────────────────────────────────────────────

/// Save a sync log entry.
///
/// The `entry_bytes` should be a postcard-serialized `SyncLogEntry`.
///
/// # Errors
///
/// Returns [`StorageError`] on database or encryption failure.
pub fn save_sync_entry(
    storage: &Storage,
    device_id: &[u8; 32],
    timestamp: u64,
    entry_bytes: &[u8],
) -> Result<(), StorageError> {
    let encrypted = encrypt_value(storage.key(), entry_bytes)?;
    let hash = device_id_hash(device_id);

    let txn = storage.db().begin_write()?;
    {
        let mut table = txn.open_table(SYNC_LOG)?;
        table.insert((hash, timestamp), encrypted.as_slice())?;
    }
    txn.commit()?;
    Ok(())
}

/// Get sync log entries for a device after a given timestamp.
///
/// # Errors
///
/// Returns [`StorageError`] on database or decryption failure.
pub fn get_sync_entries_since(
    storage: &Storage,
    device_id: &[u8; 32],
    since_timestamp: u64,
) -> Result<Vec<Vec<u8>>, StorageError> {
    let hash = device_id_hash(device_id);
    let txn = storage.db().begin_read()?;
    let table = txn.open_table(SYNC_LOG)?;

    let range_start = (hash, since_timestamp);
    let range_end = (hash, u64::MAX);

    let mut entries = Vec::new();
    for entry in table.range(range_start..=range_end)? {
        let (key, val) = entry?;
        // Verify hash matches (range may include collisions)
        if key.value().0 == hash {
            let decrypted = decrypt_value(storage.key(), val.value())?;
            entries.push(decrypted);
        }
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::temp_storage;

    #[test]
    fn save_and_load_device() {
        let storage = temp_storage();
        let id = [0xAA; 32];
        let data = b"serialized-device-info-bytes!!!!";

        save_device(&storage, &id, data).expect("save");
        let loaded = load_device(&storage, &id).expect("load");
        assert_eq!(loaded.as_deref(), Some(data.as_slice()));
    }

    #[test]
    fn load_nonexistent_device_returns_none() {
        let storage = temp_storage();
        let loaded = load_device(&storage, &[0xFF; 32]).expect("load");
        assert!(loaded.is_none());
    }

    #[test]
    fn save_overwrites_device() {
        let storage = temp_storage();
        let id = [0xBB; 32];

        save_device(&storage, &id, b"old-info-00000000000000000000000").expect("save 1");
        save_device(&storage, &id, b"new-info-00000000000000000000000").expect("save 2");

        let loaded = load_device(&storage, &id).expect("load");
        assert_eq!(
            loaded.as_deref(),
            Some(b"new-info-00000000000000000000000".as_slice())
        );
    }

    #[test]
    fn list_device_ids_works() {
        let storage = temp_storage();
        save_device(&storage, &[0x01; 32], b"device-1-info-bytes-padding-here").expect("save");
        save_device(&storage, &[0x02; 32], b"device-2-info-bytes-padding-here").expect("save");

        let ids = list_device_ids(&storage).expect("list");
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&[0x01; 32]));
        assert!(ids.contains(&[0x02; 32]));
    }

    #[test]
    fn list_devices_returns_decrypted() {
        let storage = temp_storage();
        let data1 = b"device-1-info-bytes-abcdefghijkl";
        let data2 = b"device-2-info-bytes-mnopqrstuvwx";
        save_device(&storage, &[0x01; 32], data1).expect("save");
        save_device(&storage, &[0x02; 32], data2).expect("save");

        let devices = list_devices(&storage).expect("list");
        assert_eq!(devices.len(), 2);
    }

    #[test]
    fn remove_device_works() {
        let storage = temp_storage();
        let id = [0xCC; 32];
        save_device(&storage, &id, b"device-info-to-remove-padding!!!").expect("save");
        remove_device(&storage, &id).expect("remove");

        let loaded = load_device(&storage, &id).expect("load");
        assert!(loaded.is_none());
    }

    #[test]
    fn device_data_is_encrypted_at_rest() {
        let storage = temp_storage();
        let id = [0xDD; 32];
        let data = b"secret-device-info-test-data1234";

        save_device(&storage, &id, data).expect("save");

        let txn = storage.db().begin_read().expect("read");
        let table = txn.open_table(DEVICES).expect("table");
        let raw = table.get(id.as_slice()).expect("get").expect("exists");
        let raw_bytes = raw.value();
        assert!(!raw_bytes.windows(data.len()).any(|w| w == data));
    }

    #[test]
    fn save_and_query_sync_log() {
        let storage = temp_storage();
        let device_id = [0xEE; 32];

        save_sync_entry(
            &storage,
            &device_id,
            100,
            b"entry-1-padded-to-32-bytes-here!",
        )
        .expect("save 1");
        save_sync_entry(
            &storage,
            &device_id,
            200,
            b"entry-2-padded-to-32-bytes-here!",
        )
        .expect("save 2");
        save_sync_entry(
            &storage,
            &device_id,
            300,
            b"entry-3-padded-to-32-bytes-here!",
        )
        .expect("save 3");

        // Query since timestamp 150 — should get entries at 200 and 300
        let entries = get_sync_entries_since(&storage, &device_id, 150).expect("query");
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn sync_log_empty_query() {
        let storage = temp_storage();
        let entries = get_sync_entries_since(&storage, &[0x00; 32], 0).expect("query");
        assert!(entries.is_empty());
    }
}
