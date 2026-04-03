//! Pseudonym storage CRUD operations (SPEC.md §12.6).
//!
//! Manages the monotonic counter and pseudonym→context mapping.
//! Actual key material is never stored — only the public key and context.

use redb::ReadableTable;

use crate::encrypted::{decrypt_value, encrypt_value};
use crate::types::PseudonymRecord;
use crate::{Storage, StorageError, PSEUDONYMS, PSEUDONYM_COUNTER};

/// Counter key in the singleton table.
const COUNTER_KEY: &str = "current";

/// Allocate the next pseudonym counter value and increment the singleton.
///
/// Returns the allocated counter (starting from 0).
///
/// # Errors
///
/// Returns [`StorageError`] on database failure.
pub fn next_counter(storage: &Storage) -> Result<u32, StorageError> {
    let txn = storage.db().begin_write()?;
    let counter = {
        let mut table = txn.open_table(PSEUDONYM_COUNTER)?;
        let current = table.get(COUNTER_KEY)?.map_or(0, |guard| guard.value());
        table.insert(COUNTER_KEY, current + 1)?;
        current
    };
    txn.commit()?;
    Ok(counter)
}

/// Get the current counter value (next to be allocated) without incrementing.
///
/// # Errors
///
/// Returns [`StorageError`] on database failure.
pub fn current_counter(storage: &Storage) -> Result<u32, StorageError> {
    let txn = storage.db().begin_read()?;
    let table = txn.open_table(PSEUDONYM_COUNTER)?;
    Ok(table.get(COUNTER_KEY)?.map_or(0, |guard| guard.value()))
}

/// Store a pseudonym record.
///
/// # Errors
///
/// Returns [`StorageError`] on database or encryption failure.
pub fn store(storage: &Storage, record: &PseudonymRecord) -> Result<(), StorageError> {
    let serialized =
        postcard::to_allocvec(record).map_err(|e| StorageError::Serialization(e.to_string()))?;
    let encrypted = encrypt_value(storage.key(), &serialized)?;

    let txn = storage.db().begin_write()?;
    {
        let mut table = txn.open_table(PSEUDONYMS)?;
        table.insert(record.counter, encrypted.as_slice())?;
    }
    txn.commit()?;
    Ok(())
}

/// Get a pseudonym record by counter.
///
/// # Errors
///
/// Returns [`StorageError`] on database or decryption failure.
/// Returns `Ok(None)` if the counter has no record.
pub fn get(storage: &Storage, counter: u32) -> Result<Option<PseudonymRecord>, StorageError> {
    let txn = storage.db().begin_read()?;
    let table = txn.open_table(PSEUDONYMS)?;

    match table.get(counter)? {
        Some(entry) => {
            let decrypted = decrypt_value(storage.key(), entry.value())?;
            let record: PseudonymRecord = postcard::from_bytes(&decrypted)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            Ok(Some(record))
        }
        None => Ok(None),
    }
}

/// Find a pseudonym record by its public key.
///
/// Linear scan — acceptable for small pseudonym counts (typical: <100).
///
/// # Errors
///
/// Returns [`StorageError`] on database or decryption failure.
pub fn find_by_pubkey(
    storage: &Storage,
    pubkey: &[u8],
) -> Result<Option<PseudonymRecord>, StorageError> {
    let txn = storage.db().begin_read()?;
    let table = txn.open_table(PSEUDONYMS)?;

    for entry in table.iter()? {
        let (_, value) = entry?;
        let decrypted = decrypt_value(storage.key(), value.value())?;
        let record: PseudonymRecord = postcard::from_bytes(&decrypted)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        if record.pubkey == pubkey {
            return Ok(Some(record));
        }
    }
    Ok(None)
}

/// Find a pseudonym record by context ID (`group_id` or contact hash).
///
/// Returns the most recent pseudonym for the given context (highest counter).
///
/// # Errors
///
/// Returns [`StorageError`] on database or decryption failure.
pub fn find_by_context(
    storage: &Storage,
    context_id: &[u8; 32],
) -> Result<Option<PseudonymRecord>, StorageError> {
    let txn = storage.db().begin_read()?;
    let table = txn.open_table(PSEUDONYMS)?;

    let mut best: Option<PseudonymRecord> = None;
    for entry in table.iter()? {
        let (_, value) = entry?;
        let decrypted = decrypt_value(storage.key(), value.value())?;
        let record: PseudonymRecord = postcard::from_bytes(&decrypted)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        if record.context_id == *context_id {
            best = match best {
                Some(ref prev) if prev.counter >= record.counter => best,
                _ => Some(record),
            };
        }
    }
    Ok(best)
}

/// List all pseudonym records.
///
/// # Errors
///
/// Returns [`StorageError`] on database or decryption failure.
pub fn list(storage: &Storage) -> Result<Vec<PseudonymRecord>, StorageError> {
    let txn = storage.db().begin_read()?;
    let table = txn.open_table(PSEUDONYMS)?;

    let mut records = Vec::new();
    for entry in table.iter()? {
        let (_, value) = entry?;
        let decrypted = decrypt_value(storage.key(), value.value())?;
        let record: PseudonymRecord = postcard::from_bytes(&decrypted)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        records.push(record);
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::temp_storage;
    use crate::types::PseudonymContext;

    fn make_record(counter: u32, ctx: PseudonymContext, id_byte: u8) -> PseudonymRecord {
        PseudonymRecord {
            counter,
            pubkey: vec![id_byte; 1952],
            context_type: ctx,
            context_id: [id_byte; 32],
            display_name: format!("User {id_byte}"),
            created_at: 1_700_000_000,
        }
    }

    #[test]
    fn counter_starts_at_zero() {
        let storage = temp_storage();
        assert_eq!(current_counter(&storage).unwrap(), 0);
    }

    #[test]
    fn next_counter_increments() {
        let storage = temp_storage();
        assert_eq!(next_counter(&storage).unwrap(), 0);
        assert_eq!(next_counter(&storage).unwrap(), 1);
        assert_eq!(next_counter(&storage).unwrap(), 2);
        assert_eq!(current_counter(&storage).unwrap(), 3);
    }

    #[test]
    fn store_and_get_record() {
        let storage = temp_storage();
        let record = make_record(0, PseudonymContext::Contact, 0xAA);

        store(&storage, &record).unwrap();
        let fetched = get(&storage, 0).unwrap().expect("record exists");

        assert_eq!(fetched.counter, 0);
        assert_eq!(fetched.pubkey, vec![0xAA; 1952]);
        assert_eq!(fetched.context_type, PseudonymContext::Contact);
        assert_eq!(fetched.display_name, "User 170");
    }

    #[test]
    fn get_missing_returns_none() {
        let storage = temp_storage();
        assert!(get(&storage, 42).unwrap().is_none());
    }

    #[test]
    fn find_by_pubkey_works() {
        let storage = temp_storage();
        store(&storage, &make_record(0, PseudonymContext::Contact, 0xAA)).unwrap();
        store(&storage, &make_record(1, PseudonymContext::Group, 0xBB)).unwrap();

        let found = find_by_pubkey(&storage, &vec![0xBB; 1952])
            .unwrap()
            .expect("found");
        assert_eq!(found.counter, 1);
        assert_eq!(found.context_type, PseudonymContext::Group);
    }

    #[test]
    fn find_by_pubkey_not_found() {
        let storage = temp_storage();
        store(&storage, &make_record(0, PseudonymContext::Contact, 0xAA)).unwrap();
        assert!(find_by_pubkey(&storage, &vec![0xFF; 1952])
            .unwrap()
            .is_none());
    }

    #[test]
    fn find_by_context_returns_latest() {
        let storage = temp_storage();
        // Two pseudonyms for the same group (rotation)
        store(&storage, &make_record(0, PseudonymContext::Group, 0xAA)).unwrap();
        store(&storage, &make_record(5, PseudonymContext::Group, 0xAA)).unwrap();

        let found = find_by_context(&storage, &[0xAA; 32])
            .unwrap()
            .expect("found");
        assert_eq!(found.counter, 5, "should return highest counter");
    }

    #[test]
    fn list_all_records() {
        let storage = temp_storage();
        store(&storage, &make_record(0, PseudonymContext::Contact, 0xAA)).unwrap();
        store(&storage, &make_record(1, PseudonymContext::Group, 0xBB)).unwrap();
        store(&storage, &make_record(2, PseudonymContext::Contact, 0xCC)).unwrap();

        let all = list(&storage).unwrap();
        assert_eq!(all.len(), 3);
    }
}
