//! Message deduplication window (24h).
//!
//! Protects against double-delivery on network retry.
//! See SPEC.md §6.21.

use redb::ReadableTable;

use crate::{Storage, StorageError, DEDUP_WINDOW_SECS, SEEN_IDS};

/// Check if a message ID was seen recently (within `DEDUP_WINDOW_SECS`).
/// Returns `true` if this is a duplicate (should be dropped).
///
/// Also records the ID as seen if it's new.
///
/// # Errors
///
/// Returns [`StorageError`] on database failure.
pub fn is_duplicate(storage: &Storage, message_id: &[u8; 16]) -> Result<bool, StorageError> {
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Check if already seen
    let txn = storage.db().begin_read()?;
    let table = txn.open_table(SEEN_IDS)?;
    if let Some(entry) = table.get(message_id.as_slice())? {
        let seen_at = entry.value();
        if now_secs.saturating_sub(seen_at) < DEDUP_WINDOW_SECS {
            return Ok(true);
        }
    }
    drop(table);
    drop(txn);

    // Record as seen
    let txn = storage.db().begin_write()?;
    {
        let mut table = txn.open_table(SEEN_IDS)?;
        table.insert(message_id.as_slice(), now_secs)?;
    }
    txn.commit()?;
    Ok(false)
}

/// Remove message IDs older than `DEDUP_WINDOW_SECS`.
/// Call on daemon startup and periodically.
///
/// Returns the number of entries removed.
///
/// # Errors
///
/// Returns [`StorageError`] on database failure.
pub fn gc_expired(storage: &Storage) -> Result<usize, StorageError> {
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let cutoff = now_secs.saturating_sub(DEDUP_WINDOW_SECS);

    // Collect expired keys
    let txn = storage.db().begin_read()?;
    let table = txn.open_table(SEEN_IDS)?;

    let mut expired = Vec::new();
    for entry in table.iter()? {
        let (key, value) = entry?;
        if value.value() < cutoff {
            expired.push(key.value().to_vec());
        }
    }
    drop(table);
    drop(txn);

    let count = expired.len();
    if count > 0 {
        let txn = storage.db().begin_write()?;
        {
            let mut table = txn.open_table(SEEN_IDS)?;
            for key in &expired {
                table.remove(key.as_slice())?;
            }
        }
        txn.commit()?;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::temp_storage;

    #[test]
    fn new_message_is_not_duplicate() {
        let storage = temp_storage();
        let id = [0xAA; 16];
        assert!(!is_duplicate(&storage, &id).expect("check"));
    }

    #[test]
    fn same_message_is_duplicate() {
        let storage = temp_storage();
        let id = [0xBB; 16];
        assert!(!is_duplicate(&storage, &id).expect("first"));
        assert!(is_duplicate(&storage, &id).expect("second"));
    }

    #[test]
    fn different_messages_are_not_duplicates() {
        let storage = temp_storage();
        let id1 = [0xCC; 16];
        let id2 = [0xDD; 16];
        assert!(!is_duplicate(&storage, &id1).expect("first"));
        assert!(!is_duplicate(&storage, &id2).expect("second"));
    }

    #[test]
    fn gc_removes_old_entries() {
        let storage = temp_storage();

        // Manually insert an entry with a very old timestamp
        let old_id = [0xEE; 16];
        let txn = storage.db().begin_write().expect("write");
        {
            let mut table = txn.open_table(crate::SEEN_IDS).expect("table");
            table.insert(old_id.as_slice(), 1u64).expect("insert"); // timestamp = 1 (very old)
        }
        txn.commit().expect("commit");

        // Insert a fresh entry
        let fresh_id = [0xFF; 16];
        assert!(!is_duplicate(&storage, &fresh_id).expect("fresh"));

        // GC should remove the old entry
        let removed = gc_expired(&storage).expect("gc");
        assert_eq!(removed, 1);

        // Fresh entry should still be there (is duplicate)
        assert!(is_duplicate(&storage, &fresh_id).expect("still dup"));
    }
}
