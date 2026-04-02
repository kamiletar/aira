//! Pending message queue for outgoing messages.
//!
//! Stores `EncryptedEnvelope` data that hasn't been delivered yet.
//! These are already ratchet-encrypted, so no storage-level encryption is applied.
//!
//! Key: `(contact_id: u64, seq: u64)` — seq is a monotonic counter.
//! Value: postcard-serialized `EncryptedEnvelope` bytes.

use redb::ReadableTable;

use crate::{Storage, StorageError, PENDING};

/// Enqueue a pending message for a contact.
///
/// `envelope_bytes` should be postcard-serialized `EncryptedEnvelope`.
/// The sequence number is auto-generated based on the current max.
///
/// # Errors
///
/// Returns [`StorageError`] on database failure.
pub fn enqueue(
    storage: &Storage,
    contact_id: u64,
    envelope_bytes: &[u8],
) -> Result<(), StorageError> {
    let txn = storage.db().begin_write()?;
    {
        let mut table = txn.open_table(PENDING)?;

        // Find the next sequence number for this contact
        let next_seq = next_seq_for(&table, contact_id)?;
        table.insert((contact_id, next_seq), envelope_bytes)?;
    }
    txn.commit()?;
    Ok(())
}

/// Peek at the oldest pending message for a contact without removing it.
///
/// Returns `None` if no pending messages exist.
///
/// # Errors
///
/// Returns [`StorageError`] on database failure.
pub fn peek(storage: &Storage, contact_id: u64) -> Result<Option<Vec<u8>>, StorageError> {
    let txn = storage.db().begin_read()?;
    let table = txn.open_table(PENDING)?;

    let start = (contact_id, 0u64);
    let end = (contact_id, u64::MAX);

    if let Some(entry) = table.range(start..=end)?.next() {
        let (_, value) = entry?;
        Ok(Some(value.value().to_vec()))
    } else {
        Ok(None)
    }
}

/// Dequeue (remove and return) the oldest pending message for a contact.
///
/// Returns `None` if no pending messages exist.
///
/// # Errors
///
/// Returns [`StorageError`] on database failure.
pub fn dequeue(storage: &Storage, contact_id: u64) -> Result<Option<Vec<u8>>, StorageError> {
    // First, find the key of the oldest entry
    let oldest_key = {
        let txn = storage.db().begin_read()?;
        let table = txn.open_table(PENDING)?;
        let start = (contact_id, 0u64);
        let end = (contact_id, u64::MAX);

        if let Some(entry) = table.range(start..=end)?.next() {
            let (k, _) = entry?;
            Some(k.value())
        } else {
            None
        }
    };

    match oldest_key {
        Some((cid, seq)) => {
            let txn = storage.db().begin_write()?;
            let data;
            {
                let mut table = txn.open_table(PENDING)?;
                let entry = table.remove((cid, seq))?;
                data = entry.map(|e| e.value().to_vec());
            }
            txn.commit()?;
            Ok(data)
        }
        None => Ok(None),
    }
}

/// Get the count of pending messages for a contact.
///
/// # Errors
///
/// Returns [`StorageError`] on database failure.
pub fn count(storage: &Storage, contact_id: u64) -> Result<usize, StorageError> {
    let txn = storage.db().begin_read()?;
    let table = txn.open_table(PENDING)?;

    let start = (contact_id, 0u64);
    let end = (contact_id, u64::MAX);

    let mut n = 0;
    for entry in table.range(start..=end)? {
        let _ = entry?;
        n += 1;
    }
    Ok(n)
}

/// Clear all pending messages for a contact.
///
/// Returns the number of messages cleared.
///
/// # Errors
///
/// Returns [`StorageError`] on database failure.
pub fn clear(storage: &Storage, contact_id: u64) -> Result<usize, StorageError> {
    // Collect keys
    let txn = storage.db().begin_read()?;
    let table = txn.open_table(PENDING)?;

    let start = (contact_id, 0u64);
    let end = (contact_id, u64::MAX);

    let mut keys = Vec::new();
    for entry in table.range(start..=end)? {
        let (k, _) = entry?;
        keys.push(k.value());
    }
    drop(table);
    drop(txn);

    let n = keys.len();
    if n > 0 {
        let txn = storage.db().begin_write()?;
        {
            let mut table = txn.open_table(PENDING)?;
            for (cid, seq) in &keys {
                table.remove((*cid, *seq))?;
            }
        }
        txn.commit()?;
    }
    Ok(n)
}

/// Find the next sequence number for a contact's pending queue.
fn next_seq_for(
    table: &redb::Table<(u64, u64), &[u8]>,
    contact_id: u64,
) -> Result<u64, StorageError> {
    let start = (contact_id, 0u64);
    let end = (contact_id, u64::MAX);

    let mut max_seq = 0u64;
    for entry in table.range(start..=end)? {
        let (k, _) = entry?;
        let (_, seq) = k.value();
        if seq >= max_seq {
            max_seq = seq + 1;
        }
    }
    Ok(max_seq)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::temp_storage;
    use crate::types::contact_id;

    #[test]
    fn enqueue_and_peek() {
        let storage = temp_storage();
        let cid = contact_id(b"alice");

        enqueue(&storage, cid, b"envelope-1").expect("enqueue");
        let peeked = peek(&storage, cid).expect("peek").expect("exists");
        assert_eq!(peeked, b"envelope-1");
    }

    #[test]
    fn enqueue_and_dequeue_fifo() {
        let storage = temp_storage();
        let cid = contact_id(b"bob");

        enqueue(&storage, cid, b"first").expect("enqueue 1");
        enqueue(&storage, cid, b"second").expect("enqueue 2");
        enqueue(&storage, cid, b"third").expect("enqueue 3");

        assert_eq!(
            dequeue(&storage, cid).expect("deq"),
            Some(b"first".to_vec())
        );
        assert_eq!(
            dequeue(&storage, cid).expect("deq"),
            Some(b"second".to_vec())
        );
        assert_eq!(
            dequeue(&storage, cid).expect("deq"),
            Some(b"third".to_vec())
        );
        assert_eq!(dequeue(&storage, cid).expect("deq"), None);
    }

    #[test]
    fn count_pending() {
        let storage = temp_storage();
        let cid = contact_id(b"carol");

        assert_eq!(count(&storage, cid).expect("count"), 0);
        enqueue(&storage, cid, b"msg1").expect("enqueue");
        enqueue(&storage, cid, b"msg2").expect("enqueue");
        assert_eq!(count(&storage, cid).expect("count"), 2);
    }

    #[test]
    fn clear_pending() {
        let storage = temp_storage();
        let cid = contact_id(b"dave");

        enqueue(&storage, cid, b"msg1").expect("enqueue");
        enqueue(&storage, cid, b"msg2").expect("enqueue");

        let cleared = clear(&storage, cid).expect("clear");
        assert_eq!(cleared, 2);
        assert_eq!(count(&storage, cid).expect("count"), 0);
    }

    #[test]
    fn different_contacts_independent() {
        let storage = temp_storage();
        let cid_a = contact_id(b"alice-pending");
        let cid_b = contact_id(b"bob-pending");

        enqueue(&storage, cid_a, b"for-alice").expect("enqueue");
        enqueue(&storage, cid_b, b"for-bob").expect("enqueue");

        assert_eq!(count(&storage, cid_a).expect("count"), 1);
        assert_eq!(count(&storage, cid_b).expect("count"), 1);

        assert_eq!(
            dequeue(&storage, cid_a).expect("deq"),
            Some(b"for-alice".to_vec())
        );
        assert_eq!(count(&storage, cid_b).expect("count"), 1);
    }

    #[test]
    fn peek_empty_returns_none() {
        let storage = temp_storage();
        assert!(peek(&storage, 999).expect("peek").is_none());
    }
}
