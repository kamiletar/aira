//! Message history CRUD operations.
//!
//! Key: `(contact_id: u64, timestamp_micros: u64)`.
//! Value: `StoredMessage` serialized with postcard, then encrypted.
//!
//! `contact_id` is computed as `BLAKE3(pubkey)[0..8]` (see `types::contact_id`).

use redb::ReadableTable;

use crate::encrypted::{decrypt_value, encrypt_value};
use crate::types::StoredMessage;
use crate::{Storage, StorageError, MESSAGES};

/// Store a message.
///
/// # Errors
///
/// Returns [`StorageError`] on database or encryption failure.
pub fn store(storage: &Storage, contact_id: u64, msg: &StoredMessage) -> Result<(), StorageError> {
    let serialized =
        postcard::to_allocvec(msg).map_err(|e| StorageError::Serialization(e.to_string()))?;
    let encrypted = encrypt_value(storage.key(), &serialized)?;

    let txn = storage.db().begin_write()?;
    {
        let mut table = txn.open_table(MESSAGES)?;
        table.insert((contact_id, msg.timestamp_micros), encrypted.as_slice())?;
    }
    txn.commit()?;
    Ok(())
}

/// Get message history for a contact, ordered by timestamp descending.
///
/// Returns up to `limit` messages with timestamps before `before_micros`.
/// Pass `u64::MAX` for `before_micros` to get the latest messages.
///
/// # Errors
///
/// Returns [`StorageError`] on database or decryption failure.
pub fn get_history(
    storage: &Storage,
    contact_id: u64,
    limit: u32,
    before_micros: u64,
) -> Result<Vec<StoredMessage>, StorageError> {
    let txn = storage.db().begin_read()?;
    let table = txn.open_table(MESSAGES)?;

    let start = (contact_id, 0u64);
    let end = (contact_id, before_micros);

    let mut messages = Vec::new();
    // Collect in forward order, then reverse for newest-first
    for entry in table.range(start..=end)? {
        let (_, value) = entry?;
        let decrypted = decrypt_value(storage.key(), value.value())?;
        let msg: StoredMessage = postcard::from_bytes(&decrypted)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        messages.push(msg);
    }

    // Return newest first, limited
    messages.reverse();
    messages.truncate(limit as usize);
    Ok(messages)
}

/// Delete a specific message.
///
/// # Errors
///
/// Returns [`StorageError`] on database failure.
pub fn delete(
    storage: &Storage,
    contact_id: u64,
    timestamp_micros: u64,
) -> Result<(), StorageError> {
    let txn = storage.db().begin_write()?;
    {
        let mut table = txn.open_table(MESSAGES)?;
        table.remove((contact_id, timestamp_micros))?;
    }
    txn.commit()?;
    Ok(())
}

/// Mark a message as read and set the expiry time if it has a TTL.
///
/// Returns `true` if the message was found and updated.
///
/// # Errors
///
/// Returns [`StorageError`] on database failure.
pub fn mark_read(
    storage: &Storage,
    contact_id: u64,
    timestamp_micros: u64,
) -> Result<bool, StorageError> {
    // Read the message first, then update in a separate scope
    let read_txn = storage.db().begin_read()?;
    let read_table = read_txn.open_table(MESSAGES)?;
    let raw = match read_table.get((contact_id, timestamp_micros))? {
        Some(entry) => entry.value().to_vec(),
        None => return Ok(false),
    };
    drop(read_table);
    drop(read_txn);

    let decrypted = decrypt_value(storage.key(), &raw)?;
    let mut msg: StoredMessage =
        postcard::from_bytes(&decrypted).map_err(|e| StorageError::Serialization(e.to_string()))?;

    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    msg.read_at = Some(now_secs);

    // If message has TTL, compute expiry time
    if let Some(ttl) = msg.ttl_secs {
        msg.expires_at = Some(now_secs + ttl);
    }

    let serialized =
        postcard::to_allocvec(&msg).map_err(|e| StorageError::Serialization(e.to_string()))?;
    let encrypted = encrypt_value(storage.key(), &serialized)?;

    let txn = storage.db().begin_write()?;
    {
        let mut table = txn.open_table(MESSAGES)?;
        table.insert((contact_id, timestamp_micros), encrypted.as_slice())?;
    }
    txn.commit()?;
    Ok(true)
}

/// Delete all expired messages (disappearing messages).
///
/// Returns the number of messages deleted.
///
/// # Errors
///
/// Returns [`StorageError`] on database failure.
pub fn delete_expired(storage: &Storage) -> Result<usize, StorageError> {
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Collect keys of expired messages
    let txn = storage.db().begin_read()?;
    let table = txn.open_table(MESSAGES)?;

    let mut expired_keys = Vec::new();
    for entry in table.iter()? {
        let (key, value) = entry?;
        let decrypted = decrypt_value(storage.key(), value.value())?;
        let msg: StoredMessage = postcard::from_bytes(&decrypted)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;

        if let Some(expires_at) = msg.expires_at {
            if expires_at <= now_secs {
                let (cid, ts) = key.value();
                expired_keys.push((cid, ts));
            }
        }
    }
    drop(table);
    drop(txn);

    let count = expired_keys.len();
    if count > 0 {
        let txn = storage.db().begin_write()?;
        {
            let mut table = txn.open_table(MESSAGES)?;
            for (cid, ts) in &expired_keys {
                table.remove((*cid, *ts))?;
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
    use crate::types::contact_id;

    fn make_msg(id_byte: u8, ts: u64) -> StoredMessage {
        StoredMessage {
            id: [id_byte; 16],
            sender_is_self: id_byte % 2 == 0,
            payload_bytes: vec![id_byte],
            timestamp_micros: ts,
            ttl_secs: None,
            read_at: None,
            expires_at: None,
        }
    }

    #[test]
    fn store_and_get_history() {
        let storage = temp_storage();
        let cid = contact_id(b"alice-pk");

        store(&storage, cid, &make_msg(1, 1000)).expect("store 1");
        store(&storage, cid, &make_msg(2, 2000)).expect("store 2");
        store(&storage, cid, &make_msg(3, 3000)).expect("store 3");

        let history = get_history(&storage, cid, 10, u64::MAX).expect("get history");
        assert_eq!(history.len(), 3);
        // Newest first
        assert_eq!(history[0].timestamp_micros, 3000);
        assert_eq!(history[1].timestamp_micros, 2000);
        assert_eq!(history[2].timestamp_micros, 1000);
    }

    #[test]
    fn get_history_with_limit() {
        let storage = temp_storage();
        let cid = contact_id(b"bob-pk");

        for i in 0..10 {
            store(&storage, cid, &make_msg(i, u64::from(i) * 1000)).expect("store");
        }

        let history = get_history(&storage, cid, 3, u64::MAX).expect("get history");
        assert_eq!(history.len(), 3);
    }

    #[test]
    fn get_history_with_before() {
        let storage = temp_storage();
        let cid = contact_id(b"carol-pk");

        store(&storage, cid, &make_msg(1, 1000)).expect("store");
        store(&storage, cid, &make_msg(2, 2000)).expect("store");
        store(&storage, cid, &make_msg(3, 3000)).expect("store");

        let history = get_history(&storage, cid, 10, 2500).expect("get history");
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].timestamp_micros, 2000);
    }

    #[test]
    fn delete_message() {
        let storage = temp_storage();
        let cid = contact_id(b"dave-pk");

        store(&storage, cid, &make_msg(1, 1000)).expect("store");
        store(&storage, cid, &make_msg(2, 2000)).expect("store");

        delete(&storage, cid, 1000).expect("delete");

        let history = get_history(&storage, cid, 10, u64::MAX).expect("get history");
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].timestamp_micros, 2000);
    }

    #[test]
    fn mark_read_sets_read_at() {
        let storage = temp_storage();
        let cid = contact_id(b"eve-pk");

        store(&storage, cid, &make_msg(1, 1000)).expect("store");
        let updated = mark_read(&storage, cid, 1000).expect("mark read");
        assert!(updated);

        let history = get_history(&storage, cid, 1, u64::MAX).expect("get");
        assert!(history[0].read_at.is_some());
    }

    #[test]
    fn mark_read_with_ttl_sets_expiry() {
        let storage = temp_storage();
        let cid = contact_id(b"frank-pk");

        let mut msg = make_msg(1, 1000);
        msg.ttl_secs = Some(3600); // 1 hour
        store(&storage, cid, &msg).expect("store");

        mark_read(&storage, cid, 1000).expect("mark read");

        let history = get_history(&storage, cid, 1, u64::MAX).expect("get");
        assert!(history[0].expires_at.is_some());
        assert!(history[0].read_at.is_some());
        // expires_at should be approximately read_at + 3600
        let diff = history[0].expires_at.expect("expires") - history[0].read_at.expect("read");
        assert_eq!(diff, 3600);
    }

    #[test]
    fn delete_expired_removes_expired_messages() {
        let storage = temp_storage();
        let cid = contact_id(b"grace-pk");

        // Message that expires in the past
        let mut msg = make_msg(1, 1000);
        msg.expires_at = Some(1); // expired long ago
        store(&storage, cid, &msg).expect("store expired");

        // Message that doesn't expire
        store(&storage, cid, &make_msg(2, 2000)).expect("store permanent");

        let deleted = delete_expired(&storage).expect("delete expired");
        assert_eq!(deleted, 1);

        let history = get_history(&storage, cid, 10, u64::MAX).expect("get");
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].id, [2; 16]);
    }

    #[test]
    fn different_contacts_dont_mix() {
        let storage = temp_storage();
        let cid_a = contact_id(b"alice-pk");
        let cid_b = contact_id(b"bob-pk");

        store(&storage, cid_a, &make_msg(1, 1000)).expect("store");
        store(&storage, cid_b, &make_msg(2, 2000)).expect("store");

        let hist_a = get_history(&storage, cid_a, 10, u64::MAX).expect("get");
        let hist_b = get_history(&storage, cid_b, 10, u64::MAX).expect("get");

        assert_eq!(hist_a.len(), 1);
        assert_eq!(hist_b.len(), 1);
        assert_eq!(hist_a[0].id, [1; 16]);
        assert_eq!(hist_b[0].id, [2; 16]);
    }
}
