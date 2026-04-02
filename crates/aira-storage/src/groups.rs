//! Group storage CRUD operations (SPEC.md §12).
//!
//! Key: `group_id` (32 bytes).
//! Value: `GroupInfo` serialized with postcard, then encrypted with storage key.

use redb::ReadableTable;

use crate::encrypted::{decrypt_value, encrypt_value};
use crate::types::{GroupInfo, GroupMemberInfo, StoredMessage};
use crate::{Storage, StorageError, GROUPS, GROUP_MESSAGES};

/// Create a new group.
///
/// # Errors
///
/// Returns [`StorageError`] on database or encryption failure.
pub fn create_group(storage: &Storage, group: &GroupInfo) -> Result<(), StorageError> {
    let serialized =
        postcard::to_allocvec(group).map_err(|e| StorageError::Serialization(e.to_string()))?;
    let encrypted = encrypt_value(storage.key(), &serialized)?;

    let txn = storage.db().begin_write()?;
    {
        let mut table = txn.open_table(GROUPS)?;
        table.insert(group.id.as_slice(), encrypted.as_slice())?;
    }
    txn.commit()?;
    Ok(())
}

/// Get a group by its ID.
///
/// # Errors
///
/// Returns [`StorageError::GroupNotFound`] if the group does not exist.
pub fn get_group(storage: &Storage, group_id: &[u8]) -> Result<GroupInfo, StorageError> {
    let txn = storage.db().begin_read()?;
    let table = txn.open_table(GROUPS)?;

    let entry = table.get(group_id)?.ok_or(StorageError::GroupNotFound)?;

    let decrypted = decrypt_value(storage.key(), entry.value())?;
    postcard::from_bytes(&decrypted).map_err(|e| StorageError::Serialization(e.to_string()))
}

/// List all groups.
///
/// # Errors
///
/// Returns [`StorageError`] on database or decryption failure.
pub fn list_groups(storage: &Storage) -> Result<Vec<GroupInfo>, StorageError> {
    let txn = storage.db().begin_read()?;
    let table = txn.open_table(GROUPS)?;

    let mut groups = Vec::new();
    for entry in table.iter()? {
        let (_, value) = entry?;
        let decrypted = decrypt_value(storage.key(), value.value())?;
        let info: GroupInfo = postcard::from_bytes(&decrypted)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        groups.push(info);
    }
    Ok(groups)
}

/// Update a group (overwrite the existing entry).
///
/// # Errors
///
/// Returns [`StorageError`] on database or encryption failure.
pub fn update_group(storage: &Storage, group: &GroupInfo) -> Result<(), StorageError> {
    let serialized =
        postcard::to_allocvec(group).map_err(|e| StorageError::Serialization(e.to_string()))?;
    let encrypted = encrypt_value(storage.key(), &serialized)?;

    let txn = storage.db().begin_write()?;
    {
        let mut table = txn.open_table(GROUPS)?;
        table.insert(group.id.as_slice(), encrypted.as_slice())?;
    }
    txn.commit()?;
    Ok(())
}

/// Remove a group by its ID.
///
/// # Errors
///
/// Returns [`StorageError`] on database failure. No error if group doesn't exist.
pub fn remove_group(storage: &Storage, group_id: &[u8]) -> Result<(), StorageError> {
    let txn = storage.db().begin_write()?;
    {
        let mut table = txn.open_table(GROUPS)?;
        table.remove(group_id)?;
    }
    txn.commit()?;
    Ok(())
}

/// Add a member to a group.
///
/// # Errors
///
/// Returns [`StorageError::GroupNotFound`] if the group does not exist.
pub fn add_member(
    storage: &Storage,
    group_id: &[u8],
    member: GroupMemberInfo,
) -> Result<(), StorageError> {
    let mut group = get_group(storage, group_id)?;
    group.members.push(member);
    update_group(storage, &group)
}

/// Remove a member from a group by public key.
///
/// # Errors
///
/// Returns [`StorageError::GroupNotFound`] if the group does not exist.
pub fn remove_member(
    storage: &Storage,
    group_id: &[u8],
    member_pubkey: &[u8],
) -> Result<(), StorageError> {
    let mut group = get_group(storage, group_id)?;
    group.members.retain(|m| m.pubkey != member_pubkey);
    update_group(storage, &group)
}

// ─── Group messages ─────────────────────────────────────────────────────────

/// Store a group message.
///
/// # Errors
///
/// Returns [`StorageError`] on database or encryption failure.
pub fn store_group_message(
    storage: &Storage,
    group_id: &[u8],
    msg: &StoredMessage,
) -> Result<(), StorageError> {
    let serialized =
        postcard::to_allocvec(msg).map_err(|e| StorageError::Serialization(e.to_string()))?;
    let encrypted = encrypt_value(storage.key(), &serialized)?;

    let txn = storage.db().begin_write()?;
    {
        let mut table = txn.open_table(GROUP_MESSAGES)?;
        table.insert((group_id, msg.timestamp_micros), encrypted.as_slice())?;
    }
    txn.commit()?;
    Ok(())
}

/// Get group message history, ordered by timestamp descending (newest first).
///
/// Returns up to `limit` messages.
///
/// # Errors
///
/// Returns [`StorageError`] on database or decryption failure.
pub fn get_group_history(
    storage: &Storage,
    group_id: &[u8],
    limit: u32,
) -> Result<Vec<StoredMessage>, StorageError> {
    let txn = storage.db().begin_read()?;
    let table = txn.open_table(GROUP_MESSAGES)?;

    let start = (group_id, 0u64);
    let end = (group_id, u64::MAX);

    let mut messages = Vec::new();
    for entry in table.range(start..=end)? {
        let (_, value) = entry?;
        let decrypted = decrypt_value(storage.key(), value.value())?;
        let msg: StoredMessage = postcard::from_bytes(&decrypted)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        messages.push(msg);
    }

    // Newest first
    messages.reverse();
    messages.truncate(limit as usize);
    Ok(messages)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::temp_storage;
    use crate::types::GroupRole;

    fn make_group(id_byte: u8) -> GroupInfo {
        GroupInfo {
            id: [id_byte; 32],
            name: format!("Group {id_byte}"),
            members: vec![GroupMemberInfo {
                pubkey: vec![0xAA; 32],
                role: GroupRole::Admin,
                joined_at: 1_700_000_000,
            }],
            created_by: vec![0xAA; 32],
            created_at: 1_700_000_000,
        }
    }

    fn make_group_msg(id_byte: u8, ts: u64) -> StoredMessage {
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
    fn create_and_get_group() {
        let storage = temp_storage();
        let group = make_group(1);

        create_group(&storage, &group).expect("create");
        let fetched = get_group(&storage, &[1; 32]).expect("get");

        assert_eq!(fetched.name, "Group 1");
        assert_eq!(fetched.members.len(), 1);
        assert_eq!(fetched.created_by, vec![0xAA; 32]);
    }

    #[test]
    fn get_nonexistent_group_returns_not_found() {
        let storage = temp_storage();
        let result = get_group(&storage, &[0xFF; 32]);
        assert!(matches!(result, Err(StorageError::GroupNotFound)));
    }

    #[test]
    fn list_groups_works() {
        let storage = temp_storage();
        create_group(&storage, &make_group(1)).expect("create 1");
        create_group(&storage, &make_group(2)).expect("create 2");

        let groups = list_groups(&storage).expect("list");
        assert_eq!(groups.len(), 2);
    }

    #[test]
    fn update_group_works() {
        let storage = temp_storage();
        let mut group = make_group(1);
        create_group(&storage, &group).expect("create");

        group.name = "Updated Name".into();
        update_group(&storage, &group).expect("update");

        let fetched = get_group(&storage, &[1; 32]).expect("get");
        assert_eq!(fetched.name, "Updated Name");
    }

    #[test]
    fn remove_group_works() {
        let storage = temp_storage();
        create_group(&storage, &make_group(1)).expect("create");
        remove_group(&storage, &[1; 32]).expect("remove");
        assert!(matches!(
            get_group(&storage, &[1; 32]),
            Err(StorageError::GroupNotFound)
        ));
    }

    #[test]
    fn add_and_remove_member() {
        let storage = temp_storage();
        create_group(&storage, &make_group(1)).expect("create");

        let new_member = GroupMemberInfo {
            pubkey: vec![0xBB; 32],
            role: GroupRole::Member,
            joined_at: 1_700_001_000,
        };
        add_member(&storage, &[1; 32], new_member).expect("add member");

        let group = get_group(&storage, &[1; 32]).expect("get");
        assert_eq!(group.members.len(), 2);

        remove_member(&storage, &[1; 32], &[0xBB; 32]).expect("remove member");
        let group = get_group(&storage, &[1; 32]).expect("get");
        assert_eq!(group.members.len(), 1);
    }

    #[test]
    fn store_and_get_group_messages() {
        let storage = temp_storage();
        let gid = [0x11; 32];

        store_group_message(&storage, &gid, &make_group_msg(1, 1000)).expect("store 1");
        store_group_message(&storage, &gid, &make_group_msg(2, 2000)).expect("store 2");
        store_group_message(&storage, &gid, &make_group_msg(3, 3000)).expect("store 3");

        let history = get_group_history(&storage, &gid, 10).expect("get history");
        assert_eq!(history.len(), 3);
        // Newest first
        assert_eq!(history[0].timestamp_micros, 3000);
        assert_eq!(history[1].timestamp_micros, 2000);
        assert_eq!(history[2].timestamp_micros, 1000);
    }

    #[test]
    fn group_history_limit() {
        let storage = temp_storage();
        let gid = [0x22; 32];

        for i in 0..10 {
            store_group_message(&storage, &gid, &make_group_msg(i, u64::from(i) * 1000))
                .expect("store");
        }

        let history = get_group_history(&storage, &gid, 3).expect("get history");
        assert_eq!(history.len(), 3);
    }

    #[test]
    fn different_groups_dont_mix() {
        let storage = temp_storage();
        let gid_a = [0xAA; 32];
        let gid_b = [0xBB; 32];

        store_group_message(&storage, &gid_a, &make_group_msg(1, 1000)).expect("store a");
        store_group_message(&storage, &gid_b, &make_group_msg(2, 2000)).expect("store b");

        let hist_a = get_group_history(&storage, &gid_a, 10).expect("get a");
        let hist_b = get_group_history(&storage, &gid_b, 10).expect("get b");

        assert_eq!(hist_a.len(), 1);
        assert_eq!(hist_b.len(), 1);
        assert_eq!(hist_a[0].id, [1; 16]);
        assert_eq!(hist_b[0].id, [2; 16]);
    }
}
