//! Domain types for storage — serialized with postcard.
//!
//! These types represent the data stored in redb tables.
//! Values are encrypted before storage (see `encrypted.rs`).

use serde::{Deserialize, Serialize};

/// Contact information stored in the `contacts` table.
///
/// Key: ML-DSA public key bytes.
/// Value: `ContactInfo` serialized with postcard, then encrypted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactInfo {
    /// ML-DSA-65 public key (identity).
    pub pubkey: Vec<u8>,
    /// User-assigned display name.
    pub alias: String,
    /// Unix timestamp (seconds) when the contact was added.
    pub added_at: u64,
    /// Whether the contact's Safety Number has been verified.
    pub verified: bool,
    /// Whether the contact is blocked.
    pub blocked: bool,
}

/// Message stored in the `messages` table.
///
/// Key: `(contact_id: u64, timestamp_micros: u64)`.
/// Value: `StoredMessage` serialized with postcard, then encrypted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredMessage {
    /// Unique message ID (16 random bytes).
    pub id: [u8; 16],
    /// `true` if we sent this message, `false` if received.
    pub sender_is_self: bool,
    /// Serialized `PlainPayload` bytes (postcard).
    pub payload_bytes: Vec<u8>,
    /// Message timestamp (microseconds since epoch).
    pub timestamp_micros: u64,
    /// TTL for disappearing messages (seconds), or `None` for permanent.
    pub ttl_secs: Option<u64>,
    /// Unix timestamp (seconds) when the message was read (for TTL start).
    pub read_at: Option<u64>,
    /// Unix timestamp (seconds) when the message expires and should be deleted.
    pub expires_at: Option<u64>,
}

/// Role of a member within a group (matches `aira_core::group_proto::GroupRole`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GroupRole {
    /// Can add/remove members, manage the group.
    Admin,
    /// Can read/write messages only.
    Member,
}

/// Information about a group member.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMemberInfo {
    /// Member's pseudonym public key for this group (§12.6).
    pub pubkey: Vec<u8>,
    /// User-chosen display name for this group (§12.6).
    pub display_name: String,
    /// Member's role in the group.
    pub role: GroupRole,
    /// Unix timestamp (seconds) when the member joined.
    pub joined_at: u64,
}

/// Group metadata stored in the `groups` table.
///
/// Key: `group_id` (32 bytes).
/// Value: `GroupInfo` serialized with postcard, then encrypted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupInfo {
    /// Group identifier (32 random bytes).
    pub id: [u8; 32],
    /// Group display name.
    pub name: String,
    /// Group members.
    pub members: Vec<GroupMemberInfo>,
    /// Creator's pseudonym public key (§12.6).
    pub created_by: Vec<u8>,
    /// Unix timestamp (seconds) when the group was created.
    pub created_at: u64,
}

/// Context type for a pseudonym record (§12.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PseudonymContext {
    /// Pseudonym used for a 1-on-1 contact.
    Contact,
    /// Pseudonym used for a group.
    Group,
}

/// A pseudonym key derivation record stored in the `pseudonyms` table (§12.6).
///
/// Key: `counter` (u32).
/// Value: `PseudonymRecord` serialized with postcard, then encrypted.
///
/// Maps a BIP-32-style counter to its usage context (group or contact).
/// The actual key material is derived from `MasterSeed` at runtime via
/// `derive_pseudonym_seeds(counter)` — never stored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PseudonymRecord {
    /// Counter used for KDF derivation.
    pub counter: u32,
    /// ML-DSA-65 pseudonym public key (derived, stored for lookup).
    pub pubkey: Vec<u8>,
    /// Whether this pseudonym is for a contact or a group.
    pub context_type: PseudonymContext,
    /// Context identifier: `group_id` (32 bytes) or `BLAKE3(contact_pseudonym_pubkey)[..32]`.
    pub context_id: [u8; 32],
    /// User-chosen display name for this context.
    pub display_name: String,
    /// Unix timestamp (seconds) when the pseudonym was created.
    pub created_at: u64,
}

/// Information about a linked device stored in the `devices` table.
///
/// Key: `device_id` (32 bytes).
/// Value: `DeviceInfo` serialized with postcard, then encrypted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceInfo {
    /// Unique device identifier (32 bytes).
    pub device_id: [u8; 32],
    /// Human-readable device name (e.g., "My Laptop").
    pub name: String,
    /// Serialized iroh `NodeId` for transport-level addressing.
    pub node_id: Vec<u8>,
    /// Device priority for message routing (1 = highest).
    pub priority: u8,
    /// Whether this is the primary device.
    pub is_primary: bool,
    /// Unix timestamp (seconds) when the device was linked.
    pub created_at: u64,
    /// Unix timestamp (seconds) of last activity.
    pub last_seen: u64,
}

/// An entry in the sync log table.
///
/// Key: `(device_id_hash: u64, timestamp: u64)`.
/// Value: `SyncLogEntry` serialized with postcard, then encrypted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncLogEntry {
    /// Device ID that produced this sync event.
    pub device_id: [u8; 32],
    /// Sync sequence number.
    pub sequence: u64,
    /// Number of items in the batch.
    pub item_count: u32,
    /// Unix timestamp (seconds).
    pub timestamp: u64,
}

/// Compute a deterministic hash of a device ID for table keys.
#[must_use]
pub fn device_id_hash(device_id: &[u8; 32]) -> u64 {
    let hash = blake3::hash(device_id);
    let bytes: &[u8] = hash.as_bytes();
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

/// Compute a deterministic `contact_id` (u64) from a public key.
///
/// Uses `BLAKE3(pubkey)[0..8]` interpreted as little-endian u64.
/// This is used as the first element of composite keys in the messages table.
#[must_use]
pub fn contact_id(pubkey: &[u8]) -> u64 {
    let hash = blake3::hash(pubkey);
    let bytes: &[u8] = hash.as_bytes();
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contact_id_is_deterministic() {
        let pk = b"some-public-key-bytes";
        assert_eq!(contact_id(pk), contact_id(pk));
    }

    #[test]
    fn contact_id_differs_for_different_keys() {
        let pk1 = b"key-one";
        let pk2 = b"key-two";
        assert_ne!(contact_id(pk1), contact_id(pk2));
    }

    #[test]
    fn contact_info_roundtrip() {
        let info = ContactInfo {
            pubkey: vec![1, 2, 3],
            alias: "Alice".into(),
            added_at: 1_700_000_000,
            verified: true,
            blocked: false,
        };
        let bytes = postcard::to_allocvec(&info).expect("serialize");
        let decoded: ContactInfo = postcard::from_bytes(&bytes).expect("deserialize");
        assert_eq!(decoded.alias, "Alice");
        assert!(decoded.verified);
    }

    #[test]
    fn device_info_roundtrip() {
        let info = DeviceInfo {
            device_id: [0xAB; 32],
            name: "My Laptop".into(),
            node_id: vec![0x01; 32],
            priority: 1,
            is_primary: true,
            created_at: 1_700_000_000,
            last_seen: 1_700_001_000,
        };
        let bytes = postcard::to_allocvec(&info).expect("serialize");
        let decoded: DeviceInfo = postcard::from_bytes(&bytes).expect("deserialize");
        assert_eq!(decoded, info);
    }

    #[test]
    fn sync_log_entry_roundtrip() {
        let entry = SyncLogEntry {
            device_id: [0xCD; 32],
            sequence: 42,
            item_count: 10,
            timestamp: 1_700_000_000,
        };
        let bytes = postcard::to_allocvec(&entry).expect("serialize");
        let decoded: SyncLogEntry = postcard::from_bytes(&bytes).expect("deserialize");
        assert_eq!(decoded, entry);
    }

    #[test]
    fn device_id_hash_is_deterministic() {
        let id = [0xAB; 32];
        assert_eq!(device_id_hash(&id), device_id_hash(&id));
    }

    #[test]
    fn device_id_hash_differs_for_different_ids() {
        let id1 = [0xAA; 32];
        let id2 = [0xBB; 32];
        assert_ne!(device_id_hash(&id1), device_id_hash(&id2));
    }

    #[test]
    fn stored_message_roundtrip() {
        let msg = StoredMessage {
            id: [0xAB; 16],
            sender_is_self: true,
            payload_bytes: vec![10, 20, 30],
            timestamp_micros: 1_700_000_000_000_000,
            ttl_secs: Some(3600),
            read_at: None,
            expires_at: None,
        };
        let bytes = postcard::to_allocvec(&msg).expect("serialize");
        let decoded: StoredMessage = postcard::from_bytes(&bytes).expect("deserialize");
        assert_eq!(decoded.id, [0xAB; 16]);
        assert_eq!(decoded.ttl_secs, Some(3600));
    }
}
