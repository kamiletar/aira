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
