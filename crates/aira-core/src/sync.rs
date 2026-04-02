//! Device synchronization protocol (SPEC.md §14.3).
//!
//! Pure logic for encoding/decoding sync batches between linked devices.
//! No I/O — the daemon handles transport.
//!
//! # Sync model
//!
//! - Messages are append-only: `(contact_id, timestamp, device_id) → message`
//! - Conflicts are impossible (CRDT-like merge)
//! - Only new messages after linking are synced; full history via backup export/import
//!
//! # Sync items
//!
//! - `Contact` — contact list additions/removals
//! - `Message` — text messages (sent/received)
//! - `RatchetState` — encrypted ratchet snapshot for a contact
//! - `Settings` — app settings changes
//! - `GroupInfo` — group membership changes

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::proto::AiraError;

// ─── Sync item types ────────────────────────────────────────────────────────

/// A single item to be synchronized between devices.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SyncItem {
    /// A contact was added or updated.
    ContactAdded {
        /// Contact's ML-DSA public key.
        pubkey: Vec<u8>,
        /// Display alias.
        alias: String,
        /// Whether the contact is verified.
        verified: bool,
    },
    /// A contact was removed.
    ContactRemoved {
        /// Contact's ML-DSA public key.
        pubkey: Vec<u8>,
    },
    /// A message was sent or received.
    Message {
        /// Contact's ML-DSA public key (for 1-on-1) or group ID.
        contact_key: Vec<u8>,
        /// Unique message ID.
        message_id: [u8; 16],
        /// Whether we sent this message.
        sender_is_self: bool,
        /// Serialized `PlainPayload` bytes.
        payload_bytes: Vec<u8>,
        /// Message timestamp (microseconds since epoch).
        timestamp_micros: u64,
    },
    /// Ratchet state update for a contact.
    RatchetState {
        /// Contact's ML-DSA public key.
        contact_pubkey: Vec<u8>,
        /// Serialized `RatchetSnapshot` bytes.
        snapshot_bytes: Vec<u8>,
    },
    /// A setting was changed.
    SettingChanged {
        /// Setting key.
        key: String,
        /// Setting value (serialized).
        value: Vec<u8>,
    },
    /// Group metadata update.
    GroupUpdate {
        /// Group ID.
        group_id: [u8; 32],
        /// Serialized `GroupInfo` bytes.
        info_bytes: Vec<u8>,
    },
}

/// A batch of sync items with metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncBatch {
    /// Device ID of the sender.
    pub from_device: [u8; 32],
    /// Unix timestamp (seconds) of this batch.
    pub timestamp: u64,
    /// Monotonically increasing sequence number per device.
    pub sequence: u64,
    /// Items to sync.
    pub items: Vec<SyncItem>,
}

/// Per-device sync state tracking.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncState {
    /// Device ID this state tracks.
    pub device_id: [u8; 32],
    /// Last synced timestamp (seconds).
    pub last_sync_timestamp: u64,
    /// Last synced sequence number.
    pub last_sequence: u64,
}

impl SyncState {
    /// Create initial sync state for a device.
    #[must_use]
    pub fn new(device_id: [u8; 32]) -> Self {
        Self {
            device_id,
            last_sync_timestamp: 0,
            last_sequence: 0,
        }
    }

    /// Update the state after processing a batch.
    pub fn update(&mut self, batch: &SyncBatch) {
        if batch.sequence > self.last_sequence {
            self.last_sequence = batch.sequence;
        }
        if batch.timestamp > self.last_sync_timestamp {
            self.last_sync_timestamp = batch.timestamp;
        }
    }
}

// ─── Encrypted sync encoding ────────────────────────────────────────────────

/// Encode and encrypt a sync batch for transmission.
///
/// Format: `nonce (12 bytes) || ciphertext`.
/// Uses the shared device sync key for ChaCha20-Poly1305.
///
/// # Errors
///
/// Returns [`AiraError::Serialization`] if postcard serialization fails.
/// Returns [`AiraError::Encryption`] if `ChaCha20` encryption fails.
pub fn encode_sync_batch(batch: &SyncBatch, sync_key: &[u8; 32]) -> Result<Vec<u8>, AiraError> {
    let plaintext =
        postcard::to_allocvec(batch).map_err(|e| AiraError::Serialization(e.to_string()))?;

    let cipher = ChaCha20Poly1305::new(sync_key.into());
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = chacha20poly1305::Nonce::from(nonce_bytes);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_slice())
        .map_err(|_| AiraError::Encryption)?;

    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt and decode a sync batch.
///
/// # Errors
///
/// Returns [`AiraError::Decryption`] if the data is too short or decryption fails.
/// Returns [`AiraError::Serialization`] if deserialization fails.
pub fn decode_sync_batch(data: &[u8], sync_key: &[u8; 32]) -> Result<SyncBatch, AiraError> {
    if data.len() < 28 {
        // 12 nonce + 16 auth tag minimum
        return Err(AiraError::Decryption);
    }

    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce = chacha20poly1305::Nonce::from_slice(nonce_bytes);
    let cipher = ChaCha20Poly1305::new(sync_key.into());

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| AiraError::Decryption)?;

    postcard::from_bytes(&plaintext).map_err(|e| AiraError::Serialization(e.to_string()))
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_sync_key() -> [u8; 32] {
        [0x42; 32]
    }

    fn sample_batch() -> SyncBatch {
        SyncBatch {
            from_device: [0x01; 32],
            timestamp: 1_700_000_000,
            sequence: 1,
            items: vec![
                SyncItem::ContactAdded {
                    pubkey: vec![0xAA; 32],
                    alias: "Alice".into(),
                    verified: true,
                },
                SyncItem::Message {
                    contact_key: vec![0xAA; 32],
                    message_id: [0xBB; 16],
                    sender_is_self: true,
                    payload_bytes: b"hello from device 1".to_vec(),
                    timestamp_micros: 1_700_000_000_000_000,
                },
            ],
        }
    }

    #[test]
    fn sync_batch_roundtrip() {
        let batch = sample_batch();
        let bytes = postcard::to_allocvec(&batch).expect("serialize");
        let decoded: SyncBatch = postcard::from_bytes(&bytes).expect("deserialize");
        assert_eq!(decoded, batch);
    }

    #[test]
    fn encode_decode_sync_batch() {
        let key = test_sync_key();
        let batch = sample_batch();

        let encoded = encode_sync_batch(&batch, &key).expect("encode");
        let decoded = decode_sync_batch(&encoded, &key).expect("decode");
        assert_eq!(decoded, batch);
    }

    #[test]
    fn encoded_data_is_encrypted() {
        let key = test_sync_key();
        let batch = sample_batch();
        let encoded = encode_sync_batch(&batch, &key).expect("encode");

        // The encoded data should not contain plaintext "Alice"
        let alice_bytes = b"Alice";
        assert!(!encoded.windows(alice_bytes.len()).any(|w| w == alice_bytes));
    }

    #[test]
    fn wrong_key_fails_decode() {
        let key = test_sync_key();
        let wrong_key = [0xFF; 32];
        let batch = sample_batch();

        let encoded = encode_sync_batch(&batch, &key).expect("encode");
        assert!(decode_sync_batch(&encoded, &wrong_key).is_err());
    }

    #[test]
    fn corrupted_data_fails_decode() {
        let key = test_sync_key();
        let batch = sample_batch();
        let mut encoded = encode_sync_batch(&batch, &key).expect("encode");
        let last = encoded.len() - 1;
        encoded[last] ^= 0xFF;
        assert!(decode_sync_batch(&encoded, &key).is_err());
    }

    #[test]
    fn too_short_data_fails_decode() {
        let key = test_sync_key();
        assert!(decode_sync_batch(&[0u8; 10], &key).is_err());
    }

    #[test]
    fn sync_state_update() {
        let mut state = SyncState::new([0x01; 32]);
        assert_eq!(state.last_sequence, 0);
        assert_eq!(state.last_sync_timestamp, 0);

        let batch = SyncBatch {
            from_device: [0x02; 32],
            timestamp: 1_700_000_000,
            sequence: 5,
            items: vec![],
        };
        state.update(&batch);
        assert_eq!(state.last_sequence, 5);
        assert_eq!(state.last_sync_timestamp, 1_700_000_000);

        // Earlier batch should not regress state
        let old_batch = SyncBatch {
            from_device: [0x02; 32],
            timestamp: 1_699_000_000,
            sequence: 3,
            items: vec![],
        };
        state.update(&old_batch);
        assert_eq!(state.last_sequence, 5);
        assert_eq!(state.last_sync_timestamp, 1_700_000_000);
    }

    #[test]
    fn all_sync_item_variants_roundtrip() {
        let items = vec![
            SyncItem::ContactAdded {
                pubkey: vec![1],
                alias: "A".into(),
                verified: false,
            },
            SyncItem::ContactRemoved { pubkey: vec![2] },
            SyncItem::Message {
                contact_key: vec![3],
                message_id: [0x10; 16],
                sender_is_self: false,
                payload_bytes: vec![4, 5],
                timestamp_micros: 100,
            },
            SyncItem::RatchetState {
                contact_pubkey: vec![6],
                snapshot_bytes: vec![7, 8, 9],
            },
            SyncItem::SettingChanged {
                key: "theme".into(),
                value: vec![10],
            },
            SyncItem::GroupUpdate {
                group_id: [0x20; 32],
                info_bytes: vec![11, 12],
            },
        ];

        let batch = SyncBatch {
            from_device: [0xFF; 32],
            timestamp: 999,
            sequence: 42,
            items,
        };

        let key = test_sync_key();
        let encoded = encode_sync_batch(&batch, &key).expect("encode");
        let decoded = decode_sync_batch(&encoded, &key).expect("decode");
        assert_eq!(decoded, batch);
    }

    #[test]
    fn empty_batch_roundtrip() {
        let key = test_sync_key();
        let batch = SyncBatch {
            from_device: [0; 32],
            timestamp: 0,
            sequence: 0,
            items: vec![],
        };
        let encoded = encode_sync_batch(&batch, &key).expect("encode");
        let decoded = decode_sync_batch(&encoded, &key).expect("decode");
        assert_eq!(decoded, batch);
    }

    #[test]
    fn sync_state_roundtrip() {
        let state = SyncState {
            device_id: [0xAB; 32],
            last_sync_timestamp: 1_700_000_000,
            last_sequence: 42,
        };
        let bytes = postcard::to_allocvec(&state).expect("serialize");
        let decoded: SyncState = postcard::from_bytes(&bytes).expect("deserialize");
        assert_eq!(decoded, state);
    }
}
