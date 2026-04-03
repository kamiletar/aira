//! Group chat wire protocol types (SPEC.md §12).
//!
//! - [`GroupMessage`] — plaintext group message with causal ordering
//! - [`EncryptedGroupEnvelope`] — encrypted group message envelope
//! - [`GroupControl`] — group management control messages
//! - [`GroupRole`] — admin vs member permissions

use serde::{Deserialize, Serialize};

// ─── Group roles ────────────────────────────────────────────────────────────

/// Role of a member within a group.
///
/// Admins can add/remove members; regular members can only read/write messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GroupRole {
    /// Can add/remove members, manage the group.
    Admin,
    /// Can read/write messages only.
    Member,
}

// ─── Group message ──────────────────────────────────────────────────────────

/// Plaintext group message with causal ordering via `parent_id`.
///
/// Each sender chains their own messages: `parent_id` points to the
/// sender's previous message in this group (DAG-lite, SPEC.md §12).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMessage {
    /// Group identifier (32 random bytes).
    pub group_id: [u8; 32],
    /// Sender's pseudonym public key for this group (§12.6).
    pub from: Vec<u8>,
    /// Serialized `PlainPayload` bytes.
    pub payload: Vec<u8>,
    /// Unique message ID (16 random bytes).
    pub id: [u8; 16],
    /// Previous message ID from the same sender (causal link).
    pub parent_id: Option<[u8; 16]>,
    /// Sender key counter at encryption time.
    pub counter: u64,
    /// Unix timestamp in microseconds.
    pub timestamp: u64,
}

// ─── Encrypted group envelope ───────────────────────────────────────────────

/// Encrypted group message envelope sent to each member.
///
/// The ciphertext is encrypted with the sender's Sender Key.
/// All members decrypt with the sender's chain key (stored locally).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedGroupEnvelope {
    /// Group identifier.
    pub group_id: [u8; 32],
    /// Sender's pseudonym public key for this group (§12.6).
    pub from: Vec<u8>,
    /// Sender key counter (for ordering & skip detection).
    pub counter: u64,
    /// ChaCha20-Poly1305 nonce (12 bytes).
    pub nonce: [u8; 12],
    /// Encrypted `GroupMessage` bytes.
    pub ciphertext: Vec<u8>,
}

// ─── Group control messages ────────────────────────────────────────────────

/// Control messages for group management.
///
/// Sent via 1-on-1 encrypted channels (inside `PlainPayload::GroupControl`)
/// to ensure E2E encryption of group metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GroupControl {
    /// Creator invites members to a new group.
    CreateGroup {
        /// Group identifier (32 random bytes).
        group_id: [u8; 32],
        /// Group display name.
        name: String,
        /// All initial member pseudonym pubkeys, including creator (§12.6).
        members: Vec<Vec<u8>>,
        /// Creator's initial Sender Key chain key (encrypted for this recipient).
        creator_sender_key: Vec<u8>,
    },

    /// Admin adds a new member to the group.
    AddMember {
        /// Group identifier.
        group_id: [u8; 32],
        /// New member's pseudonym public key for this group (§12.6).
        new_member: Vec<u8>,
        /// Per-member Sender Keys: `(pseudonym_pubkey, encrypted_sender_key)`.
        /// New member receives all existing members' keys.
        /// Existing members receive the new member's key.
        sender_keys: Vec<(Vec<u8>, Vec<u8>)>,
    },

    /// Admin removes a member from the group.
    RemoveMember {
        /// Group identifier.
        group_id: [u8; 32],
        /// Removed member's pseudonym public key (§12.6).
        removed: Vec<u8>,
    },

    /// Member distributes a new Sender Key after rotation.
    ///
    /// Triggered after a member is added or removed.
    SenderKeyUpdate {
        /// Group identifier.
        group_id: [u8; 32],
        /// New chain key bytes (plaintext — already inside E2E 1-on-1 channel).
        new_key: Vec<u8>,
    },

    /// Member voluntarily leaves the group.
    Leave {
        /// Group identifier.
        group_id: [u8; 32],
    },
}

// ─── Pseudonym management (§12.6) ─────────────────────────────────────────

/// Voluntary disclosure of pseudonym linkage (§12.6.6).
///
/// Allows a user to prove to a trusted contact that two of their pseudonyms
/// belong to the same identity. Sent over a 1-on-1 E2E channel.
///
/// Both signatures must verify over the canonical `(pseudonym_a, pseudonym_b)`
/// byte sequence (sorted lexicographically).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PseudonymLink {
    /// First pseudonym public key.
    pub pseudonym_a: Vec<u8>,
    /// Second pseudonym public key.
    pub pseudonym_b: Vec<u8>,
    /// ML-DSA signature by `pseudonym_a`'s signing key.
    pub sig_a: Vec<u8>,
    /// ML-DSA signature by `pseudonym_b`'s signing key.
    pub sig_b: Vec<u8>,
}

/// Pseudonym rotation within a group (§12.6.7).
///
/// Sent to all group members via 1-on-1 channels when a member
/// changes their pseudonym (new display name or key rotation).
/// Must be accompanied by a [`GroupControl::SenderKeyUpdate`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PseudonymRotation {
    /// Group identifier.
    pub group_id: [u8; 32],
    /// Old pseudonym public key (being replaced).
    pub old_pubkey: Vec<u8>,
    /// New pseudonym public key.
    pub new_pubkey: Vec<u8>,
    /// New display name (may be unchanged).
    pub new_display_name: String,
    /// ML-DSA signature by the old key over `(group_id, old_pubkey, new_pubkey)`.
    pub signature: Vec<u8>,
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_message_roundtrip() {
        let msg = GroupMessage {
            group_id: [0xAA; 32],
            from: vec![1, 2, 3],
            payload: b"hello group".to_vec(),
            id: [0xBB; 16],
            parent_id: Some([0xCC; 16]),
            counter: 42,
            timestamp: 1_700_000_000_000_000,
        };
        let bytes = postcard::to_allocvec(&msg).expect("serialize");
        let restored: GroupMessage = postcard::from_bytes(&bytes).expect("deserialize");
        assert_eq!(restored.group_id, [0xAA; 32]);
        assert_eq!(restored.from, vec![1, 2, 3]);
        assert_eq!(restored.payload, b"hello group");
        assert_eq!(restored.id, [0xBB; 16]);
        assert_eq!(restored.parent_id, Some([0xCC; 16]));
        assert_eq!(restored.counter, 42);
    }

    #[test]
    fn encrypted_group_envelope_roundtrip() {
        let env = EncryptedGroupEnvelope {
            group_id: [0x11; 32],
            from: vec![0xAB; 48],
            counter: 7,
            nonce: [0x22; 12],
            ciphertext: vec![0x33; 128],
        };
        let bytes = postcard::to_allocvec(&env).expect("serialize");
        let restored: EncryptedGroupEnvelope = postcard::from_bytes(&bytes).expect("deserialize");
        assert_eq!(restored.group_id, [0x11; 32]);
        assert_eq!(restored.counter, 7);
        assert_eq!(restored.nonce, [0x22; 12]);
        assert_eq!(restored.ciphertext.len(), 128);
    }

    #[test]
    fn group_control_create_roundtrip() {
        let ctrl = GroupControl::CreateGroup {
            group_id: [0xFF; 32],
            name: "Test Group".into(),
            members: vec![vec![1; 32], vec![2; 32]],
            creator_sender_key: vec![0xAA; 32],
        };
        let bytes = postcard::to_allocvec(&ctrl).expect("serialize");
        let restored: GroupControl = postcard::from_bytes(&bytes).expect("deserialize");
        match restored {
            GroupControl::CreateGroup {
                group_id,
                name,
                members,
                creator_sender_key,
            } => {
                assert_eq!(group_id, [0xFF; 32]);
                assert_eq!(name, "Test Group");
                assert_eq!(members.len(), 2);
                assert_eq!(creator_sender_key.len(), 32);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn group_control_variants_roundtrip() {
        let controls = vec![
            GroupControl::AddMember {
                group_id: [1; 32],
                new_member: vec![2; 32],
                sender_keys: vec![(vec![3; 32], vec![4; 32])],
            },
            GroupControl::RemoveMember {
                group_id: [5; 32],
                removed: vec![6; 32],
            },
            GroupControl::SenderKeyUpdate {
                group_id: [7; 32],
                new_key: vec![8; 32],
            },
            GroupControl::Leave { group_id: [9; 32] },
        ];
        for ctrl in controls {
            let bytes = postcard::to_allocvec(&ctrl).expect("serialize");
            let _restored: GroupControl = postcard::from_bytes(&bytes).expect("deserialize");
        }
    }

    #[test]
    fn pseudonym_link_roundtrip() {
        let link = PseudonymLink {
            pseudonym_a: vec![0xAA; 1952],
            pseudonym_b: vec![0xBB; 1952],
            sig_a: vec![0x11; 3309],
            sig_b: vec![0x22; 3309],
        };
        let bytes = postcard::to_allocvec(&link).expect("serialize");
        let restored: PseudonymLink = postcard::from_bytes(&bytes).expect("deserialize");
        assert_eq!(restored.pseudonym_a, vec![0xAA; 1952]);
        assert_eq!(restored.pseudonym_b, vec![0xBB; 1952]);
        assert_eq!(restored.sig_a.len(), 3309);
        assert_eq!(restored.sig_b.len(), 3309);
    }

    #[test]
    fn pseudonym_rotation_roundtrip() {
        let rot = PseudonymRotation {
            group_id: [0xFF; 32],
            old_pubkey: vec![0xAA; 1952],
            new_pubkey: vec![0xBB; 1952],
            new_display_name: "New Name".into(),
            signature: vec![0xCC; 3309],
        };
        let bytes = postcard::to_allocvec(&rot).expect("serialize");
        let restored: PseudonymRotation = postcard::from_bytes(&bytes).expect("deserialize");
        assert_eq!(restored.group_id, [0xFF; 32]);
        assert_eq!(restored.old_pubkey, vec![0xAA; 1952]);
        assert_eq!(restored.new_pubkey, vec![0xBB; 1952]);
        assert_eq!(restored.new_display_name, "New Name");
        assert_eq!(restored.signature.len(), 3309);
    }

    #[test]
    fn group_role_roundtrip() {
        for role in [GroupRole::Admin, GroupRole::Member] {
            let bytes = postcard::to_allocvec(&role).expect("serialize");
            let restored: GroupRole = postcard::from_bytes(&bytes).expect("deserialize");
            assert_eq!(restored, role);
        }
    }
}
