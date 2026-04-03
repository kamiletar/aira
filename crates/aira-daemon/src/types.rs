//! IPC protocol types for daemon ↔ client communication.
//!
//! Serialized with postcard over Unix socket (Linux/macOS) or Named pipe (Windows).
//! See SPEC.md §8.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Request from client (aira-cli / aira-gui) to daemon.
#[derive(Debug, Serialize, Deserialize)]
pub enum DaemonRequest {
    /// Send a text message to a contact.
    SendMessage {
        /// Contact's ML-DSA public key.
        to: Vec<u8>,
        /// Message text.
        text: String,
    },
    /// Get message history for a contact.
    GetHistory {
        /// Contact's ML-DSA public key.
        contact: Vec<u8>,
        /// Maximum number of messages to return.
        limit: u32,
    },
    /// Add a new contact.
    AddContact {
        /// Contact's ML-DSA public key.
        pubkey: Vec<u8>,
        /// Display name.
        alias: String,
    },
    /// Remove a contact.
    RemoveContact {
        /// Contact's ML-DSA public key.
        pubkey: Vec<u8>,
    },
    /// Get all contacts.
    GetContacts,
    /// Get our own public key / identity address.
    GetMyAddress,
    /// Set disappearing message TTL for a contact.
    SetTtl {
        /// Contact's ML-DSA public key.
        contact: Vec<u8>,
        /// TTL in seconds, or `None` to disable.
        ttl_secs: Option<u64>,
    },
    /// Export encrypted backup.
    ExportBackup {
        /// Output file path.
        path: PathBuf,
        /// Whether to include message history (can be large).
        include_messages: bool,
    },
    /// Import encrypted backup.
    ImportBackup {
        /// Backup file path.
        path: PathBuf,
    },
    /// Send a file to a contact.
    SendFile {
        /// Contact's ML-DSA public key.
        to: Vec<u8>,
        /// Local file path.
        path: PathBuf,
    },
    /// Set the active transport mode (SPEC.md §11A).
    ///
    /// Mode string: `"direct"`, `"obfs4"`, `"mimicry:dns"`, `"mimicry:quic:example.com"`,
    /// `"cdn:https://worker.example.com"`.
    SetTransportMode {
        /// Transport mode string (parsed by `TransportMode::from_str`).
        mode: String,
    },
    /// Get the current transport mode.
    GetTransportMode,

    /// Graceful shutdown.
    Shutdown,

    // ─── Group operations (SPEC.md §12) ─────────────────────────────────
    /// Create a new group.
    CreateGroup {
        /// Group display name.
        name: String,
        /// Pseudonym public keys of initial members (§12.6).
        members: Vec<Vec<u8>>,
    },
    /// Get all groups.
    GetGroups,
    /// Get info about a specific group.
    GetGroupInfo {
        /// Group ID (32 bytes).
        group_id: [u8; 32],
    },
    /// Send a text message to a group.
    SendGroupMessage {
        /// Group ID (32 bytes).
        group_id: [u8; 32],
        /// Message text.
        text: String,
    },
    /// Get group message history.
    GetGroupHistory {
        /// Group ID (32 bytes).
        group_id: [u8; 32],
        /// Maximum number of messages to return.
        limit: u32,
    },
    /// Add a member to a group (Admin only).
    GroupAddMember {
        /// Group ID (32 bytes).
        group_id: [u8; 32],
        /// New member's pseudonym public key (§12.6).
        member: Vec<u8>,
    },
    /// Remove a member from a group (Admin only).
    GroupRemoveMember {
        /// Group ID (32 bytes).
        group_id: [u8; 32],
        /// Member's pseudonym public key to remove (§12.6).
        member: Vec<u8>,
    },
    /// Leave a group.
    LeaveGroup {
        /// Group ID (32 bytes).
        group_id: [u8; 32],
    },
    /// Accept a group invitation — derives pseudonym and enqueues response (§12.6).
    AcceptGroupInvite {
        /// Group ID (32 bytes).
        group_id: [u8; 32],
        /// User-chosen display name for this group.
        display_name: String,
        /// Admin's pseudonym pubkey who invited us (for 1-on-1 response).
        invited_by: Vec<u8>,
    },

    // ─── Pseudonym operations (SPEC.md §12.6) ───────────────────────────
    /// Get all pseudonym records.
    GetPseudonyms,
    /// Get a pseudonym record by its counter.
    GetPseudonym {
        /// Counter value.
        counter: u32,
    },
    /// Find pseudonym for a specific context (group or contact).
    FindPseudonym {
        /// Context ID (`group_id` or contact hash).
        context_id: [u8; 32],
    },

    // ─── Device operations (SPEC.md §14) ────────────────────────────────
    /// Generate a one-time link code for pairing a new device.
    GenerateLinkCode,
    /// Link a new device using a previously generated code.
    LinkDevice {
        /// The 6-digit link code.
        code: String,
        /// Human-readable name for the new device.
        device_name: String,
    },
    /// Get all linked devices.
    GetDevices,
    /// Unlink (remove) a device.
    UnlinkDevice {
        /// Device ID to remove (32 bytes).
        device_id: [u8; 32],
    },
}

/// Response from daemon to client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DaemonResponse {
    /// Operation succeeded (no data to return).
    Ok,
    /// Operation failed.
    Error(String),
    /// Message history.
    History(Vec<aira_storage::StoredMessage>),
    /// Contact list.
    Contacts(Vec<aira_storage::ContactInfo>),
    /// Our own public key bytes.
    MyAddress(Vec<u8>),

    /// Current transport mode string.
    TransportMode(String),

    // ─── Group responses ────────────────────────────────────────────────
    /// Group created successfully.
    GroupCreated {
        /// The new group's ID (32 bytes).
        group_id: [u8; 32],
    },
    /// Single group info.
    GroupInfo(GroupInfoResp),
    /// List of all groups.
    Groups(Vec<GroupInfoResp>),
    /// Group message history.
    GroupHistory(Vec<aira_storage::StoredMessage>),

    // ─── Pseudonym responses (§12.6) ────────────────────────────────────
    /// List of all pseudonym records.
    Pseudonyms(Vec<PseudonymResp>),
    /// Single pseudonym record (or None).
    Pseudonym(Option<PseudonymResp>),

    // ─── Device responses ───────────────────────────────────────────────
    /// Generated link code for device pairing.
    LinkCode(String),
    /// Device linked successfully.
    DeviceLinked {
        /// The new device's ID.
        device_id: [u8; 32],
        /// Device display name.
        name: String,
    },
    /// List of linked devices.
    Devices(Vec<DeviceInfoResp>),
}

/// Group information returned in daemon responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupInfoResp {
    /// Group ID (32 bytes).
    pub id: [u8; 32],
    /// Group display name.
    pub name: String,
    /// Member pseudonym pubkeys with roles (§12.6).
    pub members: Vec<GroupMemberResp>,
    /// Creator's pseudonym public key (§12.6).
    pub created_by: Vec<u8>,
    /// Unix timestamp (seconds) of creation.
    pub created_at: u64,
}

/// Group member info in daemon responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMemberResp {
    /// Member's pseudonym public key for this group (§12.6).
    pub pubkey: Vec<u8>,
    /// User-chosen display name for this group (§12.6).
    pub display_name: String,
    /// "admin" or "member".
    pub role: String,
    /// Unix timestamp (seconds) when joined.
    pub joined_at: u64,
}

/// Pseudonym record returned in daemon responses (§12.6).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PseudonymResp {
    /// BIP-32-style counter.
    pub counter: u32,
    /// ML-DSA pseudonym public key.
    pub pubkey: Vec<u8>,
    /// "contact" or "group".
    pub context_type: String,
    /// Context identifier (`group_id` or contact hash).
    pub context_id: [u8; 32],
    /// User-chosen display name.
    pub display_name: String,
    /// Unix timestamp (seconds) when created.
    pub created_at: u64,
}

/// Device information returned in daemon responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfoResp {
    /// Device ID (32 bytes).
    pub device_id: [u8; 32],
    /// Human-readable device name.
    pub name: String,
    /// Whether this is the primary device.
    pub is_primary: bool,
    /// Device priority (1 = highest).
    pub priority: u8,
    /// Unix timestamp (seconds) of last activity.
    pub last_seen: u64,
}

/// Wrapper for all messages sent from daemon to client over IPC.
///
/// Both responses and events travel over the same socket connection.
/// This enum lets the client distinguish between a direct response to
/// its request and an asynchronous event from the daemon.
#[derive(Debug, Serialize, Deserialize)]
pub enum ServerMessage {
    /// Direct response to a `DaemonRequest`.
    Response(DaemonResponse),
    /// Asynchronous event (new message, contact online, file progress, etc.).
    Event(DaemonEvent),
}

/// Asynchronous event pushed from daemon to subscribed clients.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DaemonEvent {
    /// A new message was received.
    MessageReceived {
        /// Sender's ML-DSA public key.
        from: Vec<u8>,
        /// Serialized `PlainPayload` bytes.
        payload: Vec<u8>,
    },
    /// Contact came online.
    ContactOnline(Vec<u8>),
    /// Contact went offline.
    ContactOffline(Vec<u8>),
    /// File transfer progress update.
    FileProgress {
        /// Transfer ID.
        id: [u8; 16],
        /// Bytes transferred so far.
        bytes_sent: u64,
        /// Total file size in bytes.
        total: u64,
    },
    /// File transfer completed successfully.
    FileComplete {
        /// Transfer ID.
        id: [u8; 16],
        /// Local path where file was saved (for receiver).
        path: PathBuf,
    },
    /// File transfer failed.
    FileError {
        /// Transfer ID.
        id: [u8; 16],
        /// Error description.
        error: String,
    },

    // ─── Group events (SPEC.md §12) ─────────────────────────────────────
    /// A group message was received.
    GroupMessageReceived {
        /// Group ID (32 bytes).
        group_id: [u8; 32],
        /// Sender's pseudonym public key for this group (§12.6).
        from: Vec<u8>,
        /// Serialized `PlainPayload` bytes.
        payload: Vec<u8>,
    },
    /// A member joined a group.
    GroupMemberJoined {
        /// Group ID (32 bytes).
        group_id: [u8; 32],
        /// New member's pseudonym public key (§12.6).
        member: Vec<u8>,
    },
    /// A member left a group.
    GroupMemberLeft {
        /// Group ID (32 bytes).
        group_id: [u8; 32],
        /// Member's pseudonym public key (§12.6).
        member: Vec<u8>,
    },
    /// A new group was created (we were invited).
    GroupInvite {
        /// Group ID (32 bytes).
        group_id: [u8; 32],
        /// Group name.
        name: String,
        /// Inviter's pseudonym public key (§12.6).
        invited_by: Vec<u8>,
    },

    // ─── Device events (SPEC.md §14) ────────────────────────────────────
    /// A new device was linked to this identity.
    DeviceLinked {
        /// Device ID (32 bytes).
        device_id: [u8; 32],
        /// Device name.
        name: String,
    },
    /// A device was unlinked from this identity.
    DeviceUnlinked {
        /// Device ID (32 bytes).
        device_id: [u8; 32],
    },
    /// Device synchronization completed.
    SyncCompleted {
        /// Remote device ID (32 bytes).
        device_id: [u8; 32],
        /// Number of messages synced.
        messages_synced: u32,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_roundtrip() {
        let req = DaemonRequest::SendMessage {
            to: vec![1, 2, 3],
            text: "hello".into(),
        };
        let bytes = postcard::to_allocvec(&req).expect("serialize");
        let decoded: DaemonRequest = postcard::from_bytes(&bytes).expect("deserialize");
        match decoded {
            DaemonRequest::SendMessage { to, text } => {
                assert_eq!(to, vec![1, 2, 3]);
                assert_eq!(text, "hello");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn response_roundtrip() {
        let resp = DaemonResponse::MyAddress(vec![0xAB; 32]);
        let bytes = postcard::to_allocvec(&resp).expect("serialize");
        let decoded: DaemonResponse = postcard::from_bytes(&bytes).expect("deserialize");
        match decoded {
            DaemonResponse::MyAddress(addr) => assert_eq!(addr.len(), 32),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn event_roundtrip() {
        let event = DaemonEvent::MessageReceived {
            from: vec![1; 16],
            payload: b"content".to_vec(),
        };
        let bytes = postcard::to_allocvec(&event).expect("serialize");
        let decoded: DaemonEvent = postcard::from_bytes(&bytes).expect("deserialize");
        match decoded {
            DaemonEvent::MessageReceived { from, payload } => {
                assert_eq!(from.len(), 16);
                assert_eq!(payload, b"content");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn send_file_request_roundtrip() {
        let req = DaemonRequest::SendFile {
            to: vec![0xAA; 32],
            path: PathBuf::from("/tmp/test.txt"),
        };
        let bytes = postcard::to_allocvec(&req).expect("serialize");
        let decoded: DaemonRequest = postcard::from_bytes(&bytes).expect("deserialize");
        match decoded {
            DaemonRequest::SendFile { to, path } => {
                assert_eq!(to, vec![0xAA; 32]);
                assert_eq!(path, PathBuf::from("/tmp/test.txt"));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn file_progress_event_roundtrip() {
        let event = DaemonEvent::FileProgress {
            id: [0x42; 16],
            bytes_sent: 1024,
            total: 65536,
        };
        let bytes = postcard::to_allocvec(&event).expect("serialize");
        let decoded: DaemonEvent = postcard::from_bytes(&bytes).expect("deserialize");
        match decoded {
            DaemonEvent::FileProgress {
                id,
                bytes_sent,
                total,
            } => {
                assert_eq!(id, [0x42; 16]);
                assert_eq!(bytes_sent, 1024);
                assert_eq!(total, 65536);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn file_complete_event_roundtrip() {
        let event = DaemonEvent::FileComplete {
            id: [0x01; 16],
            path: PathBuf::from("/home/user/.aira/downloads/photo.jpg"),
        };
        let bytes = postcard::to_allocvec(&event).expect("serialize");
        let decoded: DaemonEvent = postcard::from_bytes(&bytes).expect("deserialize");
        match decoded {
            DaemonEvent::FileComplete { id, path } => {
                assert_eq!(id, [0x01; 16]);
                assert_eq!(path, PathBuf::from("/home/user/.aira/downloads/photo.jpg"));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn server_message_response_roundtrip() {
        let msg = ServerMessage::Response(DaemonResponse::Ok);
        let bytes = postcard::to_allocvec(&msg).expect("serialize");
        let decoded: ServerMessage = postcard::from_bytes(&bytes).expect("deserialize");
        match decoded {
            ServerMessage::Response(DaemonResponse::Ok) => {}
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn server_message_event_roundtrip() {
        let msg = ServerMessage::Event(DaemonEvent::ContactOnline(vec![0xAB; 32]));
        let bytes = postcard::to_allocvec(&msg).expect("serialize");
        let decoded: ServerMessage = postcard::from_bytes(&bytes).expect("deserialize");
        match decoded {
            ServerMessage::Event(DaemonEvent::ContactOnline(pk)) => {
                assert_eq!(pk.len(), 32);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn create_group_request_roundtrip() {
        let req = DaemonRequest::CreateGroup {
            name: "Test Group".into(),
            members: vec![vec![0xAA; 32], vec![0xBB; 32]],
        };
        let bytes = postcard::to_allocvec(&req).expect("serialize");
        let decoded: DaemonRequest = postcard::from_bytes(&bytes).expect("deserialize");
        match decoded {
            DaemonRequest::CreateGroup { name, members } => {
                assert_eq!(name, "Test Group");
                assert_eq!(members.len(), 2);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn send_group_message_request_roundtrip() {
        let req = DaemonRequest::SendGroupMessage {
            group_id: [0x11; 32],
            text: "hello group".into(),
        };
        let bytes = postcard::to_allocvec(&req).expect("serialize");
        let decoded: DaemonRequest = postcard::from_bytes(&bytes).expect("deserialize");
        match decoded {
            DaemonRequest::SendGroupMessage { group_id, text } => {
                assert_eq!(group_id, [0x11; 32]);
                assert_eq!(text, "hello group");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn group_created_response_roundtrip() {
        let resp = DaemonResponse::GroupCreated {
            group_id: [0xFF; 32],
        };
        let bytes = postcard::to_allocvec(&resp).expect("serialize");
        let decoded: DaemonResponse = postcard::from_bytes(&bytes).expect("deserialize");
        match decoded {
            DaemonResponse::GroupCreated { group_id } => {
                assert_eq!(group_id, [0xFF; 32]);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn group_info_response_roundtrip() {
        let resp = DaemonResponse::GroupInfo(GroupInfoResp {
            id: [0x22; 32],
            name: "My Group".into(),
            members: vec![GroupMemberResp {
                pubkey: vec![0xAA; 32],
                display_name: "Alice".into(),
                role: "admin".into(),
                joined_at: 1_700_000_000,
            }],
            created_by: vec![0xAA; 32],
            created_at: 1_700_000_000,
        });
        let bytes = postcard::to_allocvec(&resp).expect("serialize");
        let decoded: DaemonResponse = postcard::from_bytes(&bytes).expect("deserialize");
        match decoded {
            DaemonResponse::GroupInfo(info) => {
                assert_eq!(info.name, "My Group");
                assert_eq!(info.members.len(), 1);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn group_message_received_event_roundtrip() {
        let event = DaemonEvent::GroupMessageReceived {
            group_id: [0x33; 32],
            from: vec![0xBB; 32],
            payload: b"content".to_vec(),
        };
        let bytes = postcard::to_allocvec(&event).expect("serialize");
        let decoded: DaemonEvent = postcard::from_bytes(&bytes).expect("deserialize");
        match decoded {
            DaemonEvent::GroupMessageReceived {
                group_id,
                from,
                payload,
            } => {
                assert_eq!(group_id, [0x33; 32]);
                assert_eq!(from, vec![0xBB; 32]);
                assert_eq!(payload, b"content");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn group_member_joined_event_roundtrip() {
        let event = DaemonEvent::GroupMemberJoined {
            group_id: [0x44; 32],
            member: vec![0xCC; 32],
        };
        let bytes = postcard::to_allocvec(&event).expect("serialize");
        let decoded: DaemonEvent = postcard::from_bytes(&bytes).expect("deserialize");
        match decoded {
            DaemonEvent::GroupMemberJoined { group_id, member } => {
                assert_eq!(group_id, [0x44; 32]);
                assert_eq!(member, vec![0xCC; 32]);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn group_invite_event_roundtrip() {
        let event = DaemonEvent::GroupInvite {
            group_id: [0x55; 32],
            name: "Group Alpha".into(),
            invited_by: vec![0xDD; 32],
        };
        let bytes = postcard::to_allocvec(&event).expect("serialize");
        let decoded: DaemonEvent = postcard::from_bytes(&bytes).expect("deserialize");
        match decoded {
            DaemonEvent::GroupInvite {
                group_id,
                name,
                invited_by,
            } => {
                assert_eq!(group_id, [0x55; 32]);
                assert_eq!(name, "Group Alpha");
                assert_eq!(invited_by, vec![0xDD; 32]);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn set_transport_mode_request_roundtrip() {
        let req = DaemonRequest::SetTransportMode {
            mode: "mimicry:quic:example.com".into(),
        };
        let bytes = postcard::to_allocvec(&req).expect("serialize");
        let decoded: DaemonRequest = postcard::from_bytes(&bytes).expect("deserialize");
        match decoded {
            DaemonRequest::SetTransportMode { mode } => {
                assert_eq!(mode, "mimicry:quic:example.com");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn get_transport_mode_request_roundtrip() {
        let req = DaemonRequest::GetTransportMode;
        let bytes = postcard::to_allocvec(&req).expect("serialize");
        let decoded: DaemonRequest = postcard::from_bytes(&bytes).expect("deserialize");
        assert!(matches!(decoded, DaemonRequest::GetTransportMode));
    }

    #[test]
    fn transport_mode_response_roundtrip() {
        let resp = DaemonResponse::TransportMode("obfs4".into());
        let bytes = postcard::to_allocvec(&resp).expect("serialize");
        let decoded: DaemonResponse = postcard::from_bytes(&bytes).expect("deserialize");
        match decoded {
            DaemonResponse::TransportMode(mode) => assert_eq!(mode, "obfs4"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn file_error_event_roundtrip() {
        let event = DaemonEvent::FileError {
            id: [0xFF; 16],
            error: "connection lost".into(),
        };
        let bytes = postcard::to_allocvec(&event).expect("serialize");
        let decoded: DaemonEvent = postcard::from_bytes(&bytes).expect("deserialize");
        match decoded {
            DaemonEvent::FileError { id, error } => {
                assert_eq!(id, [0xFF; 16]);
                assert_eq!(error, "connection lost");
            }
            _ => panic!("wrong variant"),
        }
    }

    // ─── Device IPC roundtrip tests ─────────────────────────────────────

    #[test]
    fn generate_link_code_request_roundtrip() {
        let req = DaemonRequest::GenerateLinkCode;
        let bytes = postcard::to_allocvec(&req).expect("serialize");
        let decoded: DaemonRequest = postcard::from_bytes(&bytes).expect("deserialize");
        assert!(matches!(decoded, DaemonRequest::GenerateLinkCode));
    }

    #[test]
    fn link_device_request_roundtrip() {
        let req = DaemonRequest::LinkDevice {
            code: "042871".into(),
            device_name: "My Phone".into(),
        };
        let bytes = postcard::to_allocvec(&req).expect("serialize");
        let decoded: DaemonRequest = postcard::from_bytes(&bytes).expect("deserialize");
        match decoded {
            DaemonRequest::LinkDevice { code, device_name } => {
                assert_eq!(code, "042871");
                assert_eq!(device_name, "My Phone");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn get_devices_request_roundtrip() {
        let req = DaemonRequest::GetDevices;
        let bytes = postcard::to_allocvec(&req).expect("serialize");
        let decoded: DaemonRequest = postcard::from_bytes(&bytes).expect("deserialize");
        assert!(matches!(decoded, DaemonRequest::GetDevices));
    }

    #[test]
    fn unlink_device_request_roundtrip() {
        let req = DaemonRequest::UnlinkDevice {
            device_id: [0xAB; 32],
        };
        let bytes = postcard::to_allocvec(&req).expect("serialize");
        let decoded: DaemonRequest = postcard::from_bytes(&bytes).expect("deserialize");
        match decoded {
            DaemonRequest::UnlinkDevice { device_id } => {
                assert_eq!(device_id, [0xAB; 32]);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn link_code_response_roundtrip() {
        let resp = DaemonResponse::LinkCode("123456".into());
        let bytes = postcard::to_allocvec(&resp).expect("serialize");
        let decoded: DaemonResponse = postcard::from_bytes(&bytes).expect("deserialize");
        match decoded {
            DaemonResponse::LinkCode(code) => assert_eq!(code, "123456"),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn device_linked_response_roundtrip() {
        let resp = DaemonResponse::DeviceLinked {
            device_id: [0xCD; 32],
            name: "Laptop".into(),
        };
        let bytes = postcard::to_allocvec(&resp).expect("serialize");
        let decoded: DaemonResponse = postcard::from_bytes(&bytes).expect("deserialize");
        match decoded {
            DaemonResponse::DeviceLinked { device_id, name } => {
                assert_eq!(device_id, [0xCD; 32]);
                assert_eq!(name, "Laptop");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn devices_response_roundtrip() {
        let resp = DaemonResponse::Devices(vec![
            DeviceInfoResp {
                device_id: [0x01; 32],
                name: "Laptop".into(),
                is_primary: true,
                priority: 1,
                last_seen: 1_700_000_000,
            },
            DeviceInfoResp {
                device_id: [0x02; 32],
                name: "Phone".into(),
                is_primary: false,
                priority: 2,
                last_seen: 1_700_001_000,
            },
        ]);
        let bytes = postcard::to_allocvec(&resp).expect("serialize");
        let decoded: DaemonResponse = postcard::from_bytes(&bytes).expect("deserialize");
        match decoded {
            DaemonResponse::Devices(devices) => {
                assert_eq!(devices.len(), 2);
                assert_eq!(devices[0].name, "Laptop");
                assert!(devices[0].is_primary);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn device_linked_event_roundtrip() {
        let event = DaemonEvent::DeviceLinked {
            device_id: [0xEE; 32],
            name: "Tablet".into(),
        };
        let bytes = postcard::to_allocvec(&event).expect("serialize");
        let decoded: DaemonEvent = postcard::from_bytes(&bytes).expect("deserialize");
        match decoded {
            DaemonEvent::DeviceLinked { device_id, name } => {
                assert_eq!(device_id, [0xEE; 32]);
                assert_eq!(name, "Tablet");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn device_unlinked_event_roundtrip() {
        let event = DaemonEvent::DeviceUnlinked {
            device_id: [0xFF; 32],
        };
        let bytes = postcard::to_allocvec(&event).expect("serialize");
        let decoded: DaemonEvent = postcard::from_bytes(&bytes).expect("deserialize");
        match decoded {
            DaemonEvent::DeviceUnlinked { device_id } => {
                assert_eq!(device_id, [0xFF; 32]);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn sync_completed_event_roundtrip() {
        let event = DaemonEvent::SyncCompleted {
            device_id: [0x11; 32],
            messages_synced: 42,
        };
        let bytes = postcard::to_allocvec(&event).expect("serialize");
        let decoded: DaemonEvent = postcard::from_bytes(&bytes).expect("deserialize");
        match decoded {
            DaemonEvent::SyncCompleted {
                device_id,
                messages_synced,
            } => {
                assert_eq!(device_id, [0x11; 32]);
                assert_eq!(messages_synced, 42);
            }
            _ => panic!("wrong variant"),
        }
    }
}
