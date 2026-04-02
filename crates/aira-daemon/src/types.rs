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
    /// Graceful shutdown.
    Shutdown,
}

/// Response from daemon to client.
#[derive(Debug, Serialize, Deserialize)]
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
}
