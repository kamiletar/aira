//! FFI-safe types for UniFFI export.
//!
//! These types use `Vec<u8>` instead of fixed-size arrays since UniFFI
//! handles them more naturally across the FFI boundary.

/// FFI-safe error type.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum FfiError {
    /// Storage operation failed.
    #[error("storage error: {msg}")]
    Storage { msg: String },
    /// Crypto / seed derivation failed.
    #[error("crypto error: {msg}")]
    Crypto { msg: String },
    /// Invalid argument provided by caller.
    #[error("invalid argument: {msg}")]
    InvalidArgument { msg: String },
    /// Internal error (should not happen).
    #[error("internal error: {msg}")]
    Internal { msg: String },
}

/// Contact information returned to Kotlin.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiContact {
    /// Contact's ML-DSA public key.
    pub pubkey: Vec<u8>,
    /// Display alias.
    pub alias: String,
    /// Unix timestamp (seconds) when added.
    pub added_at: u64,
}

/// Message returned to Kotlin.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiMessage {
    /// 16-byte message ID.
    pub id: Vec<u8>,
    /// Whether we sent this message.
    pub sender_is_self: bool,
    /// Raw payload bytes.
    pub payload: Vec<u8>,
    /// Timestamp in microseconds since epoch.
    pub timestamp_micros: u64,
}

/// Group information returned to Kotlin.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiGroupInfo {
    /// Group ID (32 bytes).
    pub id: Vec<u8>,
    /// Group display name.
    pub name: String,
    /// Number of members.
    pub member_count: u32,
    /// Unix timestamp (seconds) of creation.
    pub created_at: u64,
}

/// Group member information returned to Kotlin.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiGroupMember {
    /// Member's pseudonym public key for this group (§12.6).
    pub pubkey: Vec<u8>,
    /// User-chosen display name for this group (§12.6).
    pub display_name: String,
    /// "admin" or "member".
    pub role: String,
    /// Unix timestamp (seconds) when joined.
    pub joined_at: u64,
}

/// Detailed group information (with members list).
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiGroupDetail {
    /// Group ID (32 bytes).
    pub id: Vec<u8>,
    /// Group display name.
    pub name: String,
    /// Full members list.
    pub members: Vec<FfiGroupMember>,
    /// Creator's public key.
    pub created_by: Vec<u8>,
    /// Unix timestamp (seconds) of creation.
    pub created_at: u64,
}

/// Device information returned to Kotlin.
#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiDeviceInfo {
    /// Device ID (32 bytes).
    pub device_id: Vec<u8>,
    /// Human-readable device name.
    pub name: String,
    /// Whether this is the primary device.
    pub is_primary: bool,
    /// Unix timestamp (seconds) of last activity.
    pub last_seen: u64,
}

// ─── Conversion helpers ────────────────────────────────────────────────────

impl From<aira_storage::ContactInfo> for FfiContact {
    fn from(c: aira_storage::ContactInfo) -> Self {
        Self {
            pubkey: c.pubkey,
            alias: c.alias,
            added_at: c.added_at,
        }
    }
}

impl From<aira_storage::StoredMessage> for FfiMessage {
    fn from(m: aira_storage::StoredMessage) -> Self {
        Self {
            id: m.id.to_vec(),
            sender_is_self: m.sender_is_self,
            payload: m.payload_bytes,
            timestamp_micros: m.timestamp_micros,
        }
    }
}

impl From<aira_daemon::types::GroupInfoResp> for FfiGroupInfo {
    #[allow(clippy::cast_possible_truncation)]
    fn from(g: aira_daemon::types::GroupInfoResp) -> Self {
        Self {
            id: g.id.to_vec(),
            name: g.name,
            member_count: g.members.len() as u32,
            created_at: g.created_at,
        }
    }
}

impl From<aira_daemon::types::GroupInfoResp> for FfiGroupDetail {
    fn from(g: aira_daemon::types::GroupInfoResp) -> Self {
        Self {
            id: g.id.to_vec(),
            name: g.name,
            members: g
                .members
                .into_iter()
                .map(|m| FfiGroupMember {
                    pubkey: m.pubkey,
                    display_name: m.display_name,
                    role: m.role,
                    joined_at: m.joined_at,
                })
                .collect(),
            created_by: g.created_by,
            created_at: g.created_at,
        }
    }
}

impl From<aira_daemon::types::DeviceInfoResp> for FfiDeviceInfo {
    fn from(d: aira_daemon::types::DeviceInfoResp) -> Self {
        Self {
            device_id: d.device_id.to_vec(),
            name: d.name,
            is_primary: d.is_primary,
            last_seen: d.last_seen,
        }
    }
}
