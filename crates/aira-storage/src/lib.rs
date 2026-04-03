//! aira-storage — redb embedded database for contacts, messages, sessions.
//!
//! The database is encrypted with a storage key derived from the seed phrase
//! (SPEC.md §7.1): `storage_key = BLAKE3-KDF(master_seed, "aira/storage/0")`.
//!
//! # Tables
//!
//! - `contacts` — contact list (ML-DSA pubkey -> `ContactInfo`)
//! - `messages` — message history ((`contact_id`, `timestamp_micros`) -> `StoredMessage`)
//! - `sessions` — ratchet states (contact pubkey -> `RatchetState`, encrypted)
//! - `pending_messages` — outgoing queue ((`contact_id`, seq) -> `EncryptedEnvelope`)
//! - `seen_message_ids` — dedup window (`message_id` -> `timestamp_secs`, SPEC.md §6.21)
//! - `settings` — app settings (key -> value)
//! - `groups` — group chat metadata (`group_id` -> `GroupInfo`)
//! - `group_messages` — group messages ((`group_id`, timestamp) -> `StoredMessage`)
//! - `pseudonyms` — pseudonym records (`counter: u32` -> `PseudonymRecord`, §12.6)
//! - `pseudonym_counter` — counter singleton (`"current"` -> `u32`)

#![deny(unsafe_code)]
#![warn(clippy::all, clippy::pedantic)]

use std::path::Path;

use redb::{Database, TableDefinition};
use zeroize::Zeroizing;

pub mod backup;
pub mod contacts;
pub mod dedup;
pub mod devices;
pub mod encrypted;
pub mod groups;
pub mod messages;
pub mod pending;
pub mod sessions;
pub mod settings;
pub mod types;

pub mod pseudonyms;

pub use types::{
    contact_id, ContactInfo, DeviceInfo, GroupInfo, GroupMemberInfo, GroupRole, PseudonymRecord,
    StoredMessage, SyncLogEntry,
};

// ─── Table definitions ──────────────────────────────────────────────────────

pub const CONTACTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("contacts");
pub const MESSAGES: TableDefinition<(u64, u64), &[u8]> = TableDefinition::new("messages");
pub const SESSIONS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("sessions");
pub const PENDING: TableDefinition<(u64, u64), &[u8]> = TableDefinition::new("pending_messages");
/// Dedup window: `message_id` (16 bytes) -> unix timestamp when seen (SPEC.md §6.21).
pub const SEEN_IDS: TableDefinition<&[u8], u64> = TableDefinition::new("seen_message_ids");
pub const SETTINGS: TableDefinition<&str, &[u8]> = TableDefinition::new("settings");
pub const GROUPS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("groups");
pub const GROUP_MESSAGES: TableDefinition<(&[u8], u64), &[u8]> =
    TableDefinition::new("group_messages");
/// Linked devices: `device_id (32 bytes)` → encrypted `DeviceInfo`.
pub const DEVICES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("devices");
/// Sync log: `(device_id_hash: u64, timestamp: u64)` → encrypted `SyncLogEntry`.
pub const SYNC_LOG: TableDefinition<(u64, u64), &[u8]> = TableDefinition::new("sync_log");
/// Pseudonym key derivation records (§12.6): `counter: u32` → encrypted `PseudonymRecord`.
pub const PSEUDONYMS: TableDefinition<u32, &[u8]> = TableDefinition::new("pseudonyms");
/// Pseudonym counter singleton: `"current"` → `u32` (next counter to allocate).
pub const PSEUDONYM_COUNTER: TableDefinition<&str, u32> = TableDefinition::new("pseudonym_counter");

/// 24-hour dedup window for message IDs (SPEC.md §6.21).
pub const DEDUP_WINDOW_SECS: u64 = 24 * 60 * 60;

// ─── Errors ─────────────────────────────────────────────────────────────────

/// Storage-layer errors.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("database error: {0}")]
    Database(#[from] redb::DatabaseError),
    #[error("table error: {0}")]
    Table(#[from] redb::TableError),
    #[error("transaction error: {0}")]
    Transaction(Box<redb::TransactionError>),
    #[error("commit error: {0}")]
    Commit(#[from] redb::CommitError),
    #[error("storage error: {0}")]
    Store(#[from] redb::StorageError),
    #[error("encryption failed")]
    Encryption,
    #[error("decryption failed (wrong key or corrupted data)")]
    Decryption,
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("contact not found")]
    ContactNotFound,
    #[error("group not found")]
    GroupNotFound,
    #[error("backup error: {0}")]
    Backup(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<redb::TransactionError> for StorageError {
    fn from(e: redb::TransactionError) -> Self {
        Self::Transaction(Box::new(e))
    }
}

// ─── Storage ────────────────────────────────────────────────────────────────

/// Main database handle wrapping redb with an encryption key.
///
/// The storage key is derived from the master seed:
/// `storage_key = BLAKE3-KDF(master_seed, "aira/storage/0")`.
///
/// All table values (except pending messages, which are already
/// ratchet-encrypted) are encrypted with ChaCha20-Poly1305 before writing.
pub struct Storage {
    db: Database,
    storage_key: Zeroizing<[u8; 32]>,
}

impl Storage {
    /// Open (or create) the database at the given path.
    ///
    /// Creates all tables on first run.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError`] if the database cannot be opened or tables
    /// cannot be created.
    pub fn open(path: &Path, storage_key: Zeroizing<[u8; 32]>) -> Result<Self, StorageError> {
        let db = Database::create(path)?;

        // Create all tables on first open
        let txn = db.begin_write()?;
        {
            let _t = txn.open_table(CONTACTS)?;
            let _t = txn.open_table(MESSAGES)?;
            let _t = txn.open_table(SESSIONS)?;
            let _t = txn.open_table(PENDING)?;
            let _t = txn.open_table(SEEN_IDS)?;
            let _t = txn.open_table(SETTINGS)?;
            let _t = txn.open_table(GROUPS)?;
            let _t = txn.open_table(GROUP_MESSAGES)?;
            let _t = txn.open_table(DEVICES)?;
            let _t = txn.open_table(SYNC_LOG)?;
            let _t = txn.open_table(PSEUDONYMS)?;
            let _t = txn.open_table(PSEUDONYM_COUNTER)?;
        }
        txn.commit()?;

        Ok(Self { db, storage_key })
    }

    /// Get a reference to the underlying redb database.
    #[must_use]
    pub fn db(&self) -> &Database {
        &self.db
    }

    /// Get a reference to the storage encryption key.
    #[must_use]
    pub fn key(&self) -> &[u8; 32] {
        &self.storage_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a temporary storage for testing.
    pub fn temp_storage() -> Storage {
        let dir = std::env::temp_dir().join(format!("aira-test-{}", rand::random::<u64>()));
        let key = Zeroizing::new([0x42u8; 32]);
        Storage::open(&dir, key).expect("open temp storage")
    }

    #[test]
    fn open_creates_database() {
        let storage = temp_storage();
        // Verify tables exist by reading them
        let txn = storage.db().begin_read().expect("begin read");
        let _t = txn.open_table(CONTACTS).expect("contacts table");
        let _t = txn.open_table(MESSAGES).expect("messages table");
        let _t = txn.open_table(SESSIONS).expect("sessions table");
        let _t = txn.open_table(PENDING).expect("pending table");
        let _t = txn.open_table(SEEN_IDS).expect("seen_ids table");
        let _t = txn.open_table(SETTINGS).expect("settings table");
    }

    #[test]
    fn open_is_idempotent() {
        let dir = std::env::temp_dir().join(format!("aira-test-{}", rand::random::<u64>()));
        let key = Zeroizing::new([0x42u8; 32]);
        let _s1 = Storage::open(&dir, key.clone()).expect("first open");
        drop(_s1);
        let _s2 = Storage::open(&dir, key).expect("second open");
    }
}
