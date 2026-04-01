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

#![deny(unsafe_code)]
#![warn(clippy::all, clippy::pedantic)]

use redb::TableDefinition;

// Table definitions
pub const CONTACTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("contacts");
pub const MESSAGES: TableDefinition<(u64, u64), &[u8]> = TableDefinition::new("messages");
pub const SESSIONS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("sessions");
pub const PENDING: TableDefinition<(&[u8], u64), &[u8]> = TableDefinition::new("pending_messages");
/// Dedup window: `message_id` -> unix timestamp when seen (SPEC.md §6.21)
pub const SEEN_IDS: TableDefinition<&[u8], u64> = TableDefinition::new("seen_message_ids");
pub const SETTINGS: TableDefinition<&str, &[u8]> = TableDefinition::new("settings");
pub const GROUPS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("groups");
pub const GROUP_MESSAGES: TableDefinition<(&[u8], u64), &[u8]> =
    TableDefinition::new("group_messages");

pub mod contacts;
pub mod dedup;
pub mod messages;
pub mod sessions;
pub mod settings;

/// 24-hour dedup window for message IDs (SPEC.md §6.21).
pub const DEDUP_WINDOW_SECS: u64 = 24 * 60 * 60;
