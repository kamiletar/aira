//! Message deduplication window (24h).
//!
//! Protects against double-delivery on network retry.
//! See SPEC.md §6.21.
//!
//! TODO(M3): implement

use crate::DEDUP_WINDOW_SECS;

/// Check if a message ID was seen recently (within DEDUP_WINDOW_SECS).
/// Returns `true` if this is a duplicate (should be dropped).
///
/// Also records the ID as seen if it's new.
pub fn is_duplicate(_db: &redb::Database, _message_id: &[u8; 16]) -> bool {
    // TODO(M3): implement via SEEN_IDS table
    false
}

/// Remove message IDs older than DEDUP_WINDOW_SECS.
/// Call on daemon startup and periodically.
pub fn gc_expired(_db: &redb::Database) {
    // TODO(M3): delete SEEN_IDS entries older than DEDUP_WINDOW_SECS
    let _ = DEDUP_WINDOW_SECS;
}
