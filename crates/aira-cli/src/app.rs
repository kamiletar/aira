//! Application state management.
//!
//! Holds contacts, messages, drafts, unread counts, and file transfer state.
//! Processes commands and daemon events to keep the UI state consistent.
//! See SPEC.md §9.

use std::collections::{HashMap, HashSet};

use aira_core::proto::{MessageMeta, PlainPayload};
use aira_daemon::types::{DaemonEvent, DaemonRequest};
use aira_storage::{ContactInfo, StoredMessage};

/// UI focus: which panel has keyboard focus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    Contacts,
    Chat,
}

/// Input mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputMode {
    /// Normal message input.
    Normal,
    /// Editing an existing message (by its ID).
    Editing([u8; 16]),
}

/// File transfer progress tracking.
#[derive(Debug, Clone)]
pub struct TransferProgress {
    pub bytes_sent: u64,
    pub total: u64,
}

/// A decoded message for display in the TUI.
#[derive(Debug, Clone)]
pub struct DisplayMessage {
    /// Unique message ID.
    pub id: [u8; 16],
    /// Whether we sent this message.
    pub is_self: bool,
    /// Formatted display text.
    pub text: String,
    /// Timestamp (microseconds since epoch).
    pub timestamp_micros: u64,
    /// Receipt status indicator.
    pub status: &'static str,
    /// TTL for disappearing messages.
    #[allow(dead_code)]
    pub ttl_secs: Option<u64>,
    /// ID of message this replies to.
    #[allow(dead_code)]
    pub reply_to: Option<[u8; 16]>,
}

/// Application state — the single source of truth for the TUI.
pub struct App {
    /// All contacts (from daemon).
    pub contacts: Vec<ContactInfo>,
    /// Currently selected contact index in the contacts list.
    pub selected_contact: usize,
    /// Message cache per contact (key: contact pubkey).
    pub messages: HashMap<Vec<u8>, Vec<DisplayMessage>>,
    /// In-memory drafts per contact (key: contact pubkey).
    pub drafts: HashMap<Vec<u8>, String>,
    /// Unread message count per contact (key: contact pubkey).
    pub unread: HashMap<Vec<u8>, u32>,
    /// Set of online contact pubkeys.
    pub online: HashSet<Vec<u8>>,
    /// Current text input.
    pub input: String,
    /// Cursor position in the input field.
    pub input_cursor: usize,
    /// Which panel has keyboard focus.
    pub focus: Focus,
    /// Current input mode (normal or editing).
    pub mode: InputMode,
    /// Active file transfers.
    pub file_transfers: HashMap<[u8; 16], TransferProgress>,
    /// Our own public key (from daemon).
    pub my_address: Vec<u8>,
    /// Status bar message.
    pub status_message: Option<String>,
    /// Whether the application is running.
    pub running: bool,
    /// Chat scroll offset (0 = bottom).
    pub scroll_offset: u16,
}

impl App {
    /// Create a new empty `App`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            contacts: Vec::new(),
            selected_contact: 0,
            messages: HashMap::new(),
            drafts: HashMap::new(),
            unread: HashMap::new(),
            online: HashSet::new(),
            input: String::new(),
            input_cursor: 0,
            focus: Focus::Contacts,
            mode: InputMode::Normal,
            file_transfers: HashMap::new(),
            my_address: Vec::new(),
            status_message: None,
            running: true,
            scroll_offset: 0,
        }
    }

    /// Get the currently selected contact, if any.
    #[must_use]
    pub fn current_contact(&self) -> Option<&ContactInfo> {
        self.contacts.get(self.selected_contact)
    }

    /// Get the pubkey of the currently selected contact.
    #[must_use]
    pub fn current_contact_pubkey(&self) -> Option<&[u8]> {
        self.current_contact().map(|c| c.pubkey.as_slice())
    }

    /// Get display messages for the currently selected contact.
    #[must_use]
    pub fn current_messages(&self) -> &[DisplayMessage] {
        self.current_contact_pubkey()
            .and_then(|pk| self.messages.get(pk))
            .map_or(&[], Vec::as_slice)
    }

    /// Switch to a different contact (by index). Saves/restores drafts.
    pub fn switch_contact(&mut self, index: usize) {
        if index >= self.contacts.len() {
            return;
        }

        // Save current draft
        if let Some(pk) = self.current_contact_pubkey().map(<[u8]>::to_vec) {
            if self.input.is_empty() {
                self.drafts.remove(&pk);
            } else {
                self.drafts.insert(pk, self.input.clone());
            }
        }

        self.selected_contact = index;

        // Restore draft for new contact
        let draft = self
            .current_contact_pubkey()
            .and_then(|pk| self.drafts.get(pk))
            .cloned()
            .unwrap_or_default();
        self.input_cursor = draft.len();
        self.input.clone_from(&draft);

        // Clear unread for newly selected contact
        if let Some(pk) = self.current_contact_pubkey().map(<[u8]>::to_vec) {
            self.unread.remove(&pk);
        }

        self.scroll_offset = 0;
        self.mode = InputMode::Normal;
    }

    /// Select next contact in the list.
    pub fn next_contact(&mut self) {
        if self.contacts.is_empty() {
            return;
        }
        let next = (self.selected_contact + 1) % self.contacts.len();
        self.switch_contact(next);
    }

    /// Select previous contact in the list.
    pub fn prev_contact(&mut self) {
        if self.contacts.is_empty() {
            return;
        }
        let prev = if self.selected_contact == 0 {
            self.contacts.len() - 1
        } else {
            self.selected_contact - 1
        };
        self.switch_contact(prev);
    }

    /// Toggle focus between Contacts panel and Chat panel.
    pub fn toggle_focus(&mut self) {
        self.focus = match self.focus {
            Focus::Contacts => Focus::Chat,
            Focus::Chat => Focus::Contacts,
        };
    }

    /// Handle a daemon event — updates local state.
    pub fn handle_event(&mut self, event: DaemonEvent) {
        match event {
            DaemonEvent::MessageReceived { from, payload } => {
                if let Some(msg) = decode_display_message(&payload, false) {
                    let is_current = self.current_contact_pubkey() == Some(from.as_slice());

                    self.messages.entry(from.clone()).or_default().push(msg);

                    if !is_current {
                        *self.unread.entry(from).or_insert(0) += 1;
                    }
                }
            }
            DaemonEvent::ContactOnline(pk) => {
                self.online.insert(pk);
            }
            DaemonEvent::ContactOffline(pk) => {
                self.online.remove(&pk);
            }
            DaemonEvent::FileProgress {
                id,
                bytes_sent,
                total,
            } => {
                self.file_transfers
                    .insert(id, TransferProgress { bytes_sent, total });
            }
            DaemonEvent::FileComplete { id, path } => {
                self.file_transfers.remove(&id);
                self.status_message = Some(format!("File saved: {}", path.display()));
            }
            DaemonEvent::FileError { id, error } => {
                self.file_transfers.remove(&id);
                self.status_message = Some(format!("File error: {error}"));
            }
        }
    }

    /// Store history messages fetched from daemon.
    pub fn set_history(&mut self, contact_pk: Vec<u8>, stored: &[StoredMessage]) {
        let display_msgs: Vec<DisplayMessage> =
            stored.iter().filter_map(decode_stored_message).collect();
        self.messages.insert(contact_pk, display_msgs);
    }

    /// Set the status bar message (will be cleared on next action).
    pub fn set_status(&mut self, msg: impl Into<String>) {
        self.status_message = Some(msg.into());
    }

    /// Build a `DaemonRequest::SendMessage` for the current input.
    ///
    /// Returns `None` if no contact is selected or input is empty.
    #[must_use]
    pub fn build_send_request(&self) -> Option<DaemonRequest> {
        let pk = self.current_contact_pubkey()?.to_vec();
        let text = self.input.trim();
        if text.is_empty() {
            return None;
        }
        Some(DaemonRequest::SendMessage {
            to: pk,
            text: text.to_string(),
        })
    }

    /// Add a sent message to the local message cache (optimistic update).
    pub fn add_sent_message(&mut self, text: &str) {
        if let Some(pk) = self.current_contact_pubkey().map(<[u8]>::to_vec) {
            let msg = DisplayMessage {
                id: rand_id(),
                is_self: true,
                text: text.to_string(),
                timestamp_micros: now_micros(),
                status: "[>]",
                ttl_secs: None,
                reply_to: None,
            };
            self.messages.entry(pk).or_default().push(msg);
        }
    }

    /// Check if a contact is online.
    #[must_use]
    pub fn is_online(&self, pubkey: &[u8]) -> bool {
        self.online.contains(pubkey)
    }

    /// Get the alias for a contact pubkey.
    #[must_use]
    pub fn contact_alias(&self, pubkey: &[u8]) -> String {
        self.contacts
            .iter()
            .find(|c| c.pubkey == pubkey)
            .map_or_else(|| hex_short(pubkey), |c| c.alias.clone())
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

/// Decode a `StoredMessage` into a `DisplayMessage`.
fn decode_stored_message(stored: &StoredMessage) -> Option<DisplayMessage> {
    let meta: MessageMeta = postcard::from_bytes(&stored.payload_bytes).ok()?;
    let text = payload_to_text(&meta.payload);

    Some(DisplayMessage {
        id: stored.id,
        is_self: stored.sender_is_self,
        text,
        timestamp_micros: stored.timestamp_micros,
        status: if stored.sender_is_self { "[ok]" } else { "" },
        ttl_secs: stored.ttl_secs,
        reply_to: meta.reply_to,
    })
}

/// Decode raw payload bytes (from a daemon event) into a `DisplayMessage`.
fn decode_display_message(payload_bytes: &[u8], is_self: bool) -> Option<DisplayMessage> {
    let meta: MessageMeta = postcard::from_bytes(payload_bytes).ok()?;
    let text = payload_to_text(&meta.payload);

    Some(DisplayMessage {
        id: meta.id,
        is_self,
        text,
        timestamp_micros: now_micros(),
        status: "",
        ttl_secs: meta.ttl.map(|d| d.as_secs()),
        reply_to: meta.reply_to,
    })
}

/// Convert a `PlainPayload` to display text.
fn payload_to_text(payload: &PlainPayload) -> String {
    match payload {
        PlainPayload::Text(t) => t.clone(),
        PlainPayload::Action(a) => format!("* {a}"),
        PlainPayload::Edit { new_text, .. } => format!("{new_text} (edited)"),
        PlainPayload::Delete { .. } => "[message deleted]".to_string(),
        PlainPayload::Reaction { emoji, .. } => format!("[reacted: {emoji}]"),
        PlainPayload::Receipt(r) => format!("[receipt: {:?}]", r.status),
        PlainPayload::Typing(true) => "[typing...]".to_string(),
        PlainPayload::Typing(false) => String::new(),
        PlainPayload::Media(m) => format!("[media: {:?}]", m.media_type),
        PlainPayload::LinkPreview(l) => format!("[link: {}]", l.url),
        PlainPayload::FileStart { name, size, .. } => {
            format!("[file: {name} ({size} bytes)]")
        }
        PlainPayload::SessionReset { reason, .. } => {
            format!("[session reset: {reason:?}]")
        }
        PlainPayload::Unknown { type_id, .. } => {
            format!("[unknown message type {type_id} — please update Aira]")
        }
    }
}

/// Generate a random 16-byte message ID.
#[allow(clippy::cast_possible_truncation)]
fn rand_id() -> [u8; 16] {
    use std::time::SystemTime;

    let mut id = [0u8; 16];
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    id[..8].copy_from_slice(&(nanos as u64).to_le_bytes());
    id[8..16].copy_from_slice(&(nanos.wrapping_shr(64) as u64).to_le_bytes());
    id
}

/// Current time in microseconds since epoch.
#[allow(clippy::cast_possible_truncation)]
fn now_micros() -> u64 {
    use std::time::SystemTime;

    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64
}

/// Short hex representation of a pubkey (first 8 bytes).
fn hex_short(bytes: &[u8]) -> String {
    let take = bytes.len().min(8);
    bytes[..take].iter().fold(String::new(), |mut acc, b| {
        use std::fmt::Write;
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_contact(alias: &str, pk: &[u8]) -> ContactInfo {
        ContactInfo {
            pubkey: pk.to_vec(),
            alias: alias.into(),
            added_at: 1_700_000_000,
            verified: false,
            blocked: false,
        }
    }

    #[test]
    fn switch_contact_saves_and_restores_draft() {
        let mut app = App::new();
        app.contacts = vec![
            make_contact("Alice", &[1; 32]),
            make_contact("Bob", &[2; 32]),
        ];
        app.selected_contact = 0;

        // Type a draft for Alice
        app.input = "hello alice".into();
        app.input_cursor = 11;

        // Switch to Bob
        app.switch_contact(1);
        assert_eq!(app.selected_contact, 1);
        assert!(app.input.is_empty());

        // Switch back to Alice — draft restored
        app.switch_contact(0);
        assert_eq!(app.input, "hello alice");
    }

    #[test]
    fn handle_message_received_updates_cache() {
        let mut app = App::new();
        let pk = vec![1; 32];
        app.contacts = vec![make_contact("Alice", &pk)];
        app.selected_contact = 0;

        let meta = MessageMeta {
            payload: PlainPayload::Text("hello!".into()),
            ttl: None,
            id: [0xAA; 16],
            reply_to: None,
        };
        let payload = postcard::to_allocvec(&meta).expect("serialize");

        app.handle_event(DaemonEvent::MessageReceived {
            from: pk.clone(),
            payload,
        });

        let msgs = app.messages.get(&pk).expect("messages exist");
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].text, "hello!");
    }

    #[test]
    fn handle_message_from_other_contact_increments_unread() {
        let mut app = App::new();
        let alice = vec![1; 32];
        let bob = vec![2; 32];
        app.contacts = vec![make_contact("Alice", &alice), make_contact("Bob", &bob)];
        app.selected_contact = 0; // Viewing Alice

        let meta = MessageMeta {
            payload: PlainPayload::Text("hey".into()),
            ttl: None,
            id: [0xBB; 16],
            reply_to: None,
        };
        let payload = postcard::to_allocvec(&meta).expect("serialize");

        app.handle_event(DaemonEvent::MessageReceived {
            from: bob.clone(),
            payload,
        });

        assert_eq!(app.unread.get(&bob), Some(&1));
        assert_eq!(app.unread.get(&alice), None);
    }

    #[test]
    fn contact_online_offline() {
        let mut app = App::new();
        let pk = vec![1; 32];

        app.handle_event(DaemonEvent::ContactOnline(pk.clone()));
        assert!(app.is_online(&pk));

        app.handle_event(DaemonEvent::ContactOffline(pk.clone()));
        assert!(!app.is_online(&pk));
    }

    #[test]
    fn file_transfer_progress_and_complete() {
        use std::path::PathBuf;

        let mut app = App::new();
        let id = [0x42; 16];

        app.handle_event(DaemonEvent::FileProgress {
            id,
            bytes_sent: 500,
            total: 1000,
        });
        assert_eq!(app.file_transfers.get(&id).unwrap().bytes_sent, 500);

        app.handle_event(DaemonEvent::FileComplete {
            id,
            path: PathBuf::from("/tmp/file.txt"),
        });
        assert!(app.file_transfers.get(&id).is_none());
        assert!(app.status_message.as_ref().unwrap().contains("File saved"));
    }

    #[test]
    fn toggle_focus() {
        let mut app = App::new();
        assert_eq!(app.focus, Focus::Contacts);
        app.toggle_focus();
        assert_eq!(app.focus, Focus::Chat);
        app.toggle_focus();
        assert_eq!(app.focus, Focus::Contacts);
    }

    #[test]
    fn payload_to_text_variants() {
        assert_eq!(payload_to_text(&PlainPayload::Text("hi".into())), "hi");
        assert_eq!(
            payload_to_text(&PlainPayload::Action("waves".into())),
            "* waves"
        );
        assert_eq!(
            payload_to_text(&PlainPayload::Delete {
                message_id: [0; 16]
            }),
            "[message deleted]"
        );
    }

    #[test]
    fn hex_short_truncates() {
        assert_eq!(hex_short(&[0xAB, 0xCD, 0xEF]), "abcdef");
        assert_eq!(hex_short(&[0; 32]).len(), 16); // 8 bytes * 2 hex chars
    }

    #[test]
    fn next_prev_contact_wraps() {
        let mut app = App::new();
        app.contacts = vec![
            make_contact("A", &[1; 32]),
            make_contact("B", &[2; 32]),
            make_contact("C", &[3; 32]),
        ];
        app.selected_contact = 0;

        app.next_contact();
        assert_eq!(app.selected_contact, 1);
        app.next_contact();
        assert_eq!(app.selected_contact, 2);
        app.next_contact();
        assert_eq!(app.selected_contact, 0); // wraps

        app.prev_contact();
        assert_eq!(app.selected_contact, 2); // wraps back
    }
}
