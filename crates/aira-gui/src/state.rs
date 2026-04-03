//! GUI application state.
//!
//! `GuiState` holds all data needed for rendering: contacts, messages,
//! groups, devices, file transfers, and settings. Updated by processing
//! `GuiUpdate` messages from the IPC bridge.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use aira_core::proto::{MessageMeta, PlainPayload};
use aira_core::util::{now_micros, rand_id};
use aira_daemon::types::{DeviceInfoResp, GroupInfoResp};
use aira_storage::{ContactInfo, StoredMessage};

use crate::ipc::GuiUpdate;

/// Which view is currently active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Contacts,
    Chat,
    AddContact,
    Settings,
    Groups,
    GroupChat,
    Transfers,
    Identity,
}

/// A decoded message ready for display.
#[derive(Debug, Clone)]
pub struct DisplayMessage {
    /// Unique message ID.
    #[allow(dead_code)]
    pub id: [u8; 16],
    /// Whether we sent this message.
    pub is_self: bool,
    /// Display text.
    pub text: String,
    /// Timestamp (microseconds since epoch).
    pub timestamp_micros: u64,
    /// Sender alias (for group messages).
    pub sender_alias: Option<String>,
}

/// File transfer progress.
#[derive(Debug, Clone)]
pub struct TransferProgress {
    pub bytes_sent: u64,
    pub total: u64,
}

/// Complete GUI state — single source of truth for rendering.
pub struct GuiState {
    // ─── Connection ─────────────────────────────────────────────────────
    /// Whether we are connected to the daemon.
    pub connected: bool,
    /// Last error or status message.
    pub status_message: Option<String>,

    // ─── Navigation ─────────────────────────────────────────────────────
    /// Currently active view.
    pub active_view: View,
    /// Previously active view (for back navigation).
    pub previous_view: Option<View>,

    // ─── Identity ───────────────────────────────────────────────────────
    /// Our own public key.
    pub my_address: Vec<u8>,

    // ─── Contacts ───────────────────────────────────────────────────────
    /// All contacts from daemon.
    pub contacts: Vec<ContactInfo>,
    /// Currently selected contact pubkey.
    pub selected_contact: Option<Vec<u8>>,
    /// Online contact pubkeys.
    pub online: HashSet<Vec<u8>>,
    /// Unread message counts per contact.
    pub unread: HashMap<Vec<u8>, u32>,
    /// Message cache per contact pubkey.
    pub messages: HashMap<Vec<u8>, Vec<DisplayMessage>>,
    /// Input drafts per contact.
    pub drafts: HashMap<Vec<u8>, String>,
    /// Current chat input text.
    pub chat_input: String,

    // ─── Groups ─────────────────────────────────────────────────────────
    /// All groups.
    pub groups: Vec<GroupInfoResp>,
    /// Currently selected group ID.
    pub selected_group: Option<[u8; 32]>,
    /// Group message cache.
    pub group_messages: HashMap<[u8; 32], Vec<DisplayMessage>>,
    /// Group unread counts.
    pub group_unread: HashMap<[u8; 32], u32>,
    /// Group chat input.
    pub group_input: String,

    // ─── Devices ────────────────────────────────────────────────────────
    /// Linked devices.
    pub devices: Vec<DeviceInfoResp>,
    /// Generated link code (if any).
    pub link_code: Option<String>,

    // ─── File transfers ─────────────────────────────────────────────────
    /// Active file transfers.
    pub transfers: HashMap<[u8; 16], TransferProgress>,
    /// Completed file paths.
    pub completed_files: Vec<PathBuf>,

    // ─── Settings ───────────────────────────────────────────────────────
    /// Current transport mode.
    pub transport_mode: String,

    // ─── Add contact form ───────────────────────────────────────────────
    /// Pubkey hex input for adding contacts.
    pub add_contact_pubkey: String,
    /// Alias input for adding contacts.
    pub add_contact_alias: String,

    // ─── Create group form ──────────────────────────────────────────────
    /// Group name input.
    pub create_group_name: String,

    // ─── Link device form ───────────────────────────────────────────────
    /// Link code input.
    pub link_code_input: String,
    /// Device name input.
    pub link_device_name: String,
}

impl GuiState {
    /// Create a new empty state.
    #[must_use]
    pub fn new() -> Self {
        Self {
            connected: false,
            status_message: Some("Connecting to daemon...".into()),
            active_view: View::Contacts,
            previous_view: None,
            my_address: Vec::new(),
            contacts: Vec::new(),
            selected_contact: None,
            online: HashSet::new(),
            unread: HashMap::new(),
            messages: HashMap::new(),
            drafts: HashMap::new(),
            chat_input: String::new(),
            groups: Vec::new(),
            selected_group: None,
            group_messages: HashMap::new(),
            group_unread: HashMap::new(),
            group_input: String::new(),
            devices: Vec::new(),
            link_code: None,
            transfers: HashMap::new(),
            completed_files: Vec::new(),
            transport_mode: "direct".into(),
            add_contact_pubkey: String::new(),
            add_contact_alias: String::new(),
            create_group_name: String::new(),
            link_code_input: String::new(),
            link_device_name: String::new(),
        }
    }

    /// Navigate to a different view, remembering the previous one.
    pub fn navigate(&mut self, view: View) {
        self.previous_view = Some(self.active_view);
        self.active_view = view;
    }

    /// Go back to the previous view.
    pub fn go_back(&mut self) {
        if let Some(prev) = self.previous_view.take() {
            self.active_view = prev;
        }
    }

    /// Select a contact and open the chat view.
    pub fn open_chat(&mut self, pubkey: Vec<u8>) {
        // Save current draft
        if let Some(prev_pk) = &self.selected_contact {
            if self.chat_input.is_empty() {
                self.drafts.remove(prev_pk);
            } else {
                self.drafts.insert(prev_pk.clone(), self.chat_input.clone());
            }
        }

        // Restore draft for new contact
        self.chat_input = self.drafts.get(&pubkey).cloned().unwrap_or_default();

        // Clear unread
        self.unread.remove(&pubkey);

        self.selected_contact = Some(pubkey);
        self.navigate(View::Chat);
    }

    /// Select a group and open the group chat view.
    pub fn open_group_chat(&mut self, group_id: [u8; 32]) {
        self.group_unread.remove(&group_id);
        self.selected_group = Some(group_id);
        self.group_input.clear();
        self.navigate(View::GroupChat);
    }

    /// Get alias for a contact pubkey, or hex prefix if unknown.
    #[must_use]
    pub fn contact_alias(&self, pubkey: &[u8]) -> String {
        self.contacts
            .iter()
            .find(|c| c.pubkey == pubkey)
            .map_or_else(
                || hex::encode(&pubkey[..4.min(pubkey.len())]),
                |c| c.alias.clone(),
            )
    }

    /// Process a `GuiUpdate` and mutate state accordingly.
    ///
    /// Returns `true` if a desktop notification should be shown.
    pub fn handle_update(&mut self, update: GuiUpdate) -> bool {
        let mut notify = false;

        match update {
            GuiUpdate::Connected => {
                self.connected = true;
                self.status_message = None;
            }
            GuiUpdate::Disconnected(e) => {
                self.connected = false;
                self.status_message = Some(format!("Disconnected: {e}"));
            }
            GuiUpdate::ContactsLoaded(contacts) => {
                self.contacts = contacts;
            }
            GuiUpdate::MyAddress(addr) => {
                self.my_address = addr;
            }
            GuiUpdate::HistoryLoaded { contact, messages } => {
                let display: Vec<DisplayMessage> = messages
                    .into_iter()
                    .map(|m| stored_to_display(&m, None))
                    .collect();
                self.messages.insert(contact, display);
            }
            GuiUpdate::MessageSent
            | GuiUpdate::Ok
            | GuiUpdate::GroupMemberJoined { .. }
            | GuiUpdate::GroupMemberLeft { .. } => {}
            GuiUpdate::ContactAdded => {
                self.add_contact_pubkey.clear();
                self.add_contact_alias.clear();
                self.status_message = Some("Contact added".into());
            }
            GuiUpdate::ContactRemoved => {
                self.status_message = Some("Contact removed".into());
            }
            GuiUpdate::TransportMode(mode) => {
                self.transport_mode = mode;
            }
            GuiUpdate::Error(e) => {
                self.status_message = Some(format!("Error: {e}"));
            }

            // ─── Async events ───────────────────────────────────────────
            GuiUpdate::MessageReceived { from, payload } => {
                let text = decode_payload_text(&payload);
                let msg = DisplayMessage {
                    id: rand_id(),
                    is_self: false,
                    text,
                    timestamp_micros: now_micros(),
                    sender_alias: Some(self.contact_alias(&from)),
                };
                self.messages.entry(from.clone()).or_default().push(msg);

                // Increment unread if not currently viewing this contact
                if self.selected_contact.as_deref() != Some(&from) || self.active_view != View::Chat
                {
                    *self.unread.entry(from).or_insert(0) += 1;
                    notify = true;
                }
            }
            GuiUpdate::ContactOnline(pk) => {
                self.online.insert(pk);
            }
            GuiUpdate::ContactOffline(pk) => {
                self.online.remove(&pk);
            }
            GuiUpdate::FileProgress {
                id,
                bytes_sent,
                total,
            } => {
                self.transfers
                    .insert(id, TransferProgress { bytes_sent, total });
            }
            GuiUpdate::FileComplete { id, path } => {
                self.transfers.remove(&id);
                self.completed_files.push(path);
            }
            GuiUpdate::FileError { id, error } => {
                self.transfers.remove(&id);
                self.status_message = Some(format!("Transfer failed: {error}"));
            }

            // ─── Group events ───────────────────────────────────────────
            GuiUpdate::GroupsLoaded(groups) => {
                self.groups = groups;
            }
            GuiUpdate::GroupCreated { group_id: _ } => {
                self.create_group_name.clear();
                self.status_message = Some("Group created".into());
            }
            GuiUpdate::GroupInfo(info) => {
                // Update group in the list
                if let Some(g) = self.groups.iter_mut().find(|g| g.id == info.id) {
                    *g = info;
                } else {
                    self.groups.push(info);
                }
            }
            GuiUpdate::GroupHistoryLoaded { group_id, messages } => {
                let display: Vec<DisplayMessage> = messages
                    .into_iter()
                    .map(|m| stored_to_display(&m, None))
                    .collect();
                self.group_messages.insert(group_id, display);
            }
            GuiUpdate::GroupMessageReceived {
                group_id,
                from,
                payload,
            } => {
                let text = decode_payload_text(&payload);
                let msg = DisplayMessage {
                    id: rand_id(),
                    is_self: false,
                    text,
                    timestamp_micros: now_micros(),
                    sender_alias: Some(self.contact_alias(&from)),
                };
                self.group_messages.entry(group_id).or_default().push(msg);

                if self.selected_group != Some(group_id) || self.active_view != View::GroupChat {
                    *self.group_unread.entry(group_id).or_insert(0) += 1;
                    notify = true;
                }
            }
            GuiUpdate::GroupInvite {
                group_id: _,
                name,
                invited_by: _,
            } => {
                self.status_message = Some(format!("Invited to group: {name}"));
                notify = true;
            }

            // ─── Device events ──────────────────────────────────────────
            GuiUpdate::LinkCode(code) => {
                self.link_code = Some(code);
            }
            GuiUpdate::DeviceLinked { device_id: _, name } => {
                self.status_message = Some(format!("Device linked: {name}"));
            }
            GuiUpdate::DevicesLoaded(devs) => {
                self.devices = devs;
            }
            GuiUpdate::DeviceUnlinked { device_id: _ } => {
                self.status_message = Some("Device unlinked".into());
            }
            GuiUpdate::SyncCompleted {
                device_id: _,
                messages_synced,
            } => {
                self.status_message = Some(format!("Sync completed: {messages_synced} messages"));
            }
        }

        notify
    }
}

impl Default for GuiState {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract display text from a `PlainPayload` enum.
fn payload_to_text(payload: &PlainPayload) -> String {
    match payload {
        PlainPayload::Text(s) => s.clone(),
        PlainPayload::Action(s) => format!("* {s}"),
        PlainPayload::Media(_) => "[media]".into(),
        PlainPayload::LinkPreview(lp) => lp.url.clone(),
        PlainPayload::Reaction { emoji, .. } => emoji.clone(),
        PlainPayload::Edit { new_text, .. } => format!("[edited] {new_text}"),
        PlainPayload::Delete { .. } => "[deleted]".into(),
        PlainPayload::Receipt(_) => "[receipt]".into(),
        PlainPayload::Typing(active) => {
            if *active {
                "[typing...]".into()
            } else {
                String::new()
            }
        }
        PlainPayload::FileStart { name, .. } => format!("[file: {name}]"),
        PlainPayload::SessionReset { .. } => "[session reset]".into(),
        PlainPayload::GroupControl(_) => "[group control]".into(),
        PlainPayload::Unknown { type_id, .. } => format!("[unknown type {type_id}]"),
    }
}

/// Decode the text from serialized payload bytes.
///
/// The payload may be a `MessageMeta` (from stored messages) or
/// a raw `PlainPayload` (from daemon events).
fn decode_payload_text(payload: &[u8]) -> String {
    // Try MessageMeta first (stored messages wrap payload in metadata)
    if let Ok(meta) = postcard::from_bytes::<MessageMeta>(payload) {
        return payload_to_text(&meta.payload);
    }
    // Fall back to raw PlainPayload
    if let Ok(pp) = postcard::from_bytes::<PlainPayload>(payload) {
        return payload_to_text(&pp);
    }
    "<invalid payload>".into()
}

/// Convert a `StoredMessage` into a `DisplayMessage`.
fn stored_to_display(msg: &StoredMessage, sender_alias: Option<String>) -> DisplayMessage {
    let text = decode_payload_text(&msg.payload_bytes);

    DisplayMessage {
        id: msg.id,
        is_self: msg.sender_is_self,
        text,
        timestamp_micros: msg.timestamp_micros,
        sender_alias,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_state_starts_disconnected() {
        let state = GuiState::new();
        assert!(!state.connected);
        assert_eq!(state.active_view, View::Contacts);
    }

    #[test]
    fn navigate_and_go_back() {
        let mut state = GuiState::new();
        assert_eq!(state.active_view, View::Contacts);
        state.navigate(View::Settings);
        assert_eq!(state.active_view, View::Settings);
        assert_eq!(state.previous_view, Some(View::Contacts));
        state.go_back();
        assert_eq!(state.active_view, View::Contacts);
    }

    #[test]
    fn open_chat_clears_unread() {
        let mut state = GuiState::new();
        let pk = vec![0xAA; 32];
        state.unread.insert(pk.clone(), 5);
        state.open_chat(pk.clone());
        assert_eq!(state.unread.get(&pk), None);
        assert_eq!(state.active_view, View::Chat);
        assert_eq!(state.selected_contact, Some(pk));
    }

    #[test]
    fn open_chat_saves_and_restores_draft() {
        let mut state = GuiState::new();
        let pk1 = vec![0xAA; 32];
        let pk2 = vec![0xBB; 32];

        state.open_chat(pk1.clone());
        state.chat_input = "draft for pk1".into();
        state.open_chat(pk2.clone());
        assert_eq!(state.chat_input, "");
        state.open_chat(pk1.clone());
        assert_eq!(state.chat_input, "draft for pk1");
    }

    #[test]
    fn handle_connected() {
        let mut state = GuiState::new();
        state.handle_update(GuiUpdate::Connected);
        assert!(state.connected);
        assert!(state.status_message.is_none());
    }

    #[test]
    fn handle_disconnected() {
        let mut state = GuiState::new();
        state.connected = true;
        state.handle_update(GuiUpdate::Disconnected("lost".into()));
        assert!(!state.connected);
        assert!(state
            .status_message
            .as_ref()
            .is_some_and(|s| s.contains("lost")));
    }

    #[test]
    fn handle_contacts_loaded() {
        let mut state = GuiState::new();
        let contacts = vec![ContactInfo {
            pubkey: vec![1; 32],
            alias: "Alice".into(),
            added_at: 0,
            verified: false,
            blocked: false,
        }];
        state.handle_update(GuiUpdate::ContactsLoaded(contacts));
        assert_eq!(state.contacts.len(), 1);
        assert_eq!(state.contacts[0].alias, "Alice");
    }

    #[test]
    fn handle_message_received_increments_unread() {
        let mut state = GuiState::new();
        state.connected = true;
        state.active_view = View::Contacts; // not in chat

        // We need a valid PlainPayload for decoding
        let payload =
            postcard::to_allocvec(&PlainPayload::Text("hello".into())).expect("serialize");

        let from = vec![0xAA; 32];
        let notify = state.handle_update(GuiUpdate::MessageReceived {
            from: from.clone(),
            payload,
        });

        assert!(notify);
        assert_eq!(state.unread.get(&from), Some(&1));
        assert_eq!(state.messages.get(&from).map(|v| v.len()), Some(1));
    }

    #[test]
    fn handle_message_received_no_unread_when_viewing_chat() {
        let mut state = GuiState::new();
        let from = vec![0xAA; 32];
        state.selected_contact = Some(from.clone());
        state.active_view = View::Chat;

        let payload =
            postcard::to_allocvec(&PlainPayload::Text("hello".into())).expect("serialize");

        let notify = state.handle_update(GuiUpdate::MessageReceived {
            from: from.clone(),
            payload,
        });

        assert!(!notify);
        assert_eq!(state.unread.get(&from), None);
    }

    #[test]
    fn handle_contact_online_offline() {
        let mut state = GuiState::new();
        let pk = vec![0xBB; 32];
        state.handle_update(GuiUpdate::ContactOnline(pk.clone()));
        assert!(state.online.contains(&pk));
        state.handle_update(GuiUpdate::ContactOffline(pk.clone()));
        assert!(!state.online.contains(&pk));
    }

    #[test]
    fn handle_file_transfer_lifecycle() {
        let mut state = GuiState::new();
        let id = [0x42; 16];

        state.handle_update(GuiUpdate::FileProgress {
            id,
            bytes_sent: 100,
            total: 1000,
        });
        assert!(state.transfers.contains_key(&id));

        state.handle_update(GuiUpdate::FileComplete {
            id,
            path: PathBuf::from("/tmp/file.txt"),
        });
        assert!(!state.transfers.contains_key(&id));
        assert_eq!(state.completed_files.len(), 1);
    }

    #[test]
    fn contact_alias_known() {
        let mut state = GuiState::new();
        state.contacts.push(ContactInfo {
            pubkey: vec![0xAA; 32],
            alias: "Alice".into(),
            added_at: 0,
            verified: false,
            blocked: false,
        });
        assert_eq!(state.contact_alias(&vec![0xAA; 32]), "Alice");
    }

    #[test]
    fn contact_alias_unknown_returns_hex_prefix() {
        let state = GuiState::new();
        let alias = state.contact_alias(&[0xAB, 0xCD, 0xEF, 0x01, 0x23]);
        assert_eq!(alias, "abcdef01");
    }
}
