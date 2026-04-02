//! Event callback interface for UniFFI.
//!
//! Kotlin implements `AiraEventListener` and registers it with `AiraRuntime`.
//! The Rust side forwards `DaemonEvent`s to the listener on a background task.

use aira_daemon::types::DaemonEvent;

/// Callback interface that Kotlin implements to receive asynchronous events.
///
/// All methods are called on a background thread — Kotlin must dispatch
/// to the main thread if UI updates are needed.
#[uniffi::export(callback_interface)]
pub trait AiraEventListener: Send + Sync {
    /// A new 1-on-1 message was received.
    fn on_message_received(&self, from: Vec<u8>, payload: Vec<u8>);

    /// A contact came online.
    fn on_contact_online(&self, pubkey: Vec<u8>);

    /// A contact went offline.
    fn on_contact_offline(&self, pubkey: Vec<u8>);

    /// A group message was received.
    fn on_group_message_received(&self, group_id: Vec<u8>, from: Vec<u8>, payload: Vec<u8>);

    /// A group invite was received.
    fn on_group_invite(&self, group_id: Vec<u8>, name: String, invited_by: Vec<u8>);

    /// File transfer progress update.
    fn on_file_progress(&self, id: Vec<u8>, bytes_sent: u64, total: u64);

    /// File transfer completed.
    fn on_file_complete(&self, id: Vec<u8>, path: String);

    /// File transfer failed.
    fn on_file_error(&self, id: Vec<u8>, error: String);

    /// A new device was linked.
    fn on_device_linked(&self, device_id: Vec<u8>, name: String);

    /// A device was unlinked.
    fn on_device_unlinked(&self, device_id: Vec<u8>);

    /// Device sync completed.
    fn on_sync_completed(&self, device_id: Vec<u8>, messages_synced: u32);
}

/// Dispatch a `DaemonEvent` to the listener callback.
pub fn dispatch_event(listener: &dyn AiraEventListener, event: DaemonEvent) {
    match event {
        DaemonEvent::MessageReceived { from, payload } => {
            listener.on_message_received(from, payload);
        }
        DaemonEvent::ContactOnline(pubkey) => {
            listener.on_contact_online(pubkey);
        }
        DaemonEvent::ContactOffline(pubkey) => {
            listener.on_contact_offline(pubkey);
        }
        DaemonEvent::GroupMessageReceived {
            group_id,
            from,
            payload,
        } => {
            listener.on_group_message_received(group_id.to_vec(), from, payload);
        }
        DaemonEvent::GroupInvite {
            group_id,
            name,
            invited_by,
        } => {
            listener.on_group_invite(group_id.to_vec(), name, invited_by);
        }
        DaemonEvent::GroupMemberJoined { .. } | DaemonEvent::GroupMemberLeft { .. } => {
            // These events don't have a direct callback mapping yet;
            // Kotlin can poll group info when needed.
        }
        DaemonEvent::FileProgress {
            id,
            bytes_sent,
            total,
        } => {
            listener.on_file_progress(id.to_vec(), bytes_sent, total);
        }
        DaemonEvent::FileComplete { id, path } => {
            listener.on_file_complete(id.to_vec(), path.to_string_lossy().to_string());
        }
        DaemonEvent::FileError { id, error } => {
            listener.on_file_error(id.to_vec(), error);
        }
        DaemonEvent::DeviceLinked { device_id, name } => {
            listener.on_device_linked(device_id.to_vec(), name);
        }
        DaemonEvent::DeviceUnlinked { device_id } => {
            listener.on_device_unlinked(device_id.to_vec());
        }
        DaemonEvent::SyncCompleted {
            device_id,
            messages_synced,
        } => {
            listener.on_sync_completed(device_id.to_vec(), messages_synced);
        }
    }
}
