//! IPC bridge between the egui UI thread and the aira-daemon.
//!
//! The bridge runs on a separate `std::thread` with its own tokio runtime.
//! Communication with the UI is via two `tokio::sync::mpsc` channels:
//! - `GuiCommand` (UI → bridge): user actions that need daemon requests.
//! - `GuiUpdate` (bridge → UI): daemon responses and asynchronous events.
//!
//! The bridge calls `egui::Context::request_repaint()` after each update
//! to wake the UI thread.

use std::path::PathBuf;

use aira_daemon::client::DaemonClient;
use aira_daemon::types::{
    DaemonEvent, DaemonRequest, DaemonResponse, DeviceInfoResp, GroupInfoResp,
};
use aira_storage::{ContactInfo, StoredMessage};
use tokio::sync::mpsc;

/// Commands sent from the GUI to the IPC bridge.
#[derive(Debug)]
#[allow(dead_code)]
pub enum GuiCommand {
    /// Fetch the full contact list.
    GetContacts,
    /// Fetch our own public key.
    GetMyAddress,
    /// Fetch message history for a contact.
    GetHistory { contact: Vec<u8>, limit: u32 },
    /// Send a text message.
    SendMessage { to: Vec<u8>, text: String },
    /// Add a new contact by pubkey.
    AddContact { pubkey: Vec<u8>, alias: String },
    /// Remove a contact.
    RemoveContact { pubkey: Vec<u8> },
    /// Set disappearing message TTL for a contact.
    SetTtl {
        contact: Vec<u8>,
        ttl_secs: Option<u64>,
    },
    /// Send a file to a contact.
    SendFile { to: Vec<u8>, path: PathBuf },
    /// Get current transport mode.
    GetTransportMode,
    /// Set transport mode.
    SetTransportMode { mode: String },
    /// Export encrypted backup.
    ExportBackup {
        path: PathBuf,
        include_messages: bool,
    },
    /// Import encrypted backup.
    ImportBackup { path: PathBuf },

    // ─── Groups ─────────────────────────────────────────────────────────
    /// Create a new group.
    CreateGroup { name: String, members: Vec<Vec<u8>> },
    /// Fetch all groups.
    GetGroups,
    /// Get group info.
    GetGroupInfo { group_id: [u8; 32] },
    /// Send a group message.
    SendGroupMessage { group_id: [u8; 32], text: String },
    /// Get group history.
    GetGroupHistory { group_id: [u8; 32], limit: u32 },
    /// Add a member to a group.
    GroupAddMember { group_id: [u8; 32], member: Vec<u8> },
    /// Remove a member from a group.
    GroupRemoveMember { group_id: [u8; 32], member: Vec<u8> },
    /// Leave a group.
    LeaveGroup { group_id: [u8; 32] },

    // ─── Devices ────────────────────────────────────────────────────────
    /// Generate a link code.
    GenerateLinkCode,
    /// Link a new device.
    LinkDevice { code: String, device_name: String },
    /// Get all linked devices.
    GetDevices,
    /// Unlink a device.
    UnlinkDevice { device_id: [u8; 32] },

    /// Graceful shutdown.
    Shutdown,
}

/// Updates sent from the IPC bridge to the GUI.
#[derive(Debug)]
#[allow(dead_code)]
pub enum GuiUpdate {
    /// Connection to daemon established.
    Connected,
    /// Connection to daemon lost or failed.
    Disconnected(String),
    /// Contact list loaded.
    ContactsLoaded(Vec<ContactInfo>),
    /// Our own address loaded.
    MyAddress(Vec<u8>),
    /// Message history loaded for a contact.
    HistoryLoaded {
        contact: Vec<u8>,
        messages: Vec<StoredMessage>,
    },
    /// A message was sent successfully.
    MessageSent,
    /// Contact added successfully.
    ContactAdded,
    /// Contact removed.
    ContactRemoved,
    /// Current transport mode.
    TransportMode(String),
    /// Generic operation succeeded.
    Ok,
    /// Error from daemon.
    Error(String),

    // ─── Async events ───────────────────────────────────────────────────
    /// New message received.
    MessageReceived { from: Vec<u8>, payload: Vec<u8> },
    /// Contact came online.
    ContactOnline(Vec<u8>),
    /// Contact went offline.
    ContactOffline(Vec<u8>),
    /// File transfer progress.
    FileProgress {
        id: [u8; 16],
        bytes_sent: u64,
        total: u64,
    },
    /// File transfer completed.
    FileComplete { id: [u8; 16], path: PathBuf },
    /// File transfer failed.
    FileError { id: [u8; 16], error: String },

    // ─── Group events ───────────────────────────────────────────────────
    /// Groups list loaded.
    GroupsLoaded(Vec<GroupInfoResp>),
    /// Group created.
    GroupCreated { group_id: [u8; 32] },
    /// Group info loaded.
    GroupInfo(GroupInfoResp),
    /// Group history loaded.
    GroupHistoryLoaded {
        group_id: [u8; 32],
        messages: Vec<StoredMessage>,
    },
    /// Group message received.
    GroupMessageReceived {
        group_id: [u8; 32],
        from: Vec<u8>,
        payload: Vec<u8>,
    },
    /// Group member joined.
    GroupMemberJoined { group_id: [u8; 32], member: Vec<u8> },
    /// Group member left.
    GroupMemberLeft { group_id: [u8; 32], member: Vec<u8> },
    /// Invited to a group.
    GroupInvite {
        group_id: [u8; 32],
        name: String,
        invited_by: Vec<u8>,
    },

    // ─── Device events ──────────────────────────────────────────────────
    /// Link code generated.
    LinkCode(String),
    /// Device linked.
    DeviceLinked { device_id: [u8; 32], name: String },
    /// Devices list loaded.
    DevicesLoaded(Vec<DeviceInfoResp>),
    /// Device unlinked.
    DeviceUnlinked { device_id: [u8; 32] },
    /// Sync completed.
    SyncCompleted {
        device_id: [u8; 32],
        messages_synced: u32,
    },
}

/// Convert a `GuiCommand` into a `DaemonRequest`.
fn command_to_request(cmd: &GuiCommand) -> Option<DaemonRequest> {
    match cmd {
        GuiCommand::GetContacts => Some(DaemonRequest::GetContacts),
        GuiCommand::GetMyAddress => Some(DaemonRequest::GetMyAddress),
        GuiCommand::GetHistory { contact, limit } => Some(DaemonRequest::GetHistory {
            contact: contact.clone(),
            limit: *limit,
        }),
        GuiCommand::SendMessage { to, text } => Some(DaemonRequest::SendMessage {
            to: to.clone(),
            text: text.clone(),
        }),
        GuiCommand::AddContact { pubkey, alias } => Some(DaemonRequest::AddContact {
            pubkey: pubkey.clone(),
            alias: alias.clone(),
        }),
        GuiCommand::RemoveContact { pubkey } => Some(DaemonRequest::RemoveContact {
            pubkey: pubkey.clone(),
        }),
        GuiCommand::SetTtl { contact, ttl_secs } => Some(DaemonRequest::SetTtl {
            contact: contact.clone(),
            ttl_secs: *ttl_secs,
        }),
        GuiCommand::SendFile { to, path } => Some(DaemonRequest::SendFile {
            to: to.clone(),
            path: path.clone(),
        }),
        GuiCommand::GetTransportMode => Some(DaemonRequest::GetTransportMode),
        GuiCommand::SetTransportMode { mode } => {
            Some(DaemonRequest::SetTransportMode { mode: mode.clone() })
        }
        GuiCommand::ExportBackup {
            path,
            include_messages,
        } => Some(DaemonRequest::ExportBackup {
            path: path.clone(),
            include_messages: *include_messages,
        }),
        GuiCommand::ImportBackup { path } => {
            Some(DaemonRequest::ImportBackup { path: path.clone() })
        }
        GuiCommand::CreateGroup { name, members } => Some(DaemonRequest::CreateGroup {
            name: name.clone(),
            members: members.clone(),
        }),
        GuiCommand::GetGroups => Some(DaemonRequest::GetGroups),
        GuiCommand::GetGroupInfo { group_id } => Some(DaemonRequest::GetGroupInfo {
            group_id: *group_id,
        }),
        GuiCommand::SendGroupMessage { group_id, text } => Some(DaemonRequest::SendGroupMessage {
            group_id: *group_id,
            text: text.clone(),
        }),
        GuiCommand::GetGroupHistory { group_id, limit } => Some(DaemonRequest::GetGroupHistory {
            group_id: *group_id,
            limit: *limit,
        }),
        GuiCommand::GroupAddMember { group_id, member } => Some(DaemonRequest::GroupAddMember {
            group_id: *group_id,
            member: member.clone(),
        }),
        GuiCommand::GroupRemoveMember { group_id, member } => {
            Some(DaemonRequest::GroupRemoveMember {
                group_id: *group_id,
                member: member.clone(),
            })
        }
        GuiCommand::LeaveGroup { group_id } => Some(DaemonRequest::LeaveGroup {
            group_id: *group_id,
        }),
        GuiCommand::GenerateLinkCode => Some(DaemonRequest::GenerateLinkCode),
        GuiCommand::LinkDevice { code, device_name } => Some(DaemonRequest::LinkDevice {
            code: code.clone(),
            device_name: device_name.clone(),
        }),
        GuiCommand::GetDevices => Some(DaemonRequest::GetDevices),
        GuiCommand::UnlinkDevice { device_id } => Some(DaemonRequest::UnlinkDevice {
            device_id: *device_id,
        }),
        GuiCommand::Shutdown => Some(DaemonRequest::Shutdown),
    }
}

/// Convert a `DaemonResponse` (with the originating command context) into a `GuiUpdate`.
fn response_to_update(cmd: &GuiCommand, resp: DaemonResponse) -> GuiUpdate {
    match resp {
        DaemonResponse::Error(e) => GuiUpdate::Error(e),
        DaemonResponse::Contacts(c) => GuiUpdate::ContactsLoaded(c),
        DaemonResponse::MyAddress(a) => GuiUpdate::MyAddress(a),
        DaemonResponse::History(msgs) => {
            if let GuiCommand::GetHistory { contact, .. } = cmd {
                GuiUpdate::HistoryLoaded {
                    contact: contact.clone(),
                    messages: msgs,
                }
            } else {
                GuiUpdate::Ok
            }
        }
        DaemonResponse::TransportMode(m) => GuiUpdate::TransportMode(m),
        DaemonResponse::GroupCreated { group_id } => GuiUpdate::GroupCreated { group_id },
        DaemonResponse::GroupInfo(info) => GuiUpdate::GroupInfo(info),
        DaemonResponse::Groups(groups) => GuiUpdate::GroupsLoaded(groups),
        DaemonResponse::GroupHistory(msgs) => {
            if let GuiCommand::GetGroupHistory { group_id, .. } = cmd {
                GuiUpdate::GroupHistoryLoaded {
                    group_id: *group_id,
                    messages: msgs,
                }
            } else {
                GuiUpdate::Ok
            }
        }
        DaemonResponse::LinkCode(code) => GuiUpdate::LinkCode(code),
        DaemonResponse::DeviceLinked { device_id, name } => {
            GuiUpdate::DeviceLinked { device_id, name }
        }
        DaemonResponse::Devices(devs) => GuiUpdate::DevicesLoaded(devs),
        DaemonResponse::Ok => match cmd {
            GuiCommand::SendMessage { .. } | GuiCommand::SendGroupMessage { .. } => {
                GuiUpdate::MessageSent
            }
            GuiCommand::AddContact { .. } => GuiUpdate::ContactAdded,
            GuiCommand::RemoveContact { .. } => GuiUpdate::ContactRemoved,
            _ => GuiUpdate::Ok,
        },
    }
}

/// Convert a `DaemonEvent` into a `GuiUpdate`.
fn event_to_update(event: DaemonEvent) -> GuiUpdate {
    match event {
        DaemonEvent::MessageReceived { from, payload } => {
            GuiUpdate::MessageReceived { from, payload }
        }
        DaemonEvent::ContactOnline(pk) => GuiUpdate::ContactOnline(pk),
        DaemonEvent::ContactOffline(pk) => GuiUpdate::ContactOffline(pk),
        DaemonEvent::FileProgress {
            id,
            bytes_sent,
            total,
        } => GuiUpdate::FileProgress {
            id,
            bytes_sent,
            total,
        },
        DaemonEvent::FileComplete { id, path } => GuiUpdate::FileComplete { id, path },
        DaemonEvent::FileError { id, error } => GuiUpdate::FileError { id, error },
        DaemonEvent::GroupMessageReceived {
            group_id,
            from,
            payload,
        } => GuiUpdate::GroupMessageReceived {
            group_id,
            from,
            payload,
        },
        DaemonEvent::GroupMemberJoined { group_id, member } => {
            GuiUpdate::GroupMemberJoined { group_id, member }
        }
        DaemonEvent::GroupMemberLeft { group_id, member } => {
            GuiUpdate::GroupMemberLeft { group_id, member }
        }
        DaemonEvent::GroupInvite {
            group_id,
            name,
            invited_by,
        } => GuiUpdate::GroupInvite {
            group_id,
            name,
            invited_by,
        },
        DaemonEvent::DeviceLinked { device_id, name } => {
            GuiUpdate::DeviceLinked { device_id, name }
        }
        DaemonEvent::DeviceUnlinked { device_id } => GuiUpdate::DeviceUnlinked { device_id },
        DaemonEvent::SyncCompleted {
            device_id,
            messages_synced,
        } => GuiUpdate::SyncCompleted {
            device_id,
            messages_synced,
        },
    }
}

/// Run the IPC bridge on a tokio runtime (called from a spawned `std::thread`).
///
/// Connects to the daemon, forwards commands from the UI as `DaemonRequest`s,
/// and sends responses and events back as `GuiUpdate`s.
pub async fn run_ipc_bridge(
    ctx: egui::Context,
    mut cmd_rx: mpsc::Receiver<GuiCommand>,
    update_tx: mpsc::Sender<GuiUpdate>,
) {
    // Connect to daemon
    let (client, mut events) = match DaemonClient::connect().await {
        Ok(pair) => {
            let _ = update_tx.send(GuiUpdate::Connected).await;
            ctx.request_repaint();
            pair
        }
        Err(e) => {
            let _ = update_tx.send(GuiUpdate::Disconnected(e.to_string())).await;
            ctx.request_repaint();
            return;
        }
    };

    loop {
        tokio::select! {
            // Handle commands from the UI
            Some(cmd) = cmd_rx.recv() => {
                let is_shutdown = matches!(cmd, GuiCommand::Shutdown);
                if let Some(req) = command_to_request(&cmd) {
                    match client.request(&req).await {
                        Ok(resp) => {
                            let update = response_to_update(&cmd, resp);
                            let _ = update_tx.send(update).await;
                            ctx.request_repaint();
                        }
                        Err(e) => {
                            let _ = update_tx.send(GuiUpdate::Disconnected(e.to_string())).await;
                            ctx.request_repaint();
                            break;
                        }
                    }
                }
                if is_shutdown {
                    break;
                }
            }
            // Handle async events from daemon
            Some(event) = events.recv() => {
                let update = event_to_update(event);
                let _ = update_tx.send(update).await;
                ctx.request_repaint();
            }
            // Both channels closed
            else => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_to_request_get_contacts() {
        let cmd = GuiCommand::GetContacts;
        let req = command_to_request(&cmd);
        assert!(matches!(req, Some(DaemonRequest::GetContacts)));
    }

    #[test]
    fn command_to_request_send_message() {
        let cmd = GuiCommand::SendMessage {
            to: vec![0xAA; 32],
            text: "hello".into(),
        };
        let req = command_to_request(&cmd);
        assert!(matches!(req, Some(DaemonRequest::SendMessage { .. })));
    }

    #[test]
    fn response_to_update_contacts() {
        let cmd = GuiCommand::GetContacts;
        let resp = DaemonResponse::Contacts(vec![]);
        let update = response_to_update(&cmd, resp);
        assert!(matches!(update, GuiUpdate::ContactsLoaded(_)));
    }

    #[test]
    fn response_to_update_error() {
        let cmd = GuiCommand::GetContacts;
        let resp = DaemonResponse::Error("fail".into());
        let update = response_to_update(&cmd, resp);
        assert!(matches!(update, GuiUpdate::Error(_)));
    }

    #[test]
    fn event_to_update_message_received() {
        let event = DaemonEvent::MessageReceived {
            from: vec![1; 16],
            payload: b"text".to_vec(),
        };
        let update = event_to_update(event);
        assert!(matches!(update, GuiUpdate::MessageReceived { .. }));
    }

    #[test]
    fn event_to_update_contact_online() {
        let event = DaemonEvent::ContactOnline(vec![0xAB; 32]);
        let update = event_to_update(event);
        assert!(matches!(update, GuiUpdate::ContactOnline(_)));
    }

    #[test]
    fn command_to_request_create_group() {
        let cmd = GuiCommand::CreateGroup {
            name: "test".into(),
            members: vec![],
        };
        let req = command_to_request(&cmd);
        assert!(matches!(req, Some(DaemonRequest::CreateGroup { .. })));
    }

    #[test]
    fn command_to_request_generate_link_code() {
        let cmd = GuiCommand::GenerateLinkCode;
        let req = command_to_request(&cmd);
        assert!(matches!(req, Some(DaemonRequest::GenerateLinkCode)));
    }
}
