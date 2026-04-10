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
use zeroize::Zeroizing;

/// Commands sent from the GUI to the IPC bridge.
///
/// `Debug` is implemented manually below so variants holding a
/// `Zeroizing<String>` seed phrase redact the secret instead of leaking
/// it via `{:?}` / `tracing::debug!`.
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

    // ─── Onboarding / connection lifecycle (Milestone 9.5) ──────────────
    /// User completed the welcome flow with a new or imported seed phrase.
    /// The bridge writes it to the OS keychain and then spawns the daemon.
    CompleteOnboarding { phrase: Zeroizing<String> },
    /// Retry connecting to the daemon (UI "Retry" button after `GaveUp`).
    RetryConnection,
    /// Wipe the stored seed phrase and return to the welcome flow.
    /// Intended for the "Forgot password" / "Reset identity" path.
    ResetIdentity,
}

impl std::fmt::Debug for GuiCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GetContacts => write!(f, "GetContacts"),
            Self::GetMyAddress => write!(f, "GetMyAddress"),
            Self::GetHistory { contact, limit } => f
                .debug_struct("GetHistory")
                .field("contact", contact)
                .field("limit", limit)
                .finish(),
            Self::SendMessage { to, text } => f
                .debug_struct("SendMessage")
                .field("to", to)
                .field("text.len", &text.len())
                .finish(),
            Self::AddContact { pubkey, alias } => f
                .debug_struct("AddContact")
                .field("pubkey", pubkey)
                .field("alias", alias)
                .finish(),
            Self::RemoveContact { pubkey } => f
                .debug_struct("RemoveContact")
                .field("pubkey", pubkey)
                .finish(),
            Self::SetTtl { contact, ttl_secs } => f
                .debug_struct("SetTtl")
                .field("contact", contact)
                .field("ttl_secs", ttl_secs)
                .finish(),
            Self::SendFile { to, path } => f
                .debug_struct("SendFile")
                .field("to", to)
                .field("path", path)
                .finish(),
            Self::GetTransportMode => write!(f, "GetTransportMode"),
            Self::SetTransportMode { mode } => f
                .debug_struct("SetTransportMode")
                .field("mode", mode)
                .finish(),
            Self::ExportBackup {
                path,
                include_messages,
            } => f
                .debug_struct("ExportBackup")
                .field("path", path)
                .field("include_messages", include_messages)
                .finish(),
            Self::ImportBackup { path } => f
                .debug_struct("ImportBackup")
                .field("path", path)
                .finish(),
            Self::CreateGroup { name, members } => f
                .debug_struct("CreateGroup")
                .field("name", name)
                .field("members.len", &members.len())
                .finish(),
            Self::GetGroups => write!(f, "GetGroups"),
            Self::GetGroupInfo { group_id } => f
                .debug_struct("GetGroupInfo")
                .field("group_id", group_id)
                .finish(),
            Self::SendGroupMessage { group_id, text } => f
                .debug_struct("SendGroupMessage")
                .field("group_id", group_id)
                .field("text.len", &text.len())
                .finish(),
            Self::GetGroupHistory { group_id, limit } => f
                .debug_struct("GetGroupHistory")
                .field("group_id", group_id)
                .field("limit", limit)
                .finish(),
            Self::GroupAddMember { group_id, member } => f
                .debug_struct("GroupAddMember")
                .field("group_id", group_id)
                .field("member", member)
                .finish(),
            Self::GroupRemoveMember { group_id, member } => f
                .debug_struct("GroupRemoveMember")
                .field("group_id", group_id)
                .field("member", member)
                .finish(),
            Self::LeaveGroup { group_id } => f
                .debug_struct("LeaveGroup")
                .field("group_id", group_id)
                .finish(),
            Self::GenerateLinkCode => write!(f, "GenerateLinkCode"),
            Self::LinkDevice { code: _, device_name } => f
                .debug_struct("LinkDevice")
                .field("code", &"[REDACTED]")
                .field("device_name", device_name)
                .finish(),
            Self::GetDevices => write!(f, "GetDevices"),
            Self::UnlinkDevice { device_id } => f
                .debug_struct("UnlinkDevice")
                .field("device_id", device_id)
                .finish(),
            Self::Shutdown => write!(f, "Shutdown"),
            Self::CompleteOnboarding { .. } => f
                .debug_struct("CompleteOnboarding")
                .field("phrase", &"[REDACTED]")
                .finish(),
            Self::RetryConnection => write!(f, "RetryConnection"),
            Self::ResetIdentity => write!(f, "ResetIdentity"),
        }
    }
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

    // ─── Onboarding / connection lifecycle (Milestone 9.5) ──────────────
    /// No seed phrase in the keychain — the GUI should show the welcome flow.
    OnboardingRequired,
    /// Daemon child process has been spawned; waiting for it to open the
    /// IPC socket / pipe.
    SpawningDaemon,
    /// Lost connection; backing off before the next attempt.
    Reconnecting { attempt: u32, next_in_ms: u64 },
    /// Spawned daemon exited before we could connect.
    DaemonSpawnFailed {
        reason: String,
        stderr: Option<String>,
    },
    /// `aira-daemon` binary not found (sibling of GUI or PATH).
    DaemonNotFound { expected_path: PathBuf },
    /// OS keychain is unavailable — usually headless Linux without
    /// `gnome-keyring` / `KWallet` running.
    KeychainUnavailable(String),
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

        // Lifecycle commands handled by the bridge itself, not forwarded
        // to the daemon as requests.
        GuiCommand::CompleteOnboarding { .. }
        | GuiCommand::RetryConnection
        | GuiCommand::ResetIdentity => None,
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
        // Pseudonym responses (§12.6) — not yet consumed by GUI
        DaemonResponse::Pseudonyms(_) | DaemonResponse::Pseudonym(_) => GuiUpdate::Ok,
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

// ─── Bridge — connection supervisor ─────────────────────────────────────

/// Backoff schedule (ms) for `Bridge::reconnect_loop`. Cap at 5 attempts,
/// ~18.5 seconds total.
const RECONNECT_BACKOFF_MS: &[u64] = &[500, 1000, 2000, 5000, 10_000];

/// Interval between post-spawn `connect()` polls.
const SPAWN_POLL_INTERVAL_MS: u64 = 200;

/// Maximum number of post-spawn connect attempts (10 seconds total).
const SPAWN_POLL_MAX_ATTEMPTS: u32 = 50;

/// IPC bridge supervisor. Owns the (possibly spawned) daemon child and the
/// current `DaemonClient` / event receiver; mediates between GUI commands
/// and daemon requests while handling onboarding, spawning, and reconnect.
struct Bridge {
    ctx: egui::Context,
    update_tx: mpsc::Sender<GuiUpdate>,
    client: Option<DaemonClient>,
    events: Option<mpsc::Receiver<DaemonEvent>>,
    handle: crate::daemon_manager::DaemonHandle,
    /// Seed phrase loaded from the keychain, kept so reconnect can re-spawn
    /// the daemon if the owned child dies mid-session.
    seed: Option<Zeroizing<String>>,
}

impl Bridge {
    fn new(ctx: egui::Context, update_tx: mpsc::Sender<GuiUpdate>) -> Self {
        Self {
            ctx,
            update_tx,
            client: None,
            events: None,
            handle: crate::daemon_manager::DaemonHandle::external(),
            seed: None,
        }
    }

    async fn send(&self, update: GuiUpdate) {
        let _ = self.update_tx.send(update).await;
        self.ctx.request_repaint();
    }

    /// Bootstrap: keychain → onboarding (if empty) → connect (or spawn + connect).
    ///
    /// Returns `true` if the bridge is Connected and ready for the main loop,
    /// `false` if a fatal error was reported (keychain unavailable, daemon
    /// binary missing, user never completed onboarding, etc.).
    async fn bootstrap(&mut self, cmd_rx: &mut mpsc::Receiver<GuiCommand>) -> bool {
        // Step 1: pull the seed phrase from the keychain, or wait for onboarding.
        let seed = match crate::keychain::load_seed_phrase() {
            Ok(Some(phrase)) => phrase,
            Ok(None) => {
                // First run — wait for the user to complete onboarding.
                self.send(GuiUpdate::OnboardingRequired).await;
                match self.wait_for_onboarding(cmd_rx).await {
                    Some(phrase) => phrase,
                    None => return false, // user closed the window
                }
            }
            Err(e) => {
                self.send(GuiUpdate::KeychainUnavailable(e.to_string())).await;
                return false;
            }
        };
        self.seed = Some(seed);

        // Step 2: try to adopt a pre-existing daemon first.
        if let Ok(pair) = DaemonClient::connect().await {
            self.client = Some(pair.0);
            self.events = Some(pair.1);
            self.handle = crate::daemon_manager::DaemonHandle::external();
            self.send(GuiUpdate::Connected).await;
            return true;
        }

        // Step 3: spawn our own daemon and poll until it answers.
        self.send(GuiUpdate::SpawningDaemon).await;
        let seed_ref = self.seed.as_ref().expect("seed set above");
        match crate::daemon_manager::spawn(seed_ref) {
            Ok(handle) => {
                self.handle = handle;
            }
            Err(e) => {
                // Distinguish "not found" from other spawn errors for a
                // better dialog — daemon_manager puts the expected path in
                // the reason string when the binary is missing.
                if e.reason.contains("not found") {
                    let expected = crate::daemon_manager::locate_daemon_binary()
                        .err()
                        .unwrap_or_default();
                    self.send(GuiUpdate::DaemonNotFound {
                        expected_path: expected,
                    })
                    .await;
                } else {
                    self.send(GuiUpdate::DaemonSpawnFailed {
                        reason: e.reason,
                        stderr: e.stderr,
                    })
                    .await;
                }
                return false;
            }
        }

        // Step 4: poll connect() up to ~10s.
        for _ in 0..SPAWN_POLL_MAX_ATTEMPTS {
            if let Some(err) = crate::daemon_manager::check_early_exit(&mut self.handle) {
                self.send(GuiUpdate::DaemonSpawnFailed {
                    reason: err.reason,
                    stderr: err.stderr,
                })
                .await;
                return false;
            }
            tokio::time::sleep(std::time::Duration::from_millis(SPAWN_POLL_INTERVAL_MS))
                .await;
            if let Ok(pair) = DaemonClient::connect().await {
                self.client = Some(pair.0);
                self.events = Some(pair.1);
                self.send(GuiUpdate::Connected).await;
                return true;
            }
        }

        self.send(GuiUpdate::DaemonSpawnFailed {
            reason: "timed out waiting for daemon to open its IPC socket".into(),
            stderr: None,
        })
        .await;
        false
    }

    /// Wait for `GuiCommand::CompleteOnboarding`, persisting the phrase to
    /// the keychain on receipt. Returns `None` if the command channel is
    /// closed (i.e. the GUI is exiting).
    async fn wait_for_onboarding(
        &mut self,
        cmd_rx: &mut mpsc::Receiver<GuiCommand>,
    ) -> Option<Zeroizing<String>> {
        while let Some(cmd) = cmd_rx.recv().await {
            match cmd {
                GuiCommand::CompleteOnboarding { phrase } => {
                    if let Err(e) = crate::keychain::store_seed_phrase(&phrase) {
                        self.send(GuiUpdate::KeychainUnavailable(e.to_string()))
                            .await;
                        // Don't return — let the user retry or close.
                        continue;
                    }
                    return Some(phrase);
                }
                GuiCommand::Shutdown => return None,
                _ => {
                    // Ignore other commands during onboarding — nothing
                    // meaningful can be forwarded to a non-existent daemon.
                }
            }
        }
        None
    }

    /// Main loop: forward GUI commands as `DaemonRequest`s, relay
    /// `DaemonEvent`s back as `GuiUpdate`s, and transition to
    /// `reconnect_loop` on error.
    async fn main_loop(&mut self, cmd_rx: &mut mpsc::Receiver<GuiCommand>) {
        loop {
            let Some(client) = self.client.as_ref() else {
                return;
            };
            let Some(events) = self.events.as_mut() else {
                return;
            };

            tokio::select! {
                maybe_cmd = cmd_rx.recv() => {
                    let Some(cmd) = maybe_cmd else { return; };
                    if matches!(cmd, GuiCommand::Shutdown) {
                        if let Some(req) = command_to_request(&cmd) {
                            let _ = client.request(&req).await;
                        }
                        return;
                    }
                    match cmd {
                        GuiCommand::RetryConnection => {
                            if self.reconnect_loop().await.is_err() {
                                self.send(GuiUpdate::Disconnected(
                                    "reconnect failed".into(),
                                )).await;
                            }
                        }
                        GuiCommand::ResetIdentity => {
                            let _ = crate::keychain::delete_seed_phrase();
                            self.seed = None;
                            self.send(GuiUpdate::OnboardingRequired).await;
                            let Some(phrase) = self.wait_for_onboarding(cmd_rx).await else {
                                return;
                            };
                            self.seed = Some(phrase);
                            if !self.respawn_after_reset().await {
                                return;
                            }
                        }
                        GuiCommand::CompleteOnboarding { .. } => {
                            // Stale — onboarding is already done. Ignore.
                        }
                        other => {
                            if let Some(req) = command_to_request(&other) {
                                match client.request(&req).await {
                                    Ok(resp) => {
                                        let update = response_to_update(&other, resp);
                                        self.send(update).await;
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            "ipc: request failed, entering reconnect: {e}"
                                        );
                                        if self.reconnect_loop().await.is_err() {
                                            self.send(GuiUpdate::Disconnected(
                                                e.to_string(),
                                            )).await;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                maybe_event = events.recv() => {
                    if let Some(event) = maybe_event {
                        let update = event_to_update(event);
                        self.send(update).await;
                    } else {
                        tracing::warn!("ipc: event channel dropped, entering reconnect");
                        if self.reconnect_loop().await.is_err() {
                            self.send(GuiUpdate::Disconnected(
                                "daemon event stream closed".into(),
                            )).await;
                        }
                    }
                }
            }
        }
    }

    /// Exponential-backoff reconnect schedule. Returns `Ok(())` on success
    /// (self.client / self.events replaced), `Err(())` after exhausting all
    /// attempts.
    async fn reconnect_loop(&mut self) -> Result<(), ()> {
        // Drop the dead client/events so we don't hold stale handles.
        self.client = None;
        self.events = None;

        for (i, delay_ms) in RECONNECT_BACKOFF_MS.iter().enumerate() {
            let attempt = (i + 1) as u32;
            self.send(GuiUpdate::Reconnecting {
                attempt,
                next_in_ms: *delay_ms,
            })
            .await;
            tokio::time::sleep(std::time::Duration::from_millis(*delay_ms)).await;

            // If our owned child died, one-shot respawn before trying connect.
            if self.handle.owned {
                if let Some(err) = crate::daemon_manager::check_early_exit(&mut self.handle) {
                    tracing::warn!("ipc: owned daemon died ({}), respawning", err.reason);
                    if let Some(seed) = self.seed.as_ref() {
                        match crate::daemon_manager::spawn(seed) {
                            Ok(handle) => self.handle = handle,
                            Err(e) => {
                                tracing::error!("ipc: respawn failed: {}", e.reason);
                                continue;
                            }
                        }
                    }
                }
            }

            match DaemonClient::connect().await {
                Ok(pair) => {
                    self.client = Some(pair.0);
                    self.events = Some(pair.1);
                    self.send(GuiUpdate::Connected).await;
                    return Ok(());
                }
                Err(e) => {
                    tracing::debug!("ipc: reconnect attempt {attempt} failed: {e}");
                }
            }
        }
        Err(())
    }

    /// Re-run the spawn + poll logic after a `ResetIdentity`. Keeps the
    /// bridge alive so the user doesn't have to restart the GUI.
    async fn respawn_after_reset(&mut self) -> bool {
        let Some(seed_ref) = self.seed.as_ref() else {
            return false;
        };
        self.send(GuiUpdate::SpawningDaemon).await;
        match crate::daemon_manager::spawn(seed_ref) {
            Ok(handle) => self.handle = handle,
            Err(e) => {
                self.send(GuiUpdate::DaemonSpawnFailed {
                    reason: e.reason,
                    stderr: e.stderr,
                })
                .await;
                return false;
            }
        }
        for _ in 0..SPAWN_POLL_MAX_ATTEMPTS {
            tokio::time::sleep(std::time::Duration::from_millis(SPAWN_POLL_INTERVAL_MS))
                .await;
            if let Ok(pair) = DaemonClient::connect().await {
                self.client = Some(pair.0);
                self.events = Some(pair.1);
                self.send(GuiUpdate::Connected).await;
                return true;
            }
        }
        self.send(GuiUpdate::DaemonSpawnFailed {
            reason: "timed out after reset".into(),
            stderr: None,
        })
        .await;
        false
    }

    /// Graceful shutdown: send Shutdown to daemon, wait briefly, then drop
    /// the handle (which kills any owned child as a fallback).
    async fn shutdown(mut self) {
        if let Some(client) = self.client.take() {
            let _ = client.request(&DaemonRequest::Shutdown).await;
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        // `self.handle` drops here — Drop impl kills owned child if alive.
    }
}

/// Run the IPC bridge on a tokio runtime (called from a spawned `std::thread`).
///
/// Owns the daemon child process lifecycle (onboarding, spawning,
/// reconnecting, graceful shutdown) via the `Bridge` supervisor.
pub async fn run_ipc_bridge(
    ctx: egui::Context,
    mut cmd_rx: mpsc::Receiver<GuiCommand>,
    update_tx: mpsc::Sender<GuiUpdate>,
) {
    let mut bridge = Bridge::new(ctx, update_tx);
    if bridge.bootstrap(&mut cmd_rx).await {
        bridge.main_loop(&mut cmd_rx).await;
    }
    bridge.shutdown().await;
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
