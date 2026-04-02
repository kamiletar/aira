//! `AiraRuntime` — the main FFI object exposed to Kotlin via UniFFI.
//!
//! Embeds the daemon logic in-process (no separate daemon process on Android).
//! Owns a tokio runtime, storage, blob store, and event broadcast channel.
//!
//! See SPEC.md §15.3 for the Android embedded-daemon architecture.

use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::{broadcast, mpsc, RwLock};

use aira_daemon::handler;
use aira_daemon::transfers::TransferManager;
use aira_daemon::types::{DaemonEvent, DaemonRequest, DaemonResponse};

use crate::callbacks::{dispatch_event, AiraEventListener};
use crate::types::{FfiContact, FfiDeviceInfo, FfiError, FfiGroupDetail, FfiGroupInfo, FfiMessage};

/// The main runtime object for the Aira messenger.
///
/// On Android, a single `AiraRuntime` instance is created by the Foreground Service
/// and shared with all Activities via `bindService()`.
#[derive(uniffi::Object)]
pub struct AiraRuntime {
    /// Tokio runtime for async operations.
    tokio_rt: tokio::runtime::Runtime,
    /// Encrypted database.
    storage: Arc<aira_storage::Storage>,
    /// In-memory blob store for file transfers.
    blob_store: aira_net::blobs::BlobStore,
    /// Transfer progress tracker.
    transfer_mgr: TransferManager,
    /// Event broadcast sender.
    event_tx: broadcast::Sender<DaemonEvent>,
    /// Shutdown signal sender.
    shutdown_tx: mpsc::Sender<()>,
    /// Registered event listener (Kotlin callback).
    listener: RwLock<Option<Arc<dyn AiraEventListener>>>,
}

#[uniffi::export]
impl AiraRuntime {
    /// Create a new runtime with the given data directory and seed phrase.
    ///
    /// This performs Argon2id key derivation (CPU-intensive) and opens the database.
    /// Call from a background thread on Android.
    ///
    /// # Errors
    ///
    /// Returns `FfiError::Crypto` if the seed phrase is invalid,
    /// `FfiError::Storage` if the database cannot be opened.
    #[uniffi::constructor]
    pub fn new(data_dir: String, seed_phrase: String) -> Result<Arc<Self>, FfiError> {
        let tokio_rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| FfiError::Internal {
                msg: format!("failed to create tokio runtime: {e}"),
            })?;

        // Derive master seed (CPU-heavy: Argon2id)
        let master_seed = aira_core::seed::MasterSeed::from_phrase(&seed_phrase)
            .map_err(|e| FfiError::Crypto { msg: e.to_string() })?;

        let storage_key = master_seed.derive("aira/storage/0");

        // Ensure data directory exists
        let dir = PathBuf::from(&data_dir);
        std::fs::create_dir_all(&dir).map_err(|e| FfiError::Storage {
            msg: format!("cannot create data dir: {e}"),
        })?;

        // Open database
        let db_path = dir.join("aira.redb");
        let storage = Arc::new(
            aira_storage::Storage::open(&db_path, storage_key)
                .map_err(|e| FfiError::Storage { msg: e.to_string() })?,
        );

        // Initial dedup GC (ignore errors, best-effort)
        let _ = aira_storage::dedup::gc_expired(&storage);

        // Create downloads directory
        let downloads_dir = dir.join("downloads");
        let _ = std::fs::create_dir_all(&downloads_dir);

        // Event broadcast channel
        let (event_tx, _) = broadcast::channel::<DaemonEvent>(256);

        // Blob store and transfer manager (BlobStore::new() requires tokio context)
        let blob_store = tokio_rt.block_on(async { aira_net::blobs::BlobStore::new() });
        let transfer_mgr = TransferManager::new(event_tx.clone());

        // Shutdown channel
        let (shutdown_tx, _shutdown_rx) = mpsc::channel::<()>(1);

        // Spawn periodic GC tasks
        let ttl_storage = storage.clone();
        let dedup_storage = storage.clone();
        tokio_rt.spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            loop {
                interval.tick().await;
                let _ = aira_storage::messages::delete_expired(&ttl_storage);
            }
        });
        tokio_rt.spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
            loop {
                interval.tick().await;
                let _ = aira_storage::dedup::gc_expired(&dedup_storage);
            }
        });

        Ok(Arc::new(Self {
            tokio_rt,
            storage,
            blob_store,
            transfer_mgr,
            event_tx,
            shutdown_tx,
            listener: RwLock::new(None),
        }))
    }

    // ─── Event listener ────────────────────────────────────────────────

    /// Register a Kotlin callback to receive asynchronous events.
    ///
    /// Replaces any previously registered listener. Pass `None` (omit call)
    /// to unregister.
    pub fn set_event_listener(&self, listener: Box<dyn AiraEventListener>) {
        let listener: Arc<dyn AiraEventListener> = Arc::from(listener);

        // Store listener
        let mut guard = self.tokio_rt.block_on(self.listener.write());
        *guard = Some(listener.clone());
        drop(guard);

        // Spawn event forwarding task
        let mut rx = self.event_tx.subscribe();
        self.tokio_rt.spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(event) => dispatch_event(listener.as_ref(), event),
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("event listener lagged by {n} events");
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });
    }

    // ─── Contacts ──────────────────────────────────────────────────────

    /// Get all contacts.
    pub fn get_contacts(&self) -> Result<Vec<FfiContact>, FfiError> {
        match self.dispatch(DaemonRequest::GetContacts) {
            DaemonResponse::Contacts(list) => Ok(list.into_iter().map(FfiContact::from).collect()),
            DaemonResponse::Error(e) => Err(FfiError::Storage { msg: e }),
            _ => Err(FfiError::Internal {
                msg: "unexpected response".into(),
            }),
        }
    }

    /// Add a new contact.
    pub fn add_contact(&self, pubkey: Vec<u8>, alias: String) -> Result<(), FfiError> {
        self.dispatch_ok(DaemonRequest::AddContact { pubkey, alias })
    }

    /// Remove a contact.
    pub fn remove_contact(&self, pubkey: Vec<u8>) -> Result<(), FfiError> {
        self.dispatch_ok(DaemonRequest::RemoveContact { pubkey })
    }

    // ─── Messages ──────────────────────────────────────────────────────

    /// Send a text message to a contact.
    pub fn send_message(&self, to: Vec<u8>, text: String) -> Result<(), FfiError> {
        self.dispatch_ok(DaemonRequest::SendMessage { to, text })
    }

    /// Get message history for a contact.
    pub fn get_history(&self, contact: Vec<u8>, limit: u32) -> Result<Vec<FfiMessage>, FfiError> {
        match self.dispatch(DaemonRequest::GetHistory { contact, limit }) {
            DaemonResponse::History(msgs) => Ok(msgs.into_iter().map(FfiMessage::from).collect()),
            DaemonResponse::Error(e) => Err(FfiError::Storage { msg: e }),
            _ => Err(FfiError::Internal {
                msg: "unexpected response".into(),
            }),
        }
    }

    /// Get our own public key / identity address.
    pub fn get_my_address(&self) -> Result<Vec<u8>, FfiError> {
        match self.dispatch(DaemonRequest::GetMyAddress) {
            DaemonResponse::MyAddress(addr) => Ok(addr),
            DaemonResponse::Error(e) => Err(FfiError::Internal { msg: e }),
            _ => Err(FfiError::Internal {
                msg: "unexpected response".into(),
            }),
        }
    }

    /// Set disappearing message TTL for a contact.
    pub fn set_ttl(&self, contact: Vec<u8>, ttl_secs: Option<u64>) -> Result<(), FfiError> {
        self.dispatch_ok(DaemonRequest::SetTtl { contact, ttl_secs })
    }

    // ─── Groups ────────────────────────────────────────────────────────

    /// Create a new group chat.
    pub fn create_group(&self, name: String, members: Vec<Vec<u8>>) -> Result<Vec<u8>, FfiError> {
        match self.dispatch(DaemonRequest::CreateGroup { name, members }) {
            DaemonResponse::GroupCreated { group_id } => Ok(group_id.to_vec()),
            DaemonResponse::Error(e) => Err(FfiError::Storage { msg: e }),
            _ => Err(FfiError::Internal {
                msg: "unexpected response".into(),
            }),
        }
    }

    /// Get all groups.
    pub fn get_groups(&self) -> Result<Vec<FfiGroupInfo>, FfiError> {
        match self.dispatch(DaemonRequest::GetGroups) {
            DaemonResponse::Groups(list) => Ok(list.into_iter().map(FfiGroupInfo::from).collect()),
            DaemonResponse::Error(e) => Err(FfiError::Storage { msg: e }),
            _ => Err(FfiError::Internal {
                msg: "unexpected response".into(),
            }),
        }
    }

    /// Get detailed info about a group (with members list).
    pub fn get_group_info(&self, group_id: Vec<u8>) -> Result<FfiGroupDetail, FfiError> {
        let gid = vec_to_group_id(&group_id)?;
        match self.dispatch(DaemonRequest::GetGroupInfo { group_id: gid }) {
            DaemonResponse::GroupInfo(info) => Ok(FfiGroupDetail::from(info)),
            DaemonResponse::Error(e) => Err(FfiError::Storage { msg: e }),
            _ => Err(FfiError::Internal {
                msg: "unexpected response".into(),
            }),
        }
    }

    /// Send a text message to a group.
    pub fn send_group_message(&self, group_id: Vec<u8>, text: String) -> Result<(), FfiError> {
        let gid = vec_to_group_id(&group_id)?;
        self.dispatch_ok(DaemonRequest::SendGroupMessage {
            group_id: gid,
            text,
        })
    }

    /// Get group message history.
    pub fn get_group_history(
        &self,
        group_id: Vec<u8>,
        limit: u32,
    ) -> Result<Vec<FfiMessage>, FfiError> {
        let gid = vec_to_group_id(&group_id)?;
        match self.dispatch(DaemonRequest::GetGroupHistory {
            group_id: gid,
            limit,
        }) {
            DaemonResponse::GroupHistory(msgs) => {
                Ok(msgs.into_iter().map(FfiMessage::from).collect())
            }
            DaemonResponse::Error(e) => Err(FfiError::Storage { msg: e }),
            _ => Err(FfiError::Internal {
                msg: "unexpected response".into(),
            }),
        }
    }

    /// Add a member to a group.
    pub fn group_add_member(&self, group_id: Vec<u8>, member: Vec<u8>) -> Result<(), FfiError> {
        let gid = vec_to_group_id(&group_id)?;
        self.dispatch_ok(DaemonRequest::GroupAddMember {
            group_id: gid,
            member,
        })
    }

    /// Remove a member from a group.
    pub fn group_remove_member(&self, group_id: Vec<u8>, member: Vec<u8>) -> Result<(), FfiError> {
        let gid = vec_to_group_id(&group_id)?;
        self.dispatch_ok(DaemonRequest::GroupRemoveMember {
            group_id: gid,
            member,
        })
    }

    /// Leave a group.
    pub fn leave_group(&self, group_id: Vec<u8>) -> Result<(), FfiError> {
        let gid = vec_to_group_id(&group_id)?;
        self.dispatch_ok(DaemonRequest::LeaveGroup { group_id: gid })
    }

    // ─── Devices ───────────────────────────────────────────────────────

    /// Get all linked devices.
    pub fn get_devices(&self) -> Result<Vec<FfiDeviceInfo>, FfiError> {
        match self.dispatch(DaemonRequest::GetDevices) {
            DaemonResponse::Devices(list) => {
                Ok(list.into_iter().map(FfiDeviceInfo::from).collect())
            }
            DaemonResponse::Error(e) => Err(FfiError::Storage { msg: e }),
            _ => Err(FfiError::Internal {
                msg: "unexpected response".into(),
            }),
        }
    }

    /// Generate a one-time link code for pairing a new device.
    pub fn generate_link_code(&self) -> Result<String, FfiError> {
        match self.dispatch(DaemonRequest::GenerateLinkCode) {
            DaemonResponse::LinkCode(code) => Ok(code),
            DaemonResponse::Error(e) => Err(FfiError::Internal { msg: e }),
            _ => Err(FfiError::Internal {
                msg: "unexpected response".into(),
            }),
        }
    }

    /// Unlink a device.
    pub fn unlink_device(&self, device_id: Vec<u8>) -> Result<(), FfiError> {
        let did = vec_to_device_id(&device_id)?;
        self.dispatch_ok(DaemonRequest::UnlinkDevice { device_id: did })
    }

    // ─── Transport ─────────────────────────────────────────────────────

    /// Set the active transport mode.
    pub fn set_transport_mode(&self, mode: String) -> Result<(), FfiError> {
        self.dispatch_ok(DaemonRequest::SetTransportMode { mode })
    }

    /// Get the current transport mode.
    pub fn get_transport_mode(&self) -> Result<String, FfiError> {
        match self.dispatch(DaemonRequest::GetTransportMode) {
            DaemonResponse::TransportMode(mode) => Ok(mode),
            DaemonResponse::Error(e) => Err(FfiError::Internal { msg: e }),
            _ => Err(FfiError::Internal {
                msg: "unexpected response".into(),
            }),
        }
    }

    // ─── Lifecycle ─────────────────────────────────────────────────────

    /// Graceful shutdown. Call when the Android service is stopped.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.try_send(());
    }
}

// ─── Private helpers ───────────────────────────────────────────────────────

impl AiraRuntime {
    /// Dispatch a `DaemonRequest` through the shared handler.
    fn dispatch(&self, request: DaemonRequest) -> DaemonResponse {
        handler::handle_request(
            &self.storage,
            &self.blob_store,
            &self.transfer_mgr,
            &self.shutdown_tx,
            request,
        )
    }

    /// Dispatch a request and expect `DaemonResponse::Ok`.
    fn dispatch_ok(&self, request: DaemonRequest) -> Result<(), FfiError> {
        match self.dispatch(request) {
            DaemonResponse::Ok => Ok(()),
            DaemonResponse::Error(e) => Err(FfiError::Storage { msg: e }),
            _ => Err(FfiError::Internal {
                msg: "unexpected response".into(),
            }),
        }
    }
}

/// Convert a `Vec<u8>` to a 32-byte group ID array.
fn vec_to_group_id(v: &[u8]) -> Result<[u8; 32], FfiError> {
    v.try_into().map_err(|_| FfiError::InvalidArgument {
        msg: format!("group_id must be 32 bytes, got {}", v.len()),
    })
}

/// Convert a `Vec<u8>` to a 32-byte device ID array.
fn vec_to_device_id(v: &[u8]) -> Result<[u8; 32], FfiError> {
    v.try_into().map_err(|_| FfiError::InvalidArgument {
        msg: format!("device_id must be 32 bytes, got {}", v.len()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// Helper: create a runtime with a temp directory and a valid test seed.
    fn test_runtime() -> Arc<AiraRuntime> {
        let dir = tempfile::tempdir().expect("create temp dir");
        // Generate a valid BIP-39 phrase for testing
        let (phrase, _seed) = aira_core::seed::MasterSeed::generate().expect("generate seed");
        AiraRuntime::new(dir.path().to_string_lossy().to_string(), phrase.to_string())
            .expect("create runtime")
    }

    #[test]
    fn runtime_create_and_shutdown() {
        let rt = test_runtime();
        // Should be able to get empty contacts
        let contacts = rt.get_contacts().expect("get contacts");
        assert!(contacts.is_empty());
        rt.shutdown();
    }

    #[test]
    fn contact_crud() {
        let rt = test_runtime();
        let pk = vec![0xAA; 32];

        // Add contact
        rt.add_contact(pk.clone(), "Alice".into())
            .expect("add contact");

        // List contacts
        let contacts = rt.get_contacts().expect("get contacts");
        assert_eq!(contacts.len(), 1);
        assert_eq!(contacts[0].alias, "Alice");
        assert_eq!(contacts[0].pubkey, pk);

        // Remove contact
        rt.remove_contact(pk).expect("remove contact");
        let contacts = rt.get_contacts().expect("get contacts");
        assert!(contacts.is_empty());

        rt.shutdown();
    }

    #[test]
    fn send_and_get_history() {
        let rt = test_runtime();
        let pk = vec![0xBB; 32];

        rt.add_contact(pk.clone(), "Bob".into())
            .expect("add contact");
        rt.send_message(pk.clone(), "hello from FFI".into())
            .expect("send message");

        let history = rt.get_history(pk, 10).expect("get history");
        assert_eq!(history.len(), 1);
        assert!(history[0].sender_is_self);
        assert_eq!(history[0].payload, b"hello from FFI");

        rt.shutdown();
    }

    #[test]
    fn group_lifecycle() {
        let rt = test_runtime();

        // Create group
        let gid = rt
            .create_group("Test Group".into(), vec![vec![0xCC; 32]])
            .expect("create group");
        assert_eq!(gid.len(), 32);

        // List groups
        let groups = rt.get_groups().expect("get groups");
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].name, "Test Group");

        // Send group message
        rt.send_group_message(gid.clone(), "hello group".into())
            .expect("send group msg");

        // Get group history
        let history = rt.get_group_history(gid.clone(), 10).expect("get history");
        assert_eq!(history.len(), 1);

        // Leave group
        rt.leave_group(gid).expect("leave group");
        let groups = rt.get_groups().expect("get groups");
        assert!(groups.is_empty());

        rt.shutdown();
    }

    #[test]
    fn transport_mode_roundtrip() {
        let rt = test_runtime();

        // Default is "direct"
        let mode = rt.get_transport_mode().expect("get mode");
        assert_eq!(mode, "direct");

        // Set to obfs4
        rt.set_transport_mode("obfs4".into()).expect("set mode");

        let mode = rt.get_transport_mode().expect("get mode");
        assert_eq!(mode, "obfs4");

        rt.shutdown();
    }

    #[test]
    fn invalid_group_id_rejected() {
        let rt = test_runtime();
        let err = rt.get_group_info(vec![1, 2, 3]).unwrap_err();
        match err {
            FfiError::InvalidArgument { msg } => {
                assert!(msg.contains("32 bytes"));
            }
            _ => panic!("expected InvalidArgument, got {err:?}"),
        }
        rt.shutdown();
    }

    #[test]
    fn event_listener_receives_callbacks() {
        use std::sync::Arc;

        struct TestListener {
            call_count: Arc<AtomicU32>,
        }

        impl AiraEventListener for TestListener {
            fn on_message_received(&self, _from: Vec<u8>, _payload: Vec<u8>) {
                self.call_count.fetch_add(1, Ordering::SeqCst);
            }
            fn on_contact_online(&self, _pubkey: Vec<u8>) {}
            fn on_contact_offline(&self, _pubkey: Vec<u8>) {}
            fn on_group_message_received(
                &self,
                _group_id: Vec<u8>,
                _from: Vec<u8>,
                _payload: Vec<u8>,
            ) {
            }
            fn on_group_invite(&self, _group_id: Vec<u8>, _name: String, _invited_by: Vec<u8>) {}
            fn on_file_progress(&self, _id: Vec<u8>, _bytes_sent: u64, _total: u64) {}
            fn on_file_complete(&self, _id: Vec<u8>, _path: String) {}
            fn on_file_error(&self, _id: Vec<u8>, _error: String) {}
            fn on_device_linked(&self, _device_id: Vec<u8>, _name: String) {}
            fn on_device_unlinked(&self, _device_id: Vec<u8>) {}
            fn on_sync_completed(&self, _device_id: Vec<u8>, _messages_synced: u32) {}
        }

        let rt = test_runtime();
        let counter = Arc::new(AtomicU32::new(0));
        let listener = TestListener {
            call_count: counter.clone(),
        };

        rt.set_event_listener(Box::new(listener));

        // Send an event through the broadcast channel
        let _ = rt.event_tx.send(DaemonEvent::MessageReceived {
            from: vec![0x01; 16],
            payload: b"test".to_vec(),
        });

        // Give the async task a moment to process
        std::thread::sleep(std::time::Duration::from_millis(100));

        assert!(counter.load(Ordering::SeqCst) >= 1);

        rt.shutdown();
    }

    #[test]
    fn get_devices_empty() {
        let rt = test_runtime();
        let devices = rt.get_devices().expect("get devices");
        assert!(devices.is_empty());
        rt.shutdown();
    }

    #[test]
    fn generate_link_code_returns_string() {
        let rt = test_runtime();
        let code = rt.generate_link_code().expect("generate code");
        assert!(!code.is_empty());
        rt.shutdown();
    }
}
