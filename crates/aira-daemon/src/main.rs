//! aira-daemon — background process managing network, crypto, and storage.
//!
//! Communicates with aira-cli (and future GUI) via IPC:
//! - Linux/macOS: Unix domain socket (~/.aira/daemon.sock)
//! - Windows:     Named pipe (\\.\pipe\aira-daemon)
//!
//! See SPEC.md §8 for the IPC API specification.

#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use tokio::sync::{broadcast, mpsc};
mod ipc;
mod transfers;

use aira_daemon::types;
use transfers::TransferManager;
use types::{
    DaemonEvent, DaemonRequest, DaemonResponse, DeviceInfoResp, GroupInfoResp, GroupMemberResp,
};

/// Default data directory.
fn data_dir() -> PathBuf {
    #[cfg(unix)]
    {
        dirs_path().unwrap_or_else(|| PathBuf::from(".aira"))
    }
    #[cfg(windows)]
    {
        dirs_path().unwrap_or_else(|| PathBuf::from(".aira"))
    }
}

fn dirs_path() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        std::env::var("HOME")
            .ok()
            .map(|h| PathBuf::from(h).join(".aira"))
    }
    #[cfg(windows)]
    {
        std::env::var("LOCALAPPDATA")
            .ok()
            .map(|d| PathBuf::from(d).join("aira"))
    }
}

/// IPC socket/pipe path.
fn ipc_path(data_dir: &std::path::Path) -> PathBuf {
    #[cfg(unix)]
    {
        data_dir.join("daemon.sock")
    }
    #[cfg(windows)]
    {
        let _ = data_dir; // Windows named pipes have a fixed path
        PathBuf::from(r"\\.\pipe\aira-daemon")
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("AIRA_LOG")
                .unwrap_or_else(|_| "aira=info".to_string())
                .as_str(),
        )
        .init();

    tracing::info!("aira-daemon starting");

    // Get seed phrase from environment variable
    let seed_phrase = std::env::var("AIRA_SEED").map_err(|_| {
        anyhow::anyhow!(
            "AIRA_SEED environment variable not set. \
             Set it to your 24-word BIP-39 seed phrase."
        )
    })?;

    // Derive master seed (CPU-heavy: Argon2id with m=256MB)
    tracing::info!("deriving master seed (this may take a few seconds)...");
    let master_seed = {
        let phrase = seed_phrase.clone();
        tokio::task::spawn_blocking(move || aira_core::seed::MasterSeed::from_phrase(&phrase))
            .await??
    };

    // Derive storage key
    let storage_key = master_seed.derive("aira/storage/0");

    // Open database
    let dir = data_dir();
    std::fs::create_dir_all(&dir)?;
    let db_path = dir.join("aira.redb");
    let storage = Arc::new(aira_storage::Storage::open(&db_path, storage_key)?);
    tracing::info!("database opened at {}", db_path.display());

    // Initial dedup GC
    let gc_count = aira_storage::dedup::gc_expired(&storage)?;
    if gc_count > 0 {
        tracing::info!("dedup GC: removed {gc_count} expired entries");
    }

    // Event broadcast channel for IPC clients
    let (event_tx, _) = broadcast::channel::<DaemonEvent>(256);

    // Blob store for file transfer (in-memory, transient)
    let blob_store = aira_net::blobs::BlobStore::new();
    tracing::info!("blob store initialized (in-memory)");

    // Transfer manager
    let transfer_mgr = TransferManager::new(event_tx.clone());

    // Create downloads directory
    let downloads_dir = dir.join("downloads");
    std::fs::create_dir_all(&downloads_dir)?;
    tracing::info!("downloads directory: {}", downloads_dir.display());

    // Shutdown channel
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);

    // Build request handler
    let handler_storage = storage.clone();
    let handler_blob_store = blob_store.clone();
    let handler_transfer_mgr = transfer_mgr.clone();
    let shutdown_signal = shutdown_tx.clone();
    let handler: ipc::RequestHandler = Arc::new(move |request| {
        handle_request(
            &handler_storage,
            &handler_blob_store,
            &handler_transfer_mgr,
            &shutdown_signal,
            request,
        )
    });

    // Start IPC server
    let ipc_socket = ipc_path(&dir);
    let ipc_handle = tokio::spawn(ipc::start_ipc_server(
        ipc_socket,
        handler,
        event_tx,
        shutdown_rx,
    ));

    // Periodic timers
    let ttl_storage = storage.clone();
    let dedup_storage = storage.clone();

    let ttl_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            match aira_storage::messages::delete_expired(&ttl_storage) {
                Ok(0) => {}
                Ok(n) => tracing::debug!("TTL GC: deleted {n} expired messages"),
                Err(e) => tracing::warn!("TTL GC error: {e}"),
            }
        }
    });

    let dedup_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            interval.tick().await;
            match aira_storage::dedup::gc_expired(&dedup_storage) {
                Ok(0) => {}
                Ok(n) => tracing::debug!("dedup GC: removed {n} expired entries"),
                Err(e) => tracing::warn!("dedup GC error: {e}"),
            }
        }
    });

    tracing::info!("aira-daemon ready");

    // Wait for IPC server to finish (shutdown signal)
    if let Err(e) = ipc_handle.await? {
        tracing::error!("IPC server error: {e}");
    }

    // Cancel timers
    ttl_handle.abort();
    dedup_handle.abort();

    tracing::info!("aira-daemon stopped");
    Ok(())
}

/// Handle a single IPC request.
#[allow(clippy::too_many_lines)]
fn handle_request(
    storage: &aira_storage::Storage,
    blob_store: &aira_net::blobs::BlobStore,
    transfer_mgr: &TransferManager,
    shutdown_tx: &mpsc::Sender<()>,
    request: DaemonRequest,
) -> DaemonResponse {
    match request {
        DaemonRequest::AddContact { pubkey, alias } => {
            match aira_storage::contacts::add(storage, &pubkey, &alias) {
                Ok(()) => DaemonResponse::Ok,
                Err(e) => DaemonResponse::Error(e.to_string()),
            }
        }
        DaemonRequest::RemoveContact { pubkey } => {
            match aira_storage::contacts::remove(storage, &pubkey) {
                Ok(()) => DaemonResponse::Ok,
                Err(e) => DaemonResponse::Error(e.to_string()),
            }
        }
        DaemonRequest::GetContacts => match aira_storage::contacts::list(storage) {
            Ok(contacts) => DaemonResponse::Contacts(contacts),
            Err(e) => DaemonResponse::Error(e.to_string()),
        },
        DaemonRequest::GetHistory { contact, limit } => {
            let cid = aira_storage::contact_id(&contact);
            match aira_storage::messages::get_history(storage, cid, limit, u64::MAX) {
                Ok(messages) => DaemonResponse::History(messages),
                Err(e) => DaemonResponse::Error(e.to_string()),
            }
        }
        DaemonRequest::SendMessage { to, text } => {
            // TODO(M5): integrate with aira-net to actually send
            // For now, store as a pending message
            let cid = aira_storage::contact_id(&to);
            let msg = aira_storage::StoredMessage {
                id: rand_id(),
                sender_is_self: true,
                payload_bytes: text.into_bytes(),
                timestamp_micros: now_micros(),
                ttl_secs: aira_storage::settings::get_ttl(storage, &to).unwrap_or(None),
                read_at: None,
                expires_at: None,
            };
            match aira_storage::messages::store(storage, cid, &msg) {
                Ok(()) => DaemonResponse::Ok,
                Err(e) => DaemonResponse::Error(e.to_string()),
            }
        }
        DaemonRequest::GetMyAddress => {
            // TODO(M5): return actual identity public key
            DaemonResponse::MyAddress(vec![])
        }
        DaemonRequest::SetTtl { contact, ttl_secs } => {
            match aira_storage::settings::set_ttl(storage, &contact, ttl_secs) {
                Ok(()) => DaemonResponse::Ok,
                Err(e) => DaemonResponse::Error(e.to_string()),
            }
        }
        DaemonRequest::ExportBackup {
            path,
            include_messages,
        } => match aira_storage::backup::export(storage, &path, include_messages) {
            Ok(()) => DaemonResponse::Ok,
            Err(e) => DaemonResponse::Error(e.to_string()),
        },
        DaemonRequest::ImportBackup { path } => {
            match aira_storage::backup::import(&path, storage.key()) {
                Ok(data) => match aira_storage::backup::restore(storage, &data) {
                    Ok(()) => DaemonResponse::Ok,
                    Err(e) => DaemonResponse::Error(format!("restore failed: {e}")),
                },
                Err(e) => DaemonResponse::Error(e.to_string()),
            }
        }
        DaemonRequest::SendFile { to: _, path } => handle_send_file(blob_store, transfer_mgr, path),
        // ─── Transport operations (SPEC.md §11A) ────────────────────────
        DaemonRequest::SetTransportMode { mode } => handle_set_transport_mode(storage, &mode),
        DaemonRequest::GetTransportMode => handle_get_transport_mode(storage),

        DaemonRequest::Shutdown => {
            let _ = shutdown_tx.try_send(());
            DaemonResponse::Ok
        }

        // ─── Group operations (SPEC.md §12) ─────────────────────────────
        DaemonRequest::CreateGroup { name, members } => {
            handle_create_group(storage, &name, &members)
        }
        DaemonRequest::GetGroups => match aira_storage::groups::list_groups(storage) {
            Ok(groups) => {
                let resp: Vec<_> = groups.iter().map(group_info_to_resp).collect();
                DaemonResponse::Groups(resp)
            }
            Err(e) => DaemonResponse::Error(e.to_string()),
        },
        DaemonRequest::GetGroupInfo { group_id } => {
            match aira_storage::groups::get_group(storage, &group_id) {
                Ok(group) => DaemonResponse::GroupInfo(group_info_to_resp(&group)),
                Err(e) => DaemonResponse::Error(e.to_string()),
            }
        }
        DaemonRequest::SendGroupMessage { group_id, text } => {
            handle_send_group_message(storage, &group_id, &text)
        }
        DaemonRequest::GetGroupHistory { group_id, limit } => {
            match aira_storage::groups::get_group_history(storage, &group_id, limit) {
                Ok(messages) => DaemonResponse::GroupHistory(messages),
                Err(e) => DaemonResponse::Error(e.to_string()),
            }
        }
        DaemonRequest::GroupAddMember { group_id, member } => {
            handle_group_add_member(storage, &group_id, &member)
        }
        DaemonRequest::GroupRemoveMember { group_id, member } => {
            handle_group_remove_member(storage, &group_id, &member)
        }
        DaemonRequest::LeaveGroup { group_id } => handle_leave_group(storage, &group_id),

        // ─── Device operations (SPEC.md §14) ────────────────────────────
        DaemonRequest::GenerateLinkCode => {
            // TODO(M8): use actual seed; for now return placeholder
            DaemonResponse::LinkCode("000000".into())
        }
        DaemonRequest::LinkDevice {
            code: _,
            device_name,
        } => {
            // TODO(M8): verify code, establish sync channel
            DaemonResponse::DeviceLinked {
                device_id: [0; 32],
                name: device_name,
            }
        }
        DaemonRequest::GetDevices => match aira_storage::devices::list_devices(storage) {
            Ok(devices) => {
                let resp: Vec<_> = devices
                    .iter()
                    .filter_map(|(id, bytes)| {
                        postcard::from_bytes::<aira_storage::DeviceInfo>(bytes)
                            .ok()
                            .map(|info| DeviceInfoResp {
                                device_id: *id,
                                name: info.name,
                                is_primary: info.is_primary,
                                priority: info.priority,
                                last_seen: info.last_seen,
                            })
                    })
                    .collect();
                DaemonResponse::Devices(resp)
            }
            Err(e) => DaemonResponse::Error(e.to_string()),
        },
        DaemonRequest::UnlinkDevice { device_id } => {
            match aira_storage::devices::remove_device(storage, &device_id) {
                Ok(()) => DaemonResponse::Ok,
                Err(e) => DaemonResponse::Error(e.to_string()),
            }
        }
    }
}

/// Convert storage `GroupInfo` to daemon response `GroupInfoResp`.
fn group_info_to_resp(group: &aira_storage::GroupInfo) -> GroupInfoResp {
    GroupInfoResp {
        id: group.id,
        name: group.name.clone(),
        members: group
            .members
            .iter()
            .map(|m| GroupMemberResp {
                pubkey: m.pubkey.clone(),
                role: match m.role {
                    aira_storage::GroupRole::Admin => "admin".into(),
                    aira_storage::GroupRole::Member => "member".into(),
                },
                joined_at: m.joined_at,
            })
            .collect(),
        created_by: group.created_by.clone(),
        created_at: group.created_at,
    }
}

/// Handle `CreateGroup` request.
fn handle_create_group(
    storage: &aira_storage::Storage,
    name: &str,
    member_pubkeys: &[Vec<u8>],
) -> DaemonResponse {
    if member_pubkeys.len() + 1 > aira_core::group::MAX_GROUP_MEMBERS {
        return DaemonResponse::Error(format!(
            "too many members (max {})",
            aira_core::group::MAX_GROUP_MEMBERS
        ));
    }

    let mut group_id = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut group_id);

    let now = now_secs();

    // Creator is Admin
    let mut members = vec![aira_storage::GroupMemberInfo {
        pubkey: vec![], // TODO: fill with our own pubkey when identity is wired
        role: aira_storage::GroupRole::Admin,
        joined_at: now,
    }];

    // Other members start as Member
    for pk in member_pubkeys {
        members.push(aira_storage::GroupMemberInfo {
            pubkey: pk.clone(),
            role: aira_storage::GroupRole::Member,
            joined_at: now,
        });
    }

    let group = aira_storage::GroupInfo {
        id: group_id,
        name: name.to_string(),
        members,
        created_by: vec![], // TODO: our pubkey
        created_at: now,
    };

    match aira_storage::groups::create_group(storage, &group) {
        Ok(()) => {
            // TODO: distribute GroupControl::CreateGroup + Sender Keys to members via 1-on-1
            DaemonResponse::GroupCreated { group_id }
        }
        Err(e) => DaemonResponse::Error(e.to_string()),
    }
}

/// Handle `SendGroupMessage` request.
fn handle_send_group_message(
    storage: &aira_storage::Storage,
    group_id: &[u8; 32],
    text: &str,
) -> DaemonResponse {
    // Verify group exists
    if aira_storage::groups::get_group(storage, group_id).is_err() {
        return DaemonResponse::Error("group not found".into());
    }

    let msg = aira_storage::StoredMessage {
        id: rand_id(),
        sender_is_self: true,
        payload_bytes: text.as_bytes().to_vec(),
        timestamp_micros: now_micros(),
        ttl_secs: None,
        read_at: None,
        expires_at: None,
    };

    match aira_storage::groups::store_group_message(storage, group_id, &msg) {
        Ok(()) => {
            // TODO: encrypt with SenderKey and fan-out to all members via 1-on-1
            DaemonResponse::Ok
        }
        Err(e) => DaemonResponse::Error(e.to_string()),
    }
}

/// Handle `GroupAddMember` request.
fn handle_group_add_member(
    storage: &aira_storage::Storage,
    group_id: &[u8; 32],
    member_pubkey: &[u8],
) -> DaemonResponse {
    let group = match aira_storage::groups::get_group(storage, group_id) {
        Ok(g) => g,
        Err(e) => return DaemonResponse::Error(e.to_string()),
    };

    if group.members.len() >= aira_core::group::MAX_GROUP_MEMBERS {
        return DaemonResponse::Error(format!(
            "group is full (max {} members)",
            aira_core::group::MAX_GROUP_MEMBERS
        ));
    }

    // TODO: verify caller is Admin (requires identity integration)

    let now = now_secs();
    let member = aira_storage::GroupMemberInfo {
        pubkey: member_pubkey.to_vec(),
        role: aira_storage::GroupRole::Member,
        joined_at: now,
    };

    match aira_storage::groups::add_member(storage, group_id, member) {
        Ok(()) => {
            // TODO: distribute Sender Keys to new member, notify group
            DaemonResponse::Ok
        }
        Err(e) => DaemonResponse::Error(e.to_string()),
    }
}

/// Handle `GroupRemoveMember` request.
fn handle_group_remove_member(
    storage: &aira_storage::Storage,
    group_id: &[u8; 32],
    member_pubkey: &[u8],
) -> DaemonResponse {
    // TODO: verify caller is Admin
    match aira_storage::groups::remove_member(storage, group_id, member_pubkey) {
        Ok(()) => {
            // TODO: distribute RemoveMember + trigger SenderKey rotation
            DaemonResponse::Ok
        }
        Err(e) => DaemonResponse::Error(e.to_string()),
    }
}

/// Handle `LeaveGroup` request.
fn handle_leave_group(storage: &aira_storage::Storage, group_id: &[u8; 32]) -> DaemonResponse {
    // TODO: send GroupControl::Leave to all members, remove our sender key
    match aira_storage::groups::remove_group(storage, group_id) {
        Ok(()) => DaemonResponse::Ok,
        Err(e) => DaemonResponse::Error(e.to_string()),
    }
}

/// Storage key for persisted transport mode.
const TRANSPORT_MODE_KEY: &str = "transport/mode";

/// Handle `SetTransportMode` request.
fn handle_set_transport_mode(storage: &aira_storage::Storage, mode_str: &str) -> DaemonResponse {
    // Validate the mode string parses correctly.
    if let Err(e) = mode_str.parse::<aira_net::transport::TransportMode>() {
        return DaemonResponse::Error(format!("invalid transport mode: {e}"));
    }

    // Persist to storage.
    match aira_storage::settings::set(storage, TRANSPORT_MODE_KEY, mode_str.as_bytes()) {
        Ok(()) => {
            tracing::info!("transport mode set to: {mode_str}");
            DaemonResponse::Ok
        }
        Err(e) => DaemonResponse::Error(format!("failed to save transport mode: {e}")),
    }
}

/// Handle `GetTransportMode` request.
fn handle_get_transport_mode(storage: &aira_storage::Storage) -> DaemonResponse {
    match aira_storage::settings::get(storage, TRANSPORT_MODE_KEY) {
        Ok(Some(bytes)) => {
            let mode_str = String::from_utf8_lossy(&bytes).to_string();
            DaemonResponse::TransportMode(mode_str)
        }
        Ok(None) => DaemonResponse::TransportMode("direct".into()),
        Err(e) => DaemonResponse::Error(format!("failed to read transport mode: {e}")),
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Handle a `SendFile` request: validate, import to blob store, track transfer.
fn handle_send_file(
    blob_store: &aira_net::blobs::BlobStore,
    transfer_mgr: &TransferManager,
    path: std::path::PathBuf,
) -> DaemonResponse {
    if !path.exists() {
        return DaemonResponse::Error(format!("file not found: {}", path.display()));
    }

    let metadata = match std::fs::metadata(&path) {
        Ok(m) => m,
        Err(e) => return DaemonResponse::Error(format!("cannot read file: {e}")),
    };
    let file_size = metadata.len();

    if file_size > aira_net::blobs::MAX_FILE_SIZE {
        return DaemonResponse::Error(format!(
            "file too large: {} bytes (max {} bytes)",
            file_size,
            aira_net::blobs::MAX_FILE_SIZE
        ));
    }

    let transfer_id = rand_id();
    let file_name = path.file_name().map_or_else(
        || "unnamed".to_string(),
        |n| n.to_string_lossy().to_string(),
    );

    let bs = blob_store.clone();
    let tm = transfer_mgr.clone();
    tokio::spawn(async move {
        let hash_result = if aira_net::blobs::BlobStore::is_inline(file_size) {
            match tokio::fs::read(&path).await {
                Ok(data) => {
                    let hash_bytes = blake3::hash(&data);
                    bs.import_bytes(data.as_slice())
                        .await
                        .map(|h| (h, file_size, *hash_bytes.as_bytes()))
                }
                Err(e) => Err(aira_net::NetError::BlobStore(format!("read file: {e}"))),
            }
        } else {
            bs.import_file(&path).await.map(|(h, s)| {
                let hash_bytes: [u8; 32] = h.into();
                (h, s, hash_bytes)
            })
        };

        match hash_result {
            Ok((_blob_hash, size, hash_bytes)) => {
                tm.start_send(transfer_id, file_name, size, hash_bytes)
                    .await;
                tm.update_progress(transfer_id, 0).await;
                // TODO(M5): send FileStart to peer via encrypted channel
                tm.update_progress(transfer_id, size).await;
                tm.complete(transfer_id, path).await;
            }
            Err(e) => {
                tm.start_send(transfer_id, file_name, file_size, [0u8; 32])
                    .await;
                tm.fail(transfer_id, e.to_string()).await;
            }
        }
    });

    DaemonResponse::Ok
}

/// Generate a random 16-byte message ID.
fn rand_id() -> [u8; 16] {
    use rand::RngCore;
    let mut id = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut id);
    id
}

/// Current time in microseconds since epoch.
#[allow(clippy::cast_possible_truncation)]
fn now_micros() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64
}
