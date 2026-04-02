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
use tokio::sync::mpsc;
mod ipc;
mod types;

use types::{DaemonRequest, DaemonResponse};

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

    // Shutdown channel
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);

    // Build request handler
    let handler_storage = storage.clone();
    let shutdown_signal = shutdown_tx.clone();
    let handler: ipc::RequestHandler =
        Arc::new(move |request| handle_request(&handler_storage, &shutdown_signal, request));

    // Start IPC server
    let ipc_socket = ipc_path(&dir);
    let ipc_handle = tokio::spawn(ipc::start_ipc_server(ipc_socket, handler, shutdown_rx));

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
fn handle_request(
    storage: &aira_storage::Storage,
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
        DaemonRequest::Shutdown => {
            let _ = shutdown_tx.try_send(());
            DaemonResponse::Ok
        }
    }
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
