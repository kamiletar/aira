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

use aira_daemon::handler;
use aira_daemon::transfers::TransferManager;
use aira_daemon::types::DaemonEvent;

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

    // Derive storage key (before wrapping seed in Arc)
    let storage_key = master_seed.derive("aira/storage/0");

    // Wrap seed in Arc for sharing with request handler (§12.6 pseudonym derivation)
    let master_seed = Arc::new(master_seed);

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

    // Build request handler (delegates to shared handler module)
    let handler_storage = storage.clone();
    let handler_seed = master_seed.clone();
    let handler_blob_store = blob_store.clone();
    let handler_transfer_mgr = transfer_mgr.clone();
    let shutdown_signal = shutdown_tx.clone();
    let request_handler: ipc::RequestHandler = Arc::new(move |request| {
        handler::handle_request(
            &handler_storage,
            &handler_seed,
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
        request_handler,
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
