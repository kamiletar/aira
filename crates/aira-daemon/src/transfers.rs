//! File transfer state management.
//!
//! Tracks active file transfers and emits progress events via broadcast channel.
//! See SPEC.md §6.2 and §8.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::{broadcast, RwLock};

use crate::types::DaemonEvent;

/// Direction of a file transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// We are sending a file to a peer.
    Sending,
    /// We are receiving a file from a peer (used when peer sends us a file).
    #[allow(dead_code)] // Will be used when receive path is wired (M5)
    Receiving,
}

/// Current status of a transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferStatus {
    /// Transfer is in progress.
    Active,
    /// Transfer completed successfully.
    Complete,
    /// Transfer failed.
    Failed,
}

/// State of a single file transfer.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields read in tests; more fields used when receive path is wired (M5)
pub struct TransferState {
    /// Transfer direction.
    pub direction: Direction,
    /// Original file name.
    pub file_name: String,
    /// Total file size in bytes.
    pub total_bytes: u64,
    /// Bytes transferred so far.
    pub transferred_bytes: u64,
    /// BLAKE3 hash of the file.
    pub hash: [u8; 32],
    /// Current status.
    pub status: TransferStatus,
}

/// Manages active file transfers and broadcasts progress events.
///
/// Thread-safe via `RwLock` — multiple readers, exclusive writer.
#[derive(Clone)]
pub struct TransferManager {
    transfers: Arc<RwLock<HashMap<[u8; 16], TransferState>>>,
    event_tx: broadcast::Sender<DaemonEvent>,
}

impl TransferManager {
    /// Create a new transfer manager with the given event broadcast channel.
    #[must_use]
    pub fn new(event_tx: broadcast::Sender<DaemonEvent>) -> Self {
        Self {
            transfers: Arc::new(RwLock::new(HashMap::new())),
            event_tx,
        }
    }

    /// Register a new outgoing file transfer.
    pub async fn start_send(
        &self,
        id: [u8; 16],
        file_name: String,
        total_bytes: u64,
        hash: [u8; 32],
    ) {
        let state = TransferState {
            direction: Direction::Sending,
            file_name,
            total_bytes,
            transferred_bytes: 0,
            hash,
            status: TransferStatus::Active,
        };
        self.transfers.write().await.insert(id, state);
    }

    /// Register a new incoming file transfer.
    #[allow(dead_code)] // Will be used when receive path is wired (M5)
    pub async fn start_receive(
        &self,
        id: [u8; 16],
        file_name: String,
        total_bytes: u64,
        hash: [u8; 32],
    ) {
        let state = TransferState {
            direction: Direction::Receiving,
            file_name,
            total_bytes,
            transferred_bytes: 0,
            hash,
            status: TransferStatus::Active,
        };
        self.transfers.write().await.insert(id, state);
    }

    /// Update transfer progress and emit a `FileProgress` event.
    ///
    /// Returns `false` if the transfer ID is unknown.
    pub async fn update_progress(&self, id: [u8; 16], bytes: u64) -> bool {
        let total = {
            let mut transfers = self.transfers.write().await;
            let Some(state) = transfers.get_mut(&id) else {
                return false;
            };
            state.transferred_bytes = bytes;
            state.total_bytes
        };

        // Best-effort event broadcast (ignore if no receivers)
        let _ = self.event_tx.send(DaemonEvent::FileProgress {
            id,
            bytes_sent: bytes,
            total,
        });
        true
    }

    /// Mark a transfer as complete and emit a `FileComplete` event.
    ///
    /// Returns `false` if the transfer ID is unknown.
    pub async fn complete(&self, id: [u8; 16], path: PathBuf) -> bool {
        let mut transfers = self.transfers.write().await;
        let Some(state) = transfers.get_mut(&id) else {
            return false;
        };
        state.status = TransferStatus::Complete;
        state.transferred_bytes = state.total_bytes;

        let _ = self.event_tx.send(DaemonEvent::FileComplete { id, path });
        true
    }

    /// Mark a transfer as failed and emit a `FileError` event.
    ///
    /// Returns `false` if the transfer ID is unknown.
    pub async fn fail(&self, id: [u8; 16], error: String) -> bool {
        let mut transfers = self.transfers.write().await;
        let Some(state) = transfers.get_mut(&id) else {
            return false;
        };
        state.status = TransferStatus::Failed;

        let _ = self.event_tx.send(DaemonEvent::FileError { id, error });
        true
    }

    /// Get the current state of a transfer.
    #[allow(dead_code)] // Used in tests; will be used by CLI status queries (M5)
    pub async fn get(&self, id: &[u8; 16]) -> Option<TransferState> {
        self.transfers.read().await.get(id).cloned()
    }

    /// Get the number of active transfers.
    #[allow(dead_code)] // Used in tests; will be used by CLI status queries (M5)
    pub async fn active_count(&self) -> usize {
        self.transfers
            .read()
            .await
            .values()
            .filter(|s| s.status == TransferStatus::Active)
            .count()
    }

    /// Remove completed/failed transfers.
    /// Returns the number of removed entries.
    #[allow(dead_code)] // Will be used by periodic GC in daemon (M5)
    pub async fn cleanup(&self) -> usize {
        let mut transfers = self.transfers.write().await;
        let before = transfers.len();
        transfers.retain(|_, s| s.status == TransferStatus::Active);
        before - transfers.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn transfer_lifecycle_send() {
        let (tx, mut rx) = broadcast::channel(16);
        let mgr = TransferManager::new(tx);

        let id = [0x42; 16];
        let hash = [0xAA; 32];

        // Start transfer
        mgr.start_send(id, "test.bin".into(), 1000, hash).await;
        assert_eq!(mgr.active_count().await, 1);

        let state = mgr.get(&id).await.unwrap();
        assert_eq!(state.direction, Direction::Sending);
        assert_eq!(state.transferred_bytes, 0);
        assert_eq!(state.total_bytes, 1000);

        // Update progress
        assert!(mgr.update_progress(id, 500).await);
        let event = rx.recv().await.unwrap();
        match event {
            DaemonEvent::FileProgress {
                id: eid,
                bytes_sent,
                total,
            } => {
                assert_eq!(eid, id);
                assert_eq!(bytes_sent, 500);
                assert_eq!(total, 1000);
            }
            _ => panic!("expected FileProgress"),
        }

        // Complete
        assert!(mgr.complete(id, PathBuf::from("/tmp/test.bin")).await);
        let event = rx.recv().await.unwrap();
        assert!(matches!(event, DaemonEvent::FileComplete { .. }));

        let state = mgr.get(&id).await.unwrap();
        assert_eq!(state.status, TransferStatus::Complete);
        assert_eq!(state.transferred_bytes, 1000);
    }

    #[tokio::test]
    async fn transfer_lifecycle_fail() {
        let (tx, mut rx) = broadcast::channel(16);
        let mgr = TransferManager::new(tx);

        let id = [0x01; 16];
        mgr.start_receive(id, "photo.jpg".into(), 5000, [0xBB; 32])
            .await;

        mgr.update_progress(id, 2000).await;
        let _ = rx.recv().await.unwrap(); // consume progress event

        assert!(mgr.fail(id, "connection lost".into()).await);
        let event = rx.recv().await.unwrap();
        match event {
            DaemonEvent::FileError { id: eid, error } => {
                assert_eq!(eid, id);
                assert_eq!(error, "connection lost");
            }
            _ => panic!("expected FileError"),
        }
    }

    #[tokio::test]
    async fn unknown_transfer_returns_false() {
        let (tx, _rx) = broadcast::channel(16);
        let mgr = TransferManager::new(tx);

        assert!(!mgr.update_progress([0xFF; 16], 100).await);
        assert!(!mgr.complete([0xFF; 16], PathBuf::from("/tmp")).await);
        assert!(!mgr.fail([0xFF; 16], "error".into()).await);
    }

    #[tokio::test]
    async fn cleanup_removes_finished() {
        let (tx, _rx) = broadcast::channel(16);
        let mgr = TransferManager::new(tx);

        mgr.start_send([1; 16], "a.bin".into(), 100, [0; 32]).await;
        mgr.start_send([2; 16], "b.bin".into(), 200, [0; 32]).await;
        mgr.start_send([3; 16], "c.bin".into(), 300, [0; 32]).await;

        mgr.complete([1; 16], PathBuf::from("/tmp/a")).await;
        mgr.fail([2; 16], "err".into()).await;

        let removed = mgr.cleanup().await;
        assert_eq!(removed, 2);
        assert_eq!(mgr.active_count().await, 1);
        assert!(mgr.get(&[3; 16]).await.is_some());
    }
}
