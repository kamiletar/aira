//! Blob store: iroh-blobs integration for file transfer.
//!
//! Wraps `iroh_blobs` with `MemStore` for content-addressed file transfer.
//! Files >= 1 MB use iroh-blobs (BLAKE3 verified streaming); files < 1 MB
//! are sent inline via the chat channel.
//!
//! See SPEC.md §6.2.

use std::path::Path;

use iroh_blobs::store::mem::MemStore;
use iroh_blobs::BlobsProtocol;
use tokio::io::AsyncReadExt;
use tracing::debug;

use crate::NetError;

/// Threshold for inline vs blob transfer (1 MB).
pub const INLINE_THRESHOLD: u64 = 1_048_576;

/// Maximum file size for transfer (4 GB).
pub const MAX_FILE_SIZE: u64 = 4 * 1024 * 1024 * 1024;

/// Wraps iroh-blobs `MemStore` + `BlobsProtocol` for file transfer.
///
/// The store is in-memory (transient) — blobs live only while the daemon runs.
/// This is appropriate for file transfer where blobs are consumed immediately.
#[derive(Clone)]
pub struct BlobStore {
    store: MemStore,
    blobs: BlobsProtocol,
}

impl BlobStore {
    /// Create a new blob store backed by in-memory storage.
    #[must_use]
    pub fn new() -> Self {
        let store = MemStore::new();
        let blobs = BlobsProtocol::new(&store, None);
        Self { store, blobs }
    }

    /// Import a file from disk into the blob store.
    ///
    /// Returns `(hash, size)` — the BLAKE3 hash and byte count.
    /// The blob is then available for peers to fetch via iroh-blobs protocol.
    ///
    /// # Errors
    ///
    /// Returns `NetError::FileNotFound` if the file doesn't exist.
    /// Returns `NetError::FileTooLarge` if the file exceeds `MAX_FILE_SIZE`.
    pub async fn import_file(&self, path: &Path) -> Result<(iroh_blobs::Hash, u64), NetError> {
        let metadata = tokio::fs::metadata(path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                NetError::FileNotFound(path.display().to_string())
            } else {
                NetError::BlobStore(format!("failed to read file metadata: {e}"))
            }
        })?;

        let size = metadata.len();
        if size > MAX_FILE_SIZE {
            return Err(NetError::FileTooLarge {
                size,
                max: MAX_FILE_SIZE,
            });
        }

        // Read file into memory and add to blob store
        let data = tokio::fs::read(path)
            .await
            .map_err(|e| NetError::BlobStore(format!("failed to read file: {e}")))?;

        let tag = self
            .store
            .add_bytes(data)
            .temp_tag()
            .await
            .map_err(|e| NetError::BlobStore(format!("failed to import blob: {e}")))?;

        let hash = tag.hash();
        debug!(%hash, size, "imported file into blob store");
        // Keep the tag alive so the blob stays in the store.
        // In a full implementation we'd track tags per transfer and drop them
        // when the transfer completes or is cancelled.
        std::mem::forget(tag);

        Ok((hash, size))
    }

    /// Import raw bytes into the blob store.
    ///
    /// Returns the BLAKE3 hash. Useful for inline data or testing.
    pub async fn import_bytes(&self, data: impl AsRef<[u8]>) -> Result<iroh_blobs::Hash, NetError> {
        let tag = self
            .store
            .add_slice(data)
            .temp_tag()
            .await
            .map_err(|e| NetError::BlobStore(format!("failed to import bytes: {e}")))?;

        let hash = tag.hash();
        std::mem::forget(tag);
        Ok(hash)
    }

    /// Read a blob's contents from the local store.
    ///
    /// Returns `None` if the blob is not present.
    pub async fn read_blob(&self, hash: iroh_blobs::Hash) -> Result<Option<Vec<u8>>, NetError> {
        let mut reader = self.store.reader(hash);
        let mut buf = Vec::new();
        match reader.read_to_end(&mut buf).await {
            Ok(_) => Ok(Some(buf)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(NetError::BlobStore(format!("failed to read blob: {e}"))),
        }
    }

    /// Get the `BlobsProtocol` for router registration.
    ///
    /// Register with `Router::builder().accept(iroh_blobs::ALPN, store.protocol())`.
    #[must_use]
    pub fn protocol(&self) -> BlobsProtocol {
        self.blobs.clone()
    }

    /// Get a reference to the underlying `MemStore`.
    #[must_use]
    pub fn store(&self) -> &MemStore {
        &self.store
    }

    /// Check if a file should be sent inline (< 1 MB) or via iroh-blobs.
    #[must_use]
    pub fn is_inline(size: u64) -> bool {
        size < INLINE_THRESHOLD
    }
}

impl Default for BlobStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn blob_import_bytes_roundtrip() {
        let store = BlobStore::new();

        let data = b"hello, iroh-blobs!";
        let hash = store.import_bytes(data.as_slice()).await.unwrap();

        let retrieved = store.read_blob(hash).await.unwrap().unwrap();
        assert_eq!(retrieved, data);
    }

    #[tokio::test]
    async fn blob_import_file_roundtrip() {
        let store = BlobStore::new();

        // Write a temp file
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test.bin");
        let data = vec![0xAB_u8; 2048];
        tokio::fs::write(&file_path, &data).await.unwrap();

        let (hash, size) = store.import_file(&file_path).await.unwrap();
        assert_eq!(size, 2048);

        let retrieved = store.read_blob(hash).await.unwrap().unwrap();
        assert_eq!(retrieved, data);
    }

    #[tokio::test]
    async fn blob_import_file_not_found() {
        let store = BlobStore::new();

        let result = store.import_file(Path::new("/nonexistent/file.bin")).await;
        assert!(matches!(result, Err(NetError::FileNotFound(_))));
    }

    #[test]
    fn inline_threshold() {
        assert!(BlobStore::is_inline(0));
        assert!(BlobStore::is_inline(1_048_575));
        assert!(!BlobStore::is_inline(1_048_576));
        assert!(!BlobStore::is_inline(10_000_000));
    }

    #[tokio::test]
    async fn blob_hash_is_deterministic() {
        let store1 = BlobStore::new();
        let store2 = BlobStore::new();

        let data = b"deterministic hash test data";
        let hash1 = store1.import_bytes(data.as_slice()).await.unwrap();
        let hash2 = store2.import_bytes(data.as_slice()).await.unwrap();

        assert_eq!(hash1, hash2, "same data must produce same BLAKE3 hash");
    }
}
