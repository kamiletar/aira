//! IPC client: connects to aira-daemon via Unix socket / Named pipe.
//!
//! Provides async request/response and event streaming over a single connection.
//! The daemon wraps all outbound frames in `ServerMessage` (response or event),
//! and the client's background reader task dispatches them accordingly.
//!
//! Shared between `aira-cli`, `aira-bot`, and any future IPC client.
//! See SPEC.md §8.

use std::path::PathBuf;

use crate::types::{DaemonEvent, DaemonRequest, DaemonResponse, ServerMessage};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, Mutex};

/// Maximum IPC message size (1 MB — matches daemon limit).
const MAX_IPC_MSG_SIZE: u32 = 1_048_576;

/// IPC client errors.
#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    /// Cannot connect to daemon (not running or wrong socket path).
    #[error("cannot connect to daemon: {0}")]
    Connect(String),
    /// I/O error on the IPC socket.
    #[error("IPC I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Postcard serialization/deserialization error.
    #[error("serialization error: {0}")]
    Serialize(String),
    /// The response channel was closed (reader task died).
    #[error("response channel closed")]
    ResponseChannelClosed,
    /// Received IPC frame exceeds maximum allowed size.
    #[error("IPC message too large: {0} bytes")]
    MessageTooLarge(u32),
}

// Platform-specific writer type (the read half is consumed by the background task).
#[cfg(unix)]
type WriteHalf = tokio::io::WriteHalf<tokio::net::UnixStream>;
#[cfg(windows)]
type WriteHalf = tokio::io::WriteHalf<tokio::net::windows::named_pipe::NamedPipeClient>;

/// A connected IPC client for communicating with the daemon.
///
/// Call [`DaemonClient::connect`] to establish the connection.
/// Use [`DaemonClient::request`] for request/response pairs and
/// receive daemon events via the channel returned by `connect`.
///
/// # Example
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use aira_daemon::client::DaemonClient;
/// use aira_daemon::types::DaemonRequest;
///
/// let (client, mut events) = DaemonClient::connect().await?;
/// let resp = client.request(&DaemonRequest::GetMyAddress).await?;
/// // Events arrive on `events` channel asynchronously.
/// # Ok(())
/// # }
/// ```
pub struct DaemonClient {
    /// Write half of the socket, protected by a mutex for concurrent access.
    writer: Mutex<WriteHalf>,
    /// Send a oneshot sender to the reader task so it can deliver the next response.
    response_tx: mpsc::Sender<oneshot::Sender<DaemonResponse>>,
}

impl DaemonClient {
    /// Connect to the daemon and return `(client, event_receiver)`.
    ///
    /// The `event_receiver` yields [`DaemonEvent`]s pushed asynchronously by
    /// the daemon (new messages, contact status changes, file transfer
    /// progress, etc.).
    ///
    /// # Errors
    ///
    /// Returns [`IpcError::Connect`] if the daemon socket is not available.
    // On Windows, named pipe open is synchronous but on Unix, connect is async.
    #[allow(clippy::unused_async)]
    pub async fn connect() -> Result<(Self, mpsc::Receiver<DaemonEvent>), IpcError> {
        let path = daemon_socket_path();

        #[cfg(unix)]
        let stream = tokio::net::UnixStream::connect(&path)
            .await
            .map_err(|e| IpcError::Connect(format!("{}: {e}", path.display())))?;

        #[cfg(windows)]
        let stream = {
            let pipe_name = path
                .to_str()
                .ok_or_else(|| IpcError::Connect("invalid pipe name".into()))?;
            tokio::net::windows::named_pipe::ClientOptions::new()
                .open(pipe_name)
                .map_err(|e| IpcError::Connect(format!("{pipe_name}: {e}")))?
        };

        let (reader, writer) = tokio::io::split(stream);

        // Channel for delivering responses to the requesting task
        let (response_tx, mut response_rx) = mpsc::channel::<oneshot::Sender<DaemonResponse>>(16);

        // Channel for delivering events to the application event loop
        let (event_tx, event_rx) = mpsc::channel::<DaemonEvent>(256);

        // Spawn background reader task
        tokio::spawn(async move {
            let mut reader = reader;
            loop {
                match read_server_message(&mut reader).await {
                    Ok(ServerMessage::Response(resp)) => {
                        // Deliver response to the waiting request
                        if let Some(tx) = response_rx.recv().await {
                            let _ = tx.send(resp);
                        }
                    }
                    Ok(ServerMessage::Event(event)) => {
                        if event_tx.send(event).await.is_err() {
                            // Event receiver dropped, shut down reader
                            break;
                        }
                    }
                    Err(_) => {
                        // Connection lost
                        break;
                    }
                }
            }
        });

        let client = Self {
            writer: Mutex::new(writer),
            response_tx,
        };

        Ok((client, event_rx))
    }

    /// Send a request to the daemon and wait for the response.
    ///
    /// # Errors
    ///
    /// Returns [`IpcError::Io`] on connection failure,
    /// [`IpcError::Serialize`] if the request cannot be serialized, or
    /// [`IpcError::ResponseChannelClosed`] if the reader task has exited.
    pub async fn request(&self, req: &DaemonRequest) -> Result<DaemonResponse, IpcError> {
        // Register a oneshot channel to receive the response
        let (tx, rx) = oneshot::channel();
        self.response_tx
            .send(tx)
            .await
            .map_err(|_| IpcError::ResponseChannelClosed)?;

        // Write the request
        let bytes = postcard::to_allocvec(req).map_err(|e| IpcError::Serialize(e.to_string()))?;
        let len = u32::try_from(bytes.len()).map_err(|_| IpcError::MessageTooLarge(u32::MAX))?;

        let mut writer = self.writer.lock().await;
        writer.write_u32_le(len).await?;
        writer.write_all(&bytes).await?;
        writer.flush().await?;
        drop(writer);

        // Wait for the response
        rx.await.map_err(|_| IpcError::ResponseChannelClosed)
    }
}

/// Read a length-prefixed `ServerMessage` from the daemon.
async fn read_server_message<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<ServerMessage, IpcError> {
    let len = reader.read_u32_le().await?;
    if len > MAX_IPC_MSG_SIZE {
        return Err(IpcError::MessageTooLarge(len));
    }

    let mut buf = vec![0u8; len as usize];
    reader.read_exact(&mut buf).await?;

    postcard::from_bytes(&buf).map_err(|e| IpcError::Serialize(e.to_string()))
}

/// Determine the daemon socket path for the current platform.
fn daemon_socket_path() -> PathBuf {
    #[cfg(unix)]
    {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        home.join(".aira").join("daemon.sock")
    }

    #[cfg(windows)]
    {
        PathBuf::from(r"\\.\pipe\aira-daemon")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_socket_path_is_set() {
        let path = daemon_socket_path();
        let path_str = path.to_string_lossy();
        #[cfg(unix)]
        assert!(path_str.contains("daemon.sock"));
        #[cfg(windows)]
        assert!(path_str.contains("aira-daemon"));
    }

    #[tokio::test]
    async fn read_server_message_roundtrip() {
        let msg = ServerMessage::Response(DaemonResponse::Ok);
        let bytes = postcard::to_allocvec(&msg).expect("serialize");

        // Build a frame: len (4 bytes LE) + payload
        let mut frame = Vec::new();
        frame.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        frame.extend_from_slice(&bytes);

        let mut cursor = std::io::Cursor::new(frame);
        let decoded = read_server_message(&mut cursor).await.expect("read");
        assert!(matches!(
            decoded,
            ServerMessage::Response(DaemonResponse::Ok)
        ));
    }

    #[tokio::test]
    async fn read_server_message_rejects_too_large() {
        // Frame claiming to be 2 MB (exceeds MAX_IPC_MSG_SIZE)
        let len: u32 = 2_000_000;
        let frame = len.to_le_bytes();
        let mut cursor = std::io::Cursor::new(frame.to_vec());
        let result = read_server_message(&mut cursor).await;
        assert!(matches!(result, Err(IpcError::MessageTooLarge(2_000_000))));
    }
}
