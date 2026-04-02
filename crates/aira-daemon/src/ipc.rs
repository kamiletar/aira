//! IPC server: Unix socket (Linux/macOS) or Named pipe (Windows).
//!
//! Handles `DaemonRequest` / `DaemonResponse` serialized with postcard.
//! Framing: 4-byte LE length prefix + postcard payload.
//! See SPEC.md §8.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use aira_daemon::types::{DaemonEvent, DaemonRequest, DaemonResponse, ServerMessage};

/// Maximum IPC message size (1 MB — well above any expected request).
const MAX_IPC_MSG_SIZE: u32 = 1_048_576;

/// Read a length-prefixed postcard message from an async reader.
async fn read_message<R: AsyncReadExt + Unpin>(reader: &mut R) -> anyhow::Result<DaemonRequest> {
    let len = reader.read_u32_le().await?;
    if len > MAX_IPC_MSG_SIZE {
        anyhow::bail!("IPC message too large: {len} bytes");
    }

    let mut buf = vec![0u8; len as usize];
    reader.read_exact(&mut buf).await?;

    let req: DaemonRequest =
        postcard::from_bytes(&buf).map_err(|e| anyhow::anyhow!("deserialize: {e}"))?;
    Ok(req)
}

/// Write a length-prefixed `ServerMessage` to an async writer.
async fn write_server_message<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    msg: &ServerMessage,
) -> anyhow::Result<()> {
    let bytes = postcard::to_allocvec(msg)?;
    let len = u32::try_from(bytes.len()).map_err(|_| anyhow::anyhow!("message too large"))?;
    writer.write_u32_le(len).await?;
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

/// Write a response wrapped in `ServerMessage`.
async fn write_response<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    response: &DaemonResponse,
) -> anyhow::Result<()> {
    write_server_message(writer, &ServerMessage::Response(response.clone())).await
}

/// Write an event wrapped in `ServerMessage`.
async fn write_event<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    event: &DaemonEvent,
) -> anyhow::Result<()> {
    write_server_message(writer, &ServerMessage::Event(event.clone())).await
}

/// Handler function type: processes a request and returns a response.
pub type RequestHandler = Arc<dyn Fn(DaemonRequest) -> DaemonResponse + Send + Sync + 'static>;

// ─── Unix socket server ─────────────────────────────────────────────────────

#[cfg(unix)]
pub async fn start_ipc_server(
    socket_path: std::path::PathBuf,
    handler: RequestHandler,
    event_tx: tokio::sync::broadcast::Sender<DaemonEvent>,
    mut shutdown: mpsc::Receiver<()>,
) -> anyhow::Result<()> {
    use tokio::net::UnixListener;

    // Remove stale socket file if it exists
    let _ = std::fs::remove_file(&socket_path);

    // Ensure parent directory exists
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let listener = UnixListener::bind(&socket_path)?;
    tracing::info!("IPC server listening on {}", socket_path.display());

    loop {
        tokio::select! {
            accept = listener.accept() => {
                match accept {
                    Ok((stream, _addr)) => {
                        let handler = handler.clone();
                        let event_rx = event_tx.subscribe();
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(stream, handler, event_rx).await {
                                tracing::warn!("IPC client error: {e}");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::error!("IPC accept error: {e}");
                    }
                }
            }
            _ = shutdown.recv() => {
                tracing::info!("IPC server shutting down");
                break;
            }
        }
    }

    // Cleanup socket file
    let _ = std::fs::remove_file(&socket_path);
    Ok(())
}

#[cfg(unix)]
async fn handle_connection(
    stream: tokio::net::UnixStream,
    handler: RequestHandler,
    mut event_rx: tokio::sync::broadcast::Receiver<DaemonEvent>,
) -> anyhow::Result<()> {
    let (reader, writer) = tokio::io::split(stream);
    let reader = Arc::new(tokio::sync::Mutex::new(reader));
    let writer = Arc::new(tokio::sync::Mutex::new(writer));

    // Spawn event forwarder
    let event_writer = writer.clone();
    let event_task = tokio::spawn(async move {
        while let Ok(event) = event_rx.recv().await {
            let mut w = event_writer.lock().await;
            if write_event(&mut *w, &event).await.is_err() {
                break;
            }
        }
    });

    // Request/response loop
    loop {
        let mut r = reader.lock().await;
        match read_message(&mut *r).await {
            Ok(request) => {
                drop(r); // release reader lock before writing
                let is_shutdown = matches!(request, DaemonRequest::Shutdown);
                let response = handler(request);
                let mut w = writer.lock().await;
                write_response(&mut *w, &response).await?;
                if is_shutdown {
                    break;
                }
            }
            Err(e) => {
                tracing::debug!("IPC connection ended: {e}");
                break;
            }
        }
    }

    event_task.abort();
    Ok(())
}

// ─── Windows named pipe server ──────────────────────────────────────────────

#[cfg(windows)]
pub async fn start_ipc_server(
    pipe_name: std::path::PathBuf,
    handler: RequestHandler,
    event_tx: tokio::sync::broadcast::Sender<DaemonEvent>,
    mut shutdown: mpsc::Receiver<()>,
) -> anyhow::Result<()> {
    use tokio::net::windows::named_pipe::ServerOptions;

    let pipe_name_str = pipe_name
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("invalid pipe name"))?
        .to_string();

    tracing::info!("IPC server listening on {pipe_name_str}");

    loop {
        let server = ServerOptions::new()
            .first_pipe_instance(false)
            .create(&pipe_name_str)?;

        tokio::select! {
            result = server.connect() => {
                match result {
                    Ok(()) => {
                        let handler = handler.clone();
                        let event_rx = event_tx.subscribe();
                        tokio::spawn(async move {
                            if let Err(e) = handle_pipe_connection(server, handler, event_rx).await {
                                tracing::warn!("IPC pipe client error: {e}");
                            }
                        });
                    }
                    Err(e) => {
                        tracing::error!("IPC pipe connect error: {e}");
                    }
                }
            }
            _ = shutdown.recv() => {
                tracing::info!("IPC server shutting down");
                break;
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
async fn handle_pipe_connection(
    pipe: tokio::net::windows::named_pipe::NamedPipeServer,
    handler: RequestHandler,
    mut event_rx: tokio::sync::broadcast::Receiver<DaemonEvent>,
) -> anyhow::Result<()> {
    let (reader, writer) = tokio::io::split(pipe);
    let reader = Arc::new(tokio::sync::Mutex::new(reader));
    let writer = Arc::new(tokio::sync::Mutex::new(writer));

    // Spawn event forwarder
    let event_writer = writer.clone();
    let event_task = tokio::spawn(async move {
        while let Ok(event) = event_rx.recv().await {
            let mut w = event_writer.lock().await;
            if write_event(&mut *w, &event).await.is_err() {
                break;
            }
        }
    });

    // Request/response loop
    loop {
        let mut r = reader.lock().await;
        match read_message(&mut *r).await {
            Ok(request) => {
                drop(r);
                let is_shutdown = matches!(request, DaemonRequest::Shutdown);
                let response = handler(request);
                let mut w = writer.lock().await;
                write_response(&mut *w, &response).await?;
                if is_shutdown {
                    break;
                }
            }
            Err(e) => {
                tracing::debug!("IPC pipe connection ended: {e}");
                break;
            }
        }
    }

    event_task.abort();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_serialization_fits_in_frame() {
        let req = DaemonRequest::SendMessage {
            to: vec![0u8; 2048], // large pubkey
            text: "a".repeat(10_000),
        };
        let bytes = postcard::to_allocvec(&req).expect("serialize");
        assert!(
            (bytes.len() as u32) < MAX_IPC_MSG_SIZE,
            "request should fit in IPC frame"
        );
    }

    #[tokio::test]
    async fn framing_roundtrip() {
        let mut buf = Vec::new();
        let response = DaemonResponse::Ok;
        write_response(&mut buf, &response).await.expect("write");

        let mut cursor = std::io::Cursor::new(buf);
        let mut tokio_cursor = tokio::io::BufReader::new(&mut cursor);
        // Read the length prefix
        let len = tokio::io::AsyncReadExt::read_u32_le(&mut tokio_cursor)
            .await
            .expect("read len");

        let mut payload = vec![0u8; len as usize];
        tokio::io::AsyncReadExt::read_exact(&mut tokio_cursor, &mut payload)
            .await
            .expect("read payload");

        // Now wrapped in ServerMessage
        let decoded: ServerMessage = postcard::from_bytes(&payload).expect("deserialize");
        assert!(matches!(
            decoded,
            ServerMessage::Response(DaemonResponse::Ok)
        ));
    }

    #[tokio::test]
    async fn event_framing_roundtrip() {
        let mut buf = Vec::new();
        let event = DaemonEvent::ContactOnline(vec![0xBB; 32]);
        write_event(&mut buf, &event).await.expect("write");

        let mut cursor = std::io::Cursor::new(buf);
        let mut tokio_cursor = tokio::io::BufReader::new(&mut cursor);
        let len = tokio::io::AsyncReadExt::read_u32_le(&mut tokio_cursor)
            .await
            .expect("read len");

        let mut payload = vec![0u8; len as usize];
        tokio::io::AsyncReadExt::read_exact(&mut tokio_cursor, &mut payload)
            .await
            .expect("read payload");

        let decoded: ServerMessage = postcard::from_bytes(&payload).expect("deserialize");
        match decoded {
            ServerMessage::Event(DaemonEvent::ContactOnline(pk)) => {
                assert_eq!(pk, vec![0xBB; 32]);
            }
            _ => panic!("expected ServerMessage::Event(ContactOnline)"),
        }
    }
}
