//! CDN Relay transport — HTTPS tunneling via Cloudflare Worker or similar.
//!
//! Encrypted payloads are POSTed to a configurable CDN endpoint URL.
//! Incoming data is retrieved via long-poll GET requests.
//!
//! This transport makes Aira traffic appear as normal HTTPS web traffic
//! to DPI systems, since all data flows through a legitimate CDN.
//!
//! See SPEC.md §11A.2.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

use super::{AiraTransport, BoxedStream, TransportError};

/// Default poll interval for incoming data (milliseconds).
const DEFAULT_POLL_INTERVAL_MS: u64 = 500;

/// CDN relay transport — HTTPS tunneling.
#[derive(Debug)]
pub struct CdnRelayTransport {
    endpoint: String,
}

impl CdnRelayTransport {
    /// Create a new CDN relay transport with the given endpoint URL.
    #[must_use]
    pub fn new(endpoint: String) -> Self {
        Self { endpoint }
    }
}

#[async_trait::async_trait]
impl AiraTransport for CdnRelayTransport {
    async fn wrap_outbound(&self, _stream: BoxedStream) -> Result<BoxedStream, TransportError> {
        // Create channels for bidirectional communication.
        let (write_tx, write_rx) = mpsc::channel::<Vec<u8>>(64);
        let (read_tx, read_rx) = mpsc::channel::<Vec<u8>>(64);

        let endpoint = self.endpoint.clone();

        // Spawn background task for HTTP POST (outbound) and GET (inbound).
        tokio::spawn(cdn_relay_task(endpoint, write_rx, read_tx));

        Ok(BoxedStream::new(CdnStream {
            write_tx,
            read_rx,
            read_buf: Vec::new(),
            read_pos: 0,
        }))
    }

    async fn accept_inbound(&self, _stream: BoxedStream) -> Result<BoxedStream, TransportError> {
        // CDN transport is symmetric — both sides connect to the CDN endpoint.
        // The underlying QUIC stream is not used directly; instead, both sides
        // tunnel through the CDN.
        let (write_tx, write_rx) = mpsc::channel::<Vec<u8>>(64);
        let (read_tx, read_rx) = mpsc::channel::<Vec<u8>>(64);

        let endpoint = self.endpoint.clone();
        tokio::spawn(cdn_relay_task(endpoint, write_rx, read_tx));

        Ok(BoxedStream::new(CdnStream {
            write_tx,
            read_rx,
            read_buf: Vec::new(),
            read_pos: 0,
        }))
    }

    fn name(&self) -> &'static str {
        "cdn"
    }
}

/// Background task that bridges channel I/O to HTTP requests.
///
/// - Reads from `write_rx` and POSTs each chunk to `{endpoint}/send`.
/// - Long-polls `{endpoint}/recv` and forwards data to `read_tx`.
async fn cdn_relay_task(
    endpoint: String,
    mut write_rx: mpsc::Receiver<Vec<u8>>,
    read_tx: mpsc::Sender<Vec<u8>>,
) {
    let client = match reqwest::Client::builder()
        .danger_accept_invalid_certs(false)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("CDN relay: failed to create HTTP client: {e}");
            return;
        }
    };

    let send_url = format!("{endpoint}/send");
    let recv_url = format!("{endpoint}/recv");

    // Spawn sender task.
    let client_send = client.clone();
    let send_url_clone = send_url.clone();
    let sender = tokio::spawn(async move {
        while let Some(data) = write_rx.recv().await {
            if let Err(e) = client_send.post(&send_url_clone).body(data).send().await {
                tracing::warn!("CDN relay POST failed: {e}");
            }
        }
    });

    // Receiver loop: long-poll for incoming data.
    let receiver = tokio::spawn(async move {
        loop {
            match client.get(&recv_url).send().await {
                Ok(resp) => {
                    if let Ok(bytes) = resp.bytes().await {
                        if !bytes.is_empty() {
                            if read_tx.send(bytes.to_vec()).await.is_err() {
                                break; // channel closed
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!("CDN relay GET failed: {e}");
                }
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(DEFAULT_POLL_INTERVAL_MS)).await;
        }
    });

    // Wait for either side to finish.
    tokio::select! {
        _ = sender => {}
        _ = receiver => {}
    }
}

/// Bidirectional stream backed by mpsc channels to a CDN relay task.
struct CdnStream {
    write_tx: mpsc::Sender<Vec<u8>>,
    read_rx: mpsc::Receiver<Vec<u8>>,
    read_buf: Vec<u8>,
    read_pos: usize,
}

impl AsyncRead for CdnStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Return buffered data first.
        if this.read_pos < this.read_buf.len() {
            let remaining = &this.read_buf[this.read_pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            this.read_pos += n;
            if this.read_pos >= this.read_buf.len() {
                this.read_buf.clear();
                this.read_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        // Try to receive from channel.
        match this.read_rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let n = data.len().min(buf.remaining());
                buf.put_slice(&data[..n]);
                if n < data.len() {
                    this.read_buf = data;
                    this.read_pos = n;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())), // channel closed = EOF
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for CdnStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let this = self.get_mut();
        match this.write_tx.try_send(buf.to_vec()) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(mpsc::error::TrySendError::Full(_)) => {
                // Channel full — register waker and return pending.
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "CDN relay channel closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cdn_transport_name() {
        let t = CdnRelayTransport::new("https://example.com".into());
        assert_eq!(t.name(), "cdn");
    }

    #[tokio::test]
    async fn cdn_stream_channel_roundtrip() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Test the CdnStream directly (without HTTP, just channels).
        let (write_tx, mut write_rx) = mpsc::channel::<Vec<u8>>(64);
        let (read_tx, read_rx) = mpsc::channel::<Vec<u8>>(64);

        let mut stream = CdnStream {
            write_tx,
            read_rx,
            read_buf: Vec::new(),
            read_pos: 0,
        };

        // Write some data.
        let data = b"cdn test data";
        stream.write_all(data).await.expect("write");

        // Verify it was sent to the channel.
        let received = write_rx.recv().await.expect("channel recv");
        assert_eq!(received, data);

        // Simulate incoming data from the "CDN".
        read_tx.send(b"response data".to_vec()).await.expect("send");

        let mut buf = vec![0u8; 13];
        stream.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, b"response data");
    }
}
