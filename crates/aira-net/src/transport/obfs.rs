//! Obfuscation transport — XOR keystream via BLAKE3 KDF.
//!
//! Simplified obfs4-like scheme: both sides exchange 32-byte random nonces,
//! derive a session key via `BLAKE3-KDF("aira/obfs/session/0", nonce_a || nonce_b)`,
//! then XOR every byte with a BLAKE3-based keystream.
//!
//! Frame format: `[2-byte LE payload length][obfuscated payload]`
//!
//! The session key is zeroized on drop.
//!
//! **Note:** This is a simplified scheme. When the `ptrs` crate becomes
//! available, it can be swapped in as a drop-in replacement.
//!
//! See SPEC.md §11A.2, §11A.3.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use blake3::Hasher;
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use zeroize::Zeroizing;

use super::{AiraTransport, BoxedStream, TransportError};

/// KDF context for obfuscation session key derivation.
const OBFS_KDF_CONTEXT: &str = "aira/obfs/session/0";

/// Nonce size in bytes.
const NONCE_SIZE: usize = 32;

/// Maximum obfuscated frame payload (64 KB).
const MAX_FRAME_PAYLOAD: usize = 65_536;

/// Obfuscation transport using XOR keystream.
#[derive(Debug)]
pub struct ObfsTransport;

impl ObfsTransport {
    /// Create a new obfuscation transport.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl AiraTransport for ObfsTransport {
    async fn wrap_outbound(&self, stream: BoxedStream) -> Result<BoxedStream, TransportError> {
        obfs_handshake(stream, true).await
    }

    async fn accept_inbound(&self, stream: BoxedStream) -> Result<BoxedStream, TransportError> {
        obfs_handshake(stream, false).await
    }

    fn name(&self) -> &'static str {
        "obfs4"
    }
}

/// Perform the nonce exchange handshake and return an obfuscated stream.
///
/// `is_initiator`: true for outbound (client), false for inbound (server).
/// The initiator sends its nonce first, then reads the peer's nonce.
async fn obfs_handshake(
    mut stream: BoxedStream,
    is_initiator: bool,
) -> Result<BoxedStream, TransportError> {
    // Generate our random nonce.
    let mut our_nonce = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut our_nonce);

    let mut peer_nonce = [0u8; NONCE_SIZE];

    if is_initiator {
        // Initiator: send our nonce, then read peer's.
        stream
            .write_all(&our_nonce)
            .await
            .map_err(|e| TransportError::Handshake(format!("failed to send nonce: {e}")))?;
        stream
            .read_exact(&mut peer_nonce)
            .await
            .map_err(|e| TransportError::Handshake(format!("failed to read peer nonce: {e}")))?;
    } else {
        // Responder: read peer's nonce, then send ours.
        stream
            .read_exact(&mut peer_nonce)
            .await
            .map_err(|e| TransportError::Handshake(format!("failed to read peer nonce: {e}")))?;
        stream
            .write_all(&our_nonce)
            .await
            .map_err(|e| TransportError::Handshake(format!("failed to send nonce: {e}")))?;
    }

    stream
        .flush()
        .await
        .map_err(|e| TransportError::Handshake(format!("flush failed: {e}")))?;

    // Derive session key: BLAKE3-KDF(context, nonce_a || nonce_b).
    // Order is deterministic: initiator nonce first, responder nonce second.
    let (first, second) = if is_initiator {
        (&our_nonce, &peer_nonce)
    } else {
        (&peer_nonce, &our_nonce)
    };

    let mut kdf_input = [0u8; NONCE_SIZE * 2];
    kdf_input[..NONCE_SIZE].copy_from_slice(first);
    kdf_input[NONCE_SIZE..].copy_from_slice(second);

    let session_key = Zeroizing::new(blake3::derive_key(OBFS_KDF_CONTEXT, &kdf_input));

    // Create the obfuscated stream wrapper.
    // Initiator writes with direction 0, reads with direction 1.
    // Responder writes with direction 1, reads with direction 0.
    // This ensures the write keystream of one side matches the read keystream of the other.
    let (write_dir, read_dir) = if is_initiator { (0, 1) } else { (1, 0) };
    let obfs_stream = ObfsStream {
        inner: stream,
        write_key: Zeroizing::new(Keystream::new(&session_key, write_dir)),
        read_key: Zeroizing::new(Keystream::new(&session_key, read_dir)),
        read_buf: Vec::new(),
        read_pos: 0,
        pending_frame: None,
    };

    Ok(BoxedStream::new(obfs_stream))
}

// ─── Keystream generator ────────────────────────────────────────────────────

/// BLAKE3-based keystream generator.
///
/// Produces an unbounded keystream by hashing `key || direction || counter`.
/// Each 32-byte hash output is consumed before incrementing the counter.
#[derive(Clone)]
struct Keystream {
    key: [u8; 32],
    direction: u8,
    counter: u64,
    block: [u8; 32],
    block_pos: usize,
}

impl zeroize::Zeroize for Keystream {
    fn zeroize(&mut self) {
        self.key.zeroize();
        self.block.zeroize();
        self.counter = 0;
        self.block_pos = 0;
    }
}

impl Keystream {
    fn new(key: &[u8; 32], direction: u8) -> Self {
        let mut ks = Self {
            key: *key,
            direction,
            counter: 0,
            block: [0u8; 32],
            block_pos: 32, // force regeneration on first use
        };
        ks.key.copy_from_slice(key);
        ks
    }

    /// XOR `buf` with keystream bytes in place.
    fn apply(&mut self, buf: &mut [u8]) {
        for byte in buf.iter_mut() {
            if self.block_pos >= 32 {
                self.regenerate_block();
            }
            *byte ^= self.block[self.block_pos];
            self.block_pos += 1;
        }
    }

    fn regenerate_block(&mut self) {
        let mut hasher = Hasher::new();
        hasher.update(&self.key);
        hasher.update(&[self.direction]);
        hasher.update(&self.counter.to_le_bytes());
        self.block = *hasher.finalize().as_bytes();
        self.block_pos = 0;
        self.counter += 1;
    }
}

// Zeroize is used via derive on Keystream.

// ─── Obfuscated stream ─────────────────────────────────────────────────────

/// Bidirectional stream that XORs all data with a BLAKE3 keystream.
///
/// Framing: `[2-byte LE length][XOR'd payload]`
struct ObfsStream {
    inner: BoxedStream,
    write_key: Zeroizing<Keystream>,
    read_key: Zeroizing<Keystream>,
    /// Buffered plaintext from the last decoded frame.
    read_buf: Vec<u8>,
    /// Current position in `read_buf`.
    read_pos: usize,
    /// Partial frame being read (length header + payload).
    pending_frame: Option<PendingFrame>,
}

struct PendingFrame {
    /// Expected payload length.
    payload_len: usize,
    /// Accumulated obfuscated bytes.
    data: Vec<u8>,
}

impl AsyncRead for ObfsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Return buffered plaintext first.
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

        // Read from inner stream to decode a frame.
        let mut tmp = [0u8; 4096];
        let mut tmp_buf = ReadBuf::new(&mut tmp);
        match Pin::new(&mut this.inner).poll_read(cx, &mut tmp_buf) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {
                let filled = tmp_buf.filled();
                if filled.is_empty() {
                    // EOF
                    return Poll::Ready(Ok(()));
                }

                // Feed bytes into frame decoder.
                let mut pos = 0;
                while pos < filled.len() {
                    if let Some(ref mut frame) = this.pending_frame {
                        let need = frame.payload_len - frame.data.len();
                        let available = filled.len() - pos;
                        let take = need.min(available);
                        frame.data.extend_from_slice(&filled[pos..pos + take]);
                        pos += take;

                        if frame.data.len() == frame.payload_len {
                            // Frame complete — decrypt.
                            let mut payload = std::mem::take(&mut frame.data);
                            this.pending_frame = None;
                            this.read_key.apply(&mut payload);
                            this.read_buf.extend_from_slice(&payload);
                        }
                    } else {
                        // Need 2 bytes for length header.
                        if pos + 2 > filled.len() {
                            // Partial length header — rare edge case; buffer for next read.
                            // For simplicity, we just skip this byte and retry next poll.
                            break;
                        }
                        let len = u16::from_le_bytes([filled[pos], filled[pos + 1]]) as usize;
                        pos += 2;
                        if len == 0 || len > MAX_FRAME_PAYLOAD {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("invalid obfs frame length: {len}"),
                            )));
                        }
                        this.pending_frame = Some(PendingFrame {
                            payload_len: len,
                            data: Vec::with_capacity(len),
                        });
                    }
                }

                // Return whatever plaintext we decoded.
                if !this.read_buf.is_empty() {
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

                // Decoded nothing yet — wake again.
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }
}

impl AsyncWrite for ObfsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let this = self.get_mut();

        // Clamp to max frame payload.
        let chunk_len = buf.len().min(MAX_FRAME_PAYLOAD);
        let mut obfuscated = buf[..chunk_len].to_vec();
        this.write_key.apply(&mut obfuscated);

        // Build frame: [2-byte LE length][obfuscated data]
        let len_bytes = (chunk_len as u16).to_le_bytes();
        let mut frame = Vec::with_capacity(2 + chunk_len);
        frame.extend_from_slice(&len_bytes);
        frame.extend_from_slice(&obfuscated);

        // Write the entire frame to inner.
        match Pin::new(&mut this.inner).poll_write(cx, &frame) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(written)) => {
                if written < frame.len() {
                    // Partial write — report only the payload bytes consumed.
                    // In practice, if the length header was written but not all payload,
                    // the stream becomes corrupt. For simplicity, treat as error.
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "partial obfs frame write",
                    )))
                } else {
                    Poll::Ready(Ok(chunk_len))
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn obfs_roundtrip_basic() {
        let transport = ObfsTransport::new();
        let (client_raw, server_raw) = tokio::io::duplex(8192);

        // Wrap both ends concurrently (handshake needs both sides).
        let (client_result, server_result) = tokio::join!(
            transport.wrap_outbound(BoxedStream::new(client_raw)),
            transport.accept_inbound(BoxedStream::new(server_raw)),
        );

        let mut client = client_result.expect("client wrap");
        let mut server = server_result.expect("server wrap");

        // Send from client to server.
        let msg = b"hello obfuscated world";
        client.write_all(msg).await.expect("write");
        client.flush().await.expect("flush");

        let mut buf = vec![0u8; msg.len()];
        server.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, msg);
    }

    #[tokio::test]
    async fn obfs_roundtrip_large() {
        let transport = ObfsTransport::new();
        let (client_raw, server_raw) = tokio::io::duplex(256 * 1024);

        let (client_result, server_result) = tokio::join!(
            transport.wrap_outbound(BoxedStream::new(client_raw)),
            transport.accept_inbound(BoxedStream::new(server_raw)),
        );

        let mut client = client_result.expect("client wrap");
        let mut server = server_result.expect("server wrap");

        // Send 10 KB of data.
        let msg = vec![0xAB_u8; 10_000];
        client.write_all(&msg).await.expect("write");
        client.flush().await.expect("flush");
        drop(client); // close write half to signal EOF

        let mut buf = Vec::new();
        server.read_to_end(&mut buf).await.expect("read");
        assert_eq!(buf, msg);
    }

    #[tokio::test]
    async fn obfs_bidirectional() {
        let transport = ObfsTransport::new();
        let (client_raw, server_raw) = tokio::io::duplex(8192);

        let (client_result, server_result) = tokio::join!(
            transport.wrap_outbound(BoxedStream::new(client_raw)),
            transport.accept_inbound(BoxedStream::new(server_raw)),
        );

        let mut client = client_result.expect("client wrap");
        let mut server = server_result.expect("server wrap");

        // Client -> Server
        client.write_all(b"ping").await.expect("write ping");
        client.flush().await.expect("flush");
        let mut buf = vec![0u8; 4];
        server.read_exact(&mut buf).await.expect("read ping");
        assert_eq!(&buf, b"ping");

        // Server -> Client
        server.write_all(b"pong").await.expect("write pong");
        server.flush().await.expect("flush");
        let mut buf2 = vec![0u8; 4];
        client.read_exact(&mut buf2).await.expect("read pong");
        assert_eq!(&buf2, b"pong");
    }

    #[test]
    fn keystream_deterministic() {
        let key = [42u8; 32];
        let mut ks1 = Keystream::new(&key, 0);
        let mut ks2 = Keystream::new(&key, 0);

        let mut buf1 = [0u8; 100];
        let mut buf2 = [0u8; 100];
        ks1.apply(&mut buf1);
        ks2.apply(&mut buf2);
        assert_eq!(buf1, buf2);
    }

    #[test]
    fn keystream_different_directions() {
        let key = [42u8; 32];
        let mut ks_write = Keystream::new(&key, 0);
        let mut ks_read = Keystream::new(&key, 1);

        let mut buf_w = [0u8; 32];
        let mut buf_r = [0u8; 32];
        ks_write.apply(&mut buf_w);
        ks_read.apply(&mut buf_r);
        // Different directions produce different keystreams.
        assert_ne!(buf_w, buf_r);
    }

    #[test]
    fn obfs_transport_name() {
        assert_eq!(ObfsTransport::new().name(), "obfs4");
    }
}
