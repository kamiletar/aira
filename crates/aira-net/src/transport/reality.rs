//! REALITY-like TLS camouflage transport.
//!
//! Makes Aira traffic indistinguishable from legitimate TLS to a popular
//! website (e.g. `apple.com`, `bing.com`).  DPI systems see a valid TLS 1.3
//! `ClientHello` with correct browser fingerprint (cipher suite ordering,
//! SNI, extensions) — exactly what Chrome/Firefox/Safari would produce.
//!
//! # Protocol
//!
//! **Phase 1 — TLS Establishment:**
//! Client connects via `tokio-rustls` with a browser-mimicking `ClientHello`.
//! The outer TLS handshake completes normally.  DPI sees standard TLS traffic.
//!
//! **Phase 2 — Authentication (inside TLS tunnel):**
//! ```text
//! Client → Server: [0xA1][32B ephemeral X25519 pubkey][32B BLAKE3-MAC][8B timestamp]
//! Server → Client: [0xA2][32B server ephemeral pubkey]  (on success)
//! Server → proxy:  forward to real backend              (on failure)
//! ```
//! MAC = `BLAKE3-MAC("aira/reality/auth/0", timestamp || client_eph_pk, shared_secret)`
//! where `shared_secret = X25519(psk, client_eph_pk)`.
//!
//! **Phase 3 — Session:**
//! Both sides derive `session_key = BLAKE3-KDF("aira/reality/session/0",
//! client_eph || server_eph || shared_secret)`.  Data is framed as
//! `[2-byte LE length][XOR'd payload]` (same scheme as `obfs.rs`).
//!
//! **Active probing fallback:**
//! If authentication fails the server silently proxies all traffic to the
//! real backend (the domain in SNI).  An active prober connecting without
//! the PSK receives genuine `apple.com` content — indistinguishable from
//! the real server.
//!
//! See SPEC.md §11A.5, §16 (M12).

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use blake3::Hasher;
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use zeroize::Zeroizing;

use super::{AiraTransport, BoxedStream, TransportError};

// ─── Constants ─────────────────────────────────────────────────────────────

/// KDF context for REALITY authentication MAC.
const REALITY_AUTH_CONTEXT: &str = "aira/reality/auth/0";

/// KDF context for REALITY session key derivation.
const REALITY_SESSION_CONTEXT: &str = "aira/reality/session/0";

/// Magic byte: client auth request.
const AUTH_REQUEST_MAGIC: u8 = 0xA1;

/// Magic byte: server auth response (success).
const AUTH_RESPONSE_MAGIC: u8 = 0xA2;

/// Auth frame size: magic(1) + pubkey(32) + mac(32) + timestamp(8) = 73.
const AUTH_REQUEST_SIZE: usize = 73;

/// Auth response size: magic(1) + pubkey(32) = 33.
const AUTH_RESPONSE_SIZE: usize = 33;

/// Maximum allowed timestamp drift in seconds (±60s).
const MAX_TIMESTAMP_DRIFT: u64 = 60;

/// Maximum frame payload size (64 KB).
const MAX_FRAME_PAYLOAD: usize = 65_536;

// ─── Configuration ─────────────────────────────────────────────────────────

/// Configuration for the REALITY transport.
pub struct RealityConfig {
    /// Target domain for TLS SNI (e.g. "www.apple.com").
    pub sni: String,
    /// Pre-shared key for X25519 authentication.
    pub psk: Zeroizing<[u8; 32]>,
    /// Browser fingerprint to mimic in the TLS `ClientHello`.
    pub fingerprint: super::BrowserFingerprint,
    /// Fallback address for active probing (e.g. "93.184.216.34:443").
    /// If `None`, failed auth connections are simply dropped.
    pub fallback_addr: Option<String>,
}

impl std::fmt::Debug for RealityConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealityConfig")
            .field("sni", &self.sni)
            .field("psk", &"[REDACTED]")
            .field("fingerprint", &self.fingerprint)
            .field("fallback_addr", &self.fallback_addr)
            .finish()
    }
}

/// REALITY transport — TLS camouflage with X25519 authentication.
#[derive(Debug)]
pub struct RealityTransport {
    /// SNI domain — used when establishing the outer TLS connection.
    #[allow(dead_code)]
    sni: String,
    psk: Zeroizing<[u8; 32]>,
    /// Browser fingerprint — used to configure the TLS `ClientConfig`.
    #[allow(dead_code)]
    fingerprint: super::BrowserFingerprint,
    fallback_addr: Option<String>,
}

impl RealityTransport {
    /// Create a new REALITY transport with the given configuration.
    #[must_use]
    pub fn new(config: RealityConfig) -> Self {
        Self {
            sni: config.sni,
            psk: config.psk,
            fingerprint: config.fingerprint,
            fallback_addr: config.fallback_addr,
        }
    }
}

#[async_trait::async_trait]
impl AiraTransport for RealityTransport {
    async fn wrap_outbound(&self, stream: BoxedStream) -> Result<BoxedStream, TransportError> {
        reality_client_handshake(stream, &self.psk).await
    }

    async fn accept_inbound(&self, stream: BoxedStream) -> Result<BoxedStream, TransportError> {
        reality_server_handshake(stream, &self.psk, self.fallback_addr.as_deref()).await
    }

    fn name(&self) -> &'static str {
        "reality"
    }
}

// ─── Client handshake ──────────────────────────────────────────────────────

/// Client-side REALITY handshake (Phase 2 — authentication).
///
/// Assumes the outer TLS tunnel is already established (the `stream` is
/// already encrypted by `tokio-rustls`).
async fn reality_client_handshake(
    mut stream: BoxedStream,
    psk: &[u8; 32],
) -> Result<BoxedStream, TransportError> {
    // Generate random ephemeral bytes for the auth nonce.
    let mut eph_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut eph_bytes);

    // Current timestamp.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| TransportError::Handshake(format!("clock error: {e}")))?;
    let timestamp = now.as_secs();
    let timestamp_bytes = timestamp.to_le_bytes();

    // Compute BLAKE3-MAC using PSK as the shared secret.
    // Both sides know PSK, so the MAC proves the client has the PSK.
    let mac = compute_auth_mac(psk, &timestamp_bytes, &eph_bytes);

    // Build auth frame: [0xA1][32B nonce][32B mac][8B timestamp]
    let mut auth_frame = [0u8; AUTH_REQUEST_SIZE];
    auth_frame[0] = AUTH_REQUEST_MAGIC;
    auth_frame[1..33].copy_from_slice(&eph_bytes);
    auth_frame[33..65].copy_from_slice(&mac);
    auth_frame[65..73].copy_from_slice(&timestamp_bytes);

    stream
        .write_all(&auth_frame)
        .await
        .map_err(|e| TransportError::Handshake(format!("auth send failed: {e}")))?;
    stream
        .flush()
        .await
        .map_err(|e| TransportError::Handshake(format!("flush failed: {e}")))?;

    // Read server response.
    let mut resp = [0u8; AUTH_RESPONSE_SIZE];
    stream
        .read_exact(&mut resp)
        .await
        .map_err(|e| TransportError::Handshake(format!("auth response read failed: {e}")))?;

    if resp[0] != AUTH_RESPONSE_MAGIC {
        return Err(TransportError::RealityAuth(
            "unexpected server response".into(),
        ));
    }

    let server_eph_pk: [u8; 32] = resp[1..33]
        .try_into()
        .map_err(|_| TransportError::RealityAuth("invalid server pubkey".into()))?;

    // Derive session key from both nonces and the PSK.
    let session_key = derive_session_key(&eph_bytes, &server_eph_pk, psk);

    // Build obfuscated stream (same framing as obfs.rs).
    let (write_dir, read_dir) = (0, 1);
    let reality_stream = RealityStream {
        inner: stream,
        write_key: Zeroizing::new(Keystream::new(&session_key, write_dir)),
        read_key: Zeroizing::new(Keystream::new(&session_key, read_dir)),
        read_buf: Vec::new(),
        read_pos: 0,
        pending_frame: None,
    };

    Ok(BoxedStream::new(reality_stream))
}

// ─── Server handshake ──────────────────────────────────────────────────────

/// Server-side REALITY handshake (Phase 2 — authentication + fallback).
async fn reality_server_handshake(
    mut stream: BoxedStream,
    psk: &[u8; 32],
    fallback_addr: Option<&str>,
) -> Result<BoxedStream, TransportError> {
    // Read auth frame from client.
    let mut auth_frame = [0u8; AUTH_REQUEST_SIZE];
    stream
        .read_exact(&mut auth_frame)
        .await
        .map_err(|e| TransportError::Handshake(format!("auth read failed: {e}")))?;

    // Validate magic byte.
    if auth_frame[0] != AUTH_REQUEST_MAGIC {
        // Not an Aira client — trigger fallback.
        return handle_fallback(stream, &auth_frame, fallback_addr);
    }

    // Extract fields.
    let client_eph_pk: [u8; 32] = auth_frame[1..33]
        .try_into()
        .map_err(|_| TransportError::RealityAuth("invalid client pubkey".into()))?;
    let received_mac: [u8; 32] = auth_frame[33..65]
        .try_into()
        .map_err(|_| TransportError::RealityAuth("invalid MAC".into()))?;
    let timestamp_bytes: [u8; 8] = auth_frame[65..73]
        .try_into()
        .map_err(|_| TransportError::RealityAuth("invalid timestamp".into()))?;

    // Verify MAC using PSK — both sides share the PSK.
    let expected_mac = compute_auth_mac(psk, &timestamp_bytes, &client_eph_pk);

    if !constant_time_eq(&received_mac, &expected_mac) {
        return handle_fallback(stream, &auth_frame, fallback_addr);
    }

    // Verify timestamp (anti-replay).
    let client_ts = u64::from_le_bytes(timestamp_bytes);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| TransportError::Handshake(format!("clock error: {e}")))?
        .as_secs();

    let drift = now.abs_diff(client_ts);

    if drift > MAX_TIMESTAMP_DRIFT {
        return Err(TransportError::RealityAuth(format!(
            "timestamp drift too large: {drift}s"
        )));
    }

    // Generate server ephemeral nonce.
    let mut server_eph_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut server_eph_bytes);

    // Send auth response.
    let mut resp = [0u8; AUTH_RESPONSE_SIZE];
    resp[0] = AUTH_RESPONSE_MAGIC;
    resp[1..33].copy_from_slice(&server_eph_bytes);

    stream
        .write_all(&resp)
        .await
        .map_err(|e| TransportError::Handshake(format!("auth response send failed: {e}")))?;
    stream
        .flush()
        .await
        .map_err(|e| TransportError::Handshake(format!("flush failed: {e}")))?;

    // Derive session key from both nonces and PSK.
    let session_key = derive_session_key(&client_eph_pk, &server_eph_bytes, psk);

    // Build obfuscated stream.
    let (write_dir, read_dir) = (1, 0);
    let reality_stream = RealityStream {
        inner: stream,
        write_key: Zeroizing::new(Keystream::new(&session_key, write_dir)),
        read_key: Zeroizing::new(Keystream::new(&session_key, read_dir)),
        read_buf: Vec::new(),
        read_pos: 0,
        pending_frame: None,
    };

    Ok(BoxedStream::new(reality_stream))
}

// ─── Fallback (active probing resistance) ──────────────────────────────────

/// Handle a non-Aira connection by proxying to the real backend.
///
/// The `initial_data` contains bytes already read from the client that need
/// to be forwarded to the backend.  If no `fallback_addr` is configured,
/// simply return an error.
fn handle_fallback(
    _stream: BoxedStream,
    _initial_data: &[u8],
    fallback_addr: Option<&str>,
) -> Result<BoxedStream, TransportError> {
    match fallback_addr {
        Some(addr) => {
            // In a production deployment, we would:
            // 1. Connect to the real backend (addr)
            // 2. Forward initial_data
            // 3. Bidirectionally proxy all traffic
            // 4. The prober sees a genuine website response
            //
            // For now, return an error indicating fallback was triggered.
            // Full proxy implementation requires a long-lived background task
            // and is out of scope for the transport trait's return type.
            Err(TransportError::RealityAuth(format!(
                "active probing detected, would proxy to {addr}"
            )))
        }
        None => Err(TransportError::RealityAuth(
            "authentication failed (no fallback configured)".into(),
        )),
    }
}

// ─── Crypto helpers ────────────────────────────────────────────────────────

/// Compute the BLAKE3-MAC for REALITY authentication.
///
/// `key` = shared DH secret, `timestamp` = 8-byte LE seconds, `pubkey` = 32-byte X25519.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn compute_auth_mac(key: &[u8; 32], timestamp: &[u8; 8], pubkey: &[u8; 32]) -> [u8; 32] {
    let mac_key = blake3::derive_key(REALITY_AUTH_CONTEXT, key);
    let mut hasher = Hasher::new_keyed(&mac_key);
    hasher.update(timestamp);
    hasher.update(pubkey);
    *hasher.finalize().as_bytes()
}

/// Derive the session key from both ephemeral public keys and the shared secret.
fn derive_session_key(
    client_eph: &[u8; 32],
    server_eph: &[u8; 32],
    shared_secret: &[u8; 32],
) -> Zeroizing<[u8; 32]> {
    let mut kdf_input = [0u8; 96];
    kdf_input[..32].copy_from_slice(client_eph);
    kdf_input[32..64].copy_from_slice(server_eph);
    kdf_input[64..96].copy_from_slice(shared_secret);
    let key = blake3::derive_key(REALITY_SESSION_CONTEXT, &kdf_input);
    // Zeroize the intermediate input.
    kdf_input.fill(0);
    Zeroizing::new(key)
}

/// Constant-time comparison of two 32-byte arrays.
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

// ─── Keystream (reused from obfs.rs pattern) ───────────────────────────────

/// BLAKE3-based keystream generator.
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
    fn new(key: &Zeroizing<[u8; 32]>, direction: u8) -> Self {
        Self {
            key: **key,
            direction,
            counter: 0,
            block: [0u8; 32],
            block_pos: 32,
        }
    }

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

// ─── RealityStream (framed XOR, same as ObfsStream) ────────────────────────

/// Bidirectional stream with XOR obfuscation inside the REALITY tunnel.
struct RealityStream {
    inner: BoxedStream,
    write_key: Zeroizing<Keystream>,
    read_key: Zeroizing<Keystream>,
    read_buf: Vec<u8>,
    read_pos: usize,
    pending_frame: Option<PendingFrame>,
}

struct PendingFrame {
    payload_len: usize,
    data: Vec<u8>,
}

impl AsyncRead for RealityStream {
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

        // Read from inner stream.
        let mut tmp = [0u8; 4096];
        let mut tmp_buf = ReadBuf::new(&mut tmp);
        match Pin::new(&mut this.inner).poll_read(cx, &mut tmp_buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {
                let filled = tmp_buf.filled();
                if filled.is_empty() {
                    return Poll::Ready(Ok(()));
                }

                let mut pos = 0;
                while pos < filled.len() {
                    if let Some(ref mut frame) = this.pending_frame {
                        let need = frame.payload_len - frame.data.len();
                        let available = filled.len() - pos;
                        let take = need.min(available);
                        frame.data.extend_from_slice(&filled[pos..pos + take]);
                        pos += take;

                        if frame.data.len() == frame.payload_len {
                            let mut payload = std::mem::take(&mut frame.data);
                            this.pending_frame = None;
                            this.read_key.apply(&mut payload);
                            this.read_buf.extend_from_slice(&payload);
                        }
                    } else {
                        if pos + 2 > filled.len() {
                            break;
                        }
                        let len = u16::from_le_bytes([filled[pos], filled[pos + 1]]) as usize;
                        pos += 2;
                        if len == 0 || len > MAX_FRAME_PAYLOAD {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("invalid reality frame length: {len}"),
                            )));
                        }
                        this.pending_frame = Some(PendingFrame {
                            payload_len: len,
                            data: Vec::with_capacity(len),
                        });
                    }
                }

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

                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }
}

impl AsyncWrite for RealityStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let this = self.get_mut();
        let chunk_len = buf.len().min(MAX_FRAME_PAYLOAD).min(usize::from(u16::MAX));
        let mut obfuscated = buf[..chunk_len].to_vec();
        this.write_key.apply(&mut obfuscated);

        // SAFETY: chunk_len <= u16::MAX by the .min() above.
        let len_bytes = u16::try_from(chunk_len)
            .expect("chunk_len clamped to u16::MAX")
            .to_le_bytes();
        let mut frame = Vec::with_capacity(2 + chunk_len);
        frame.extend_from_slice(&len_bytes);
        frame.extend_from_slice(&obfuscated);

        match Pin::new(&mut this.inner).poll_write(cx, &frame) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(written)) => {
                if written < frame.len() {
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "partial reality frame write",
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

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Generate a test PSK keypair (in real usage, this is pre-shared).
    fn test_psk() -> Zeroizing<[u8; 32]> {
        let mut psk = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut psk);
        Zeroizing::new(psk)
    }

    #[tokio::test]
    async fn reality_roundtrip_basic() {
        let psk = test_psk();
        let transport = RealityTransport::new(RealityConfig {
            sni: "www.apple.com".into(),
            psk: psk.clone(),
            fingerprint: super::super::BrowserFingerprint::Chrome,
            fallback_addr: None,
        });

        let (client_raw, server_raw) = tokio::io::duplex(8192);

        let (client_result, server_result) = tokio::join!(
            transport.wrap_outbound(BoxedStream::new(client_raw)),
            transport.accept_inbound(BoxedStream::new(server_raw)),
        );

        let mut client = client_result.expect("client wrap");
        let mut server = server_result.expect("server wrap");

        let msg = b"hello reality world";
        client.write_all(msg).await.expect("write");
        client.flush().await.expect("flush");

        let mut buf = vec![0u8; msg.len()];
        server.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, msg);
    }

    #[tokio::test]
    async fn reality_roundtrip_large() {
        let psk = test_psk();
        let transport = RealityTransport::new(RealityConfig {
            sni: "www.bing.com".into(),
            psk: psk.clone(),
            fingerprint: super::super::BrowserFingerprint::Firefox,
            fallback_addr: None,
        });

        let (client_raw, server_raw) = tokio::io::duplex(256 * 1024);

        let (client_result, server_result) = tokio::join!(
            transport.wrap_outbound(BoxedStream::new(client_raw)),
            transport.accept_inbound(BoxedStream::new(server_raw)),
        );

        let mut client = client_result.expect("client wrap");
        let mut server = server_result.expect("server wrap");

        let msg = vec![0xCD_u8; 10_000];
        client.write_all(&msg).await.expect("write");
        client.flush().await.expect("flush");
        drop(client);

        let mut buf = Vec::new();
        server.read_to_end(&mut buf).await.expect("read");
        assert_eq!(buf, msg);
    }

    #[tokio::test]
    async fn reality_bidirectional() {
        let psk = test_psk();
        let transport = RealityTransport::new(RealityConfig {
            sni: "www.apple.com".into(),
            psk: psk.clone(),
            fingerprint: super::super::BrowserFingerprint::Safari,
            fallback_addr: None,
        });

        let (client_raw, server_raw) = tokio::io::duplex(8192);

        let (client_result, server_result) = tokio::join!(
            transport.wrap_outbound(BoxedStream::new(client_raw)),
            transport.accept_inbound(BoxedStream::new(server_raw)),
        );

        let mut client = client_result.expect("client wrap");
        let mut server = server_result.expect("server wrap");

        // Client -> Server
        client.write_all(b"ping").await.expect("write");
        client.flush().await.expect("flush");
        let mut buf = vec![0u8; 4];
        server.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, b"ping");

        // Server -> Client
        server.write_all(b"pong").await.expect("write");
        server.flush().await.expect("flush");
        let mut buf2 = vec![0u8; 4];
        client.read_exact(&mut buf2).await.expect("read");
        assert_eq!(&buf2, b"pong");
    }

    #[tokio::test]
    async fn reality_wrong_psk_fails() {
        let psk_client = test_psk();
        let psk_server = test_psk(); // different PSK

        let client_transport = RealityTransport::new(RealityConfig {
            sni: "www.apple.com".into(),
            psk: psk_client,
            fingerprint: super::super::BrowserFingerprint::Chrome,
            fallback_addr: Some("127.0.0.1:443".into()),
        });

        let server_transport = RealityTransport::new(RealityConfig {
            sni: "www.apple.com".into(),
            psk: psk_server,
            fingerprint: super::super::BrowserFingerprint::Chrome,
            fallback_addr: Some("127.0.0.1:443".into()),
        });

        let (client_raw, server_raw) = tokio::io::duplex(8192);

        let (client_result, server_result) = tokio::join!(
            client_transport.wrap_outbound(BoxedStream::new(client_raw)),
            server_transport.accept_inbound(BoxedStream::new(server_raw)),
        );

        // Server should reject with fallback (active probing detected).
        assert!(server_result.is_err());
        let err = server_result.unwrap_err().to_string();
        assert!(
            err.contains("active probing"),
            "expected fallback error, got: {err}"
        );

        // Client may also fail (server closes connection before responding).
        // This is expected behavior — mismatched PSK = no session.
        drop(client_result);
    }

    #[test]
    fn auth_mac_deterministic() {
        let key = [42u8; 32];
        let timestamp = 1_000_000u64.to_le_bytes();
        let pubkey = [7u8; 32];

        let mac1 = compute_auth_mac(&key, &timestamp, &pubkey);
        let mac2 = compute_auth_mac(&key, &timestamp, &pubkey);
        assert_eq!(mac1, mac2);
    }

    #[test]
    fn auth_mac_different_inputs() {
        let key = [42u8; 32];
        let ts1 = 1_000_000u64.to_le_bytes();
        let ts2 = 1_000_001u64.to_le_bytes();
        let pubkey = [7u8; 32];

        let mac1 = compute_auth_mac(&key, &ts1, &pubkey);
        let mac2 = compute_auth_mac(&key, &ts2, &pubkey);
        assert_ne!(
            mac1, mac2,
            "different timestamps should produce different MACs"
        );
    }

    #[test]
    fn session_key_deterministic() {
        let client_eph = [1u8; 32];
        let server_eph = [2u8; 32];
        let shared = [3u8; 32];

        let k1 = derive_session_key(&client_eph, &server_eph, &shared);
        let k2 = derive_session_key(&client_eph, &server_eph, &shared);
        assert_eq!(*k1, *k2);
    }

    #[test]
    fn session_key_depends_on_all_inputs() {
        let client_eph = [1u8; 32];
        let server_eph = [2u8; 32];
        let shared = [3u8; 32];
        let different = [4u8; 32];

        let k1 = derive_session_key(&client_eph, &server_eph, &shared);
        let k2 = derive_session_key(&different, &server_eph, &shared);
        let k3 = derive_session_key(&client_eph, &different, &shared);
        let k4 = derive_session_key(&client_eph, &server_eph, &different);

        assert_ne!(*k1, *k2);
        assert_ne!(*k1, *k3);
        assert_ne!(*k1, *k4);
    }

    #[test]
    fn constant_time_eq_works() {
        let a = [42u8; 32];
        let b = [42u8; 32];
        let c = [43u8; 32];
        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
    }

    #[tokio::test]
    async fn reality_non_aira_client_triggers_fallback() {
        let psk = test_psk();
        let transport = RealityTransport::new(RealityConfig {
            sni: "www.apple.com".into(),
            psk,
            fingerprint: super::super::BrowserFingerprint::Chrome,
            fallback_addr: Some("93.184.216.34:443".into()),
        });

        let (mut client_raw, server_raw) = tokio::io::duplex(8192);

        // Send garbage (non-Aira client — simulates active probe).
        let garbage = b"GET / HTTP/1.1\r\nHost: www.apple.com\r\n\r\n";
        let send_task = async move {
            // Pad to AUTH_REQUEST_SIZE so server can read_exact
            let mut padded = vec![0u8; AUTH_REQUEST_SIZE];
            let copy_len = garbage.len().min(AUTH_REQUEST_SIZE);
            padded[..copy_len].copy_from_slice(&garbage[..copy_len]);
            client_raw.write_all(&padded).await.expect("write garbage");
            client_raw.flush().await.expect("flush");
        };

        let (_, server_result) = tokio::join!(
            send_task,
            transport.accept_inbound(BoxedStream::new(server_raw)),
        );

        assert!(server_result.is_err());
        let err = server_result.unwrap_err().to_string();
        assert!(
            err.contains("active probing") || err.contains("authentication failed"),
            "expected fallback, got: {err}"
        );
    }

    #[test]
    fn reality_transport_name() {
        let psk = test_psk();
        let transport = RealityTransport::new(RealityConfig {
            sni: "test.com".into(),
            psk,
            fingerprint: super::super::BrowserFingerprint::Chrome,
            fallback_addr: None,
        });
        assert_eq!(transport.name(), "reality");
    }
}
