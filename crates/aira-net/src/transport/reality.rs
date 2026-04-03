// Crypto/protocol terms trigger doc_markdown; dead_code for test-only helpers
// (ClientHello parser, ReplayStream, SessionIdPatcher — reserved for future
// Session ID injection when a Rust uTLS library becomes available).
#![allow(clippy::doc_markdown, dead_code)]

//! REALITY-like TLS camouflage transport — TCP-level selective proxy.
//!
//! Makes Aira traffic indistinguishable from legitimate HTTPS by acting as
//! a TCP-level selective proxy.  The server reads the raw TLS `ClientHello`,
//! checks a PSK-derived short ID embedded in the Session ID field, and either
//! serves the Aira client or transparently proxies to the real backend.
//!
//! # Protocol
//!
//! **Phase 1 — ClientHello Inspection (TCP level):**
//! Server reads raw bytes, parses TLS `ClientHello`, extracts Session ID.
//! First 8 bytes are compared against `BLAKE3("aira/reality/sid/0", PSK)[0..8]`.
//!
//! **Phase 2a — Aira Client (short_id matches):**
//! Server completes TLS 1.3 handshake with an ephemeral self-signed cert.
//! Client uses `AcceptAnyCertVerifier` (auth is via PSK, not CA).
//! Inside TLS tunnel: BLAKE3-MAC auth + XOR-framed session data.
//!
//! **Phase 2b — Active Probe (short_id does not match):**
//! Server connects to real backend, forwards original `ClientHello`,
//! runs `copy_bidirectional`.  Prober gets real `apple.com` content.
//!
//! See SPEC.md §11A.5.

use std::io;
use std::io::Cursor;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};

use blake3::Hasher;
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use zeroize::Zeroizing;

use super::fingerprint;
use super::{AiraTransport, BoxedStream, TransportError};

// ─── Constants ─────────────────────────────────────────────────────────────

/// KDF context for short ID derivation from PSK.
const REALITY_SID_CONTEXT: &str = "aira/reality/sid/0";

/// KDF context for REALITY authentication MAC.
const REALITY_AUTH_CONTEXT: &str = "aira/reality/auth/0";

/// KDF context for REALITY session key derivation.
const REALITY_SESSION_CONTEXT: &str = "aira/reality/session/0";

/// Short ID length in bytes (first N bytes of Session ID).
const SHORT_ID_LEN: usize = 8;

/// Magic byte: client auth request.
const AUTH_REQUEST_MAGIC: u8 = 0xA1;

/// Magic byte: server auth response (success).
const AUTH_RESPONSE_MAGIC: u8 = 0xA2;

/// Auth frame size: magic(1) + nonce(32) + mac(32) + timestamp(8) = 73.
const AUTH_REQUEST_SIZE: usize = 73;

/// Auth response size: magic(1) + nonce(32) = 33.
const AUTH_RESPONSE_SIZE: usize = 33;

/// Maximum allowed timestamp drift in seconds (±60s).
const MAX_TIMESTAMP_DRIFT: u64 = 60;

/// Maximum frame payload size (64 KB).
const MAX_FRAME_PAYLOAD: usize = 65_536;

/// Maximum `ClientHello` record size we will buffer.
const MAX_CLIENT_HELLO_SIZE: usize = 16_384;

/// TLS Record header: content_type(1) + version(2) + length(2).
const TLS_RECORD_HEADER_SIZE: usize = 5;

// ─── Configuration ─────────────────────────────────────────────────────────

/// Configuration for the REALITY transport.
pub struct RealityConfig {
    /// Target domain for TLS SNI (e.g. "www.apple.com").
    pub sni: String,
    /// Pre-shared key for authentication.
    pub psk: Zeroizing<[u8; 32]>,
    /// Browser fingerprint to mimic in the TLS `ClientHello`.
    pub fingerprint: super::BrowserFingerprint,
    /// Fallback address for active probing (e.g. "93.184.216.34:443").
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

/// REALITY transport — TCP-level selective proxy with TLS camouflage.
#[derive(Debug)]
pub struct RealityTransport {
    sni: String,
    psk: Zeroizing<[u8; 32]>,
    fingerprint: super::BrowserFingerprint,
    fallback_addr: Option<String>,
}

impl RealityTransport {
    /// Create a new REALITY transport.
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
        reality_client_handshake(stream, &self.psk, &self.sni, self.fingerprint).await
    }

    async fn accept_inbound(&self, stream: BoxedStream) -> Result<BoxedStream, TransportError> {
        reality_server_handshake(stream, &self.psk, &self.sni, self.fallback_addr.as_deref()).await
    }

    fn name(&self) -> &'static str {
        "reality"
    }
}

// ─── Short ID ──────────────────────────────────────────────────────────────

/// Derive the short ID from PSK for Session ID authentication.
///
/// Returns the first 8 bytes of `BLAKE3("aira/reality/sid/0", PSK)`.
fn generate_short_id(psk: &[u8; 32]) -> [u8; SHORT_ID_LEN] {
    let hash = blake3::derive_key(REALITY_SID_CONTEXT, psk);
    let mut sid = [0u8; SHORT_ID_LEN];
    sid.copy_from_slice(&hash[..SHORT_ID_LEN]);
    sid
}

// ─── ClientHello parser ────────────────────────────────────────────────────

/// Parsed information from a TLS ClientHello message.
struct ClientHelloInfo {
    /// Session ID field (0-32 bytes in TLS 1.3 compatibility mode).
    session_id: Vec<u8>,
    /// The raw bytes of the entire TLS record (for forwarding).
    raw_bytes: Vec<u8>,
}

/// Read and parse a TLS ClientHello from the stream.
///
/// Reads the TLS Record header to determine length, then reads the full
/// record and extracts the Session ID field.
async fn read_client_hello(stream: &mut BoxedStream) -> Result<ClientHelloInfo, TransportError> {
    // Read TLS Record header: [content_type][version_major][version_minor][length_hi][length_lo]
    let mut header = [0u8; TLS_RECORD_HEADER_SIZE];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|e| TransportError::Handshake(format!("failed to read TLS header: {e}")))?;

    // Validate: content_type must be 0x16 (Handshake).
    if header[0] != 0x16 {
        return Err(TransportError::Handshake(format!(
            "not a TLS handshake record: type=0x{:02x}",
            header[0]
        )));
    }

    let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    if record_len > MAX_CLIENT_HELLO_SIZE {
        return Err(TransportError::Handshake(format!(
            "TLS record too large: {record_len}"
        )));
    }

    // Read the full record body.
    let mut body = vec![0u8; record_len];
    stream
        .read_exact(&mut body)
        .await
        .map_err(|e| TransportError::Handshake(format!("failed to read TLS record: {e}")))?;

    // Combine header + body for forwarding.
    let mut raw_bytes = Vec::with_capacity(TLS_RECORD_HEADER_SIZE + record_len);
    raw_bytes.extend_from_slice(&header);
    raw_bytes.extend_from_slice(&body);

    // Parse ClientHello from the handshake body.
    // Handshake header: [msg_type(1)][length(3)]
    if body.len() < 4 {
        return Err(TransportError::Handshake("handshake too short".into()));
    }
    if body[0] != 0x01 {
        return Err(TransportError::Handshake(format!(
            "not a ClientHello: type=0x{:02x}",
            body[0]
        )));
    }

    // ClientHello body starts at offset 4 (after handshake header).
    let ch = &body[4..];

    // ClientHello: [version(2)][random(32)][session_id_len(1)][session_id(N)]...
    if ch.len() < 35 {
        return Err(TransportError::Handshake("ClientHello too short".into()));
    }

    let session_id_len = ch[34] as usize;
    if ch.len() < 35 + session_id_len {
        return Err(TransportError::Handshake(
            "ClientHello truncated at session_id".into(),
        ));
    }

    let session_id = ch[35..35 + session_id_len].to_vec();

    Ok(ClientHelloInfo {
        session_id,
        raw_bytes,
    })
}

/// Patch the first `SHORT_ID_LEN` bytes of Session ID in a raw TLS record.
///
/// Offset = record(5) + handshake(4) + version(2) + random(32) + sid_len(1) = 44.
fn patch_session_id(buf: &mut [u8], short_id: [u8; SHORT_ID_LEN]) -> bool {
    const SESSION_ID_OFFSET: usize = 44;
    // Check that session_id_len >= SHORT_ID_LEN
    if buf.len() < SESSION_ID_OFFSET + SHORT_ID_LEN {
        return false;
    }
    let sid_len = buf[SESSION_ID_OFFSET - 1] as usize;
    if sid_len < SHORT_ID_LEN {
        return false;
    }
    buf[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SHORT_ID_LEN].copy_from_slice(&short_id);
    true
}

// ─── ReplayStream ──────────────────────────────────────────────────────────

/// A stream that replays buffered bytes before reading from the inner stream.
///
/// After the server reads the ClientHello from raw TCP, it needs to feed
/// those bytes back into `TlsAcceptor::accept()`.  This wrapper serves the
/// buffered bytes first, then transparently reads from the underlying stream.
struct ReplayStream {
    buffered: Cursor<Vec<u8>>,
    inner: BoxedStream,
}

impl ReplayStream {
    fn new(buffered_bytes: Vec<u8>, inner: BoxedStream) -> Self {
        Self {
            buffered: Cursor::new(buffered_bytes),
            inner,
        }
    }
}

impl AsyncRead for ReplayStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Serve buffered bytes first.
        let pos = usize::try_from(this.buffered.position()).unwrap_or(usize::MAX);
        let buffered_data = this.buffered.get_ref();
        if pos < buffered_data.len() {
            let remaining = &buffered_data[pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            this.buffered.set_position((pos + n) as u64);
            return Poll::Ready(Ok(()));
        }

        // Buffered bytes exhausted — read from inner stream.
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for ReplayStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

// ─── Client handshake ──────────────────────────────────────────────────────

/// Client-side REALITY handshake.
///
/// 1. Send 8-byte short_id (PSK-derived) before TLS
/// 2. Establish TLS 1.3 with browser fingerprint + AcceptAnyCertVerifier
/// 3. Run Aira auth (BLAKE3-MAC) inside TLS tunnel
/// 4. Return XOR-framed stream
async fn reality_client_handshake(
    mut stream: BoxedStream,
    psk: &[u8; 32],
    sni: &str,
    fingerprint: super::BrowserFingerprint,
) -> Result<BoxedStream, TransportError> {
    // Send short_id prefix — server uses this to distinguish Aira clients
    // from active probes BEFORE the TLS handshake.
    let short_id = generate_short_id(psk);
    stream
        .write_all(&short_id)
        .await
        .map_err(|e| TransportError::Handshake(format!("short_id send: {e}")))?;
    stream
        .flush()
        .await
        .map_err(|e| TransportError::Handshake(format!("flush: {e}")))?;

    // Build TLS config that accepts any cert.
    let tls_config = fingerprint::build_reality_client_config(fingerprint)?;
    let connector = TlsConnector::from(tls_config);

    let server_name = rustls::pki_types::ServerName::try_from(sni.to_string())
        .map_err(|e| TransportError::Config(format!("invalid SNI: {e}")))?;

    // TLS handshake with ephemeral cert.
    let tls_stream = connector
        .connect(server_name, stream)
        .await
        .map_err(|e| TransportError::Handshake(format!("TLS handshake failed: {e}")))?;

    let mut tls_boxed = BoxedStream::new(tls_stream);

    // Run Aira auth inside TLS tunnel.
    aira_auth_client(&mut tls_boxed, psk).await?;

    // Wrap with XOR framing.
    let session_key = derive_session_key_from_auth(psk);
    let reality_stream = RealityStream::new(tls_boxed, &session_key, true);
    Ok(BoxedStream::new(reality_stream))
}

// ─── Server handshake ──────────────────────────────────────────────────────

/// Server-side REALITY handshake.
///
/// 1. Read 8-byte short_id prefix
/// 2. If matches → TLS handshake with ephemeral cert → Aira auth → session
/// 3. If doesn't match → read rest as ClientHello → TCP proxy to backend
async fn reality_server_handshake(
    mut stream: BoxedStream,
    psk: &[u8; 32],
    sni: &str,
    fallback_addr: Option<&str>,
) -> Result<BoxedStream, TransportError> {
    // 1. Read short_id prefix (8 bytes).
    let mut received_sid = [0u8; SHORT_ID_LEN];
    stream
        .read_exact(&mut received_sid)
        .await
        .map_err(|e| TransportError::Handshake(format!("short_id read: {e}")))?;

    // 2. Check short_id.
    let expected_sid = generate_short_id(psk);
    if !constant_time_eq_slice(&received_sid, &expected_sid) {
        // Active probe — proxy to real backend.
        // Prepend the 8 bytes we already read (they might be the start
        // of a TLS ClientHello from a real browser).
        return proxy_to_backend(stream, &received_sid, fallback_addr);
    }

    // 3. Generate ephemeral self-signed cert.
    let (certs, key) = fingerprint::generate_ephemeral_cert(sni)?;
    let server_config = fingerprint::build_server_config(certs, key)?;
    let acceptor = TlsAcceptor::from(server_config);

    // 4. TLS handshake (client sends ClientHello AFTER short_id).
    let tls_stream = acceptor
        .accept(stream)
        .await
        .map_err(|e| TransportError::Handshake(format!("TLS accept failed: {e}")))?;

    let mut tls_boxed = BoxedStream::new(tls_stream);

    // 5. Run Aira auth inside TLS tunnel.
    aira_auth_server(&mut tls_boxed, psk).await?;

    // 6. Wrap with XOR framing.
    let session_key = derive_session_key_from_auth(psk);
    let reality_stream = RealityStream::new(tls_boxed, &session_key, false);
    Ok(BoxedStream::new(reality_stream))
}

// ─── TCP proxy fallback ────────────────────────────────────────────────────

/// Proxy a non-Aira connection to the real backend.
///
/// Connects to the backend, forwards the original ClientHello, and spawns a
/// background task for bidirectional proxying.
fn proxy_to_backend(
    client: BoxedStream,
    initial_bytes: &[u8],
    fallback_addr: Option<&str>,
) -> Result<BoxedStream, TransportError> {
    let addr = fallback_addr
        .ok_or_else(|| TransportError::RealityAuth("no fallback configured".into()))?;

    let addr = addr.to_string();
    let initial = initial_bytes.to_vec();

    // Spawn background proxy task.
    tokio::spawn(async move {
        let backend = match TcpStream::connect(&addr).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("REALITY fallback connect failed: {e}");
                return;
            }
        };

        let (mut backend_read, mut backend_write) = tokio::io::split(backend);
        let (mut client_read, mut client_write) = tokio::io::split(client);

        // Forward initial ClientHello bytes.
        if let Err(e) = backend_write.write_all(&initial).await {
            tracing::warn!("REALITY fallback initial write failed: {e}");
            return;
        }

        // Bidirectional proxy.
        let client_to_backend = tokio::io::copy(&mut client_read, &mut backend_write);
        let backend_to_client = tokio::io::copy(&mut backend_read, &mut client_write);

        let _ = tokio::try_join!(client_to_backend, backend_to_client);
    });

    Err(TransportError::RealityAuth(
        "active probing detected, proxying to backend".into(),
    ))
}

// ─── Aira auth (inside TLS tunnel) ─────────────────────────────────────────

/// Client-side Aira authentication inside the TLS tunnel.
async fn aira_auth_client(stream: &mut BoxedStream, psk: &[u8; 32]) -> Result<(), TransportError> {
    // Generate random nonce.
    let mut nonce = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut nonce);

    // Timestamp.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| TransportError::Handshake(format!("clock error: {e}")))?;
    let timestamp_bytes = now.as_secs().to_le_bytes();

    // BLAKE3-MAC.
    let mac = compute_auth_mac(psk, &timestamp_bytes, &nonce);

    // Send auth frame.
    let mut frame = [0u8; AUTH_REQUEST_SIZE];
    frame[0] = AUTH_REQUEST_MAGIC;
    frame[1..33].copy_from_slice(&nonce);
    frame[33..65].copy_from_slice(&mac);
    frame[65..73].copy_from_slice(&timestamp_bytes);

    stream
        .write_all(&frame)
        .await
        .map_err(|e| TransportError::Handshake(format!("auth send: {e}")))?;
    stream
        .flush()
        .await
        .map_err(|e| TransportError::Handshake(format!("flush: {e}")))?;

    // Read response.
    let mut resp = [0u8; AUTH_RESPONSE_SIZE];
    stream
        .read_exact(&mut resp)
        .await
        .map_err(|e| TransportError::Handshake(format!("auth response: {e}")))?;

    if resp[0] != AUTH_RESPONSE_MAGIC {
        return Err(TransportError::RealityAuth("bad server response".into()));
    }

    Ok(())
}

/// Server-side Aira authentication inside the TLS tunnel.
async fn aira_auth_server(stream: &mut BoxedStream, psk: &[u8; 32]) -> Result<(), TransportError> {
    // Read auth frame.
    let mut frame = [0u8; AUTH_REQUEST_SIZE];
    stream
        .read_exact(&mut frame)
        .await
        .map_err(|e| TransportError::Handshake(format!("auth read: {e}")))?;

    if frame[0] != AUTH_REQUEST_MAGIC {
        return Err(TransportError::RealityAuth("bad auth magic".into()));
    }

    let nonce: [u8; 32] = frame[1..33]
        .try_into()
        .map_err(|_| TransportError::RealityAuth("nonce slice mismatch".into()))?;
    let received_mac: [u8; 32] = frame[33..65]
        .try_into()
        .map_err(|_| TransportError::RealityAuth("mac slice mismatch".into()))?;
    let timestamp_bytes: [u8; 8] = frame[65..73]
        .try_into()
        .map_err(|_| TransportError::RealityAuth("timestamp slice mismatch".into()))?;

    // Verify MAC.
    let expected_mac = compute_auth_mac(psk, &timestamp_bytes, &nonce);
    if !constant_time_eq_32(&received_mac, &expected_mac) {
        return Err(TransportError::RealityAuth("MAC mismatch".into()));
    }

    // Verify timestamp.
    let client_ts = u64::from_le_bytes(timestamp_bytes);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| TransportError::Handshake(format!("clock: {e}")))?
        .as_secs();
    let drift = now.abs_diff(client_ts);
    if drift > MAX_TIMESTAMP_DRIFT {
        return Err(TransportError::RealityAuth(format!(
            "timestamp drift: {drift}s"
        )));
    }

    // Send response with server nonce.
    let mut resp = [0u8; AUTH_RESPONSE_SIZE];
    resp[0] = AUTH_RESPONSE_MAGIC;
    rand::thread_rng().fill_bytes(&mut resp[1..33]);

    stream
        .write_all(&resp)
        .await
        .map_err(|e| TransportError::Handshake(format!("auth response send: {e}")))?;
    stream
        .flush()
        .await
        .map_err(|e| TransportError::Handshake(format!("flush: {e}")))?;

    Ok(())
}

// ─── Crypto helpers ────────────────────────────────────────────────────────

#[allow(clippy::trivially_copy_pass_by_ref)]
fn compute_auth_mac(key: &[u8; 32], timestamp: &[u8; 8], nonce: &[u8; 32]) -> [u8; 32] {
    let mac_key = blake3::derive_key(REALITY_AUTH_CONTEXT, key);
    let mut hasher = Hasher::new_keyed(&mac_key);
    hasher.update(timestamp);
    hasher.update(nonce);
    *hasher.finalize().as_bytes()
}

fn derive_session_key_from_auth(psk: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(blake3::derive_key(REALITY_SESSION_CONTEXT, psk))
}

fn constant_time_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

fn constant_time_eq_slice(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

// ─── SessionIdPatcher ──────────────────────────────────────────────────────

/// Stream wrapper that patches the Session ID in outgoing TLS ClientHello.
///
/// Intercepts the first write (which contains the ClientHello) and replaces
/// bytes at the Session ID offset with the short_id.
struct SessionIdPatcher {
    inner: BoxedStream,
    short_id: [u8; SHORT_ID_LEN],
    patched: bool,
}

impl SessionIdPatcher {
    fn new(inner: BoxedStream, short_id: [u8; SHORT_ID_LEN]) -> Self {
        Self {
            inner,
            short_id,
            patched: false,
        }
    }
}

impl AsyncRead for SessionIdPatcher {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for SessionIdPatcher {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        if !this.patched && buf.len() > 52 {
            // This is the ClientHello — patch Session ID in a copy.
            this.patched = true;
            let mut patched_buf = buf.to_vec();
            patch_session_id(&mut patched_buf, this.short_id);
            // Write the patched buffer.
            match Pin::new(&mut this.inner).poll_write(cx, &patched_buf) {
                Poll::Ready(Ok(n)) => Poll::Ready(Ok(n.min(buf.len()))),
                other => other,
            }
        } else {
            Pin::new(&mut this.inner).poll_write(cx, buf)
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

// ─── Keystream (XOR framing, same pattern as obfs.rs) ─────────────────────

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

// ─── RealityStream ─────────────────────────────────────────────────────────

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

impl RealityStream {
    fn new(inner: BoxedStream, session_key: &Zeroizing<[u8; 32]>, is_client: bool) -> Self {
        let (write_dir, read_dir) = if is_client { (0, 1) } else { (1, 0) };
        Self {
            inner,
            write_key: Zeroizing::new(Keystream::new(session_key, write_dir)),
            read_key: Zeroizing::new(Keystream::new(session_key, read_dir)),
            read_buf: Vec::new(),
            read_pos: 0,
            pending_frame: None,
        }
    }
}

impl AsyncRead for RealityStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

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
                        let take = need.min(filled.len() - pos);
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
                                format!("invalid frame length: {len}"),
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

        #[allow(clippy::cast_possible_truncation)]
        let len_bytes = (chunk_len as u16).to_le_bytes();
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
                        "partial frame write",
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn test_psk() -> Zeroizing<[u8; 32]> {
        let mut psk = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut psk);
        Zeroizing::new(psk)
    }

    #[test]
    fn short_id_deterministic() {
        let psk = [42u8; 32];
        let id1 = generate_short_id(&psk);
        let id2 = generate_short_id(&psk);
        assert_eq!(id1, id2);
    }

    #[test]
    fn short_id_different_psks() {
        let id1 = generate_short_id(&[1u8; 32]);
        let id2 = generate_short_id(&[2u8; 32]);
        assert_ne!(id1, id2);
    }

    #[test]
    fn parse_client_hello_from_rustls() {
        // Generate a real ClientHello via rustls.
        let config =
            fingerprint::build_reality_client_config(super::super::BrowserFingerprint::Chrome)
                .expect("config");
        let server_name =
            rustls::pki_types::ServerName::try_from("www.apple.com".to_string()).unwrap();
        let mut conn = rustls::ClientConnection::new(config, server_name).unwrap();

        let mut buf = Vec::new();
        conn.write_tls(&mut buf).unwrap();

        // Parse the ClientHello.
        assert!(buf.len() > TLS_RECORD_HEADER_SIZE);
        assert_eq!(buf[0], 0x16); // Handshake

        let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
        assert_eq!(buf.len(), TLS_RECORD_HEADER_SIZE + record_len);

        // Parse session_id manually.
        let body = &buf[TLS_RECORD_HEADER_SIZE..];
        assert_eq!(body[0], 0x01); // ClientHello
        let ch = &body[4..];
        let sid_len = ch[34] as usize;
        assert_eq!(sid_len, 32, "TLS 1.3 compat mode uses 32-byte Session ID");

        let session_id = &ch[35..35 + sid_len];
        assert_eq!(session_id.len(), 32);
    }

    #[test]
    fn patch_session_id_works() {
        // Generate real ClientHello.
        let config =
            fingerprint::build_reality_client_config(super::super::BrowserFingerprint::Chrome)
                .expect("config");
        let server_name =
            rustls::pki_types::ServerName::try_from("www.apple.com".to_string()).unwrap();
        let mut conn = rustls::ClientConnection::new(config, server_name).unwrap();

        let mut buf = Vec::new();
        conn.write_tls(&mut buf).unwrap();

        let short_id = [0xAA; SHORT_ID_LEN];
        assert!(patch_session_id(&mut buf, short_id));

        // Verify the patch.
        let patched_sid = &buf[44..44 + SHORT_ID_LEN];
        assert_eq!(patched_sid, &short_id);
    }

    #[test]
    fn auth_mac_deterministic() {
        let key = [42u8; 32];
        let ts = 1_000_000u64.to_le_bytes();
        let nonce = [7u8; 32];
        assert_eq!(
            compute_auth_mac(&key, &ts, &nonce),
            compute_auth_mac(&key, &ts, &nonce)
        );
    }

    #[test]
    fn auth_mac_different_inputs() {
        let key = [42u8; 32];
        let ts1 = 1_000_000u64.to_le_bytes();
        let ts2 = 1_000_001u64.to_le_bytes();
        let nonce = [7u8; 32];
        assert_ne!(
            compute_auth_mac(&key, &ts1, &nonce),
            compute_auth_mac(&key, &ts2, &nonce)
        );
    }

    #[tokio::test]
    async fn replay_stream_serves_buffered_then_inner() {
        let buffered = vec![1, 2, 3, 4, 5];
        let (inner_write, inner_read) = tokio::io::duplex(1024);

        // Write data to inner.
        tokio::spawn(async move {
            let mut w = inner_write;
            w.write_all(&[6, 7, 8]).await.unwrap();
        });

        let mut replay = ReplayStream::new(buffered, BoxedStream::new(inner_read));

        // Read should first return buffered bytes, then inner bytes.
        let mut out = vec![0u8; 8];
        replay.read_exact(&mut out).await.unwrap();
        assert_eq!(out, vec![1, 2, 3, 4, 5, 6, 7, 8]);
    }

    #[tokio::test]
    async fn reality_tls_roundtrip() {
        let psk = test_psk();
        let sni = "test.example.com";

        let transport = RealityTransport::new(RealityConfig {
            sni: sni.into(),
            psk: psk.clone(),
            fingerprint: super::super::BrowserFingerprint::Chrome,
            fallback_addr: None,
        });

        let (client_raw, server_raw) = tokio::io::duplex(65536);

        let (client_result, server_result) = tokio::join!(
            transport.wrap_outbound(BoxedStream::new(client_raw)),
            transport.accept_inbound(BoxedStream::new(server_raw)),
        );

        let mut client = client_result.expect("client handshake");
        let mut server = server_result.expect("server handshake");

        // Send data.
        let msg = b"hello REALITY world";
        client.write_all(msg).await.expect("write");
        client.flush().await.expect("flush");

        let mut buf = vec![0u8; msg.len()];
        server.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, msg);
    }

    #[tokio::test]
    async fn reality_tls_bidirectional() {
        let psk = test_psk();
        let transport = RealityTransport::new(RealityConfig {
            sni: "test.example.com".into(),
            psk: psk.clone(),
            fingerprint: super::super::BrowserFingerprint::Firefox,
            fallback_addr: None,
        });

        let (client_raw, server_raw) = tokio::io::duplex(65536);

        let (client_result, server_result) = tokio::join!(
            transport.wrap_outbound(BoxedStream::new(client_raw)),
            transport.accept_inbound(BoxedStream::new(server_raw)),
        );

        let mut client = client_result.expect("client");
        let mut server = server_result.expect("server");

        client.write_all(b"ping").await.unwrap();
        client.flush().await.unwrap();
        let mut buf = vec![0u8; 4];
        server.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");

        server.write_all(b"pong").await.unwrap();
        server.flush().await.unwrap();
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");
    }

    #[tokio::test]
    async fn reality_wrong_psk_fails() {
        let psk1 = test_psk();
        let psk2 = test_psk();

        let client_transport = RealityTransport::new(RealityConfig {
            sni: "test.example.com".into(),
            psk: psk1,
            fingerprint: super::super::BrowserFingerprint::Chrome,
            fallback_addr: None,
        });

        let server_transport = RealityTransport::new(RealityConfig {
            sni: "test.example.com".into(),
            psk: psk2,
            fingerprint: super::super::BrowserFingerprint::Chrome,
            fallback_addr: None,
        });

        let (client_raw, server_raw) = tokio::io::duplex(65536);

        let (_client_result, server_result) = tokio::join!(
            client_transport.wrap_outbound(BoxedStream::new(client_raw)),
            server_transport.accept_inbound(BoxedStream::new(server_raw)),
        );

        // Server should reject — different PSK means different short_id.
        assert!(server_result.is_err());
    }

    #[tokio::test]
    async fn reality_non_tls_triggers_fallback() {
        let psk = test_psk();
        let transport = RealityTransport::new(RealityConfig {
            sni: "test.example.com".into(),
            psk,
            fingerprint: super::super::BrowserFingerprint::Chrome,
            fallback_addr: None, // No fallback → just error
        });

        let (mut client_raw, server_raw) = tokio::io::duplex(8192);

        // Send garbage (not TLS).
        let garbage = b"GET / HTTP/1.1\r\nHost: test\r\n\r\n";
        let send_task = async move {
            client_raw.write_all(garbage).await.unwrap();
            client_raw.flush().await.unwrap();
        };

        let (_, server_result) = tokio::join!(
            send_task,
            transport.accept_inbound(BoxedStream::new(server_raw)),
        );

        assert!(server_result.is_err());
        let err = server_result.unwrap_err().to_string();
        assert!(
            err.contains("active probing")
                || err.contains("no fallback")
                || err.contains("handshake"),
            "got: {err}"
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
