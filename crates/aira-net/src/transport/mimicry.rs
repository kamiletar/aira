//! CPS Protocol Mimicry transport.
//!
//! Wraps Aira traffic in headers that make it appear as legitimate
//! DNS, QUIC, SIP, or STUN traffic to Deep Packet Inspection systems.
//!
//! Frame format: `[1-byte profile tag][2-byte LE payload length][header][payload]`
//!
//! See SPEC.md §11A.4.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use rand::Rng;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::{AiraTransport, BoxedStream, MimicryProfile, TransportError};

// ─── Profile tags (first byte of each frame) ───────────────────────────────

const TAG_DNS: u8 = 0x01;
const TAG_QUIC: u8 = 0x02;
const TAG_SIP: u8 = 0x03;
const TAG_STUN: u8 = 0x04;

/// Maximum mimicry frame payload (64 KB).
const MAX_FRAME_PAYLOAD: usize = 65_536;

/// Mimicry transport — CPS protocol signature.
#[derive(Debug)]
pub struct MimicryTransport {
    profile: MimicryProfile,
}

impl MimicryTransport {
    /// Create a new mimicry transport with the given profile.
    #[must_use]
    pub fn new(profile: MimicryProfile) -> Self {
        Self { profile }
    }
}

#[async_trait::async_trait]
impl AiraTransport for MimicryTransport {
    async fn wrap_outbound(&self, mut stream: BoxedStream) -> Result<BoxedStream, TransportError> {
        // Send profile tag so the peer knows how to decode.
        let tag = profile_tag(&self.profile);
        stream
            .write_all(&[tag])
            .await
            .map_err(|e| TransportError::Handshake(format!("failed to send mimicry tag: {e}")))?;
        stream
            .flush()
            .await
            .map_err(|e| TransportError::Handshake(format!("flush failed: {e}")))?;

        Ok(BoxedStream::new(MimicryStream {
            inner: stream,
            profile: self.profile.clone(),
            read_buf: Vec::new(),
            read_pos: 0,
            pending_frame: None,
        }))
    }

    async fn accept_inbound(&self, mut stream: BoxedStream) -> Result<BoxedStream, TransportError> {
        // Read profile tag from peer.
        let mut tag_buf = [0u8; 1];
        stream
            .read_exact(&mut tag_buf)
            .await
            .map_err(|e| TransportError::Handshake(format!("failed to read mimicry tag: {e}")))?;

        let profile = tag_to_profile(tag_buf[0], &self.profile)?;

        Ok(BoxedStream::new(MimicryStream {
            inner: stream,
            profile,
            read_buf: Vec::new(),
            read_pos: 0,
            pending_frame: None,
        }))
    }

    fn name(&self) -> &'static str {
        "mimicry"
    }
}

fn profile_tag(profile: &MimicryProfile) -> u8 {
    match profile {
        MimicryProfile::Dns => TAG_DNS,
        MimicryProfile::Quic { .. } => TAG_QUIC,
        MimicryProfile::Sip => TAG_SIP,
        MimicryProfile::Stun => TAG_STUN,
        MimicryProfile::Custom(_) => TAG_DNS, // fallback
    }
}

fn tag_to_profile(tag: u8, hint: &MimicryProfile) -> Result<MimicryProfile, TransportError> {
    match tag {
        TAG_DNS => Ok(MimicryProfile::Dns),
        TAG_QUIC => {
            // Use the SNI from our own config as hint.
            let sni = if let MimicryProfile::Quic { sni } = hint {
                sni.clone()
            } else {
                "www.google.com".into()
            };
            Ok(MimicryProfile::Quic { sni })
        }
        TAG_SIP => Ok(MimicryProfile::Sip),
        TAG_STUN => Ok(MimicryProfile::Stun),
        _ => Err(TransportError::Handshake(format!(
            "unknown mimicry profile tag: {tag:#04x}"
        ))),
    }
}

// ─── Protocol header generators ─────────────────────────────────────────────

/// Generate a DNS-like header for the given payload.
///
/// DNS query format (simplified):
/// - 2 bytes: transaction ID (random)
/// - 2 bytes: flags (0x0100 = standard query)
/// - 2 bytes: questions count (1)
/// - 2 bytes: answers (0)
/// - 2 bytes: authority (0)
/// - 2 bytes: additional (0)
fn dns_header() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let txid: u16 = rng.gen();
    let mut hdr = Vec::with_capacity(12);
    hdr.extend_from_slice(&txid.to_be_bytes());
    hdr.extend_from_slice(&[0x01, 0x00]); // flags: standard query
    hdr.extend_from_slice(&[0x00, 0x01]); // 1 question
    hdr.extend_from_slice(&[0x00, 0x00]); // 0 answers
    hdr.extend_from_slice(&[0x00, 0x00]); // 0 authority
    hdr.extend_from_slice(&[0x00, 0x00]); // 0 additional
    hdr
}

/// Generate a QUIC Initial packet header.
///
/// QUIC long header format (simplified):
/// - 1 byte: header form + type (0xC0 = long header, Initial)
/// - 4 bytes: version (0x00000001 = QUIC v1)
/// - 1 byte: DCID length
/// - N bytes: DCID (random 8 bytes)
/// - 1 byte: SCID length
/// - N bytes: SCID (random 8 bytes)
fn quic_header() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut hdr = Vec::with_capacity(24);
    hdr.push(0xC0); // long header, Initial
    hdr.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // QUIC v1
    hdr.push(8); // DCID length
    let mut dcid = [0u8; 8];
    rng.fill(&mut dcid);
    hdr.extend_from_slice(&dcid);
    hdr.push(8); // SCID length
    let mut scid = [0u8; 8];
    rng.fill(&mut scid);
    hdr.extend_from_slice(&scid);
    hdr
}

/// Generate a SIP-like header.
///
/// A minimal SIP INVITE line + Content-Length header.
fn sip_header(payload_len: usize) -> Vec<u8> {
    format!("INVITE sip:user@host SIP/2.0\r\nContent-Length: {payload_len}\r\n\r\n").into_bytes()
}

/// Generate a STUN Binding Request header.
///
/// STUN header format:
/// - 2 bytes: message type (0x0001 = Binding Request)
/// - 2 bytes: message length
/// - 4 bytes: magic cookie (0x2112A442)
/// - 12 bytes: transaction ID (random)
fn stun_header(payload_len: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut hdr = Vec::with_capacity(20);
    hdr.extend_from_slice(&[0x00, 0x01]); // Binding Request
    hdr.extend_from_slice(&(payload_len as u16).to_be_bytes());
    hdr.extend_from_slice(&[0x21, 0x12, 0xA4, 0x42]); // magic cookie
    let mut txid = [0u8; 12];
    rng.fill(&mut txid);
    hdr.extend_from_slice(&txid);
    hdr
}

/// Generate a header for the given profile and payload length.
fn generate_header(profile: &MimicryProfile, payload_len: usize) -> Vec<u8> {
    match profile {
        MimicryProfile::Dns => dns_header(),
        MimicryProfile::Quic { .. } => quic_header(),
        MimicryProfile::Sip => sip_header(payload_len),
        MimicryProfile::Stun => stun_header(payload_len),
        MimicryProfile::Custom(_) => dns_header(), // fallback
    }
}

// ─── Mimicry stream ─────────────────────────────────────────────────────────

/// Bidirectional stream that wraps data in protocol-mimicking frames.
///
/// Write frame: `[2-byte LE header_len][header bytes][2-byte LE payload_len][payload]`
/// Read frame:  same format, strip header and return payload.
struct MimicryStream {
    inner: BoxedStream,
    profile: MimicryProfile,
    read_buf: Vec<u8>,
    read_pos: usize,
    pending_frame: Option<MimicryPendingFrame>,
}

enum MimicryPendingFrame {
    /// Reading 2-byte header length.
    HeaderLen { buf: [u8; 2], pos: usize },
    /// Reading header bytes (to discard).
    Header { remaining: usize },
    /// Reading 2-byte payload length.
    PayloadLen { buf: [u8; 2], pos: usize },
    /// Reading payload bytes.
    Payload { data: Vec<u8>, remaining: usize },
}

impl AsyncRead for MimicryStream {
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

        // Initialize state machine if needed.
        if this.pending_frame.is_none() {
            this.pending_frame = Some(MimicryPendingFrame::HeaderLen {
                buf: [0; 2],
                pos: 0,
            });
        }

        // Drive the frame state machine by reading from inner.
        loop {
            match this.pending_frame.take() {
                Some(MimicryPendingFrame::HeaderLen { mut buf, mut pos }) => {
                    let mut read_buf = ReadBuf::new(&mut buf[pos..]);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                        Poll::Pending => {
                            this.pending_frame = Some(MimicryPendingFrame::HeaderLen { buf, pos });
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(())) => {
                            let filled = read_buf.filled().len();
                            if filled == 0 {
                                return Poll::Ready(Ok(())); // EOF
                            }
                            pos += filled;
                            if pos < 2 {
                                this.pending_frame =
                                    Some(MimicryPendingFrame::HeaderLen { buf, pos });
                                continue;
                            }
                            let header_len = u16::from_le_bytes(buf) as usize;
                            this.pending_frame = Some(MimicryPendingFrame::Header {
                                remaining: header_len,
                            });
                        }
                    }
                }
                Some(MimicryPendingFrame::Header { remaining }) => {
                    if remaining == 0 {
                        this.pending_frame = Some(MimicryPendingFrame::PayloadLen {
                            buf: [0; 2],
                            pos: 0,
                        });
                        continue;
                    }
                    // Read and discard header bytes.
                    let discard_len = remaining.min(4096);
                    let mut discard = vec![0u8; discard_len];
                    let mut read_buf = ReadBuf::new(&mut discard);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                        Poll::Pending => {
                            this.pending_frame = Some(MimicryPendingFrame::Header { remaining });
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(())) => {
                            let filled = read_buf.filled().len();
                            if filled == 0 {
                                return Poll::Ready(Ok(())); // EOF
                            }
                            this.pending_frame = Some(MimicryPendingFrame::Header {
                                remaining: remaining - filled,
                            });
                        }
                    }
                }
                Some(MimicryPendingFrame::PayloadLen { mut buf, mut pos }) => {
                    let mut read_buf = ReadBuf::new(&mut buf[pos..]);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                        Poll::Pending => {
                            this.pending_frame = Some(MimicryPendingFrame::PayloadLen { buf, pos });
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(())) => {
                            let filled = read_buf.filled().len();
                            if filled == 0 {
                                return Poll::Ready(Ok(())); // EOF
                            }
                            pos += filled;
                            if pos < 2 {
                                this.pending_frame =
                                    Some(MimicryPendingFrame::PayloadLen { buf, pos });
                                continue;
                            }
                            let payload_len = u16::from_le_bytes(buf) as usize;
                            if payload_len > MAX_FRAME_PAYLOAD {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    format!("mimicry frame too large: {payload_len}"),
                                )));
                            }
                            this.pending_frame = Some(MimicryPendingFrame::Payload {
                                data: Vec::with_capacity(payload_len),
                                remaining: payload_len,
                            });
                        }
                    }
                }
                Some(MimicryPendingFrame::Payload {
                    mut data,
                    remaining,
                }) => {
                    if remaining == 0 {
                        // Frame complete.
                        this.read_buf = data;
                        this.read_pos = 0;
                        this.pending_frame = None;

                        let out = &this.read_buf[this.read_pos..];
                        let n = out.len().min(buf.remaining());
                        buf.put_slice(&out[..n]);
                        this.read_pos += n;
                        if this.read_pos >= this.read_buf.len() {
                            this.read_buf.clear();
                            this.read_pos = 0;
                        }
                        return Poll::Ready(Ok(()));
                    }
                    let read_len = remaining.min(4096);
                    let mut tmp = vec![0u8; read_len];
                    let mut read_buf = ReadBuf::new(&mut tmp);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                        Poll::Pending => {
                            this.pending_frame =
                                Some(MimicryPendingFrame::Payload { data, remaining });
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(())) => {
                            let filled = read_buf.filled().len();
                            if filled == 0 {
                                return Poll::Ready(Ok(())); // EOF
                            }
                            data.extend_from_slice(&tmp[..filled]);
                            this.pending_frame = Some(MimicryPendingFrame::Payload {
                                data,
                                remaining: remaining - filled,
                            });
                        }
                    }
                }
                None => {
                    // Start reading a new frame.
                    this.pending_frame = Some(MimicryPendingFrame::HeaderLen {
                        buf: [0; 2],
                        pos: 0,
                    });
                }
            }
        }
    }
}

impl AsyncWrite for MimicryStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let this = self.get_mut();
        let chunk_len = buf.len().min(MAX_FRAME_PAYLOAD);

        // Generate protocol header.
        let header = generate_header(&this.profile, chunk_len);
        let header_len = header.len() as u16;
        let payload_len = chunk_len as u16;

        // Build frame: [2-byte LE header_len][header][2-byte LE payload_len][payload]
        let frame_size = 2 + header.len() + 2 + chunk_len;
        let mut frame = Vec::with_capacity(frame_size);
        frame.extend_from_slice(&header_len.to_le_bytes());
        frame.extend_from_slice(&header);
        frame.extend_from_slice(&payload_len.to_le_bytes());
        frame.extend_from_slice(&buf[..chunk_len]);

        match Pin::new(&mut this.inner).poll_write(cx, &frame) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(written)) => {
                if written < frame.len() {
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "partial mimicry frame write",
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

    const DNS_HEADER_LEN: usize = 12;
    const QUIC_HEADER_LEN: usize = 1 + 4 + 1 + 8 + 1 + 8; // 23
    const STUN_HEADER_LEN: usize = 20;

    async fn mimicry_roundtrip(profile: MimicryProfile) {
        let transport = MimicryTransport::new(profile);
        let (client_raw, server_raw) = tokio::io::duplex(32768);

        let (client_result, server_result) = tokio::join!(
            transport.wrap_outbound(BoxedStream::new(client_raw)),
            transport.accept_inbound(BoxedStream::new(server_raw)),
        );

        let mut client = client_result.expect("client wrap");
        let mut server = server_result.expect("server wrap");

        let msg = b"mimicry test payload";
        client.write_all(msg).await.expect("write");
        client.flush().await.expect("flush");

        let mut buf = vec![0u8; msg.len()];
        server.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, msg);
    }

    #[tokio::test]
    async fn mimicry_dns_roundtrip() {
        mimicry_roundtrip(MimicryProfile::Dns).await;
    }

    #[tokio::test]
    async fn mimicry_quic_roundtrip() {
        mimicry_roundtrip(MimicryProfile::Quic {
            sni: "www.google.com".into(),
        })
        .await;
    }

    #[tokio::test]
    async fn mimicry_sip_roundtrip() {
        mimicry_roundtrip(MimicryProfile::Sip).await;
    }

    #[tokio::test]
    async fn mimicry_stun_roundtrip() {
        mimicry_roundtrip(MimicryProfile::Stun).await;
    }

    #[tokio::test]
    async fn mimicry_large_payload() {
        let transport = MimicryTransport::new(MimicryProfile::Dns);
        let (client_raw, server_raw) = tokio::io::duplex(256 * 1024);

        let (client_result, server_result) = tokio::join!(
            transport.wrap_outbound(BoxedStream::new(client_raw)),
            transport.accept_inbound(BoxedStream::new(server_raw)),
        );

        let mut client = client_result.expect("client wrap");
        let mut server = server_result.expect("server wrap");

        let msg = vec![0xCD_u8; 8000];
        client.write_all(&msg).await.expect("write");
        client.flush().await.expect("flush");
        drop(client);

        let mut buf = Vec::new();
        server.read_to_end(&mut buf).await.expect("read");
        assert_eq!(buf, msg);
    }

    #[test]
    fn dns_header_has_correct_length() {
        let hdr = dns_header();
        assert_eq!(hdr.len(), DNS_HEADER_LEN);
        // Flags should be 0x0100 (standard query).
        assert_eq!(hdr[2], 0x01);
        assert_eq!(hdr[3], 0x00);
    }

    #[test]
    fn quic_header_has_correct_structure() {
        let hdr = quic_header();
        assert_eq!(hdr.len(), QUIC_HEADER_LEN);
        // First byte: long header + Initial.
        assert_eq!(hdr[0], 0xC0);
        // Version: QUIC v1.
        assert_eq!(&hdr[1..5], &[0x00, 0x00, 0x00, 0x01]);
    }

    #[test]
    fn stun_header_has_magic_cookie() {
        let hdr = stun_header(100);
        assert_eq!(hdr.len(), STUN_HEADER_LEN);
        // Binding Request.
        assert_eq!(&hdr[0..2], &[0x00, 0x01]);
        // Magic cookie.
        assert_eq!(&hdr[4..8], &[0x21, 0x12, 0xA4, 0x42]);
    }

    #[test]
    fn mimicry_transport_name() {
        let t = MimicryTransport::new(MimicryProfile::Dns);
        assert_eq!(t.name(), "mimicry");
    }
}
