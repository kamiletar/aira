//! Pluggable transport stack for DPI resistance.
//!
//! Each layer is independently configurable:
//! `aira-core (encrypted) → Padding → Obfuscation → Transport`
//!
//! See SPEC.md §11A.
//!
//! # Transport modes
//!
//! - [`DirectTransport`] — plain QUIC via iroh, no obfuscation (default)
//! - [`ObfsTransport`] — XOR keystream obfuscation via BLAKE3 KDF (feature `obfs4`)
//! - [`MimicryTransport`] — CPS protocol mimicry: DNS/QUIC/SIP/STUN (feature `mimicry`)
//! - [`CdnRelayTransport`] — HTTPS tunneling via CDN endpoint (feature `cdn`)
//!
//! # Future (M12)
//!
//! - REALITY-like TLS camouflage (feature `reality`)
//! - Tor via arti (feature `tor`)

use std::fmt;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};

#[cfg(feature = "cdn")]
pub mod cdn;
pub mod direct;
#[cfg(feature = "mimicry")]
pub mod mimicry;
#[cfg(feature = "obfs4")]
pub mod obfs;
// pub mod reality; // M12: REALITY-like TLS camouflage
// pub mod tor;     // M12: Tor via arti (feature = "tor")

// ─── Types ──────────────────────────────────────────────────────────────────

/// A boxed async bidirectional stream — object-safe return type for [`AiraTransport`].
///
/// Wraps separate read/write halves because Rust trait objects cannot combine
/// `AsyncRead + AsyncWrite` in a single `dyn` (only one non-auto trait allowed).
pub struct BoxedStream {
    reader: Pin<Box<dyn AsyncRead + Send + Unpin>>,
    writer: Pin<Box<dyn AsyncWrite + Send + Unpin>>,
}

impl BoxedStream {
    /// Wrap any `AsyncRead + AsyncWrite + Send + Unpin` stream.
    pub fn new<S>(stream: S) -> Self
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            reader: Box::pin(reader),
            writer: Box::pin(writer),
        }
    }
}

impl AsyncRead for BoxedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.reader.as_mut().poll_read(cx, buf)
    }
}

impl AsyncWrite for BoxedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.writer.as_mut().poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.writer.as_mut().poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.writer.as_mut().poll_shutdown(cx)
    }
}

/// Errors from the transport layer.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// I/O error in the underlying stream.
    #[error("transport I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Handshake failed (e.g. nonce exchange in obfs).
    #[error("transport handshake failed: {0}")]
    Handshake(String),

    /// Invalid configuration (e.g. unknown mode string).
    #[error("invalid transport configuration: {0}")]
    Config(String),

    /// Feature not compiled in.
    #[error("transport not available: {feature} (compile with --features {feature})")]
    NotAvailable { feature: String },

    /// CDN endpoint error.
    #[error("CDN relay error: {0}")]
    CdnRelay(String),
}

// ─── Transport mode ─────────────────────────────────────────────────────────

/// Active transport mode — persisted in storage, sent over IPC as string.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransportMode {
    /// Plain QUIC via iroh — no obfuscation (default).
    #[default]
    Direct,
    /// XOR keystream obfuscation via BLAKE3 KDF.
    Obfs4,
    /// CPS protocol mimicry — packets look like another protocol.
    Mimicry(MimicryProfile),
    /// HTTPS tunneling via CDN endpoint.
    CdnRelay {
        /// CDN worker endpoint URL.
        endpoint: String,
    },
}


impl fmt::Display for TransportMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direct => write!(f, "direct"),
            Self::Obfs4 => write!(f, "obfs4"),
            Self::Mimicry(profile) => write!(f, "mimicry:{profile}"),
            Self::CdnRelay { endpoint } => write!(f, "cdn:{endpoint}"),
        }
    }
}

impl FromStr for TransportMode {
    type Err = TransportError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "direct" => Ok(Self::Direct),
            "obfs4" => Ok(Self::Obfs4),
            _ if s.starts_with("mimicry:") => {
                let profile_str = &s["mimicry:".len()..];
                let profile = profile_str.parse::<MimicryProfile>()?;
                Ok(Self::Mimicry(profile))
            }
            _ if s.starts_with("cdn:") => {
                let endpoint = s["cdn:".len()..].to_string();
                if endpoint.is_empty() {
                    return Err(TransportError::Config(
                        "CDN endpoint URL cannot be empty".into(),
                    ));
                }
                Ok(Self::CdnRelay { endpoint })
            }
            _ => Err(TransportError::Config(format!(
                "unknown transport mode: {s}"
            ))),
        }
    }
}

// ─── Mimicry profiles (CPS — Custom Protocol Signature) ────────────────────

/// Protocol to mimic when using CPS transport.
///
/// See SPEC.md §11A.4 for CPS specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MimicryProfile {
    /// Packets look like DNS queries/responses.
    Dns,
    /// Packets look like QUIC/HTTP3 to a legitimate server.
    Quic {
        /// SNI hostname to mimic (e.g. "www.google.com").
        sni: String,
    },
    /// Packets look like SIP (`VoIP`) messages.
    Sip,
    /// Packets look like STUN (WebRTC NAT traversal) messages.
    Stun,
    /// Custom CPS signature.
    Custom(CpsSignature),
}

impl fmt::Display for MimicryProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dns => write!(f, "dns"),
            Self::Quic { sni } => write!(f, "quic:{sni}"),
            Self::Sip => write!(f, "sip"),
            Self::Stun => write!(f, "stun"),
            Self::Custom(_) => write!(f, "custom"),
        }
    }
}

impl FromStr for MimicryProfile {
    type Err = TransportError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "dns" => Ok(Self::Dns),
            "sip" => Ok(Self::Sip),
            "stun" => Ok(Self::Stun),
            _ if s.starts_with("quic:") => {
                let sni = s["quic:".len()..].to_string();
                if sni.is_empty() {
                    return Err(TransportError::Config(
                        "QUIC mimicry requires SNI hostname".into(),
                    ));
                }
                Ok(Self::Quic { sni })
            }
            _ => Err(TransportError::Config(format!(
                "unknown mimicry profile: {s}"
            ))),
        }
    }
}

/// CPS — Custom Protocol Signature (`AmneziaWG` 2.0 inspired).
///
/// A template-based system for constructing protocol-mimicking packet headers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpsSignature {
    /// Header template tokens.
    pub template: Vec<CpsToken>,
    /// Allowed total packet size range `(min, max)`.
    pub size_range: (usize, usize),
}

/// Token in a CPS header template.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CpsToken {
    /// Fixed bytes (magic number / protocol header).
    Bytes(Vec<u8>),
    /// Current timestamp (4 bytes, big-endian seconds since epoch).
    Timestamp,
    /// N cryptographically random bytes.
    Random(usize),
    /// N random ASCII alphanumeric characters.
    RandomAlphaNum(usize),
    /// N random ASCII decimal digits.
    RandomDigits(usize),
}

// ─── Transport trait ────────────────────────────────────────────────────────

/// Abstraction over pluggable transports.
///
/// Wraps an existing async stream (typically a QUIC byte stream) in an
/// obfuscation layer. Each implementation applies a different strategy
/// (XOR, protocol mimicry, HTTP tunneling, etc.).
///
/// The trait is object-safe (`BoxedStream` instead of `impl Trait`) so
/// the daemon can hold `Arc<dyn AiraTransport>` and swap transports at
/// runtime via the `/transport` CLI command.
#[async_trait::async_trait]
pub trait AiraTransport: Send + Sync + fmt::Debug {
    /// Wrap an outbound connection in the selected transport.
    async fn wrap_outbound(&self, stream: BoxedStream) -> Result<BoxedStream, TransportError>;

    /// Accept and unwrap an inbound connection.
    async fn accept_inbound(&self, stream: BoxedStream) -> Result<BoxedStream, TransportError>;

    /// Human-readable transport name (for logging/status).
    fn name(&self) -> &'static str;
}

// ─── Factory ────────────────────────────────────────────────────────────────

/// Create a transport implementation from a [`TransportMode`].
///
/// Returns `TransportError::NotAvailable` if the required feature is not compiled in.
pub fn create_transport(mode: &TransportMode) -> Result<Arc<dyn AiraTransport>, TransportError> {
    match mode {
        TransportMode::Direct => Ok(Arc::new(direct::DirectTransport)),

        #[cfg(feature = "obfs4")]
        TransportMode::Obfs4 => Ok(Arc::new(obfs::ObfsTransport::new())),
        #[cfg(not(feature = "obfs4"))]
        TransportMode::Obfs4 => Err(TransportError::NotAvailable {
            feature: "obfs4".into(),
        }),

        #[cfg(feature = "mimicry")]
        TransportMode::Mimicry(profile) => {
            Ok(Arc::new(mimicry::MimicryTransport::new(profile.clone())))
        }
        #[cfg(not(feature = "mimicry"))]
        TransportMode::Mimicry(_) => Err(TransportError::NotAvailable {
            feature: "mimicry".into(),
        }),

        #[cfg(feature = "cdn")]
        TransportMode::CdnRelay { endpoint } => {
            Ok(Arc::new(cdn::CdnRelayTransport::new(endpoint.clone())))
        }
        #[cfg(not(feature = "cdn"))]
        TransportMode::CdnRelay { .. } => Err(TransportError::NotAvailable {
            feature: "cdn".into(),
        }),
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_mode_display_roundtrip() {
        let modes = [
            TransportMode::Direct,
            TransportMode::Obfs4,
            TransportMode::Mimicry(MimicryProfile::Dns),
            TransportMode::Mimicry(MimicryProfile::Quic {
                sni: "www.google.com".into(),
            }),
            TransportMode::Mimicry(MimicryProfile::Sip),
            TransportMode::Mimicry(MimicryProfile::Stun),
            TransportMode::CdnRelay {
                endpoint: "https://worker.example.com".into(),
            },
        ];

        for mode in &modes {
            let s = mode.to_string();
            let parsed: TransportMode = s.parse().expect("parse failed");
            assert_eq!(&parsed, mode, "roundtrip failed for {s}");
        }
    }

    #[test]
    fn transport_mode_postcard_roundtrip() {
        let mode = TransportMode::Mimicry(MimicryProfile::Quic {
            sni: "example.com".into(),
        });
        let bytes = postcard::to_allocvec(&mode).expect("serialize");
        let decoded: TransportMode = postcard::from_bytes(&bytes).expect("deserialize");
        assert_eq!(decoded, mode);
    }

    #[test]
    fn transport_mode_default_is_direct() {
        assert_eq!(TransportMode::default(), TransportMode::Direct);
    }

    #[test]
    fn transport_mode_parse_errors() {
        assert!("unknown".parse::<TransportMode>().is_err());
        assert!("cdn:".parse::<TransportMode>().is_err());
        assert!("mimicry:quic:".parse::<TransportMode>().is_err());
        assert!("mimicry:unknown".parse::<TransportMode>().is_err());
    }

    #[test]
    fn factory_direct_always_available() {
        let t = create_transport(&TransportMode::Direct).expect("direct must work");
        assert_eq!(t.name(), "direct");
    }

    #[test]
    fn cps_signature_postcard_roundtrip() {
        let sig = CpsSignature {
            template: vec![
                CpsToken::Bytes(vec![0x00, 0x01]),
                CpsToken::Timestamp,
                CpsToken::Random(16),
                CpsToken::RandomAlphaNum(8),
                CpsToken::RandomDigits(4),
            ],
            size_range: (64, 512),
        };
        let bytes = postcard::to_allocvec(&sig).expect("serialize");
        let decoded: CpsSignature = postcard::from_bytes(&bytes).expect("deserialize");
        assert_eq!(decoded, sig);
    }
}
