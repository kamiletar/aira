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
#[cfg(feature = "reality")]
pub mod fingerprint;
#[cfg(feature = "mimicry")]
pub mod mimicry;
#[cfg(feature = "obfs4")]
pub mod obfs;
#[cfg(feature = "reality")]
pub mod reality;
#[cfg(feature = "tor")]
pub mod tor;

// ─── Types ──────────────────────────────────────────────────────────────────

/// A boxed async bidirectional stream — object-safe return type for [`AiraTransport`].
///
/// Wraps separate read/write halves because Rust trait objects cannot combine
/// `AsyncRead + AsyncWrite` in a single `dyn` (only one non-auto trait allowed).
pub struct BoxedStream {
    reader: Pin<Box<dyn AsyncRead + Send + Unpin>>,
    writer: Pin<Box<dyn AsyncWrite + Send + Unpin>>,
}

impl fmt::Debug for BoxedStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoxedStream").finish_non_exhaustive()
    }
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

    /// REALITY authentication failure.
    #[error("REALITY auth error: {0}")]
    RealityAuth(String),

    /// Tor transport error.
    #[error("Tor error: {0}")]
    Tor(String),
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
    /// REALITY-like TLS camouflage — traffic looks like TLS to a legitimate site.
    Reality {
        /// Target domain for SNI (e.g. "www.apple.com").
        sni: String,
        /// Browser fingerprint to mimic in TLS `ClientHello`.
        fingerprint: BrowserFingerprint,
    },
    /// Tor transport — route traffic through the Tor network.
    Tor {
        /// Expose as a Tor hidden service (.onion).
        hidden_service: bool,
    },
}

/// Browser TLS fingerprint to mimic in REALITY transport.
///
/// Each variant produces a `ClientHello` matching the specified browser's
/// cipher suite ordering, extension list, and supported groups.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum BrowserFingerprint {
    /// Chrome / Chromium TLS 1.3 fingerprint.
    #[default]
    Chrome,
    /// Firefox TLS 1.3 fingerprint.
    Firefox,
    /// Safari TLS 1.3 fingerprint.
    Safari,
}

impl fmt::Display for BrowserFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Chrome => write!(f, "chrome"),
            Self::Firefox => write!(f, "firefox"),
            Self::Safari => write!(f, "safari"),
        }
    }
}

impl FromStr for BrowserFingerprint {
    type Err = TransportError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "chrome" => Ok(Self::Chrome),
            "firefox" => Ok(Self::Firefox),
            "safari" => Ok(Self::Safari),
            _ => Err(TransportError::Config(format!(
                "unknown browser fingerprint: {s}"
            ))),
        }
    }
}

/// Secrets required by certain transports (not serialized into [`TransportMode`]).
pub struct TransportSecrets {
    /// Pre-shared key for REALITY authentication (X25519).
    pub reality_psk: Option<zeroize::Zeroizing<[u8; 32]>>,
}

impl fmt::Display for TransportMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direct => write!(f, "direct"),
            Self::Obfs4 => write!(f, "obfs4"),
            Self::Mimicry(profile) => write!(f, "mimicry:{profile}"),
            Self::CdnRelay { endpoint } => write!(f, "cdn:{endpoint}"),
            Self::Reality { sni, fingerprint } => write!(f, "reality:{sni}:{fingerprint}"),
            Self::Tor { hidden_service } => {
                if *hidden_service {
                    write!(f, "tor:hidden")
                } else {
                    write!(f, "tor")
                }
            }
        }
    }
}

impl FromStr for TransportMode {
    type Err = TransportError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "direct" => Ok(Self::Direct),
            "obfs4" => Ok(Self::Obfs4),
            "tor" => Ok(Self::Tor {
                hidden_service: false,
            }),
            "tor:hidden" => Ok(Self::Tor {
                hidden_service: true,
            }),
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
            _ if s.starts_with("reality:") => {
                // Format: "reality:<sni>:<fingerprint>"
                let rest = &s["reality:".len()..];
                let parts: Vec<&str> = rest.splitn(2, ':').collect();
                if parts.is_empty() || parts[0].is_empty() {
                    return Err(TransportError::Config(
                        "REALITY requires SNI hostname".into(),
                    ));
                }
                let sni = parts[0].to_string();
                let fingerprint = if parts.len() > 1 {
                    parts[1].parse::<BrowserFingerprint>()?
                } else {
                    BrowserFingerprint::default()
                };
                Ok(Self::Reality { sni, fingerprint })
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
///
/// For transports that require secrets (e.g. REALITY PSK), pass [`TransportSecrets`].
/// Passing `None` is fine for transports that don't need secrets.
pub fn create_transport(
    mode: &TransportMode,
    #[cfg_attr(not(feature = "reality"), allow(unused_variables))]
    secrets: Option<&TransportSecrets>,
) -> Result<Arc<dyn AiraTransport>, TransportError> {
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

        #[cfg(feature = "reality")]
        TransportMode::Reality { sni, fingerprint } => {
            let psk = secrets.and_then(|s| s.reality_psk.clone()).ok_or_else(|| {
                TransportError::Config("REALITY transport requires PSK in secrets".into())
            })?;
            Ok(Arc::new(reality::RealityTransport::new(
                reality::RealityConfig {
                    sni: sni.clone(),
                    psk,
                    fingerprint: *fingerprint,
                    fallback_addr: None,
                },
            )))
        }
        #[cfg(not(feature = "reality"))]
        TransportMode::Reality { .. } => Err(TransportError::NotAvailable {
            feature: "reality".into(),
        }),

        #[cfg(feature = "tor")]
        TransportMode::Tor { hidden_service } => {
            Ok(Arc::new(tor::TorTransport::new(tor::TorConfig {
                hidden_service: *hidden_service,
                pool_size: 3,
            })))
        }
        #[cfg(not(feature = "tor"))]
        TransportMode::Tor { .. } => Err(TransportError::NotAvailable {
            feature: "tor".into(),
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
            TransportMode::Reality {
                sni: "www.apple.com".into(),
                fingerprint: BrowserFingerprint::Chrome,
            },
            TransportMode::Reality {
                sni: "www.bing.com".into(),
                fingerprint: BrowserFingerprint::Firefox,
            },
            TransportMode::Tor {
                hidden_service: false,
            },
            TransportMode::Tor {
                hidden_service: true,
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
        assert!("reality:".parse::<TransportMode>().is_err());
    }

    #[test]
    fn factory_direct_always_available() {
        let t = create_transport(&TransportMode::Direct, None).expect("direct must work");
        assert_eq!(t.name(), "direct");
    }

    #[test]
    fn browser_fingerprint_display_roundtrip() {
        for fp in [
            BrowserFingerprint::Chrome,
            BrowserFingerprint::Firefox,
            BrowserFingerprint::Safari,
        ] {
            let s = fp.to_string();
            let parsed: BrowserFingerprint = s.parse().expect("parse failed");
            assert_eq!(parsed, fp);
        }
    }

    #[test]
    fn browser_fingerprint_default_is_chrome() {
        assert_eq!(BrowserFingerprint::default(), BrowserFingerprint::Chrome);
    }

    #[test]
    fn reality_mode_default_fingerprint() {
        // "reality:www.apple.com" should default to Chrome fingerprint
        let mode: TransportMode = "reality:www.apple.com".parse().expect("parse");
        assert_eq!(
            mode,
            TransportMode::Reality {
                sni: "www.apple.com".into(),
                fingerprint: BrowserFingerprint::Chrome,
            }
        );
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
