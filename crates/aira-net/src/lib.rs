//! aira-net — network layer: iroh QUIC, NAT traversal, relay, pluggable transports.
//!
//! # Key modules
//!
//! - [`endpoint`] — iroh 0.97 Endpoint wrapper, QUIC config
//! - [`connection`] — session management per peer, framing utilities
//! - [`discovery`] — peer discovery + invitation links
//! - [`relay`] — store-and-forward relay with pairwise mailboxes (SPEC.md §6.5)
//! - [`ratelimit`] — connection tiers + GCRA rate limiting (SPEC.md §11B)
//! - [`transport`] — pluggable transport stack (SPEC.md §11A)

#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

pub mod connection;
pub mod discovery;
pub mod endpoint;
pub mod protocol;
pub mod ratelimit;
pub mod relay;
pub mod transport;

/// ALPN protocol identifiers.
pub mod alpn {
    pub const CHAT: &[u8] = b"aira/1/chat";
    pub const FILE: &[u8] = b"aira/1/file";
    pub const HANDSHAKE: &[u8] = b"aira/1/handshake";
    pub const RELAY: &[u8] = b"aira/1/relay";
}

// ─── Errors ──────────────────────────────────────────────────────────────────

/// Network layer errors.
#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error("failed to bind endpoint: {0}")]
    Bind(String),

    #[error("connection failed: {0}")]
    Connect(String),

    #[error("connection closed: {0}")]
    ConnectionClosed(String),

    #[error("stream error: {0}")]
    Stream(String),

    #[error("relay error: {0}")]
    Relay(String),

    #[error("mailbox full ({current}/{max} envelopes)")]
    MailboxFull { current: usize, max: usize },

    #[error("mailbox not found")]
    MailboxNotFound,

    #[error("envelope too large: {size} bytes (max {max})")]
    EnvelopeTooLarge { size: usize, max: usize },

    #[error("rate limited")]
    RateLimited,

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("discovery error: {0}")]
    Discovery(String),

    #[error("peer not found")]
    PeerNotFound,

    #[error("operation timed out")]
    Timeout,

    #[error("iroh error: {0}")]
    Iroh(#[from] anyhow::Error),
}

impl From<postcard::Error> for NetError {
    fn from(e: postcard::Error) -> Self {
        Self::Serialization(e.to_string())
    }
}
