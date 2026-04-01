//! aira-net — network layer: iroh QUIC, NAT traversal, relay, pluggable transports.
//!
//! # Key modules
//!
//! - [`endpoint`] — iroh 0.97 Endpoint wrapper, QUIC config
//! - [`connection`] — session management per peer
//! - [`discovery`] — DHT peer discovery + direct add
//! - [`relay`] — store-and-forward relay with pairwise mailboxes (SPEC.md §6.5)
//! - [`ratelimit`] — connection tiers + GCRA rate limiting (SPEC.md §11B)
//! - [`transport`] — pluggable transport stack (SPEC.md §11A)
//!   - `transport::direct` — plain QUIC
//!   - `transport::obfs` — obfs4/o5 via ptrs
//!   - `transport::mimicry` — protocol mimicry (DNS/QUIC/SIP)
//!   - `transport::cdn` — CDN relay (Cloudflare Worker)
//!   - `transport::reality` — REALITY-like TLS camouflage (v0.3)
//!   - `transport::tor` — Tor via arti (v0.3, feature = "tor")

#![warn(clippy::all, clippy::pedantic)]

pub mod connection;
pub mod discovery;
pub mod endpoint;
pub mod relay;
pub mod ratelimit;
pub mod transport;

/// ALPN protocol identifiers.
pub mod alpn {
    pub const CHAT: &[u8] = b"aira/1/chat";
    pub const FILE: &[u8] = b"aira/1/file";
    pub const HANDSHAKE: &[u8] = b"aira/1/handshake";
    pub const RELAY: &[u8] = b"aira/1/relay";
}
