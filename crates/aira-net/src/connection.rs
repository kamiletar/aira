//! Session management — one logical session per peer.
//!
//! Tracks connection state, tier (Verified/Known/Stranger), and
//! provides framing utilities for length-prefixed postcard messages
//! over QUIC streams.
//!
//! See SPEC.md §5, §11B.

use std::collections::HashMap;
use std::time::Instant;

use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::EndpointId;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::NetError;

// ─── Framing ─────────────────────────────────────────────────────────────────

/// Maximum framed message size (256 KB).
const MAX_FRAME_SIZE: u32 = 256 * 1024;

/// Write a length-prefixed postcard-encoded message to a QUIC send stream.
///
/// Format: `[u32 big-endian length][postcard bytes]`
pub async fn write_framed<T: Serialize>(stream: &mut SendStream, msg: &T) -> Result<(), NetError> {
    let bytes = postcard::to_allocvec(msg)?;
    let len = u32::try_from(bytes.len()).map_err(|_| NetError::EnvelopeTooLarge {
        size: bytes.len(),
        max: MAX_FRAME_SIZE as usize,
    })?;
    if len > MAX_FRAME_SIZE {
        return Err(NetError::EnvelopeTooLarge {
            size: bytes.len(),
            max: MAX_FRAME_SIZE as usize,
        });
    }
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|e| NetError::Stream(e.to_string()))?;
    stream
        .write_all(&bytes)
        .await
        .map_err(|e| NetError::Stream(e.to_string()))?;
    Ok(())
}

/// Read a length-prefixed postcard-encoded message from a QUIC recv stream.
pub async fn read_framed<T: for<'de> Deserialize<'de>>(
    stream: &mut RecvStream,
) -> Result<T, NetError> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| NetError::Stream(e.to_string()))?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_SIZE {
        return Err(NetError::EnvelopeTooLarge {
            size: len as usize,
            max: MAX_FRAME_SIZE as usize,
        });
    }
    let mut buf = vec![0u8; len as usize];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(|e| NetError::Stream(e.to_string()))?;
    postcard::from_bytes(&buf).map_err(Into::into)
}

// ─── Peer session management ─────────────────────────────────────────────────

/// Trust tier for a peer — determines rate limits and capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerTier {
    /// Verified contact — unlimited messaging.
    Verified,
    /// Known peer (added but not yet verified) — 100 msg/min.
    Known,
    /// Stranger — 5 msg/min + `PoW` required.
    Stranger,
}

/// Connection lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Active QUIC connection.
    Connected,
    /// No active connection.
    Disconnected,
    /// PQXDH handshake in progress.
    Handshaking,
}

/// Per-peer session state tracked by the connection manager.
#[derive(Debug)]
pub struct PeerSession {
    /// Peer's endpoint identity.
    pub endpoint_id: EndpointId,
    /// Trust tier.
    pub tier: PeerTier,
    /// Current connection state.
    pub state: ConnectionState,
    /// Active QUIC connection handle (if connected).
    pub connection: Option<Connection>,
    /// Last time we saw activity from this peer.
    pub last_seen: Instant,
}

impl PeerSession {
    /// Create a new peer session in `Disconnected` state.
    #[must_use]
    pub fn new(endpoint_id: EndpointId, tier: PeerTier) -> Self {
        Self {
            endpoint_id,
            tier,
            state: ConnectionState::Disconnected,
            connection: None,
            last_seen: Instant::now(),
        }
    }
}

/// Manages per-peer sessions.
///
/// Thread-safe via [`RwLock`] — reads (lookups) are more frequent than writes.
#[derive(Debug, Default)]
pub struct ConnectionManager {
    peers: RwLock<HashMap<EndpointId, PeerSession>>,
}

impl ConnectionManager {
    /// Create an empty connection manager.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register or update a peer session.
    pub async fn upsert(&self, session: PeerSession) {
        let mut peers = self.peers.write().await;
        peers.insert(session.endpoint_id, session);
    }

    /// Get the tier for a peer, or `None` if unknown.
    pub async fn tier(&self, id: &EndpointId) -> Option<PeerTier> {
        let peers = self.peers.read().await;
        peers.get(id).map(|s| s.tier)
    }

    /// Update the connection handle and state for a peer.
    pub async fn set_connected(&self, id: &EndpointId, conn: Connection) {
        let mut peers = self.peers.write().await;
        if let Some(session) = peers.get_mut(id) {
            session.connection = Some(conn);
            session.state = ConnectionState::Connected;
            session.last_seen = Instant::now();
        }
    }

    /// Mark a peer as disconnected.
    pub async fn set_disconnected(&self, id: &EndpointId) {
        let mut peers = self.peers.write().await;
        if let Some(session) = peers.get_mut(id) {
            session.connection = None;
            session.state = ConnectionState::Disconnected;
        }
    }

    /// Update the tier for a peer.
    pub async fn set_tier(&self, id: &EndpointId, tier: PeerTier) {
        let mut peers = self.peers.write().await;
        if let Some(session) = peers.get_mut(id) {
            session.tier = tier;
        }
    }

    /// Remove a peer entirely.
    pub async fn remove(&self, id: &EndpointId) -> Option<PeerSession> {
        let mut peers = self.peers.write().await;
        peers.remove(id)
    }

    /// Check if a peer is currently connected.
    pub async fn is_connected(&self, id: &EndpointId) -> bool {
        let peers = self.peers.read().await;
        peers
            .get(id)
            .is_some_and(|s| s.state == ConnectionState::Connected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_peer_session_lifecycle() {
        let mgr = ConnectionManager::new();
        let id = EndpointId::from_bytes(&[1u8; 32]).unwrap();

        // Initially empty
        assert!(mgr.tier(&id).await.is_none());
        assert!(!mgr.is_connected(&id).await);

        // Add a stranger
        let session = PeerSession::new(id, PeerTier::Stranger);
        mgr.upsert(session).await;
        assert_eq!(mgr.tier(&id).await, Some(PeerTier::Stranger));

        // Upgrade to verified
        mgr.set_tier(&id, PeerTier::Verified).await;
        assert_eq!(mgr.tier(&id).await, Some(PeerTier::Verified));

        // Remove
        let removed = mgr.remove(&id).await;
        assert!(removed.is_some());
        assert!(mgr.tier(&id).await.is_none());
    }

    #[tokio::test]
    async fn test_framing_roundtrip() {
        // Test framing with in-process QUIC connection
        let ep1 = crate::endpoint::AiraEndpoint::bind_for_test(None)
            .await
            .unwrap();
        let ep2 = crate::endpoint::AiraEndpoint::bind_for_test(None)
            .await
            .unwrap();

        let ep2_addr = ep2.addr();

        // Server: accept and read a framed message
        let ep2_clone = ep2.clone();
        let server = tokio::spawn(async move {
            let incoming = ep2_clone.accept().await.expect("no incoming");
            let conn = incoming.await.expect("accept failed");
            let (_, mut recv) = conn.accept_bi().await.expect("accept_bi failed");
            let msg: String = read_framed(&mut recv).await.expect("read_framed failed");
            msg
        });

        // Client: connect and write a framed message
        let conn = ep1.connect(ep2_addr, crate::alpn::CHAT).await.unwrap();
        let (mut send, _) = conn.open_bi().await.expect("open_bi failed");
        write_framed(&mut send, &"hello aira".to_string())
            .await
            .unwrap();
        send.finish().expect("finish failed");

        let received = server.await.unwrap();
        assert_eq!(received, "hello aira");

        ep1.close().await;
        ep2.close().await;
    }
}
