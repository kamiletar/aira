//! iroh 0.97 Endpoint wrapper with QUIC configuration.
//!
//! Provides [`AiraEndpoint`] — a thin wrapper around [`iroh::Endpoint`] configured
//! with Aira's ALPN protocols and sensible QUIC defaults.
//!
//! See SPEC.md §5.1, §11B.3.

use std::fmt;
use std::time::Duration;

use iroh::endpoint::{self, presets, IdleTimeout, VarInt};
use iroh::{Endpoint, EndpointAddr, EndpointId, SecretKey};

use crate::NetError;

/// Default max concurrent bidirectional streams per connection.
const MAX_BIDI_STREAMS: u32 = 128;
/// Default max concurrent unidirectional streams per connection.
const MAX_UNI_STREAMS: u32 = 128;
/// Default idle timeout.
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
/// Default keep-alive interval.
const KEEP_ALIVE: Duration = Duration::from_secs(15);

/// Aira endpoint wrapper around [`iroh::Endpoint`].
///
/// Configures QUIC with Aira's ALPN protocols, stream limits, and timeouts.
#[derive(Clone)]
pub struct AiraEndpoint {
    inner: Endpoint,
}

impl fmt::Debug for AiraEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AiraEndpoint")
            .field("id", &self.id().to_string())
            .finish()
    }
}

impl AiraEndpoint {
    /// Bind a new Aira endpoint with default n0 discovery and relay.
    ///
    /// If `secret_key` is `None`, a random key is generated.
    pub async fn bind(secret_key: Option<SecretKey>) -> Result<Self, NetError> {
        Self::bind_inner(secret_key, false).await
    }

    /// Bind a new Aira endpoint for testing (empty builder, no discovery service).
    ///
    /// Uses iroh's default relay for connectivity between test endpoints.
    pub async fn bind_for_test(secret_key: Option<SecretKey>) -> Result<Self, NetError> {
        Self::bind_inner(secret_key, true).await
    }

    async fn bind_inner(secret_key: Option<SecretKey>, is_test: bool) -> Result<Self, NetError> {
        let all_alpns = vec![
            crate::alpn::CHAT.to_vec(),
            crate::alpn::FILE.to_vec(),
            crate::alpn::HANDSHAKE.to_vec(),
            crate::alpn::RELAY.to_vec(),
        ];

        let idle_timeout: IdleTimeout = IDLE_TIMEOUT
            .try_into()
            .map_err(|e: iroh::endpoint::VarIntBoundsExceeded| NetError::Bind(e.to_string()))?;

        let transport_config = endpoint::QuicTransportConfig::builder()
            .max_concurrent_bidi_streams(VarInt::from_u32(MAX_BIDI_STREAMS))
            .max_concurrent_uni_streams(VarInt::from_u32(MAX_UNI_STREAMS))
            .max_idle_timeout(Some(idle_timeout))
            .keep_alive_interval(KEEP_ALIVE)
            .build();

        // For tests: empty builder (no discovery, default relay for loopback connectivity).
        // For production: n0 preset with DNS discovery + relay.
        let mut builder = if is_test {
            Endpoint::empty_builder()
        } else {
            Endpoint::builder(presets::N0)
        };

        builder = builder.alpns(all_alpns).transport_config(transport_config);

        if let Some(key) = secret_key {
            builder = builder.secret_key(key);
        }

        let endpoint = builder
            .bind()
            .await
            .map_err(|e| NetError::Bind(e.to_string()))?;

        Ok(Self { inner: endpoint })
    }

    /// Returns the endpoint's unique identity.
    #[must_use]
    pub fn id(&self) -> EndpointId {
        self.inner.id()
    }

    /// Returns the full address of this endpoint (id + transport addresses).
    #[must_use]
    pub fn addr(&self) -> EndpointAddr {
        self.inner.addr()
    }

    /// Waits until the endpoint has at least one reachable address.
    pub async fn online(&self) {
        self.inner.online().await;
    }

    /// Connect to a remote endpoint.
    pub async fn connect(
        &self,
        addr: impl Into<EndpointAddr>,
        alpn: &[u8],
    ) -> Result<endpoint::Connection, NetError> {
        self.inner
            .connect(addr, alpn)
            .await
            .map_err(|e| NetError::Connect(e.to_string()))
    }

    /// Accept an incoming connection.
    ///
    /// Returns `None` if the endpoint is closed.
    pub async fn accept(&self) -> Option<endpoint::Incoming> {
        self.inner.accept().await
    }

    /// Returns a reference to the inner iroh `Endpoint`.
    ///
    /// Useful for building a [`iroh::protocol::Router`].
    #[must_use]
    pub fn endpoint(&self) -> &Endpoint {
        &self.inner
    }

    /// Gracefully close the endpoint.
    pub async fn close(&self) {
        self.inner.close().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_endpoint_binds() {
        let ep = AiraEndpoint::bind_for_test(None).await.unwrap();
        let id = ep.id();
        assert_ne!(id.as_bytes(), &[0u8; 32]);
        ep.close().await;
    }

    #[tokio::test]
    async fn test_two_endpoints_connect() {
        let ep1 = AiraEndpoint::bind_for_test(None).await.unwrap();
        let ep2 = AiraEndpoint::bind_for_test(None).await.unwrap();

        let ep2_addr = ep2.addr();
        let ep2_id = ep2.id();

        // Spawn server accept loop
        let ep2_clone = ep2.clone();
        let server_task = tokio::spawn(async move {
            let incoming = ep2_clone.accept().await.expect("accept failed");
            let conn = incoming.await.expect("connecting failed");
            conn.close(0u32.into(), b"bye!");
        });

        let conn = ep1.connect(ep2_addr, crate::alpn::CHAT).await.unwrap();

        assert_eq!(conn.remote_id(), ep2_id);

        conn.closed().await;
        server_task.await.unwrap();
        ep1.close().await;
        ep2.close().await;
    }
}
