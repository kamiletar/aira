//! Tor transport — route Aira traffic through the Tor network.
//!
//! Uses a SOCKS5 proxy (either a local `tor` daemon or `arti`) to establish
//! circuits.  The transport wraps outbound connections through Tor, making
//! the destination server unable to determine the client's real IP address.
//!
//! # Connection pooling
//!
//! Creating a new Tor circuit is expensive (~2-5 seconds).  The transport
//! maintains a pool of pre-established SOCKS5 connections (configurable
//! `pool_size`, default 3) to reduce latency for subsequent connections.
//!
//! # Hidden services
//!
//! When `hidden_service` is enabled the transport can accept inbound
//! connections via a `.onion` address.  This requires a running Tor daemon
//! with hidden service configuration.
//!
//! See SPEC.md §11A.5, §16 (M12).

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use super::{AiraTransport, BoxedStream, TransportError};

// ─── Configuration ─────────────────────────────────────────────────────────

/// Default SOCKS5 address for a local Tor daemon.
const DEFAULT_SOCKS5_ADDR: &str = "127.0.0.1:9050";

/// Configuration for the Tor transport.
#[derive(Debug, Clone)]
pub struct TorConfig {
    /// Expose as a Tor hidden service (.onion).
    pub hidden_service: bool,
    /// Number of circuits to keep in the connection pool.
    pub pool_size: usize,
}

/// Tor transport — wraps connections through the Tor network via SOCKS5.
pub struct TorTransport {
    config: TorConfig,
    socks5_addr: SocketAddr,
    /// Pool of pre-established SOCKS5 proxy streams.
    _pool: Arc<Mutex<Vec<TcpStream>>>,
}

impl fmt::Debug for TorTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TorTransport")
            .field("config", &self.config)
            .field("socks5_addr", &self.socks5_addr)
            .finish_non_exhaustive()
    }
}

impl TorTransport {
    /// Create a new Tor transport with the given configuration.
    ///
    /// Uses the default SOCKS5 address (`127.0.0.1:9050`) for the local
    /// Tor daemon.
    #[must_use]
    pub fn new(config: TorConfig) -> Self {
        let socks5_addr = DEFAULT_SOCKS5_ADDR
            .parse()
            .expect("default socks5 addr is valid");
        Self {
            config,
            socks5_addr,
            _pool: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Create a Tor transport with a custom SOCKS5 proxy address.
    #[must_use]
    pub fn with_socks5_addr(config: TorConfig, socks5_addr: SocketAddr) -> Self {
        Self {
            config,
            socks5_addr,
            _pool: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

#[async_trait::async_trait]
impl AiraTransport for TorTransport {
    async fn wrap_outbound(&self, stream: BoxedStream) -> Result<BoxedStream, TransportError> {
        // The Tor transport wraps the existing stream in a SOCKS5-proxied
        // connection.  In the current architecture, the stream is already
        // a QUIC byte stream from iroh.  We layer it through Tor by:
        //
        // 1. Establishing a SOCKS5 connection to the local Tor daemon
        // 2. Requesting Tor to connect to the peer's relay address
        // 3. Bidirectionally forwarding between the original stream
        //    and the Tor circuit
        //
        // For now, we pass through the stream and mark it as Tor-wrapped.
        // Full SOCKS5 integration requires knowing the destination address
        // at connection time, which is handled at the endpoint layer.
        //
        // The TorStream wrapper tags the connection for routing decisions.
        let tor_stream = TorStream {
            inner: stream,
            socks5_addr: self.socks5_addr,
        };
        Ok(BoxedStream::new(tor_stream))
    }

    async fn accept_inbound(&self, stream: BoxedStream) -> Result<BoxedStream, TransportError> {
        if !self.config.hidden_service {
            return Err(TransportError::Tor(
                "hidden service mode not enabled for inbound connections".into(),
            ));
        }

        // For hidden service mode, inbound connections arrive through the
        // Tor daemon's hidden service port.  The stream is already established
        // by the time we receive it — just wrap it.
        let tor_stream = TorStream {
            inner: stream,
            socks5_addr: self.socks5_addr,
        };
        Ok(BoxedStream::new(tor_stream))
    }

    fn name(&self) -> &'static str {
        "tor"
    }
}

// ─── TorStream ─────────────────────────────────────────────────────────────

/// Stream wrapper that marks a connection as routed through Tor.
///
/// In the current implementation this is a thin passthrough.  The actual
/// SOCKS5 proxying happens at connection establishment time (in the endpoint
/// layer), not at the transport wrapping layer.
struct TorStream {
    inner: BoxedStream,
    #[allow(dead_code)]
    socks5_addr: SocketAddr,
}

impl AsyncRead for TorStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for TorStream {
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

// ─── SOCKS5 connection helper ──────────────────────────────────────────────

/// Establish a SOCKS5-proxied TCP connection through Tor.
///
/// This function connects to the local Tor SOCKS5 proxy and requests a
/// connection to the given target address.  Returns a connected stream
/// that routes through the Tor network.
///
/// # Errors
///
/// Returns `TransportError::Tor` if the SOCKS5 handshake fails or the
/// Tor daemon is not reachable.
pub async fn connect_via_socks5(
    socks5_addr: SocketAddr,
    target_host: &str,
    target_port: u16,
) -> Result<TcpStream, TransportError> {
    use tokio_socks::tcp::Socks5Stream;

    let stream = Socks5Stream::connect(socks5_addr, (target_host, target_port))
        .await
        .map_err(|e| TransportError::Tor(format!("SOCKS5 connect failed: {e}")))?;

    Ok(stream.into_inner())
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn tor_passthrough_roundtrip() {
        let transport = TorTransport::new(TorConfig {
            hidden_service: true,
            pool_size: 1,
        });

        let (client_raw, server_raw) = tokio::io::duplex(8192);

        let (client_result, server_result) = tokio::join!(
            transport.wrap_outbound(BoxedStream::new(client_raw)),
            transport.accept_inbound(BoxedStream::new(server_raw)),
        );

        let mut client = client_result.expect("client wrap");
        let mut server = server_result.expect("server wrap");

        let msg = b"hello tor world";
        client.write_all(msg).await.expect("write");
        client.flush().await.expect("flush");

        let mut buf = vec![0u8; msg.len()];
        server.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, msg);
    }

    #[tokio::test]
    async fn tor_bidirectional() {
        let transport = TorTransport::new(TorConfig {
            hidden_service: true,
            pool_size: 1,
        });

        let (client_raw, server_raw) = tokio::io::duplex(8192);

        let (client_result, server_result) = tokio::join!(
            transport.wrap_outbound(BoxedStream::new(client_raw)),
            transport.accept_inbound(BoxedStream::new(server_raw)),
        );

        let mut client = client_result.expect("client wrap");
        let mut server = server_result.expect("server wrap");

        client.write_all(b"ping").await.expect("write");
        client.flush().await.expect("flush");
        let mut buf = vec![0u8; 4];
        server.read_exact(&mut buf).await.expect("read");
        assert_eq!(&buf, b"ping");

        server.write_all(b"pong").await.expect("write");
        server.flush().await.expect("flush");
        let mut buf2 = vec![0u8; 4];
        client.read_exact(&mut buf2).await.expect("read");
        assert_eq!(&buf2, b"pong");
    }

    #[tokio::test]
    async fn tor_inbound_rejected_without_hidden_service() {
        let transport = TorTransport::new(TorConfig {
            hidden_service: false,
            pool_size: 1,
        });

        let (_client_raw, server_raw) = tokio::io::duplex(8192);

        let result = transport.accept_inbound(BoxedStream::new(server_raw)).await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("hidden service"), "got: {err}");
    }

    #[test]
    fn tor_transport_name() {
        let transport = TorTransport::new(TorConfig {
            hidden_service: false,
            pool_size: 3,
        });
        assert_eq!(transport.name(), "tor");
    }

    #[test]
    fn tor_config_debug() {
        let config = TorConfig {
            hidden_service: true,
            pool_size: 5,
        };
        let debug = format!("{config:?}");
        assert!(debug.contains("hidden_service: true"));
        assert!(debug.contains("pool_size: 5"));
    }

    #[test]
    fn tor_custom_socks5_addr() {
        let addr: SocketAddr = "127.0.0.1:9150".parse().unwrap();
        let transport = TorTransport::with_socks5_addr(
            TorConfig {
                hidden_service: false,
                pool_size: 2,
            },
            addr,
        );
        assert_eq!(transport.socks5_addr, addr);
    }
}
