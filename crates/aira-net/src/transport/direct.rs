//! Direct transport — plain QUIC via iroh, no obfuscation.
//!
//! Default mode for networks without censorship.
//! The stream passes through unchanged.

use super::{AiraTransport, BoxedStream, TransportError};

/// Direct transport — no obfuscation, stream passthrough.
#[derive(Debug)]
pub struct DirectTransport;

#[async_trait::async_trait]
impl AiraTransport for DirectTransport {
    async fn wrap_outbound(&self, stream: BoxedStream) -> Result<BoxedStream, TransportError> {
        Ok(stream)
    }

    async fn accept_inbound(&self, stream: BoxedStream) -> Result<BoxedStream, TransportError> {
        Ok(stream)
    }

    fn name(&self) -> &'static str {
        "direct"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn direct_passthrough_roundtrip() {
        let transport = DirectTransport;
        let (client, server) = tokio::io::duplex(1024);

        let mut wrapped_client = transport
            .wrap_outbound(BoxedStream::new(client))
            .await
            .expect("wrap_outbound");
        let mut wrapped_server = transport
            .accept_inbound(BoxedStream::new(server))
            .await
            .expect("accept_inbound");

        // Write from client, read from server.
        let payload = b"hello DPI resistance";
        wrapped_client.write_all(payload).await.expect("write");
        drop(wrapped_client); // close write half

        let mut buf = Vec::new();
        wrapped_server.read_to_end(&mut buf).await.expect("read");
        assert_eq!(buf, payload);
    }

    #[tokio::test]
    async fn direct_transport_name() {
        let t = DirectTransport;
        assert_eq!(t.name(), "direct");
    }
}
