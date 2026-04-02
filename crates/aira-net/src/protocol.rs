//! Protocol handlers for Aira's ALPN protocols.
//!
//! Each ALPN gets its own [`ProtocolHandler`] impl:
//! - `aira/1/chat` — [`ChatHandler`]: encrypted message exchange
//! - `aira/1/handshake` — [`HandshakeHandler`]: PQXDH key exchange
//! - `aira/1/relay` — handled by [`crate::relay::RelayServer`]
//!
//! See SPEC.md §5.4.

use std::sync::Arc;

use aira_core::proto::Message;
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::connection::{read_framed, write_framed};
use crate::relay::RelayServer;

// ─── Chat handler ───────────────────────────────────────────────────────────

/// Incoming message from a peer, along with their endpoint ID.
#[derive(Debug)]
pub struct IncomingMessage {
    /// The peer that sent the message.
    pub from: iroh::EndpointId,
    /// The message received.
    pub message: Message,
}

/// Protocol handler for `aira/1/chat` — encrypted message exchange.
///
/// Accepts bidirectional streams, reads framed [`Message`] values,
/// and forwards them via an MPSC channel for the application to process.
#[derive(Debug, Clone)]
pub struct ChatHandler {
    incoming_tx: mpsc::Sender<IncomingMessage>,
}

impl ChatHandler {
    /// Create a new chat handler with a channel for incoming messages.
    ///
    /// Returns the handler and a receiver for incoming messages.
    #[must_use]
    pub fn new(buffer: usize) -> (Self, mpsc::Receiver<IncomingMessage>) {
        let (tx, rx) = mpsc::channel(buffer);
        (Self { incoming_tx: tx }, rx)
    }
}

impl ProtocolHandler for ChatHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let remote_id = connection.remote_id();
        debug!(%remote_id, "chat: accepted connection");

        loop {
            let Ok((mut send, mut recv)) = connection.accept_bi().await else {
                break; // Connection closed
            };

            let msg: Message = match read_framed(&mut recv).await {
                Ok(msg) => msg,
                Err(e) => {
                    warn!("chat: failed to read message: {e}");
                    break;
                }
            };

            // Handle ping/pong at protocol level
            match &msg {
                Message::Ping => {
                    if let Err(e) = write_framed(&mut send, &Message::Pong).await {
                        warn!("chat: failed to send pong: {e}");
                    }
                    continue;
                }
                Message::Pong => continue,
                _ => {}
            }

            // Forward to application
            let incoming = IncomingMessage {
                from: remote_id,
                message: msg,
            };
            if self.incoming_tx.send(incoming).await.is_err() {
                // Receiver dropped — application shutting down
                break;
            }
        }

        Ok(())
    }
}

// ─── Handshake handler ──────────────────────────────────────────────────────

/// Incoming handshake from a peer.
#[derive(Debug)]
pub struct IncomingHandshake {
    /// The peer that initiated the handshake.
    pub from: iroh::EndpointId,
    /// The handshake init message.
    pub message: Message,
    /// Send stream for replying with `HandshakeAck`.
    pub reply_tx: mpsc::Sender<Message>,
}

/// Protocol handler for `aira/1/handshake` — PQXDH key exchange.
///
/// Reads a handshake init, forwards it to the application for processing,
/// and sends back the handshake ack.
#[derive(Debug, Clone)]
pub struct HandshakeHandler {
    incoming_tx: mpsc::Sender<IncomingHandshake>,
}

impl HandshakeHandler {
    /// Create a new handshake handler.
    #[must_use]
    pub fn new(buffer: usize) -> (Self, mpsc::Receiver<IncomingHandshake>) {
        let (tx, rx) = mpsc::channel(buffer);
        (Self { incoming_tx: tx }, rx)
    }
}

impl ProtocolHandler for HandshakeHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let remote_id = connection.remote_id();
        debug!(%remote_id, "handshake: accepted connection");

        let (mut send, mut recv) = connection
            .accept_bi()
            .await
            .map_err(AcceptError::from_err)?;

        let msg: Message = read_framed(&mut recv)
            .await
            .map_err(AcceptError::from_err)?;

        // Create a channel for the application to reply
        let (reply_tx, mut reply_rx) = mpsc::channel(1);

        let handshake = IncomingHandshake {
            from: remote_id,
            message: msg,
            reply_tx,
        };

        self.incoming_tx
            .send(handshake)
            .await
            .map_err(|_| AcceptError::from_err(std::io::Error::other("handler dropped")))?;

        // Wait for reply from application
        if let Some(ack) = reply_rx.recv().await {
            write_framed(&mut send, &ack)
                .await
                .map_err(AcceptError::from_err)?;
        }

        Ok(())
    }
}

// ─── Router assembly ────────────────────────────────────────────────────────

/// Build an iroh `Router` with Aira's protocol handlers.
///
/// Registers handlers for all supported ALPNs:
/// - `aira/1/chat` → `ChatHandler`
/// - `aira/1/handshake` → `HandshakeHandler`
/// - `aira/1/relay` → `RelayServer`
#[must_use]
pub fn build_router(
    endpoint: &crate::endpoint::AiraEndpoint,
    chat_handler: ChatHandler,
    handshake_handler: HandshakeHandler,
    relay_server: Arc<RelayServer>,
) -> Router {
    Router::builder(endpoint.endpoint().clone())
        .accept(crate::alpn::CHAT, chat_handler)
        .accept(crate::alpn::HANDSHAKE, handshake_handler)
        .accept(crate::alpn::RELAY, relay_server)
        .spawn()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aira_core::proto::EncryptedEnvelope;

    #[tokio::test]
    async fn test_chat_handler_ping_pong() {
        let ep1 = crate::endpoint::AiraEndpoint::bind_for_test(None)
            .await
            .unwrap();
        let ep2 = crate::endpoint::AiraEndpoint::bind_for_test(None)
            .await
            .unwrap();

        let (chat_handler, _rx) = ChatHandler::new(16);
        let (hs_handler, _hs_rx) = HandshakeHandler::new(16);
        let relay = Arc::new(RelayServer::with_defaults());

        let _router = build_router(&ep2, chat_handler, hs_handler, relay);
        let ep2_addr = ep2.addr();

        // Connect and send a ping
        let conn = ep1.connect(ep2_addr, crate::alpn::CHAT).await.unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        write_framed(&mut send, &Message::Ping).await.unwrap();

        let resp: Message = read_framed(&mut recv).await.unwrap();
        assert!(matches!(resp, Message::Pong));

        conn.close(0u32.into(), b"done");
        ep1.close().await;
        ep2.close().await;
    }

    #[tokio::test]
    async fn test_chat_handler_receives_message() {
        let ep1 = crate::endpoint::AiraEndpoint::bind_for_test(None)
            .await
            .unwrap();
        let ep2 = crate::endpoint::AiraEndpoint::bind_for_test(None)
            .await
            .unwrap();

        let (chat_handler, mut rx) = ChatHandler::new(16);
        let (hs_handler, _hs_rx) = HandshakeHandler::new(16);
        let relay = Arc::new(RelayServer::with_defaults());

        let _router = build_router(&ep2, chat_handler, hs_handler, relay);
        let ep2_addr = ep2.addr();

        let conn = ep1.connect(ep2_addr, crate::alpn::CHAT).await.unwrap();
        let (mut send, _recv) = conn.open_bi().await.unwrap();

        let envelope = EncryptedEnvelope {
            nonce: [1u8; 12],
            counter: 42,
            ciphertext: b"hello encrypted".to_vec(),
        };
        write_framed(&mut send, &Message::Encrypted(envelope.clone()))
            .await
            .unwrap();
        send.finish().unwrap();

        // Should receive the message via channel
        let incoming = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(incoming.from, ep1.id());
        match incoming.message {
            Message::Encrypted(env) => {
                assert_eq!(env.counter, 42);
                assert_eq!(env.ciphertext, b"hello encrypted");
            }
            _ => panic!("expected Encrypted message"),
        }

        ep1.close().await;
        ep2.close().await;
    }
}
