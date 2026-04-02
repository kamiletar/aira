//! Integration test: Two nodes exchange encrypted messages via `aira/1/chat`.
//!
//! Flow: Alice and Bob each bind an endpoint, Alice connects to Bob's chat handler,
//! sends an encrypted envelope, Bob receives it via the incoming message channel.

use std::sync::Arc;
use std::time::Duration;

use aira_core::proto::{EncryptedEnvelope, Message};
use aira_net::connection::{read_framed, write_framed};
use aira_net::endpoint::AiraEndpoint;
use aira_net::protocol::{build_router, ChatHandler, HandshakeHandler};
use aira_net::relay::RelayServer;

#[tokio::test]
async fn two_nodes_exchange_message() {
    // --- Setup Alice (sender) ---
    let alice = AiraEndpoint::bind_for_test(None).await.unwrap();

    // --- Setup Bob (receiver) with router ---
    let bob = AiraEndpoint::bind_for_test(None).await.unwrap();
    let (chat_handler, mut incoming_rx) = ChatHandler::new(16);
    let (hs_handler, _hs_rx) = HandshakeHandler::new(16);
    let relay = Arc::new(RelayServer::with_defaults());
    let router = build_router(&bob, chat_handler, hs_handler, relay, None);

    let bob_addr = bob.addr();

    // --- Alice sends an encrypted message to Bob ---
    let envelope = EncryptedEnvelope {
        nonce: [0xAA; 12],
        counter: 1,
        ciphertext: b"hello bob, this is alice".to_vec(),
    };

    let conn = alice.connect(bob_addr, aira_net::alpn::CHAT).await.unwrap();
    let (mut send, _recv) = conn.open_bi().await.unwrap();
    write_framed(&mut send, &Message::Encrypted(envelope.clone()))
        .await
        .unwrap();
    send.finish().unwrap();

    // --- Bob receives the message ---
    let incoming = tokio::time::timeout(Duration::from_secs(10), incoming_rx.recv())
        .await
        .expect("timed out waiting for message")
        .expect("channel closed");

    assert_eq!(incoming.from, alice.id());
    match incoming.message {
        Message::Encrypted(env) => {
            assert_eq!(env.counter, 1);
            assert_eq!(env.nonce, [0xAA; 12]);
            assert_eq!(env.ciphertext, b"hello bob, this is alice");
        }
        other => panic!("expected Encrypted, got {other:?}"),
    }

    // --- Alice sends a second message ---
    let conn2 = alice
        .connect(bob.addr(), aira_net::alpn::CHAT)
        .await
        .unwrap();
    let (mut send2, _) = conn2.open_bi().await.unwrap();
    let envelope2 = EncryptedEnvelope {
        nonce: [0xBB; 12],
        counter: 2,
        ciphertext: b"second message".to_vec(),
    };
    write_framed(&mut send2, &Message::Encrypted(envelope2))
        .await
        .unwrap();
    send2.finish().unwrap();

    let incoming2 = tokio::time::timeout(Duration::from_secs(10), incoming_rx.recv())
        .await
        .expect("timed out")
        .expect("closed");
    match incoming2.message {
        Message::Encrypted(env) => assert_eq!(env.counter, 2),
        other => panic!("expected Encrypted, got {other:?}"),
    }

    // --- Cleanup ---
    conn.close(0u32.into(), b"done");
    conn2.close(0u32.into(), b"done");
    router.shutdown().await.unwrap();
    alice.close().await;
    bob.close().await;
}

#[tokio::test]
async fn ping_pong_over_chat() {
    let alice = AiraEndpoint::bind_for_test(None).await.unwrap();
    let bob = AiraEndpoint::bind_for_test(None).await.unwrap();

    let (chat_handler, _rx) = ChatHandler::new(16);
    let (hs_handler, _hs_rx) = HandshakeHandler::new(16);
    let relay = Arc::new(RelayServer::with_defaults());
    let router = build_router(&bob, chat_handler, hs_handler, relay, None);

    let conn = alice
        .connect(bob.addr(), aira_net::alpn::CHAT)
        .await
        .unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();

    write_framed(&mut send, &Message::Ping).await.unwrap();
    let resp: Message = read_framed(&mut recv).await.unwrap();
    assert!(matches!(resp, Message::Pong));

    conn.close(0u32.into(), b"done");
    router.shutdown().await.unwrap();
    alice.close().await;
    bob.close().await;
}
