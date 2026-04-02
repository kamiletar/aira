//! Integration test: Message relay when peer is offline.
//!
//! Flow:
//! 1. Alice and Bob derive a shared mailbox ID
//! 2. Bob goes offline
//! 3. Alice deposits an encrypted envelope on the relay
//! 4. Bob comes back online, retrieves the envelope from the relay
//! 5. Bob acks, relay mailbox is emptied

use std::sync::Arc;
use std::time::Duration;

use aira_core::proto::EncryptedEnvelope;
use aira_net::endpoint::AiraEndpoint;
use aira_net::protocol::{build_router, ChatHandler, HandshakeHandler};
use aira_net::relay::{derive_mailbox_id, RelayClient, RelayServer};

#[tokio::test]
async fn message_relay_when_peer_offline() {
    // --- Setup relay server ---
    let relay_ep = AiraEndpoint::bind_for_test(None).await.unwrap();
    let relay_server = Arc::new(RelayServer::with_defaults());
    let (chat_handler, _rx) = ChatHandler::new(1);
    let (hs_handler, _hs_rx) = HandshakeHandler::new(1);
    let relay_router = build_router(
        &relay_ep,
        chat_handler,
        hs_handler,
        Arc::clone(&relay_server),
    );
    let relay_addr = relay_ep.addr();

    // --- Setup Alice (sender) ---
    let alice = AiraEndpoint::bind_for_test(None).await.unwrap();

    // --- Derive shared mailbox ID (simulating a shared secret from handshake) ---
    let shared_secret = [0x42u8; 32]; // In real use, derived from PQXDH handshake
    let mailbox_id = derive_mailbox_id(&shared_secret);

    // --- Bob is "offline" — we just don't create him yet ---

    // --- Alice deposits an envelope for Bob ---
    let alice_relay = RelayClient::new(alice.clone(), relay_addr.clone());
    let envelope = EncryptedEnvelope {
        nonce: [0xCC; 12],
        counter: 1,
        ciphertext: b"offline message for bob".to_vec(),
    };
    alice_relay
        .deposit(mailbox_id, envelope.clone())
        .await
        .unwrap();

    // Deposit a second message
    let envelope2 = EncryptedEnvelope {
        nonce: [0xDD; 12],
        counter: 2,
        ciphertext: b"second offline message".to_vec(),
    };
    alice_relay
        .deposit(mailbox_id, envelope2.clone())
        .await
        .unwrap();

    // --- Bob comes online and retrieves ---
    let bob = AiraEndpoint::bind_for_test(None).await.unwrap();
    let bob_relay = RelayClient::new(bob.clone(), relay_addr.clone());

    let retrieved = bob_relay.retrieve(mailbox_id).await.unwrap();
    assert_eq!(retrieved.len(), 2);
    assert_eq!(retrieved[0].counter, 1);
    assert_eq!(retrieved[0].ciphertext, b"offline message for bob");
    assert_eq!(retrieved[1].counter, 2);
    assert_eq!(retrieved[1].ciphertext, b"second offline message");

    // --- Bob acks both messages ---
    bob_relay.ack(mailbox_id, vec![1, 2]).await.unwrap();

    // --- Verify relay mailbox is empty ---
    let remaining = bob_relay.retrieve(mailbox_id).await.unwrap();
    assert!(remaining.is_empty(), "mailbox should be empty after ack");

    // --- Cleanup ---
    relay_router.shutdown().await.unwrap();
    alice.close().await;
    bob.close().await;
    relay_ep.close().await;
}

#[tokio::test]
async fn relay_mailbox_id_is_deterministic() {
    // Both peers compute the same mailbox ID from the same shared secret
    let secret = [0x99u8; 32];
    let id_alice = derive_mailbox_id(&secret);
    let id_bob = derive_mailbox_id(&secret);
    assert_eq!(id_alice, id_bob);

    // Different secrets produce different IDs
    let other_secret = [0xAA; 32];
    let id_other = derive_mailbox_id(&other_secret);
    assert_ne!(id_alice, id_other);
}

#[tokio::test]
async fn relay_quota_enforcement() {
    let relay_ep = AiraEndpoint::bind_for_test(None).await.unwrap();
    let config = aira_net::relay::RelayConfig {
        max_envelopes: 2,
        ..Default::default()
    };
    let relay_server = Arc::new(RelayServer::new(config));
    let (chat_handler, _rx) = ChatHandler::new(1);
    let (hs_handler, _hs_rx) = HandshakeHandler::new(1);
    let relay_router = build_router(
        &relay_ep,
        chat_handler,
        hs_handler,
        Arc::clone(&relay_server),
    );

    let client_ep = AiraEndpoint::bind_for_test(None).await.unwrap();
    let client = RelayClient::new(client_ep.clone(), relay_ep.addr());
    let mailbox_id = [0x55u8; 32];

    // First two should succeed
    for i in 0..2 {
        let env = EncryptedEnvelope {
            nonce: [0; 12],
            counter: i,
            ciphertext: vec![0u8; 10],
        };
        client.deposit(mailbox_id, env).await.unwrap();
    }

    // Third should fail (quota exceeded)
    let env = EncryptedEnvelope {
        nonce: [0; 12],
        counter: 2,
        ciphertext: vec![0u8; 10],
    };
    let result = client.deposit(mailbox_id, env).await;
    assert!(result.is_err(), "should be rate-limited at 2 envelopes");

    relay_router.shutdown().await.unwrap();
    client_ep.close().await;
    relay_ep.close().await;
}
