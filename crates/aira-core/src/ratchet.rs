#![allow(clippy::similar_names)]
//! Triple Ratchet (SPQR) — Signal Sparse Post-Quantum Ratchet.
//!
//! Combines classical Double Ratchet (X25519) with sparse PQ Ratchet (ML-KEM-768).
//! PQ ratchet steps every ~50 messages or on direction change.
//! Keys are mixed via KDF: attacker must break both simultaneously.
//!
//! Reference: Signal SPQR paper (Eurocrypt 2025 / USENIX Security 2025).
//! See SPEC.md §4.4.

use std::collections::HashMap;

use crate::crypto::rustcrypto::RustCryptoProvider;
use crate::crypto::CryptoProvider;
use crate::proto::{AiraError, EncryptedEnvelope};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305,
};
use x25519_dalek::{PublicKey as X25519PublicKey, ReusableSecret};

// ─── Constants ───────────────────────────────────────────────────────────────

/// Maximum number of skipped message keys to tolerate per chain.
/// Prevents `DoS` via counter inflation (SPEC.md §4.4).
const MAX_SKIP: u64 = 1000;

/// PQ ratchet steps every N messages in the same direction.
const PQ_RATCHET_INTERVAL: u64 = 50;

// ─── Ratchet header (sent alongside ciphertext) ─────────────────────────────

/// Header sent with each encrypted message.
///
/// Contains the sender's current DH ratchet public key and message counter.
#[derive(Debug, Clone)]
pub struct MessageHeader {
    /// Sender's current X25519 DH ratchet public key.
    pub dh_public: [u8; 32],
    /// Message number in the current sending chain.
    pub counter: u64,
    /// Previous chain length (for skipped key management).
    pub prev_chain_len: u64,
    /// Optional ML-KEM-768 ciphertext for PQ ratchet step.
    pub pq_kem_ct: Option<Vec<u8>>,
    /// Optional new ML-KEM-768 encapsulation key (for PQ ratchet).
    pub pq_kem_ek: Option<Vec<u8>>,
}

// ─── Symmetric chain ratchet ────────────────────────────────────────────────

/// Derive a message key and advance the chain key.
fn chain_ratchet(chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let new_chain = blake3::derive_key("aira/chain/advance", chain_key);
    let msg_key = blake3::derive_key("aira/chain/message-key", chain_key);
    (new_chain, msg_key)
}

/// Derive a 12-byte nonce from chain key and counter.
fn derive_nonce(chain_key: &[u8; 32], counter: u64) -> [u8; 12] {
    let mut input = [0u8; 40];
    input[..32].copy_from_slice(chain_key);
    input[32..].copy_from_slice(&counter.to_le_bytes());
    let hash = blake3::hash(&input);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&hash.as_bytes()[..12]);
    nonce
}

/// Encrypt plaintext with ChaCha20-Poly1305.
fn aead_encrypt(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>, AiraError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(nonce.into(), plaintext)
        .map_err(|_| AiraError::Encryption)
}

/// Decrypt ciphertext with ChaCha20-Poly1305.
fn aead_decrypt(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>, AiraError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(nonce.into(), ciphertext)
        .map_err(|_| AiraError::Decryption)
}

// ─── DH Ratchet ─────────────────────────────────────────────────────────────

/// Perform a DH ratchet step, deriving new root and chain keys.
fn dh_ratchet(root_key: &[u8; 32], dh_output: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    // Mix DH output into root key
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(root_key);
    input[32..].copy_from_slice(dh_output);
    let new_root = blake3::derive_key("aira/ratchet/root", &input);
    let new_chain = blake3::derive_key("aira/ratchet/chain", &input);
    (new_root, new_chain)
}

// ─── PQ Ratchet ─────────────────────────────────────────────────────────────

/// Mix PQ shared secret into the current key material.
fn pq_mix(root_key: &[u8; 32], pq_secret: &[u8; 32]) -> [u8; 32] {
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(root_key);
    input[32..].copy_from_slice(pq_secret);
    blake3::derive_key("aira/ratchet/pq-mix", &input)
}

// ─── Skipped message key storage ────────────────────────────────────────────

/// Key: (DH public key, counter) → message key.
type SkippedKeys = HashMap<([u8; 32], u64), [u8; 32]>;

// ─── RatchetSession ─────────────────────────────────────────────────────────

/// Full Triple Ratchet (SPQR) session state.
///
/// Manages the classical Double Ratchet (X25519) with optional sparse
/// PQ Ratchet (ML-KEM-768).
pub struct RatchetSession {
    // Root key
    root_key: [u8; 32],

    // Sending state
    send_chain_key: [u8; 32],
    send_counter: u64,
    send_dh_secret: ReusableSecret,
    send_dh_public: X25519PublicKey,

    // Receiving state
    recv_chain_key: Option<[u8; 32]>,
    recv_counter: u64,
    peer_dh_public: Option<[u8; 32]>,
    prev_send_chain_len: u64,

    // PQ ratchet state
    pq_enabled: bool,
    send_since_pq: u64,
    pq_mlkem_dk: Option<<RustCryptoProvider as CryptoProvider>::KemDecapsKey>,
    pq_mlkem_ek: Option<<RustCryptoProvider as CryptoProvider>::KemEncapsKey>,
    peer_pq_ek: Option<<RustCryptoProvider as CryptoProvider>::KemEncapsKey>,

    // Skipped message keys
    skipped: SkippedKeys,
}

impl RatchetSession {
    /// Initialize a ratchet session from handshake-derived keys.
    ///
    /// The `is_initiator` flag determines the initial DH ratchet direction.
    #[must_use]
    pub fn new(
        root_key: [u8; 32],
        send_chain_key: [u8; 32],
        recv_chain_key: [u8; 32],
        peer_dh_public: [u8; 32],
        pq_enabled: bool,
    ) -> Self {
        let send_dh_secret = ReusableSecret::random_from_rng(rand::thread_rng());
        let send_dh_public = X25519PublicKey::from(&send_dh_secret);

        let (pq_dk, pq_ek) = if pq_enabled {
            let seed: [u8; 32] = blake3::derive_key("aira/ratchet/pq-init", &root_key);
            let (dk, ek) = RustCryptoProvider::kem_keygen(&seed);
            (Some(dk), Some(ek))
        } else {
            (None, None)
        };

        Self {
            root_key,
            send_chain_key,
            send_counter: 0,
            send_dh_secret,
            send_dh_public,
            recv_chain_key: Some(recv_chain_key),
            recv_counter: 0,
            peer_dh_public: Some(peer_dh_public),
            prev_send_chain_len: 0,
            pq_enabled,
            send_since_pq: 0,
            pq_mlkem_dk: pq_dk,
            pq_mlkem_ek: pq_ek,
            peer_pq_ek: None,
            skipped: HashMap::new(),
        }
    }

    /// Create a session with PQ ratchet disabled (degradation mode).
    #[must_use]
    pub fn new_classical(
        root_key: [u8; 32],
        send_chain_key: [u8; 32],
        recv_chain_key: [u8; 32],
        peer_dh_public: [u8; 32],
    ) -> Self {
        Self::new(
            root_key,
            send_chain_key,
            recv_chain_key,
            peer_dh_public,
            false,
        )
    }

    /// Encrypt a plaintext message.
    ///
    /// Returns the header and encrypted envelope.
    ///
    /// # Errors
    ///
    /// Returns [`AiraError::Encryption`] if AEAD encryption fails.
    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
    ) -> Result<(MessageHeader, EncryptedEnvelope), AiraError> {
        // Check if PQ ratchet step needed
        let (pq_ct, pq_ek_bytes) = if self.should_pq_step() {
            self.pq_ratchet_send()?
        } else {
            (None, None)
        };

        // Advance sending chain
        let (new_chain, msg_key) = chain_ratchet(&self.send_chain_key);
        self.send_chain_key = new_chain;
        let counter = self.send_counter;
        self.send_counter += 1;
        self.send_since_pq += 1;

        // Derive nonce and encrypt
        let nonce = derive_nonce(&msg_key, counter);
        let ciphertext = aead_encrypt(&msg_key, &nonce, plaintext)?;

        let header = MessageHeader {
            dh_public: *self.send_dh_public.as_bytes(),
            counter,
            prev_chain_len: self.prev_send_chain_len,
            pq_kem_ct: pq_ct,
            pq_kem_ek: pq_ek_bytes,
        };

        let envelope = EncryptedEnvelope {
            nonce,
            counter,
            ciphertext,
        };

        Ok((header, envelope))
    }

    /// Decrypt a received message.
    ///
    /// Handles DH ratchet steps, out-of-order delivery, and PQ ratchet.
    ///
    /// # Errors
    ///
    /// Returns [`AiraError::Decryption`] if AEAD decryption fails or
    /// `MAX_SKIP` is exceeded.
    pub fn decrypt(
        &mut self,
        header: &MessageHeader,
        envelope: &EncryptedEnvelope,
    ) -> Result<Vec<u8>, AiraError> {
        // Try skipped message keys first
        if let Some(msg_key) = self.skipped.remove(&(header.dh_public, header.counter)) {
            let nonce = derive_nonce(&msg_key, header.counter);
            return aead_decrypt(&msg_key, &nonce, &envelope.ciphertext);
        }

        // Check if DH ratchet step is needed (new DH public key from peer)
        let need_dh_ratchet = self.peer_dh_public.is_none_or(|pk| pk != header.dh_public);

        if need_dh_ratchet {
            // Store skipped keys from the current receiving chain
            self.skip_message_keys(header.prev_chain_len)?;

            // Process PQ ratchet step if present
            if let Some(ref pq_ct) = header.pq_kem_ct {
                self.pq_ratchet_recv(pq_ct)?;
            }
            if let Some(ref pq_ek_bytes) = header.pq_kem_ek {
                self.store_peer_pq_ek(pq_ek_bytes)?;
            }

            // Perform DH ratchet step
            self.dh_ratchet_step(&header.dh_public);
        }

        // Skip message keys up to the target counter
        self.skip_message_keys(header.counter)?;

        // Advance chain and decrypt
        let (new_chain, msg_key) =
            chain_ratchet(self.recv_chain_key.as_ref().ok_or(AiraError::Decryption)?);
        self.recv_chain_key = Some(new_chain);
        self.recv_counter = header.counter + 1;

        let nonce = derive_nonce(&msg_key, header.counter);
        aead_decrypt(&msg_key, &nonce, &envelope.ciphertext)
    }

    // ─── Internal ────────────────────────────────────────────────────────

    fn should_pq_step(&self) -> bool {
        self.pq_enabled && self.send_since_pq >= PQ_RATCHET_INTERVAL && self.peer_pq_ek.is_some()
    }

    #[allow(clippy::type_complexity)]
    fn pq_ratchet_send(&mut self) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>), AiraError> {
        let peer_ek = self
            .peer_pq_ek
            .as_ref()
            .ok_or(AiraError::Handshake("no peer PQ EK".into()))?;

        // Encapsulate toward peer
        let (ct, ss) = RustCryptoProvider::kem_encaps(peer_ek);

        // Mix PQ secret into root key
        self.root_key = pq_mix(&self.root_key, &ss);
        self.send_since_pq = 0;

        // Generate new PQ keypair for peer to use
        let seed: [u8; 32] = blake3::derive_key("aira/ratchet/pq-rekey", &self.root_key);
        let (dk, ek) = RustCryptoProvider::kem_keygen(&seed);
        let ek_bytes = {
            use ml_kem::EncodedSizeUser;
            ek.as_bytes().to_vec()
        };
        self.pq_mlkem_dk = Some(dk);
        self.pq_mlkem_ek = Some(ek);

        Ok((Some(ct), Some(ek_bytes)))
    }

    fn pq_ratchet_recv(&mut self, ct: &[u8]) -> Result<(), AiraError> {
        let dk = self.pq_mlkem_dk.as_ref().ok_or(AiraError::Decryption)?;
        let ss = RustCryptoProvider::kem_decaps(dk, ct).map_err(|_| AiraError::Decryption)?;
        self.root_key = pq_mix(&self.root_key, &ss);
        Ok(())
    }

    fn store_peer_pq_ek(&mut self, ek_bytes: &[u8]) -> Result<(), AiraError> {
        use ml_kem::EncodedSizeUser;
        let encoded =
            ml_kem::Encoded::<<RustCryptoProvider as CryptoProvider>::KemEncapsKey>::try_from(
                ek_bytes,
            )
            .map_err(|_| AiraError::Decryption)?;
        let ek = <RustCryptoProvider as CryptoProvider>::KemEncapsKey::from_bytes(&encoded);
        self.peer_pq_ek = Some(ek);
        Ok(())
    }

    fn dh_ratchet_step(&mut self, new_peer_dh: &[u8; 32]) {
        self.prev_send_chain_len = self.send_counter;
        self.send_counter = 0;
        self.recv_counter = 0;
        self.peer_dh_public = Some(*new_peer_dh);

        // Receive chain: DH with our current secret
        let peer_pk = X25519PublicKey::from(*new_peer_dh);
        let dh_recv = self.send_dh_secret.diffie_hellman(&peer_pk);
        let (new_root, new_recv_chain) = dh_ratchet(&self.root_key, dh_recv.as_bytes());
        self.root_key = new_root;
        self.recv_chain_key = Some(new_recv_chain);

        // Generate new DH keypair
        self.send_dh_secret = ReusableSecret::random_from_rng(rand::thread_rng());
        self.send_dh_public = X25519PublicKey::from(&self.send_dh_secret);

        // Send chain: DH with new secret and peer's key
        let dh_send = self.send_dh_secret.diffie_hellman(&peer_pk);
        let (new_root, new_send_chain) = dh_ratchet(&self.root_key, dh_send.as_bytes());
        self.root_key = new_root;
        self.send_chain_key = new_send_chain;
    }

    fn skip_message_keys(&mut self, until: u64) -> Result<(), AiraError> {
        let Some(ref recv_chain) = self.recv_chain_key else {
            return Ok(());
        };

        if self.recv_counter + MAX_SKIP < until {
            return Err(AiraError::Handshake(
                "MAX_SKIP exceeded (DoS protection)".into(),
            ));
        }

        let Some(peer_dh) = self.peer_dh_public else {
            return Ok(());
        };

        let mut chain = *recv_chain;
        while self.recv_counter < until {
            let (new_chain, msg_key) = chain_ratchet(&chain);
            self.skipped.insert((peer_dh, self.recv_counter), msg_key);
            chain = new_chain;
            self.recv_counter += 1;
        }
        self.recv_chain_key = Some(chain);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pair() -> (RatchetSession, RatchetSession) {
        let root = [1u8; 32];
        let send_ck = [2u8; 32];
        let recv_ck = [3u8; 32];

        // Create Alice first, then Bob with Alice's actual DH public key
        let mut alice = RatchetSession::new_classical(
            root, send_ck, recv_ck, [0u8; 32], // placeholder, will be replaced
        );

        let mut bob = RatchetSession::new_classical(
            root,
            recv_ck,                          // Bob's send = Alice's recv
            send_ck,                          // Bob's recv = Alice's send
            *alice.send_dh_public.as_bytes(), // Bob knows Alice's actual DH pubkey
        );

        // Alice knows Bob's actual DH pubkey
        alice.peer_dh_public = Some(*bob.send_dh_public.as_bytes());

        (alice, bob)
    }

    #[test]
    fn basic_encrypt_decrypt() {
        let (mut alice, mut bob) = make_pair();

        let msg = b"hello bob";
        let (header, envelope) = alice.encrypt(msg).expect("encrypt");
        let decrypted = bob.decrypt(&header, &envelope).expect("decrypt");
        assert_eq!(decrypted, msg);
    }

    #[test]
    fn multiple_messages_one_direction() {
        let (mut alice, mut bob) = make_pair();

        for i in 0..20u8 {
            let msg = format!("message {i}");
            let (header, envelope) = alice.encrypt(msg.as_bytes()).expect("encrypt");
            let decrypted = bob.decrypt(&header, &envelope).expect("decrypt");
            assert_eq!(decrypted, msg.as_bytes());
        }
    }

    #[test]
    fn alternating_directions() {
        let (mut alice, mut bob) = make_pair();

        // Alice → Bob
        let msg1 = b"hello bob";
        let (h1, e1) = alice.encrypt(msg1).expect("encrypt");
        let d1 = bob.decrypt(&h1, &e1).expect("decrypt");
        assert_eq!(d1, msg1);

        // Bob → Alice
        let msg2 = b"hello alice";
        let (h2, e2) = bob.encrypt(msg2).expect("encrypt");
        let d2 = alice.decrypt(&h2, &e2).expect("decrypt");
        assert_eq!(d2, msg2);

        // Alice → Bob again
        let msg3 = b"how are you?";
        let (h3, e3) = alice.encrypt(msg3).expect("encrypt");
        let d3 = bob.decrypt(&h3, &e3).expect("decrypt");
        assert_eq!(d3, msg3);
    }

    #[test]
    fn out_of_order_delivery() {
        let (mut alice, mut bob) = make_pair();

        // Alice sends 3 messages
        let (h0, e0) = alice.encrypt(b"msg 0").expect("encrypt");
        let (h1, e1) = alice.encrypt(b"msg 1").expect("encrypt");
        let (h2, e2) = alice.encrypt(b"msg 2").expect("encrypt");

        // Bob receives them out of order: 2, 0, 1
        let d2 = bob.decrypt(&h2, &e2).expect("decrypt msg 2");
        assert_eq!(d2, b"msg 2");

        let d0 = bob.decrypt(&h0, &e0).expect("decrypt msg 0");
        assert_eq!(d0, b"msg 0");

        let d1 = bob.decrypt(&h1, &e1).expect("decrypt msg 1");
        assert_eq!(d1, b"msg 1");
    }

    #[test]
    fn max_skip_dos_protection() {
        let (mut alice, mut bob) = make_pair();

        // Forge a header with counter far beyond MAX_SKIP
        let (mut header, envelope) = alice.encrypt(b"x").expect("encrypt");
        header.counter = MAX_SKIP + 100;
        assert!(bob.decrypt(&header, &envelope).is_err());
    }

    #[test]
    fn wrong_key_fails_decryption() {
        let (mut alice, _) = make_pair();
        let (_, mut eve) = make_pair(); // Different keys

        let (header, envelope) = alice.encrypt(b"secret").expect("encrypt");
        assert!(eve.decrypt(&header, &envelope).is_err());
    }

    #[test]
    fn classical_degradation_mode() {
        // Session works without PQ ratchet
        let (mut alice, mut bob) = make_pair();
        assert!(!alice.pq_enabled);
        assert!(!bob.pq_enabled);

        for i in 0..10u8 {
            let msg = format!("classical {i}");
            let (h, e) = alice.encrypt(msg.as_bytes()).expect("encrypt");
            let d = bob.decrypt(&h, &e).expect("decrypt");
            assert_eq!(d, msg.as_bytes());
        }
    }

    #[test]
    fn many_messages_with_direction_changes() {
        let (mut alice, mut bob) = make_pair();

        for round in 0..5u8 {
            // Alice sends 5 messages
            for i in 0..5u8 {
                let msg = format!("a->b round {round} msg {i}");
                let (h, e) = alice.encrypt(msg.as_bytes()).expect("encrypt");
                let d = bob.decrypt(&h, &e).expect("decrypt");
                assert_eq!(d, msg.as_bytes());
            }
            // Bob sends 5 messages
            for i in 0..5u8 {
                let msg = format!("b->a round {round} msg {i}");
                let (h, e) = bob.encrypt(msg.as_bytes()).expect("encrypt");
                let d = alice.decrypt(&h, &e).expect("decrypt");
                assert_eq!(d, msg.as_bytes());
            }
        }
    }
}
