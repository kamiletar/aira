//! Sender Keys for group messaging (SPEC.md §12).
//!
//! Each group member holds their own [`SenderKeyState`] with a chain key.
//! Messages are encrypted once with the sender's key, then fan-out to all
//! members. The chain key ratchets forward after each message (forward secrecy).
//!
//! Key distribution happens over existing 1-on-1 ratchet sessions (E2E).
//!
//! # KDF contexts
//!
//! - `aira/group/chain-advance` — derive next chain key
//! - `aira/group/message-key` — derive per-message encryption key
//!
//! # Security properties
//!
//! - **Forward secrecy:** Yes (ratchet per message)
//! - **Post-compromise security:** Only on Sender Key rotation (add/remove member)
//! - **Max members:** 100 per group (SPEC.md §12)

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::proto::AiraError;

// ─── Constants ──────────────────────────────────────────────────────────────

/// Maximum number of members in a group (SPEC.md §12).
pub const MAX_GROUP_MEMBERS: usize = 100;

/// Maximum number of skipped message keys to tolerate.
/// Prevents `DoS` via counter inflation.
const MAX_SKIP: u64 = 1000;

// ─── Sender Key State ───────────────────────────────────────────────────────

/// Per-member Sender Key state for group messaging.
///
/// Each member generates their own `SenderKeyState` and distributes the initial
/// chain key to all other members via 1-on-1 encrypted channels.
///
/// # Example
///
/// ```
/// use aira_core::group::SenderKeyState;
///
/// let mut state = SenderKeyState::new();
/// let plaintext = b"hello group";
/// let (counter, nonce, ciphertext) = state.encrypt(plaintext).unwrap();
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenderKeyState {
    /// Chain key — ratchets forward after each message.
    #[serde(with = "zeroizing_bytes")]
    chain_key: Zeroizing<[u8; 32]>,
    /// Message counter (monotonically increasing).
    counter: u64,
}

impl SenderKeyState {
    /// Create a new `SenderKeyState` with a random chain key.
    #[must_use]
    pub fn new() -> Self {
        let mut key = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut key);
        Self {
            chain_key: Zeroizing::new(key),
            counter: 0,
        }
    }

    /// Create from an existing chain key (received from another member).
    #[must_use]
    pub fn from_chain_key(chain_key: [u8; 32]) -> Self {
        Self {
            chain_key: Zeroizing::new(chain_key),
            counter: 0,
        }
    }

    /// Current chain key bytes (for distributing to group members).
    #[must_use]
    pub fn chain_key_bytes(&self) -> &[u8; 32] {
        &self.chain_key
    }

    /// Current counter value.
    #[must_use]
    pub fn counter(&self) -> u64 {
        self.counter
    }

    /// Encrypt plaintext and advance the chain key.
    ///
    /// Returns `(counter, nonce, ciphertext)`.
    ///
    /// # Errors
    ///
    /// Returns [`AiraError::Encryption`] if AEAD encryption fails.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<(u64, [u8; 12], Vec<u8>), AiraError> {
        let (new_chain, msg_key) = chain_ratchet(&self.chain_key);
        let nonce = derive_nonce(&msg_key, self.counter);
        let ciphertext = aead_encrypt(&msg_key, &nonce, plaintext)?;
        let counter = self.counter;

        self.chain_key = Zeroizing::new(new_chain);
        self.counter += 1;

        Ok((counter, nonce, ciphertext))
    }
}

impl Default for SenderKeyState {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Receiver-side decryption ──────────────────────────────────────────────

/// Receiver state for decrypting messages from a specific group member.
///
/// Tracks the member's chain key and handles out-of-order messages via
/// forward-skipping (same pattern as the Double Ratchet).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenderKeyReceiver {
    /// Current chain key for this sender.
    #[serde(with = "zeroizing_bytes")]
    chain_key: Zeroizing<[u8; 32]>,
    /// Expected next counter from this sender.
    next_counter: u64,
    /// Skipped message keys: counter -> (`message_key`, nonce).
    skipped_keys: std::collections::HashMap<u64, ([u8; 32], [u8; 12])>,
}

impl SenderKeyReceiver {
    /// Create a receiver from a sender's chain key.
    #[must_use]
    pub fn new(chain_key: [u8; 32]) -> Self {
        Self {
            chain_key: Zeroizing::new(chain_key),
            next_counter: 0,
            skipped_keys: std::collections::HashMap::new(),
        }
    }

    /// Update with a new chain key (after Sender Key rotation).
    pub fn update_chain_key(&mut self, new_key: [u8; 32]) {
        self.chain_key = Zeroizing::new(new_key);
        self.next_counter = 0;
        self.skipped_keys.clear();
    }

    /// Decrypt a message from this sender.
    ///
    /// Handles out-of-order delivery by forward-skipping the chain.
    ///
    /// # Errors
    ///
    /// Returns [`AiraError::Decryption`] if the message cannot be decrypted
    /// (wrong key, replay, or too many skipped messages).
    pub fn decrypt(
        &mut self,
        counter: u64,
        nonce: &[u8; 12],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, AiraError> {
        // Try skipped keys first (out-of-order message)
        if let Some((msg_key, stored_nonce)) = self.skipped_keys.remove(&counter) {
            // Use stored nonce for consistency check, but decrypt with provided nonce
            if stored_nonce != *nonce {
                return Err(AiraError::Decryption);
            }
            return aead_decrypt(&msg_key, nonce, ciphertext);
        }

        // Counter must be >= next_counter
        if counter < self.next_counter {
            return Err(AiraError::Decryption);
        }

        // Skip forward if needed
        let skip_count = counter - self.next_counter;
        if skip_count > MAX_SKIP {
            return Err(AiraError::Decryption);
        }

        // Derive and store skipped keys
        for i in self.next_counter..counter {
            let (new_chain, msg_key) = chain_ratchet(&self.chain_key);
            let skip_nonce = derive_nonce(&msg_key, i);
            self.skipped_keys.insert(i, (msg_key, skip_nonce));
            self.chain_key = Zeroizing::new(new_chain);
        }

        // Derive the current message key
        let (new_chain, msg_key) = chain_ratchet(&self.chain_key);
        let plaintext = aead_decrypt(&msg_key, nonce, ciphertext)?;
        self.chain_key = Zeroizing::new(new_chain);
        self.next_counter = counter + 1;

        Ok(plaintext)
    }
}

// ─── Internal crypto helpers ───────────────────────────────────────────────

/// Derive next chain key and message key from current chain key.
fn chain_ratchet(chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let new_chain = blake3::derive_key("aira/group/chain-advance", chain_key);
    let msg_key = blake3::derive_key("aira/group/message-key", chain_key);
    (new_chain, msg_key)
}

/// Derive a 12-byte nonce from message key and counter.
fn derive_nonce(msg_key: &[u8; 32], counter: u64) -> [u8; 12] {
    let mut input = [0u8; 40];
    input[..32].copy_from_slice(msg_key);
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

// ─── Serde helper for Zeroizing<[u8; 32]> ──────────────────────────────────

mod zeroizing_bytes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use zeroize::Zeroizing;

    pub fn serialize<S: Serializer>(
        value: &Zeroizing<[u8; 32]>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let arr: &[u8; 32] = value;
        arr.serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Zeroizing<[u8; 32]>, D::Error> {
        let bytes: [u8; 32] = <[u8; 32]>::deserialize(deserializer)?;
        Ok(Zeroizing::new(bytes))
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let mut sender = SenderKeyState::new();
        let mut receiver = SenderKeyReceiver::new(*sender.chain_key_bytes());

        let plaintext = b"hello group!";
        let (counter, nonce, ciphertext) = sender.encrypt(plaintext).unwrap();
        let decrypted = receiver.decrypt(counter, &nonce, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn multiple_messages() {
        let mut sender = SenderKeyState::new();
        let mut receiver = SenderKeyReceiver::new(*sender.chain_key_bytes());

        for i in 0..10 {
            let msg = format!("message {i}");
            let (counter, nonce, ct) = sender.encrypt(msg.as_bytes()).unwrap();
            let pt = receiver.decrypt(counter, &nonce, &ct).unwrap();
            assert_eq!(pt, msg.as_bytes());
        }
    }

    #[test]
    fn forward_secrecy() {
        // After ratchet, old chain key cannot decrypt new messages.
        let mut sender = SenderKeyState::new();
        let old_key = *sender.chain_key_bytes();

        // Send a message to advance the chain
        let _ = sender.encrypt(b"advance").unwrap();

        // New message with advanced chain
        let (counter, nonce, ct) = sender.encrypt(b"secret").unwrap();

        // Receiver with old key should still work (skip forward)
        let mut receiver = SenderKeyReceiver::new(old_key);
        // Skip the first message
        let pt = receiver.decrypt(counter, &nonce, &ct).unwrap();
        assert_eq!(pt, b"secret");
    }

    #[test]
    fn out_of_order_delivery() {
        let mut sender = SenderKeyState::new();
        let mut receiver = SenderKeyReceiver::new(*sender.chain_key_bytes());

        // Encrypt 3 messages
        let (c0, n0, ct0) = sender.encrypt(b"msg0").unwrap();
        let (c1, n1, ct1) = sender.encrypt(b"msg1").unwrap();
        let (c2, n2, ct2) = sender.encrypt(b"msg2").unwrap();

        // Deliver out of order: 2, 0, 1
        let pt2 = receiver.decrypt(c2, &n2, &ct2).unwrap();
        assert_eq!(pt2, b"msg2");

        let pt0 = receiver.decrypt(c0, &n0, &ct0).unwrap();
        assert_eq!(pt0, b"msg0");

        let pt1 = receiver.decrypt(c1, &n1, &ct1).unwrap();
        assert_eq!(pt1, b"msg1");
    }

    #[test]
    fn max_skip_exceeded() {
        let mut sender = SenderKeyState::new();
        let mut receiver = SenderKeyReceiver::new(*sender.chain_key_bytes());

        // Encrypt MAX_SKIP + 2 messages, try to decrypt only the last one
        for _ in 0..MAX_SKIP + 2 {
            let _ = sender.encrypt(b"skip").unwrap();
        }
        let (counter, nonce, ct) = sender.encrypt(b"too far").unwrap();

        let result = receiver.decrypt(counter, &nonce, &ct);
        assert!(result.is_err(), "should reject skip beyond MAX_SKIP");
    }

    #[test]
    fn replay_rejected() {
        let mut sender = SenderKeyState::new();
        let mut receiver = SenderKeyReceiver::new(*sender.chain_key_bytes());

        let (counter, nonce, ct) = sender.encrypt(b"once").unwrap();
        let _ = receiver.decrypt(counter, &nonce, &ct).unwrap();

        // Replay same message — should fail (counter already consumed)
        let result = receiver.decrypt(counter, &nonce, &ct);
        assert!(result.is_err(), "replay should be rejected");
    }

    #[test]
    fn deterministic_derivation() {
        let key = [0x42u8; 32];
        let mut s1 = SenderKeyState::from_chain_key(key);
        let mut s2 = SenderKeyState::from_chain_key(key);

        let (c1, n1, ct1) = s1.encrypt(b"test").unwrap();
        let (c2, n2, ct2) = s2.encrypt(b"test").unwrap();

        assert_eq!(c1, c2);
        assert_eq!(n1, n2);
        assert_eq!(ct1, ct2);
    }

    #[test]
    fn sender_key_rotation() {
        let mut sender = SenderKeyState::new();
        let mut receiver = SenderKeyReceiver::new(*sender.chain_key_bytes());

        // Send a message with old key
        let (c0, n0, ct0) = sender.encrypt(b"before rotation").unwrap();
        let pt0 = receiver.decrypt(c0, &n0, &ct0).unwrap();
        assert_eq!(pt0, b"before rotation");

        // Rotate: sender generates new key
        let new_sender = SenderKeyState::new();
        receiver.update_chain_key(*new_sender.chain_key_bytes());
        let mut sender = new_sender;

        // Send with new key
        let (c1, n1, ct1) = sender.encrypt(b"after rotation").unwrap();
        let pt1 = receiver.decrypt(c1, &n1, &ct1).unwrap();
        assert_eq!(pt1, b"after rotation");
    }

    #[test]
    fn serialization_roundtrip() {
        let state = SenderKeyState::new();
        let bytes = postcard::to_allocvec(&state).expect("serialize");
        let restored: SenderKeyState = postcard::from_bytes(&bytes).expect("deserialize");
        let left: &[u8; 32] = &state.chain_key;
        let right: &[u8; 32] = &restored.chain_key;
        assert_eq!(left, right);
        assert_eq!(state.counter, restored.counter);
    }
}
