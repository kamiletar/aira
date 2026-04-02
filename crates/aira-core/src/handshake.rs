#![allow(clippy::similar_names)]
//! PQXDH handshake + capability negotiation.
//!
//! Adapts Signal PQXDH (X3DH extension with PQ KEM) for Aira.
//! After successful handshake, Triple Ratchet (SPQR) is activated.
//!
//! # Protocol flow
//!
//! 1. Initiator sends `HandshakeInit` (identity + ephemeral X25519 + ML-KEM encaps key + caps)
//! 2. Responder sends `HandshakeAck` (identity + X25519 ephemeral + ML-KEM ciphertext + caps)
//! 3. Both derive identical `SessionKeys` via hybrid KEM combiner
//!
//! See SPEC.md §4.5.

use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::crypto::rustcrypto::RustCryptoProvider;
use crate::crypto::CryptoProvider;
use crate::identity::Identity;
use crate::kem;
use crate::proto::{AiraError, Capabilities, HandshakeAck, HandshakeInit};
use crate::seed::MasterSeed;

/// Current protocol version.
const PROTOCOL_VERSION: u16 = 1;

/// Feature flags for capability negotiation.
pub mod features {
    /// Post-quantum ratchet support.
    pub const PQ_RATCHET: u64 = 1 << 0;
    /// File transfer support.
    pub const FILE_TRANSFER: u64 = 1 << 1;
    /// Disappearing messages support.
    pub const DISAPPEARING: u64 = 1 << 2;
}

/// Session keys derived from a successful handshake.
///
/// These are fed into the Triple Ratchet as initial keying material.
pub struct SessionKeys {
    /// Root key for the ratchet (32 bytes).
    pub root_key: Zeroizing<[u8; 32]>,
    /// Initial sending chain key (initiator→responder direction).
    pub send_chain_key: Zeroizing<[u8; 32]>,
    /// Initial receiving chain key (responder→initiator direction).
    pub recv_chain_key: Zeroizing<[u8; 32]>,
    /// Negotiated capabilities (intersection of both peers).
    pub capabilities: Capabilities,
}

/// Initiator side of the PQXDH handshake.
pub struct Initiator {
    /// Our identity
    identity: Identity,
    /// Ephemeral X25519 secret (consumed during finish)
    eph_secret: Option<EphemeralSecret>,
    /// Our ephemeral X25519 public key
    eph_public: X25519PublicKey,
    /// Our static X25519 secret (for future key agreement)
    _x25519_sk: StaticSecret,
    /// Our ML-KEM decaps key
    mlkem_dk: <RustCryptoProvider as CryptoProvider>::KemDecapsKey,
    /// Our ML-KEM encaps key (sent to responder)
    mlkem_ek: <RustCryptoProvider as CryptoProvider>::KemEncapsKey,
    /// Our capabilities
    caps: Capabilities,
}

impl Initiator {
    /// Create an initiator from a master seed.
    #[must_use]
    pub fn new(seed: &MasterSeed) -> Self {
        let identity = Identity::from_seed(seed);
        let dh_seed = seed.derive("aira/x25519/0");
        let kem_seed = seed.derive("aira/mlkem/0");

        let x25519_sk = kem::x25519_secret_from_seed(&dh_seed);
        let (mlkem_dk, mlkem_ek) = RustCryptoProvider::kem_keygen(&kem_seed);

        let eph_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
        let eph_public = X25519PublicKey::from(&eph_secret);

        let caps = default_capabilities();

        Self {
            identity,
            eph_secret: Some(eph_secret),
            eph_public,
            _x25519_sk: x25519_sk,
            mlkem_dk,
            mlkem_ek,
            caps,
        }
    }

    /// Generate the `HandshakeInit` message to send to the responder.
    #[must_use]
    pub fn start(&self) -> HandshakeInit {
        let identity_pk = self.identity.public_key_bytes();
        let kem_encaps_pk = encode_mlkem_ek(&self.mlkem_ek);
        let x25519_pk = *self.eph_public.as_bytes();

        // Sign: identity_pk || kem_encaps_pk || x25519_pk || capabilities
        let mut signed_data = Vec::new();
        signed_data.extend_from_slice(&identity_pk);
        signed_data.extend_from_slice(&kem_encaps_pk);
        signed_data.extend_from_slice(&x25519_pk);
        signed_data.extend_from_slice(&self.caps.min_version.to_le_bytes());
        signed_data.extend_from_slice(&self.caps.max_version.to_le_bytes());
        signed_data.extend_from_slice(&self.caps.features.to_le_bytes());

        let signature = self.identity.sign(&signed_data);

        HandshakeInit {
            identity_pk,
            kem_encaps_pk,
            x25519_pk,
            capabilities: self.caps.clone(),
            signature,
        }
    }

    /// Process the responder's `HandshakeAck` and derive session keys.
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - ML-DSA signature verification fails
    /// - ML-KEM decapsulation fails
    /// - Version negotiation fails
    pub fn finish(mut self, ack: &HandshakeAck) -> Result<SessionKeys, AiraError> {
        // Verify responder's signature
        let resp_vk = decode_identity_vk(&ack.identity_pk)?;
        let signed_data = build_ack_signed_data(ack);
        if !Identity::verify_with_key(&resp_vk, &signed_data, &ack.signature) {
            return Err(AiraError::Handshake("invalid responder signature".into()));
        }

        // Negotiate capabilities
        let caps = negotiate_capabilities(&self.caps, &ack.capabilities)?;

        // X25519 DH with responder's ephemeral
        let eph_secret = self
            .eph_secret
            .take()
            .ok_or_else(|| AiraError::Handshake("handshake already finished".into()))?;
        let resp_x25519_pk = X25519PublicKey::from(ack.x25519_pk);
        let x25519_ss = eph_secret.diffie_hellman(&resp_x25519_pk);

        // ML-KEM decapsulation
        let mlkem_ss = RustCryptoProvider::kem_decaps(&self.mlkem_dk, &ack.kem_ciphertext)
            .map_err(|_| AiraError::Handshake("ML-KEM decaps failed".into()))?;

        // Combine secrets and derive session keys
        let combined = crate::kem::combine_secrets(
            x25519_ss.as_bytes(),
            &mlkem_ss,
            self.eph_public.as_bytes(),
            &ack.kem_ciphertext,
        );

        Ok(derive_session_keys(&combined, caps, Role::Initiator))
    }
}

/// Responder side of the PQXDH handshake.
pub struct Responder {
    identity: Identity,
    _x25519_sk: StaticSecret,
    _mlkem_dk: <RustCryptoProvider as CryptoProvider>::KemDecapsKey,
    _mlkem_ek: <RustCryptoProvider as CryptoProvider>::KemEncapsKey,
    caps: Capabilities,
}

impl Responder {
    /// Create a responder from a master seed.
    #[must_use]
    pub fn new(seed: &MasterSeed) -> Self {
        let identity = Identity::from_seed(seed);
        let dh_seed = seed.derive("aira/x25519/0");
        let kem_seed = seed.derive("aira/mlkem/0");

        let x25519_sk = kem::x25519_secret_from_seed(&dh_seed);
        let (mlkem_dk, mlkem_ek) = RustCryptoProvider::kem_keygen(&kem_seed);

        let caps = default_capabilities();

        Self {
            identity,
            _x25519_sk: x25519_sk,
            _mlkem_dk: mlkem_dk,
            _mlkem_ek: mlkem_ek,
            caps,
        }
    }

    /// Process an `HandshakeInit` and produce the `HandshakeAck` + session keys.
    ///
    /// # Errors
    ///
    /// Returns error if signature verification or capability negotiation fails.
    pub fn respond(self, init: &HandshakeInit) -> Result<(HandshakeAck, SessionKeys), AiraError> {
        // Verify initiator's signature
        let init_vk = decode_identity_vk(&init.identity_pk)?;
        let signed_data = build_init_signed_data(init);
        if !Identity::verify_with_key(&init_vk, &signed_data, &init.signature) {
            return Err(AiraError::Handshake("invalid initiator signature".into()));
        }

        // Negotiate capabilities
        let caps = negotiate_capabilities(&self.caps, &init.capabilities)?;

        // Decode initiator's ML-KEM encapsulation key
        let init_mlkem_ek = decode_mlkem_ek(&init.kem_encaps_pk)?;

        // ML-KEM encapsulation toward initiator
        let (mlkem_ct, mlkem_ss) = RustCryptoProvider::kem_encaps(&init_mlkem_ek);

        // X25519: generate ephemeral, DH with initiator's ephemeral
        let eph_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
        let eph_public = X25519PublicKey::from(&eph_secret);
        let init_x25519_pk = X25519PublicKey::from(init.x25519_pk);
        let x25519_ss = eph_secret.diffie_hellman(&init_x25519_pk);

        // Build and sign the ack
        let ack = HandshakeAck {
            identity_pk: self.identity.public_key_bytes(),
            kem_ciphertext: mlkem_ct.clone(),
            x25519_pk: *eph_public.as_bytes(),
            capabilities: self.caps.clone(),
            signature: Vec::new(), // placeholder, filled below
        };

        let ack_signed_data = build_ack_signed_data(&ack);
        let signature = self.identity.sign(&ack_signed_data);
        let ack = HandshakeAck { signature, ..ack };

        // Combine secrets
        let combined = crate::kem::combine_secrets(
            x25519_ss.as_bytes(),
            &mlkem_ss,
            &init.x25519_pk,
            &mlkem_ct,
        );

        let session_keys = derive_session_keys(&combined, caps, Role::Responder);
        Ok((ack, session_keys))
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn default_capabilities() -> Capabilities {
    Capabilities {
        min_version: PROTOCOL_VERSION,
        max_version: PROTOCOL_VERSION,
        features: features::PQ_RATCHET | features::FILE_TRANSFER | features::DISAPPEARING,
    }
}

fn negotiate_capabilities(
    ours: &Capabilities,
    theirs: &Capabilities,
) -> Result<Capabilities, AiraError> {
    // Version: must have overlap
    let version = ours.max_version.min(theirs.max_version);
    if version < ours.min_version || version < theirs.min_version {
        return Err(AiraError::VersionMismatch);
    }

    Ok(Capabilities {
        min_version: ours.min_version.max(theirs.min_version),
        max_version: version,
        features: ours.features & theirs.features, // intersection
    })
}

/// Handshake role determines key direction assignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Initiator,
    Responder,
}

fn derive_session_keys(combined: &[u8; 32], capabilities: Capabilities, role: Role) -> SessionKeys {
    let root_key = Zeroizing::new(blake3::derive_key("aira/session/root/v1", combined));
    // Derive directional chain keys: init→resp and resp→init
    let init_to_resp = Zeroizing::new(blake3::derive_key("aira/session/init-to-resp/v1", combined));
    let resp_to_init = Zeroizing::new(blake3::derive_key("aira/session/resp-to-init/v1", combined));

    let (send_chain_key, recv_chain_key) = match role {
        Role::Initiator => (init_to_resp, resp_to_init),
        Role::Responder => (resp_to_init, init_to_resp),
    };

    SessionKeys {
        root_key,
        send_chain_key,
        recv_chain_key,
        capabilities,
    }
}

fn build_init_signed_data(init: &HandshakeInit) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&init.identity_pk);
    data.extend_from_slice(&init.kem_encaps_pk);
    data.extend_from_slice(&init.x25519_pk);
    data.extend_from_slice(&init.capabilities.min_version.to_le_bytes());
    data.extend_from_slice(&init.capabilities.max_version.to_le_bytes());
    data.extend_from_slice(&init.capabilities.features.to_le_bytes());
    data
}

fn build_ack_signed_data(ack: &HandshakeAck) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&ack.identity_pk);
    data.extend_from_slice(&ack.kem_ciphertext);
    data.extend_from_slice(&ack.x25519_pk);
    data.extend_from_slice(&ack.capabilities.min_version.to_le_bytes());
    data.extend_from_slice(&ack.capabilities.max_version.to_le_bytes());
    data.extend_from_slice(&ack.capabilities.features.to_le_bytes());
    data
}

fn encode_mlkem_ek(ek: &<RustCryptoProvider as CryptoProvider>::KemEncapsKey) -> Vec<u8> {
    use ml_kem::EncodedSizeUser;
    ek.as_bytes().to_vec()
}

fn decode_mlkem_ek(
    bytes: &[u8],
) -> Result<<RustCryptoProvider as CryptoProvider>::KemEncapsKey, AiraError> {
    use ml_kem::EncodedSizeUser;
    let encoded =
        ml_kem::Encoded::<<RustCryptoProvider as CryptoProvider>::KemEncapsKey>::try_from(bytes)
            .map_err(|_| AiraError::Handshake("invalid ML-KEM encapsulation key".into()))?;
    Ok(<RustCryptoProvider as CryptoProvider>::KemEncapsKey::from_bytes(&encoded))
}

fn decode_identity_vk(
    bytes: &[u8],
) -> Result<<RustCryptoProvider as CryptoProvider>::VerifyingKey, AiraError> {
    use ml_dsa::{EncodedVerifyingKey, MlDsa65, VerifyingKey};
    let encoded = EncodedVerifyingKey::<MlDsa65>::try_from(bytes)
        .map_err(|_| AiraError::Handshake("invalid ML-DSA verifying key".into()))?;
    Ok(VerifyingKey::decode(&encoded))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed::{test_helpers, Platform};

    fn make_seed(n: u8) -> MasterSeed {
        let phrase = test_helpers::encode_entropy(&[n; 32]);
        MasterSeed::from_phrase_with_platform(&phrase, Platform::Mobile).expect("test seed")
    }

    #[test]
    fn full_handshake_produces_same_session_keys() {
        let alice_seed = make_seed(1);
        let bob_seed = make_seed(2);

        let alice = Initiator::new(&alice_seed);
        let bob = Responder::new(&bob_seed);

        let init_msg = alice.start();
        let (ack_msg, bob_keys) = bob.respond(&init_msg).expect("bob respond");
        let alice_keys = alice.finish(&ack_msg).expect("alice finish");

        let ar: &[u8; 32] = &alice_keys.root_key;
        let br: &[u8; 32] = &bob_keys.root_key;
        assert_eq!(ar, br, "root keys must match");

        // Note: send/recv are swapped between initiator and responder
        let as_: &[u8; 32] = &alice_keys.send_chain_key;
        let br_: &[u8; 32] = &bob_keys.recv_chain_key;
        assert_eq!(as_, br_, "alice send = bob recv");

        let ar_: &[u8; 32] = &alice_keys.recv_chain_key;
        let bs_: &[u8; 32] = &bob_keys.send_chain_key;
        assert_eq!(ar_, bs_, "alice recv = bob send");
    }

    #[test]
    fn handshake_invalid_signature_rejected() {
        let alice_seed = make_seed(3);
        let bob_seed = make_seed(4);

        let alice = Initiator::new(&alice_seed);
        let bob = Responder::new(&bob_seed);

        let mut init_msg = alice.start();
        // Corrupt signature
        if let Some(b) = init_msg.signature.first_mut() {
            *b ^= 0xFF;
        }

        assert!(bob.respond(&init_msg).is_err());
    }

    #[test]
    fn capability_negotiation_intersection() {
        let ours = Capabilities {
            min_version: 1,
            max_version: 2,
            features: features::PQ_RATCHET | features::FILE_TRANSFER,
        };
        let theirs = Capabilities {
            min_version: 1,
            max_version: 1,
            features: features::PQ_RATCHET | features::DISAPPEARING,
        };
        let result = negotiate_capabilities(&ours, &theirs).expect("should negotiate");
        assert_eq!(result.max_version, 1);
        assert_eq!(result.features, features::PQ_RATCHET); // intersection
    }

    #[test]
    fn capability_version_mismatch_rejected() {
        let ours = Capabilities {
            min_version: 2,
            max_version: 3,
            features: 0,
        };
        let theirs = Capabilities {
            min_version: 1,
            max_version: 1,
            features: 0,
        };
        assert!(negotiate_capabilities(&ours, &theirs).is_err());
    }
}
