//! Hybrid KEM: X25519 + ML-KEM-768.
//!
//! Combines classical ECDH (X25519) with post-quantum KEM (ML-KEM-768).
//! Both must be broken simultaneously for an attack to succeed.
//!
//! Combiner follows IETF draft-ounsworth-cfrg-kem-combiners:
//! ```text
//! shared = BLAKE3-KDF("aira/hybrid-kem/v1",
//!     counter=1 || BLAKE3(x25519_ss) || BLAKE3(mlkem_ss) || x25519_ct || mlkem_ct)
//! ```
//!
//! See SPEC.md §4.2.

#![allow(clippy::similar_names)]
// x25519_sk/ss/ct and mlkem_dk/ek/ct are intentionally named by protocol role

use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::crypto::{ActiveProvider, CryptoError, CryptoProvider};

/// KDF context for the hybrid combiner (see `docs/KEY_CONTEXTS.md`).
const HYBRID_KEM_CONTEXT: &str = "aira/hybrid-kem/v1";

/// Output of hybrid KEM encapsulation.
pub struct HybridKemOutput {
    /// X25519 ephemeral public key (32 bytes).
    pub x25519_ct: [u8; 32],
    /// ML-KEM-768 ciphertext (1088 bytes).
    pub mlkem_ct: Vec<u8>,
    /// Combined shared secret (32 bytes, zeroized on drop).
    pub shared_secret: Zeroizing<[u8; 32]>,
}

/// Perform hybrid encapsulation toward a peer.
///
/// Uses ephemeral X25519 + ML-KEM-768 encapsulation.
///
/// # Arguments
///
/// * `peer_x25519_pk` — peer's static `X25519` public key
/// * `peer_mlkem_ek` — peer's `ML-KEM-768` encapsulation key
/// # Errors
///
/// Returns [`CryptoError::EncapsFailed`] if ML-KEM encapsulation fails.
pub fn hybrid_encaps(
    peer_x25519_pk: &X25519PublicKey,
    peer_mlkem_ek: &<ActiveProvider as CryptoProvider>::KemEncapsKey,
) -> Result<HybridKemOutput, CryptoError> {
    // X25519 ephemeral DH
    let eph_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
    let eph_public = X25519PublicKey::from(&eph_secret);
    let x25519_ss = eph_secret.diffie_hellman(peer_x25519_pk);

    // ML-KEM-768 encapsulation
    let (mlkem_ct, mlkem_ss) = ActiveProvider::kem_encaps(peer_mlkem_ek)?;

    // Combine via BLAKE3-KDF
    let shared_secret = combine_secrets(
        x25519_ss.as_bytes(),
        &mlkem_ss,
        eph_public.as_bytes(),
        &mlkem_ct,
    );

    Ok(HybridKemOutput {
        x25519_ct: *eph_public.as_bytes(),
        mlkem_ct,
        shared_secret,
    })
}

/// Perform hybrid decapsulation.
///
/// # Arguments
///
/// * `x25519_sk` — our static X25519 secret key
/// * `mlkem_dk` — our ML-KEM-768 decapsulation key
/// * `x25519_ct` — peer's ephemeral X25519 public key
/// * `mlkem_ct` — ML-KEM-768 ciphertext
///
/// # Errors
///
/// Returns [`CryptoError::DecapsFailed`] if ML-KEM decapsulation fails.
pub fn hybrid_decaps(
    x25519_sk: &StaticSecret,
    mlkem_dk: &<ActiveProvider as CryptoProvider>::KemDecapsKey,
    x25519_ct: &[u8; 32],
    mlkem_ct: &[u8],
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    // X25519 DH with peer's ephemeral public key
    let peer_pk = X25519PublicKey::from(*x25519_ct);
    let x25519_ss = x25519_sk.diffie_hellman(&peer_pk);

    // ML-KEM-768 decapsulation
    let mlkem_ss = ActiveProvider::kem_decaps(mlkem_dk, mlkem_ct)?;

    // Combine via BLAKE3-KDF
    let shared_secret = combine_secrets(x25519_ss.as_bytes(), &mlkem_ss, x25519_ct, mlkem_ct);

    Ok(shared_secret)
}

/// IETF-style KEM combiner with domain separation.
///
/// ```text
/// input = counter(1) || BLAKE3(x25519_ss) || BLAKE3(mlkem_ss) || x25519_ct || mlkem_ct
/// output = BLAKE3-KDF(HYBRID_KEM_CONTEXT, input)
/// ```
///
/// Includes ciphertexts to prevent re-binding attacks.
pub(crate) fn combine_secrets(
    x25519_ss: &[u8; 32],
    mlkem_ss: &[u8; 32],
    x25519_ct: &[u8],
    mlkem_ct: &[u8],
) -> Zeroizing<[u8; 32]> {
    // Hash individual secrets for domain separation
    let h_x25519 = blake3::hash(x25519_ss);
    let h_mlkem = blake3::hash(mlkem_ss);

    // Build KDF input: counter || hashed_secrets || ciphertexts
    let counter: [u8; 4] = 1u32.to_be_bytes();
    let mut kdf_input = Zeroizing::new(Vec::with_capacity(
        4 + 32 + 32 + x25519_ct.len() + mlkem_ct.len(),
    ));
    kdf_input.extend_from_slice(&counter);
    kdf_input.extend_from_slice(h_x25519.as_bytes());
    kdf_input.extend_from_slice(h_mlkem.as_bytes());
    kdf_input.extend_from_slice(x25519_ct);
    kdf_input.extend_from_slice(mlkem_ct);

    Zeroizing::new(blake3::derive_key(HYBRID_KEM_CONTEXT, &kdf_input))
}

/// Derive an X25519 static secret from a 32-byte seed.
///
/// The seed should come from `MasterSeed::derive("aira/x25519/0")`.
#[must_use]
pub fn x25519_secret_from_seed(seed: &[u8; 32]) -> StaticSecret {
    StaticSecret::from(*seed)
}

/// Get the X25519 public key from a static secret.
#[must_use]
pub fn x25519_public_key(secret: &StaticSecret) -> X25519PublicKey {
    X25519PublicKey::from(secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed::{test_helpers, MasterSeed, Platform};

    fn test_keypair() -> (
        StaticSecret,
        X25519PublicKey,
        <ActiveProvider as CryptoProvider>::KemDecapsKey,
        <ActiveProvider as CryptoProvider>::KemEncapsKey,
    ) {
        let phrase = test_helpers::encode_entropy(&[77u8; 32]);
        let seed =
            MasterSeed::from_phrase_with_platform(&phrase, Platform::Mobile).expect("test seed");
        let x_seed = seed.derive("aira/x25519/0");
        let m_seed = seed.derive("aira/mlkem/0");

        let x_sk = x25519_secret_from_seed(&x_seed);
        let x_pk = x25519_public_key(&x_sk);
        let (m_dk, m_ek) = ActiveProvider::kem_keygen(&m_seed).expect("kem keygen");

        (x_sk, x_pk, m_dk, m_ek)
    }

    #[test]
    fn hybrid_encaps_decaps_roundtrip() {
        let (x_sk, x_pk, m_dk, m_ek) = test_keypair();

        let output = hybrid_encaps(&x_pk, &m_ek).expect("encaps");
        let decapped = hybrid_decaps(&x_sk, &m_dk, &output.x25519_ct, &output.mlkem_ct)
            .expect("decaps should succeed");

        let a: &[u8; 32] = &output.shared_secret;
        let b: &[u8; 32] = &decapped;
        assert_eq!(a, b, "encaps/decaps must produce same shared secret");
    }

    #[test]
    fn different_peers_different_secrets() {
        let (_, x_pk1, _, m_ek1) = test_keypair();

        let phrase2 = test_helpers::encode_entropy(&[88u8; 32]);
        let seed2 =
            MasterSeed::from_phrase_with_platform(&phrase2, Platform::Mobile).expect("test seed");
        let x_seed2 = seed2.derive("aira/x25519/0");
        let m_seed2 = seed2.derive("aira/mlkem/0");
        let x_pk2 = x25519_public_key(&x25519_secret_from_seed(&x_seed2));
        let (_, m_ek2) = ActiveProvider::kem_keygen(&m_seed2).expect("kem keygen2");

        let out1 = hybrid_encaps(&x_pk1, &m_ek1).expect("encaps1");
        let out2 = hybrid_encaps(&x_pk2, &m_ek2).expect("encaps2");

        let a: &[u8; 32] = &out1.shared_secret;
        let b: &[u8; 32] = &out2.shared_secret;
        assert_ne!(a, b, "different peers must yield different secrets");
    }

    #[test]
    fn tampered_mlkem_ct_fails() {
        let (x_sk, x_pk, m_dk, m_ek) = test_keypair();
        let output = hybrid_encaps(&x_pk, &m_ek).expect("encaps");

        // Tamper with ML-KEM ciphertext
        let mut bad_ct = output.mlkem_ct.clone();
        bad_ct[0] ^= 0xFF;

        // ML-KEM uses implicit rejection: decaps succeeds but returns
        // a different (random) shared secret
        let decapped = hybrid_decaps(&x_sk, &m_dk, &output.x25519_ct, &bad_ct);
        match decapped {
            Ok(ss) => {
                let a: &[u8; 32] = &output.shared_secret;
                let b: &[u8; 32] = &ss;
                assert_ne!(a, b, "tampered CT must produce different shared secret");
            }
            Err(_) => {} // Also acceptable
        }
    }
}
