//! `RustCrypto` backend (Phase 1): ml-kem + ml-dsa — pure Rust.
//!
//! See SPEC.md §10.1 for the migration strategy to aws-lc-rs (Phase 2).

use ml_dsa::{signature::Verifier, KeyGen, MlDsa65, Signature};
use ml_kem::{
    kem::{Decapsulate, Encapsulate},
    KemCore, MlKem768,
};
use zeroize::Zeroizing;

use super::{CryptoError, CryptoProvider};

/// Phase 1 crypto backend using pure-Rust `RustCrypto` crates.
pub struct RustCryptoProvider;

impl CryptoProvider for RustCryptoProvider {
    type SigningKey = ml_dsa::SigningKey<MlDsa65>;
    type VerifyingKey = ml_dsa::VerifyingKey<MlDsa65>;
    type KemDecapsKey = <MlKem768 as KemCore>::DecapsulationKey;
    type KemEncapsKey = <MlKem768 as KemCore>::EncapsulationKey;

    fn identity_keygen(seed: &[u8; 32]) -> (Self::SigningKey, Self::VerifyingKey) {
        let seed_arr = ml_dsa::B32::from(*seed);
        let kp = MlDsa65::key_gen_internal(&seed_arr);
        (kp.signing_key().clone(), kp.verifying_key().clone())
    }

    fn sign(key: &Self::SigningKey, msg: &[u8]) -> Vec<u8> {
        // Deterministic signing with empty context
        let sig: Signature<MlDsa65> = key
            .sign_deterministic(msg, &[])
            .expect("signing should not fail with valid key");
        sig.encode().to_vec()
    }

    fn verify(key: &Self::VerifyingKey, msg: &[u8], sig: &[u8]) -> bool {
        let Ok(signature) = Signature::<MlDsa65>::try_from(sig) else {
            return false;
        };
        key.verify(msg, &signature).is_ok()
    }

    fn kem_keygen(seed: &[u8; 32]) -> (Self::KemDecapsKey, Self::KemEncapsKey) {
        // Split single 32-byte seed into two independent seeds for ML-KEM
        // via BLAKE3-KDF with unique contexts (key isolation)
        let d = blake3::derive_key("aira/kem-keygen-d", seed);
        let z = blake3::derive_key("aira/kem-keygen-z", seed);
        let d = ml_kem::B32::from(d);
        let z = ml_kem::B32::from(z);
        MlKem768::generate_deterministic(&d, &z)
    }

    fn kem_encaps(pk: &Self::KemEncapsKey) -> (Vec<u8>, Zeroizing<[u8; 32]>) {
        let mut rng = rand::thread_rng();
        let (ct, shared_key) = pk
            .encapsulate(&mut rng)
            .expect("ML-KEM encapsulation should not fail");
        (ct.to_vec(), Zeroizing::new(shared_key.into()))
    }

    fn kem_decaps(sk: &Self::KemDecapsKey, ct: &[u8]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
        let ct_arr =
            ml_kem::Ciphertext::<MlKem768>::try_from(ct).map_err(|_| CryptoError::DecapsFailed)?;
        let shared_key = sk
            .decapsulate(&ct_arr)
            .map_err(|()| CryptoError::DecapsFailed)?;
        Ok(Zeroizing::new(shared_key.into()))
    }

    // ─── Serialization ──────────────────────────────────────────────────

    fn encode_verifying_key(key: &Self::VerifyingKey) -> Vec<u8> {
        use ml_dsa::EncodedVerifyingKey;
        let encoded: EncodedVerifyingKey<MlDsa65> = key.encode();
        encoded.to_vec()
    }

    fn decode_verifying_key(bytes: &[u8]) -> Result<Self::VerifyingKey, CryptoError> {
        use ml_dsa::{EncodedVerifyingKey, VerifyingKey};
        let encoded =
            EncodedVerifyingKey::<MlDsa65>::try_from(bytes).map_err(|_| CryptoError::InvalidKey)?;
        Ok(VerifyingKey::decode(&encoded))
    }

    fn encode_kem_encaps_key(key: &Self::KemEncapsKey) -> Vec<u8> {
        use ml_kem::EncodedSizeUser;
        key.as_bytes().to_vec()
    }

    fn decode_kem_encaps_key(bytes: &[u8]) -> Result<Self::KemEncapsKey, CryptoError> {
        use ml_kem::EncodedSizeUser;
        let encoded = ml_kem::Encoded::<Self::KemEncapsKey>::try_from(bytes)
            .map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self::KemEncapsKey::from_bytes(&encoded))
    }

    fn encode_kem_decaps_key(key: &Self::KemDecapsKey) -> Vec<u8> {
        use ml_kem::EncodedSizeUser;
        key.as_bytes().to_vec()
    }

    fn decode_kem_decaps_key(bytes: &[u8]) -> Result<Self::KemDecapsKey, CryptoError> {
        use ml_kem::EncodedSizeUser;
        let encoded = ml_kem::Encoded::<Self::KemDecapsKey>::try_from(bytes)
            .map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self::KemDecapsKey::from_bytes(&encoded))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dsa_sign_verify_roundtrip() {
        let seed = [42u8; 32];
        let (sk, vk) = RustCryptoProvider::identity_keygen(&seed);
        let msg = b"hello aira";
        let sig = RustCryptoProvider::sign(&sk, msg);
        assert!(RustCryptoProvider::verify(&vk, msg, &sig));
    }

    #[test]
    fn dsa_deterministic_keygen() {
        let seed = [7u8; 32];
        let (sk1, vk1) = RustCryptoProvider::identity_keygen(&seed);
        let (sk2, vk2) = RustCryptoProvider::identity_keygen(&seed);

        // Same seed → same keys
        let msg = b"test determinism";
        let sig1 = RustCryptoProvider::sign(&sk1, msg);
        let sig2 = RustCryptoProvider::sign(&sk2, msg);
        assert_eq!(
            sig1, sig2,
            "deterministic keygen must produce identical signatures"
        );
        assert!(RustCryptoProvider::verify(&vk1, msg, &sig2));
        assert!(RustCryptoProvider::verify(&vk2, msg, &sig1));
    }

    #[test]
    fn dsa_invalid_signature_rejected() {
        let seed = [1u8; 32];
        let (_, vk) = RustCryptoProvider::identity_keygen(&seed);
        assert!(!RustCryptoProvider::verify(&vk, b"msg", &[0u8; 100]));
    }

    #[test]
    fn dsa_wrong_key_rejected() {
        let (sk1, _) = RustCryptoProvider::identity_keygen(&[1u8; 32]);
        let (_, vk2) = RustCryptoProvider::identity_keygen(&[2u8; 32]);
        let sig = RustCryptoProvider::sign(&sk1, b"msg");
        assert!(!RustCryptoProvider::verify(&vk2, b"msg", &sig));
    }

    #[test]
    fn kem_encaps_decaps_roundtrip() {
        let seed = [99u8; 32];
        let (dk, ek) = RustCryptoProvider::kem_keygen(&seed);

        let (ct, shared_send) = RustCryptoProvider::kem_encaps(&ek);
        let shared_recv = RustCryptoProvider::kem_decaps(&dk, &ct).expect("decaps should succeed");

        let ss: &[u8; 32] = &shared_send;
        let sr: &[u8; 32] = &shared_recv;
        assert_eq!(ss, sr, "encaps/decaps must agree on shared secret");
    }

    #[test]
    fn kem_deterministic_keygen() {
        let seed = [55u8; 32];
        let (dk1, ek1) = RustCryptoProvider::kem_keygen(&seed);
        let (dk2, ek2) = RustCryptoProvider::kem_keygen(&seed);

        // Encapsulate to both copies — both should decaps correctly
        let (ct, ss) = RustCryptoProvider::kem_encaps(&ek1);
        let ss2 = RustCryptoProvider::kem_decaps(&dk2, &ct).expect("cross decaps");
        let a: &[u8; 32] = &ss;
        let b: &[u8; 32] = &ss2;
        assert_eq!(a, b);

        let (ct, ss) = RustCryptoProvider::kem_encaps(&ek2);
        let ss2 = RustCryptoProvider::kem_decaps(&dk1, &ct).expect("cross decaps");
        let a: &[u8; 32] = &ss;
        let b: &[u8; 32] = &ss2;
        assert_eq!(a, b);
    }

    #[test]
    fn kem_invalid_ciphertext_rejected() {
        let seed = [33u8; 32];
        let (dk, _) = RustCryptoProvider::kem_keygen(&seed);
        // ML-KEM always decapsulates (implicit rejection), but with wrong seed → different key
        // So we just verify decaps doesn't panic on garbage input
        let garbage = vec![0u8; 1088]; // ML-KEM-768 ciphertext size
        let _ = RustCryptoProvider::kem_decaps(&dk, &garbage);
    }
}
