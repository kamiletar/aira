//! `aws-lc-rs` FIPS 140-3 backend (Phase 2).
//!
//! Uses aws-lc-rs for ML-DSA-65 signing/verification and ML-KEM-768
//! encapsulation/decapsulation. Deterministic keygen uses RustCrypto's
//! ml-kem for seed-based generation (FIPS 203 compatible), then imports
//! the raw key bytes into aws-lc-rs types for all runtime operations.
//!
//! Activated with `--features=fips`.

use aws_lc_rs::kem::{self as aws_kem, Ciphertext, ML_KEM_768};
use aws_lc_rs::signature::KeyPair;
use aws_lc_rs::unstable::signature::{PqdsaKeyPair, ML_DSA_65, ML_DSA_65_SIGNING};
use zeroize::Zeroizing;

use super::{CryptoError, CryptoProvider};

// ─── ML-KEM-768 sizes (FIPS 203) ───────────────────────────────────────────

const MLKEM768_SECRET_KEY_LEN: usize = 2400;
const MLKEM768_PUBLIC_KEY_LEN: usize = 1184;
#[cfg(test)]
const MLKEM768_CIPHERTEXT_LEN: usize = 1088;

// ─── ML-DSA-65 sizes (FIPS 204) ────────────────────────────────────────────

const MLDSA65_PUBLIC_KEY_LEN: usize = 1952;
const MLDSA65_SIGNATURE_LEN: usize = 3309;

// ─── Wrapper types ──────────────────────────────────────────────────────────

/// Signing key wrapper with zeroize-on-drop semantics.
///
/// Stores the `PqdsaKeyPair` and the raw seed for reconstruction.
pub struct AwsLcSigningKey {
    keypair: PqdsaKeyPair,
    /// Raw seed (32 bytes); retained only for zeroize-on-drop guarantees.
    _seed: Zeroizing<[u8; 32]>,
}

impl zeroize::ZeroizeOnDrop for AwsLcSigningKey {}

impl Drop for AwsLcSigningKey {
    fn drop(&mut self) {
        // seed is Zeroizing — auto-zeroized
        // keypair is opaque aws-lc-rs type — cleaned by its own Drop
    }
}

/// Verifying key wrapper that implements Clone.
#[derive(Clone)]
pub struct AwsLcVerifyingKey {
    /// Raw public key bytes for verification and serialization.
    bytes: Vec<u8>,
}

/// ML-KEM decapsulation key wrapper with zeroize-on-drop semantics.
pub struct AwsLcKemDecapsKey {
    /// aws-lc-rs decapsulation key.
    inner: aws_kem::DecapsulationKey,
    /// Raw secret key bytes for serialization; zeroized on drop.
    raw: Zeroizing<Vec<u8>>,
}

impl zeroize::ZeroizeOnDrop for AwsLcKemDecapsKey {}

impl Drop for AwsLcKemDecapsKey {
    fn drop(&mut self) {
        // raw is Zeroizing<Vec<u8>> — auto-zeroized
        // inner is opaque aws-lc-rs type — cleaned by its own Drop
    }
}

/// ML-KEM encapsulation key wrapper that implements Clone.
#[derive(Clone)]
pub struct AwsLcKemEncapsKey {
    /// Raw public key bytes for reconstruction and serialization.
    bytes: Vec<u8>,
}

// ─── Provider ───────────────────────────────────────────────────────────────

/// FIPS 140-3 crypto backend using `aws-lc-rs`.
pub struct AwsLcProvider;

impl CryptoProvider for AwsLcProvider {
    type SigningKey = AwsLcSigningKey;
    type VerifyingKey = AwsLcVerifyingKey;
    type KemDecapsKey = AwsLcKemDecapsKey;
    type KemEncapsKey = AwsLcKemEncapsKey;

    fn identity_keygen(seed: &[u8; 32]) -> (Self::SigningKey, Self::VerifyingKey) {
        let keypair = PqdsaKeyPair::from_seed(&ML_DSA_65_SIGNING, seed)
            .expect("ML-DSA-65 keygen from valid 32-byte seed should not fail");

        let vk_bytes = keypair.public_key().as_ref().to_vec();

        let signing_key = AwsLcSigningKey {
            keypair,
            _seed: Zeroizing::new(*seed),
        };
        let verifying_key = AwsLcVerifyingKey { bytes: vk_bytes };

        (signing_key, verifying_key)
    }

    fn sign(key: &Self::SigningKey, msg: &[u8]) -> Vec<u8> {
        let mut sig_buf = vec![0u8; MLDSA65_SIGNATURE_LEN];
        let sig_len = key
            .keypair
            .sign(msg, &mut sig_buf)
            .expect("signing with valid key should not fail");
        sig_buf.truncate(sig_len);
        sig_buf
    }

    fn verify(key: &Self::VerifyingKey, msg: &[u8], sig: &[u8]) -> bool {
        use aws_lc_rs::signature;
        let unparsed = signature::UnparsedPublicKey::new(&ML_DSA_65, &key.bytes);
        unparsed.verify(msg, sig).is_ok()
    }

    fn kem_keygen(seed: &[u8; 32]) -> (Self::KemDecapsKey, Self::KemEncapsKey) {
        // Use RustCrypto ml-kem for deterministic keygen (FIPS 203 compatible),
        // then import raw bytes into aws-lc-rs types for runtime operations.
        use ml_kem::{EncodedSizeUser, KemCore, MlKem768};

        let d = blake3::derive_key("aira/kem-keygen-d", seed);
        let z = blake3::derive_key("aira/kem-keygen-z", seed);
        let d = ml_kem::B32::from(d);
        let z = ml_kem::B32::from(z);
        let (rc_dk, rc_ek) = MlKem768::generate_deterministic(&d, &z);

        let dk_bytes = rc_dk.as_bytes().to_vec();
        let ek_bytes = rc_ek.as_bytes().to_vec();

        // Import into aws-lc-rs
        let aws_dk = aws_kem::DecapsulationKey::new(&ML_KEM_768, &dk_bytes)
            .expect("ML-KEM-768 secret key import should not fail");

        (
            AwsLcKemDecapsKey {
                inner: aws_dk,
                raw: Zeroizing::new(dk_bytes),
            },
            AwsLcKemEncapsKey { bytes: ek_bytes },
        )
    }

    fn kem_encaps(pk: &Self::KemEncapsKey) -> (Vec<u8>, Zeroizing<[u8; 32]>) {
        let aws_ek = aws_kem::EncapsulationKey::new(&ML_KEM_768, &pk.bytes)
            .expect("ML-KEM-768 public key import should not fail");
        let (ct, ss) = aws_ek
            .encapsulate()
            .expect("ML-KEM encapsulation should not fail");
        let mut shared = [0u8; 32];
        shared.copy_from_slice(ss.as_ref());
        (ct.as_ref().to_vec(), Zeroizing::new(shared))
    }

    fn kem_decaps(sk: &Self::KemDecapsKey, ct: &[u8]) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
        let ciphertext = Ciphertext::from(ct);
        let ss = sk
            .inner
            .decapsulate(ciphertext)
            .map_err(|_| CryptoError::DecapsFailed)?;
        let mut shared = [0u8; 32];
        shared.copy_from_slice(ss.as_ref());
        Ok(Zeroizing::new(shared))
    }

    // ─── Serialization ──────────────────────────────────────────────────

    fn encode_verifying_key(key: &Self::VerifyingKey) -> Vec<u8> {
        key.bytes.clone()
    }

    fn decode_verifying_key(bytes: &[u8]) -> Result<Self::VerifyingKey, CryptoError> {
        if bytes.len() != MLDSA65_PUBLIC_KEY_LEN {
            return Err(CryptoError::InvalidKey);
        }
        // ML-DSA verifying key is validated on use (during verify)
        Ok(AwsLcVerifyingKey {
            bytes: bytes.to_vec(),
        })
    }

    fn encode_kem_encaps_key(key: &Self::KemEncapsKey) -> Vec<u8> {
        key.bytes.clone()
    }

    fn decode_kem_encaps_key(bytes: &[u8]) -> Result<Self::KemEncapsKey, CryptoError> {
        if bytes.len() != MLKEM768_PUBLIC_KEY_LEN {
            return Err(CryptoError::InvalidKey);
        }
        // Validate by attempting to construct
        aws_kem::EncapsulationKey::new(&ML_KEM_768, bytes).map_err(|_| CryptoError::InvalidKey)?;
        Ok(AwsLcKemEncapsKey {
            bytes: bytes.to_vec(),
        })
    }

    fn encode_kem_decaps_key(key: &Self::KemDecapsKey) -> Vec<u8> {
        let raw: &Vec<u8> = &key.raw;
        raw.clone()
    }

    fn decode_kem_decaps_key(bytes: &[u8]) -> Result<Self::KemDecapsKey, CryptoError> {
        if bytes.len() != MLKEM768_SECRET_KEY_LEN {
            return Err(CryptoError::InvalidKey);
        }
        let aws_dk = aws_kem::DecapsulationKey::new(&ML_KEM_768, bytes)
            .map_err(|_| CryptoError::InvalidKey)?;
        Ok(AwsLcKemDecapsKey {
            inner: aws_dk,
            raw: Zeroizing::new(bytes.to_vec()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dsa_sign_verify_roundtrip() {
        let seed = [42u8; 32];
        let (sk, vk) = AwsLcProvider::identity_keygen(&seed);
        let msg = b"hello aira fips";
        let sig = AwsLcProvider::sign(&sk, msg);
        assert!(AwsLcProvider::verify(&vk, msg, &sig));
    }

    #[test]
    fn dsa_deterministic_keygen() {
        let seed = [7u8; 32];
        let (_, vk1) = AwsLcProvider::identity_keygen(&seed);
        let (_, vk2) = AwsLcProvider::identity_keygen(&seed);
        assert_eq!(
            vk1.bytes, vk2.bytes,
            "deterministic keygen must produce identical public keys"
        );
    }

    #[test]
    fn dsa_invalid_signature_rejected() {
        let seed = [1u8; 32];
        let (_, vk) = AwsLcProvider::identity_keygen(&seed);
        assert!(!AwsLcProvider::verify(&vk, b"msg", &[0u8; 100]));
    }

    #[test]
    fn dsa_wrong_key_rejected() {
        let (sk1, _) = AwsLcProvider::identity_keygen(&[1u8; 32]);
        let (_, vk2) = AwsLcProvider::identity_keygen(&[2u8; 32]);
        let sig = AwsLcProvider::sign(&sk1, b"msg");
        assert!(!AwsLcProvider::verify(&vk2, b"msg", &sig));
    }

    #[test]
    fn kem_encaps_decaps_roundtrip() {
        let seed = [99u8; 32];
        let (dk, ek) = AwsLcProvider::kem_keygen(&seed);

        let (ct, shared_send) = AwsLcProvider::kem_encaps(&ek);
        let shared_recv = AwsLcProvider::kem_decaps(&dk, &ct).expect("decaps should succeed");

        let ss: &[u8; 32] = &shared_send;
        let sr: &[u8; 32] = &shared_recv;
        assert_eq!(ss, sr, "encaps/decaps must agree on shared secret");
    }

    #[test]
    fn kem_deterministic_keygen() {
        let seed = [55u8; 32];
        let (dk1, ek1) = AwsLcProvider::kem_keygen(&seed);
        let (dk2, ek2) = AwsLcProvider::kem_keygen(&seed);

        // Both copies should have identical public keys
        assert_eq!(ek1.bytes, ek2.bytes, "deterministic keygen must match");

        // Cross-decaps: encaps to ek1, decaps with dk2
        let (ct, ss) = AwsLcProvider::kem_encaps(&ek1);
        let ss2 = AwsLcProvider::kem_decaps(&dk2, &ct).expect("cross decaps");
        let a: &[u8; 32] = &ss;
        let b: &[u8; 32] = &ss2;
        assert_eq!(a, b);

        let (ct, ss) = AwsLcProvider::kem_encaps(&ek2);
        let ss2 = AwsLcProvider::kem_decaps(&dk1, &ct).expect("cross decaps");
        let a: &[u8; 32] = &ss;
        let b: &[u8; 32] = &ss2;
        assert_eq!(a, b);
    }

    #[test]
    fn kem_invalid_ciphertext_rejected() {
        let seed = [33u8; 32];
        let (dk, _) = AwsLcProvider::kem_keygen(&seed);
        let garbage = vec![0u8; MLKEM768_CIPHERTEXT_LEN];
        // ML-KEM uses implicit rejection — decaps succeeds but produces
        // a different shared secret. Just verify no panic.
        let _ = AwsLcProvider::kem_decaps(&dk, &garbage);
    }

    #[test]
    fn encode_decode_verifying_key_roundtrip() {
        let seed = [10u8; 32];
        let (_, vk) = AwsLcProvider::identity_keygen(&seed);
        let encoded = AwsLcProvider::encode_verifying_key(&vk);
        let decoded = AwsLcProvider::decode_verifying_key(&encoded).expect("decode");
        assert_eq!(vk.bytes, decoded.bytes);
    }

    #[test]
    fn encode_decode_kem_keys_roundtrip() {
        let seed = [20u8; 32];
        let (dk, ek) = AwsLcProvider::kem_keygen(&seed);

        // Encaps key roundtrip
        let ek_bytes = AwsLcProvider::encode_kem_encaps_key(&ek);
        let ek2 = AwsLcProvider::decode_kem_encaps_key(&ek_bytes).expect("decode ek");
        assert_eq!(ek.bytes, ek2.bytes);

        // Decaps key roundtrip
        let dk_bytes = AwsLcProvider::encode_kem_decaps_key(&dk);
        let dk2 = AwsLcProvider::decode_kem_decaps_key(&dk_bytes).expect("decode dk");

        // Verify functionality: encaps with original ek, decaps with restored dk
        let (ct, ss1) = AwsLcProvider::kem_encaps(&ek);
        let ss2 = AwsLcProvider::kem_decaps(&dk2, &ct).expect("decaps with restored key");
        let a: &[u8; 32] = &ss1;
        let b: &[u8; 32] = &ss2;
        assert_eq!(a, b);
    }
}
