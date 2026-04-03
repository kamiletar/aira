//! Cross-backend compatibility tests: RustCrypto ↔ aws-lc-rs.
//!
//! Activated with `--features=compat-test`. Both backends are compiled
//! simultaneously and tested for interoperability.
//!
//! These tests verify that:
//! - Same seed → same ML-DSA-65 public keys (byte-equal)
//! - Signatures from one backend verify with the other
//! - Same seed → same ML-KEM-768 keypairs (byte-equal)
//! - ML-KEM encaps with one → decaps with the other

#![cfg(all(test, feature = "compat-test"))]

use super::awslc::AwsLcProvider;
use super::rustcrypto::RustCryptoProvider;
use super::CryptoProvider;

// ─── ML-DSA-65 cross-backend tests ─────────────────────────────────────────

#[test]
fn cross_dsa_same_seed_same_public_key() {
    let seed = [42u8; 32];
    let (_, rc_vk) = RustCryptoProvider::identity_keygen(&seed).expect("rc keygen");
    let (_, aws_vk) = AwsLcProvider::identity_keygen(&seed).expect("aws keygen");

    let rc_bytes = RustCryptoProvider::encode_verifying_key(&rc_vk);
    let aws_bytes = AwsLcProvider::encode_verifying_key(&aws_vk);

    assert_eq!(
        rc_bytes, aws_bytes,
        "same seed must produce identical ML-DSA-65 public keys across backends"
    );
}

#[test]
fn cross_dsa_rustcrypto_sign_awslc_verify() {
    let seed = [7u8; 32];
    let (rc_sk, _) = RustCryptoProvider::identity_keygen(&seed).expect("rc keygen");
    let (_, aws_vk) = AwsLcProvider::identity_keygen(&seed).expect("aws keygen");

    let msg = b"cross-backend verification test";
    let sig = RustCryptoProvider::sign(&rc_sk, msg).expect("sign");

    assert!(
        AwsLcProvider::verify(&aws_vk, msg, &sig),
        "RustCrypto signature must verify with aws-lc-rs key"
    );
}

#[test]
fn cross_dsa_awslc_sign_rustcrypto_verify() {
    let seed = [13u8; 32];
    let (_, rc_vk) = RustCryptoProvider::identity_keygen(&seed).expect("rc keygen");
    let (aws_sk, _) = AwsLcProvider::identity_keygen(&seed).expect("aws keygen");

    let msg = b"reverse cross-backend test";
    let sig = AwsLcProvider::sign(&aws_sk, msg).expect("sign");

    assert!(
        RustCryptoProvider::verify(&rc_vk, msg, &sig),
        "aws-lc-rs signature must verify with RustCrypto key"
    );
}

// ─── ML-KEM-768 cross-backend tests ────────────────────────────────────────

#[test]
fn cross_kem_same_seed_same_keys() {
    let seed = [55u8; 32];
    let (rc_dk, rc_ek) = RustCryptoProvider::kem_keygen(&seed).expect("rc keygen");
    let (aws_dk, aws_ek) = AwsLcProvider::kem_keygen(&seed).expect("aws keygen");

    let rc_ek_bytes = RustCryptoProvider::encode_kem_encaps_key(&rc_ek);
    let aws_ek_bytes = AwsLcProvider::encode_kem_encaps_key(&aws_ek);

    assert_eq!(
        rc_ek_bytes, aws_ek_bytes,
        "same seed must produce identical ML-KEM-768 encapsulation keys"
    );

    let rc_dk_bytes = RustCryptoProvider::encode_kem_decaps_key(&rc_dk);
    let aws_dk_bytes = AwsLcProvider::encode_kem_decaps_key(&aws_dk);

    assert_eq!(
        rc_dk_bytes, aws_dk_bytes,
        "same seed must produce identical ML-KEM-768 decapsulation keys"
    );
}

#[test]
fn cross_kem_rustcrypto_encaps_awslc_decaps() {
    let seed = [99u8; 32];
    let (_, rc_ek) = RustCryptoProvider::kem_keygen(&seed).expect("rc keygen");
    let (aws_dk, _) = AwsLcProvider::kem_keygen(&seed).expect("aws keygen");

    // Encapsulate with RustCrypto
    let (ct, rc_ss) = RustCryptoProvider::kem_encaps(&rc_ek).expect("encaps");

    // Decapsulate with aws-lc-rs
    let aws_ss = AwsLcProvider::kem_decaps(&aws_dk, &ct).expect("cross decaps");

    let a: &[u8; 32] = &rc_ss;
    let b: &[u8; 32] = &aws_ss;
    assert_eq!(
        a, b,
        "RustCrypto encaps + aws-lc-rs decaps must produce same shared secret"
    );
}

#[test]
fn cross_kem_awslc_encaps_rustcrypto_decaps() {
    let seed = [77u8; 32];
    let (rc_dk, _) = RustCryptoProvider::kem_keygen(&seed).expect("rc keygen");
    let (_, aws_ek) = AwsLcProvider::kem_keygen(&seed).expect("aws keygen");

    // Encapsulate with aws-lc-rs
    let (ct, aws_ss) = AwsLcProvider::kem_encaps(&aws_ek).expect("encaps");

    // Decapsulate with RustCrypto
    let rc_ss = RustCryptoProvider::kem_decaps(&rc_dk, &ct).expect("cross decaps");

    let a: &[u8; 32] = &aws_ss;
    let b: &[u8; 32] = &rc_ss;
    assert_eq!(
        a, b,
        "aws-lc-rs encaps + RustCrypto decaps must produce same shared secret"
    );
}

// ─── Key serialization cross-backend tests ──────────────────────────────────

#[test]
fn cross_verifying_key_decode() {
    let seed = [30u8; 32];
    let (_, rc_vk) = RustCryptoProvider::identity_keygen(&seed).expect("keygen");
    let rc_bytes = RustCryptoProvider::encode_verifying_key(&rc_vk);

    // Decode RustCrypto bytes with aws-lc-rs
    let aws_vk =
        AwsLcProvider::decode_verifying_key(&rc_bytes).expect("cross decode verifying key");
    let aws_bytes = AwsLcProvider::encode_verifying_key(&aws_vk);
    assert_eq!(rc_bytes, aws_bytes);
}

#[test]
fn cross_kem_encaps_key_decode() {
    let seed = [40u8; 32];
    let (_, rc_ek) = RustCryptoProvider::kem_keygen(&seed).expect("keygen");
    let rc_bytes = RustCryptoProvider::encode_kem_encaps_key(&rc_ek);

    // Decode RustCrypto bytes with aws-lc-rs and use for encapsulation
    let aws_ek =
        AwsLcProvider::decode_kem_encaps_key(&rc_bytes).expect("cross decode kem encaps key");
    let aws_bytes = AwsLcProvider::encode_kem_encaps_key(&aws_ek);
    assert_eq!(rc_bytes, aws_bytes);
}
