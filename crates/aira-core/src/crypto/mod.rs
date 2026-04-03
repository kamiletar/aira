//! `CryptoProvider` abstraction — allows swapping `RustCrypto` (Phase 1)
//! for aws-lc-rs FIPS 140-3 (Phase 2) without rewriting protocol logic.
//!
//! See SPEC.md §10.1 for the migration strategy.
//! See `docs/KEY_CONTEXTS.md` for the canonical list of KDF contexts.

pub mod rustcrypto;

#[cfg(any(feature = "fips", feature = "compat-test"))]
pub mod awslc;

#[cfg(feature = "compat-test")]
mod compat_tests;

/// Active crypto backend, selected at compile time.
///
/// Default: [`rustcrypto::RustCryptoProvider`] (pure Rust).
/// With `--features=fips`: [`awslc::AwsLcProvider`] (FIPS 140-3).
#[cfg(not(feature = "fips"))]
pub type ActiveProvider = rustcrypto::RustCryptoProvider;

/// Active crypto backend (FIPS mode).
#[cfg(feature = "fips")]
pub type ActiveProvider = awslc::AwsLcProvider;

/// Abstraction over PQ cryptographic backends.
///
/// Implementations: [`rustcrypto`] (Phase 1), [`awslc`] (Phase 2, FIPS).
pub trait CryptoProvider {
    type SigningKey: zeroize::ZeroizeOnDrop;
    type VerifyingKey: Clone;
    type KemDecapsKey: zeroize::ZeroizeOnDrop;
    type KemEncapsKey: Clone;

    /// Generate ML-DSA-65 identity keypair from a 32-byte seed.
    fn identity_keygen(seed: &[u8; 32]) -> (Self::SigningKey, Self::VerifyingKey);

    /// Sign a message with ML-DSA-65.
    fn sign(key: &Self::SigningKey, msg: &[u8]) -> Vec<u8>;

    /// Verify an ML-DSA-65 signature.
    fn verify(key: &Self::VerifyingKey, msg: &[u8], sig: &[u8]) -> bool;

    /// Generate ML-KEM-768 keypair from a 32-byte seed.
    fn kem_keygen(seed: &[u8; 32]) -> (Self::KemDecapsKey, Self::KemEncapsKey);

    /// ML-KEM-768 encapsulation. Returns (ciphertext, `shared_secret`).
    fn kem_encaps(pk: &Self::KemEncapsKey) -> (Vec<u8>, zeroize::Zeroizing<[u8; 32]>);

    /// ML-KEM-768 decapsulation. Returns `shared_secret`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::DecapsFailed`] if the ciphertext is invalid.
    fn kem_decaps(
        sk: &Self::KemDecapsKey,
        ct: &[u8],
    ) -> Result<zeroize::Zeroizing<[u8; 32]>, CryptoError>;

    // ─── Serialization ──────────────────────────────────────────────────

    /// Encode a verifying (public) key to bytes.
    fn encode_verifying_key(key: &Self::VerifyingKey) -> Vec<u8>;

    /// Decode a verifying key from bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidKey`] if the bytes are malformed.
    fn decode_verifying_key(bytes: &[u8]) -> Result<Self::VerifyingKey, CryptoError>;

    /// Encode a KEM encapsulation (public) key to bytes.
    fn encode_kem_encaps_key(key: &Self::KemEncapsKey) -> Vec<u8>;

    /// Decode a KEM encapsulation key from bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidKey`] if the bytes are malformed.
    fn decode_kem_encaps_key(bytes: &[u8]) -> Result<Self::KemEncapsKey, CryptoError>;

    /// Encode a KEM decapsulation (secret) key to bytes.
    fn encode_kem_decaps_key(key: &Self::KemDecapsKey) -> Vec<u8>;

    /// Decode a KEM decapsulation key from bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidKey`] if the bytes are malformed.
    fn decode_kem_decaps_key(bytes: &[u8]) -> Result<Self::KemDecapsKey, CryptoError>;
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("KEM decapsulation failed")]
    DecapsFailed,
    #[error("signature verification failed")]
    VerificationFailed,
    #[error("invalid key material")]
    InvalidKey,
}
