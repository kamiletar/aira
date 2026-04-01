//! CryptoProvider abstraction — allows swapping RustCrypto (Phase 1)
//! for aws-lc-rs FIPS 140-3 (Phase 2) without rewriting protocol logic.
//!
//! See SPEC.md §10.1 for the migration strategy.
//! See docs/KEY_CONTEXTS.md for the canonical list of KDF contexts.

pub mod rustcrypto;
// pub mod awslc;  // Phase 2: uncomment when migrating to FIPS

/// Abstraction over PQ cryptographic backends.
///
/// Implementations: [`rustcrypto`] (Phase 1), `awslc` (Phase 2).
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

    /// ML-KEM-768 encapsulation. Returns (ciphertext, shared_secret).
    fn kem_encaps(pk: &Self::KemEncapsKey) -> (Vec<u8>, zeroize::Zeroizing<[u8; 32]>);

    /// ML-KEM-768 decapsulation. Returns shared_secret.
    fn kem_decaps(
        sk: &Self::KemDecapsKey,
        ct: &[u8],
    ) -> Result<zeroize::Zeroizing<[u8; 32]>, CryptoError>;
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
