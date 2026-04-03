//! ML-DSA-65 identity keypair.
//!
//! The identity key is derived deterministically from the master seed:
//! `BLAKE3-KDF(master_seed, "aira/identity/0")` → ML-DSA-65 keypair.
//!
//! The verifying (public) key is the user's address — shared openly.
//! See SPEC.md §4.1.

use crate::crypto::{ActiveProvider, CryptoProvider};
use crate::proto::AiraError;
use crate::seed::MasterSeed;

/// The user's identity keypair (ML-DSA-65).
///
/// Derived deterministically from the master seed.
/// The signing key is zeroized on drop (via `ZeroizeOnDrop`).
pub struct Identity {
    signing_key: <ActiveProvider as CryptoProvider>::SigningKey,
    verifying_key: <ActiveProvider as CryptoProvider>::VerifyingKey,
}

impl Identity {
    /// Create identity from a master seed.
    ///
    /// Derives the identity signing key via BLAKE3-KDF with context
    /// `"aira/identity/0"`.
    /// Create identity from a master seed.
    ///
    /// # Errors
    ///
    /// Returns [`AiraError::Crypto`] if key generation fails.
    pub fn from_seed(seed: &MasterSeed) -> Result<Self, AiraError> {
        let derived = seed.derive("aira/identity/0");
        let (signing_key, verifying_key) = ActiveProvider::identity_keygen(&derived)
            .map_err(|e| AiraError::Crypto(e.to_string()))?;
        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// Create identity from a BIP-39 phrase (convenience wrapper).
    ///
    /// # Errors
    ///
    /// Returns [`AiraError::SeedDerivation`], [`AiraError::InvalidSeedPhrase`],
    /// or [`AiraError::Crypto`] if the phrase is invalid or keygen fails.
    pub fn from_phrase(phrase: &str) -> Result<Self, AiraError> {
        let seed = MasterSeed::from_phrase(phrase)?;
        Self::from_seed(&seed)
    }

    /// Sign a message with the identity's ML-DSA-65 signing key.
    ///
    /// # Errors
    ///
    /// Returns [`AiraError::Crypto`] if signing fails.
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, AiraError> {
        ActiveProvider::sign(&self.signing_key, msg).map_err(|e| AiraError::Crypto(e.to_string()))
    }

    /// Verify a signature against the identity's public key.
    #[must_use]
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        ActiveProvider::verify(&self.verifying_key, msg, sig)
    }

    /// Verify a signature against an arbitrary verifying key.
    #[must_use]
    pub fn verify_with_key(
        key: &<ActiveProvider as CryptoProvider>::VerifyingKey,
        msg: &[u8],
        sig: &[u8],
    ) -> bool {
        ActiveProvider::verify(key, msg, sig)
    }

    /// Get the encoded public (verifying) key bytes.
    ///
    /// This is the user's address (1,952 bytes for ML-DSA-65).
    #[must_use]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        ActiveProvider::encode_verifying_key(&self.verifying_key)
    }

    /// Get a short fingerprint for oral verification.
    ///
    /// Returns 16 hex characters: `BLAKE3(pubkey)[..8]` formatted as
    /// `xxxx-xxxx-xxxx-xxxx`.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        let pk_bytes = self.public_key_bytes();
        let hash = blake3::hash(&pk_bytes);
        let bytes = &hash.as_bytes()[..8];
        format!(
            "{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        )
    }

    /// Get a reference to the verifying key.
    #[must_use]
    pub fn verifying_key(&self) -> &<ActiveProvider as CryptoProvider>::VerifyingKey {
        &self.verifying_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_seed() -> MasterSeed {
        // Use a fixed phrase for deterministic testing
        // We use from_phrase_with_platform to avoid heavy desktop Argon2
        use crate::seed::Platform;
        let entropy = [42u8; 32];
        let phrase = crate::seed::test_helpers::encode_entropy(&entropy);
        MasterSeed::from_phrase_with_platform(&phrase, Platform::Mobile)
            .expect("test phrase should work")
    }

    #[test]
    fn identity_from_seed_is_deterministic() {
        // Larger stack: ML-DSA-65 keygen uses ~4KB+ on stack
        std::thread::Builder::new()
            .stack_size(8 * 1024 * 1024)
            .spawn(|| {
                let seed = test_seed();
                let id1 = Identity::from_seed(&seed).expect("from_seed 1");
                let id2 = Identity::from_seed(&seed).expect("from_seed 2");

                assert_eq!(
                    id1.public_key_bytes(),
                    id2.public_key_bytes(),
                    "same seed must produce identical public keys"
                );

                let msg = b"determinism check";
                let sig1 = id1.sign(msg).expect("sign1");
                let sig2 = id2.sign(msg).expect("sign2");
                assert!(id1.verify(msg, &sig2));
                assert!(id2.verify(msg, &sig1));
            })
            .expect("thread spawn")
            .join()
            .expect("thread join");
    }

    #[test]
    fn identity_sign_verify() {
        let id = Identity::from_seed(&test_seed()).expect("from_seed");
        let msg = b"hello aira";
        let sig = id.sign(msg).expect("sign");
        assert!(id.verify(msg, &sig));
        assert!(!id.verify(b"wrong message", &sig));
    }

    #[test]
    fn identity_fingerprint_format() {
        let id = Identity::from_seed(&test_seed()).expect("from_seed");
        let fp = id.fingerprint();
        // Format: xxxx-xxxx-xxxx-xxxx (19 chars total)
        assert_eq!(fp.len(), 19);
        assert_eq!(fp.chars().filter(|&c| c == '-').count(), 3);
    }

    #[test]
    fn identity_public_key_size() {
        let id = Identity::from_seed(&test_seed()).expect("from_seed");
        let pk = id.public_key_bytes();
        assert_eq!(pk.len(), 1952, "ML-DSA-65 verifying key is 1952 bytes");
    }
}
