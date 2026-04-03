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
    #[must_use]
    pub fn from_seed(seed: &MasterSeed) -> Self {
        let derived = seed.derive("aira/identity/0");
        let (signing_key, verifying_key) = ActiveProvider::identity_keygen(&derived);
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Create identity from a BIP-39 phrase (convenience wrapper).
    ///
    /// # Errors
    ///
    /// Returns [`AiraError::SeedDerivation`] or [`AiraError::InvalidSeedPhrase`]
    /// if the phrase is invalid.
    pub fn from_phrase(phrase: &str) -> Result<Self, AiraError> {
        let seed = MasterSeed::from_phrase(phrase)?;
        Ok(Self::from_seed(&seed))
    }

    /// Sign a message with the identity's ML-DSA-65 signing key.
    #[must_use]
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        ActiveProvider::sign(&self.signing_key, msg)
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
        let seed = test_seed();
        let id1 = Identity::from_seed(&seed);
        let id2 = Identity::from_seed(&seed);

        // Same seed → same keys (public keys must match)
        assert_eq!(
            id1.public_key_bytes(),
            id2.public_key_bytes(),
            "same seed must produce identical public keys"
        );

        // Cross-verification: sig from one key verifies with the other
        let msg = b"determinism check";
        let sig1 = id1.sign(msg);
        let sig2 = id2.sign(msg);
        assert!(id1.verify(msg, &sig2));
        assert!(id2.verify(msg, &sig1));
    }

    #[test]
    fn identity_sign_verify() {
        let id = Identity::from_seed(&test_seed());
        let msg = b"hello aira";
        let sig = id.sign(msg);
        assert!(id.verify(msg, &sig));
        assert!(!id.verify(b"wrong message", &sig));
    }

    #[test]
    fn identity_fingerprint_format() {
        let id = Identity::from_seed(&test_seed());
        let fp = id.fingerprint();
        // Format: xxxx-xxxx-xxxx-xxxx (19 chars total)
        assert_eq!(fp.len(), 19);
        assert_eq!(fp.chars().filter(|&c| c == '-').count(), 3);
    }

    #[test]
    fn identity_public_key_size() {
        let id = Identity::from_seed(&test_seed());
        let pk = id.public_key_bytes();
        assert_eq!(pk.len(), 1952, "ML-DSA-65 verifying key is 1952 bytes");
    }
}
