//! BIP-39 seed phrase and deterministic key derivation.
//!
//! A user's entire identity is recoverable from a 24-word BIP-39 phrase.
//! All keys are derived deterministically via Argon2id + BLAKE3-KDF.
//!
//! # Key derivation contexts (see `docs/KEY_CONTEXTS.md`)
//!
//! | Context                | Algorithm   | Purpose                  |
//! |------------------------|-------------|--------------------------|
//! | `aira/identity/0`      | ML-DSA-65   | Identity signing key     |
//! | `aira/x25519/0`        | X25519      | ECDH component of KEM    |
//! | `aira/mlkem/0`         | ML-KEM-768  | PQ KEM component         |
//! | `aira/storage/0`       | `ChaCha20`  | Database encryption key  |
//!
//! # Security
//!
//! Argon2id with m=256MB prevents GPU/ASIC brute-force of the seed phrase.
//! The `/0` generation suffix allows key rotation without changing the phrase.

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::proto::AiraError;

/// Argon2id parameters for seed derivation.
/// m=256MB, t=3 iterations, p=4 lanes.
const ARGON2_M_COST: u32 = 262_144; // 256 MB in KiB
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 4;
const ARGON2_SALT: &[u8] = b"aira-master-v1";

/// The master seed derived from the BIP-39 phrase.
///
/// This is the root secret. All keys are derived from it.
/// It is zeroized on drop.
#[derive(ZeroizeOnDrop)]
pub struct MasterSeed(Zeroizing<[u8; 32]>);

impl MasterSeed {
    /// Derive a master seed from a 24-word BIP-39 mnemonic phrase.
    ///
    /// This is intentionally slow (~1-3s) due to Argon2id memory-hardness.
    ///
    /// # Errors
    ///
    /// Returns [`AiraError::SeedDerivation`] if the phrase is invalid or
    /// Argon2id hashing fails.
    pub fn from_phrase(phrase: &str) -> Result<Self, AiraError> {
        let entropy = bip39_decode(phrase)?;
        let mut seed = Zeroizing::new([0u8; 32]);

        let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
            .map_err(|_| AiraError::SeedDerivation("invalid argon2 params".into()))?;

        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(&entropy, ARGON2_SALT, seed.as_mut())
            .map_err(|e| AiraError::SeedDerivation(e.to_string()))?;

        Ok(Self(seed))
    }

    /// Generate a new random 24-word BIP-39 mnemonic and derive the seed.
    ///
    /// # Panics
    ///
    /// Panics if the internally generated phrase fails to parse (should never
    /// happen — indicates a bug in BIP-39 encoding).
    #[must_use]
    pub fn generate() -> (String, Self) {
        let entropy: [u8; 32] = rand_entropy();
        let phrase = bip39_encode(&entropy);
        let seed = Self::from_phrase(&phrase).expect("generated phrase is always valid");
        (phrase, seed)
    }

    /// Derive a 32-byte subkey for a specific purpose.
    ///
    /// The `context` string must be unique per use-case (see `docs/KEY_CONTEXTS.md`).
    /// Using the same context for different purposes is a security vulnerability.
    #[must_use]
    pub fn derive(&self, context: &str) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(blake3::derive_key(context, self.0.as_ref()))
    }
}

/// Decode BIP-39 mnemonic to raw entropy bytes.
fn bip39_decode(_phrase: &str) -> Result<Vec<u8>, AiraError> {
    // TODO(M1): implement BIP-39 decode using bip39 crate or custom wordlist
    todo!("implement BIP-39 decode")
}

/// Encode raw entropy bytes to BIP-39 mnemonic.
fn bip39_encode(_entropy: &[u8]) -> String {
    // TODO(M1): implement BIP-39 encode
    todo!("implement BIP-39 encode")
}

/// Generate cryptographically random 32 bytes.
fn rand_entropy() -> [u8; 32] {
    // TODO(M1): use rand::thread_rng or getrandom
    todo!("implement random entropy generation")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_is_deterministic() {
        // Same phrase → same derived keys on any machine
        // TODO(M1): add actual BIP-39 test vector
    }

    #[test]
    fn contexts_produce_different_keys() {
        // Ensure different KDF contexts produce different keys
        // (key isolation guarantee)
    }
}
