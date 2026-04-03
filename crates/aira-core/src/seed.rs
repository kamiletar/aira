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
use sha2::{Digest, Sha256};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::bip39_wordlist::BIP39_WORDS;
use crate::proto::AiraError;

// ─── Argon2id parameters ─────────────────────────────────────────────────────

/// Desktop Argon2id parameters: m=256MB, t=3 iterations, p=4 lanes.
const ARGON2_DESKTOP_M_COST: u32 = 262_144; // 256 MB in KiB
const ARGON2_DESKTOP_T_COST: u32 = 3;
const ARGON2_DESKTOP_P_COST: u32 = 4;
const ARGON2_DESKTOP_SALT: &[u8] = b"aira-master-v1-m256";

/// Mobile Argon2id parameters: m=64MB, t=4 iterations, p=4 lanes.
const ARGON2_MOBILE_M_COST: u32 = 65_536; // 64 MB in KiB
const ARGON2_MOBILE_T_COST: u32 = 4;
const ARGON2_MOBILE_P_COST: u32 = 4;
const ARGON2_MOBILE_SALT: &[u8] = b"aira-master-v1-m64";

/// Platform profile for Argon2id parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// Desktop: m=256MB, t=3, p=4
    Desktop,
    /// Mobile: m=64MB, t=4, p=4
    Mobile,
}

impl Platform {
    fn argon2_params(self) -> (u32, u32, u32, &'static [u8]) {
        match self {
            Self::Desktop => (
                ARGON2_DESKTOP_M_COST,
                ARGON2_DESKTOP_T_COST,
                ARGON2_DESKTOP_P_COST,
                ARGON2_DESKTOP_SALT,
            ),
            Self::Mobile => (
                ARGON2_MOBILE_M_COST,
                ARGON2_MOBILE_T_COST,
                ARGON2_MOBILE_P_COST,
                ARGON2_MOBILE_SALT,
            ),
        }
    }
}

// ─── MasterSeed ──────────────────────────────────────────────────────────────

/// The master seed derived from the BIP-39 phrase.
///
/// This is the root secret. All keys are derived from it.
/// It is zeroized on drop.
#[derive(ZeroizeOnDrop)]
pub struct MasterSeed(Zeroizing<[u8; 32]>);

impl MasterSeed {
    /// Derive a master seed from a 24-word BIP-39 mnemonic phrase.
    ///
    /// Uses desktop Argon2id parameters (m=256MB).
    /// This is intentionally slow (~1-3s) due to Argon2id memory-hardness.
    ///
    /// # Errors
    ///
    /// Returns [`AiraError::SeedDerivation`] if the phrase is invalid or
    /// Argon2id hashing fails.
    pub fn from_phrase(phrase: &str) -> Result<Self, AiraError> {
        Self::from_phrase_with_platform(phrase, Platform::Desktop)
    }

    /// Derive a master seed with specific platform parameters.
    ///
    /// Use [`Platform::Mobile`] for mobile devices with limited RAM.
    ///
    /// # Errors
    ///
    /// Returns [`AiraError::SeedDerivation`] if the phrase is invalid or
    /// Argon2id hashing fails.
    pub fn from_phrase_with_platform(phrase: &str, platform: Platform) -> Result<Self, AiraError> {
        let entropy = bip39_decode(phrase)?;
        let (m_cost, t_cost, p_cost, salt) = platform.argon2_params();
        let mut seed = Zeroizing::new([0u8; 32]);

        let params = Params::new(m_cost, t_cost, p_cost, Some(32))
            .map_err(|_| AiraError::SeedDerivation("invalid argon2 params".into()))?;

        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(&entropy, salt, seed.as_mut())
            .map_err(|e| AiraError::SeedDerivation(e.to_string()))?;

        Ok(Self(seed))
    }

    /// Generate a new random 24-word BIP-39 mnemonic and derive the seed.
    ///
    /// Returns `(phrase, seed)` so the user can back up the phrase.
    ///
    /// # Errors
    ///
    /// Returns [`AiraError::SeedDerivation`] if Argon2id hashing fails
    /// (should never happen with valid parameters).
    pub fn generate() -> Result<(String, Self), AiraError> {
        let entropy: [u8; 32] = rand_entropy();
        let phrase = bip39_encode(&entropy);
        let seed = Self::from_phrase(&phrase)?;
        Ok((phrase, seed))
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

// ─── BIP-39 ──────────────────────────────────────────────────────────────────

/// Encode 32 bytes of entropy into a 24-word BIP-39 mnemonic.
///
/// BIP-39 for 256-bit entropy:
/// - Take SHA-256 of entropy, use first 8 bits as checksum
/// - Concatenate entropy (256 bits) + checksum (8 bits) = 264 bits
/// - Split into 24 groups of 11 bits → 24 word indices
fn bip39_encode(entropy: &[u8; 32]) -> String {
    let checksum = Sha256::digest(entropy)[0]; // first byte = 8 bits of checksum

    // Build 264-bit value: entropy (256 bits) || checksum (8 bits)
    // We work with a 33-byte array
    let mut bits = [0u8; 33];
    bits[..32].copy_from_slice(entropy);
    bits[32] = checksum;

    let mut words = Vec::with_capacity(24);
    for i in 0..24 {
        let bit_offset = i * 11;
        let index = extract_11_bits(&bits, bit_offset);
        words.push(BIP39_WORDS[index as usize]);
    }

    words.join(" ")
}

/// Decode a 24-word BIP-39 mnemonic to 32 bytes of entropy.
///
/// Validates word count, word presence in wordlist, and checksum.
///
/// # Errors
///
/// Returns [`AiraError::InvalidSeedPhrase`] if:
/// - Word count is not 24
/// - A word is not in the BIP-39 English wordlist
/// - The checksum does not match
fn bip39_decode(phrase: &str) -> Result<Vec<u8>, AiraError> {
    let words: Vec<&str> = phrase.split_whitespace().collect();
    if words.len() != 24 {
        return Err(AiraError::InvalidSeedPhrase);
    }

    // Look up each word's 11-bit index
    let mut indices = Vec::with_capacity(24);
    for word in &words {
        let idx = BIP39_WORDS
            .iter()
            .position(|w| w == word)
            .ok_or(AiraError::InvalidSeedPhrase)?;
        #[allow(clippy::cast_possible_truncation)]
        indices.push(idx as u16);
    }

    // Reconstruct 264 bits (33 bytes) from 24 x 11-bit indices
    let mut bits = [0u8; 33];
    for (i, &idx) in indices.iter().enumerate() {
        set_11_bits(&mut bits, i * 11, idx);
    }

    // Split: first 32 bytes = entropy, last byte's high bit = checksum (8 bits)
    let entropy = &bits[..32];
    let stored_checksum = bits[32];

    // Verify checksum
    let computed_checksum = Sha256::digest(entropy)[0];
    if stored_checksum != computed_checksum {
        return Err(AiraError::InvalidSeedPhrase);
    }

    Ok(entropy.to_vec())
}

/// Extract an 11-bit value starting at `bit_offset` from a byte array.
fn extract_11_bits(data: &[u8], bit_offset: usize) -> u16 {
    let byte_idx = bit_offset / 8;
    let bit_idx = bit_offset % 8;

    // Read 3 bytes (max needed for 11 bits spanning byte boundaries)
    let b0 = u32::from(*data.get(byte_idx).unwrap_or(&0));
    let b1 = u32::from(*data.get(byte_idx + 1).unwrap_or(&0));
    let b2 = u32::from(*data.get(byte_idx + 2).unwrap_or(&0));

    let combined = (b0 << 16) | (b1 << 8) | b2;
    let shift = 24 - 11 - bit_idx;

    #[allow(clippy::cast_possible_truncation)]
    let result = ((combined >> shift) & 0x7FF) as u16;
    result
}

/// Set an 11-bit value at `bit_offset` in a byte array.
fn set_11_bits(data: &mut [u8], bit_offset: usize, value: u16) {
    for bit in 0..11 {
        let src_bit = (value >> (10 - bit)) & 1;
        let dst_pos = bit_offset + bit;
        let byte_idx = dst_pos / 8;
        let bit_idx = 7 - (dst_pos % 8);
        if byte_idx < data.len() {
            if src_bit == 1 {
                data[byte_idx] |= 1 << bit_idx;
            } else {
                data[byte_idx] &= !(1 << bit_idx);
            }
        }
    }
}

/// Generate cryptographically random 32 bytes.
fn rand_entropy() -> [u8; 32] {
    use rand::RngCore;
    let mut entropy = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut entropy);
    entropy
}

// ─── Pseudonym Seeds (§12.6) ────────────────────────────────────────────────

/// Derived seed material for a per-context pseudonym keypair (§12.6).
///
/// Each counter yields an isolated set of seeds for ML-DSA signing, X25519 DH,
/// and ML-KEM-768 KEM. Counter→context mapping (group or contact) lives in
/// storage, not in the derivation path — so even with a compromised master seed,
/// an attacker cannot link a pseudonym to a specific group without storage access.
///
/// # Example
///
/// ```
/// # // Pseudonym derivation requires a MasterSeed, shown conceptually:
/// # // let seed = MasterSeed::from_phrase("...").unwrap();
/// # // let ps = seed.derive_pseudonym_seeds(0);
/// # // ps.signing — 32 bytes for ML-DSA-65 keygen
/// # // ps.x25519  — 32 bytes for X25519 keygen
/// # // ps.mlkem   — 32 bytes for ML-KEM-768 keygen
/// ```
#[derive(ZeroizeOnDrop)]
pub struct PseudonymSeeds {
    /// Seed for ML-DSA-65 signing keypair derivation.
    pub signing: Zeroizing<[u8; 32]>,
    /// Seed for X25519 DH keypair derivation.
    pub x25519: Zeroizing<[u8; 32]>,
    /// Seed for ML-KEM-768 KEM keypair derivation.
    pub mlkem: Zeroizing<[u8; 32]>,
}

impl MasterSeed {
    /// Derive pseudonym seed material for a specific counter (§12.6 BIP-32 model).
    ///
    /// Each counter yields an isolated set of keys: ML-DSA signing, X25519 DH,
    /// and ML-KEM-768 KEM. Counter→context mapping lives in storage.
    ///
    /// # KDF contexts (see `docs/KEY_CONTEXTS.md`)
    ///
    /// - `aira/pseudonym/<counter>/signing`
    /// - `aira/pseudonym/<counter>/x25519`
    /// - `aira/pseudonym/<counter>/mlkem`
    #[must_use]
    pub fn derive_pseudonym_seeds(&self, counter: u32) -> PseudonymSeeds {
        PseudonymSeeds {
            signing: self.derive(&format!("aira/pseudonym/{counter}/signing")),
            x25519: self.derive(&format!("aira/pseudonym/{counter}/x25519")),
            mlkem: self.derive(&format!("aira/pseudonym/{counter}/mlkem")),
        }
    }
}

/// Test helpers — exposed only in test builds for other modules.
#[cfg(test)]
pub(crate) mod test_helpers {
    use super::bip39_encode;

    /// Encode entropy to a BIP-39 phrase (test only).
    pub fn encode_entropy(entropy: &[u8; 32]) -> String {
        bip39_encode(entropy)
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bip39_encode_decode_roundtrip() {
        let entropy: [u8; 32] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98,
            0x76, 0x54, 0x32, 0x10,
        ];
        let phrase = bip39_encode(&entropy);
        let words: Vec<&str> = phrase.split_whitespace().collect();
        assert_eq!(words.len(), 24, "must produce 24 words");

        let decoded = bip39_decode(&phrase).expect("valid phrase should decode");
        assert_eq!(
            decoded.as_slice(),
            &entropy,
            "roundtrip must preserve entropy"
        );
    }

    #[test]
    fn bip39_random_roundtrip() {
        let entropy = rand_entropy();
        let phrase = bip39_encode(&entropy);
        let decoded = bip39_decode(&phrase).expect("generated phrase should decode");
        assert_eq!(decoded.as_slice(), &entropy);
    }

    #[test]
    fn bip39_invalid_word_rejected() {
        let phrase = "abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid acoustic acquire across act action actor actress xyznotaword";
        assert!(bip39_decode(phrase).is_err());
    }

    #[test]
    fn bip39_wrong_word_count_rejected() {
        assert!(bip39_decode("abandon ability able").is_err());
        assert!(bip39_decode("").is_err());
    }

    #[test]
    fn bip39_bad_checksum_rejected() {
        let entropy = rand_entropy();
        let phrase = bip39_encode(&entropy);
        // Replace last word to corrupt checksum
        let mut words: Vec<&str> = phrase.split_whitespace().collect();
        let last = words.last().copied().unwrap_or("abandon");
        let replacement = if last == "abandon" {
            "ability"
        } else {
            "abandon"
        };
        *words.last_mut().expect("non-empty") = replacement;
        let bad_phrase = words.join(" ");
        assert!(bip39_decode(&bad_phrase).is_err());
    }

    #[test]
    fn derive_produces_different_keys_for_different_contexts() {
        let entropy = rand_entropy();
        let phrase = bip39_encode(&entropy);
        let seed = MasterSeed::from_phrase(&phrase).expect("valid phrase");

        let key_identity = seed.derive("aira/identity/0");
        let key_x25519 = seed.derive("aira/x25519/0");
        let key_mlkem = seed.derive("aira/mlkem/0");
        let key_storage = seed.derive("aira/storage/0");

        // All keys must be different (key isolation guarantee)
        let ki: &[u8; 32] = &key_identity;
        let kx: &[u8; 32] = &key_x25519;
        let km: &[u8; 32] = &key_mlkem;
        let ks: &[u8; 32] = &key_storage;
        assert_ne!(ki, kx);
        assert_ne!(ki, km);
        assert_ne!(ki, ks);
        assert_ne!(kx, km);
        assert_ne!(kx, ks);
        assert_ne!(km, ks);
    }

    #[test]
    fn pseudonym_seeds_deterministic() {
        let entropy = rand_entropy();
        let phrase = bip39_encode(&entropy);
        let seed1 = MasterSeed::from_phrase(&phrase).expect("valid phrase");
        let seed2 = MasterSeed::from_phrase(&phrase).expect("valid phrase");

        let ps1 = seed1.derive_pseudonym_seeds(0);
        let ps2 = seed2.derive_pseudonym_seeds(0);

        let s1: &[u8; 32] = &ps1.signing;
        let s2: &[u8; 32] = &ps2.signing;
        assert_eq!(s1, s2, "same seed+counter must produce same signing seed");

        let x1: &[u8; 32] = &ps1.x25519;
        let x2: &[u8; 32] = &ps2.x25519;
        assert_eq!(x1, x2, "same seed+counter must produce same x25519 seed");

        let m1: &[u8; 32] = &ps1.mlkem;
        let m2: &[u8; 32] = &ps2.mlkem;
        assert_eq!(m1, m2, "same seed+counter must produce same mlkem seed");
    }

    #[test]
    fn pseudonym_seeds_isolated_across_counters() {
        let entropy = rand_entropy();
        let phrase = bip39_encode(&entropy);
        let seed = MasterSeed::from_phrase(&phrase).expect("valid phrase");

        let ps0 = seed.derive_pseudonym_seeds(0);
        let ps1 = seed.derive_pseudonym_seeds(1);

        let s0: &[u8; 32] = &ps0.signing;
        let s1: &[u8; 32] = &ps1.signing;
        assert_ne!(s0, s1, "different counters must produce different keys");

        let x0: &[u8; 32] = &ps0.x25519;
        let x1: &[u8; 32] = &ps1.x25519;
        assert_ne!(x0, x1);

        let m0: &[u8; 32] = &ps0.mlkem;
        let m1: &[u8; 32] = &ps1.mlkem;
        assert_ne!(m0, m1);
    }

    #[test]
    fn pseudonym_seeds_isolated_from_identity() {
        let entropy = rand_entropy();
        let phrase = bip39_encode(&entropy);
        let seed = MasterSeed::from_phrase(&phrase).expect("valid phrase");

        let ps = seed.derive_pseudonym_seeds(0);
        let identity = seed.derive("aira/identity/0");
        let x25519 = seed.derive("aira/x25519/0");
        let mlkem = seed.derive("aira/mlkem/0");
        let storage = seed.derive("aira/storage/0");

        let ps_signing: &[u8; 32] = &ps.signing;
        let ki: &[u8; 32] = &identity;
        let kx: &[u8; 32] = &x25519;
        let km: &[u8; 32] = &mlkem;
        let ks: &[u8; 32] = &storage;

        assert_ne!(ps_signing, ki, "pseudonym must not collide with identity");
        assert_ne!(ps_signing, kx, "pseudonym must not collide with x25519");
        assert_ne!(ps_signing, km, "pseudonym must not collide with mlkem");
        assert_ne!(ps_signing, ks, "pseudonym must not collide with storage");
    }

    #[test]
    fn pseudonym_seeds_internal_isolation() {
        let entropy = rand_entropy();
        let phrase = bip39_encode(&entropy);
        let seed = MasterSeed::from_phrase(&phrase).expect("valid phrase");

        let ps = seed.derive_pseudonym_seeds(0);
        let s: &[u8; 32] = &ps.signing;
        let x: &[u8; 32] = &ps.x25519;
        let m: &[u8; 32] = &ps.mlkem;

        assert_ne!(s, x, "signing != x25519 within same pseudonym");
        assert_ne!(s, m, "signing != mlkem within same pseudonym");
        assert_ne!(x, m, "x25519 != mlkem within same pseudonym");
    }

    #[test]
    fn generate_produces_valid_phrase_and_seed() {
        let (phrase, seed) = MasterSeed::generate().expect("generate");
        let words: Vec<&str> = phrase.split_whitespace().collect();
        assert_eq!(words.len(), 24, "BIP-39 phrase must be 24 words");

        // Phrase can re-derive the same seed
        let seed2 = MasterSeed::from_phrase(&phrase).expect("from_phrase");
        let k1: &[u8; 32] = &seed.derive("aira/identity/0");
        let k2: &[u8; 32] = &seed2.derive("aira/identity/0");
        assert_eq!(k1, k2, "generate() seed must be recoverable from phrase");
    }

    #[test]
    fn extract_11_bits_basic() {
        // 0x7FF = 11 bits all set = 2047
        let data = [0xFF, 0xE0, 0x00]; // 11111111 11100000 00000000
        assert_eq!(extract_11_bits(&data, 0), 0x7FF);

        // First word index 0 (all zeros)
        let data = [0x00, 0x00, 0x00];
        assert_eq!(extract_11_bits(&data, 0), 0);
    }
}
