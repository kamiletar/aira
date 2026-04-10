//! Optional password-based encryption of the seed phrase.
//!
//! By default the seed phrase is stored plaintext in the OS keychain
//! (keychain ACLs + per-user login protection, same model as
//! Signal/Telegram Desktop). For users who want an extra layer, the
//! Settings view exposes a "Protect identity with password" toggle that
//! encrypts the phrase with a user-chosen passphrase before storing it.
//!
//! ## Construction
//!
//! - **KDF:** Argon2id, `m = 128 MiB, t = 3, p = 1`. This is lighter than
//!   the seed KDF in `aira-core` (m=256 MiB) because it runs in the UI
//!   thread on every unlock and we don't want a 3-second blocking hang
//!   on every GUI launch. It still keeps a GPU-resistant budget.
//! - **AEAD:** ChaCha20-Poly1305 with a per-vault random nonce.
//! - **Serialization:** postcard (matches the rest of the codebase).
//!
//! ## Key isolation (per `docs/KEY_CONTEXTS.md` rules)
//!
//! The Argon2id context here is *only* password → vault key. It uses a
//! per-vault random salt and is never derived from the master seed, so
//! there's no risk of cross-context key reuse with `aira-core/storage` or
//! `aira-core/identity` derivations. This context is registered in
//! `docs/KEY_CONTEXTS.md` as `aira-gui/password-vault/v1`.
//!
//! ## Version byte
//!
//! `SeedVault::version = 1` allows future migrations (e.g. stronger
//! parameters, different AEAD) without silent corruption.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

/// Current vault format version.
const VAULT_VERSION: u8 = 1;

/// Argon2id memory cost: 128 MiB. Halved from aira-core's 256 MiB so the
/// unlock step is ~1 second on modern desktops instead of ~3 seconds.
const ARGON2_M_COST_KIB: u32 = 128 * 1024;
/// Argon2id time cost (iterations).
const ARGON2_T_COST: u32 = 3;
/// Argon2id parallelism.
const ARGON2_P_COST: u32 = 1;

/// Errors returned by [`lock`] / [`unlock`].
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("argon2 error: {0}")]
    Argon2(String),
    #[error("aead error: {0}")]
    Aead(String),
    #[error("postcard (de)serialization error: {0}")]
    Postcard(#[from] postcard::Error),
    #[error("unsupported vault version {0}")]
    UnsupportedVersion(u8),
    #[error("ciphertext is not valid UTF-8")]
    NotUtf8,
}

/// On-disk / on-keychain format of a password-protected seed phrase.
#[derive(Debug, Serialize, Deserialize)]
struct SeedVault {
    version: u8,
    salt: [u8; 16],
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

impl Drop for SeedVault {
    fn drop(&mut self) {
        // Zeroize the ciphertext buffer on drop. Salt/nonce are not
        // secrets but zeroizing them costs nothing.
        self.salt.zeroize();
        self.nonce.zeroize();
        self.ciphertext.zeroize();
    }
}

/// Derive the vault key from a password and salt using Argon2id.
fn derive_key(
    password: &Zeroizing<String>,
    salt: &[u8; 16],
) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    let params = Params::new(ARGON2_M_COST_KIB, ARGON2_T_COST, ARGON2_P_COST, Some(32))
        .map_err(|e| VaultError::Argon2(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|e| VaultError::Argon2(e.to_string()))?;
    Ok(key)
}

/// Encrypt a seed phrase with a user password. Returns the serialized
/// vault blob ready to store in the keychain.
///
/// # Errors
///
/// Returns [`VaultError::Argon2`] or [`VaultError::Aead`] on cryptographic
/// failures, or [`VaultError::Postcard`] on serialization errors. These
/// should be unreachable in practice with valid inputs.
pub fn lock(
    phrase: &Zeroizing<String>,
    password: &Zeroizing<String>,
) -> Result<Vec<u8>, VaultError> {
    let mut rng = rand::thread_rng();
    let mut salt = [0u8; 16];
    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce_bytes);

    let key = derive_key(password, &salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, phrase.as_bytes())
        .map_err(|e| VaultError::Aead(e.to_string()))?;

    let vault = SeedVault {
        version: VAULT_VERSION,
        salt,
        nonce: nonce_bytes,
        ciphertext,
    };

    let blob = postcard::to_stdvec(&vault)?;
    Ok(blob)
}

/// Decrypt a vault blob with the user password. Returns the recovered
/// seed phrase on success.
///
/// # Errors
///
/// Returns [`VaultError::UnsupportedVersion`] if the blob version is
/// unknown, [`VaultError::Postcard`] if the blob is malformed,
/// [`VaultError::Argon2`] on KDF failure, [`VaultError::Aead`] if the
/// password is wrong or the ciphertext has been tampered with, or
/// [`VaultError::NotUtf8`] if the decrypted bytes aren't valid UTF-8.
pub fn unlock(blob: &[u8], password: &Zeroizing<String>) -> Result<Zeroizing<String>, VaultError> {
    let vault: SeedVault = postcard::from_bytes(blob)?;
    if vault.version != VAULT_VERSION {
        return Err(VaultError::UnsupportedVersion(vault.version));
    }

    let key = derive_key(password, &vault.salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
    let nonce = Nonce::from_slice(&vault.nonce);

    let plaintext = cipher
        .decrypt(nonce, vault.ciphertext.as_slice())
        .map_err(|e| VaultError::Aead(e.to_string()))?;

    // Wrap in Zeroizing before any fallible step so a parse error still
    // wipes the bytes on drop.
    let mut plaintext = Zeroizing::new(plaintext);
    let phrase = String::from_utf8(plaintext.to_vec()).map_err(|_| VaultError::NotUtf8)?;
    plaintext.zeroize();
    Ok(Zeroizing::new(phrase))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_phrase() -> Zeroizing<String> {
        Zeroizing::new(
            "abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon abandon abandon art"
                .to_string(),
        )
    }

    #[test]
    fn lock_unlock_roundtrip() {
        let phrase = sample_phrase();
        let password = Zeroizing::new("correct horse battery staple".to_string());
        let blob = lock(&phrase, &password).expect("lock");
        let recovered = unlock(&blob, &password).expect("unlock");
        assert_eq!(recovered.as_str(), phrase.as_str());
    }

    #[test]
    fn unlock_with_wrong_password_fails() {
        let phrase = sample_phrase();
        let good = Zeroizing::new("correct horse battery staple".to_string());
        let bad = Zeroizing::new("incorrect horse battery staple".to_string());
        let blob = lock(&phrase, &good).expect("lock");
        assert!(matches!(unlock(&blob, &bad), Err(VaultError::Aead(_))));
    }

    #[test]
    fn unlock_corrupted_blob_fails() {
        let phrase = sample_phrase();
        let password = Zeroizing::new("abc".to_string());
        let mut blob = lock(&phrase, &password).expect("lock");
        // Flip a byte near the end of the ciphertext to trigger an AEAD
        // authentication failure.
        let n = blob.len();
        blob[n - 1] ^= 0x01;
        assert!(unlock(&blob, &password).is_err());
    }

    #[test]
    fn unlock_rejects_unknown_version() {
        let phrase = sample_phrase();
        let password = Zeroizing::new("abc".to_string());
        let blob = lock(&phrase, &password).expect("lock");
        // First byte of a postcard-encoded SeedVault is the `version`
        // field. Flip it to 99 to simulate a future-format blob.
        let mut tampered = blob.clone();
        tampered[0] = 99;
        let err = unlock(&tampered, &password);
        assert!(
            matches!(err, Err(VaultError::UnsupportedVersion(99))),
            "unexpected: {err:?}"
        );
    }

    #[test]
    fn different_salts_produce_different_ciphertexts() {
        // Same phrase + same password should still produce distinct blobs
        // because salt and nonce are random.
        let phrase = sample_phrase();
        let password = Zeroizing::new("abc".to_string());
        let a = lock(&phrase, &password).expect("lock a");
        let b = lock(&phrase, &password).expect("lock b");
        assert_ne!(a, b);
    }
}
