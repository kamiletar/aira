//! Application-level encryption for redb values.
//!
//! redb has no built-in encryption. We encrypt values before writing
//! and decrypt after reading, using ChaCha20-Poly1305 with random nonces.
//!
//! Format: `nonce (12 bytes) || ciphertext (variable)`
//!
//! See SPEC.md §7.1.

#![allow(clippy::module_name_repetitions)]

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use rand::RngCore;

use crate::StorageError;

/// Minimum size of an encrypted blob (12-byte nonce + 16-byte auth tag).
const MIN_ENCRYPTED_LEN: usize = 12 + 16;

/// Encrypt a plaintext value with ChaCha20-Poly1305.
///
/// Returns `nonce (12 bytes) || ciphertext`.
/// Uses a random nonce for each encryption.
///
/// # Errors
///
/// Returns [`StorageError::Encryption`] if encryption fails.
pub fn encrypt_value(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, StorageError> {
    let cipher = ChaCha20Poly1305::new(key.into());

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = chacha20poly1305::Nonce::from(nonce_bytes);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| StorageError::Encryption)?;

    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt a value encrypted with [`encrypt_value`].
///
/// Expects `nonce (12 bytes) || ciphertext`.
///
/// # Errors
///
/// Returns [`StorageError::Decryption`] if:
/// - The blob is too short (< 28 bytes)
/// - The authentication tag is invalid (wrong key or corrupted data)
pub fn decrypt_value(key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>, StorageError> {
    if blob.len() < MIN_ENCRYPTED_LEN {
        return Err(StorageError::Decryption);
    }

    let (nonce_bytes, ciphertext) = blob.split_at(12);
    let nonce = chacha20poly1305::Nonce::from_slice(nonce_bytes);
    let cipher = ChaCha20Poly1305::new(key.into());

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| StorageError::Decryption)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        [0x42; 32]
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = test_key();
        let plaintext = b"hello, encrypted world!";
        let encrypted = encrypt_value(&key, plaintext).expect("encrypt");
        let decrypted = decrypt_value(&key, &encrypted).expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn encrypted_differs_from_plaintext() {
        let key = test_key();
        let plaintext = b"secret data";
        let encrypted = encrypt_value(&key, plaintext).expect("encrypt");
        // Ciphertext portion (after nonce) must differ from plaintext
        assert_ne!(&encrypted[12..12 + plaintext.len()], &plaintext[..]);
    }

    #[test]
    fn different_nonces_each_call() {
        let key = test_key();
        let plaintext = b"same data";
        let enc1 = encrypt_value(&key, plaintext).expect("encrypt");
        let enc2 = encrypt_value(&key, plaintext).expect("encrypt");
        // Nonces (first 12 bytes) should differ
        assert_ne!(&enc1[..12], &enc2[..12]);
        // Both should decrypt to the same plaintext
        assert_eq!(
            decrypt_value(&key, &enc1).expect("decrypt"),
            decrypt_value(&key, &enc2).expect("decrypt")
        );
    }

    #[test]
    fn wrong_key_fails() {
        let key = test_key();
        let wrong_key = [0xFF; 32];
        let encrypted = encrypt_value(&key, b"data").expect("encrypt");
        assert!(decrypt_value(&wrong_key, &encrypted).is_err());
    }

    #[test]
    fn corrupted_data_fails() {
        let key = test_key();
        let mut encrypted = encrypt_value(&key, b"data").expect("encrypt");
        // Flip a byte in the ciphertext
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0xFF;
        assert!(decrypt_value(&key, &encrypted).is_err());
    }

    #[test]
    fn too_short_blob_fails() {
        let key = test_key();
        assert!(decrypt_value(&key, &[0u8; 10]).is_err());
    }

    #[test]
    fn empty_plaintext_roundtrip() {
        let key = test_key();
        let encrypted = encrypt_value(&key, b"").expect("encrypt");
        let decrypted = decrypt_value(&key, &encrypted).expect("decrypt");
        assert!(decrypted.is_empty());
    }
}
