//! OS keychain integration for storing the BIP-39 seed phrase.
//!
//! Uses the `keyring` crate for cross-platform access:
//! - Linux: Secret Service (GNOME/KDE)
//! - macOS: Keychain
//! - Windows: Credential Manager
//!
//! Two storage modes are supported, exposed via [`StoredSeed`]:
//!
//! - [`StoredSeed::Plain`] (default): account
//!   `seed-phrase-plain-v1` holds the UTF-8 BIP-39 phrase directly.
//!   This is the "Signal/Telegram Desktop" model: OS ACL protection
//!   only, no extra password.
//! - [`StoredSeed::Vault`]: account `seed-phrase-vault-v1` holds a
//!   base64-encoded `password_vault::SeedVault` blob. Unlocking requires
//!   the user's password on every GUI startup.
//!
//! On load, the module checks the vault account first (security-
//! preferring), then the plain account. Exactly one of the two should
//! be populated at any time — `clear_all()` deletes both.
//!
//! ## Backwards compatibility
//!
//! Chunk A1 of Milestone 9.5 used the legacy account name
//! `"daemon-passphrase"` for the plaintext entry. On first run of a
//! v0.3.5 build, [`load_seed`] will also check that legacy account and,
//! if found, migrate it to `seed-phrase-plain-v1`, then delete the old
//! entry. This is a one-time, best-effort migration; failure to delete
//! the old entry is non-fatal.

use base64::Engine as _;
use zeroize::Zeroizing;

/// Service name used in the OS keychain.
const SERVICE: &str = "aira-messenger";
/// Account for plaintext seed phrase storage (current format).
const ACCOUNT_PLAIN: &str = "seed-phrase-plain-v1";
/// Account for password-protected vault blob storage.
const ACCOUNT_VAULT: &str = "seed-phrase-vault-v1";
/// Legacy account name used in Chunk A1 (before the dual-mode split).
const ACCOUNT_LEGACY: &str = "daemon-passphrase";

/// Keychain errors.
#[derive(Debug, thiserror::Error)]
pub enum KeychainError {
    #[error("keychain error: {0}")]
    Keyring(#[from] keyring::Error),
    #[error("vault blob base64 decode error: {0}")]
    Base64(String),
}

/// Representation of what we loaded from the keychain. Either a plaintext
/// phrase (ready to use immediately) or a locked vault blob that needs
/// to be decrypted with the user's password via `password_vault::unlock`.
///
/// `Vault` is currently unused at runtime — Chunks B3/B4 will wire it up
/// in the Settings view and the Unlock screen. Marked `#[allow(dead_code)]`
/// until then.
#[allow(dead_code)]
pub enum StoredSeed {
    Plain(Zeroizing<String>),
    Vault(Vec<u8>),
}

/// Load whichever seed entry exists in the keychain, preferring the
/// encrypted vault form.
///
/// Returns `Ok(None)` if neither account is present (fresh install or
/// post-reset); the caller should show the onboarding flow.
///
/// Performs a one-time migration from the legacy `daemon-passphrase`
/// account name to `seed-phrase-plain-v1`. Migration failure is
/// silently ignored — the returned phrase is still valid.
///
/// # Errors
///
/// Returns `KeychainError` if the OS keychain is unavailable, or
/// `KeychainError::Base64` if the vault blob is corrupted at rest.
pub fn load_seed() -> Result<Option<StoredSeed>, KeychainError> {
    // Prefer vault: if a password-protected entry exists, use it
    // regardless of any stray plaintext entry.
    if let Some(blob) = try_get(ACCOUNT_VAULT)? {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(blob.as_bytes())
            .map_err(|e| KeychainError::Base64(e.to_string()))?;
        return Ok(Some(StoredSeed::Vault(bytes)));
    }

    if let Some(phrase) = try_get(ACCOUNT_PLAIN)? {
        return Ok(Some(StoredSeed::Plain(Zeroizing::new(phrase))));
    }

    // Legacy migration path.
    if let Some(phrase) = try_get(ACCOUNT_LEGACY)? {
        let wrapped = Zeroizing::new(phrase);
        if let Err(e) = store_plain(&wrapped) {
            tracing::warn!("keychain: legacy migration store_plain failed: {e}");
        } else if let Err(e) = delete_account(ACCOUNT_LEGACY) {
            tracing::warn!("keychain: legacy delete failed: {e}");
        }
        return Ok(Some(StoredSeed::Plain(wrapped)));
    }

    Ok(None)
}

/// Backwards-compatible helper used by the IPC bridge bootstrap path
/// that currently only understands plaintext seeds. Returns `None` for
/// vault-mode installations so the bridge can surface a
/// "password required" update (chunk B4).
///
/// # Errors
///
/// Propagates `KeychainError` from [`load_seed`].
pub fn load_seed_phrase() -> Result<Option<Zeroizing<String>>, KeychainError> {
    match load_seed()? {
        Some(StoredSeed::Plain(phrase)) => Ok(Some(phrase)),
        Some(StoredSeed::Vault(_)) | None => Ok(None),
    }
}

/// Store a plaintext seed phrase, overwriting any existing vault entry.
///
/// # Errors
///
/// Returns `KeychainError` if the OS keychain is unavailable.
pub fn store_plain(phrase: &Zeroizing<String>) -> Result<(), KeychainError> {
    let entry = keyring::Entry::new(SERVICE, ACCOUNT_PLAIN)?;
    entry.set_password(phrase.as_str())?;
    let _ = delete_account(ACCOUNT_VAULT);
    Ok(())
}

/// Alias retained for callers that still use the chunk-A1 name. Writes
/// to the plaintext account.
///
/// # Errors
///
/// Returns `KeychainError` if the OS keychain is unavailable.
pub fn store_seed_phrase(phrase: &Zeroizing<String>) -> Result<(), KeychainError> {
    store_plain(phrase)
}

/// Store a password-protected vault blob, overwriting any existing
/// plaintext entry.
///
/// # Errors
///
/// Returns `KeychainError` if the OS keychain is unavailable.
#[allow(dead_code)]
pub fn store_vault(blob: &[u8]) -> Result<(), KeychainError> {
    let encoded = base64::engine::general_purpose::STANDARD.encode(blob);
    let entry = keyring::Entry::new(SERVICE, ACCOUNT_VAULT)?;
    entry.set_password(&encoded)?;
    let _ = delete_account(ACCOUNT_PLAIN);
    Ok(())
}

/// Delete both the plain and vault entries (identity reset).
///
/// # Errors
///
/// Returns `KeychainError` if the OS keychain is unavailable.
pub fn clear_all() -> Result<(), KeychainError> {
    let _ = delete_account(ACCOUNT_PLAIN);
    let _ = delete_account(ACCOUNT_VAULT);
    let _ = delete_account(ACCOUNT_LEGACY);
    Ok(())
}

/// Alias used by the existing IPC bridge code (`ResetIdentity` path).
///
/// # Errors
///
/// Returns `KeychainError` if the OS keychain is unavailable.
pub fn delete_seed_phrase() -> Result<(), KeychainError> {
    clear_all()
}

/// Low-level helper: delete a single account, treating `NoEntry` as success.
fn delete_account(account: &str) -> Result<(), KeychainError> {
    let entry = keyring::Entry::new(SERVICE, account)?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(KeychainError::Keyring(e)),
    }
}

/// Low-level helper: fetch an account's value, treating `NoEntry` as
/// `None`.
fn try_get(account: &str) -> Result<Option<String>, KeychainError> {
    let entry = keyring::Entry::new(SERVICE, account)?;
    match entry.get_password() {
        Ok(v) => Ok(Some(v)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(KeychainError::Keyring(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: keychain tests require a running secret service / keychain
    // agent, so they are marked #[ignore]. Run with
    // `cargo test -p aira-gui -- --ignored` on a machine with an
    // unlocked keychain.

    #[test]
    #[ignore]
    fn plain_roundtrip() {
        let phrase = Zeroizing::new("test plain phrase 123".to_string());
        store_plain(&phrase).expect("store");
        match load_seed().expect("load") {
            Some(StoredSeed::Plain(loaded)) => assert_eq!(loaded.as_str(), phrase.as_str()),
            other => panic!("expected Plain, got {other:?}", other = match other {
                Some(StoredSeed::Plain(_)) => "Plain",
                Some(StoredSeed::Vault(_)) => "Vault",
                None => "None",
            }),
        }
        clear_all().expect("clear");
        assert!(load_seed().expect("load after clear").is_none());
    }

    #[test]
    #[ignore]
    fn vault_roundtrip() {
        let blob = vec![1, 2, 3, 4, 5];
        store_vault(&blob).expect("store");
        match load_seed().expect("load") {
            Some(StoredSeed::Vault(loaded)) => assert_eq!(loaded, blob),
            _ => panic!("expected Vault"),
        }
        clear_all().expect("clear");
    }

    #[test]
    #[ignore]
    fn store_plain_removes_vault_and_vice_versa() {
        store_vault(&[9, 9, 9]).expect("store vault");
        let phrase = Zeroizing::new("abc".to_string());
        store_plain(&phrase).expect("store plain");
        match load_seed().expect("load") {
            Some(StoredSeed::Plain(_)) => {}
            _ => panic!("expected Plain after overwrite"),
        }

        store_vault(&[1]).expect("re-store vault");
        match load_seed().expect("load") {
            Some(StoredSeed::Vault(_)) => {}
            _ => panic!("expected Vault after overwrite"),
        }
        clear_all().expect("clear");
    }
}
