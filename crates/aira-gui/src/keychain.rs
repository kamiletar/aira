//! OS keychain integration for storing the BIP-39 seed phrase.
//!
//! Uses the `keyring` crate for cross-platform access:
//! - Linux: Secret Service (GNOME/KDE)
//! - macOS: Keychain
//! - Windows: Credential Manager
//!
//! The seed phrase is wrapped in [`zeroize::Zeroizing`] so the in-memory copy
//! is wiped when dropped. Note that the `keyring` crate itself returns plain
//! `String`s internally; we convert to `Zeroizing` at the earliest point.

use zeroize::Zeroizing;

/// Service name used in the OS keychain.
const SERVICE: &str = "aira-messenger";
/// Account name for the plain-text seed phrase entry.
///
/// The account was previously `"daemon-passphrase"`; kept the same value so
/// existing installations (if any) keep working during this milestone. A
/// future Phase B introduces a separate `"seed-phrase-vault-v1"` account for
/// the password-protected variant.
const ACCOUNT: &str = "daemon-passphrase";

/// Keychain errors.
#[derive(Debug, thiserror::Error)]
pub enum KeychainError {
    #[error("keychain error: {0}")]
    Keyring(#[from] keyring::Error),
}

/// Store a BIP-39 seed phrase in the OS keychain.
///
/// The phrase is consumed from the provided `Zeroizing<String>` and passed
/// to the `keyring` crate which copies it into its own internal buffer. The
/// original `Zeroizing` wrapper ensures our local copy is wiped when dropped.
///
/// # Errors
///
/// Returns `KeychainError` if the OS keychain is unavailable.
pub fn store_seed_phrase(phrase: &Zeroizing<String>) -> Result<(), KeychainError> {
    let entry = keyring::Entry::new(SERVICE, ACCOUNT)?;
    entry.set_password(phrase.as_str())?;
    Ok(())
}

/// Load the BIP-39 seed phrase from the OS keychain.
///
/// Returns `None` if no phrase is stored (first run — caller should show the
/// onboarding flow).
///
/// # Errors
///
/// Returns `KeychainError` if the OS keychain is unavailable.
pub fn load_seed_phrase() -> Result<Option<Zeroizing<String>>, KeychainError> {
    let entry = keyring::Entry::new(SERVICE, ACCOUNT)?;
    match entry.get_password() {
        Ok(pass) => Ok(Some(Zeroizing::new(pass))),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(KeychainError::Keyring(e)),
    }
}

/// Delete the seed phrase from the OS keychain.
///
/// Used when the user resets their identity.
///
/// # Errors
///
/// Returns `KeychainError` if the OS keychain is unavailable.
pub fn delete_seed_phrase() -> Result<(), KeychainError> {
    let entry = keyring::Entry::new(SERVICE, ACCOUNT)?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(KeychainError::Keyring(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: keychain tests require a running secret service / keychain agent.
    // On CI without a keychain, these will fail; mark as #[ignore].

    #[test]
    #[ignore]
    fn store_load_delete_roundtrip() {
        let phrase = Zeroizing::new("test-pass-123".to_string());
        store_seed_phrase(&phrase).expect("store");
        let loaded = load_seed_phrase().expect("load");
        assert_eq!(
            loaded.as_ref().map(|z| z.as_str()),
            Some("test-pass-123")
        );
        delete_seed_phrase().expect("delete");
        let after = load_seed_phrase().expect("load after delete");
        assert!(after.is_none());
    }
}
