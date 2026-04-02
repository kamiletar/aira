//! OS keychain integration for storing the daemon unlock passphrase.
//!
//! Uses the `keyring` crate for cross-platform access:
//! - Linux: Secret Service (GNOME/KDE)
//! - macOS: Keychain
//! - Windows: Credential Manager

/// Service name used in the OS keychain.
const SERVICE: &str = "aira-messenger";
/// Account name used in the OS keychain.
const ACCOUNT: &str = "daemon-passphrase";

/// Keychain errors.
#[derive(Debug, thiserror::Error)]
pub enum KeychainError {
    #[error("keychain error: {0}")]
    Keyring(#[from] keyring::Error),
}

/// Store a passphrase in the OS keychain.
///
/// # Errors
///
/// Returns `KeychainError` if the OS keychain is unavailable.
pub fn store_passphrase(passphrase: &str) -> Result<(), KeychainError> {
    let entry = keyring::Entry::new(SERVICE, ACCOUNT)?;
    entry.set_password(passphrase)?;
    Ok(())
}

/// Load a passphrase from the OS keychain.
///
/// Returns `None` if no passphrase is stored.
///
/// # Errors
///
/// Returns `KeychainError` if the OS keychain is unavailable.
pub fn load_passphrase() -> Result<Option<String>, KeychainError> {
    let entry = keyring::Entry::new(SERVICE, ACCOUNT)?;
    match entry.get_password() {
        Ok(pass) => Ok(Some(pass)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(KeychainError::Keyring(e)),
    }
}

/// Delete the passphrase from the OS keychain.
///
/// # Errors
///
/// Returns `KeychainError` if the OS keychain is unavailable.
pub fn delete_passphrase() -> Result<(), KeychainError> {
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
        store_passphrase("test-pass-123").expect("store");
        let loaded = load_passphrase().expect("load");
        assert_eq!(loaded, Some("test-pass-123".to_string()));
        delete_passphrase().expect("delete");
        let after = load_passphrase().expect("load after delete");
        assert_eq!(after, None);
    }
}
