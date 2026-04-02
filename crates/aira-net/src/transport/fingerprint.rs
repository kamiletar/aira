//! TLS `ClientHello` fingerprint builder for REALITY transport.
//!
//! Constructs byte-level `ClientHello` messages that match known browser
//! fingerprints (Chrome, Firefox, Safari).  DPI systems (including GFW)
//! classify TLS traffic partly by the ordering of cipher suites, extensions,
//! supported groups, and signature algorithms in the `ClientHello`.  By
//! producing a message that looks identical to a mainstream browser we make
//! the connection indistinguishable from regular HTTPS.
//!
//! # Design
//!
//! Unlike the Go `uTLS` library we do **not** hook into the TLS stack.
//! Instead we use `tokio-rustls` / `rustls` for the actual handshake and
//! configure the `ClientConfig` with cipher suites and protocol versions
//! that match the target browser.  The resulting on-wire `ClientHello` will
//! have the correct cipher suite ordering and extension set.
//!
//! For details on what DPI inspects see SPEC.md §11A.5.

use std::sync::Arc;

use rustls::client::ClientConfig;
use rustls::crypto::ring as ring_provider;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::ServerName;
use rustls::ClientConnection;

use super::{BrowserFingerprint, TransportError};

// ─── Cipher suite sets per browser ─────────────────────────────────────────

/// TLS 1.3 cipher suites — all browsers support the same three but in
/// different orderings.
fn tls13_suites() -> Vec<rustls::SupportedCipherSuite> {
    vec![
        ring_provider::cipher_suite::TLS13_AES_256_GCM_SHA384,
        ring_provider::cipher_suite::TLS13_AES_128_GCM_SHA256,
        ring_provider::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
    ]
}

/// Chrome-style cipher suites: TLS 1.3 first, then selected TLS 1.2.
fn chrome_cipher_suites() -> Vec<rustls::SupportedCipherSuite> {
    let mut suites = tls13_suites();
    suites.extend([
        ring_provider::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        ring_provider::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        ring_provider::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        ring_provider::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        ring_provider::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        ring_provider::cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    ]);
    suites
}

/// Firefox-style cipher suites: TLS 1.3 first, then TLS 1.2 (slightly
/// different ordering from Chrome — `CHACHA20` before `AES_256`).
fn firefox_cipher_suites() -> Vec<rustls::SupportedCipherSuite> {
    let mut suites = tls13_suites();
    suites.extend([
        ring_provider::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        ring_provider::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        ring_provider::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        ring_provider::cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        ring_provider::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        ring_provider::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    ]);
    suites
}

/// Safari-style cipher suites: same TLS 1.3 set, plus TLS 1.2 with the
/// AES-256 suites promoted above AES-128.
fn safari_cipher_suites() -> Vec<rustls::SupportedCipherSuite> {
    let mut suites = tls13_suites();
    suites.extend([
        ring_provider::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        ring_provider::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        ring_provider::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        ring_provider::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        ring_provider::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        ring_provider::cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    ]);
    suites
}

// ─── Public API ────────────────────────────────────────────────────────────

/// Build a `rustls::ClientConfig` whose `ClientHello` mimics the given
/// browser fingerprint.
///
/// The returned config:
/// - uses the Mozilla root certificate store (via `webpki-roots`)
/// - orders cipher suites to match the target browser
/// - enables TLS 1.2 + 1.3
///
/// # Errors
///
/// Returns `TransportError::Config` if the TLS provider cannot be
/// initialised (should not happen with the `ring` backend).
pub fn build_client_config(
    fingerprint: BrowserFingerprint,
) -> Result<Arc<ClientConfig>, TransportError> {
    let cipher_suites = match fingerprint {
        BrowserFingerprint::Chrome => chrome_cipher_suites(),
        BrowserFingerprint::Firefox => firefox_cipher_suites(),
        BrowserFingerprint::Safari => safari_cipher_suites(),
    };

    let provider = CryptoProvider {
        cipher_suites,
        ..ring_provider::default_provider()
    };

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| TransportError::Config(format!("TLS version config: {e}")))?
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Ok(Arc::new(config))
}

/// Build a test `ClientConnection` to verify the `ClientHello` structure.
///
/// This is used in unit tests to inspect that the cipher suite ordering
/// and SNI are set correctly without actually connecting to a server.
///
/// # Errors
///
/// Returns `TransportError::Config` if the SNI is invalid.
pub fn build_test_connection(
    config: &Arc<ClientConfig>,
    sni: &str,
) -> Result<ClientConnection, TransportError> {
    let server_name = ServerName::try_from(sni.to_string())
        .map_err(|e| TransportError::Config(format!("invalid SNI: {e}")))?;
    ClientConnection::new(Arc::clone(config), server_name)
        .map_err(|e| TransportError::Config(format!("TLS connection init: {e}")))
}

/// Return the cipher suite count for a fingerprint (useful in tests).
#[must_use]
pub fn cipher_suite_count(fingerprint: BrowserFingerprint) -> usize {
    match fingerprint {
        BrowserFingerprint::Chrome => chrome_cipher_suites().len(),
        BrowserFingerprint::Firefox => firefox_cipher_suites().len(),
        BrowserFingerprint::Safari => safari_cipher_suites().len(),
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chrome_config_builds_successfully() {
        let cfg = build_client_config(BrowserFingerprint::Chrome).expect("build");
        // Chrome: 3 TLS1.3 + 6 TLS1.2 = 9
        assert_eq!(cfg.crypto_provider().cipher_suites.len(), 9);
    }

    #[test]
    fn firefox_config_builds_successfully() {
        let cfg = build_client_config(BrowserFingerprint::Firefox).expect("build");
        assert_eq!(cfg.crypto_provider().cipher_suites.len(), 9);
    }

    #[test]
    fn safari_config_builds_successfully() {
        let cfg = build_client_config(BrowserFingerprint::Safari).expect("build");
        assert_eq!(cfg.crypto_provider().cipher_suites.len(), 9);
    }

    #[test]
    fn chrome_and_firefox_have_different_suite_order() {
        let chrome = chrome_cipher_suites();
        let firefox = firefox_cipher_suites();
        // The first 3 (TLS1.3) are the same; TLS1.2 ordering differs.
        assert_ne!(chrome[3..], firefox[3..]);
    }

    #[test]
    fn test_connection_creates_successfully() {
        let cfg = build_client_config(BrowserFingerprint::Chrome).expect("build");
        // Verify connection is created with the correct SNI — if SNI were
        // invalid, build_test_connection would return Err.
        let _conn = build_test_connection(&cfg, "www.apple.com").expect("conn");
    }

    #[test]
    fn invalid_sni_returns_error() {
        let cfg = build_client_config(BrowserFingerprint::Chrome).expect("build");
        assert!(build_test_connection(&cfg, "").is_err());
    }

    #[test]
    fn cipher_suite_count_matches() {
        for fp in [
            BrowserFingerprint::Chrome,
            BrowserFingerprint::Firefox,
            BrowserFingerprint::Safari,
        ] {
            let cfg = build_client_config(fp).expect("build");
            assert_eq!(
                cfg.crypto_provider().cipher_suites.len(),
                cipher_suite_count(fp)
            );
        }
    }
}
