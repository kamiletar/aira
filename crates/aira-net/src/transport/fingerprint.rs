//! TLS fingerprint builder and REALITY TLS helpers.
//!
//! Provides:
//! - Browser-mimicking `ClientConfig` (Chrome/Firefox/Safari cipher suite ordering)
//! - `AcceptAnyCertVerifier` — client-side cert verifier for REALITY (accepts any cert)
//! - `build_reality_client_config` — `ClientConfig` for REALITY clients
//! - `build_server_config` — `ServerConfig` with ephemeral self-signed cert
//! - `generate_ephemeral_cert` — generates a self-signed cert for the given SNI
//!
//! See SPEC.md §11A.5.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::ClientConfig;
use rustls::crypto::ring as ring_provider;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConnection, DigitallySignedStruct, Error as TlsError, SignatureScheme};

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

fn browser_provider(fingerprint: BrowserFingerprint) -> CryptoProvider {
    let cipher_suites = match fingerprint {
        BrowserFingerprint::Chrome => chrome_cipher_suites(),
        BrowserFingerprint::Firefox => firefox_cipher_suites(),
        BrowserFingerprint::Safari => safari_cipher_suites(),
    };
    CryptoProvider {
        cipher_suites,
        ..ring_provider::default_provider()
    }
}

// ─── AcceptAnyCertVerifier ─────────────────────────────────────────────────

/// Certificate verifier that accepts **any** server certificate.
///
/// Used by REALITY clients because authentication is handled by the PSK
/// (short ID in Session ID + BLAKE3-MAC), not by CA-based certificate
/// validation.  The TLS layer is purely for DPI camouflage.
#[derive(Debug)]
struct AcceptAnyCertVerifier(Arc<CryptoProvider>);

impl ServerCertVerifier for AcceptAnyCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

// ─── Public API ────────────────────────────────────────────────────────────

/// Build a `rustls::ClientConfig` with standard CA verification and
/// browser-mimicking cipher suites.
///
/// Used for testing and non-REALITY connections.
pub fn build_client_config(
    fingerprint: BrowserFingerprint,
) -> Result<Arc<ClientConfig>, TransportError> {
    let provider = browser_provider(fingerprint);

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| TransportError::Config(format!("TLS version config: {e}")))?
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Ok(Arc::new(config))
}

/// Build a `rustls::ClientConfig` for REALITY transport.
///
/// Uses [`AcceptAnyCertVerifier`] instead of standard CA validation,
/// since the server presents an ephemeral self-signed certificate.
/// Authentication is handled by PSK (short ID + BLAKE3-MAC).
pub fn build_reality_client_config(
    fingerprint: BrowserFingerprint,
) -> Result<Arc<ClientConfig>, TransportError> {
    let provider = Arc::new(browser_provider(fingerprint));

    let config = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| TransportError::Config(format!("TLS version config: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCertVerifier(provider)))
        .with_no_client_auth();

    Ok(Arc::new(config))
}

/// Build a `rustls::ServerConfig` with the given certificate chain and key.
///
/// Used by the REALITY server to present an ephemeral self-signed cert.
pub fn build_server_config(
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<rustls::ServerConfig>, TransportError> {
    let provider = Arc::new(ring_provider::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| TransportError::Config(format!("TLS server version config: {e}")))?
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .map_err(|e| TransportError::Config(format!("TLS server cert config: {e}")))?;

    Ok(Arc::new(config))
}

/// Generate an ephemeral self-signed TLS certificate for the given SNI domain.
///
/// Returns `(cert_chain, private_key)` for use with [`build_server_config`].
pub fn generate_ephemeral_cert(
    sni: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), TransportError> {
    let cert = rcgen::generate_simple_self_signed(vec![sni.to_string()])
        .map_err(|e| TransportError::Config(format!("cert generation failed: {e}")))?;

    let cert_der = CertificateDer::from(cert.cert);
    let key_der = PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());

    Ok((vec![cert_der], key_der))
}

/// Build a test `ClientConnection` to verify the `ClientHello` structure.
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
        assert_ne!(chrome[3..], firefox[3..]);
    }

    #[test]
    fn test_connection_creates_successfully() {
        let cfg = build_client_config(BrowserFingerprint::Chrome).expect("build");
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

    #[test]
    fn reality_client_config_builds() {
        let cfg = build_reality_client_config(BrowserFingerprint::Chrome).expect("build");
        assert_eq!(cfg.crypto_provider().cipher_suites.len(), 9);
    }

    #[test]
    fn ephemeral_cert_generates() {
        let (certs, _key) = generate_ephemeral_cert("www.apple.com").expect("gen");
        assert_eq!(certs.len(), 1);
        assert!(!certs[0].is_empty());
    }

    #[test]
    fn server_config_builds_with_ephemeral_cert() {
        let (certs, key) = generate_ephemeral_cert("test.example.com").expect("gen");
        let _cfg = build_server_config(certs, key).expect("build");
    }
}
