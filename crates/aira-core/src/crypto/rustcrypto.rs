//! `RustCrypto` backend (Phase 1): ml-kem + ml-dsa — pure Rust.
//!
//! See SPEC.md §10.1 for the migration strategy to aws-lc-rs (Phase 2).
//! TODO(M1): implement `CryptoProvider` for `RustCrypto`

use super::{CryptoError, CryptoProvider};
use zeroize::Zeroizing;

pub struct RustCryptoProvider;

impl CryptoProvider for RustCryptoProvider {
    type SigningKey = (); // TODO(M1): ml_dsa::SigningKey<ml_dsa::MlDsa65>
    type VerifyingKey = (); // TODO(M1): ml_dsa::VerifyingKey<ml_dsa::MlDsa65>
    type KemDecapsKey = (); // TODO(M1): ml_kem::DecapsKey<ml_kem::MlKem768>
    type KemEncapsKey = (); // TODO(M1): ml_kem::EncapsKey<ml_kem::MlKem768>

    fn identity_keygen(_seed: &[u8; 32]) -> (Self::SigningKey, Self::VerifyingKey) {
        todo!("M1: implement ML-DSA-65 keygen from seed")
    }

    fn sign(_key: &Self::SigningKey, _msg: &[u8]) -> Vec<u8> {
        todo!("M1: implement ML-DSA-65 sign")
    }

    fn verify(_key: &Self::VerifyingKey, _msg: &[u8], _sig: &[u8]) -> bool {
        todo!("M1: implement ML-DSA-65 verify")
    }

    fn kem_keygen(_seed: &[u8; 32]) -> (Self::KemDecapsKey, Self::KemEncapsKey) {
        todo!("M1: implement ML-KEM-768 keygen from seed")
    }

    fn kem_encaps(_pk: &Self::KemEncapsKey) -> (Vec<u8>, Zeroizing<[u8; 32]>) {
        todo!("M1: implement ML-KEM-768 encaps")
    }

    fn kem_decaps(
        _sk: &Self::KemDecapsKey,
        _ct: &[u8],
    ) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
        todo!("M1: implement ML-KEM-768 decaps")
    }
}
