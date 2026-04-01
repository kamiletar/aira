//! ML-DSA-65 identity keypair.
//!
//! The identity key is derived deterministically from the master seed:
//! `BLAKE3-KDF(master_seed, "aira/identity/0")` → ML-DSA-65 keypair.
//!
//! The verifying (public) key is the user's address — shared openly.
//!
//! TODO(M1): full implementation

/// The user's identity keypair (ML-DSA-65).
/// Derived from master seed, zeroized on drop.
///
/// TODO(M1): add fields and #[derive(ZeroizeOnDrop)] once ml-dsa types are wired up:
///   verifying_key: ml_dsa::VerifyingKey<ml_dsa::MlDsa65>,
///   signing_key: zeroize::Zeroizing<ml_dsa::SigningKey<ml_dsa::MlDsa65>>,
///   master_seed: zeroize::Zeroizing<[u8; 32]>,
pub struct Identity {
    _placeholder: (),
}

impl Drop for Identity {
    fn drop(&mut self) {
        // TODO(M1): zeroize signing_key and master_seed here
    }
}
