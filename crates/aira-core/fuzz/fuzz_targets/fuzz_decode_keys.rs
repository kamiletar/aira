//! Fuzz target for CryptoProvider key decoding functions.
//!
//! Ensures that arbitrary byte inputs never panic in decode_verifying_key,
//! decode_kem_encaps_key, and decode_kem_decaps_key.
//!
//! Run: `cargo fuzz run fuzz_decode_keys`

#![no_main]

use aira_core::crypto::rustcrypto::RustCryptoProvider;
use aira_core::crypto::CryptoProvider;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Must never panic on any input — only return Ok or Err
    let _ = RustCryptoProvider::decode_verifying_key(data);
    let _ = RustCryptoProvider::decode_kem_encaps_key(data);
    let _ = RustCryptoProvider::decode_kem_decaps_key(data);
});
