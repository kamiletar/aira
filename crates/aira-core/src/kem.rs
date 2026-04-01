//! Hybrid KEM: X25519 + ML-KEM-768.
//!
//! `SharedSecret = BLAKE3(X25519_secret || MLKEM768_secret || context)`
//!
//! Both must be broken simultaneously for an attack to succeed.
//! See SPEC.md §4.2.
//!
//! TODO(M1): full implementation
