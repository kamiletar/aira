//! Triple Ratchet (SPQR) — Signal Sparse Post-Quantum Ratchet.
//!
//! Combines classical Double Ratchet (X25519) with sparse PQ Ratchet (ML-KEM-768).
//! PQ ratchet steps every ~50 messages or on direction change.
//! Keys are mixed via KDF: attacker must break both simultaneously.
//!
//! Reference: Signal SPQR paper (Eurocrypt 2025 / USENIX Security 2025).
//! See SPEC.md §4.4.
//!
//! TODO(M1): full implementation
