//! aira-core — cryptography, protocol, Triple Ratchet (SPQR)
//!
//! This crate contains the core cryptographic and protocol logic for Aira.
//! It is platform-agnostic and has no I/O — pure computation.
//!
//! # Key modules
//!
//! - [`crypto`] — `CryptoProvider` trait and implementations
//! - [`seed`] — BIP-39 seed phrase and deterministic key derivation
//! - [`identity`] — ML-DSA-65 identity keypair
//! - [`kem`] — Hybrid X25519 + ML-KEM-768 key agreement
//! - [`handshake`] — PQXDH handshake + capability negotiation
//! - [`ratchet`] — Triple Ratchet (SPQR): classical DR + PQ ratchet
//! - [`proto`] — Message format, `PlainPayload`, `EncryptedEnvelope`
//! - [`padding`] — Message padding to fixed-size blocks
//! - [`safety`] — Safety Numbers for key verification
//! - [`i18n`] — Mozilla Fluent i18n

#![deny(unsafe_code)]
#![warn(clippy::all, clippy::pedantic)]
// `unwrap_used` is forbidden in production code but relaxed for tests,
// where terse `.unwrap()` is idiomatic and panic-on-failure is the
// desired behavior. `forbid` cannot be overridden, so we use `deny` here
// and add `#[allow]` to test modules as needed.
#![deny(clippy::unwrap_used)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss,
        clippy::cast_possible_wrap
    )
)]

mod bip39_wordlist;
pub mod crypto;
pub mod device;
pub mod group;
pub mod group_proto;
pub mod handshake;
pub mod i18n;
pub mod identity;
pub mod kem;
pub mod padding;
pub mod proto;
pub mod ratchet;
pub mod safety;
pub mod seed;
pub mod spam;
pub mod sync;
pub mod util;
