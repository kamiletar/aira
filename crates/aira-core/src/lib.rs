//! aira-core — cryptography, protocol, Triple Ratchet (SPQR)
//!
//! This crate contains the core cryptographic and protocol logic for Aira.
//! It is platform-agnostic and has no I/O — pure computation.
//!
//! # Key modules
//!
//! - [`crypto`] — CryptoProvider trait and implementations
//! - [`seed`] — BIP-39 seed phrase and deterministic key derivation
//! - [`identity`] — ML-DSA-65 identity keypair
//! - [`kem`] — Hybrid X25519 + ML-KEM-768 key agreement
//! - [`handshake`] — PQXDH handshake + capability negotiation
//! - [`ratchet`] — Triple Ratchet (SPQR): classical DR + PQ ratchet
//! - [`proto`] — Message format, PlainPayload, EncryptedEnvelope
//! - [`padding`] — Message padding to fixed-size blocks
//! - [`safety`] — Safety Numbers for key verification
//! - [`i18n`] — Mozilla Fluent i18n

#![deny(unsafe_code)]
#![warn(clippy::all, clippy::pedantic)]
#![forbid(clippy::unwrap_used)]

pub mod crypto;
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
