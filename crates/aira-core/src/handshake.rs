//! PQXDH handshake + capability negotiation.
//!
//! Adapts Signal PQXDH (X3DH extension with PQ KEM) for Aira.
//! After successful handshake, Triple Ratchet (SPQR) is activated.
//! See SPEC.md §4.5, §6.4.
//!
//! TODO(M1): full implementation
