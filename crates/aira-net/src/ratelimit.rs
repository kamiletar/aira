//! Connection tiers + GCRA rate limiting (governor crate).
//!
//! Tier 1 — Verified contacts: unlimited
//! Tier 2 — Known peers: 100 msg/min
//! Tier 3 — Strangers: 5 msg/min + PoW required
//!
//! See SPEC.md §11B.1.
//!
//! TODO(M2): full implementation
