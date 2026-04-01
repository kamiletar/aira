//! Store-and-forward relay with pairwise mailboxes.
//!
//! Relay stores encrypted envelopes (≤64 KB each) for offline peers.
//! Relay NEVER stores file content — only message notifications.
//! `Mailbox ID = BLAKE3(shared_secret || "mailbox")` — pairwise, unlinkable.
//!
//! Quotas: 10 MB / 100 msgs per mailbox, TTL 7 days.
//! See SPEC.md §6.3b, §6.5, §11B.5.
//!
//! TODO(M2): full implementation
