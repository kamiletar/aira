//! Peer discovery: DHT lookup and direct add.
//!
//! DHT: ML-DSA_pubkey → iroh_NodeId (signed records, PoW, TTL 24h).
//! Direct add: user enters hex ML-DSA pubkey — no server needed.
//! See SPEC.md §5.2, §11B.4.
//!
//! TODO(M2): full implementation
