//! Pluggable transport stack.
//!
//! Each layer is independently configurable:
//! aira-core (encrypted) → Padding → Obfuscation → Transport
//!
//! See SPEC.md §11A.
//!
//! TODO(M7): implement obfs/mimicry/cdn transports
//! TODO(M12): implement REALITY and Tor transports

/// Abstraction over pluggable transports.
pub trait AiraTransport: Send + Sync {
    // TODO(M7): async wrap_outbound / accept_inbound
}

pub mod direct;
// pub mod obfs;    // M7: obfs4/o5 via ptrs
// pub mod mimicry; // M7: protocol mimicry
// pub mod cdn;     // M7: Cloudflare Worker relay
// pub mod reality; // M12: REALITY-like TLS camouflage
// pub mod tor;     // M12: Tor via arti (feature = "tor")
