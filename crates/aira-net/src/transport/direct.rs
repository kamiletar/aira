//! Direct transport — plain QUIC via iroh, no obfuscation.
//!
//! Default mode for networks without censorship.
//! TODO(M2): implement

use super::AiraTransport;

pub struct DirectTransport;

impl AiraTransport for DirectTransport {}
