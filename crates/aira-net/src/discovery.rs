//! Peer discovery: invitation links and direct add.
//!
//! Primary mechanism for v0.1 is invitation links:
//! `aira://add/<base64url(postcard(InvitationData))>`
//!
//! DHT discovery is optional in v0.1 and will be implemented in a later milestone.
//! See SPEC.md §5.2, §11B.4.

use serde::{Deserialize, Serialize};

use crate::NetError;

/// An invitation link containing a peer's identity public key and network address.
///
/// Format: `aira://add/<base64url(postcard(InvitationLink))>`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvitationLink {
    /// ML-DSA-65 identity public key (1952 bytes).
    pub identity_pk: Vec<u8>,
    /// Serialized `EndpointAddr` for establishing connection.
    pub endpoint_addr_bytes: Vec<u8>,
}

impl InvitationLink {
    /// Create a new invitation link.
    #[must_use]
    pub fn new(identity_pk: Vec<u8>, endpoint_addr_bytes: Vec<u8>) -> Self {
        Self {
            identity_pk,
            endpoint_addr_bytes,
        }
    }

    /// Encode as a URI string: `aira://add/<base64url>`.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization fails.
    pub fn to_uri(&self) -> Result<String, NetError> {
        let bytes = postcard::to_allocvec(self)?;
        let encoded = base64url_encode(&bytes);
        Ok(format!("aira://add/{encoded}"))
    }

    /// Decode from a URI string.
    ///
    /// # Errors
    ///
    /// Returns an error if the URI is malformed or deserialization fails.
    pub fn from_uri(uri: &str) -> Result<Self, NetError> {
        let payload = uri
            .strip_prefix("aira://add/")
            .ok_or_else(|| NetError::Discovery("invalid invitation URI prefix".into()))?;

        let bytes = base64url_decode(payload).map_err(|e| NetError::Discovery(e.clone()))?;

        postcard::from_bytes(&bytes).map_err(Into::into)
    }
}

// ─── Base64url encoding (RFC 4648 §5, no padding) ──────────────────────────

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn base64url_encode(data: &[u8]) -> String {
    let mut out = Vec::with_capacity(data.len().div_ceil(3) * 4);
    let chunks = data.chunks_exact(3);
    let remainder = chunks.remainder();

    for chunk in chunks {
        let n = (u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8) | u32::from(chunk[2]);
        out.push(B64[((n >> 18) & 0x3f) as usize]);
        out.push(B64[((n >> 12) & 0x3f) as usize]);
        out.push(B64[((n >> 6) & 0x3f) as usize]);
        out.push(B64[(n & 0x3f) as usize]);
    }

    match remainder.len() {
        1 => {
            let n = u32::from(remainder[0]);
            out.push(B64[((n >> 2) & 0x3f) as usize]);
            out.push(B64[((n << 4) & 0x3f) as usize]);
        }
        2 => {
            let n = (u32::from(remainder[0]) << 8) | u32::from(remainder[1]);
            out.push(B64[((n >> 10) & 0x3f) as usize]);
            out.push(B64[((n >> 4) & 0x3f) as usize]);
            out.push(B64[((n << 2) & 0x3f) as usize]);
        }
        _ => {}
    }

    // SAFETY: B64 table contains only ASCII bytes
    unsafe { String::from_utf8_unchecked(out) }
}

fn base64url_decode(s: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;

    for c in s.bytes() {
        let val = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            b'=' => continue,
            _ => return Err(format!("invalid base64url character: {}", c as char)),
        };
        buf = (buf << 6) | u32::from(val);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            #[allow(clippy::cast_possible_truncation)]
            out.push((buf >> bits) as u8); // Always ≤ 0xFF after masking
            buf &= (1 << bits) - 1;
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invitation_link_roundtrip() {
        let link = InvitationLink::new(vec![1, 2, 3, 4, 5], vec![10, 20, 30]);
        let uri = link.to_uri().unwrap();
        assert!(uri.starts_with("aira://add/"));

        let decoded = InvitationLink::from_uri(&uri).unwrap();
        assert_eq!(decoded.identity_pk, vec![1, 2, 3, 4, 5]);
        assert_eq!(decoded.endpoint_addr_bytes, vec![10, 20, 30]);
    }

    #[test]
    fn test_invitation_link_invalid() {
        assert!(InvitationLink::from_uri("https://example.com").is_err());
        assert!(InvitationLink::from_uri("aira://add/!!!").is_err());
    }

    #[test]
    fn test_base64url_roundtrip() {
        let data = b"hello world, this is a test of base64url encoding!";
        let encoded = base64url_encode(data);
        let decoded = base64url_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base64url_various_lengths() {
        // Test all remainder cases (0, 1, 2 bytes)
        for len in 0..20 {
            let data: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let encoded = base64url_encode(&data);
            let decoded = base64url_decode(&encoded).unwrap();
            assert_eq!(decoded, data, "failed for length {len}");
        }
    }
}
