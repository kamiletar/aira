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

// ─── DHT multidevice records (SPEC.md §14.4) ───────────────────────────────

/// A single device entry in a multidevice DHT record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceEntry {
    /// Device's iroh `NodeId` (serialized).
    pub node_id: Vec<u8>,
    /// Device priority for message routing (1 = highest).
    pub priority: u8,
    /// Unix timestamp (seconds) of last seen activity.
    pub last_seen: u64,
}

/// DHT record advertising multiple devices for a single identity.
///
/// ```text
/// ML-DSA_pubkey → DeviceRecord {
///     devices: [DeviceEntry, ...],
///     signature: ML-DSA_sign(postcard(devices))
/// }
/// ```
///
/// Bob sends to Alice's device with highest priority, or to all
/// if broadcast mode is active.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRecord {
    /// Identity public key (ML-DSA-65).
    pub identity_pk: Vec<u8>,
    /// All registered devices for this identity.
    pub devices: Vec<DeviceEntry>,
    /// ML-DSA signature over `postcard(devices)` for authentication.
    pub signature: Vec<u8>,
}

impl DeviceRecord {
    /// Create a new device record (unsigned — caller must sign).
    #[must_use]
    pub fn new(identity_pk: Vec<u8>, devices: Vec<DeviceEntry>) -> Self {
        Self {
            identity_pk,
            devices,
            signature: Vec::new(),
        }
    }

    /// Get the device bytes to be signed: `postcard(devices)`.
    ///
    /// # Errors
    ///
    /// Returns [`NetError`] if serialization fails.
    pub fn signable_bytes(&self) -> Result<Vec<u8>, NetError> {
        postcard::to_allocvec(&self.devices).map_err(Into::into)
    }

    /// Get the highest-priority (lowest number) device.
    #[must_use]
    pub fn highest_priority_device(&self) -> Option<&DeviceEntry> {
        self.devices.iter().min_by_key(|d| d.priority)
    }

    /// Number of registered devices.
    #[must_use]
    pub fn device_count(&self) -> usize {
        self.devices.len()
    }

    /// Encode to bytes for DHT storage.
    ///
    /// # Errors
    ///
    /// Returns [`NetError`] if serialization fails.
    pub fn to_bytes(&self) -> Result<Vec<u8>, NetError> {
        postcard::to_allocvec(self).map_err(Into::into)
    }

    /// Decode from bytes.
    ///
    /// # Errors
    ///
    /// Returns [`NetError`] if deserialization fails.
    pub fn from_bytes(data: &[u8]) -> Result<Self, NetError> {
        postcard::from_bytes(data).map_err(Into::into)
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
    fn device_entry_roundtrip() {
        let entry = DeviceEntry {
            node_id: vec![0xAA; 32],
            priority: 1,
            last_seen: 1_700_000_000,
        };
        let bytes = postcard::to_allocvec(&entry).unwrap();
        let decoded: DeviceEntry = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, entry);
    }

    #[test]
    fn device_record_roundtrip() {
        let record = DeviceRecord {
            identity_pk: vec![0x01; 64],
            devices: vec![
                DeviceEntry {
                    node_id: vec![0xAA; 32],
                    priority: 1,
                    last_seen: 1_700_000_000,
                },
                DeviceEntry {
                    node_id: vec![0xBB; 32],
                    priority: 2,
                    last_seen: 1_700_001_000,
                },
            ],
            signature: vec![0xFF; 128],
        };
        let bytes = record.to_bytes().unwrap();
        let decoded = DeviceRecord::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.devices.len(), 2);
        assert_eq!(decoded.identity_pk, record.identity_pk);
    }

    #[test]
    fn device_record_highest_priority() {
        let record = DeviceRecord::new(
            vec![0x01; 64],
            vec![
                DeviceEntry {
                    node_id: vec![0xAA; 32],
                    priority: 3,
                    last_seen: 100,
                },
                DeviceEntry {
                    node_id: vec![0xBB; 32],
                    priority: 1,
                    last_seen: 200,
                },
                DeviceEntry {
                    node_id: vec![0xCC; 32],
                    priority: 2,
                    last_seen: 300,
                },
            ],
        );
        let best = record.highest_priority_device().unwrap();
        assert_eq!(best.priority, 1);
        assert_eq!(best.node_id, vec![0xBB; 32]);
    }

    #[test]
    fn device_record_signable_bytes_deterministic() {
        let record = DeviceRecord::new(
            vec![0x01; 64],
            vec![DeviceEntry {
                node_id: vec![0xAA; 32],
                priority: 1,
                last_seen: 100,
            }],
        );
        let sig1 = record.signable_bytes().unwrap();
        let sig2 = record.signable_bytes().unwrap();
        assert_eq!(sig1, sig2);
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
