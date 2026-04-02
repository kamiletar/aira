//! Linked Devices Protocol — multidevice support (SPEC.md §14).
//!
//! One seed phrase → one Identity, but each device has its own
//! iroh `NodeId` and prekeys. Devices form a "Device Group" (max 5)
//! and synchronize messages/ratchet states via an encrypted channel.
//!
//! # Device ID derivation
//!
//! ```text
//! device_id = BLAKE3-KDF(master_seed, "aira/device/id")[0..32]
//! sync_key  = BLAKE3-KDF(master_seed, "aira/device/sync-key")
//! ```
//!
//! # Linking protocol
//!
//! 1. Device A: `/link` → generates a 6-digit one-time code
//! 2. Device B: `/link <code>` → verifies the code
//! 3. Devices establish a secure sync channel using `sync_key`
//! 4. Device A sends: contacts, ratchet states, pending messages
//! 5. Device B registers its `NodeId` in DHT under the same Identity

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::proto::AiraError;
use crate::seed::MasterSeed;

// ─── Constants ──────────────────────────────────────────────────────────────

/// Maximum number of linked devices per identity (SPEC.md §14.5).
pub const MAX_DEVICES: usize = 5;

/// KDF context for deriving a device identifier.
const DEVICE_ID_CONTEXT: &str = "aira/device/id";

/// KDF context for deriving the device-to-device sync encryption key.
const DEVICE_SYNC_KEY_CONTEXT: &str = "aira/device/sync-key";

/// KDF context for deriving one-time link code material.
const DEVICE_LINK_CODE_CONTEXT: &str = "aira/device/link-code";

/// Link code validity window in seconds (5 minutes).
const LINK_CODE_VALIDITY_SECS: u64 = 300;

// ─── Device info ────────────────────────────────────────────────────────────

/// Information about a single linked device.
///
/// Stored in the `devices` table (encrypted).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceInfo {
    /// Unique device identifier: `BLAKE3-KDF(seed, "aira/device/id")[0..32]`
    /// combined with a device index to differentiate devices on the same seed.
    pub device_id: [u8; 32],
    /// Human-readable device name (e.g., "My Laptop", "Work Phone").
    pub name: String,
    /// Serialized iroh `NodeId` for transport-level addressing.
    pub node_id: Vec<u8>,
    /// Device priority for message routing (1 = highest).
    pub priority: u8,
    /// Whether this is the primary (first) device.
    pub is_primary: bool,
    /// Unix timestamp (seconds) when the device was linked.
    pub created_at: u64,
    /// Unix timestamp (seconds) of last activity.
    pub last_seen: u64,
}

// ─── Device Group ───────────────────────────────────────────────────────────

/// A group of linked devices belonging to the same identity.
///
/// Manages the device list and enforces the 5-device limit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceGroup {
    /// Ordered list of linked devices.
    devices: Vec<DeviceInfo>,
}

impl DeviceGroup {
    /// Create an empty device group.
    #[must_use]
    pub fn new() -> Self {
        Self {
            devices: Vec::new(),
        }
    }

    /// Create a device group with an initial primary device.
    #[must_use]
    pub fn with_primary(device: DeviceInfo) -> Self {
        Self {
            devices: vec![device],
        }
    }

    /// Add a device to the group.
    ///
    /// # Errors
    ///
    /// Returns [`AiraError::DeviceGroupFull`] if already at [`MAX_DEVICES`].
    /// Returns [`AiraError::Device`] if a device with the same ID already exists.
    pub fn add(&mut self, device: DeviceInfo) -> Result<(), AiraError> {
        if self.devices.len() >= MAX_DEVICES {
            return Err(AiraError::DeviceGroupFull { max: MAX_DEVICES });
        }
        if self.devices.iter().any(|d| d.device_id == device.device_id) {
            return Err(AiraError::Device("device already linked".into()));
        }
        self.devices.push(device);
        Ok(())
    }

    /// Remove a device by its ID.
    ///
    /// # Errors
    ///
    /// Returns [`AiraError::Device`] if the device is not found or is the
    /// primary device (cannot remove primary).
    pub fn remove(&mut self, device_id: &[u8; 32]) -> Result<DeviceInfo, AiraError> {
        let pos = self
            .devices
            .iter()
            .position(|d| &d.device_id == device_id)
            .ok_or_else(|| AiraError::Device("device not found".into()))?;

        if self.devices[pos].is_primary {
            return Err(AiraError::Device("cannot remove primary device".into()));
        }

        Ok(self.devices.remove(pos))
    }

    /// Get a device by its ID.
    #[must_use]
    pub fn get(&self, device_id: &[u8; 32]) -> Option<&DeviceInfo> {
        self.devices.iter().find(|d| &d.device_id == device_id)
    }

    /// Get all devices, ordered by priority.
    #[must_use]
    pub fn devices(&self) -> &[DeviceInfo] {
        &self.devices
    }

    /// Number of linked devices.
    #[must_use]
    pub fn len(&self) -> usize {
        self.devices.len()
    }

    /// Whether the group is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }

    /// Get the primary device.
    #[must_use]
    pub fn primary(&self) -> Option<&DeviceInfo> {
        self.devices.iter().find(|d| d.is_primary)
    }

    /// Get the device with highest priority (lowest number).
    #[must_use]
    pub fn highest_priority(&self) -> Option<&DeviceInfo> {
        self.devices.iter().min_by_key(|d| d.priority)
    }
}

impl Default for DeviceGroup {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Key derivation helpers ─────────────────────────────────────────────────

/// Derive a deterministic device ID for the given device index.
///
/// `device_id = BLAKE3-KDF(seed, "aira/device/id" || index_bytes)`.
/// Each index produces a unique, deterministic ID.
#[must_use]
pub fn derive_device_id(seed: &MasterSeed, index: u32) -> [u8; 32] {
    // Combine the base context with the index for uniqueness
    let mut context_material = [0u8; 36]; // 32 (seed-derived) + 4 (index)
    let base = seed.derive(DEVICE_ID_CONTEXT);
    context_material[..32].copy_from_slice(base.as_ref());
    context_material[32..].copy_from_slice(&index.to_le_bytes());
    blake3::hash(&context_material).into()
}

/// Derive the device-to-device sync encryption key.
///
/// All devices sharing the same seed derive the same sync key,
/// so they can encrypt/decrypt sync messages without additional handshake.
#[must_use]
pub fn derive_sync_key(seed: &MasterSeed) -> Zeroizing<[u8; 32]> {
    seed.derive(DEVICE_SYNC_KEY_CONTEXT)
}

/// Generate a 6-digit one-time link code.
///
/// The code is derived from the seed and a timestamp bucket
/// (5-minute window), so both sides can independently compute/verify it.
///
/// Returns a zero-padded 6-digit string (e.g., "042871").
#[must_use]
pub fn generate_link_code(seed: &MasterSeed, timestamp_secs: u64) -> String {
    let bucket = timestamp_secs / LINK_CODE_VALIDITY_SECS;
    let code_material = seed.derive(DEVICE_LINK_CODE_CONTEXT);

    // Mix bucket into the code material
    let mut input = [0u8; 40]; // 32 + 8
    input[..32].copy_from_slice(code_material.as_ref());
    input[32..].copy_from_slice(&bucket.to_le_bytes());

    let hash = blake3::hash(&input);
    let bytes = hash.as_bytes();
    let num = u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]);

    format!("{:06}", num % 1_000_000)
}

/// Verify a link code against the current and previous time bucket.
///
/// Checks both the current and previous 5-minute windows to account
/// for clock skew and codes generated near bucket boundaries.
#[must_use]
pub fn verify_link_code(seed: &MasterSeed, code: &str, timestamp_secs: u64) -> bool {
    let current = generate_link_code(seed, timestamp_secs);
    if code == current {
        return true;
    }
    // Also check previous bucket for boundary tolerance
    if timestamp_secs >= LINK_CODE_VALIDITY_SECS {
        let previous = generate_link_code(seed, timestamp_secs - LINK_CODE_VALIDITY_SECS);
        if code == previous {
            return true;
        }
    }
    false
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_seed() -> MasterSeed {
        let (_phrase, seed) = MasterSeed::generate().expect("generate seed");
        seed
    }

    fn make_device(id: [u8; 32], name: &str, primary: bool, priority: u8) -> DeviceInfo {
        DeviceInfo {
            device_id: id,
            name: name.into(),
            node_id: vec![0xAA; 32],
            priority,
            is_primary: primary,
            created_at: 1_700_000_000,
            last_seen: 1_700_000_000,
        }
    }

    #[test]
    fn device_id_is_deterministic() {
        let seed = test_seed();
        let id1 = derive_device_id(&seed, 0);
        let id2 = derive_device_id(&seed, 0);
        assert_eq!(id1, id2, "same seed + index must produce same device ID");
    }

    #[test]
    fn device_id_differs_for_different_indices() {
        let seed = test_seed();
        let id0 = derive_device_id(&seed, 0);
        let id1 = derive_device_id(&seed, 1);
        let id2 = derive_device_id(&seed, 2);
        assert_ne!(id0, id1);
        assert_ne!(id0, id2);
        assert_ne!(id1, id2);
    }

    #[test]
    fn sync_key_is_deterministic() {
        let seed = test_seed();
        let k1 = derive_sync_key(&seed);
        let k2 = derive_sync_key(&seed);
        let k1_ref: &[u8; 32] = &k1;
        let k2_ref: &[u8; 32] = &k2;
        assert_eq!(k1_ref, k2_ref);
    }

    #[test]
    fn sync_key_differs_from_device_id() {
        let seed = test_seed();
        let device_id = derive_device_id(&seed, 0);
        let sync_key = derive_sync_key(&seed);
        let sk_ref: &[u8; 32] = &sync_key;
        assert_ne!(&device_id, sk_ref);
    }

    #[test]
    fn link_code_is_6_digits() {
        let seed = test_seed();
        let code = generate_link_code(&seed, 1_700_000_000);
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn link_code_is_deterministic_within_bucket() {
        let seed = test_seed();
        // Align to bucket start, then sample two points well inside
        let bucket_start = (1_700_000_000 / LINK_CODE_VALIDITY_SECS) * LINK_CODE_VALIDITY_SECS;
        let code1 = generate_link_code(&seed, bucket_start + 10);
        let code2 = generate_link_code(&seed, bucket_start + 50);
        assert_eq!(code1, code2, "same bucket should produce same code");
    }

    #[test]
    fn link_code_differs_between_buckets() {
        let seed = test_seed();
        let code1 = generate_link_code(&seed, 1_700_000_000);
        let code2 = generate_link_code(&seed, 1_700_000_600); // +10 min
        assert_ne!(
            code1, code2,
            "different buckets should produce different codes"
        );
    }

    #[test]
    fn verify_link_code_current_bucket() {
        let seed = test_seed();
        let ts = 1_700_000_100;
        let code = generate_link_code(&seed, ts);
        assert!(verify_link_code(&seed, &code, ts));
    }

    #[test]
    fn verify_link_code_previous_bucket() {
        let seed = test_seed();
        let ts = 1_700_000_000;
        let code = generate_link_code(&seed, ts);
        // Check with a timestamp in the next bucket
        let next_ts = ts + LINK_CODE_VALIDITY_SECS;
        assert!(verify_link_code(&seed, &code, next_ts));
    }

    #[test]
    fn verify_link_code_expired() {
        let seed = test_seed();
        let ts = 1_700_000_000;
        let code = generate_link_code(&seed, ts);
        // Two buckets later — should be expired
        let far_ts = ts + LINK_CODE_VALIDITY_SECS * 3;
        assert!(!verify_link_code(&seed, &code, far_ts));
    }

    #[test]
    fn device_group_add_and_get() {
        let mut group = DeviceGroup::new();
        let dev = make_device([1; 32], "Laptop", true, 1);
        group.add(dev.clone()).expect("add");
        assert_eq!(group.len(), 1);
        assert_eq!(group.get(&[1; 32]), Some(&dev));
    }

    #[test]
    fn device_group_max_limit() {
        let mut group = DeviceGroup::new();
        for i in 0..MAX_DEVICES {
            #[allow(clippy::cast_possible_truncation)]
            let id = {
                let mut arr = [0u8; 32];
                arr[0] = i as u8;
                arr
            };
            let dev = make_device(id, &format!("Device {i}"), i == 0, (i + 1) as u8);
            group.add(dev).expect("add device");
        }
        assert_eq!(group.len(), MAX_DEVICES);

        // Adding one more should fail
        let extra = make_device([0xFF; 32], "Extra", false, 6);
        let err = group.add(extra).unwrap_err();
        assert!(err.to_string().contains("full"));
    }

    #[test]
    fn device_group_duplicate_rejected() {
        let mut group = DeviceGroup::new();
        let dev = make_device([1; 32], "Laptop", true, 1);
        group.add(dev.clone()).expect("add");
        let err = group.add(dev).unwrap_err();
        assert!(err.to_string().contains("already linked"));
    }

    #[test]
    fn device_group_remove() {
        let mut group = DeviceGroup::new();
        group
            .add(make_device([1; 32], "Primary", true, 1))
            .expect("add");
        group
            .add(make_device([2; 32], "Secondary", false, 2))
            .expect("add");

        let removed = group.remove(&[2; 32]).expect("remove");
        assert_eq!(removed.name, "Secondary");
        assert_eq!(group.len(), 1);
    }

    #[test]
    fn device_group_cannot_remove_primary() {
        let mut group = DeviceGroup::new();
        group
            .add(make_device([1; 32], "Primary", true, 1))
            .expect("add");

        let err = group.remove(&[1; 32]).unwrap_err();
        assert!(err.to_string().contains("primary"));
    }

    #[test]
    fn device_group_remove_nonexistent() {
        let mut group = DeviceGroup::new();
        group
            .add(make_device([1; 32], "Primary", true, 1))
            .expect("add");
        let err = group.remove(&[99; 32]).unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn device_group_primary_and_priority() {
        let mut group = DeviceGroup::new();
        group
            .add(make_device([1; 32], "Primary", true, 2))
            .expect("add");
        group
            .add(make_device([2; 32], "High priority", false, 1))
            .expect("add");

        assert_eq!(group.primary().expect("primary").name, "Primary");
        assert_eq!(
            group.highest_priority().expect("highest").name,
            "High priority"
        );
    }

    #[test]
    fn device_info_roundtrip() {
        let info = DeviceInfo {
            device_id: [0xAB; 32],
            name: "Test Device".into(),
            node_id: vec![0x01; 32],
            priority: 1,
            is_primary: true,
            created_at: 1_700_000_000,
            last_seen: 1_700_001_000,
        };
        let bytes = postcard::to_allocvec(&info).expect("serialize");
        let decoded: DeviceInfo = postcard::from_bytes(&bytes).expect("deserialize");
        assert_eq!(decoded, info);
    }

    #[test]
    fn device_group_roundtrip() {
        let mut group = DeviceGroup::new();
        group.add(make_device([1; 32], "A", true, 1)).expect("add");
        group.add(make_device([2; 32], "B", false, 2)).expect("add");

        let bytes = postcard::to_allocvec(&group).expect("serialize");
        let decoded: DeviceGroup = postcard::from_bytes(&bytes).expect("deserialize");
        assert_eq!(decoded.len(), 2);
    }
}
