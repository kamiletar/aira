//! Integration tests for multidevice support (SPEC.md §14).
//!
//! Verifies that two devices from the same seed can:
//! - Derive the same identity
//! - Get different device IDs
//! - Share a sync key
//! - Generate/verify link codes
//! - Serialize/deserialize ratchet state for handoff
//! - Encode/decode sync batches

use aira_core::device::{
    derive_device_id, derive_sync_key, generate_link_code, verify_link_code, DeviceGroup,
    DeviceInfo, MAX_DEVICES,
};
use aira_core::ratchet::RatchetSnapshot;
use aira_core::seed::MasterSeed;
use aira_core::sync::{decode_sync_batch, encode_sync_batch, SyncBatch, SyncItem, SyncState};

/// Two devices from the same seed share the same identity but different device IDs.
#[test]
fn two_devices_same_seed_different_ids() {
    let (phrase, _seed) = MasterSeed::generate().expect("generate");
    let seed_a = MasterSeed::from_phrase(&phrase).expect("seed A");
    let seed_b = MasterSeed::from_phrase(&phrase).expect("seed B");

    // Same identity key
    let identity_a = seed_a.derive("aira/identity/0");
    let identity_b = seed_b.derive("aira/identity/0");
    let ia: &[u8; 32] = &identity_a;
    let ib: &[u8; 32] = &identity_b;
    assert_eq!(ia, ib, "same identity");

    // Different device IDs
    let device_a = derive_device_id(&seed_a, 0);
    let device_b = derive_device_id(&seed_b, 1);
    assert_ne!(device_a, device_b, "different device IDs");

    // Same sync key
    let sync_a = derive_sync_key(&seed_a);
    let sync_b = derive_sync_key(&seed_b);
    let sa: &[u8; 32] = &sync_a;
    let sb: &[u8; 32] = &sync_b;
    assert_eq!(sa, sb, "same sync key for same seed");
}

/// Link code generated on device A can be verified on device B (same seed).
#[test]
fn link_code_cross_device_verification() {
    let (phrase, _seed) = MasterSeed::generate().expect("generate");
    let seed_a = MasterSeed::from_phrase(&phrase).expect("seed A");
    let seed_b = MasterSeed::from_phrase(&phrase).expect("seed B");

    let timestamp = 1_700_000_000;
    let code = generate_link_code(&seed_a, timestamp);

    // Device B can verify the code
    assert!(
        verify_link_code(&seed_b, &code, timestamp),
        "same seed should verify"
    );

    // Different seed cannot verify
    let (_other_phrase, other_seed) = MasterSeed::generate().expect("other");
    assert!(
        !verify_link_code(&other_seed, &code, timestamp),
        "different seed should not verify"
    );
}

/// Ratchet state can be serialized on device A and deserialized on device B.
#[test]
fn ratchet_state_handoff() {
    let snapshot = RatchetSnapshot {
        root_key: [0x42; 32],
        send_chain_key: [0x43; 32],
        send_counter: 100,
        send_dh_secret_bytes: [0x44; 32],
        send_dh_public_bytes: [0x45; 32],
        recv_chain_key: Some([0x46; 32]),
        recv_counter: 50,
        peer_dh_public: Some([0x47; 32]),
        prev_send_chain_len: 10,
        pq_enabled: true,
        send_since_pq: 25,
        pq_dk_bytes: Some(vec![0x48; 64]),
        pq_ek_bytes: Some(vec![0x49; 64]),
        peer_pq_ek_bytes: Some(vec![0x4A; 64]),
        skipped_entries: vec![([0x4B; 32], 5, [0x4C; 32])],
    };

    // Serialize on device A
    let bytes = postcard::to_allocvec(&snapshot).expect("serialize");

    // Deserialize on device B
    let restored: RatchetSnapshot = postcard::from_bytes(&bytes).expect("deserialize");

    assert_eq!(restored.root_key, snapshot.root_key);
    assert_eq!(restored.send_counter, 100);
    assert_eq!(restored.recv_counter, 50);
    assert!(restored.pq_enabled);
    assert_eq!(restored.skipped_entries.len(), 1);
}

/// Sync batch encrypted by device A can be decrypted by device B (same seed).
#[test]
fn sync_batch_cross_device() {
    let (phrase, _seed) = MasterSeed::generate().expect("generate");
    let seed_a = MasterSeed::from_phrase(&phrase).expect("seed A");
    let seed_b = MasterSeed::from_phrase(&phrase).expect("seed B");

    let sync_key_a = derive_sync_key(&seed_a);
    let sync_key_b = derive_sync_key(&seed_b);

    let batch = SyncBatch {
        from_device: derive_device_id(&seed_a, 0),
        timestamp: 1_700_000_000,
        sequence: 1,
        items: vec![
            SyncItem::ContactAdded {
                pubkey: vec![0xAA; 32],
                alias: "Alice".into(),
                verified: true,
            },
            SyncItem::Message {
                contact_key: vec![0xAA; 32],
                message_id: [0xBB; 16],
                sender_is_self: true,
                payload_bytes: b"hello from device A".to_vec(),
                timestamp_micros: 1_700_000_000_000_000,
            },
            SyncItem::RatchetState {
                contact_pubkey: vec![0xAA; 32],
                snapshot_bytes: vec![0xCC; 128],
            },
        ],
    };

    // Encrypt on device A
    let encrypted = encode_sync_batch(&batch, &sync_key_a).expect("encode");

    // Decrypt on device B (same sync key)
    let decrypted = decode_sync_batch(&encrypted, &sync_key_b).expect("decode");

    assert_eq!(decrypted.items.len(), 3);
    assert_eq!(decrypted.from_device, batch.from_device);
    assert_eq!(decrypted.sequence, 1);
}

/// Sync state tracks progress correctly across multiple batches.
#[test]
fn sync_state_progression() {
    let mut state = SyncState::new([0x01; 32]);

    let batch1 = SyncBatch {
        from_device: [0x02; 32],
        timestamp: 100,
        sequence: 1,
        items: vec![SyncItem::ContactAdded {
            pubkey: vec![1],
            alias: "A".into(),
            verified: false,
        }],
    };
    state.update(&batch1);
    assert_eq!(state.last_sequence, 1);

    let batch2 = SyncBatch {
        from_device: [0x02; 32],
        timestamp: 200,
        sequence: 5,
        items: vec![],
    };
    state.update(&batch2);
    assert_eq!(state.last_sequence, 5);
    assert_eq!(state.last_sync_timestamp, 200);

    // Earlier batch shouldn't regress
    let batch_old = SyncBatch {
        from_device: [0x02; 32],
        timestamp: 50,
        sequence: 2,
        items: vec![],
    };
    state.update(&batch_old);
    assert_eq!(state.last_sequence, 5, "should not regress");
    assert_eq!(state.last_sync_timestamp, 200, "should not regress");
}

/// Device group enforces limits correctly.
#[test]
fn device_group_full_lifecycle() {
    let mut group = DeviceGroup::new();

    // Add primary
    let primary = DeviceInfo {
        device_id: [0x01; 32],
        name: "Primary Laptop".into(),
        node_id: vec![0xAA; 32],
        priority: 1,
        is_primary: true,
        created_at: 1_700_000_000,
        last_seen: 1_700_000_000,
    };
    group.add(primary).expect("add primary");
    assert_eq!(group.len(), 1);

    // Add secondary devices
    for i in 1..MAX_DEVICES {
        let mut id = [0u8; 32];
        #[allow(clippy::cast_possible_truncation)]
        {
            id[0] = (i + 1) as u8;
        }
        let dev = DeviceInfo {
            device_id: id,
            name: format!("Device {i}"),
            node_id: vec![0xBB; 32],
            #[allow(clippy::cast_possible_truncation)]
            priority: (i + 1) as u8,
            is_primary: false,
            created_at: 1_700_000_000,
            last_seen: 1_700_000_000,
        };
        group.add(dev).expect("add device");
    }
    assert_eq!(group.len(), MAX_DEVICES);

    // Cannot add more
    let extra = DeviceInfo {
        device_id: [0xFF; 32],
        name: "Extra".into(),
        node_id: vec![],
        priority: 10,
        is_primary: false,
        created_at: 0,
        last_seen: 0,
    };
    assert!(group.add(extra).is_err());

    // Cannot remove primary
    assert!(group.remove(&[0x01; 32]).is_err());

    // Can remove secondary
    let mut remove_id = [0u8; 32];
    remove_id[0] = 2;
    group.remove(&remove_id).expect("remove secondary");
    assert_eq!(group.len(), MAX_DEVICES - 1);

    // Priority ordering
    assert_eq!(group.primary().expect("primary").priority, 1);
}
