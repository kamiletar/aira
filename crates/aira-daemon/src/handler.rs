//! Request handler logic shared between the daemon binary and FFI.
//!
//! Extracted from `main.rs` so that both the standalone daemon process
//! (communicating over IPC) and the embedded Android runtime (via `UniFFI`)
//! can reuse the same request-handling code.

#![allow(clippy::module_name_repetitions)]

use aira_core::crypto::{ActiveProvider, CryptoProvider};
use aira_core::seed::MasterSeed;
use aira_core::util::{now_micros, now_secs, rand_id};

use crate::types::{
    DaemonRequest, DaemonResponse, DeviceInfoResp, GroupInfoResp, GroupMemberResp, PseudonymResp,
};
use tokio::sync::mpsc;

/// Storage key for persisted transport mode.
const TRANSPORT_MODE_KEY: &str = "transport/mode";

/// Handle a single daemon request, returning a response.
///
/// This is the core dispatch function: it pattern-matches on `DaemonRequest`
/// and calls into `aira-storage` / `aira-net` accordingly.
///
/// The `seed` parameter enables pseudonym key derivation (§12.6) for group
/// operations and contact exchange.
#[allow(clippy::too_many_lines)]
pub fn handle_request(
    storage: &aira_storage::Storage,
    seed: &MasterSeed,
    blob_store: &aira_net::blobs::BlobStore,
    transfer_mgr: &crate::transfers::TransferManager,
    shutdown_tx: &mpsc::Sender<()>,
    request: DaemonRequest,
) -> DaemonResponse {
    match request {
        DaemonRequest::AddContact { pubkey, alias } => {
            match aira_storage::contacts::add(storage, &pubkey, &alias) {
                Ok(()) => DaemonResponse::Ok,
                Err(e) => DaemonResponse::Error(e.to_string()),
            }
        }
        DaemonRequest::RemoveContact { pubkey } => {
            match aira_storage::contacts::remove(storage, &pubkey) {
                Ok(()) => DaemonResponse::Ok,
                Err(e) => DaemonResponse::Error(e.to_string()),
            }
        }
        DaemonRequest::GetContacts => match aira_storage::contacts::list(storage) {
            Ok(contacts) => DaemonResponse::Contacts(contacts),
            Err(e) => DaemonResponse::Error(e.to_string()),
        },
        DaemonRequest::GetHistory { contact, limit } => {
            let cid = aira_storage::contact_id(&contact);
            match aira_storage::messages::get_history(storage, cid, limit, u64::MAX) {
                Ok(messages) => DaemonResponse::History(messages),
                Err(e) => DaemonResponse::Error(e.to_string()),
            }
        }
        DaemonRequest::SendMessage { to, text } => {
            let cid = aira_storage::contact_id(&to);
            let msg = aira_storage::StoredMessage {
                id: rand_id(),
                sender_is_self: true,
                payload_bytes: text.into_bytes(),
                timestamp_micros: now_micros(),
                ttl_secs: aira_storage::settings::get_ttl(storage, &to).unwrap_or(None),
                read_at: None,
                expires_at: None,
            };
            match aira_storage::messages::store(storage, cid, &msg) {
                Ok(()) => DaemonResponse::Ok,
                Err(e) => DaemonResponse::Error(e.to_string()),
            }
        }
        DaemonRequest::GetMyAddress => {
            // Derive a new pseudonym for contact exchange (§12.6.5).
            // Each call generates a fresh keypair — two invitation links are unlinkable.
            let context_id = {
                let mut id = [0u8; 32];
                rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut id);
                id
            };
            match derive_pseudonym_pubkey(
                storage,
                seed,
                aira_storage::types::PseudonymContext::Contact,
                context_id,
                "",
            ) {
                Ok((_counter, pubkey)) => DaemonResponse::MyAddress(pubkey),
                Err(e) => DaemonResponse::Error(format!("pseudonym derivation failed: {e}")),
            }
        }
        DaemonRequest::SetTtl { contact, ttl_secs } => {
            match aira_storage::settings::set_ttl(storage, &contact, ttl_secs) {
                Ok(()) => DaemonResponse::Ok,
                Err(e) => DaemonResponse::Error(e.to_string()),
            }
        }
        DaemonRequest::ExportBackup {
            path,
            include_messages,
        } => match aira_storage::backup::export(storage, &path, include_messages) {
            Ok(()) => DaemonResponse::Ok,
            Err(e) => DaemonResponse::Error(e.to_string()),
        },
        DaemonRequest::ImportBackup { path } => {
            match aira_storage::backup::import(&path, storage.key()) {
                Ok(data) => match aira_storage::backup::restore(storage, &data) {
                    Ok(()) => DaemonResponse::Ok,
                    Err(e) => DaemonResponse::Error(format!("restore failed: {e}")),
                },
                Err(e) => DaemonResponse::Error(e.to_string()),
            }
        }
        DaemonRequest::SendFile { to, path } => {
            handle_send_file(storage, blob_store, transfer_mgr, &to, path)
        }
        DaemonRequest::SetTransportMode { mode } => handle_set_transport_mode(storage, &mode),
        DaemonRequest::GetTransportMode => handle_get_transport_mode(storage),

        DaemonRequest::Shutdown => {
            let _ = shutdown_tx.try_send(());
            DaemonResponse::Ok
        }

        // ─── Group operations (SPEC.md §12) ─────────────────────────────
        DaemonRequest::CreateGroup { name, members } => {
            handle_create_group(storage, seed, &name, &members)
        }
        DaemonRequest::GetGroups => match aira_storage::groups::list_groups(storage) {
            Ok(groups) => {
                let resp: Vec<_> = groups.iter().map(group_info_to_resp).collect();
                DaemonResponse::Groups(resp)
            }
            Err(e) => DaemonResponse::Error(e.to_string()),
        },
        DaemonRequest::GetGroupInfo { group_id } => {
            match aira_storage::groups::get_group(storage, &group_id) {
                Ok(group) => DaemonResponse::GroupInfo(group_info_to_resp(&group)),
                Err(e) => DaemonResponse::Error(e.to_string()),
            }
        }
        DaemonRequest::SendGroupMessage { group_id, text } => {
            handle_send_group_message(storage, &group_id, &text)
        }
        DaemonRequest::GetGroupHistory { group_id, limit } => {
            match aira_storage::groups::get_group_history(storage, &group_id, limit) {
                Ok(messages) => DaemonResponse::GroupHistory(messages),
                Err(e) => DaemonResponse::Error(e.to_string()),
            }
        }
        DaemonRequest::GroupAddMember { group_id, member } => {
            handle_group_add_member(storage, &group_id, &member)
        }
        DaemonRequest::GroupRemoveMember { group_id, member } => {
            handle_group_remove_member(storage, &group_id, &member)
        }
        DaemonRequest::LeaveGroup { group_id } => handle_leave_group(storage, &group_id),
        DaemonRequest::AcceptGroupInvite {
            group_id,
            display_name,
            invited_by,
        } => handle_accept_group_invite(storage, seed, &group_id, &display_name, &invited_by),

        // ─── Pseudonym operations (SPEC.md §12.6) ───────────────────────
        DaemonRequest::GetPseudonyms => match aira_storage::pseudonyms::list(storage) {
            Ok(records) => {
                let resp: Vec<_> = records.iter().map(pseudonym_to_resp).collect();
                DaemonResponse::Pseudonyms(resp)
            }
            Err(e) => DaemonResponse::Error(e.to_string()),
        },
        DaemonRequest::GetPseudonym { counter } => {
            match aira_storage::pseudonyms::get(storage, counter) {
                Ok(record) => DaemonResponse::Pseudonym(record.as_ref().map(pseudonym_to_resp)),
                Err(e) => DaemonResponse::Error(e.to_string()),
            }
        }
        DaemonRequest::FindPseudonym { context_id } => {
            match aira_storage::pseudonyms::find_by_context(storage, &context_id) {
                Ok(record) => DaemonResponse::Pseudonym(record.as_ref().map(pseudonym_to_resp)),
                Err(e) => DaemonResponse::Error(e.to_string()),
            }
        }

        // ─── Device operations (SPEC.md §14) ────────────────────────────
        DaemonRequest::GenerateLinkCode => {
            let code = aira_core::device::generate_link_code(seed, now_secs());
            DaemonResponse::LinkCode(code)
        }
        DaemonRequest::LinkDevice { code, device_name } => {
            if !aira_core::device::verify_link_code(seed, &code, now_secs()) {
                return DaemonResponse::Error("invalid or expired link code".into());
            }
            // Derive a device ID and store the new linked device
            let device_id = {
                let hash = blake3::derive_key("aira/device/id-from-code", code.as_bytes());
                let mut id = [0u8; 32];
                id.copy_from_slice(&hash);
                id
            };
            let device_info = aira_storage::DeviceInfo {
                device_id,
                name: device_name.clone(),
                node_id: vec![], // Populated when device announces its iroh NodeId
                priority: 2,     // Secondary device by default
                is_primary: false,
                created_at: now_secs(),
                last_seen: now_secs(),
            };
            let info_bytes = match postcard::to_allocvec(&device_info) {
                Ok(b) => b,
                Err(e) => return DaemonResponse::Error(format!("serialize device: {e}")),
            };
            match aira_storage::devices::save_device(storage, &device_id, &info_bytes) {
                Ok(()) => DaemonResponse::DeviceLinked {
                    device_id,
                    name: device_name,
                },
                Err(e) => DaemonResponse::Error(e.to_string()),
            }
        }
        DaemonRequest::GetDevices => match aira_storage::devices::list_devices(storage) {
            Ok(devices) => {
                let resp: Vec<_> = devices
                    .iter()
                    .filter_map(|(id, bytes)| {
                        postcard::from_bytes::<aira_storage::DeviceInfo>(bytes)
                            .ok()
                            .map(|info| DeviceInfoResp {
                                device_id: *id,
                                name: info.name,
                                is_primary: info.is_primary,
                                priority: info.priority,
                                last_seen: info.last_seen,
                            })
                    })
                    .collect();
                DaemonResponse::Devices(resp)
            }
            Err(e) => DaemonResponse::Error(e.to_string()),
        },
        DaemonRequest::UnlinkDevice { device_id } => {
            match aira_storage::devices::remove_device(storage, &device_id) {
                Ok(()) => DaemonResponse::Ok,
                Err(e) => DaemonResponse::Error(e.to_string()),
            }
        }
    }
}

/// Convert storage `GroupInfo` to daemon response `GroupInfoResp`.
#[must_use]
pub(crate) fn group_info_to_resp(group: &aira_storage::GroupInfo) -> GroupInfoResp {
    GroupInfoResp {
        id: group.id,
        name: group.name.clone(),
        members: group
            .members
            .iter()
            .map(|m| GroupMemberResp {
                pubkey: m.pubkey.clone(),
                display_name: m.display_name.clone(),
                role: match m.role {
                    aira_storage::GroupRole::Admin => "admin".into(),
                    aira_storage::GroupRole::Member => "member".into(),
                },
                joined_at: m.joined_at,
            })
            .collect(),
        created_by: group.created_by.clone(),
        created_at: group.created_at,
    }
}

/// Convert storage `PseudonymRecord` to daemon response `PseudonymResp`.
fn pseudonym_to_resp(record: &aira_storage::PseudonymRecord) -> PseudonymResp {
    PseudonymResp {
        counter: record.counter,
        pubkey: record.pubkey.clone(),
        context_type: match record.context_type {
            aira_storage::types::PseudonymContext::Contact => "contact".into(),
            aira_storage::types::PseudonymContext::Group => "group".into(),
        },
        context_id: record.context_id,
        display_name: record.display_name.clone(),
        created_at: record.created_at,
    }
}

/// Serialize a `GroupControl` as `PlainPayload::GroupControl` and enqueue
/// in pending queue for each recipient.
///
/// This is the distribution mechanism for group management messages.
/// Messages are enqueued as plaintext postcard bytes — the network layer
/// will encrypt them with the 1-on-1 ratchet session when delivering.
fn enqueue_group_control(
    storage: &aira_storage::Storage,
    control: &aira_core::group_proto::GroupControl,
    recipients: &[Vec<u8>],
) {
    let payload = aira_core::proto::PlainPayload::GroupControl(control.clone());
    let payload_bytes = match postcard::to_allocvec(&payload) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("failed to serialize GroupControl: {e}");
            return;
        }
    };

    for recipient_pubkey in recipients {
        let cid = aira_storage::contact_id(recipient_pubkey);
        if let Err(e) = aira_storage::pending::enqueue(storage, cid, &payload_bytes) {
            tracing::error!("failed to enqueue GroupControl for contact: {e}");
        }
    }
}

/// Derive a pseudonym ML-DSA public key for a given counter.
///
/// Allocates the next counter from storage, derives the keypair, stores
/// the pseudonym record, and returns `(counter, pubkey_bytes)`.
fn derive_pseudonym_pubkey(
    storage: &aira_storage::Storage,
    seed: &MasterSeed,
    context_type: aira_storage::types::PseudonymContext,
    context_id: [u8; 32],
    display_name: &str,
) -> Result<(u32, Vec<u8>), String> {
    let counter = aira_storage::pseudonyms::next_counter(storage).map_err(|e| e.to_string())?;
    let ps = seed.derive_pseudonym_seeds(counter);

    let (_sk, vk) =
        ActiveProvider::identity_keygen(&ps.signing).map_err(|e| format!("keygen: {e}"))?;
    let pubkey = ActiveProvider::encode_verifying_key(&vk);

    let record = aira_storage::PseudonymRecord {
        counter,
        pubkey: pubkey.clone(),
        context_type,
        context_id,
        display_name: display_name.to_string(),
        created_at: now_secs(),
    };
    aira_storage::pseudonyms::store(storage, &record).map_err(|e| e.to_string())?;

    Ok((counter, pubkey))
}

/// Handle `CreateGroup` request.
fn handle_create_group(
    storage: &aira_storage::Storage,
    seed: &MasterSeed,
    name: &str,
    member_pubkeys: &[Vec<u8>],
) -> DaemonResponse {
    if member_pubkeys.len() + 1 > aira_core::group::MAX_GROUP_MEMBERS {
        return DaemonResponse::Error(format!(
            "too many members (max {})",
            aira_core::group::MAX_GROUP_MEMBERS
        ));
    }

    let mut group_id = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut group_id);

    let now = now_secs();

    // Derive our pseudonym for this group (§12.6)
    let our_pubkey = match derive_pseudonym_pubkey(
        storage,
        seed,
        aira_storage::types::PseudonymContext::Group,
        group_id,
        name,
    ) {
        Ok((_counter, pk)) => pk,
        Err(e) => return DaemonResponse::Error(format!("pseudonym derivation failed: {e}")),
    };

    // Generate creator's initial Sender Key (§12.1)
    let creator_sk = aira_core::group::SenderKeyState::new();

    // Creator is Admin with derived pseudonym + sender key
    let mut members = vec![aira_storage::GroupMemberInfo {
        pubkey: our_pubkey.clone(),
        display_name: name.to_string(),
        role: aira_storage::GroupRole::Admin,
        joined_at: now,
        sender_chain_key: *creator_sk.chain_key_bytes(),
    }];

    // Other members start as Member — pseudonym pubkeys provided by invitees (§12.6)
    // Chain key zero-filled until they send SenderKeyUpdate after accepting invite
    for pk in member_pubkeys {
        members.push(aira_storage::GroupMemberInfo {
            pubkey: pk.clone(),
            display_name: String::new(),
            role: aira_storage::GroupRole::Member,
            joined_at: now,
            sender_chain_key: [0; 32],
        });
    }

    let group = aira_storage::GroupInfo {
        id: group_id,
        name: name.to_string(),
        members,
        created_by: our_pubkey,
        created_at: now,
    };

    match aira_storage::groups::create_group(storage, &group) {
        Ok(()) => {
            // Distribute CreateGroup to all members via 1-on-1 pending queue
            let all_member_pubkeys: Vec<Vec<u8>> = group
                .members
                .iter()
                .filter(|m| m.pubkey != group.created_by)
                .map(|m| m.pubkey.clone())
                .collect();

            let control = aira_core::group_proto::GroupControl::CreateGroup {
                group_id,
                name: name.to_string(),
                members: group.members.iter().map(|m| m.pubkey.clone()).collect(),
                creator_sender_key: creator_sk.chain_key_bytes().to_vec(),
            };
            enqueue_group_control(storage, &control, &all_member_pubkeys);

            DaemonResponse::GroupCreated { group_id }
        }
        Err(e) => DaemonResponse::Error(e.to_string()),
    }
}

/// Handle `SendGroupMessage` request.
fn handle_send_group_message(
    storage: &aira_storage::Storage,
    group_id: &[u8; 32],
    text: &str,
) -> DaemonResponse {
    let Ok(group) = aira_storage::groups::get_group(storage, group_id) else {
        return DaemonResponse::Error("group not found".into());
    };

    let msg = aira_storage::StoredMessage {
        id: rand_id(),
        sender_is_self: true,
        payload_bytes: text.as_bytes().to_vec(),
        timestamp_micros: now_micros(),
        ttl_secs: None,
        read_at: None,
        expires_at: None,
    };

    match aira_storage::groups::store_group_message(storage, group_id, &msg) {
        Ok(()) => {
            // Fan-out plaintext payload to all members via pending queue.
            // Network layer will encrypt with SenderKey when delivering.
            let payload = aira_core::proto::PlainPayload::Text(text.to_string());
            if let Ok(payload_bytes) = postcard::to_allocvec(&payload) {
                let recipients: Vec<Vec<u8>> =
                    group.members.iter().map(|m| m.pubkey.clone()).collect();
                for pk in &recipients {
                    let cid = aira_storage::contact_id(pk);
                    let _ = aira_storage::pending::enqueue(storage, cid, &payload_bytes);
                }
            }
            DaemonResponse::Ok
        }
        Err(e) => DaemonResponse::Error(e.to_string()),
    }
}

/// Handle `GroupAddMember` request.
fn handle_group_add_member(
    storage: &aira_storage::Storage,
    group_id: &[u8; 32],
    member_pubkey: &[u8],
) -> DaemonResponse {
    let group = match aira_storage::groups::get_group(storage, group_id) {
        Ok(g) => g,
        Err(e) => return DaemonResponse::Error(e.to_string()),
    };

    if group.members.len() >= aira_core::group::MAX_GROUP_MEMBERS {
        return DaemonResponse::Error(format!(
            "group is full (max {} members)",
            aira_core::group::MAX_GROUP_MEMBERS
        ));
    }

    let now = now_secs();
    let member = aira_storage::GroupMemberInfo {
        pubkey: member_pubkey.to_vec(),
        display_name: String::new(), // Filled when member responds with pseudonym (§12.6)
        role: aira_storage::GroupRole::Member,
        joined_at: now,
        sender_chain_key: [0; 32], // Zero until member sends SenderKeyUpdate
    };

    match aira_storage::groups::add_member(storage, group_id, member) {
        Ok(()) => {
            // Collect existing members' chain keys for the new member
            let sender_keys: Vec<(Vec<u8>, Vec<u8>)> = group
                .members
                .iter()
                .filter(|m| m.sender_chain_key != [0; 32])
                .map(|m| (m.pubkey.clone(), m.sender_chain_key.to_vec()))
                .collect();

            let control = aira_core::group_proto::GroupControl::AddMember {
                group_id: *group_id,
                new_member: member_pubkey.to_vec(),
                sender_keys,
            };
            let recipients: Vec<Vec<u8>> = group.members.iter().map(|m| m.pubkey.clone()).collect();
            enqueue_group_control(storage, &control, &recipients);

            DaemonResponse::Ok
        }
        Err(e) => DaemonResponse::Error(e.to_string()),
    }
}

/// Handle `GroupRemoveMember` request.
fn handle_group_remove_member(
    storage: &aira_storage::Storage,
    group_id: &[u8; 32],
    member_pubkey: &[u8],
) -> DaemonResponse {
    let group = match aira_storage::groups::get_group(storage, group_id) {
        Ok(g) => g,
        Err(e) => return DaemonResponse::Error(e.to_string()),
    };

    match aira_storage::groups::remove_member(storage, group_id, member_pubkey) {
        Ok(()) => {
            // Notify all remaining members (including the removed one)
            let control = aira_core::group_proto::GroupControl::RemoveMember {
                group_id: *group_id,
                removed: member_pubkey.to_vec(),
            };
            let recipients: Vec<Vec<u8>> = group.members.iter().map(|m| m.pubkey.clone()).collect();
            enqueue_group_control(storage, &control, &recipients);

            DaemonResponse::Ok
        }
        Err(e) => DaemonResponse::Error(e.to_string()),
    }
}

/// Handle `LeaveGroup` request.
fn handle_leave_group(storage: &aira_storage::Storage, group_id: &[u8; 32]) -> DaemonResponse {
    // Get group members before removing so we can notify them
    let members: Vec<Vec<u8>> = aira_storage::groups::get_group(storage, group_id)
        .map(|g| g.members.iter().map(|m| m.pubkey.clone()).collect())
        .unwrap_or_default();

    match aira_storage::groups::remove_group(storage, group_id) {
        Ok(()) => {
            // Notify all members that we left
            let control = aira_core::group_proto::GroupControl::Leave {
                group_id: *group_id,
            };
            enqueue_group_control(storage, &control, &members);

            DaemonResponse::Ok
        }
        Err(e) => DaemonResponse::Error(e.to_string()),
    }
}

/// Handle `AcceptGroupInvite` — invitee derives pseudonym and enqueues response (§12.6).
fn handle_accept_group_invite(
    storage: &aira_storage::Storage,
    seed: &MasterSeed,
    group_id: &[u8; 32],
    display_name: &str,
    invited_by: &[u8],
) -> DaemonResponse {
    // Derive our pseudonym for this group
    let our_pubkey = match derive_pseudonym_pubkey(
        storage,
        seed,
        aira_storage::types::PseudonymContext::Group,
        *group_id,
        display_name,
    ) {
        Ok((_counter, pk)) => pk,
        Err(e) => return DaemonResponse::Error(format!("pseudonym derivation failed: {e}")),
    };

    // Generate our initial Sender Key for this group (§12.1)
    let our_sk = aira_core::group::SenderKeyState::new();

    // Send our chain key to the admin (who will distribute to other members)
    let control = aira_core::group_proto::GroupControl::SenderKeyUpdate {
        group_id: *group_id,
        new_key: our_sk.chain_key_bytes().to_vec(),
    };
    enqueue_group_control(storage, &control, &[invited_by.to_vec()]);

    DaemonResponse::MyAddress(our_pubkey)
}

// ─── Receiver-side: incoming message processing ───────────────────────────

/// Process an incoming `PlainPayload` received from the network.
///
/// Called when the network layer decrypts a 1-on-1 message and delivers it.
/// Routes to the appropriate handler based on payload variant.
///
/// # Errors
///
/// Returns a description of what went wrong.
pub fn handle_incoming_payload(
    storage: &aira_storage::Storage,
    seed: &MasterSeed,
    sender_pubkey: &[u8],
    payload_bytes: &[u8],
    event_tx: &tokio::sync::broadcast::Sender<crate::types::DaemonEvent>,
) -> Result<(), String> {
    let payload: aira_core::proto::PlainPayload =
        postcard::from_bytes(payload_bytes).map_err(|e| format!("deserialize payload: {e}"))?;

    match payload {
        aira_core::proto::PlainPayload::GroupControl(control) => {
            handle_incoming_group_control(storage, seed, sender_pubkey, &control, event_tx)
        }
        aira_core::proto::PlainPayload::Text(text) => {
            // Store as incoming 1-on-1 message
            let cid = aira_storage::contact_id(sender_pubkey);
            let msg = aira_storage::StoredMessage {
                id: rand_id(),
                sender_is_self: false,
                payload_bytes: text.into_bytes(),
                timestamp_micros: now_micros(),
                ttl_secs: None,
                read_at: None,
                expires_at: None,
            };
            aira_storage::messages::store(storage, cid, &msg).map_err(|e| e.to_string())?;
            let _ = event_tx.send(crate::types::DaemonEvent::MessageReceived {
                from: sender_pubkey.to_vec(),
                payload: msg.payload_bytes,
            });
            Ok(())
        }
        // Other payload types (Action, Media, Reaction, etc.) — store as raw bytes
        _ => {
            let cid = aira_storage::contact_id(sender_pubkey);
            let msg = aira_storage::StoredMessage {
                id: rand_id(),
                sender_is_self: false,
                payload_bytes: payload_bytes.to_vec(),
                timestamp_micros: now_micros(),
                ttl_secs: None,
                read_at: None,
                expires_at: None,
            };
            aira_storage::messages::store(storage, cid, &msg).map_err(|e| e.to_string())?;
            let _ = event_tx.send(crate::types::DaemonEvent::MessageReceived {
                from: sender_pubkey.to_vec(),
                payload: msg.payload_bytes,
            });
            Ok(())
        }
    }
}

/// Process an incoming `GroupControl` message from a group member.
///
/// Dispatches to variant-specific handlers and emits appropriate `DaemonEvent`s.
#[allow(clippy::too_many_lines)]
fn handle_incoming_group_control(
    storage: &aira_storage::Storage,
    seed: &MasterSeed,
    sender_pubkey: &[u8],
    control: &aira_core::group_proto::GroupControl,
    event_tx: &tokio::sync::broadcast::Sender<crate::types::DaemonEvent>,
) -> Result<(), String> {
    match control {
        aira_core::group_proto::GroupControl::CreateGroup {
            group_id,
            name,
            members,
            creator_sender_key,
        } => {
            // We're being invited to a new group
            let now = now_secs();
            let group_members: Vec<aira_storage::GroupMemberInfo> = members
                .iter()
                .map(|pk| {
                    let is_creator = pk == sender_pubkey;
                    aira_storage::GroupMemberInfo {
                        pubkey: pk.clone(),
                        display_name: String::new(),
                        role: if is_creator {
                            aira_storage::GroupRole::Admin
                        } else {
                            aira_storage::GroupRole::Member
                        },
                        joined_at: now,
                        sender_chain_key: if is_creator {
                            let mut key = [0u8; 32];
                            let len = creator_sender_key.len().min(32);
                            key[..len].copy_from_slice(&creator_sender_key[..len]);
                            key
                        } else {
                            [0; 32]
                        },
                    }
                })
                .collect();

            let group = aira_storage::GroupInfo {
                id: *group_id,
                name: name.clone(),
                members: group_members,
                created_by: sender_pubkey.to_vec(),
                created_at: now,
            };

            aira_storage::groups::create_group(storage, &group).map_err(|e| e.to_string())?;

            let _ = event_tx.send(crate::types::DaemonEvent::GroupInvite {
                group_id: *group_id,
                name: name.clone(),
                invited_by: sender_pubkey.to_vec(),
            });

            // Auto-accept: derive pseudonym and send SenderKeyUpdate back
            // (UI can override with manual AcceptGroupInvite if preferred)
            let _ = handle_accept_group_invite(storage, seed, group_id, "", sender_pubkey);

            Ok(())
        }

        aira_core::group_proto::GroupControl::AddMember {
            group_id,
            new_member,
            sender_keys,
        } => {
            let mut group =
                aira_storage::groups::get_group(storage, group_id).map_err(|e| e.to_string())?;

            // Add new member if not already present
            if !group.members.iter().any(|m| m.pubkey == *new_member) {
                group.members.push(aira_storage::GroupMemberInfo {
                    pubkey: new_member.clone(),
                    display_name: String::new(),
                    role: aira_storage::GroupRole::Member,
                    joined_at: now_secs(),
                    sender_chain_key: [0; 32],
                });
            }

            // Update sender chain keys from distributed keys
            for (pk, chain_key_bytes) in sender_keys {
                if let Some(member) = group.members.iter_mut().find(|m| m.pubkey == *pk) {
                    let len = chain_key_bytes.len().min(32);
                    member.sender_chain_key[..len].copy_from_slice(&chain_key_bytes[..len]);
                }
            }

            aira_storage::groups::update_group(storage, &group).map_err(|e| e.to_string())?;

            let _ = event_tx.send(crate::types::DaemonEvent::GroupMemberJoined {
                group_id: *group_id,
                member: new_member.clone(),
            });

            Ok(())
        }

        aira_core::group_proto::GroupControl::RemoveMember { group_id, removed } => {
            aira_storage::groups::remove_member(storage, group_id, removed)
                .map_err(|e| e.to_string())?;

            let _ = event_tx.send(crate::types::DaemonEvent::GroupMemberLeft {
                group_id: *group_id,
                member: removed.clone(),
            });

            // Trigger Sender Key rotation: generate new key and distribute
            let our_sk = aira_core::group::SenderKeyState::new();
            let group =
                aira_storage::groups::get_group(storage, group_id).map_err(|e| e.to_string())?;
            let recipients: Vec<Vec<u8>> = group.members.iter().map(|m| m.pubkey.clone()).collect();

            let update = aira_core::group_proto::GroupControl::SenderKeyUpdate {
                group_id: *group_id,
                new_key: our_sk.chain_key_bytes().to_vec(),
            };
            enqueue_group_control(storage, &update, &recipients);

            Ok(())
        }

        aira_core::group_proto::GroupControl::SenderKeyUpdate { group_id, new_key } => {
            let mut group =
                aira_storage::groups::get_group(storage, group_id).map_err(|e| e.to_string())?;

            // Find the sender in group members and update their chain key
            if let Some(member) = group.members.iter_mut().find(|m| m.pubkey == sender_pubkey) {
                let len = new_key.len().min(32);
                member.sender_chain_key = [0; 32];
                member.sender_chain_key[..len].copy_from_slice(&new_key[..len]);

                aira_storage::groups::update_group(storage, &group).map_err(|e| e.to_string())?;
            }

            Ok(())
        }

        aira_core::group_proto::GroupControl::Leave { group_id } => {
            aira_storage::groups::remove_member(storage, group_id, sender_pubkey)
                .map_err(|e| e.to_string())?;

            let _ = event_tx.send(crate::types::DaemonEvent::GroupMemberLeft {
                group_id: *group_id,
                member: sender_pubkey.to_vec(),
            });

            Ok(())
        }
    }
}

/// Handle `SetTransportMode` request.
fn handle_set_transport_mode(storage: &aira_storage::Storage, mode_str: &str) -> DaemonResponse {
    if let Err(e) = mode_str.parse::<aira_net::transport::TransportMode>() {
        return DaemonResponse::Error(format!("invalid transport mode: {e}"));
    }

    match aira_storage::settings::set(storage, TRANSPORT_MODE_KEY, mode_str.as_bytes()) {
        Ok(()) => {
            tracing::info!("transport mode set to: {mode_str}");
            DaemonResponse::Ok
        }
        Err(e) => DaemonResponse::Error(format!("failed to save transport mode: {e}")),
    }
}

/// Handle `GetTransportMode` request.
fn handle_get_transport_mode(storage: &aira_storage::Storage) -> DaemonResponse {
    match aira_storage::settings::get(storage, TRANSPORT_MODE_KEY) {
        Ok(Some(bytes)) => {
            let mode_str = String::from_utf8_lossy(&bytes).to_string();
            DaemonResponse::TransportMode(mode_str)
        }
        Ok(None) => DaemonResponse::TransportMode("direct".into()),
        Err(e) => DaemonResponse::Error(format!("failed to read transport mode: {e}")),
    }
}

/// Handle a `SendFile` request: validate, import to blob store, enqueue `FileStart`, track transfer.
fn handle_send_file(
    storage: &aira_storage::Storage,
    blob_store: &aira_net::blobs::BlobStore,
    transfer_mgr: &crate::transfers::TransferManager,
    to: &[u8],
    path: std::path::PathBuf,
) -> DaemonResponse {
    if !path.exists() {
        return DaemonResponse::Error(format!("file not found: {}", path.display()));
    }

    let metadata = match std::fs::metadata(&path) {
        Ok(m) => m,
        Err(e) => return DaemonResponse::Error(format!("cannot read file: {e}")),
    };
    let file_size = metadata.len();

    if file_size > aira_net::blobs::MAX_FILE_SIZE {
        return DaemonResponse::Error(format!(
            "file too large: {} bytes (max {} bytes)",
            file_size,
            aira_net::blobs::MAX_FILE_SIZE
        ));
    }

    let transfer_id = rand_id();
    let file_name = path.file_name().map_or_else(
        || "unnamed".to_string(),
        |n| n.to_string_lossy().to_string(),
    );

    // Pre-compute file hash synchronously for FileStart
    let file_hash = match std::fs::read(&path) {
        Ok(data) => *blake3::hash(&data).as_bytes(),
        Err(e) => return DaemonResponse::Error(format!("cannot read file: {e}")),
    };

    // Enqueue FileStart to peer via pending queue (before async blob import)
    let file_start = aira_core::proto::PlainPayload::FileStart {
        id: transfer_id,
        name: file_name.clone(),
        size: file_size,
        hash: file_hash,
    };
    if let Ok(payload_bytes) = postcard::to_allocvec(&file_start) {
        let cid = aira_storage::contact_id(to);
        let _ = aira_storage::pending::enqueue(storage, cid, &payload_bytes);
    }

    let bs = blob_store.clone();
    let tm = transfer_mgr.clone();
    tokio::spawn(async move {
        let hash_result = if aira_net::blobs::BlobStore::is_inline(file_size) {
            match tokio::fs::read(&path).await {
                Ok(data) => {
                    let hash_bytes = blake3::hash(&data);
                    bs.import_bytes(data.as_slice())
                        .await
                        .map(|h| (h, file_size, *hash_bytes.as_bytes()))
                }
                Err(e) => Err(aira_net::NetError::BlobStore(format!("read file: {e}"))),
            }
        } else {
            bs.import_file(&path).await.map(|(h, s)| {
                let hash_bytes: [u8; 32] = h.into();
                (h, s, hash_bytes)
            })
        };

        match hash_result {
            Ok((_blob_hash, size, hash_bytes)) => {
                tm.start_send(transfer_id, file_name, size, hash_bytes)
                    .await;
                tm.update_progress(transfer_id, 0).await;
                tm.update_progress(transfer_id, size).await;
                tm.complete(transfer_id, path).await;
            }
            Err(e) => {
                tm.start_send(transfer_id, file_name, file_size, [0u8; 32])
                    .await;
                tm.fail(transfer_id, e.to_string()).await;
            }
        }
    });

    DaemonResponse::Ok
}
