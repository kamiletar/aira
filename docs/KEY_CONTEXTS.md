# KDF Key Contexts — Aira

Все контексты для `blake3::derive_key()`. Каждый ключ используется ровно в одном контексте (Key Isolation).

**Совместимость бэкендов:** все контексты идентичны для RustCrypto (default) и aws-lc-rs (`--features=fips`).
Одинаковый seed → одинаковые ключи → совместимые сообщения между бэкендами.

## Master Seed Derivation

| Контекст | Назначение | Крейт |
|----------|-----------|-------|
| `aira/identity/0` | ML-DSA-65 identity signing key | aira-core/identity |
| `aira/x25519/0` | X25519 static DH key | aira-core/handshake |
| `aira/mlkem/0` | ML-KEM-768 KEM key (input to kem_keygen) | aira-core/handshake |
| `aira/storage/0` | Storage encryption key | aira-storage |

## ML-KEM Internal (seed splitting)

| Контекст | Назначение | Крейт |
|----------|-----------|-------|
| `aira/kem-keygen-d` | ML-KEM-768 deterministic keygen: seed d | aira-core/crypto |
| `aira/kem-keygen-z` | ML-KEM-768 deterministic keygen: seed z | aira-core/crypto |

## Hybrid KEM

| Контекст | Назначение | Крейт |
|----------|-----------|-------|
| `aira/hybrid-kem/v1` | X25519+ML-KEM IETF-style combiner | aira-core/kem |

## Handshake Session Keys

| Контекст | Назначение | Крейт |
|----------|-----------|-------|
| `aira/session/root/v1` | Session root key from combined secrets | aira-core/handshake |
| `aira/session/init-to-resp/v1` | Directional chain key: initiator→responder | aira-core/handshake |
| `aira/session/resp-to-init/v1` | Directional chain key: responder→initiator | aira-core/handshake |

## Double Ratchet (1-on-1)

| Контекст | Назначение | Крейт |
|----------|-----------|-------|
| `aira/chain/advance` | Symmetric chain key advancement | aira-core/ratchet |
| `aira/chain/message-key` | Per-message encryption key | aira-core/ratchet |
| `aira/ratchet/root` | Root key after DH ratchet step | aira-core/ratchet |
| `aira/ratchet/chain` | Chain key after DH ratchet step | aira-core/ratchet |

## PQ Ratchet (SPQR)

| Контекст | Назначение | Крейт |
|----------|-----------|-------|
| `aira/ratchet/pq-mix` | Mix PQ shared secret into root key | aira-core/ratchet |
| `aira/ratchet/pq-init` | Initial PQ keypair seed from root key | aira-core/ratchet |
| `aira/ratchet/pq-rekey` | PQ rekey seed after ratchet step | aira-core/ratchet |

## Device Management (Multidevice)

| Контекст | Назначение | Крейт |
|----------|-----------|-------|
| `aira/device/id` | Device ID derivation (per-index) | aira-core/device |
| `aira/device/sync-key` | Device-to-device sync encryption key | aira-core/device |
| `aira/device/link-code` | One-time linking code material | aira-core/device |

## Group Sender Keys

| Контекст | Назначение | Крейт |
|----------|-----------|-------|
| `aira/group/chain-advance` | Group sender key chain advancement | aira-core/group |
| `aira/group/message-key` | Per-message group encryption key | aira-core/group |

## Relay

| Контекст | Назначение | Крейт |
|----------|-----------|-------|
| `aira/relay/mailbox/v1` | Pairwise mailbox ID derivation | aira-net/relay |

## Pseudonym Keys (Unlinkable Identity, BIP-32 style)

> Per-context pseudonym keypairs (§12.6). Counter — монотонный u32 (hardened
> derivation). Mapping counter→context хранится в storage. Counter не содержит
> group_id/contact_id — при компрометации seed перебор невозможен.

| Контекст | Назначение | Крейт |
|----------|-----------|-------|
| `aira/pseudonym/<counter>/signing` | Per-context ML-DSA-65 signing key | aira-core/seed |
| `aira/pseudonym/<counter>/x25519` | Per-context X25519 DH key | aira-core/seed |
| `aira/pseudonym/<counter>/mlkem` | Per-context ML-KEM-768 KEM key (input to kem_keygen) | aira-core/seed |

## Transport Layer (DPI Resistance)

| Контекст | Назначение | Крейт |
|----------|-----------|-------|
| `aira/obfs/session/0` | Obfuscation session key (XOR keystream) | aira-net/transport |
| `aira/reality/sid/0` | REALITY short ID derivation from PSK | aira-net/transport |
| `aira/reality/auth/0` | REALITY authentication MAC key derivation | aira-net/transport |
| `aira/reality/session/0` | REALITY session key derivation | aira-net/transport |
