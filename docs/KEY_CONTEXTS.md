# KDF Key Contexts — Aira

Все контексты для `blake3::derive_key()`. Каждый ключ используется ровно в одном контексте (Key Isolation).

## Master Seed Derivation

| Контекст | Назначение | Крейт |
|----------|-----------|-------|
| `aira/storage/0` | Storage encryption key | aira-storage |

## Double Ratchet (1-on-1)

| Контекст | Назначение | Крейт |
|----------|-----------|-------|
| `aira/chain/advance` | Symmetric chain key advancement | aira-core/ratchet |
| `aira/chain/message-key` | Per-message encryption key | aira-core/ratchet |
| `aira/ratchet/root` | Root key after DH ratchet step | aira-core/ratchet |
| `aira/ratchet/chain` | Chain key after DH ratchet step | aira-core/ratchet |

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

## Transport Layer (DPI Resistance)

| Контекст | Назначение | Крейт |
|----------|-----------|-------|
| `aira/obfs/session/0` | Obfuscation session key (XOR keystream) | aira-net/transport |
| `aira/reality/sid/0` | REALITY short ID derivation from PSK | aira-net/transport |
| `aira/reality/auth/0` | REALITY authentication MAC key derivation | aira-net/transport |
| `aira/reality/session/0` | REALITY session key derivation | aira-net/transport |
