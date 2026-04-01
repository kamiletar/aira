# Сетевой слой (aira-net)

> Полная спека: SPEC.md §5, §11A, §11B

## iroh 0.97

iroh — Rust P2P библиотека от n0. Решает:
- QUIC поверх UDP (TLS 1.3)
- NAT traversal (hole punching + QAD)
- Relay fallback (DERP-серверы при симметричном NAT)
- Адресация пиров по публичному ключу (NodeId)

```rust
// Важно: iroh NodeId ≠ ML-DSA Identity
// NodeId — Ed25519 (транспортный)
// ML-DSA Identity — для протокола Aira
// Владение Identity доказывается при handshake
```

## Relay — store-and-forward

Relay НИКОГДА не хранит содержимое файлов.
Только зашифрованные сообщения (max 64 KB per envelope).

```
Alice (offline) ──→ [Relay mailbox] ──→ Bob (when online)
```

Pairwise mailboxes: `BLAKE3(shared_secret ‖ "mailbox")` — relay не может
связать разные чаты одного пользователя.

## Pluggable Transport Stack

```
aira-core (encrypted) → Padding → Obfuscation → Transport
```

| Режим | Когда использовать |
|-------|-------------------|
| direct | Без цензуры |
| obfs4 | Умеренная цензура (РФ, TR) |
| mimicry | Продвинутая цензура |
| reality | GFW-уровень, active probing |
| cdn | CDN relay (Cloudflare) |
| tor | Максимальная анонимность |

## DoS защита (Connection Tiers)

| Tier | Кто | Лимиты |
|------|-----|--------|
| 1 | Verified contacts | Без ограничений |
| 2 | Known peers | 100 msg/min |
| 3 | Strangers | 5 msg/min + PoW |

## ALPN идентификаторы

```rust
pub const ALPN_CHAT: &[u8]      = b"aira/1/chat";
pub const ALPN_FILE: &[u8]      = b"aira/1/file";
pub const ALPN_HANDSHAKE: &[u8] = b"aira/1/handshake";
pub const ALPN_RELAY: &[u8]     = b"aira/1/relay";
```
