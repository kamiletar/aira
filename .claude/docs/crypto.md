# Криптографическая схема Aira

> Полная спека: SPEC.md §4

## Ключевые алгоритмы

| Назначение | Алгоритм | Крейт |
|-----------|---------|-------|
| Identity signing | ML-DSA-65 (FIPS 204) | `ml-dsa` |
| Key agreement (PQ) | ML-KEM-768 (FIPS 203) | `ml-kem` |
| Key agreement (classical) | X25519 | `x25519-dalek` |
| Hybrid shared secret | BLAKE3(X25519‖ML-KEM‖ctx) | `blake3` |
| Symmetric encryption | ChaCha20-Poly1305 | `chacha20poly1305` |
| Hashing / KDF | BLAKE3 | `blake3` |
| Memory-hard KDF | Argon2id (m=256MB) | `argon2` |
| Ratchet | Triple Ratchet (SPQR) | custom (на примитивах выше) |
| Handshake | PQXDH | custom |

## Key Derivation Tree

```
Seed Phrase (24 BIP-39 words)
    ↓ Argon2id(m=256MB, t=3, p=4, salt="aira-master-v1-m256")   # профиль Mobile (m64, другая соль) удаляется — одна фраза = одна identity
Master Seed (32 bytes)
    ├── BLAKE3-KDF("aira/identity/0")  → ML-DSA-65 Signing Key
    ├── BLAKE3-KDF("aira/x25519/0")   → X25519 Static Key
    ├── BLAKE3-KDF("aira/mlkem/0")    → ML-KEM-768 Decaps Key
    └── BLAKE3-KDF("aira/storage/0")  → Storage Encryption Key
```

## KEY CONTEXTS (docs/KEY_CONTEXTS.md)

Полный список в `docs/KEY_CONTEXTS.md`. Правило: один контекст → один ключ → одна цель.

## Triple Ratchet (SPQR)

Реализует Signal SPQR (Sparse Post-Quantum Ratchet, Eurocrypt 2025):

```
┌─────────────────────────────────┐
│  Classical Double Ratchet (X25519) │
│  • DH ratchet при каждом обмене    │
│  • Symmetric chain ratchet /msg   │
├─────────────────────────────────┤
│  PQ Ratchet (ML-KEM-768)          │
│  • Sparse: каждые ~50 сообщений   │
├─────────────────────────────────┤
│  session_key = KDF(classical‖pq)  │
└─────────────────────────────────┘
```

## PQXDH Handshake

```
Alice                              Bob
  ├── [Identity_A, EphemeralKEM] ──→
  ←── [Identity_B, EphemeralKEM] ──┤
  ├── [Encrypted: "Hello"] ────────→
  │   (Triple Ratchet activated)
```

## Session Reset (SPEC.md §4.9)

Если ratchet state потерян — `SessionReset` PlainPayload инициирует новый PQXDH.
Пользователь видит: "⚠ Keys reset. Verify Safety Number."

## Критичные ошибки которых нельзя допускать

- **Cross-protocol key reuse** — пример: Threema (USENIX 2023). Один ключ в двух контекстах = атака.
- **Non-constant-time MAC comparison** — `==` вместо `subtle::ConstantTimeEq`
- **Забыть zeroize** — секрет в памяти после Drop
- **Hardcoded context strings** — если два разных места используют одну строку контекста

## Фазы crypto backend

- **Phase 1 (v0.1-v0.2):** RustCrypto (ml-kem + ml-dsa) — pure Rust, быстрая итерация
- **Phase 2 (v0.3+):** aws-lc-rs — FIPS 140-3 validated, production hardened
- Абстракция: `CryptoProvider` trait в `crates/aira-core/src/crypto/mod.rs`

## Протокол v2 (M19a) — что меняется относительно кода v0.3.5

Находки C1–C7 аудита (`.claude/docs/audit-2026-09/core-audit.md`): wire не несёт заголовок ratchet и AEAD без AAD; decrypt не транзакционен;
PQ-шаг ratchet никогда не стартует; handshake не PQXDH (нет ephemeral ML-KEM), подписи без SIGMA-binding и без EndpointId; PoW `ContactRequest`
переиспользуем (нет nonce/timestamp). В v2: `Message::Ratchet { header, envelope }` с header как AAD; транзакционный decrypt; ephemeral ML-KEM в
каждом handshake + `SignedPrekeyBundle { device_id, … }` для асинхронного старта через mailbox; EndpointId обеих сторон в подписываемых данных;
per-file ключ `aira/file/key/v2`; PoW над `recipient_pubkey ‖ server_nonce ‖ slot ‖ request` с адаптивной сложностью; `ContactStamp`
(hashcash над pseudonym_pk ‖ epoch, M22) вместо «PoW на ключ». Хоп-ключи onion (M24b): гибридный KEM раз в сутки, симметричные per-hop ключи.
