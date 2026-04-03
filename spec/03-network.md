# SPEC §5: Сетевой слой (aira-net)

[← Индекс](../SPEC.md)

---

## 5. Сетевой слой (aira-net)

### 5.1 Транспорт: iroh

**iroh** — Rust P2P библиотека от n0, Inc. Используется как транспортный
фундамент. Решает за нас:

- QUIC поверх UDP (встроенное TLS 1.3)
- NAT traversal (hole punching, QAD)
- Relay fallback через DERP-серверы при симметричном NAT
- Адресация пиров по публичному ключу (NodeId)

```toml
[dependencies]
iroh = "0.97"
iroh-blobs = "0.99"  # для передачи файлов
```

**Важно**: iroh использует Ed25519 для транспортной идентичности (NodeId).
Это классическая криптография на транспортном уровне — допустимо, т.к.
защищает от пассивного прослушивания сегодня. PQ-защита содержимого
обеспечивается на уровне Application Layer (п. 4).

NodeId iroh и ML-DSA Identity пользователя — разные ключи. При первом
соединении пользователь доказывает владение своим ML-DSA Identity через
handshake (п. 4.5).

### 5.2 Peer Discovery

Два механизма:

**a) Прямое добавление:**

> ⚠️ ML-DSA-65 публичный ключ = 1,952 байта = ~3,904 hex символа.
> Это **невозможно** ввести вручную (в отличие от 64-символьного Tox ID).

**Форматы обмена ключами (от простого к сложному):**

> **Per-contact pseudonyms (§12.6):** каждый invitation link содержит
> уникальный **pseudonym pubkey**, деривированный из MasterSeed через
> монотонный counter (BIP-32 модель). Получатель видит только pseudonym —
> невозможно связать два invitation link одного пользователя.
>
> При каждом вызове `/mykey` деривируется **новый** pseudonym keypair.
> Ранее выданные invitation links остаются валидными.

1. **QR-код** — сканирование камерой при встрече. ML-DSA pseudonym pubkey
   (1952 байт) помещается в QR Version 40 (binary mode, 2953 байт capacity),
   но QR будет очень плотным. Рекомендуется: QR содержит ссылку, не сам ключ.

2. **Invitation link** — `aira://add/<base64url(pseudonym_pubkey)>#<short_fingerprint>`
   Копируется через буфер обмена, мессенджер, email. Длина ~2,600 символов.
   При открытии — Aira отображает fingerprint для верификации.
   **Каждый вызов генерирует новый pseudonym** — два link'а нелинкуемы.

3. **Short fingerprint** — для устной верификации:
   `BLAKE3(pseudonym_pubkey)[..8]` → 16 hex символов (например, `a7f3-b2c1-e4d5-9f0a`).
   НЕ используется для добавления (коллизии!), только для подтверждения
   что обе стороны видят один ключ.

4. **Relay-assisted exchange** — Alice публикует одноразовый Contact Request
   на relay, Bob получает ссылку `aira://relay/<relay_id>/<one_time_token>`.
   Relay хранит зашифрованный pseudonym pubkey + handshake init (TTL: 24 часа).

```
CLI:
  /mykey           → показывает QR в терминале (sixel/kitty) + invitation link
  /add <link>      → добавить по invitation link
  /add --scan      → сканировать QR (если есть камера)
```

**b) DHT** — для поиска NodeId по ML-DSA публичному ключу:

- Пользователь публикует в DHT: `ML-DSA_pubkey → iroh_NodeId`
- Запись подписана ML-DSA ключом (нельзя подделать)
- DHT реализуется поверх iroh-gossip или отдельным Kademlia
- В v0.1 DHT — опционален, direct add обязателен

### 5.3 Bootstrap ноды

- Минимум 3 публичных bootstrap ноды в разных регионах
- Bootstrap нода = обычная нода без контактов (только peer discovery)
- Список зашит в бинарник, обновляется через signed update

### 5.4 Протокол поверх iroh

Определить ALPN-идентификаторы:

```rust
pub const ALPN_CHAT: &[u8] = b"aira/1/chat";
pub const ALPN_FILE: &[u8] = b"aira/1/file";
pub const ALPN_HANDSHAKE: &[u8] = b"aira/1/handshake";
```

---
