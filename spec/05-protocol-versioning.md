# SPEC §6.4-6.6: Протокол — версионирование, relay mailboxes, padding

[← Индекс](../SPEC.md)

---

### 6.4 Версионирование протокола

> **Релизный протокол = v2** (решение владельца A2, 24.09.2026): `min_version = max_version = 2`,
> совместимости с v1 (0.3.x) нет — у 0.3.x не было сетевого слоя, ломать нечего. v1 объявлен
> pre-release без гарантий. Формат v2 (`Message::Ratchet { header, envelope }`, header в AAD,
> PQXDH-handshake с транскриптом) — §6.1 и Milestone 19a; здесь — только negotiation.

При handshake стороны обмениваются **capability set** — набором
поддерживаемых версий протокола и фич:

```rust
#[derive(Serialize, Deserialize)]
pub struct Capabilities {
    /// Минимальная поддерживаемая версия протокола (релиз: 2)
    pub min_version: u16,
    /// Максимальная (текущая) версия (релиз: 2)
    pub max_version: u16,
    /// Битовая маска поддерживаемых фич (`handshake::features`, ниже)
    pub features: u64,
    /// Поддерживаемые cipher suites (в порядке предпочтения)
    pub cipher_suites: Vec<CipherSuite>,
}

/// Cipher suite определяет полный набор криптографических алгоритмов.
/// Отделён от feature flags — crypto agility требует отдельного negotiation.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum CipherSuite {
    /// Единственный суит v2: ChaCha20-Poly1305 + BLAKE3 + ML-KEM-768 + X25519 + ML-DSA-65
    Aira1 = 0,
    // Будущие суиты (AES-GCM, ML-KEM-1024, etc.) добавляются без breaking change
}

/// Биты `features` — ЕДИНЫЙ список, один и тот же в спеке и в коде
/// (`crates/aira-core/src/handshake.rs`, `pub mod features`). M19a фиксирует его для v2.
pub mod features {
    pub const PQ_RATCHET:    u64 = 1 << 0; // SPQR PQ ratchet (§4.4)
    pub const FILE_TRANSFER: u64 = 1 << 1; // передача файлов (§6.2)
    pub const DISAPPEARING:  u64 = 1 << 2; // автоудаление сообщений (§6.7)
    // ─── Резерв (M19a): биты заняты заранее, в бете не выставляются ───
    pub const GROUPS:        u64 = 1 << 3; // групповые чаты v2 (§12, M25)
    pub const MULTIDEVICE:   u64 = 1 << 4; // мультидевайс v2 (§14, M26)
    // Биты 5..63 свободны. Реакции/ответы/edit/receipts/typing/pin/профили (M28)
    // бита не требуют: они едут внутри `PlainPayload`, а вариант для них
    // резервируется заранее (§6.16.1 п.5), а не согласуется флагом.
}
```

> До M19a в коде (`handshake.rs:28-34`) только первые три бита. Прежний список спеки
> (`TRIPLE_RATCHET = 1<<0, DISAPPEARING_MSG = 1<<1, REACTIONS = 1<<2, …, PIN = 1<<10`) с кодом
> не совпадал ни по именам, ни по битам (аудит G8) и отменён.

Правила negotiation:

- **Версии:** `max(min_A, min_B)..min(max_A, max_B)` — если пусто, handshake отклоняется.
  Для релиза это означает: v2 ↔ v2, любая другая пара отклоняется
- **Фичи:** пересечение (AND) битовых масок
- **Cipher suite:** выбирается первый общий из списков обеих сторон
  (в порядке предпочтения инициатора). Если общих нет — handshake отклоняется.
- `PQ_RATCHET`: если не поддерживается — fallback на классический DR, но понижение
  атакующим невозможно: `Capabilities` обеих сторон входят в подписанный транскрипт
  handshake (M19a)

### 6.5 Pairwise relay mailboxes (снижение метаданных)

Вдохновлено SimpleX Chat — каждый контакт получает уникальный relay
endpoint, чтобы relay не мог связать разные чаты одного пользователя.
Речь о **mailbox relay** (`aira-relay`, §6.3b, Milestone 21) — не о транспортном
iroh-relay (§5.1.1); термины — глоссарий §20.

```
Alice → Bob:     relay-A/mailbox-abc123   (коробка направления A→B)
Bob → Alice:     relay-A/mailbox-9f1e07   (коробка направления B→A)
Alice → Carol:   relay-B/mailbox-def456
Alice → Dave:    relay-A/mailbox-ghi789
```

- **Две коробки на пару, по направлению** (решение владельца A1, 24.09.2026): иначе `Ack`
  одной стороны по счётчику ratchet удалял бы конверты другой
- Mailbox ID детерминистичен из pairwise `shared_secret` (§4.2) — оба пира знают адрес
  без дополнительного обмена:
  `mailbox_id[dir] = derive_key("aira/relay/mailbox/v2/" ‖ dir, shared_secret)`,
  `dir ∈ {"a2b", "b2a"}`. Ключи `owner_key[dir]` / `sender_key[dir]` (Ed25519 — подписи
  `Register/Retrieve/Ack/Delete` и `Deposit`) — из того же секрета, контексты
  `aira/relay/owner/v2/<dir>`, `aira/relay/sender/v2/<dir>` (`docs/KEY_CONTEXTS.md`).
  Полная спецификация протокола (`RelayHello`, `Register`, `Deposit`, `Retrieve`, `Ack`,
  intro-mailbox, квоты) — §6.3b и M21
- Relay видит только публичные ключи коробок, размер и время конвертов; не знает, что abc123
  и ghi789 принадлежат одному пользователю
- Пользователь может использовать разные relay для разных контактов; в контакт-записи и
  приглашении — 2–3 `RelayRef` у разных операторов (§6.3b), retrieve со всех + дедуп
- Прежняя формула `BLAKE3(shared_secret ‖ "mailbox")` и контекст `aira/relay/mailbox/v1`
  (одна коробка на пару, `aira-net/src/relay.rs`, ALPN `aira/1/relay`) — v1, удаляются в M21

**Резервы формата (M21 п.3), которые понадобятся после беты:**

- `Deposit { targets: Vec<(mailbox_id, sender_sig)>, envelope }`, `targets.len() ≤ 100`,
  квота отправителя считает `targets.len()` — тело конверта хранится один раз, ссылки N.
  Нужен групповому fan-out (§12.3, M25): один конверт в N pairwise-коробок участников.
  «Групповая коробка» с id из группового секрета отвергнута — relay увидел бы состав группы (§12.6)
- `Register { …, device_id }` — одна коробка = одно устройство, если мультидевайс идёт по
  модели per-device сессий (§14.3c, решение C3 — открыто; в бете `device_id` = устройство 0)

### 6.6 Padding (скрытие длины сообщений)

Зашифрованные сообщения раскрывают длину plaintext. Padding добавляет
случайные байты до фиксированных блоков:

```rust
fn pad_message(plaintext: &[u8]) -> Vec<u8> {
    // Блоки: 256, 512, 1024, 2048, 4096 байт
    let block_sizes = [256, 512, 1024, 2048, 4096];
    let target = block_sizes
        .iter()
        .find(|&&s| s >= plaintext.len() + 2) // +2 для длины
        .unwrap_or(&4096);
    let mut padded = Vec::with_capacity(*target);
    padded.extend_from_slice(&(plaintext.len() as u16).to_le_bytes());
    padded.extend_from_slice(plaintext);
    padded.resize(*target, 0); // zero-padding
    padded
}
```

- Скрывает разницу между "набирает" (Typing: ~10 байт) и коротким
  сообщением (~50 байт) — оба выглядят как 256-байтный блок
- Опционально: dummy traffic (отправка пустых зашифрованных пакетов
  по таймеру) для скрытия паттернов активности; системно — mix-профиль
  Aira Onion (§5.5, M24d)

