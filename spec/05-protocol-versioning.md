# SPEC §6.4-6.6: Протокол — версионирование, relay mailboxes, padding

[← Индекс](../SPEC.md)

---

### 6.4 Версионирование протокола

При handshake стороны обмениваются **capability set** — набором
поддерживаемых версий протокола и фич:

```rust
#[derive(Serialize, Deserialize)]
pub struct Capabilities {
    /// Минимальная поддерживаемая версия протокола
    pub min_version: u16,
    /// Максимальная (текущая) версия
    pub max_version: u16,
    /// Битовая маска поддерживаемых фич
    pub features: u64,
    /// Поддерживаемые cipher suites (в порядке предпочтения)
    pub cipher_suites: Vec<CipherSuite>,
}

/// Cipher suite определяет полный набор криптографических алгоритмов.
/// Отделён от feature flags — crypto agility требует отдельного negotiation.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum CipherSuite {
    /// v0.1 default: ChaCha20-Poly1305 + BLAKE3 + ML-KEM-768 + X25519 + ML-DSA-65
    Aira1 = 0,
    // Будущие суиты (AES-GCM, ML-KEM-1024, etc.) добавляются без breaking change
}

bitflags! {
    pub struct Features: u64 {
        const TRIPLE_RATCHET    = 1 << 0;  // SPQR PQ ratchet
        const DISAPPEARING_MSG  = 1 << 1;  // автоудаление сообщений
        const REACTIONS         = 1 << 2;  // реакции на сообщения
        const REPLY             = 1 << 3;  // ответ на сообщение
        const FILE_TRANSFER     = 1 << 4;  // передача файлов
        const GROUPS            = 1 << 5;  // групповые чаты
        const PADDING           = 1 << 6;  // traffic padding
        const EDIT_DELETE       = 1 << 7;  // редактирование/удаление сообщений
        const MEDIA             = 1 << 8;  // inline медиа (изображения, аудио, видео)
        const LINK_PREVIEW      = 1 << 9;  // link previews (v0.2)
        const PIN               = 1 << 10; // закрепление сообщений
    }
}
```

Правила negotiation:

- **Версии:** `max(min_A, min_B)..min(max_A, max_B)` — если пусто, handshake отклоняется
- **Фичи:** пересечение (AND) битовых масок
- **Cipher suite:** выбирается первый общий из списков обеих сторон
  (в порядке предпочтения инициатора). Если общих нет — handshake отклоняется.
- TRIPLE_RATCHET: если не поддерживается — fallback на классический DR
  (но не может быть понижен атакующим)

### 6.5 Pairwise relay mailboxes (снижение метаданных)

Вдохновлено SimpleX Chat — каждый контакт получает уникальный relay
endpoint, чтобы relay не мог связать разные чаты одного пользователя.

```
Alice ←→ Bob:    relay-A/mailbox-abc123
Alice ←→ Carol:  relay-B/mailbox-def456
Alice ←→ Dave:   relay-A/mailbox-ghi789
```

- Mailbox ID = `BLAKE3(shared_secret ‖ "mailbox")` — детерминистичный,
  оба пира знают адрес без дополнительного обмена
- Relay видит только отдельные mailbox'ы, не зная что abc123 и ghi789
  принадлежат одному пользователю
- Пользователь может использовать разные relay для разных контактов

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
  по таймеру) для скрытия паттернов активности

