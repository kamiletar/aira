# SPEC §6.7-6.15: Протокол — сообщения, реакции, receipts

[← Индекс](../SPEC.md)

---

### 6.7 Disappearing messages (v0.1)

Автоудаление сообщений через заданное время:

```rust
pub enum PlainPayload {
    Text(String),
    Action(String),
    // ... остальные варианты
}

/// Обёртка с метаданными сообщения
pub struct MessageMeta {
    pub payload: PlainPayload,
    /// Время жизни сообщения (None = навсегда)
    pub ttl: Option<Duration>,
    /// ID сообщения (для реакций, ответов, receipts)
    pub id: [u8; 16],
    /// ID сообщения, на которое отвечаем
    pub reply_to: Option<[u8; 16]>,
}
```

- TTL устанавливается per-chat (настройка: 30с / 5мин / 1ч / 1д / 7д / off)
- Таймер начинается после прочтения (read receipt), не после отправки
- Daemon удаляет из redb по расписанию
- UI показывает оставшееся время

### 6.8 Реакции и ответы (v0.1)

```rust
pub enum PlainPayload {
    Text(String),
    Action(String),
    /// Реакция на сообщение
    Reaction { message_id: [u8; 16], emoji: String },
    /// ... остальные варианты
}
```

- Emoji ограничено одним Unicode codepoint (без пользовательских стикеров)
- Reply: `reply_to` в `MessageMeta` — клиент показывает цитату
- Реакции на уже удалённое (disappearing) сообщение — игнорируются

### 6.9 Верификация ключей — Safety Numbers (v0.1)

TOFU (Trust On First Use) уязвим к MITM при первом соединении. Для
верификации добавляется **Safety Number** (как в Signal):

```rust
/// Safety Number computation — итеративный хэш с version binding.
/// Аналог Signal (5200 итераций SHA-512), адаптирован под BLAKE3.
///
/// Итерации замедляют brute-force поиск коллизий при отображении
/// 256-bit хэша в виде 60 десятичных цифр (~200 бит).
/// Version binding гарантирует смену Safety Number при обновлении
/// криптографических алгоритмов.
pub fn safety_number(
    key_a: &PubKey,
    key_b: &PubKey,
    protocol_version: u16,
) -> String {
    // Compute fingerprint for each key independently (like Signal)
    let fp_a = fingerprint(key_a, protocol_version);
    let fp_b = fingerprint(key_b, protocol_version);
    // Sort and concatenate for display
    let (first, second) = if key_a < key_b { (fp_a, fp_b) } else { (fp_b, fp_a) };
    format_as_digits(&first, 30) + &format_as_digits(&second, 30)
}

fn fingerprint(key: &PubKey, version: u16) -> [u8; 32] {
    let mut hash = [0u8; 32];
    hash.copy_from_slice(blake3::hash(key.as_bytes()).as_bytes());
    for _ in 0..5200 {
        let mut input = Vec::with_capacity(2 + 32 + key.as_bytes().len());
        input.extend_from_slice(&version.to_le_bytes());
        input.extend_from_slice(&hash);
        input.extend_from_slice(key.as_bytes());
        hash.copy_from_slice(blake3::hash(&input).as_bytes());
    }
    hash
}
```

- Оба пира вычисляют одинаковый Safety Number
- Сравнение: вслух при встрече, или QR-кодом
- CLI: `/verify <contact>` — показывает Safety Number
- При смене ключа контакта — уведомление + автоматический reset trust

### 6.10 Export/import аккаунта (v0.1)

Seed-фраза восстанавливает ключи, но не контакты, историю и настройки.

```
/export → aira-backup-2026-04-01.aira.enc

Содержимое (зашифровано storage key):
  - contacts.postcard     — список контактов с alias'ами
  - settings.postcard     — настройки (TTL, relay, etc.)
  - ratchet_states/       — текущие ratchet state для каждого контакта
  - messages/ (optional)  — история сообщений

/import aira-backup-2026-04-01.aira.enc
  → запросит seed-фразу для расшифровки
```

- Seed-фраза нужна для восстановления storage key (п. 4.8)
- Бэкап НЕ содержит seed-фразу или master key
- История опциональна (может быть большой)

### 6.11 Медиа-сообщения (v0.1)

Отличие от file transfer: медиа отображается inline с превью.

- **Изображения:** отправитель генерирует JPEG thumbnail (≤ 10KB,
  макс 320x320) и включает в `MediaPayload`. Получатель видит
  превью мгновенно, полное изображение скачивает через iroh-blobs.
- **Голосовые заметки:** `MediaType::Audio` с `duration_secs`.
  Формат: Opus в OGG контейнере. Макс длительность: 15 минут.
- **Видео:** `MediaType::Video` с thumbnail + duration + dimensions.
  Формат: H.264/H.265 в MP4. Макс размер: 100 MB.

Приватность: thumbnail включён в зашифрованное сообщение —
relay/сеть видят только размер конверта, не содержимое.

### 6.12 Link previews (v0.2)

Когда пользователь отправляет URL, клиент может сгенерировать превью:

- **Генерирует отправитель** (не получатель!) — получатель НЕ делает
  HTTP запрос к серверу ссылки, чтобы не раскрывать IP/активность
- Отправитель скачивает Open Graph метаданные (title, description, image)
- Thumbnail: JPEG ≤ 10KB, включён в `LinkPreviewPayload`
- **Opt-out:** настройка "не генерировать link previews" (privacy mode)
- Если отправитель использует Tor transport — previews безопасны

### 6.13 Редактирование и удаление сообщений (v0.1)

```
Редактирование:
  Alice отправляет: Edit { message_id: <id>, new_text: "исправленный текст" }
  Bob обновляет сообщение в UI, показывает "(ред.)"

Удаление:
  Alice отправляет: Delete { message_id: <id> }
  Bob удаляет сообщение из UI, показывает "сообщение удалено"
```

**Ограничения:**

- Редактировать/удалять можно только свои сообщения
- Окно редактирования: 24 часа после отправки
- Удаление — "мягкое": tombstone остаётся в истории (контакт видел
  оригинал, нечестно делать вид что сообщения не было)
- В disappearing чатах: Edit/Delete не продлевают TTL

### 6.14 Delivery и Read receipts (v0.1)

Раздельные статусы доставки:

```
Отправлено  → [✓]   (локально сохранено)
Доставлено  → [✓✓]  (ReceiptStatus::Delivered — дошло до устройства)
Прочитано   → [✓✓]  (ReceiptStatus::Read — пользователь открыл чат)
Воспроизвед.→ [▶✓]  (ReceiptStatus::Played — для аудио/видео)
```

- Read receipt запускает таймер disappearing messages (п. 6.7)
- **Privacy:** read receipts можно отключить per-contact или глобально.
  Если отключены — отправляется только Delivered, не Read.
- Receipts — отдельные зашифрованные сообщения (не metadata)

### 6.15 Typing indicators — приватность (v0.1)

`Typing(bool)` раскрывает паттерны активности (когда пользователь
печатает, думает, переписывает).

- **По умолчанию: включены** (ожидаемый UX)
- **Настройка:** отключаемы глобально или per-contact
- Если отключены — `Typing` сообщения не отправляются
- **Не** отправляются в disappearing чатах с TTL < 5 минут
  (слишком детальная утечка активности)
- Rate limit: максимум 1 Typing event / 3 секунды

