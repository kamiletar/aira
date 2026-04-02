# SPEC §6.1-6.3: Протокол — формат пакетов, файлы, offline

[← Индекс](../SPEC.md)

---

## 6. Протокол сообщений

### 6.1 Формат пакетов

Сериализация: **postcard** (компактный, no_std, без аллокаций где возможно)

```rust
// aira-core/src/proto.rs

#[derive(Serialize, Deserialize)]
pub enum Message {
    /// Первый handshake
    Handshake(HandshakeInit),
    /// Ответ на handshake
    HandshakeAck(HandshakeAck),
    /// Зашифрованное сообщение (Triple Ratchet / SPQR)
    Encrypted(EncryptedEnvelope),
    /// Управление передачей файла
    FileOffer(FileOffer),
    FileChunk(FileChunk),
    FileAck(FileAck),
    /// Служебные
    Ping,
    Pong,
}

#[derive(Serialize, Deserialize)]
pub struct EncryptedEnvelope {
    /// Nonce для ChaCha20-Poly1305 (деривируется из counter, см. ниже)
    pub nonce: [u8; 12],
    /// Счётчик сообщения в ratchet (монотонно возрастает)
    pub counter: u64,
    /// Зашифрованный payload
    pub ciphertext: Vec<u8>,
    /// PQ KEM ciphertext (присутствует при шаге PQ ratchet, см. §4.4)
    pub pq_kem_ct: Option<Vec<u8>>,
}
```

**Nonce crash safety:**

Повторение nonce с тем же ключом в ChaCha20-Poly1305 = катастрофическая
потеря конфиденциальности и целостности. Стратегия защиты:

```
Nonce = BLAKE3(chain_key || counter)[..12]
```

- `counter` монотонно возрастает, **никогда не сбрасывается** в рамках
  одного chain key
- **Write-ahead counter:** при запуске daemon записывает в redb
  `persisted_counter = current_counter + SKIP_AHEAD` (SKIP_AHEAD = 1000).
  При крэше без корректного shutdown — counter перезапускается с
  `persisted_counter`, гарантируя отсутствие повторений
- При каждом шаге ratchet (новый chain key) — counter сбрасывается в 0
  (безопасно, т.к. ключ другой)
- Получатель хранит `max_seen_counter` per chain и отклоняет `counter <=
  max_seen_counter` (защита от replay)

```rust
// aira-core/src/ratchet.rs

const SKIP_AHEAD: u64 = 1000;

impl RatchetState {
    /// Вызывается при запуске daemon — резервирует диапазон counter'ов
    pub fn persist_counter_checkpoint(&mut self, db: &Database) -> Result<()> {
        self.persisted_counter = self.counter + SKIP_AHEAD;
        db.write_counter(self.contact_id, self.persisted_counter)?;
        Ok(())
    }
}
```

```rust
#[derive(Serialize, Deserialize)]
pub enum PlainPayload {
    // --- Контент ---
    Text(String),
    /// Действие от третьего лица (/me делает что-то)
    Action(String),
    /// Inline медиа: изображение, аудио, видео (см. п. 6.11)
    Media(MediaPayload),
    /// Ссылка с превью (см. п. 6.12)
    LinkPreview(LinkPreviewPayload),

    // --- Операции над сообщениями ---
    /// Реакция на сообщение (см. п. 6.8)
    Reaction { message_id: [u8; 16], emoji: String },
    /// Редактирование сообщения (см. п. 6.13)
    Edit { message_id: [u8; 16], new_text: String },
    /// Удаление сообщения (см. п. 6.13)
    Delete { message_id: [u8; 16] },

    // --- Статусы ---
    /// Уведомление о доставке/прочтении (см. п. 6.14)
    Receipt(ReceiptPayload),
    /// Статус набора текста (опционально, см. п. 6.15)
    Typing(bool),

    // --- Файлы ---
    /// Уведомление о начале передачи файла
    FileStart { id: [u8; 16], name: String, size: u64, hash: [u8; 32] },

    // --- Управление сессией ---
    /// Запрос на сброс и перезапуск сессии (см. п. 4.9)
    SessionReset {
        reason: SessionResetReason,
        new_kem_pk: Vec<u8>,
    },

    // --- Закрепление (v0.1) ---
    /// Закрепить/открепить сообщение в чате (см. п. 6.23)
    Pin { message_id: [u8; 16], pinned: bool },

    // --- Расширяемость (см. п. 6.16) ---
    /// Неизвестный тип — старые клиенты игнорируют
    Unknown { type_id: u16, data: Vec<u8> },
}

#[derive(Serialize, Deserialize)]
pub struct MediaPayload {
    pub media_type: MediaType,
    /// BLAKE3 хэш полного файла (для скачивания через iroh-blobs)
    pub hash: [u8; 32],
    /// Размер в байтах
    pub size: u64,
    /// Inline thumbnail (JPEG, ≤ 10 KB) — для мгновенного превью
    pub thumbnail: Option<Vec<u8>>,
    /// Длительность в секундах (для аудио/видео)
    pub duration_secs: Option<f32>,
    /// Размеры (для изображений/видео)
    pub width: Option<u32>,
    pub height: Option<u32>,
}

#[derive(Serialize, Deserialize)]
pub enum MediaType { Image, Audio, Video }

#[derive(Serialize, Deserialize)]
pub struct LinkPreviewPayload {
    pub url: String,
    pub title: Option<String>,
    pub description: Option<String>,
    /// Thumbnail (JPEG, ≤ 10 KB) — генерируется отправителем
    pub thumbnail: Option<Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
pub struct ReceiptPayload {
    pub message_id: [u8; 16],
    pub status: ReceiptStatus,
}

#[derive(Serialize, Deserialize)]
pub enum ReceiptStatus {
    /// Доставлено на устройство
    Delivered,
    /// Прочитано пользователем (начинает TTL disappearing)
    Read,
    /// Воспроизведено (для аудио/видео)
    Played,
}

/// Обёртка с метаданными сообщения (см. п. 6.7)
#[derive(Serialize, Deserialize)]
pub struct MessageMeta {
    pub payload: PlainPayload,
    /// Время жизни (None = навсегда, см. п. 6.7)
    pub ttl: Option<Duration>,
    /// ID сообщения
    pub id: [u8; 16],
    /// ID сообщения, на которое отвечаем (см. п. 6.8)
    pub reply_to: Option<[u8; 16]>,
}
```

### 6.2 Передача файлов

- Файлы > 1 МБ передаются через **iroh-blobs** (BLAKE3 content-addressed,
  возобновляемая передача, верификация хэша)
- Файлы < 1 МБ — inline в EncryptedEnvelope
- При передаче через iroh-blobs: hash передаётся в зашифрованном сообщении,
  сам файл запрашивается через iroh-blobs API

### 6.3 Offline сообщения

Если собеседник офлайн, сообщения буферизуются и доставляются при
следующем подключении. Два механизма:

**a) Локальная очередь (v0.1):**

- Сообщение шифруется Triple Ratchet и сохраняется в `pending_messages`
  таблицу redb
- При обнаружении пира онлайн — daemon автоматически доставляет очередь
- Порядок гарантируется счётчиком ratchet (`counter`)
- Ограничение: 1000 сообщений / 100 MB на контакт
- Если оба пира были офлайн — при встрече обмен очередями двусторонний

**b) Relay Store-and-Forward (v0.1):**

> ⚠️ Критично для реального использования — без relay мессенджер работает
> только если оба пира одновременно онлайн. На мобильных (iOS) фоновое
> соединение живёт ~30 сек — relay обязателен.

- Доверенный relay хранит зашифрованные конверты (не может прочитать)
- Пир при подключении забирает свои сообщения с relay
- TTL: 7 дней, затем relay удаляет
- Relay идентифицируется по iroh NodeId, выбирается пользователем
- Relay не знает содержимое — только размер и timestamp
- Каждый контакт получает **уникальный pairwise relay mailbox** —
  relay не может связать разные чаты одного пользователя (см. п. 6.5)

**Mailbox registration (заложено для mobile push, v0.3):**

```rust
/// Конфигурация mailbox при регистрации на relay
#[derive(Serialize, Deserialize)]
pub struct MailboxConfig {
    pub mailbox_id: [u8; 32],
    /// Опциональный push endpoint для wake-up уведомлений (v0.3)
    /// В v0.1 = None; заложено сейчас чтобы избежать breaking change
    pub notification_endpoint: Option<NotificationEndpoint>,
}

/// Push-уведомление для мобильных клиентов.
/// Relay отправляет wake-up (без содержимого!) — клиент просыпается
/// и забирает сообщения через обычный retrieve.
#[derive(Serialize, Deserialize)]
pub enum NotificationEndpoint {
    /// UnifiedPush (децентрализованный, без Google)
    UnifiedPush { url: String },
    /// Firebase Cloud Messaging (Android fallback)
    Fcm { registration_id: String },
}
```

> ⚠️ Push endpoint заложен в wire format сейчас, хотя используется
> только в v0.3. Это предотвращает breaking change relay протокола
> при добавлении mobile support.

```rust
// aira-storage: таблица pending messages
const PENDING: TableDefinition<(/* contact_id */ &[u8], /* seq */ u64), &[u8]> =
    TableDefinition::new("pending_messages");
    // value: postcard(EncryptedEnvelope) — уже зашифровано, ждёт доставки
```

