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

- **Порог inline = лимит конверта.** Файл кладётся inline в `EncryptedEnvelope`, только если весь конверт
  ≤ `MAX_ENVELOPE_SIZE` (64 KB, §6.22). В коде порог `INLINE_THRESHOLD = 1 MB` (`aira-net/src/blobs.rs`)
  противоречит лимиту конверта — в M19a порог выводится из константы `aira-core`, отдельной константы в
  `aira-net` не остаётся.
- Всё крупнее — через **iroh-blobs** (BLAKE3 content-addressed, возобновляемая передача, верификация хэша),
  до 4 GB (`MAX_FILE_SIZE`).
- **Шифрование blob (план, M19a; решение владельца A12).** Сейчас blob идёт открытым содержимым под
  классическим TLS iroh: не PQ-защищён, и любой, кто знает хэш, получает файл. В протоколе v2 файл
  шифруется **per-file ключом из ratchet**: `file_key = derive_key("aira/file/key/v2", session_secret ‖
  file_id)` — оба конца выводят его из состояния сессии без дополнительного обмена; blob = шифротекст
  (ChaCha20-Poly1305, чанки с индексом в AAD); `FileStart.hash` = BLAKE3 **от шифротекста**; iroh-blobs
  верифицирует шифротекст, расшифровка — после скачивания. Точная схема чанков / nonce фиксируется в M19a
  (`docs/KEY_CONTEXTS.md`).
- `FileStart { id, name, size, hash }` идёт в зашифрованном сообщении; сам blob запрашивается по хэшу через
  ALPN `aira/2/file`; `FileComplete` — только по `FileAck` от пира (M19). Приёмная сторона —
  `iroh_blobs::store::fs` на диске, не в памяти.
- Через mailbox relay файлы не идут никогда (§6.22). По профилям (`direct` / hide-IP / onion) — таблица в
  §6.22 и §5.5.9.

### 6.3 Offline сообщения

Если собеседник офлайн, сообщения буферизуются и доставляются при
следующем подключении. Два механизма:

**a) Локальная очередь (v0.1; в коде):**

- Сообщение шифруется Triple Ratchet и сохраняется в `pending_messages`
  таблицу redb
- **Инвариант: в PENDING лежит только `postcard(EncryptedEnvelope)`** — никогда plaintext
  (тип-обёртка `PendingEnvelope`, заголовок `{ enqueued_at, size }`; M19 Phase A п.2)
- При обнаружении пира онлайн — daemon доставляет очередь: `connect` (таймаут 5 с) →
  `write_framed` → `Message::Ack { counter }` от пира → `dequeue` **только после ack**;
  триггеры: старт, входящее соединение, backoff [5 с, 30 с, 2 мин, 10 мин, 1 ч]
- Порядок гарантируется счётчиком ratchet (`counter`)
- Ограничение: 1000 сообщений / 100 MB на контакт → `DaemonResponse::Error(QueueFull)`; GC 7 дней
- Если оба пира были офлайн — при встрече обмен очередями двусторонний

**b) Relay Store-and-Forward — `aira-relay` mailbox v2 (план, M21):**

> ⚠️ Критично для реального использования — без relay мессенджер работает
> только если оба пира одновременно онлайн (Android FGS ограничен по времени,
> десктоп выключают). Это **mailbox relay** (`aira-relay`, ALPN `aira/2/relay`),
> не транспортный `iroh-relay` — см. §5.1.1. В коде сейчас — mailbox v1
> (`aira-net/src/relay.rs`, `aira/1/relay`) без аутентификации; удаляется в M21
> без совместимости (решение владельца A2).

**Модель коробок — две на пару, по направлению** (решение владельца A1; SimpleX-style,
ключи из shared secret PQXDH — §6.5):

```
mailbox_id[dir] = derive_key("aira/relay/mailbox/v2/" ‖ dir, shared_secret)  // dir = A→B | B→A (лексикографический порядок pubkeys)
owner_key[dir]  = Ed25519 из derive_key("aira/relay/owner/v2/"  ‖ dir, shared_secret)  // получатель направления
sender_key[dir] = Ed25519 из derive_key("aira/relay/sender/v2/" ‖ dir, shared_secret)  // отправитель направления
```

Обе стороны выводят все три, relay получает только публичные ключи. Коробка `A→B`
принадлежит B (owner), пишет в неё A (sender): Alice больше не получает свои же
депозиты, а `Ack` одного направления не удаляет конверты другого.

**Протокол** (`crates/aira-relay`, postcard; каждый запрос подписан и включает
`relay_nonce` из `RelayHello` — защита от replay):

```rust
pub const RELAY_PROTOCOL_VERSION: u16 = 2;

/// Первое сообщение relay → клиент (см. §11B.5.1)
pub struct RelayHello {
    pub protocol_version: u16,             // 2
    pub supported_versions: Vec<u16>,
    pub capabilities: RelayCapabilities,   // STORE_FORWARD | PUSH_NOTIFY | INTRO | ONION_HOP
    pub relay_nonce: [u8; 32],             // challenge на сессию
    pub catalog_class: RelayClass,         // anchor | server | server-pinned | client
    pub operator_id: [u8; 32],
    pub min_client_version: Version,       // клиент отклоняет relay ниже min_relay_version каталога
    pub limits: RelayLimits,               // envelope_max, per-box, ttl — дефолты 64 KB / 100 / 10 MB / 7 д
}

pub enum RelayRequest {
    /// Владелец регистрирует коробку (подпись owner_sk над полями ‖ relay_nonce).
    /// Коробка живёт, пока владелец обновляет регистрацию (раз в 7 дней). Без Register коробки нет (AP-6).
    Register {
        mailbox_id: [u8; 32],
        owner_pk: [u8; 32],
        sender_pk: [u8; 32],
        notification_endpoint: Option<NotificationEndpoint>,
        ttl_hint: u32,
        device_id: Option<[u8; 32]>,       // резерв под мультидевайс v2 (M26; решение C3 — per-device сессии)
        surb_stock: Vec<Surb>,             // резерв под Wake через onion (M24b); до него пусто
        sig: [u8; 64],
    },
    /// Депозит конверта в 1..=100 коробок (подпись sender_sk[dir] каждой коробки над
    /// BLAKE3(envelope) ‖ mailbox_id ‖ relay_nonce). >1 цели — группы v2 (M25): один шифротекст
    /// sender key на всех участников.
    Deposit {
        targets: Vec<DepositTarget>,       // { mailbox_id, sig }, ≤ 100
        envelope: EncryptedEnvelope,       // ≤ MAX_ENVELOPE_SIZE
    },
    /// Выгрузка постранично (ответ ≤ MAX_FRAME_SIZE); подпись owner_sk.
    Retrieve { mailbox_id: [u8; 32], after_seq: u64, limit: u16, sig: [u8; 64] },
    /// Подтверждение по seq relay (не по ratchet-counter) — relay удаляет всё ≤ up_to_seq.
    Ack { mailbox_id: [u8; 32], up_to_seq: u64, sig: [u8; 64] },
    Delete { mailbox_id: [u8; 32], sig: [u8; 64] },
    /// Первый контакт без общего секрета (§5.2 п.4): intro-коробка по pseudonym_pk получателя.
    IntroDeposit { intro_id: [u8; 32], request: ContactRequest, pow: Pow },
}

pub enum RelayResponse {
    Registered { expires_at: u64 },
    Deposited { seq: u64, envelope_id: [u8; 32] },
    Envelopes { items: Vec<(u64 /* seq */, EncryptedEnvelope)>, next_seq: Option<u64> },
    Ok,
    Error(RelayError),  // MailboxNotFound | Unauthorized | QuotaExceeded | TooLarge | PowRequired { bits } | Busy
}
```

- `seq` присваивает relay при приёме (монотонно на коробку); порядок сообщений восстанавливается по
  ratchet-`counter` после расшифровки (skipped keys, `MAX_SKIP = 1000`), не по `seq`.
- `envelope_id = BLAKE3("aira/relay/envelope-id/v2" ‖ header)` — дедуп при `Retrieve` с нескольких relay
  (тот же ключ, что в `dedup.rs`).
- **Депозит может приходить от onion-хопа** (M24b, §5.5): депозитор ≠ отправитель; авторизация — подпись
  `sender_sk` внутри; лимиты relay считаются по `sender_pk` / коробке, **не** по IP / `EndpointId`
  депозитора (инвариант AP-5).
- **Intro-mailbox** (`intro_id = derive_key("aira/relay/intro/v2", pseudonym_pk)`): только `ContactRequest`
  с **PoW ≥ 20 бит** над `relay_nonce ‖ request` (+ `slot`, M22), rate limit по `EndpointId`; только на relay
  класса `anchor`/`server`. Единственное место PoW на relay — обычный `Deposit` авторизуется подписью.
- **Квоты и TTL** (§11B.5): конверт ≤ 64 KB; 100 конвертов / 10 MB на коробку; **TTL 7 дней на конверт**
  (`received_at`); общий cap 1 GB; GC каждый час, приоритет вытеснения — коробки без `Retrieve` дольше всего;
  `Register` ≤ 20/сутки на `EndpointId`. Лимиты клиент читает из `RelayHello.limits` /
  `.well-known/aira-relay.json`; константы — дефолты, не догма.
- **Допуск:** все запросы — под сетевым токеном со `scope: MAILBOX` (intro — `INTRO`), §5.1.1 (M22).
- **Что видит relay:** `mailbox_id`, размеры, время, `EndpointId` клиента и набор коробок, которые он трогает;
  содержимое — нет. v2.1: случайный `EndpointId` на relay-сессию (relay не связывает коробки одного
  пользователя); с M24b депозиты и retrieve приходят через хопы (§5.5.12).

**Где живут мои коробки — `MailboxConfig`** (в контакт-записи и в invitation link; без IP):

```rust
/// Ссылка на хост коробки. Никогда не содержит IP.
#[derive(Serialize, Deserialize)]
pub struct MailboxRef {
    pub hop_id: EndpointId,          // EndpointId aira-relay (хоп-идентичность хоста, не чат-ключ)
    pub relay_urls: Vec<RelayUrl>,   // как дойти до хоста (iroh-relay); pin — из RelayRef / каталога (§5.1.1)
    pub mailbox_id: [u8; 32],        // выводится обеими сторонами; в записи — для самодостаточности и миграции
}

#[derive(Serialize, Deserialize)]
pub struct MailboxConfig {
    /// 2–3 хоста разных операторов (не более одного на operator_id, IPv4 /24, IPv6 /48), без класса `client`.
    pub mailboxes: Vec<MailboxRef>,
    /// Push wake-up (без содержимого); только UnifiedPush по push_allowlist relay.
    pub notification_endpoint: Option<NotificationEndpoint>,
}

/// Push-уведомление для мобильных клиентов: relay шлёт пустой wake-up — без содержимого
/// и без mailbox_id; клиент просыпается и делает Retrieve по всем своим коробкам.
#[derive(Serialize, Deserialize)]
pub enum NotificationEndpoint {
    /// UnifiedPush (децентрализованный, без Google). FCM исключён: F-Droid его запрещает,
    /// а relay сообщества не может allowlist'ить Google-эндпоинты.
    UnifiedPush { url: String },
}
```

- **N-of-2:** отправитель при недоставке напрямую делает `Deposit` параллельно в первые 2 доступных хоста из
  2–3 (таймаут 10 с на каждый), успех = хотя бы один `Deposited`; получатель делает `Retrieve` со всех,
  дедуп по `envelope_id`, `Ack` на каждом по его `seq`. Цена — ×2 трафика и хранилища на конверт (учтено в
  cap 1 GB); `N ≤ 3` зашито в клиенте.
- **Push:** URL — только из `push_allowlist` relay (по умолчанию push-шлюз проекта + `ntfy.sh`), без
  редиректов и приватных диапазонов, ≤ 1/мин на коробку (§5.1.1). После M24b — `Wake` по SURB через хопы.
- **Смена хоста:** подписанный `MailboxMigration` (§11B.5.1); старые коробки живут grace period.
- Android: FGS только на время `Retrieve` (по push / onResume), не постоянно.

```rust
// aira-storage: таблица pending messages (локальная очередь, п. a)
const PENDING: TableDefinition<(/* contact_id */ &[u8], /* seq */ u64), &[u8]> =
    TableDefinition::new("pending_messages");
    // value: postcard(EncryptedEnvelope) — уже зашифровано, ждёт доставки; plaintext здесь запрещён
```
