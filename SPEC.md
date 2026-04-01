# SPEC: Aira — постквантовый P2P мессенджер на Rust

> Техническое задание для агента Claude Code.\
> Версия: 0.2 | Дата: апрель 2026 | Обновлено после исследования PQ/P2P ландшафта

---

## 1. Контекст и цели

Проект создаётся с нуля как замена Tox-подобных мессенджеров. Совместимость
с существующей Tox-сетью **не требуется** — это осознанное архитектурное
решение, позволяющее избавиться от legacy-ограничений 2013 года.

### Цели

- **Memory safety** — 100% safe Rust, `unsafe` только в явно аргументированных
  местах с `// SAFETY:` комментарием
- **Post-quantum security** — устойчивость к атакам квантового компьютера,
  защита от "harvest now, decrypt later"
- **Decentralization** — нет центрального сервера, нет доверенной третьей
  стороны
- **Simplicity** — только чат + передача файлов, никакого голоса/видео

### Не входит в scope v0.1

- Голосовые/видеозвонки
- Групповые чаты (v0.2, см. п. 12)
- Мультидевайс (v0.3, см. п. 14)
- GUI (CLI-first, egui потом, см. п. 15)

---

## 2. Структура репозитория

Полная структура репозитория — см. п. 15.6.

---

## 3. Архитектура по слоям

```
┌─────────────────────────────────────────────────┐
│  CLI / Future GUI                               │  aira-cli
├─────────────────────────────────────────────────┤
│  Application Layer                              │
│  • Contacts (add/remove/block)                  │  aira-core
│  • Message history                              │
│  • File transfer API                            │
├─────────────────────────────────────────────────┤
│  Messaging Layer                                │
│  • Triple Ratchet / SPQR (PQ forward secrecy)   │  aira-core
│  • Message framing, ordering & padding          │
│  • File chunking & reassembly                   │
├─────────────────────────────────────────────────┤
│  Session Layer                                  │
│  • PQ Handshake (PQXDH)                        │  aira-core
│  • Hybrid KEM: X25519 + ML-KEM-768             │
│  • Identity: ML-DSA-65                          │
├─────────────────────────────────────────────────┤
│  Transport Layer                                │
│  • iroh 0.97+ (QUIC/noq + NAT traversal)       │  aira-net
│  • Peer discovery (iroh + DHT)                  │
│  • Relay store-and-forward (pairwise mailboxes) │
├─────────────────────────────────────────────────┤
│  Obfuscation Layer (pluggable, п. 11A)          │  aira-net
│  • direct / obfs4 / mimicry / REALITY / Tor     │
└─────────────────────────────────────────────────┘
```

---

## 4. Криптографическая схема

### 4.1 Идентичность пользователя

Каждый пользователь имеет **Identity Keypair**:

- Алгоритм: **ML-DSA-65** (FIPS 204, Dilithium)
- Публичный ключ = адрес пользователя (как в Tox)
- Отображается пользователю как hex-строка или QR-код
- Ключи выводятся детерминистично из **seed-фразы** (см. п. 4.8)
- Крейт: `ml-dsa` из RustCrypto

```rust
// aira-core/src/identity.rs
pub struct Identity {
    pub verifying_key: ml_dsa::VerifyingKey<ml_dsa::MlDsa65>,
    signing_key: zeroize::Zeroizing<ml_dsa::SigningKey<ml_dsa::MlDsa65>>,
    /// Master seed для деривации всех ключей (зашифрован в storage)
    master_seed: zeroize::Zeroizing<[u8; 32]>,
}
```

### 4.2 Key Agreement (сессионные ключи)

Используется **гибридный KEM** для защиты от "harvest now, decrypt later":

```
SharedSecret = BLAKE3(X25519_secret || MLKEM768_secret || context)
```

- **X25519** — классический ECDH (защита от атак сегодня)
- **ML-KEM-768** — постквантовый KEM (защита от квантового компьютера)
- Оба должны быть скомпрометированы одновременно, чтобы атака удалась
- Крейт: `ml-kem` из RustCrypto, `x25519-dalek`

### 4.3 Симметричное шифрование

- **ChaCha20-Poly1305** (256-бит ключ, квантово-устойчив)
- Крейт: `chacha20poly1305` из RustCrypto

### 4.4 Forward Secrecy — Triple Ratchet (SPQR)

**Triple Ratchet** по модели Signal SPQR (Sparse Post-Quantum Ratchet,
Eurocrypt 2025) — два ratchet работают параллельно:

```
┌──────────────────────────────────────────────────┐
│  Classical Double Ratchet (X25519)                │
│  • DH ratchet при каждом обмене сообщениями       │
│  • Symmetric chain ratchet для каждого сообщения  │
├──────────────────────────────────────────────────┤
│  PQ Ratchet (ML-KEM-768)                         │
│  • KEM ratchet каждые N сообщений (sparse)       │
│  • ML-KEM encapsulation/decapsulation            │
├──────────────────────────────────────────────────┤
│  Key mixing: session_key = KDF(classical ‖ pq)   │
│  Каждое сообщение защищено обоими ratchet'ами     │
└──────────────────────────────────────────────────┘
```

**Почему не просто Double Ratchet:**

- Классический DR защищает ongoing messages только X25519
- Если квантовый компьютер скомпрометирует X25519 — все сообщения
  после handshake раскрыты (PQ защита только на этапе X3DH-PQ)
- Triple Ratchet смешивает PQ + классику на каждое сообщение

**"Sparse" означает:** PQ ratchet шагает не на каждое сообщение (ML-KEM
encapsulation — ~1952 байт CT), а каждые ~50 сообщений или при смене
направления диалога. Между шагами — классический DR. Ключи смешиваются
через KDF, поэтому атакующий должен сломать оба.

**Деградация:** если один из ratchet'ов не поддерживается (старый клиент) —
сессия работает только на классическом DR. Но не может быть принудительно
понижена атакующим (SPQR property).

- Реализовать самостоятельно поверх примитивов из п. 4.2-4.3
- Reference: Signal SPQR paper (Eurocrypt 2025, USENIX Security 2025)

### 4.5 Handshake (PQXDH)

Адаптация Signal PQXDH — расширение X3DH с PQ KEM:

```
Alice                                    Bob
  |                                       |
  | --- [Identity_A, Ephemeral_KEM_CT] -> |
  |                                       | (Bob decapsulates, derives root key)
  | <- [Identity_B, Ephemeral_KEM_CT] -- |
  |                                       |
  | ---- [Encrypted: "Hello"] ----------> |
  |       (Triple Ratchet activated)      |
```

### 4.6 Хэширование и KDF

- **BLAKE3** для всего (быстрее SHA-3, не уязвим к length extension)
- Крейт: `blake3`

### 4.7 Ключи в памяти

- Все секретные ключи в `zeroize::Zeroizing<_>` — автоочистка при Drop
- Крейт: `zeroize`

### 4.8 Seed-фраза и детерминистичная деривация ключей

Аккаунт создаётся из **seed-фразы** (24 слова, BIP-39 wordlist). Это
единственный секрет, который пользователю нужно сохранить для полного
восстановления аккаунта на любом устройстве.

**Схема деривации:**

```
Seed Phrase (24 words, BIP-39 wordlist)
    ↓ Argon2id(phrase, salt="aira-master-v1", m=256MB, t=3, p=4)
Master Seed (32 bytes)
    ↓ BLAKE3-KDF(context="aira/identity/0")
ML-DSA-65 Signing Key (identity)
    ↓ BLAKE3-KDF(context="aira/x25519/0")
X25519 Static Key
    ↓ BLAKE3-KDF(context="aira/mlkem/0")
ML-KEM-768 Decapsulation Key
    ↓ BLAKE3-KDF(context="aira/storage/0")
Storage Encryption Key (для redb)
```

**Почему Argon2id, а не PBKDF2:**

- Seed-фраза — 24 слова из словаря 2048 — перебираема при утечке
- Argon2id — memory-hard, GPU/ASIC resistant
- 256 MB памяти при деривации = дорогой брутфорс
- Крейт: `argon2`

**Нюанс ML-DSA:** `ml-dsa` крейт генерирует ключи из 32-байтного seed
через внутренний `expandA` / `expandS`. Нужно убедиться что API принимает
внешний seed (xi-seed в FIPS 204). Если нет — использовать деривированный
seed как источник для `ChaChaRng` и передать в keygen.

**Суффикс `/0`** в контексте деривации — номер поколения ключа. Позволяет
ротацию ключей в будущем (инкремент `/1`, `/2`, ...) без смены seed-фразы.

### 4.9 Session Reset (перезапуск сессии)

**Проблема:** ratchet state может быть потерян — переустановка приложения,
восстановление из бэкапа без ratchet states, повреждение storage. Без явного
механизма сессия "зависает": стороны не могут расшифровать сообщения друг друга.

> ⚠️ Это нельзя добавить потом без breaking change в протоколе.
> Опыт Matrix и Wire: отсутствие session reset → накапливающиеся
> "undecryptable" сообщения, которые пользователи не могут исправить.

**Решение — `SessionReset` как специальный PlainPayload:**

```rust
pub enum PlainPayload {
    // ... остальные варианты
    /// Запрос на полный сброс и перезапуск сессии через PQXDH
    SessionReset {
        /// Причина сброса (для отображения пользователю)
        reason: SessionResetReason,
        /// Новый ephemeral ключ для нового handshake
        new_kem_pk: Vec<u8>,
    },
}

pub enum SessionResetReason {
    /// Потеря ratchet state (переустановка, восстановление)
    StateLost,
    /// Пользователь явно запросил сброс
    UserRequested,
    /// Автоматическое обнаружение рассинхронизации
    OutOfSync { last_valid_counter: u64 },
}
```

**Процесс:**

```
Alice (потеряла ratchet state)        Bob
  |                                    |
  | --- SessionReset { StateLost } --> |
  |     (зашифровано последним         |
  |      известным ключом или          |
  |      plaintext если ключей нет)    |
  |                                    | ⚠ UI: "Alice переустановила Aira.
  |                                    |    Ключи безопасности изменились."
  | <-- HandshakeInit (новый PQXDH) -- |
  | --- HandshakeAck ----------------> |
  | <---- Encrypted (новый ratchet) -- |
```

**Безопасность:**

- После reset — Safety Number меняется, пользователь видит уведомление
- Старая история остаётся (если была), но новые сообщения в новом ratchet
- Если обе стороны потеряли ключи — любая из них инициирует reset
- Автодетекция: если N подряд сообщений не расшифровываются → предложить reset

```
CLI: /reset-session <contact>
  ⚠ Это сбросит ключи шифрования с Alice.
  После сброса верифицируйте Safety Number.
  Продолжить? [y/N]
```

```rust
// aira-core/src/seed.rs

pub struct MasterSeed(zeroize::Zeroizing<[u8; 32]>);

impl MasterSeed {
    /// Создать из seed-фразы (24 слова)
    pub fn from_phrase(phrase: &str) -> Result<Self, SeedError> {
        let entropy = bip39_decode(phrase)?;
        let mut seed = [0u8; 32];
        argon2id_hash(&entropy, b"aira-master-v1", &mut seed)?;
        Ok(Self(zeroize::Zeroizing::new(seed)))
    }

    /// Сгенерировать новую seed-фразу
    pub fn generate() -> (String, Self) {
        let entropy = rand::random::<[u8; 32]>();
        let phrase = bip39_encode(&entropy);
        let seed = Self::from_phrase(&phrase).unwrap();
        (phrase, seed)
    }

    /// Деривировать ключ для конкретной цели
    pub fn derive(&self, context: &str) -> zeroize::Zeroizing<[u8; 32]> {
        let mut out = [0u8; 32];
        blake3::derive_key(context, &self.0, &mut out);
        zeroize::Zeroizing::new(out)
    }
}
```

**UX при первом запуске:**

```
> aira init

  Создать новый аккаунт или восстановить?
    [1] Новый аккаунт
    [2] Восстановить из seed-фразы

> 1

  ⚠ Запишите seed-фразу и храните в безопасном месте!
  Это единственный способ восстановить аккаунт.

  abandon ability able about above absent
  absorb abstract absurd abuse access accident
  achieve acid acoustic acquire across act
  adapt add admit adult advance advice

  Введите фразу для подтверждения: _

  ✓ Аккаунт создан
  Ваш публичный ключ: 7f3a...b2c1
```

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

**a) Прямое добавление** — пользователь вводит hex-строку ML-DSA публичного
ключа собеседника (как в Tox). Простейший и самый надёжный способ.

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
    /// Nonce для ChaCha20-Poly1305
    pub nonce: [u8; 12],
    /// Счётчик сообщения в ratchet
    pub counter: u64,
    /// Зашифрованный payload
    pub ciphertext: Vec<u8>,
}

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

```rust
// aira-storage: таблица pending messages
const PENDING: TableDefinition<(/* contact_id */ &[u8], /* seq */ u64), &[u8]> =
    TableDefinition::new("pending_messages");
    // value: postcard(EncryptedEnvelope) — уже зашифровано, ждёт доставки
```

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
    }
}
```

Правила negotiation:

- Выбирается `max(min_version_A, min_version_B)..min(max_version_A, max_version_B)`
- Если диапазон пуст — handshake отклоняется
- Фичи: пересечение (AND) битовых масок
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
pub fn safety_number(key_a: &PubKey, key_b: &PubKey) -> String {
    let sorted = if key_a < key_b {
        [key_a.as_bytes(), key_b.as_bytes()].concat()
    } else {
        [key_b.as_bytes(), key_a.as_bytes()].concat()
    };
    let hash = blake3::hash(&sorted);
    // 60 цифр, группами по 5
    format_as_digits(hash.as_bytes(), 60)
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

### 6.16 Расширяемость протокола

`PlainPayload::Unknown { type_id, data }` позволяет добавлять новые
типы сообщений без breaking change:

- Старый клиент получает `Unknown` → показывает "Обновите Aira
  чтобы увидеть это сообщение"
- `type_id` — зарезервированные диапазоны:
  - 0-999: core protocol (зарезервировано)
  - 1000-9999: official extensions
  - 10000+: community extensions
- `data` — произвольные байты, интерпретация зависит от `type_id`
- Capability negotiation (п. 6.4) сообщает какие type_id поддерживаются

### 6.17 Профили пользователей (v0.1)

Каждый пользователь имеет публичный профиль, подписанный ML-DSA:

```rust
#[derive(Serialize, Deserialize)]
pub struct UserProfile {
    /// Отображаемое имя (≤ 64 символов)
    pub display_name: Option<String>,
    /// Аватар (JPEG, ≤ 32 KB, max 256x256)
    pub avatar: Option<Vec<u8>>,
    /// Текстовый статус (≤ 140 символов)
    pub status: Option<String>,
    /// Версия профиля (инкрементируется при обновлении)
    pub version: u32,
    /// Подпись всех полей ML-DSA ключом
    pub signature: Vec<u8>,
}
```

- Профиль передаётся при handshake и Contact Request
- Обновления профиля — подписанное сообщение контактам
- Контакт может переопределить display_name локальным alias'ом
- Аватар хранится локально у контакта, не на relay
- В группах: отображается display_name из профиля

### 6.18 Удаление аккаунта / отзыв ключа

Механизм безвозвратного уничтожения identity:

```
/delete-account

  ⚠ Это действие НЕОБРАТИМО!
  Все контакты будут уведомлены. Ваш ключ будет отозван.
  Введите "DELETE" для подтверждения: _

Процесс:
  1. Публикация KeyRevocation записи в DHT
     (подписана ML-DSA — доказывает что владелец ключа сам отозвал)
  2. Отправка RevocationNotice всем контактам
  3. Удаление всех ratchet states
  4. Zeroize master_seed и всех ключей в памяти
  5. Уничтожение локальной базы данных (перезапись random bytes)
  6. Удаление конфигурации
```

```rust
#[derive(Serialize, Deserialize)]
pub struct KeyRevocation {
    pub pubkey: PubKey,
    pub reason: RevocationReason,
    pub revoked_at: u64,
    /// Подпись отзываемым ключом (proof of ownership)
    pub signature: Vec<u8>,
}

pub enum RevocationReason {
    /// Пользователь удалил аккаунт
    AccountDeleted,
    /// Ключ скомпрометирован
    KeyCompromised,
    /// Ротация на новый ключ
    KeyRotated { new_pubkey: PubKey },
}
```

- KeyRevocation публикуется в DHT и хранится 90 дней
- Ноды при обнаружении RevocationReason::KeyCompromised —
  автоматически блокируют старый ключ
- KeyRotated — контакты могут автоматически обновить ключ
  (если новый ключ деривирован из того же seed, п. 4.8)

### 6.19 Block на уровне протокола

Поведение при блокировке контакта:

```
/block <contact>

Что происходит:
  1. Все пакеты от заблокированного — silent drop
     (атакующий НЕ знает что заблокирован — privacy)
  2. Соединение не закрывается явно (чтобы не сигнализировать блок)
  3. Pending messages от заблокированного — удаляются
  4. DHT запросы от заблокированного pubkey — игнорируются
  5. Contact Request от заблокированного — отбрасываются без PoW проверки
  6. В группах: сообщения от заблокированного — не отображаются
     (client-side ignore, группа не знает о блокировке)
```

- Block list хранится локально (не публикуется)
- Список блокировок включается в export/import бэкапа
- `/unblock <contact>` — снимает блокировку

### 6.20 Deniability (отрицаемость)

Криптографическое свойство: **невозможно доказать третьей стороне что
конкретный человек написал конкретное сообщение.**

Triple Ratchet (SPQR) обеспечивает deniability через:

- **Симметричные MAC ключи:** обе стороны могут создать идентичный MAC.
  Любая из сторон могла написать сообщение.
- **Нет цифровой подписи на сообщениях:** ML-DSA используется только
  для identity (handshake), не для подписи каждого сообщения
- **Ephemeral keys:** DH ratchet ключи уничтожаются после использования

**Следствие:** скриншот чата не является криптографическим доказательством.
Алиса может показать чат Бобу, но не может доказать суду что это Боб
написал конкретные слова — Алиса могла создать тот же MAC сама.

> ⚠️ Deniability работает на криптографическом уровне. На уровне устройства
> (скриншоты, физический доступ) — нет. Forward-secure deletion (п. 6.7)
> помогает, но не гарантирует.

### 6.21 Дедупликация сообщений

При network retry или двойной доставке через relay одно сообщение может
прийти дважды. Без явной дедупликации пользователь увидит дубликаты.

```rust
// aira-storage: окно дедупликации (24 часа)
const SEEN_IDS: TableDefinition<&[u8], u64> =
    TableDefinition::new("seen_message_ids");
    // key: message_id ([u8; 16])
    // value: timestamp_secs — для GC

// aira-daemon: при получении каждого EncryptedEnvelope
fn handle_message(envelope: EncryptedEnvelope, payload: MessageMeta) -> Result<()> {
    let id = &payload.id;
    let db = storage.begin_write()?;
    if db.open_table(SEEN_IDS)?.get(id.as_slice())?.is_some() {
        return Ok(()); // silent drop — дубликат
    }
    db.open_table(SEEN_IDS)?.insert(id.as_slice(), timestamp_secs())?;
    // ... обработка нового сообщения
}
```

- Окно: 24 часа (сообщения старше 24 ч принимаются без dedup — слишком старые)
- GC: daemon удаляет записи из `seen_message_ids` старше 24 ч при каждом запуске
- Размер окна при 1000 сообщений/день: ~16 KB (16 байт × 1000)
- `SessionReset` (п. 4.9) сбрасывает окно для данного контакта

### 6.22 Лимиты размеров и инвариант relay

**Ключевой инвариант:**

> Relay НИКОГДА не хранит содержимое файлов — только зашифрованные сообщения.
> Файловая передача (iroh-blobs) требует оба пира онлайн.

Когда Alice отправляет файл 2GB офлайн-Bob:

1. Relay получает `FileStart { hash, size, name }` — зашифрованный пакет ~200 байт
2. Bob приходит онлайн, видит уведомление о файле
3. Скачивание — прямое iroh-blobs соединение к Alice
4. Alice офлайн → файл недоступен до её появления

**Явные лимиты (DoS protection):**

| Объект                         | Лимит  | Где проверяется          |
| ------------------------------ | ------ | ------------------------ |
| `EncryptedEnvelope.ciphertext` | 64 KB  | Relay и получатель       |
| Inline thumbnail (Media/Link)  | 10 KB  | Отправитель + получатель |
| Файл через iroh-blobs          | 4 GB   | iroh-blobs уровень       |
| ContactRequest message         | 256 B  | Уже в п. 13.2            |
| Display name / статус          | 64/140 | Уже в п. 6.17            |

**Relay:**

- Один deposited пакет: max **64 KB** — всё больше отклоняется с ошибкой
- Mailbox cap: 10 MB / 100 сообщений (уже в п. 11B.5)

> Без явного лимита relay можно положить произвольно большой `EncryptedEnvelope`,
> полностью заняв хранилище. 64 KB — потолок на текстовые сообщения с thumbnail.

---

## 7. Хранилище (aira-storage)

База данных: **redb** (pure Rust, embedded, без unsafe в публичном API)

```rust
// Таблицы
const CONTACTS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("contacts");
    // key: ML-DSA pubkey bytes
    // value: postcard(ContactInfo)

const MESSAGES: TableDefinition<(u64, u64), &[u8]> =
    TableDefinition::new("messages");
    // key: (contact_id, timestamp_micros)
    // value: postcard(StoredMessage)

const SESSIONS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("sessions");
    // key: contact pubkey
    // value: postcard(RatchetState) — зашифровано master key

const SETTINGS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("settings");
```

### 7.1 Защита базы данных

- База данных зашифрована storage key
- Storage key = `BLAKE3-KDF(master_seed, "aira/storage/0")` — деривируется
  из seed-фразы (см. п. 4.8)
- Storage key кэшируется в памяти daemon'а (zeroized при shutdown)
- Опционально: storage key хранится в OS keychain (keyring крейт),
  чтобы не вводить seed-фразу при каждом запуске

---

## 8. Daemon и IPC

**aira-daemon** работает как фоновый процесс, **aira-cli** — тонкий
клиент, общающийся с daemon через Unix socket / Named pipe (Windows).

```
aira-daemon (сетевой стек, крипто, storage)
      ↕  IPC (postcard over Unix socket)
aira-cli    aira-gui (future)
```

IPC API — простой request/response + event stream:

```rust
pub enum DaemonRequest {
    SendMessage { to: PubKey, text: String },
    SendFile { to: PubKey, path: PathBuf },
    GetHistory { contact: PubKey, limit: u32 },
    AddContact { pubkey: PubKey, alias: String },
    GetMyAddress,
    // ...
}

pub enum DaemonEvent {
    MessageReceived { from: PubKey, payload: PlainPayload },
    FileProgress { id: [u8; 16], bytes_received: u64 },
    ContactOnline(PubKey),
    ContactOffline(PubKey),
}
```

---

## 9. CLI (aira-cli)

TUI на **ratatui**. Минимальный UX:

```
┌─ aira ─────────────────────────────────────────────────────┐
│ Contacts          │ Alice [online]                            │
│ > Alice ●         │                                           │
│   Bob             │  [10:42] Alice: привет!                   │
│   Carol           │  [10:43] You: привет                      │
│                   │  [10:43] Alice: как дела?                 │
│                   │                                           │
│                   │ > _                                        │
│ [A]dd [D]el [Q]uit│ /file /clear /info                        │
└───────────────────┴───────────────────────────────────────────┘
```

Команды:

- `/add <pubkey>` — добавить контакт
- `/file <path>` — отправить файл
- `/me <action>` — действие от третьего лица (`* Alice делает что-то`)
- `/mykey` — показать свой публичный ключ (для sharing)
- `/verify <contact>` — показать Safety Number для верификации ключей
- `/disappear <time>` — включить автоудаление (30s/5m/1h/1d/7d/off)
- `/export [path]` — экспорт зашифрованного бэкапа
- `/import <path>` — импорт бэкапа (запросит seed-фразу)
- `/transport <mode>` — режим транспорта (direct/obfs4/mimicry/reality/tor)
- `/mute <contact> [duration]` — заглушить контакт
- `/block <contact>` — заблокировать контакт (silent drop, п. 6.19)
- `/unblock <contact>` — разблокировать контакт
- `/profile [name|avatar|status]` — редактировать свой профиль (п. 6.17)
- `/delete-account` — безвозвратное удаление аккаунта (п. 6.18)
- `/info` — версия, статус сети, relay, capabilities
- `/lang <code>` — сменить язык интерфейса (en/ru/es/zh/ar/...)

### 9.1 Мультиязычность (i18n)

Все строки интерфейса (CLI, GUI, мобильные клиенты) локализуемы.

**Подход: Fluent (Mozilla Project)**

```
# locales/en/main.ftl
contacts-title = Contacts
message-placeholder = Type a message...
status-online = online
status-offline = offline
add-contact = Add contact
verify-prompt = Compare this Safety Number with { $contact }:
disappearing-set = Messages will disappear after { $time }
seed-warning = Write down your seed phrase and keep it safe!
file-transfer = Sending { $filename } ({ $size })...
```

```
# locales/ru/main.ftl
contacts-title = Контакты
message-placeholder = Введите сообщение...
status-online = в сети
status-offline = не в сети
add-contact = Добавить контакт
verify-prompt = Сравните Safety Number с { $contact }:
disappearing-set = Сообщения удалятся через { $time }
seed-warning = Запишите seed-фразу и храните в безопасном месте!
file-transfer = Отправка { $filename } ({ $size })...
```

**Почему Fluent, а не gettext/i18n-embed:**

- Создан Mozilla для Firefox — battle-tested
- Поддерживает плюрализацию, пол, числовые форматы из коробки
- Крейт `fluent-rs` — pure Rust, no_std-совместимый
- `.ftl` файлы легко переводить (человекочитаемый формат)
- Используется в Firefox, Thunderbird, и Servo

**Реализация:**

```rust
// aira-core/src/i18n.rs

use fluent::{FluentBundle, FluentResource};
use unic_langid::LanguageIdentifier;

pub struct I18n {
    bundle: FluentBundle<FluentResource>,
    locale: LanguageIdentifier,
}

impl I18n {
    pub fn new(locale: &str) -> Self {
        let lang: LanguageIdentifier = locale.parse().unwrap_or("en".parse().unwrap());
        let ftl = load_ftl(&lang); // из embedded ресурсов или файловой системы
        let resource = FluentResource::try_new(ftl).expect("valid FTL");
        let mut bundle = FluentBundle::new(vec![lang.clone()]);
        bundle.add_resource(resource).expect("no conflicts");
        Self { bundle, locale: lang }
    }

    pub fn t(&self, id: &str) -> String {
        let msg = self.bundle.get_message(id).expect("message exists");
        let pattern = msg.value().expect("has value");
        self.bundle.format_pattern(pattern, None, &mut vec![]).to_string()
    }
}
```

**Языки v0.1:** English (en), Русский (ru)
**Языки v0.2:** + Español (es), 中文 (zh), العربية (ar), Deutsch (de),
Français (fr), 日本語 (ja), Português (pt), हिन्दी (hi)

**Seed-фраза:** BIP-39 wordlist существует на ~10 языках. Пользователь
выбирает язык seed-фразы при генерации. Внутренне хранится как entropy,
отображение зависит от выбранного языка wordlist.

**Определение языка:**

1. Явная настройка (`/lang ru` или config)
2. Переменная окружения `LANG` / `LC_MESSAGES`
3. OS locale (Android: `Locale.getDefault()`, iOS: `Locale.preferredLanguages`)
4. Fallback: English

---

## 10. Зависимости (Cargo.toml workspace)

```toml
[workspace.dependencies]
# Async runtime
tokio = { version = "1", features = ["full"] }

# Networking (iroh ~1.0, вышел из RC-серии 0.97+)
iroh = "0.97"             # QUIC (noq) + NAT traversal + relay
iroh-blobs = "0.99"       # BLAKE3 content-addressed file transfer

# Post-quantum crypto — см. п. 10.1 «Стратегия крипто-бэкендов»
# Фаза 1 (разработка): RustCrypto — pure Rust, быстрая итерация
ml-kem = "0.2"            # FIPS 203 — ML-KEM-768 (stable)
ml-dsa = "0.0.4"          # FIPS 204 — ML-DSA-65 (⚠️ ранняя версия)
# Фаза 2 (production): aws-lc-rs — FIPS 140-3 валидированный
# aws-lc-rs = "1.16"      # ML-KEM + ML-DSA + seed-based keygen

# Классический компонент гибридного KEM
x25519-dalek = { version = "2", features = ["static_secrets"] }

# Симметрика
chacha20poly1305 = "0.10"

# Хэширование и KDF
blake3 = "1"

# Seed phrase & KDF
argon2 = "0.5"              # memory-hard KDF для seed-фразы

# Zeroization
zeroize = { version = "1", features = ["derive"] }

# Сериализация
serde = { version = "1", features = ["derive"] }
postcard = { version = "1", features = ["alloc"] }

# База данных
redb = "2"

# TUI
ratatui = "0.29"
crossterm = "0.28"

# i18n (Mozilla Fluent)
fluent = "0.16"
fluent-bundle = "0.15"
unic-langid = "0.9"
rust-embed = "8"            # встраивание .ftl файлов в бинарник

# Rate limiting & DoS protection
governor = "0.8"            # GCRA rate limiter (keyed, atomic)

# Pluggable transports / DPI resistance
ptrs = "0.8"                # obfs4/o5 (pure Rust PT framework)
# arti-client = "0.27"     # Tor (feature = "tor")
# hysteria2 = "0.1"        # Hysteria 2 (feature = "hysteria")

# Ошибки
thiserror = "2"
anyhow = "1"

# Логирование
tracing = "0.1"
tracing-subscriber = "0.3"

# GUI (desktop)
eframe = "0.29"
egui = "0.29"

# Кроссплатформенные утилиты
notify-rust = "4"         # OS уведомления (Linux/macOS/Windows)
keyring = "3"             # OS keychain
tray-icon = "0.19"        # системный трей
uniffi = "0.28"           # FFI биндинги (Android/iOS)
```

### 10.1 Стратегия крипто-бэкендов

> ⚠️ **На апрель 2026 ни один pure-Rust PQ крейт не прошёл независимый
> security audit.** ml-dsa (0.0.4) имел уязвимость GHSA-5x2r-hc65-25f9
> (неправильная верификация подписей). ml-kem (0.2.3) стабильнее, но
> тоже без аудита.

**Фаза 1 — Разработка и тестирование (v0.1-v0.2):**

- RustCrypto `ml-kem` + `ml-dsa` — pure Rust, простая компиляция,
  быстрая итерация, WASM-совместимость
- Абстрагировать крипто через trait'ы (`CryptoProvider`), чтобы
  бэкенд можно было заменить без переписывания логики

**Фаза 2 — Production (v0.3+):**

- `aws-lc-rs` — единственная FIPS 140-3 валидированная библиотека
  с ML-KEM + ML-DSA. Поддерживает `PqdsaKeyPair::from_seed()`
- Минус: не pure Rust (C-обёртка aws-lc), требует cmake
- Плюс: production-hardened, используется AWS (KMS, S3, CloudFront)

**Альтернатива для high-assurance:**

- `libcrux` (Cryspen) — формально верифицирован через hax + F*,
  но все крейты < 0.1 (pre-release)

```rust
// aira-core/src/crypto/mod.rs — абстракция крипто-бэкенда

pub trait CryptoProvider {
    type SigningKey;
    type VerifyingKey;
    type KemDecapsKey;
    type KemEncapsKey;

    fn keygen_from_seed(seed: &[u8; 32]) -> (Self::SigningKey, Self::VerifyingKey);
    fn sign(key: &Self::SigningKey, msg: &[u8]) -> Vec<u8>;
    fn verify(key: &Self::VerifyingKey, msg: &[u8], sig: &[u8]) -> bool;
    fn kem_encaps(pk: &Self::KemEncapsKey) -> (Vec<u8>, [u8; 32]);
    fn kem_decaps(sk: &Self::KemDecapsKey, ct: &[u8]) -> [u8; 32];
}

// Реализации:
pub mod rustcrypto;  // ml-kem + ml-dsa (фаза 1)
// pub mod awslc;    // aws-lc-rs (фаза 2)
```

---

## 11. Модель угроз

Файл `docs/THREAT_MODEL.md` должен покрывать:

| Угроза                                                     | Митигация                                           |
| ---------------------------------------------------------- | --------------------------------------------------- |
| Пассивное прослушивание трафика сейчас                     | QUIC TLS 1.3 + ChaCha20-Poly1305                    |
| Quantum adversary (сбор трафика сейчас, расшифровка потом) | ML-KEM-768 гибридный KEM                            |
| Подделка идентичности                                      | ML-DSA-65 подпись, TOFU model                       |
| Компрометация одного сообщения                             | Triple Ratchet (SPQR) forward secrecy               |
| PQ атака на ongoing messages (не только handshake)         | SPQR: PQ ratchet каждые ~50 сообщений               |
| Memory safety exploits                                     | Safe Rust, zeroize                                  |
| Metadata (кто с кем общается)                              | Pairwise relay mailboxes, padding                   |
| Traffic analysis (длина сообщений)                         | Padding до фиксированных блоков 256-4096 байт       |
| MITM при первом соединении                                 | Safety Numbers, TOFU + out-of-band верификация      |
| Атака на bootstrap ноды                                    | Signed peer records, TOFU для контактов             |
| Спам / массовые Contact Request                            | PoW (20 бит), rate limiting, block list             |
| Flood в групповых чатах                                    | Rate limit 30 msg/min, admin-only invites           |
| DPI / блокировка протокола                                 | Pluggable transports, protocol mimicry (п. 11A)     |
| Активное зондирование (active probing)                     | REALITY-like: fallback на легитимный сайт           |
| DDoS / connection exhaustion                               | Connection tiers, puzzles, rate limiting (п.11B)    |
| CPU exhaustion через крипто                                | Adaptive puzzles перед PQ handshake                 |
| DHT poisoning / Sybil                                      | IP diversity, signed records, PoW (п. 11B.4)        |
| Relay flooding                                             | Per-identity квоты, ring buffer, PoW (п. 11B.5)     |
| Amplification attack                                       | QUIC 3x limit, authenticated deposits               |
| Eclipse attack (изоляция ноды)                             | Subnet diversity, anchor connections (п. 11B.7)     |
| Доказательство авторства сообщения третьей стороне         | Deniability: симметричные MAC, нет подписей (6.20)  |
| Скомпрометированный ключ                                   | Key revocation + DHT, уведомление контактов (6.18)  |
| Link preview утечка IP                                     | Превью генерирует отправитель, не получатель (6.12) |
| Typing indicator как метаданные активности                 | Opt-out per-contact, rate limit (п. 6.15)           |

Вне scope v0.1: полная анонимность на уровне сети (onion routing).

---

## 11A. Защита от DPI и цензуры

### 11A.1 Модель угрозы

DPI-системы (ТСПУ в РФ, GFW в Китае, NessFW в Иране) анализируют трафик
на нескольких уровнях:

| Уровень        | Что видит DPI                   | Как блокирует                              |
| -------------- | ------------------------------- | ------------------------------------------ |
| IP/Port        | Destination IP + порт           | Блокировка IP, портов                      |
| Протокол       | QUIC headers, SNI в TLS         | Блокировка по сигнатуре протокола          |
| Статистика     | Размер/время пакетов            | ML-классификация (CNN/LSTM)                |
| Active probing | Ответы на нестандартные запросы | Подключается к серверу, проверяет протокол |

### 11A.2 Архитектура: Pluggable Transport Stack

Вдохновлено ptrs (Rust PT framework) и AmneziaWG 2.0. Каждый слой
независимо конфигурируем:

```
┌──────────────────────────────────────────────────┐
│  aira-core: зашифрованные сообщения (ChaCha20)   │
├──────────────────────────────────────────────────┤
│  Padding Layer: все пакеты → фиксированный размер│
│  (16 KB, как SimpleX Chat)                       │
├──────────────────────────────────────────────────┤
│  Obfuscation Layer (pluggable):                  │
│  • none      — прямой QUIC (без цензуры)         │
│  • obfs4/o5  — рандомизация (ptrs крейт)         │
│  • mimicry   — мимикрия под DNS/QUIC/SIP         │
│  • reality   — мимикрия под TLS к реальному сайту│
│  • hysteria2 — маскировка под HTTP/3             │
├──────────────────────────────────────────────────┤
│  Transport Layer (pluggable):                    │
│  • direct    — прямое UDP соединение             │
│  • relay     — через iroh relay (WebSocket/TLS)  │
│  • cdn       — через Cloudflare Worker / CDN     │
│  • tor       — через Tor (arti)                  │
│  • snowflake — через ephemeral WebRTC peers      │
└──────────────────────────────────────────────────┘
```

### 11A.3 Режимы для разных уровней цензуры

**Режим 1 — Без цензуры (по умолчанию):**

- Прямой QUIC, message padding
- Минимальный overhead

**Режим 2 — Умеренная цензура (Россия, Турция):**

- obfs4/o5 обфускация через ptrs
- CDN relay (Cloudflare Worker) как fallback
- iroh relay через WebSocket+TLS (выглядит как обычный HTTPS)

**Режим 3 — Тяжёлая цензура (Китай, Иран):**

- REALITY-like мимикрия: соединение выглядит как TLS к apple.com/bing.com
- Провал аутентификации → трафик проксируется к реальному сайту
  (active probing не обнаружит протокол)
- Или: Tor через Snowflake/WebTunnel
- Или: Protocol mimicry в стиле AmneziaWG CPS (Custom Protocol Signature)

### 11A.4 Protocol Mimicry (вдохновлено AmneziaWG 2.0)

CPS (Custom Protocol Signature) — система мимикрии пакетов под
легитимные протоколы. Каждый пакет получает заголовок, неотличимый
для DPI от целевого протокола:

```rust
// aira-net/src/transport/mimicry.rs

pub enum MimicryProfile {
    /// Без мимикрии — стандартный QUIC
    None,
    /// Пакеты выглядят как DNS запросы/ответы
    Dns,
    /// Пакеты выглядят как QUIC/HTTP/3 к легитимному серверу
    Quic { sni: String },
    /// Пакеты выглядят как SIP (VoIP звонки)
    Sip,
    /// Пакеты выглядят как STUN (WebRTC NAT traversal)
    Stun,
    /// Кастомная сигнатура (CPS формат)
    Custom(CpsSignature),
}

/// CPS — Custom Protocol Signature (как в AmneziaWG 2.0)
pub struct CpsSignature {
    /// Шаблон: <b 0xHEX> <t> <r N> <rc N> <rd N>
    pub template: Vec<CpsToken>,
    /// Допустимый диапазон размеров пакетов
    pub size_range: (usize, usize),
}

pub enum CpsToken {
    /// Фиксированные байты (magic number протокола)
    Bytes(Vec<u8>),
    /// Текущий timestamp (4 bytes)
    Timestamp,
    /// N случайных байтов
    Random(usize),
    /// N случайных ASCII alphanumeric
    RandomAlphaNum(usize),
    /// N случайных цифр
    RandomDigits(usize),
}
```

**Как работает:**

1. Исходящий пакет оборачивается в CPS-заголовок перед отправкой
2. DPI видит пакет, соответствующий сигнатуре DNS/QUIC/SIP
3. Принимающая сторона снимает CPS-заголовок и обрабатывает QUIC пакет
4. Параметры CPS синхронизируются при handshake

### 11A.5 REALITY-like Transport (защита от active probing)

Самый эффективный метод против GFW-уровня DPI:

```
Клиент                     Сервер Aira                   Реальный сайт
  |                           |                              |
  |--- TLS ClientHello ------>| (SNI: apple.com)             |
  |   (выглядит как Chrome)   |                              |
  |                           |-- Проверка: наш клиент? --   |
  |                           |   ДА: aira handshake         |
  |<-- aira session --------->|                              |
  |                           |                              |
  |   НЕТ (active probe):    |                              |
  |                           |--- Прокси к apple.com ------>|
  |<-- apple.com response ----|<-- Реальный ответ -----------|
  |   (DPI видит легитимный   |                              |
  |    apple.com трафик)      |                              |
```

- Используется uTLS для мимикрии TLS fingerprint браузера
  (Chrome, Firefox, Safari, random)
- Не нужен собственный домен или TLS сертификат
- X25519 pre-shared key для идентификации клиента
- Реализация потребует порта из Xray REALITY (Go → Rust)

### 11A.6 Интеграция с iroh

iroh поддерживает `CustomTransport` trait — произвольная обёртка
над async streams. Интеграция:

```rust
// aira-net/src/transport/mod.rs

pub trait AiraTransport: Send + Sync {
    /// Оборачивает исходящее соединение в выбранный транспорт
    async fn wrap_outbound(
        &self,
        stream: impl AsyncRead + AsyncWrite + Send,
        target: &NodeId,
    ) -> Result<impl AsyncRead + AsyncWrite + Send>;

    /// Принимает входящее соединение
    async fn accept_inbound(
        &self,
        stream: impl AsyncRead + AsyncWrite + Send,
    ) -> Result<impl AsyncRead + AsyncWrite + Send>;
}

// Реализации:
pub struct DirectTransport;       // без обфускации
pub struct Obfs4Transport;        // ptrs obfs4/o5
pub struct MimicryTransport;      // CPS protocol mimicry
pub struct RealityTransport;      // REALITY-like TLS camouflage
pub struct TorTransport;          // через arti
pub struct CdnRelayTransport;     // через Cloudflare Worker
```

### 11A.7 Зависимости

```toml
# Pluggable transports
ptrs = "0.8"              # obfs4/o5 (pure Rust PT framework)

# Опциональные (feature flags):
# arti-client = "0.27"   # Tor transport (feature = "tor")
# hysteria2 = "0.1"      # Hysteria 2 QUIC masquerade (feature = "hysteria")
```

### 11A.8 UX

```
> aira config transport

  Режим транспорта:
    [1] Прямой (без обфускации) — лучшая скорость
    [2] Обфускация (obfs4) — умеренная цензура
    [3] Мимикрия (QUIC/DNS/SIP) — продвинутая цензура
    [4] REALITY — максимальная защита от DPI
    [5] Tor — максимальная анонимность

> 3

  Мимикрия под:
    [1] DNS запросы
    [2] QUIC/HTTP/3
    [3] SIP (VoIP)
    [4] STUN (WebRTC)

> 2
  ✓ Транспорт: мимикрия под QUIC/HTTP/3
  Для собеседника настройка применится автоматически.
```

CLI команда: `/transport <mode>` — переключение режима

---

## 11B. Защита от DDoS и флуда

В P2P мессенджере каждая нода — и клиент, и сервер. Нет центральной
инфраструктуры для поглощения DDoS. Защита строится на трёх принципах:
**приоритизация контактов**, **adaptive cost** и **graceful degradation**.

### 11B.1 Connection Tiers — приоритизация соединений

Все входящие соединения делятся на 3 уровня:

```
Tier 1 — Verified contacts (в контакт-листе)
  → Без ограничений, максимальный приоритет
  → Никогда не дропаются при перегрузке

Tier 2 — Known peers (были handshake, не в контактах)
  → Rate limit: 100 msg/min, 10 connections
  → Дропаются при перегрузке после Tier 3

Tier 3 — Strangers (неизвестные ноды)
  → Rate limit: 5 msg/min, 2 connections
  → PoW обязателен для любого взаимодействия
  → Первыми дропаются при перегрузке
```

```rust
// aira-net/src/ratelimit.rs

use governor::{Quota, RateLimiter};
use std::num::NonZeroU32;

pub struct PeerLimits {
    pub contacts: Quota,     // unlimited (u32::MAX / sec)
    pub known: Quota,        // 100/min
    pub strangers: Quota,    // 5/min
}

impl Default for PeerLimits {
    fn default() -> Self {
        Self {
            contacts: Quota::per_second(NonZeroU32::MAX),
            known: Quota::per_minute(NonZeroU32::new(100).unwrap()),
            strangers: Quota::per_minute(NonZeroU32::new(5).unwrap()),
        }
    }
}
```

### 11B.2 Adaptive Client Puzzles

Перед PQ handshake незнакомая нода должна решить puzzle. Сложность
адаптируется к текущей нагрузке:

```
Нагрузка < 50%:  puzzle 16 бит (~1 ms)
Нагрузка 50-80%: puzzle 20 бит (~16 ms)
Нагрузка 80-95%: puzzle 24 бит (~256 ms)
Нагрузка > 95%:  puzzle 28 бит (~4 сек) + отклонение Tier 3
```

```rust
pub struct AdaptivePuzzle {
    /// Текущая сложность (ведущие нули в BLAKE3 хэше)
    pub difficulty: u8,
    /// Серверный nonce (предотвращает precomputation)
    pub server_nonce: [u8; 16],
    /// Timestamp (puzzle истекает через 30 секунд)
    pub issued_at: u64,
}

impl AdaptivePuzzle {
    pub fn verify(&self, client_nonce: u64) -> bool {
        let now = timestamp_secs();
        if now - self.issued_at > 30 { return false; } // expired
        let hash = blake3::hash(&[
            &self.server_nonce[..],
            &client_nonce.to_le_bytes(),
        ].concat());
        leading_zeros(hash.as_bytes()) >= self.difficulty as u32
    }
}
```

**Почему это работает:** легитимный пользователь решает puzzle один раз
при добавлении контакта. Атакующий должен решать для каждого соединения,
и стоимость растёт экспоненциально при увеличении нагрузки.

**PQ crypto НЕ является DoS вектором:** ML-KEM decapsulation ~0.05ms
(быстрее RSA в 14x), ML-DSA verify — ~0.3ms. Puzzle перед handshake
стоит дороже самой криптографии.

### 11B.3 QUIC-level защита

iroh/QUIC предоставляет встроенные механизмы:

```rust
// aira-net/src/endpoint.rs — конфигурация QUIC

let mut transport = quinn::TransportConfig::default();
// Ограничение потоков на соединение
transport.max_concurrent_bidi_streams(16u32.into());
transport.max_concurrent_uni_streams(32u32.into());
// Ограничение буферов
transport.receive_window(256u32.into());        // 256 KB
transport.send_window(256u64.into());           // 256 KB
transport.stream_receive_window(64u32.into());  // 64 KB per stream
// Таймауты
transport.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
// Retry tokens — address validation до выделения ресурсов
transport.retry_token_lifetime(Duration::from_secs(15));
```

**Amplification limit:** QUIC ограничивает ответ до 3x размера запроса
до подтверждения адреса (Retry token). Атакующий не может использовать
ноду как усилитель.

### 11B.4 DHT anti-Sybil

DHT — наиболее уязвимый компонент к Sybil-атаке (атакующий создаёт
тысячи фейковых нод и заполняет таблицу маршрутизации):

**Митигации:**

a) **IP diversity:** максимум 2 ноды из одной /16 подсети в routing table.
Атакующий с одного диапазона IP не может занять всю таблицу.

b) **Signed DHT records:** каждая запись `ML-DSA_pubkey → NodeId` подписана
ML-DSA ключом. Фейковые записи отбрасываются при проверке подписи.

c) **PoW для DHT publish:** публикация записи в DHT требует PoW (16 бит).
Подтверждение записи другими нодами — без PoW (бесплатно).

d) **TTL + refresh:** записи истекают через 24 часа. Нода должна
переопубликовать. Устаревшие записи автоматически удаляются.

e) **Fallback на direct add:** DHT опционален. Если DHT скомпрометирован —
пользователи обмениваются ключами напрямую (hex-строка / QR).

f) **Anchor connections:** daemon поддерживает 3-5 долгоживущих соединений
с проверенными нодами (bootstrap + контакты). Это предотвращает
eclipse attack — полную изоляцию ноды фейковыми пирами.

### 11B.5 Relay anti-flood

Relay хранит зашифрованные конверты для офлайн пользователей. Защита:

```
Per-identity квоты:
  - 10 MB max на mailbox (ring buffer — старые вытесняются)
  - 100 сообщений max на mailbox
  - 30 deposits/min на отправителя
  - PoW (16 бит) на каждый deposit от не-контактов

Per-relay лимиты:
  - 1 GB total storage cap
  - GC каждые 6 часов: удаление expired (TTL 7 дней)
  - Приоритет: mailbox'ы с недавним retrieve > заброшенные
```

```rust
pub struct RelayQuota {
    pub max_mailbox_size: usize,        // 10 MB
    pub max_messages_per_mailbox: u32,  // 100
    pub deposit_rate: Quota,            // 30/min
    pub pow_difficulty: u8,             // 16 бит для не-контактов
    pub total_storage_cap: usize,       // 1 GB
    pub ttl: Duration,                  // 7 дней
}
```

### 11B.6 Flood protection в личных чатах

Даже контакт может начать спамить (compromised device, malware):

```
Per-contact rate limits (настраиваемые):
  Default:    500 msg/min (высокий лимит для нормального использования)
  Файлы:     10 file offers/min
  Typing:    60 typing events/min

Превышение → автоматический cooldown:
  1x:  предупреждение пользователю
  3x:  mute на 5 минут
  10x: автоматический mute на 1 час + уведомление

Команда: /mute <contact> [duration] — ручной mute
```

### 11B.7 Eclipse attack prevention

Eclipse attack — атакующий заполняет все соединения ноды своими
пирами, изолируя жертву от реальной сети.

**Митигации:**

a) **Subnet diversity:** максимум 2 peer из одной /16 подсети.
Одновременно: минимум 3 разных /16 в connection table.

b) **Anchor connections:** 3-5 hardcoded соединений с bootstrap нодами
и проверенными контактами. Эти соединения никогда не вытесняются.

c) **Connection table protection:** новые ноды не могут вытеснить
долгоживущие соединения. Eviction policy: приоритет по возрасту
соединения, tier, и subnet diversity.

d) **Мониторинг:** daemon логирует аномалии (резкий рост новых
соединений, потеря всех anchor'ов). Уведомление пользователю.

### 11B.8 Graceful degradation

При перегрузке нода деградирует предсказуемо:

```
Load Level  | Действие
------------|-----------------------------------------------
< 50%       | Нормальная работа
50-70%      | Увеличение puzzle difficulty для Tier 3
70-85%      | Отклонение новых Tier 3 соединений
85-95%      | Отклонение новых Tier 2 + файлы только от Tier 1
> 95%       | Только Tier 1 (контакты), все остальные — отклонение
            | + уведомление пользователю "Under attack"
```

Метрики нагрузки: CPU usage + active connections + memory + bandwidth.

### 11B.9 Зависимости

```toml
# Rate limiting
governor = "0.8"          # GCRA rate limiter (keyed, atomic)
```

---

## 12. Групповые чаты (v0.2)

### 12.1 Протокол: Sender Keys + Group Ratchet

**Почему не MLS (RFC 9420):** MLS требует Delivery Service (центральный сервер
для ordering), что противоречит P2P архитектуре. MLS также чрезмерно сложен
для небольших групп.

**Почему не простой fan-out:** fan-out (отправка каждому участнику отдельно)
не масштабируется — N участников = N шифрований на каждое сообщение.

**Выбор: Sender Keys** (как в Signal Groups):

```
Создатель группы:
  1. Генерирует GroupId = random [u8; 32]
  2. Генерирует свой Sender Key (ChaCha20 chain key)
  3. Отправляет Sender Key каждому участнику через 1-на-1 канал (E2E)

Участник при вступлении:
  1. Получает список участников + их Sender Keys (через 1-на-1)
  2. Генерирует свой Sender Key
  3. Раздаёт свой Sender Key всем участникам (через 1-на-1)

Отправка сообщения в группу:
  1. Шифрует сообщение своим Sender Key (одно шифрование!)
  2. Отправляет всем участникам (fan-out зашифрованного пакета)
  3. Ratchet Sender Key вперёд (forward secrecy)
```

### 12.2 Структуры данных

```rust
// aira-core/src/group.rs

pub struct Group {
    pub id: [u8; 32],
    pub name: String,
    pub members: Vec<GroupMember>,
    pub created_by: PubKey,
    pub created_at: u64,
}

pub struct GroupMember {
    pub pubkey: PubKey,
    pub sender_key: SenderKeyState,
    pub role: GroupRole,
    pub joined_at: u64,
}

pub enum GroupRole {
    Admin,    // может добавлять/удалять участников
    Member,   // только чтение/запись сообщений
}

pub struct SenderKeyState {
    pub chain_key: zeroize::Zeroizing<[u8; 32]>,
    pub counter: u64,
}
```

### 12.3 Ограничения v0.2

- Максимум 100 участников в группе
- Только Admin добавляет/удаляет участников
- При удалении участника — все пересоздают Sender Keys (PCS)
- Нет редактирования/удаления сообщений
- Оффлайн участник получает пропущенные сообщения через локальную очередь

### 12.4 Causal Ordering в группах

**Проблема:** Alice и Bob отправляют сообщения одновременно. Carol видит их
в одном порядке, Dave — в другом. В P2P нет центрального сервера для ordering.

> Урок Matrix: без causal ordering пользователи видят бессвязные разговоры.
> Retrofitting невозможен — меняет формат каждого группового сообщения.

**Решение — DAG-lite через `parent_id`:**

```rust
// aira-core/src/group_proto.rs

pub struct GroupMessage {
    pub group_id: [u8; 32],
    pub from: PubKey,
    pub payload: PlainPayload,
    pub id: [u8; 16],
    /// ID предыдущего сообщения в группе от этого же отправителя
    /// (causal link — мой last known message)
    pub parent_id: Option<[u8; 16]>,
    pub timestamp: u64,
}
```

**Алгоритм отображения:**

```
При получении GroupMessage:
  1. Если parent_id = None → первое сообщение, добавить в конец
  2. Если parent_id известен → вставить после него
  3. Если parent_id неизвестен (пропущено) →
     a. Показать placeholder "загрузка..."
     b. Запросить пропущенное у отправителя
     c. Timeout 10 сек → показать out-of-order с маркером "⚠ порядок нарушен"
```

**Ограничения (намеренно простое решение):**

- `parent_id` — только цепочка каждого отправителя, не глобальный DAG
- Не гарантирует идентичный порядок у всех (eventual consistency)
- Достаточно для чата — строгий порядок нужен только для reply (п. 6.8)
- Строгий глобальный порядок (MLS / vector clocks) — v0.4+

### 12.5 Протокол ротации Sender Key

Раздел 12.3 упоминает PCS при удалении участника, но не специфицирует протокол.
Отсутствие явного протокола — источник несогласованности состояния группы.

**Триггеры ротации:**

- Участник добавлен → новый Sender Key от добавившего Admin
- Участник удалён → все участники генерируют новые Sender Keys (PCS)
- Участник покинул группу (`/leave`) → то же что и удаление

```rust
pub enum GroupControl {
    /// Admin добавляет участника
    AddMember {
        new_member: PubKey,
        /// Зашифрованные Sender Keys всех участников для нового
        /// member_keys[i] = encrypt(members[i].sender_key, new_member_pubkey)
        member_keys: Vec<(PubKey, Vec<u8>)>,
    },
    /// Admin удаляет участника — инициирует ротацию
    RemoveMember {
        removed: PubKey,
    },
    /// Ответ на RemoveMember — новый Sender Key от каждого участника
    SenderKeyUpdate {
        /// Новый Sender Key, зашифрованный для каждого оставшегося участника
        keys: Vec<(PubKey, Vec<u8>)>,
    },
}
```

**Протокол при удалении участника:**

```
Admin удаляет Bob (offline):
  1. Admin отправляет RemoveMember { removed: Bob } всем (включая Bob)
  2. Каждый участник генерирует новый SenderKeyState
  3. Каждый отправляет SenderKeyUpdate через 1-на-1 каналы ко всем участникам
  4. До получения SenderKeyUpdate от участника X — сообщения от X в старом ratchet

Офлайн-участник при reconnect:
  - Получает RemoveMember из pending queue
  - Генерирует новый Sender Key
  - Рассылает SenderKeyUpdate всем участникам
  - До этого момента — не может отправлять в группу, только получать

Timeout (участник не ответил N часов):
  - Daemon логирует, UI показывает "ожидание ключей от Carol..."
  - Admin может force-rotate (вычеркнуть Carol без её ключа) — данные от Carol
    до этого момента не дешифруются другими участниками (приемлемо)
```

**Инварианты безопасности:**

- Удалённый участник не получает `SenderKeyUpdate` → не может читать новые сообщения
- Новый участник не получает старые Sender Keys → не может читать историю (FS)
- Bob офлайн при удалении → получает `RemoveMember` при reconnect,
  знает что удалён, не может писать в группу

---

## 13. Защита от спама

### 13.1 Модель: contact-first

В P2P мессенджере без сервера нет централизованного модератора. Защита
строится на принципе: **нельзя отправить сообщение незнакомцу без его
согласия**.

### 13.2 Механизмы

**a) Contact Request (v0.1):**

```
Alice хочет написать Bob:
  1. Alice отправляет ContactRequest (подписанный ML-DSA):
     - свой публичный ключ
     - короткое сообщение (≤ 256 байт, plaintext)
     - Proof-of-Work (см. ниже)
  2. Bob видит запрос, решает: Accept / Reject / Block
  3. Accept → обмен handshake (п. 4.5), начало чата
  4. Reject → Alice уведомляется
  5. Block → все будущие запросы от Alice отбрасываются
```

**b) Proof-of-Work для Contact Request:**

- Для отправки запроса нужно вычислить `BLAKE3(request || nonce)` с N
  ведущими нулевыми битами
- Сложность: ~1 секунда на обычном CPU (≈20 бит)
- Предотвращает массовую рассылку запросов ботами
- Не влияет на обычных пользователей (разовая задержка)

```rust
// aira-core/src/spam.rs

pub struct ContactRequest {
    pub from: PubKey,
    pub message: String,          // ≤ 256 bytes
    pub pow_nonce: u64,
    pub pow_difficulty: u8,       // required leading zero bits
    pub signature: MlDsaSignature,
}

impl ContactRequest {
    pub fn verify_pow(&self) -> bool {
        let hash = blake3::hash(&self.to_pow_bytes());
        leading_zeros(hash.as_bytes()) >= self.pow_difficulty as u32
    }
}
```

**c) Rate limiting (v0.1):**

- Daemon отбрасывает > 10 Contact Request / минуту от разных ключей
- 3 запроса от одного ключа / час = автоматический временный бан (1 час)
- Уведомление пользователю о заблокированных запросах

**d) Репутация контактов (v0.2):**

- Контакт, добавленный вручную (по hex-ключу) = доверенный
- Контакт через Contact Request = обычный
- Заблокированный = все пакеты от него отбрасываются на уровне сети
- "Friend-of-friend" discovery: Bob рекомендует Alice контакт Carol
  (подписанный voucher) — Carol получает сниженный PoW

### 13.3 Защита от спама в группах (v0.2)

- Только Admin может добавлять участников
- Участник не может приглашать без роли Admin
- Flood protection: > 30 сообщений/минуту от одного участника = mute на 5 мин

---

## 14. Мультидевайс — работа на нескольких устройствах (v0.3)

### 14.1 Проблема

Triple Ratchet (SPQR) привязан к конкретной сессии между двумя устройствами.
Если Alice имеет телефон и ноутбук — это два разных ratchet state для Bob.
Bob должен знать, на какое устройство отправлять.

### 14.2 Архитектура: Device Group

```
Alice Identity (ML-DSA, из seed-фразы)
  ├── Device A (laptop):  own iroh NodeId, own prekeys
  ├── Device B (phone):   own iroh NodeId, own prekeys
  └── Device C (tablet):  own iroh NodeId, own prekeys
```

**Ключевой принцип:** один seed → один Identity, но каждое устройство
имеет свой транспортный ключ (iroh NodeId) и свои prekeys.

### 14.3 Синхронизация

**a) Linked Devices Protocol:**

```
Привязка нового устройства:
  1. На Device A: /link — генерирует одноразовый QR/код
  2. На Device B: /link <code> — сканирует
  3. Устройства устанавливают защищённый канал (seed-derived shared key)
  4. Device A отправляет Device B:
     - Список контактов (pubkeys + aliases)
     - Текущие ratchet states (зашифрованные)
     - Pending messages
  5. Device B регистрирует свой NodeId в DHT под тем же Identity
```

**b) Синхронизация сообщений между устройствами:**

- Каждое сообщение (отправленное и полученное) реплицируется на все
  linked devices через зашифрованный канал
- Используется CRDT-подобный merge: (contact_id, timestamp, device_id) → message
- Конфликты невозможны (сообщения append-only)

**c) Ratchet state sync:**

- Только одно устройство ведёт ratchet с конкретным контактом в данный момент
- "Active device" для контакта = последнее, откуда отправлено сообщение
- Другие устройства получают копию через device sync канал
- При переключении устройства — ratchet state передаётся

### 14.4 DHT запись для мультидевайс

```
ML-DSA_pubkey → {
    devices: [
        { node_id: iroh_NodeId_A, priority: 1, last_seen: ts },
        { node_id: iroh_NodeId_B, priority: 2, last_seen: ts },
    ],
    signature: ML-DSA_sign(devices)
}
```

Bob отправляет сообщение Alice на устройство с наивысшим приоритетом
(или на все, если broadcast mode).

### 14.5 Ограничения

- Максимум 5 linked devices
- Seed-фраза нужна для привязки (proof of ownership)
- Отвязка устройства = ротация prekeys на остальных
- История сообщений НЕ синхронизируется полностью (только новые после link)
  — полная синхронизация через export/import бэкапа

---

## 15. Кроссплатформенность и GUI

### 15.1 Стратегия: общее ядро + платформенные клиенты

```
┌─────────────────────────────────────────────────────────────────┐
│                    aira-core (pure Rust)                       │
│  крипто, протокол, ratchet, группы, spam — ВСЕ платформы        │
├─────────────────────────────────────────────────────────────────┤
│                    aira-net (Rust + iroh)                      │
│  сеть, NAT traversal, relay — ВСЕ платформы                     │
├─────────────────────────────────────────────────────────────────┤
│                    aira-storage (Rust + redb)                  │
│  локальная БД — ВСЕ платформы                                   │
├─────────────────────────────────────────────────────────────────┤
│                    aira-daemon (Rust + tokio)                  │
│  фоновый процесс — desktop (Linux/macOS/Windows)                │
│  встроенный в app — mobile (Android/iOS)                        │
├──────────┬──────────┬──────────┬──────────┬─────────────────────┤
│  CLI     │ Desktop  │ Android  │  iOS     │  Web (future)       │
│ ratatui  │  egui    │ Kotlin + │ Swift +  │  WASM + egui        │
│          │          │ UniFFI   │ UniFFI   │                     │
└──────────┴──────────┴──────────┴──────────┴─────────────────────┘
```

### 15.2 Desktop: Linux, macOS, Windows (v0.1 CLI → v0.2 GUI)

**v0.1 — CLI (ratatui):**

- Единый бинарник, работает везде где есть терминал
- `aira-daemon` + `aira-cli` общаются через IPC:
  - Linux/macOS: Unix domain socket (`~/.aira/daemon.sock`)
  - Windows: Named pipe (`\\.\pipe\aira-daemon`)

**v0.2 — Desktop GUI (egui/eframe):**

- Pure Rust, один исходный код → бинарник для каждой ОС
- egui рендерит через wgpu (Vulkan/Metal/DX12) — нативная
  производительность, нет WebView
- GUI общается с daemon через тот же IPC что и CLI
- Системный трей: daemon работает в фоне, GUI открывается по клику

```rust
// crates/aira-gui/src/main.rs
// Один исходник → cargo build для каждой платформы

fn main() {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([400.0, 600.0])
            .with_icon(load_icon()),
        ..Default::default()
    };
    eframe::run_native("aira", options, Box::new(|_| Ok(Box::new(App::new()))));
}
```

**Особенности по ОС:**

|             | Linux                      | macOS              | Windows                    |
| ----------- | -------------------------- | ------------------ | -------------------------- |
| IPC         | Unix socket                | Unix socket        | Named pipe                 |
| Автозапуск  | systemd user service       | LaunchAgent        | Registry / Task Scheduler  |
| Уведомления | libnotify / D-Bus          | NSUserNotification | Windows Toast              |
| Keychain    | Secret Service (GNOME/KDE) | macOS Keychain     | Windows Credential Manager |
| Трей        | libappindicator            | NSStatusItem       | Shell_NotifyIcon           |

Крейты: `notify-rust` (уведомления), `keyring` (OS keychain), `tray-icon` (системный трей)

### 15.3 Android (v0.3)

**Архитектура:** Kotlin UI + Rust core через **UniFFI** (Mozilla)

```
┌─────────────────────────────┐
│  Kotlin UI (Jetpack Compose)│  — нативный Material You
├─────────────────────────────┤
│  UniFFI binding layer       │  — автогенерация Kotlin ↔ Rust
├─────────────────────────────┤
│  aira-core + net + storage│  — .so библиотека (ARM64/x86_64)
│  daemon встроен в app       │  — нет отдельного процесса
└─────────────────────────────┘
```

- **UniFFI** генерирует Kotlin биндинги из Rust интерфейсов автоматически
- Daemon не отдельный процесс — встроен в app, работает через Android
  Foreground Service (чтобы ОС не убивала)
- Push-уведомления: **UnifiedPush** (децентрализованный, без Google) или
  Firebase FCM как fallback — relay отправляет "wake-up" нотификацию,
  содержимое сообщения НЕ проходит через push-сервер
- Storage: redb работает на Android (обычный файл в app sandbox)
- Target: `aarch64-linux-android`, `x86_64-linux-android` (эмулятор)

```toml
# Cargo.toml для Android .so
[lib]
crate-type = ["cdylib"]

[dependencies]
uniffi = "0.28"
```

### 15.4 iOS (v0.3)

**Архитектура:** Swift UI + Rust core через **UniFFI**

```
┌─────────────────────────────┐
│  SwiftUI                    │  — нативный iOS дизайн
├─────────────────────────────┤
│  UniFFI binding layer       │  — автогенерация Swift ↔ Rust
├─────────────────────────────┤
│  aira-core + net + storage│  — .a статическая библиотека (ARM64)
│  daemon встроен в app       │  — нет отдельного процесса
└─────────────────────────────┘
```

- UniFFI генерирует Swift биндинги
- Компиляция: `aarch64-apple-ios` (device), `aarch64-apple-ios-sim` (M-series sim)
- Фоновая работа: iOS Network Extension или BGTaskScheduler — ограничено,
  но достаточно для получения сообщений при wake-up
- Push: Apple Push Notification (APNs) — relay отправляет wake-up,
  содержимое E2E зашифровано
- **Ограничение iOS:** фоновое сетевое подключение убивается через ~30 сек.
  Решение: relay store-and-forward (п. 6.3b) критичен для iOS

### 15.5 Web (future, после v0.3)

- `aira-core` компилируется в **WASM** (уже no_std-совместимый)
- egui + eframe имеют WASM backend из коробки
- Сеть: iroh WASM поддержка (через WebTransport / WebSocket relay)
- Storage: IndexedDB через `idb` крейт
- **Ограничения:** нет прямого UDP (только через relay), производительность
  Argon2id в WASM ниже (~3-5x медленнее)

### 15.6 Структура репозитория (обновлённая)

```
aira/
├── Cargo.toml                # workspace
├── crates/
│   ├── aira-core/          # протокол, крипто — все платформы
│   ├── aira-net/           # сетевой слой + pluggable transports
│   ├── aira-storage/       # хранилище — все платформы
│   ├── aira-daemon/        # фоновый процесс — desktop
│   ├── aira-cli/           # TUI — desktop
│   ├── aira-gui/           # egui GUI — desktop (Linux/macOS/Windows)
│   └── aira-ffi/           # UniFFI биндинги — mobile (Android/iOS)
├── mobile/
│   ├── android/              # Kotlin + Jetpack Compose
│   └── ios/                  # Swift + SwiftUI
├── locales/                  # i18n — Fluent .ftl файлы
│   ├── en/                   # English (базовый)
│   ├── ru/                   # Русский
│   └── .../                  # другие языки
├── bootstrap/                # bootstrap-ноды
├── docs/
└── tests/
    └── integration/
```

### 15.7 Матрица CI/CD

| Платформа     | Target                     | Артефакт             | CI                                    |
| ------------- | -------------------------- | -------------------- | ------------------------------------- |
| Linux x86_64  | `x86_64-unknown-linux-gnu` | AppImage / .deb      | GitHub Actions                        |
| macOS ARM     | `aarch64-apple-darwin`     | .dmg / .app          | GitHub Actions (macOS runner)         |
| macOS Intel   | `x86_64-apple-darwin`      | .dmg / .app          | GitHub Actions (macOS runner)         |
| Windows       | `x86_64-pc-windows-msvc`   | .msi / portable .exe | GitHub Actions (Windows runner)       |
| Android ARM64 | `aarch64-linux-android`    | .apk / .aab          | GitHub Actions + NDK                  |
| iOS ARM64     | `aarch64-apple-ios`        | .ipa (TestFlight)    | GitHub Actions (macOS runner) + Xcode |
| Web (WASM)    | `wasm32-unknown-unknown`   | static site          | GitHub Actions                        |

---

## 16. Порядок реализации

### Milestone 1 — Core crypto (3-4 недели)

1. `aira-core/src/crypto/mod.rs` — trait `CryptoProvider` (абстракция бэкенда)
2. `aira-core/src/crypto/rustcrypto.rs` — реализация на ml-kem + ml-dsa
3. `aira-core/src/seed.rs` — seed-фраза (BIP-39), Argon2id KDF, деривация ключей
4. `aira-core/src/identity.rs` — ML-DSA keypair из seed, генерация, сериализация
5. `aira-core/src/kem.rs` — гибридный X25519+ML-KEM-768 KEM
6. `aira-core/src/handshake.rs` — PQXDH handshake + capability negotiation
7. `aira-core/src/ratchet.rs` — Triple Ratchet (SPQR): классический DR + PQ ratchet
8. `aira-core/src/padding.rs` — message padding до фиксированных блоков
9. `aira-core/src/safety.rs` — Safety Numbers для верификации ключей
10. Unit тесты для каждого модуля
11. Property-based тесты (proptest) для крипто-примитивов
12. Тест: seed-фраза → одинаковые ключи на разных машинах (детерминистичность)
13. Тест: Triple Ratchet деградация при отсутствии PQ поддержки

### Milestone 2 — Networking + Relay (3-4 недели)

1. `aira-net/src/endpoint.rs` — iroh 0.97+ Endpoint обёртка
2. `aira-net/src/connection.rs` — управление сессиями
3. `aira-net/src/discovery.rs` — DHT и direct add
4. `aira-net/src/relay.rs` — store-and-forward relay с pairwise mailboxes
5. Bootstrap нода + relay нода (может быть одной)
6. Протокол deposit/retrieve зашифрованных конвертов, TTL, GC
7. Интеграционный тест: два узла обмениваются сообщением
8. Интеграционный тест: сообщение через relay при офлайн пире

### Milestone 3 — Storage + Daemon (1-2 недели)

1. `aira-storage/` — redb схема, CRUD операции + pending_messages
2. Шифрование базы данных (storage key из seed)
3. `aira-daemon/` — event loop, IPC сокет
4. Disappearing messages — daemon удаляет по TTL
5. Export/import бэкапа

### Milestone 4 — File transfer (1 неделя)

1. Интеграция iroh-blobs 0.99+
2. Chunked transfer для больших файлов
3. Progress reporting через IPC events

### Milestone 5 — CLI (1-2 недели)

1. `aira-cli/` — ratatui TUI
2. Все команды: /add, /file, /me, /mykey, /info, /verify, /export, /import
3. Disappearing messages UI (таймер)
4. Реакции и ответы
5. End-to-end тест через CLI

### Milestone 6 — Групповые чаты (v0.2, 2-3 недели)

1. `aira-core/src/group.rs` — Sender Keys, Group Ratchet
2. `aira-core/src/group_proto.rs` — протокол создания/управления группой
3. `aira-storage/` — таблицы groups, group_messages
4. Интеграция с daemon IPC (create/join/leave group)
5. CLI: отображение групповых чатов
6. Интеграционный тест: 3 ноды в группе

### Milestone 7 — DPI resistance (v0.2, 2-3 недели)

1. `aira-net/src/transport/mod.rs` — trait `AiraTransport`, direct transport
2. `aira-net/src/transport/obfs.rs` — obfs4/o5 через ptrs
3. `aira-net/src/transport/mimicry.rs` — CPS protocol mimicry (DNS/QUIC/SIP)
4. `aira-net/src/transport/cdn.rs` — CDN relay (Cloudflare Worker)
5. CLI: `/transport <mode>` — переключение режима
6. Тест: DPI-симулятор (nDPI/Wireshark) не распознаёт aira трафик

### Milestone 8 — Мультидевайс (v0.3, 3-4 недели)

1. `aira-core/src/device.rs` — Linked Devices Protocol
2. `aira-core/src/sync.rs` — синхронизация сообщений между устройствами
3. DHT мультидевайс записи
4. Ratchet state handoff между устройствами
5. CLI: `/link`, `/devices`, `/unlink`
6. Интеграционный тест: 2 устройства одного пользователя

### Milestone 9 — Desktop GUI (v0.3, 2-3 недели)

1. `aira-gui/` — egui/eframe приложение
2. Системный трей + daemon management
3. OS keychain интеграция (keyring)
4. Нативные уведомления (notify-rust)
5. Сборка: AppImage (Linux), .dmg (macOS), .msi (Windows)

### Milestone 10 — Mobile: Android (v0.3, 3-4 недели)

1. `aira-ffi/` — UniFFI биндинги
2. `mobile/android/` — Kotlin + Jetpack Compose UI
3. Foreground Service для daemon
4. UnifiedPush / FCM wake-up уведомления
5. .apk сборка через GitHub Actions + NDK

### Milestone 11 — Mobile: iOS (v0.3, 3-4 недели)

1. UniFFI → Swift биндинги
2. `mobile/ios/` — SwiftUI
3. Network Extension / BGTaskScheduler
4. APNs wake-up уведомления
5. TestFlight сборка

### Milestone 12 — REALITY + Tor transport (v0.3, 3-4 недели)

1. `aira-net/src/transport/reality.rs` — REALITY-like TLS camouflage
2. `aira-net/src/transport/tor.rs` — интеграция с arti
3. uTLS мимикрия browser fingerprint (Chrome/Firefox/Safari)
4. Fallback к легитимному сайту при active probing
5. Тест: active probing не обнаруживает aira

### Milestone 13 — Крипто-бэкенд aws-lc-rs (v0.3, 1-2 недели)

1. `aira-core/src/crypto/awslc.rs` — реализация CryptoProvider на aws-lc-rs
2. FIPS 140-3 validated ML-KEM + ML-DSA
3. Seed-based keygen через `PqdsaKeyPair::from_seed()`
4. Feature flag: `--features=fips` для переключения бэкенда
5. Тесты совместимости: сообщения RustCrypto ↔ aws-lc-rs

---

## 17. Качество кода

### Обязательно

- `#![deny(unsafe_code)]` в `aira-core` и `aira-storage`
- `#![warn(clippy::all, clippy::pedantic)]` везде
- Каждый публичный API — docstring с примером
- Все секреты — через `zeroize::Zeroizing<_>`
- Никаких `unwrap()` в production коде (только в тестах)

### CI (GitHub Actions)

```yaml
- cargo fmt --check
- cargo clippy -- -D warnings
- cargo test --all-features
- cargo audit # проверка уязвимостей в зависимостях
- cargo deny check # лицензии, дубли
```

### Тестирование

- Unit тесты в каждом crate
- Интеграционные тесты в `tests/integration/` — поднимают две ноды in-process
- Fuzz тесты для парсинга протокольных пакетов (cargo-fuzz):
  - `fuzz_target!(|data| { postcard::from_bytes::<Message>(data).ok(); })`
  - `fuzz_target!(|data| { postcard::from_bytes::<GroupMessage>(data).ok(); })`
  - Особенно важно для relay: любой пакет от незнакомца парсится на приёмной стороне

### Изоляция криптографических ключей

> Урок Threema (USENIX Security 2023): использование одного ключа в двух разных
> криптографических контекстах создаёт cross-protocol атаки, которые невозможно
> исправить без полного сброса ключей у всех пользователей.

**Обязательное правило:** каждый ключ — ровно один криптографический контекст.

```rust
// ✅ Каждый KDF-вывод — уникальный контекст
let identity_key   = seed.derive("aira/identity/0");    // ML-DSA signing
let x25519_key     = seed.derive("aira/x25519/0");      // ECDH key agreement
let mlkem_key      = seed.derive("aira/mlkem/0");       // KEM
let storage_key    = seed.derive("aira/storage/0");     // DB encryption
let mailbox_id     = BLAKE3(shared_secret || "mailbox"); // Relay mailbox ID

// ❌ Запрещено: использовать identity_key для шифрования данных
// ❌ Запрещено: использовать storage_key в качестве MAC-ключа
// ❌ Запрещено: один и тот же ключ в handshake и в ratchet
```

**Документирование:** все KDF-контексты перечислены в `docs/KEY_CONTEXTS.md`:

```markdown
# Key Contexts (docs/KEY_CONTEXTS.md)

| Context string  | Algorithm  | Purpose                  | Used by     |
| --------------- | ---------- | ------------------------ | ----------- |
| aira/identity/0 | ML-DSA-65  | Identity signing         | identity.rs |
| aira/x25519/0   | X25519     | ECDH component of hybrid | kem.rs      |
| aira/mlkem/0    | ML-KEM-768 | PQ KEM component         | kem.rs      |
| aira/storage/0  | ChaCha20   | DB encryption key        | storage.rs  |
| BLAKE3(ss       |            | "mailbox")               | -           |
```

При code review: любое использование ключа вне его задокументированного контекста
должно немедленно блокировать PR.

---

## 18. Открытые вопросы для обсуждения

1. **iroh NodeId vs ML-DSA Identity** — стоит ли сделать ML-DSA ключ
   транспортной идентичностью, заменив Ed25519? Требует форка iroh или
   ожидания поддержки PQ в iroh.

2. **Bootstrap нода** — self-hosted только или публичные? Нужен механизм
   обновления списка bootstrap нод без обновления бинарника.

3. **Имена пользователей** — только псевдонимы в контакт-листе у каждого
   клиента, или глобальный namespace? Рекомендую локальные псевдонимы (проще,
   нет доверенной третьей стороны).

4. **Key Transparency / AKD (v0.4+)** — Safety Numbers (п. 6.9) решают задачу
   верификации между двумя людьми. Но как проверить что все контакты видят
   одинаковый публичный ключ (защита от targeted MITM только для одного пира)?

   Варианты:
   - **Auditable Key Directory (Signal KT)** — прозрачный журнал всех ключей,
     любой может проверить. Требует доверенного сервера — противоречит P2P.
   - **Gossip verification** — контакты "сплетничают" об увиденных ключах.
     Если Bob видит другой ключ Alice чем Carol — обнаружение MITM.
   - **DHT-based key consistency** — публикация ключей в DHT с историей изменений.
     Ноды могут сравнивать версии.

   Рекомендация: оставить в открытых вопросах, решить при достижении v0.4.

5. **IPFS для persistent file delivery (v0.2+)** — сейчас файлы требуют оба пира
   онлайн (relay хранит только хэш, не файл). Опциональный IPFS-пиннинг мог бы
   позволить скачать файл пока отправитель офлайн. Требует:
   - Шифрование файла сессионным ключом перед публикацией
   - Явное согласие пользователя (файл становится доступен на IPFS)
   - Нарушает pure P2P модель — должно быть строго opt-in

---

## 19. Соглашения для Claude Code агента

- Язык кода: Rust edition 2021
- Язык комментариев в коде: английский
- Язык документации (README, SPEC): русский или английский
- Ветки: `main` (стабильная), `dev` (разработка), `feat/*`
- Коммиты: conventional commits (`feat:`, `fix:`, `chore:`, `docs:`)
- При добавлении крейта — проверить дату последнего коммита и количество
  скачиваний на crates.io
- При изменении крипто-кода — обязательно добавить/обновить тесты
- Не использовать `todo!()` без GitHub issue номера в комментарии

---

_Spec v0.3 — источники: RustCrypto ml-kem 0.2/ml-dsa 0.0.4, iroh 0.97 (n0),
aws-lc-rs FIPS 140-3, Signal PQXDH + SPQR (Eurocrypt 2025), SimpleX Chat
(pairwise queues), Project Eleven PQC Rust survey (July 2025), noq QUIC
announcement (March 2026), NIST FIPS 203/204/205 (August 2024),
Threema protocol analysis (USENIX Security 2023), Meta Messenger E2EE design (2023),
Signal Key Transparency (2024), Matrix causal ordering lessons,
SoK multi-device messaging (IACR 2021), Wire MLS adoption retrospective_
