# SPEC §7: Хранилище (aira-storage)

[← Индекс](../SPEC.md)

---

## 7. Хранилище (aira-storage)

База данных: **redb** (pure Rust, embedded, без unsafe в публичном API).
Все значения — `postcard(T)`, зашифрованные storage-ключом (§7.1); ключи таблиц — открытые.

```rust
// crates/aira-storage/src/lib.rs — таблицы v1 (v0.3.5); пометки «M19/M25» — план
const CONTACTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("contacts");
    // key: ML-DSA pubkey контакта
    // value: ContactInfo { pubkey, alias, added_at, verified, blocked }
    // v2 (M19 Phase A п.1): + endpoint_addr (iroh EndpointAddr без IP), relays: Vec<RelayRef>;
    //   индекс pseudonym → contact для входящих по псевдониму

const MESSAGES: TableDefinition<(u64, u64), &[u8]> = TableDefinition::new("messages");
    // key: (contact_id, timestamp_micros)
    // value: StoredMessage { id, sender_is_self, payload_bytes, timestamp_micros,
    //                        ttl_secs, read_at, expires_at }
    // payload_bytes = postcard(MessageMeta) — единый контракт с проводом и IPC (M19, §8)

const SESSIONS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("sessions");
    // key: contact pubkey; value: RatchetSnapshot — сохраняется ДО отправки (M19 Phase A)

const PENDING: TableDefinition<(u64, u64), &[u8]> = TableDefinition::new("pending_messages");
    // key: (contact_id, seq)
    // value: ТОЛЬКО postcard(EncryptedEnvelope) — инвариант §6.3a; тип-обёртка
    //   PendingEnvelope { enqueued_at, size, envelope } (M19 Phase A п.2).
    //   ⚠️ v1 клал сюда plaintext и sender keys групп — устранено отключением групп в бете
    // лимиты: 1000 сообщений / 100 MB на контакт → Error(QueueFull); GC 7 дней

const SEEN_IDS: TableDefinition<&[u8], u64> = TableDefinition::new("seen_message_ids");
    // dedup-окно 24 ч (§6.21): key = BLAKE3(sender_pubkey ‖ counter ‖ nonce)[..16] → unix ts
    // (M19 Phase A п.3; проверяется ДО ratchet-decrypt)

const SETTINGS: TableDefinition<&str, &[u8]> = TableDefinition::new("settings");
    // TTL per-chat, relays, hide_ip, device_index (= 0 до M26) и др.

const META: TableDefinition<&str, u32> = TableDefinition::new("meta");
    // "schema_version" → u32; цепочка миграций при Storage::open (M19 Phase A п.1)

// ─── Группы (§12): таблицы v1, схема меняется в M25 ───
const GROUPS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("groups");
    // group_id → GroupInfo { id, name, members: Vec<GroupMemberInfo>, created_by, created_at }
const GROUP_MESSAGES: TableDefinition<(&[u8], u64), &[u8]> = TableDefinition::new("group_messages");
    // v1: (group_id, timestamp_micros) → StoredMessage — коллизия в микросекунду затирает (G6)
    // M25: (group_id, member_index, counter); + group_sender_states:
    //   (group_id, member) → Zeroizing(SenderKeyState | SenderKeyReceiver) — персистентная FS (G4)

// ─── Мультидевайс (§14): примитивы, в бете не используются (M26) ───
const DEVICES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("devices");
    // device_id (32) → DeviceInfo { device_id, name, node_id, priority, is_primary, linked_at, … }
const SYNC_LOG: TableDefinition<(u64, u64), &[u8]> = TableDefinition::new("sync_log");
    // (device_id_hash, timestamp) → SyncLogEntry

// ─── Псевдонимы (§12.6) ───
const PSEUDONYMS: TableDefinition<u32, &[u8]> = TableDefinition::new("pseudonyms");
    // counter → PseudonymRecord { counter, pubkey, context_type, context_id, display_name, created_at }
const PSEUDONYM_COUNTER: TableDefinition<&str, u32> = TableDefinition::new("pseudonym_counter");
    // "current" → u32. Раскладка counter = (device_index << 28) | local (M19 Phase A п.7):
    //   иначе два устройства выдадут aira/pseudonym/0/* разным контекстам (key isolation, §14.2)
```

### 7.1 Защита базы данных

- Storage key = `BLAKE3-KDF(master_seed, "aira/storage/0")` — деривируется
  из seed-фразы (см. п. 4.8)
- Storage key кэшируется в памяти daemon'а (zeroized при shutdown)
- Опционально: storage key хранится в OS keychain (keyring крейт),
  чтобы не вводить seed-фразу при каждом запуске

**Механизм шифрования (application-level):**

redb не поддерживает встроенное шифрование. Используется application-level
шифрование values перед записью:

```rust
// crates/aira-storage/src/encrypted.rs — фактическая сигнатура v1 (v0.3.5)

/// ChaCha20-Poly1305; blob = nonce (12 случайных байт) ‖ ciphertext
pub fn encrypt_value(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, StorageError>;
pub fn decrypt_value(key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>, StorageError>;

// M19 Phase A п.5 — AAD, чтобы ciphertext нельзя было переставить между строками и таблицами
// (сейчас атакующий с правом записи в файл может подменить значение одной строки другой):
pub fn encrypt_value(key: &[u8; 32], table: &str, row_key: &[u8], plaintext: &[u8]) -> …;
pub fn decrypt_value(key: &[u8; 32], table: &str, row_key: &[u8], blob: &[u8]) -> …;
//   aad = table ‖ row_key
```

**Права на файлы (M19b п.3, аудит S8):** каталог данных `~/.aira` — `0700`; `aira.redb`,
бэкапы, `ipc.token` и Unix-сокет — `0600` (в v0.3.5 создаются по umask); Windows — ACL
«только текущий пользователь», имя pipe с SID.

**Trade-offs:**

- Ключи таблиц (pubkey, timestamps) **не зашифрованы** — допустимо для
  локальной БД (атакующий с доступом к файлу видит pubkey контактов,
  но не содержимое сообщений и ratchet state)
- Альтернатива для mobile: оценить SQLCipher (полное шифрование
  включая индексы, аудированное решение, используется Mozilla/Microsoft)
- Ratchet states (таблица `sessions`) — критичны, шифруются обязательно
- `pending_messages` содержит только уже зашифрованные ratchet'ом конверты,
  но таблица всё равно под storage-ключом (метаданные очереди)
- TTL-GC (`delete_expired`) расшифровывает значения при сканировании — при росте базы
  вторичная таблица `expiry` (после беты)

### 7.2 Версия схемы, миграции, бэкап

- `meta.schema_version` + цепочка миграций при `Storage::open` (M19 Phase A п.1);
  v1 → v2: `ContactInfo.endpoint_addr/relays`, индекс `pseudonym → contact`. Политика беты:
  **совместимость баз до 1.0 не гарантируется**, но обновления беты не теряют данные —
  миграции обязательны с первой беты (§6.6.7 аудита)
- **Бэкап (§6.10, `backup.rs`):** формат `AIRA` ‖ version (1 байт) ‖ nonce ‖ ciphertext.
  Сейчас `VERSION = 1` (contacts, messages, sessions, settings). **`VERSION = 2`
  (M19 Phase A п.4):** + groups, group_messages, devices, pseudonyms, `pseudonym_counter`;
  лимит размера при импорте (решение A19); после restore `pseudonym_counter.local ≥ max + 1`
  — иначе повторная выдача одного псевдонима в другой контекст (нарушение key isolation).
  Тестовые фикстуры `aira-v1.redb` / `backup-v1.aira.enc` снимаются **до** смены схемы
- redb остаётся 2.x (2.6) для беты; апгрейд на redb 4 (смена формата файла, нужен для
  wasm32) — вместе с решением C13 по браузеру (M14)

---
