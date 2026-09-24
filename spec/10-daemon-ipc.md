# SPEC §8: Daemon и IPC

[← Индекс](../SPEC.md)

---

## 8. Daemon и IPC

**aira-daemon** работает как фоновый процесс; **aira-cli**, **aira-gui** и боты (§17A) — тонкие
клиенты, общающиеся с daemon через Unix socket / Named pipe (Windows). На Android демон встроен
в приложение (`aira-ffi`, тот же `net_task` из библиотеки `aira-daemon`, M19 п.14).

```
aira-daemon (сетевой стек, крипто, storage)
      ↕  IPC (postcard, length-prefixed, over Unix socket / named pipe)
aira-cli    aira-gui    aira-bot (§17A)
```

Один сокет несёт request/response и поток событий:
`ServerMessage::{ Response(DaemonResponse), Event(DaemonEvent) }`. Кадр ≤ 1 MiB (проверяется до
аллокации). Сериализация — postcard, поэтому enum'ы ниже **append-only** (§6.16.1). IPC — внутренний
контракт одного релиза (демон и клиент из одной сборки), совместимость между версиями не обещается;
golden-байты IPC-типов входят в тесты (M19a).

**Запуск и аутентификация (M19b п.3, решения A18/B11):**

- `aira-daemon [--data-dir <dir>] [--socket <path>]`, переменная `AIRA_DATA_DIR` — второй
  экземпляр демона с другим seed на той же учётной записи (например, бот со своей identity, §17A).
  Сейчас каталог данных жёсткий: `$HOME/.aira` / `%LOCALAPPDATA%\aira`
- Права: `0700` на каталог данных, `0600` на сокет, проверка `SO_PEERCRED` (uid); Windows — имя
  пайпа с SID пользователя, `first_pipe_instance(true)`, security descriptor «только текущий
  пользователь». Сейчас любой локальный процесс может `Shutdown` и `ExportBackup { path }`
- Токен `<data_dir>/ipc.token` (0600) передаётся в первом кадре; клиентская библиотека —
  `aira_daemon::client::DaemonClient::{connect, connect_with_token}` (общая для CLI/GUI/бота;
  выделяется в крейт `aira-ipc` вместе с единым декодером событий, M19 / §14.0).
  Scoped-токены (`read-only`, `reply-only`) — M27
- Seed в демон — не через `AIRA_SEED` env (история shell, `/proc/<pid>/environ`), а через stdin при
  spawn / IPC-handshake / keychain; `AIRA_SEED` — только `cfg(debug_assertions)` (M19b п.2)

### 8.0 IPC API — состояние на 2026-09 (`crates/aira-daemon/src/types.rs`) и план M19

Пометки: **M19** — добавляется или меняется при подключении сети; **бета: отключено** — вариант
остаётся в enum (позиция занята), но демон отвечает `Error("… not available in this beta")`
и в клиентах команда скрыта (§15.8 п.7).

```rust
pub enum DaemonRequest {
    // ─── Сообщения и контакты ───
    SendMessage { to: Vec<u8>, text: String },
        // M19: заворачивает в MessageMeta { payload, ttl, id, reply_to } → ratchet-encrypt →
        //      прямая доставка (5 с) → pending → deposit на relay контакта; sessions::save ДО отправки
    GetHistory { contact: Vec<u8>, limit: u32 },
        // M19: вызывает messages::mark_read → старт TTL (§6.7); сейчас mark_read никто не вызывает
    AddContact { pubkey: Vec<u8>, alias: String },
        // M19: AddContact { uri: String, alias: Option<String> } — по invitation link aira://add/…
        //      (1952-байтный pubkey руками не вводится, §5.2); валидация длины ключа на границе IPC
    RemoveContact { pubkey: Vec<u8> },      // удаляет контакт; НЕ блокировка (см. BlockContact)
    GetContacts,
    GetMyAddress,
        // создаёт НОВЫЙ псевдоним при каждом вызове (растит таблицу pseudonyms, B5);
        // клиентам использовать GetInvitation (M19)
    SetTtl { contact: Vec<u8>, ttl_secs: Option<u64> },   // saturating add (M19 Phase A)
    ExportBackup { path: PathBuf, include_messages: bool },
    ImportBackup { path: PathBuf },                       // VERSION 2, лимит размера (M19 Phase A п.4)
    SendFile { to: Vec<u8>, path: PathBuf },              // ≥ 1 MB — iroh-blobs под per-file ключом (§6.2)
    SetTransportMode { mode: String },
    GetTransportMode,
        // удаляются вместе с transport/* (M19b, решение A13); до удаления mode ≠ "direct" → Error
    Shutdown,

    // ─── Группы (§12) — бета: отключено, реализация M25 ───
    CreateGroup { name: String, members: Vec<Vec<u8>> },
    GetGroups,
    GetGroupInfo { group_id: [u8; 32] },
    SendGroupMessage { group_id: [u8; 32], text: String },
    GetGroupHistory { group_id: [u8; 32], limit: u32 },
    GroupAddMember { group_id: [u8; 32], member: Vec<u8> },
    GroupRemoveMember { group_id: [u8; 32], member: Vec<u8> },
    LeaveGroup { group_id: [u8; 32] },
    AcceptGroupInvite { group_id: [u8; 32], display_name: String, invited_by: Vec<u8> },

    // ─── Псевдонимы (§12.6) ───
    GetPseudonyms,
    GetPseudonym { counter: u32 },
    FindPseudonym { context_id: [u8; 32] },

    // ─── Устройства (§14) — бета: отключено, реализация M26 ───
    GenerateLinkCode,
    LinkDevice { code: String, device_name: String },
    GetDevices,
    UnlinkDevice { device_id: [u8; 32] },

    // ─── M19 / M19b (append-only, в конец enum) ───
    GetInvitation,
        // aira://add/<base64url(postcard(InvitationLink { version, pseudonym_pk, endpoint_id,
        // relays: Vec<RelayRef>, fingerprint_hint, expires_at, stamp, sig }))> —
        // СТАБИЛЬНЫЙ псевдоним (выданные хранятся), без IP (решение A7); QR — byte-mode
    AcceptContact { pubkey: Vec<u8> },      // ответ на ContactRequestReceived
    RejectContact { pubkey: Vec<u8> },
    BlockContact { pubkey: Vec<u8> },       // §6.19: контакт остаётся в списке, blocked = true;
    UnblockContact { pubkey: Vec<u8> },     //   входящие конверты и handshake — silent drop (F2)
    GetSafetyNumber { contact: Vec<u8> },   // §6.9, ≥ 128 бит, одна строка у обеих сторон
    SetRelays { relays: Vec<RelayRef> },    // свои 1–2 relay (RelayMap), каталог — отдельно (B3)
    GetRelays,
    GetNetStatus,
}

pub enum DaemonResponse {
    Ok,
    Error(String),
    History(Vec<StoredMessage>),            // payload_bytes = postcard(MessageMeta) (M19)
    Contacts(Vec<ContactInfo>),
    MyAddress(Vec<u8>),
    TransportMode(String),                  // удаляется с транспортами (M19b)
    // группы / псевдонимы / устройства (бета: группы и устройства не возвращаются):
    GroupCreated { group_id: [u8; 32] }, GroupInfo(GroupInfoResp), Groups(Vec<GroupInfoResp>),
    GroupHistory(Vec<StoredMessage>),
    Pseudonyms(Vec<PseudonymResp>), Pseudonym(Option<PseudonymResp>),
    LinkCode(String), DeviceLinked { device_id: [u8; 32], name: String }, Devices(Vec<DeviceInfoResp>),
    // M19 / M19b:
    Invitation(String),                     // ссылка aira://add/…
    SafetyNumber(String),
    Relays(Vec<RelayRef>),
    NetStatus(NetStatus),                   // { home_relay, relay_ok, direct_addrs_hidden, pending, … }
    ContactRequests(Vec<ContactRequestResp>),
}

pub enum DaemonEvent {
    /// Новое сообщение. Единый контракт (M19 Phase B п.11, аудит B2): вместо
    /// `{ from, payload: Vec<u8> }`, где демон, CLI, GUI и бот понимали `payload` тремя
    /// несовместимыми способами (сырой UTF-8 / postcard(MessageMeta) / postcard(PlainPayload)).
    MessageReceived { from: Vec<u8>, message: StoredMessage },   // payload_bytes = postcard(MessageMeta)
    ContactOnline(Vec<u8>),
    ContactOffline(Vec<u8>),
    FileProgress { id: [u8; 16], bytes_sent: u64, total: u64 },
    FileComplete { id: [u8; 16], path: PathBuf },     // только по FileAck от пира (M19 п.13)
    FileError { id: [u8; 16], error: String },
    // группы (§12) — демон их сейчас не эмитит; M25:
    GroupMessageReceived { group_id: [u8; 32], from: Vec<u8>, payload: Vec<u8> },
    GroupMemberJoined { group_id: [u8; 32], member: Vec<u8> },
    GroupMemberLeft { group_id: [u8; 32], member: Vec<u8> },
    GroupInvite { group_id: [u8; 32], name: String, invited_by: Vec<u8> },
    // устройства (§14) — не эмитятся; M26:
    DeviceLinked { device_id: [u8; 32], name: String },
    DeviceUnlinked { device_id: [u8; 32] },
    SyncCompleted { device_id: [u8; 32], messages_synced: u32 },
    // M19 (append-only):
    DeliveryState { id: [u8; 16], state: DeliveryState },  // Sent | Queued | Relayed | Delivered
                                                           // (Delivered — по Message::Ack { counter })
    NetStatus(NetStatus),                                  // смена home relay, offline, re-home (watchdog)
    ContactRequestReceived { from: Vec<u8>, message: String, stamp: Option<ContactStamp> }, // §13, M22
}
```

Форвардер событий (M19 п.11): broadcast-канал ёмкостью 4096, `RecvError::Lagged` обрабатывается
(клиент получает `NetStatus`/пересинхронизацию), а не роняет соединение. События приходят всем
подключённым клиентам — бот видит и события GUI (§17A.5).

### 8.1 CPU-intensive операции в async runtime

> ⚠️ ML-KEM decapsulation (~0.05ms), ML-DSA verify (~0.3ms) — быстрые.
> Но Argon2id (m=256MB, t=3) и ML-DSA keygen — **блокирующие операции**
> длительностью 1-10 секунд. Выполнение в tokio task заблокирует executor.

**Правило:** все CPU-heavy крипто-операции выполняются через
`tokio::task::spawn_blocking`; сам `handle_request` — async (в v0.3.5 синхронный
`Fn(DaemonRequest) -> DaemonResponse` прямо в tokio-таске — M19 Phase A):

```rust
// aira-daemon/src/crypto_tasks.rs

/// Argon2id KDF — блокирующая операция (1-10 сек)
pub async fn derive_master_seed(phrase: &str) -> Result<MasterSeed> {
    let phrase = phrase.to_string();
    tokio::task::spawn_blocking(move || {
        MasterSeed::from_phrase(&phrase)
    }).await?
}

/// ML-DSA keygen — блокирующая операция (~50ms)
pub async fn generate_identity(seed: &MasterSeed) -> Result<Identity> {
    let seed = seed.clone();
    tokio::task::spawn_blocking(move || {
        Identity::from_seed(&seed)
    }).await?
}
```

**Быстрые операции** (< 1ms) выполняются inline в async task:
ML-KEM encaps/decaps, ChaCha20 encrypt/decrypt, BLAKE3 hash, ratchet step

---
