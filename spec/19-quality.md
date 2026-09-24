# SPEC §17+17A: Качество кода и Bot API

[← Индекс](../SPEC.md)

---

## 17. Качество кода

### Обязательно

- `#![deny(unsafe_code)]` в `aira-core` и `aira-storage`; цель — `unsafe_code = "deny"` на весь
  workspace после замены `unsafe` в `aira-gui` на `String::zeroize()` и `from_utf8_unchecked` в
  `discovery.rs` на safe-вариант (S3, M19b/M23)
- `#![warn(clippy::all, clippy::pedantic)]` везде
- **`[workspace.lints]` в корневом `Cargo.toml` (M18, решение A15):** `clippy::unwrap_used = "deny"`,
  `clippy::panic = "deny"`, `clippy::todo = "deny"`, `clippy::expect_used = "warn"`,
  `clippy::indexing_slicing = "warn"`; в каждом крейте — `[lints] workspace = true`. Сейчас
  `#![deny(clippy::unwrap_used)]` стоит только в `aira-core` (S10) — должен действовать **во всех
  крейтах** (§10)
- Каждый публичный API — docstring с примером
- Все секреты — через `zeroize::Zeroizing<_>` (включая seed-фразу и BIP-39-энтропию, S4);
  ручной `Debug` с `[REDACTED]` для структур с ключами (`RatchetSnapshot`, `SenderKeyState`,
  `SyncItem`, `GroupControl` — S5, M19a; правило в `.claude/rules/security.md`, решение B8)
- Никаких `unwrap()` в production коде (только в тестах)
- Сравнения MAC/транскриптов — `subtle::ConstantTimeEq`
- Каждый парсер внешних данных — с fuzz-таргетом (ниже); входящие кадры проверяют длину до аллокации
- Публичные документы — существуют и поддерживаются вместе с кодом: `README.md`, `SECURITY.md`
  (disclosure, окно 90 дней), `LICENSE-MIT`/`LICENSE-APACHE` (условие SignPath), `docs/THREAT_MODEL.md`
  и `docs/PRIVACY.md` (таблица обещаний по четырём наблюдателям, без слов «анонимный»/«невзламываемый»
  — решение B12), `docs/INSTALL.md`, `docs/KEY_CONTEXTS.md`

### CI (GitHub Actions) — M18 п.8 / M23 п.1, п.4

```yaml
# rust-toolchain.toml пинит stable: плавающий @stable ронял clippy при каждом релизе Rust
- cargo fmt --check
- cargo clippy --workspace --all-features --all-targets -- -D warnings
- cargo test --workspace --all-features --locked   # 65 тестов за feature-гейтами никогда не бежали (§8.3 аудита)
- cargo audit / cargo deny check                   # блокирующие + schedule раз в сутки; ignore только со сроком
- cargo fuzz build                                 # все fuzz-крейты (nightly) на каждом PR;
                                                   # на main / по расписанию — run 60 с на таргет
- cargo llvm-cov                                   # coverage (M23)
- cargo check -p aira-core --target wasm32-unknown-unknown   # гвард для M14
```

Матрица (M23, решения B7/D5): ubuntu-22.04 (контейнер — glibc-baseline для AppImage) / windows /
macos × stable + MSRV 1.91; Windows/macOS — на `main` и тегах, на PR — ubuntu. Релизный workflow:
SHA-пины actions + Dependabot, `permissions` least-privilege, `persist-credentials: false`,
`--locked`, без кэша, `SOURCE_DATE_EPOCH`/`--remap-path-prefix`, job `verify` (тег ↔ версия ↔ CI
зелёный), `SHA256SUMS` + GitHub attestations (SLSA L2 для беты, L3 к 1.0), cargo-auditable,
CycloneDX SBOM, minisign; `environment: release` с ручным approve (D8). Ветки: только `main` + PR
(D9). Supply chain и подпись — отдельный трек «M22-infra» параллельно M19 (D6).

### Тестирование

- Unit тесты в каждом crate; **known-answer-векторы** `crates/aira-core/tests/vectors/v0_3_5.json`
  (seed → VK/подпись/EK/DK, derive по фиксированной фразе, снимаются в worktree тега v0.3.5) —
  детерминизм ключей доказывается сравнением с фиксированными байтами, а не двумя вызовами в
  одном процессе (M18 шаг 0; расхождение VK после миграции = релиз-блокер)
- **Golden-байты** для каждого wire/IPC/storage-типа (`tests/vectors/wire_v2/*.bin`): roundtrip-тесты
  не ловят перестановку вариантов enum (§6.16.1); фикстуры `aira-v1.redb`/`backup-v1.aira.enc`
  снимаются до смены схемы (M19 Phase A п.0)
- Интеграционные: два демона in-process → сообщение доходит; перезапуск → сессия жива (M19 Phase C;
  требует `ipc.rs` в lib / крейт `aira-node`); «Bob офлайн 3 дня, порядок и dedup» через
  `aira-relay` (M21); «два relay, kill одного → re-home ≤ 60 с» (M20). «Группа из трёх демонов» —
  M25 (без реализации групп тест невозможен)
- Property-based (`proptest` объявлен в dev-deps aira-core, 0 использований — M18/M19a, план
  `test-coverage-audit.md` §4): `unpad(pad(m)) == m` и размеры блоков; BIP-39 кодек; postcard
  roundtrip **всех** wire/IPC/storage-типов; ratchet как state machine (`{A→B, B→A, deliver, drop,
  snapshot_restore}`, при `Err` состояние неизменно); `SenderKeyReceiver` в окне MAX_SKIP; гибридный
  KEM (порча любого байта ct → `Err`/другой ss); dedup; лимиты размеров для любой длины;
  `InvitationLink`/base64url; `encrypt_value` (инверсия бита → `Err`); попарная различность
  `derive`; `safety_number` (симметрия — решение A22)
- Fuzz (cargo-fuzz). Сейчас 2 таргета в `crates/aira-core/fuzz` (`fuzz_parse_message`,
  `fuzz_decode_keys`), и они **не собираются** (`postcard` не в `fuzz/Cargo.toml`); чинится в
  M18 п.7, seed-корпус коммитится (A20), CI-джоб `fuzz`. Таргеты (M19a п.7 и далее):
  - `aira-core/fuzz`: `fuzz_parse_message` (расширить: `MessageMeta`, `GroupControl`,
    `EncryptedGroupEnvelope`, `GroupMessage`), `fuzz_decode_keys`, `fuzz_wire_message` (`Message`
    v2), `fuzz_handshake` (`HandshakeInit/Ack` → `Responder::respond`/`Initiator::finish`, seed без
    Argon2 через `test-utils`), `fuzz_ratchet_decrypt` (инвариант: при `Err` снапшот до/после равен),
    `fuzz_ratchet_snapshot`, `fuzz_sync_batch`, `fuzz_group_decrypt` (`skipped_keys.len() ≤ MAX_SKIP`),
    `fuzz_contact_request`, `fuzz_bip39` (`validate_seed_phrase`, без Argon2)
  - `aira-net/fuzz`: `fuzz_invitation_link` (`from_uri`, base64url, `DeviceRecord::from_bytes`),
    `fuzz_framing` (`read_framed` через `Cursor`); `aira-relay/fuzz`: `fuzz_relay_request`
    (`RelayRequest` v2, M21); `aira-daemon/fuzz`: `fuzz_ipc` (`DaemonRequest`, `ServerMessage`, кадр
    > 1 MiB); `aira-storage/fuzz`: `fuzz_backup` (`import_bytes`, `decrypt_value`); M20 — `fuzz_config`
    (TOML `[network]`)
  - Регрессия без nightly: `fuzz_corpus_regression` в `cargo test` прогоняет корпус и артефакты через
    те же функции (`aira_core::fuzz_hooks::<name>` под feature `fuzzing`)
  - Особенно важно для relay: любой пакет от незнакомца парсится на приёмной стороне
- Таймерные тесты — `tokio::time::pause()`/`advance`, не реальный `sleep`; тесты с `let _ =` без
  assert (например `kem_invalid_ciphertext_rejected`) — переписать (M18)

### Изоляция криптографических ключей

> Урок Threema (USENIX Security 2023): использование одного ключа в двух разных
> криптографических контекстах создаёт cross-protocol атаки, которые невозможно
> исправить без полного сброса ключей у всех пользователей.

**Обязательное правило:** каждый ключ — ровно один криптографический контекст.

```rust
// ✅ Каждый KDF-вывод — уникальный контекст
let identity_key   = seed.derive("aira/identity/0");              // ML-DSA signing
let x25519_key     = seed.derive("aira/x25519/0");                // ECDH key agreement
let mlkem_key      = seed.derive("aira/mlkem/0");                 // KEM
let storage_key    = seed.derive("aira/storage/0");               // DB encryption
let iroh_secret    = seed.derive("aira/iroh/secret/0");           // транспортный ключ устройства 0 (M19)
let pseudonym_sk   = seed.derive("aira/pseudonym/<counter>/signing"); // per-context (§12.6)
let mailbox_id     = derive_key("aira/relay/mailbox/v2/a2b", shared_secret); // §6.5, M21

// ❌ Запрещено: использовать identity_key для шифрования данных
// ❌ Запрещено: использовать storage_key в качестве MAC-ключа
// ❌ Запрещено: один и тот же ключ в handshake и в ratchet
// ❌ Запрещено: один pseudonym counter в двух контекстах (в т.ч. на двух устройствах — §14.2)
```

**Документирование:** все KDF-контексты перечислены в `docs/KEY_CONTEXTS.md`
(30 контекстов на 2026-09, все найдены в коде; хоп-идентичность §5.5 — «не-KDF, локальный RNG»):

```markdown
# Key Contexts (docs/KEY_CONTEXTS.md) — фрагмент

| Context string                  | Algorithm  | Purpose                        | Used by            |
| ------------------------------- | ---------- | ------------------------------ | ------------------ |
| aira/identity/0                 | ML-DSA-65  | Identity signing               | identity.rs        |
| aira/x25519/0                   | X25519     | ECDH component of hybrid       | kem.rs             |
| aira/mlkem/0                    | ML-KEM-768 | PQ KEM component               | kem.rs             |
| aira/storage/0                  | ChaCha20   | DB encryption key              | storage            |
| aira/iroh/secret/<device_index> | Ed25519    | iroh transport key per device  | daemon (M19)       |
| aira/relay/mailbox/v2/<dir>     | BLAKE3     | Pairwise mailbox id per dir    | aira-relay (M21)   |
```

При code review: любое использование ключа вне его задокументированного контекста
должно немедленно блокировать PR.

---

## 17A. Bot API (SDK для собственного демона; v2 — Milestone 27)

> **Статус на 2026-09** (аудит E §3, решение владельца B11): `crates/aira-bot` (626 строк:
> `trait Bot`, `BotContext`, `run_bot`, пример `echo`, 11 тестов без живого демона) — **клиент IPC
> демона пользователя**, а не «нода со своим seed», как утверждала прежняя редакция. В бету 0.5
> Bot API **не входит** (не в чеклисте беты, не влияет на аудит ядра); SDK держится зелёным по ходу
> M19/M19b — единый формат `MessageReceived` (B2), IPC-токен (B3), `--data-dir` (B1). Bot API v2 —
> **M27** (после 1.0). До M19 демон не подключён к сети, поэтому бот сегодня не получит ни одного
> входящего сообщения. Документация для авторов ботов — `docs/BOT_SDK.md`.

### 17A.1 Архитектура: бот = automation-клиент демона

```
┌──────────────────────────────┐
│  Пользовательский код бота   │  Rust (impl Bot); отдельный процесс
├──────────────────────────────┤
│  Bot SDK (aira-bot)          │  trait Bot + BotContext + run_bot
├──────────────────────────────┤  ↕ IPC (§8) — тот же протокол, что у CLI/GUI
│  aira-daemon                 │  сеть, крипто, storage — identity владельца демона
└──────────────────────────────┘
```

**Модель v1 (реализована):** бот подключается к сокету **собственного демона пользователя**
(`DaemonClient::connect()` → `~/.aira/daemon.sock` / `\\.\pipe\aira-daemon`), действует под его
identity и видит всю переписку этого демона (и может вызвать любой запрос, включая
`ExportBackup`, `Shutdown`). Это «automation SDK для своего аккаунта» — как userbot, не как
Telegram Bot API.

**Бот с отдельной identity** (свой seed, свои ключи, свой ratchet с каждым контактом) =
**отдельный экземпляр демона**: `aira-daemon --data-dir <dir> --socket <path>` или
`AIRA_DATA_DIR` (M19b п.3). SDK не меняется — только путь к сокету и токену. Именно в этой
конфигурации верны свойства прежней редакции §17A: бот — полноправный участник E2E, relay и сеть
не знают, что пир — бот, бот не может прочитать чужие сообщения (у него нет их ratchet-сессий).

**Отклонено / перенесено:** «бот — нода внутри процесса демона», `aira-daemon --bot my_bot.wasm`
(plugin в процессе демона) и Lua — не реализуются; WASM sandbox — M27+ (§17A.6, не в 1.0).

### 17A.2 Bot SDK (aira-bot) — фактический API

```rust
// crates/aira-bot/src/lib.rs
/// RPITIT (`impl Future + Send`) — трейт НЕ object-safe: `impl Bot` / generics, не `dyn Bot`.
/// Все методы имеют no-op реализацию по умолчанию.
pub trait Bot: Send + Sync + 'static {
    fn on_message(&self, ctx: &BotContext, msg: IncomingMessage)
        -> impl Future<Output = Result<(), BotError>> + Send;
    fn on_contact_online(&self, ctx: &BotContext, pubkey: Vec<u8>) -> impl Future<…> + Send;
    fn on_contact_offline(&self, ctx: &BotContext, pubkey: Vec<u8>) -> impl Future<…> + Send;
    // Группы — в бете события не приходят (группы отключены); M25/M27:
    fn on_group_message(&self, ctx: &BotContext, msg: IncomingGroupMessage) -> impl Future<…> + Send;
    fn on_group_member_joined(&self, ctx: &BotContext, group_id: [u8; 32], member: Vec<u8>) -> …;
    fn on_group_member_left(&self, ctx: &BotContext, group_id: [u8; 32], member: Vec<u8>) -> …;
    fn on_group_invite(&self, ctx: &BotContext, group_id: [u8; 32], name: String, invited_by: Vec<u8>) -> …;
}
// M27: on_contact_added (после accept ContactRequest), on_command("/start", args)

pub struct IncomingMessage { pub from: Vec<u8>, pub text: String }   // Text и Action

// crates/aira-bot/src/context.rs
#[derive(Clone)]
pub struct BotContext { client: Arc<DaemonClient> }   // поле приватное (прежняя редакция: pub daemon)
impl BotContext {
    pub async fn reply(&self, to: &[u8], text: &str) -> Result<(), BotError>;        // SendMessage
    pub async fn send_file(&self, to: &[u8], path: PathBuf) -> Result<(), BotError>; // SendFile
    pub async fn contacts(&self) -> Result<Vec<ContactInfo>, BotError>;
    pub async fn history(&self, contact: &[u8], limit: u32) -> Result<Vec<StoredMessage>, BotError>;
        // payload_bytes = postcard(MessageMeta) после M19 (до M19 — три несовместимых формата, B2)
    pub async fn my_address(&self) -> Result<Vec<u8>, BotError>;
        // ⚠️ GetMyAddress создаёт НОВЫЙ псевдоним при каждом вызове (B5) —
        // M19: my_invitation() -> Result<String, BotError>  (aira://add/…, стабильный псевдоним)
    pub async fn send_group_message(&self, group_id: [u8; 32], text: &str) -> Result<(), BotError>;
        // бета: Error("groups are not available in this beta")
}

// crates/aira-bot/src/runner.rs
pub async fn run_bot(bot: impl Bot) -> Result<(), BotError>;
    // DaemonClient::connect() → event loop → dispatch; Ctrl+C.
    // M19b: чтение <data_dir>/ipc.token (DaemonClient::connect_with_token), путь к сокету из конфига;
    // reconnect с backoff (как у GUI Bridge) — опционально
```

### 17A.3 Пример: echo-бот (`crates/aira-bot/examples/echo.rs`)

```rust
use aira_bot::{run_bot, Bot, BotContext, BotError, IncomingMessage};

struct EchoBot;

impl Bot for EchoBot {
    fn on_message(
        &self,
        ctx: &BotContext,
        msg: IncomingMessage,
    ) -> impl std::future::Future<Output = Result<(), BotError>> + Send {
        let reply_text = format!("Echo: {}", msg.text);
        let to = msg.from.clone();
        let ctx = ctx.clone();
        async move { ctx.reply(&to, &reply_text).await }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    run_bot(EchoBot).await?;
    Ok(())
}
```

### 17A.4 Запуск бота

```bash
# 1. Бот управляет вашим аккаунтом (модель v1):
aira-daemon &                          # обычный демон пользователя
cargo run --example echo -p aira-bot   # подключается к ~/.aira/daemon.sock

# 2. Бот со своей identity (M19b): отдельный демон с отдельным seed и сокетом
AIRA_DATA_DIR=~/.aira-bot aira-daemon --socket ~/.aira-bot/daemon.sock &
my-echo-bot                            # путь к сокету/токену — из конфига SDK (M19b)
```

Бот — всегда отдельный процесс (бинарник), общается с демоном по IPC (§8). С M19b подключение
требует токена `<data_dir>/ipc.token` (`DaemonClient::connect_with_token`) — до этого любой
локальный процесс = бот (B3).

### 17A.5 Ограничения и безопасность

- Бот видит **plaintext** всех сообщений демона, к которому подключён, — by design. Для «бота как
  доверенного собеседника, который видит только свои чаты» — отдельный демон (§17A.1)
- Scope'ов у IPC-токена нет: бот может `ImportBackup/ExportBackup/Shutdown/SetTtl` и получает
  broadcast всех событий (в т.ч. адресованных GUI). Scoped-токены (`read-only`, `reply-only`) —
  M27; до того — отдельный демон
- Rate limits §11B.6 (500 msg/min per-contact) применяются демоном к **сетевым пирам**, не к
  IPC-клиенту; бот, флудящий контактам, упрётся в лимиты их демонов
- **Bot flag в профиле:** `UserProfile.is_bot` (§6.17) — после появления `UserProfile` (M28) → M27;
  клиенты отображают «[BOT]»; бот не может скрыть статус (подпись профиля ML-DSA)
- Группы для ботов — после M25 (методы `on_group_*` / `send_group_message` в бете не работают)
- Бот подчиняется §13 (contact-first): писать может только контактам; незнакомцу — только
  `ContactRequest` с PoW
- Файловые события (`FileProgress/Complete/Error`) боту сейчас не диспатчатся

### 17A.6 WASM sandbox (M27+, не в 1.0)

Для запуска ненадёжного кода ботов (в коде нет — `wasmtime` отсутствует в зависимостях):

- Бот компилируется в WASM
- Запускается в sandbox (`wasmtime`) с ограничениями:
  - Нет доступа к файловой системе (кроме явно разрешённых)
  - Нет сетевого доступа (только через Bot SDK)
  - Memory limit: 64 MB
  - CPU timeout: 5 сек на обработку одного сообщения
- Host предоставляет SDK через WASM imports

---
