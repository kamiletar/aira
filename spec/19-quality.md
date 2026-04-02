# SPEC §17+17A: Качество кода и Bot API

[← Индекс](../SPEC.md)

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

## 17A. Bot API (v0.2)

### 17A.1 Архитектура: бот = обычный пир

> В E2E P2P мессенджере бот — это **обычная нода с ML-DSA Identity**,
> которая запускает пользовательский код вместо UI.

В отличие от Telegram/Discord (бот на сервере видит plaintext через API
платформы), в Aira бот — полноправный участник E2E шифрования. Это значит:

- Бот имеет свой seed, свои ключи, свой ratchet state с каждым контактом
- Бот получает расшифрованные сообщения и отвечает через обычный протокол
- Relay/сеть не знают, что пир — бот (privacy)
- Бот может участвовать в группах (v0.2) как обычный member

```
┌──────────────────────────────┐
│  Пользовательский код бота   │  Lua / WASM / Rust plugin
├──────────────────────────────┤
│  Bot SDK (aira-bot)          │  Rust библиотека
├──────────────────────────────┤
│  aira-core + aira-net        │  полный стек крипто + сеть
└──────────────────────────────┘
```

### 17A.2 Bot SDK (aira-bot)

```rust
// crates/aira-bot/src/lib.rs

/// Trait, который реализует пользовательский бот
#[async_trait]
pub trait Bot: Send + Sync {
    /// Вызывается при получении текстового сообщения
    async fn on_message(&self, ctx: &BotContext, msg: IncomingMessage) -> Result<()>;

    /// Вызывается при добавлении в контакты (Contact Request accepted)
    async fn on_contact_added(&self, ctx: &BotContext, contact: PubKey) -> Result<()> {
        Ok(()) // default: ничего не делать
    }

    /// Вызывается при получении команды (/start, /help, ...)
    async fn on_command(&self, ctx: &BotContext, cmd: &str, args: &str) -> Result<()> {
        Ok(())
    }
}

pub struct BotContext {
    pub daemon: DaemonClient, // IPC к aira-daemon
}

impl BotContext {
    /// Ответить на сообщение
    pub async fn reply(&self, to: &PubKey, text: &str) -> Result<()>;

    /// Отправить файл
    pub async fn send_file(&self, to: &PubKey, path: &Path) -> Result<()>;

    /// Получить историю
    pub async fn history(&self, contact: &PubKey, limit: u32) -> Result<Vec<StoredMessage>>;
}
```

### 17A.3 Пример: echo-бот

```rust
struct EchoBot;

#[async_trait]
impl Bot for EchoBot {
    async fn on_message(&self, ctx: &BotContext, msg: IncomingMessage) -> Result<()> {
        ctx.reply(&msg.from, &format!("Echo: {}", msg.text)).await
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    aira_bot::run(EchoBot).await
}
```

### 17A.4 Запуск бота

```bash
# Бот — отдельный бинарник, подключается к daemon по IPC
aira-daemon &              # обычный daemon
my-echo-bot                # подключается к daemon, слушает сообщения

# Или: бот как daemon plugin (загружается в процесс daemon)
aira-daemon --bot my_bot.wasm
```

### 17A.5 Ограничения и безопасность

- Бот видит **plaintext** всех сообщений своих контактов — это by design
  (бот = доверенный собеседник, как в реальном чате)
- Бот **не может** прочитать чужие сообщения (E2E — бот участвует
  только в своих ratchet sessions)
- Rate limits: бот подчиняется тем же лимитам что обычный пир
  (500 msg/min per-contact, §11B.6)
- **Bot flag в профиле:** `UserProfile` получает поле
  `pub is_bot: bool` — клиенты отображают "[BOT]" рядом с именем
- Бот не может скрыть свой bot-статус (подпись профиля ML-DSA)

### 17A.6 WASM sandbox (v0.3)

Для запуска ненадёжного кода ботов:

- Бот компилируется в WASM
- Запускается в sandbox (`wasmtime`) с ограничениями:
  - Нет доступа к файловой системе (кроме явно разрешённых)
  - Нет сетевого доступа (только через Bot SDK)
  - Memory limit: 64 MB
  - CPU timeout: 5 сек на обработку одного сообщения
- Host предоставляет SDK через WASM imports

---

## 18. Открытые вопросы для обсуждения
