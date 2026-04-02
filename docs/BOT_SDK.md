# Aira Bot SDK

Библиотека для создания ботов для мессенджера Aira. Бот подключается к
работающему `aira-daemon` через IPC и реагирует на входящие сообщения.

## Быстрый старт

### 1. Зависимости

```toml
[dependencies]
aira-bot = { path = "crates/aira-bot" }
tokio = { version = "1", features = ["full"] }
tracing-subscriber = "0.3"
```

### 2. Реализация бота

```rust
use aira_bot::{Bot, BotContext, BotError, IncomingMessage, run_bot};

struct EchoBot;

impl Bot for EchoBot {
    fn on_message(
        &self,
        ctx: &BotContext,
        msg: IncomingMessage,
    ) -> impl std::future::Future<Output = Result<(), BotError>> + Send {
        let text = format!("Echo: {}", msg.text);
        let to = msg.from.clone();
        let ctx = ctx.clone();
        async move { ctx.reply(&to, &text).await }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    run_bot(EchoBot).await?;
    Ok(())
}
```

### 3. Запуск

```bash
# Сначала запустите daemon
cargo run -p aira-daemon

# В другом терминале — бот
cargo run --example echo -p aira-bot
```

## Trait `Bot`

Все методы имеют реализацию по умолчанию (no-op). Переопределите только те
события, на которые ваш бот должен реагировать.

| Метод | Когда вызывается |
|-------|-----------------|
| `on_message` | Получено текстовое сообщение (DM) |
| `on_group_message` | Получено текстовое сообщение в группе |
| `on_contact_online` | Контакт появился в сети |
| `on_contact_offline` | Контакт ушёл из сети |
| `on_group_member_joined` | Участник вступил в группу |
| `on_group_member_left` | Участник покинул группу |
| `on_group_invite` | Получено приглашение в группу |

## `BotContext`

Обёртка над IPC-клиентом с удобными методами:

| Метод | Описание |
|-------|----------|
| `reply(to, text)` | Отправить текстовое сообщение контакту |
| `send_group_message(group_id, text)` | Отправить сообщение в группу |
| `my_address()` | Получить собственный публичный ключ |
| `contacts()` | Получить список контактов |
| `history(contact, limit)` | Получить историю сообщений |
| `send_file(to, path)` | Отправить файл контакту |

`BotContext` реализует `Clone` — его можно безопасно передавать в spawned tasks.

## Архитектура

```
┌─────────────┐     IPC      ┌──────────────┐
│  aira-bot   │◄────────────►│ aira-daemon  │
│  (ваш бот)  │  postcard    │  (сеть, БД)  │
└─────────────┘  len-prefix  └──────────────┘
```

Бот использует тот же IPC-протокол, что и CLI (`aira-cli`).
Общий клиент находится в `aira-daemon::client`.

## Ограничения (v0.2)

- WASM sandbox для изоляции ботов запланирован на v0.3
- Бот видит только текстовые сообщения (`PlainPayload::Text` и `Action`)
- Файловые события (progress, complete, error) не доставляются боту
