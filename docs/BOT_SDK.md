# Aira Bot SDK

Библиотека для создания ботов для мессенджера Aira. Бот подключается к
работающему `aira-daemon` через IPC и реагирует на входящие сообщения.

> **Статус (сентябрь 2026):** SDK — клиент IPC **вашего собственного демона** (модель
> «automation SDK», спека §17A). В бету 0.5 Bot API не входит; SDK поддерживается рабочим
> по ходу релизного пути (M19/M19b), Bot API v2 — Milestone 27 (после 1.0). До M19 демон не
> подключён к сети, поэтому бот сегодня не получит ни одного входящего сообщения.

## Модель: бот = клиент вашего демона

- Бот подключается к сокету демона текущего пользователя (`~/.aira/daemon.sock`,
  `\\.\pipe\aira-daemon`) и действует **под его identity**: видит всю переписку этого демона,
  отвечает от его имени и может вызвать любой IPC-запрос (в том числе `ExportBackup`,
  `Shutdown`). Запускайте только код, которому доверяете как самому себе.
- **Бот с отдельной identity** (свой seed, свои контакты, свой ratchet с каждым собеседником) —
  отдельный экземпляр демона: `aira-daemon --data-dir <dir> --socket <path>` или
  `AIRA_DATA_DIR=<dir>` (появится в M19b). SDK не меняется — указываете путь к сокету.
- **Аутентификация:** с M19b демон требует токен `<data_dir>/ipc.token`; `run_bot` читает его
  сам (`DaemonClient::connect_with_token`). Scoped-токены (`read-only`, `reply-only`) — M27;
  до этого единственный способ ограничить бота — отдельный демон.

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

# Бот со своей identity (после M19b): отдельный демон с отдельным seed и сокетом
AIRA_DATA_DIR=~/.aira-bot cargo run -p aira-daemon -- --socket ~/.aira-bot/daemon.sock
# путь к сокету/токену для бота — через конфиг SDK (форма фиксируется в M19b)
```

## Trait `Bot`

Все методы имеют реализацию по умолчанию (no-op). Переопределите только те
события, на которые ваш бот должен реагировать. Трейт использует RPITIT
(`impl Future + Send`) и **не object-safe** — используйте `impl Bot`/generics, не `dyn Bot`.

| Метод | Когда вызывается | Статус |
|-------|-----------------|--------|
| `on_message` | Получено текстовое сообщение (DM) | после M19 |
| `on_contact_online` | Контакт появился в сети | после M19 |
| `on_contact_offline` | Контакт ушёл из сети | после M19 |
| `on_group_message` | Получено текстовое сообщение в группе | группы отключены в бете; M25/M27 |
| `on_group_member_joined` | Участник вступил в группу | M25/M27 |
| `on_group_member_left` | Участник покинул группу | M25/M27 |
| `on_group_invite` | Получено приглашение в группу | M25/M27 |

Планируется в M27: `on_contact_added` (после принятия contact request), `on_command`
(`/start`, `/help`, …).

## `BotContext`

Обёртка над IPC-клиентом с удобными методами:

| Метод | Описание | Примечание |
|-------|----------|------------|
| `reply(to, text)` | Отправить текстовое сообщение контакту | — |
| `send_file(to, path)` | Отправить файл контакту | — |
| `contacts()` | Получить список контактов | — |
| `history(contact, limit)` | Получить историю сообщений | `payload_bytes` = postcard(`MessageMeta`) после M19 |
| `my_address()` | Получить собственный публичный ключ | ⚠️ создаёт **новый** псевдоним при каждом вызове — не опрашивайте в цикле; в M19 заменяется на `my_invitation()` → ссылка `aira://add/…` со стабильным псевдонимом |
| `send_group_message(group_id, text)` | Отправить сообщение в группу | в бете демон отвечает `Error` (группы отключены) |

`BotContext` реализует `Clone` — его можно безопасно передавать в spawned tasks.

## Архитектура

```
┌─────────────┐     IPC      ┌──────────────┐
│  aira-bot   │◄────────────►│ aira-daemon  │
│  (ваш бот)  │  postcard    │  (сеть, БД)  │
└─────────────┘  len-prefix  └──────────────┘
```

Бот использует тот же IPC-протокол, что и CLI (`aira-cli`) и GUI.
Общий клиент находится в `aira-daemon::client` (в M19 выделяется в крейт `aira-ipc` вместе
с единым декодером событий для всех клиентов).

## Ограничения (сентябрь 2026)

- Бот подключается к демону текущего пользователя и видит **всю** его переписку; отдельная
  identity = отдельный демон (`AIRA_DATA_DIR`, M19b)
- Аутентификация IPC-токеном — с M19b; до этого к демону может подключиться любой локальный процесс
- Бот видит только текстовые сообщения (`PlainPayload::Text` и `Action`); до M19 демон, CLI, GUI и
  бот используют три несовместимых формата `MessageReceived.payload`, поэтому текст до бота не дойдёт —
  единый контракт `MessageMeta` вводится в M19
- `my_address()` создаёт новый псевдоним при каждом вызове — используйте `my_invitation()` (M19)
- Группы: `on_group_*` и `send_group_message` в бете не работают (M25, для ботов — M27)
- Нет `is_bot` в профиле (профили — M28, флаг — M27), нет `on_contact_added`/`on_command` (M27)
- Файловые события (progress, complete, error) не доставляются боту
- Rate limits применяются демонами получателей к сетевому пиру, не к боту как IPC-клиенту
- WASM sandbox для изоляции ботов — M27+, не в 1.0
