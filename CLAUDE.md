# CLAUDE.md — Aira

Этот файл содержит инструкции для Claude Code при работе с кодом в этом репозитории.

## Общайся со мной на русском

## Проект

**Aira** — постквантовый P2P мессенджер на Rust. Спека разбита на `spec/*.md`, индекс в `SPEC.md`.

## Технологический стек

- **Язык:** Rust (edition 2021) | **Async:** tokio 1
- **Сеть:** iroh 0.97+ (QUIC/noq + NAT traversal + relay)
- **Крипто (phase 1):** ml-kem 0.2, ml-dsa 0.1, x25519-dalek 2, chacha20poly1305, blake3, argon2
- **Хранилище:** redb 2 (embedded, pure Rust)
- **CLI:** ratatui 0.29 + crossterm 0.28
- **Сериализация:** postcard 1 + serde
- **i18n:** fluent 0.16 (Mozilla Fluent)
- **FFI:** uniffi 0.28 (Android/iOS биндинги)

## Структура крейтов

```
crates/
├── aira-core/      # криптография, протокол, ratchet — все платформы
├── aira-net/       # iroh, NAT traversal, relay, pluggable transports
├── aira-storage/   # redb хранилище — все платформы
├── aira-daemon/    # фоновый процесс, IPC сокет
├── aira-cli/       # ratatui TUI
├── aira-gui/       # egui/eframe desktop GUI (v0.3)
├── aira-bot/       # Bot SDK для написания ботов (v0.2)
└── aira-ffi/       # UniFFI биндинги для Android (v0.3, iOS исключён)
```

## Методология

- **TDD:** Red → Green → Refactor
- **Milestone-driven:** сначала реализуй milestone по плану в SPEC.md (раздел 16)
- **Коммиты:** делай автоматически после готовых изменений, поднимай версию в root Cargo.toml
- **Документируй:** находки и особенности добавляй в `.claude/docs/`

## Команды

```bash
cargo build                        # сборка всех крейтов
cargo test                         # все тесты
cargo test -p aira-core            # тесты конкретного крейта
cargo clippy -- -D warnings        # линтинг
cargo fmt                          # форматирование
cargo audit                        # уязвимости в зависимостях
cargo deny check                   # лицензии и дубли
cargo fuzz run <target>            # фаззинг (cargo-fuzz)
```

**Перед коммитом:** `cargo fmt` → `cargo clippy -- -D warnings` → `cargo test`

## Безопасность — критичные правила

**Key Isolation (обязательно):** каждый ключ — ровно один криптографический контекст.
Все KDF-контексты задокументированы в `docs/KEY_CONTEXTS.md`. Нарушение = блок PR.

**Запрещено в `aira-core` и `aira-storage`:** `#![deny(unsafe_code)]` — нет unsafe кода.
В других крейтах `unsafe` допустим только с `// SAFETY:` комментарием.

**Секреты в памяти:** все секретные ключи через `zeroize::Zeroizing<_>` — автоочистка при Drop.

**Никакого `unwrap()`** в production коде (только в тестах). Используй `?` и `thiserror`.

## Импорты (важные паттерны)

```rust
// Seed-фраза и деривация ключей
use crate::seed::MasterSeed;

// Постквантовая криптография
use ml_kem::MlKem768;
use ml_dsa::MlDsa65;

// Хэширование и KDF
use blake3;

// Сериализация (вместо bincode — postcard)
use postcard;

// Секреты в памяти
use zeroize::Zeroizing;
```

## Код-стиль

- Комментарии в коде: **английский**
- Документация и README: **русский**
- Каждый публичный API — docstring с примером
- `#![warn(clippy::all, clippy::pedantic)]` везде
- Константы вместо magic numbers

## MCP серверы

context7 (docs), sequential-thinking (сложные алгоритмы), agent-mail (координация)

## Git

Ветки: `main` (стабильная), `dev` (разработка), `feat/*`, `fix/*`
Коммиты: conventional commits (`feat(core):`, `fix(net):`, `chore(deps):`)
Scope: `core`, `net`, `storage`, `daemon`, `cli`, `gui`, `ffi`, `deps`, `config`

---

**Spec:** `SPEC.md` | **Обновлено:** апрель 2026 | **Rust** edition 2021 | **iroh** 0.97
