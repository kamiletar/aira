# Правила Git

## Формат коммитов

```
<type>(<scope>): <description>
```

### Типы

| Тип        | Описание                            |
| ---------- | ----------------------------------- |
| `feat`     | Новая функциональность              |
| `fix`      | Исправление бага                    |
| `refactor` | Рефакторинг без изменения поведения |
| `docs`     | Документация                        |
| `test`     | Тесты                               |
| `chore`    | Обслуживание (deps, config)         |
| `perf`     | Оптимизация производительности      |
| `security` | Исправление уязвимости              |

### Scope

- `core` — aira-core (крипто, протокол, ratchet)
- `net` — aira-net (iroh, relay, transports)
- `storage` — aira-storage (redb)
- `daemon` — aira-daemon (IPC, event loop)
- `cli` — aira-cli (TUI)
- `gui` — aira-gui (egui)
- `ffi` — aira-ffi (UniFFI)
- `deps` — зависимости
- `config` — конфигурация

## Ветки

```
main          # стабильная
dev           # разработка
feat/*        # новые фичи
fix/*         # баг-фиксы
milestone/*   # работа над конкретным milestone из SPEC.md
```

## Правила

- Коммиты на английском (для международного проекта)
- Один коммит = одно логическое изменение
- Не коммитить `.env`, `*.key`, `*.pem`, `*.redb` (тестовые базы)
- Делать коммит сразу после готовых изменений
- Перед коммитом: `cargo fmt` → `cargo clippy -- -D warnings` → `cargo test`
- При изменении крипто-кода — обязательно обновить тесты

## Версионирование

Версия в `Cargo.toml` workspace — семантическое версионирование:
- `0.1.x` — Milestone 1-5 (CLI MVP)
- `0.2.x` — Milestone 6-7 (groups + DPI)
- `0.3.x` — Milestone 8-13 (multi-device + GUI + mobile)
