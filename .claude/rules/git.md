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
- `net` — aira-net (iroh, endpoint, framing, blobs)
- `relay` — aira-relay (M21)
- `onion` — aira-onion (M24b)
- `storage` — aira-storage (redb)
- `daemon` — aira-daemon (IPC, event loop)
- `cli` — aira-cli (TUI)
- `gui` — aira-gui (egui)
- `ffi` — aira-ffi (UniFFI)
- `deps` — зависимости
- `config` — конфигурация
- `ci` — workflows, supply chain

## Ветки (решение владельца 24.09.2026)

```
main          # единственная долгоживущая ветка; защищена ruleset'ом, только через PR
feat/*        # новые фичи
fix/*         # баг-фиксы
milestone/*   # работа над конкретным milestone из spec/18-milestones.md (например milestone/18-iroh-pq)
```

- Ветки `dev` нет; упоминания `dev`/`milestone/M10-*` в CI-триггерах удаляются в M18.
- Теги `v*` ставит только CI-job `verify` (тег ↔ версия в `Cargo.toml` ↔ зелёный `main`); тег никогда не переставляется.
- `release.sh` не пушит мимо PR.

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
- `0.4.x` — M18–M22 (bridge-релизы без обещания совместимости)
- `0.5.0-beta.N` — M23 (публичная бета)
- `0.6.x` — M24–M28; `1.0` — после внешнего аудита
