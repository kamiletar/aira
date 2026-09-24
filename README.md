# Aira

Постквантовый P2P-мессенджер на Rust: ML-KEM-768 + X25519 (гибридный KEM), ML-DSA-65 (идентичность),
Triple Ratchet с PQ-шагом, iroh (QUIC + NAT traversal), redb, egui/ratatui.

> **Статус: pre-release.** Версия 0.3.5 содержит криптоядро, хранилище, демон и клиенты (GUI, CLI, Android preview),
> но **сетевой слой ещё не подключён к демону**: сообщения сохраняются локально и не доставляются между устройствами.
> Публичная бета (`0.5.0-beta`) выйдет после релизного пути M18–M23 (`spec/18-milestones.md` §16.1).
> Не используйте 0.3.x для реальной переписки.

## Что обещает Aira (и чего пока нет)

| Свойство | 0.3.5 | Бета 0.5 (план) | 1.0 (план) |
|---|---|---|---|
| Сквозное шифрование с постквантовым KEM | ядро есть, сеть не подключена | да (протокол v2) | да |
| Forward secrecy / PQ-ratchet | ядро есть (PQ-шаг не активен) | да | да |
| Офлайн-доставка через mailbox-relay | нет | да (`aira-relay`) | да, relay сообщества |
| IP скрыт от собеседника | нет | **да** (relay-only по умолчанию) | да |
| IP скрыт от оператора relay | нет | нет (честно в THREAT_MODEL) | да, Aira Onion (все пиры — хопы) |
| Устойчивость к блокировкам | нет | relay на своём домене | мосты без каталога, обфускация |
| Группы, мультидевайс, боты | примитивы в коде | отключены | после 1.0 или отдельным милстоуном |

Подробно — [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) и [docs/PRIVACY.md](docs/PRIVACY.md). Слов «анонимный»
и «невзламываемый» в проекте нет намеренно: обещания сформулированы по конкретным наблюдателям.

## Установка

[docs/INSTALL.md](docs/INSTALL.md) — инсталляторы для Windows, macOS, Linux и Android preview (см. ограничения там же).

## Сборка из исходников

```bash
git clone https://github.com/kamiletar/aira
cd aira
cargo build --release          # Rust stable (MSRV 1.91 после M18)
cargo test --workspace
```

Linux: для GUI нужны `libgtk-3-dev`, `libxdo-dev`, `libxcb-*`.

## Документация

- [SPEC.md](SPEC.md) — спецификация (индекс), разделы в `spec/`.
- [spec/18-milestones.md](spec/18-milestones.md) — релизный путь M18–M28.
- [docs/KEY_CONTEXTS.md](docs/KEY_CONTEXTS.md) — все KDF-контексты (Key Isolation).
- [docs/BOT_SDK.md](docs/BOT_SDK.md) — Bot SDK (после беты).
- `.claude/docs/release-audit-2026-09.md` — аудит готовности к релизу (сентябрь 2026).

## Безопасность

Уязвимости — по [SECURITY.md](SECURITY.md). Внешний аудит криптоядра запланирован перед 1.0.

## Вклад

Ветка `main` защищена, изменения через PR. Коммиты — conventional commits. Правила: `.claude/rules/`.
Перед коммитом: `cargo fmt` → `cargo clippy -- -D warnings` → `cargo test`.

## Лицензия

MIT OR Apache-2.0, на выбор получателя: [LICENSE-MIT](LICENSE-MIT), [LICENSE-APACHE](LICENSE-APACHE).
