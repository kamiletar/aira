# SPEC: Aira — постквантовый P2P мессенджер на Rust

> Техническое задание для агента Claude Code.\
> Версия: 0.2 | Дата: апрель 2026 | Обновлено после исследования PQ/P2P ландшафта

---

## Оглавление

Спецификация разбита на отдельные файлы в директории `spec/`.

### Основы

| # | Раздел | Файл |
|---|--------|------|
| §1-3 | Контекст, цели, архитектура | [01-overview.md](spec/01-overview.md) |
| §4 | Криптографическая схема | [02-crypto.md](spec/02-crypto.md) |
| §5 | Сетевой слой (aira-net) | [03-network.md](spec/03-network.md) |

### Протокол сообщений (§6)

| # | Раздел | Файл |
|---|--------|------|
| §6.1-6.3 | Формат пакетов, файлы, offline | [04-protocol-wire.md](spec/04-protocol-wire.md) |
| §6.4-6.6 | Версионирование, relay mailboxes, padding | [05-protocol-versioning.md](spec/05-protocol-versioning.md) |
| §6.7-6.15 | Сообщения, реакции, receipts, typing | [06-protocol-messaging.md](spec/06-protocol-messaging.md) |
| §6.16-6.18 | Расширяемость, профили, удаление аккаунта | [07-protocol-extensibility.md](spec/07-protocol-extensibility.md) |
| §6.19-6.24 | Block, deniability, dedup, лимиты | [08-protocol-security.md](spec/08-protocol-security.md) |

### Инфраструктура

| # | Раздел | Файл |
|---|--------|------|
| §7 | Хранилище (aira-storage) | [09-storage.md](spec/09-storage.md) |
| §8 | Daemon и IPC | [10-daemon-ipc.md](spec/10-daemon-ipc.md) |
| §9 | CLI (aira-cli) + i18n | [11-cli.md](spec/11-cli.md) |
| §10 | Зависимости (Cargo.toml) | [12-dependencies.md](spec/12-dependencies.md) |

### Безопасность

| # | Раздел | Файл |
|---|--------|------|
| §11+11A+11B | Модель угроз, DPI, DDoS | [13-threat-model.md](spec/13-threat-model.md) |
| §13 | Защита от спама | [15-spam.md](spec/15-spam.md) |

### Расширения (v0.2+)

| # | Раздел | Файл |
|---|--------|------|
| §12 | Групповые чаты (v0.2) | [14-groups.md](spec/14-groups.md) |
| §14 | Мультидевайс (v0.3) | [16-multidevice.md](spec/16-multidevice.md) |
| §15 | Кроссплатформенность и GUI | [17-cross-platform.md](spec/17-cross-platform.md) |

### Управление проектом

| # | Раздел | Файл |
|---|--------|------|
| §16 | Порядок реализации (milestones) | [18-milestones.md](spec/18-milestones.md) |
| §17+17A | Качество кода + Bot API | [19-quality.md](spec/19-quality.md) |
| §18-19 | Открытые вопросы, соглашения | [20-appendix.md](spec/20-appendix.md) |
