# SPEC: Aira — постквантовый P2P мессенджер на Rust

> Техническое задание для агента Claude Code.\
> Версия: 0.5 | Дата: сентябрь 2026 | Релизный путь M18–M23 (§16.1), пересмотр §12/§14/§17A по аудиту 2026-09

---

## Оглавление

Спецификация разбита на отдельные файлы в директории `spec/`.

> **Статус на сентябрь 2026** (аудит `.claude/docs/release-audit-2026-09.md`, решения владельца 24.09 —
> `.claude/docs/audit-2026-09/owner-decisions.md`): релизный протокол — **v2** (M19a, без совместимости
> с 0.3.x), сеть в демоне — M19, offline-доставка — `aira-relay` mailbox v2 (M21), свой iroh-relay +
> pkarr-discovery на своём домене (M20; DHT — после релиза). **Бета 0.5 = egui + CLI** (+ Android preview);
> группы, мультидевайс и Bot API в бете **отключены** (реализация M25/M26/M27 после беты). Транспорты
> `transport/*` (obfs4/mimicry/REALITY/Tor) удалены; `hide_ip = true` по умолчанию; обход блокировок —
> iroh-relay на своём домене, мосты (M24c), Aira Onion (M24b).

### Основы

| # | Раздел | Файл |
|---|--------|------|
| §1-3 | Контекст, цели, архитектура | [01-overview.md](spec/01-overview.md) |
| §4 | Криптографическая схема | [02-crypto.md](spec/02-crypto.md) |
| §5 | Сетевой слой (aira-net): iroh, discovery (pkarr); §5.1.1 свой iroh-relay + iroh-dns-server (M20); §5.5 Aira Onion (план, M24b) | [03-network.md](spec/03-network.md) |

### Протокол сообщений (§6)

| # | Раздел | Файл |
|---|--------|------|
| §6.1-6.3 | Формат пакетов (v2), файлы, offline (§6.3b — `aira-relay`) | [04-protocol-wire.md](spec/04-protocol-wire.md) |
| §6.4-6.6 | Версионирование (v2, `Features`), mailbox v2, padding | [05-protocol-versioning.md](spec/05-protocol-versioning.md) |
| §6.7-6.15 | Сообщения, реакции, receipts, typing (+ таблица статуса §6.7–6.24) | [06-protocol-messaging.md](spec/06-protocol-messaging.md) |
| §6.16-6.18 | Расширяемость (postcard, резерв вариантов), профили, удаление аккаунта | [07-protocol-extensibility.md](spec/07-protocol-extensibility.md) |
| §6.19-6.25 | Block, deniability, dedup, лимиты, разметка | [08-protocol-security.md](spec/08-protocol-security.md) |

### Инфраструктура

| # | Раздел | Файл |
|---|--------|------|
| §7 | Хранилище (aira-storage): таблицы, `meta.schema_version`, шифрование, бэкап v2 | [09-storage.md](spec/09-storage.md) |
| §8 | Daemon и IPC (полный список запросов/событий, аутентификация) | [10-daemon-ipc.md](spec/10-daemon-ipc.md) |
| §9 | CLI (aira-cli) + i18n | [11-cli.md](spec/11-cli.md) |
| §10 | Зависимости (Cargo.toml) — целевые версии M18 | [12-dependencies.md](spec/12-dependencies.md) |

### Безопасность

| # | Раздел | Файл |
|---|--------|------|
| §11+11A+11B | Модель угроз, DPI, DDoS | [13-threat-model.md](spec/13-threat-model.md) |
| §13 | Защита от спама (contact-first, PoW v2, `ContactStamp` — M22) | [15-spam.md](spec/15-spam.md) |

### Расширения (после беты)

| # | Раздел | Файл |
|---|--------|------|
| §12 | Групповые чаты (v2 — M25, после беты; в бете отключены) | [14-groups.md](spec/14-groups.md) |
| §14 | Мультидевайс (M26, после 1.0; в бете отключён) | [16-multidevice.md](spec/16-multidevice.md) |
| §15 | Кроссплатформенность и GUI (бета = egui + CLI; Tauri — M17, между бетой и 1.0) | [17-cross-platform.md](spec/17-cross-platform.md) |

### Управление проектом

| # | Раздел | Файл |
|---|--------|------|
| §16 | Порядок реализации (milestones); §16.1 — релизный путь M18–M23 (сентябрь 2026), M24–M28 после беты | [18-milestones.md](spec/18-milestones.md) |
| §17+17A | Качество кода + Bot API (SDK для собственного демона; v2 — M27) | [19-quality.md](spec/19-quality.md) |
| §18-20 | Открытые вопросы, соглашения, глоссарий | [20-appendix.md](spec/20-appendix.md) |
