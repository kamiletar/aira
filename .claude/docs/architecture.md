# Архитектура Aira

> Детальная спека: `SPEC.md` (индекс) и `spec/*.md`. Релизный путь — `spec/18-milestones.md` §16.1.
> Состояние кода на сентябрь 2026 — `.claude/docs/release-audit-2026-09.md` (§0 резюме).

## Слои системы

```
┌─────────────────────────────────────────────────┐
│  CLI (ratatui) / Desktop GUI (egui) / Android   │  aira-cli / aira-gui / aira-ffi (бета: egui + CLI; Android preview)
├─────────────────────────────────────────────────┤
│  Daemon (IPC через Unix socket / Named pipe)    │  aira-daemon
├─────────────────────────────────────────────────┤
│  Application Layer                              │
│  • Contacts, message history, file transfer API │  aira-core / aira-storage
├─────────────────────────────────────────────────┤
│  Messaging Layer                                │
│  • Triple Ratchet / SPQR (PQ forward secrecy)   │  aira-core
│  • Wire v2: header как AAD, padding, dedup      │
├─────────────────────────────────────────────────┤
│  Session Layer                                  │
│  • PQXDH-подобный handshake (v2, M19a)          │  aira-core
│  • Hybrid KEM: X25519 + ML-KEM-768              │
│  • Identity: ML-DSA-65; per-contact pseudonyms  │
├─────────────────────────────────────────────────┤
│  Anonymity Layer (план, M24b–M24d)              │  aira-onion + aira-net
│  • Aira Onion: все пиры — хопы, mailbox в узле  │
├─────────────────────────────────────────────────┤
│  Transport Layer                                │
│  • iroh 1.2 (QUIC/noq + NAT traversal)          │  aira-net
│  • hide_ip: relay-only по умолчанию             │
│  • iroh-relay (транспорт) / aira-relay (mailbox)│  aira-relay (M21)
│  • Мосты: CustomTransport-обфускация (M24c)     │
└─────────────────────────────────────────────────┘
```

## Крейты

| Крейт | Зависит от | Назначение | Статус |
|-------|-----------|-----------|--------|
| `aira-core` | — | Крипто, протокол, ratchet, i18n | код; протокол v2 в M19a |
| `aira-net` | aira-core | iroh, endpoint, framing, blobs, (hop.rs — M24b) | код без интеграции в демон; `transport/*` удаляется в M18 |
| `aira-storage` | aira-core | redb | код; schema_version/миграции в M19 |
| `aira-daemon` | core + net + storage | Фоновый процесс, IPC | код; сеть подключается в M19 |
| `aira-cli` | через IPC | ratatui TUI | код |
| `aira-gui` | через IPC | egui desktop GUI | код (основной клиент беты) |
| `aira-ffi` | core + net + storage | UniFFI для Android | код; preview |
| `aira-bot` | через IPC | Bot SDK | код; в бете отключён, M27 |
| `aira-relay` | core + net | standalone relay: iroh-relay + mailbox v2 | **план, M21** |
| `aira-onion` | core | ячейки, маршруты, SURB, бюджеты хопов (без iroh) | **план, M24b** |

## Важные инварианты

1. **Relay никогда не хранит файлы** — только зашифрованные конверты (≤ 64 KB); mailbox только по регистрации владельца.
2. **Файлы ≥ 1 MB шифруются per-file ключом из ratchet** (M19a); iroh-blobs переносит только шифротекст.
3. **Каждый ключ — ровно один контекст** (`docs/KEY_CONTEXTS.md`); хоп-идентичность — из локального RNG, не из seed.
4. **aira-core, aira-storage, aira-onion — только safe Rust** (`#![deny(unsafe_code)]`).
5. **IP скрыт от собеседника по умолчанию** (relay-only); прямое соединение — осознанный per-contact выбор.
6. **Любой форвардящий код соблюдает AP-1…AP-7** (`spec/03-network.md` §5.5): нет exit, следующий хоп только из своей таблицы, фиксированные ячейки, тарифицированные байты, хоп не источник, хранилище по регистрации.
7. **Клиент не регистрирует `RelayServer`** — иначе каждый клиент становится открытым mailbox без auth.

## Релизный путь (сентябрь 2026)

```
M18 (iroh 1.2 + PQ-крейты + CI-гварды + LICENSE, дедлайн 30.09) → M19a (протокол v2) → M19 (демон в сети)
   ‖ параллельно: M19b (клиенты), M20 (свой iroh-relay), трек M22-infra (подпись, attestations, SBOM)
→ M21 (aira-relay mailbox v2) → M22 (anti-abuse) → M23 (бета 0.5: egui + CLI, Android preview)
→ M16 → M25 (группы v2) → M17 (Tauri) → M24a/M24b (community relays, Aira Onion) → M24c (мосты) → 1.0
→ M24d (mix) → M26 (мультидевайс v2) → M28 (§6.x) → M15 → M27 (Bot API v2) → M14 (браузер)
```

Версии: `0.4.x` — M18–M22, `0.5.0-beta.N` — M23, `0.6.x` — M24–M28, `1.0` — после внешнего аудита.
Исторические M1–M13 — в `spec/18-milestones.md` (статус по коду — `.claude/docs/audit-2026-09/spec-drift-audit.md`).
