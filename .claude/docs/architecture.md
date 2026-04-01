# Архитектура Aira

> Детальная спека: `SPEC.md` (корень репозитория)

## Слои системы

```
┌─────────────────────────────────────────────────┐
│  CLI (ratatui) / Desktop GUI (egui) / Mobile    │  aira-cli / aira-gui / aira-ffi
├─────────────────────────────────────────────────┤
│  Daemon (IPC через Unix socket / Named pipe)    │  aira-daemon
├─────────────────────────────────────────────────┤
│  Application Layer                              │
│  • Contacts, message history, file transfer API  │  aira-core
├─────────────────────────────────────────────────┤
│  Messaging Layer                                │
│  • Triple Ratchet / SPQR (PQ forward secrecy)   │  aira-core
│  • Message framing, ordering, padding           │
├─────────────────────────────────────────────────┤
│  Session Layer                                  │
│  • PQXDH handshake                              │  aira-core
│  • Hybrid KEM: X25519 + ML-KEM-768             │
│  • Identity: ML-DSA-65                          │
├─────────────────────────────────────────────────┤
│  Transport Layer                                │
│  • iroh 0.97 (QUIC/noq + NAT traversal)        │  aira-net
│  • Relay store-and-forward (pairwise mailboxes) │
├─────────────────────────────────────────────────┤
│  Obfuscation Layer (pluggable)                  │  aira-net
│  • direct / obfs4 / mimicry / REALITY / Tor     │
└─────────────────────────────────────────────────┘
```

## Крейты

| Крейт | Зависит от | Назначение |
|-------|-----------|-----------|
| `aira-core` | — | Крипто, протокол, ratchet, i18n |
| `aira-net` | aira-core | iroh, relay, transports |
| `aira-storage` | aira-core | redb база данных |
| `aira-daemon` | core + net + storage | Фоновый процесс, IPC |
| `aira-cli` | aira-core (через IPC) | ratatui TUI |
| `aira-gui` | aira-core (через IPC) | egui desktop GUI |
| `aira-ffi` | core + net + storage | UniFFI для Android/iOS |

## Важные инварианты

1. **Relay никогда не хранит файлы** — только зашифрованные сообщения (≤64 KB)
2. **Файловая передача (iroh-blobs) требует оба пира онлайн**
3. **Каждый ключ — ровно один контекст** (см. docs/KEY_CONTEXTS.md)
4. **aira-core и aira-storage — только safe Rust** (`#![deny(unsafe_code)]`)

## Roadmap (Milestones)

| Milestone | Версия | Содержание |
|-----------|--------|-----------|
| M1 | 0.1.0 | Core crypto: seed, KEM, handshake, Triple Ratchet |
| M2 | 0.1.1 | Networking: iroh, relay, pairwise mailboxes |
| M3 | 0.1.2 | Storage + Daemon: redb, IPC, disappearing messages |
| M4 | 0.1.3 | File transfer: iroh-blobs |
| M5 | 0.1.4 | CLI: ratatui TUI, все команды |
| M6 | 0.2.0 | Groups: Sender Keys + causal ordering |
| M7 | 0.2.1 | DPI resistance: obfs4, mimicry, CDN relay |
| M8 | 0.3.0 | Multi-device: Linked Devices Protocol |
| M9 | 0.3.1 | Desktop GUI: egui/eframe |
| M10 | 0.3.2 | Android: UniFFI + Kotlin |
| M11 | 0.3.3 | iOS: UniFFI + Swift |
| M12 | 0.3.4 | REALITY + Tor transport |
| M13 | 0.3.5 | aws-lc-rs FIPS 140-3 crypto backend |
