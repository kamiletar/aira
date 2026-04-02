# SPEC: Aira — постквантовый P2P мессенджер на Rust

> Техническое задание для агента Claude Code.\
> Версия: 0.2 | Дата: апрель 2026 | Обновлено после исследования PQ/P2P ландшафта

[← Индекс](../SPEC.md)

---

## 1. Контекст и цели

Проект создаётся с нуля как замена Tox-подобных мессенджеров. Совместимость
с существующей Tox-сетью **не требуется** — это осознанное архитектурное
решение, позволяющее избавиться от legacy-ограничений 2013 года.

### Цели

- **Memory safety** — 100% safe Rust, `unsafe` только в явно аргументированных
  местах с `// SAFETY:` комментарием
- **Post-quantum security** — устойчивость к атакам квантового компьютера,
  защита от "harvest now, decrypt later"
- **Decentralization** — нет центрального сервера, нет доверенной третьей
  стороны
- **Simplicity** — только чат + передача файлов, никакого голоса/видео

### Не входит в scope v0.1

- Голосовые/видеозвонки
- Групповые чаты (v0.2, см. п. 12)
- Мультидевайс (v0.3, см. п. 14)
- GUI (CLI-first, egui потом, см. п. 15)
- ~~iOS~~ — **исключён из проекта** (iOS убивает фоновые P2P соединения
  через ~30 сек, VPN Extension ограничен 25MB RAM, Briar отказался от iOS
  по тем же причинам; 10% потерь push-уведомлений на SimpleX Chat)

---

## 2. Структура репозитория

Полная структура репозитория — см. п. 15.6.

---

## 3. Архитектура по слоям

```
┌─────────────────────────────────────────────────┐
│  CLI / Future GUI                               │  aira-cli
├─────────────────────────────────────────────────┤
│  Application Layer                              │
│  • Contacts (add/remove/block)                  │  aira-core
│  • Message history                              │
│  • File transfer API                            │
├─────────────────────────────────────────────────┤
│  Messaging Layer                                │
│  • Triple Ratchet / SPQR (PQ forward secrecy)   │  aira-core
│  • Message framing, ordering & padding          │
│  • File chunking & reassembly                   │
├─────────────────────────────────────────────────┤
│  Session Layer                                  │
│  • PQ Handshake (PQXDH)                        │  aira-core
│  • Hybrid KEM: X25519 + ML-KEM-768             │
│  • Identity: ML-DSA-65                          │
├─────────────────────────────────────────────────┤
│  Transport Layer                                │
│  • iroh 0.97+ (QUIC/noq + NAT traversal)       │  aira-net
│  • Peer discovery (iroh + DHT)                  │
│  • Relay store-and-forward (pairwise mailboxes) │
├─────────────────────────────────────────────────┤
│  Obfuscation Layer (pluggable, п. 11A)          │  aira-net
│  • direct / obfs4 / mimicry / REALITY / Tor     │
└─────────────────────────────────────────────────┘
```
