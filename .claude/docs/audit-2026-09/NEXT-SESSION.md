# Продолжение в следующей сессии — состояние на 2026-09-23 (фаза 3 D–G, сессия claude/vigilant-sagan-9kta8v)

## Что сделано (кумулятивно)

1. **Аудит готовности к релизу** — `.claude/docs/release-audit-2026-09.md` (главный документ, §0–§8).
   Полные отчёты — в этой папке: `facts-crates.md`, `relay-deploy-plan.md`, `pq-crypto-migration.md`,
   `pow-antiabuse.md`, `core-audit.md`, `clients-audit.md`, `daemon-storage-audit.md`, `spec-drift-audit.md`,
   `release-2026-requirements.md`, `security-compliance-audit.md` (A), `net-audit.md` (B),
   `test-coverage-audit.md` (C), `spec-remainder-audit.md` (E), `onion-antiabuse.md` (G),
   `ci-supply-chain-audit.md` (D), `community-relays.md` (F); сырые сводки агентов — `raw/*`.
2. **Планы** — `spec/18-milestones.md` §16.1 + M18–M23; две ⚠️-заметки в начале §16.1 перечисляют правки из
   аудита §8, **ещё не внесённые в текст милстоунов**.
3. Тема владельца 23.09 — «протокол нельзя превратить в паразитирующий прокси» + «скрыть IP хоп-хоп-хоп» +
   «задействовать всех пиров» + «список relay = блок-лист РКН» → отчёт **G** `onion-antiabuse.md` (дизайн
   Aira Onion v1, инварианты AP-1…AP-7, ответ «все пиры — да, с ограничениями по классу устройства и
   юрисдикции», M24a–M24e) и выжимка §8.7.

## Статус тем фазы 3

| # | Тема | Файл | Статус |
|---|---|---|---|
| A | Security-compliance | `security-compliance-audit.md` | ✅ отчёт + §8.1 |
| B | aira-net | `net-audit.md` | ✅ отчёт + §8.2 (⚠️ §3 про `postcard(ep.addr())` в ссылке — отменено G: ссылка без IP) |
| C | Тесты/фаззинг | `test-coverage-audit.md` | ✅ отчёт + §8.3 |
| D | CI/CD и supply chain | `ci-supply-chain-audit.md` | ✅ отчёт (848 строк) + §8.4 + `raw/2026-09-24-D-summary.md` |
| E | Остаток спеки (группы, мультидевайс, боты, §6.x, Tauri) | `spec-remainder-audit.md` | ✅ отчёт + §8.5 + `raw/2026-09-23-E-summary.md` |
| F | Community relays (standalone aira-relay, relay в клиенте, N-of-M) | `community-relays.md` | ✅ отчёт (518 строк) + §8.6 + `raw/2026-09-24-F-summary.md`; нумерация M24a/M24b |
| G | Скрытие IP + анти-паразитный форвардинг, все пиры как хопы | `onion-antiabuse.md` | ✅ отчёт + §8.7 + заметка в spec §16.1 |

## Что осталось (по порядку)

1. Фаза 3 (A–G) завершена; все отчёты и выжимки §8.1–§8.7 на месте. Сводный список решений владельца —
   `owner-decisions.md` (A: до M18/M19, B: до беты, C: после, D/F: CI и relay). Самые срочные (до M18/M19):
   iroh 1.2; LICENSE-MIT/APACHE + README до тега v0.4.0; CI-гварды (CI красный с 10.04); `hide_ip` по
   умолчанию; ссылка без IP; iroh SecretKey per-device; контракт `MessageReceived`; группы/мультидевайс/боты
   в бете отключить; REALITY исключить; transport/* удалить.
2. Получить ответы владельца по `owner-decisions.md` (хотя бы группа A) — без них правки планов ниже
   останутся с развилками.
3. **Внести правки планов из §8.1–§8.7 в текст M18–M23** `spec/18-milestones.md` и добавить M24a–M24e,
   M25–M28 (нумерация: M24a каталог relay + community-server-relay, M24b client-relay, M24c Aira Onion v1, M24d мосты/обфускация, M24e mix;
   M25 группы v2, M26 мультидевайс v2, M27 Bot API v2, M28 §6.x). Спека: новый §5.5 «Aira Onion»
   (`spec/03-network.md`), §11/§11A/§11B.5/§6.22 по §8 G, 33 правки из E §5, §6.5.3 главного документа.
4. Запуск M18 (дедлайн **30.09.2026** — отключение публичных relay n0 для iroh 0.9x; целевая версия iroh 1.2).

## Ключевые выводы (чтобы не перечитывать всё)

- Блокер №0: демон не в сети; блокер №1: iroh 0.97 → 1.2 до 30.09 (тянет ml-dsa 0.1.1 + ml-kem 0.3).
- aira-core протокол v1 к релизу не готов (C1–C7) → M19a до wiring; группы/мультидевайс/боты — не готовы
  вовсе (E), в бете отключить.
- Сеть: два relay на mail-сервере (iroh-relay stateless + aira-relay mailbox v2); каждый клиент **не**
  должен регистрировать `RelayServer` (B); **relay-only (`hide_ip`) по умолчанию** и ссылка без IP (G).
- Anti-abuse: per-action adaptive PoW + contact-first; PoW на ключ — не делать (§5.3); те же PoW/квоты —
  для `HopSetup` в onion (G).
- Onion (G): «все форвардят» = защита от паразитов при инвариантах AP-1…AP-7; глобального каталога relay
  нет (РКН); хоп-идентичность отдельно от чат-идентичности; M24c–d после M21.
- Релиз 2026: SignPath (Windows), Apple $99, Flathub исключить, Android developer verification (§6.6).
- CI/supply chain (D): CI на `main` красный с 10.04 (18 advisories, clippy 1.98); нет LICENSE-файлов и README;
  release.yml с write-токеном исполняет непроверенный linuxdeploy; 0 SHA-пинов; SLSA L2 к бете.
- Community relays (F): один бинарь `aira-relay` со встроенным iroh-relay + токен допуска; один home relay на
  endpoint → watchdog re-home + 2–3 `RelayRef`; client-relay только транспорт (opt-in), push-URL = SSRF-вектор.

## Оговорка про номера строк

Отчёты цитируют `spec/18-milestones.md:NNN` по состоянию на момент написания; ⚠️-заметки в начале §16.1
(07.09 и 23.09) сдвинули всё ниже строки 398 на +2 каждая. Отчёты A–C и F/D цитируют старую нумерацию,
E — сдвиг +2, G — актуальную. При переносе правок в спеку ориентироваться на текст пунктов, не на номера.

## Инструменты/окружение (эта сессия — облако, Linux)

- Зависимости скачаны `cargo fetch` (iroh 0.97/1.2, iroh-relay 1.2 в `~/.cargo/registry`); `cargo audit`/
  `cargo deny` не установлены. Сборка/тесты не запускались.
- WebSearch работает; WebFetch к arxiv.org и blog.torproject.org заблокирован egress-прокси.
- Агенты D/E/F запускались параллельно (лимит сессии здесь не мешает), G — вручную.
