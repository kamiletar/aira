# Продолжение в следующей сессии — состояние на 2026-09-24 (вечер): аудит и документация завершены, следующий шаг — M18

## Что сделано (кумулятивно, всё в `main`)

1. **Аудит готовности к релизу** — `.claude/docs/release-audit-2026-09.md` (§0–§8). Полные отчёты фазы 3 A–G — в этой
   папке (`security-compliance-audit.md`, `net-audit.md`, `test-coverage-audit.md`, `ci-supply-chain-audit.md`,
   `spec-remainder-audit.md`, `community-relays.md`, `onion-antiabuse.md`); сводки агентов — `raw/*`.
2. **Решения владельца** — `owner-decisions.md`: 24.09 получено 17 решений (A1–A4, A6, A11–A13, B1, B4, B6, B10, C4, C5, C16,
   D4–D6, D9, F1/F2), остальные приняты по рекомендации; открыто: B2/F10 (бюджет второго anchor-VPS и `relays.<domain>`),
   C1 (группы до/после 1.0), C2 (подпись групповых конвертов), C3 (модель мультидевайса), C6 (strict-список стран),
   C11 (имя фичи onion), C13 (браузер), C17 (подпись invitation link vs QR), D1 (настройки GitHub — действие владельца).
3. **Спека приведена к аудиту и решениям (24.09):** `SPEC.md` v0.5; `spec/18-milestones.md` §16.1 + M18–M28 полностью
   переписаны (1 511 строк; M22-infra; M24a.1/a.2 community relays, M24b Aira Onion, M24c мосты, M24d mix; M25–M28);
   `spec/03` (§5.1.1 роли relay, §5.3 каталог, §5.5 Aira Onion нормативно), `spec/04` (§6.3b mailbox v2, per-file ключ),
   `spec/08` (§6.22), `spec/13` (§11/§11A/§11B), `docs/KEY_CONTEXTS.md` (статусы, план-контексты), 16 файлов точечных
   правок из E (`spec/01,02,05,06,07,09,10,11,12,14,15,16,17,19,20`, `docs/BOT_SDK.md`).
4. **Документы репозитория:** `README.md`, `SECURITY.md`, `LICENSE-MIT`, `LICENSE-APACHE`, `docs/THREAT_MODEL.md`,
   `docs/PRIVACY.md`; `docs/INSTALL.md` честно про 0.3.5 без сети / APK / glibc / подписи; `CLAUDE.md`, `.claude/rules/*`,
   `.claude/docs/*` обновлены под решения (ветки только `main` + PR, AP-инварианты, hide_ip, Debug без секретов).

## Что делать дальше (по порядку)

1. **Старт M18** (`spec/18-milestones.md` § Milestone 18; дедлайн ядра миграции — **30.09.2026**): ветка `milestone/18-iroh-pq`,
   шаг 0 — snapshot-векторы с тега v0.3.5 (`git worktree add ../aira-v035 v0.3.5`), затем Cargo bump (iroh 1.2, iroh-blobs
   0.103, ml-dsa 0.1.1, ml-kem 0.3.2, rust-version 1.91), `endpoint.rs:78` `empty_builder` → `presets::Minimal`,
   `rustcrypto.rs`/`awslc.rs`, удаление `transport/*`, CI-гварды (п.8), workspace-линты, фаззинг (п.7). PR в `main`, тег
   `v0.4.0` через job `verify`.
2. Параллельно (владелец, не код): D1 — настройки GitHub (rulesets `main`/`v*`, Dependabot alerts, secret scanning,
   private vulnerability reporting), заявка в SignPath Foundation (LICENSE и README уже есть), генерация minisign-ключа
   (офлайн + бэкап ×2), решение по B2/F10 (второй VPS).
3. Затем M19a → M19 (+ M19b, M20, M22-infra параллельно) → M21 → M22 → M23 по спеке.

## Ключевые выводы (чтобы не перечитывать всё)

- Блокер №0: демон не в сети; блокер №1: iroh 0.97 → 1.2 до 30.09 (тянет ml-dsa 0.1.1 + ml-kem 0.3.2).
- Протокол v1 к релизу не готов (C1–C7) → M19a до wiring; группы/мультидевайс/боты в бете отключены.
- Сеть: `hide_ip = true` по умолчанию, ссылка без IP, RelayMap = свои relay, клиент не регистрирует `RelayServer`;
  два relay (iroh-relay + aira-relay в одном бинаре); один home relay на endpoint → watchdog + `RelayRef` ×2–3.
- Anti-abuse: adaptive PoW со `slot`, `ContactStamp` вместо «PoW на ключ»; токены допуска relay.
- Onion (M24b): «все форвардят» = защита от паразитов при инвариантах AP-1…AP-7; глобального каталога нет.
- CI красный с 10.04 (18 advisories + clippy 1.98) — чинится в M18 п.8; релиз 2026: SignPath + minisign, без Apple/Android
  verification, Linux в контейнере 22.04, SLSA L2 к бете.

## Оговорка про номера строк

Отчёты цитируют `spec/18-milestones.md:NNN` по состоянию на момент написания; после переписки 24.09 нумерация строк
спеки другая — ориентироваться на текст пунктов (M19 п.7/п.10/п.12 и т.п. сохранены), не на номера. Номера строк
**кода** (`crates/**`) актуальны: исходники не менялись с тега v0.3.5.

## Инструменты/окружение (сессия 23–24.09 — облако, Linux)

- Зависимости скачаны `cargo fetch` (iroh 0.97/1.2, iroh-relay 1.2 в `~/.cargo/registry`); `cargo audit`/`cargo deny` не
  установлены; сборка/тесты не запускались (docs-only сессия).
- WebSearch работает; WebFetch к arxiv.org, blog.torproject.org, docs.github.com, letsencrypt.org и части doc-сайтов
  заблокирован egress-прокси.
- Агенты запускались параллельно по непересекающимся файлам; `phase3-workflow.js` — исторический.
