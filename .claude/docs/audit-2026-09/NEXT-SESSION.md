# Продолжение в следующей сессии — состояние на 2026-09-07 (поздний вечер, после фазы 3 A–C)

## Что сделано

1. **Аудит готовности к релизу** — `.claude/docs/release-audit-2026-09.md` (главный документ, §0–§7).
   Полные результаты агентов — в этой папке: `facts-crates.md`, `relay-deploy-plan.md`,
   `pq-crypto-migration.md`, `pow-antiabuse.md`, `core-audit.md`, `clients-audit.md`,
   `daemon-storage-audit.md`, `spec-drift-audit.md`, `release-2026-requirements.md`;
   сырой JSON агентов — `raw/*.json`.
2. **Планы для Sonnet 5** — `spec/18-milestones.md` §16.1 + Milestone 18, 19a, 19, 19b, 20, 21, 22, 23
   и «Пересмотр M9.6 и M14–17» (строки 396–776). Это основной handoff-документ: каждый милстоун
   с файлами, строками, тестами и критериями.
3. Память: `~/.claude/projects/C--web-aira/memory/project_release_audit_2026_09.md`.

Агентов было 10, по одному: 8 успешных (iroh-relay, pow-sybil, core, clients, daemon-storage,
spec-drift, pq-crypto, wasm — см. ниже), offline и release-2026 упали дважды — их темы синтезированы
вручную из спасённых транскриптов (§4.3 и §6.6 аудита).

## Что осталось (по порядку)

1. Все агенты отработали; wasm записан в аудит §6 и в спеку («Пересмотр M14», §14.0 предпосылки).
   Аудит завершён. Документы закоммичены (`9d7cc38` + финальный `docs(spec)` коммит этой сессии).
   ⚠️ **Не включать** в будущие коммиты незакоммиченные `Cargo.toml`/`Cargo.lock` владельца
   (bump ml-dsa rc.4, не собирается — решение: откатить в M18) и `habr_article.md`
   (untracked, правится в M21).
2. Открытые решения владельца по браузеру (аудит §6.5.0): миграция БД 0.3.x через redb 2.6
   `upgrade()` или несовместимость; iOS Safari «не поддерживается»; seed между сессиями браузера
   (повторный derive vs vault); `aira-ipc`/`aira-node` выделять в M19 (рекомендуется).
3. **Правки спеки под §6.5.3 аудита** (устаревшие версии/даты, DERP→iroh-relay, §6.3b iOS,
   дубликат §13 в spec/14-groups.md, версия спеки 0.2 vs 0.4) — можно отдельным `docs(spec)`
   коммитом или в рамках M18/M20/M21/M22, где указано.
4. **Решения владельца** (8 пунктов в §16.1 спеки / §6.5.4 аудита): mailbox v2 две коробки;
   протокол v2 без совместимости; DHT после релиза; убрать Platform::Mobile; порты mail-сервера
   (вариант A/B); Android в бете; developer verification; бюджет подписи.
5. Запуск M18 (дедлайн **30.09.2026** — отключение публичных relay n0 для iroh 0.9x).

## Фаза 3 аудита (начата 2026-09-07 вечером, по указанию «продолжим аудит»)

Области, которые фазы 1–2 не покрыли кодом. Агенты идут **по одному**, каждый сам пишет полный
отчёт в этот каталог (файл указан) и возвращает короткую сводку; выжимка затем переносится в
`release-audit-2026-09.md` как §8–§11 и в планы M18–M23 спеки. Если сессия оборвалась —
смотреть, какие файлы ниже уже существуют, и продолжать со следующего.

| # | Тема | Файл отчёта | Статус |
|---|------|-------------|--------|
| A | Security-compliance по всему workspace (rules/security.md: unwrap/unsafe/zeroize/ct_eq/64 KB, KEY_CONTEXTS.md vs код) | `security-compliance-audit.md` | ✅ отчёт + §8.1 аудита; правки планов ещё не внесены в спеку |
| B | aira-net: endpoint/discovery/relay-клиент/transports, DPI §11A, NAT, invitation link, лимиты | `net-audit.md` | ✅ отчёт + §8.2 аудита; правки планов ещё не внесены в спеку (⚠️ M19 п.7 RelayServer) |
| C | Тесты и фаззинг: непокрытые публичные API, отсутствие `fuzz/`, proptest, интеграционные two-nodes | `test-coverage-audit.md` | ✅ отчёт + §8.3 аудита; правки планов ещё не внесены в спеку |
| D | CI/CD и supply chain: `.github/workflows/*` vs §6.6.5 (пины SHA, permissions, attestations, SBOM, cargo-auditable, release.yml подпись), cargo deny | `ci-supply-chain-audit.md` | ❌ упал по лимиту сессии (~19:00), файла нет — перезапустить |
| E | Остаток спеки: группы §12 (M6/M7), Bot API §17A, мультидевайс §14 — что из этого нужно к 1.0, что отложить | `spec-remainder-audit.md` | ❌ упал по лимиту сессии, файла нет — перезапустить |
| F | Community relays (запрос владельца 07.09 вечером): простота подъёма relay сообществом, режим «стать relay» в клиенте при публичном IP (opt-in, приложение само предлагает), нестабильность клиент-relay → резервирование N-of-M; плюс **отдельный standalone `aira-relay`** (бинарь/Docker/документация оператора) для подъёма на собственном сервере — «чтобы сообщество плодило релеи и повышало отказоустойчивость»; прецеденты chatmail/SimpleX/Nostr NIP-65/Tor Snowflake/Tox | `community-relays.md` | ⏳ не запускался (в скрипте есть, но workflow стартовал раньше) — запустить |

После каждого агента: выжимка в аудит-документ + коммит `docs(audit): …` только docs/spec.

**Как продолжить в следующей сессии (первым делом):**
1. `Workflow({scriptPath: "<скрипт ниже>", resumeFromRunId: "wf_1a8f6c82-919"})` — A/B/C вернутся из кэша,
   D → E → F пойдут по одному (журнал: D и E помечены `failed`, кэша нет; F в скрипте есть).
   Альтернатива без workflow — по одному `Agent` с промптами из скрипта (секция TOPICS, ключи D/E/F).
2. После каждого: выжимка в `release-audit-2026-09.md` §8.4/§8.5/§8.6 (заготовки есть) по образцу §8.1–8.3,
   raw JSON из журнала → `raw/<agentId>.json`, коммит `docs(audit): …`.
3. Затем — **внести правки планов из §8.1–8.6 в `spec/18-milestones.md`** (в §16.1 стоит ⚠️-заметка с
   самым важным; полные списки `plan_changes` — в `raw/a1c5b7cca4e37a69a.json`, `raw/a579b3ceafc9b3851.json`,
   `raw/a2593b8a7011c8976.json`) и собрать все «решения владельца» из §8 в один список для Kami.

Запуск: Workflow `wf_1a8f6c82-919` (task w07uqn76c), скрипт
`…\099428dc-…\workflows\scripts\aira-audit-phase3-sequential-wf_1a8f6c82-919.js`, журнал
`…\subagents\workflows\wf_1a8f6c82-919\journal.jsonl` (в нём — структурированные результаты каждого
агента: file_written, summary, blockers, top_findings, plan_changes, open_questions). Если сессия
оборвалась — `Workflow({scriptPath, resumeFromRunId: "wf_1a8f6c82-919"})` доделает оставшиеся
темы; готовые файлы отчётов выше уже на диске.

## Ключевые выводы (чтобы не перечитывать всё)

- Блокер №0: демон не в сети, `SendMessage` пишет только в redb; «что с сообщением при офлайне
  3 дня» — ничего, никогда (§4.1a).
- Блокер №1: iroh 0.97 → 1.1 до 30.09; тянет за собой ml-dsa 0.1.1 + ml-kem 0.3.2 (§2, §2.1);
  миграция ключей пользователям не нужна, но нужен snapshot-тест VK с тега v0.3.5.
- aira-core протокол v1 к релизу не готов (C1–C7, §2.5) → M19a до wiring.
- Два relay на mail-сервере: iroh-relay (stateless, §3.3) + aira-relay mailbox v2 (§4.3).
- PoW на создание ключа — не делать; per-action adaptive PoW + contact-first (§5.3).
- Клиенты: keyring mock, APK не подписан, Android без provisioning seed, контакт = 3900 hex (§5.5).
- Релиз 2026: SignPath Foundation (Windows), Apple $99, Flathub исключить (AI-политика),
  Android developer verification с 30.09.2026 в 4 странах (§6.6).

## Инструменты/окружение

- WebFetch/curl заблокированы hook'ом → `context-mode execute` с python urllib.
- Агентов запускать **по одному** (лимит сессии); результаты сразу в md.
- Worktree `scratchpad/head-wt` удалён; scratchpad сессии:
  `C:\Users\Kami\AppData\Local\Temp\claude\C--web-aira\099428dc-2d91-4436-8543-4bf51c9d4475\scratchpad`.
