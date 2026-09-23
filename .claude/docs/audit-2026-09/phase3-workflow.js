export const meta = {
  name: 'aira-audit-phase3-sequential',
  description: 'Phase 3 of the Aira release audit: 5 code-level topics, strictly one agent at a time; each agent writes its own report file',
  phases: [
    { title: 'A security-compliance', detail: 'rules/security.md across the workspace + KEY_CONTEXTS.md' },
    { title: 'B aira-net', detail: 'endpoint/discovery/relay/transports/DPI audit' },
    { title: 'C tests-fuzz', detail: 'coverage gaps, fuzz targets, proptest' },
    { title: 'D ci-supply-chain', detail: '.github/workflows vs 2026 supply-chain requirements' },
    { title: 'E spec-remainder', detail: 'groups, multidevice, bot API: keep/defer for 1.0' },
    { title: 'F community-relays', detail: 'self-hosted relays, client-as-relay opt-in, redundancy' },
  ],
}

const SUMMARY = {
  type: 'object',
  properties: {
    file_written: { type: 'string', description: 'absolute path of the report file you wrote' },
    summary: { type: 'string', description: '5-10 sentences, Russian, the essence for the main audit document' },
    blockers: { type: 'array', items: { type: 'string' }, description: 'release blockers found (Russian, with file:line)' },
    top_findings: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          severity: { type: 'string', description: 'BLOCKER | HIGH | MEDIUM | LOW' },
          title: { type: 'string' },
          location: { type: 'string', description: 'path:line or spec section' },
          fix: { type: 'string' },
          milestone: { type: 'string', description: 'M18..M23 or new' },
        },
        required: ['severity', 'title', 'location', 'fix'],
      },
    },
    plan_changes: { type: 'array', items: { type: 'string' }, description: 'concrete edits to spec/18-milestones.md M18-M23 (Russian)' },
    open_questions: { type: 'array', items: { type: 'string' }, description: 'decisions the owner must make' },
  },
  required: ['file_written', 'summary', 'top_findings'],
}

const COMMON = `
Ты — аудитор проекта Aira (постквантовый P2P-мессенджер на Rust). Репозиторий: C:\\web\\aira (Windows; есть Bash и PowerShell; ripgrep/Grep, Read, Glob, Write доступны). Workspace v0.3.5, ветка main (HEAD уточни через git log).

ЖЁСТКИЕ ПРАВИЛА
- Ничего не менять в исходниках, не запускать git commit, не трогать Cargo.toml / Cargo.lock (там незакоммиченный diff владельца) и habr_article.md. Не устанавливать инструменты. Не запускать других агентов.
- Разрешено: чтение любых файлов, grep, дешёвые cargo-команды (cargo metadata, cargo test -- --list, cargo tree). cargo build/test целиком — только если явно сказано в задании.
- WebFetch и curl заблокированы хуком; если нужны внешние факты — WebSearch, с указанием источника и даты.
- ОТЧЁТ ПИШИ САМ в указанный файл (Write), НА РУССКОМ (идентификаторы, имена файлов, цитаты кода — как есть). СНАЧАЛА создай файл со скелетом разделов, ЗАТЕМ дописывай разделы по мере работы (сессия может оборваться по лимиту — частичный отчёт ценнее отсутствующего). В конце — финальный проход: резюме сверху.
- Каждая находка: severity (BLOCKER/HIGH/MEDIUM/LOW), доказательство (path:line + короткая цитата), последствие, исправление, целевой milestone. Милстоуны релизного пути определены в C:\\web\\aira\\spec\\18-milestones.md, раздел «16.1 Релизный путь» и Milestone 18–23 (строки ~396–776): M18 iroh 1.1 + PQ-крейты (дедлайн 30.09.2026), M19a протокол v2 в aira-core, M19 сетевой слой в демоне, M19b клиенты (keyring/QR/seed), M20 iroh-relay на mail-сервере, M21 aira-relay mailbox v2, M22 релизная инфраструктура (подпись, CI, SBOM), M23 бета/1.0. Прочитай этот раздел ПЕРЕД тем, как раскладывать задачи по милстоунам.
- Не повторяй то, что уже есть в предыдущих отчётах фазы 1–2 (каталог C:\\web\\aira\\.claude\\docs\\audit-2026-09\\ и главный документ C:\\web\\aira\\.claude\\docs\\release-audit-2026-09.md) — ссылайся на них, добавляй новое. Указанные ниже файлы контекста прочитай сначала.
- Выводы только по прочитанному коду; не гадай. Если что-то не проверил — так и напиши в разделе «Не проверено».
- Финальный ответ — только структурированный вывод по схеме (summary на русском); всё подробное — в файле.
`

const TOPICS = [
  {
    key: 'A security-compliance',
    label: 'audit:security-compliance',
    file: 'C:\\web\\aira\\.claude\\docs\\audit-2026-09\\security-compliance-audit.md',
    prompt: `
ЗАДАНИЕ A — соответствие правилам безопасности по всему workspace.
Отчёт: {FILE}
Контекст сначала: C:\\web\\aira\\.claude\\rules\\security.md (чеклист), C:\\web\\aira\\docs\\KEY_CONTEXTS.md, C:\\web\\aira\\.claude\\docs\\audit-2026-09\\core-audit.md (уже найденные C1–C15 в aira-core — не дублируй), release-audit-2026-09.md §2.5 и §4.1a.

Разведка (проверь и уточни): unsafe вне core/storage — crates/aira-gui/src/{onboarding.rs:103,state.rs:78-86,views/settings.rs:464,views/unlock.rs:113} (as_bytes_mut для зануления String) и crates/aira-net/src/discovery.rs:182 (from_utf8_unchecked); #![deny(unsafe_code)] найден только в 3 файлах; subtle/ct_eq используется только в aira-net/src/transport/reality.rs и aira-gui/src/theme.rs; unwrap/expect в src (включая тестовые модули): core 238, storage 230, net 149, daemon 103, cli 40, gui 28, ffi 22, bot 3. В коде есть KDF-контекст "aira/device/id-from-code", которого НЕТ в KEY_CONTEXTS.md; строки "aira/1/chat|file|handshake|relay" — вероятно ALPN, не KDF (подтверди).

Проверь по каждому крейту (core, storage, net, daemon, cli, gui, ffi, bot):
1. deny(unsafe_code): на уровне крейта (lib.rs/main.rs) для aira-core и aira-storage — достаточно ли; каждый unsafe в других крейтах — есть ли // SAFETY:, корректен ли (as_bytes_mut с записью нулей — валидный UTF-8? drop-порядок?), можно ли заменить на zeroize::Zeroize для String.
2. unwrap()/expect()/panic!/unreachable!/index [] на внешних данных в НЕтестовых путях: перечисли по файлам с path:line, отдели #[cfg(test)]. Особо: daemon (IPC-обработчики), net (парсинг кадров), storage (redb), ffi (границы FFI — паника через FFI = UB/abort).
3. Zeroize: все секреты (seed/mnemonic, x25519 secret, ML-KEM dk, ML-DSA sk, root/chain/message keys, storage key, пароли, link-code, relay auth tokens) — обёрнуты ли в Zeroizing/ZeroizeOnDrop; derive(Debug/Clone/Serialize) на типах с секретами; секреты в tracing/log; секреты в IPC-сообщениях и в FFI (строки в Kotlin).
4. Лимиты размеров: 64 KB envelope (MAX_ENVELOPE_SIZE) и другие константы — применяются ли ДО десериализации во всех точках входа внешних данных (aira-net protocol.rs/relay.rs/transport/*, aira-core proto/handshake, daemon IPC-фрейминг, ffi). postcard::from_bytes на неограниченном входе; аллокации по длине из сети; Vec::with_capacity(len из кадра).
5. Constant-time: сравнения MAC/тегов/токенов/pseudonym/fingerprint/link-code/IPC-auth через == вместо ct_eq; ранние выходы, зависящие от секрета.
6. KEY_CONTEXTS.md vs код: таблица контекст → файл:строка → назначение; отсутствующие в документе; контексты, используемые более чем для одной цели; динамические контексты (format!) и риск коллизий; nonce/counter-схемы (повторное использование nonce при одном ключе — особенно ratchet, storage, obfs/reality сессии); AAD; источники случайности (OsRng/getrandom/thread_rng/тестовые RNG, достижимые в prod).
7. Прочее: арифметика на недоверенных значениях (as-касты, overflow, slice-индексы по длинам из сети), debug_assert в security-проверках, let _ = на security-значимых Result, логирование PII (peer id, текст сообщений, IP) на info/debug, права на файлы БД/seed (Unix mode, Windows ACL), права на IPC-сокет/named pipe, временные файлы, backup.
8. Парсеры без fuzz — только список (подробно — задание C).

Структура отчёта: 0) резюме и таблица «пункт чеклиста rules/security.md → статус (✅/⚠️/❌) → где»; 1–8) разделы по пунктам выше с находками; 9) задачи по милстоунам (M18/M19a/M19/M19b/M21/M22) с path:line; 10) «Не проверено».`,
  },
  {
    key: 'B aira-net',
    label: 'audit:aira-net',
    file: 'C:\\web\\aira\\.claude\\docs\\audit-2026-09\\net-audit.md',
    prompt: `
ЗАДАНИЕ B — аудит крейта aira-net (5.8k строк): что реально есть, что мёртвое, что нужно для M18/M19/M20/M21.
Отчёт: {FILE}
Контекст сначала: C:\\web\\aira\\spec\\03-network.md (§5), C:\\web\\aira\\spec\\13-threat-model.md (§11, 11A DPI, 11B DDoS), C:\\web\\aira\\spec\\04-protocol-wire.md, отчёты C:\\web\\aira\\.claude\\docs\\audit-2026-09\\{facts-crates.md,relay-deploy-plan.md,daemon-storage-audit.md} и release-audit-2026-09.md §3, §4.1a, §4.3, §6.4. Известно: демон НЕ поднимает Endpoint/Router (блокер №0); эксперимент с iroh 1.1 дал 3 ошибки в endpoint.rs; в спеке §16.1 M19 описывает подключение net_task/SessionManager.

Файлы (строки): transport/direct.rs 61, ratelimit.rs 84, lib.rs 108, endpoint.rs 184, blobs.rs 206, connection.rs 260, transport/cdn.rs 264, protocol.rs 278, transport/fingerprint.rs 309, transport/tor.rs 316, discovery.rs 330, transport/obfs.rs 480, transport/mimicry.rs 568, transport/mod.rs 588, relay.rs 669, transport/reality.rs 1136; tests/: dpi_simulator.rs, relay_offline.rs, two_node_chat.rs. Прочитай ВСЕ модули целиком.

Вопросы:
1. Карта модулей: файл → назначение → раздел спеки → статус (подключено к реальному пути соединения / автономный код без интеграции / частично / мёртвое) → кто вызывает (grep по workspace: daemon, cli, gui, ffi, tests). Особо: transport/* — реально ли транспорты встроены в iroh (custom transport/socket, relay-over-…), или это самостоятельные реализации, которые никто не использует; что проверяет tests/dpi_simulator.rs.
2. relay.rs: что это (RelayServer mailbox v1? клиент?), протокол кадров, аутентификация владельца mailbox, лимиты, хранение, TTL, соответствие дизайну mailbox v2 из аудита §4.3 — что переиспользуется в M21, что выкидывается. tests/relay_offline.rs — что доказывает.
3. discovery.rs: invitation link aira://add/… (формат, что внутри, подпись?, размер), pkarr/DNS discovery, from_utf8_unchecked:182 — корректность; как это ляжет в M19b (QR/ссылка) и M20 (relay_url в ссылке).
4. endpoint.rs/connection.rs/protocol.rs: сборка Endpoint (discovery, RelayMode, ALPN "aira/1/*"), версии протокола, фрейминг, лимиты размеров, таймауты, обработка ошибок; полный список мест, которые сломает iroh 0.97→1.1 (NodeId→EndpointId, RelayMode/RelayMap, discovery builder/presets, Endpoint::connect/accept, iroh-blobs версия и наличие wasm), с оценкой объёма правок для M18.
5. blobs.rs: файлы через iroh-blobs — рабочее? размеры, лимиты, привязка к сессии/шифрованию.
6. Безопасность/DoS: неограниченные чтения, отсутствие таймаутов, ratelimit.rs — где применяется, лимит соединений, память на соединение, anti-replay, аутентификация пиров (identity vs iroh EndpointId — как связаны, SIGMA-binding из §2.5), логирование IP/peer id; unwrap/expect в prod-путях (список path:line).
7. Конфигурация relay: можно ли задать свой relay URL (RelayMode::Custom) из конфигурации демона; что нужно добавить для mail-сервера (аудит §3.3) — конкретные точки в коде.
8. Transport/DPI (§11A): для reality/obfs/mimicry/fingerprint/tor/cdn — что реализовано, криптографическая корректность (контексты aira/reality/*, aira/obfs/*, nonce, replay, ct_eq), тестовое покрытие, реалистичность; рекомендация: что оставить в 1.0, что вынести за релиз, что удалить.

Структура отчёта: 0) резюме; 1) карта модулей (таблица); 2–8) по вопросам; 9) задачи по M18/M19/M20/M21 с path:line и оценкой; 10) тесты, которые нужно добавить; 11) «Не проверено».`,
  },
  {
    key: 'C tests-fuzz',
    label: 'audit:tests-fuzz',
    file: 'C:\\web\\aira\\.claude\\docs\\audit-2026-09\\test-coverage-audit.md',
    prompt: `
ЗАДАНИЕ C — покрытие тестами и фаззингом.
Отчёт: {FILE}
Контекст сначала: C:\\web\\aira\\.claude\\rules\\testing.md (требования: unit, детерминизм seed, невалидные входы без паники, интеграционный сквозной, proptest, fuzz для всех парсеров внешних данных), spec/19-quality.md (§17), отчёты audit-2026-09/{core-audit.md,daemon-storage-audit.md,clients-audit.md} (не дублируй найденное), release-audit-2026-09.md §1.

Разведка: #[test]/#[tokio::test] по крейтам: core 130 (+tests/multidevice.rs), storage 84, net 104 (+tests/dpi_simulator.rs, relay_offline.rs, two_node_chat.rs), daemon 53, cli 69, gui 40, ffi 9, bot 11; proptest! нигде не используется; фаззинг: только crates/aira-core/fuzz с двумя таргетами fuzz_decode_keys.rs и fuzz_parse_message.rs; в фазе 1 cargo test дал 435/435.

Разрешено: cargo test --workspace -- --list (перечисление), cargo llvm-cov ТОЛЬКО если уже установлен (проверь cargo llvm-cov --version; если есть — один запуск --workspace --summary-only, лимит 10 минут; иначе не устанавливать, а оценить покрытие по grep).

Проверь:
1. Матрица: модуль/публичный API (pub fn, pub struct с pub методами по lib.rs каждого крейта) → какие тесты его покрывают → пробелы. Приоритет: crypto (seed-деривация, handshake/PQXDH, ratchet, KEM/DSA обёртки, padding, dedup, spam), storage (шифрование, pending, миграции/schema_version, backup), daemon (IPC-обработчики, SessionManager), net (protocol/relay/discovery), ffi.
2. Обязательные тесты по rules/testing.md для каждого milestone: детерминизм seed → ключи (есть ли, где), невалидные входы (парсеры не паникуют), сквозной интеграционный на уровне ДЕМОНА (две ноды in-process через IPC) — подтверди отсутствие; что доказывает tests/two_node_chat.rs (уровень aira-net).
3. Фаззинг: полный список парсеров внешних данных (postcard::from_bytes на wire-типах, сообщения handshake, кадры relay, transport/{reality,obfs,mimicry,fingerprint}, invitation link, IPC-фрейминг, mnemonic/seed-phrase, импорт backup, конфиг-файлы) → есть ли таргет; предложи таргеты (имя, путь, что фаззить, arbitrary-структуры); проверь crates/aira-core/fuzz/Cargo.toml (libfuzzer-sys версия, workspace exclusion, cargo fuzz на Windows требует Linux/WSL — как гонять в CI).
4. Proptest: конкретные свойства (padding roundtrip, сериализация roundtrip всех wire-типов, ratchet out-of-order/skip-keys, dedup, лимиты размеров, invitation link roundtrip).
5. Качество существующих тестов: #[ignore], тесты со sleep/таймингами (флаки), зависящие от сети/DNS/публичных relay n0 (после 30.09.2026 сломаются!), тавтологические (мок проверяет мок), тесты с keyring mock; тесты, которые сломает M18 (iroh 1.1, ml-kem 0.3 seed 64 байта) и M19a (протокол v2) — список.
6. CI (.github/workflows/ci.yml): что именно запускается (--workspace? --all-features? doc-тесты? интеграционные с сетью?), MSRV.
7. Snapshot/вектор-тесты: для M18 нужен snapshot-тест VK/подписей с тега v0.3.5 (аудит §2.1) — опиши, как его сделать (git show v0.3.5:… или сохранить фикстуры сейчас), какие фикстуры зафиксировать до миграции.

Структура отчёта: 0) резюме с цифрами; 1) матрица покрытия по крейтам; 2) обязательные тесты по testing.md — статус; 3) план фаззинга; 4) план proptest; 5) хрупкие/устаревающие тесты; 6) CI; 7) задачи по милстоунам (M18: фикстуры + snapshot; M19a: векторы v2; M19: two-nodes daemon; M21: mailbox); 8) «Не проверено».`,
  },
  {
    key: 'D ci-supply-chain',
    label: 'audit:ci-supply-chain',
    file: 'C:\\web\\aira\\.claude\\docs\\audit-2026-09\\ci-supply-chain-audit.md',
    prompt: `
ЗАДАНИЕ D — CI/CD и supply chain против требований релиза 2026.
Отчёт: {FILE}
Контекст сначала: C:\\web\\aira\\.github\\workflows\\{ci.yml (62 строки),android.yml (150),release.yml (270)} — целиком; deny.toml; .cargo/audit.toml; корневой Cargo.toml (workspace metadata, license, publish; НЕ менять); docs/INSTALL.md; .claude/docs/release.md; отчёт audit-2026-09/release-2026-requirements.md (разделы про supply chain, подпись, attestations) и release-audit-2026-09.md §1, §6.6.5–§6.6.7 (чеклисты) — не дублируй, проверяй реальное состояние против них. Известно из фазы 1: cargo audit показал 17 уязвимостей (quinn-proto, hickory-proto, rustls-webpki, quick-xml, h2 …), APK в релизе не подписан (app-release-unsigned.apk), README.md в корне отсутствует (проверь).

Разведка: все actions приколоты тегами (actions/checkout@v4, dtolnay/rust-toolchain@stable, Swatinem/rust-cache@v2, android-actions/setup-android@v3, actions/setup-java@v4, gradle/actions/setup-gradle@v4, softprops/action-gh-release@v2, upload/download-artifact@v4), а не SHA; rust-toolchain.toml отсутствует (stable плавает).

Проверь:
1. По каждому workflow: триггеры (pull_request_target? push tags? кто может запустить), permissions (есть ли блок, least privilege, id-token), секреты (какие используются, утечка в логи/артефакты), пины, кэш (poisoning), шаги проверки (fmt/clippy/test/audit/deny — что реально запускается и на каких ОС/таргетах), --locked, doc-тесты, wasm32 guard (нужен для M14.0), MSRV.
2. release.yml: матрица таргетов (windows/mac/linux/android — какие есть), стрип/оптимизация, checksums (SHA256SUMS), подпись (cosign/minisign/GPG/Authenticode/notarization) — отсутствие, attestations (actions/attest-build-provenance, SLSA), SBOM (cargo-cyclonedx), cargo-auditable, воспроизводимость (SOURCE_DATE_EPOCH, --remap-path-prefix, зафиксированный toolchain), согласованность версии Cargo.toml ↔ тега, changelog/release notes, имена артефактов, APK: где теряется подпись, что нужно для подписи (keystore в secrets, apksigner) и для developer verification.
3. android.yml: NDK версия (r28 нужен для 16 KB страниц, targetSdk 36 к 31.08.2026 — сверь с аудитом §6.6.4), cargo-ndk, ABI, proguard.
4. deny.toml и .cargo/audit.toml: список игнорируемых advisories — каждый обоснован? покрывает ли 17 текущих? лицензии (MPL-2.0, OFL, UFL) — совместимость с MIT/Apache-2.0 дистрибутива; sources (git-зависимости?); multiple-versions warn — сколько дублей (cargo tree -d).
5. Управление репозиторием: dependabot/renovate, CODEOWNERS, SECURITY.md, CONTRIBUTING, LICENSE-файлы (оба), README, CHANGELOG, branch protection (не проверить — отметь как вопрос владельцу), GitHub Releases/tags история (git tag -l).
6. WebSearch (только по необходимости, с источниками и датами): актуальные версии/SHA-пины actions/attest-build-provenance, slsa-github-generator, cargo-auditable, cargo-cyclonedx, cargo-vet, StepSecurity harden-runner, OpenSSF Scorecard; требования GitHub artifact attestations для public repo.
7. Deliverable: (а) таблица «требование §6.6.5/§6.6.7 → статус сейчас → что сделать → milestone (M18 CI-гварды; M22 подпись/attestations/SBOM; M23 релиз)»; (б) набросок ci.yml v2 и release.yml v2 (permissions, jobs, шаги) в code-блоках ВНУТРИ отчёта (в репозиторий yml не писать); (в) список advisories для audit.toml с обоснованиями; (г) вопросы владельцу (бюджет подписи, secrets, keystore).

Структура: 0) резюме; 1) текущее состояние по workflow; 2) release.yml; 3) android.yml; 4) deny/audit; 5) управление репо; 6) внешние факты; 7) таблица требований; 8) наброски yml; 9) задачи по милстоунам; 10) «Не проверено».`,
  },
  {
    key: 'E spec-remainder',
    label: 'audit:spec-remainder',
    file: 'C:\\web\\aira\\.claude\\docs\\audit-2026-09\\spec-remainder-audit.md',
    prompt: `
ЗАДАНИЕ E — остаток спеки: группы, мультидевайс, Bot API — что нужно к 1.0, что отложить, что переделывать после протокола v2.
Отчёт: {FILE}
Контекст сначала: spec/14-groups.md (§12; известно: там продублирован §13 — найди и опиши), spec/16-multidevice.md (§14), spec/19-quality.md (§17A Bot API), docs/BOT_SDK.md, spec/18-milestones.md (M6, M7, M8–M13 и раздел 16.1 + «Пересмотр M9.6 и M14–17»), отчёты audit-2026-09/spec-drift-audit.md (таблица статуса M1–M17 — не дублируй), core-audit.md (C1–C7: протокол v1 будет заменён v2 в M19a — оцени, что это ломает в группах/мультидевайсе), release-audit-2026-09.md §6.5.

Код: найди модули групп и мультидевайса (grep -ril "group" crates/aira-core/src, "device"/"link" — контексты aira/group/{chain-advance,message-key}, aira/device/{id,id-from-code,link-code,sync-key}), crates/aira-core/tests/multidevice.rs, crates/aira-bot (626 строк), их использование в daemon/cli/gui/ffi (grep по workspace).

Проверь:
1. Группы (§12): что реализовано (sender keys? групповой ratchet? членство, добавление/удаление, ротация ключей при удалении, forward secrecy, post-compromise security), где хранится состояние, подключено ли к daemon/CLI/GUI, тесты; расхождения с §12; зависимость от протокола v2 (M19a) и от mailbox v2 (M21: групповая доставка через relay — N коробок?); безопасность текущего кода (контексты, nonce, порядок сообщений, replay); рекомендация: 1.0 / после 1.0 / переписать; оценка объёма.
2. Мультидевайс (§14): контексты aira/device/*, link-code (энтропия, TTL, канал передачи), синхронизация состояния (что синхронизируется, ratchet-состояние на нескольких устройствах — конфликт с forward secrecy?), tests/multidevice.rs — что проверяет; подключено ли к клиентам; рекомендация и оценка.
3. Bot API (§17A, aira-bot): что есть, зависимость от IPC демона и от блокера №0, аутентификация ботов/токены, хранение, безопасность; нужен ли к 1.0 (владелец планирует ботов?) — предложи вариант «минимальный Bot API после M19».
4. Прочие разделы спеки, не покрытые фазами 1–2: §6.7–6.18 (реакции, receipts, typing, профили, удаление аккаунта, голосовые заметки, разметка) — статус в коде одной таблицей (реализовано/частично/нет) и что из этого обязательно для беты; i18n (fluent) — состояние; §15 Tauri v2 (коммит 971e038) — как согласуется с M19b (egui/eframe GUI) — противоречие? 
5. Спека как документ: SPEC.md «Версия 0.2 | апрель 2026» устарел; дубликат §13; предложи ТОЧНЫЙ список правок (файл, что заменить на что) в дополнение к release-audit §6.5.3, чтобы Sonnet 5 мог выполнить их одним коммитом docs(spec).
6. Предложи, куда в релизном пути поставить группы/мультидевайс/ботов: новые милстоуны M24+ после 1.0 или внутрь M23 — с обоснованием и зависимостями.

Структура: 0) резюме; 1) группы; 2) мультидевайс; 3) Bot API; 4) таблица прочих фич §6.x + i18n + Tauri; 5) правки спеки (точный список); 6) размещение в релизном пути; 7) «Не проверено».`,
  },
  {
    key: 'F community-relays',
    label: 'audit:community-relays',
    file: 'C:\\web\\aira\\.claude\\docs\\audit-2026-09\\community-relays.md',
    prompt: `
ЗАДАНИЕ F — сообщество relay: простота самостоятельного подъёма relay, режим «стать relay» в клиенте для пользователей с публичным IP (opt-in), резервирование нестабильных relay.
Отчёт: {FILE}
Постановка владельца (дословно): «учти ещё в аудите простоту подъёма релеев сообществом + возможность быть релеем для тех у кого паблик айпи, чтобы приложение само предлагало поучаствовать в сообществе и побыть релеем. Нужно понимать что релеи поднятые через клиент чата, не стабильные и должны резервироваться». Второе уточнение владельца: «также отдельно должен быть релей для подъёма на собственном сервере, чтобы сообщество плодило релеи и повышало отказоустойчивость сети» — то есть ДВА самостоятельных продукта: (1) standalone `aira-relay` — отдельный серверный бинарь/Docker-образ/пакет с собственной документацией и релизами, рассчитанный на энтузиастов с VPS/домашним сервером; (2) режим relay внутри клиента для пользователей с публичным IP. Оба должны попадать в общий каталог relay, а сеть — переживать падение любого из них.
Контекст сначала: release-audit-2026-09.md §3 (iroh-relay 1.1, план деплоя на mail-сервере), §4.3 (mailbox v2), §5 (PoW/anti-abuse), §6.4 (браузер и relay); отчёты audit-2026-09/{relay-deploy-plan.md,pow-antiabuse.md,net-audit.md (если существует — карта relay.rs/endpoint.rs/discovery.rs)}; spec/03-network.md §5, spec/13-threat-model.md, spec/18-milestones.md M20/M21. Код: crates/aira-net/src/{relay.rs,endpoint.rs,discovery.rs,ratelimit.rs}, конфигурация демона (crates/aira-daemon), crates/aira-net/tests/relay_offline.rs.

Исследуй (WebSearch, источники с датами) и спроектируй:
1. Прецеденты: Delta Chat chatmail relays (cmdeploy, community-run), SimpleX SMP/XFTP servers (self-host, адреса серверов в ссылках, operator policies), Nostr relays (NIP-65 outbox/relay lists, NIP-11), Tor relays/bridges и Snowflake («побыть прокси» одной кнопкой), Tox bootstrap/TCP relay nodes (public list), Session/Lokinet (staking), Matrix homeservers, Yggdrasil public peers, Tailscale DERP (custom DERP map, DERP mesh, home relay), iroh: RelayMap с несколькими relay, выбор home relay, поведение при падении home relay, конфиг iroh-relay (LetsEncrypt/Manual/Reloading cert modes, QAD, лимиты, metrics), возможность встроить iroh-relay server в приложение (feature server), TLS для relay без домена (self-signed + pin? insecure_skip_relay_cert_verify? sslip.io/nip.io / DNS-01 через поддомен проекта).
2. Standalone aira-relay как отдельный продукт: где живёт (отдельный крейт в workspace `crates/aira-relay` или отдельный репозиторий — см. решение о границах репозиториев в spec §15/коммит 971e038), что входит (iroh-relay server + mailbox v2 + healthz/metrics + ACME), формат дистрибуции (бинарь в GitHub Releases для linux-x86_64/aarch64, Docker-образ ghcr.io, deb/rpm/nix позже), документация оператора (docs/RELAY.md: требования, порты, домен, обновление, бэкап mailbox, лимиты, абьюз-политика), версионирование протокола relay и совместимость клиент↔relay разных версий, авто-обновление/уведомление об устаревании. Простота подъёма: целевой UX для оператора-энтузиаста — один бинарь aira-relay (iroh-relay + mailbox v2 в одном процессе?) с init/doctor, Docker compose, systemd, встроенный ACME, healthz/metrics, авто-регистрация в каталоге relay; что требует домена и портов 80/443, а что работает на голом IP с pinned-сертификатом; объём работ.
3. Режим «стать relay» в клиенте: как клиент определяет публичный IP/достижимость (что даёт iroh: direct addrs, NAT type, QAD; активная проверка порта через существующий relay), UX opt-in (что показать, какие риски объяснить: раскрытие IP, трафик, DDoS, юридика — только ciphertext), лимиты ресурсов (полоса, соединения, хранилище), безопасность демона с открытым портом, desktop (Windows/Linux/macOS: firewall/UPnP/NAT-PMP), Android — исключить?; что клиент-relay предоставляет: только iroh-relay (stateless, безопаснее) или ещё mailbox (stateful — чужие данные на домашнем ПК); рекомендация.
4. Нестабильность и резервирование: классы доступности (server / residential-ephemeral), health-scoring и uptime-история на клиентах, N-of-M депозит в mailbox v2 (несколько коробок у разных relay, дедуп при retrieve, цена трафика), список relay в приглашении/контакте/pkarr-записи (аналог NIP-65: 2–3 relay на identity), смена home relay в iroh и републикация адреса, fallback на якорный relay проекта (mail-сервер), выбор relay у разных операторов (анти-Sybil/анализ трафика), автоисключение мёртвых, каталог: signed relay list (кто подписывает, обновление, DNS/pkarr/в приложении), PoW/квоты на relay для защиты операторов (§5).
5. Модель угроз: злонамеренный community relay (метаданные, дроп, задержка, корреляция), Sybil-relay, утечка IP оператора, злоупотребление хранилищем; что уже закрывает mailbox v2 (owner/sender pseudonyms), что добавить.
6. Что в коде уже есть/мешает: конфиг relay в демоне, RelayServer в aira-net/relay.rs (запуск из клиента?), лимиты, ratelimit.rs — точки с path:line.
7. Deliverable: (а) архитектура «community relays» для Aira (таблица ролей: anchor relay проекта / server relay сообщества / client relay), (б) правки в дизайн mailbox v2 (§4.3) и в M20/M21 спеки, (в) новый milestone (M24 «Community relay mode» или внутрь M23?) с задачами, оценкой и зависимостями, (г) вопросы владельцу (кто подписывает каталог relay; домен для поддоменов операторов; включать ли mailbox в клиент-relay).

Структура: 0) резюме; 1) прецеденты (таблица); 2) факты iroh-relay; 3) UX оператора; 4) режим клиента; 5) резервирование; 6) угрозы; 7) код; 8) архитектура и правки планов; 9) «Не проверено».`,
  },
]

const results = []
for (const t of TOPICS) {
  phase(t.key)
  log(`→ ${t.key}: пишет ${t.file}`)
  const prompt = COMMON + '\n' + t.prompt.replace('{FILE}', t.file)
  let r = null
  try {
    r = await agent(prompt, { label: t.label, phase: t.key, schema: SUMMARY })
  } catch (e) {
    log(`✗ ${t.key} failed: ${e && e.message ? e.message : e}`)
  }
  if (!r) log(`✗ ${t.key}: нет результата (проверь, существует ли ${t.file})`)
  else log(`✓ ${t.key}: ${r.top_findings ? r.top_findings.length : 0} находок, blockers=${r.blockers ? r.blockers.length : 0}`)
  results.push({ topic: t.key, file: t.file, result: r })
}
return results