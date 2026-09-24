# SPEC §16: Порядок реализации

[← Индекс](../SPEC.md)

---

## 16. Порядок реализации

### Milestone 1 — Core crypto (3-4 недели)

1. `aira-core/src/crypto/mod.rs` — trait `CryptoProvider` (абстракция бэкенда)
2. `aira-core/src/crypto/rustcrypto.rs` — реализация на ml-kem + ml-dsa
3. `aira-core/src/seed.rs` — seed-фраза (BIP-39), Argon2id KDF, деривация ключей
4. `aira-core/src/identity.rs` — ML-DSA keypair из seed, генерация, сериализация
5. `aira-core/src/kem.rs` — гибридный X25519+ML-KEM-768 KEM
6. `aira-core/src/handshake.rs` — PQXDH handshake + capability negotiation
7. `aira-core/src/ratchet.rs` — Triple Ratchet (SPQR): классический DR + PQ ratchet
8. `aira-core/src/padding.rs` — message padding до фиксированных блоков
9. `aira-core/src/safety.rs` — Safety Numbers для верификации ключей
10. Unit тесты для каждого модуля
11. Property-based тесты (proptest) для крипто-примитивов
12. Тест: seed-фраза → одинаковые ключи на разных машинах (детерминистичность)
13. Тест: Triple Ratchet деградация при отсутствии PQ поддержки

### Milestone 2 — Networking + Relay (3-4 недели)

1. `aira-net/src/endpoint.rs` — iroh 0.97+ Endpoint обёртка
2. `aira-net/src/connection.rs` — управление сессиями
3. `aira-net/src/discovery.rs` — DHT и direct add
4. `aira-net/src/relay.rs` — store-and-forward relay с pairwise mailboxes
5. Bootstrap нода + relay нода (может быть одной)
6. Протокол deposit/retrieve зашифрованных конвертов, TTL, GC
7. Интеграционный тест: два узла обмениваются сообщением
8. Интеграционный тест: сообщение через relay при офлайн пире

### Milestone 3 — Storage + Daemon (1-2 недели)

1. `aira-storage/` — redb схема, CRUD операции + pending_messages
2. Шифрование базы данных (storage key из seed)
3. `aira-daemon/` — event loop, IPC сокет
4. Disappearing messages — daemon удаляет по TTL
5. Export/import бэкапа

### Milestone 4 — File transfer (1 неделя)

1. Интеграция iroh-blobs 0.99+
2. Chunked transfer для больших файлов
3. Progress reporting через IPC events

### Milestone 5 — CLI (1-2 недели)

1. `aira-cli/` — ratatui TUI
2. Все команды: /add, /file, /me, /mykey, /info, /verify, /export, /import
3. Disappearing messages UI (таймер)
4. Реакции и ответы
5. End-to-end тест через CLI

### Milestone 6 — Групповые чаты (v0.2, 2-3 недели)

**Статус (24.09.2026):** библиотека (`group.rs`, `group_proto.rs`) + IPC/UI без доставки; в бете 0.5
отключено, реализация — Milestone 25 (§16.1).

1. `aira-core/src/group.rs` — Sender Keys, Group Ratchet
2. `aira-core/src/group_proto.rs` — протокол создания/управления группой
3. `aira-storage/` — таблицы groups, group_messages
4. Интеграция с daemon IPC (create/join/leave group)
5. CLI: отображение групповых чатов
6. Интеграционный тест: 3 ноды в группе

### Milestone 6A — Bot SDK (v0.2, 1-2 недели)

**Статус (24.09.2026):** SDK — клиент демона пользователя; принята модель «SDK для собственного демона»
(`--data-dir/--socket`, M19b), Bot API v2 — Milestone 27 (§16.1).

1. `aira-bot/src/lib.rs` — trait `Bot`, `BotContext`
2. IPC клиент для daemon (подписка на события, отправка сообщений)
3. Пример: echo-бот
4. Документация: как написать и запустить бота
5. WASM sandbox (wasmtime) — v0.3

### Milestone 7 — DPI resistance (v0.2, 2-3 недели)

**Статус (24.09.2026):** `transport/*` удаляется в M18 (решение A13); DPI-история беты — iroh-relay по
WSS:443 на своём домене (M20), обфускация — датаграммный `CustomTransport` в Milestone 24c (§16.1).

1. `aira-net/src/transport/mod.rs` — trait `AiraTransport`, direct transport
2. `aira-net/src/transport/obfs.rs` — obfs4/o5 через ptrs
3. `aira-net/src/transport/mimicry.rs` — CPS protocol mimicry (DNS/QUIC/SIP)
4. `aira-net/src/transport/cdn.rs` — CDN relay (Cloudflare Worker)
5. CLI: `/transport <mode>` — переключение режима
6. Тест: DPI-симулятор (nDPI/Wireshark) не распознаёт aira трафик

### Milestone 8 — Мультидевайс (v0.3, 3-4 недели)

**Статус (24.09.2026):** примитивы (`device.rs`, `sync.rs`) без синхронизации — «привязка» = локальная
запись; в бете 0.5 отключено, реализация — Milestone 26 (§16.1).

1. `aira-core/src/device.rs` — Linked Devices Protocol
2. `aira-core/src/sync.rs` — синхронизация сообщений между устройствами
3. DHT мультидевайс записи
4. Ratchet state handoff между устройствами
5. CLI: `/link`, `/devices`, `/unlink`
6. Интеграционный тест: 2 устройства одного пользователя

### Milestone 9 — Desktop GUI (v0.3, 2-3 недели)

1. `aira-gui/` — egui/eframe приложение
2. Системный трей + daemon management
3. OS keychain интеграция (keyring)
4. Нативные уведомления (notify-rust)
5. Сборка: AppImage (Linux), .dmg (macOS), .msi (Windows)

### Milestone 9.5 — GUI UX: auto-spawn, onboarding, password vault, инсталляторы (v0.3.5, 2-3 недели)

**Контекст:** после релиза v0.3.4 `aira-gui.exe` не работает при двойном клике — daemon нужно запускать руками с `AIRA_SEED`, keychain-заготовка не подключена, нет retry при разрывах, нет первого запуска. Решаем все эти проблемы и заодно делаем полноценные инсталляторы для всех десктоп-платформ.

**Phase A — MVP (двойной клик → работает):**
1. `aira-gui/src/keychain.rs` — переименовать API в `store_seed_phrase`/`load_seed_phrase`/`delete_seed_phrase`, все значения в `zeroize::Zeroizing<String>`, подключить модуль (снять `#[allow(dead_code)]`).
2. `aira-gui/src/daemon_manager.rs` (new) — `locate_daemon_binary()` (`current_exe().parent()` + fallback PATH), `spawn(seed)` через `std::process::Command` с `CREATE_NO_WINDOW` на Windows, `stderr: Stdio::piped()`, `check_early_exit()`, `impl Drop` с kill при owned.
3. `aira-gui/src/onboarding.rs` + `views/welcome.rs` (new) — Welcome / Create new identity (показ phrase + checkbox "записал") / Import existing (BIP-39 валидация через `aira_core::seed::MasterSeed::from_phrase`).
4. `state::ConnectionState` enum заменяет `connected: bool`: `Uninitialized / OnboardingRequired / Onboarding / SpawningDaemon / Connecting / Connected / Disconnected{can_retry} / Reconnecting{attempt,delay} / GaveUp`.
5. Новые `GuiCommand` (`CompleteOnboarding`, `RetryConnection`, `ResetIdentity`) и `GuiUpdate` (`OnboardingRequired`, `SpawningDaemon`, `Reconnecting`, `DaemonSpawnFailed`, `DaemonNotFound`, `KeychainUnavailable`). Manual Debug для вариантов с phrase — `"[REDACTED]"`.
6. Переписать `ipc::run_ipc_bridge` на `Bridge { bootstrap, main_loop, reconnect_loop, shutdown }`:
   - `bootstrap`: keychain → onboarding если пусто → try connect (pre-existing daemon, owned=false) → spawn + poll 200ms×50 если нет (owned=true).
   - `main_loop`: на request/event error вызывать `reconnect_loop`, не break.
   - `reconnect_loop`: backoff `[500, 1000, 2000, 5000, 10000]` ms, one-shot re-spawn если owned child умер.
   - `shutdown`: `DaemonRequest::Shutdown` → sleep 500ms → `DaemonHandle::drop` убивает owned child.
7. `app.rs` — status bar match по `conn_state` (Online / Starting daemon / Reconnecting (N) / Offline + Retry), `on_exit` handler, welcome early return.

**Phase B — опциональная защита паролем:**
1. `aira-gui/src/password_vault.rs` (new) — `SeedVault { version, salt, nonce, ciphertext }` через postcard, `lock/unlock` с Argon2id (m=128MB, t=3, p=1) + ChaCha20Poly1305. KDF context `aira-gui/password-vault/v1` — добавить в `docs/KEY_CONTEXTS.md`.
2. `keychain.rs` — dual mode: `StoredSeed::Plain` (account `seed-phrase-plain-v1`) или `Vault(Vec<u8>)` (account `seed-phrase-vault-v1`). `load_seed()` возвращает то что есть.
3. `views/settings.rs` — секция Security с toggle "Protect identity with password", модалки Set/Change/Disable.
4. `views/unlock.rs` (new) + `ConnectionState::Locked{attempt}` + новый bootstrap бранч для Vault с ожиданием `GuiCommand::SubmitPassword`.
5. "Forgot password? Reset identity" — очищает vault, возвращает в onboarding (восстановление только через Import записанной phrase).

**Phase C — инсталляторы для десктопа:**
1. **Windows:** `cargo-wix` + WiX Toolset v4. `crates/aira-gui/wix/main.wxs` включает `aira-gui.exe`, `aira-daemon.exe`, `aira.exe`, Start Menu shortcut, per-user install (без admin). Артефакт `aira-0.3.5-setup.msi`. Без code signing в v0.3.5 (SmartScreen warning — документируем).
2. **macOS:** `scripts/bundle-macos.sh` собирает `Aira.app` (GUI + daemon как siblings в `Contents/MacOS/`, Info.plist, .icns из iconset). `create-dmg` упаковывает в `.dmg` для обоих arch (ARM + Intel). Без notarization в v0.3.5 — документируем `xattr -dr com.apple.quarantine` или ПКМ → Open.
3. **Linux:** `scripts/bundle-appimage.sh` через `linuxdeploy` — AppImage с bundled GTK (основной), опционально `cargo deb -p aira-gui` для `.deb`. Результат: `Aira-0.3.5-x86_64.AppImage` + `aira-gui_0.3.5_amd64.deb`.
4. `.github/workflows/release.yml` — добавить шаги MSI/DMG/AppImage в существующие platform jobs, загрузка в тот же GitHub Release вместе с raw бинарниками.
5. `docs/INSTALL.md` (new) — пошаговая установка, обход warning'ов (SmartScreen/Gatekeeper), uninstall.
6. `aira-web` (отдельный репо): обновить `download-section.tsx` — primary ссылки на installers, secondary на raw бинарники.

**Тесты:** unit — onboarding validate, daemon_manager locate, password_vault roundtrip, state handle_update, reconnect mock через `DaemonClientLike` trait + `tokio::time::pause/advance`. Manual — 12-шаговый сценарий (fresh install → onboarding → daemon spawn → reconnect на kill → close → restart → password protect → unlock → disable → reset identity).

**Безопасность:** Все места с seed phrase через `Zeroizing<String>`; Manual Debug с `[REDACTED]`; никаких `tracing` с phrase. `Command::env` libstd-лимит (нет zeroize копии) — документировано в комментарии, жизнь копии до `spawn()`. KDF контексты изолированы (password-vault не пересекается с storage/identity).

### Milestone 9.6 — Security, Android signing, i18n, темы, UX polish (v0.3.6, 2-3 недели)

**Контекст:** после v0.3.5 остались долги:
- **Security:** `RUSTSEC-2025-0144` (ml-dsa 0.0.4 timing side-channel) заглушён ignore'ом в `deny.toml` / `.cargo/audit.toml`. Нужен реальный upgrade.
- **Android:** APK подписан только debug-ключом → пользователь не может обновить поверх предыдущей установки.
- **GUI:** весь UI hardcoded на English; нет переключения светлой/тёмной темы (сейчас только dark); контакты и чаты выглядят грубо.

Не цели: code signing для Windows/macOS (отдельный бюджетный вопрос, отложено на v0.4), уменьшение размера AppImage, iOS.

**Phase A — Security hardening**

1. **ml-dsa 0.0.4 → 0.1.0+**
   - Workspace dep bump в корневом `Cargo.toml`.
   - Переписать `crates/aira-core/src/crypto/rustcrypto.rs` под новый API. Breaking изменения: `SigningKey::sign` / `VerifyingKey::verify` могли поменять сигнатуру; `serialize/deserialize` через SPKI; возможна миграция seed-based keygen из `Pqdsa::KeyPair::from_seed()` на новый trait.
   - Обновить тесты в `crates/aira-core/src/crypto/` — как минимум `identity.rs` roundtrip, `sign_verify` unit.
   - Проверить cross-backend compat тест (RustCrypto ↔ aws-lc-rs feature flag), если `aira-core/src/crypto/awslc.rs` уже существует к этому моменту.
   - Удалить `RUSTSEC-2025-0144` из `deny.toml` [advisories.ignore] и `.cargo/audit.toml`.
   - Регрессионный тест: подпись от v0.3.5 (снэпшот) должна **не** расшифровываться v0.3.6 без явной миграции — если это breaking для wire format, нужен plan на bridge release (реально: подпись — это только local identity, не влияет на wire, поэтому upgrade незаметен для пользователя).

**Phase B — Android release signing**

2. **Release keystore + CI secrets**
   - `mobile/android/app/build.gradle.kts`: добавить `signingConfigs { create("release") { ... } }`, читать параметры из env (`RELEASE_KEYSTORE_PATH`, `RELEASE_KEYSTORE_PASSWORD`, `RELEASE_KEY_ALIAS`, `RELEASE_KEY_PASSWORD`).
   - `buildTypes { release { signingConfig = signingConfigs.getByName("release") } }`.
   - Локально: сгенерить `aira-release.keystore` через `keytool`, закодировать в base64, положить в репо только `docs/ANDROID_SIGNING.md` с инструкцией (сам keystore — **НЕ в git**).
   - GitHub Secrets: `ANDROID_KEYSTORE_BASE64`, `ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_ALIAS`, `ANDROID_KEY_PASSWORD`.
   - `.github/workflows/release.yml` — в Android job перед `gradle assembleRelease` расшифровать base64 в файл, экспортировать env vars.
   - Финальный шаг: `apksigner verify --verbose --print-certs aira-0.3.6-android.apk` для проверки.
   - Предупреждение для пользователей v0.3.5 → v0.3.6: **нужна переустановка** (старый debug-ключ отличается от нового release). Документировать в `docs/INSTALL.md` → "Upgrade notes".

**Phase C — Internationalization (сразу 10 языков)**

3. **Fluent locales для GUI**
   - `crates/aira-gui/assets/locales/{en,ru,de,es,fr,pt,ar,hi,ja,zh}.ftl` — по одному файлу на локаль, параллельно синхронизированы с `aira-web/messages/*.json`.
   - Использовать существующий `aira_core::i18n::I18n` или создать тонкий GUI-specific wrapper. В `aira-core` уже есть fluent dep и `i18n` модуль.
   - Новый модуль `crates/aira-gui/src/locale.rs`: `tr("welcome.title")` функция, держит глобальный `OnceLock<I18n>`.
   - `GuiState.locale: String` с автодетекцией через `sys-locale` crate → fallback "en" если локаль не поддерживается.
   - Settings → Language dropdown: `en, ru, de, es, fr, pt, ar, hi, ja, zh`. Смена через команду `GuiCommand::SetLocale` → перерендер на следующем `update()`.
   - Все hardcoded строки в `views/welcome.rs`, `views/unlock.rs`, `views/settings.rs`, `views/contacts.rs`, `views/chat.rs`, `app.rs` (status bar) заменить на `tr("…")`.
   - RTL поддержка для `ar`: egui имеет `LayoutDirection::RightToLeft` — применить когда locale starts with "ar" / "he".
   - Chunk split: (B3a) инфраструктура + en/ru, (B3b) остальные 8 языков — можно делать параллельно.

**Phase D — Темы (dark / light / system)**

4. **`ColorScheme` и light palette**
   - `crates/aira-gui/src/theme.rs`: текущий dark вынести в `DarkPalette`, добавить `LightPalette` с hand-picked цветами.
   - `enum ColorScheme { System, Light, Dark }`, persisted в `GuiState.color_scheme`.
   - Зависимость `dark-light = "1"` или `egui` built-in OS-theme detection (если есть в текущей версии 0.29).
   - `apply_theme(ctx)` выбирает палитру на основе `state.color_scheme` (если `System` — спрашиваем dark-light раз на старте + по таймеру 5 сек).
   - Settings → Appearance section: radio с 3 вариантами + live preview.
   - Сохранение выбора: дополнительный keychain entry `aira-messenger / gui-settings` (JSON) или простой файл `$LOCALAPPDATA/aira/gui-settings.json`. Лучше файл, т.к. не секретный.
   - Chunk: (D4a) theme enum + light palette, (D4b) OS detection + Settings UI.

**Phase E — UX polish: contacts & chat**

5. **Contacts view**
   - `widgets/avatar.rs` (new): детерминированный hash-to-color по pubkey + первая буква alias, round 36dp.
   - Contact row: аватар + alias + last-message preview + unread badge + status dot.
   - `ContactListItem` layout: 2 строки — alias + short preview, right side — timestamp + unread bubble.
   - Search field сверху списка → фильтр по alias (case-insensitive, substring match).
   - Online/offline статус: используем `state.online: HashSet<pubkey>` из ipc events → green/grey dot overlaid на аватар.

6. **Chat view**
   - Date separators: группировать сообщения по дням — "Today", "Yesterday", "April 8, 2026".
   - Message grouping: consecutive сообщения от одного автора без аватара каждый раз.
   - Delivered/read indicators: одна галочка (delivered), две (read). Протокол: read receipt через уже существующее событие `MessageReceived` + новый `MessageRead { message_id }` в daemon IPC (нужно расширить `DaemonRequest`/`DaemonEvent`). Off-scope если протокол не готов — отложить до 9.7.
   - Multi-line input: `TextEdit::multiline` + Shift+Enter = newline, Enter = send.
   - Auto-scroll к последнему сообщению при новом input или receive.

**Тесты:**
- Unit: `locale::tr` fallback chain (en missing → error; ru missing key → en fallback → key name).
- Unit: `theme::ColorScheme::resolve(System)` returns Dark on dark OS, Light on light OS.
- Snapshot (insta): locale files все содержат одинаковый set ключей (key parity check через скрипт).
- Integration: startup с `AIRA_LOCALE=ja` env var → UI рендерится на японском.
- Manual: MSI upgrade v0.3.5 → v0.3.6 (in-place), Android APK signing verify, light theme все views.

**Файлы к созданию:**
- `crates/aira-gui/assets/locales/*.ftl` (×10)
- `crates/aira-gui/src/locale.rs`
- `crates/aira-gui/src/widgets/avatar.rs`
- `docs/ANDROID_SIGNING.md`

**Файлы к изменению:**
- `Cargo.toml` (workspace, ml-dsa bump)
- `crates/aira-core/src/crypto/rustcrypto.rs` (ml-dsa API)
- `crates/aira-gui/src/theme.rs` (light palette + ColorScheme)
- `crates/aira-gui/src/state.rs` (locale + color_scheme fields)
- `crates/aira-gui/src/views/*.rs` (все строки → tr)
- `crates/aira-gui/src/views/settings.rs` (Language + Appearance sections)
- `crates/aira-gui/src/main.rs` (init locale + theme)
- `crates/aira-gui/Cargo.toml` (sys-locale, dark-light deps)
- `mobile/android/app/build.gradle.kts` (signingConfigs)
- `.github/workflows/release.yml` (Android keystore decode)
- `.cargo/audit.toml`, `deny.toml` (убрать RUSTSEC-2025-0144)
- `docs/INSTALL.md` (upgrade notes для Android)

**Sequencing:**
1. Phase A (ml-dsa) — неделя, требует внимания к крипто-API.
2. Phase B (Android signing) — 1-2 дня, но требует GitHub Secrets.
3. Phase C (i18n) — 4-5 дней: инфраструктура + en/ru + остальные 8 параллельно.
4. Phase D (themes) — 2-3 дня.
5. Phase E (UX) — 3-4 дня: contacts → chat → polish.
6. Release v0.3.6.

### Milestone 10 — Mobile: Android (v0.3, 3-4 недели)

1. `aira-ffi/` — UniFFI биндинги
2. `mobile/android/` — Kotlin + Jetpack Compose UI
3. Foreground Service для daemon
4. UnifiedPush / FCM wake-up уведомления
5. .apk сборка через GitHub Actions + NDK

### ~~Milestone 11 — Mobile: iOS~~ — ИСКЛЮЧЁН (см. §15.4)

### Milestone 12 — REALITY + Tor transport (v0.3, 3-4 недели)

**Статус (24.09.2026):** исключён (A13): `reality.rs` криптографически несостоятелен (S2), модули удаляются в
M18; мосты и обфускация — Milestone 24c (§16.1).

1. `aira-net/src/transport/reality.rs` — REALITY-like TLS camouflage
2. `aira-net/src/transport/tor.rs` — интеграция с arti
3. uTLS мимикрия browser fingerprint (Chrome/Firefox/Safari)
4. Fallback к легитимному сайту при active probing
5. Тест: active probing не обнаруживает aira

### Milestone 13 — Крипто-бэкенд aws-lc-rs (v0.3, 1-2 недели)

1. `aira-core/src/crypto/awslc.rs` — реализация CryptoProvider на aws-lc-rs
2. FIPS 140-3 validated ML-KEM + ML-DSA
3. Seed-based keygen через `PqdsaKeyPair::from_seed()`
4. Feature flag: `--features=fips` для переключения бэкенда
5. Тесты совместимости: сообщения RustCrypto ↔ aws-lc-rs

### Milestone 14 — WASM-ядро для браузера (v0.4, 3-4 недели)

**Зачем:** дать попробовать Aira без установки. Веб-демо живёт в другом репозитории
(монорепо `letar`, приложение `aira-try`), здесь — только ядро и его публикация.

Разбор ограничений браузера, замеры и решения по UI — в §15.5.

#### 14.1 Крейт `crates/aira-wasm`

1. Обёртка `wasm-bindgen` рядом с `aira-ffi` (тот же принцип: одна платформенная обёртка на
   платформу, ядро не знает о платформе). n0 рекомендует именно свой прикладной крейт-обёртку,
   а не npm-пакет самого `iroh`
2. Публичный API повторяет IPC демона (§8): request/response + поток событий. На стороне JS это
   `postMessage` в Web Worker — **воркер играет роль демона**, протокол не переписывается
3. ⚠️ `getrandom` 0.3: feature `wasm_js` включать **только здесь**. В `aira-core` нельзя — включение
   в библиотеке ломает не-web WASM-сборки и раздувает `Cargo.lock` на всех целях
4. Тест: `wasm-bindgen-test` в headless-браузере в CI

#### 14.2 `aira-core` под wasm

1. Проверить сборку под `wasm32-unknown-unknown` — все зависимости уже чистый Rust
   (`ml-kem`, `ml-dsa`, `x25519-dalek`, `chacha20poly1305`, `blake3`, `argon2`, `subtle`, `sha2`)
2. `aws-lc-rs` (feature `fips`) под wasm не собирается — задокументировать как несовместимость
   и закрыть feature-гейтом с внятной ошибкой компиляции
3. ⚠️ **Argon2id: параметры не менять.** Прод-путь один — `Platform::Desktop`
   (m=256 МБ, t=3, p=4, соль `aira-master-v1-m256`). `Platform::Mobile` используется только в
   тестах. Если браузер возьмёт другие параметры, из той же seed-фразы получится **другая
   личность** — учётка не перенесётся в нативный клиент
4. `SharedArrayBuffer`/COOP-COEP не нужны: feature `parallel` у `argon2` выключена, `rayon` в
   workspace нет → лейны считаются последовательно, результат детерминированный на всех платформах
5. Замерить время derive в браузере (ожидание 3–9 с) и пик памяти. WASM не возвращает линейную
   память — 256 МБ остаются занятыми до закрытия вкладки, проверить мобильный Safari на OOM

#### 14.3 `aira-net` под wasm

1. `tokio` с `features = ["full"]` под `wasm32-unknown-unknown` не собирается — отдельный набор
   features для wasm-цели
2. `iroh` с `default-features = false` (иначе сборка падает; отключается `metrics`)
3. Путь без hole punching: соединения только через relay по WebSocket. Прямых соединений из
   песочницы не бывает
4. Транспорты `obfs4`/`reality`/`cdn`/`tor` под wasm недоступны (нужны свои сокеты) — исключить
   из wasm-сборки, не пытаться эмулировать
5. Опционально: bump `iroh` 0.97 → 1.0 (вышла 2026-06-16, в документации по wasm примеры уже
   на `version = "1"`)

#### 14.4 `aira-storage` под wasm

1. Бэкенд `redb-opfs` (готовый крейт от Wire) — `redb` поверх Origin Private File System
2. ⚠️ Требует Web Worker: синхронный доступ к OPFS доступен только там. Это совпадает с 14.1 —
   всё ядро и так живёт в воркере

#### 14.5 CI и публикация

1. Цель `wasm32-unknown-unknown` в матрице сборки (§15.7)
2. Сборка через `wasm-pack`, публикация npm-пакета из этого репозитория на каждый релиз
3. Версия пакета совпадает с версией workspace

### Milestone 15 — Голосовые заметки (v0.4, 1-2 недели)

Решение владельца 2026-07-30: это замена звонкам, которые исключены навсегда (§1).

**Протокол уже готов, менять его не надо.** §6.11 описывает голосовые заметки как
`MediaType::Audio` с `duration_secs`, формат Opus в OGG, максимум 15 минут. В коде поле
`MediaPayload.duration_secs: Option<f32>` уже есть. Аудио-зависимостей в проекте нет ни одной —
работа целиком клиентская.

1. **Кодек и запись.** Биндинги к `libopus`. Захват с устройства: `cpal`. Целевой битрейт
   16–24 кбит/с, моно, 20 мс кадры. Контейнер OGG
2. **CBR, а не VBR.** Осознанно жертвуем несколькими процентами качества: VBR-размер кадра
   коррелирует с фонемами, известны атаки восстановления фраз из шифрованного VoIP. Заметка —
   один блоб, а не поток, но принцип тот же: постоянный битрейт дешевле, чем объяснять потом
3. **Ограничения.** Максимум 15 минут (§6.11) и явный лимит по размеру, чтобы заметка не
   превращалась в скрытый файлообмен. Проверять **до** записи, а не после
4. **Waveform для превью.** Считает отправитель (как thumbnail у изображений, §6.11 — получатель
   не обрабатывает чужие данные). Огрубить до ~64 значений, положить в `thumbnail` как компактный
   массив, а не как JPEG-картинку
5. **Воспроизведение.** `rodio` либо прямой вывод через `cpal`. Скорость 1x/1.5x/2x
6. **Приватность — записать в UI явно.** Голос это биометрия: узнаваем и не отзывается, в отличие
   от текста. Значит по умолчанию предлагать TTL (исчезающие сообщения, §6.7) и не хранить
   отправленные заметки дольше, чем сам разговор
7. **Раскладка по клиентам** — см. §15.8. Запись только в полных клиентах (Tauri/React, Android).
   CLI и egui: показать `[голосовая заметка, 0:12]`, дать сохранить в файл, воспроизведение
   опционально. Записывать из TUI — не нужно
8. **Браузер (§15.5).** Запись через `MediaRecorder`, Opus там уже есть в самом браузере —
   биндинги к `libopus` в wasm не нужны

### Milestone 16 — Разметка сообщений (v0.4, 1 неделя)

Решение владельца 2026-07-30. Безопасное подмножество и обоснование запретов — §6.25.
Протокол не меняется: по проводу идёт исходный текст, разметку рисует получатель.

1. `aira-core/src/markup.rs` — разбор через `pulldown-cmark`, HTML отключён флагом, лимит
   глубины вложенности. Выход — нейтральное дерево спанов, не HTML: его должны уметь рисовать и
   React, и Compose, и ratatui
2. Юникод-гигиена: вырезание bidi-управляющих (`U+202A`–`U+202E`, `U+2066`–`U+2069`) и символов
   нулевой ширины. ⚠️ RTL-текст не трогать — арабский в локалях должен работать
3. Внутри блоков кода невидимые символы **подсвечивать**, а не удалять (trojan source,
   CVE-2021-42574) — аудитория копирует оттуда команды в терминал
4. Автоссылки + детект homograph-подмены домена, показ punycode. Подписей у ссылок в v1 нет
5. `cargo fuzz` таргет на парсер — вход недоверенный по определению
6. Рендер: полные клиенты — весь набор; CLI/egui — подмножество по §15.8 п. 5

### Milestone 17 — Основной desktop-клиент на Tauri (v0.4, 3-5 недель)

Решение владельца 2026-07-30: движок Tauri v2, обоснование и границы репозиториев — §15.9.
egui-клиент не удаляется, а переходит в класс минимальных (§15.8).

1. **Оболочка `desktop/` (этот репозиторий).** `src-tauri` линкует `aira-core`/`aira-net`/
   `aira-storage` напрямую — демон для GUI больше не нужен, вместе с ним уходит auto-spawn из
   Milestone 9.5 и весь его класс проблем
2. **Команды Tauri повторяют IPC демона (§8)** — request/response + поток событий. Не изобретать
   второй контракт: на нём же держится переносимость интерфейса между десктопом и вебом (§15.9)
3. **Секреты не пересекают границу в JS.** Наружу отдаются отпечатки, статусы, расшифрованный
   текст сообщений — но не ключи и не seed. `zeroize` работает на Rust-стороне
4. **Фронтенд приходит готовым** — `frontendDist` на распакованный npm-пакет со собранной
   статикой из `letar` (§15.9). Своего JS-тулчейна репозиторий не заводит
5. **Инсталляторы.** Milestone 9.5 сделал MSI/DMG/AppImage для egui-бинаря; для Tauri они
   собираются его собственным бандлером — переиспользуется подпись и нотаризация, но не скрипты
6. ⚠️ **Linux — главный риск.** WebKitGTK: проверить рендер, ввод, IME и упаковку `webkit2gtk`
   в AppImage **до** того, как переносить фичи. Если окажется неприемлемо — решение по движку
   пересматривается, поэтому проверка идёт первым делом, а не последним
7. **Перенос по функциям, а не «всё сразу».** Порядок: онбординг и seed → список контактов и
   сверка отпечатков → переписка 1-на-1 → файлы → группы (после M25) → голосовые заметки (M15) →
   разметка (M16)
8. Системный трей, автозапуск и уведомления — по таблице §15.2, но через плагины Tauri

---


## 16.1 Релизный путь (пересмотр сентября 2026)

> Правки аудита 2026-09 (§8.1–§8.7) и решения владельца 24.09 внесены в текст ниже 24.09.2026; история — `.claude/docs/audit-2026-09/`.

Номера строк кода в M18–M28 — по HEAD `7726b46` (исходники не менялись с тега v0.3.5, только docs-коммиты).
Полные отчёты: `.claude/docs/release-audit-2026-09.md` (§2.5, §4, §5, §8) и `.claude/docs/audit-2026-09/*.md`
(`net-audit`, `security-compliance-audit`, `test-coverage-audit`, `ci-supply-chain-audit`, `spec-remainder-audit`,
`community-relays`, `onion-antiabuse`); решения владельца — `audit-2026-09/owner-decisions.md` (коды A1…F10 ниже — оттуда).

**Контекст.** Аудит 2026-09-07 (HEAD `971e038`, v0.3.5) и фаза 3 (23–24.09, HEAD `7726b46`) показали:

- **Блокер №0:** `aira-daemon` не поднимает iroh Endpoint/Router и не использует handshake/ratchet/relay.
  `SendMessage` пишет в redb и отвечает `Ok`; `pending::dequeue` не вызывается нигде. Сообщения
  никогда не покидают локальную базу — ни онлайн, ни офлайн. Всё, что описано в M2–M4 как
  «сетевое», существует только как библиотечный код в `aira-net` и его тесты; ни один символ
  `AiraEndpoint/build_router/ChatHandler/RelayClient` не используется вне крейта.
- **Блокер №1:** n0 отключает публичные relay для клиентов iroh 0.9x **30 сентября 2026**.
  Клиенты за NAT на v0.3.5 после этой даты не соединятся. Миграция на iroh 1.2 одновременно
  разблокирует `ml-dsa 0.1.1` (iroh-base 0.97 пинит `digest = "=0.11.0-rc.10"`) и снимает
  advisories quinn-proto / hickory-proto.
- Протокольный слой `aira-core` (ratchet, handshake) не готов к «релизу с обещанием
  совместимости» (§2.5 аудита, находки C1–C7): wire не несёт заголовок ratchet, AEAD без AAD,
  PQ-шаг ratchet никогда не стартует, handshake не PQXDH, подписи без SIGMA-binding.
- **CI на `main` красный с 10.04.2026** (run 35933020292): 18 advisories `cargo audit` (6 закрываются
  `cargo update`, 4 — iroh 1.x, 8 — quick-xml ×4 в egui/rfd/notify-rust) и clippy 1.98 из-за плавающего
  `@stable` без `rust-toolchain.toml`. `LICENSE-MIT`/`LICENSE-APACHE`/`README.md` при «MIT OR Apache-2.0»
  появились только 24.09.2026 (вместе с `SECURITY.md`, `docs/THREAT_MODEL.md`, `docs/PRIVACY.md`;
  `docs/INSTALL.md` поправлен: «0.3.5 без сети», APK не подписан, glibc, SignPath / без Apple). `release.yml`
  с write-токеном исполняет непроверенный `linuxdeploy`; 0 SHA-пинов, нет `permissions`/`--locked`/
  Dependabot; APK неподписан; 65 из 500 тестов никогда не выполняются в CI, фаззинг не собирается,
  детерминизм seed → ключи не доказан ни одним вектором, сквозного теста демона нет (`ipc.rs` заперт в
  бинарнике).
- **Группы, мультидевайс, Bot API** существуют как криптопримитивы, IPC-запросы и экраны во всех
  четырёх клиентах, но ничего не доставляют: группы шлют `PlainPayload::Text` каждому участнику без
  Sender Keys и без wire-типа, входящий `GroupControl` принимается без авторизации (S1), sender-состояния
  не персистятся; «привязка устройства» — локальная запись; бот не распарсит текст после wiring (три
  формата `MessageReceived`). Из §6.x сломаны disappearing messages (`mark_read` никто не вызывает) и
  `/block` (= `RemoveContact`).
- **IP-утечки:** `AiraEndpoint::bind` всегда с IP-транспортами и hole punching (`endpoint.rs:56-95`),
  режима relay-only нет; invitation link по прежнему плану нёс бы `postcard(ep.addr())` с LAN- и
  публичными IP; `net_report` шлёт пробы до 5 relay из RelayMap; mailbox v1 видит IP депозитора;
  iroh-relay пишет IP клиента в `info_span`.
- **`transport/*` — 3 722 строки (64 % aira-net):** байтовые обёртки, не встраиваемые в iroh (QUIC/UDP),
  выключены фичами, не собираются в CI с апреля, криптографически несостоятельны (obfs без секрета,
  REALITY со статическим ключом, CDN/Tor — заглушки); GUI/CLI при этом «выбирают REALITY/Tor».
- Клиенты: `keyring` без platform-features (mock store → seed не переживает перезапуск GUI),
  релизный APK не подписан вообще, Android-оболочка без provisioning seed; `AIRA_SEED` через env;
  IPC-сокет без аутентификации и с правами по umask.

**Порядок.** Milestone 9.6 и 14–17 переносятся *после* релизного пути. Версии:
`0.4.x` — M18–M22 (bridge-релизы без обещания совместимости), `0.5.0-beta.N` — M23,
`1.0` — после внешнего аудита. Релизный протокол = **v2** (`min_version = max_version = 2`);
v1 объявляется pre-release без гарантий (у v0.3.x сети нет — ломать нечего). **Бета 0.5: desktop = egui
(минимальный класс §15.8) + CLI, Android — preview без APK; Tauri (M17) — между бетой и 1.0** (B10, B4).

```
M18 (iroh 1.2 + PQ + CI-гварды + LICENSE) -> M19a (протокол v2) -> M19 (демон в сети) -> M21 (aira-relay) -> M22 -> M23 -> бета 0.5
                                                                     | параллельно с M19:
                                                                     |-- M19b (клиентские блокеры; Android-пакет после десктопа)
                                                                     |-- M20 (свой iroh-relay + discovery на mail-сервере)
                                                                     |-- M22-infra (подпись SignPath/minisign, attestations, SBOM)
после беты: M16 -> M25 -> M17 -> M24a + M24b (параллельно) -> M24c -> 1.0 -> M24d -> M26 -> M28 -> M15 -> M27 -> M14
```

**Решения владельца (24.09.2026)** — принято (✅ спрошено, ☑ по рекомендации; коды — `owner-decisions.md`):

1. **Протокол и база:** mailbox v2 — **две коробки на пару** (A1); v2 **без совместимости с 0.3.x** (A2);
   DHT после релиза, discovery = pkarr на своём `iroh-dns-server` (A3); `Platform::Mobile` удалить, тесты
   на `MasterSeed::from_raw` (A4); iroh **1.2** (A5); `publish_direct_addrs = false` (A14); iroh `SecretKey`
   per-device `aira/iroh/secret/<device_index>`, единый контракт `MessageReceived`/`MessageMeta`,
   `pseudonym_counter` по `device_index` (A8–A10); файлы ≥ 1 MB — per-file ключ в M19a (A12); backup v2 с
   лимитом импорта (A19); seed через FFI — bytes + Keystore (A17); права 0700/0600 + `SO_PEERCRED` (A18);
   `safety_number` симметрична (A22); seed-корпус фаззинга коммитить (A20).
2. **Сеть и приватность:** **`hide_ip = true` по умолчанию**, direct — per-contact opt-in, **invitation
   link без IP** (A6, A7); RelayMap клиента = свои 1–2 relay (B3); `RUST_LOG=warn` на relay (B13); relay на
   mail-сервере — **вариант A** (nginx `stream` + SNI passthrough, udp/7842) (B1); **`transport/*` удалить**,
   REALITY исключён, обфускация → `CustomTransport` в M24c (A13, C14); Aira Onion (M24b) **до 1.0** (C4),
   второй `Endpoint` под хоп (C5), мобильные — только клиент (C7, F9), профиль `standard` (C8), файлы в
   hidden-профиле — медленная полоса ≤ 10 MB + direct с предупреждением (C9), share 32 KB/s / 3 GB/мес +
   счётчик (C10), IdentityStamp — не в первом релизе (C12), `ContactStamp` вместо «префикса ключа» (C16).
3. **Состав беты:** группы, мультидевайс, Bot API **отключить честно** (A11; из §6.x — только TTL + block,
   C15); **бета = egui + CLI**, Tauri между бетой и 1.0 (B10); Android — **preview без APK** до подписи,
   developer verification — нет (B4, B5, D3); Bot API = «SDK для собственного демона» (B11); THREAT_MODEL/
   PRIVACY — таблица обещаний по четырём наблюдателям, без «анонимный»/«невзламываемый» (B12); правило
   «ручной `Debug` с `[REDACTED]`» в `rules/security.md` (B8).
4. **CI и релизы:** workspace-линты и CI-гварды в M18 (A15, D6); quick-xml — ignore до M19b, egui 0.36 там
   же (D4); подпись — **SignPath + minisign**, без Apple $99 (macOS без notarization, честно в INSTALL.md)
   и без Android verification (B6, D2); трек **«M22-infra»** параллельно M19 (D6); SLSA L2 для беты, L3 к
   1.0 (D7); `environment: release` с approve (D8); Linux-сборки в контейнере ubuntu:22.04 (D5); ветки —
   **только `main` + PR**, теги через job `verify`, rulesets `main`/`v*` (D9); LICENSE + README — в
   репозитории с 24.09 (D10); Windows/macOS-раннеры на `main`/тегах (B7); тесты handler.rs в aira-daemon (B9).
5. **Community relays:** каталог — **один офлайн-ключ ML-DSA-65**, 2-of-3 к 1.0 (F1); операторам без
   поддоменов — свой домен либо IP + pin (F2); mailbox в client-relay — нет (F3); client-relay как home
   relay — только opt-in (F4); override гейта strict-страны через Advanced (F5); токены Ed25519 (F6);
   открытые relay в каталог не пускать (F7); абьюз-контакт и юридический раздел `docs/RELAY.md` (F8).

Открыто (в тексте ниже — «решение владельца (открыто)»): **B2/F10** — бюджет второго anchor-VPS и
`relays.<domain>` до беты; **C1** — группы v2 (M25) до 1.0 или после; **C2** — подпись групповых
конвертов (к M25); **C3** — модель мультидевайса (к M21 `Register{device_id}`); **C6** — strict-список
стран (к M24c); **C11** — имя фичи onion; **C13** — браузер (к M14); **C17** — подпись invitation link vs
QR (ML-DSA-65 3 309 Б не влезает в QR V40-L 2 953 Б вместе с ключом; рекомендация — Ed25519-подключ
64 Б от псевдонима; к M19b); **D1** — настройки GitHub-репозитория (действие владельца, не решение).

### Milestone 18 — Миграция iroh 1.2 + ml-dsa 0.1.1 / ml-kem 0.3.2, CI-гварды, LICENSE (v0.4.0, 5–8 дней; ядро миграции — до 30.09.2026)

**Зачем:** без этого клиенты за NAT перестанут работать 30.09.2026, а `ml-dsa 0.0.4` несёт три
известных дефекта (RUSTSEC-2025-0144 / CVE-2026-22705 timing при подписи; CVE-2026-24850
нестрогая проверка hint'ов; GHSA-h37v-hp6w-2pp8 — валидная подпись может не пройти верификацию).
Все закрыты в `ml-dsa 0.1.1`. Заодно — зелёный CI, лицензии и удаление мёртвых транспортов: тег
`v0.4.0` не ставится на красный `main` без LICENSE. Один PR в `main` (ветки `milestone/*` больше не
используются — D9).

⚠️ Незакоммиченный bump `ml-dsa = "0.1.0-rc.4"` в `Cargo.toml` не собирается (sha3 rc.6 vs keccak)
и не нужен — откатить, целевые версии ниже. `ml-dsa 0.1.1` не резолвится при iroh 0.97, поэтому
Phase A из M9.6 отдельно невозможна. Без отката `cargo test -p aira-net` не компилируется.

1. **Шаг 0 — снапшот-векторы с тега v0.3.5 (до любых правок).** `git worktree add ../aira-v035 v0.3.5`
   (рабочая копия не собирается — см. ⚠️); временный тест `tests/dump_vectors.rs` (`#[ignore]`, удаляется
   после) печатает hex в `crates/aira-core/tests/vectors/v0_3_5.json`: `identity_vk`
   (`identity_keygen(&[7u8;32])` → `encode_verifying_key`, 1952 Б), `identity_sig` (`sign(sk,
   b"aira-snapshot-v1")`, 3309 Б), `kem_ek`/`kem_dk` (1184 / 2400 Б legacy expanded), `kem_ct`/`kem_ss`
   (encaps недетерминирован → фиксируется `decaps(dk, ct_fixed) == ss_fixed`), `seed_desktop` —
   `MasterSeed::from_phrase("abandon"×23 + "art")` с **Desktop**-профилем → `derive("aira/identity/0" |
   "aira/storage/0" | "aira/mlkem/0")` (≈ 2 с и 256 MB — `slow-tests`, но в CI запускать), `pseudonym_vk_0`,
   `contact_id(identity_vk)`, `hybrid_kdf` (`combine_secrets` на фиксированных входах — фиксирует контекст
   `aira/hybrid-kem/v1` и BE-counter), `link_code` (`generate_link_code(seed_raw, 1_700_000_000)`),
   `ratchet_snapshot_v035` (postcard-снапшот сессии с `pq_enabled = true` после 3 сообщений — для п.6).
   Постоянный тест `tests/vectors.rs` сравнивает каждый ключ; расхождение `identity_vk` после миграции =
   **релиз-блокер** (адрес пользователя = байты VK).
2. **Cargo.toml (workspace):** `iroh = { version = "1.2", default-features = false, features =
   ["metrics", "portmapper", "fast-apple-datapath", "tls-ring"] }` (1.2.0 от 09.09.2026, wire совместим
   с 1.1), `iroh-relay = "1.2"` (feature `server` — **только** в `aira-relay`, M21; daemon/ffi его не
   линкуют), `iroh-blobs` из той же линейки (0.103 сверена для 1.1; при 1.2 проверить),
   `ml-dsa = { version = "0.1.1", features = ["zeroize"] }`, `ml-kem = { version = "0.3.2",
   features = ["zeroize", "getrandom"] }` (фича `deterministic` удалена), `kem = "0.3"`,
   `aws-lc-rs = "1.18"` без `unstable`, `rust-version = "1.91"` + `rust-version.workspace = true` во всех
   крейтах. x25519-dalek 2 / chacha20poly1305 0.10 / argon2 0.5 / rand 0.8 **не трогать** (типами не
   пересекаются; rand 0.8 и 0.10 в графе одновременно — допустимо). После отката Cargo.lock проверить
   `cargo tree -i zeroize` (ml-kem/ml-dsa/x25519 остаются с `zeroize`) и `cargo tree -d -i rand` — не
   смешивать `rand_core` 0.6/0.9 в `crypto/rustcrypto.rs:59-63` (A16).
3. `crates/aira-net/src/endpoint.rs:78` — `Endpoint::empty_builder()` удалён в 1.x →
   `Endpoint::builder(presets::Minimal)` в тестах (без relay/discovery; поправить doc-комментарий
   `:49-53` — тесты идут с `RelayMode::Disabled`, не через relay n0); `presets::N0` в проде остаётся до
   M20. Сверено по исходникам 1.1.0/1.2.0: ~30 остальных точек API и iroh-blobs совпадают, вне aira-net
   iroh никто не использует — **правок вне aira-net не ожидается** (≈ 0,5 дня вместе с прогоном 104
   тестов aira-net и `cargo clippy -p aira-net --all-targets`); `lib.rs:5` «iroh 0.97» → 1.2.
4. `crates/aira-core/src/crypto/rustcrypto.rs` (сигнатуры трейта `CryptoProvider` в
   `crypto/mod.rs:29-111` не меняются): `identity_keygen` → `SigningKey::<MlDsa65>::from_seed` +
   `signature::Keypair::verifying_key`; `sign` через `sign_deterministic(msg, &[])` (сохранён);
   `kem_keygen` → `DecapsulationKey768::from_seed(d ‖ z)` (контексты `aira/kem-keygen-d/-z`
   остаются) + `dk.encapsulation_key()`; `kem_encaps` → `pk.encapsulate()` без RNG; `kem_decaps`
   → `decapsulate_slice` (длина ≠ 1088 → ошибка); `decode_kem_encaps_key` → `TryKeyInit::new`
   (теперь валидирует EK по FIPS 203 §7.2); `encode_kem_decaps_key` → 64-байтный `Seed`;
   `decode_kem_decaps_key` — по длине: 64 → `from_seed`, 2400 → deprecated
   `ExpandedKeyEncoding::from_expanded_bytes` (legacy-снапшоты v0.3.5). Размеры — константы.
5. `crates/aira-core/src/crypto/awslc.rs:12` → `aws_lc_rs::signature::{PqdsaKeyPair, ML_DSA_65,
   ML_DSA_65_SIGNING}`; `:124-141` expanded DK через `from_seed` + `to_expanded_bytes`.
   ⚠️ aws-lc-rs 1.18 переводит `fips` на модуль AWS-LC-FIPS 4.0, который **ещё не сертифицирован**
   — не заявлять «FIPS-validated ML-DSA».
6. `handshake.rs:82,195` (вывод типов), `ratchet.rs:442-444/488-492` — снапшот через новый
   `encode_kem_decaps_key`, чтение обоих форматов; тест «снапшот v0.3.5 с 2400-байтным DK читается»
   (вектор `ratchet_snapshot_v035` из п.1).
7. Тесты: (а) snapshot-совпадение VK/EK/подписи и derive-векторов с `v0_3_5.json`; (б) `cargo test -p
   aira-core --features compat-test` (8 кросс-бэкендных); (в) EK с коэффициентами ≥ q → `Err(InvalidKey)`;
   (г) CT длины 1087/1089 → `Err`; (д) proptest sign/verify roundtrip (16 кейсов); (е) fuzz-таргеты
   `decode_verifying_key` / `decode_kem_encaps_key` (есть, актуальны); (ж) **починка `crates/aira-core/fuzz`**:
   `postcard = "1"`, `arbitrary = { features = ["derive"] }`, `[profile.release] debug = 1`, `exclude`
   fuzz-крейтов в корневом Cargo.toml, `.gitignore` `**/fuzz/target/`, `**/fuzz/artifacts/`; seed-корпус
   `fuzz/corpus/<target>/` **коммитить** (A20; одноразовый `dump_corpus` из существующих тестов) + CI-job
   `fuzz-build` (`cargo fuzz build` на каждом PR, nightly toolchain); (з) `MasterSeed::from_raw([u8; 32])` под
   `cfg(any(test, feature = "test-utils"))` — 5 тестовых модулей на `Platform::Mobile` (`handshake.rs:363`,
   `identity.rs:118`, `kem.rs:163,193`, `daemon/handler.rs:964`, `ffi/runtime.rs:412-418`) переводятся на
   него **до** удаления `Platform::Mobile` в M19a (иначе каждый тест — Argon2 256 MB, в FFI дважды);
   (и) честный `kem_invalid_ciphertext_rejected` (`rustcrypto.rs:195` — сейчас `let _` без assert);
   таймерные тесты `relay.rs:643-670`, `ffi/runtime.rs:576`, `gui/daemon_manager.rs:238` → `start_paused` +
   `time::advance` и реальные assert.
8. **CI-гварды** (0,5–1 день, без зависимости от кода iroh; наброски `rust-toolchain.toml` / `ci.yml` v2 /
   `release.yml` v2 / `dependabot.yml` — `ci-supply-chain-audit.md` §8, сверять, не копировать вслепую):
   - `rust-toolchain.toml` в корне (stable запинен, bump — осознанным коммитом `chore(config)`); починить
     clippy 1.98: `crates/aira-net/src/discovery.rs:155` (`as_chunks::<3>()`), `relay.rs:112`
     (`Duration::from_hours(168)` или `#[allow(clippy::duration_suboptimal_units)]`).
   - `chore(deps)`: `cargo update -p rustls -p rustls-webpki -p h2 -p crossbeam-epoch -p webbrowser
     -p quinn-proto -p anyhow -p memmap2` (6 advisories до миграции), `cargo update -p spin` (yanked);
     4 уходят с iroh 1.2; **quick-xml ×4** (egui 0.29 / rfd / notify-rust) — временный ignore **со сроком
     до M19b** (D4; bump egui 0.36 там). После этого `cargo audit` чист.
   - `deny.toml` / `.cargo/audit.toml` (целевые файлы — отчёт §4.5): удалить `RUSTSEC-2025-0144`
     (`deny.toml:45`, `.cargo/audit.toml:12`) и 9 ignore-ID на крейты вне lock; `unmaintained = "workspace"`,
     `yanked = "deny"`, `[graph] all-features = true` (после п.10); `publish = false` во всех 8 крейтах +
     `allow-wildcard-paths`. GHSA-h37v-hp6w-2pp8 (ml-dsa) в RustSec нет — видит только Dependabot.
   - `ci.yml`: `--locked` везде, `cargo test --workspace --all-features --locked` и clippy с `--all-features`
     (впервые запустит 17 крипто-тестов `fips`/`compat-test`; transport-тесты уходят с п.10), SHA-пины
     всех actions (таблица снята `git ls-remote` 24.09) + `.github/dependabot.yml`, `permissions: {}` +
     per-job, `persist-credentials: false`, `concurrency`, `timeout-minutes`, `schedule` для audit
     (cargo-deny-action@v2.1.1 + install-action cargo-audit@0.22.2, `--deny yanked`; сейчас инструменты
     компилируются каждый прогон ~7,5 мин), jobs `msrv` (1.91), `wasm32` (`cargo check -p aira-core
     --target wasm32-unknown-unknown`, non-blocking до M14), `android-check`, `fuzz-build` (п.7ж);
     триггеры — `push: [main]` + `pull_request`, несуществующие `dev` / `milestone/M10-*` убрать (D9).
   - `release.yml` минимум для v0.4.0: `permissions: {}` + per-job, `persist-credentials: false`, `--locked`,
     linuxdeploy по тегу + sha256, `linuxdeploy-plugin-gtk.sh` вендорить в `packaging/linux/`, job `verify`
     (тег ↔ версия `Cargo.toml`/`main.wxs`, ветка `main`, зелёный CI), `if-no-files-found: error` + `test -f`
     вместо `|| true`, `prerelease` для версий с `-`, **APK из assets убрать** (D3), `cargo-ndk@4.1.2
     --locked`. Полный `release.yml` v2 (attestations/SBOM/контейнер) — трек M22-infra.
   - Владелец в Settings (D1, вне репозитория): Workflow permissions → read, Dependabot alerts + security
     updates, secret scanning + push protection, private vulnerability reporting, ruleset `main` (required
     checks, no force-push) и `v*` (только владелец, теги не переставлять — v0.3.5 переставлялся);
     `release.sh` больше не пушит мимо PR.
9. **Workspace-линты** (A15, после отката Cargo.toml): `[workspace.lints.clippy] unwrap_used / panic /
   unimplemented / todo = "deny"`, `expect_used / indexing_slicing = "warn"`, `[workspace.lints.rust]
   unsafe_code = "deny"` (aira-gui — `warn` до замены `unsafe` на `String::zeroize()` в M19b п.2, затем
   deny), `[lints] workspace = true` во всех крейтах; 9 `expect()` на константах → `const`/`let-else`.
10. **Удалить `transport/*`** (A13; ≈ 0,5 дня): `transport/{obfs,mimicry,cdn,reality,fingerprint,tor}.rs`,
    фичи `obfs4/mimicry/cdn/reality/tor` и optional-deps (`reqwest`, `rustls`, `tokio-rustls`, `webpki-roots`,
    `rcgen`, `tokio-socks`; `aira-net/Cargo.toml:27-49`), `tests/dpi_simulator.rs`, `transport/mod.rs:28-40,
    401-466`; `TransportMode` — строковый формат settings оставить, enum обрезать до `direct`;
    `docs/KEY_CONTEXTS.md:92-95` (`aira/reality/*`, `aira/obfs/*`) убрать; спека §11A → таблица статусов,
    §11A.6 → `unstable-custom-transports` (датаграммный `CustomTransport` iroh 1.2, M24c); 45
    transport-тестов уходят с кодом (A21), CI-job `--all-features` для aira-net не нужен (C14). Скрытие
    выбора транспорта в UI — M19b п.5. DPI-история беты = iroh-relay по WSS:443 на своём домене (M20).
11. **`LICENSE-MIT` + `LICENSE-APACHE` + `README.md`** — уже в репозитории (24.09.2026, честный pre-release
    статус; вместе с `SECURITY.md`, `docs/THREAT_MODEL.md`, `docs/PRIVACY.md`) — **проверить перед тегом
    v0.4.0**: файлы на месте, `README.md` упоминает v0.4.0 как bridge-релиз без сети, архивы релиза
    содержат LICENSE (D10; условие заявки в SignPath, M22-infra).
12. Документы: `spec/12-dependencies.md` (iroh 1.2, iroh-relay 1.2, iroh-blobs, ml-dsa 0.1.1, ml-kem 0.3,
    getrandom 0.4, rust-version 1.91), `CLAUDE.md`, `spec/03-network.md:21-22`, `spec/01-overview.md:103`;
    `habr_article.md` блок Cargo.toml; `.claude/rules/git.md` — ветки только `main` + PR;
    `.claude/rules/testing.md:60,83-84` — реальные имена fuzz-таргетов. Тег `v0.4.0` — bridge-релиз:
    только зависимости, CI и удаление транспортов, без сети, без APK (release notes честно).

Не цели: PQ-TLS на транспорте (`iroh/tls-aws-lc-rs` + `rustls/prefer-post-quantum`) — отдельная
фича `pq-tls` в aira-net после релиза (нативная сборка aws-lc, несовместимо с wasm); bump egui (M19b).

### Milestone 19a — Протокол v2 в aira-core (v0.4.x, ~2,5 недели)

**Зачем:** wiring демона к сети (M19) поверх текущего wire-формата означал бы ломать формат
дважды. Находки C1–C7 аудита закрываются здесь, до сетевого кода; здесь же — дешёвые резервы
форматов для M25/M26 (postcard-enum позиционный: вариант, не зарезервированный в v2, позже добавить
без поломки v2-клиентов нельзя — §6.16.1, неизвестный discriminant = ошибка десериализации, а не
`Unknown`).

1. **Wire-формат (C1).** `proto.rs`: `Message::Ratchet { header: MessageHeader, envelope:
   EncryptedEnvelope }` — `dh_public`, `prev_chain_len`, `pq_kem_ct`, `pq_kem_ek` из `ratchet.rs:40-52`
   идут в заголовке; `header` целиком — AAD для AEAD. **`Message::Ack { counter }`** в chat-протоколе
   (`proto.rs:11-20`, `protocol.rs:54-95`) — без него dequeue-после-ack в M19 п.10 невозможен. ALPN
   `aira/2/{chat,handshake,file}` (`lib.rs:38-44`). **Одна константа `MAX_ENVELOPE_SIZE`** в aira-core
   (сейчас три: `connection.rs:22`, `ratchet.rs:33`, `relay.rs:111`); `MAX_FRAME_SIZE` = envelope +
   заголовок ratchet + запас (≤ 96 KB), relay v2 использует её же; `RatchetSession::decrypt` проверяет
   размер (`ratchet.rs:323`). Plaintext ratchet-конверта — **всегда `postcard(MessageMeta)`**
   (`MessageMeta { payload, ttl, id, reply_to }`; B2 — сейчас демон эмитит сырой UTF-8). Резерв
   `PlainPayload::GroupMessage(EncryptedGroupEnvelope)` (тело — заглушка до M25) и вариантов для M28
   (`Reaction`, `Receipt`, `Typing`, `Pin`, `Profile` — заглушки; 0,5 дня), биты `GROUPS` /
   `MULTIDEVICE` в `features`, **единый список битов `Features`** в §6.4 и `handshake.rs:28-34` (сейчас
   расходятся). Версия формата в `Capabilities` (§6.4): `min_version = max_version = 2`. Описать в
   `spec/04-protocol-wire.md` §6.1.
2. **Транзакционный decrypt (C2).** `ratchet.rs:297-323`: все skip/DH/PQ-шаги на клоне
   состояния, коммит только после успешного `aead_decrypt`. Тест «битый header / битый ciphertext
   не меняет `to_snapshot()`».
3. **Рабочий PQ-шаг (C3, C4).** `RatchetSession::new` получает ML-KEM ek пира из handshake;
   `pq_kem_ct` обрабатывается независимо от `need_dh_ratchet`; ML-KEM keypair ratchet — из OS RNG
   (`root_key` только для KDF-миксинга, контексты `aira/ratchet/pq-init` / `pq-rekey` пересмотреть
   в `docs/KEY_CONTEXTS.md`). Спека §4.4 обещает шаг «при смене направления» — реализовать
   direction-change trigger в дополнение к `PQ_RATCHET_INTERVAL = 50`. Тесты: 100+ сообщений с
   `pq_enabled = true` в обе стороны, снапшот после PQ-шага, out-of-order через PQ-шаг.
4. **Handshake = PQXDH-подобный (C5, C6).** Ephemeral ML-KEM keypair на каждый handshake;
   `identity_pk` обеих сторон и все публичные значения в `derive_session_keys`; SIGMA-binding —
   подпись ack над `init ‖ ack`; **EndpointId обеих сторон в подписываемых данных init/ack**
   (`handshake.rs:110-117,316-336`; `IncomingHandshake.from` передаётся в `HandshakeResponder::respond`,
   `protocol.rs:102-109`) — иначе identity ↔ EndpointId не связаны; nonce инициатора + timestamp против
   replay; сравнения транскриптов — через `subtle::ct_eq`. Для асинхронного старта через relay (M21) —
   подписанный PQ prekey bundle **`SignedPrekeyBundle { device_id, x25519, mlkem_ek, sig, expires }`**
   (`device_id` — резерв M26). Тесты: replay, identity misbinding, downgrade (клиент с `pq=false`),
   подпись/`expires` bundle. §4.5.1 (chunked handshake ≤ 1200 B) переписать под QUIC-стримы + relay
   fallback (C12).
5. **`spam.rs` (C7):** `min_difficulty` задаёт верификатор; PoW над `recipient_pubkey ‖ server_nonce ‖
   slot ‖ request` (`slot` — временной слот, чтобы верификатор проверял без состояния; сейчас —
   replay/precomputation); **общая функция адаптивной сложности** — одна для `ContactRequest`,
   intro-mailbox (M21 п.4) и `HopSetup` (M24b); проверка ML-DSA подписи `ContactRequest`; `RateLimiter`
   на bounded LRU с ключом по EndpointId. `Message::ContactRequest` в `proto.rs` (подключение в демон —
   M22). Criterion-бенч BLAKE3-PoW → таблица §11B.2 пересчитана (ожидание: 16 бит ≈ 10 мс, 20 ≈ 0,2 с,
   24 ≈ 3 с, 28 ≈ 50 с однопоточно).
6. **Мелкое:** binding identity ↔ iroh `EndpointId` при handshake (C8, хранится в `contacts`);
   `derive_device_id(seed, index)` вместо `aira/device/id-from-code` (деривация из `handler.rs:200` переезжает
   в `aira-core::device`, контекст в KEY_CONTEXTS — C9/S20); **`Platform::Mobile` удалить** (A4; тесты уже на
   `from_raw` из M18 п.7з), `Platform::Browser` не вводить; fingerprint ≥ 128 бит для `/verify`, 8-байтный —
   только подсказка в invitation link (C10); combiner-контекст и порядок байт counter — спеку привести к
   коду (C12); `verify_link_code` через `ConstantTimeEq` + лимит попыток, явный zeroize
   `pq_mlkem_dk`/`send_dh_secret` в `Drop` (C14); `safety_number` симметрична к порядку ключей (A22;
   `safety.rs:39-40`, сейчас 0 тестов). **Per-file ключ файлов (A12, 1–2 дня):** контекст `aira/file/key/v2`
   из ratchet-цепочки, `FileStart` несёт ключ и nonce, blob в iroh-blobs = **ciphertext** (хэш и размер — по
   ciphertext); без этого файлы ≥ 1 MB идут открытым содержимым под классическим TLS iroh и доступны
   любому, кто знает хэш (`blobs.rs:74-79`).
7. **Zeroize и Debug (S4, S5, S6, S15).** `seed.rs:123-141,190-223,262-267`: `generate() ->
   (Zeroizing<String>, Self)`, `generate_phrase_only() -> Zeroizing<String>`, `bip39_decode ->
   Zeroizing<[u8;32]>`, энтропия/`bits`/`indices` в `Zeroizing`; ручной `Debug` с `[REDACTED]` для
   `RatchetSnapshot` (`ratchet.rs:125`), `SenderKeyState`/`SenderKeyReceiver` (`group.rs:54,128`),
   `SyncItem` (`sync.rs:30-80`), `GroupControl` (`group_proto.rs:73-120`); правило «ручной `Debug` с
   `[REDACTED]`» — в `.claude/rules/security.md` (B8); `group.rs:136` `skipped_keys` и `:212-216`
   `chain_ratchet` в `Zeroizing` + `impl Drop`, nonce группового сообщения выводить локально (`:201`) —
   **только резерв**: группы в бете отключены, полная переработка — M25; `device.rs:186-190,214-216` и
   `ratchet.rs:57-61` буферы в `Zeroizing`.
8. **Тесты и fuzz (C11; полный план — `test-coverage-audit.md` §3–§4).** `crates/aira-core/fuzz`:
   `fuzz_wire_message`, `fuzz_handshake` (`Arbitrary` + `from_raw`), `fuzz_ratchet_decrypt` (инвариант
   «`to_snapshot()` не изменился при `Err`»), `fuzz_ratchet_snapshot`, `fuzz_sync_batch`,
   `fuzz_group_decrypt` (`skipped_keys.len() ≤ MAX_SKIP`), `fuzz_contact_request`, `fuzz_bip39`
   (`validate_phrase` без Argon2), `unpad_message`; новый `crates/aira-net/fuzz`: `fuzz_invitation_link`,
   `fuzz_relay_request` (пока жив v1; в M21 — в `aira-relay`), `fuzz_framing` (после перевода `read_framed`
   на generic `AsyncRead + Unpin`). Proptest (15 свойств из §4 отчёта): padding, BIP-39 кодек, postcard
   roundtrip **всех** wire/IPC/storage-типов, ratchet как state machine с `pq_enabled` (при `Err`
   состояние неизменно), `SenderKeyReceiver`, гибридный KEM (16 кейсов), лимиты размеров для любой
   длины, base64url, `derive` попарно различны, `link_code`, `safety_number`. **Golden-байты
   wire-форматов** `tests/vectors/wire_v2/{message_ratchet,handshake_init,handshake_ack,group_control,
   contact_request}.bin` (`to_allocvec(fixture) == include_bytes!` — перестановка вариантов enum ломает
   тест намеренно; сейчас 0 golden-тестов, `proto.rs` — 0 тестов); handshake-транскрипт как вектор с
   инъекцией RNG под `test-utils`; `capability_negotiation_intersection` (`handshake.rs:423`) под
   `min = max = 2`. CI: `cargo fuzz build` на PR (M18), `cargo fuzz run` 60 с/таргет на `main`/nightly,
   регрессия корпуса без nightly — `tests/fuzz_regression.rs`.
9. Спека: §4.2/§4.4/§4.5 (`spec/02-crypto.md`) приведены к коду; `docs/KEY_CONTEXTS.md` дополнен
   (`aira/file/key/v2`, `derive_device_id`, `aira/ratchet/pq-*`; примечание, что `aira/reality/*` удалены в
   M18); `spec/05-protocol-versioning.md` §6.4 — «релизный протокол v2», единый список `Features`,
   правило резервирования вариантов §6.16.1; `spec/04-protocol-wire.md` — `Ack`, `MessageMeta`, per-file
   ключ.

### Milestone 19 — Сетевой слой в демоне (v0.4.x, 2–3 недели + ≈ 3–4 дня hardening aira-net; блокер №0)

**Зачем:** после этого милстоуна мессенджер впервые доставляет сообщения. Карта точек подключения
с файлами и строками — аудит §4.1a. Группы/мультидевайс здесь **не** подключаются (A11) — только
отключаются честно; авторизация `GroupControl` (S1) снимается отключением, а не реализацией.

**Phase A — Storage-предпосылки (до сетевого кода)**

0. **Фикстуры до миграции схемы** (сделать на v0.3.5 **до** правок `ContactInfo`/backup VERSION —
   иначе миграцию проверить нечем): `crates/aira-storage/tests/fixtures/aira-v1.redb` (1 контакт,
   2 сообщения, 1 сессия с настоящим `RatchetSnapshot`, 1 группа, 2 псевдонима, `pseudonym_counter = 2`)
   и `backup-v1.aira.enc` с ключом `[0x42; 32]`; тесты `open_v1_migrates_to_v2`,
   `import_v1_backup_restores_counter`.
1. `aira-storage`: таблица `meta { schema_version: u32 }`, цепочка миграций при `Storage::open`;
   v1 → v2: `ContactInfo` получает `endpoint_id: EndpointId` (без `EndpointAddr` с IP — при `hide_ip`
   в базе нет ни одного `TransportAddr::Ip`; прямой режим для контакта — только флаг `direct_allowed`,
   адреса iroh обменивает сам через relay), **`mailboxes: Vec<MailboxRef { hop_id, relay_urls,
   mailbox_id }>`** (без IP; заполняется в M21) и **`relays: Vec<RelayRef { url, endpoint_id, class,
   pin }>`** (2–3 записи, разные операторы, без класса `client`; единое поле с `MailboxConfig.relays`
   M21 п.7 — не два); поле `blocked` начинает проверяться (п.11); индексы `pseudonym → contact` для
   входящих по псевдониму и `endpoint_id → contact` для gate в п.11.
2. `pending.rs`: инвариант «в PENDING только `postcard(EncryptedEnvelope)`» — тип-обёртка
   `PendingEnvelope` вместо `&[u8]`; заголовок `{ enqueued_at, size }`; лимиты 1000 сообщений /
   100 MB на контакт → `DaemonResponse::Error(QueueFull)`; per-contact `seq` без полного скана; GC
   7 дней. ⚠️ Сейчас fan-out групп кладёт plaintext и sender keys в нешифруемую таблицу
   (`handler.rs:305, 464, 901`) — fan-out в бете не подключается (п.9), но PENDING всё равно шифровать
   storage-ключом.
3. `dedup.rs`: ключ `BLAKE3(sender_pubkey ‖ counter ‖ nonce)[..16]` — вызывать до ratchet-decrypt.
4. `backup.rs` VERSION = 2: groups, group_messages, devices, pseudonyms + `pseudonym_counter`
   (сейчас после restore counter = 0 → повтор псевдонимов, нарушение §12.6); лимит размера импорта +
   версия схемы в заголовке (A19), `Zeroizing` на расшифрованный блоб (`backup.rs:128-150`);
   `export_bytes/import_bytes` (§14.0) и fuzz `backup::import` + per-table decode
   (`crates/aira-storage/fuzz`).
5. `encrypted.rs`: AAD = `table_name ‖ row_key` (ciphertext нельзя переставить между строками);
   `messages.rs:123`: `now_secs.saturating_add(ttl)` + cap TTL на границе IPC/FFI (`u64::MAX` из
   IPC сейчас — паника в debug).
6. **`device_index` и ключи устройства** (A8, A10; 1 день): iroh `SecretKey` =
   `seed.derive("aira/iroh/secret/<device_index>")`, `device_index = 0` в settings (M26 использует 1..;
   «детерминированно из seed без индекса» дало бы один `EndpointId` на все устройства → re-keying всех
   адресов при мультидевайсе); per-device случайный ключ не нужен. `pseudonym_counter` (`storage/
   pseudonyms.rs:22-32`): `counter = (device_index << 28) | local`, restore ставит `local ≥ max + 1`
   (иначе два устройства выдают одинаковые `aira/pseudonym/<n>/*` — нарушение key isolation).
   Контексты в `docs/KEY_CONTEXTS.md`; там же исключение: **хоп-идентичность и KEM-ключи хопа (M24b) —
   локальный RNG, не из seed** (иначе контакт находит IP пользователя в записях хопов).

**Phase B — `net_task`**

7. `aira-daemon/src/main.rs:100-160` после `Storage::open`: **`AiraEndpoint::bind_with(NetConfig {
   hide_ip: true, relays, device_index, .. }, secret_key)`** (`endpoint.rs:45`; при `hide_ip` —
   `builder.clear_ip_transports()` iroh 1.2 `endpoint.rs:510`, дефолт `true` — A6) →
   **`protocol::build_router(&ep, ChatHandler, HandshakeHandler, Some(&blob_store))` без
   `Arc<RelayServer>`** (`protocol.rs:178-195`), ALPN `aira/1/relay` убрать из `all_alpns` (`endpoint.rs:61`),
   `RelayServer` в клиенте не инстанцировать (иначе каждый клиент беты — открытый mailbox-relay с 10-MB
   коробками для любого EndpointId) → `Receiver<IncomingMessage>`, `Receiver<IncomingHandshake>`.
   Endpoint — через `AiraPreset` из M20, до него `presets::N0` (только разработка). Hardening aira-net
   здесь же: таймауты `connect` 5 с / `read_framed` 30 с / ответ на handshake 10 с (`endpoint.rs:115-124`,
   `connection.rs:51-72`, `protocol.rs:63-69,158` — сейчас ни одного); `EnvelopeTooLarge` → пропустить кадр,
   не рвать соединение; инкрементальное выделение в `read_framed` (`connection.rs:66`: 128 стримов ×
   256 KB = 32 MB на соединение); QUIC-лимиты §11B.3 — 16/32 стрима, окна 256/64 KB, idle 30 с
   (`endpoint.rs:17-23,68-73`); `#![deny(clippy::unwrap_used, clippy::expect_used)]` в aira-net (`lib.rs:12-27`).
8. Новый `aira-daemon/src/net_task.rs`: `SessionManager { HashMap<pubkey, RatchetSession> }`;
   при старте `sessions::list_contacts → load → RatchetSession::from_snapshot`; после **каждого**
   send/recv `to_snapshot → sessions::save` **до** отправки в сеть (crash между send и save =
   повтор chain key).
9. `handler.rs:29-36` `handle_request` становится `async` (или получает `mpsc::Sender<NetCommand>`);
   тяжёлое — `spawn_blocking` (`std::fs::read` файла до 4 GiB в `handler.rs:895` → потоковый BLAKE3).
   `SendMessage` → `MessageMeta { payload, ttl, id, reply_to }` → ratchet-encrypt → `pending::enqueue` →
   `NetCommand::Deliver { contact }`; `handle_send_file` (863-949) — так же. **Группы и устройства в бете
   отключены (A11):** `CreateGroup … AcceptGroupInvite` → `Error("groups are not available in this
   beta")`, `enqueue_group_control` (300-320) и `handle_send_group_message` (441-477) не подключаются;
   входящий `PlainPayload::GroupControl` (`handler.rs:688-819`) → `warn!` + игнор (S1 — auto-accept
   `CreateGroup`, `AddMember` без роли Admin, перезапись чужих sender keys — снимается отключением, полная
   авторизация — M25); `LinkDevice/ListDevices/UnlinkDevice` → `Error("multi-device is not available in
   this beta")`. `let _ =` на значимых `Result` → `warn!` (`handler.rs:470,739,909`).
10. Таск `pending_drain`: `pending::peek` → `ep.connect(addr, alpn::CHAT)` (таймаут 5 с) →
    `connection::write_framed` → **`Message::Ack { counter }`** (M19a п.1) → `pending::dequeue`;
    триггеры: старт, входящее соединение, backoff [5 с, 30 с, 2 мин, 10 мин, 1 ч]. **Без fallback на
    `aira/1/relay`**: до M21 только pending + прямая доставка (через relay-транспорт iroh, не mailbox),
    `DeliveryState::Queued` честно в UI; после M21 — deposit в mailbox v2 (M21 п.7). Причины: relay v1
    без auth, `Retrieve` не выгружает коробку > 256 KB, хостить его некому.
11. Входящие: **gate «EndpointId известен и есть сессия» до decrypt** (индекс из п.1; `Message::Ratchet`
    от незнакомого EndpointId → drop + счётчик) → `is_duplicate` → ratchet decrypt → существующий
    `handle_incoming_payload` (`handler.rs:621-674`) → **`DaemonEvent::MessageReceived { from, message:
    StoredMessage }`** (`payload_bytes = postcard(MessageMeta)`) — единый контракт для CLI/GUI/bot (сейчас
    три несовместимых формата: `handler.rs:641,648-651`, `cli/app.rs:399-400`, `gui/state.rs:598-608`,
    `bot/runner.rs:135-142`). Обязательный минимум §6.x для беты (C15): **`messages::mark_read` при
    `GetHistory`/открытии чата** (иначе TTL §6.7 никогда не срабатывает — `storage/messages.rs:119-123`),
    **`BlockContact / UnblockContact`** + drop входящих сообщений и handshake от `blocked` (сейчас `/block`
    = `RemoveContact`, `contacts.rs:143` не проверяется), **`GetSafetyNumber { contact }`** (§6.9).
    `ContactOnline/Offline` — `ConnectionManager::set_connected/set_disconnected` (`connection.rs:155-172`)
    подключить к `net_task` и заполнять `PeerTier` из `contacts`, либо удалить вместе с `PeerTier`/
    `DeviceRecord` (мёртвый код не оставлять); события `DeliveryState { id, Sent | Queued | Relayed |
    Delivered }`, `NetStatus { home_relay, hide_ip, .. }`; форвардер событий (`ipc.rs:129, 224`)
    обрабатывает `RecvError::Lagged` вместо выхода, ёмкость канала 4096.
12. Контакты: `DaemonRequest::GetInvitation` → `aira://add/<base64url(postcard(InvitationLink))>`
    (`discovery.rs:20-45`) со **стабильным** pseudonym (выданные хранить; `GetMyAddress` сейчас генерирует
    новый при каждом вызове — `handler.rs:77-95`). **Ссылка без IP** (A7): `EndpointAddr::new(id)
    .with_relay_url(url)`, **не** `postcard(ep.addr())` — `Endpoint::addr()` содержит LAN- и публичные IP
    (`endpoint_addr.rs:42-62`); `InvitationLink { version, pseudonym_pk, endpoint_id, relays: Vec<RelayRef>
    (2–3), fingerprint_hint (8 Б), expires_at, contact_stamp: Option<ContactStamp> (M22 п.4), sig }`
    (сейчас нет ни версии, ни подписи, `endpoint_addr_bytes` никем не заполняется). Схема `sig` —
    **решение владельца (открыто, C17)**: подпись ML-DSA-65 (3 309 Б) вместе с ключом не влезает в QR V40-L
    (2 953 Б); рекомендация — Ed25519-подключ (64 Б) от псевдонима (контекст в KEY_CONTEXTS), альтернативы
    — подпись только в текстовой ссылке или QR без подписи. Cap URI 4 KB, канонический base64url, проверка
    длин полей; `DeviceRecord` из `discovery.rs` удалить, `:181-182` `from_utf8_unchecked` → safe +
    `#![deny(unsafe_code)]`. `AddContact { uri }`; `ContactRequestReceived` + `AcceptContact/RejectContact`;
    per-contact **`SetContactDirect { contact, allowed }`** («быстрый режим»: hole punching с этим
    контактом раскрывает ему IP; UI — M19b п.4); `SetRelays / GetRelays / GetNetStatus` в IPC
    (`spec/10-daemon-ipc.md`). Тест: «в ссылке нет `TransportAddr::Ip`».
13. Файлы: `BlobStore` на `iroh_blobs::store::fs::FsStore` (`blobs.rs:52-105`; сейчас `MemStore` — файл
    целиком в память до 4 GiB), `add_path` вместо `fs::read`, `TempTag` в `TransferManager` вместо
    `mem::forget` (`blobs.rs:86,103`); **приёмная сторона** — fetch по хэшу из `FileStart` на ALPN blobs
    (сейчас её нет вообще), blob = ciphertext под per-file ключом (M19a п.6); `FileComplete` только по
    `FileAck` от пира (`proto.rs:17`); `FsStore` переживает рестарт.
14. `aira-ffi/src/runtime.rs:95-125` — тот же `net_task` из общей библиотеки `aira-daemon` (lib); Android
    получает сеть автоматически. **`ipc.rs` → библиотека** (`aira_daemon::ipc` с `start_ipc_server(path,
    handler, event_rx)` и тестовым транспортом — `tokio::io::duplex` или сокет во временном каталоге /
    уникальный пайп на Windows): сейчас `mod ipc` живёт в бинарнике (`main.rs:26`), каталога
    `crates/aira-daemon/tests` нет и сквозной тест п.15 структурно невозможен (альтернатива — крейты
    `aira-ipc`/`aira-node` из §14.0, C13). `runtime.rs:85,108,115` `let _` → `warn!`; `set_event_listener`
    (`:137-158`) отменяет предыдущую forwarding-задачу.

**Phase C — Тесты**

15. `crates/aira-daemon/tests/two_daemons.rs`: два демона in-process с реальным IPC-сокетом (seed через
    `MasterSeed::from_raw`, сеть `bind_for_test` без relay) → `AddContact` по invitation link →
    `SendMessage` → у второго `MessageReceived { message: StoredMessage }`; перезапуск первого → сессия
    жива (снапшот); Bob офлайн → PENDING → Bob онлайн → `DeliveryState::Delivered` (без relay — M21);
    дубликат по сети не попадает в историю; `BlockContact` → входящее отброшено; `mark_read` → сообщение
    с TTL исчезает; `CreateGroup` → `Error`, входящий `GroupControl` не создаёт группу; `SetTtl u64::MAX` →
    без паники; файл через blobs с `FileAck`, blob не читается без ключа из `FileStart`, `FsStore` после
    рестарта; `Ratchet` от EndpointId без сессии не доходит до ratchet; битый кадр не рвёт соединение;
    handshake без ответа 10 с → соединение закрыто. Это единственный тест, который докажет доставку.
16. Unit: `read_message` IPC (`Cursor`, len > 1 MiB → `Err`; сейчас серверный парсер не вызывается ни
    одним тестом), `HandshakeHandler::accept`, `ConnectionManager` (если оставлен), `sessions.rs` с
    настоящим `RatchetSnapshot` (сейчас `b"ratchet-snapshot"`), `pending` QueueFull, `dedup` новый ключ,
    `messages.rs` коллизия микросекунды; `read_framed`: длина > `MAX_FRAME_SIZE` → `Err` **без** выделения,
    заголовок больше данных + таймаут → `Err(Timeout)` ≤ 30 с; FFI-тесты без двойного Argon2 (`from_raw`),
    `TempDir` в фикстуре; тесты `handler.rs` дублируются в aira-daemon (B9).

Группа из трёх демонов (закрывала M6 п.6) — перенесена в M25: тест без реализации невозможен.

### Milestone 19b — Клиентские блокеры беты (параллельно с M19, ~1,5 недели; Android-пакет — после десктопа, бету не блокирует)

**Desktop (GUI/CLI/демон)**

1. `Cargo.toml:93`: `keyring = { version = "3", features = ["windows-native", "apple-native",
   "sync-secret-service"] }` (или `linux-native` + vendored для AppImage без libdbus) — сейчас
   компилируется **mock in-memory store**, seed не переживает перезапуск GUI. Снять `#[ignore]` с
   roundtrip-тестов `keychain.rs:189,209,221` в Windows/macOS-джобах CI (раннеры на `main`/тегах —
   B7). Ручная проверка: создать identity → закрыть → запустить → нет welcome.
2. Seed в демон не через `AIRA_SEED` env (`main.rs:85-96`; история shell, `/proc/<pid>/environ`), а через
   stdin при spawn / IPC-handshake / keychain (вынести `aira-gui/keychain.rs` в общий модуль). `AIRA_SEED`
   — только `cfg(debug_assertions)`, до отказа от env — `Zeroizing<String>` + `env::remove_var`
   (`main.rs:85-98`); keychain `try_get -> Option<Zeroizing<String>>` (`keychain.rs:170-177`). CLI: `aira
   init` / `aira start`. GUI: убрать «Copy seed to clipboard» или очищать буфер через 30 с
   (`welcome.rs:156-157`). **Keychain delete-до-write** + проброс ошибок в UI (`keychain.rs:107-136` — `let _
   = delete…`, seed может остаться в OS keychain после reset; `ipc.rs:755,796`), проверка `load_seed() ==
   None` после reset, тест «delete падает» (S7). **`unsafe` в aira-gui → `String::zeroize()`**
   (`onboarding.rs:103`, `state.rs:78,82,86`, `views/settings.rs:462-468`, `views/unlock.rs:112-113`), затем
   `unsafe_code = "deny"` для aira-gui через workspace-линты M18 п.9 (S3).
3. IPC-аутентификация: Unix — `chmod 0700 ~/.aira` (`main.rs:107-108`), `0600` на `aira.redb` и backup
   (`lib.rs:140`, `backup.rs:114`), сокет `set_permissions(0600)` после bind (`ipc.rs:83`), `downloads` 0700
   (`main.rs:130-131`), проверка `SO_PEERCRED` uid (A18; сейчас 0 вызовов `set_permissions` во всём
   workspace); Windows — имя пайпа с SID пользователя, `first_pipe_instance(true)`, security descriptor
   «только текущий пользователь»; токен `<data_dir>/ipc.token` (0600) в первом кадре. Сейчас любой
   локальный процесс может `Shutdown` и `ExportBackup{path}` с расшифрованными ratchet-снапшотами.
   **Bot SDK** (B11): `aira_daemon::client::DaemonClient::connect_with_token(path)`, aira-bot читает
   `<data_dir>/ipc.token` (иначе бот сломается после этого пункта); `aira-daemon --data-dir <dir>
   [--socket <path>]` + `AIRA_DATA_DIR` — второй экземпляр демона для бота со своим seed (сейчас data dir
   жёсткий, `daemon/main.rs:33-56`); §17A переписать под «SDK для собственного демона». Тест `stat` прав на
   Unix; fuzz `DaemonRequest` (`crates/aira-daemon/fuzz`).
4. Контакты в UI: экран «Share my link» с QR — **byte-mode `postcard(InvitationLink)`** (`qrcode` + egui
   Image; текстовый URI ≈ 2,8 KB в QR не влезает; состав подписи — по C17, M19 п.12), «Add contact» по
   ссылке (вставка/сканер из буфера), входящие contact requests с Accept/Reject; тумблер на контакте
   **«разрешить прямое соединение»** (M19 п.12 `SetContactDirect`; текст: раскрывает IP этому контакту, по
   умолчанию выключен); CLI `/invite`, `/add <uri>`, `/requests`, `/direct <contact> on|off`; `/verify` —
   через `GetSafetyNumber` (M19 п.11), `/block` → `BlockContact`. Валидация длины pubkey (`add_contact.rs:60`,
   `handler.rs:38-43`) и `MAX_ENVELOPE_SIZE` для текста (`handler.rs:64`) — константы в `aira-core`; хелпер
   `test_pubkey(tag)` (1952 Б) в core `test-utils` вместо 54 литералов `vec![0x..; 32]`. **Скрыть UI групп и
   устройств во всех клиентах** (A11): egui `views/groups.rs`, Settings «Linked devices», CLI `/group /link
   /devices /unlink`, FFI/Android `GroupsScreen` и device-методы → `Unsupported`; **убрать CLI-заглушки из
   справки и автодополнения**: `/mute /unblock /profile /lang /search /delete-account` (реализация — M28).
5. Settings → «Network»: список relay с классом и статусом (`GetNetStatus`, `home_relay_status` из
   M20), индикатор в status bar, строка «режим: relay-only, IP скрыт» (дефолт `hide_ip`); CLI `/relay`.
   **Выбор транспорта скрыть**: `SetTransportMode ≠ direct` → `Error("not supported")`
   (`handler.rs:835-848`, `views/settings.rs:50`, `cli/main.rs:442`) — сейчас GUI/CLI позволяют выбрать
   REALITY/Tor, а демон отвечает `Ok` при неизменном трафике; модули удалены в M18 п.10. **Превью ссылок
   — opt-in при `hide_ip`** (иначе IP уходит на чужой сервер мимо relay).
6. `README.md` (есть с 24.09; обновить статус, ссылка на INSTALL.md), `docs/INSTALL.md` (поправлен
   24.09: «0.3.5 без сети», APK не подписан, glibc 2.39, SignPath / без Apple; после перехода сборок в
   контейнер ubuntu:22.04 в M22-infra вернуть baseline «Ubuntu 22.04+ / glibc 2.35»; macOS — без
   notarization честно: `xattr -dr com.apple.quarantine` / ПКМ → Open, на Sequoia+ через System
   Settings).
7. **egui 0.29 → 0.36** (+ rfd, notify-rust): закрывает quick-xml ×4 и снимает временный ignore из
   M18 п.8 (D4); проверить `dark-light`/тему и `Image` для QR.

**Android — preview (B4): APK не публикуется до подписи; пакет делается после десктопа, бету не блокирует**

8. FFI: `generate_seed_phrase() -> String`, `validate_seed_phrase(&str) -> bool` (fuzz `fuzz_bip39`
   без Argon2); seed через FFI — **bytes/`ByteArray` + Android Keystore**, не `String` (Kotlin String
   нельзя затереть; A17); `Zeroizing` первой строкой `AiraRuntime::new` (`runtime.rs:56-66`; сейчас
   0 вхождений zeroize в aira-ffi при объявленной зависимости).
9. Kotlin: `OnboardingScreen` (create/import) → `EncryptedSharedPreferences` / Keystore-wrapped
   blob (сейчас никто не пишет `seed_phrase`, сервис молча `return`, `repository = null`);
   `IdentityScreen` с QR; `AddContactScreen` — сканер (ML Kit / ZXing); `GroupsScreen` и устройства
   скрыты (п.4).
10. `mobile/android/app/proguard-rules.pro` (файла нет при `isMinifyEnabled = true`): `-keep class
    com.sun.jna.** { *; }`, `-keep class * implements com.sun.jna.** { *; }`, `-keep class
    uniffi.aira_ffi.** { *; }`.
11. **Release signing** (M9.6 Phase B, конкретика D): keystore генерирует владелец, хранит офлайн + бэкап
    ×2 (D2; ключ нужен **до** возможной регистрации developer verification); environment `android-release`
    + секреты `ANDROID_KEYSTORE_B64/PASSWORD`, `ANDROID_KEY_ALIAS/PASSWORD`; `signingConfigs.release` из
    env в `build.gradle.kts:23-32`; `apksigner verify --verbose --print-certs` в CI + отпечаток в
    `docs/ANDROID_SIGNING.md`; `.gitignore` `*.jks *.keystore`. До этого `release.yml:225-236` публиковал
    `app-release-unsigned.apk` — **убрано из assets в M18 п.8**. Developer verification ($25 + ID;
    sideload-ограничения с 30.09.2026 в BR/ID/SG/TH, глобально 2027) — не регистрироваться (B5), описать в
    INSTALL.md. Пользователям — переустановка (ключ другой).
12. `targetSdk 36` (Play с 31.08.2026); NDK **`28.2.13676358`** из образа ubuntu-24.04 (`ANDROID_NDK_HOME`,
    без `setup-android`; 16 KB page size; сейчас 26.1), `cargo-ndk@4.1.2 --locked` (`-o jniLibs`); Gradle
    wrapper 8.11.1 закоммитить (сейчас системный Gradle 9.7.1 при AGP 8.7.0) + `setup-gradle@v6`;
    `versionCode` с pre-release-номером; `android.yml` без `paths`-фильтра (не бежал с 10.04), с
    `permissions`, без `rust-tests`; в `release.yml` Android-job **не блокирует desktop-релиз**; FGS
    `specialUse` с `PROPERTY_SPECIAL_USE_FGS_SUBTYPE` вместо `dataSync` (6 ч/сутки на Android 15+), после
    M21 — FGS только на время retrieve; убрать `firebase-messaging` (F-Droid запрещает FCM), оставить
    UnifiedPush; `values-ru`. Android исключён из ролей relay/hop навсегда (C7, F9).

### Milestone 20 — Собственный iroh-relay и discovery на mail-сервере (1 неделя, параллельно с M19)

**Зачем:** публичные relay n0 «для development и hobby», без SLA, видят метаданные и отключают
клиентов 0.9x 30.09.2026. iroh-relay **stateless**: хранит соединения, не данные; трафик E2E-зашифрован.
Первый шаг: stock `iroh-relay` поднимается сейчас, в M21 его заменяет один бинарь `aira-relay --mode
full` со встроенным iroh-relay (тот же порт и конфиг). Полный план с конфигами —
`.claude/docs/audit-2026-09/relay-deploy-plan.md`. При `hide_ip = true` (M19 п.7) весь трафик беты идёт
через этот relay: он должен выдержать реальную нагрузку, а его оператор видит IP + EndpointId всех
пользователей (честно в PRIVACY.md).

1. DNS `relay.<domain>` → mail-сервер; firewall: tcp/443 (есть) + **udp/7842** (QAD — замена STUN;
   3478 не нужен; открыт — B1); 9090 (metrics) только localhost.
2. `iroh-relay` **v1.2.0** (≥ 1.0.2 обязательно: до неё короткий кадр ронял сервер), сборка из тега
   `cargo build --profile optimized-release -p iroh-relay --features server` или docker
   `n0computer/iroh-relay:v1.2.0` по digest; пользователь `iroh-relay`, `/etc/iroh-relay/config.toml`,
   `/var/lib/iroh-relay/certs`, systemd unit (`Restart=always`, `LimitNOFILE=131072`,
   `ProtectSystem=strict`, **`RUST_LOG=warn`** — на `info` relay пишет IP клиента в `info_span`,
   `http_server.rs:499`; B13).
3. **Вариант A — решение владельца (B1):** nginx `stream { ssl_preread }` — SNI `relay.<domain>` →
   `127.0.0.1:8443` насквозь; relay сам получает Let's Encrypt (TLS-ALPN-01, `cert_mode =
   "LetsEncrypt"`); быстрый exporter-handshake работает. Прежние HTTPS-vhost'ы webmail переезжают
   на `127.0.0.1:8444` (+ `proxy_protocol`). **Вариант B (запасной):** TLS терминирует nginx (`proxy_pass`,
   `Upgrade`, проброс `Sec-WebSocket-Protocol`, таймауты 1 ч), relay **`cert_mode = "Reloading"`** (есть в
   1.2.0, `main.rs:673-684`; не `Manual` + certbot deploy-hook) на certbot-сертификате; клиенты идут по
   challenge-fallback (+1 RTT) — тот же путь, что в браузере.
4. Лимиты: **`[limits] accept_conn_limit / accept_conn_burst` в iroh-relay ≤ 1.2.0 не реализованы**
   (`server.rs:486-503`, «not currently implemented») — лимит соединений делать в nginx (`stream`:
   `limit_conn`; вариант B: `limit_req`) + fail2ban, позже — свой `max_clients` в `AccessControl` aira-relay
   (M21 п.5); реально работает только `client.rx bytes_per_second = 2_000_000`. `access.shared_token =
   ["aira-v2"]` как протокольная метка-заглушка с явной оговоркой «не секрет» до токенов допуска (M22
   п.3); `access = "everyone"` не оставлять. Проверка `curl --fail https://relay.<domain>/healthz`.
5. `iroh-dns-server` 1.2 для pkarr на `dns.<domain>` (`[https] port = 8445`, `[mainline] enabled =
   false`, `pkarr_put_rate_limit = "smart"`); порт 53 и NS-делегирование — позже. pkarr по умолчанию
   IP не публикует (`AddrFilter::relay_only`) — оставить.
6. Клиент: `crates/aira-net/src/preset.rs` — **`AiraPreset { relays, relay_auth_token, ca_tls_config,
   pkarr_relay, dns_origin, publish_direct_addrs = false, n0_fallback = false }`** `impl
   iroh::endpoint::presets::Preset` (по образцу `presets::N0`: `relay_mode(RelayMode::Custom(RelayMap))`,
   `PkarrPublisher/PkarrResolver::builder(url)` на своём домене, `DnsAddressLookup` вне wasm);
   **`NetConfig { hide_ip: true, relays, device_index, direct_contacts, .. }`** + `AiraEndpoint::bind_with(cfg,
   secret_key)` (M19 п.7). **RelayMap клиента = только свои 1–2 relay** (B3): `net_report` шлёт пробы до
   5 relay из RelayMap (`net_report.rs:497-505`) и раздаёт им IP — каталог сообщества (M24a.1) живёт
   отдельной структурой. Relay-список — из снапшота каталога (`aira-core::catalog` — заготовка: два
   anchor; подпись проверяется с M24a.1); `ca_tls_config` пока `embedded()` (pin-верификатор — M24a.1);
   `publish_direct_addrs = false` (A14). **`home_relay_status()` → `DaemonEvent::NetStatus` + watchdog
   30 с**: у iroh ровно один home relay на endpoint, при падении — бесконечный backoff и стейл
   pkarr-запись (`iroh-1.2.0/src/socket/transports/relay/actor.rs:326-354,392-399,910-919`, issue
   n0-computer/iroh#4476) → watchdog делает `remove_relay`/re-home на второй relay и републикацию pkarr;
   фича `unstable-net-report`. Конфиг демона `[network] relays = [...], pkarr_relay = "..."` + env
   `AIRA_RELAYS`, ключи `net/*` в settings, IPC `SetRelays/GetRelays/GetNetStatus` (M19 п.12); **n0-fallback
   выключен по умолчанию**.
7. Второй relay на VPS в другом регионе до релиза (без него одна точка отказа; бюджет — **решение
   владельца (открыто, B2/F10)**, вместе с DNS `relays.<domain>` для каталога/токенов/пробы M22–M24a);
   оба anchor — в снапшот каталога; Prometheus локально; обновлять relay в течение суток после
   релиза iroh.
8. Спека: `spec/03-network.md` §5.1 «DERP» → iroh-relay (WebSocket/TLS + QAD), новый §5.1.1
   «Собственный iroh-relay + iroh-dns-server», §5.2b/§5.3 (DHT, bootstrap-ноды) → pkarr/DNS,
   DHT — после релиза (A3); `spec/17-cross-platform.md:196` несуществующий `bootstrap/` → `deploy/`;
   глоссарий §20: «transport relay» vs «mailbox relay»; §5.1.2 «Роли relay» — M21 п.9.
9. Тесты (dev-фича `test-utils` iroh): `tests/relay_transport.rs` с **`iroh::test_utils::run_relay_server`
   ×2** — relay-only соединение (direct-адреса удалены из `EndpointAddr`), `n0_fallback = false` →
   `Endpoint::addr().relay_url` = свой relay, недоступный relay → `connect` падает за ≤ 5 с; **kill одного
   relay → re-home ≤ 60 с**, доставка после повторного lookup (регресс на #4476); «второй relay-URL в
   `EndpointAddr` используется / нет» — зафиксировать поведение iroh; unit-тест `AiraPreset`; proptest/fuzz
   парсинга `[network]` TOML (`fuzz_config`). Существующие тесты остаются на `presets::Minimal`.

### Milestone 21 — `aira-relay`: offline-доставка v2 (2–3 недели + 1 неделя на standalone-продукт)

**Зачем:** spec §6.3b/§6.5/§11B.5 обещают store-and-forward, а в коде — in-memory `RelayServer` без
аутентификации (Retrieve/Delete любому, кто знает `mailbox_id`), без квот отправителя, одна коробка на
пару, `Retrieve` одним кадром (> 256 KB рвёт стрим), и демон его не использует. Дизайн — аудит §4.3 +
`community-relays.md` §8.2; формула mailbox ID в трёх источниках расходится (§6.5, `relay.rs:28`,
`habr_article.md:367`) — фиксируется здесь. Это же продукт для сообщества («relay на своём VPS за 15
минут», §8.6), поэтому один бинарь и `docs/RELAY.md` — сразу.

1. **Крейт `crates/aira-relay` = один бинарь `aira-relay`** со встроенным iroh-relay (`iroh-relay =
   { features = ["server"] }` — только здесь; `Server::spawn` + собственный `AccessControl`, пример
   `iroh-1.2.0/src/test_utils.rs:51-84`), mailbox v2, intro-mailbox, `/healthz`, метриками, ACME
   (`LetsEncrypt` / `Reloading`); режимы **`--mode full | transport | mailbox`** (`transport` — cfg-гейт без
   mailbox/ACME/push, для M24a.2); mailbox-сервис — iroh-endpoint (`AiraPreset`), ALPN `aira/2/relay`, redb
   (`mailboxes`, `envelopes(mailbox_id, seq)`, `stats`), конфиг TOML; **один systemd-юнит** (заменяет stock
   iroh-relay из M20); `aira-relay init / doctor / status` (DNS, порты, ACME, clock skew, диск); `deploy/`
   (compose, systemd, `install.sh`); `release.yml`: linux x86_64 + aarch64 tar.gz с unit-файлом, musl для
   контейнера `ghcr.io/kamiletar/aira-relay` (по SHA, `provenance`/`sbom`, без `latest`) + attestation
   (M22-infra). Клиент в aira-net — `relay_client.rs` (одно соединение на relay, стримы на запросы,
   таймауты, `RelayHello`). **Удалить** `aira-net/src/relay.rs`, ALPN `aira/1/relay`, `tests/relay_offline.rs`
   (сценарий — в п.8); `NetError::{MailboxFull, MailboxNotFound, RateLimited}` → aira-relay;
   `docs/KEY_CONTEXTS.md:74` `aira/relay/mailbox/v1` удалить.
2. **Две коробки на пару по направлению (A1):** `mailbox_id[dir] = derive_key("aira/relay/mailbox/v2/"
   ‖ dir, shared_secret)`; `owner_key[dir]`, `sender_key[dir]` — Ed25519 из shared secret
   (`aira/relay/owner/v2/dir`, `aira/relay/sender/v2/dir`, в `docs/KEY_CONTEXTS.md`); relay видит
   только публичные. (Ack по ratchet-counter в одной коробке на два направления удалял чужие конверты —
   `relay.rs:285-291`; закрыто дизайном.)
3. Протокол: **`RelayHello { protocol_version: 2, supported, capabilities, catalog_class, operator_id,
   min_client_version }`** + `relay_nonce` (клиент отклоняет relay ниже `min_relay_version` каталога);
   **`Register { mailbox_id, owner_pk, sender_pk, device_id, notification_endpoint, ttl_hint, surb_stock: [] }`**
   (подпись owner; `device_id` — резерв M26, модель — **решение владельца (открыто, C3)**, рекомендация
   per-device/Sesame; `surb_stock` пусто до M24b); **`Deposit { targets: Vec<(mailbox_id, sender_sig)>,
   envelope }`**, `targets.len() ≤ 100`, квота отправителя считает `targets.len()` (резерв fan-out групп M25;
   незарегистрированная коробка → `MailboxNotFound`; nonce против replay); **`envelope_id =
   BLAKE3("aira/relay/envelope-id/v2" ‖ header)`** для дедупа при N-of-2; **`Retrieve { after_seq, limit }` —
   ответ ≤ `MAX_FRAME_SIZE`** (v1 отдавал до 6,4 MB одним кадром), `Ack { up_to_seq }` / `Delete` (подпись
   owner + nonce), `seq` присваивает relay, порядок у клиента — по ratchet-`counter`; `RelayMigration`
   (§11B.5.1) подписанная. **Депозит может приходить от хопа (M24b, AP-5):** авторизация только подписью
   `sender_sk`, лимиты по `sender_pk`/`mailbox`, не по EndpointId/IP депозитора. Все операции — под токеном
   допуска `scope: MAILBOX` (до M22 п.3 — метка «не секрет»).
4. **Intro-mailbox** по `pseudonym_pubkey` получателя (`aira/relay/intro/v2`): только
   `ContactRequest` с PoW ≥ 20 бит над `relay_nonce ‖ slot ‖ request` (общая функция сложности из
   M19a п.5) + rate limit по EndpointId; `scope: INTRO` — единственное место PoW на relay.
5. Квоты (§11B.5, переписать под v2): 100 конвертов / 10 MB на коробку, конверт ≤ 64 KB
   (`MAX_ENVELOPE_SIZE` из aira-core), TTL 7 дней **на конверт**, `total_cap` 1 GB, GC каждый час с
   приоритетом вытеснения коробок без retrieve, `Register` ≤ 20/сутки на EndpointId; **`max_mailboxes`**
   (глобально и per-owner), **`max_clients`** + accept-лимит в `AccessControl::on_connect` (замена no-op
   `accept_conn_limit`), `storage_budget` на ноду (0 у клиентских нод — F3), `Ack` без списков произвольной
   длины; лимиты публикуются в `.well-known/aira-relay.json` (дефолты, не догма; AP-6).
6. Push: `NotificationEndpoint::UnifiedPush { url }` — пустой wake-up без содержимого и без
   mailbox_id; клиент делает retrieve по всем своим коробкам. **URL только из `push_allowlist`**
   (единственный outbound relay = SSRF-вектор; без редиректов и приватных диапазонов, AP-1); в
   `--mode transport` push/ACME отсутствуют в коде. FCM — нет.
7. Демон: `relay_poll` (старт, каждые N мин, по push/onResume) → decrypt (skipped keys) → dedup →
   store → ack; при недоставке напрямую — **`deposit` N-of-2 параллельно** во все relay контакта,
   `Retrieve` со всех + дедуп по `envelope_id`; **`MailboxConfig.relays` = `ContactInfo.relays`** (одно поле,
   M19 Phase A п.1): 2–3 `RelayRef` разных операторов (`operator_id`, /24 и /48), без класса `client`;
   `DeliveryState::Relayed` после подтверждения депозита. Android: FGS только на время retrieve.
8. Тесты (`crates/aira-relay/tests`): «Bob офлайн 3 дня → Alice шлёт 3 сообщения → Bob вернулся →
   порядок и dedup»; «relay перезапущен — конверты на месте»; «чужой EndpointId / чужой `owner_key` не
   может retrieve»; «deposit без регистрации → `MailboxNotFound`»; «replay `Deposit` с тем же nonce
   отклонён»; «20 конвертов × 64 KB выгружаются полностью (пагинация)»; «ack по seq: одинаковые
   ratchet-counter в двух коробках не мешают»; **«N-of-2: один relay мёртв — доставлено»**; **«дубликат с
   двух relay — один в истории»**; **«push вне allowlist → отказ»**; «deposit без токена / с чужим
   endpoint_id → Deny» (после M22); quota/TTL/GC; proptest кодека; fuzz `RelayRequest`/`RelayResponse` v2,
   `RelayAnnounce` и токена в `crates/aira-relay/fuzz`.
9. Спека и документы: §6.3b, §6.5 (формула v2), §11B.5, §11B.5.1 переписаны; `spec/03-network.md`
   §5.1.2 «Роли relay» (anchor / community-server / клиентская нода — таблица `community-relays.md` §8.1);
   `spec/20-appendix.md:13` п.2 закрыть; `habr_article.md` раздел «Pairwise Relay Mailboxes» — под v2 и
   статус; **`docs/RELAY.md` v1**: установка за 15 минут (`install.sh`/Docker/tar.gz), `init/doctor`,
   порты и ACME, лимиты, `RUST_LOG=warn`, обновления, абьюз-контакт и юридический раздел («relay не
   exit», аналогия Tor bridge, не юридическая консультация — F8).

### Milestone 22 — Anti-abuse и токены допуска (1,5 недели) + трек «M22-infra» (параллельно M19)

**Вердикт по «ресурсоёмкому PoW при создании первого ключа»:** не вводить как основную меру
(аудит §5.3): цена ключа амортизируется (одна identity = бесконечный спам), DDoS relay идёт с
бесплатных Ed25519 EndpointId и от identity не зависит, grinding ломает детерминизм seed → identity
(или заставляет ждать минуты при каждом восстановлении), GPU-асимметрия 50–1000×. Вместо —
**цена каждого действия** + contact-first (§13.1). IdentityStamp — не в первом релизе (C12).

1. `Message::ContactRequest` (из M19a) в демоне: приём напрямую и через intro-mailbox; PoW
   адаптивный 16 → 28 бит (верификатор задаёт по нагрузке, `slot`/nonce живёт 30 с), **одна функция
   адаптивной сложности и `slot`-привязки** для `ContactRequest`, intro-mailbox (M21 п.4) и `HopSetup`
   (M24b); `RateLimiter::keyed` по EndpointId (10/мин, 3/ч на ключ, бан 1 ч); событие
   `ContactRequestReceived`.
2. Adaptive puzzle перед handshake от незнакомой ноды (§11B.2) — тот же код; контакты (Tier 1)
   без puzzle; tiers подключаются через **`EndpointHooks` iroh 1.2** (`endpoint/hooks.rs`) — та же точка,
   что инвариант AP-2 в M24b; `ratelimit.rs` tiers ↔ `ConnectionManager`/`contacts` в демоне.
3. **Токены допуска relay — обязательно (F):** в iroh отправитель всегда идёт на home relay получателя,
   поэтому `shared_token`/`allowlist` для сообщества непригодны. **`POST /token`** на anchor (`aira-relay
   --catalog`, DNS `relays.<domain>`): PoW adaptive из п.1–2, rate-limit по IP/EndpointId, срок 24 ч, `scope:
   RELAY | MAILBOX | INTRO`, привязка к EndpointId, ключ **Ed25519** (F6); **`AiraAccess`** — верификатор в
   `aira-relay` (`AccessControl`, офлайн по ключу из каталога; `iroh-relay-1.2.0/src/server.rs:224-233,
   256-278,285-310`); **`access.http.url → /relay-auth`** для stock `iroh-relay`; **denylist** EndpointId в
   подписанном каталоге; ответ `/token` несёт `X-Aira-Country` — вместе со `strict_countries` каталога это
   данные для гейтов M24a.2/M24c. Тесты: без токена → `Deny`; чужой endpoint_id → `Deny`; истёкший →
   `auth_denied_reason` + автопродление. Заглушка-метка из M20 п.4 удаляется.
4. `ContactStamp` (решение владельца 24.09, аудит §5.3.1 — вместо идеи «уровень надёжности по префиксу
   ключа»): hashcash-штамп `BLAKE3("aira/contact-stamp/v1" ‖ pseudonym_pk ‖ epoch ‖ bits ‖ nonce)` с ведущими
   нулями, epoch = неделя (истекает, приоритет нельзя купить навсегда), считается per-pseudonym (не линкует
   псевдонимы), не меняет ключ и seed (после восстановления пересчитывается в фоне); поле в `InvitationLink`,
   `ContactRequest`, `NodeRecord` хопа (M24b); даёт tier в очередях ContactRequest незнакомцев, `HopSetup`
   и регистрации mailbox; UI — бейдж «дорогой контакт» без цифр. 1–2 дня в aira-core + поля. Настоящий
   уровень надёжности — граф и поведение: контакт > контакт контакта > незнакомец со штампом > без.
   Privacy Pass rate-limited tokens — после релиза.
5. Спека: §13.2 (`spec/15-spam.md`) под adaptive difficulty, дубликат §13 из `spec/14-groups.md:406-471`
   удалить; новый §11B.10 «Стоимость identity» с этим вердиктом; таблица времён §11B.2 из бенча M19a;
   §11B.5.3 «Токены допуска».
6. Тесты: rate limit по EndpointId — 6-е сообщение stranger за минуту отброшено, contact без лимита,
   лимит соединений на tier; `ContactRequest` PoW negative (`difficulty < min` → reject); fuzz 60 с/таргет и
   coverage — блокирующие джобы (см. M23 п.1).

**Трек «M22-infra» — подпись, attestations, SBOM, релизный workflow (D6; параллельно M19/M19b,
нужны только решения владельца по бюджету и секретам; сетевые милстоуны не блокирует).** Полные
формулировки — `ci-supply-chain-audit.md` §9.1 «M23», набросок `release.yml` v2 — §8.3 (сверять, не копировать).

1. **Подпись (B6):** заявка в **SignPath Foundation** (Windows; бесплатно для OSS; условие — LICENSE +
   README + релизы, выполнено 24.09 + v0.4.0) → подпись MSI/exe в `release.yml` через SignPath-action;
   **minisign**-ключ владельца (офлайн, бэкап ×2 — D2) → `SHA256SUMS.minisig` на каждый релиз (тот же ключ
   для Tauri updater M17). Apple Developer $99 / notarization — **нет** (Sequoia+ через System Settings,
   Homebrew с 01.09.2026 не принимает — честно в INSTALL.md); Android developer verification — нет.
2. **`release.yml` v2:** `SHA256SUMS` + `actions/attest-build-provenance@v4` (`subject-checksums`;
   permissions `id-token`/`attestations`/`artifact-metadata: write`) — **SLSA Build L2** (L3 = reusable
   workflow, к 1.0 — D7); `cargo auditable build`; SBOM `cargo cyclonedx --describe binaries` +
   `actions/attest-sbom`; Linux-сборки в **контейнере `ubuntu:22.04`** (glibc 2.35; D5) + проверка `GLIBC_`
   (после этого INSTALL.md — baseline Ubuntu 22.04+); пин раннеров `ubuntu-24.04`/`macos-15`/`windows-2025`
   (`macos-latest` = macOS 26, `LSMinimumSystemVersion 10.13` фикция → `MACOSX_DEPLOYMENT_TARGET=11.0`); без
   rust-cache; `SOURCE_DATE_EPOCH` + `--remap-path-prefix`; **`environment: release` с ручным approve** (D8);
   `draft`/`prerelease`/`make_latest` (канал `0.5.0-beta.N` не становится latest); `check-artifacts.sh`;
   LICENSE/README/CHANGELOG в архивах; `--install-version` для MSI, `$env:GITHUB_REF_NAME` в pwsh; `cargo
   test` перед публикацией; `aira-relay` в матрице (M21 п.1).
3. `scorecard.yml` + `harden-runner` (audit; `block` — к 1.0); Dependabot security updates (файл из M18
   п.8); `.gitignore` `*.jks *.keystore`.
4. Документы: `docs/INSTALL.md` — `gh attestation verify`, `minisign -V`, обход Gatekeeper через System
   Settings, минимальная glibc; `docs/RELEASING.md` — порядок релиза (verify-job, draft, approve, подпись).

### Milestone 23 — Release hardening и публичная бета (1–2 недели → v0.5.0-beta.1)

Чеклист «минимум для беты» (аудит §6.6.7):

1. CI: `cargo audit`, `cargo deny`, clippy на запиненном stable — блокирующие (из M18 п.8);
   **ОС-матрица тестов ubuntu/windows/macos × stable + job `msrv` 1.91 — блокирующая**
   (`--all-features --locked`); интеграционные тесты M19 (`two_daemons`) и M21 (`crates/aira-relay/tests`)
   в матрице; fuzz 60 с/таргет; coverage `cargo llvm-cov` с порогом для aira-core (после первого замера,
   не ниже текущего); `cargo test` в `release.yml` перед публикацией.
2. Подписи: Windows — SignPath Foundation + `SHA256SUMS.minisig` (трек M22-infra; запасной — Certum
   OSS ~$50; Azure Artifact Signing физлицам вне US/CA недоступен, EV репутации больше не даёт);
   macOS — **без** Developer ID/notarization (B6; Sequoia+ через System Settings, Homebrew с 01.09.2026 не
   принимает) — честно в INSTALL.md; Android — APK не публикуется до подписи (M19b п.11).
3. Документы: `README.md`, `SECURITY.md` (контакт, ключ, 90 дней), `docs/THREAT_MODEL.md`, `docs/PRIVACY.md`
   — **созданы 24.09.2026; обновлять статусы «план → код» по мере реализации M19–M22**. THREAT_MODEL —
   таблица обещаний по четырём наблюдателям (собеседник; оператор одного relay / mailbox / хопа;
   провайдер и ТСПУ; глобальный пассивный наблюдатель; плюс Sybil-оператор хопов) с колонками «сейчас /
   после M19–M20 / после M24b / после M24d» из `onion-antiabuse.md` §1: «Aira скрывает IP от собеседника
   (relay-only) и, с M24b, от любого одного оператора инфраструктуры; защита от провайдера — устойчивость
   к блокировкам, не невидимость; от глобального наблюдателя — только в mix-профиле и с оговорками»;
   «невзламываемый» не употреблять нигде, «анонимный» — до M24b (B12); строки «группы — не реализовано»,
   «файлы — только 1:1, per-file ключ», «оператор anchor-relay видит IP + EndpointId всех пользователей
   беты». PRIVACY — «что видит оператор relay (anchor / сообщества / клиентская нода)», push без
   содержимого. `CHANGELOG.md`; `docs/INSTALL.md` (relay по умолчанию и `hide_ip`, Android preview, macOS без
   notarization, baseline Ubuntu 22.04+ / glibc 2.35 после M22-infra, `gh attestation verify` + `minisign
   -V`, ссылка на `docs/RELAY.md`); `CONTRIBUTING.md`, `CODEOWNERS`, шаблоны issue/PR. **Известные
   ограничения беты:** группы, мультидевайс, боты, реакции/ответы, edit/delete, receipts, typing, профили,
   search, mute, pin — после беты (M25–M28); голосовые (M15), разметка (M16), Tauri (M17), браузер (M14) —
   после беты; i18n — только en.
4. `release.yml` v2 — из трека M22-infra (SLSA Build L2: `SHA256SUMS` + `attest-build-provenance`,
   `cargo-auditable`, SBOM cyclonedx + `attest-sbom`, контейнер ubuntu:22.04, `environment: release`);
   здесь — финальная проверка: draft-релиз → ручной approve → `SHA256SUMS.minisig` → `prerelease: true`,
   `make_latest: false` для `0.5.0-beta.N`; `gh attestation verify` артефактов с чистой машины.
5. Схема версии БД (M19 Phase A) + явная политика «бета не гарантирует совместимость баз до 1.0»
   (протокол v2 без совместимости с 0.3.x — A2).
6. Android: preview — APK не публикуется до подписи (M19b п.11); Flathub — исключить (политика 2026
   запрещает AI-assisted код и PR); Play — не в бете.
7. GitHub Releases pre-release `0.5.0-beta.N` (tag ruleset `v*`, теги не переставлять, job `verify`);
   release notes: «relay-only по умолчанию — IP скрыт от собеседника», «standalone `aira-relay` доступен,
   роль relay в клиенте — после беты (M24a.2)», ограничения из п.3, шаблон bug report.
8. Состав беты (B10): desktop = egui (минимальный класс §15.8: онбординг, контакты и QR, 1:1-чат,
   файлы, TTL, block, safety number, экран Network) + CLI; Android — preview; Tauri (M17) — после беты,
   до 1.0.

Для 1.0 (после беты): внешний аудит aira-core + aira-relay + aira-onion (OTF Red Team Lab / OSTIF /
NLnet NGI Zero после возобновления calls) — аудировать тот протокол, который будет в 1.0, поэтому M24b
(и M25, если C1 = «до 1.0») идут до аудита; reproducible builds (`trim-paths`, `SOURCE_DATE_EPOCH`,
`scripts/reproduce.sh`) с независимой проверкой; `cargo vet` с импортом Mozilla/Google; reusable
release-workflow (SLSA L3), `harden-runner block`, signed commits/tags; 2-of-3 подпись каталога relay
(F1); winget / Homebrew tap (после подписи) / F-Droid (reproducible + flavor без FCM); решение по
Android developer verification до 2027.

### Milestone 24 — Сеть сообщества: community relays, Aira Onion, мосты (после M23; M24a–M24c до 1.0 — решение C4; M24d после 1.0)

Постановка владельца: сообщество плодит relay и повышает отказоустойчивость (`community-relays.md`);
IP скрывается от собеседника, оператора relay, провайдера и глобального наблюдателя, все пиры участвуют в
форвардинге, протокол нельзя превратить в паразитный прокси (`onion-antiabuse.md`). Вывод отчётов: «все
форвардят» и «нет паразитов» — одно требование, закрываемое семью инвариантами. Три роли инфраструктуры
(`community-relays.md` §8.1): **anchor** (relay проекта, M20/M21; токены, каталог, pkarr, брокер),
**community-server** (`aira-relay` энтузиаста: домен или IP + pin), **клиентская нода** (desktop с opt-in
ролью `relay` — только транспорт). У ноды **две iroh-идентичности** (C5): чат-EndpointId из seed и
хоп-EndpointId из локального RNG (второй `Endpoint` в демоне); роли `relay`/`mailbox`/`hop` чат-идентичность
не используют.

**Инварианты AP-1…AP-7 (onion-antiabuse.md §4) — обязательны для любого кода, который что-либо
форвардит: хоп, mailbox, роль relay в клиенте, standalone `aira-relay`; нарушение = блок PR:**

- **AP-1 Нет выхода.** В протоколе хопа нет «соединись с host:port»; терминал маршрута — mailbox v2
  (`Deposit`) на ноде Aira или SURB-ответ; файлы, превью, внешнее — никогда через хоп.
- **AP-2 Следующий хоп — только из своей таблицы.** Адрес по `next: EndpointId` берётся из таблицы нод /
  через свой relay, `TransportAddr::Ip` в ячейке невалиден; `EndpointHooks::before_connect` отклоняет
  адреса не из таблицы (иначе хоп — распылитель QUIC Initial по чужим IP).
- **AP-3 Ячейки маленькие и фиксированные** (1 KB полезных, остальное — фрагментация); ничего потокового.
- **AP-4 Каждый байт тарифицирован.** Форвардинг только под `key_id` за PoW с бюджетом байт и скорости;
  у ноды общий `share`, fair queuing; сложность PoW растёт с нагрузкой.
- **AP-5 Хоп не источник и не отвечает за содержимое.** Говорит только с нодами Aira; депозит
  авторизуется подписью `sender_sk` внутри ячейки, mailbox лимитирует по sender/owner, не по IP хопа.
- **AP-6 Хранилище — только зарегистрированные коробки** (`Register` с PoW, ≤ N/сутки, квоты, бюджет).
- **AP-7 Ёмкость растёт с нагрузкой.** Форвардинг включён у всех, у кого безопасен (desktop unmetered —
  по умолчанию, opt-out); I2P-модель.

Классы нод (флаги в `NodeRecord`, `onion-antiabuse.md` §5.1): `server` (aira-relay) — hop/mailbox/bridge;
`desktop-public` — hop по умолчанию, mailbox по бюджету диска, bridge; `desktop-nat` — hop с весом ×0.3;
`laptop-battery` — share ×0.25; `mobile` — только клиент (C7, F9); модификатор `hidden` (strict-страна или
выбор пользователя) — только для контактов, без листинга. Дефолты share: 32 KB/s, 3 GB/мес + счётчик
«вы помогли сети на N MB» (C10).

**M24a.1 — Каталог relay и community-server-relay (2–3 недели; после M21, M22)**

1. `aira-core::catalog`: `RelayCatalog { version, issued_at, expires_at (≤ 7 дней), min_client_version,
   min_relay_version, strict_countries, relays: Vec<RelayEntry>, denylist: Vec<EndpointId>,
   next_signing_key, signature }`, `RelayEntry { url, mailbox_endpoint_id, class, services: bitflags
   { IROH_RELAY, QAD, MAILBOX, INTRO, ONION_HOP }, region, operator_id, pin, limits, first_seen,
   uptime_30d, contact }`; postcard + JSON-зеркало; **подпись одним офлайн-ключом ML-DSA-65** (F1;
   2-of-3 к 1.0), публичный ключ вшит в бинарь, ротация через `next_signing_key`; парсер с fuzz-таргетом.
2. Сервис каталога `aira-relay --catalog` на anchor (`relays.<domain>`, F10): `RelayAnnounce` (подпись
   оператора + PoW 20 бит + ≤ 5 записей на `operator_id`), active-checks каждые 5 мин (`/healthz`, WSS
   `/relay`, QAD, `RelayHello`, `.well-known/aira-relay.json`), state-машина классов: `candidate` → `server`
   после 72 ч с ≥ 99 % проверок и версией ≥ `min_relay_version`; 3 неуспеха подряд → `down`, 24 ч `down` или
   30 дней без `announce` → удаление; выдача подписанного файла (подпись — ручной шаг, еженедельно или по
   событию); брокер `client`-записей (≤ 3 за запрос, по токену, в файл не попадают — против перечисления
   residential IP); `strict_countries`; открытые relay (`access = "everyone"`) не пускать (F7); `denylist`.
3. Оператор: `aira-relay register / withdraw / doctor / status / update-check`,
   `.well-known/aira-relay.json`; **без поддоменов операторам** (F2): свой домен + ACME (класс `server`)
   либо голый IP + `cert = "self-signed"` с печатью pin (класс `server-pinned`; Let's Encrypt по IP
   невозможен — `tokio-rustls-acme` знает только `Identifier::Dns`).
4. Клиент: загрузка/проверка каталога (раз в сутки + при старте; просроченный используется, но
   `client`-класс не запрашивается; раздача — снапшот в бинаре, `GET relays.<domain>/catalog.v1`, зеркало на
   GitHub, ALPN `aira/2/catalog` на anchor); `relay_stats` + health-score + backoff; выбор home relay и
   M mailbox-relay по правилу **разных операторов и /24, /48**, ранжирование `uptime_30d` × latency; anchor
   всегда в RelayMap; **pin-верификатор** в `ca_tls_config` (`custom_server_cert_verifier`: SNI/IP → pin из
   каталога или `RelayRef` контакта, иначе webpki); `RelayRef` в `InvitationLink` (M19 п.12) может нести
   relay вне каталога — URL + pin, аналог bridge-line; `client`-класс как home relay — только opt-in или
   fallback при недоступности anchor ≥ 2 мин (F4); UI «Network → Relays» (список, класс, статус, opt-in
   «использовать relay сообщества»), CLI `/relay`.
5. Тесты: подпись / просрочка / `next_signing_key`; state-машина классов (proptest по последовательности
   проверок); «relay другого оператора выбран для второй коробки»; «pin не совпал → соединение
   отклонено»; e2e: три in-process relay (anchor + 2 server), падение одного, доставка через второй.
6. Документы: `docs/RELAY.md` v2 (регистрация, классы), `spec/03-network.md` §5.5 «Каталог relay» (§5.3
   «signed update» → каталог), `spec/13` §11B.5.2 «Community relays», PRIVACY.md.

**M24a.2 — Opt-in роли `relay` и `mailbox` в клиенте поверх дефолтной роли `hop` (≈ 3 недели; после
M24a.1 и M19b п.5; полный UI — с M17)**

1. `aira-relay --mode transport --bind … --cert self-signed --announce-ephemeral` (cfg-гейт без
   mailbox/ACME/push; роль `relay` = **только транспорт**, mailbox в ней нет — F3), лимиты `limits.rs`
   (полоса, `max_clients` 50, трафик/мес, диск 0), глобальный token-bucket над `set_client_rate_limit`.
2. Демон: детектор кандидата (`net_report`: `global_v4/v6`, `mapping_varies`, portmapper; стабильность
   адреса 24 ч; metered; страна из `X-Aira-Country`; Android исключён навсегда — F9), IPC
   `SetRelayMode/GetRelayStatus`, супервизор дочернего процесса `aira-relay` (**отдельный процесс и
   хоп-EndpointId**, не чат-ключ; перезапуск, остановка при смене сети/metered/батарее), проба через anchor
   `POST /probe` с двух anchor, `announce` каждые 10 мин, `withdraw` при остановке.
3. Anchor: `POST /probe` (TLS+WS `/relay` + QAD к кандидату → `reachable_v4/v6, rtt, observed_ip`),
   rate-limit по токену.
4. UI: экран согласия (публикация IP, трафик, юридика; тексты в Fluent), лимиты, статистика, счётчик «вы
   помогли сети» (C10), трей; egui — тумблер + лимиты; Tauri/letar — полный экран. Гейты: metered/батарея →
   пауза; strict-страна → выключено, override через Advanced с предупреждением (F5); firewall-подсказки
   (`doctor`), UPnP/NAT-PMP TCP-маппинг через `portmapper` (поддержку TCP проверить). Роль `mailbox` на
   клиентской ноде — **отдельный opt-in в Advanced** с предупреждением о хранении чужих данных (не часть
   роли `relay`), класс не выше `candidate` до 72 ч uptime — контакты его не выберут; по умолчанию выключена.
5. CI-guard: `aira-ffi` не зависит от `aira-relay`; `aira-daemon` не линкует `iroh-relay/server`.
6. Тесты: матрица `should_offer_relay`; «без согласия процесс не стартует»; «metered → пауза»;
   «51-й клиент → Deny»; «20 ГБ → withdraw»; e2e с anchor-пробой на loopback.

**M24b — Aira Onion v1 (4–6 недель; после M21 и M24a.1, параллельно с M25/M17; до 1.0 — C4)**

Дизайн (`onion-antiabuse.md` §5): `NodeRecord` с гибридными KEM-ключами хопа (локальные, ротация раз в
неделю); `HopSetup` раз в сутки на хоп (X25519 + ML-KEM-768 через `kem.rs::hybrid_encaps` — постквантово,
без KEM в каждом пакете) + адаптивный PoW из M22 п.1 (`ContactStamp` — скидка) + бюджет 8 MB/24 ч и
16 KB/s на ключ; ячейка 1 280 Б (3 слоя × 80 + 1 024 + тег); маршрут S → G_s → M_s → **H** ← M_r ← G_r ← R,
где H — mailbox v2 (композиция SimpleX 2-hop и Veilid safety/private route); ответы по обратному
состоянию 30 с, push по SURB (`Register.surb_stock`, M21 п.3); профили `fast` (1+M+1) / **`standard` (2+M+2,
по умолчанию — C8)** / `mix` (M24d); файлы ≤ 10 MB через «медленную полосу» с PoW-марками, крупнее —
direct с предупреждением (C9). Имя фичи — **решение владельца (открыто, C11)**.

1. `crates/aira-onion` (`#![deny(unsafe_code)]`, без iroh): `NodeRecord` (подпись, TTL), `Cell` (слои,
   сдвиг, keystream, тег), `HopSetup`, фрагментация, SURB, бюджеты и PoW-верификация; proptest
   (roundtrip слоёв, «после снятия слоя длина не меняется», anti-replay) и fuzz (`Cell`, `NodeRecord`,
   `HopSetup` — внешние данные по определению) — 1,5 недели.
2. `aira-net/src/hop.rs`: `HopHandler: ProtocolHandler` на `aira/2/hop`, таблица ключей (LRU, окна),
   обратное состояние 30 с, DRR между ключами, share-бюджет, `EndpointHooks::before_connect` (AP-2),
   второй `Endpoint` под хоп-идентичность, rate-limited peer exchange, uptime-история — 1 неделя.
3. Маршруты в демоне: guard-выбор (персистентность, разнообразие /16 и AS, вес по uptime), профили
   `standard/fast`, повтор по таймауту, реплики H, `Wake` по SURB, `GetPeers`, `BridgeOffer` в `PlainPayload`
   (friend-bridges через E2E-канал контактов — точки входа без глобального каталога: «все пиры форвардят,
   но не все перечислимы»), hidden mode (только контакты и их маршруты), IPC `GetNetStatus { role,
   share_used, keys, guards }`, бюджеты в settings — 1 неделя.
4. `aira-relay`: тот же `HopHandler` + приём `Deposit` из ячеек (AP-5, M21 п.3), `surb_stock` — 0,5 недели.
5. Тесты: 5 демонов in-process (S, G, M, H, R) — доставка; «H не знает IP S и R»; «хоп не соединяется с IP
   из ячейки»; бюджет исчерпан → `Busy`; replay → drop; churn (убить M посреди передачи) — 1 неделя.
6. Спека: новый §5.5 «Aira Onion», §11 («вне scope: onion» → M24b), §11A (профили вместо режимов), §11B.5 +
   бюджеты хопов, §6.22 файлы по профилям, глоссарий; `docs/KEY_CONTEXTS.md`: `aira/hop/{key,fwd,back,surb,
   pow}/v1` (хоп-идентичность и KEM-ключи хопа — локальный RNG, исключение из M19 Phase A п.6);
   THREAT_MODEL — колонка «после M24b», матрица видимости `onion-antiabuse.md` §5.10.

**M24c — Мосты и обфускация (2–3 недели; до 1.0 для strict-стран)**

1. Датаграммный **`CustomTransport`** iroh 1.2 (`socket/transports/custom.rs`, фича
   `unstable-custom-transports` — риск API, зафиксировать версию iroh) вместо удалённых в M18 п.10 байтовых
   `transport/*`; первый хоп / relay через мост.
2. `aira/bridge/obfs/v1` (KEY_CONTEXTS): PSK-обфускация датаграмм без сигнатуры; `BridgeOffer { addr, psk,
   expires }` в `PlainPayload` и в ссылке — мосты раздаются контактам, не каталогом.
3. Hidden mode авто: **strict-список стран — решение владельца (открыто, C6)**; рекомендация — список в
   репозитории (старт — список I2P: RU, CN, IR, …), обновление с релизами, страна — `X-Aira-Country` своего
   relay + локаль + выбор в онбординге; в strict-профиле «relay только через мост»; override через Advanced
   с предупреждением (F5).
4. **DPI-тест на реальном трафике** (nDPI/Wireshark — требование M7 п.6, до сих пор не выполненное): QUIC
   v1 к relay фингерпринтится (ALPN `aira/*` и TLS-параметры читаемы в QUIC Initial), мост — без сигнатуры;
   тест обязателен до объявления фичи. Спека: §11A таблица статусов → «мосты v1», §11A.6; THREAT_MODEL
   строка «провайдер / ТСПУ».

**M24d — Mix-профиль (2 недели; после 1.0)**

1. Loopix: Poisson-задержки на хопах, cover-петли клиента и H (≈ 1,7 GB/мес, только desktop),
   `Drop`-ячейки, метрики.
2. Профиль `mix` в настройках; THREAT_MODEL — колонка «глобальный наблюдатель» с оговоркой о размере
   активного множества.
3. Тесты: распределение задержек, cover-трафик не отличим по размеру и ритму.

### Milestone 25 — Группы v2 (3–4 недели; после беты; до 1.0 или после — решение владельца (открыто, C1))

**Зачем:** групповой код v0.3.5 не доставляет и небезопасен (G1–G6, S1 в `spec-remainder-audit.md`
§1), в бете отключён (M19 п.9). Зависимости: M19a (резерв `PlainPayload::GroupMessage`, бит `GROUPS`),
M21 (`Deposit{targets}`, офлайн-control через mailbox), M22 (contact-first: `ContactRequest`-gate перед
`CreateGroup` от незнакомцев); от M24 не зависит. Если «1.0 без групп» — M25 уходит за 1.0 и требует
отдельного аудита `group.rs` (~600 строк core). Нагрузка fan-out `Deposit{targets}` (N× на сообщение)
входит в модель квот relay (M21 п.5, M24a).

1. Модель участника `{ pseudonym_pk, contact_id, role, epoch }` (G3: сейчас псевдоним у создателя vs
   1:1-ключ у получателя, control адресуется в очередь несуществующего контакта —
   `handler.rs:373-394,429,699,725,314-316`).
2. Wire: `EncryptedGroupEnvelope` в зарезервированном `PlainPayload::GroupMessage`; Sender Keys реально
   применяются (G1: `handle_send_group_message` рассылает `PlainPayload::Text` каждому, включая себя —
   `handler.rs:441-477`); **подпись конверта — решение владельца (открыто, C2)**: рекомендация —
   Ed25519 per sender key (64 Б) + AAD `group_id ‖ sender ‖ counter` (G2: `group_proto.rs:54-65`,
   `group.rs:230-235` — любой участник может подделать `from`), PQ-вариант ML-DSA-65 псевдонимом
   (3,3 KB/сообщение) — позже.
3. Персистентность: таблица `group_sender_states`, запись до отправки (G4: `group.rs:36,187,219-227` —
   повтор (key, nonce) после рестарта, MAX_SKIP-тупик); zeroize и локальный nonce из M19a п.7 (S6).
4. Авторизация `GroupControl` (S1; `handler.rs:688-819`): `CreateGroup` → только `GroupInviteReceived`
   без записи в БД и без auto-accept (`:737-739`), cap `members ≤ MAX_GROUP_MEMBERS`; `AddMember /
   RemoveMember` требуют `role == Admin` у `sender_pubkey`; `sender_keys` принимаются только для
   `new_member` (`:764-768`); все sender-key поля ровно 32 Б (`:711-712, :766-767, :811-813`);
   epoch-ротация §12.5 полностью (G5); порядок и dedup §12.4 — ключ не `(group_id, timestamp_micros)` (G6).
5. Fan-out через mailbox v2 `Deposit{targets}` (M21 п.3), офлайн-control через коробки; групповые
   запросы в IPC включаются обратно, UI групп открывается (egui `views/groups.rs`, CLI `/group`, Android
   `GroupsScreen`, Tauri — M17 п.7).
6. Тесты: **группа из трёх демонов** (перенесено из M19 Phase C): create → сообщение → все получили,
   + Bob офлайн → через mailbox; «AddMember от Member отклонён», «чужой pk в sender_keys
   игнорируется», «CreateGroup без accept не создаёт группу», «sender key 31 байт отклонён», «замена
   `from` без ключа подписи → отклонено»; fuzz `fuzz_group_decrypt` (M19a п.8), proptest
   `SenderKeyReceiver` (окно, replay, ротация).
7. Спека §12 переписана (`spec-remainder-audit.md` §5.3), `spec/14-groups.md` без дубликата §13;
   THREAT_MODEL — «группы: реализовано»; `habr_article.md`.

### Milestone 26 — Мультидевайс v2 (4–6 недель; после 1.0 → 1.1: меняет модель сессий, повторный аудит ядра)

Зависимости: M19 Phase A п.6 (`device_index`, `pseudonym_counter`), M20 (pkarr), M21 п.3
(`Register{device_id}`), M19a п.4 (`SignedPrekeyBundle{device_id}`); M25 не обязателен (`GroupUpdate`
sync-item без него пуст). Число коробок на пользователя × устройства — в модель квот relay.

1. Модель — **решение владельца (открыто, C3)**: per-device сессии (Sesame; рекомендация) или handoff с
   арендой (§14.3c в нынешнем виде несовместим с mailbox v2 — D4); определяет семантику `device_id`.
2. per-device `EndpointId` (`aira/iroh/secret/<device_index>`, index 1..4) и `DeviceRecord` в pkarr /
   `InvitationLink`; `SignedPrekeyBundle` per device; per-device коробки в mailbox v2.
3. Привязка: QR с одноразовым секретом вместо link-code (D5: 20 бит энтропии, канал не определён, код
   ничего не доказывает); `derive_device_id(seed, index)` (M19a п.6); sync через ALPN `aira/2/sync`
   (`sync.rs` сейчас никем не вызывается): контакты, сообщения, настройки; ratchet state — по модели п.1.
4. IPC `LinkDevice / ListDevices / UnlinkDevice` включаются обратно (M19 п.9), UI «Linked devices».
5. Тесты: 2 устройства одного пользователя (M8 п.6); unlink → старое устройство не расшифровывает
   новые сообщения; key isolation псевдонимов на двух устройствах (M19 Phase A п.6).
6. Спека §14 переписана (D7: термины и ссылки устарели), `docs/KEY_CONTEXTS.md`, THREAT_MODEL.

### Milestone 27 — Bot API v2 (1–2 недели + sandbox отдельно; после 1.0)

Зависимости: M19b п.3 (`ipc.token`, `--data-dir/--socket`), M25 для групповых ботов.

1. Модель «SDK для собственного демона» (B11): бот = свой демон со своим seed (`aira-daemon --data-dir`),
   SDK — клиент через `connect_with_token`; §17A и `docs/BOT_SDK.md` переписаны под код (B4 — API
   §17A.2/17A.4/17A.6 расходится с кодом).
2. `UserProfile.is_bot` (§6.17); scoped IPC-токены (`read`, `send`, `admin`; сейчас scope'ов нет — B3);
   `on_command`; `my_address()` без создания псевдонима на каждый вызов (B5).
3. Группы для ботов (после M25).
4. WASM sandbox (wasmtime, M6A п.5) — опционально, отдельная оценка.
5. Тесты: echo-бот e2e через два демона; токен без scope `send` → `Error`.

### Milestone 28 — Дешёвые фичи §6.x (2–3 недели суммарно, дробится; 0.6.x / 1.x)

Зависимости: M19 (`MessageMeta` по проводу и в IPC), M19a п.1 (зарезервированные варианты
`PlainPayload::{Reaction, Receipt, Typing, Pin, Profile}`; если чего-то нет — v2.1 с битом capabilities).

1. Реакции и ответы (`reply_to` уже в `MessageMeta`), edit/delete.
2. Read/played receipts (`MessageRead { message_id }` в IPC + по проводу; одна/две галочки в egui из
   M9.6 Phase E), typing.
3. Pin, search (локальный, по расшифрованной истории), mute.
4. Профили без `is_bot` (имя/аватар, §6.17); i18n — подключить fluent (en/ru, 33 ключа) к Tauri/letar и
   CLI, `/lang` (M9.6 Phase C; для egui — только отдельным решением владельца).
5. CLI-команды возвращаются в справку по мере реализации (`/mute /unblock /profile /lang /search
   /delete-account` — убраны в M19b п.4).
6. Тесты: roundtrip и golden-байты новых вариантов; receipts не утекают при `blocked`.

### Пересмотр Milestone 6–9.6 и 14–17

- **Статусы старых милстоунов (по коду HEAD 7726b46):** M6 — библиотека + IPC/UI без доставки, реализация →
  M25; M6A — SDK для собственного демона → M27; **M7 и M12 — `transport/*` удалены в M18 (A13)**,
  DPI-история беты = iroh-relay по WSS:443 на своём домене (M20), обфускация возвращается как
  датаграммный `CustomTransport` в M24c, REALITY исключён; M8 — примитивы → M26; M10 — Android preview
  (M19b); M13 — `awslc.rs` есть, FIPS не заявлять (M18 п.5).
- **M9.6:** Phase A выполняется в M18; Phase B — в M19b п.11 (после десктопа, бету не блокирует);
  Phase C/D/E (i18n, темы, UX polish) — после беты и **по умолчанию уже в Tauri (M17)**; для egui —
  только отдельным решением владельца (заморозка минимального класса §15.8); i18n-инфраструктура —
  M28 п.4.
- **Бета 0.5: desktop = egui (минимальный класс) + CLI, Android — preview без APK** (B10, B4); Tauri
  (M17) — между бетой и 1.0.
- **Порядок после беты:** **M16 → M25 → M17 → M24a + M24b (параллельно, другой разработчик/агент) →
  M24c → 1.0 (внешний аудит) → M24d → M26 → M28 → M15 → M27 → M14.**
  - **M16 (разметка)** — дёшево и безопасно, первым после беты.
  - **M25 (группы v2)** — до Tauri, чтобы M17 п.7 переносил группы уже рабочими («… → группы» в M17
    п.7 читать как «после M25»); до 1.0 или после — C1 открыто.
  - **M17 (Tauri)** — после того, как сетевой слой стабилен в демоне (иначе перенос UI поверх
    неработающей доставки удваивает миграционный долг); minisign-ключ из M22-infra — тот же для updater.
  - **M24a/M24b** — параллельно M25/M17, до 1.0 (C4): внешний аудит должен видеть тот протокол, который
    будет в 1.0; **M24c** — до 1.0 для strict-стран; **M24d** — после 1.0.
  - **M26, M28, M15 (голосовые), M27** — после 1.0 в этом порядке.
- **M14 (браузер)** — последним, после M21 и всего вышеперечисленного (4–6 недель): без своего relay (M20)
  браузер не подключится, без mailbox (M21) не получит ничего при закрытой вкладке. Исследование — аудит
  §6; решения по браузеру — **решение владельца (открыто, C13)**, рекомендации ниже.
  Правки к тексту M14 выше:
  - §14.4: **`redb-opfs` не использовать** — `GPL-3.0-only` (Aira MIT/Apache-2.0), README
    «statement of intent», git-зависимость на master redb, репозиторий мёртв с 2025-09-25, на
    crates.io нет. Вместо него свой `OpfsBackend` (~200–300 строк) поверх redb 4
    `StorageBackend` в dedicated Worker (`send_wrapper` для Send+Sync); этап 0 —
    `InMemoryBackend` + периодический зашифрованный снапшот в OPFS. `navigator.storage.persist()`
    обязателен (Safari вытесняет данные через 7 дней без взаимодействия; потеря ratchet-состояния
    = невозможность расшифровать дальнейшие сообщения).
  - §14.1 п.3: `getrandom` **0.4** (iroh 1.2) и 0.2 (`js`, пока жив rand 0.8) — фичи только в
    `aira-wasm` как target-specific deps; с 0.3.4 `--cfg getrandom_backend` не нужен.
  - §14.2 п.3: `Platform::Mobile` удалён (M19a), `Platform::Browser` не вводить; Argon2id 256 МБ
    считать в отдельном одноразовом KDF-воркере и терминировать его (WASM-память не
    возвращается); seed между сессиями — vault, не повторный derive (C13); iOS Safari может убить
    вкладку молча — веб-клиент, вероятно, «desktop + Android Chrome», iOS не поддерживается.
  - §14.3: п.5 «опционально iroh 1.0» → iroh 1.2 обязателен (M18); `iroh = { version = "1",
    default-features = false, features = ["tls-ring"] }` (aws-lc-rs/PQ-TLS под wasm недоступен);
    `tokio` только sync/macros/rt/time/io-util + `n0-future`; **iroh-blobs не поддерживает
    браузер** (issue #90) — файлы в браузере исключены, `SendFile` → `Unsupported`; discovery —
    relay_url + EndpointId внутри InvitationLink/контакта, без pkarr-lookup из браузера; п.4 —
    транспорты `obfs4/reality/cdn/tor` уже удалены (M18 п.10), под wasm недоступен и `CustomTransport`
    (M24c).
  - Новый **§14.0 — предпосылки в ядре (внутри M18/M19, 3–5 дней):** redb 2.6 → 4.2 (redb < 3.1
    не компилируется под wasm32; формат v2 удалён в 3.0 → миграция через `redb2 = { package =
    "redb", version = "2.6" }` + `Database::upgrade()` либо объявить БД 0.3.x несовместимой —
    C13, рекомендация: несовместимость, как и протокол v2 по A2) и `Storage::open_with_backend`;
    `backup.rs` → `export_bytes/import_bytes` (M19 Phase A п.4); единая точка времени
    `aira_core::util::{now_micros, now_secs}` на `web-time` (сейчас `SystemTime::now()` в util.rs:16,25,
    contacts.rs:18, dedup.rs:19,55, messages.rs:114,147 паникует под wasm; `Instant` в connection.rs);
    tokio per-target в aira-net; cfg-гейты на `blobs`; крейт `aira-ipc` (types.rs + фрейминг, без tokio) и
    библиотека `aira-node` (SessionManager, handler, pending-дренаж) — их же используют aira-daemon,
    aira-ffi и aira-wasm (минимум в M19 п.14 — `ipc.rs` в lib; полное выделение — по C13); `rust-embed`
    `debug-embed` для wasm; CI guard `cargo check -p aira-core --target wasm32-unknown-unknown` (M18 п.8).
  - §14.5: `wasm-pack build --target web --release` + `wasm-opt -Oz`, `wasm-pack test --headless
    --chrome --firefox`; **размер .wasm (gz/brotli) — первый замер**, при > 5–8 МБ демо на мобильных
    бесполезно. CSP `script-src 'self' 'wasm-unsafe-eval'; connect-src 'self'
    wss://relay.<domain>; worker-src 'self'`; COOP/COEP не нужны. Web Push не делать.
  - Требования к relay (M20/M21): TLS 443 с публичным сертификатом, WebSocket `/relay` через
    nginx (браузер всегда на challenge-fallback; при варианте A SNI passthrough — отдельный vhost для
    web), **отдельный ротируемый токен допуска для web** (уходит в `?token=` URL → логи прокси; выдача
    через `POST /token` из M22 п.3), CORS на `/pkarr/*` и `/healthz` при необходимости; aira-relay без
    допущений о прямом UDP, PoW/квоты на intro-mailbox до открытия веб-демо; hide_ip в браузере —
    по построению (только relay).

---
