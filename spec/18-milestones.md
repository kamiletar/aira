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

1. `aira-core/src/group.rs` — Sender Keys, Group Ratchet
2. `aira-core/src/group_proto.rs` — протокол создания/управления группой
3. `aira-storage/` — таблицы groups, group_messages
4. Интеграция с daemon IPC (create/join/leave group)
5. CLI: отображение групповых чатов
6. Интеграционный тест: 3 ноды в группе

### Milestone 6A — Bot SDK (v0.2, 1-2 недели)

1. `aira-bot/src/lib.rs` — trait `Bot`, `BotContext`
2. IPC клиент для daemon (подписка на события, отправка сообщений)
3. Пример: echo-бот
4. Документация: как написать и запустить бота
5. WASM sandbox (wasmtime) — v0.3

### Milestone 7 — DPI resistance (v0.2, 2-3 недели)

1. `aira-net/src/transport/mod.rs` — trait `AiraTransport`, direct transport
2. `aira-net/src/transport/obfs.rs` — obfs4/o5 через ptrs
3. `aira-net/src/transport/mimicry.rs` — CPS protocol mimicry (DNS/QUIC/SIP)
4. `aira-net/src/transport/cdn.rs` — CDN relay (Cloudflare Worker)
5. CLI: `/transport <mode>` — переключение режима
6. Тест: DPI-симулятор (nDPI/Wireshark) не распознаёт aira трафик

### Milestone 8 — Мультидевайс (v0.3, 3-4 недели)

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
   сверка отпечатков → переписка 1-на-1 → файлы → группы → голосовые заметки (M15) →
   разметка (M16)
8. Системный трей, автозапуск и уведомления — по таблице §15.2, но через плагины Tauri

---


## 16.1 Релизный путь (пересмотр сентября 2026)

> ⚠️ **Фаза 3 аудита (07.09.2026, вечер)** дала правки к M18–M23, ещё **не внесённые** в текст ниже — см. `.claude/docs/release-audit-2026-09.md` §8 (по темам: §8.1 security-compliance, §8.2 aira-net, §8.3 тесты/фаззинг, далее CI, остаток спеки, community relays). Самое важное: **M19 п.7 — НЕ регистрировать `Arc<RelayServer>` в роутере клиента** (каждый клиент стал бы открытым mailbox-relay без auth); **M19 п.10 — без fallback на `aira/1/relay`** (Retrieve v1 не выгружает коробку > 256 KB); M18 п.3 — правок вне aira-net не ожидается (1 строка в endpoint.rs:78); M19 Phase B — авторизация входящих `GroupControl` (handler.rs:688-819) до подключения приёма групп; M19b — удалить transport/\* и скрыть выбор транспорта в UI. Перед стартом M18 перенести правки из §8 в этот раздел.
>
> ⚠️ **Фаза 3, продолжение (23.09.2026, темы D–G, аудит §8.4–§8.7).** Добавились: **§8.5** (группы/мультидевайс/Bot API — в бете 0.5 отключить честно; блокеры плана до M19: iroh SecretKey per-device `aira/iroh/secret/<device_index>`, единый контракт `MessageReceived`/`MessageMeta`, `pseudonym_counter` по `device_index`; TTL и `/block` сломаны; реализация — M25 группы v2, M26 мультидевайс v2, M27 Bot API v2, M28 §6.x); **§8.7** (скрытие IP и анти-паразитный форвардинг при участии всех пиров, `.claude/docs/audit-2026-09/onion-antiabuse.md`: M19 п.7 — `NetConfig { hide_ip }` → `clear_ip_transports()` iroh 1.2, дефолт true; M19b п.12 — **invitation link без IP** (`EndpointAddr::new(id).with_relay_url(url)`, не `postcard(ep.addr())`); M20 п.4 — `accept_conn_limit/burst` в iroh-relay не реализованы, RelayMap клиента = свои 1–2 relay; M18 — iroh 1.2.0 (09.09.2026); новые **M24a/M24b** community relays: каталог + server-relay, client-relay (§8.6), **M24c** Aira Onion v1, **M24d** мосты/обфускация через `CustomTransport`, **M24e** mix-профиль; инварианты AP-1…AP-7 обязательны для любого форвардящего кода). **§8.4** (CI на `main` красный с 10.04: 18 advisories + clippy 1.98 из-за плавающего `@stable`; в корне нет `LICENSE-MIT`/`LICENSE-APACHE`/README при «MIT OR Apache-2.0» — до тега v0.4.0; `release.yml` с write-токеном исполняет непроверенный `linuxdeploy`; 0 SHA-пинов, нет `permissions`/`--locked`/Dependabot; M18 п.8 → полный список CI-гвардов, M23 п.4 → SLSA L2 + `SHA256SUMS` + auditable + SBOM); **§8.6** (один бинарь `aira-relay` со встроенным iroh-relay и токеном допуска вместо двух юнитов M20/M21; у iroh один home relay на endpoint → watchdog re-home + 2–3 `RelayRef` в приглашении/контакте до беты; client-relay — только транспорт, opt-in, отдельный процесс; push-URL mailbox = SSRF → `push_allowlist`; `cert_mode = "Reloading"` в 1.2). Сводный список решений владельца — `.claude/docs/audit-2026-09/owner-decisions.md`.

**Контекст.** Аудит 2026-09-07 (`.claude/docs/release-audit-2026-09.md`, HEAD `971e038`, v0.3.5) показал:

- **Блокер №0:** `aira-daemon` не поднимает iroh Endpoint/Router и не использует handshake/ratchet/relay.
  `SendMessage` пишет в redb и отвечает `Ok`; `pending::dequeue` не вызывается нигде. Сообщения
  никогда не покидают локальную базу — ни онлайн, ни офлайн. Всё, что описано в M2–M4 как
  «сетевое», существует только как библиотечный код в `aira-net` и его тесты.
- **Блокер №1:** n0 отключает публичные relay для клиентов iroh 0.9x **30 сентября 2026**.
  Клиенты за NAT на v0.3.5 после этой даты не соединятся. Миграция на iroh 1.1 одновременно
  разблокирует `ml-dsa 0.1.1` (iroh-base 0.97 пинит `digest = "=0.11.0-rc.10"`) и снимает
  advisories quinn-proto / hickory-proto.
- Протокольный слой `aira-core` (ratchet, handshake) не готов к «релизу с обещанием
  совместимости» (§2.5 аудита, находки C1–C7): wire не несёт заголовок ratchet, AEAD без AAD,
  PQ-шаг ratchet никогда не стартует, handshake не PQXDH, подписи без SIGMA-binding.
- Клиенты: `keyring` без platform-features (mock store → seed не переживает перезапуск GUI),
  релизный APK не подписан вообще, Android-оболочка без provisioning seed.

**Порядок.** Milestone 9.6 и 14–17 переносятся *после* релизного пути. Версии:
`0.4.x` — M18–M22 (bridge-релизы без обещания совместимости), `0.5.0-beta.N` — M23,
`1.0` — после внешнего аудита. Релизный протокол = **v2** (`min_version = max_version = 2`);
v1 объявляется pre-release без гарантий (у v0.3.x сети нет — ломать нечего).

```
M18 (iroh 1.1 + PQ) -> M19a (протокол v2) -> M19 (демон в сети) -> M21 (aira-relay) -> M22 -> M23 -> бета
                                                 | параллельно с M19:
                                                 |-- M19b (клиентские блокеры, Android)
                                                 |-- M20 (свой iroh-relay + discovery)
```

Решения, которые нужны от владельца до старта (каждое — одна строка в PR-описании M18):

1. Mailbox v2: две коробки на пару по направлению (рекомендуется) или одна (§6.5 сейчас).
2. Протокол v2 без совместимости с 0.3.x — да (рекомендуется).
3. DHT (§5.2b, §11B.4) уходит после релиза; discovery = pkarr через свой `iroh-dns-server` — да.
4. `Platform::Mobile` в `seed.rs` удалить (разные соли → разные identity из одной фразы) — да.
5. Порты mail-сервера: кто держит 80/443 (nginx?), открыт ли udp/7842 → вариант A или B в M20.
6. Android в первой бете: доводить (M19b Android-пакет) или пометить preview и убрать из assets.
7. Android developer verification ($25 + government ID; блокировка sideload с 30.09.2026 в
   BR/ID/SG/TH, глобально 2027) — регистрироваться или принять ограничение.
8. Бюджет подписи: Apple Developer $99/год (notarization); Windows — заявка в SignPath
   Foundation (бесплатно для OSS) или Certum OSS (~$50).

### Milestone 18 — Миграция iroh 1.1 + ml-dsa 0.1.1 / ml-kem 0.3.2 (v0.4.0, 3–5 дней, дедлайн 30.09.2026)

**Зачем:** без этого клиенты за NAT перестанут работать 30.09.2026, а `ml-dsa 0.0.4` несёт три
известных дефекта (RUSTSEC-2025-0144 / CVE-2026-22705 timing при подписи; CVE-2026-24850
нестрогая проверка hint'ов; GHSA-h37v-hp6w-2pp8 — валидная подпись может не пройти верификацию).
Все закрыты в `ml-dsa 0.1.1`. Один PR, ветка `milestone/18-iroh-pq`.

⚠️ Незакоммиченный bump `ml-dsa = "0.1.0-rc.4"` в `Cargo.toml` не собирается (sha3 rc.6 vs keccak)
и не нужен — откатить, целевые версии ниже. `ml-dsa 0.1.1` не резолвится при iroh 0.97, поэтому
Phase A из M9.6 отдельно невозможна.

1. **Шаг 0 — снапшот-векторы с тега v0.3.5 (до любых правок).** `git worktree add ../aira-v035
   v0.3.5`; временный тест печатает hex для `seed = [7u8; 32]`: `identity_keygen →
   encode_verifying_key` (1952 байт), `sign(sk, b"aira-snapshot-v1")` (3309), `kem_keygen →
   encode_kem_encaps_key` (1184) и `encode_kem_decaps_key` (2400), плюс
   `MasterSeed::from_phrase(<фиксированная фраза>).derive("aira/identity/0")`. Сохранить в
   `crates/aira-core/tests/vectors/v0_3_5.json`. Расхождение VK после миграции = **релиз-блокер**
   (адрес пользователя = байты VK).
2. **Cargo.toml (workspace):** `iroh = { version = "1.1", default-features = false, features =
   ["metrics", "portmapper", "fast-apple-datapath", "tls-ring"] }`, `iroh-blobs = "0.103"`,
   `ml-dsa = { version = "0.1.1", features = ["zeroize"] }`, `ml-kem = { version = "0.3.2",
   features = ["zeroize", "getrandom"] }` (фича `deterministic` удалена), `kem = "0.3"`,
   `aws-lc-rs = "1.18"` без `unstable`, `rust-version = "1.91"`. x25519-dalek 2 /
   chacha20poly1305 0.10 / argon2 0.5 / rand 0.8 **не трогать** (типами не пересекаются; rand 0.8 и
   0.10 в графе одновременно — допустимо).
3. `crates/aira-net/src/endpoint.rs:78` — `Endpoint::empty_builder()` удалён в 1.x →
   `Endpoint::builder(presets::Minimal)` в тестах; `presets::N0` в проде остаётся до M20.
   Далее `cargo check --workspace --all-targets` и починка daemon/ffi/gui/cli по мере всплытия
   (эксперимент остановился на aira-net, объём выше неизвестен).
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
   `encode_kem_decaps_key`, чтение обоих форматов; тест «снапшот v0.3.5 с 2400-байтным DK читается».
7. Тесты: (а) snapshot-совпадение VK/EK/подписи с `v0_3_5.json`; (б) `cargo test -p aira-core
   --features compat-test` (8 кросс-бэкендных); (в) EK с коэффициентами ≥ q → `Err(InvalidKey)`;
   (г) CT длины 1087/1089 → `Err`; (д) proptest sign/verify roundtrip; (е) fuzz-таргеты
   `decode_verifying_key` / `decode_kem_encaps_key`.
8. Удалить `RUSTSEC-2025-0144` из `deny.toml:45` и `.cargo/audit.toml:12`. `cargo audit` должен
   потерять quinn-proto / hickory-proto / ml-dsa. CI: посмотреть лог упавшего job Clippy от
   2026-07-30 (локально exit 0 на rustc 1.94.1), починить под актуальный stable.
9. Документы: `spec/12-dependencies.md` (iroh 1.1, iroh-blobs 0.103, ml-dsa 0.1.1, ml-kem 0.3,
   getrandom 0.4, rust-version 1.91), `CLAUDE.md`, `spec/03-network.md:21-22`,
   `spec/01-overview.md:103`; `habr_article.md` блок Cargo.toml. Тег `v0.4.0` — bridge-релиз,
   только зависимости, без сети (release notes честно).

Не цели: PQ-TLS на транспорте (`iroh/tls-aws-lc-rs` + `rustls/prefer-post-quantum`) — отдельная
фича `pq-tls` в aira-net после релиза (нативная сборка aws-lc, несовместимо с wasm).

### Milestone 19a — Протокол v2 в aira-core (v0.4.x, ~2 недели)

**Зачем:** wiring демона к сети (M19) поверх текущего wire-формата означал бы ломать формат
дважды. Находки C1–C7 аудита закрываются здесь, до сетевого кода.

1. **Wire-формат (C1).** `proto.rs`: `Message::Ratchet { header: MessageHeader, envelope:
   EncryptedEnvelope }` — `dh_public`, `prev_chain_len`, `pq_kem_ct`, `pq_kem_ek` из `ratchet.rs:40-52`
   идут в заголовке; `header` целиком — AAD для AEAD. Версия формата в `Capabilities` (§6.4):
   `min_version = max_version = 2`. Описать в `spec/04-protocol-wire.md` §6.1.
2. **Транзакционный decrypt (C2).** `ratchet.rs:297-323`: все skip/DH/PQ-шаги на клоне
   состояния, коммит только после успешного `aead_decrypt`. Тест «битый header / битый ciphertext
   не меняет состояние сессии».
3. **Рабочий PQ-шаг (C3, C4).** `RatchetSession::new` получает ML-KEM ek пира из handshake;
   `pq_kem_ct` обрабатывается независимо от `need_dh_ratchet`; ML-KEM keypair ratchet — из OS RNG
   (`root_key` только для KDF-миксинга, контексты `aira/ratchet/pq-init` / `pq-rekey` пересмотреть
   в `docs/KEY_CONTEXTS.md`). Спека §4.4 обещает шаг «при смене направления» — реализовать
   direction-change trigger в дополнение к `PQ_RATCHET_INTERVAL = 50`. Тесты: 100+ сообщений с
   `pq_enabled = true` в обе стороны, снапшот после PQ-шага, out-of-order через PQ-шаг.
4. **Handshake = PQXDH-подобный (C5, C6).** Ephemeral ML-KEM keypair на каждый handshake;
   `identity_pk` обеих сторон и все публичные значения в `derive_session_keys`; SIGMA-binding —
   подпись ack над `init ‖ ack`; nonce инициатора + timestamp против replay. Для асинхронного старта
   через relay (M21) — подписанный PQ prekey bundle (`SignedPrekeyBundle { x25519, mlkem_ek,
   sig, expires }`). Тесты: replay, identity misbinding, downgrade (клиент с `pq=false`).
   §4.5.1 (chunked handshake ≤ 1200 B) переписать под QUIC-стримы + relay fallback (C12).
5. **`spam.rs` (C7):** `min_difficulty` задаёт верификатор; PoW над
   `recipient_pubkey ‖ server_nonce ‖ issued_at ‖ request` (сейчас — replay/precomputation); проверка
   ML-DSA подписи `ContactRequest`; `RateLimiter` на bounded LRU. `Message::ContactRequest` в
   `proto.rs` (подключение в демон — M22). Criterion-бенч BLAKE3-PoW → таблица §11B.2 пересчитана
   (ожидание: 16 бит ≈ 10 мс, 20 ≈ 0,2 с, 24 ≈ 3 с, 28 ≈ 50 с однопоточно).
6. **Мелкое:** binding identity ↔ iroh `EndpointId` при handshake (C8, хранится в `contacts`);
   `derive_device_id(seed, index)` + контекст в KEY_CONTEXTS (C9); fingerprint ≥ 128 бит для
   `/verify`, 8-байтный — только подсказка в invitation link (C10); combiner-контекст и порядок
   байт counter — спеку привести к коду (C12); `verify_link_code` через `ConstantTimeEq` + лимит
   попыток, явный zeroize `pq_mlkem_dk`/`send_dh_secret` в `Drop` (C14).
7. **Тесты и fuzz (C11):** fuzz-таргеты на `Message` (включая `HandshakeInit` с лимитами длин),
   `GroupControl`, `RatchetSnapshot`, `read_framed`; proptest roundtrip padding / ratchet;
   `cargo fuzz` в CI по 60 с на таргет.
8. Спека: §4.2/§4.4/§4.5 (`spec/02-crypto.md`) приведены к коду; `docs/KEY_CONTEXTS.md` дополнен;
   `spec/05-protocol-versioning.md` §6.4 — «релизный протокол v2».

### Milestone 19 — Сетевой слой в демоне (v0.4.x, 2–3 недели, блокер №0)

**Зачем:** после этого милстоуна мессенджер впервые доставляет сообщения. Карта точек подключения
с файлами и строками — аудит §4.1a.

**Phase A — Storage-предпосылки (до сетевого кода)**

1. `aira-storage`: таблица `meta { schema_version: u32 }`, цепочка миграций при `Storage::open`;
   v1 → v2: `ContactInfo` получает `endpoint_addr: Vec<u8>` (iroh `EndpointAddr`, postcard) и
   `relays: Vec<RelayRef>`; индекс `pseudonym → contact` для входящих по псевдониму.
2. `pending.rs`: инвариант «в PENDING только `postcard(EncryptedEnvelope)`» — тип-обёртка
   `PendingEnvelope` вместо `&[u8]`; заголовок `{ enqueued_at, size }`; лимиты 1000 сообщений /
   100 MB на контакт → `DaemonResponse::Error(QueueFull)`; per-contact `seq` без полного скана; GC
   7 дней. ⚠️ Сейчас fan-out групп кладёт plaintext и sender keys в нешифруемую таблицу
   (`handler.rs:305, 464, 901`) — до фикса шифровать PENDING storage-ключом.
3. `dedup.rs`: ключ `BLAKE3(sender_pubkey ‖ counter ‖ nonce)[..16]` — вызывать до ratchet-decrypt.
4. `backup.rs` VERSION = 2: groups, group_messages, devices, pseudonyms + `pseudonym_counter`
   (сейчас после restore counter = 0 → повтор псевдонимов, нарушение §12.6).
5. `encrypted.rs`: AAD = `table_name ‖ row_key` (ciphertext нельзя переставить между строками).
6. Новый KDF-контекст для iroh `SecretKey` в `docs/KEY_CONTEXTS.md`. Решение: детерминированно из
   seed (стабильный `EndpointId`, простая доставка) — по умолчанию; per-device случайный ключ в
   settings — опция позже (§12.6).

**Phase B — `net_task`**

7. `aira-daemon/src/main.rs:100-160` после `Storage::open`: `AiraEndpoint::bind(Some(secret_key))`
   (`endpoint.rs:45`) → `protocol::build_router(&ep, ChatHandler, HandshakeHandler,
   Arc<RelayServer>, Some(&blob_store))` (`protocol.rs:178-195`) → `Receiver<IncomingMessage>`,
   `Receiver<IncomingHandshake>`. Endpoint — через `AiraPreset` из M20, до него `presets::N0`.
8. Новый `aira-daemon/src/net_task.rs`: `SessionManager { HashMap<pubkey, RatchetSession> }`;
   при старте `sessions::list_contacts → load → RatchetSession::from_snapshot`; после **каждого**
   send/recv `to_snapshot → sessions::save` **до** отправки в сеть (crash между send и save =
   повтор chain key).
9. `handler.rs:29-36` `handle_request` становится `async` (или получает
   `mpsc::Sender<NetCommand>`); тяжёлое — `spawn_blocking` (`std::fs::read` файла до 4 GiB в
   `handler.rs:895` → потоковый BLAKE3). `SendMessage` → ratchet-encrypt → `pending::enqueue` →
   `NetCommand::Deliver { contact }`; то же для `enqueue_group_control` (300-320),
   `handle_send_group_message` (441-477), `handle_send_file` (863-949).
10. Таск `pending_drain`: `pending::peek` → `ep.connect(addr, alpn::CHAT)` (таймаут 5 с) →
    `connection::write_framed` → ack → `pending::dequeue`; триггеры: старт, входящее соединение,
    backoff [5 с, 30 с, 2 мин, 10 мин, 1 ч]. Fallback при недоставке — `RelayClient::deposit`
    (до M21 — существующий `aira/1/relay`, после — v2).
11. Входящие: `IncomingMessage` → `is_duplicate` → ratchet decrypt → существующий
    `handle_incoming_payload` (`handler.rs:621-674`) → `DaemonEvent::MessageReceived`.
    `ContactOnline/Offline` — из `ConnectionManager::set_connected/set_disconnected`
    (`connection.rs:155-172`); новые события `DeliveryState { id, Sent | Queued | Relayed |
    Delivered }`, `NetStatus`. Форвардер событий (`ipc.rs:129, 224`) обрабатывает
    `RecvError::Lagged` вместо выхода; ёмкость канала 4096.
12. Контакты: `DaemonRequest::GetInvitation` → `aira://add/<base64url(postcard(InvitationLink))>`
    (`discovery.rs:20-45`) со **стабильным** pseudonym (выданные хранить; `GetMyAddress` сейчас
    генерирует новый при каждом вызове — `handler.rs:77-95`) + `EndpointAddr`;
    `AddContact { uri }` парсит ссылку; `ContactRequestReceived` + `AcceptContact/RejectContact`.
    `SetRelays / GetRelays / GetNetStatus` в IPC (`spec/10-daemon-ipc.md`).
13. Файлы: `FileComplete` только по `FileAck` от пира (`proto.rs:17`); ALPN FILE в router;
    BlobStore — `iroh_blobs::store::fs` на диск.
14. `aira-ffi/src/runtime.rs:95-125` — тот же `net_task` из общей библиотеки `aira-daemon` (lib);
    Android получает сеть автоматически.

**Phase C — Тесты**

15. `crates/aira-daemon/tests/two_daemons.rs`: два демона in-process с реальным IPC-сокетом →
    `AddContact` по invitation link → `SendMessage` → у второго `MessageReceived`; перезапуск
    первого → сессия жива (снапшот); Bob офлайн → сообщение в PENDING → Bob онлайн → доставлено,
    `DeliveryState::Delivered`; дубликат по сети не попадает в историю.
16. Группа из трёх демонов: create → сообщение → все получили (закрывает M6 п.6).

### Milestone 19b — Клиентские блокеры беты (параллельно с M19, ~1 неделя + Android-пакет)

**Desktop (GUI/CLI/демон)**

1. `Cargo.toml:93`: `keyring = { version = "3", features = ["windows-native", "apple-native",
   "sync-secret-service"] }` (или `linux-native` + vendored для AppImage без libdbus) — сейчас
   компилируется **mock in-memory store**, seed не переживает перезапуск GUI. Снять `#[ignore]` с
   roundtrip-тестов `keychain.rs:189,209,221` хотя бы на Windows/macOS в CI. Ручная проверка:
   создать identity → закрыть → запустить → нет welcome.
2. Seed в демон не через `AIRA_SEED` env (`main.rs:85-96`; история shell, `/proc/<pid>/environ`),
   а через stdin при spawn / IPC-handshake / keychain (вынести `aira-gui/keychain.rs` в общий
   модуль). `AIRA_SEED` — только `cfg(debug_assertions)`. CLI: `aira init` / `aira start`.
   GUI: убрать «Copy seed to clipboard» или очищать буфер через 30 с (`welcome.rs:156-157`).
3. IPC-аутентификация: Unix — `chmod 0700 ~/.aira`, `0600` сокет, проверка `SO_PEERCRED` uid;
   Windows — имя пайпа с SID пользователя, `first_pipe_instance(true)`, security descriptor «только
   текущий пользователь»; токен `<data_dir>/ipc.token` (0600) в первом кадре. Сейчас любой локальный
   процесс может `Shutdown` и `ExportBackup{path}` с расшифрованными ratchet-снапшотами.
4. Контакты в UI: экран «Share my link» с QR (`qrcode` + egui Image), «Add contact» по ссылке
   (вставка/сканер из буфера), входящие contact requests с Accept/Reject; CLI `/invite`, `/add
   <uri>`, `/requests`. Валидация длины pubkey (`add_contact.rs:60`, `handler.rs:38-43`) и
   `MAX_ENVELOPE_SIZE` для текста (`handler.rs:64`) — константы в `aira-core`.
5. Settings → «Network»: список relay, статус (`GetNetStatus`), индикатор в status bar; CLI `/relay`.
6. `README.md` в корне (ссылка на INSTALL.md, статус беты), `docs/INSTALL.md` поправить
   (Android-раздел неверен: APK не подписан вообще, а не «debug-подписью»).

**Android (решение владельца: доводить или preview)**

7. FFI: `generate_seed_phrase() -> String`, `validate_seed_phrase(&str) -> bool`;
   `seed_phrase` через `Zeroizing` (сейчас 0 вхождений zeroize в aira-ffi).
8. Kotlin: `OnboardingScreen` (create/import) → `EncryptedSharedPreferences` / Keystore-wrapped
   blob (сейчас никто не пишет `seed_phrase`, сервис молча `return`, `repository = null`);
   `IdentityScreen` с QR; `AddContactScreen` — сканер (ML Kit / ZXing).
9. `mobile/android/app/proguard-rules.pro` (файла нет при `isMinifyEnabled = true`): `-keep class
   com.sun.jna.** { *; }`, `-keep class * implements com.sun.jna.** { *; }`, `-keep class
   uniffi.aira_ffi.** { *; }`.
10. M9.6 Phase B как есть (signingConfigs из env, GitHub Secrets, `apksigner verify` в CI,
    `docs/ANDROID_SIGNING.md`) — сейчас `release.yml:229-235` публикует `app-release-unsigned.apk`.
11. `targetSdk 36` (Play с 31.08.2026), NDK **r28** (16 KB page size по умолчанию; сейчас 26.1),
    `cargo-ndk` запинить; FGS `specialUse` с `PROPERTY_SPECIAL_USE_FGS_SUBTYPE` вместо `dataSync`
    (6 ч/сутки на Android 15+), а после M21 — FGS только на время retrieve; убрать
    `firebase-messaging` (F-Droid запрещает FCM), оставить UnifiedPush; `values-ru`.

### Milestone 20 — Собственный iroh-relay и discovery на mail-сервере (1 неделя, параллельно с M19)

**Зачем:** публичные relay n0 «для development и hobby», без SLA, видят метаданные (IP, время,
объёмы) и отключают клиентов 0.9x 30.09.2026. iroh-relay **stateless**: хранит соединения, не
данные; трафик E2E-зашифрован. Это первый из двух процессов на mail-сервере (второй —
`aira-relay`, M21). Полный план с конфигами — `.claude/docs/audit-2026-09/relay-deploy-plan.md`.

1. DNS `relay.<domain>` → mail-сервер; firewall: tcp/443 (есть) + **udp/7842** (QAD — замена STUN;
   3478 не нужен); 9090 (metrics) только localhost.
2. `iroh-relay` v1.1.0 (≥ 1.0.2 обязательно: до неё короткий кадр ронял сервер), сборка из тега
   `cargo build --profile optimized-release -p iroh-relay --features server` или docker
   `n0computer/iroh-relay:v1.1.0` по digest; пользователь `iroh-relay`, `/etc/iroh-relay/config.toml`,
   `/var/lib/iroh-relay/certs`, systemd unit (`Restart=always`, `LimitNOFILE=131072`,
   `ProtectSystem=strict`).
3. **Вариант A (рекомендуется):** nginx `stream { ssl_preread }` — SNI `relay.<domain>` →
   `127.0.0.1:8443` насквозь; relay сам получает Let's Encrypt (TLS-ALPN-01, `cert_mode =
   "LetsEncrypt"`); быстрый exporter-handshake работает. Прежние HTTPS-vhost'ы webmail переезжают
   на `127.0.0.1:8444` (+ `proxy_protocol`). **Вариант B:** TLS терминирует nginx (`proxy_pass`,
   `Upgrade`, проброс `Sec-WebSocket-Protocol`, таймауты 1 ч), relay `cert_mode = "Manual"` на
   certbot-сертификате; клиенты идут по challenge-fallback (+1 RTT) — тот же путь, что в браузере.
4. `[limits] accept_conn_limit = 50.0, accept_conn_burst = 200, client.rx bytes_per_second =
   2_000_000`; `access = "everyone"` на старте (позже `access.http.url` → сервис Aira с
   PoW-гейтом, M22). Проверка `curl --fail https://relay.<domain>/healthz`.
5. `iroh-dns-server` 1.1 для pkarr на `dns.<domain>` (`[https] port = 8445`, `[mainline] enabled =
   false`, `pkarr_put_rate_limit = "smart"`); порт 53 и NS-делегирование — позже.
6. Клиент: `crates/aira-net/src/preset.rs` — `AiraPreset` (по образцу `presets::N0`:
   `relay_mode(RelayMode::Custom(RelayMap))`, `PkarrPublisher::builder(url)` /
   `PkarrResolver::builder(url)` на своём домене, `DnsAddressLookup` вне wasm); конфиг демона
   `[network] relays = [...], pkarr_relay = "..."`, **n0-fallback выключен по умолчанию**;
   `AddrFilter` — решение владельца (публиковать прямые IP или только relay).
7. Второй relay на VPS до релиза (без него одна точка отказа); Prometheus локально; обновлять
   relay в течение суток после релиза iroh.
8. Спека: `spec/03-network.md` §5.1 «DERP» → iroh-relay (WebSocket/TLS + QAD), новый §5.1.1
   «Собственный iroh-relay + iroh-dns-server», §5.2b/§5.3 (DHT, bootstrap-ноды) → pkarr/DNS,
   DHT — после релиза; глоссарий §20: «transport relay» vs «mailbox relay».

### Milestone 21 — `aira-relay`: offline-доставка v2 (2–3 недели)

**Зачем:** spec §6.3b/§6.5/§11B.5 обещают store-and-forward, а в коде — in-memory `RelayServer`
без аутентификации (Retrieve/Delete любому, кто знает `mailbox_id`), без квот отправителя, одна
коробка на пару, и демон его не использует. Дизайн — аудит §4.3; формула mailbox ID в трёх
источниках расходится (§6.5 спеки, `relay.rs:28`, `habr_article.md:367`) — фиксируется здесь.

1. Крейт `crates/aira-relay` + бинарник `aira-relay`: обычный iroh-endpoint (`AiraPreset`), ALPN
   `aira/2/relay`, redb (`mailboxes`, `envelopes(mailbox_id, seq)`, `stats`), конфиг TOML,
   systemd unit рядом с iroh-relay. Старый ALPN `aira/1/relay` и `aira-net/src/relay.rs` удалить.
2. **Две коробки на пару по направлению:** `mailbox_id[dir] = derive_key("aira/relay/mailbox/v2/"
   ‖ dir, shared_secret)`; `owner_key[dir]`, `sender_key[dir]` — Ed25519 из shared secret
   (`aira/relay/owner/v2/dir`, `aira/relay/sender/v2/dir`, в `docs/KEY_CONTEXTS.md`); relay видит
   только публичные.
3. Протокол: `RelayHello { protocol_version: 2, supported, capabilities }` + `relay_nonce`;
   `Register { mailbox_id, owner_pk, sender_pk, notification_endpoint, ttl_hint }` (подпись owner);
   `Deposit { mailbox_id, envelope }` (подпись sender + nonce; незарегистрированная коробка →
   `MailboxNotFound`); `Retrieve { after_seq }` / `Ack { up_to_seq }` / `Delete` (подпись owner +
   nonce); `seq` присваивает relay. `RelayMigration` (§11B.5.1) подписанная.
4. **Intro-mailbox** по `pseudonym_pubkey` получателя (`aira/relay/intro/v2`): только
   `ContactRequest` с PoW ≥ 20 бит над `relay_nonce ‖ request` + rate limit по EndpointId —
   единственное место PoW на relay.
5. Квоты (§11B.5, переписать под v2): 100 конвертов / 10 MB на коробку, конверт ≤ 64 KB, TTL 7
   дней **на конверт**, общий cap 1 GB, GC каждый час с приоритетом вытеснения коробок без
   retrieve, `Register` ≤ 20/сутки на EndpointId.
6. Push: `NotificationEndpoint::UnifiedPush { url }` — пустой wake-up без содержимого и без
   mailbox_id; клиент делает retrieve по всем своим коробкам. FCM — нет.
7. Демон: `relay_poll` (старт, каждые N мин, по push/onResume) → decrypt (skipped keys) → dedup →
   store → ack; `deposit` при недоставке напрямую во все relay контакта; `MailboxConfig.relays` в
   контакт-записи (из invitation link). Android: FGS только на время retrieve.
8. Тесты: «Bob офлайн 3 дня → Alice шлёт 3 сообщения → Bob вернулся → порядок и dedup»; «relay
   перезапущен — конверты на месте»; «чужой EndpointId не может retrieve»; «deposit без
   регистрации отклонён»; quota/TTL/GC; proptest кодека, fuzz парсера `RelayRequest`.
9. Спека: §6.3b, §6.5 (формула v2), §11B.5, §11B.5.1 переписаны; `habr_article.md` раздел
   «Pairwise Relay Mailboxes» — под v2 и статус.

### Milestone 22 — Anti-abuse (1 неделя)

**Вердикт по «ресурсоёмкому PoW при создании первого ключа»:** не вводить как основную меру
(аудит §5.3): цена ключа амортизируется (одна identity = бесконечный спам), DDoS relay идёт с
бесплатных Ed25519 EndpointId и от identity не зависит, grinding ломает детерминизм seed → identity
(или заставляет ждать минуты при каждом восстановлении), GPU-асимметрия 50–1000×. Вместо —
**цена каждого действия** + contact-first (§13.1).

1. `Message::ContactRequest` (из M19a) в демоне: приём напрямую и через intro-mailbox; PoW
   адаптивный 16 → 28 бит (верификатор задаёт по нагрузке, nonce живёт 30 с), `RateLimiter`
   (10/мин, 3/ч на ключ, бан 1 ч); событие `ContactRequestReceived`.
2. Adaptive puzzle перед handshake от незнакомой ноды (§11B.2) — тот же код; контакты (Tier 1)
   без puzzle; `ratelimit.rs` tiers подключить к `ConnectionManager` в демоне.
3. Опционально: `access.http.url` для iroh-relay → сервис, который пускает EndpointId после первой
   успешной регистрации mailbox.
4. Отложено (после релиза, низкий приоритет): `IdentityStamp` — Hashcash-штамп над детерминированным
   pubkey (`BLAKE3("aira/identity-stamp/v1" ‖ pubkey ‖ bits ‖ nonce)`, 22 бита ≈ 0,5–1 с),
   пересчитывается в фоне, снижает PoW на ContactRequest; Privacy Pass rate-limited tokens.
5. Спека: §13.2 (`spec/15-spam.md`) под adaptive difficulty, дубликат §13 из `spec/14-groups.md`
   удалить; новый §11B.10 «Стоимость identity» с этим вердиктом; таблица времён §11B.2 из бенча M19a.

### Milestone 23 — Release hardening и публичная бета (1–2 недели → v0.5.0-beta.1)

Чеклист «минимум для беты» (аудит §6.6.7):

1. CI: `cargo audit`, `cargo deny`, clippy на актуальном stable — блокирующие jobs; интеграционные
   тесты M19/M21 в матрице.
2. Подписи: Android release keystore + `apksigner verify` (обязательно); Windows — SignPath
   Foundation (бесплатно для OSS; запасной Certum OSS ~$50; Azure Artifact Signing физлицам вне
   US/CA недоступен, EV репутации больше не даёт); macOS — Developer ID $99 + notarization (иначе
   Sequoia+ через System Settings, Homebrew с 01.09.2026 не принимает). Отказ — честно в INSTALL.md.
3. Документы: `README.md`, `SECURITY.md` (контакт, ключ, 90 дней), `docs/THREAT_MODEL.md` (из §11
   с пометками «реализовано/план»), `PRIVACY.md` (что видит оператор relay), `CHANGELOG.md`,
   `INSTALL.md` (relay по умолчанию, статус Android).
4. `release.yml`: `actions/attest-build-provenance` (SLSA L3, бесплатно для публичных репо),
   бинари через `cargo-auditable`, SBOM `cargo-cyclonedx`, sha256.
5. Схема версии БД (M19 Phase A) + явная политика «бета не гарантирует совместимость баз до 1.0».
6. Android: либо доведён (M19b Android-пакет), либо APK не публикуется в бете. Flathub —
   исключить (политика 2026 запрещает AI-assisted код и PR). Play — не в бете.
7. GitHub Releases pre-release `0.5.0-beta.N`, шаблон bug report, известные ограничения.

Для 1.0 (после беты): внешний аудит aira-core + aira-relay (OTF Red Team Lab / OSTIF / NLnet NGI
Zero после возобновления calls), reproducible builds (`trim-paths`, `SOURCE_DATE_EPOCH`) с
независимой проверкой, `cargo vet` с импортом Mozilla/Google, winget / Homebrew tap / F-Droid
(reproducible + flavor без FCM), решение по Android developer verification до 2027.

### Пересмотр Milestone 9.6 и 14–17

- **M9.6:** Phase A выполняется в M18; Phase B — в M19b; Phase C/D (i18n, темы) и E — после беты.
- **M16 (разметка)** — дёшево и безопасно, первым после беты. **M15 (голосовые)** — после M16.
- **M17 (Tauri)** — после того, как сетевой слой стабилен в демоне; иначе перенос UI поверх
  неработающей доставки удваивает миграционный долг.
- **M14 (браузер)** — последним, после M21 (4–6 недель): без своего relay (M20) браузер не
  подключится, без mailbox (M21) не получит ничего при закрытой вкладке. Исследование — аудит §6.
  Правки к тексту M14 выше:
  - §14.4: **`redb-opfs` не использовать** — `GPL-3.0-only` (Aira MIT/Apache-2.0), README
    «statement of intent», git-зависимость на master redb, репозиторий мёртв с 2025-09-25, на
    crates.io нет. Вместо него свой `OpfsBackend` (~200–300 строк) поверх redb 4
    `StorageBackend` в dedicated Worker (`send_wrapper` для Send+Sync); этап 0 —
    `InMemoryBackend` + периодический зашифрованный снапшот в OPFS. `navigator.storage.persist()`
    обязателен (Safari вытесняет данные через 7 дней без взаимодействия; потеря ratchet-состояния
    = невозможность расшифровать дальнейшие сообщения).
  - §14.1 п.3: `getrandom` **0.4** (iroh 1.1) и 0.2 (`js`, пока жив rand 0.8) — фичи только в
    `aira-wasm` как target-specific deps; с 0.3.4 `--cfg getrandom_backend` не нужен.
  - §14.2 п.3: `Platform::Mobile` удалить (M19), `Platform::Browser` не вводить; Argon2id 256 МБ
    считать в отдельном одноразовом KDF-воркере и терминировать его (WASM-память не
    возвращается); iOS Safari может убить вкладку молча — веб-клиент, вероятно, «desktop + Android
    Chrome», iOS не поддерживается (решение владельца).
  - §14.3: п.5 «опционально iroh 1.0» → iroh 1.1 обязателен (M18); `iroh = { version = "1",
    default-features = false, features = ["tls-ring"] }` (aws-lc-rs/PQ-TLS под wasm недоступен);
    `tokio` только sync/macros/rt/time/io-util + `n0-future`; **iroh-blobs не поддерживает
    браузер** (issue #90) — файлы в браузере исключены, `SendFile` → `Unsupported`; discovery —
    relay_url + EndpointId внутри InvitationLink/контакта, без pkarr-lookup из браузера.
  - Новый **§14.0 — предпосылки в ядре (внутри M18/M19, 3–5 дней):** redb 2.6 → 4.2 (redb < 3.1
    не компилируется под wasm32; формат v2 удалён в 3.0 → миграция через `redb2 = { package =
    "redb", version = "2.6" }` + `Database::upgrade()` либо объявить БД 0.3.x несовместимой —
    решение владельца) и `Storage::open_with_backend`; `backup.rs` → `export_bytes/import_bytes`;
    единая точка времени `aira_core::util::{now_micros, now_secs}` на `web-time` (сейчас
    `SystemTime::now()` в util.rs:16,25, contacts.rs:18, dedup.rs:19,55, messages.rs:114,147
    паникует под wasm; `Instant` в connection.rs/relay.rs); tokio per-target в aira-net; cfg-гейты
    на `blobs` и `RelayServer`; крейт `aira-ipc` (types.rs + фрейминг, без tokio) и библиотека
    `aira-node` (SessionManager, handler, pending-дренаж) — их же используют aira-daemon, aira-ffi
    и aira-wasm; `rust-embed` `debug-embed` для wasm; CI guard `cargo check -p aira-core --target
    wasm32-unknown-unknown`.
  - §14.5: `wasm-pack build --target web --release` + `wasm-opt -Oz`, `wasm-pack test --headless
    --chrome --firefox`; **размер .wasm (gz/brotli) — первый замер**, при > 5–8 МБ демо на мобильных
    бесполезно. CSP `script-src 'self' 'wasm-unsafe-eval'; connect-src 'self'
    wss://relay.<domain>; worker-src 'self'`; COOP/COEP не нужны. Web Push не делать.
  - Требования к relay (M20/M21): TLS 443 с публичным сертификатом, WebSocket `/relay` через
    nginx (браузер всегда на challenge-fallback), **отдельный ротируемый `shared_token` для web**
    (уходит в `?token=` URL → логи прокси), CORS на `/pkarr/*` и `/healthz` при необходимости;
    aira-relay без допущений о прямом UDP, PoW/квоты на intro-mailbox до открытия веб-демо.

---
