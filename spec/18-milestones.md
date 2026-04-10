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

---

