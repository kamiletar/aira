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

