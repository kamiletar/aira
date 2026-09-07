# Клиенты (GUI/CLI/FFI/Android) — результат аудита кода (2026-09-07, HEAD 971e038)

> Источник: raw `raw/a42d1f647994de6ec.json`. Выжимка — в `../release-audit-2026-09.md` §5.5.

## Scope

Аудит клиентов Aira (HEAD 971e038, workspace 0.3.5) на готовность к публичной бете: crates/aira-gui (egui 0.29), crates/aira-cli (ratatui), crates/aira-ffi + mobile/android, плюс aira-daemon как единственный бэкенд всех клиентов. Сопоставление с Milestone 9.5 (Phase A/B/C) и 9.6 (Phase A–E) в spec/18-milestones.md. Только Read/Grep/Glob, cargo не запускался (факты сборки/аудита — из scratchpad/facts-crates.md).

## Резюме

Milestone 9.5 (auto-spawn, onboarding, password vault, MSI/DMG/AppImage) реализован почти полностью, Milestone 9.6 — не начат ни в одной фазе (ml-dsa bump не компилируется и заблокирован iroh 0.97; Android без signingConfigs, релизный APK вообще UNSIGNED; i18n/темы/locale.rs отсутствуют). Но главные блокеры не в UI: (1) aira-daemon не поднимает iroh Endpoint и никогда не отправляет сообщения в сеть — SendMessage только пишет в redb, handle_incoming_payload вызывается только из тестов; relay/mailbox (aira-net/src/relay.rs), invitation links (discovery.rs) и PoW contact request (aira-core/src/spam.rs) существуют как библиотечный код, но не подключены к демону, а значит ни в GUI, ни в CLI, ни в Android их нет; (2) keyring = "3" без platform-features → в Cargo.lock keyring 3.6.3 тянет только log+zeroize, т.е. компилируется mock in-memory store — seed phrase GUI не переживает перезапуск; (3) Android-приложение — мёртвая оболочка: никто не записывает seed_phrase в SharedPreferences, FFI не умеет генерировать seed, сервис молча выходит, repository остаётся null; R8 minify включён без proguard-rules.pro (файла нет) при JNA/UniFFI. Путь пользователя ломается на шаге «добавить контакт» (вставка ~3900 hex-символов ML-DSA-ключа, без ссылки/QR, адрес меняется при каждом открытии Identity) и окончательно — на «первое сообщение» (не доставляется никогда). Для беты нужна интеграция сети в демон (endpoint + handshake + relay client + pending-очередь), затем починка keyring/Android, затем 9.6.

## Что реализовано

| Качество | Что | Evidence | Примечание |
|---|---|---|---|
| works-but-rough | M9.5 Phase A — keychain.rs API (store/load/delete, Zeroizing, dual Plain/Vault) | crates/aira-gui/src/keychain.rs:37-39 (accounts seed-phrase-plain-v1/vault-v1), :56 Plain(Zeroizing<String>), :74 load_seed, :120 store_seed_phrase, :155 delete_seed_phrase | Код есть, но бэкенда нет: Cargo.toml:93 `keyring = "3"` без features → Cargo.lock keyring 3.6.3 deps = [log, zeroize] (нет windows-sys/security-framework/secret-service) → keyring 3.x падает на mock store. Тесты keychain помечены #[ignore] (keychain.rs:189,209,221), поэтому CI это не ловит. |
| production | M9.5 Phase A — daemon_manager.rs (locate, spawn через AIRA_SEED env, CREATE_NO_WINDOW, stderr capture, manual Debug) | crates/aira-gui/src/daemon_manager.rs:4-6,16-17,85-90,138-142 |  |
| works-but-rough | M9.5 Phase A — onboarding (Create/Import, BIP-39 валидация, checkbox, копирование фразы) | crates/aira-gui/src/onboarding.rs:35 (Debug не течёт), views/welcome.rs:49,67,156-168,192,261-262 | welcome.rs:156-157 копирует seed phrase в системный буфер обмена без авто-очистки. |
| production | M9.5 Phase A — ConnectionState + Bridge{bootstrap, main_loop, reconnect_loop, shutdown}, backoff [500,1000,2000,5000,10000], poll 200ms | crates/aira-gui/src/state.rs:103-117; ipc.rs:567,570,611,769,862,1039 |  |
| production | M9.5 Phase B — password vault (Argon2id m=128MiB, ChaCha20Poly1305, контекст aira-gui/password-vault/v1), unlock view, Locked state, Set/Change/Disable | crates/aira-gui/src/password_vault.rs:11-24,45,108,147; views/unlock.rs; state.rs:69-72,108; ipc.rs:738,944,969,1005; docs/KEY_CONTEXTS.md:107 |  |
| production | M9.5 Phase C — инсталляторы: cargo-wix MSI, bundle-macos.sh/DMG, bundle-appimage.sh, release.yml, docs/INSTALL.md | crates/aira-gui/Cargo.toml [package.metadata.wix]; crates/aira-gui/wix/main.wxs; scripts/bundle-macos.sh, bundle-appimage.sh; .github/workflows/release.yml:95-152; docs/INSTALL.md:23-127 | Релиз v0.3.5 с MSI/DMG/AppImage/APK реально выложен (facts-crates.md). Без code signing (документировано). |
| missing | M9.6 Phase A — ml-dsa 0.0.4 → 0.1.x | Cargo.toml bump до 0.1.0-rc.4 не закоммичен; facts-crates.md: cargo check FAIL (sha3 rc.6 / keccak), ml-dsa 0.1.1 не резолвится при iroh 0.97 (iroh-base пинит digest =0.11.0-rc.10) | Заблокировано миграцией iroh → 1.x; нельзя сделать отдельной фазой. |
| missing | M9.6 Phase B — Android release signing | mobile/android/app/build.gradle.kts: нет signingConfigs; release.yml:229-235 копирует app-release-unsigned.apk как aira-<ver>-android.apk | Хуже, чем описано в спеке («debug-подпись», INSTALL.md:133): релизный APK вообще без подписи → Android его не установит. |
| missing | M9.6 Phase C — i18n (10 языков, locale.rs, sys-locale) | crates/aira-gui/assets содержит только шрифты и icon.png; нет src/locale.rs; Cargo.toml без fluent/sys-locale; все строки hardcoded (add_contact.rs, welcome.rs, settings.rs) |  |
| missing | M9.6 Phase D — темы dark/light/system | crates/aira-gui/src/theme.rs:179 единственный apply_theme, нет ColorScheme/LightPalette; settings.rs без Appearance |  |
| works-but-rough | M9.6 Phase E — UX polish (avatar, search, date separators, delivered, multiline) | contacts.rs:82-103 аватар с инициалами + status dot (через theme::avatar_color, а не widgets/avatar.rs); chat.rs:55 stick_to_bottom; chat.rs:67 TextEdit::singleline; нет search/date separators/delivered |  |
| works-but-rough | GUI: добавление контакта | crates/aira-gui/src/views/add_contact.rs:33-40 ввод «ML-DSA public key in hex»; валидация только hex::decode (:60), длина не проверяется; aira-storage contacts::add тоже без проверки длины | Нет invitation link (aira://add/… из aira-net/src/discovery.rs:4,42), нет QR, нет contact request/PoW. Identity view (identity.rs:34-55) показывает hex + Copy; daemon GetMyAddress (handler.rs:77-93) генерирует НОВЫЙ pseudonym при каждом вызове. |
| stub | GUI: отправка сообщения → сеть | aira-daemon/src/handler.rs:64-75 SendMessage = только messages::store; aira-daemon/src/main.rs:100-160 — нет Endpoint/Router, только IPC + BlobStore; handle_incoming_payload (handler.rs:621) вызывается лишь из тестов (:1103-1322); aira_net в daemon используется только для blobs/transport mode (grep) | Сообщения никуда не уходят. «Офлайн-получатель» неотличим от онлайн — доставки нет вообще. |
| missing | Relay / offline-очередь в клиентах | grep relay\|offline\|queue по aira-gui/aira-cli/aira-ffi/android: только метка «Offline» (app.rs:240), событие ContactOffline и multidevice LinkCode; aira-storage PENDING table (lib.rs:60) не используется демоном; RelayServer/RelayClient (aira-net/src/relay.rs:149,345,383) не подключены |  |
| stub | PoW contact request | aira-core/src/spam.rs:14 POW_DIFFICULTY_BITS=20, :71 verify_pow, :96 solve_pow; в aira-net/daemon/gui/cli/ffi не используется (grep spam::\|ContactRequest пусто) |  |
| works-but-rough | CLI (ratatui) | crates/aira-cli/src/main.rs:58-66 — при отсутствии демона печатает «Is the aira-daemon running?» и exit(1); нет spawn/keychain/onboarding; демон требует AIRA_SEED env (aira-daemon/src/main.rs:85-87); /verify → «coming in M6» (main.rs:455) | Для CLI-пользователя seed phrase живёт в переменной окружения (история shell, /proc/<pid>/environ). README.md в корне отсутствует. |
| stub | Android: сервис, push, onboarding | AiraDaemonService.kt:44-48 читает seed из plain SharedPreferences и `return`, если нет; ни один Kotlin-файл не делает putString(seed_phrase); FFI runtime.rs:56 принимает готовую phrase, нет generate; MainActivity.kt:27 repository=null навсегда; FcmService.kt:24 и UnifiedPushReceiver.kt:28 — TODO, endpoint не регистрируется; IdentityScreen.kt:42 TODO seed/QR; AddContactScreen.kt:47 «Public Key (hex)»; res/ только values/ (без локалей) |  |
| works-but-rough | Android: build config | build.gradle.kts: targetSdk 35, minSdk 26, isMinifyEnabled=true + proguard-rules.pro (файла нет: ls mobile/android/app → только build.gradle.kts, src/), JNA 5.14 + UniFFI без keep-rules; Manifest foregroundServiceType=dataSync; firebase-messaging без плагина google-services; release.yml:181-188 cargo ndk --platform 26, NDK 26.1, cargo-ndk без пина версии |  |
| production | Секреты: Zeroizing / Debug / логи (GUI) | Zeroizing в ipc.rs(14), keychain.rs(8), onboarding.rs(8), password_vault.rs(18), settings.rs(5), unlock.rs(3); manual Debug для SubmitPassword (ipc.rs:116,220) и DaemonSpawnError (daemon_manager.rs:85-90); grep tracing/println с phrase\|seed\|password → нет утечек | FFI runtime.rs:56 `seed_phrase: String` без Zeroizing (0 вхождений в aira-ffi). |
| production | unwrap/expect/panic в production-путях GUI/CLI | GUI: ipc.rs:651 expect(«seed set above»), main.rs:68,116,119, tray.rs:81 — все на старте/инвариантах; CLI: 0 (commands.rs:120 — doc-comment) |  |

## Находки

### [blocker] Демон не подключён к сети: сообщения никогда не отправляются и не принимаются

- **Evidence:** crates/aira-daemon/src/main.rs:100-160 создаёт только Storage, BlobStore, TransferManager, IPC-сервер — ни aira_net::endpoint::AiraEndpoint, ни build_router (aira-net/src/protocol.rs:182-188) не вызываются. handler.rs:64-75 SendMessage = messages::store(). handle_incoming_payload (handler.rs:621) вызывается только из тестов (:1103,1164,1216,1262,1303,1322). aira-net имеет всё нужное: endpoint.rs:55-98 (presets::N0 с relay+DNS discovery), протокол-хендлеры, relay.rs RelayServer/RelayClient, tests/two_node_chat.rs и relay_offline.rs.
- **Impact:** Весь путь пользователя после «первое сообщение» — фикция: GUI/CLI/Android покажут сообщение в истории, получатель никогда его не увидит. Офлайн-сценарий, свой relay, PoW — всё не имеет точки подключения.
- **Recommendation:** Отдельный milestone «Daemon networking integration» ПЕРЕД любыми UI-работами: (1) в main.rs поднять AiraEndpoint::bind (не test-режим), build_router с chat/handshake/relay ALPN; (2) SendMessage → handshake + отправка envelope через connection.rs, при ошибке — запись в PENDING (aira-storage/src/lib.rs:60) и фоновый retry; (3) входящие envelope → handle_incoming_payload → broadcast MessageReceived; (4) GetMyAddress возвращать InvitationLink (pseudonym_pk + endpoint_addr_bytes, discovery.rs:20-45), а не голый pubkey; (5) интеграционный тест daemon↔daemon через IPC (spec M2 п.7-8).

### [blocker] keyring без platform-features → seed phrase GUI хранится в mock in-memory store и теряется при перезапуске

- **Evidence:** Cargo.toml:93 `keyring = "3"` (нет features); crates/aira-gui/Cargo.toml `keyring.workspace = true`; Cargo.lock keyring 3.6.3 dependencies = [log, zeroize] — нет windows-sys / security-framework / secret-service / dbus. keyring 3.x без platform-feature компилирует mock credential store (https://docs.rs/keyring/3.6.3 → Platforms / Features). Тесты keychain.rs:189,209,221 помечены #[ignore], поэтому не ловят.
- **Impact:** Каждый запуск aira-gui = onboarding заново; «Create new identity» даёт новую личность, контакты предыдущей теряются; password vault тоже не сохраняется. Шаг «перезапуск» из пути пользователя сломан.
- **Recommendation:** В workspace Cargo.toml: `keyring = { version = "3", features = ["windows-native", "apple-native", "sync-secret-service"] }` (или linux-native+vendored для AppImage без libdbus). Убрать #[ignore] с roundtrip-тестов хотя бы в CI на Windows/macOS. Ручная проверка: запуск → создать identity → закрыть → запустить → не должно быть welcome.

### [blocker] Android-приложение нефункционально: нет провижининга seed, сервис молча выходит, UI без repository

- **Evidence:** AiraDaemonService.kt:44-48 читает "seed_phrase" из getSharedPreferences("aira_prefs") и `return` при null; grep putString по mobile/ — ни одной записи; crates/aira-ffi/src/runtime.rs:56 AiraRuntime::new(data_dir, seed_phrase) — нет generate/validate seed в FFI API (:56-360); MainActivity.kt:27,32 repository остаётся null; NavGraph.kt:25 принимает AiraRepository? без экрана onboarding; IdentityScreen.kt:42 TODO.
- **Impact:** После установки APK пользователь видит пустые экраны, ничего не работает. Плюс seed в plain SharedPreferences (не Keystore/EncryptedSharedPreferences) — при появлении кода это будет уязвимость.
- **Recommendation:** FFI: добавить `generate_seed_phrase() -> String` и `validate_seed_phrase(&str) -> bool` (через aira_core::seed::MasterSeed); Kotlin: OnboardingScreen (create/import) → хранение через androidx.security EncryptedSharedPreferences или Android Keystore-wrapped blob; сервис стартует runtime после onboarding; экран-заглушка пока repository == null.

### [blocker] Релизный APK не подписан вообще (app-release-unsigned.apk) — не устанавливается

- **Evidence:** .github/workflows/release.yml:229-235: APK_SRC=app-release-unsigned.apk → aira-<ver>-android.apk; build.gradle.kts без signingConfigs; docs/INSTALL.md:133 ошибочно утверждает «debug-подпись».
- **Impact:** Установка на любом Android завершится INSTALL_PARSE_FAILED_NO_CERTIFICATES. Milestone 9.6 Phase B.
- **Recommendation:** Сделать по спеке 9.6 Phase B: signingConfigs.release из env, GitHub Secrets ANDROID_KEYSTORE_BASE64/…, apksigner verify в CI, docs/ANDROID_SIGNING.md, поправить INSTALL.md.

### [high] Добавление контакта = вставка ~3900 hex-символов, адрес меняется при каждом показе, нет invitation link / QR / contact request

- **Evidence:** crates/aira-gui/src/views/add_contact.rs:33-40,60 (hex, только hex::decode, без проверки длины); AddContactScreen.kt:47; CLI commands /add; identity.rs:34-55 hex_encode(my_address) + Copy; handler.rs:77-93 GetMyAddress каждый раз rand context_id → новый pseudonym; aira-net/src/discovery.rs:4,20-45 формат aira://add/<base64url(postcard(InvitationLink{pseudonym_pk, endpoint_addr_bytes}))> не используется ни одним клиентом; aira-core/src/spam.rs PoW не подключён.
- **Impact:** Даже после интеграции сети пользователи не смогут найти друг друга: у контакта нет endpoint-адреса, а «адрес» не стабилен. UX неприемлем для беты.
- **Recommendation:** (1) daemon: `GetInvitation` → aira://add/… URI (пседоним + iroh EndpointAddr), хранить выданные пседонимы; `AddContact { uri }` парсит InvitationLink; (2) GUI: экран «Share my link» с QR (crate `qrcode` + egui Image), «Add contact» с полем ссылки + сканирование из буфера; Android — ML Kit/ZXing сканер; (3) contact request с PoW (spam.rs, difficulty 20) в handshake-хендлере aira-net + событие ContactRequestReceived + accept/reject в UI.

### [high] Android release-сборка: R8 minify без proguard-rules.pro при JNA/UniFFI; FGS dataSync ограничен 6 ч на Android 15; FCM без google-services

- **Evidence:** build.gradle.kts:23-29 isMinifyEnabled/isShrinkResources=true + "proguard-rules.pro" — файла нет (ls mobile/android/app); зависимости jna 5.14.0@aar + сгенерированный uniffi Kotlin (release.yml:203-208); AndroidManifest.xml:44-47 foregroundServiceType="dataSync" при targetSdk 35 (https://developer.android.com/about/versions/15/behavior-changes-15#datasync-timeout — лимит 6 ч/сутки); firebase-messaging-ktx:24.1.0 без плагина com.google.gms.google-services и google-services.json; FcmService.kt:24, UnifiedPushReceiver.kt:28 — TODO.
- **Impact:** R8 обфусцирует/удаляет классы uniffi.aira_ffi.* и JNA Structure → крэш при первом вызове в release; демон будет убит системой через 6 ч; push не работает, а FCM тянет Google-зависимость (F-Droid несовместимо).
- **Recommendation:** Добавить proguard-rules.pro (-keep class com.sun.jna.** {*;} -keep class * implements com.sun.jna.** {*;} -keep class uniffi.aira_ffi.** {*;}); тип сервиса → remoteMessaging или specialUse с обоснованием (https://developer.android.com/develop/background-work/services/fg-service-types); либо доделать регистрацию push-endpoint через FFI, либо убрать FCM и оставить UnifiedPush; проверить 16 KB page-size ELF-alignment .so (NDK 26.1 не выравнивает по умолчанию, cargo-ndk не запинен) — https://developer.android.com/guide/practice/page-sizes; для Google Play с 31.08.2026 нужен targetSdk 36 (https://developer.android.com/google/play/requirements/target-sdk).

### [high] ml-dsa bump (Milestone 9.6 Phase A) не компилируется и заблокирован iroh 0.97

- **Evidence:** facts-crates.md: Cargo.toml ml-dsa 0.1.0-rc.4 незакоммичен, cargo check FAIL (sha3 rc.6/keccak p1600); ml-dsa 0.1.1 не резолвится с iroh-base 0.97 (digest =0.11.0-rc.10); эксперимент C: iroh 1.1 + ml-dsa 0.1.1 + ml-kem 0.3.2 резолвится, 15 ошибок только в crates/aira-core/src/crypto/rustcrypto.rs; cargo audit: 17 уязвимостей (quinn-proto RUSTSEC-2026-0185 high, hickory-proto без фикса в 0.25 и др.), CI job Security Audit красный.
- **Impact:** Релиз с ml-dsa 0.0.4 (RUSTSEC-2025-0144 заглушён в deny.toml) и красным cargo audit — плохо для «постквантового» мессенджера с публичной репутацией.
- **Recommendation:** Откатить незакоммиченный bump; выполнить связкой: iroh 0.97→1.1 (aira-net/src/endpoint.rs: Endpoint::empty_builder удалён) + iroh-blobs 0.103 + ml-dsa 0.1.1 (SigningKey::from_seed, Signer::sign) + ml-kem 0.3.2 (Seed 64 байта d‖z вместо feature deterministic); затем убрать ignore из deny.toml/.cargo/audit.toml.

### [high] Нет понятия relay в клиентах и демоне: нельзя указать свой relay на mail-сервере, нет статуса relay

- **Evidence:** grep relay по aira-gui/aira-cli/aira-ffi/android — только цвет STATUS_OFFLINE и ALPN-константа; aira-net/src/endpoint.rs:76-80 жёстко presets::N0 (relay n0.computer) без параметра; aira-net/src/relay.rs RelayServer (:149) и RelayClient (:345, deposit :383) не имеют потребителя; нет бинаря relay-ноды ([[bin]] только aira, aira-daemon, uniffi-bindgen, aira-gui).
- **Impact:** Клиенты за NAT зависят от публичных relay n0; собственный relay из темы (1) нереализуем без изменений в net/daemon; store-and-forward (тема 2) невозможен.
- **Recommendation:** (1) `aira-net`: RelayMode/relay_url в конфиге endpoint (iroh RelayMap с собственным iroh-relay сервером — feature `server` в iroh-relay 1.1 даёт TLS/ACME); (2) бинарь `aira-relay` (или флаг демона `--relay-server`) с RelayServer + GC; (3) daemon: RelayClient.deposit при недоступности пира, fetch при старте/по push; (4) IPC: `SetRelay{url}`, `GetRelayStatus` → GUI Settings «Relay» + индикатор в status bar, CLI `/relay`.

### [medium] Seed phrase в переменной окружения (CLI/демон) и в буфере обмена (GUI)

- **Evidence:** crates/aira-daemon/src/main.rs:85-96 env AIRA_SEED обязателен; crates/aira-gui/src/daemon_manager.rs:4-6,16-17 (документированный libstd-лимит без zeroize); crates/aira-gui/src/views/welcome.rs:156-157 copied_text = phrase без очистки; crates/aira-cli/src/main.rs:58-66 не умеет ни запускать демон, ни хранить seed.
- **Impact:** У CLI-пользователя фраза попадает в историю shell и environ процесса; GUI оставляет фразу в clipboard (clipboard-менеджеры логируют).
- **Recommendation:** Демон: принимать seed через stdin/IPC-handshake или keychain (переиспользовать aira-gui/keychain.rs, вынести в aira-daemon), AIRA_SEED оставить только для dev; CLI: `aira init`/`aira start` с keychain; GUI: убрать «Copy to clipboard» для seed или очищать через N секунд.

### [medium] Валидация входа: длина pubkey и размер сообщения не проверяются на границе IPC/UI

- **Evidence:** add_contact.rs:60 hex::decode без проверки длины; AddContactScreen.kt:67 trim только; aira-daemon/src/handler.rs:38-43 contacts::add без проверки; SendMessage :64 text.into_bytes() без MAX_ENVELOPE_SIZE.
- **Impact:** Мусорные контакты, при появлении сети — ошибки на handshake вместо понятного сообщения; риск DoS-размеров (rules/security.md п.4).
- **Recommendation:** Константы PUBKEY_LEN/MAX_MESSAGE_LEN в aira-core, проверка в handler и UI с человеческой ошибкой.

### [medium] i18n и темы отсутствуют, UI только English/dark (M9.6 C/D)

- **Evidence:** нет crates/aira-gui/src/locale.rs, assets/locales, fluent/sys-locale в aira-gui/Cargo.toml; theme.rs:179 одна палитра; Android res/ только values/.
- **Impact:** Для русскоязычной аудитории (Habr-статья в корне) и «10 языков» из спеки — не готово.
- **Recommendation:** Делать по спеке 9.6 Phase C/D, но после сетевой интеграции; Android — values-ru и т.д. одновременно.

### [low] Windows named pipe с фиксированным именем; отсутствуют README и Upgrade notes

- **Evidence:** aira-daemon/src/main.rs:67-68 `\\.\pipe\aira-daemon`; ls *.md в корне → нет README.md; INSTALL.md:128-135 неверно про debug-подпись.
- **Impact:** Два пользователя на одной машине / два профиля конфликтуют; нет точки входа для новых пользователей на GitHub.
- **Recommendation:** Имя пайпа с SID/username; README с ссылкой на INSTALL.md; поправить Android-раздел.

## Расхождения спека ↔ код

- spec/18-milestones.md M2 п.5-8 (bootstrap/relay нода, deposit/retrieve, тест через relay при офлайн-пире) — в aira-net есть relay.rs и tests/relay_offline.rs, но M3 «aira-daemon — event loop» реализован без сетевого event loop: демон не использует aira_net::endpoint/protocol/relay/discovery (handler.rs:64-75, main.rs:100-160).
- M3 п.1 «pending_messages» — таблица PENDING объявлена (aira-storage/src/lib.rs:60), демон её не использует.
- M9.5 Phase A п.1 «подключить keychain» — модуль подключён, но без platform-features keyring (Cargo.toml:93) → mock store; спека 9.5 требовала ручной 12-шаговый сценарий с restart — он не мог пройти.
- M9.6 «Контекст: APK подписан только debug-ключом» и docs/INSTALL.md:133 — фактически release.yml:229-235 публикует app-release-unsigned.apk (без подписи вообще).
- M9.6 Phase A (ml-dsa) описана как самостоятельная недельная фаза — по facts-crates.md невозможна без миграции iroh 0.97→1.x (digest pin в iroh-base 0.97).
- M9.6 Phase E: спека требует widgets/avatar.rs, search, date separators, multiline input — реализован только аватар в contacts.rs:82-103 и stick_to_bottom (chat.rs:55); input singleline (chat.rs:67).
- spec/17-cross-platform §15.5 / M14: redb-opfs отсутствует на crates.io (facts-crates.md) — план M14.4 требует пересмотра хранилища для браузера.
- Milestone 10 (Android) заявлен как v0.3, но Android-клиент не имеет onboarding/seed (AiraDaemonService.kt:44-48, IdentityScreen.kt:42 TODO), push — TODO (FcmService.kt:24, UnifiedPushReceiver.kt:28).
- CLI /verify — «coming in M6» (aira-cli/src/main.rs:455), хотя M6 помечен выполненным (группы есть в daemon handler).

## Открытые вопросы

- Подтвердить mock-store keyring вручную: запустить aira-gui v0.3.5 → создать identity → перезапустить; если welcome появляется снова — блокер подтверждён (по Cargo.lock backends не скомпилированы).
- Есть ли где-то ветка/worktree с интеграцией iroh в демон (M2 п.7-8 тесты two_node_chat.rs существуют на уровне aira-net) — или сетевую интеграцию демона нужно проектировать с нуля?
- Целевая дистрибуция Android — только sideload (GitHub Releases) или Google Play/F-Droid? От этого зависят targetSdk 36, 16 KB page-size, отказ от FCM.
- Какой формат relay для «своего relay на mail-сервере»: iroh-relay (HTTP/WSS relay для NAT traversal, нужен TLS-домен) и/или aira store-and-forward RelayServer (QUIC ALPN aira/1/relay) — это два разных компонента, оба нужны для тем (1) и (2).
- Модель PoW при создании первого ключа (тема 3): PoW привязан к identity (одноразово, проверяется relay/пирами через сертификат) или к каждому contact request (spam.rs, difficulty 20)? Текущий код поддерживает только второе.
- Почему CI Clippy на main упал 2026-07-30 при локальном exit 0 (facts-crates.md) — нужен лог job'а; вероятно новый stable с новыми lint'ами.
