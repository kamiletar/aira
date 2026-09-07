# Покрытие тестами и фаззингом — аудит (2026-09-07, HEAD d001981, v0.3.5)

> Задание C фазы 3 аудита. Не дублирует `core-audit.md` (п. (j) и находка «нет proptest, fuzz не покрывает
> Message/Handshake/Group/Snapshot»), `daemon-storage-audit.md` (строка «Тесты daemon/storage» в таблице
> реализованного), `clients-audit.md` (keychain `#[ignore]`), `../release-audit-2026-09.md` §1 (435/435) — ссылается
> на них и добавляет новое. Милстоуны — `spec/18-milestones.md` §16.1, M18–M23 (строки 396–762).
>
> **Метод.** Только Read/Grep/awk; `cargo test --workspace -- --list` **недоступен**: рабочая копия не собирается
> из-за незакоммиченного `ml-dsa = "0.1.0-rc.4"` в `Cargo.toml` (`sha3-0.11.0-rc.6` → `keccak::p1600` не найден —
> проверено `cargo test --workspace --no-run`), а трогать Cargo.toml/Cargo.lock запрещено. `cargo llvm-cov` и
> `cargo fuzz` **не установлены** (`no such command`), поэтому строчного покрытия нет — оценка по grep.
> Перечисление тестов: awk по `#[test]`/`#[tokio::test]` → 500 функций; суммы по крейтам совпадают с разведкой
> и с 435 passed фазы 1 (см. §0).

## 0. Резюме

**Цифры (HEAD d001981).**

| Крейт | `#[test]`/`#[tokio::test]` | Из них не запускаются в CI | Интеграционные (`tests/`) | Doc-тесты |
|---|---|---|---|---|
| aira-core | 124 в `src/` + 6 в `tests/multidevice.rs` = **130** | 17 (awslc.rs 9 за `fips`, compat_tests.rs 8 за `compat-test`) | 1 файл, 6 тестов, без сети | 13 |
| aira-net | 87 в `src/` + 17 в `tests/` = **104** | **45** (obfs 6, mimicry 9, reality 12, fingerprint 10, tor 6, cdn 2 — модули за feature, `default = []`) | 3 файла: two_node_chat 2, relay_offline 3, dpi_simulator 12 | 1 |
| aira-storage | **84** | 0 | 0 | 0 |
| aira-daemon | **53** (types 29, handler 14, transfers 4, ipc 3, client 3) | 0 | 0 (каталога `tests/` нет) | 1 (+1 `no_run`) |
| aira-cli | **69** (commands 53, app 9, ui 3, notifications 3, main 1) | 0 | 0 | 0 |
| aira-gui | **40** | 3 `#[ignore]` (keychain) | 0 (каталог `crates/aira-gui/tests` пустой) | 0 |
| aira-ffi | **9** | 0 | 0 | 0 |
| aira-bot | **11** | 0 | 0 | 2 (+2 `no_run`) |
| **Итого** | **500** | **65 (13 %)** | 23 | ~17 |

500 − 62 (feature-gated) − 3 (`#[ignore]`) = **435** — ровно столько прошло в фазе 1, т.е. 13 % тестов (весь DPI-транспорт
и оба крипто-бэкенда aws-lc) в CI **никогда не выполняются**. `proptest = "1"` объявлен (`crates/aira-core/Cargo.toml:49`),
`proptest!` — 0 использований во всём workspace. Фаззинг: 2 таргета в `crates/aira-core/fuzz`, из них
`fuzz_parse_message.rs` **не компилируется** (использует `postcard::from_bytes`, а `fuzz/Cargo.toml:9-11` зависит только
от `libfuzzer-sys` и `aira-core`; aira-core `postcard` не реэкспортирует — grep `pub use postcard` пуст), корпуса нет
(`ls crates/aira-core/fuzz` → только Cargo.toml и fuzz_targets/), т.е. фаззинг не запускался ни разу.

**Главное.**

1. **Обязательные тесты по `rules/testing.md` выполнены на 1 из 4.** Unit-тесты есть почти везде (исключения: `safety.rs`
   — 0 тестов на `safety_number`, `cli/src/ipc.rs` — 0). **Детерминизм «seed → одинаковые ключи на разных машинах» не
   доказан**: все тесты сравнивают два вызова в одном процессе (`seed.rs:502-512`, `identity.rs:123`,
   `rustcrypto.rs:129-145`), ни одного known-answer-вектора «фиксированная фраза → ожидаемый hex». Именно поэтому
   M18 шаг 0 (снапшот VK/EK с тега v0.3.5) — единственный способ доказать, что миграция ml-dsa/ml-kem не поменяла
   адреса пользователей. **Сквозного теста на уровне демона нет и он структурно невозможен**: IPC-сервер живёт в
   бинарнике (`crates/aira-daemon/src/main.rs:26 mod ipc;`, `start_ipc_server` не экспортируется из `lib.rs:21-24`),
   каталога `crates/aira-daemon/tests/` нет. `tests/two_node_chat.rs` доказывает только QUIC-соединение + ALPN +
   фрейминг + канал `ChatHandler` с **поддельным** ciphertext (`b"hello bob, this is alice"`, строка 31) — ни handshake,
   ни ratchet, ни storage, ни IPC в нём нет.
2. **CI не соответствует spec §17**: `ci.yml:53` запускает `cargo test --workspace` без `--all-features`
   (спека: `cargo test --all-features`), нет MSRV-джоба (`rust-version = "1.82"` никогда не проверялась; после M18 —
   1.91), нет Windows/macOS в матрице (named pipe IPC `main.rs:65-69` и keychain не тестируются нигде), нет fuzz,
   нет coverage.
3. **Хрупкость к M18/M19a высокая, но предсказуемая** (§5.4–5.6): компиляционный слом всего aira-net через
   `Endpoint::empty_builder()` (`endpoint.rs:78`), 5 тестовых модулей завязаны на `Platform::Mobile`, который M19
   удаляет (решение владельца №4), 54 места в тестах daemon/ffi/gui/cli/bot используют 32-байтные «pubkey», которые
   сломает валидация длины из M19b п.4; изменение `Message`/`EncryptedEnvelope` в M19a затрагивает ~20 тестов
   aira-net + оба fuzz-таргета. Список — §5.
4. Хорошая новость: тесты aira-net **не зависят от публичных relay n0** — `bind_for_test` использует
   `Endpoint::empty_builder()`, что в iroh 0.97 означает `RelayMode::Disabled` (`~/.cargo/registry/.../iroh-0.97.0/src/endpoint.rs:171`);
   после 30.09.2026 они не сломаются (комментарий `endpoint.rs:53` «Uses iroh's default relay» неверен). Зато
   production-путь `bind()` с `presets::N0` не покрыт ни одним тестом.

Приоритетные задачи по милстоунам — §7; полный план fuzz — §3, proptest — §4.

## 1. Матрица покрытия по крейтам

Легенда: ✅ покрыто, ◐ частично, ❌ нет тестов. «Тесты» — имена функций (файл:строка), «Пробел» — что не проверяется.
Публичный API извлечён awk'ом (`pub fn`/`pub struct`/`pub enum` до первого `#[cfg(test)]`, 482 строки).

### 1.1 aira-core (приоритет: crypto)

| Модуль / API | Тесты | Статус | Пробелы (новое, не из core-audit) |
|---|---|---|---|
| `crypto/mod.rs` — trait `CryptoProvider` (12 fn) + `crypto/rustcrypto.rs` | rustcrypto.rs:120-208 — 7: sign/verify roundtrip, `dsa_deterministic_keygen` ([7u8;32]), invalid sig, wrong key, KEM roundtrip, `kem_deterministic_keygen` ([55u8;32]), `kem_invalid_ciphertext_rejected` | ◐ | **Нет KAT**: детерминизм проверяется как «два вызова дают одно», байты VK/EK/подписи ни с чем не сравниваются → миграция ml-dsa 0.0.4→0.1.1 незаметно поменяла бы адрес. `kem_invalid_ciphertext_rejected` (rustcrypto.rs:195-202) — `let _ = kem_decaps(...)` **без assert** (проверяет только «не паникует», имя лжёт). `decode_verifying_key`/`decode_kem_encaps_key`/`decode_kem_decaps_key` с неверной длиной — только в неработающем fuzz-таргете, unit-теста нет. |
| `crypto/awslc.rs` (fips) | awslc.rs:229-330 — 9 (зеркало rustcrypto + encode/decode roundtrip) | ❌ в CI | За `--features fips`; никогда не запускались в CI (`ci.yml:53`). Компилируемость на Windows/CI не проверялась (aws-lc-rs = cmake/nasm). |
| `crypto/compat_tests.rs` (compat-test) | 8 cross-backend | ❌ в CI | Единственные тесты, где VK сравниваются **побайтно** (`cross_dsa_same_seed_same_public_key`, compat_tests.rs:21-33) — но между двумя бэкендами одной сборки, не с зафиксированным вектором. |
| `seed.rs` — `from_phrase`, `from_phrase_with_platform`, `generate`, `generate_phrase`, `derive`, `derive_pseudonym_seeds` | seed.rs:337-525 — 12: bip39 roundtrip ×2, invalid word/count/checksum, `derive_produces_different_keys_for_different_contexts`, pseudonym ×4, `generate_produces_valid_phrase_and_seed`, `extract_11_bits_basic` | ◐ | Нет KAT для Argon2id Desktop-профиля (фиксированная фраза → ожидаемый seed/`derive("aira/identity/0")` hex) — правило «на разных машинах» не выполняется. Не тестируются: регистр/лишние пробелы во фразе (`bip39_decode` seed.rs:186 — `split_whitespace`, чувствителен к регистру), `Platform::Desktop` vs `Mobile` дают разные seed (задокументированный риск core-audit п.6 — теста нет), `set_11_bits` (только через roundtrip). |
| `identity.rs` — `from_seed`, `from_phrase`, `sign`, `verify`, `verify_with_key`, `public_key_bytes`, `fingerprint`, `verifying_key` | identity.rs:123-172 — 4 | ◐ | `identity_public_key_size` (:171, `== 1952`) — единственная «снапшот-проверка» формата во всём крейте. `from_phrase`, `verify_with_key` с чужим ключом, `fingerprint` KAT — нет. |
| `kem.rs` — `HybridKeypair`, `hybrid_encaps`/`decaps`, `combine_secrets` | kem.rs:175-225 — 3 (roundtrip, разные пиры, `tampered_mlkem_ct_fails`) | ◐ | Нет KAT комбайнера (контекст `aira/hybrid-kem/v1`, BE-counter — core-audit low: спека расходится; тест зафиксировал бы формулу). Порча X25519-части ct не тестируется. |
| `handshake.rs` — `Initiator::{new,start,finish}`, `Responder::{new,respond}`, `negotiate_capabilities` | handshake.rs:367-453 — 4 (в потоках с 8 MB стеком) | ◐ | Кроме replay/misbinding/downgrade (core-audit): **не тестируется путь ошибок декодирования** — `respond()` с `identity_pk`/`kem_encaps_pk` неверной длины (`decode_identity_vk` :215, `decode_kem_ek` :140) → должен вернуть `Err(Handshake)`, unit-теста нет. `Capabilities` с `min_version > max_version` от пира — нет. |
| `ratchet.rs` — `RatchetSession::{new,new_classical,encrypt,decrypt,to_snapshot,from_snapshot}` | ratchet.rs:607-756 — 9 | ◐ | Кроме PQ (core-audit): проверка `MAX_ENVELOPE_SIZE` (ratchet.rs:323) **не покрыта** (grep константы в тестах пуст); `snapshot_roundtrip` (:706) — только классическая сессия без skipped keys (сообщения доставлены по порядку) → сериализация `skipped_entries` и `pq_*_bytes` живой сессией не тестируется; `max_skip_dos_protection` (:672) подделывает `header.counter` **без** проверки, что состояние Bob не изменилось (C2). |
| `proto.rs` — `Message`, `EncryptedEnvelope`, `PlainPayload`, `HandshakeInit/Ack`, `Capabilities`, `File*` | 0 в модуле | ❌ | Ни одного golden-byte теста: перестановка вариантов enum молча ломает wire (postcard кодирует индекс варианта). |
| `padding.rs` — `pad_message`, `unpad_message` | padding.rs:73-147 — 8 | ✅ | Единственный пробел — property-тест (это буквально пример из rules/testing.md:36-43). |
| `group.rs` — `SenderKeyState`, `SenderKeyReceiver` | group.rs:274-410 — 9 (roundtrip, FS, out-of-order, max_skip, replay, rotation, serde) | ✅ | — |
| `group_proto.rs` | group_proto.rs:171-300 — 7 serde roundtrip | ◐ | Только roundtrip с фейковыми размерами (`vec![0xAA; 1952]`); семантика (подписи `PseudonymLink`) не проверяется — но и кода проверки нет. |
| `device.rs` (14 pub fn) | device.rs:271-480 — 19 | ✅ | `verify_link_code` через `String ==` (core-audit low) — тест не заметит замену на ct_eq, ок. |
| `sync.rs` | sync.rs:214-360 — 10 (вкл. wrong key, corrupted, too short) | ✅ | — |
| `spam.rs` — `ContactRequest`, `verify_pow`, `solve_pow`, `RateLimiter` | spam.rs:203-315 — 8 | ◐ | Нет негативного теста «difficulty=0 в запросе отклоняется» (сейчас он бы **упал** — верификатор доверяет запросу, core-audit high); `signature` не проверяется и не тестируется. Тесты PoW используют difficulty 8 — быстро, ок. |
| `safety.rs` — `safety_number(key_a, key_b)` | **0** | ❌ | Формат, длина, симметричность относительно порядка аргументов (safety.rs:39-40 конкатенирует `first‖second`) — ничего не проверено; это то, что пользователь сверяет голосом. |
| `i18n.rs` | 7 | ✅ | FTL встроены через rust-embed (`i18n.rs:19-20`) — внешним вводом не являются. |
| `util.rs` — `rand_id`, `now_micros`, `now_secs` | 0 | ❌ (тривиально) | — |
| `tests/multidevice.rs` | 6 | ◐ | `ratchet_state_handoff` (:72-104) — serde roundtrip `RatchetSnapshot` с фейковыми 64-байтными PQ-ключами, `from_snapshot` не вызывается → «handoff» не доказан. Все 6 — чистый core, без сети/демона (M8 п.6 «2 устройства» не закрыт). |

### 1.2 aira-storage

| Модуль | Тесты | Статус | Пробелы |
|---|---|---|---|
| `lib.rs` — `Storage::open`, `key`, `db` | 2 (`open_creates_database`, `open_is_idempotent`) | ◐ | Нет теста «повреждённый/чужой файл → ошибка, а не паника» (daemon-audit: `main.rs:110 ?` роняет демон); нет `schema_version` (кода нет). `temp_storage()` (lib.rs:182-186) создаёт каталоги в `%TEMP%` и **никогда не удаляет** — каждый прогон оставляет ~80 каталогов `aira-test-*`. |
| `encrypted.rs` — `encrypt_value`, `decrypt_value` | 7 (roundtrip, wrong key, corrupted, too short, empty, разные nonce) | ✅ | AAD нет в коде (daemon-audit low) — тест «ciphertext из другой строки не принимается» невозможен до фикса. |
| `backup.rs` — `export`, `import`, `restore` | 5 (backup.rs:199-320) | ◐ | `import_invalid_file_fails` — только «not a backup» (плохой magic). Нет: неверная `VERSION` (backup.rs:139), обрезанный файл после заголовка, валидный заголовок + мусор (decrypt → Err). **Нет фикстуры файла v1** — при `VERSION = 2` (M19 Phase A п.4) миграцию проверить будет нечем. `import` читает путь → для fuzz нужен `import_bytes` (уже запланирован §14.0). |
| `pending.rs` — enqueue/peek/dequeue/count/clear | 6 | ◐ | Лимитов 1000/100 MB нет в коде → тестов нет; порядок при >1 контакте ✅. |
| `dedup.rs` — `is_duplicate`, `gc_expired` | 4 (`gc_removes_old_entries` вставляет timestamp=1 напрямую в таблицу — хорошо, без sleep) | ✅ | — |
| `sessions.rs` | 6 | ◐ | Все тесты кладут `b"ratchet-snapshot"` — **ни один не сериализует настоящий `RatchetSnapshot`** → связка core↔storage не проверена. |
| `messages.rs` | 8 | ◐ | Коллизия ключа `(contact_id, timestamp_micros)` (daemon-audit low) — теста нет; `delete_expired` ✅. |
| `contacts.rs` 7, `groups.rs` 9, `devices.rs` 9, `pseudonyms.rs` 8, `settings.rs` 5, `types.rs` 8 | | ✅ | `contact_id_is_deterministic` (types.rs:190) — опять «два вызова», не KAT; `contact_id` = `BLAKE3(pubkey)[0..8]` — ключ всей истории, стоит зафиксировать вектор. |

### 1.3 aira-net

| Модуль | Тесты | Статус | Пробелы |
|---|---|---|---|
| `endpoint.rs` — `bind`, `bind_for_test`, `id`, `addr`, `online`, `connect`, `accept`, `close` | 2 (`test_endpoint_binds`, `test_two_endpoints_connect`) — реальные UDP-сокеты | ◐ | `bind()` (production, `presets::N0`, endpoint.rs:80) — **0 тестов**; `online()` — 0. `test_endpoint_binds` проверяет только `id != [0;32]`. |
| `connection.rs` — `write_framed`, `read_framed`, `PeerSession`, `ConnectionManager` | 2 (`test_peer_session_lifecycle`, `test_framing_roundtrip` по QUIC) | ◐ | `read_framed` с `len > MAX_FRAME_SIZE` (connection.rs:60) и с обрывом стрима — не тестируется; `read_framed` принимает `&mut RecvStream` (iroh) → не фаззится без рефакторинга на generic `AsyncRead`. `set_connected/set_disconnected` (:155-172) — нет. |
| `protocol.rs` — `ChatHandler`, `HandshakeHandler`, `build_router` | 2 (ping/pong, receives message) | ◐ | **`HandshakeHandler::accept` (protocol.rs:129+) — 0 тестов**; `IncomingHandshake.reply_tx` путь — 0; поведение при мусоре в стриме (`warn` + break, :63-68) — 0; ALPN FILE/blobs — 0. |
| `relay.rs` — `RelayServer` (handle_request, accept, spawn_gc), `RelayClient` (deposit/retrieve/ack), `derive_mailbox_id` | 9 unit (уровень `handle_request`) + 3 в `tests/relay_offline.rs` | ✅ логика / ◐ сеть | `RelayServer::accept` (framing loop :303-325) только через интеграцию; `RelayClient::deposit` маппинг ошибок (`MailboxFull{current:0,max:0}` :392) — проверяется лишь `is_err()`. `test_relay_gc_ttl` — таймерный (§5.2). |
| `discovery.rs` — `InvitationLink::{to_uri,from_uri}`, `DeviceRecord`, base64url | 8 | ◐ | `from_uri` с валидным base64url, но невалидным postcard — нет; длина `pseudonym_pk` не ограничена и не тестируется; собственная реализация base64url (discovery.rs:145-210) — только example-based roundtrip (`test_base64url_various_lengths` :321) — кандидат №1 на proptest. |
| `ratelimit.rs` | 3 | ✅ | — |
| `blobs.rs` | 5 | ✅ | In-memory только. |
| `transport/mod.rs` — `TransportMode`/`MimicryProfile` `FromStr`/`Display`, `create_transport` | 9 (вкл. `transport_mode_parse_errors`) | ✅ | — |
| `transport/{obfs,mimicry,reality,fingerprint,tor,cdn}.rs` | 45 | ❌ в CI | Модули за `#[cfg(feature)]` (`transport/mod.rs:28-39`), `default = []` (`aira-net/Cargo.toml`), CI без `--all-features` → **весь DPI-код (M7, M12) не тестируется в CI**. Локально в фазе 1 тоже не запускались (435 = без них). Внутри: obfs/mimicry roundtrip-тесты через `tokio::io::duplex(8192 / 256K)` — кадры никогда не рвутся по границе чтения, см. §4 п.10 и §5.3. |
| `tests/two_node_chat.rs` | 2 | ◐ | См. §2.4. |
| `tests/relay_offline.rs` | 3 | ✅ для v1 | Устареет целиком в M21 (`aira/1/relay` удаляется). |
| `tests/dpi_simulator.rs` | 12 | ◐ | Классификатор — самописный (30 строк, dpi_simulator.rs:27-77), не nDPI; 9 из 12 тестов проверяют **сам классификатор на рукописных заголовках**, а не выход транспортов (`obfs_output_is_undetectable` :151 строит «fake_obfs» руками, реальный `ObfsTransport` не вызывается — модуль за feature). Реальный транспорт участвует только в `direct_transport_passes_payload_unchanged`. Заявление M7 п.6 «DPI-simulator не детектирует Aira» этим набором не доказано. |

### 1.4 aira-daemon

| Модуль | Тесты | Статус | Пробелы |
|---|---|---|---|
| `types.rs` — `DaemonRequest` (29 вариантов), `DaemonResponse`, `DaemonEvent`, `ServerMessage` | 29 postcard roundtrip | ◐ | Roundtrip через `serde` derive тавтологичен (проверяет serde, не формат); golden-байтов нет → перестановка варианта в enum (IPC-совместимость GUI↔демон разных версий) не ловится. |
| `handler.rs` — `handle_request` (диспетчер 29 запросов), `handle_incoming_payload` | 14 (handler.rs:985-1560) | ◐ | Напрямую покрыты: create_group, 5 incoming GroupControl, incoming Text, GetMyAddress, GroupAddMember, LeaveGroup, GenerateLinkCode, LinkDevice(invalid), GetPseudonyms, derive_pseudonym. **Через aira-ffi** (runtime.rs → `handle_request`): AddContact/GetContacts/RemoveContact, SendMessage/GetHistory, GetGroups/SendGroupMessage/GetGroupHistory, Set/GetTransportMode, GetDevices. **Нигде**: `SetTtl`, `ExportBackup`, `ImportBackup`, `SendFile` (handler.rs:863-949 — синхронное чтение файла до 4 GiB, daemon-audit medium), `Shutdown`, `GetGroupInfo`, `GroupRemoveMember`, `AcceptGroupInvite`, `GetPseudonym`, `FindPseudonym`, `UnlinkDevice`. Покрытие демона зависит от тестов другого крейта (FFI) — если Android станет preview и `aira-ffi` уйдёт из workspace, демон потеряет половину тестов. `test_storage()` (handler.rs:970-974) — каталоги в `%TEMP%` без удаления. |
| `ipc.rs` (в **бинарнике**, `main.rs:26`) — `read_message`, `write_*`, `start_ipc_server` | 3 (ipc.rs:262-323) | ◐ | Тесты вызывают только `write_response`/`write_event` и разбирают буфер вручную; **`read_message` (ipc.rs:18-30, серверный парсер IPC + проверка 1 MiB) не вызывается ни одним тестом**. `start_ipc_server` (Unix/Windows) — 0; форвардер событий (`Lagged`, daemon-audit medium) — 0. |
| `client.rs` — `DaemonClient::{connect,request}`, `read_server_message` | 3 (`read_server_message_rejects_too_large` ✅) | ◐ | `connect`/`request` — 0 (нужен живой сервер). |
| `transfers.rs` — `TransferManager` | 4 | ✅ | — |
| `main.rs` — конфиг (AIRA_SEED), TTL/dedup GC-таски | 0 | ❌ | — |

### 1.5 aira-ffi, aira-gui, aira-cli, aira-bot

| Крейт / модуль | Тесты | Пробелы |
|---|---|---|
| ffi `runtime.rs` (23 pub fn) | 9 | Не покрыты: `AiraRuntime::new` с невалидной фразой → `FfiError`, `vec_to_device_id` (есть только `invalid_group_id_rejected`), `unlink_device`, `link_device`, `export/import backup`, `send_file`. `event_listener_receives_callbacks` — `thread::sleep(100ms)` (runtime.rs:576). `test_runtime()` (runtime.rs:412-418): `tempfile::tempdir()` **дропается при выходе из функции**, пока runtime держит redb в этом каталоге — на Windows удаление молча не удаётся, на Linux каталог unlink'ается под живой БД; каждый тест делает **два** Argon2id 256 MB (`MasterSeed::generate()` + `AiraRuntime::new` → `from_phrase`, runtime.rs:65), 9 тестов параллельно → до ~4,5 GB пик. |
| ffi `callbacks.rs` `dispatch_event`, `types.rs` | 0 напрямую | 1 из 13 событий проверено косвенно. |
| gui `state.rs` 13, `ipc.rs` 8, `onboarding.rs` 6, `password_vault.rs` 5, `keychain.rs` 3 (`#[ignore]`), `daemon_manager.rs` 2, `notifications.rs` 1, `message_bubble.rs` 2 | 40 | `ipc.rs` тесты — `matches!` на вариант (маппинг команд), `Bridge`/reconnect/spawn (ipc.rs:567-1050) — 0; `daemon_manager::locate_returns_err_when_missing` (:238-262) принимает **и Ok, и Err** — тавтология; `password_vault` ×5 по 128 MiB Argon2 — медленно, но корректно; `keychain` ×3 ignored → и mock-store keyring (clients-audit blocker) не ловится. `views/*`, `app.rs`, `tray.rs`, `theme.rs` — 0 (egui, ожидаемо). |
| cli `commands.rs` 53, `app.rs` 9, `ui.rs` 3, `notifications.rs` 3, `main.rs` 1 | 69 | `cli/src/ipc.rs` — **0**; `main.rs` — только `parse_ttl_variants`; hex-fallback `hex::decode(..).unwrap_or_else(|_| pubkey.as_bytes().to_vec())` (main.rs:300,475,538,556) — не-hex ввод молча уходит как байты, теста нет. |
| bot | 11 | `run_bot` (runner.rs) с живым демоном — 0; `extract_text_returns_none_for_garbage` ✅. |

## 2. Обязательные тесты по `rules/testing.md` — статус

| Требование (testing.md:87-93) | Статус | Где есть | Чего нет |
|---|---|---|---|
| Unit-тесты для каждой новой функции | ◐ | Все модули core/storage кроме `safety.rs`, `util.rs`, `proto.rs` | §1: `safety_number`, `HandshakeHandler`, `read_message` IPC, 12 вариантов `DaemonRequest`, `bind()`. |
| **Детерминизм seed → одинаковые ключи на разных машинах** | ❌ | Только внутрипроцессные сравнения: `seed.rs:502-512`, `seed.rs:417`, `identity.rs:123`, `rustcrypto.rs:129,175`, `awslc.rs:238,277` (за feature), `compat_tests.rs:21,68` (за feature, между бэкендами), `device.rs:271,290`, `storage/types.rs:190,247`, `relay.rs:443` | **Ни одного known-answer теста** (фиксированный вход → зафиксированный hex). `handler.rs:958-965` имеет фиксированную фразу `abandon×23 art`, но с `Platform::Mobile` и без ожидаемых байт. Без KAT нельзя заметить ни смену Argon2-параметров/соли, ни смену keygen в ml-dsa/ml-kem, ни смену `contact_id`. → M18 шаг 0 (§7.1). |
| Невалидные входы не паникуют | ◐ | bip39 (seed.rs:364-390), padding (:116-135), sync (:243-267), encrypted (:111-133), backup (:273-297), `read_server_message_rejects_too_large` (client.rs:234), `transport_mode_parse_errors`, `test_invitation_link_invalid`, ratchet `max_skip`/`wrong_key`, `dsa_invalid_signature_rejected` | Нет negative-тестов для: `HandshakeInit` с ключами неверной длины, `read_message` IPC > 1 MiB (сервер), `read_framed` > 256 KB, `RelayRequest` мусор, `InvitationLink` валидный b64 + мусор, `RatchetSnapshot` с мусором в `pq_*_bytes` → `from_snapshot` Err, `import` backup с плохой версией, кадры obfs/mimicry/REALITY (feature). Fuzz-таргет для `PlainPayload` не компилируется. |
| Интеграционный тест сквозного сценария | ◐ уровень aira-net / ❌ уровень демона | `tests/two_node_chat.rs`, `tests/relay_offline.rs` | См. 2.4. Ни один тест не запускает `main.rs`, IPC-сокет, `handle_request` + сеть. |
| Property-based (proptest) — M1 п.11 (`spec/18-milestones.md:21`) | ❌ | dev-dependency объявлена | 0 `proptest!`. |
| Fuzz для всех парсеров внешних данных | ❌ | 2 таргета (1 не собирается) | §3. |

### 2.1 Что декларируют милстоуны и что есть

| Милстоун, пункт | Заявлено | Факт |
|---|---|---|
| M1 п.10-11 (`18-milestones.md:20-21`) | unit + proptest для крипто-примитивов | unit ✅, proptest ❌ |
| M2 п.7-8 (:33-34) | два узла обмениваются сообщением; сообщение через relay при офлайн-пире | ✅ на уровне aira-net (`two_node_chat.rs:16`, `relay_offline.rs:18`) с фейковым ciphertext |
| M3 п.5 (:56) | End-to-end тест через CLI | ❌ — cli тесты только парсер команд |
| M6 п.6 (:65) | 3 ноды в группе | ❌ — group.rs тесты чисто криптографические; M19 Phase C п.16 |
| M8 п.6 (:91) | 2 устройства одного пользователя | ◐ — `tests/multidevice.rs` без сети/демона |
| M7 п.6 | DPI-симулятор не детектирует Aira | ◐ — самописный классификатор, реальные транспорты за feature не участвуют (§1.3) |

### 2.2 Детерминизм — где именно нужны векторы (для M18 шаг 0)

Все точки, где байты зависят от seed и являются **внешними идентификаторами** (изменение = потеря контактов/адреса):

1. `MasterSeed::from_phrase(phrase)` — Argon2id m=262144/t=3/p=4, соль `aira-master-v1-m256` (seed.rs:28-36, 100-115) → 32 байта.
2. `seed.derive("aira/identity/0")` → `identity_keygen` → `encode_verifying_key` (1952 байта) = адрес пользователя.
3. `seed.derive("aira/mlkem/0")` → `kem_keygen` (`aira/kem-keygen-d/-z`, rustcrypto.rs:51-56) → EK 1184 / DK 2400.
4. `derive_pseudonym_seeds(counter)` → псевдонимные VK (seed.rs, handler.rs:985-1000).
5. `contact_id(pubkey)` = `BLAKE3(pubkey)[0..8]` (storage/types.rs:177-183) — ключ всех таблиц.
6. `derive_mailbox_id(shared_secret)` (relay.rs:85) — уходит в M21.
7. `derive_device_id`/`derive_sync_key`/`generate_link_code(seed, t)` (device.rs:184-227).
8. `sign(sk, msg)` детерминированная (rustcrypto.rs:29-30) — подпись как вектор.

Сейчас ни для одной из них нет ожидаемого значения в репозитории.

### 2.3 Сквозной тест на уровне демона — подтверждение отсутствия

- `ls crates/aira-daemon/tests` → каталога нет; `crates/aira-daemon/src/lib.rs:21-24` экспортирует только `client`, `handler`, `transfers`, `types`.
- `ipc.rs` подключён как `mod ipc;` в `main.rs:26`; `pub async fn start_ipc_server` (ipc.rs:67 unix / :165 windows) виден только бинарнику → интеграционный тест **не может** поднять сервер in-process. Единственный способ сейчас — спавнить бинарник `aira-daemon` с `AIRA_SEED` (256 MB Argon2 на старте, `main.rs:94-98`).
- grep по всем `tests/` и `#[tokio::test]`: `DaemonClient::connect` не вызывается ни одним тестом; `handle_request` в тестах вызывается напрямую (handler.rs, runtime.rs).
- Вывод: M19 Phase C п.15 (`two_daemons.rs`) требует предварительного шага — вынести `ipc.rs` в библиотеку (`aira_daemon::ipc` или крейт `aira-node` из §14.0) и добавить тестовый конструктор seed без Argon2 (§5.5).

### 2.4 Что доказывает `tests/two_node_chat.rs` (и чего не доказывает)

`two_nodes_exchange_message` (:16-90): два `AiraEndpoint::bind_for_test(None)` (iroh `empty_builder` → `RelayMode::Disabled`, без discovery, адрес — прямые локальные сокеты из `bob.addr()`), `build_router` у Bob с `ChatHandler`, Alice открывает bi-stream по ALPN `aira/1/chat`, пишет `Message::Encrypted(EncryptedEnvelope{nonce:[0xAA;12], counter:1, ciphertext:b"hello bob, this is alice"})`, Bob получает `IncomingMessage{from: alice.id(), message}` из mpsc и сравнивает поля; второе сообщение — по новому соединению.

Доказывает: QUIC-соединение iroh на loopback, регистрация ALPN, `write_framed`/`read_framed` (u32 BE + postcard), `ChatHandler::accept` доставляет в канал, `from` = `EndpointId` отправителя.

Не доказывает: handshake (`HandshakeHandler` даже не получает соединений), ratchet (ciphertext — plaintext-строка, `RatchetSession` не создаётся), привязку `EndpointId` ↔ ML-DSA identity (core-audit C8), storage, dedup, pending, IPC, relay-fallback, работу за NAT/через relay (relay отключён), production `bind()`. `ping_pong_over_chat` — только Ping/Pong. Таймауты 10 с (:44, :75) — разумно.

## 3. План фаззинга

### 3.1 Состояние инфраструктуры

- `crates/aira-core/fuzz/Cargo.toml`: `libfuzzer-sys = "0.4"` (актуальная мажорная линия), `aira-core = { path = ".." }`, собственный `[workspace] members = ["."]` — корректно исключает крейт из корневого workspace (в корневом `Cargo.toml:1-11` `exclude` нет, но вложенный `[workspace]` достаточен). **Нет `postcard`** → `fuzz_parse_message.rs:10,14-16` не компилируется. Нет `arbitrary`, нет `[profile.release] debug = 1`.
- `.gitignore:9-11`: `fuzz/target/`, `fuzz/corpus/`, `fuzz/artifacts/` — паттерны со слэшем в середине **привязаны к корню** репозитория и не матчат `crates/aira-core/fuzz/corpus/` → корпус/артефакты попадут в git. Нужно `**/fuzz/target/` и т.д. (или наоборот — корпус коммитить сознательно, см. ниже).
- `rules/testing.md:60,83-84` называют таргеты `parse_message` / `parse_group_message`; реальные — `fuzz_parse_message` / `fuzz_decode_keys`; `parse_group_message` не существует.
- `cargo fuzz` не установлен; на Windows официальная поддержка cargo-fuzz — через WSL/Linux (в задании зафиксировано так; отдельно не проверялось). В CI — ubuntu + nightly.

### 3.2 Полный список парсеров внешних данных → таргеты

| # | Парсер (path:line) | Источник данных | Таргет есть? | Предлагаемый таргет |
|---|---|---|---|---|
| 1 | `read_framed::<Message>` — `connection.rs:52-71`, вызов `protocol.rs:63` (ChatHandler) | сеть, любой пир | ❌ (`fuzz_parse_message` — только `PlainPayload`/`EncryptedEnvelope`, и не собирается) | `aira-core/fuzz/fuzz_targets/fuzz_wire_message.rs`: `postcard::from_bytes::<Message>(data)`; после M19a — `Message::Ratchet{header, envelope}`. |
| 2 | `HandshakeInit`/`HandshakeAck` → `Responder::respond` (`handshake.rs:213-262`, decode :215) / `Initiator::finish` (:138-171, decode :140) | сеть, незнакомец (`HandshakeHandler`) | ❌ | `fuzz_handshake.rs`: `#[derive(Arbitrary)] struct ArbInit { identity_pk: Vec<u8>, kem_encaps_pk: Vec<u8>, x25519_pk: [u8;32], caps: (u16,u16,u64), signature: Vec<u8> }` → `HandshakeInit` → `Responder::new(&FIXED_SEED).respond(&init)`; то же для `finish` с `ArbAck`. Требует дешёвого конструктора seed без Argon2 (`MasterSeed::from_raw([u8;32])` под `#[cfg(feature = "test-utils")]`) — иначе 256 MB на итерацию. |
| 3 | `RatchetSession::decrypt(header, envelope)` — `ratchet.rs:290-330` | сеть (после M19a header в wire) | ❌ | `fuzz_ratchet_decrypt.rs`: фиксированная пара `new_classical` (как `make_pair` ratchet.rs:580-604), `Arbitrary` `MessageHeader` (dh_public [u8;32], prev_chain_len u64, counter u64, pq_kem_ct/ek Option<Vec<u8>>) + `EncryptedEnvelope`; инвариант после M19a C2: при `Err` `to_snapshot()` до/после равны. |
| 4 | `RatchetSnapshot` postcard → `from_snapshot` (`ratchet.rs:484-535`), читается `sessions::load` | локальная БД (зашифрована) — после backup/restore чужой файл | ❌ | `fuzz_ratchet_snapshot.rs`: `from_bytes::<RatchetSnapshot>` → `from_snapshot` (декодирование `pq_*_bytes` — `decode_kem_*`, после M18 валидирующее). |
| 5 | `PlainPayload` (вкл. `GroupControl`) — `handler.rs:629 handle_incoming_payload` | сеть после decrypt | ◐ (таргет есть, не собирается) | Починить `fuzz_parse_message` (`postcard = "1"` в fuzz/Cargo.toml); расширить: `GroupControl`, `MessageMeta`, `EncryptedGroupEnvelope`, `GroupMessage` (`group_proto.rs`). |
| 6 | `SenderKeyReceiver::decrypt(counter, nonce, ct)` — `group.rs:165-200` | сеть (группы) | ❌ | `fuzz_group_decrypt.rs`: фиксированный chain key, Arbitrary `(u64, [u8;12], Vec<u8>)`; инвариант: `skipped_keys.len() ≤ MAX_SKIP`. |
| 7 | `decode_sync_batch` — `sync.rs:166-179` (AEAD → postcard `SyncBatch`) | другое устройство (после M8/сети) | ❌ | `fuzz_sync_batch.rs`: `from_bytes::<SyncBatch>` и `::<SyncState>` напрямую (AEAD-слой фаззить бессмысленно). |
| 8 | `InvitationLink::from_uri` + `base64url_decode` (`discovery.rs:52-61, 180-210`), `DeviceRecord::from_bytes` (:145) | пользователь вставляет/сканирует QR — недоверенно | ❌ | **Новый крейт `crates/aira-net/fuzz`**: `fuzz_invitation_link.rs` (`from_uri(str)`, `base64url_decode`, `DeviceRecord::from_bytes`). |
| 9 | `RelayRequest` — `relay.rs:311 read_framed` в `RelayServer::accept`; `RelayResponse` — `:363` у клиента | сеть, любой пир | ❌ | `aira-net/fuzz/fuzz_relay_request.rs`: `from_bytes::<RelayRequest>` + `RelayServer::handle_request` (сейчас `async fn` private, relay.rs:198 — сделать `pub` под `#[doc(hidden)]`/feature `fuzzing`; в M21 переезжает в `aira-relay` — таргет писать там). |
| 10 | `read_framed` фрейминг (`connection.rs:52-71`) | сеть | ❌ | Не фаззится: сигнатура `&mut RecvStream`. Рефакторинг на `impl AsyncRead + Unpin` (M19a п.7 «read_framed») → `fuzz_framing.rs` через `tokio::io::Cursor`/`duplex`. |
| 11 | IPC: `read_message` → `DaemonRequest` (`ipc.rs:18-30`), `read_server_message` → `ServerMessage` (`client.rs:174-186`) | локальный, **неаутентифицированный** сокет (daemon-audit high) | ❌ | `crates/aira-daemon/fuzz/fuzz_ipc.rs`: `from_bytes::<DaemonRequest>`, `::<ServerMessage>`; после вынесения `read_message` в lib — через `Cursor` с длиной > 1 MiB. |
| 12 | `backup::import` (`backup.rs:127-149`: magic/version/decrypt/postcard `BackupData`) | файл пользователя | ❌ | `crates/aira-storage/fuzz/fuzz_backup.rs` после `import_bytes(&[u8], key)` (§14.0) + `from_bytes::<BackupData>`; `decrypt_value` (encrypted.rs:56) отдельно. |
| 13 | `bip39_decode` (`seed.rs:186-220`) | ввод пользователя (onboarding GUI/Android) | ❌ | `fuzz_bip39.rs`: `MasterSeed::validate_phrase(&str)` (публичной функции нет — M19b п.7 добавляет `validate_seed_phrase`; фаззить её, **без** Argon2). |
| 14 | `ContactRequest` postcard + `verify_pow` (`spam.rs:35-62`) | сеть, незнакомец (M19a/M22) | ❌ | `fuzz_contact_request.rs` — вместе с переписыванием верификатора в M19a п.5. |
| 15 | Транспорты: obfs декодер (`obfs.rs:221-313`), mimicry state machine (`mimicry.rs:232-400`), REALITY `read_client_hello` (`reality.rs:172-236`), `patch_session_id` (:241-252), `ReplayStream`; fingerprint SNI | сеть, DPI/активный зонд | ❌ | `aira-net/fuzz/fuzz_obfs_stream.rs`, `fuzz_mimicry_stream.rs`, `fuzz_reality_hello.rs` (features `obfs4`/`mimicry`/`reality`): произвольные байты во внутренний `duplex`, читать до EOF/ошибки; инвариант — нет паники, `read_buf` ≤ `MAX_FRAME_PAYLOAD` (65 536). Приоритет ниже релизного пути (транспорты не в M18–M23). |
| 16 | `TransportMode::from_str` (`transport/mod.rs:320-345`, вызов `handler.rs:837`) | строка из IPC | ◐ example-тесты | Дёшево: `fuzz_transport_mode.rs` (str → parse → Display → parse == исходный). |
| 17 | Конфиг-файлы | — | н/д | Демон читает только env (`main.rs:76-98`), конфигов нет. M20 п.6 вводит TOML `[network]` → тогда `fuzz_config.rs` (`toml::from_str::<NetConfig>`). |
| 18 | `decode_verifying_key`/`decode_kem_encaps_key`/`decode_kem_decaps_key` | сеть (handshake), БД | ✅ `fuzz_decode_keys.rs` | После M18 `decode_kem_encaps_key` валидирует EK (FIPS 203 §7.2) — таргет актуален как есть. |
| 19 | CLI `commands::parse` (`cli/commands.rs`), GUI `password_vault::unlock` blob (`password_vault.rs:148`), keychain base64 (`keychain.rs:78`) | локальный пользователь / keyring | ◐ example | Низкий приоритет; `unlock` можно покрыть proptest «любой blob → Err или Ok, без паники». |
| 20 | Значения redb (postcard после `decrypt_value`) — contacts/messages/groups/pseudonyms | локальная БД под AEAD | — | Не фаззить (AEAD гарантирует целостность); достаточно п.4 и п.12. |

### 3.3 Как гонять

1. **Починить сборку** (M18): в `crates/aira-core/fuzz/Cargo.toml` добавить `postcard = "1"`, `arbitrary = { version = "1", features = ["derive"] }`, `[profile.release] debug = 1`; в корневой `Cargo.toml` — `exclude = ["crates/aira-core/fuzz", "crates/aira-net/fuzz", ...]` для явности; `.gitignore` → `**/fuzz/target/`, `**/fuzz/artifacts/`; корпус (`fuzz/corpus/<target>/`) **коммитить** — сгенерировать из существующих тестов (валидные `Message`, `HandshakeInit`, `RatchetSnapshot`, `RelayRequest`, invitation URI) одноразовым `#[test] #[ignore] fn dump_corpus()`.
2. **CI-джоб `fuzz`** (ubuntu-latest, `dtolnay/rust-toolchain@nightly`, `cargo install cargo-fuzz` через `taiki-e/install-action` или `cargo-binstall`): на каждом PR — `cargo fuzz build` во всех fuzz-крейтах (ловит сегодняшнюю поломку); на `main`/nightly-schedule — `cargo fuzz run <t> -- -max_total_time=60` по таргету (M19a п.7), артефакты `fuzz/artifacts` — upload при падении.
3. **Регрессия без nightly** (работает на Windows/stable): `#[test] fn fuzz_corpus_regression()` в `crates/aira-core/tests/fuzz_regression.rs` — прогоняет каждый файл из `fuzz/corpus/*` и `fuzz/artifacts/*` через ту же функцию, что и таргет (вынести тело таргета в `aira_core::fuzz_hooks::<name>(data)` под feature `fuzzing`). Это гарантирует, что найденные crash-инпуты навсегда остаются в `cargo test`.
4. Локально на Windows: WSL2 + `cargo +nightly fuzz run` из `crates/aira-core` (cargo-fuzz ищет `./fuzz` относительно пакета; из корня репо не найдёт).

## 4. План proptest

`proptest = "1"` уже в dev-dependencies aira-core. Для aira-net/storage/daemon добавить. `ProptestConfig::with_cases(N)` подбирать по цене (KEM/Argon2 — мало кейсов; padding/serde — 1000+).

| # | Свойство | Модуль (стратегия) | Замечание |
|---|---|---|---|
| 1 | `unpad(pad(m)) == m` для `m: Vec<u8>` длиной 0..=4094; `pad(m).len() ∈ {256,512,1024,2048,4096}` и минимальный ≥ len+2; `len > 4094 → None`; `unpad(any bytes)` не паникует | `padding.rs` (`prop::collection::vec(any::<u8>(), 0..=4094)`) | Буквальный пример из `rules/testing.md:36-43`. |
| 2 | `bip39_decode(bip39_encode(e)) == e` для `e: [u8;32]`; `bip39_decode(any String)` не паникует; замена одного слова → `Err` (для 24-словных фраз с чексуммой 8 бит вероятность ложного успеха 1/256 — считать статистически, не строго) | `seed.rs` (`any::<[u8;32]>()`, `"[a-z ]{0,300}"`) | Без Argon2 — только кодек. |
| 3 | postcard roundtrip `from_bytes(to_allocvec(x)) == x` для **всех** wire/IPC/storage-типов: `Message`, `EncryptedEnvelope`, `PlainPayload`, `MessageMeta`, `HandshakeInit/Ack`, `Capabilities`, `GroupControl`, `GroupMessage`, `EncryptedGroupEnvelope`, `RatchetSnapshot`, `SyncBatch`/`SyncState`, `ContactRequest`, `RelayRequest/Response`, `InvitationLink`, `DeviceRecord`, `DaemonRequest/Response/Event`, `ServerMessage`, `ContactInfo`, `StoredMessage`, `GroupInfo`, `DeviceInfo`, `TransportMode` (Display↔FromStr) | Нужен `Arbitrary`/`Strategy` для каждого типа — `#[cfg_attr(test, derive(proptest_derive::Arbitrary))]` или `arbitrary` crate (общий с fuzz, п.3.3) | Дополнить **golden-байтами**: для каждого типа один `assert_eq!(to_allocvec(&fixture), include_bytes!("vectors/<type>.bin"))` — иначе roundtrip не защищает совместимость (§1.4). |
| 4 | **Ratchet как state machine**: произвольная последовательность операций `{A→B, B→A, deliver(i), drop(i), snapshot_restore(A|B)}` при ограничении «не более MAX_SKIP пропусков» → каждое доставленное сообщение расшифровывается в исходный plaintext, повторная доставка → `Err`, после `snapshot/restore` обе стороны продолжают; после M19a — при `Err` состояние неизменно (C2), с `pq_enabled = true` (C3) | `ratchet.rs` (`prop::collection::vec(op_strategy(), 1..200)`) | Расширяет `many_messages_with_direction_changes` (ratchet.rs:736) и `out_of_order_delivery` (:652). |
| 5 | `SenderKeyReceiver`: любая перестановка counter'ов в окне MAX_SKIP расшифровывается; replay → Err; после `update_chain_key` старые counter'ы → Err | `group.rs` | |
| 6 | Гибридный KEM: `decaps(dk, encaps(ek)) == ss` для случайных seed; порча любого байта `x25519_ct` или `mlkem_ct` → `Err` либо `ss' ≠ ss` | `kem.rs` (`cases = 16`, каждый ML-KEM keygen ~мс) | |
| 7 | `dedup`: для любой последовательности `[u8;16]` первое вхождение `false`, повтор `true`, разные id независимы | `storage/dedup.rs` (`cases = 8`, temp_storage на кейс) | |
| 8 | Лимиты размеров: `write_framed(x)` с `len(postcard(x)) > 256 KB` → `EnvelopeTooLarge`; relay `Deposit` с `ciphertext.len() + 20 > max_envelope_size` → `EnvelopeTooLarge` **для любой** длины (сейчас проверено одно значение, relay.rs:561); `RatchetSession::decrypt` с `ciphertext.len() > 65 536` → `Err`; IPC `read_message` с len > 1 MiB → Err | `connection.rs`, `relay.rs:214`, `ratchet.rs:323`, `ipc.rs:19` | |
| 9 | `InvitationLink::from_uri(to_uri(l)) == l` для произвольных `pseudonym_pk`/`endpoint_addr_bytes`; `base64url_decode(base64url_encode(b)) == b` для `b: Vec<u8>` любой длины (в т.ч. 0, 1, 2 mod 3) — собственная реализация `discovery.rs:145-210` | `discovery.rs` | Сейчас `test_base64url_various_lengths` (:321) — несколько длин вручную. |
| 10 | **Транспорты как стримы**: для `payload: Vec<u8>` и произвольного разбиения на write-чанки `(1..=4096)` и read-буферы `(1..=4096)` через `duplex(64)` — `received == payload` для obfs, mimicry (все профили), REALITY-frame | `transport/{obfs,mimicry,reality}.rs` (features) | Существующие тесты используют `duplex(8192)`/`(256K)` и `write_all` целиком → 2-байтный заголовок кадра **никогда не рвётся по границе чтения**. В `obfs.rs:270-275` этот случай явно не обработан («Partial length header — … we just skip this byte») — байт теряется, поток рассинхронизируется; свойство поймает. |
| 11 | `decrypt_value(encrypt_value(p)) == p`; инверсия любого бита ciphertext → `Err`; `decrypt_value(any bytes)` не паникует | `storage/encrypted.rs` | |
| 12 | `seed.derive(a) != seed.derive(b)` для любых `a != b` (строки); `derive_pseudonym_seeds(i)` попарно различны | `seed.rs` (дешёво: BLAKE3) | |
| 13 | `verify_link_code(seed, generate_link_code(seed, t), t')` истинно для `t' ∈ [t, t+299]` и ложно для `t' ≥ t+600`; код всегда 6 цифр | `device.rs` | |
| 14 | `safety_number(a, b)`: фиксированная длина/алфавит; проверить и зафиксировать, симметрична ли относительно `(a, b)` ↔ `(b, a)` (по коду safety.rs:39-40 — зависит от порядка; если UI показывает обеим сторонам, нужна сортировка) | `safety.rs` | Сейчас 0 тестов. |
| 15 | `TransportMode`: `parse(display(m)) == m` для сгенерированных `m` (SNI `[a-z0-9.-]{1,63}`), `parse(any str)` не паникует | `transport/mod.rs` | |

## 5. Хрупкие / устаревающие тесты

### 5.1 `#[ignore]`

Только `crates/aira-gui/src/keychain.rs:189, 209, 221` (3) — «requires a running OS keychain». Из-за этого mock-store keyring
(clients-audit blocker) не ловится ни в CI, ни локально. Снять ignore на Windows/macOS-раннерах после M19b п.1.

### 5.2 Тайминги (потенциально флаки)

| Тест | Механизм | Риск / фикс |
|---|---|---|
| `relay.rs:643-670 test_relay_gc_ttl` | `ttl = 50 ms`, `gc_interval = 30 ms`, реальный `tokio::time::sleep(150 ms)` (:664) | На загруженном CI GC может не успеть/успеть дважды. → `#[tokio::test(start_paused = true)]` + `tokio::time::advance(Duration::from_millis(100))`. |
| `aira-ffi/src/runtime.rs:532-582 event_listener_receives_callbacks` | `std::thread::sleep(100 ms)` (:576) в ожидании spawn'нутой async-задачи | Гонка; → `Notify`/канал с `recv_timeout`. |
| `two_node_chat.rs:44,75`, `protocol.rs:257` | `timeout(10 с / 5 с)` на приём | Норма. |
| `padding.rs:137 padding_is_random_not_zero` | `assert_ne!` двух случайных 253-байтных паддингов | Вероятность ложного падения ~2^-2024, норма. |
| `password_vault.rs` ×5, `identity.rs`, `kem.rs`, `handshake.rs` (Mobile 64 MB ×2 seed'а), `aira-ffi` ×9 (Desktop 256 MB ×2) | Argon2id в каждом тесте | Не флаки, но медленно и memory-heavy; FFI-тесты параллельно → до ~4,5 GB (§1.5). → тестовый конструктор seed без Argon2 (§5.5). |

`spam.rs:203 pow_verify_works` (`assert!(!verify_pow(data, nonce + 1, 8))`) — детерминирован (вход константа), не флаки.

### 5.3 Зависимость от сети / DNS / публичных relay n0

- 11 unit-тестов aira-net (`endpoint.rs:152,160`, `connection.rs:225`, `protocol.rs:203,232`) + 5 интеграционных
  (`two_node_chat.rs` ×2, `relay_offline.rs:18,105`, `dpi_simulator.rs:130` — последний без сокетов) биндят реальные UDP-сокеты
  через `AiraEndpoint::bind_for_test(None)`.
- `bind_for_test` → `Endpoint::empty_builder()` (`endpoint.rs:78`). В iroh 0.97 `empty_builder` = «no address lookup services,
  and `RelayMode::Disabled`» (`iroh-0.97.0/src/endpoint.rs:171,836`) → **никакого обращения к relay n0 и DNS** — после
  30.09.2026 эти тесты не сломаются. Комментарий `endpoint.rs:53` («Uses iroh's default relay for connectivity») неверен — поправить в M18.
- Обратная сторона: production `bind()` → `presets::N0` (`endpoint.rs:80`) не покрыт вообще; после M20 (`AiraPreset`) нужен unit-тест
  «relay map содержит только свой URL, n0-fallback выключен».
- Тестов, ходящих в DNS/интернет, нет (grep `n0.computer`/`iroh.link`/`dns` в тестах пуст).

### 5.4 Тавтологические / слабые тесты

| Тест | Почему слабый |
|---|---|
| `rustcrypto.rs:195 kem_invalid_ciphertext_rejected` | `let _ = kem_decaps(..)` — без assert; проверяет отсутствие паники, имя обещает отклонение. После M18 (`decapsulate_slice`, длина ≠ 1088 → Err) переписать как (г) из M18 п.7. |
| `daemon_manager.rs:238 locate_returns_err_when_missing` | `match Ok/Err` — обе ветки проходят, проверяется только имя файла. |
| `daemon/types.rs` 29 roundtrip'ов, `group_proto.rs` 7, `storage/types.rs` 4, `transport/mod.rs:512`, `spam.rs:228` | Roundtrip через serde-derive — проверяют serde, а не формат; без golden-байтов не ловят изменение порядка вариантов/полей. |
| `gui/ipc.rs:1069-1135` 8 тестов | `matches!` на вариант enum после тривиального маппинга. |
| `endpoint.rs:152 test_endpoint_binds` | `assert_ne!(id, [0;32])`. |
| `dpi_simulator.rs` 9 из 12 | Проверяют самописный классификатор на рукописных байтах, не выход транспортов (§1.3). |
| `multidevice.rs:72 ratchet_state_handoff` | Serde roundtrip с фейковыми 64-байтными PQ-ключами, `from_snapshot` не вызывается. |
| `ffi/runtime.rs:592 generate_link_code_returns_string` | `!code.is_empty()`. |

### 5.5 Что сломает M18 (iroh 1.1 + ml-dsa 0.1.1 + ml-kem 0.3.2)

**Компиляция (весь крейт → все его тесты):**

- `crates/aira-net/src/endpoint.rs:78 Endpoint::empty_builder()` удалён в 1.x → не собирается aira-net → **все 104 теста aira-net + daemon (53) + ffi (9) + gui (40) + cli (69) + bot (11)** не запускаются до правки (`Endpoint::builder(presets::Minimal)` по спеке; что именно включает `presets::Minimal` в 1.1 — relay/discovery — здесь не проверено, см. §8). Прочие iroh-API в тестах (`conn.remote_id()`, `ep.id()/addr()`, `router.shutdown()`, `EndpointAddr`) — проверить `cargo check --all-targets`.
- `crates/aira-core/src/crypto/rustcrypto.rs` (все 7 тестов — компилируются после переписывания провайдера, семантика сохраняется), `awslc.rs` 9 (за `fips`), `compat_tests.rs` 8 (за `compat-test`) — как в M18 п.4-5.
- `handshake.rs:82,195` вывод типов → 4 теста handshake.

**Семантика после починки:**

- `ratchet.rs:706 snapshot_roundtrip` — классическая сессия (`pq_dk_bytes = None`) → не затронут; но `multidevice.rs:72` кладёт `pq_dk_bytes: Some(vec![0x48; 64])` — 64 байта = новая длина seed-формата DK по M18 п.4 («64 → `from_seed`»); тест только сериализует и **не** вызывает `from_snapshot`, поэтому пройдёт — но перестанет быть «фейковым» и станет вводить в заблуждение. Заменить на настоящий снапшот из `RatchetSession::new` с PQ.
- `identity.rs:171` (`== 1952`), `handler.rs:999,1058,1376,1377,1556` (`== 1952`) — должны пройти (формат VK не меняется); это и есть текущие неявные снапшот-проверки — **их недостаточно** (совпадение длины ≠ совпадение байт).
- `rustcrypto.rs:195` — см. 5.4.
- `decode_kem_encaps_key` становится валидирующим → любые тесты, декодирующие фейковый EK, упали бы; grep показал: таких нет (fake EK только в `multidevice.rs` без декодирования) ✓.
- Feature `deterministic` ml-kem удалена — только Cargo.toml.
- `rust-version = "1.91"` — CI на `stable` пройдёт; локальный rustc 1.94.1 ✓.

### 5.6 Что сломает M19a (протокол v2) и M19 Phase A

| Изменение | Затронутые тесты |
|---|---|
| `Message::Encrypted(EncryptedEnvelope)` → `Message::Ratchet { header, envelope }`, header в AAD (M19a п.1) | `protocol.rs:232 test_chat_handler_receives_message`; `two_node_chat.rs:16,93`; `relay.rs` 9 unit + `make_envelope` (:458) + `relay_offline.rs:18,105` (RelayRequest::Deposit несёт `EncryptedEnvelope`); `fuzz_parse_message.rs`; `dpi_simulator.rs:71-76` эвристика «Aira = u32 BE len + тег < 16» — не зависит. |
| Транзакционный decrypt (п.2) | `ratchet.rs:672 max_skip_dos_protection` — при AAD-аутентификации заголовка падение произойдёт на AEAD, а не на MAX_SKIP → тест перестаёт проверять MAX_SKIP; переписать с подписанным/валидным заголовком и явной проверкой типа ошибки + «состояние не изменилось». |
| PQ-шаг (п.3), `RatchetSession::new` получает ek пира | `make_pair` (ratchet.rs:580-604) использует `new_classical` — не ломается; новые тесты по спеке. |
| PQXDH handshake, поля `HandshakeInit/Ack` (п.4) | `handshake.rs:367,400` (тампер `signature[0]` — останется валиден); `capability_negotiation_intersection` (:423) — версии 1..2 ∩ 1..1 = Ok(1); при политике `min_version = max_version = 2` **ожидание меняется** (v1-пир должен отклоняться). |
| `spam.rs` верификатор (п.5) | `pow_verify_works`, `contact_request_pow_roundtrip`, `contact_request_serialization` — переписать под `recipient ‖ server_nonce ‖ issued_at ‖ request`; 5 `rate_limiter_*` — под bounded LRU. |
| `Platform::Mobile` удаляется (M19, решение №4) | `handshake.rs:363`, `identity.rs:118`, `kem.rs:163,193`, `daemon/handler.rs:964` — тестовые seed'ы через Mobile-профиль (64 MB). Без замены каждый из ~10 тестов будет делать 256 MB Argon2. → `MasterSeed::from_raw([u8;32])` под `#[cfg(any(test, feature = "test-utils"))]` (в `seed.rs` рядом с `pub(crate) mod test_helpers`, :321) + использовать в fuzz (§3.2 п.2). |
| M19 Phase A п.2: `PendingEnvelope` вместо `&[u8]` | `pending.rs` 6 тестов; `handler.rs:1021,1382,1426` (enqueue-эффекты); `backup.rs` не затронут. |
| п.3: ключ dedup `BLAKE3(sender ‖ counter ‖ nonce)` | `dedup.rs` 4 — если сигнатура `is_duplicate(&Storage, &[u8;16])` сохранится, не ломаются. |
| п.1: `ContactInfo` + `endpoint_addr`, `relays`; schema_version | Литералы `ContactInfo { .. }` — 7 мест (`cli/app.rs`, `gui/state.rs`, `storage/contacts.rs`, `storage/types.rs`) + `contact_info_roundtrip`; нужна фикстура БД v1 (§7.3). |
| п.4: backup `VERSION = 2` | `backup.rs` 5 тестов пройдут; добавить фикстуру v1-файла до изменения. |
| M19b п.4: валидация длины pubkey (1952) | **54** литерала `vec![0x..; 32]` как pubkey в тестах daemon/ffi/gui/cli/bot (+ storage `b"pk-…-32-bytes"`) → хелпер `test_pubkey(tag: u8) -> Vec<u8>` (1952 байта) в общем `aira-core::test_utils`. |
| M21: `aira/1/relay` удаляется | `relay.rs` 9 + `relay_offline.rs` 3 — удалить/переписать в `crates/aira-relay/tests`. |

## 6. CI (`.github/workflows/ci.yml`)

| Джоб | Что делает | Замечания |
|---|---|---|
| `fmt` | `cargo fmt --all -- --check` | ✓ |
| `clippy` | `cargo clippy --workspace --all-targets -- -D warnings`, ubuntu, `dtolnay/rust-toolchain@stable` | `--all-targets` компилирует тесты ✓, но **без `--all-features`** → transport/fips-код не линтится. Красный с 30.07 (release-audit §1). |
| `test` | `cargo test --workspace`, ubuntu, stable | **Нет `--all-features`** (spec §17: `cargo test --all-features`) → 62 теста никогда не запускались (§0). Doc-тесты (≈17) выполняются в составе `cargo test` ✓. Нет `--locked` (Cargo.lock может молча обновиться). Только Linux: Windows named pipe (`main.rs:65-69`, `client.rs:196`), macOS keychain, `CREATE_NO_WINDOW` (gui/daemon_manager.rs) — без покрытия. Интеграционные тесты aira-net биндят UDP на раннере — работает (были зелёные). |
| `audit` | `cargo install cargo-audit cargo-deny` (каждый раз, без кэша) → `cargo audit`, `cargo deny check` | Красный (17 advisories). |
| — | MSRV | Нет джоба; `rust-version = "1.82"` (Cargo.toml:20) никогда не проверялась. После M18 → 1.91. |
| — | fuzz / coverage / nextest | Нет. |
| `release.yml`, `android.yml` | Сборка бинарей/APK | `cargo test` не вызывается нигде (grep пуст) — релизный тег может уйти без единого прогона тестов на целевой ОС. |

Рекомендуемый вид (M22/M23 п.1): матрица `ubuntu/windows/macos` × `stable`, шаги `cargo test --workspace --all-features
--locked` (на ubuntu — с `libgtk`, на всех — с `--exclude aira-gui` если egui не собирается headless), отдельный
`msrv` (`dtolnay/rust-toolchain@1.91` + `cargo check --workspace --all-targets`), `fuzz-build` (nightly, §3.3), `coverage`
(`cargo llvm-cov --workspace --all-features --lcov` → артефакт; порог — после M19), интеграционные M19/M21 в той же матрице.

## 7. Задачи по милстоунам

### 7.1 M18 — фикстуры и snapshot-тест (шаг 0 спеки, дополнения)

**Как снять векторы до миграции** (два равноценных способа; первый — без worktree):

- **Проверено:** `git log --oneline v0.3.5..HEAD -- crates/aira-core/` и `git diff --stat v0.3.5..HEAD -- crates/*/src` пусты —
  с тега v0.3.5 были только 6 docs-коммитов, исходники core/storage/net не менялись. Значит векторы, снятые в чистом worktree
  тега (`git worktree add ../aira-v035 v0.3.5`, как в спеке) и в worktree HEAD, идентичны; рабочая копия для этого не годится
  (незакоммиченный `ml-dsa rc.4` не собирается).
- Временный тест в worktree (`crates/aira-core/tests/dump_vectors.rs`, `#[ignore]`, `cargo test -p aira-core -- --ignored --nocapture`)
  печатает JSON и **удаляется после**.

**Что зафиксировать в `crates/aira-core/tests/vectors/v0_3_5.json`** (все — hex):

| Ключ | Вход | Значение (длина) |
|---|---|---|
| `identity_vk` | `identity_keygen(&[7u8;32])` → `encode_verifying_key` | 1952 B |
| `identity_sig` | `sign(sk, b"aira-snapshot-v1")` (детерминированная, ctx пустой) | 3309 B |
| `kem_ek`, `kem_dk` | `kem_keygen(&[7u8;32])` → encode | 1184 B, 2400 B (legacy expanded — после M18 читается по длине) |
| `kem_ct`, `kem_ss` | encaps **нельзя** зафиксировать (RNG) → фиксировать `decaps(dk_v035, ct_fixed) == ss_fixed`, где `ct_fixed` получен один раз на v0.3.5 | 1088 B, 32 B |
| `seed_desktop` | `MasterSeed::from_phrase("abandon"×23 + "art")` (Desktop!) → `derive("aira/identity/0")`, `derive("aira/storage/0")`, `derive("aira/mlkem/0")` | 3 × 32 B (первый тест с Desktop-профилем; ~2 с и 256 MB — пометить `#[ignore]` или feature `slow-tests`, но в CI запускать) |
| `pseudonym_vk_0` | `derive_pseudonym_seeds(0)` → VK | 1952 B |
| `contact_id` | `contact_id(identity_vk)` | 8 B |
| `hybrid_kdf` | `combine_secrets` на фиксированных `x25519_ss/mlkem_ss/cts` (kem.rs:85-105) | 32 B — фиксирует контекст `aira/hybrid-kem/v1` и BE-counter |
| `link_code` | `generate_link_code(seed_raw, 1_700_000_000)` | 6 цифр |
| `ratchet_snapshot_v035` | `postcard(to_snapshot())` сессии `new(..., pq_enabled = true)` после 3 сообщений | байты — для теста «снапшот v0.3.5 с 2400-байтным DK читается» (M18 п.6) |

Тест `crates/aira-core/tests/vectors.rs`: для каждого ключа `assert_eq!(hex(actual), fixture[key])`; расхождение `identity_vk`
= релиз-блокер по спеке. Дополнительно (спека п.7 в-е): `decode_kem_encaps_key` с коэффициентом ≥ q → `Err(InvalidKey)`;
`kem_decaps` с ct 1087/1089 → `Err`; proptest sign/verify (§4 — 16 кейсов); fuzz `decode_*` уже есть.

Прочее в M18: починить `fuzz/Cargo.toml` (§3.3 п.1) и добавить CI-джоб `cargo fuzz build`; исправить комментарий
`endpoint.rs:53`; `cargo test --workspace --all-features` в `ci.yml` (transport-тесты впервые побегут в CI — возможны
падения, это и нужно узнать до M19); `MasterSeed::from_raw` для тестов (§5.6) — заранее, чтобы M19 не тянул Argon2 в каждый тест.

### 7.2 M19a — векторы протокола v2 и тесты

1. Golden-байты v2: `crates/aira-core/tests/vectors/wire_v2/{message_ratchet,handshake_init,handshake_ack,group_control}.bin` —
   `to_allocvec(fixture) == include_bytes!` + roundtrip; любое изменение enum ломает тест намеренно.
2. Handshake-транскрипт как вектор: с `MasterSeed::from_raw` и **инъекцией RNG** (ephemeral X25519/ML-KEM из seeded ChaCha под
   `test-utils`) — иначе PQXDH-транскрипт не детерминирован. Тесты replay / identity misbinding / downgrade (`pq = false`) / prekey
   bundle подпись и `expires`.
3. Ratchet: proptest state machine (§4 п.4) с `pq_enabled = true`, тест «битый header/ciphertext не меняет `to_snapshot()`»,
   100+ сообщений в обе стороны через PQ-шаг + out-of-order через PQ-шаг + snapshot после PQ-шага (спека п.3).
4. Fuzz-таргеты §3.2 п.1-7, 14; `read_framed` на generic `AsyncRead` (п.10); CI 60 с/таргет.
5. `capability_negotiation_intersection` переписать под `min = max = 2`.

### 7.3 M19 — two-daemons и storage-фикстуры

1. **Предпосылка** (Phase B п.7-8 или §14.0 `aira-node`): `ipc.rs` → `aira_daemon::ipc` (lib) с `start_ipc_server(path, handler, event_rx)`
   и тестовым транспортом (`tokio::io::duplex` или реальный сокет во временном каталоге / уникальное имя пайпа на Windows).
2. `crates/aira-daemon/tests/two_daemons.rs` по спеке п.15 + п.16 (3 демона, группа). Seed'ы — `from_raw`. Сеть — `bind_for_test`
   (relay disabled) → проверяются доставка, snapshot после каждого сообщения, PENDING при офлайне, dedup. Сценарий «Bob офлайн → PENDING →
   онлайн → Delivered» без relay (relay — M21).
3. **Фикстуры до миграции схемы** (Phase A п.1, п.4): сейчас, на v0.3.5, сгенерировать `crates/aira-storage/tests/fixtures/aira-v1.redb`
   (1 контакт, 2 сообщения, 1 сессия с настоящим `RatchetSnapshot`, 1 группа, 2 псевдонима, `pseudonym_counter = 2`) и `backup-v1.aira.enc`
   с известным ключом `[0x42;32]`; тесты `open_v1_migrates_to_v2` и `import_v1_backup_restores_counter`. Без фикстур миграцию
   проверить нечем — **сделать до правок `ContactInfo`**.
4. `sessions.rs`: тест с настоящим `RatchetSnapshot` (сейчас `b"ratchet-snapshot"`), `pending.rs`: лимиты 1000/100 MB и `QueueFull`,
   `dedup.rs`: новый ключ, `messages.rs`: коллизия микросекунды.
5. `read_message` IPC unit-тест (`Cursor` с len > 1 MiB), `HandshakeHandler` unit-тест, `ConnectionManager::set_connected/disconnected`.
6. FFI-тесты: убрать двойной Argon2 (`test_runtime` через `from_raw`/env `AIRA_TEST_FAST_KDF`), держать `TempDir` в фикстуре.

### 7.4 M19b — клиентские тесты

- Снять `#[ignore]` с `keychain.rs:189,209,221` на Windows/macOS-раннерах (`cargo test -p aira-gui -- --ignored` в матрице).
- `test_pubkey()` хелпер 1952 байта и замена 54 литералов (§5.6) вместе с валидацией длины.
- Тест `validate_seed_phrase` (FFI, п.7) + fuzz §3.2 п.13.

### 7.5 M20 / M21 / M22 / M23

- **M20:** unit-тест `AiraPreset` (relay map = свой URL, `n0` fallback off, pkarr URL), тест парсинга `[network]` TOML + fuzz (§3.2 п.17);
  комментарий/док: тесты остаются на `Minimal`/relay-disabled.
- **M21:** тесты спеки п.8 в `crates/aira-relay/tests/`; fuzz `RelayRequest` v2 (§3.2 п.9) в `crates/aira-relay/fuzz`; proptest кодека;
  удалить `relay.rs` тесты v1 и `relay_offline.rs`; тест «Retrieve чужим `owner_key` → Err» — сейчас невозможен (auth нет).
- **M22:** `fuzz` (60 с/таргет) и `coverage` — блокирующие джобы; `ContactRequest` PoW negative-тесты (`difficulty < min` → reject).
- **M23:** матрица ОС + `--all-features --locked`, MSRV 1.91, интеграционные M19/M21 в матрице, порог покрытия для `aira-core`
  (после первого `llvm-cov` замера; ориентир — не ниже текущего).

## 8. Не проверено

- **Строчное/ветвевое покрытие** — `cargo llvm-cov` не установлен; цифр нет, только структурная оценка по grep.
- `cargo test --workspace -- --list` — не запускался (рабочая копия не собирается из-за незакоммиченного `ml-dsa rc.4`); имена
  тестов сняты awk'ом по атрибутам — возможны ±1-2 расхождения (макросы, `#[cfg]`-гейты внутри тестовых модулей).
- Компилируются ли и проходят ли 45 transport-тестов (`--features obfs4,mimicry,reality,tor,cdn`) и 17 крипто-тестов (`fips`,
  `compat-test`, aws-lc-rs требует cmake/nasm на Windows) — ни здесь, ни в фазе 1 не запускались.
- Что включает `presets::Minimal` в iroh 1.1 (relay/discovery) и полный список API-изменений iroh 0.97 → 1.1 в тестах — офлайн не
  проверялось (WebSearch/WebFetch не использовались).
- Поддержка cargo-fuzz на Windows напрямую (без WSL) и актуальная версия `libfuzzer-sys` — не проверялись.
- Реальная длительность/пиковая память FFI- и GUI-тестов (Argon2) — оценка по параметрам (256 MB / 128 MiB), не измерение.
- Симметричность `safety_number(a,b)` — по коду зависит от порядка (safety.rs:39-40), UI-ожидание не смотрел.
- Поведение `obfs.rs:270-275` при разрыве заголовка кадра — вывод по чтению кода и комментария автора, не воспроизведён тестом.
- Логи упавших CI-джобов (clippy 30.07) — GitHub не открывался.
- Внешние источники (docs.rs iroh 1.1 presets, crates.io версии libfuzzer-sys/cargo-fuzz) — не запрашивались; все выводы —
  по локальному коду и реестру `~/.cargo/registry` (iroh 0.97.0).
