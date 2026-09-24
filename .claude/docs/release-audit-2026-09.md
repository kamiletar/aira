# Аудит готовности Aira к релизу — сентябрь 2026

> Рабочий документ аудита; все 10 агентов отработали (2 — с ручным синтезом из спасённых транскриптов). Статус на конец сессии 2026-09-07 — `audit-2026-09/NEXT-SESSION.md`.
> Дата начала: 2026-09-07. HEAD: `971e038` (main). Workspace 0.3.5.
> Итоговая цель: планы для передачи Sonnet 5 (см. раздел «Планы» в конце и `spec/18-milestones.md`).
> Полные результаты агентов (факты с URL, полные рекомендации) — в `audit-2026-09/`: `facts-crates.md`,
> `relay-deploy-plan.md`, `pq-crypto-migration.md`, `pow-antiabuse.md`, `core-audit.md`, `clients-audit.md`, `daemon-storage-audit.md`, `spec-drift-audit.md`, `release-2026-requirements.md`, `wasm-browser.md`, `NEXT-SESSION.md`; сырой JSON — `audit-2026-09/raw/`.

## 0. Резюме на текущий момент

0. **Блокер №0 — демон не подключён к сети.** `crates/aira-daemon/src/main.rs` поднимает только IPC-сервер,
   TTL-GC и dedup-GC; `AiraEndpoint::bind`, `build_router`, `HandshakeHandler`, `ChatHandler`, ratchet-сессии
   **нигде не вызываются** ни в daemon, ни в aira-ffi (grep по `aira_net::` — только `blobs::BlobStore` и
   `TransportMode` парсинг). `DaemonRequest::SendMessage` (handler.rs:61-76) кладёт сообщение в локальную redb
   и отвечает `Ok` — по сети ничего не уходит. Очередь `pending_messages` заполняется (`enqueue` в handler.rs:316,
   470, 909 для group control / group fan-out / FileStart), но `pending::dequeue` **не вызывается нигде** в
   production-коде. Итог: v0.3.5 — это набор протестированных библиотек (aira-core 107 тестов, aira-net 42,
   интеграционные two_node_chat/relay_offline) и UI-оболочки, но **не работающий мессенджер**. Все остальные
   пункты плана зависят от «подключения» демона к aira-net.
1. **Блокер №1 — iroh 0.97 → 1.1.0.** n0 отключает публичные relay для клиентов iroh 0.9x
   **30 сентября 2026**. Клиенты v0.3.5 за NAT после этой даты перестанут соединяться.
   Миграция одновременно: (a) снимает RUSTSEC-2026-0185 (quinn-proto) и hickory-proto 0.25 без фикса,
   (b) разблокирует ml-dsa 0.1.1 (iroh-base 0.97 пинит `digest =0.11.0-rc.10`, ml-dsa 0.1.1 требует
   digest ^0.11 stable), (c) исправляет регрессию hole punching 0.96/0.97 (починена в 0.98).
2. **Незакоммиченный bump `ml-dsa = 0.1.0-rc.4` не компилируется** (sha3 rc.6 vs keccak). Правильная цель —
   `ml-dsa = "0.1.1"` + `ml-kem = "0.3.2"`, но только вместе с iroh 1.1 (см. §2).
3. **Offline через relay не реализован end-to-end.** `aira-net::relay` — in-memory сервер + клиент +
   один интеграционный тест; демон `RelayClient`/`RelayServer` не использует вообще. Локальная очередь
   `pending_messages` есть, доставляется только при живом соединении.
4. **Два разных «relay» в спеке смешаны**: iroh-relay (stateless, WebSocket+QAD, нужен всем за NAT) и
   Aira mailbox relay (store-and-forward, §6.3b/§6.5/§11B.5). На mail-сервере нужны оба, это два процесса.
5. CI на main красный с 2026-07-30 (clippy + cargo audit). Локально clippy зелёный (rustc 1.94.1),
   тесты 435/435, `cargo audit` — 17 уязвимостей.

## 1. Сборка, CI, тесты, аудит зависимостей (проверено локально, worktree HEAD)

| Проверка | Результат |
|---|---|
| `cargo clippy --workspace --all-targets -- -D warnings` | exit 0 (rustc 1.94.1 от 2026-03-25). В CI 30.07 упал — вероятно, новый stable toolchain с новыми lint'ами; нужно посмотреть лог CI |
| `cargo test --workspace` | **435 passed, 0 failed**, 14 бинарей (core 107, net 42, daemon 53, gui 37+3 ignored, cli 69, ffi 9, bot 11, multidevice 6, …) |
| `cargo audit` | **17 vulnerabilities, 12 warnings, exit 1** |
| `cargo deny check` | exit 1 (те же advisories + wildcard path-deps в aira-bot) |
| GitHub CI run 30501538193 (2026-07-30) | Clippy: fail, Security Audit: fail, Format/Test: ok |
| Releases | v0.3.4, v0.3.5 (оба 2026-04-10): MSI, DMG ×2, AppImage, tar.gz ×3, zip, APK + sha256 |

Уязвимости (`cargo audit`, HEAD):

- **quinn-proto 0.11.14 — RUSTSEC-2026-0185 (high 7.5)**, remote memory exhaustion → ≥0.11.15. iroh 1.x использует `noq` — уходит с апгрейдом iroh.
- **hickory-proto 0.25.2 — RUSTSEC-2026-0118 (unbounded loop, фикса в 0.25 НЕТ) и -0119 (O(n²))** → 0.26.1. iroh 1.1 тянет hickory-resolver 0.26 — уходит с апгрейдом.
- h2 0.4.13 RUSTSEC-2026-0258 → ≥0.4.16; crossbeam-epoch 0.9.18 RUSTSEC-2026-0204 → ≥0.9.20.
- rustls-webpki 0.103.10 — RUSTSEC-2026-0098/0099/0104 → ≥0.103.13.
- quick-xml в 4 версиях (0.30/0.37/0.38/0.39) — RUSTSEC-2026-0194/0195 (high) → ≥0.41 (скорее всего egui/winit-цепочка).
- webbrowser 1.2.0 RUSTSEC-2026-0257 → ≥1.2.2.
- warnings: ttf-parser unmaintained; anyhow / event-listener / lru / memmap2 / rand unsound; yanked: der 0.8.0, pkarr 5.0.4, spin 0.9.8/0.10.0.

## 2. Зависимости: версии и цепочка блокировок

Проверено через crates.io API 2026-09-07:

| crate | в Cargo.lock | latest stable | дата | заметка |
|---|---|---|---|---|
| iroh / iroh-relay / iroh-base | 0.97.0 | **1.1.0** | 2026-08-25 | 1.0.0 = 2026-06-15; rust-version **1.91**; QUIC = `noq`; getrandom 0.4, rand 0.10, ed25519-dalek 3 |
| iroh-blobs | 0.99.0 | 0.103.0 | 2026-06-15 | требует iroh ^1.0 |
| ml-dsa | 0.1.0-rc.5 (toml: rc.4, не закоммичен) | **0.1.1** | 2026-06-05 | rust 1.85; `SigningKey::from_seed(&Seed)` 32 байта, FIPS 204 Alg.6 |
| ml-kem | 0.2.3 | **0.3.2** | 2026-05-10 | фича `deterministic` удалена; Seed = 64 байта (d‖z) |
| sha3 / keccak | 0.11.0-rc.6 / 0.1.6+0.2.0 | 0.12.0 / 0.2.2 | | текущая поломка сборки |
| redb | 2.6.3 | 4.2.0 | 2026-08-17 | |
| redb-opfs | — | **нет на crates.io (404)** | GitHub wireapp/redb-opfs, последнее обновление 2025-09-25 | риск для M14.4 |
| argon2 / x25519-dalek / chacha20poly1305 | 0.5.3 / 2.0.1 / 0.10.1 | 0.6.0 / 3.0.0 / 0.11.0 | | новое поколение RustCrypto |
| egui/eframe | 0.29.1 | 0.36.1 | 2026-08-07 | |
| uniffi | 0.28.3 | 0.32.0 | 2026-06-30 | |
| aws-lc-rs | 1.16 | 1.18.1 | 2026-09-01 | |
| tauri | — | 2.11.5 | 2026-07-01 | |

Toolchain на машине: rustc 1.94.1. Workspace `rust-version = "1.82"` → для iroh 1.1 нужно **1.91**.

Эксперименты в worktree HEAD (только `cargo check`):

- **A. ml-dsa 0.1.1 при iroh 0.97 → не разрешается**: iroh-base 0.97 пинит `digest = "=0.11.0-rc.10"`, ml-dsa 0.1.1 → shake 0.1 → digest ^0.11. Вывод: Milestone 9.6 Phase A невозможен без миграции iroh.
- **B. ml-kem 0.3.2 → фича `deterministic` удалена** (есть alloc, default, getrandom, hazmat, pem, pkcs8, zeroize).
- **C. iroh 1.1 + iroh-blobs 0.103 + ml-dsa 0.1.1 + ml-kem 0.3.2 → зависимости разрешаются.** Компиляция: **15 ошибок, все в `crates/aira-core/src/crypto/rustcrypto.rs`** (+2 вывода типов в handshake.rs:82,195 как следствие):
  - `ml_dsa::KeyGen`, `MlDsa65::key_gen_internal(&seed)` → `SigningKey::<MlDsa65>::from_seed(&Seed)`
  - `key.sign_deterministic(msg, &[])` → `Signer::sign` / `try_sign`
  - `ml_kem::KemCore`, `MlKem768::generate_deterministic(&d, &z)` → 64-байтный `Seed` → `DecapsulationKey768`
  - `ml_kem::EncodedSizeUser`, `ml_kem::Encoded::<..>` → новая кодировка ключей
- **D. Только iroh 1.1 + iroh-blobs 0.103 → 3 ошибки в `crates/aira-net/src/endpoint.rs`** (`Endpoint::empty_builder` удалён; в 1.x `Endpoint::builder(preset)` с `presets::{Empty, Minimal, N0, N0DisableRelay}`). Ошибки в daemon/ffi/gui не показаны (сборка остановилась на aira-net), но aira-net — единственный прямой потребитель iroh.

Оценка: миграция iroh — 1–3 дня; миграция PQ-API — 1 файл, ~1 день. Делать одним PR.

### 2.1 PQ-крипто: что именно чинит bump и как мигрировать (исследование, raw `audit-2026-09/raw/a7f5c950e594124c7.json`)

**Три дефекта ml-dsa 0.0.4, с которыми выпущен v0.3.5** (все закрыты в ml-dsa 0.1.1 от 2026-06-05):

| Advisory | Суть | Affected / fixed |
|---|---|---|
| RUSTSEC-2025-0144 = CVE-2026-22705 | timing side-channel в `decompose` при **подписи** (деление на данных, производных от s2/t0); CVSS 6.4 | ≤0.1.0-rc.2 / ≥rc.3 (Barrett) |
| GHSA-5x2r-hc65-25f9 = CVE-2026-24850 | верификация принимает подписи с повторяющимися hint-индексами (`<=` вместо `<`) | ≥0.0.4 <rc.4 |
| GHSA-h37v-hp6w-2pp8 | `use_hint` при r0=0 прибавляет вместо вычитания → **валидная подпись может не пройти** | ≤rc.4 / 0.1.0 |

Ни один не меняет формат ключей/подписей: keygen = FIPS 204 Alg.6 (`key_gen_internal(seed)` → `SigningKey::from_seed`), подпись — детерминированная с пустым ctx (`sign_deterministic(msg, &[])` **сохранён** в 0.1.1). Aira не хранит PQ-ключи, а выводит их из seed при старте (identity.rs:32, handshake.rs:76-82), поэтому **миграция ключей пользователям не нужна**, но совпадение байт VK/EK на одном seed нужно закрепить snapshot-тестом (адрес пользователя = VK-байты; статически из CHANGELOG это не доказуемо).

**ml-kem 0.3.2:** `DecapsulationKey768::from_seed(d‖z)` внутри вызывает тот же `generate_deterministic(d,z)` (decapsulation_key.rs:51-53) → EK совпадёт с 0.2.3 при seed = d‖z; контексты `aira/kem-keygen-d`/`-z` (KEY_CONTEXTS.md:21-22) остаются. `TryKeyInit::new` теперь **валидирует EK** (FIPS 203 §7.2), чего в v0.3.5 не было — обновить тест «невалидный EK → ошибка». Удалены `Kem`/`KemCore`; `encapsulate()` без RNG при фиче `getrandom`; `decapsulate_slice(&[u8])` из kem 0.3.

**Единственный затронутый формат хранения** — ratchet-снапшот: ratchet.rs:442-444 пишет expanded DK (2400 байт) через `encode_kem_decaps_key`; в 0.3 читается только deprecated `ExpandedKeyEncoding::from_expanded_bytes`. Перевести снапшот на 64-байтный seed (`KeyExport::to_bytes`), читать оба формата по длине (64 / 2400).

**awslc.rs тоже ломается** (awslc.rs:124-141 использует `KemCore`/`generate_deterministic`; :12 `unstable::signature::PqdsaKeyPair`). aws-lc-rs 1.18 стабилизировал ML-DSA (`aws_lc_rs::signature::PqdsaKeyPair`, фича `unstable` не нужна), но перевёл `fips` на модуль AWS-LC-FIPS 4.0, который **ещё не сертифицирован** (сертифицированный 3.x — только в 1.17.x, где ML-DSA `unstable`). Заявлять «FIPS-validated ML-DSA» нельзя.

**Остальной RustCrypto не трогать:** x25519-dalek 2, chacha20poly1305 0.10, argon2 0.5, rand 0.8 остаются (не пересекаются типами с ml-dsa/ml-kem); в графе будут rand 0.8+0.10, rand_core 0.6+0.10, getrandom 0.2/0.3/0.4 одновременно — допустимо. MSRV → 1.91 (iroh). Версию workspace → 0.4.0 (breaking формат DK-снапшота + iroh 1.x).

**Целевой Cargo.toml (workspace):**

```toml
iroh       = { version = "1.1", default-features = false, features = ["metrics", "portmapper", "fast-apple-datapath", "tls-ring"] }
iroh-blobs = "0.103"
ml-dsa = { version = "0.1.1", features = ["zeroize"] }
ml-kem = { version = "0.3.2", features = ["zeroize", "getrandom"] }   # фича deterministic удалена
kem    = "0.3"
aws-lc-rs = { version = "1.18" }   # без features = ["unstable"]
```

**Порядок миграции (один PR):** шаг 0 — snapshot-векторы на теге v0.3.5 (`git worktree add ../aira-v035 v0.3.5`; seed=[7u8;32] → hex VK 1952 / подпись 3309 / EK 1184 / DK 2400 + `derive("aira/identity/0")` от фиксированной фразы → `crates/aira-core/tests/vectors/v0_3_5.json`); шаг 1 — iroh 1.1 в endpoint.rs; шаг 2 — rustcrypto.rs (сигнатуры трейта `CryptoProvider` в crypto/mod.rs:29-111 не меняются; `identity_keygen` → `SigningKey::from_seed` + `Keypair::verifying_key`; `kem_keygen` → `DecapsulationKey768::from_seed(d‖z)` + `dk.encapsulation_key()`; `kem_encaps` → `pk.encapsulate()`; `kem_decaps` → `decapsulate_slice`; `decode_kem_encaps_key` → `TryKeyInit::new` с `InvalidKey`; `decode_kem_decaps_key` — по длине 64/2400); шаг 3 — awslc.rs; шаг 4 — handshake.rs:82,195 (вывод типов), ratchet.rs:442-444/488-492 + тест чтения снапшота v0.3.5; шаг 5 — тесты (snapshot-совпадение VK/EK/подписи — при расхождении VK это релиз-блокер; `--features compat-test` 8 тестов; EK с коэффициентами ≥q → Err; CT 1087/1089 → Err; proptest sign/verify; fuzz на decode); шаг 6 — fmt/clippy/test/audit/deny, удалить RUSTSEC-2025-0144 из deny.toml:45 и .cargo/audit.toml:12.

**PQ-TLS на транспорте** (X25519MLKEM768 в QUIC iroh): фичи `iroh/tls-aws-lc-rs` + `rustls/prefer-post-quantum`; только провайдер aws-lc-rs (ring не умеет), нативная C/asm-сборка (cmake/nasm/NDK) в CI, **несовместимо с wasm (M14)**; identity транспорта остаётся Ed25519 (ограничение iroh). Рекомендация: cargo-фича `pq-tls` в aira-net, после релиза; PQ-гарантии Aira держатся на уровне протокола (PQXDH + PQ-ratchet).

**Стандарты на 09.2026:** SP 800-227 финал (09.2025), RFC 9881 (ML-DSA в X.509, 10.2025), FIPS 206 FN-DSA — draft, HQC/FIPS 207 к 2027; X-Wing (draft-connolly-…-10) и draft-ietf-tls-ecdhe-mlkem-05 — не RFC; комбайнер Aira ссылается на draft-ounsworth-cfrg-kem-combiners-05, **заброшенный с 2024-08** (kem.rs:6) — wire не менять, но в spec/02-crypto.md пометить формулу как Aira-специфичную; кандидат на v0.5 — X-Wing-подобная схема с EK в KDF.

**Signal SPQR vs Aira:** SPQR — «sparse по байтам» (ML-KEM Braid непрерывно, EK/CT режутся на 42-байтные чанки с Reed–Solomon erasure-кодом в каждом сообщении; формально верифицирован hax/F*+ProVerif; крейта на crates.io нет). Aira — «sparse во времени» (полный CT раз в `PQ_RATCHET_INTERVAL = 50`, ratchet.rs:30): окно без PQ-PCS до 50 сообщений, сообщения с pq_kem_ct на ~2.3 KB больше остальных (трафик-анализ / целевой дроп — вектор, на который прямо указывает Signal); спека §4.4 обещает шаг «при смене направления», код (`should_pq_step`, ratchet.rs:369-371) шагает только по счётчику — закрыть в M19a (direction-change trigger). Полный SPQR-chunking — v0.5.

**Side-channel-фон 2026:** за полгода advisories по ML-DSA у RustCrypto ×2, libcrux ×2, libgcrypt, wolfSSL ×2 (сводка Bernstein 2026-07-04) → `cargo audit` в CI как блокирующий job и быстрый цикл patch-релизов. `sign_deterministic` (rnd=0) уязвимее к fault-атакам, чем hedged; для desktop/mobile риск низкий, менять до релиза не нужно.

## 2.5 Криптопротокол (aira-core) — находки аудита кода

Полный отчёт агента: `audit-2026-09/raw/a1dd76fc4df1828ce.json`. Примитивы (seed, KEM-combiner, AEAD, zeroize, отсутствие unwrap/unsafe в prod-путях) — в порядке. Протокольный слой к релизу **не готов**:

| # | Severity | Находка | Evidence | Что делать |
|---|---|---|---|---|
| C1 | **blocker** | Wire-формат не несёт заголовок ratchet: `Message::Encrypted(EncryptedEnvelope{nonce,counter,ciphertext})` без `dh_public/prev_chain_len/pq_kem_ct/pq_kem_ek` из `MessageHeader` | `proto.rs:11-29` vs `ratchet.rs:40-52`; `RatchetSession` вне ratchet.rs используется только в `tests/multidevice.rs` | Ввести `Message::Ratchet { header, envelope }` (или расширить envelope), header в AAD, версия формата (§6.4), fuzz на `Message` |
| C2 | **blocker** | Заголовок не аутентифицирован (AEAD без AAD), состояние мутируется **до** проверки AEAD → один битый пакет необратимо десинхронизирует сессию; подмена `pq_kem_ek` подсовывает ключ атакующего | `ratchet.rs:75-80` (`aead_encrypt` без AAD), `:297-323` (skip/dh/pq-шаги до `aead_decrypt` :322, без отката) | Как в Signal DR: header = associated data; все изменения на клоне состояния, коммит после успешного decrypt; тест «битый header не меняет состояние» |
| C3 | high | PQ-шаг ratchet **никогда не стартует** (`should_pq_step` требует `peer_pq_ek`, который заполняется только из входящего заголовка, который шлётся только после PQ-шага) и при старте сломал бы сессию (`pq_kem_ct` обрабатывается только внутри `need_dh_ratchet`) → «Triple Ratchet» фактически Double Ratchet; все 9 тестов — `new_classical` | `ratchet.rs:330-332, 357-362, 305, 335-352, 297-306, 275-279, 241` | Передавать ML-KEM ek пира из handshake в `RatchetSession::new`; обрабатывать pq-поля независимо от DH-шага; тесты 100+ сообщений с `pq_enabled=true` в обе стороны + snapshot после PQ-шага |
| C4 | high | PQ-keypair'ы ratchet детерминированно из `root_key` (одинаковы у обоих пиров) → PQ-шаг не даёт post-compromise security | `ratchet.rs:216-218` (`aira/ratchet/pq-init`), `:345-346` (`aira/ratchet/pq-rekey`) | ML-KEM keypair из OS RNG (как X25519 в `:375-376`), root_key только для KDF-миксинга |
| C5 | high | Handshake — не PQXDH: статический ML-KEM из seed (`aira/mlkem/0`) → нет PQ forward secrecy при компрометации seed; одна eph-eph X25519; статический X25519 не используется | `handshake.rs:77-78, 190-191, 57, 177, 150-152, 226-230`; спека §4.5 обещает `Ephemeral_KEM_CT` | Ephemeral ML-KEM keypair на каждый handshake; identity_pk обоих + все публичные значения в `derive_session_keys`; для асинхронного старта через relay — signed PQ prekey bundle (связать с M21) |
| C6 | high | Подписи handshake не связывают пира и транскрипт → identity misbinding (UKS); `HandshakeInit` без nonce/timestamp → replay | `handshake.rs:105-118, 242-247, 297-311`; `proto.rs:156-162` | SIGMA-стиль: подпись ack над `init ‖ ack`, identity_pk обоих в KDF, nonce инициатора; тесты replay/подмены identity |
| C7 | high | `spam.rs`: верификатор берёт `difficulty` из самого запроса (0 проходит), PoW без получателя/времени (replay), `signature` не проверяется, модуль не подключён; `RateLimiter` без ограничения размера таблиц | `spam.rs:49-76` | См. §5.3: `min_difficulty` на приёмнике, PoW над `relay_nonce ‖ recipient ‖ from ‖ ts`, проверка ML-DSA подписи, bounded LRU |
| C8 | medium | Отправитель `Encrypted` в `ChatHandler` — iroh `EndpointId`, не ML-DSA identity; нет таблицы `contact_pubkey ↔ EndpointId`, проверяемой на handshake | `aira-net/src/protocol.rs:28, 85` | В M19: binding identity ↔ EndpointId при handshake, хранить в `contacts`, отбрасывать чужие EndpointId |
| C9 | medium | KDF-контекст `aira/device/id-from-code` не задокументирован в `docs/KEY_CONTEXTS.md`; device_id из 6-значного кода (10⁶ значений, коллизии) | `aira-daemon/src/handler.rs:200`; `device.rs:184` | Выводить device_id через `derive_device_id(seed, index)`, задокументировать |
| C10 | medium | Fingerprint 64 бит (8 байт BLAKE3, 16 hex) — мало для устной верификации против таргетированного подбора (Signal ~112 бит на сторону) | `identity.rs:91-100`; spec §5.2 п.3 | ≥128 бит в `/verify`; 8-байтный — только подсказка в invitation link |
| C11 | medium | Тесты: `proptest` объявлен, `proptest!` не используется; fuzz только `PlainPayload/EncryptedEnvelope/decode_keys`; не фаззятся `Message` (вкл. `HandshakeInit` с `Vec<u8>` без лимитов), `GroupControl`, `RatchetSnapshot`, `read_framed`; нет тестов downgrade/replay | `aira-core/fuzz/fuzz_targets/*`, `Cargo.toml:49` | Fuzz на `Message`/`GroupControl`/`RatchetSnapshot`/framing; proptest roundtrip padding/ratchet; тесты downgrade и replay |
| C12 | low | Расхождения со спекой: combiner-контекст `aira/hybrid-kem/v1` (код) vs `aira/hybrid-kem/1` (спека), counter BE (код) vs LE (спека); §4.5.1 chunked handshake ≤1200 B не реализован и избыточен для QUIC-стримов | `kem.rs:23, 92`; spec/02-crypto.md:37,43,166-205 | Привести спеку к коду; §4.5.1 переписать (QUIC-стримы + relay fallback) |
| C13 | low | Случайные 96-битные nonce под одним storage-ключом (birthday 2³²) | `aira-storage/src/encrypted.rs:32-33`, `sync.rs:144-146` | XChaCha20-Poly1305 или per-record ключ |
| C14 | low | `verify_link_code` через `String ==` без rate-limit; `Drop` для `RatchetSession` не затирает `pq_mlkem_dk`/`send_dh_secret` явно | `device.rs:209-245`; `ratchet.rs:563-573` | `subtle::ConstantTimeEq`, лимит попыток; проверить features `zeroize` у ml-kem/x25519 при миграции |
| C15 | medium | Миграция PQ-API затрагивает и `crypto/awslc.rs:129-134` (`generate_deterministic` для FIPS-провайдера), не только `rustcrypto.rs` | `awslc.rs:129-134` | Учесть в M18 |

Покрытие тестами aira-core: 130 `#[test]` (18 за feature `compat-test`), 0 proptest, 2 fuzz-таргета. Handshake — 4 теста, ratchet с PQ — 0.

Вывод для плана: **M19 (демон в сети) невозможен без предварительного «M19a — протокол v2»**: C1–C6 (wire header + AAD + рабочий PQ-шаг + свежие PQ-ключи + ephemeral KEM в handshake + SIGMA-binding + anti-replay). Это ~2 недели работы в aira-core с полным набором тестов и fuzz, и делать её нужно **до** wiring'а, иначе wire-формат придётся ломать дважды.

## 3. Сеть и relay

### 3.1 Что есть в коде

- `crates/aira-net/src/endpoint.rs:80` — production endpoint строится с `presets::N0` → публичные relay и DNS n0. Своего RelayMap/discovery нет, конфига relay в демоне нет.
- `crates/aira-net/src/relay.rs` (669 строк) — **Aira mailbox relay**: `RelayServer` (ProtocolHandler на ALPN `aira/1/relay`) + `RelayClient`. Протокол `Deposit/Retrieve/Ack/DeleteMailbox`. Факты:
  - хранилище — `HashMap` в памяти, персистентности нет (рестарт = потеря всех писем);
  - `mailbox_id = blake3::derive_key("aira/relay/mailbox/v1", shared_secret)` — **одна коробка на пару на оба направления** (Alice при retrieve получит и свои депозиты);
  - **retrieve/ack/delete без аутентификации** — знание id = bearer; deposit без PoW/квот отправителя/rate limit;
  - GC по `last_activity` коробки, а не по TTL конверта (`received_at` помечен `dead_code`);
  - лимиты: 100 конвертов / 10 MB / 64 KB на конверт / TTL 7 дней.
- `crates/aira-daemon` — `RelayClient`/`RelayServer` **не используются** (grep пуст). Бинарника relay нет; `main.rs` принимает только `AIRA_SEED` из env.
- `crates/aira-net/src/ratelimit.rs` (84 строки) — минимальный лимитер.
- Тесты: `tests/relay_offline.rs` (deposit → retrieve → ack), `tests/two_node_chat.rs`, `tests/dpi_simulator.rs`.

### 3.2 iroh-relay 1.1 — факты из исследования (источники: docs.iroh.computer, iroh.computer/blog, исходники v1.1.0)

- Публичные relay n0: «development and hobby use only», rate-limited, без SLA, видят метаданные (IP, время, объёмы), «не рекомендуются для sensitive data». Поддержка клиентов **v0.9x заканчивается 30.09.2026**.
- iroh-relay **stateless**: не хранит данные приложения, только форвардит. Store-and-forward — это отдельный сервис Aira.
- Транспорт до relay с 0.91 — только **WebSocket `/relay`**; STUN (3478) в 1.x **нет**, его заменил **QAD (QUIC Address Discovery) на UDP 7842**, который требует `[tls]` у relay. Без QAD клиенты за NAT не узнают публичный адрес → почти весь трафик пойдёт через relay.
- Порты по умолчанию: HTTP 80, HTTPS 443, QAD UDP 7842, metrics 9090. Docker README с `3478/udp` устарел.
- Handshake клиента: быстрый путь через TLS keying-material exporter (0-RTT) + fallback ServerChallenge/ClientAuth (используется в браузере и за TLS-терминирующим прокси).
- Access control: `access = "everyone"` | `allowlist`/`denylist` по EndpointId | `shared_token` (Bearer / `?token=` в браузере, без отзыва) | `access.http.url` (callout с `X-Iroh-Endpoint-Id` → `true`). Лимиты: `[limits] accept_conn_limit/burst`, `client.rx.bytes_per_second/max_burst_bytes`, live `set_client_rate_limit`.
- Безопасная версия relay — **≥1.0.2** (до неё panic от короткого кадра ронял сервер). n0 советует version-lock и второй relay в другом регионе (fail-over автоматический по RelayMap).
- Discovery на своём домене: `presets::Minimal` + `PkarrPublisher::builder(url)` + `PkarrResolver::builder(url)` (HTTPS `/pkarr`, без NS-делегирования) + опционально `DnsAddressLookup` + iroh-dns-server 1.1 (порт 53).
- Браузер: `iroh = { version = "1", default-features = false }`, только relay по `wss://host/relay`, токен только `?token=`.
- Статистика n0: ~9 из 10 сетевых конфигураций дают прямое соединение, ~95 % байт напрямую.
- Клиентский API 1.1: `Endpoint::builder(preset).relay_mode(RelayMode::Custom(RelayMap::from_iter([url])))`, `RelayConfig::new(url, Some(RelayQuicConfig::new(7842)))`, `.with_auth_token`, `Endpoint::insert_relay/remove_relay`, `clear_relay_transports`.

### 3.3 План деплоя iroh-relay на mail-сервере (кратко; полная версия в `scratchpad/results/*.json` → перенести в spec)

1. DNS: `relay.<domain>` → IP mail-сервера. Firewall: tcp/443 (уже открыт), **udp/7842** (QAD). Не открывать 9090.
2. Бинарник `iroh-relay` v1.1.0 (GitHub releases без checksum → собрать из тега `cargo build --profile optimized-release -p iroh-relay --features server` или docker `n0computer/iroh-relay:v1.1.0` по digest). Пользователь `iroh-relay`, `/etc/iroh-relay/config.toml`, `/var/lib/iroh-relay/certs`.
3. **Вариант A (рекомендуемый):** nginx `stream { ssl_preread }` — SNI `relay.<domain>` → `127.0.0.1:8443` (TLS насквозь, relay сам берёт Let's Encrypt через TLS-ALPN-01, работает быстрый exporter-handshake); прежние HTTPS-vhost'ы webmail переезжают на `127.0.0.1:8444` (+ `proxy_protocol` для real IP).
   `config.toml`: `http_bind_addr="127.0.0.1:3340"`, `enable_quic_addr_discovery=true`, `[tls] https_bind_addr="127.0.0.1:8443" quic_bind_addr="[::]:7842" hostname="relay.<domain>" cert_mode="LetsEncrypt" cert_dir=... contact=...`, `[limits] accept_conn_limit=50.0 accept_conn_burst=200 [limits.client.rx] bytes_per_second=2000000 max_burst_bytes=8000000`, `metrics_bind_addr="127.0.0.1:9090"`.
   **Вариант B:** TLS терминирует nginx (`proxy_pass https://127.0.0.1:8443`, `Upgrade`/`Connection`, проброс `Sec-WebSocket-Protocol`, таймауты 1h), relay с `cert_mode="Manual"` на certbot-сертификате + deploy-hook restart. Клиенты идут по challenge-fallback (+1 RTT).
4. systemd unit (User=iroh-relay, Restart=always, LimitNOFILE=131072, ProtectSystem=strict, ReadWritePaths=/var/lib/iroh-relay). Проверка `curl --fail https://relay.<domain>/healthz`.
5. iroh-dns-server 1.1 для pkarr (`[https] port=8445 domains=["dns.<domain>"]`, `[mainline] enabled=false`, `pkarr_put_rate_limit="smart"`); DNS-порт 53 и NS-делегирование — позже.
6. Клиент: `crates/aira-net/src/preset.rs` — `AiraPreset` (копия N0: `relay_mode(Custom(RelayMap))`, `PkarrPublisher`/`PkarrResolver` на своём домене, `DnsAddressLookup` вне wasm), конфиг демона `[network] relays = [...] pkarr_relay = "..."`, **n0-fallback выключен по умолчанию**.
7. Эксплуатация: второй relay на VPS до релиза; Prometheus локально; обновлять relay в течение суток после релиза iroh; позже `access.http.url` → сервис Aira с PoW-гейтом.

Открытые вопросы для владельца: какой веб-сервер/ОС на mail-сервере и кто держит 80/443; доступен ли UDP 7842 у хостера; ожидаемое число клиентов (sizing `[limits]`); публиковать ли прямые IP в pkarr (`AddrFilter::unfiltered()` ускоряет прямые соединения, но раскрывает IP всем, кто знает EndpointId).

## 4. Offline-доставка

### 4.1 Текущее состояние (проверено по коду)

- **Сетевого пути нет вообще** (см. §0, блокер №0): демон не поднимает endpoint, `SendMessage` пишет в redb и всё. Пользователю показывается «отправлено», но сообщение никуда не уходит — ни онлайн, ни офлайн.
- Локальная очередь `pending_messages`: API `enqueue/peek/dequeue/count/clear` (`crates/aira-storage/src/pending.rs`). В демоне только `enqueue` (handler.rs:316 group control, :470 group fan-out, :909 FileStart); `dequeue` в production-коде **не вызывается**. Полезная нагрузка кладётся как **plaintext postcard** (комментарий handler.rs:299-301: «network layer will encrypt … when delivering»), ratchet не применяется, причём таблица PENDING **исключена из storage-шифрования** (lib.rs:123-124, pending.rs:3-4 — «там уже ratchet-encrypted envelope», что неправда): открытый текст групповых сообщений и групповые sender keys (handler.rs:430, 602-606) лежат на диске в открытом виде. Лимиты 1000 msg / 100 MB из spec §6.3a не реализованы, TTL нет, `count`/`enqueue` — O(n). 1:1-текст в очередь не попадает вообще.
- Relay-путь (spec §6.3b): `aira-net::relay` — библиотека + тест; в демоне не используется; сервер in-memory, без auth/квот отправителя/персистентности, одна коробка на пару (§3.1).
- Ratchet готов к out-of-order: `MAX_SKIP = 1000`, skipped keys (`crates/aira-core/src/ratchet.rs:27, 145, 329-330`).
- Android: `mobile/android/app/src/main/AndroidManifest.xml:40` — `foregroundServiceType="dataSync"`, `targetSdk = 35`. На Android 15+ **dataSync ограничен 6 часами в сутки** (`Service.onTimeout`), т.е. постоянный P2P-демон на телефоне невозможен без relay-очереди и wake-up.

### 4.1a Демон и хранилище: что есть и куда подключать сеть (аудит кода, raw `audit-2026-09/raw/a24dfaf96a2e63a16.json`)

**Ответ на вопрос «что с сообщением, если получатель офлайн 3 дня»:** ничего — и не 3 дня, а никогда. `SendMessage` (handler.rs:61-76) пишет `StoredMessage{sender_is_self:true, expires_at:None}` в `messages` и отвечает `Ok`. Ни `pending::enqueue`, ни ratchet, ни `sessions::save` (единственные вызовы — backup.rs:182,205), ни `dedup::is_duplicate` (нигде, кроме своих тестов) в этом пути нет. Клиент видит «отправлено», получатель не получит ничего ни сейчас, ни после возврата в сеть.

**Что работает и покрыто тестами (переиспользовать):**

| Компонент | Состояние | Evidence |
|---|---|---|
| IPC: Unix socket `~/.aira/daemon.sock` / named pipe `\\.\pipe\aira-daemon`, кадр u32 LE + postcard, лимит 1 MiB, мультиплекс Response/Event | production | main.rs:44-69, ipc.rs:15-43,117-160,212-255, client.rs:83,149 |
| `DaemonRequest` (29 вариантов: сообщения, контакты, TTL, backup, файлы, transport mode, группы, псевдонимы, устройства) и `DaemonEvent` (13 вариантов) | production, но **без сетевых запросов/событий** | types.rs:12-172, 176-222, 299-389 |
| Storage: redb, ChaCha20-Poly1305 на значения, ключ `aira/storage/0` (`Zeroizing`) | works | lib.rs:125-128, encrypted.rs:29-44, KEY_CONTEXTS.md:15 |
| `sessions.rs` save/load/remove/list_contacts `RatchetSnapshot` (zeroize при Drop) | works, **не используется демоном** | sessions.rs:20,44,62,77; ratchet.rs:126-160,440,484 |
| `pending.rs` enqueue/peek/dequeue/count/clear, FIFO per contact | works-but-rough (см. §4.1) | pending.rs:21-173 |
| `dedup.rs` окно 24 ч + GC каждый час | works, **ключ дедупа не из чего взять**: у `EncryptedEnvelope{nonce,counter,ciphertext}` нет message_id, `StoredMessage.id` генерирует получатель | dedup.rs:18-88, proto.rs:23-30, handler.rs:639 |
| `backup.rs` v1: contacts, settings, ratchet_states, messages | works; **не включает** groups, devices, pseudonyms + counter → после restore counter = 0 (повтор псевдонимов, §12.6) | backup.rs:27-36,160-191, pseudonyms.rs:26 |
| Группы: CreateGroup/Send/Add/Remove/Leave/AcceptInvite + входящие GroupControl | логика есть, fan-out — plaintext в PENDING «в никуда»; SenderKey-шифрование делегировано несуществующему «network layer» (handler.rs:462-463) | handler.rs:300-609, 680+ |
| Файлы: `SendFile` → BLAKE3 всего файла `std::fs::read` (до 4 GiB, синхронно в handler) → in-memory BlobStore → `FileComplete` **без пира** | stub | handler.rs:863-949, protocol.rs:185-192 (ALPN FILE не обслуживается) |
| Мультидевайс: link code, `DeviceInfo.node_id = vec![]` навсегда, sync_log никто не пишет | stub | handler.rs:190-253 |
| Периодика: TTL-GC каждые 30 с (полный decrypt всех сообщений), dedup-GC; FFI runtime повторяет то же | works-but-rough | main.rs:163-190, messages.rs:146-169, runtime.rs:101-117 |
| unwrap/expect/panic/unsafe в production-путях daemon/storage | **0** (`#![deny(unsafe_code)]`) | awk-скан |
| Тесты: daemon 53 unit (29 — postcard roundtrip), storage 84 unit; интеграционных через реальный сокет/два демона — **нет** | — | нет `crates/aira-daemon/tests` |

**Карта подключения сети (для M19, файлы и функции):**

1. `main.rs:100-160` после `Storage::open`: `AiraEndpoint::bind(Some(secret_key))` (endpoint.rs:45) — `secret_key` из seed по **новому KDF-контексту** (в KEY_CONTEXTS.md его нет; решить: детерминированный из seed = стабильный EndpointId, или случайный per-device в settings — лучше для §12.6, но адрес надо публиковать контактам); затем `protocol::build_router(&ep, ChatHandler, HandshakeHandler, Arc<RelayServer>, Some(&blob_store))` (protocol.rs:178-195) → `Receiver<IncomingMessage>` (protocol.rs:26-31), `Receiver<IncomingHandshake>` (:102-109).
2. Новый `aira-daemon/src/net_task.rs`: `SessionManager{HashMap<pubkey, RatchetSession>}` — при старте `sessions::list_contacts` → `load` → `RatchetSession::from_snapshot`; после **каждого** send/recv `to_snapshot` → `sessions::save` **до** отправки в сеть (crash между send и save = повтор chain key).
3. `handler.rs:29-36` `handle_request` — синхронный `Fn(DaemonRequest)->DaemonResponse` (ipc.rs:62), вызывается прямо в tokio-таске (ipc.rs:144,239): сделать async или передать `mpsc::Sender<NetCommand>`; `SendMessage` → ratchet-encrypt → `pending::enqueue(cid, postcard(EncryptedEnvelope))` → `net_tx.send(Deliver{cid})`; то же для `enqueue_group_control` (300-320), `handle_send_group_message` (441-477), `handle_send_file` (863-949).
4. Таск `pending_drain`: `pending::peek` → `ep.connect(addr, alpn::CHAT)` (endpoint.rs:115) → `connection::write_framed` (connection.rs:27) → ack → `pending::dequeue`; триггеры: старт, входящее соединение, backoff-таймер; fallback — `RelayClient::deposit` (relay.rs:353,383) / в M21 — aira-relay v2.
5. Входящие: `IncomingMessage{from, message}` → `is_duplicate` по ключу `BLAKE3(sender ‖ counter ‖ nonce)[..16]` → ratchet decrypt (ratchet.rs:323 проверяет MAX_ENVELOPE_SIZE) → существующий `handle_incoming_payload` (handler.rs:621-674, уже эмитит `MessageReceived`); `ContactOnline/Offline` (объявлены, никогда не эмитятся) — из `ConnectionManager::set_connected/set_disconnected` (connection.rs:155-172).
6. Storage: `ContactInfo{pubkey, alias, added_at, verified, blocked}` (types.rs:13-24) **не содержит EndpointAddr** — демон не знает, куда звонить; `AddContact{pubkey, alias}` (types.rs:28-33) отбрасывает `endpoint_addr_bytes` из `InvitationLink`. Нужны поле `endpoint_addr`/`relays` в ContactInfo (**миграция схемы — версии схемы БД нет вообще**, любое изменение postcard-структур ломает существующие aira.redb), ключи settings `relay/url` (конвенция уже есть: settings.rs:3, `transport/mode` handler.rs:19), `DaemonRequest::{SetRelay, GetNetStatus}`, `DaemonEvent::{DeliveryState{id, Sent|Queued|Relayed|Delivered}, NetStatus}`.
7. Открытый вопрос дизайна: сессия хранится по pubkey контакта (sessions.rs:4), а `GetMyAddress` выдаёт новый псевдоним на каждый вызов (handler.rs:77-95) — по какому ключу получатель находит сессию входящего? Нужна таблица pseudonym→contact или pseudonym в `IncomingMessage`.

**Находки по демону/хранилищу (кроме блокера №0):**

- [high] PENDING без шифрования и с plaintext (см. §4.1) — зафиксировать инвариант «в PENDING только `EncryptedEnvelope`» типом-обёрткой; до того шифровать storage-ключом.
- [high] Очередь без лимитов/TTL/порядка по ratchet counter (spec §6.3a: 1000/100 MB) — заголовок `{enqueued_at, size}`, `QueueFull`, per-contact seq без скана, GC 7 дней.
- [high] IPC без аутентификации и прав: Unix socket без `0600`/`SO_PEERCRED`, Windows pipe с глобальным именем, `first_pipe_instance(false)`, без security descriptor — любой локальный процесс может `Shutdown`, `ExportBackup{path}` (расшифрованные ratchet snapshots) и `ImportBackup`. Фикс: chmod 0700/0600, peer uid; имя пайпа с SID, `first_pipe_instance(true)`, SD «только текущий пользователь», токен `<data_dir>/ipc.token`.
- [medium] Синхронный handler в async-таске + `std::fs::read` до 4 GiB → подвешивает все IPC (spec §8.1 требует spawn_blocking); хэшировать потоково.
- [medium] Форвардер событий выходит из цикла при `RecvError::Lagged` (ipc.rs:129,224; ёмкость 256) — после всплеска событий клиент молча перестаёт их получать; обрабатывать Lagged, ёмкость 4096.
- [medium] Backup v1 без groups/devices/pseudonyms/counter → VERSION=2.
- [medium] Нет версии схемы БД → таблица `meta{schema_version}` + цепочка миграций до первого релиза.
- [low] Storage-шифрование без AAD (ciphertext переставляем между строками при доступе на запись) → `aad = table ‖ row_key`; ключ messages `(contact_id, timestamp_micros)` — коллизия в микросекунду затирает сообщение; TTL-GC каждые 30 с расшифровывает всё — вторичная таблица expiry.
- [low] Отправитель файла получает `FileComplete` без передачи; BlobStore in-memory — `complete` только по `FileAck`, FsStore.

### 4.2 Что делают другие (факты из исследования)

- **SimpleX SMP** (spec v21, 2026-07-05): однонаправленные очереди; создаёт **получатель** (`NEW recipientAuthPublicKey recipientDhPublicKey …`, опциональный basic-auth пароль сервера для создания очередей); отправитель получает отдельный sender-id и подписывает свои команды своим ключом; сервер шифрует доставляемые тела DH-ключом получателя (сервер не может связать sender-id и recipient-id по содержимому); квота ~128 сообщений на очередь (`QUOTA`), TTL недоставленных — дни (настройка сервера, по умолчанию ~21 день); «router security requirements»: не хранить логи, не делать снапшоты, in-memory рекомендуется.
- **Session/Oxen**: swarm из service nodes по pubkey получателя, envelope с TTL и nonce PoW (в ранних версиях), 3 копии, TTL ~14 дней.
- **Briar Mailbox**: REST через Tor, Bearer-токен владельца, отдельные токены контактам; синхронизация только когда обе стороны онлайн — основная жалоба пользователей Briar.
- **Tox**: только «pseudo-offline» (сообщение ждёт, пока оба онлайн) — главная UX-проблема Tox.
- **Signal sealed sender**: сервер знает получателя, не знает отправителя (sender certificate + delivery token); NDSS'21 «Improving Signal's Sealed Sender» — деанонимизация по delivery receipts.
- **Delta Chat / chatmail** (2026): почта как транспорт, Postfix+Dovecot+chatmaild, push через токен, «outer envelope» с рандомизированной датой; для Aira — не транспорт, а образец эксплуатации relay на mail-сервере (acmetool, filtermail, expire).
- **Android FGS**: `dataSync`/`mediaProcessing` — 6 ч/сутки (Android 15+); `remoteMessaging` — «перенос сообщений между устройствами», не для постоянного соединения; для мессенджеров рабочий путь — короткая FGS по push (UnifiedPush AND_3.1.0 spec, ntfy) → retrieve → стоп.

### 4.3 Дизайн «Aira mailbox relay v2» (для Sonnet 5)

**Роли.** Два процесса на mail-сервере: `iroh-relay` (stateless, §3) и `aira-relay` — новый бинарник (крейт `crates/aira-relay`), обычный iroh-endpoint с ALPN `aira/2/relay`, сам ходит через iroh-relay/QAD (доп. портов не нужно; для прямых соединений можно открыть фиксированный UDP-порт). Хранилище — redb (таблицы `mailboxes`, `envelopes(mailbox_id, seq)`, `stats`), не in-memory.

**Модель коробок — по направлению, SimpleX-style, но ключи из shared secret PQXDH:**
- `mailbox_id[A→B] = derive_key("aira/relay/mailbox/v2/" ‖ dir, shared_secret)` — **две коробки на пару** (dir = lexicographic order pubkeys). Убирает проблему «Alice получает свои же депозиты».
- `owner_key[dir]`, `sender_key[dir]` — Ed25519-пары, детерминированно из shared secret (`aira/relay/owner/v2/dir`, `aira/relay/sender/v2/dir`; занести в `docs/KEY_CONTEXTS.md`). Обе стороны могут их вывести, но relay получает только публичные.
- `Register { mailbox_id, owner_pk, sender_pk, notification_endpoint: Option<NotificationEndpoint>, ttl_hint }` — подписан owner_sk; коробка живёт, пока владелец обновляет регистрацию (раз в 7 дней).
- `Deposit { mailbox_id, envelope }` — подписан sender_sk + `relay_nonce` (challenge из `RelayHello`, защита от replay). Незарегистрированная коробка → `MailboxNotFound` (не создавать «по факту депозита» — иначе флуд).
- `Retrieve { mailbox_id, after_seq }` / `Ack { mailbox_id, up_to_seq }` / `Delete` — подписаны owner_sk + relay_nonce. Relay присваивает `seq` при приёме; ack по seq, а не по ratchet-counter.
- Первый контакт (нет shared secret): **intro-mailbox** по `pseudonym_pubkey` получателя (`aira/relay/intro/v2`), депозит только `ContactRequest` с **PoW ≥ 20 бит** над `relay_nonce ‖ request` (spam.rs уже умеет) + rate limit по EndpointId. Это единственное место, где нужен PoW на relay.
- Квоты (spec §11B.5): 100 конвертов / 10 MB на коробку, 64 KB конверт, TTL 7 дней **на конверт** (`received_at`), общий cap 1 GB, GC каждый час, приоритет вытеснения — коробки без retrieve дольше всего. Лимиты `Register`/день на EndpointId.
- Push: `NotificationEndpoint::UnifiedPush{url}` — relay шлёт пустой wake-up (без содержимого и без mailbox_id; клиент сам делает retrieve по всем своим коробкам). FCM — позже.
- Версионирование (spec §11B.5.1): `RelayHello { protocol_version: 2, supported: [2], capabilities: STORE_FORWARD|PUSH_NOTIFY }`; старый ALPN `aira/1/relay` удалить (в проде его никто не использует).
- Метаданные: relay видит EndpointId клиента и набор коробок, которые он трогает. v2.1: отдельный iroh-endpoint со случайным ключом на сессию для relay-операций (дёшево, см. iroh `Endpoint::bind` со случайным SecretKey) — тогда связать коробки одного пользователя нельзя.
- Multi-relay: `MailboxConfig.relays: Vec<RelayUrl/EndpointId>` в контакт-записи, отправитель пробует по порядку; миграция — подписанное `RelayMigration` (spec §11B.5.1).

**Демон (после блокера №0):**
1. `net_task`: endpoint (`AiraPreset`, §3.3) + router (chat/handshake/file/relay-client) + `SessionManager` (ratchet per contact, из aira-core).
2. `SendMessage`: шифруем ratchet'ом → пробуем прямую доставку (connect с таймаутом 5 с) → при неудаче `pending::enqueue` **уже зашифрованного** `EncryptedEnvelope` (не plaintext) → `relay_client.deposit` во все relay контакта → `DeliveryState::{Sent, Queued, Relayed, Delivered}` в IPC-событии.
3. `pending_drain`: при старте, при `peer_online` (успешный connect / входящее соединение), по таймеру с backoff [5 с, 30 с, 2 мин, 10 мин, 1 ч]; `dequeue` только после ack.
4. `relay_poll`: retrieve при старте, каждые N мин, по push, по «пробуждению» (ffi: onResume/UnifiedPush) → decrypt (ratchet skipped keys) → dedup (`dedup.rs`) → store → ack.
5. Groups: group control через ту же очередь, но уже как `EncryptedEnvelope` на каждого участника.
6. Тесты: интеграционный «Bob офлайн 3 дня → Alice шлёт 3 сообщения → Bob возвращается → порядок и dedup», «relay перезапущен — письма на месте (redb)», «чужой EndpointId не может retrieve», «deposit без регистрации отклонён», proptest на кодек `RelayRequest`, fuzz на парсер.

## 5. PoW / anti-abuse

### 5.1 Текущее состояние (проверено по коду)

- `crates/aira-core/src/spam.rs` (313 строк): `POW_DIFFICULTY_BITS = 20` (BLAKE3, `solve_pow/verify_pow`), `ContactRequest` с `pow_nonce`, `RateLimiter` (10/мин всего, 3/час на ключ, бан 1 ч). **Не используется нигде** вне aira-core (grep по daemon/net/cli/gui/ffi пуст); `aira-net/src/ratelimit.rs` — governor по tier'ам, тоже без потребителей в демоне.
- Seed → identity: Argon2id **m=256 MB, t=3, p=4**, соль `aira-master-v1-m256` (`seed.rs:29-33`); профиль Mobile (64 MB) только для тестов. Это уже секунды CPU на создание identity, но **не публично проверяемо** (нет proof).
- Спека: §11B.2 adaptive puzzles 16–28 бит перед handshake, §11B.4 PoW 16 бит на DHT publish, §11B.5 PoW 16 бит на relay deposit от не-контактов, §13.2 PoW 20 бит на ContactRequest. Про PoW при **создании identity** в спеке ничего нет.
- Ключевое ограничение для идеи «PoW при создании ключа»: identity детерминистически выводится из seed-фразы; любой key-grinding должен быть детерминированным перебором counter от seed, иначе ломается восстановление из фразы.

### 5.2 Прецеденты (факты из исследования)

- **Tor onion services (0.4.8, 2023)** — PoW-защита от DoS: Equi-X (Equihash<60,3> поверх HashX; быстрая проверка, минимальная асимметрия CPU/GPU), **динамическая сложность**: в покое 0, под атакой растёт; 5–30 мс на решение в норме, до ~1 мин под атакой; сервис приоритизирует соединения по effort. Ключевое: PoW **на действие (connect)** и **адаптивный**, а не на создание ключа.
- **Nostr NIP-13** — PoW как ведущие нулевые биты в id события (и опционально «mining» pubkey); статус draft/optional; на практике спам в Nostr решается web-of-trust, paid relays и NIP-42 auth, а не PoW.
- **Bitmessage** — PoW на каждое сообщение, вес растёт с размером и TTL (`nonceTrialsPerByte`, `payloadLengthExtraBytes`).
- **Hashcash (1997)** — 20 бит ≈ секунда на CPU того времени; сегодня 20 бит SHA/BLAKE3 ≈ 1M хешей ≈ 0.3–0.5 с на десктопе, ~2–3 с на телефоне, ~5 с в wasm; GPU даёт ×100 и более → одноразовые пороги против ботнета/фермы не работают (Laurie & Clayton, «Proof-of-Work Proves Not to Work», 2004).
- **Session** — PoW в envelope существовал в ранних версиях, фактически заменён лимитами на уровне swarm.
- **iroh-relay** — с 1.0.2 live rate limits `set_client_rate_limit`, `[limits]` в конфиге; `access.http.url` — внешний allow-callout по EndpointId.
- **QUIC (RFC 9000)** — anti-amplification 3× до валидации адреса + Retry-токены; в `noq`/iroh есть из коробки.
- **RandomX / memory-hard** — CPU-bias, но тяжёлая верификация и большие таблицы; для клиентских puzzle Tor осознанно выбрал Equi-X.

### 5.3 Вердикт по идее «ресурсоёмкий PoW при создании первого ключа»

**Не делать как основную защиту.** Причины:

1. **Амортизация.** Одна identity = неограниченный спам/флуд после единственного платежа. Бот-ферма заплатит один раз (на GPU в 100× дешевле, чем жертва на телефоне) и дальше бесплатна. Против ботоводства работает не цена ключа, а **цена каждого действия** + **contact-first** (незнакомец не может писать без Accept — уже в спеке §13.1).
2. **DDoS relay не зависит от identity.** iroh-relay/QUIC атакуют пакетами и соединениями с произвольными Ed25519 EndpointId (бесплатны); ML-DSA identity в этом пути вообще не участвует. Защита relay — `[limits]`, `access.http` + QUIC anti-amplification, а не PoW на ключ.
3. **Детерминизм seed → identity.** Grinding ключа (N ведущих нулей в pubkey/fingerprint) должен быть детерминированным перебором `counter` от seed, иначе фраза не восстанавливает аккаунт. Значит при восстановлении из фразы пользователь **снова** ждёт минуты (на телефоне/в браузере — десятки минут), либо counter надо хранить рядом с фразой (ломает 24-словную модель). ML-DSA-65 keygen ~50–100 µs на десктопе → 20 бит ≈ 1–2 мин, 24 бит ≈ 20–30 мин, на телефоне ×5–10, в wasm ещё хуже; GPU-реализации ML-DSA (cuPQC) делают это в тысячи раз быстрее — асимметрия против честного пользователя.
4. **UX/доступность.** Argon2id 256 MB уже даёт 1–3 с на десктопе и 3–9 с в браузере (spec §15.5); добавлять минуты ожидания на онбординге — прямой удар по конверсии.

**Что делать вместо (per-action, adaptive, verifiable):**

| Точка | Механизм | Параметры v1 |
|---|---|---|
| ContactRequest (незнакомец → пользователь, напрямую или через intro-mailbox relay) | PoW BLAKE3 над `server_nonce ‖ request` (spam.rs уже есть), **адаптивная сложность** как в Tor: базово 16 бит (~10–30 мс), при нагрузке до 24–28 бит; nonce истекает 30 с; + `RateLimiter` (10/мин, 3/ч/ключ, бан 1 ч) | `POW_MIN=16, POW_MAX=28`, шаг по load |
| Регистрация mailbox / intro-mailbox на aira-relay | лимит N/сутки на EndpointId + PoW 20 бит для intro; обычные mailbox — только подписью owner_sk | `REGISTER_PER_DAY=20` |
| Deposit в обычную mailbox | подпись sender_sk (контакты); PoW не нужен | — |
| iroh-relay | `[limits]` (accept_conn_limit, client.rx bytes/s), `access.http.url` → сервис Aira, который пускает EndpointId только после первой успешной регистрации mailbox (или всех — на старте) | 50 conn/s, 2 MB/s |
| Handshake от незнакомой ноды (spec §11B.2) | тот же adaptive puzzle перед PQXDH; contacts (Tier 1) — без puzzle | 16→28 бит |
| DHT publish (spec §11B.4) | PoW 16 бит на запись + TTL 24 ч | — |
| Локальный флуд от контакта (spec §11B.6) | rate limit per contact + mute | 500 msg/min |

**Единственная разумная «цена ключа»:** оставить Argon2id 256 MB как есть (это уже защита seed-фразы от brute force, не anti-Sybil) и **не** вводить публичный PoW на identity. Если владелец всё же хочет «дорогой ключ» как сигнал доверия — реализовать как **опциональный бейдж** (fingerprint с ≥16 ведущими нулями, детерминированный перебор counter от seed, счётчик хранится в профиле и передаётся в invitation link), который снижает PoW для ContactRequest, но не является требованием. Приоритет — низкий, после релиза.

**Дополнения из исследования (агент pow-sybil, полный JSON в `audit-2026-09/raw/a6a6c3c36573ff5a4.json`):**

- Числа: Dilithium3 keygen ≈ 256k циклов (AVX2) → ~15k keygen/с/ядро; cuPQC на H100 — 6,5 млн ML-DSA-65 keygen/с. Key-grinding 24 бита ≈ 2,3 мин на 8-ядерном десктопе / ~40 мин в один поток / 2,6 с на H100; 28 бит ≈ 37 мин / 11 ч / 41 с. Асимметрия GPU:desktop ≈ 50×, GPU:телефон ≈ 500×, GPU:браузер ≈ 1000×.
- Equi-X (Tor): 1,8 MiB памяти, proof 16 байт, верификация ~50 мкс, GPU ≤10 % от CPU; RandomX отвергнут Tor как client puzzle из-за тяжёлой верификации («top half» атака на верификатор). Memory-hard puzzle с симметричной верификацией без rate-limit — сам DoS-вектор.
- Tor hspow: клиент замеряет свою скорость, показывает оценку времени, на мобильном рекомендует desktop; сервер приоритизирует очередь по effort; плюс лимиты на intro points (Proposal 305) — «одного решения нет, подходы комбинируются».
- Таблица времён в spec §11B.2 занижена ~5–10× (предполагает ~65 MH/s; реальный однопоточный BLAKE3 на коротком входе 5–10 MH/s): 16 бит ≈ 10 мс, 20 ≈ 0,1–0,2 с, 24 ≈ 2–3 с, 28 ≈ 30–50 с; WASM ×3–5. Нужен criterion-бенч в aira-core до фиксации таблицы.
- **Дефект текущего PoW ContactRequest**: `to_pow_bytes = from ‖ message ‖ difficulty` (spam.rs:49-55) — нет nonce получателя и timestamp → одно решение переиспользуется бесконечно (precomputation/replay). Добавить `recipient_pubkey ‖ server_nonce ‖ issued_at`.
- **Дефект переносимости identity**: соли Argon2 разные для Desktop (`aira-master-v1-m256`) и Mobile (`aira-master-v1-m64`) (seed.rs:33,39) → одна фраза даёт **разные** master seed на разных профилях. `from_phrase()` по умолчанию Desktop; проверено: `Platform::Mobile` встречается только в тесте (`aira-daemon/src/handler.rs:964`), aira-ffi/Android используют Desktop-профиль → identity переносима, но Android платит 256 MB RAM на деривацию. Профиль Mobile из кода/спеки лучше убрать, чтобы никто не включил его «для скорости».
- Если владелец хочет «публично проверяемую цену identity» — только **вариант A: Hashcash-штамп над детерминированным pubkey** (`IdentityStamp { nonce, bits, created_at }`, `BLAKE3("aira/identity-stamp/v1" ‖ pubkey ‖ bits ‖ nonce)` с ведущими нулями; ключ не меняется, штамп пересчитывается в фоне после восстановления, 22 бита ≈ 0,5–1 с на десктопе), прикладывается к DHT-записи/invitation link/регистрации mailbox. Вариант B (grinding seed_i до условия) — отклонить.
- Privacy Pass rate-limited tokens (IETF draft) — альтернатива для анонимного дозирования ContactRequest в v2; issuer = relay.

**Memory-hard puzzle вместо BLAKE3?** Для v1 — нет: BLAKE3 + адаптивная сложность + nonce достаточно против случайного спама, а против GPU-фермы спасает не puzzle, а contact-first + лимиты relay. Equi-X в Rust стабильного крейта нет; Argon2id-puzzle (m=16 MB, t=1) можно рассмотреть в v2 для intro-mailbox.

## 5.5 Клиенты (GUI / CLI / FFI / Android) — готовность к бете

Источник: аудит кода агентом (raw: `audit-2026-09/raw/a42d1f647994de6ec.json`), только Read/Grep, без cargo.

**Итог:** Milestone 9.5 (auto-spawn демона, onboarding, password vault, MSI/DMG/AppImage) сделан почти полностью;
Milestone 9.6 не начат ни в одной фазе. Но главные блокеры не в UI, а ниже: демон не в сети (§0), keyring
без platform-фич, Android-оболочка без provisioning seed и с неподписанным APK.

### 5.5.1 Статус по спеке

| Фаза | Статус | Evidence |
|---|---|---|
| 9.5 A: keychain.rs (store/load/delete, Zeroizing, Plain/Vault) | код есть, **бэкенда нет** | `Cargo.toml:93` `keyring = "3"` без features → в Cargo.lock keyring 3.6.3 тянет только log+zeroize → компилируется **mock in-memory store**; тесты keychain помечены `#[ignore]` (keychain.rs:189,209,221), CI это не ловит |
| 9.5 A: daemon_manager.rs (spawn через `AIRA_SEED`, CREATE_NO_WINDOW, stderr capture) | production | daemon_manager.rs:4-6,16-17,85-90,138-142 |
| 9.5 A: onboarding Create/Import, BIP-39 валидация | works-but-rough | welcome.rs:49,67,156-168; копирование seed в системный буфер без авто-очистки (welcome.rs:156-157) |
| 9.5 A: ConnectionState + Bridge (bootstrap/main_loop/reconnect, backoff 0.5–10 с, poll 200 мс) | production | state.rs:103-117; ipc.rs:567-1039 |
| 9.5 B: password vault (Argon2id m=128MiB, ChaCha20Poly1305, контекст `aira-gui/password-vault/v1`), unlock view | production | password_vault.rs:11-24,45,108,147; docs/KEY_CONTEXTS.md:107 |
| 9.5 C: инсталляторы MSI (cargo-wix), DMG, AppImage, release.yml, INSTALL.md | production (без code signing) | release.yml:95-152; docs/INSTALL.md:23-127 |
| 9.6 A: ml-dsa 0.1.x | **missing / заблокировано** | bump до rc.4 не закоммичен и не собирается; 0.1.1 недоступна до iroh 1.x (§2) |
| 9.6 B: Android release signing | **missing, хуже спеки** | build.gradle.kts без `signingConfigs`; release.yml:229-235 публикует `app-release-unsigned.apk` как `aira-<ver>-android.apk` → **APK вообще не подписан**, Android его не установит (INSTALL.md:133 ошибочно пишет «debug-подпись») |
| 9.6 C: i18n 10 языков, locale.rs | missing | нет `src/locale.rs`, нет fluent/sys-locale в aira-gui/Cargo.toml, все строки hardcoded; Android `res/` только `values/` |
| 9.6 D: темы dark/light/system | missing | theme.rs:179 единственный `apply_theme`; settings без Appearance |
| 9.6 E: UX polish | частично | аватар с инициалами contacts.rs:82-103, stick_to_bottom chat.rs:55; ввод singleline (chat.rs:67); нет search / date separators / delivered |

### 5.5.2 Путь пользователя (где ломается)

1. Установка → первый запуск → создание seed: работает (GUI). CLI: демон требует `AIRA_SEED` в env (aira-daemon/src/main.rs:85-96) — фраза попадает в историю shell и `/proc/<pid>/environ`; CLI не умеет ни запускать демон, ни хранить seed (aira-cli/src/main.rs:58-66 → «Is the aira-daemon running?» и exit 1).
2. **Перезапуск GUI: ломается.** keyring = mock store → каждый запуск начинается с onboarding, «Create new identity» даёт новую личность, контакты и vault предыдущей теряются.
3. **Добавление контакта: ломается по UX.** GUI (add_contact.rs:33-40,60), Android (AddContactScreen.kt:47) и CLI требуют вставить ~3900 hex-символов ML-DSA-ключа; валидация только `hex::decode` без проверки длины (и в `aira-storage contacts::add` тоже). `GetMyAddress` (handler.rs:77-93) генерирует **новый pseudonym при каждом вызове** — «адрес» нестабилен. Формат `aira://add/<base64url(postcard(InvitationLink{pseudonym_pk, endpoint_addr_bytes}))>` из aira-net/src/discovery.rs:20-45 не использует ни один клиент; QR нет; contact request/PoW не подключены. Даже после сетевой интеграции у контакта нет endpoint-адреса.
4. **Первое сообщение: не доставляется никогда** (§0). GUI/CLI/Android покажут его в истории, получатель не увидит. Офлайн-получатель неотличим от онлайн.
5. Понятие relay в клиентах отсутствует: grep relay|offline|queue по aira-gui/aira-cli/aira-ffi/android — только метка «Offline» (app.rs:240) и событие ContactOffline. Нельзя указать свой relay, нет статуса relay, нет бинаря relay-ноды (`[[bin]]` только aira, aira-daemon, uniffi-bindgen, aira-gui).

### 5.5.3 Android — мёртвая оболочка

- `AiraDaemonService.kt:44-48` читает `seed_phrase` из plain SharedPreferences и молча `return`, если нет; ни один Kotlin-файл не делает `putString(seed_phrase)`; FFI `AiraRuntime::new(data_dir, seed_phrase)` (runtime.rs:56) не умеет генерировать/валидировать seed; `MainActivity.kt:27` repository = null навсегда; `IdentityScreen.kt:42` TODO; `FcmService.kt:24`, `UnifiedPushReceiver.kt:28` — TODO, endpoint не регистрируется.
- `build.gradle.kts:23-29`: `isMinifyEnabled=true` + `proguard-rules.pro`, **файла нет** → R8 обфусцирует/удаляет `uniffi.aira_ffi.*` и JNA `Structure` → крэш при первом вызове в release.
- Manifest `foregroundServiceType="dataSync"` при targetSdk 35 → лимит 6 ч/сутки на Android 15; firebase-messaging без плагина google-services (и несовместимо с F-Droid); NDK 26.1 не выравнивает `.so` по 16 KB; cargo-ndk без пина; Google Play с 31.08.2026 требует targetSdk 36.
- FFI `seed_phrase: String` без Zeroizing (0 вхождений zeroize в aira-ffi).

### 5.5.4 Прочее

- Секреты в GUI в порядке: Zeroizing в ipc/keychain/onboarding/password_vault/settings/unlock, ручной Debug для SubmitPassword и DaemonSpawnError, утечек phrase|seed|password в логах нет.
- unwrap/expect в production-путях GUI: ipc.rs:651, main.rs:68,116,119, tray.rs:81 — все на старте/инвариантах; CLI: 0.
- `SendMessage` (handler.rs:64) `text.into_bytes()` без проверки `MAX_ENVELOPE_SIZE`; нужны константы PUBKEY_LEN/MAX_MESSAGE_LEN в aira-core и проверка на границе IPC и UI.
- Windows named pipe `\\.\pipe\aira-daemon` (main.rs:67-68) фиксированный → два пользователя/профиля на одной машине конфликтуют.
- README.md в корне отсутствует; INSTALL.md про Android неверен; CLI `/verify` → «coming in M6» (main.rs:455), хотя M6 помечен выполненным.

### 5.5.5 Что это меняет в планах

- В M19 (демон в сети) обязательно войти: `GetInvitation` → `aira://add/…` (стабильный pseudonym + iroh EndpointAddr, выданные псевдонимы хранить), `AddContact { uri }`, событие `ContactRequestReceived` + accept/reject; GUI «Share my link» с QR (`qrcode` + egui Image), Android — сканер.
- Отдельный короткий милстоун **M19b — Клиентские блокеры**: keyring platform-features (`windows-native`, `apple-native`, `sync-secret-service`/`linux-native`), снять `#[ignore]` с roundtrip-тестов на Windows/macOS; seed в демон через stdin/IPC/keychain (AIRA_SEED — только dev); IPC `SetRelay/GetRelayStatus` + Settings «Relay» + индикатор.
- Android (M10-fix, перед бетой на Android): FFI `generate_seed_phrase()/validate_seed_phrase()`, OnboardingScreen, EncryptedSharedPreferences/Keystore, `proguard-rules.pro` (keep `com.sun.jna.**`, `uniffi.aira_ffi.**`), `signingConfigs.release` из GitHub Secrets + `apksigner verify` в CI, FGS `remoteMessaging`/`specialUse`, убрать FCM (оставить UnifiedPush), 16 KB alignment, targetSdk 36. Если Android-бета не в первом релизе — пометить APK как «preview» и убрать из release assets.
- M9.6 C/D (i18n, темы) — после сетевой интеграции, не блокер беты.

## 6. Браузерная версия (M14) — исследование (raw `audit-2026-09/raw/adea149893e3b2312.json`, полный текст `wasm-browser.md`)

**Вердикт:** браузер технически возможен только как «relay-only демо» и только **после** M18 (iroh 1.1 + redb ≥ 3.1), M19 (сетевая логика демона как переиспользуемая библиотека), M20 (свой iroh-relay с WebSocket/TLS/токеном) и M21 (mailbox — иначе закрытая вкладка = потеря сообщений). Сам M14 — 4–6 недель после релиза. Но «M14.0 — предпосылки в ядре» дёшевы (3–5 дней) и должны войти в M18/M19, пока код и формат БД всё равно ломаются.

### 6.1 Блокеры и факты

- **redb 2.6.3 не компилируется под wasm32** (починено в redb 3.1.0, 2025-09-25); формат файла v2 **удалён в redb 3.0** → апгрейд redb 2 → 4 = смена формата с одноразовой миграцией `Database::upgrade()` через redb 2.6 (alias `redb2`) или объявление БД 0.3.x несовместимой (решение владельца). Делать в M18/M19 вместе с `meta{schema_version}` (§4.1a).
- **redb-opfs непригоден:** `license = "GPL-3.0-only"` (Aira — MIT OR Apache-2.0), README «statement of intent, not an accurate reflection of the current state», зависимость на git master redb, единственный issue — «License», нет на crates.io, репозиторий мёртв с 2025-09-25. → Свой `OpfsBackend` (~200–300 строк) поверх redb 4 `StorageBackend` (5 методов: len/read/set_len/sync_data/write + close) в dedicated Worker; web-sys типы !Send → `send_wrapper::SendWrapper` (уже в Cargo.lock). Этап 0 — `InMemoryBackend` + периодический зашифрованный снапшот в OPFS.
- **iroh-blobs не поддерживает браузер** (issue #90, открыт с 2025-10) → файлы в браузере исключаются, `aira-net::blobs` под `#[cfg(not(target_family = "wasm"))]`.
- **iroh в браузере:** только через relay (UDP из песочницы нет, hole punching невозможен; WebTransport — открытый issue #3750); `iroh = { version = "1", default-features = false, features = ["tls-ring"] }` (aws-lc-rs под wasm не работает → PQ-TLS в браузере недоступен); wasm-зависимости iroh 1.1: wasm-bindgen-futures, web-time, getrandom 0.4 (`wasm_js`), n0-future 0.3; в браузере handshake relay всегда challenge-fallback (нет TLS-exporter).
- **tokio `full` не собирается под wasm** (`compile_error!`: только sync, macros, io-util, rt, time) → per-target features в aira-net + `n0-future` для spawn/sleep/timeout.
- **`SystemTime::now()` паникует под wasm32**: aira-core util.rs:16,25; aira-storage contacts.rs:18, dedup.rs:19,55, messages.rs:114,147; `Instant` в aira-net connection.rs:10 и relay.rs → `web-time` (уже в lock).
- **Три getrandom в Cargo.lock** (0.2.17 через rand 0.8, 0.3.4, 0.4.2) → фичи `js`/`wasm_js` только в финальном крейте aira-wasm как target-specific deps; после M18 (rand 0.10 через ml-kem 0.3) остаётся один getrandom 0.4. Спека §14.1 п.3 (getrandom 0.3) устарела.
- **Argon2id 256 МБ в WASM:** параметры менять нельзя (иначе другая identity); WASM-память не возвращается (`memory.grow` только растёт) → KDF в отдельном одноразовом Worker'е, результат (32 байта) через postMessage, затем `worker.terminate()`; iOS Safari может убить вкладку без события; Safari без SIMD ~1.5× медленнее; ожидание ≥1.2 с на desktop Chrome, на мобильных заметно больше — нужен замер. `Platform::Mobile` удалить, `Platform::Browser` не вводить.
- **OPFS `createSyncAccessHandle`** только в dedicated Worker (Chrome 108+, Safari 16.4+, Firefox 111+); handle эксклюзивен на файл — вторая вкладка того же origin не откроет БД (Web Locks / BroadcastChannel «уже открыто»). **Вытеснение:** Safari удаляет данные origin после 7 дней без взаимодействия, iOS — под давлением; `navigator.storage.persist()` + предупреждение в UI. Для ratchet потеря состояния = невозможность расшифровать дальнейшие сообщения, не просто «потеря кэша».
- **CSP:** `script-src 'self' 'wasm-unsafe-eval'; connect-src 'self' wss://relay.<domain>; worker-src 'self'`; COOP/COEP не нужны, пока нет wasm-threads (argon2 `parallel`/rayon не включать).
- **Web Push невозможен** без application server (VAPID, БД подписок, push-сервис вендора; iOS только для Home-Screen web-app) — не делать; доставка только при открытой вкладке + retrieve из mailbox (M21).
- Прочее: rust-embed в debug-сборке читает `locales/` с диска → фича `debug-embed` для wasm; тесты со `std::thread` в aira-core под `cfg(not(target_arch = "wasm32"))`; governor/quanta вероятно соберутся; wasm-bindgen 0.2.128, wasm-pack 0.15; на машине не установлен target wasm32; в CI wasm-цели нет.

### 6.2 M14.0 — предпосылки в ядре (внутри M18/M19, 3–5 дней)

1. redb 2.6 → 4.2 в M18 (с миграцией или объявлением несовместимости), `Storage::open_with_backend(impl StorageBackend, key)` рядом с `open(path)`; backup.rs → `export_bytes/import_bytes` + файловые обёртки под `cfg(not wasm)`.
2. Единая точка времени `aira_core::util::{now_micros, now_secs}` на `web_time`, storage переводится на util; `Instant` → `web_time::Instant`.
3. aira-net: tokio per-target, `n0-future` вместо прямых `tokio::spawn/time` в клиентских путях; cfg-гейты на `blobs` и серверную половину `relay` (RelayServer); transport/* остаются за фичами.
4. IPC-типы демона (types.rs + фрейминг postcard) → отдельный крейт `aira-ipc` без tokio; сетевая логика M19 (SessionManager, handler, pending-дренаж, presence) — библиотека `aira-node` с абстракцией spawn/time, которую используют aira-daemon, aira-ffi и aira-wasm. **Ключевое требование к M19**: не привязывать логику к `tokio::main`/`std::fs`, иначе браузер станет третьей копией сетевого кода.
5. seed.rs: удалить `Platform::Mobile` (тесты на cfg(test)-параметры).
6. CI guard с M18: `rustup target add wasm32-unknown-unknown && cargo check -p aira-core --target wasm32-unknown-unknown`; позже `-p aira-net --no-default-features`, `-p aira-storage`.

### 6.3 M14 (после M21, 4–6 недель) — кратко

`crates/aira-wasm` (cdylib+rlib; target-deps getrandom `wasm_js`/`js`, wasm-bindgen, web-sys, send_wrapper, n0-future, wasm-tracing) экспортирует `init`, `request(bytes) -> Promise<bytes>` (postcard из aira-ipc), `on_event`, `set_locale`; всё в dedicated Worker, main thread — JS-прокси. Отдельный KDF-воркер `aira-kdf` с терминацией. `OpfsBackend` (или InMemory + снапшот как этап 0), `navigator.storage.persist()`. Сеть: `AiraEndpoint::bind` с `RelayMode::Custom` на свой relay (`wss://relay.<domain>/relay`, `with_auth_token`), dial по EndpointAddr из InvitationLink/контакта (relay_url внутри, без pkarr-lookup из браузера), mailbox-клиент M21; `SendFile` → `Unsupported`. CI: `wasm-pack build --target web --release` + `wasm-opt -Oz`, `wasm-pack test --headless --chrome --firefox`, размер .wasm (gz/brotli) как метрика — **первый замер определяет реалистичность** (если > 5–8 МБ gz — демо бесполезно на мобильных). Страница `try.<domain>` с дисклеймером о доставке кода через веб.

### 6.4 Требования к relay для браузера (закладывать в M20/M21)

- iroh-relay ≥ 1.0.2 (ставить 1.1.0), TLS 443 с публично доверенным сертификатом; WebSocket `/relay` + субпротокол `iroh-relay-v2` проходят через nginx (для браузера вариант B из §3.3 равноценен A — он всегда на challenge-fallback); `[limits.client.rx]` считать с учётом того, что 100 % байт браузерных клиентов идут через relay.
- Auth: `shared_token` для web — **отдельный** от нативных и ротируемый (в браузере токен уходит в `?token=` URL WebSocket → логи прокси/DevTools); далее `access.http.url` с PoW-гейтом (M22).
- CORS: для WebSocket не нужен; нужен `Access-Control-Allow-Origin` на iroh-dns-server `/pkarr/*` и `/healthz`, если страница их вызывает (лучше обойтись без).
- aira-relay (M21): протокол работает поверх relay-only QUIC без допущений о прямом UDP; квоты/PoW на intro-mailbox обязательны до открытия веб-демо (браузерные identity создаются легко).

### 6.5.0 Решения владельца по браузеру

- Миграция БД 0.3.x через redb 2.6 `upgrade()` или объявить 0.4 несовместимой с локальными БД 0.3.x?
- Веб-клиент = только desktop-браузеры + Android Chrome; iOS Safari — «не поддерживается» (память, вытеснение)?
- Seed между сессиями браузера: повторный derive при каждом открытии (секунды) или зашифрованный паролем vault в OPFS (как GUI M9.5)?
- `aira-ipc`/`aira-node` выделять в M19 сразу (рекомендуется) или как рефакторинг после релиза?

**Что не делать:** redb-opfs (GPL, мёртв), `Platform::Browser`, argon2 `parallel`/wasm-threads (COOP/COEP + nightly build-std), Web Push, egui в браузере, дублирование сетевого кода демона в aira-wasm.

## 6.5 Спека и планы vs код (аудит spec-drift, raw `audit-2026-09/raw/ac81a6c66b88a9930.json`)

### 6.5.1 Статус милстоунов по коду (HEAD 971e038)

| M | Статус | Что есть | Чего нет |
|---|---|---|---|
| M1 Core crypto | partial | все модули aira-core, commit c277849 | C1–C7 (§2.5): wire без ratchet-header, AEAD без AAD, PQ-шаг не стартует, handshake не PQXDH; `proptest!` не используется |
| M2 Networking + Relay | partial | endpoint/connection/discovery/relay в aira-net, тесты two_node_chat/relay_offline | п.3 DHT (discovery.rs:6 «later milestone»), п.5 bootstrap/relay-нода, relay in-memory и только в тестах; всё на presets::N0 |
| M3 Storage + Daemon | partial | схема, шифрование, IPC, TTL, backup | демон без Endpoint, `pending::dequeue` не вызывается (§4.1a) |
| M4 File transfer | partial | BlobStore, TransferManager, IPC-события | передачи между узлами нет (§4.1a) |
| M5 CLI | done | все команды §16 M5 (commands.rs) | e2e по сети невозможен |
| M6 Группы | partial | group.rs/group_proto.rs, storage groups/pseudonyms, handler 354-680 | интеграционного теста «3 ноды» нет, доставка control не подключена |
| M6A Bot SDK | done | aira-bot, docs/BOT_SDK.md | п.5 WASM sandbox (wasmtime) |
| M7 DPI resistance | partial | transport/{direct,obfs,mimicry,cdn}, dpi_simulator | obfs = XOR-keystream, не obfs4/ptrs (Cargo.toml:75 закомментирован); CDN симулирован; транспорты не задействованы демоном |
| M8 Мультидевайс | partial | device.rs/sync.rs, tests/multidevice.rs, devices.rs, CLI | DHT-публикации нет; `node_id` пуст; sync_log не пишется |
| M9 Desktop GUI | partial | aira-gui, tray, notifications, инсталляторы | keyring mock (§5.5), code signing нет |
| M9.5 | done (с оговоркой keyring) | все три фазы закоммичены | keychain без реального бэкенда |
| M9.6 | **not started** | — | RUSTSEC-2025-0144 всё ещё в ignore (deny.toml:45, .cargo/audit.toml:12); APK unsigned; нет locales/locale.rs/avatar.rs/ANDROID_SIGNING.md |
| M10 Android | partial | aira-ffi, Kotlin-оболочка, release job | APK не подписан, FFI = Desktop-Argon2 (runtime.rs:65), provisioning seed нет (§5.5.3) |
| M11 iOS | исключён | — | — |
| M12 REALITY + Tor | partial | reality.rs/tor.rs/fingerprint.rs | arti нет (SOCKS5 только), uTLS нет (reality.rs:3), active probing только unit |
| M13 aws-lc-rs | done | awslc.rs, compat_tests.rs, features fips/compat-test | миграция PQ-API затронет awslc.rs:129-134 |
| M14 WASM | not started | только спека | redb-opfs нет на crates.io |
| M15 Voice | not started | §6.11 MediaType::Audio описан | opus/cpal нет |
| M16 Markup | not started | §6.25 описан | markup.rs нет |
| M17 Tauri | not started | только спека | desktop/ нет |

### 6.5.2 Противоречия спеки (relay / offline / PoW) — править при добавлении M18–M23

1. **Два relay смешаны** (блокер для понимания): spec/03-network.md:16 «DERP-серверы» (live, iroh) vs spec/04-protocol-wire.md:192-215 §6.3b «доверенный relay хранит конверты… выбирается пользователем» vs spec/05-protocol-versioning.md:61-77 §6.5 vs habr_article.md:308,591-595. Код: `RelayServer` — ALPN-хендлер `aira/1/relay` на iroh-узле, не iroh-relay. → В §5.1 DERP→iroh-relay, новый §5.1.1 «Собственный iroh-relay + iroh-dns-server (pkarr)» и `AiraPreset`; в §6.3b явно назвать второй процесс `aira-relay`; глоссарий §20: «transport relay» / «mailbox relay».
2. **Формула mailbox ID в трёх вариантах**: §6.5 `BLAKE3(shared_secret ‖ "mailbox")`; relay.rs:28,85 `derive_key("aira/relay/mailbox/v1", shared_secret)`; habr_article.md:367 `BLAKE3(ML-DSA_A ‖ ML-DSA_B)` — последняя линкуема и противоречит цели §6.5. → Зафиксировать v2 из §4.3 (две коробки по направлению) в §6.5, KEY_CONTEXTS.md и статье.
3. **§11B.5 (spec/13-threat-model.md:436-462)** обещает 30 deposits/min на отправителя, PoW 16 бит для не-контактов, 1 GB cap, GC 6 ч с приоритетом; таблица §11 «Amplification → authenticated deposits». Код relay.rs:34-48: запросы без отправителя/подписи, Retrieve/DeleteMailbox любому, знающему id; GC по last_activity коробки; HashMap в RAM. → Заменить §11B.5 + §6.3b протоколом v2 (§4.3); ALPN `aira/1/relay` удалить.
4. **§11B.5.1** (RelayHello/RelayCapabilities/RelayMigration/multi-relay, spec/13:464-503) и **§6.3 MailboxConfig/NotificationEndpoint** («заложен в wire format сейчас», spec/04:216-248) — в коде 0 совпадений. Утверждение «заложено» ложно → пометить «реализуется в M21», RelayHello v2 + Register с notification_endpoint сразу.
5. **Relay «выбирается пользователем»** (§6.3b:211), «несколько relay» (§11B.5.1:497-502), settings хранит relay (spec/06:105) — в IPC (types.rs) нет SetRelay/GetRelay, в CLI нет `/relay`. → spec/10-daemon-ipc.md: `GetRelays/SetRelays`, событие `RelayStatus`; spec/11-cli.md `/relay`; в контакт-записи поле `relays`.
6. **PoW на ContactRequest «v0.1»** (spec/15-spam.md:17-58, spec/13:23) — `Message::ContactRequest` в proto.rs нет, `spam::` вне aira-core не импортируется, handshake без puzzle. → M22: `Message::ContactRequest` (nonce получателя, difficulty задаёт verifier — C7), проверка в daemon и handshake.
7. **§11B.2 AdaptivePuzzle 16→28 бит перед handshake, Tier 3 «PoW обязателен»** — grep puzzle → 0; ratelimit.rs:24-40 только governor-квоты; таблица времён занижена 5–10× → пересчитать (16 бит ≈ 10 мс, 20 ≈ 0.2 с, 24 ≈ 3 с, 28 ≈ 50 с однопоточно).
8. **Защиты от массовой генерации identity в спеке нет** и она противоречила бы §5.2 (per-contact pseudonyms: десятки ключей у одного пользователя). → Новый §11B.10 «Стоимость identity»: per-action PoW, лимит регистраций mailbox на EndpointId/сутки, опционально IdentityStamp (Hashcash над детерминированным pubkey) как публично проверяемый штамп — согласуется с §5.3.
9. **§5.3 bootstrap-ноды «зашиты в бинарник» и §5.2b DHT** — в коде нет, discovery целиком на n0. После 30.09.2026 без своего pkarr/DNS discovery узлы не найдут друг друга даже при живом relay. → Переписать §5.2b/§5.3 под pkarr publish/resolve через собственный iroh-dns-server + relay-map; DHT — после релиза; spec/16-multidevice.md:40,57 «DHT-запись» → «pkarr/DNS-запись».
10. **Ratchet/handshake v1 непригодны для «релиза с обещанием совместимости»** (C1–C7). → В §6.4 зафиксировать: релизный протокол = v2 (`min_version = max_version = 2`), v1 — pre-release без гарантий; описать `Message::Ratchet{header, envelope}` в §6.1 и PQXDH-транскрипт в §4.5.

### 6.5.3 Устаревшие утверждения (править одним коммитом `docs(spec)`)

- Версии: spec/12-dependencies.md:8 «iroh ~1.0, вышел из RC-серии 0.97+» vs :15 `iroh = "0.97"`; :21 ml-dsa «0.1 (≥0.1.0-rc.4)»; :20 ml-kem 0.2; :45 redb 2; spec/03-network.md:21-22, spec/01-overview.md:103, CLAUDE.md:14-16,110; spec/18-milestones.md:308-309 «опционально bump iroh → 1.0» (обязательно), :281 getrandom 0.3 (→ 0.4); habr_article.md:70-71,80-81,84. Цель: iroh 1.1 / iroh-blobs 0.103 / ml-dsa 0.1.1 / ml-kem 0.3 / redb 4 (или оставить 2.6 с обоснованием) / getrandom 0.4 / rust-version 1.91.
- Версия спеки: spec/20-appendix.md:57 «Spec v0.4» vs SPEC.md:4 и spec/01-overview.md:4 «Версия 0.2, апрель 2026» → унифицировать (0.5, сентябрь 2026).
- §6.3b:209 обосновывает relay через iOS (исключён) → Android FGS / любой офлайн-пир; §5.1 «DERP» → iroh-relay (WebSocket/TLS, QAD udp/7842).
- spec/14-groups.md:410-471 дублирует spec/15-spam.md §13.1–13.2 → удалить дубликат.
- docs/THREAT_MODEL.md, требуемый spec/13:9, не существует → M23.
- §15.7 (spec/17:204-212) обещает wasm32 и .aab в CI — их нет → пометить «после релиза».
- habr_article.md: :604 «M2 Done» (partial), :371-376 ring buffer / PoW перед депозитом / TTL 24–48 ч / per-identity квоты (ничего нет; спека 7 дней), :121 mobile-Argon2 m=64MB (FFI использует Desktop; Platform::Mobile только в тестах), :599-613 roadmap (M12/M13 уже done). Переписать раздел «Pairwise Relay Mailboxes» под v2 и статус «в M21».
- docs/INSTALL.md:133 «debug-подпись» → APK не подписан вообще; README.md отсутствует.

### 6.5.4 Решения, которые нужны от владельца

1. Mailbox: одна коробка на пару (§6.5 сейчас) или две по направлению (v2, §4.3)? Рекомендация — две.
2. Релизный протокол v2 без совместимости с 0.3.x (`min_version = 2`)? Рекомендация — да (у 0.3.x нет сети, ломать нечего).
3. DHT (§5.2b, §11B.4) — перенести в «после релиза», discovery = pkarr/iroh-dns-server? Рекомендация — да.
4. IdentityStamp (Hashcash над pubkey) как компромисс по «цене первого ключа» — нужен ли и куда класть (InvitationLink / HandshakeInit)? Рекомендация — не в первом релизе.
5. `Platform::Mobile` в seed.rs — удалить (разные соли = разные identity из одной фразы)? Рекомендация — удалить и поправить habr_article.md:121.
6. redb-opfs для M14 — vendoring/форк wireapp/redb-opfs или IndexedDB-fallback? Отложено до после релиза.
7. Порты на mail-сервере: кто держит 80/443, открыт ли udp/7842 — выбор варианта A/B из §3.3.
8. Android в первом релизе — включать или помечать preview (§5.5.3)?

## 6.6 Требования публичного релиза в 2026 (площадки, подпись, supply chain)

> Агент research:release-2026 дважды упал (лимит сессии; обрыв соединения при генерации ответа) после 49 веб-поисков. Раздел синтезирован мной из его спасённых результатов (`scratchpad/salvage/release-2026*.md`); полная выжимка фактов с источниками — `audit-2026-09/release-2026-requirements.md`.

### 6.6.1 Windows

- **Azure Trusted Signing → переименован в Azure Artifact Signing (2026)**: $9.99/мес (5000 подписей, 1 профиль) или $99.99/мес; сертификаты живут 24 ч, авто-ротация; даёт базовую репутацию SmartScreen. **Индивидуальные разработчики — только США/Канада** (организации: US, CA, EU, UK, AU, NZ, JP, KR, SG, CH, NO, IL); верификация личности через Entra Verified ID (биометрическое селфи). Для Kami как физлица вне US/CA — недоступно.
- **EV больше не даёт мгновенной репутации** (изменение Microsoft 2024): OV ≈ EV для SmartScreen, репутация набирается органически по установкам. Март 2026: тихая миграция на новые intermediate CA («Microsoft ID Verified CS EOC CA 03») вызвала предупреждения даже у доверенных издателей.
- **SignPath Foundation** — бесплатная OV-подпись для OSS: OSI-лицензия без коммерческого dual-licensing, активная поддержка, проект уже выпущен в подписываемой форме; ключ в HSM фонда, подпись через managed pipeline; заявка — от дней до недель. **Рекомендуемый путь для Aira.**
- **Certum Open Source Code Signing** — от $49.99, только для физлиц, publisher фиксирован как «Open Source Developer, <имя>», коммерческое подписывать нельзя (отзыв); облако SimplySign без USB-токена; верификация по документу/нотариусу/визиту + utility bill + URL проекта. С 27.02.2026 максимальный срок сертификата 459 дней. Запасной вариант.
- **winget**: MSI принимается; неподписанные файлы набирают репутацию заново с каждым обновлением; PR в winget-pkgs отклоняется, если инсталлятор триггерит SmartScreen. MSI (cargo-wix) остаётся правильным форматом для machine-wide установки; MSIX — не нужен.

### 6.6.2 macOS

- Apple Developer Program $99/год; нотаризация включена без доплаты; требует Developer ID + hardened runtime (sandbox не обязателен; entitlements — в `.entitlements`, без provisioning profile).
- Sequoia+ (и Tahoe, 15.09.2025): Control-click-обход Gatekeeper убран, пользователь должен идти в System Settings → Privacy & Security. Без нотаризации бета на macOS — только для терпеливых.
- **Homebrew**: casks без codesign+notarization удаляются из официального tap **с 1 сентября 2026** (уже действует) → без Developer ID Aira в homebrew/cask не попадёт (только собственный tap).

### 6.6.3 Linux

- **Flathub запрещает AI-generated/AI-assisted код, документацию и PR** (политика 2026, дословно: «Applications containing AI-generated or AI-assisted code, documentation, or any other content are not allowed»). Для Aira (разработка через Claude Code, что публично задокументировано в репозитории) **Flathub исключить**; также Flathub проверяет историю репозитория и не принимает console apps. Tray через StatusNotifier требует `--talk-name=org.kde.StatusNotifierWatcher`.
- Основной канал — AppImage (есть) + при желании собственный Flatpak-репозиторий / OBS / AUR. Подписи на Linux не требуются, достаточно sha256 + attestations.

### 6.6.4 Android

- **Google Play**: с **31.08.2026** новые приложения и обновления — targetSdk **36** (продление до 01.11.2026 по запросу); существующие — ≥35. 16 KB page size: новые с 01.11.2025, обновления с мая 2026 (продление до 31.05.2026) — **сроки уже прошли**; NDK **r28** выравнивает `.so` по 16 KB по умолчанию (Aira: NDK 26.1.10909125 в release.yml → обновить, `cargo-ndk` запинить). Личный аккаунт (создан после 13.11.2023): **closed testing с 12 тестерами 14 дней непрерывно** до production. Privacy policy + Data safety form обязательны, нарушение = удаление.
- **Android developer verification**: с **30.09.2026** сертифицированные устройства в Бразилии, Индонезии, Сингапуре, Таиланде блокируют обычную установку APK от неверифицированных разработчиков — включая sideload и сторонние магазины; **глобально — 2027**. Регистрация: $25 (Full Distribution) + government ID через Android Developer Console; бесплатный limited-distribution аккаунт без ID — до 20 устройств (для хобби, не для публичного релиза). Обход для пользователя: ADB или «advanced flow» (developer mode, перезагрузка, 24 ч ожидания, повторная аутентификация). F-Droid заявляет, что требование убивает проект. Для Aira: GitHub-APK без регистрации разработчика перестанет ставиться в 4 странах с 30.09.2026 и везде в 2027 → **решение владельца** (регистрация за $25 + ID vs принять ограничение).
- **FGS**: `dataSync` — 6 ч/сутки на Android 15+ (targetSdk 35+), затем `onTimeout`; из `BOOT_COMPLETED` dataSync-FGS запускать нельзя; Android 16: jobs из FGS подчиняются quota. Для постоянного P2P-соединения — тип `specialUse` с обоснованием (`PROPERTY_SPECIAL_USE_FGS_SUBTYPE`; при публикации в Play проходит ревью), но архитектурно правильный ответ — **relay mailbox + push wake-up (M21)**, чтобы FGS работал только во время retrieve. Прецедент: Molly-FOSS (форк Signal) живёт на UnifiedPush.
- **F-Droid**: FCM/Firebase запрещены как проприетарные → build flavor без FCM или полный отказ (Aira: убрать firebase-messaging, оставить UnifiedPush); anti-feature NonFreeNet при зависимости от проприетарного сервиса. Reproducible builds для F-Droid с Rust: пин `rustup` toolchain, тот же путь NDK, `SOURCE_DATE_EPOCH`, фиксированные `CARGO_TARGET_DIR`/`CARGO_HOME`.
- APK Signature Scheme v3 lineage (`apksigner rotate`) позволяет ротацию ключа; рекомендация — ротация раз в 2 года. Первый релизный ключ (M9.6 B) — сразу «настоящий», keystore вне git, backup в двух местах.

### 6.6.5 Supply chain и воспроизводимость

- **GitHub artifact attestations** (Sigstore, SLSA Build L3) — бесплатно для публичных репо: `actions/attest-build-provenance` в release.yml, проверка `gh attestation verify`. Минимальная стоимость, максимальный эффект.
- **cargo-auditable** (список зависимостей внутри бинаря → `cargo audit bin`), **cargo-cyclonedx** SBOM к каждому релизу (старт с Cargo.lock, валидация SBOM Validator).
- **cargo-vet**: пул аудитов Mozilla/Google 14k крейтов покрывает 60–75 % типичного графа (`cargo vet import mozilla`, `… google`); медианный лаг аудита 29 дней. cargo-deny достаточно для беты; cargo-vet — для 1.0.
- **Reproducible builds**: profile `trim-paths`, `SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)`, `--remap-path-prefix`, `CARGO_INCREMENTAL=0`. Прецеденты: SimpleX v6.4 — Linux/CLI/server reproducible с независимой ко-подписью (RunOnFlux), страница /reproduce, sha256 + подписи чексумм; Briar — первое reproducible-приложение в F-Droid (disorderfs).

### 6.6.6 Аудит, гранты, disclosure

- **OTF Red Team Lab** — бесплатные аудиты для internet-freedom проектов (Briar: Radically Open Security, crystal-box, сентябрь–октябрь 2023); **OSTIF** (финансирование LF/OpenSSF, Sovereign Tech Agency); **NLnet NGI Zero** — большинство open calls на паузе летом 2026 до запуска программ Open Internet Stack осенью. Коммерческие цены Cure53/Trail of Bits/ROS агент не нашёл; порядок величины по рынку — десятки тысяч USD за 2–4 недели. Для беты — внутренний аудит по чеклисту security.md + публичная threat model; для 1.0 — заявка в OTF/OSTIF на aira-core + aira-relay.
- Disclosure: `SECURITY.md` с контактом и PGP/age-ключом, окно 90 дней; bug bounty — не сейчас (нет бюджета, нет смысла до аудита).
- Прецедент SimpleX: версионированные спеки протокола прямо в репозитории (`simplexmq/protocol/*.md`, SMP v20, threat model `overview-tjr.md`) — Aira уже так делает (`spec/`), но нужен публичный `docs/THREAT_MODEL.md` (§6.5.3).

### 6.6.7 Чеклисты

**Минимум для публичной беты** (после M18–M22, входит в M23):

1. Сквозной тест «два демона → сообщение доходит», офлайн-доставка через aira-relay в интеграционном тесте; CI зелёный, `cargo audit`/`cargo deny` — блокирующие jobs, clippy на актуальном stable.
2. Подпись: Android — release keystore + `apksigner verify` (обязательно, иначе APK не ставится); Windows — заявка в SignPath Foundation (бесплатно; запасной — Certum OSS ~$50); macOS — Developer ID $99 + notarization (иначе Sequoia+ через System Settings и нет Homebrew). Если решено без подписи — честно в INSTALL.md.
3. Документы: README.md, SECURITY.md, docs/THREAT_MODEL.md, PRIVACY.md (что видит relay-оператор: IP, время, объёмы; что не видит), CHANGELOG, обновлённый INSTALL.md (relay по умолчанию, Android-статус).
4. Release assets: sha256 + GitHub attestations, бинари через cargo-auditable, SBOM CycloneDX.
5. Android: targetSdk 36, NDK r28, proguard-rules.pro, FGS specialUse + push через UnifiedPush без FCM, provisioning seed (§5.5.3) — либо **APK не входит в бету** (pre-release «preview» отдельным assets или вовсе не публикуется).
6. Схема версии БД + миграции (§4.1a), чтобы бета-обновления не теряли данные; политика «бета не гарантирует совместимость баз до 1.0» — явно.
7. Канал: GitHub Releases pre-release, версия `0.5.0-beta.N`, шаблон bug report, известные ограничения в release notes.

**Для 1.0:**

1. Внешний аудит aira-core + aira-relay (OTF Red Team Lab / OSTIF / NLnet после открытия calls) и публикация отчёта.
2. Reproducible builds Linux/CLI/relay + независимая проверка; cargo-vet с импортом Mozilla/Google.
3. Дистрибуция: winget (после подписи), Homebrew tap (после notarization), F-Droid (reproducible + flavor без FCM), Google Play только при готовности к closed testing 12×14 дней + Data safety + developer verification; Flathub — нет.
4. Решение по Android developer verification до глобального включения (2027).
5. Формализованная disclosure policy, версия протокола зафиксирована как v2 «стабильная», спека версионирована вместе с релизом.

## 7. Планы (черновик, заполняется)

Порядок (по зависимостям и дедлайну 30.09):

1. **M18 — Миграция iroh 1.1 + PQ-крейты** (блокер, до 30.09, 3–5 дней). Cargo bump (`iroh = "1.1"`, `iroh-blobs = "0.103"`, `ml-dsa = "0.1.1"`, `ml-kem = "0.3.2"`), `rust-version = "1.91"`, `endpoint.rs` (presets), `rustcrypto.rs` (15 ошибок, §2) + `awslc.rs:12,124-141`, KEY_CONTEXTS без изменений, **шаг 0 — snapshot-векторы с тега v0.3.5** (VK/подпись/EK/DK + derive от фиксированной фразы; расхождение VK = релиз-блокер), ratchet-снапшот на 64-байтный seed с чтением legacy 2400 байт, тесты на невалидный EK/CT, `compat-test`, удалить ignore RUSTSEC-2025-0144 (deny.toml:45, .cargo/audit.toml:12), `cargo audit` чистый, CI зелёный (проверить clippy на актуальном stable), `aws-lc-rs = "1.18"` без `unstable`; версия workspace → **0.4.0** (breaking формат снапшота + iroh 1.x), tag как «bridge» (только deps, без сети). Порядок шагов — §2.1. PQ-TLS (`pq-tls` фича, aws-lc-rs) — после релиза.
1a. **M19a — Протокол v2 в aira-core** (блокер, ~2 недели, после M18): C1–C7 из §2.5 — `Message::Ratchet{header, envelope}` с header в AAD; транзакционный decrypt (клон состояния); рабочий PQ-шаг (ek пира из handshake, обработка pq-полей независимо от DH-шага, свежие ML-KEM keypair из RNG); handshake = PQXDH-подобный (ephemeral ML-KEM, SIGMA-binding identity+транскрипт, nonce/anti-replay, identity_pk в KDF); `spam.rs` с `min_difficulty`, привязкой к получателю/nonce и проверкой подписи; fuzz на `Message`/`GroupControl`/`RatchetSnapshot`/framing, proptest, тесты PQ-ratchet/downgrade/replay; `docs/KEY_CONTEXTS.md` дополнить; спека §4.2/§4.4/§4.5 приведена к коду.
2. **M19 — Демон подключается к сети** (блокер №0, 2–3 недели, после M19a). `net_task` в `aira-daemon/src/main.rs`: `AiraEndpoint::bind` + `build_router` + `SessionManager` (PQXDH handshake → ratchet per contact, персист в `sessions.rs`) + отправка `SendMessage` по сети + приём входящих → IPC events + дренаж `pending_messages` (уже зашифрованных конвертов) + presence. То же в `aira-ffi/src/runtime.rs`. Сквозной тест: два демона в процессе → сообщение доходит; перезапуск демона → сессия жива. Карта точек подключения (файлы/функции) — §4.1a. Сюда же (§5.5.5): `GetInvitation`/`AddContact{uri}` через `aira://add/…` со стабильным pseudonym + EndpointAddr, `ContactRequestReceived` + accept/reject. Предпосылки в storage (до сетевого кода): таблица `meta{schema_version}` + миграция v1→v2 (`ContactInfo.endpoint_addr/relays`), инвариант «PENDING = только `EncryptedEnvelope`» + лимиты 1000/100 MB + TTL, ключ дедупа `BLAKE3(sender‖counter‖nonce)`, `sessions::save` до отправки, новый KDF-контекст для iroh SecretKey в KEY_CONTEXTS.md, `handle_request` async/`spawn_blocking`, `DeliveryState`/`NetStatus` события, обработка `Lagged` в форвардере событий.
2b. **M19b — Клиентские блокеры беты** (§5.5, §4.1a, ~1 неделя, параллельно с M19): keyring platform-features + снятие `#[ignore]`; seed в демон через stdin/IPC/keychain вместо `AIRA_SEED`; IPC-аутентификация и права (0600/`SO_PEERCRED`, имя пайпа с SID + security descriptor, `ipc.token`); backup v2 (groups/devices/pseudonyms/counter); QR «Share my link» / ввод ссылки в GUI и CLI; валидация длины pubkey и размера сообщения на границе IPC/UI; IPC `SetRelay/GetRelayStatus` + Settings «Relay»; имя named pipe с username; README.md. Android — отдельный пакет (§5.5.3): FFI generate/validate seed, OnboardingScreen, EncryptedSharedPreferences, proguard-rules.pro, signingConfigs + apksigner в CI, FGS remoteMessaging, UnifiedPush без FCM, 16 KB alignment, targetSdk 36 — либо APK убирается из release assets до готовности.
3. **M20 — Свой iroh-relay + discovery на mail-сервере** (§3.3, 1 неделя, параллельно с M19) + `AiraPreset` + конфиг демона `[network]` + второй relay + `cargo audit`/`deny` в CI зелёные.
4. **M21 — Offline v2: `aira-relay` mailbox-сервис** (§4.3, 2–3 недели): крейт `aira-relay` (redb, ALPN `aira/2/relay`, Register/Deposit/Retrieve/Ack по подписям из shared secret, intro-mailbox с PoW, квоты, TTL, GC, UnifiedPush wake-up) + клиентская часть в демоне (`relay_poll`, `deposit` при недоставке) + Android: FGS только на время retrieve.
5. **M22 — Anti-abuse** (§5.3, 1 неделя): подключить `spam.rs` (ContactRequest + adaptive PoW 16→28 бит + RateLimiter) и `ratelimit.rs` (tiers) в демон/handshake; `access.http` для iroh-relay — опционально.
6. **M23 — Release hardening** (§6.6.7, 1–2 недели): чеклист «минимум для беты» — CI-гейты (audit/deny/clippy), подписи (Android keystore обязательно; SignPath Foundation для Windows; Developer ID + notarization для macOS — или честный отказ в INSTALL.md), документы (README, SECURITY, THREAT_MODEL, PRIVACY, CHANGELOG, INSTALL), attestations + cargo-auditable + SBOM в release.yml, схема версии БД, pre-release `0.5.0-beta.N`; Android либо доведён (targetSdk 36, NDK r28, proguard, specialUse+UnifiedPush, provisioning seed), либо исключён из беты. Flathub исключить (AI-политика). Решения владельца: Android developer verification ($25 + ID, дедлайн 30.09.2026 для 4 стран / 2027 глобально), бюджет на Apple $99.
7. **M14 (пересмотр) — Браузер** (§6): после M21, 4–6 недель; «M14.0 — предпосылки в ядре» (§6.2: redb 4 + `open_with_backend`, web-time, tokio per-target + n0-future, cfg-гейты blobs/RelayServer, крейты `aira-ipc`/`aira-node`, удалить `Platform::Mobile`, CI guard `cargo check --target wasm32`) — внутри M18/M19. redb-opfs не использовать (GPL-3.0, мёртв) — свой `OpfsBackend`. Первый замер размера .wasm определяет реалистичность.

Не входит в релизный путь (отложить): M15 голосовые заметки, M16 разметка, M17 Tauri — пока нет сетевого слоя, переносить UI бессмысленно.

---

## 8. Фаза 3 (код и инфраструктура) — сводка по темам A–F

> Полные отчёты — `audit-2026-09/<файл>` (агенты пишут их сами). Здесь только выжимка; статус тем — `audit-2026-09/NEXT-SESSION.md`. Заполняется по мере завершения агентов.

### 8.1 Security-compliance по workspace (`security-compliance-audit.md`, raw `raw/a1c5b7cca4e37a69a.json`)

**Итог.** Формальный чеклист `rules/security.md` в ядре выполняется: `deny(unsafe_code)` в aira-core/aira-storage; в production-путях всех 8 крейтов нет `unwrap()/panic!/unreachable!` (9 `expect()` только на константах); долгоживущие ключи в `Zeroizing`; все 30 KDF-контекстов из KEY_CONTEXTS.md найдены в коде и не пересекаются (единственное расхождение — `aira/device/id-from-code`, деривация в `aira-daemon/src/handler.rs:200`, перенести в `aira-core::device` и задокументировать); сетевые и IPC-кадры проверяют длину до аллокации (256 KB кадр, 1 MiB IPC, 64 KB envelope); RNG — `thread_rng`; единственный MAC (REALITY) сравнивается через `subtle`. За пределами ядра дисциплина держится на людях: `deny(clippy::unwrap_used)` только в aira-core, нет `[workspace.lints]`; 0 вызовов `set_permissions/mode()` во всём workspace.

**Новых безусловных релиз-блокеров нет.** Условный блокер S1 (HIGH): входящие `GroupControl` в `crates/aira-daemon/src/handler.rs:688-819` без авторизации отправителя — `CreateGroup` от любого контакта создаёт группу с auto-accept (:737-739) и рассылкой наших ключей, `AddMember/RemoveMember` не требуют роли Admin, `AddMember.sender_keys` перезаписывает sender-chain-ключи любых участников (:764-768), короткие ключи дополняются нулями (:711-712, :766-767, :811-813), ветки приёма `PlainPayload::GroupMessage` нет (:631-672). Становится блокером, если группы входят в 1.0 (см. §8.5); закрыть в M19 Phase B до подключения приёма групп.

**Остальные находки (severity → где → milestone):**
- HIGH S2 — REALITY (`aira-net/src/transport/reality.rs:336-346, 385-396, 505-516, 541-575, 588-590, 707-715`): статичный session key на все сессии (повтор keystream), replay auth-кадра в окне 60 с, ответ сервера без MAC, `short_id` открытым текстом до TLS, `AcceptAnyCertVerifier`, `fallback_addr` всегда `None` (`transport/mod.rs:445`) — активный пробер отличает сервер от fallback. → M22: переработать или исключить из релиза (рекомендация — исключить, см. §8.2).
- MEDIUM S4 — seed-фраза/BIP-39-энтропия без `Zeroizing`: `aira-core/src/seed.rs:123-141,190-223,262-267`, `aira-daemon/src/main.rs:85-98`, `aira-ffi/src/runtime.rs:56-66` (0 использований zeroize при объявленной зависимости), `aira-gui/src/keychain.rs:170-177`. → M19a (core) + M19b (daemon/ffi/gui).
- MEDIUM S5 — `derive(Debug)` с секретами: `RatchetSnapshot` (ratchet.rs:125), `SenderKeyState/SenderKeyReceiver` (group.rs:54,128, +Clone), `SyncItem` (sync.rs:30-80), `GroupControl` (group_proto.rs:73-120). → M19a: ручной `Debug` с `[REDACTED]`.
- MEDIUM S6 — group.rs: message keys и `skipped_keys` без zeroize, nonce группового сообщения берётся с провода (:201) вместо локальной деривации. → M19a.
- MEDIUM S7 — keychain GUI: `let _ = delete…` (`aira-gui/src/keychain.rs:107-136`, `ipc.rs:755,796`) — seed может остаться в OS keychain после reset; `load_seed` предпочитает vault. → M19b.
- MEDIUM S8 — права на файлы: `~/.aira`, `aira.redb` (с plaintext `pending_messages`), downloads, backup и Unix-сокет создаются по umask (`aira-daemon/src/main.rs:107-110,130-131`, `ipc.rs:76-83`, `aira-storage/src/backup.rs:114`, `lib.rs:140`). → M19b п.3: 0700/0600 + `set_permissions` на сокет.
- MEDIUM S9 — obfs/mimicry: `chunk_len as u16` при 65 536 байт → заголовок длины 0 → обрыв/десинхронизация (`obfs.rs:273-276,327-332`, `mimicry.rs:417-422`). Неактуально, если транспорты удаляются (§8.2).
- MEDIUM S3 — `unsafe` без `// SAFETY:` в aira-gui (4 из 6: onboarding.rs:103, state.rs:78,82,86, views/settings.rs:462-468, views/unlock.rs:112-113) — заменить на `String::zeroize()`; `discovery.rs:181-182` `from_utf8_unchecked` → safe; затем `unsafe_code = "deny"` на весь workspace. → M19b/M23.
- LOW S10 — линты: `[workspace.lints.clippy] unwrap_used/panic/todo = deny`, `expect_used/indexing_slicing = warn` (после отката diff владельца в Cargo.toml). → M23 (или раньше — вопрос владельцу).
- LOW — relay v1: без cap на число mailbox'ов, `Ack.counters` без cap, `Retrieve` до 100×64 KB одним ответом > MAX_FRAME_SIZE 256 KB (`relay.rs:231,265-297`). → закрывается дизайном v2 (M21).
- LOW S11 — `let _ =` на значимых `Result` (handler.rs:470,739,909; ffi/runtime.rs:85,108,115). → M19.
- LOW — invite-URI без лимита длины, неканонический base64url (`discovery.rs:53-61,185-211`). → M19b п.4.
- LOW — `now_secs + ttl` без saturating (`aira-storage/src/messages.rs:123`): `u64::MAX` из IPC/FFI → паника в debug. → M19 Phase A.
- LOW — 15+ парсеров внешних данных без fuzz при 2 таргетах (список в отчёте §8; план — §8.3).

**Правки планов M18–M23 (внести в spec/18-milestones.md, полный текст — `raw/a1c5b7cca4e37a69a.json` → `plan_changes`):** M18 — после отката Cargo.toml проверить фичи `zeroize` у ml-kem/ml-dsa/x25519 и не смешивать rand 0.8/0.9 в `crypto/rustcrypto.rs:59-63`; M19a — Zeroizing seed-материала, ручной Debug, group.rs zeroize + локальный nonce, `aira/device/id-from-code` в KEY_CONTEXTS, ct_eq на сравнениях транскриптов; M19 Phase A — saturating TTL, лимит импорта backup; M19 Phase B — авторизация GroupControl + ветка GroupMessage + `warn!` вместо `let _`; M19 Phase C — 6 тестов (AddMember от Member отклонён, чужой pk в sender_keys игнорируется, CreateGroup без accept, ключ 31 байт, запись 65 536 байт, SetTtl u64::MAX); M19b — права на файлы/сокет, seed через FFI как bytes + Android Keystore, unsafe → zeroize, keychain delete-до-write, cap URI 4 KB; M21 — max_mailboxes, cap counters, пагинация Retrieve; M22 — решение по REALITY; M23 — workspace-линты, cargo fuzz smoke в CI.

**Решения владельца:** (1) REALITY — переработать до 1.0 или исключить (рекомендуется исключить); (2) входят ли группы в 1.0 (→ статус S1); (3) правило «ручной Debug с [REDACTED]» в rules/security.md; (4) workspace-линты в M18 или M23; (5) seed через FFI — String или ByteArray + Keystore; (6) права на Unix — chmod через std или XDG_RUNTIME_DIR + проверка владельца; (7) backup v2 — лимит импорта или потоковый формат.

### 8.2 aira-net: карта модулей, DPI-транспорты, iroh 1.1 (`net-audit.md`, raw `raw/a579b3ceafc9b3851.json`)

**Итог.** aira-net (5 851 строка) к реальному пути соединения не подключён: демон и FFI используют только `blobs::BlobStore` (in-memory, без сети) и `TransportMode::from_str`; ни один символ `AiraEndpoint/build_router/ChatHandler/RelayClient` не используется вне крейта (grep = 0) — блокер №0 подтверждён. endpoint/connection/protocol — рабочая автономная обвязка iroh с 7 сетевыми тестами на loopback (`empty_builder` без relay — от n0 не зависят). relay.rs — mailbox v1 без аутентификации. ratelimit/ConnectionManager/PeerTier/DeviceRecord — мёртвый код. **transport/\* — 3 722 строки (64 % крейта)**: шесть реализаций поверх `tokio::io::duplex`, которые не могут быть встроены в iroh (QUIC/UDP, не байтовые потоки), выключены фичами в daemon/ffi, не собираются в CI с апреля и криптографически несостоятельны (obfs без секрета, REALITY с открытым 8-байтным префиксом и статическим ключом, mimicry с length-prefix перед фейковым заголовком, CDN/Tor — заглушки). При этом GUI/CLI позволяют выбрать REALITY/Tor, а демон отвечает Ok (`handler.rs:835-848`, `views/settings.rs:50`, `cli/main.rs:442`).

**Миграция iroh 0.97→1.1 для aira-net сверена по исходникам 1.1.0: одна строка** (`endpoint.rs:78` `empty_builder` → `Endpoint::builder(presets::Minimal)`), ~30 остальных точек API и iroh-blobs 0.103 совпадают; вне aira-net iroh никто не использует. M18 п.3 «объём неизвестен» → «правок вне aira-net не ожидается»; предпосылка — откат незакоммиченного `ml-dsa = 0.1.0-rc.4`.

**БЛОКЕР ПЛАНА (M19 п.7, spec/18-milestones.md:563-566):** `build_router` регистрирует `Arc<RelayServer>` на ALPN `aira/1/relay` (`protocol.rs:182-188`, `endpoint.rs:61`, `relay.rs:231`) без аутентификации и без глобального cap → **каждый клиент беты становится открытым mailbox-relay** с 10-MB коробками по запросу любого EndpointId (удалённое исчерпание памяти). Убрать `RelayServer` из `build_router` и ALPN RELAY из `all_alpns` в M19, не ждать M21.

**Остальные находки:**
- HIGH — `Retrieve` v1 отдаёт всю коробку одним кадром; > 256 KB → стрим рвётся (`relay.rs:268-274`, `connection.rs:22,33-38`). → M19 п.10: **без** fallback на `aira/1/relay` до M21 (только pending + прямая доставка, `DeliveryState::Queued` честно в UI); M21 — `Retrieve{after_seq, limit}`, ответ ≤ MAX_FRAME_SIZE.
- HIGH — файлы ≥ 1 MB через iroh-blobs открытым содержимым под классическим TLS iroh (`blobs.rs:74-79`, `protocol.rs:190-192`): не PQ-защищены, blob доступен любому с хэшем. → M19a: per-file ключ из ratchet (`aira/file/key/v2`), blob = ciphertext; минимум — оговорка в THREAT_MODEL/PRIVACY (M23).
- HIGH — выбор REALITY/obfs4/Tor в GUI/CLI при неизменном трафике. → M19b: `SetTransportMode ≠ direct` → `Error("not supported")`, скрыть в UI.
- HIGH — DPI-транспорты: удалить модули, фичи и optional-deps (reqwest, rustls, tokio-rustls, webpki-roots, rcgen, tokio-socks), `tests/dpi_simulator.rs`; spec §11A → таблица статусов, §11A.6 → `unstable-custom-transports` (датаграммный CustomTransport iroh 1.1). DPI-история беты = iroh-relay по WSS:443 на своём домене (M20). → M19b.
- MEDIUM — нет ни одного таймаута (connect, `read_framed`, `RelayClient::request`, ответ на handshake: `endpoint.rs:115-124`, `connection.rs:51-72`, `relay.rs:361-380`, `protocol.rs:158`). → M19: 5 с / 30 с / 10 с.
- MEDIUM — `read_framed` выделяет 256 KB по заголовку (128 стримов × 256 KB = 32 MB/соединение), QUIC-лимиты §11B.3 не выставлены, соединения не ограничены (`connection.rs:59-66`, `endpoint.rs:17-23,68-73`). → M19 (инкрементальное выделение, 16/32 стрима, окна 256/64 KB, idle 30 с), M22 (`EndpointHooks` iroh 1.1 для tiers).
- MEDIUM — identity ↔ EndpointId не связаны: подпись handshake не покрывает EndpointId (`handshake.rs:316-336`, `protocol.rs:26-31`). → M19a: EndpointId обеих сторон в подписываемые данные; M19: отбрасывать `Encrypted` от EndpointId без сессии до decrypt.
- MEDIUM — Ack по ratchet-counter в одной коробке на два направления удаляет чужие конверты (`relay.rs:285-291`). → закрыто дизайном v2.
- MEDIUM — `MemStore`: файл целиком в память до 4 GiB, temp-теги `forget` → рост памяти; приёмной стороны файлов нет (`blobs.rs:70,86,103`). → M19: `FsStore` + приём по хэшу из `FileStart` + `FileAck`.
- LOW — `InvitationLink` без версии/подписи/fingerprint/срока, `endpoint_addr_bytes` никем не заполняется, ≈2,8 KB текстом не влезает в QR. → M19b: version/fingerprint_hint/expires_at/подпись, QR в byte-mode (postcard).

**Правки планов:** M18 п.3 (объём), M19 п.7 (без RelayServer), M19 п.10 (без fallback v1), M19a (ALPN `aira/2/*`, `Message::Ack{counter}` — без него dequeue-после-ack невозможен, EndpointId в подпись, одна константа размера конверта, per-file ключ), M19 (таймауты, лимиты, FsStore, gate по EndpointId), M19b (транспорты/UI/QR), M20 п.6 (сигнатура `AiraPreset { relays, relay_auth_token, pkarr_relay, dns_origin, publish_direct_addrs, n0_fallback }` + `NetConfig` + `bind_with`, `publish_direct_addrs = false` по умолчанию, тест с `iroh::test_utils::run_relay_server`), M21 п.3 (пагинация, удалить `aira/relay/mailbox/v1` из KEY_CONTEXTS:74), M22 (`EndpointHooks`, keyed RateLimiter).

**Решения владельца:** (1) шифровать файлы ≥ 1 MB per-file ключом в M19a (1–2 дня) или бета с оговоркой; (2) transport/\* удалить из main или в ветку `experimental/transports`; (3) `publish_direct_addrs` — публиковать прямые IP клиентов в pkarr (быстрее, но IP виден всем, кто знает EndpointId) — предлагаемый дефолт для беты `false`; (4) оставлять ли CI-job `cargo check -p aira-net --all-features`, если транспорты не удаляются.

### 8.3 Тесты и фаззинг (`test-coverage-audit.md`, raw `raw/a2593b8a7011c8976.json`)

**Итог.** 500 тест-функций (core 130, net 104, storage 84, daemon 53, cli 69, gui 40, ffi 9, bot 11), но **65 из них (13 %) никогда не выполняются в CI**: 45 тестов DPI-транспортов за feature-гейтами (`default = []`) и 17 тестов крипто-бэкендов aws-lc (`fips`/`compat-test`) — `ci.yml:53` запускает `cargo test --workspace` без `--all-features` вопреки spec §17; ещё 3 keychain-теста под `#[ignore]`. Из четырёх обязательных требований `rules/testing.md` полностью выполнено одно (unit-тесты). Хорошая новость: тесты aira-net не зависят от публичных relay n0 (`bind_for_test` → `empty_builder` = `RelayMode::Disabled`), после 30.09.2026 не сломаются; production `bind()` с `presets::N0` не покрыт вообще. С тега v0.3.5 исходники не менялись (6 docs-коммитов) — векторы можно снять в worktree тега.

**Условные блокеры (для M18/M19):**
- **Детерминизм seed → ключи нигде не доказан**: все тесты сравнивают два вызова в одном процессе (`seed.rs:502-512`, `identity.rs:123`, `rustcrypto.rs:129-145`), ни одного known-answer-вектора. Без `crates/aira-core/tests/vectors/v0_3_5.json` M18 не сможет доказать сохранность адресов пользователей (условие M18 шаг 0: «расхождение VK = релиз-блокер»).
- **Фаззинг фактически отсутствует**: `fuzz_parse_message.rs:14-16` не компилируется (нет `postcard` в `fuzz/Cargo.toml:9-11`), корпуса нет, `proptest` объявлен в dev-deps и не использован ни разу. Требование «fuzz для всех парсеров» и M19a п.7 «cargo fuzz в CI» невыполнимы до починки.
- **Сквозной тест уровня демона структурно невозможен**: `ipc.rs` подключён как `mod ipc` в бинарнике (`aira-daemon/src/main.rs:26`), `start_ipc_server` не экспортируется из lib, каталога `crates/aira-daemon/tests` нет. `tests/two_node_chat.rs` доказывает лишь QUIC+ALPN+фрейминг+канал ChatHandler с поддельным ciphertext — без handshake/ratchet/storage/IPC. Зависимость для M19 Phase C п.15 (двухдемонный тест), не учтённая в плане: вынести `ipc.rs` в lib (или крейт `aira-node` из §14.0).

**Остальные находки:**
- HIGH — CI не запускает 62 feature-gated теста (`ci.yml:53`). → M18: `cargo test --workspace --all-features --locked`, clippy с `--all-features`; закладывать время — transport-тесты никогда не бежали.
- MEDIUM — серверный парсер IPC `read_message` (`ipc.rs:18-30`) не вызывается ни одним тестом (тесты :262-323 только `write_*`); `HandshakeHandler::accept` и production `bind()` без тестов. → M19.
- MEDIUM — 5 тестовых модулей сидят на `Platform::Mobile`, который M19 удаляет (`handshake.rs:363`, `identity.rs:118`, `kem.rs:163,193`, `daemon/handler.rs:964`, `ffi/runtime.rs:412-418`); без дешёвого seed каждый тест получит Argon2 256 MB (в FFI — дважды на тест ×9). → M18: `MasterSeed::from_raw([u8;32])` под `cfg(any(test, feature = "test-utils"))`.
- MEDIUM — M19a/M19 Phase A ломают ~40 тестов без фикстур (`Message::Encrypted` в protocol.rs:232, two_node_chat.rs, 9 relay-тестов + relay_offline.rs, `capability_negotiation_intersection` handshake.rs:423, spam.rs:203-240, ratchet.rs:672, ContactInfo-литералы ×7, backup VERSION). → до правок схемы сгенерировать `crates/aira-storage/tests/fixtures/aira-v1.redb` и `backup-v1.aira.enc`, golden-байты `tests/vectors/wire_v2/*.bin`.
- MEDIUM — нет golden-byte тестов ни для одного wire/IPC/storage формата (29 roundtrip в `daemon/types.rs:396-856` через serde-derive, `proto.rs` — 0 тестов): перестановка вариантов enum ломает совместимость молча. → M19a.
- MEDIUM — валидация длины pubkey (M19b п.4) сломает 54 литерала `vec![0x..; 32]` в daemon/ffi/gui/cli/bot. → хелпер `test_pubkey(tag)` (1952 B) в core test-utils.
- MEDIUM — таймерные/слабые тесты: `relay.rs:643-670` (реальный sleep 150 ms), `ffi/runtime.rs:576`, `rustcrypto.rs:195` (`let _` без assert — `kem_invalid_ciphertext_rejected` тавтологичен), `gui/daemon_manager.rs:238` (Ok и Err оба проходят). → M18: `start_paused` + `time::advance`, реальные assert.
- MEDIUM — obfs decoder теряет байт при разрыве 2-байтного заголовка между чтениями (`obfs.rs:270-275`, «we just skip this byte»); неактуально при удалении транспортов (§8.2).
- LOW — `safety.rs` (safety_number) 0 тестов; `cli/src/ipc.rs` 0; `MAX_ENVELOPE_SIZE` в ratchet decrypt не проверяется (ratchet.rs:323); sessions-тесты не используют настоящий `RatchetSnapshot`; `.claude/rules/testing.md:60,83-84` ссылается на несуществующие таргеты `parse_message/parse_group_message`; утечка temp-каталогов; пустой `crates/aira-gui/tests`.

**Правки планов (полный текст — `raw/a2593b8a7011c8976.json` → `plan_changes`):** M18 п.1 — состав `v0_3_5.json` (VK/подпись/EK/DK, derive `aira/identity/0|storage/0|mlkem/0` для фразы abandon×23 art с Desktop-профилем, decaps(dk, ct_fixed), pseudonym_vk_0, contact_id, combine_secrets, link_code, postcard-снапшот сессии с pq_enabled) — снимать в worktree тега; M18 п.7 — починка fuzz (postcard, arbitrary, .gitignore `**/fuzz/target/`, seed-корпус) + CI-джоб `cargo fuzz build`, `MasterSeed::from_raw`, честный `kem_invalid_ciphertext_rejected`; M18 п.8 — `--all-features --locked`; M19a п.7 — конкретные таргеты (fuzz_wire_message, fuzz_handshake, fuzz_ratchet_decrypt с инвариантом «состояние не изменилось при Err», fuzz_ratchet_snapshot, fuzz_sync_batch, fuzz_group_decrypt, fuzz_contact_request; `crates/aira-net/fuzz`: fuzz_invitation_link, fuzz_relay_request, fuzz_framing) и 15 proptest-свойств; M19 Phase A п.0 — фикстуры до миграции; M19 Phase B/C — ipc.rs → lib перед two_daemons.rs, unit-тесты read_message/HandshakeHandler/ConnectionManager; M19b — снять `#[ignore]` с keychain-тестов в Windows/macOS-джобах, `test_pubkey`; M20 — unit-тест AiraPreset + proptest TOML `[network]`; M21 — fuzz RelayRequest v2 в `crates/aira-relay/fuzz`; M22/M23 — CI-матрица ubuntu/windows/macos × stable + msrv 1.91 + fuzz 60 с/таргет + coverage (cargo llvm-cov) как блокирующие.

**Решения владельца:** (1) `MasterSeed::from_raw` под test-utils (рекомендуется) или оставить `Platform::Mobile` только для тестов; (2) коммитить seed-корпус фаззинга в репозиторий (рекомендуется) или только CI-артефакты; (3) Windows+macOS раннеры на каждый PR или только main/теги; (4) если 45 transport-тестов окажутся красными после `--all-features` — чинить в M18 или исключить features из CI до удаления транспортов; (5) должна ли `safety_number` быть симметричной к порядку ключей (safety.rs:39-40); (6) нужны ли дублирующие тесты handler.rs в aira-daemon, если aira-ffi уйдёт из CI вместе с Android-preview.

### 8.4 CI/CD и supply chain (`ci-supply-chain-audit.md`, сводка `raw/2026-09-24-D-summary.md`)

**Итог.** CI на `main` красный с 10.04 и красный сегодня (run 35933020292): Security Audit — **18 уязвимостей** (к 17 из фазы 1 добавился `rustls 0.23.37`, RUSTSEC-2026-0285 от 14.09), Clippy — 2 ошибки от stable 1.98 (`aira-net/src/discovery.rs:155`, `relay.rs:112`; в июле на 1.97 падали три другие строки) — структурная причина: `@stable` без `rust-toolchain.toml` при `pedantic` + `-D warnings`. Из 18 уязвимостей 6 закрываются `cargo update` уже сейчас, 4 — iroh 1.x (M18), 8 — quick-xml ×4 версии в egui/rfd/notify-rust (bump egui 0.36 или ignore со сроком). Supply chain workflow'ов не соответствует ни одному пункту §6.6.5: 0 SHA-пинов, нет `permissions` в ci/android, `contents: write` всем jobs `release.yml` при persisted-токене, и в том же job скачивается и исполняется непроверенный код (`linuxdeploy` `continuous` + plugin из `master`, без checksum); нет `--locked`, релиз с rust-cache, нет Dependabot и schedule-audit. Assets защищены только `.sha256`-сайдкарами того же job — нет `SHA256SUMS`, подписи, attestations, SBOM, cargo-auditable, проверки тег↔версия; релиз всегда «latest» (сломает канал `0.5.0-beta.N`); `if-no-files-found: ignore` + `|| true` скрывают потерю DMG/AppImage; AppImage с ubuntu-24.04 (glibc 2.39) не запустится на «Ubuntu 22.04+» из INSTALL.md. Android: NDK 26.1 (r28c предустановлен на раннере), `cargo-ndk` без версии, Gradle-обёртки нет (системный Gradle 9.7.1 при AGP 8.7.0), `android.yml` не бежал с 10.04 из-за `paths`, а `release` зависит от android — тихая поломка заблокирует desktop-релиз. deny/audit: 9 из 22 ignore-ID указывают на крейты, которых нет в lock, 10 — транзитивные unmaintained, `publish = false` нигде, `[graph]` нет; GHSA-h37v-hp6w-2pp8 (ml-dsa) в RustSec отсутствует — видит только Dependabot. **Новый блокер: нет `LICENSE-MIT`/`LICENSE-APACHE` и README при `license = "MIT OR Apache-2.0"` и двух публичных релизах — до тега v0.4.0 и до заявки в SignPath.**

**Блокеры:** B1 CI-гейты красные (`ci.yml:37,53-62`) → M18; B2 APK не подписан (`release.yml:225-236`, `build.gradle.kts:23-32`, в CI нет keystore/`apksigner`) → M19b; B3 нет LICENSE/README (`Cargo.toml:18`) → M18, до v0.4.0; B4 непроверенный код в релизном job с write-токеном (`release.yml:11-12,127-131`; `checkout@v4` без `persist-credentials: false`) → M18.

**Остальные находки:** HIGH — actions без SHA-пинов (таблица пинов снята `git ls-remote` 24.09) и старые мажоры на Node 20; нет least privilege; нет `--locked`, релиз с кэшем; assets без подписи/attestations/SBOM/auditable/`SHA256SUMS`; релиз без проверок тег↔версия/main/CI, `release.sh` пушит мимо PR, тег v0.3.5 переставлялся; Android-CI (NDK, cargo-ndk, gradlew, `paths`, decoupling от desktop-релиза). MEDIUM — мусор в deny/audit; audit-инструменты компилируются каждый прогон (~7,5 мин) без schedule; только ubuntu, нет MSRV/wasm32/concurrency/timeout; glibc 2.39 vs «22.04+»; плавающие раннеры (`macos-latest` = macOS 26, `LSMinimumSystemVersion 10.13` фикция); тихая потеря артефактов; нет Dependabot. LOW — несуществующие ветки `dev`/`milestone/M10-*` в триггерах, `rust-version` только у aira-gui, versionCode без pre-release, `*.jks` не в .gitignore, архивы без LICENSE.

**Правки планов (полные формулировки — отчёт §9.2; наброски `rust-toolchain.toml`/`ci.yml` v2/`release.yml` v2/`dependabot.yml`/`scorecard.yml` — §8 отчёта):** M18 п.8 → полный список CI-гвардов (toolchain-пин, `--locked`, SHA-пины + Dependabot, permissions/`persist-credentials: false`, schedule, msrv/wasm32/android-check, `cargo update` для 6 записей, решение по quick-xml, чистка deny/audit + `publish = false`, linuxdeploy по тегу + вендоринг plugin, job `verify`, `if-no-files-found: error`, clippy 1.98); M18 п.9 — LICENSE-MIT/APACHE + README до тега v0.4.0, APK из assets v0.4.0 убрать; M19b п.10–11 — environment `android-release`, 4 секрета, `apksigner verify --print-certs`, отпечаток в docs, NDK `28.2.13676358`, `cargo-ndk@4.1.2`, Gradle wrapper 8.11.1 + `setup-gradle@v6`, `android.yml` без `paths`, decoupling, versionCode; M21 п.1 — `aira-relay` в матрице релиза + контейнер ghcr с provenance/SBOM; M23 п.1 — ОС-матрица блокирующая + coverage; M23 п.4 — SLSA **L2** для беты (L3 = reusable workflow к 1.0), `SHA256SUMS` + `attest-build-provenance@v4.2.2`, cargo-auditable, cyclonedx + attest-sbom, контейнер ubuntu:22.04, пин раннеров, без кэша, `SOURCE_DATE_EPOCH`/remap, `environment: release`, draft/prerelease/`make_latest`, minisign, scorecard/harden-runner, INSTALL.md (`gh attestation verify`, Sequoia, glibc); M23 п.3 — CONTRIBUTING/CODEOWNERS/шаблоны; «для 1.0» — reusable workflow (L3), harden-runner block, signed tags.

**Решения владельца (10):** настройки репо (права `GITHUB_TOKEN`, allowed actions, fork-approval, rulesets `main`/`v*`, Dependabot alerts, secret scanning, private vulnerability reporting); бюджет/заявки (Apple $99, SignPath после LICENSE+README, Android developer verification — ключ подписи нужен **до** регистрации; кто хранит keystore и minisign-ключ, офлайн-бэкап ×2); APK в v0.4.0/бете — убрать до подписи (рекомендуется); quick-xml — ignore со сроком или блокировать M18 на egui 0.36; Windows/macOS-раннеры на каждый PR или только main/теги; Linux baseline — контейнер 22.04 или glibc ≥ 2.39; M23 или отдельный «M22-infra»; SLSA L2 для беты, L3 к 1.0; `environment: release` с ручным approve; ветка `dev` — завести или убрать из правил/CI.

### 8.5 Остаток спеки: группы, мультидевайс, Bot API (`spec-remainder-audit.md`, сводка `raw/2026-09-23-E-summary.md`)

**Итог.** Группы §12, мультидевайс §14 и Bot API §17A существуют как криптопримитивы, IPC-запросы и экраны во всех четырёх клиентах, но ни одно не доставляет данные и не готово к бете. Групповые сообщения не шифруются Sender Keys и не имеют wire-типа — `handle_send_group_message` рассылает `PlainPayload::Text` каждому участнику, включая себя (`handler.rs:441-477`); внутри группы нет аутентификации отправителя (любой участник знает chain key любого, `group_proto.rs:54-65`; AEAD без AAD, `group.rs:230-235`); идентификаторы участников несогласованы (псевдоним у создателя vs 1:1-ключ у получателя, control-сообщения адресуются в очередь несуществующего контакта — `handler.rs:373-394,699,725,314-316`); sender-состояния не персистятся — после рестарта повторяется пара (key, nonce) (`group.rs:36,187,219-227`). «Привязка устройства» — локальная запись без синхронизации (`handler.rs:194-225`; `sync.rs` никем не вызывается). Bot SDK — клиент демона пользователя (видит всю переписку), второй демон невозможен (data dir жёсткий), а после wiring бот не получит ни одного текста: демон эмитит сырой UTF-8, CLI ждёт `MessageMeta`, GUI пробует оба, бот — `PlainPayload` (`handler.rs:641,648-651`, `cli/app.rs:399-400`, `gui/state.rs:598-608`, `bot/runner.rs:135-142`). Из §6.x к бете обязательны и сломаны disappearing messages (`expires_at` ставится только в `mark_read`, которого никто не вызывает — `storage/messages.rs:119-123`) и блокировка (`/block` = `RemoveContact`, поле `blocked` нигде не проверяется); `/verify` и ещё шесть CLI-команд — заглушки; i18n (fluent, en/ru, 33 ключа) не подключён ни к одному клиенту. **Рекомендация: в бете 0.5 честно отключить все три подсистемы**, в M19a/M19/M21 оставить только дешёвые резервы (≈ 4 дня), реализацию вынести в M25 (группы v2, 3–4 нед.), M26 (мультидевайс v2, 4–6 нед.), M27 (Bot API v2), M28 (дешёвые фичи §6.x); **M24 — за community relays + onion** (§8.6, §8.7).

**Блокеры плана (править до старта M19):**
- D2 — M19 Phase A п.6 (`spec/18-milestones.md:559-561`): iroh SecretKey «детерминированно из seed» → два устройства = один `EndpointId` в каждом InvitationLink → `aira/iroh/secret/<device_index>`, index 0 (0,5 дня). Согласуется с §8.7: хоп-идентичность — отдельный локальный ключ.
- B2 — три несовместимых формата `MessageReceived.payload`; M19 п.11 переиспользует этот путь как есть → входящие тексты не отобразятся; единый контракт `MessageMeta` по проводу и в IPC.
- D3 (HIGH, до M19b) — `storage/pseudonyms.rs:22-32`: счётчик псевдонимов per-БД → на двух устройствах одинаковые контексты `aira/pseudonym/<n>/*` (нарушение key isolation) — `pseudonym_counter = device_index << 28 | local`.

**Остальные находки:** HIGH G1–G3 (Sender Keys не применяются; нет подписи/AAD; идентификаторы участников), MEDIUM G4–G6 (персистентность FS, ротация §12.5 частична, порядок/dedup — ключ `(group_id, timestamp_micros)` перезаписывает); HIGH D1 (привязка устройства локальна), MEDIUM D4 (handoff ratchet §14.3c несовместим с mailbox v2 — `Register{device_id}` в M21); HIGH B1 (SDK = клиент демона пользователя, нужны `--data-dir/--socket`), MEDIUM B3 (бот сломается после M19b без `ipc.token`); MEDIUM F1/F2 (TTL, block); LOW — биты `Features` спека ≠ код; §6.16.1: неизвестный discriminant postcard = ошибка десериализации, а не `Unknown` — резервировать варианты заранее.

**Правки планов (полный текст — отчёт §6.1/§6.3; 33 правки спеки — §5):** M19a п.1 — резерв `PlainPayload::GroupMessage`, биты GROUPS/MULTIDEVICE, единый список `Features`, plaintext ratchet-конверта = `postcard(MessageMeta)`; M19a п.4 — `SignedPrekeyBundle { device_id, … }`; M19 Phase A п.6 — `aira/iroh/secret/<device_index>`; новый п.7 — раскладка `pseudonym_counter`; M19 Phase B п.9 — групповые запросы → `Error("groups are not available in this beta")`, входящий `GroupControl` → warn + игнор (S1 снимается отключением); п.11 — `MessageReceived { from, message: StoredMessage }`, `mark_read`, `BlockContact/UnblockContact`, `GetSafetyNumber`; Phase C п.16 — удалить (→ M25); M19b — скрыть UI групп/устройств во всех клиентах, убрать CLI-заглушки из справки, `connect_with_token` в aira-bot, `--data-dir/--socket`; M21 п.3 — `Register{…, device_id}`, `Deposit{targets: Vec<(mailbox_id, sig)>, envelope}` ≤ 100 (групповой fan-out хранит тело один раз); M23 — известные ограничения беты; «Пересмотр M9.6/M14–17» — M24–M28 и порядок после беты: M16 → M25 → M17 → (M24 параллельно) → 1.0 → M26 → M28 → M15 → M27 → M14. Спека: версия 0.5, дубликат §13 (`spec/14-groups.md:406-471`) удалить.

**Решения владельца:** (1) группы v2 до 1.0 (+3–4 нед., аудит покроет `group.rs`) или после; (2) подпись групповых конвертов — ML-DSA-65 псевдонимом (3,3 KB/сообщение, PQ) или Ed25519 per sender key (64 Б); (3) мультидевайс — per-device сессии (Sesame) или handoff с арендой (определяет `device_id` в M21 `Register`); (4) бета 0.5 = только минимальные клиенты (egui/CLI)? Tauri до 1.0 или после; (5) Bot API — «SDK для собственного демона» + `--data-dir` (рекомендуется) или §17A «нода со своим seed».

### 8.6 Community relays: standalone aira-relay, relay в клиенте, резервирование (`community-relays.md`)

Постановка владельца (07.09): (1) отдельный standalone `aira-relay` для подъёма на собственном сервере — «чтобы сообщество плодило релеи и повышало отказоустойчивость сети»; (2) при публичном IP клиент сам предлагает «побыть relay» (opt-in); (3) клиент-relay нестабильны → обязательное резервирование.

**Итог (`community-relays.md`, сводка `raw/2026-09-24-F-summary.md`).** Два продукта ложатся в одну архитектуру из трёх ролей — anchor-relay проекта, community-server-relay, client-relay — при трёх условиях, продиктованных iroh 1.2 и прецедентами (Snowflake, SimpleX, chatmail, Nostr): (а) один бинарь `aira-relay` со встроенным iroh-relay (`Server::spawn` + собственный `AccessControl`), mailbox v2, ACME, `/healthz` и регистрацией в подписанном каталоге — вместо двух systemd-юнитов из M20/M21; (б) допуск по общесетевому подписанному токену, проверяемому каждым relay офлайн (в iroh отправитель всегда идёт на home relay получателя, поэтому `shared_token`/`allowlist` для сообщества непригодны); (в) client-relay как «Snowflake для Aira» — только транспорт, без mailbox, self-signed + pin, эфемерная запись через брокер, отдельный процесс и ключ, по умолчанию выключен на мобильных/metered/в строгих странах, с экраном согласия о публикации IP. Ключевое ограничение резервирования: у iroh ровно один home relay на endpoint; при падении — бесконечный backoff и стейл pkarr-запись (`iroh-1.2.0/src/socket/transports/relay/actor.rs:326-354,392-399,910-919`; issue n0-computer/iroh#4476) → резервирование транспорта = watchdog re-home + 2–3 `RelayRef` у контакта; N-of-M применимо только к mailbox (N = 2 у разных операторов, дедуп по `envelope_id`). Новое: `accept_conn_limit/burst` — no-op (подтверждает §8.7); `cert_mode = "Reloading"` есть в 1.2.0 (закрывает вопрос hot-reload из relay-deploy-plan); relay «на голом IP» через Let's Encrypt невозможен (форк `tokio-rustls-acme` знает только `Identifier::Dns`) → только pin через `CaTlsConfig::custom_server_cert_verifier`; push-URL mailbox v2 — единственный outbound/SSRF-вектор relay (инвариант AP-1 из §8.7) → `push_allowlist`. **Согласование с §8.7:** роль `hop` (форвардинг onion-ячеек) по умолчанию у desktop-нод — тема G; opt-in по F остаются роли `relay` (встроенный iroh-relay, нужен сертификат/pin) и `mailbox`.

**Блокеры:** абсолютных нет. Условные: без правок форматов до беты (`RelayRef` в приглашении/контакте, `RelayHello` с классом, заглушка токена, `push_allowlist`) — миграция форматов после релиза; блокер плана «`RelayServer` в каждом клиенте» (§8.2) подтверждён как антипример client-relay.

**Находки:** HIGH — один home relay на endpoint, бесконечный backoff + стейл pkarr → watchdog `home_relay_status` → `remove_relay`/re-home/републикация, регресс-тест (M20/M21/M24a); HIGH — схема допуска: сетевой токен `AiraRelayToken`, офлайн-проверка в `AccessControl` (`iroh-relay-1.2.0/src/server.rs:224-233,256-278,285-310`, `main.rs:160-197`), выдача на anchor `POST /token` (PoW, 24 ч, scope, привязка к EndpointId), `access.http.url → /relay-auth` для stock iroh-relay, denylist в каталоге (M20 заглушка, M22); HIGH — push-URL как SSRF-вектор → `push_allowlist`, без редиректов/приватных диапазонов (M21); HIGH — relay без домена: self-signed + pin в `RelayEntry`/`RelayRef`, поле `ca_tls_config` в `AiraPreset` (M20/M24a); MEDIUM — `accept_conn_limit/burst` no-op → nginx `limit_conn/limit_req` + fail2ban, свой `max_clients` (M20/M21); MEDIUM — список relay в `InvitationLink`/`ContactInfo`/`MailboxConfig` до беты: `RelayRef { url, endpoint_id, class, pin }` ×2–3, правило «разные операторы» (M19b п.4, M21 п.7); MEDIUM — client-relay как отдельный процесс `aira-relay --mode transport`, CI-guard на зависимости daemon/ffi (M24a.2); MEDIUM — один бинарь, в `release.yml` нет musl/aarch64/Docker (M21); MEDIUM — гейт «страна/metered» требует данных, которых у клиента нет → `strict_countries` в каталоге + `X-Aira-Country` из `/token` + локаль, Android — cfg-исключение (M22/M24a.2); LOW — `cert_mode = "Reloading"` (M20), iroh 1.2 (M18), спека: несуществующий `bootstrap/`, §5.3 «signed update», открытый §20 п.2.

**Правки планов (полные — отчёт §8.7):** M18 — `iroh-relay = "1.2"` (feature `server`, только в aira-relay); M19b п.4 — `InvitationLink.relays: Vec<RelayRef>` (2–3) вместе с version/expires/подписью, п.5 — список relay с классом/статусом; M20 — п.2 1.2.0, п.3 вариант B → `cert_mode = "Reloading"`, п.4 no-op лимиты → nginx + fail2ban, `access.shared_token` как заглушка «не секрет», п.6 — relay-список из снапшота каталога, поля `relay_auth_token`/`ca_tls_config`, фича `unstable-net-report`, `home_relay_status` → `NetStatus` + watchdog 30 с, новый п.9 — тест «два `run_relay_server`, kill одного → re-home ≤ 60 с»; M21 — п.1 один бинарь со встроенным iroh-relay, `--mode full|transport|mailbox`, один юнит, `deploy/`, musl + Docker + attestation; п.3 `RelayHello` ← `catalog_class, operator_id, min_client_version`, `envelope_id`, N-of-2; п.5 `max_clients`, accept-лимит, `push_allowlist`; п.7 `MailboxConfig.relays` 2–3 разных операторов, `Retrieve` со всех + дедуп; п.8 тесты Deny/N-of-2/дубликат/push вне allowlist/fuzz токена; п.9 `docs/RELAY.md` v1, `spec/03` §5.1.2 «Роли relay», закрыть `spec/20` п.2; оценка +1 неделя; M22 — п.3 из «опционально» в обязательное (`POST /token`, `AiraAccess`, `/relay-auth`, denylist), `strict_countries` + `X-Aira-Country`; M23 — «что видит оператор relay» в PRIVACY.md/THREAT_MODEL, INSTALL.md → RELAY.md, release notes; **M24a.1** каталог (формат/подпись ML-DSA-65/раздача/брокер client-записей/active-checks/классы), `register/withdraw/doctor`, `.well-known/aira-relay.json`, клиентский health-score + pin-верификатор + правило разных операторов (2–3 нед.); **M24a.2** роли `relay`/`mailbox` в клиенте поверх дефолтной `hop` (детектор кандидата, `POST /probe` с двух anchor, супервизор дочернего процесса, лимиты, экран согласия, гейты metered/страна/Android, CI-guard) (≈ 3 нед.); плюс ≈ 3–4 недели сверх M21 на standalone-продукт (Docker/musl, `init/doctor/register`, `docs/RELAY.md`).

**Решения владельца (10):** кто подписывает каталог (один офлайн-ключ ML-DSA-65 или 2-of-3; автоподпись client-брокера делегированным ключом); поддомены операторов `<id>.r.<domain>` (нужен DNS-сервис с API) или «свой домен либо IP + pin»; mailbox в client-relay — нет (подтвердить); client-relay как home relay только opt-in/при блокировке anchor; override гейта строгих стран через Advanced с предупреждением; ключ токенов Ed25519 или ML-DSA-65; открытые relay (`access = "everyone"`) в каталог не пускать; абьюз-контакт и юридический раздел RELAY.md («не exit», аналогия Tor bridge); Android исключён из relay-режима; бюджет второго anchor-VPS и `relays.<domain>` (каталог/токены/проба) до беты.

### 8.7 Скрытие IP и защита от паразитного прокси при участии всех пиров (`onion-antiabuse.md`)

Постановка владельца (23.09): протокол нельзя превратить в паразитирующий прокси (слив чужого трафика через relay, exit в интернет, mailbox как хранилище, чужой трафик с IP пользователя); IP скрывать от собеседника, оператора relay, провайдера/DPI и глобального наблюдателя; свой onion-слой поверх aira-relay; **задействовать всех пиров**, а не только opt-in; «если список relay известен, РКН заблочит их влёт».

**Итог.** «Все форвардят» и «нет паразитов» — не компромисс, а одно требование. Паразитный прокси возникает от четырёх свойств сети (выход в интернет; хоп соединяется с адресом из пакета; большие нетарифицированные кадры; форвардеров мало относительно потребителей), а не от того, кто форвардит. Семь инвариантов AP-1…AP-7 (нет exit; следующий хоп только из своей таблицы; ячейки 1 KB фиксированные; каждый байт под PoW-ключом с бюджетом; хоп никогда не источник; хранилище только по регистрации; ёмкость растёт с нагрузкой — I2P-модель с 2003 г.) закрывают все четыре сценария при любом составе форвардеров. Ограничения роли хопа — только по классу устройства (мобильные — клиент; ноутбук на батарее — share ×0.25; desktop unmetered — **хоп по умолчанию**, opt-out) и юрисдикции (hidden mode для strict-стран, как в I2P). Против блок-листа: глобального каталога нет — точки входа идут через invitation link, E2E-канал контактов (friend-bridges — darknet Hyphanet) и rate-limited peer exchange; «все пиры форвардят, но не все перечислимы». Слово «невзламываемый» не употреблять — таблица обещаний по четырём наблюдателям в §1 отчёта.

**Дизайн Aira Onion v1 (§5 отчёта):** две iroh-идентичности (чат — из seed, хоп — локальный RNG; иначе контакт находит ваш IP в записях хопов); `NodeRecord` с гибридными KEM-ключами хопа; `HopSetup` раз в сутки на хоп (X25519 + ML-KEM-768 через `kem.rs::hybrid_encaps` — постквантово, как Outfox/Nym WPES'25, но без KEM в каждом пакете) + адаптивный PoW (`spam.rs`, Tor hspow) + бюджет 8 MB/24 ч и 16 KB/s на ключ; share ноды 32 KB/s и 3 GB/мес; ячейка 1 280 B (3 слоя × 80 + 1 024 + тег); маршрут S→G_s→M_s→**H**←M_r←G_r←R, где H — mailbox v2 (композиция SimpleX 2-hop и Veilid safety/private route); ответы по обратному состоянию 30 с, push по SURB; профили fast / standard / mix (Loopix: Poisson-задержки + cover-петли ≈ 1,7 GB/мес, только desktop); файлы ≤ 10 MB через «медленную полосу» с PoW-марками, крупнее — direct с предупреждением. Обфускация первого хопа — датаграммный `CustomTransport` iroh 1.2 (`socket/transports/custom.rs:24`), а не байтовые обёртки `transport/*` (которые удаляются по §8.2).

**Находки по коду/планам:** HIGH — `AiraEndpoint::bind` всегда с IP-транспортами и hole punching (`endpoint.rs:56-95`), режима relay-only нет; iroh 1.2 даёт `clear_ip_transports()` (`endpoint.rs:510`) → `NetConfig.hide_ip`, дефолт true (решение владельца); HIGH — план M19b п.12 / net-audit §3 кладёт `postcard(ep.addr())` в invitation link, а `Endpoint::addr()` содержит LAN- и публичные IP (`endpoint.rs:1207`, `endpoint_addr.rs:42-62`) → ссылка = `EndpointAddr::new(id).with_relay_url(url)`; MEDIUM — `net_report` шлёт пробы до 5 relay из RelayMap (`net_report.rs:497-505`) → RelayMap клиента = свои 1–2 relay, каталог сообщества отдельно; MEDIUM — mailbox видит IP/EndpointId депозитора (`relay.rs:214-263`, §4.3) → v2 принимает депозит от хопа с подписью sender внутри; MEDIUM (план) — `accept_conn_limit/burst` в iroh-relay 1.2 «not currently implemented» (`server.rs:486-500`) → M20 п.4: только `client.rx`, лимит соединений на nginx/`AccessControl::on_connect`; MEDIUM — ALPN `aira/*` и TLS-параметры читаются из QUIC Initial (RFC 9001), ТСПУ фингерпринтит QUIC v1; LOW — iroh-relay пишет IP клиента в `info_span` (`http_server.rs:499`) → `RUST_LOG=warn`; INFO — iroh 1.2.0 вышла 09.09.2026 → M18 `iroh = "1.2"`. Проверено: pkarr по умолчанию IP не публикует (`AddrFilter::relay_only`).

**Правки планов:** M18 (1.2); M19 Phase A п.1 (`ContactInfo.mailboxes` без IP) и п.6 (хоп-идентичность не из seed); M19 Phase B п.7 (`bind_with(NetConfig { hide_ip })`) и п.12 (ссылка без IP, тест «нет `TransportAddr::Ip`»); M19b (превью ссылок opt-in при `hide_ip`, экран Network); M20 п.4/п.6; M21 п.3/п.5 (депозит от хопа, лимиты по `sender_pk`, storage budget, `surb_stock`); M22 (общая адаптивная сложность и `slot` для `ContactRequest`/intro/`HopSetup`); M23 (формулировки THREAT_MODEL из §1 отчёта); новые **M24b Aira Onion v1 (4–6 нед., до 1.0)**, **M24c мосты и обфускация (2–3 нед., до 1.0 для strict-стран)**, **M24d mix-профиль (2 нед., после 1.0)**; M24a — community relays (§8.6). Спека: новый §5.5 «Aira Onion», §11 (onion → M24b), §11A (профили вместо режимов), §11B.5 (бюджеты хопов), §6.22 (файлы по профилям), KEY_CONTEXTS (`aira/hop/*`, `aira/bridge/obfs/v1`).

**Решения владельца (10, §9 отчёта):** `hide_ip = true` в бете; второй `Endpoint` под хоп; strict-список стран и авто-hidden; мобильные — только клиент; профиль по умолчанию standard; файлы в hidden-профиле; дефолты share; M24b до 1.0; имя фичи; заменить «невзламываемый» таблицей обещаний.
