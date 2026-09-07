# aira-core — результат аудита кода (2026-09-07, HEAD 971e038)

> Источник: raw `raw/a1dd76fc4df1828ce.json`. Выжимка — в `../release-audit-2026-09.md` §2.5.

## Scope

Аудит crates/aira-core (7995 строк, HEAD 971e038, workspace 0.3.5) + сквозные grep по aira-net/aira-storage/aira-daemon/aira-ffi. Только Read/Grep/Glob, cargo не запускался. Пункты (a)–(j) из задания. Факты о крейтах взяты из scratchpad/facts-crates.md, блокер №0 (демон без сети) уже зафиксирован в .claude/docs/release-audit-2026-09.md §0 — здесь дополнен аспектами aira-core.

## Резюме

Криптопримитивы в aira-core качественные (нет unwrap/unsafe в prod-путях, ключи zeroize-ятся, KDF-контексты уникальны), но протокольный слой к релизу не готов: (1) Triple Ratchet — по факту Double Ratchet: PQ-шаг не может стартовать (peer_pq_ek никогда не устанавливается), а если бы стартовал — ломает сессию (получатель обрабатывает pq_kem_ct только при смене DH-ключа); PQ-keypair'ы детерминированно выводятся из root_key → нет PQ post-compromise security; заголовок ratchet не аутентифицирован (нет AAD) и состояние мутируется до проверки AEAD → DoS-десинхронизация одним битым пакетом; ни одного теста с pq_enabled=true. (2) Handshake — не PQXDH: одна ephemeral-ephemeral X25519 + статический ML-KEM-ключ из seed (нет PQ forward secrecy при компрометации seed), подписи не покрывают идентичность пира и транскрипт → identity misbinding/UKS, HandshakeInit полностью replayable. (3) Wire-формат Message::Encrypted не содержит MessageHeader → ratchet физически не может быть подключён без изменения proto. (4) spam.rs: PoW-верификатор доверяет difficulty из самого запроса (difficulty=0 проходит), PoW не привязан к получателю/времени; весь spam.rs и RateLimiter не используются нигде. (5) Расхождения KEY_CONTEXTS.md: контекст aira/device/id-from-code (daemon/handler.rs:200) не задокументирован; combiner context "aira/hybrid-kem/v1" vs спека "aira/hybrid-kem/1", counter BE vs спека LE. (6) Argon2: Android FFI использует Desktop-профиль 256 MB; Mobile-профиль с другой солью даёт другой seed из той же фразы. (7) Миграция ml-dsa 0.1.1/ml-kem 0.3.2 затрагивает rustcrypto.rs целиком + awslc.rs:129-134 (тоже ml_kem для детерминированного keygen). Тесты: core 130 #[test] (в т.ч. 18 в compat_tests за feature), proptest объявлен, но proptest! не используется ни разу; fuzz — 2 таргета в crates/aira-core/fuzz (handshake/ratchet/group не фаззятся).

## Что реализовано

| Качество | Что | Evidence | Примечание |
|---|---|---|---|
| works-but-rough | (a) Double Ratchet: chain/DH ratchet, skipped keys, MAX_SKIP, лимит envelope | crates/aira-core/src/ratchet.rs:27 MAX_SKIP=1000; :33 MAX_ENVELOPE_SIZE=65536 (проверка :290); :57-61 chain_ratchet; :93-101 dh_ratchet; :536-560 skip_message_keys (skipped HashMap :116); тесты :607-756 out_of_order_delivery, max_skip_dos_protection, many_messages_with_direction_changes | Все 9 тестов используют new_classical (pq_enabled=false). Заголовок не аутентифицирован (aead_encrypt без AAD, :75-80), состояние мутируется до AEAD-проверки (:297-323). |
| stub | (a) PQ (ML-KEM) шаг ratchet — SPQR | ratchet.rs:30 PQ_RATCHET_INTERVAL=50; :330-332 should_pq_step требует peer_pq_ek.is_some(); peer_pq_ek устанавливается только в store_peer_pq_ek (:357-362), вызываемом из decrypt только при header.pq_kem_ek (:305), который генерируется только в pq_ratchet_send (:335-352), требующем peer_pq_ek → цикл; никакого set_peer_pq_ek нет (grep peer_pq_ek по workspace: только ratchet.rs и tests/multidevice.rs:87 с фейковыми 64 байтами) | Мёртвая ветка: PQ-шаг никогда не стартует. Кроме того, pq_kem_ct обрабатывается только внутри блока need_dh_ratchet (:297-306), а отправитель может приложить его без смены DH → root_key разъедется. |
| works-but-rough | (b) Handshake + capability negotiation | handshake.rs:74-88 Initiator::new (x25519_sk из aira/x25519/0, mlkem из aira/mlkem/0 — статические); :97-126 start() подписывает identity_pk\|\|kem_ek\|\|x25519_pk\|\|caps; :135-171 finish(); :204-262 respond(); :270-284 negotiate_capabilities (min/max version, features &); тесты :353-453 (4 теста) | Не PQXDH (см. findings): один ephemeral DH, статический KEM-ключ, подписи без binding к пиру/транскрипту, нет replay-защиты. Фрагментация §4.5.1 не реализована ни в core, ни в aira-net (grep fragment — только spec). |
| production | (c) Hybrid KEM combiner | kem.rs:23 HYBRID_KEM_CONTEXT="aira/hybrid-kem/v1"; combine_secrets :85-105: counter(1u32 BE) \|\| BLAKE3(x25519_ss) \|\| BLAKE3(mlkem_ss) \|\| x25519_ct \|\| mlkem_ct → blake3::derive_key | Соответствует spec/02-crypto.md:35-44 по структуре; расхождения: контекст "aira/hybrid-kem/1" в спеке vs "v1" в коде, counter LE в спеке vs to_be_bytes() в коде. ML-KEM ek в KDF не входит (X-Wing включает pk) — допустимо для IND-CCA, но нет MAL-BIND-K-PK. |
| works-but-rough | (d) Key isolation / KDF-контексты | grep '"aira/' по crates (non-test): 30 контекстов; docs/KEY_CONTEXTS.md перечисляет 30; все ratchet/session/kem/identity/device/group/reality/obfs/relay контексты совпадают | Расхождение: aira/device/id-from-code (crates/aira-daemon/src/handler.rs:200) отсутствует в docs/KEY_CONTEXTS.md. ML-DSA подписи с пустым context (rustcrypto.rs:30 sign_deterministic(msg, &[])) — identity-ключ подписывает init и ack без доменного префикса (различимы только по длине полей). |
| works-but-rough | (e) Seed / Argon2id | seed.rs:28-36: Desktop m=262144 KiB (256 MB), t=3, p=4, salt "aira-master-v1-m256"; Mobile m=65536 (64 MB), t=4, p=4, salt "aira-master-v1-m64"; from_phrase() :89 → Desktop; derive() :148 blake3::derive_key | Platform::Mobile в prod не используется (grep: только тесты handshake.rs:363, identity.rs:118, kem.rs:163,193, daemon/handler.rs:964). aira-ffi/src/runtime.rs:65 (Android) вызывает from_phrase → 256 MB Argon2 на телефоне. Разные соли → одна фраза даёт РАЗНЫЕ identity на Desktop/Mobile — если когда-либо включить Mobile, мультидевайс сломается. |
| stub | (f) spam.rs: PoW + RateLimiter + ContactRequest | spam.rs: POW_DIFFICULTY_BITS=20; ContactRequest{from,message,pow_nonce,pow_difficulty,signature}; verify_pow использует self.pow_difficulty; RateLimiter.check per_key/global/banned; grep solve_pow/verify_pow/RateLimiter/ContactRequest по workspace вне spam.rs — 0 использований (aira-net/src/ratelimit.rs — отдельный governor-лимитер по PeerTier) | Не подключён нигде. ContactRequest.signature никогда не проверяется (нет verify в spam.rs). PoW при создании первого ключа (тема 3 владельца) отсутствует вообще. |
| production | (g) unwrap/expect/panic/unsafe в non-test коде core/net/storage/daemon | awk-скан до первого #[cfg(test)] во всех src/*.rs: aira-core/src/i18n.rs:179 expect("en is valid") на константе; aira-net/src/discovery.rs:182 unsafe from_utf8_unchecked с // SAFETY (:181); aira-net/src/ratelimit.rs:29,34 expect("nonzero") на константах; aira-net/src/transport/tor.rs:74 expect на константном адресе; crypto/compat_tests.rs:23-153 — 18 expect, но модуль за #[cfg(feature="compat-test")] (crypto/mod.rs:12) | Паник на внешних данных нет; unimplemented!/todo!/unreachable! — 0. |
| works-but-rough | (h) Zeroize / constant-time | SessionKeys поля Zeroizing (handshake.rs:36-44); MasterSeed #[derive(ZeroizeOnDrop)] (seed.rs:75); RatchetSession/RatchetSnapshot Drop с zeroize (ratchet.rs:148-162, 563-573); kem combine_secrets kdf_input Zeroizing (kem.rs:95); subtle в Cargo.toml (crates/aira-core/Cargo.toml:38), но grep ct_eq по aira-core/src — 0 | MAC-сравнений вручную нет (AEAD через chacha20poly1305 — constant-time внутри). Но: device.rs:234,240 verify_link_code сравнивает 6-значный код через String == (не ct); group.rs:174 stored_nonce != *nonce; send_dh_secret (StaticSecret) в RatchetSession не zeroize-ится явно в Drop (:563-573) — x25519-dalek zeroize-ит сам при feature zeroize; pq_mlkem_dk (ml-kem DecapsulationKey) в Drop не затирается. |
| works-but-rough | (i) crypto/rustcrypto.rs — текущее ml-dsa/ml-kem API | rustcrypto.rs:4 use ml_dsa::{signature::Verifier, KeyGen, MlDsa65, Signature}; :5-8 ml_kem::{kem::{Decapsulate,Encapsulate}, KemCore, MlKem768}; :21-22 ml_dsa::B32 + MlDsa65::key_gen_internal(&seed); :29-30 sign_deterministic(msg,&[]); :36 Signature::try_from; :51-55 blake3 d/z → MlKem768::generate_deterministic(&d,&z); :75-99 EncodedVerifyingKey/EncodedSizeUser/Encoded::<..>; awslc.rs:129-134 тоже ml_kem::{EncodedSizeUser,KemCore,MlKem768}::generate_deterministic для FIPS-провайдера | Для 0.1.1/0.3.2 менять: KeyGen/key_gen_internal → SigningKey::<MlDsa65>::from_seed(&Seed); sign_deterministic(msg,&[]) → signature::Signer::try_sign (детерминированный по умолчанию); Signature::try_from → SignatureEncoding/TryFrom<&[u8]>; KemCore/generate_deterministic → 64-байтный Seed (d‖z) — совпадает с текущей схемой d/z из blake3, но проверить порядок; EncodedSizeUser/Encoded → новые типы DecapsulationKey768/EncapsulationKey768 + KeyEncoding-замена; в awslc.rs то же место keygen. handshake.rs:82,195 — вывод типов. Feature `deterministic` в ml-kem 0.3 удалена (facts B). |
| works-but-rough | (j) Тесты / proptest / fuzz | grep '#[test]': aira-core 130 (из них 18 в crypto/compat_tests.rs за feature), aira-net 62+42 tokio, aira-storage 84, aira-daemon 38+15 tokio; proptest = "1" в crates/aira-core/Cargo.toml:49, grep proptest! в aira-core/src — 0; fuzz: crates/aira-core/fuzz/fuzz_targets/fuzz_parse_message.rs (PlainPayload, EncryptedEnvelope) и fuzz_decode_keys.rs (decode_verifying_key/kem keys); корневой fuzz/ отсутствует | Не фаззятся: postcard::from_bytes::<Message> (весь wire enum, вкл. HandshakeInit/Ack), GroupControl/GroupMessage, RatchetSnapshot, aira-net read_framed. Нет теста ratchet с pq_enabled=true, нет теста replay/downgrade handshake. |

## Находки

### [blocker] Ratchet и handshake не подключены к wire-формату: Message::Encrypted не несёт MessageHeader

- **Evidence:** crates/aira-core/src/proto.rs:11-19 enum Message { Handshake, HandshakeAck, Encrypted(EncryptedEnvelope), ... }; EncryptedEnvelope :23-29 = {nonce, counter, ciphertext} — нет dh_public/prev_chain_len/pq_kem_ct/pq_kem_ek из ratchet.rs:40-52 MessageHeader. grep MessageHeader/RatchetSession по workspace вне ratchet.rs: только tests/multidevice.rs. Демон: crates/aira-daemon/src/main.rs:120-204 поднимает только IPC/TTL/dedup (уже зафиксировано в .claude/docs/release-audit-2026-09.md §0).
- **Impact:** Даже после подключения демона к aira-net получатель не сможет вызвать RatchetSession::decrypt — заголовок не передаётся. Сообщения физически не шифруются E2E; pending_messages хранит plaintext postcard (handler.rs:299-301). Релиз как «PQ-мессенджер» невозможен.
- **Recommendation:** Расширить EncryptedEnvelope (или ввести Message::Ratchet{header, envelope}) с полями MessageHeader; header включить в AAD (см. следующий finding); добавить fuzz-таргет на Message; версионировать формат (spec/05-protocol-versioning.md).

### [blocker] Заголовок ratchet не аутентифицирован и состояние мутируется до проверки AEAD — DoS-десинхронизация одним пакетом

- **Evidence:** ratchet.rs:75-80 aead_encrypt(key, nonce, plaintext) без AAD; decrypt :297-323: skip_message_keys, pq_ratchet_recv, store_peer_pq_ek, dh_ratchet_step, advance recv_chain выполняются ДО aead_decrypt (:322) и не откатываются при ошибке.
- **Impact:** Активный атакующий (или любой, кто может подать пакет от имени пира — sender в ChatHandler это iroh EndpointId, не ML-DSA identity: aira-net/src/protocol.rs:28,85) отправляет header с чужим dh_public → dh_ratchet_step переписывает root/chain keys, AEAD падает, но сессия уже необратимо разошлась; подмена pq_kem_ek подсовывает ключ атакующего в peer_pq_ek.
- **Recommendation:** Как в Signal DR: header как associated data (Payload{msg, aad}); все изменения делать на клоне состояния и коммитить только после успешного decrypt; тест «битый header не меняет состояние».

### [high] PQ-шаг ratchet никогда не стартует (chicken-and-egg) и при старте сломал бы сессию — «Triple Ratchet» по факту Double Ratchet

- **Evidence:** ratchet.rs:330-332 should_pq_step требует peer_pq_ek.is_some(); peer_pq_ek заполняется только store_peer_pq_ek (:357-362) ← decrypt при header.pq_kem_ek (:305) ← encrypt только если pq_ratchet_send (:335-352) ← should_pq_step. Начальный ek пира из handshake в RatchetSession::new (:205-244) не передаётся (peer_pq_ek: None, :241). Получатель обрабатывает pq_kem_ct только внутри if need_dh_ratchet (:297-306), а отправитель прикладывает ct на 50-м сообщении без смены DH (:275-279). Тесты :600-756 — все new_classical.
- **Impact:** Заявленная PQ-защита ratchet (spec §4.4, README) не работает; HNDL-стойкость держится только на статическом ML-KEM в handshake (см. ниже). Ни один тест не покрывает pq_enabled=true.
- **Recommendation:** Передавать peer ML-KEM ek из HandshakeInit/Ack в RatchetSession::new; обрабатывать pq_kem_ct/ek в decrypt независимо от need_dh_ratchet (по флагу в header, с dedup); добавить тесты 100+ сообщений с pq_enabled=true в обе стороны и snapshot после PQ-шага.

### [high] PQ-keypair'ы ratchet детерминированно выводятся из root_key — нет post-compromise security от PQ-шага; оба пира генерируют одинаковый keypair

- **Evidence:** ratchet.rs:216-218 seed = derive_key("aira/ratchet/pq-init", &root_key) → kem_keygen (root_key одинаков у обоих → dk/ek идентичны у Alice и Bob); :345-346 "aira/ratchet/pq-rekey" из self.root_key.
- **Impact:** Атакующий, знающий состояние (root_key) в момент rekey, вычисляет dk и декапсулирует все последующие pq_kem_ct из заголовков → PQ-ratchet не «лечит» компрометацию (цель SPQR). Единственная свежесть — рандом encapsulate у отправителя.
- **Recommendation:** Генерировать ML-KEM keypair из OS RNG (как X25519 в dh_ratchet_step :375-376); root_key использовать только для KDF-миксинга.

### [high] Handshake — не PQXDH: статический ML-KEM-ключ из seed (нет PQ forward secrecy), одна ephemeral DH, статический X25519 не используется

- **Evidence:** handshake.rs:77-78,190-191: kem_seed = seed.derive("aira/mlkem/0") → тот же ML-KEM keypair на все handshake; x25519_sk хранится как _x25519_sk (:57,177) и не участвует; DH только eph×eph (:150-152, :226-230). Спека spec/02-crypto.md:152-163 говорит «Ephemeral_KEM_CT», §4.5 «адаптация PQXDH».
- **Impact:** Компрометация seed + квантовый компьютер = расшифровка всех прошлых сессий по записанному трафику (нет PQ-FS); классический FS есть. Также нет KCI-защиты (identity не участвует в KDF). Расхождение спека/код.
- **Recommendation:** Ephemeral ML-KEM keypair на каждый handshake (initiator генерирует свежий ek, ключ живёт до finish); опционально semi-static signed prekey для асинхронного старта через relay (тема 2). Включить identity_pk обоих + все публичные значения в derive_session_keys.

### [high] Подписи handshake не связывают идентичность пира и транскрипт → identity misbinding (UKS) и replay HandshakeInit

- **Evidence:** handshake.rs:105-118 init подписывает только свои поля; :242-247 ack подписывает только свои поля (без init.x25519_pk/kem_ek/identity_pk); derive_session_keys :297-311 — из combined без identity; нет nonce/timestamp в HandshakeInit (proto.rs:156-162).
- **Impact:** Мэллори переподписывает чужой HandshakeInit своим identity (публичные поля копирует) → Bob считает, что говорит с Мэллори, Alice — что с Bob'ом, ключи совпадают (классический UKS на SIGMA без binding). Старый HandshakeInit можно проиграть повторно.
- **Recommendation:** SIGMA-стиль: подпись ack над транскриптом (init‖ack), включить identity_pk обоих в KDF-вход, добавить nonce инициатора в ack-подпись; тест на replay и на подмену identity_pk.

### [high] spam.rs PoW: difficulty берётся из самого запроса, PoW не привязан к получателю/времени; ContactRequest.signature не проверяется; модуль не используется

- **Evidence:** spam.rs: ContactRequest::verify_pow → verify_pow(bytes, nonce, self.pow_difficulty) — верификатор не сравнивает с POW_DIFFICULTY_BITS; to_pow_bytes = from||message||difficulty (нет recipient, timestamp, nonce relay); поля signature нигде не verify; grep по workspace — 0 использований spam::*.
- **Impact:** Для темы 3 (PoW против ботов) текущий код бесполезен: difficulty=0 проходит, одно решение переиспользуется против всех получателей бесконечно; 20 бит blake3 ≈ 1M хешей (<1 c на десктопе) — не «ресурсоёмко».
- **Recommendation:** Верификатор: require pow_difficulty >= min; PoW над relay_nonce‖recipient_pk‖from‖timestamp; проверять ML-DSA подпись ContactRequest; для «PoW при создании ключа» — отдельный дизайн (например, identity-commitment с Argon2/Equihash-стилем и публикуемым доказательством), в spec/15-spam.md отсутствует. RateLimiter.per_key/banned не ограничены по размеру — bounded LRU.

### [medium] aira/device/id-from-code не задокументирован в docs/KEY_CONTEXTS.md

- **Evidence:** crates/aira-daemon/src/handler.rs:200 blake3::derive_key("aira/device/id-from-code", code.as_bytes()); docs/KEY_CONTEXTS.md — контекста нет (30 задокументированных vs 30 в коде, но набор отличается на этот элемент; aira/1/* — ALPN, не KDF).
- **Impact:** Нарушение правила «все контексты в KEY_CONTEXTS.md» (блок PR по правилам проекта). Плюс device_id выводится из 6-значного кода — 10^6 возможных id, коллизии между устройствами.
- **Recommendation:** Задокументировать или (лучше) выводить device_id через device.rs derive_device_id(seed, index) (device.rs:184).

### [medium] Android FFI использует Desktop-профиль Argon2 (256 MB); Mobile-профиль с другой солью несовместим по identity

- **Evidence:** crates/aira-ffi/src/runtime.rs:65 MasterSeed::from_phrase(...) → seed.rs:89 Platform::Desktop; seed.rs:32,36 разные соли "aira-master-v1-m256"/"aira-master-v1-m64"; Platform::Mobile только в тестах (grep).
- **Impact:** На бюджетных Android 256 MB Argon2 в процессе приложения → OOM-kill / ANR при входе. Если переключить FFI на Mobile — та же фраза даст другой identity, чем на десктопе (мультидевайс/восстановление сломаются).
- **Recommendation:** Единая соль и единые параметры для всех платформ (спека: параметры фиксированы), либо Mobile только в тестах, как сейчас, но с проверкой доступной памяти и понятной ошибкой в FFI; задокументировать в spec/17-cross-platform.md.

### [medium] Fingerprint 64 бит (8 байт BLAKE3) слишком короткий для устной верификации против таргетированного подбора

- **Evidence:** identity.rs:91-100 hash.as_bytes()[..8] → 16 hex; spec/03-network.md:62-64 фиксирует то же и оговаривает «не для добавления».
- **Impact:** Second-preimage 2^64 keygen ML-DSA — дорого, но в пределах nation-state; Signal safety number ~112 бит на сторону. Если fingerprint используется как единственная сверка (CLI /verify), риск подмены при MITM в момент обмена ключами.
- **Recommendation:** ≥ 128 бит (например 30 десятичных групп или 32 hex) в /verify; короткий 8-байтный оставить только как «подсказку» в invitation link.

### [low] Расхождения кода со spec §4.2/§4.5.1

- **Evidence:** kem.rs:23 "aira/hybrid-kem/v1" vs spec/02-crypto.md:37 "aira/hybrid-kem/1"; kem.rs:92 1u32.to_be_bytes() vs spec:43 «32-bit LE»; §4.5.1 (spec/02-crypto.md:166-205) требует chunked handshake ≤1200 B на уровне aira-net — не реализовано (grep fragment/chunk в aira-net — нет).
- **Impact:** Нет interop-последствий (единственная реализация), но спека — источник истины для Sonnet 5. Замечание к §4.5.1: QUIC-стримы не порождают IP-фрагментации (данные режутся по MTU внутри QUIC), требование избыточно; реальная проблема — размер QUIC Initial/TLS, а это iroh.
- **Recommendation:** Привести спеку к коду (контекст, порядок байт) или наоборот; §4.5.1 переписать: полагаться на QUIC-стримы + relay-fallback, chunking убрать.

### [low] Случайные 96-битные nonce с долгоживущим storage-ключом (birthday bound 2^32)

- **Evidence:** crates/aira-storage/src/encrypted.rs:32-33 rand nonce 12 байт под единым ключом aira/storage/0 (storage/lib.rs:121); аналогично sync.rs:144-146.
- **Impact:** После ~2^32 записей вероятность коллизии nonce с ChaCha20-Poly1305 становится значимой; при интенсивной перезаписи (TTL GC, счётчики) достижимо за годы.
- **Recommendation:** XChaCha20-Poly1305 (24-байт nonce) или per-record ключ derive_key(storage_key, record_id).

### [low] verify_link_code сравнивает через String == и не имеет rate-limit; 6-значный код на 5-минутное окно

- **Evidence:** device.rs:209-245 (format!("{:06}", num % 1_000_000), == в :234,240); daemon handler.rs:195 без счётчика попыток.
- **Impact:** Только через локальный IPC-сокет — низкий риск; но модель «код выводится из seed» означает, что верифицирующее устройство уже имеет seed, т.е. link code не переносит секрет — проверить, что это соответствует spec/16-multidevice.md.
- **Recommendation:** subtle::ConstantTimeEq; лимит попыток; уточнить дизайн linking в спеке.

### [low] Drop RatchetSession не затирает ML-KEM decapsulation key и X25519 secret явно

- **Evidence:** ratchet.rs:563-573 zeroize только root_key, send_chain_key, recv_chain_key, skipped; pq_mlkem_dk/send_dh_secret не трогаются (зависит от zeroize-feature в ml-kem/x25519-dalek).
- **Impact:** Секреты могут остаться в куче после освобождения, если у зависимостей не включён feature zeroize.
- **Recommendation:** Проверить features `zeroize` для ml-kem/ml-dsa/x25519-dalek в Cargo.toml; при миграции на ml-kem 0.3 — обернуть dk в Zeroizing-совместимый тип.

### [medium] Тестовое покрытие крипто-протокола: нет proptest, fuzz не покрывает Message/Handshake/Group/Snapshot

- **Evidence:** proptest! в aira-core/src — 0 при зависимости в Cargo.toml:49; fuzz-таргеты только PlainPayload/EncryptedEnvelope и decode_*keys (crates/aira-core/fuzz/fuzz_targets/*.rs); handshake tests :353-453 — 4 теста (нет replay/downgrade PQ_RATCHET); ratchet — 0 тестов с PQ.
- **Impact:** Правила проекта (.claude/rules/testing.md) требуют proptest и fuzz для всех парсеров внешних данных; wire-enum Message с HandshakeInit (Vec<u8> без лимитов) не фаззится.
- **Recommendation:** Добавить fuzz для postcard::from_bytes::<Message>, GroupControl, RatchetSnapshot; proptest padding/ratchet roundtrip; тесты downgrade (features без PQ_RATCHET) и replay.

## Расхождения спека ↔ код

- spec/02-crypto.md §4.4 «Triple Ratchet / SPQR»: код — Double Ratchet с нерабочей PQ-веткой (ratchet.rs:330-362), PQ-keypair'ы из root_key, а не свежие.
- spec/02-crypto.md §4.5 «PQXDH, Ephemeral_KEM_CT»: код — статический ML-KEM из seed aira/mlkem/0 (handshake.rs:78,191), одна eph-eph X25519, статический X25519 не используется.
- spec/02-crypto.md §4.2 combiner: контекст "aira/hybrid-kem/1" и counter LE vs код "aira/hybrid-kem/v1" и BE (kem.rs:23,92).
- spec/02-crypto.md §4.5.1 chunked handshake ≤1200 B: не реализовано; требование технически избыточно для QUIC-стримов.
- spec/04-protocol-wire.md:22,199 «Encrypted = Triple Ratchet»: proto.rs EncryptedEnvelope без ratchet-заголовка; pending_messages хранит plaintext (handler.rs:299-301).
- spec/13-threat-model.md:23 «Спам: PoW 20 бит, rate limiting»: spam.rs не подключён, верификатор доверяет difficulty из запроса; PoW при создании ключа в спеке отсутствует.
- docs/KEY_CONTEXTS.md: нет aira/device/id-from-code (daemon/handler.rs:200).
- spec/17-cross-platform.md / seed.rs: Platform::Mobile «только тесты» — соблюдено, но Android через from_phrase получает 256 MB Argon2.
- spec/18-milestones.md Milestone 1 п.7 «Triple Ratchet» и п.13 «тест деградации» помечены как сделанные, но PQ-режим не покрыт ни одним тестом.

## Открытые вопросы

- Как ML-DSA identity привязывается к iroh EndpointId (ChatHandler.from = EndpointId, protocol.rs:28,85)? Нужна таблица contact_pubkey ↔ EndpointId с проверкой на handshake, иначе sender любого Encrypted-сообщения неаутентифицирован.
- Должен ли responder использовать свой статический/semi-static ML-KEM (для асинхронного старта через relay, тема 2) — тогда нужен signed PQ prekey bundle на relay, как в PQXDH; текущий Responder._mlkem_dk не используется (handshake.rs:178).
- Ожидаемая политика при features без PQ_RATCHET от пира: молча деградировать (new_classical) или отказывать/предупреждать пользователя? Сейчас negotiate_capabilities молча пересекает флаги.
- Где будет PoW «при создании первого ключа» (тема 3): локально (бессмысленно без проверяющей стороны) или как commitment, публикуемый на relay/DHT? В спеке нет; нужно решение владельца до передачи Sonnet 5.
- Соль Argon2 для Android: оставить Desktop-параметры (256 MB) с риском OOM или унифицировать параметры на всех платформах (ломает существующие seed'ы? нет — v0.3.5 демон уже Desktop)?
- Порядок миграции: ml-dsa 0.1.1 заблокирован до iroh 1.1 (facts A) — исправления ratchet/handshake делать на текущих ml-dsa rc/ml-kem 0.2 и потом мигрировать, или сначала мигрировать (rustcrypto.rs + awslc.rs:129-134), потом чинить протокол?
