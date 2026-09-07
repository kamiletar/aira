# aira-net — аудит крейта (2026-09-07, HEAD d001981, v0.3.5)

> Задание B фазы 3 релизного аудита. Главный документ — `../release-audit-2026-09.md` (§3, §4.1a, §4.3, §6.4).
> Не повторяет `daemon-storage-audit.md`, `relay-deploy-plan.md`, `facts-crates.md` — ссылается на них и добавляет новое.
> Метод: прочитаны все 16 модулей `crates/aira-net/src` (5 851 строка) и 3 интеграционных теста целиком; grep по workspace;
> API iroh 0.97.0 / 1.1.0, iroh-blobs 0.99.0 / 0.103.0, noq 0.17.0 сверены по исходникам в `~/.cargo/registry/src`.
> Сборка/тесты не запускались (см. §11). Статус: **завершён** 2026-09-07.

## 0. Резюме

**Что aira-net есть на самом деле.** Из 5 851 строки к реальному пути соединения не подключено ничего: демон и FFI используют только
`blobs::BlobStore` (in-memory, без сети) и `TransportMode::from_str` для валидации строки настроек. `endpoint.rs`/`connection.rs`/`protocol.rs`
(622 строки) — рабочая, но автономная обвязка iroh с 7 сетевыми тестами на loopback; `relay.rs` (669) — mailbox v1 без аутентификации,
подлежащий удалению в M21; `discovery.rs` (330) — формат ссылки без подписи/версии и мёртвый DHT-код; `ratelimit.rs`, `ConnectionManager`,
`PeerTier` — мёртвые; `transport/*` (3 722 строки, 64 % крейта) — шесть реализаций поверх `tokio::io::duplex`, которые не могут быть встроены
в iroh (QUIC/UDP, а не байтовые потоки), выключены фичами в daemon/ffi, не собираются в CI с апреля и криптографически несостоятельны
(obfs без секрета, «REALITY» с открытым 8-байтным префиксом и статическим ключом, mimicry с length-prefix перед фейковым заголовком, CDN/Tor —
заглушки). При этом GUI/CLI позволяют выбрать «REALITY»/«Tor», демон отвечает `Ok` и хранит режим — трафик не меняется.

**Миграция iroh 0.97 → 1.1 для aira-net — 1 строка** (`endpoint.rs:78` `empty_builder()` → `builder(presets::Minimal)`), остальные ~30 точек
API сверены по исходникам 1.1.0 и совпадают; iroh-blobs 0.99 → 0.103 — без правок; вне aira-net iroh никто не использует → пункт M18 п.3
«объём неизвестен» можно закрыть как «не ожидается». Свой relay задать нельзя: `presets::N0` зашит, `bind()` принимает только `SecretKey`;
нужен `AiraPreset` + `NetConfig` + `[network]` в демоне (M20, ≈ 1,5 дня в aira-net).

**Главные находки.**

| Sev | Находка | Где | Исправление | MS |
|---|---|---|---|---|
| BLOCKER (план) | M19 п.7 велит регистрировать `Arc<RelayServer>` в роутере клиента → каждый клиент беты = открытый mailbox-relay без auth, неограниченные 10-MB коробки по запросу любого EndpointId (remote OOM) | `protocol.rs:182-188`, `endpoint.rs:61`, `relay.rs:231`, `spec/18:563-566` | убрать `RelayServer` из `build_router` и ALPN RELAY из `all_alpns` в M19, не ждать M21 | M19 |
| HIGH | `Retrieve` отдаёт всю коробку одним кадром; при > 256 KB `write_framed` рвёт стрим → коробка невыгружаема, ack невозможен; M19 п.10 «fallback через `aira/1/relay` до M21» на этом сломается | `relay.rs:268-274`, `connection.rs:22,33` | v1 из демона не использовать; v2 — пагинация `Retrieve{after_seq,limit}` | M19 (план), M21 |
| HIGH | Файлы ≥ 1 MB идут через iroh-blobs открытым содержимым под классическим TLS iroh; PQ-обещание §11 («harvest now, decrypt later») на файлы не распространяется; blob доступен любому, кто знает хэш, пока жив store | `blobs.rs:74-79`, `protocol.rs:190-192` | per-file ключ из ratchet, blob = ciphertext; минимум — честно в THREAT_MODEL/PRIVACY | M19a/M19 (M23 docs) |
| HIGH | Пользователь выбирает REALITY/obfs4/Tor в UI → демон `Ok`, режим «активен», трафик прежний — ложное чувство защиты в стране с цензурой | `handler.rs:835-848`, `gui/views/settings.rs:50`, `cli/main.rs:442` | `SetTransportMode` ≠ direct → `Error("not supported")`; скрыть выбор | M19b |
| HIGH | DPI-транспорты: не встраиваемы, не компилируются в CI, криптографически несостоятельны, 6 optional-зависимостей в Cargo.lock | `transport/*`, `aira-net/Cargo.toml:27-49`, `ci.yml:37,51` | удалить модули/фичи/deps/`dpi_simulator.rs`; §11A — таблица статусов; DPI-история беты = iroh-relay/WSS:443 (M20) | M19b (+M22 SBOM) |
| MEDIUM | Нет таймаутов: `connect`, `read_framed`, `RelayClient::request`, ожидание ответа приложения на handshake | `endpoint.rs:115-124`, `connection.rs:51-72`, `relay.rs:361-380`, `protocol.rs:158` | `tokio::time::timeout` 5/30/10 с | M19 |
| MEDIUM | `read_framed` выделяет 256 KB по заголовку; 128 стримов × 256 KB = 32 MB/соединение; лимиты §11B.3 (16/32, окна, idle 30 с) не выставлены; соединений не ограничивает никто | `connection.rs:59-66`, `endpoint.rs:17-23` | инкрементальное чтение; лимиты по спеке; `EndpointHooks` 1.1 для tiers | M19 / M22 |
| MEDIUM | identity ↔ EndpointId не связаны: подпись handshake не покрывает EndpointId, `IncomingMessage.from` — только EndpointId; любой EndpointId может слать `Encrypted` в сессию до decrypt | `handshake.rs:316-336`, `protocol.rs:26-31` | EndpointId обеих сторон в подписываемые данные (M19a п.6); gate по известному EndpointId до decrypt | M19a/M19 |
| MEDIUM | Ack по ratchet-`counter` в одной коробке на два направления удаляет чужие конверты; коробки создаются любым deposit, глобального cap нет | `relay.rs:285-291, 231` | закрыто дизайном v2 (две коробки, `seq`, `Register`) | M21 |
| MEDIUM | `ratelimit.rs`/`ConnectionManager`/`PeerTier` — мёртвые; лимитер не keyed, per-peer состояние хранить негде | `ratelimit.rs:24-49`, `connection.rs:131-194` | `RateLimiter::keyed` по EndpointId + tier из `contacts` через hooks | M22 |
| MEDIUM | `MemStore`: файл целиком в память (до 4 GiB), temp-теги `forget` → монотонный рост памяти демона | `blobs.rs:70,86,103` | `FsStore::load`, `add_path`, теги с освобождением | M19 |
| MEDIUM | Баг фрейминга: неполный 2-байтный заголовок длины на границе чтения отбрасывается → рассинхронизация (obfs, reality) | `obfs.rs:273-276`, `reality.rs:793-795` | снимается удалением модулей | M19b |
| LOW | `InvitationLink`: нет версии/подписи/fingerprint/срока; `endpoint_addr_bytes` никем не заполняется; ссылка ≈ 2,8 KB не влезает в QR как текст; неканонический base64url принимается; лишний `unsafe` | `discovery.rs:20-61,181-182,185-211` | `version`, подпись, QR в byte-mode; `#![deny(unsafe_code)]` | M19b |
| LOW | Ошибки клиента relay обнуляют поля; `debug!` пишет EndpointId; три разных константы размера конверта (256 KB / 64 KB / 64 KB) | `relay.rs:398,400`, `protocol.rs:56,132`, `connection.rs:22` | косметика; одна константа в aira-core | M19a |

**Правки плана `spec/18-milestones.md`:** (1) M19 п.7 — `build_router` без `RelayServer`, ALPN RELAY убрать сразу; (2) M19 п.10 — без fallback
на `aira/1/relay`, до M21 только `pending` + прямая доставка; (3) M18 п.3 — «объём вне aira-net не ожидается», предпосылка — откат
незакоммиченного `ml-dsa`; (4) M19a — ALPN `aira/2/*`, ack в chat-протоколе, EndpointId в подписи handshake, шифрование файлов (или пункт
в M23 п.3 о честной записи в THREAT_MODEL); (5) M19b — `SetTransportMode` ≠ direct → ошибка, удаление `transport/*` и `dpi_simulator.rs`,
§11A → таблица статусов, §11A.6 → `unstable-custom-transports`; (6) M20 п.6 — сигнатура `AiraPreset`/`NetConfig`/`bind_with` из §7,
`publish_direct_addrs = false` по умолчанию; (7) M21 п.3 — пагинация `Retrieve`, ответ ≤ `MAX_FRAME_SIZE`.

**Открытые вопросы владельцу:** шифровать ли файлы per-file ключом в M19a (1–2 дня) или выпускать бету с оговоркой «файлы > 1 MB не
PQ-защищены»; удалять транспорты из `main` или переносить в ветку `experimental/transports`; `publish_direct_addrs` (AddrFilter) — прямые IP
в pkarr или только relay.

## 1. Карта модулей

Потребители aira-net вне крейта (grep по `crates/`, исключая сам aira-net): **только** `blobs::BlobStore`, `blobs::MAX_FILE_SIZE`,
`BlobStore::is_inline`, `NetError::BlobStore` (daemon `handler.rs:32,865,880-884,915,923`, `main.rs:123`; ffi `runtime.rs:33,95`)
и `transport::TransportMode::from_str` для валидации строки (`handler.rs:837`). Ни один из символов `AiraEndpoint`, `build_router`,
`ChatHandler`, `HandshakeHandler`, `read_framed`, `RelayClient`, `RelayServer`, `ConnectionManager`, `PeerTier`, `limiter_for_tier`,
`check_rate`, `InvitationLink`, `DeviceRecord`, `derive_mailbox_id`, `endpoint_addr_bytes` не встречается вне aira-net (0 вхождений каждый).
`aira-daemon/Cargo.toml:14` и `aira-ffi/Cargo.toml:14` подключают крейт **без фич** → модули `transport/{obfs,mimicry,cdn,reality,fingerprint,tor}`
не компилируются ни в бинарях, ни в CI (`.github/workflows/ci.yml:37,51` — `--workspace` без `--all-features`).

| Файл (строк) | Назначение | Спека | Статус | Кто вызывает |
|---|---|---|---|---|
| `lib.rs` (108) | ALPN `aira/1/{chat,file,handshake,relay}` (`:38-44`), `NetError` (`:51-102`) | §5.4 | подключено (типы) | daemon: `NetError::BlobStore` |
| `endpoint.rs` (184) | `AiraEndpoint` — обёртка `iroh::Endpoint`; `presets::N0` в проде (`:80`), `Endpoint::empty_builder()` в тестах (`:78`); QUIC-лимиты 128/128 стримов, idle 60 с, keepalive 15 с (`:17-23`) | §5.1, §11B.3 | автономный, без интеграции | только тесты aira-net |
| `connection.rs` (260) | фрейминг `u32 BE len ‖ postcard`, `MAX_FRAME_SIZE` 256 KB (`:22-72`); `PeerTier`/`ConnectionManager` (`:78-194`) | §5, §11B.1 | фрейминг — используется relay/protocol; `ConnectionManager` — **мёртвый** (только свой тест) | — |
| `protocol.rs` (278) | `ChatHandler`, `HandshakeHandler` (ProtocolHandler), `build_router` (`:178-195`) | §5.4 | автономный, без интеграции (демон не строит Router) | тесты aira-net |
| `relay.rs` (669) | mailbox v1: `RelayServer` (ProtocolHandler на `aira/1/relay`) + `RelayClient`; in-memory `HashMap` | §6.3b, §6.5, §11B.5 | автономный; по плану M21 — **удалить** | тесты aira-net |
| `discovery.rs` (330) | `InvitationLink` `aira://add/…` (`:20-61`), `DeviceRecord` для DHT (`:68-147`), свой base64url (`:151-211`) | §5.2, §14.4 | автономный; `DeviceRecord` — мёртвый (DHT после релиза, решение №3) | — |
| `blobs.rs` (206) | `BlobStore` = `iroh_blobs::store::mem::MemStore` + `BlobsProtocol` | §6.2 | **подключено** к демону/ffi, но без сети (см. §5) | daemon, ffi |
| `ratelimit.rs` (84) | `limiter_for_tier` → governor `direct` limiter | §11B.1 | **мёртвый** | — |
| `transport/mod.rs` (588) | `TransportMode`/`MimicryProfile`/`CpsSignature` (serde+FromStr), `AiraTransport` trait, `BoxedStream`, фабрика `create_transport` (`:401-466`) | §11A.2, §11A.6 | `TransportMode::from_str` — используется демоном для валидации строки; всё остальное — автономный код | daemon `handler.rs:837` |
| `transport/direct.rs` (61) | passthrough | §11A.3 режим 1 | автономный | тест dpi_simulator |
| `transport/obfs.rs` (480) | XOR-keystream по BLAKE3 от двух публичных nonce; feature `obfs4` | §11A.3 режим 2 | **не компилируется в проде/CI**; никем не вызывается | — |
| `transport/mimicry.rs` (568) | псевдо-заголовки DNS/QUIC/SIP/STUN перед payload; feature `mimicry` | §11A.4 | то же | — |
| `transport/cdn.rs` (264) | POST/GET на `{endpoint}/send`,`/recv` через reqwest; feature `cdn` | §11A.2 | заглушка; воркера в репо нет | — |
| `transport/reality.rs` (1136) | «REALITY-like»: 8-байтный short_id в открытую → TLS с самоподписанным сертификатом → BLAKE3-MAC → XOR; feature `reality` | §11A.5 | то же; половина файла помечена `dead_code` (`:4`) | — |
| `transport/fingerprint.rs` (309) | rustls `ClientConfig` с переставленными cipher suites, `AcceptAnyCertVerifier`; feature `reality` | §11A.5 (uTLS) | вспомогательный для reality | — |
| `transport/tor.rs` (316) | passthrough с полем `socks5_addr`; `connect_via_socks5` не вызывается (`:192-204`); feature `tor` | §11A.3 режим 3 | заглушка | — |
| `tests/two_node_chat.rs` (116) | Alice→Bob `Message::Encrypted` через `aira/1/chat` на loopback; ping/pong | M2 п.7 | работает (offline-loopback, см. §4) | — |
| `tests/relay_offline.rs` (148) | deposit→retrieve→ack через реальные QUIC-соединения; квота `max_envelopes` | M2 п.8 | работает; что доказывает — §2 | — |
| `tests/dpi_simulator.rs` (199) | игрушечный классификатор по первым байтам + проверка **вручную собранных** байтов | M7 п.6 | не тестирует транспорты (см. §8) | — |

**Транспорты и iroh.** `AiraTransport::wrap_outbound/accept_inbound` (`transport/mod.rs:382-391`) оборачивают абстрактный
`BoxedStream` (`AsyncRead + AsyncWrite`). У iroh нет такого места: QUIC живёт поверх UDP-датаграмм, а точка расширения в iroh 1.1 —
`iroh::endpoint::transports::{CustomTransport, CustomSender, Transmit}` за фичей `unstable-custom-transports`
(iroh-1.1.0 `src/endpoint.rs:30-40`) — уровень датаграмм, не байтовых потоков. В `endpoint.rs`/`protocol.rs` нет ни одного вызова
`wrap_outbound`/`accept_inbound` (grep: только внутри `transport/*` и тестов). Вывод: **весь `transport/*` — самостоятельные реализации
поверх `tokio::io::duplex`, к сетевому пути не подключены и подключены быть не могут в текущей форме.** Спека §11A.6 («iroh поддерживает
`CustomTransport` trait» с `impl AsyncRead + AsyncWrite`) описывает несуществующий API.

**Что проверяет `tests/dpi_simulator.rs`.** Классификатор `classify()` (`:28-75`) смотрит на первые 5–12 байт. Тесты:
`direct_transport_passes_payload_unchanged` (`:130-148`) — passthrough; `obfs_output_is_undetectable` (`:151-167`) — собирает
«похожие на obfs» байты **вручную** (`rand` + `[0x00,0x0A]`), `ObfsTransport` не вызывается; `mimicry_*_detected_as_*` (`:170-199`) —
кормят классификатору **вручную собранные заголовки**, а не выход `MimicryStream` (у которого на проводе первыми идут 2 байта LE длины
заголовка, `mimicry.rs:424-430` — см. §8). Ни nDPI, ни Wireshark, ни реальный трафик не участвуют. Требование M7 п.6 не выполнено.

## 2. relay.rs — mailbox v1

**Что это.** Одновременно сервер и клиент mailbox-протокола v1 на ALPN `aira/1/relay`:
- `RelayServer` (`relay.rs:149-152`) — `ProtocolHandler` (`:311-339`): один bi-stream на соединение, цикл `read_framed → handle_request → write_framed`.
- `RelayClient` (`:345-434`) — `deposit/retrieve/ack`; каждый запрос = **новое QUIC-соединение** (`:362-365`), `DeleteMailbox` клиентом не вызывается.

**Кадры.** Общий фрейминг `connection.rs:27-72` (`u32 BE` длина + postcard, ≤ 256 KB). Запросы `RelayRequest` (`:34-49`):
`Deposit{mailbox_id,envelope}`, `Retrieve{mailbox_id}`, `Ack{mailbox_id,counters:Vec<u64>}`, `DeleteMailbox{mailbox_id}`;
ответы `RelayResponse` (`:53-67`), коды `RelayErrorCode` (`:71-77`). **Нет** `RelayHello`/версии/capabilities (§11B.5.1), нет nonce.

**Аутентификация владельца.** Отсутствует полностью: любой, кто знает 32 байта `mailbox_id`, делает `Retrieve`/`Ack`/`DeleteMailbox`
(`:265, :281, :299`); `Deposit` — от кого угодно, без PoW/подписи/rate limit (`:214-263`). Это уже зафиксировано в аудите §3.1; новое ниже.

**Хранение, лимиты, TTL** (`RelayConfig::default` `:109-113`): 100 конвертов / 10 MB на коробку, конверт ≤ 64 KB (считается как
`ciphertext + 20`, `:219`), TTL 7 дней, GC раз в 60 с по `last_activity` **коробки** (`:187`), `received_at` — `dead_code` (`:124`).
Общего cap (спека §11B.5: 1 GB) нет; коробка создаётся **при первом deposit** (`entry().or_insert_with`, `:231`) → число коробок не ограничено.

**Новые находки (не в §3.1):**

- **[HIGH] Retrieve ломается, когда коробка больше ~256 KB.** `handle_retrieve` клонирует **все** конверты в один `RelayResponse::Envelopes`
  (`relay.rs:268-274`); `write_framed` отвергает кадр > `MAX_FRAME_SIZE = 256 KB` (`connection.rs:22,33-38`) → сервер пишет `warn!` и рвёт
  стрим (`relay.rs:331-334`), клиент получает `NetError::Stream`. Квота 10 MB недостижима: после ~4 конвертов по 64 KB коробка становится
  **невыгружаемой**, ack невозможен, конверты живут до TTL. Последствие для M19 п.10 (fallback через `aira/1/relay` до M21): офлайн-доставка
  перестанет работать после нескольких сообщений с файлами/медиа. Исправление: пагинация `Retrieve{after_seq, limit}` (в v2 уже есть `after_seq`)
  и/или потоковая отдача по одному конверту на кадр. Целевой milestone: **M21** (v2), а до него — не использовать v1 из демона вовсе (см. §9).
- **[MEDIUM] Ack по ratchet-`counter` в общей коробке на два направления.** `handle_ack` удаляет все конверты с `envelope.counter ∈ counters`
  (`relay.rs:285-291`). Одна коробка на пару (`derive_mailbox_id`, `:85-87`) + независимые счётчики двух ratchet-цепей → Bob, подтверждая
  свой counter=5, удаляет и конверт Alice с counter=5. Устраняется дизайном v2 (две коробки, `seq` от relay) — **M21**.
- **[LOW] Ошибки клиента теряют данные:** `MailboxFull{current:0,max:0}`, `EnvelopeTooLarge{size:0,max:0}` (`relay.rs:398,400`).
- **[MEDIUM] Память под DoS:** без регистрации любой EndpointId создаёт неограниченное число коробок по 10 MB; `RwLock<HashMap>` держится
  на весь `retain` в GC (`:184-187`). В v2 (`Register` обязателен, cap 1 GB, вытеснение) закрыто по дизайну — **M21**.

**Соответствие дизайну v2 (аудит §4.3) — что переиспользуется, что выкидывается.**

| Элемент v1 | Судьба в M21 |
|---|---|
| Значения квот `RelayConfig` (100/10 MB/64 KB/7 дней) | переиспользовать как константы, добавить `total_cap`, `gc_interval = 1 ч`, `register_per_day` |
| Форма `RelayErrorCode` | расширить (`Unauthorized`, `BadNonce`, `VersionMismatch`, `QuotaExceeded{kind}`) |
| Сценарий `tests/relay_offline.rs` (deposit→retrieve→ack по сети) | переиспользовать как шаблон интеграционного теста `crates/aira-relay/tests/` |
| `derive_mailbox_id` / контекст `aira/relay/mailbox/v1` (`:28`), `docs/KEY_CONTEXTS.md:74` | заменить на `aira/relay/mailbox/v2/<dir>` + `owner/sender` ключи; v1-контекст удалить из KEY_CONTEXTS |
| `RelayRequest`/`RelayResponse` без auth и версии | выкинуть: v2 = `RelayHello` + подписанные запросы + `seq` |
| In-memory `HashMap` + GC по `last_activity` | выкинуть: redb, TTL на конверт |
| `RelayServer` как `ProtocolHandler` в **клиентском** крейте и его регистрация в `build_router` (`protocol.rs:188`) | выкинуть вместе с ALPN `aira/1/relay` (M21 п.1); см. блокер §6/§9 |
| `RelayClient` (соединение на запрос) | переписать: одно соединение на relay, мультиплекс по стримам, таймауты |

**Что доказывает `tests/relay_offline.rs`.** `message_relay_when_peer_offline` (`:17-87`): через реальные iroh-соединения на loopback (без relay
n0 — см. §4) depositы попадают в коробку, retrieve отдаёт их в порядке FIFO, ack удаляет. `relay_quota_enforcement` (`:104-148`) — третий deposit
при `max_envelopes = 2` даёт `Err`. `relay_mailbox_id_is_deterministic` дублирует unit-тест. **Не доказывает:** персистентность (её нет),
TTL по сети, аутентификацию (её нет), поведение при коробке > 256 KB (упадёт), интеграцию с демоном (её нет). Bob «офлайн» — это просто
неподнятый endpoint; никакого ожидания/backoff/повторной доставки не тестируется.

## 3. discovery.rs — invitation link, pkarr/DNS

**Формат.** `aira://add/<base64url(postcard(InvitationLink))>` (`discovery.rs:42-46`), `InvitationLink { pseudonym_pk: Vec<u8>, endpoint_addr_bytes: Vec<u8> }`
(`:20-25`). Внутри: ML-DSA-65 pseudonym pubkey (1952 байт) + «сериализованный `EndpointAddr`» — но в workspace **нет кода**, который бы
сериализовал/десериализовал `EndpointAddr` в это поле (0 вхождений `endpoint_addr_bytes` вне aira-net; демон `AddContact{pubkey, alias}` ссылку
не парсит — аудит §4.1a). Подписи нет, версии формата нет, fingerprint'а (§5.2 п.2-3 обещает `#<short_fingerprint>`) нет, срока годности нет,
relay-информации нет.

**Размер.** postcard: 2 + 1952 + 1 + `len(EndpointAddr)` (id 32 + relay URL ~45 + 0–3 direct addr по ~19) ≈ 2 030–2 100 байт →
base64url ≈ 2 710–2 800 символов + 11 (`aira://add/`) ≈ **2,75–2,85 KB**. QR Version 40-L, binary mode = 2 953 байт — влезает только
если кодировать **байты**, а не URI-строку (строка на 33 % длиннее и уже не влезает). С M20 (relay_url в ссылке — обычно уже внутри
`EndpointAddr`) и M21 (`relays: Vec<RelayRef>`) — ссылка растёт. Рекомендация для M19b: QR несёт **сырые байты** `postcard(InvitationLink)`
(режим byte), а не текст URI; текстовая ссылка — для буфера обмена; предусмотреть `version: u8` первым полем.

**pkarr/DNS discovery.** В `discovery.rs` его **нет** — модуль содержит только ссылку и `DeviceRecord` (`:68-147`, «DHT multidevice records»,
§14.4). Discovery целиком делегирован пресету `presets::N0` в `endpoint.rs:80` (pkarr publisher/resolver + DNS n0, iroh-0.97 `presets.rs:47-66`).
`DeviceRecord` (`identity_pk`, `devices[]`, `signature` над `postcard(devices)`) — подпись **не покрывает `identity_pk`** и не привязана к
времени → переносима между записями; но модуль мёртв, DHT ушёл после релиза (решение №3) — **удалить** или пометить `#[cfg(feature = "dht")]`.

**`from_utf8_unchecked:182`.** `base64url_encode` (`:153-183`) пишет только байты из таблицы `B64` (ASCII) → инвариант UTF-8 верен, SAFETY-комментарий
есть (`:181`), правило `.claude/rules/unsafe.md` формально соблюдено. Но `unsafe` здесь **не нужен**: `String::with_capacity` + `push(char)`
или `String::from_utf8(out).map_err(...)` стоят столько же. У aira-net нет `#![deny(unsafe_code)]` (в отличие от aira-core/aira-storage) —
рекомендуется добавить, единственный `unsafe` в крейте — этот. **[LOW]**, M19b (когда модуль трогают ради QR).

**Декодер `base64url_decode` (`:185-211`).** Корректен для канонического входа; принимает **неканонические** строки (хвостовые биты не
проверяются на ноль, `=` молча пропускается `:197`) → одна ссылка имеет много строковых представлений (мешает дедупу ссылок по строке,
безопасности не угрожает). Нет лимита длины входа (allocation `s.len()*3/4`, `:186`) — для `AddContact{uri}` через IPC ограничено 1 MB IPC-кадром.
Тест `test_invitation_link_invalid` (`:229-232`) не покрывает ни неканонические строки, ни мусор после валидного префикса. **[LOW]**.

**Как это ляжет в M19b/M20.**
- M19b: `DaemonRequest::GetInvitation` должен заполнять `endpoint_addr_bytes = postcard(ep.addr())` (iroh `EndpointAddr` — `Serialize`) и
  использовать **стабильный** pseudonym (spec M19 п.12); `AddContact{uri}` → `InvitationLink::from_uri` → `EndpointAddr` → `ContactInfo.endpoint_addr`.
  Добавить в структуру `version: u8`, `fingerprint_hint: [u8;8]` (C10 аудита ядра), `expires_at: Option<u64>`; подпись pseudonym-ключом
  над всем остальным (иначе MITM подменяет `endpoint_addr_bytes` в ссылке, переданной через незащищённый канал — ключ остаётся честным, но
  трафик уходит на чужой EndpointId, который затем провалит handshake; это DoS, не компрометация).
- M20: relay URL уже входит в `EndpointAddr` (поле `relay_url` в iroh); отдельного поля не нужно. Для M21 — `relays: Vec<RelayRef>` (EndpointId
  aira-relay + iroh relay URL) добавляется отдельным полем, и это ещё +40–80 байт на relay.

## 4. endpoint.rs / connection.rs / protocol.rs — iroh 0.97 → 1.1

**Сборка Endpoint** (`endpoint.rs:56-95`): ALPN все четыре (`:57-62`); `QuicTransportConfig` 128 bidi / 128 uni, idle 60 с, keepalive 15 с
(`:17-23, :68-73`); прод — `Endpoint::builder(presets::N0)` (`:80`), тесты — `Endpoint::empty_builder()` (`:78`). **Нет** `RelayMode`,
`addr_filter`, `bind_addr`, discovery на своём домене, proxy, `ca_tls_config`. `bind()` принимает только `Option<SecretKey>` (`:45`).

Уточнение к комментарию `endpoint.rs:49-51` («Uses iroh's default relay for connectivity between test endpoints»): по исходнику iroh-0.97
`Builder::empty()` (`endpoint.rs:172-198`) `transports = [default_ipv4, default_ipv6]` — relay-транспорта **нет**, discovery нет → все тесты
aira-net работают чисто на loopback и не зависят от n0 (после 30.09.2026 не сломаются). В iroh 1.1 `Builder::empty()` (`endpoint.rs:191-221`)
идентичен плюс `crypto_provider: None` — поэтому `presets::Empty` не биндится, а `presets::Minimal` (только crypto provider, `presets.rs:59-63`,
`cfg(with_crypto_provider)` → нужна фича `tls-ring`) — точный эквивалент сегодняшнего `empty_builder()`.

**Версии протокола.** Единственный маркер — строка `1` в ALPN (`lib.rs:39-42`); `Capabilities{min,max,features}` есть только в handshake
aira-core. Спека §6.4 обещает `cipher_suites` — в `proto.rs:174-178` его нет (известно, C-находки ядра).

**Фрейминг и лимиты.** `read_framed` (`connection.rs:51-72`): читает 4 байта длины, проверяет `≤ 256 KB`, **сразу выделяет** `vec![0u8; len]`
(`:66`) и ждёт `read_exact` без таймаута. `MAX_FRAME_SIZE` 256 KB ≠ `MAX_ENVELOPE_SIZE` 64 KB (`aira-core/ratchet.rs:33`) ≠ relay 64 KB —
три константы в трёх местах; для v2 зафиксировать одну в aira-core.

**Таймауты.** Нет ни одного `tokio::time::timeout` в aira-net вне тестов: `AiraEndpoint::connect` (`endpoint.rs:115-124`), `RelayClient::request`
(`relay.rs:361-380`), `read_framed`, `HandshakeHandler` ожидание ответа приложения (`protocol.rs:158`) — все могут висеть до QUIC idle (60 с,
продлевается keepalive'ами пира).

**Обработка ошибок.** `ChatHandler::accept` (`protocol.rs:54-95`) при первой ошибке чтения **рвёт всё соединение** (`:63-69`); Ping/Pong
обрабатываются на месте (`:72-81`); ответный `send` для обычных сообщений не используется → **нет ack** на уровне протокола, а M19 п.10
требует «ack → `pending::dequeue`». `HandshakeHandler` (`:130-165`) — один init на соединение, ответ через `mpsc(1)`. `RelayServer` в
`ProtocolHandler::accept` глотает `NetError::Stream` как «нормальное закрытие» (`relay.rs:322`). Сообщения `Handshake/FileOffer/FileChunk`
на ALPN CHAT пропускаются как есть (`:83-91`) — фильтр по типу на уровне ALPN отсутствует.

**Что сломает iroh 0.97 → 1.1 (сверено по исходникам 1.1.0):**

| Место | 0.97 | 1.1 | Правка |
|---|---|---|---|
| `endpoint.rs:78` | `Endpoint::empty_builder()` | удалён; `Builder::empty()` есть, но `presets::Empty` не биндится без crypto provider | `Endpoint::builder(presets::Minimal)` |
| `endpoint.rs:66` `VarIntBoundsExceeded` | `iroh::endpoint::VarIntBoundsExceeded` | есть (`endpoint.rs:114` re-export из noq) | без изменений; 2 «ошибки вывода типов» из эксперимента D — вероятно каскад от строки 78 (не проверено) |
| `QuicTransportConfig::builder().max_concurrent_*_streams/max_idle_timeout/keep_alive_interval.build()` | quinn | noq: `endpoint/quic.rs:134,176,211,365` — те же имена | без изменений |
| `Endpoint::{id,addr,online,connect,accept,close}`, `Connection::{remote_id,accept_bi,open_bi,close,closed}` | — | `endpoint.rs:1183,1199,1358,1052,1165,1706`; `connection.rs:563,901,959,917` | без изменений |
| `SendStream::finish() -> Result<(), ClosedStream>`, `RecvStream::read_exact` | quinn | noq `send_stream.rs:186`, `recv_stream.rs:89` | без изменений |
| `protocol::{ProtocolHandler, AcceptError::from_err, Router::builder().accept().spawn(), Router::shutdown}` | — | `protocol.rs:228-300,137,406,484,501,429`; trait получил default-методы `on_accepting`/`shutdown` | без изменений |
| `EndpointId::{from_bytes, as_bytes}`, `SecretKey`, `EndpointAddr` | — | iroh-base 1.1 `key.rs:70,111,122,261`, `endpoint_addr.rs:42` | без изменений (переименование NodeId→EndpointId уже сделано в 0.97; `discovery.rs:69` и спека §5.1 ещё говорят «NodeId») |
| `iroh_blobs::{ALPN, store::mem::MemStore, BlobsProtocol::new(&Store, None), add_bytes/add_slice().temp_tag(), reader(hash)}` | 0.99 | 0.103: `protocol.rs:406` (тот же `/iroh-bytes/4`), `store/mem.rs:76,118` + `Deref<Target=Store>` (`:92-93`), `api/blobs.rs:140,177,186`, `net_protocol.rs:72` | без изменений (эксперимент D дошёл до endpoint.rs, значит blobs.rs собрался) |
| Фичи | `iroh = "0.97"` default | default = `metrics, fast-apple-datapath, portmapper, tls-ring`; `presets::Minimal` требует `tls-ring`/`tls-aws-lc-rs` | как в M18 п.2 |
| MSRV | 1.82 | 1.91 | `rust-version = "1.91"` |

**Оценка объёма M18 для aira-net: 1 строка кода + фичи в Cargo.toml + rust-version, ≈ 0,5 дня с прогоном тестов.** Пункт M18 п.3
(«починка daemon/ffi/gui/cli по мере всплытия, объём неизвестен») можно сузить: эти крейты используют из aira-net только `blobs::*`
и `TransportMode::from_str` (см. §1), напрямую iroh — никто (grep `iroh::` вне aira-net — 0). Ожидаемый объём вне aira-net — **ноль**.
Обязательно закоммитить откат `ml-dsa = "0.1.0-rc.4"` перед миграцией — на текущем дереве `cargo test -p aira-net -- --list` не компилируется
из-за `sha3 0.11.0-rc.6` (проверено; причина — в `facts-crates.md`).

**Что нового в 1.1 понадобится M20/M22 (адреса в исходниках 1.1.0):** `RelayMode::{Custom(RelayMap), custom(iter)}` (`endpoint.rs:1925-1965`),
`RelayMap: FromIterator<RelayUrl|RelayConfig>` + `with_auth_token` (iroh-relay `relay_map.rs:154,163,203`), `RelayConfig`/`RelayQuicConfig`
(`:232,292`), `Endpoint::insert_relay/remove_relay` (`endpoint.rs:984,998`), `Builder::clear_relay_transports` (`:510`),
`Builder::addr_filter(AddrFilter)` (`:617`) и `PkarrPublisherBuilder::addr_filter` (`pkarr.rs:217`), `PkarrPublisher::builder(url)` (`pkarr.rs:290`),
`PkarrResolver::builder(url)` (`:507`), `DnsAddressLookup::builder(origin)` (`dns.rs:78`), трейт `Preset { fn apply(self, Builder) -> Builder }`
(`presets.rs:21-23`), `EndpointHooks` (`endpoint/hooks.rs`, `BeforeConnectOutcome`/`AfterHandshakeOutcome`) — точка для tiers/puzzles M22,
`test_utils::run_relay_server()` (фича `test-utils`, `test_utils.rs:34`).

## 5. blobs.rs — файлы через iroh-blobs

**Рабочее ли.** Локально — да: `MemStore` + `BlobsProtocol` (`blobs.rs:37-41`), `import_file/import_bytes/read_blob` покрыты 5 тестами;
`protocol()` (`:124`) отдаёт `BlobsProtocol` для `Router` (регистрируется в `build_router`, `protocol.rs:190-192`). По сети — **нет**:
в крейте нет ни одной операции скачивания (`Downloader`, `remote().fetch`, `iroh_blobs::api::downloader` не используются), ALPN `aira/1/file`
объявлен (`lib.rs:40`), но обработчика на него нет ни в aira-net, ни в демоне; демон отправителю шлёт `FileComplete` без передачи
(аудит §4.1a). Приёмной стороны файла не существует.

**Размеры/лимиты.** `INLINE_THRESHOLD` 1 MB (`:19`), `MAX_FILE_SIZE` 4 GiB (`:22`). `import_file` читает **весь файл в память**
(`tokio::fs::read`, `:70`) и кладёт в in-memory store → 4 GiB файл = 4–8 GiB RSS (копия в `Bytes` + bao outboard). `MemStore` не имеет
cap'а. `std::mem::forget(tag)` (`:86, :103`) — temp-теги утекают намеренно («держим blob живым»), удаления нет → память демона растёт
монотонно на каждый отправленный/принятый файл до рестарта. **[MEDIUM]**, M19 п.13: `iroh_blobs::store::fs::FsStore::load(path)`
(0.103 `store/fs.rs:1390`) + `add_path` вместо `read` + именованные теги с удалением по завершении трансфера.

**Привязка к сессии/шифрованию — отсутствует, и это дыра в модели угроз.** iroh-blobs отдаёт содержимое по хэшу **любому** соединению с
ALPN `/iroh-bytes/4` без авторизации; сам blob — открытые байты файла (`add_bytes(data)`, `:74-79`). Защита содержимого файла в пути =
только QUIC TLS 1.3 iroh (X25519/Ed25519, классика). Таблица §11 обещает «Quantum adversary (сбор трафика сейчас, расшифровка потом) →
ML-KEM-768» — для файлов ≥ 1 MB это **неправда**: перехваченный трафик iroh-blobs расшифровывается после взлома X25519, ratchet-ключи не
участвуют. Плюс: кто знает 32-байтный хэш (сосед по группе, relay-оператор — нет, только участник), тот может скачать файл повторно в любой
момент, пока blob жив в store (а он живёт до рестарта). **[HIGH]**, M19 п.13 (или M19a как часть протокола v2): шифровать файл per-file
ключом из ratchet (`aira/file/key/v2`, ChaCha20-Poly1305 потоково по чанкам или blob = ciphertext), передавать ключ в `FileStart`;
хэш блоба = хэш **шифротекста**. Минимум для беты: честно в `docs/THREAT_MODEL.md`/`PRIVACY.md` (M23 п.3) — «файлы > 1 MB не PQ-защищены».

**iroh-blobs 0.103 и wasm.** API, который использует `blobs.rs`, в 0.103 присутствует без изменений (таблица §4). Браузер не поддерживается
(аудит §6.1) — `cfg`-гейт на `blobs` уже запланирован в §14.0.

## 6. Безопасность / DoS

**[BLOCKER — дефект плана] Каждый клиент станет открытым mailbox-relay.** `build_router` требует `Arc<RelayServer>` и регистрирует его
на `aira/1/relay` (`protocol.rs:182-188`), `AiraEndpoint` анонсирует ALPN RELAY всегда (`endpoint.rs:61`). M19 Phase B п.7
(`spec/18-milestones.md:563-566`) дословно велит вызвать `build_router(&ep, ChatHandler, HandshakeHandler, Arc<RelayServer>, …)` в
демоне. Результат: каждый desktop/Android-клиент беты принимает от **любого** EndpointId deposit'ы без аутентификации в неограниченное
число коробок по 10 MB (`relay.rs:231`) — удалённое исчерпание памяти пользовательского демона одним запросом в цикле, плюс использование
чужих клиентов как бесплатного хранилища. Исправление: в M19 п.7 убрать `Arc<RelayServer>` из сигнатуры (`relay_server: Option<…>` или
удалить параметр и ALPN RELAY из `all_alpns` сразу, не дожидаясь M21 п.1). Целевой milestone: **M19** (правка плана — сейчас).

**Неограниченные чтения / память на соединение.** `read_framed` выделяет до 256 KB по 4-байтному заголовку до прихода данных
(`connection.rs:59-66`); лимит стримов 128 bidi на соединение (`endpoint.rs:17`) → 32 MB на соединение при нулевых затратах атакующего;
число входящих соединений `Router` не ограничивает (в 1.1 — через `EndpointHooks`/`iroh-util::AccessLimit`). Спека §11B.3 требует 16/32 стрима,
`receive_window` 256 KB, `stream_receive_window` 64 KB, idle 30 с — ни один из лимитов окон не выставлен. **[MEDIUM]**, M19 (лимиты) / M22
(hooks): читать заголовок → выделять инкрементально (`Vec::with_capacity(min(len, 16 KB))` + `read_buf` по частям), 16/32 стрима, окна по спеке,
таймаут чтения кадра 30 с.

**Отсутствие таймаутов** — §4: `connect`, `RelayClient::request`, `read_framed`, ожидание ответа приложения в `HandshakeHandler`
(`protocol.rs:158`). Slowloris на handshake: открыть соединение с ALPN HANDSHAKE, послать init, не читать ответ — занят слот `mpsc(buffer)`
и таска. **[MEDIUM]**, M19: `timeout(5 s, connect)`, `timeout(30 s, read_framed)`, `timeout(10 s, reply_rx.recv())`.

**ratelimit.rs — где применяется.** Нигде: `limiter_for_tier`/`check_rate` вызываются только из своих тестов (`ratelimit.rs:56-84`);
`PeerTier` присваивается только в тесте `connection.rs:210`; `ConnectionManager` не создаётся ни в одном production-пути. Кроме того
лимитер `direct` (не keyed) создаётся заново при каждом вызове `limiter_for_tier` (`:24-38`) — per-peer состояние хранить негде.
Спека §11B.1 (10/2 соединений на tier, дроп при перегрузке) не реализована. **[MEDIUM]**, M22 п.2: `governor::RateLimiter::keyed`
по `EndpointId` + tier из `contacts`, подключить через `EndpointHooks::after_handshake` (1.1) и в `ChatHandler::accept`.

**Anti-replay.** На уровне aira-net нет: повторный `Deposit` того же конверта принимается (`relay.rs:214-263`), повторный `Message::Encrypted`
пробрасывается в приложение (`protocol.rs:83-91`); дедуп в демоне не подключён (аудит §4.1a). Replay handshake-init — находка C5/C6 ядра.
Закрывается M19 п.3 (dedup до decrypt) + M19a п.4 (nonce/timestamp в handshake) + M21 (relay_nonce).

**Аутентификация пиров: identity ↔ EndpointId.** iroh аутентифицирует **EndpointId** (Ed25519, TLS 1.3 обоюдно); приложение получает
`IncomingMessage { from: EndpointId, message }` (`protocol.rs:26-31`) — идентичность ML-DSA в нём отсутствует. Подписанные данные handshake
(`aira-core/handshake.rs:316-336`) содержат `identity_pk ‖ kem_ek ‖ x25519_pk ‖ capabilities` и **не содержат EndpointId ни одной стороны**
→ транспортный и прикладной ключ никак не связаны (C8 ядра). Следствие для aira-net/M19: если `SessionManager` будет искать сессию по
`from: EndpointId` (единственное, что есть), то (а) атакующий с любым EndpointId может слать `Encrypted` в адрес любой сессии — decrypt
провалится, но CPU/skipped-keys тратятся; (б) при смене EndpointId контакта (переустановка, per-device ключ §12.6) сессия «теряется».
Требование к M19a п.6 (SIGMA-binding): включить `initiator_endpoint_id ‖ responder_endpoint_id` в подписываемые данные init/ack и хранить
пару `(contact, endpoint_id)` в `contacts`; в `ChatHandler` — отбрасывать `Encrypted` от EndpointId без сессии **до** decrypt. **[MEDIUM]**, M19a/M19.

**Логирование.** `debug!(%remote_id, …)` в `protocol.rs:56,132`, `debug!(%hash, size, …)` в `blobs.rs:82` — EndpointId и хэши файлов на
уровне debug; IP aira-net не пишет (iroh на `trace` пишет пути/адреса). Для `PRIVACY.md` (M23): «при `AIRA_LOG=debug` в логах EndpointId
собеседников». **[LOW]**.

**`unwrap`/`expect`/`unsafe` в production-путях aira-net (полный список):**
- `ratelimit.rs:29`, `:34` — `NonZeroU32::new(100).expect("nonzero")` / `new(5).expect(…)` (константы, невозможная паника; заменить на
  `const` `NonZeroU32::new(..).unwrap()` в const-контексте — clippy `expect_used` не включён в aira-net, `lib.rs:12-27` только `pedantic`).
- `tor.rs:72-74` — `"127.0.0.1:9050".parse().expect("default socks5 addr is valid")` (константа; feature `tor`, не компилируется в проде).
- `discovery.rs:182` — `unsafe { String::from_utf8_unchecked(out) }` с SAFETY-комментарием (§3; заменить, добавить `#![deny(unsafe_code)]`).
- `reality.rs:289` — `unwrap_or(usize::MAX)` (безопасно).
Всё остальное — `?`/`map_err`. Правило security.md §5 выполняется; рекомендация: `#![deny(clippy::unwrap_used, clippy::expect_used)]` как в aira-core.

**Прочее.**
- `RelayServer::accept` держит одно соединение = один стрим; `RelayClient` открывает **QUIC-соединение на каждый запрос** (`relay.rs:362`) —
  handshake TLS + возможный hole punching на каждый deposit. Для v2 — одно соединение, стримы.
- `ChatHandler` рвёт соединение при любом невалидном кадре (`protocol.rs:63-69`) — один битый пакет = переподключение; для v2 — пропускать
  кадр, считать ошибки, рвать после N.
- `std::time::Instant` в `connection.rs:10,122` и `relay.rs:12` — уже учтено в §14.0 спеки (wasm).

## 7. Конфигурация relay

**Сейчас невозможно.** `presets::N0` зашит в `endpoint.rs:80`; `AiraEndpoint::bind(Option<SecretKey>)` (`:45`) других параметров не
принимает; `RelayMode` в крейте не упоминается; демон конфигурации сети не имеет (`relay/url` — только в doc-комментарии и тестах
`aira-storage/settings.rs:3,126`, `backup.rs:204`). `RelayMode::Custom(RelayMap)` в iroh 0.97 и 1.1 есть — не задействован.

**Что добавить для mail-сервера (аудит §3.3, план деплоя «Этап 6») — конкретные точки:**

1. `crates/aira-net/src/preset.rs` (новый): 
   ```rust
   pub struct AiraPreset { pub relays: Vec<RelayUrl>, pub relay_auth_token: Option<String>,
                           pub pkarr_relay: Option<Url>, pub dns_origin: Option<String>,
                           pub publish_direct_addrs: bool, pub n0_fallback: bool }
   impl iroh::endpoint::presets::Preset for AiraPreset { fn apply(self, b: Builder) -> Builder { … } }
   ```
   Внутри: `b.relay_mode(RelayMode::Custom(RelayMap::from_iter(relays)))` (при токене — `RelayMap::with_auth_token`), для QAD —
   `RelayConfig::new(url, Some(RelayQuicConfig::new(7842)))`; `b.address_lookup(PkarrPublisher::builder(url).addr_filter(…))`,
   `b.address_lookup(PkarrResolver::builder(url))`, `#[cfg(not(wasm_browser))] b.address_lookup(DnsAddressLookup::builder(origin))`;
   `n0_fallback` = дополнительно применить `presets::N0` (по умолчанию **false**, §11 — метаданные третьей стороне). Трейт `Preset`
   в 0.97 и 1.1 одинаков (`presets.rs:21-24`) — можно писать до M18, но `PkarrResolver::builder(url)` есть только в 1.1.
2. `endpoint.rs:45-95`: `pub struct NetConfig { preset: AiraPreset, transport: QuicLimits }`, `AiraEndpoint::bind_with(cfg, secret_key)`;
   `bind()` оставить как обёртку с дефолтами из бинарника (свои relay). `bind_for_test` → `presets::Minimal` (M18) или
   `test_utils::run_relay_server()` + `RelayMode::Custom` (M20 тест).
3. `aira-daemon/src/main.rs:100-160`: чтение `<data_dir>/config.toml` `[network] relays = [...], pkarr_relay = "...", dns_origin = "...",
   n0_fallback = false` (сериализация в `settings` под ключами `net/relays`, `net/pkarr_relay`), env-override `AIRA_RELAYS` для первого
   запуска; передать в `bind_with`. Значения по умолчанию — `relay.<domain>` mail-сервера + второй VPS (M20 п.7).
4. IPC `SetRelays/GetRelays/GetNetStatus` (M19 п.12 уже перечислены); `Endpoint::insert_relay/remove_relay` (1.1 `endpoint.rs:984,998`)
   позволяют менять список без рестарта.
5. `docs/KEY_CONTEXTS.md`: контекст iroh `SecretKey` (M19 Phase A п.6) — сейчас отсутствует (grep `iroh|EndpointId` по файлу — 0).
6. Спека `spec/03-network.md:16` («DERP»), `:21-22` (версии), `:85-89` (bootstrap-ноды — заменить на relay/pkarr), `§5.1` «NodeId» → EndpointId.

## 8. Transport / DPI (§11A)

Общее для всех шести: (1) не подключены к iroh и не могут быть (§1); (2) выключены фичами в daemon/ffi и не собираются в CI —
последняя гарантированная компиляция — коммиты 2026-04-03 (`git log`: `b0de791`, `32a5ff7`, `ca3378d`); (3) при этом пользователь
**может выбрать любой режим** в GUI (`aira-gui/views/settings.rs:50`) и CLI (`/transport`, `aira-cli/main.rs:442`): демон валидирует строку
(`handler.rs:837`), сохраняет в settings и отвечает `Ok`; `GetTransportMode` возвращает «reality:www.apple.com:chrome» — UI показывает
режим как активный, трафик не меняется. **[HIGH — честность перед пользователем в стране с цензурой]**, M19b: `SetTransportMode` с
режимом ≠ `direct` → `DaemonResponse::Error("not supported in this release")`, в UI скрыть/задизейблить выбор.

| Транспорт | Что реализовано | Криптографическая корректность | Тесты | Реалистичность против DPI |
|---|---|---|---|---|
| `direct.rs` | passthrough | н/п | 2 | н/п |
| `obfs.rs` («obfs4») | обмен двумя 32-байтными nonce **в открытую** (`:77-97`), `key = derive_key("aira/obfs/session/0", nonce_a‖nonce_b)` (`:116`), XOR с BLAKE3(key‖dir‖counter) (`:183-191`), кадры `u16 LE len ‖ payload` (`:331-335`) | **Ключа нет**: всё, из чего он выводится, идёт по проводу → любой наблюдатель (DPI) восстанавливает keystream и снимает «обфускацию»; активный зондировщик проходит «handshake» (нет секрета/подписи). Это не obfs4 (ntor + bridge key + серверный auth). Контекст `aira/obfs/session/0` в KEY_CONTEXTS формально изолирован, но не защищает ничего. **Баг**: неполный 2-байтный заголовок длины на границе чтения молча отбрасывается (`:273-276` «skip this byte») → рассинхронизация потока | 6 (roundtrip на duplex) | сигнатура: 32 случайных байта, затем `u16 LE` длины — тривиальный классификатор; энтропийная фильтрация ловит |
| `mimicry.rs` | кадр `u16 LE header_len ‖ header ‖ u16 LE payload_len ‖ payload` (`:424-430`); тег профиля первым байтом (`:45-56`) | н/п (без крипто) | 9 (roundtrip + форма заголовков) | **на проводе первыми идут 2 байта длины (`0x0C 0x00` для DNS), а не DNS-заголовок** → даже собственный `dpi_simulator` на реальном выходе стрима классифицировал бы `Unknown`, не `Dns`; «QUIC Initial» внутри байтового потока — QUIC живёт в UDP-датаграммах; SIP/STUN-«заголовки» без тела протокола ловятся любым парсером. Профиль выбирает клиент, сервер верит тегу (`:100-118`) |
| `cdn.rs` | `POST {endpoint}/send`, `GET {endpoint}/recv` раз в 500 мс (`:100-133`); входной stream **игнорируется** (`:39, :57`) | нет сессии/идентификатора/auth: все клиенты одного endpoint читают общий `/recv`; порядок/потери не обрабатываются | 2 (без HTTP) | заглушка: воркера нет в репо (grep `worker/cloudflare` — только спека) |
| `reality.rs` + `fingerprint.rs` | клиент шлёт 8 байт `short_id = derive_key("aira/reality/sid/0", psk)[..8]` **до TLS в открытую** (`:336-346`); сервер сравнивает `ct_eq` (`:394`), поднимает TLS с самоподписанным сертификатом на SNI (`:402-410`); внутри — `AUTH_REQUEST {magic, nonce, MAC, ts}` (`:474-516`), `MAC = keyed_blake3(derive_key("aira/reality/auth/0", psk), ts‖nonce)` (`:580-586`), drift ±60 с (`:553`), затем XOR c **статическим** `derive_key("aira/reality/session/0", psk)` (`:588-590`) | (а) статический 8-байтный префикс на проводе = сигнатура протокола и replayable «пропуск» к TLS-серверу с самоподписанным сертификатом на `www.apple.com` — активный прубер отличает за одно соединение; (б) auth-MAC не включает серверный nonce (сервер шлёт его **после** проверки, `:561-563`, и никто не использует) → replay в окне ±60 с; (в) session key статичен на PSK → keystream одинаков во всех соединениях (счётчик с 0) — внутри TLS это лишь избыточность, но как «слой» — two-time pad; (г) `AcceptAnyCertVerifier` принимает любую подпись (`fingerprint.rs:122-129`), MAC не привязан к TLS-каналу (нет exporter/transcript) → MITM на TLS-слое прозрачен; (д) заявленный в шапке механизм (Session ID в ClientHello, `:15-17`) **не реализован**: `read_client_hello`, `patch_session_id`, `SessionIdPatcher`, `ReplayStream` — `dead_code` (`:4`); (е) `create_transport` ставит `fallback_addr: None` (`mod.rs:445`) → активный прубер получает разрыв, а не apple.com. `ct_eq` — используется корректно (`:394, :543`) | 12 + 10 (roundtrip на duplex, wrong PSK, non-TLS) | «uTLS-мимикрия» = переставленные cipher suites в rustls (`fingerprint.rs:36-77`; TLS 1.3-набор одинаков для всех «браузеров», `:27-33`) — JA3/JA4 rustls остаётся rustls (расширения, GREASE, key_share, sigalgs не трогаются). Не REALITY, не uTLS |
| `tor.rs` | passthrough с меткой (`:95-115`); `connect_via_socks5` (`:192-204`) никем не вызывается; `_pool` не используется (`:53`); hidden service — только флаг | н/п | 6 (passthrough) | заглушка; arti (спека §11A.7) не подключён |

Контексты `aira/reality/{sid,auth,session}/0` и `aira/obfs/session/0` в `docs/KEY_CONTEXTS.md:92-95` не нарушают Key Isolation
(каждый — своя цель), но при удалении модулей их нужно убрать из таблицы.

**Рекомендация.**
- **Оставить в 1.0:** только `TransportMode::Direct`. Реальная DPI-устойчивость беты — это iroh-relay по WebSocket/TLS 443 на своём домене
  (M20; в §11A.3 это «режим 2»), опционально второй relay на VPS. Это единственный работающий транспорт, «похожий на HTTPS».
- **Вынести за релиз (спека, не код):** REALITY/uTLS, obfs4 (через `ptrs`/lyrebird-совместимую реализацию), Tor (arti), CDN — как «после
  1.0, требует `unstable-custom-transports` iroh на уровне датаграмм либо отдельный TCP/WebSocket-транспорт до собственного relay». В §11A
  оставить таблицу «режим → статус (реализовано / план)».
- **Удалить из репозитория сейчас (M19b или отдельный `chore(net)` PR перед M22):** `transport/{obfs,mimicry,cdn,reality,fingerprint,tor}.rs`,
  фичи `obfs4/mimicry/cdn/reality/tor` и optional-зависимости `reqwest`, `rustls`, `tokio-rustls`, `webpki-roots`, `rcgen`, `tokio-socks`
  (`aira-net/Cargo.toml:27-38, 41-49`; в `Cargo.lock` присутствуют `reqwest 0.12.28`, `rustls 0.23.37`, `tokio-rustls 0.26.4`,
  `tokio-socks 0.5.2`, `rcgen 0.13.2/0.14.7`, `webpki-roots 1.0.6` — лишняя поверхность для `cargo audit`/SBOM M22-M23),
  `tests/dpi_simulator.rs`; оставить `TransportMode` как enum с одним вариантом либо строкой `"direct"` для совместимости settings/IPC.
  Причина держать код в `main`, где его никто не собирает, отсутствует; в git-истории он остаётся. Альтернатива — ветка `experimental/transports`.

## 9. Задачи по M18 / M19 / M20 / M21

Оценки — чистое время одного разработчика, без учёта ревью.

### M18 — iroh 1.1 (aira-net: ≈ 0,5 дня)
| # | Задача | Где | Оценка |
|---|---|---|---|
| 18.1 | `Endpoint::empty_builder()` → `Endpoint::builder(presets::Minimal)`; поправить doc-комментарий `:49-51` (relay в тестах нет ни сейчас, ни после) | `endpoint.rs:77-81` | 15 мин |
| 18.2 | `iroh` фичи (`default-features = false`, `metrics, portmapper, fast-apple-datapath, tls-ring`), `iroh-blobs = "0.103"`, `rust-version = "1.91"`; `lib.rs:5` «iroh 0.97» → 1.1 | `Cargo.toml:27-28`, `aira-net/src/lib.rs:5` | 15 мин |
| 18.3 | Прогнать 104 теста aira-net (2+2+2 сетевых на loopback), `cargo clippy -p aira-net --all-targets` | — | 1–2 ч |
| 18.4 | Уточнить план M18 п.3: вне aira-net iroh никто не использует (§1, §4) — «объём выше неизвестен» → «не ожидается»; блокирующая предпосылка — откат незакоммиченного `ml-dsa = "0.1.0-rc.4"` | `spec/18-milestones.md:464-467` | правка текста |
| 18.5 | Решить: CI-job `cargo check -p aira-net --all-features` **или** удаление транспортов (§8). Оставлять несобираемый код после смены MSRV/iroh — долг растёт | `.github/workflows/ci.yml:37,51` | 30 мин / см. 19b.4 |

### M19a — протокол v2 (влияет на aira-net)
| # | Задача | Где | Оценка |
|---|---|---|---|
| 19a.1 | ALPN `aira/2/{chat,handshake,file}`; `aira/1/relay` удалить из `all_alpns` (см. 19.1) | `lib.rs:38-44`, `endpoint.rs:57-62` | 30 мин |
| 19a.2 | SIGMA-binding с EndpointId: подписываемые данные init/ack включают оба EndpointId; `IncomingHandshake` уже несёт `from` — передать в `HandshakeResponder::respond` | `aira-core/handshake.rs:110-117,316-336`; `protocol.rs:102-109` | 0,5 дня (в составе M19a п.4/6) |
| 19a.3 | Одна константа размера конверта в aira-core (`MAX_ENVELOPE_SIZE`), `MAX_FRAME_SIZE` = envelope + заголовок ratchet + запас (≤ 96 KB), relay v2 использует её же | `connection.rs:22`, `ratchet.rs:33`, `relay.rs:111` | 1 ч |
| 19a.4 | Ack на уровне chat-протокола: `Message::Ack { counter }` или ответный кадр в том же bi-stream — без него M19 п.10 (`dequeue` после ack) не реализуем | `protocol.rs:54-95`, `proto.rs:11-20` | 0,5 дня |
| 19a.5 | Шифрование файлов per-file ключом из ratchet (§5), `FileStart` несёт ключ; blob = ciphertext | `proto.rs:63-68`, `blobs.rs` | 1–2 дня (или честная запись в THREAT_MODEL, M23) |

### M19 — демон в сети (aira-net-часть: ≈ 3–4 дня из 2–3 недель)
| # | Задача | Где | Оценка |
|---|---|---|---|
| 19.1 | **Правка плана (BLOCKER §6):** M19 п.7 — `build_router(&ep, chat, handshake, blobs)` **без** `Arc<RelayServer>`; ALPN RELAY из `endpoint.rs:61` убрать; `RelayServer` не инстанцировать в клиенте | `spec/18-milestones.md:563-566`, `protocol.rs:178-195` | 1 ч |
| 19.2 | **Правка плана:** M19 п.10 «fallback — `RelayClient::deposit` в существующий `aira/1/relay` до M21» — **не делать** (нет auth, retrieve > 256 KB ломается §2, некому его хостить). До M21 — только `pending` + прямая доставка; `DeliveryState::Queued` честно в UI | `spec/18-milestones.md:576-579` | правка текста |
| 19.3 | Таймауты: `connect` 5 с, `read_framed` 30 с, ответ приложения на handshake 10 с; `EnvelopeTooLarge` → не рвать соединение, а пропускать кадр | `endpoint.rs:115-124`, `connection.rs:51-72`, `protocol.rs:63-69,158` | 0,5 дня |
| 19.4 | Инкрементальное выделение в `read_framed`; QUIC-лимиты по §11B.3 (16/32 стрима, окна 256/64 KB, idle 30 с) | `connection.rs:66`, `endpoint.rs:17-23,68-73` | 0,5 дня |
| 19.5 | `IncomingMessage` → в демоне gate «EndpointId известен и есть сессия» до decrypt; таблица `endpoint_id → contact` (Phase A п.1 уже добавляет `endpoint_addr`) | `protocol.rs:26-31`; daemon | в составе net_task |
| 19.6 | `InvitationLink`: `version`, `fingerprint_hint`, `expires_at`, подпись pseudonym-ключом; заполнять `endpoint_addr_bytes = postcard(EndpointAddr)`; убрать `unsafe`, `#![deny(unsafe_code)]`; удалить `DeviceRecord` | `discovery.rs:20-61,68-147,181-182` | 1 день (с QR в M19b) |
| 19.7 | `BlobStore` на `FsStore`, `add_path` вместо `fs::read`, теги с освобождением; приёмная сторона (`Downloader`/`remote().fetch` по хэшу из `FileStart`) на ALPN blobs; `FileAck` | `blobs.rs:52-105`, `protocol.rs:190-192` | 2 дня |
| 19.8 | `ConnectionManager` либо подключить к `net_task` (`ContactOnline/Offline`, M19 п.11), либо удалить; `PeerTier` — заполнять из `contacts` | `connection.rs:131-194` | 0,5 дня |
| 19.9 | `#![deny(clippy::unwrap_used, clippy::expect_used)]` в aira-net, константы в `ratelimit.rs:29,34` через const | `lib.rs:12-27` | 30 мин |

### M19b — клиенты (aira-net-часть)
| # | Задача | Где | Оценка |
|---|---|---|---|
| 19b.1 | `SetTransportMode` ≠ `direct` → `Error("not supported")`; в GUI/CLI скрыть выбор транспорта (§8, HIGH) | `handler.rs:835-848`, `aira-gui/views/settings.rs:50`, `aira-cli/main.rs:442` | 1 ч |
| 19b.2 | QR = байты `postcard(InvitationLink)` (byte mode), не текст URI (§3, размер) | GUI/CLI | в составе п.4 M19b |
| 19b.3 | `TransportMode` сериализуется в settings как строка — оставить формат, обрезать enum | `transport/mod.rs:143-168` | вместе с 19b.4 |
| 19b.4 | Удалить `transport/{obfs,mimicry,cdn,reality,fingerprint,tor}.rs`, фичи и optional-зависимости, `tests/dpi_simulator.rs`; KEY_CONTEXTS `:92-95`; спека §11A → таблица статусов, §11A.6 → `unstable-custom-transports` | `aira-net/Cargo.toml:27-49`, `transport/mod.rs:28-40,401-466` | 0,5 дня |

### M20 — свой iroh-relay + discovery (aira-net: ≈ 1,5 дня)
| # | Задача | Где | Оценка |
|---|---|---|---|
| 20.1 | `preset.rs::AiraPreset` (сигнатура §7 п.1), `NetConfig`, `AiraEndpoint::bind_with` | новый файл, `endpoint.rs:45-95` | 1 день |
| 20.2 | Конфиг демона `[network]` + env `AIRA_RELAYS`, ключи `net/*` в settings, IPC `SetRelays/GetRelays/GetNetStatus` | `main.rs:100-160`, `types.rs` | 0,5 дня (часть M19 п.12) |
| 20.3 | Тест с `iroh::test_utils::run_relay_server()` (фича `test-utils` в dev-deps): два endpoint'а, direct-адреса удалены из `EndpointAddr`, соединение через relay | `tests/relay_transport.rs` (новый) | 0,5 дня |
| 20.4 | Решение владельца `publish_direct_addrs` (AddrFilter) — дефолт **false** для беты (§11 метаданные), опция в settings | `preset.rs` | — |

### M21 — aira-relay v2 (что берётся из aira-net)
| # | Задача | Где | Оценка |
|---|---|---|---|
| 21.1 | Удалить `relay.rs`, `NetError::{MailboxFull, MailboxNotFound, RateLimited}` перенести в `aira-relay` | `relay.rs`, `lib.rs:63-73` | 1 ч |
| 21.2 | Перенести в v2: значения квот, форму `RelayErrorCode`, сценарий `tests/relay_offline.rs`; добавить пагинацию `Retrieve{after_seq, limit ≤ N}` с ответом ≤ `MAX_FRAME_SIZE` (§2 HIGH) и ack по `seq` | `crates/aira-relay` | в составе M21 п.3 |
| 21.3 | Клиент relay в aira-net (`relay_client.rs`): одно соединение на relay, стримы на запросы, таймауты, `RelayHello` | новый | 2 дня (в составе M21 п.7) |
| 21.4 | `docs/KEY_CONTEXTS.md:74` — `aira/relay/mailbox/v1` удалить, v2-контексты добавить | docs | 15 мин |

## 10. Тесты, которые нужно добавить

Сейчас в aira-net 104 `#[test]`/`#[tokio::test]` (по grep; 45 из них — в feature-gated транспортах и `dpi_simulator.rs`, в CI не выполняются).
Сетевых (реальные QUIC-соединения) — 7: `endpoint.rs:160`, `connection.rs:225`, `protocol.rs:203,232`, `two_node_chat.rs` ×2,
`relay_offline.rs` ×2. Нет ни одного fuzz-таргета и ни одного proptest.

**M18**
1. `cargo test -p aira-net` зелёный на iroh 1.1 (существующие 7 сетевых тестов — регрессия миграции).
2. CI: `cargo check -p aira-net --all-features` — если транспорты не удаляются.

**M19a / M19**
3. `read_framed`: длина > `MAX_FRAME_SIZE` → `Err` **без** выделения; длина в заголовке больше фактических данных + таймаут → `Err(Timeout)` за ≤ 30 с.
4. Fuzz `read_framed` (заголовок + postcard `Message`), fuzz `InvitationLink::from_uri`, fuzz `RelayRequest` (пока relay v1 жив).
5. Proptest `base64url_encode/decode` roundtrip + «decode(encode(x)) канонична»; отказ на мусор после валидного payload.
6. `ChatHandler`: `Message::Encrypted` от EndpointId без сессии не доходит до ratchet (после 19.5); битый кадр не рвёт соединение (после 19.3).
7. `HandshakeHandler`: приложение не отвечает 10 с → соединение закрыто, слот освобождён.
8. Файлы: отправитель → получатель через blobs с `FileAck`; blob-ciphertext не читается без ключа из `FileStart` (после 19a.5); `FsStore` переживает рестарт.
9. `two_daemons.rs` (спека M19 п.15) — единственный тест, который докажет доставку.

**M20**
10. `AiraPreset` + `run_relay_server()`: relay-only соединение; `n0_fallback = false` → `Endpoint::addr().relay_url` указывает на свой relay; при недоступном relay — `connect` падает за ≤ 5 с, не висит.
11. Парсинг `[network]` из TOML и env, roundtrip через settings.

**M21** (к списку M21 п.8 спеки)
12. Коробка с 20 конвертами по 64 KB выгружается полностью (пагинация) — регрессия §2 HIGH.
13. Ack по `seq`: две коробки на пару, одинаковые ratchet-counter не мешают.
14. `Deposit` без `Register` → `MailboxNotFound`; replay `Deposit` с тем же nonce → отклонён.

**M22**
15. Rate limit по EndpointId: 6-е сообщение от stranger за минуту отброшено; contact — без лимита; лимит соединений на tier.

## 11. Не проверено

- **Компиляция и прогон тестов aira-net на этом дереве** — `cargo test -p aira-net -- --list` падает на `sha3 0.11.0-rc.6` из-за
  незакоммиченного bump'а `ml-dsa` в `Cargo.toml` владельца (та же причина, что в `facts-crates.md`). Число тестов (104) — по grep, а не по
  списку `cargo test`. Данные `facts-crates.md` «net 42» относятся к HEAD 971e038 без диффа.
- **Собираются ли feature-gated транспорты** (`--features obfs4,mimicry,cdn,reality,tor`) на rustc 1.94 / rustls 0.23.37 — не собирал;
  последняя известная сборка — 2026-04-03.
- **Эксперимент D** (3 ошибки в `endpoint.rs` при iroh 1.1) не повторялся; предположение, что 2 «ошибки вывода типов» — каскад от
  `empty_builder`, основано на чтении API 1.1, не на компиляции.
- Поведение `presets::Minimal` при bind под Windows (IPv6 loopback) — не запускал.
- Реальный трафик транспортов через nDPI/Wireshark — не запускал; выводы §8 о детектируемости — по формату кадров в коде.
- Пиковая память `MemStore` на большом файле и фактическая утечка temp-тегов — оценка по коду (`std::mem::forget`), без замера.
- Работоспособность `RelayClient` против relay с коробкой > 256 KB — вывод по коду (`write_framed` проверка `:33`), тестом не воспроизводил.
- Точная длина `postcard(EndpointAddr)` в iroh 1.1 для оценки размера ссылки (§3) — оценка ±100 байт.
- `aira-relay`/community relays (§8.6 главного документа) — вне задания B.
