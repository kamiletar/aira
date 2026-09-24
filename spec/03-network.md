# SPEC §5: Сетевой слой (aira-net)

[← Индекс](../SPEC.md)

---

## 5. Сетевой слой (aira-net)

> Обновлено 24.09.2026 по аудиту 2026-09 (`.claude/docs/audit-2026-09/{net-audit,community-relays,onion-antiabuse}.md`)
> и решениям владельца (`owner-decisions.md`). Пометка «(план, M<N>)» = в коде ещё нет, появится в указанном
> milestone (`spec/18-milestones.md` §16.1); без пометки — реализовано либо нормативное требование к любой реализации.

### 5.1 Транспорт: iroh

**iroh** — Rust P2P библиотека от n0, Inc. Используется как транспортный
фундамент. Решает за нас:

- QUIC поверх UDP (встроенное TLS 1.3; в iroh 1.x QUIC-стек — `noq`)
- NAT traversal: hole punching + **QAD** (QUIC Address Discovery, UDP 7842 на relay; STUN в iroh 1.x нет)
- Relay fallback через **iroh-relay** (WebSocket `/relay` поверх TLS 443) при симметричном NAT —
  и основной путь при `hide_ip` (см. ниже)
- Адресация пиров по публичному ключу (`EndpointId`, Ed25519)

```toml
[dependencies]
iroh = "1.2"          # целевая версия (M18); в коде сейчас 0.97 — публичные relay n0 отключают 0.9x 30.09.2026
iroh-blobs = "0.103"  # передача файлов (M18); в коде сейчас 0.99
# iroh-relay = { version = "1.2", features = ["server"] } — только в crates/aira-relay (M21), не в клиенте
```

**Важно**: iroh использует Ed25519 для транспортной идентичности (`EndpointId`).
Это классическая криптография на транспортном уровне — допустимо, т.к.
защищает от пассивного прослушивания сегодня. PQ-защита содержимого
обеспечивается на уровне Application Layer (п. 4).

`EndpointId` iroh и ML-DSA Identity пользователя — разные ключи. При первом
соединении пользователь доказывает владение своим ML-DSA Identity через
handshake (п. 4.5); в протоколе v2 (M19a) `EndpointId` обеих сторон входит в
подписываемый транскрипт handshake — иначе identity и транспортный адрес не связаны.
iroh `SecretKey` чат-endpoint'а выводится из seed per-device
(`aira/iroh/secret/<device_index>`, план M19; `docs/KEY_CONTEXTS.md`). У ноды с ролью
хопа (§5.5) есть **вторая** iroh-идентичность — из локального RNG, не из seed.

**Скрытие IP от собеседника (решение владельца 24.09.2026; план, M19/M19b).** По умолчанию `hide_ip = true`:

- `AiraEndpoint::bind_with(NetConfig { hide_ip: true, .. })` → `builder.clear_ip_transports()` (iroh 1.2):
  endpoint **без IP-транспортов** — не делает hole punching, не отвечает на чужие попытки, весь трафик идёт
  через relay. Контакт видит только `EndpointId` и relay-URL.
- Прямое соединение — **per-contact opt-in** («быстрый режим»: раскрывает IP этому контакту, и только ему).
- pkarr публикует только relay-URL: `AddrFilter::relay_only()` (дефолт iroh; `publish_direct_addrs = false`).
- Invitation link **не содержит IP**: `EndpointAddr::new(id).with_relay_url(url)`, любой `TransportAddr::Ip`
  отбрасывается; тест «в ссылке нет IP» (M19b). Ссылка, пересланная через чужой мессенджер, не раскрывает
  ни LAN-, ни публичный адрес.
- Превью ссылок (§6.12) при `hide_ip` — opt-in (отправитель ходит по URL со своим IP).
- Честная формулировка до M24b: **IP скрыт от собеседника; от оператора вашего relay — нет** (он видит
  IP + `EndpointId` + время/объёмы, но не содержимое). От оператора — с §5.5 (M24b).

### 5.1.1 Роли relay и собственная инфраструктура

**Два разных «relay».** Термины (глоссарий §20):

| Термин | Что это | Состояние | Где |
|---|---|---|---|
| **transport relay** = `iroh-relay` | stateless-транспорт iroh: форвардит QUIC-кадры между подключёнными к нему endpoint'ами, даёт QAD; ничего не хранит, содержимое не видит (E2E + TLS между endpoint'ами) | свой relay на `relay.<domain>` — план, M20 | mail-сервер проекта + VPS; relay сообщества |
| **mailbox relay** = `aira-relay` | сервис Aira поверх iroh (ALPN `aira/2/relay`): store-and-forward зашифрованных конвертов (mailbox v2, §6.3b), intro-mailbox, push-wake | план, M21; в коде — `aira-net/src/relay.rs` v1 (удаляется) | тот же бинарь |

**Один бинарь `aira-relay`** (план, M21; вместо двух systemd-юнитов): встроенный `iroh-relay`
(библиотечный `Server::spawn` + собственный `AccessControl`), mailbox v2 + intro, ACME (TLS-ALPN-01),
`/healthz`, метрики (localhost:9090), `.well-known/aira-relay.json` (лимиты и версия для клиентов),
регистрация в каталоге (§5.3). Режимы:

```
aira-relay --mode full        # iroh-relay + QAD + mailbox v2 + intro + push (anchor, server сообщества)
aira-relay --mode transport   # только iroh-relay + QAD; mailbox/ACME/push отсутствуют в коде (cfg-гейт) — роль `relay` в клиенте
aira-relay --mode mailbox     # только mailbox v2 за чужим iroh-relay
aira-relay --catalog          # сервис каталога / токенов / пробы на anchor (план, M24a.1)
```

**Три роли** (таблица §8.1 `community-relays.md`):

| Роль | Кто держит | iroh-relay (транспорт + QAD) | mailbox v2 / intro | Класс в каталоге | Обещание доступности |
|---|---|---|---|---|---|
| **Anchor-relay проекта** | mail-сервер + VPS в другом регионе (M20/M21) | да: домен, ACME, tcp/443 + udp/7842 | да (полные квоты) + intro-mailbox; выдаёт токены допуска, держит каталог и брокер, `iroh-dns-server` (pkarr), push-шлюз | `anchor` | целевой 99,5 %; всегда в `RelayMap` клиента |
| **Community-server-relay** | энтузиаст: VPS / домашний сервер; свой домен **или голый IP + pin** | да | по желанию оператора (`--mode transport` — без); intro — только `anchor`/`server` | `server` / `server-pinned` | измеряется каталогом (`uptime_30d`), 72 ч испытательного срока |
| **Роли `relay` и `mailbox` в клиенте** (opt-in; план, M24a.2) | desktop с публичным IP, поверх дефолтной роли `hop` (§5.5) | да: отдельный процесс `aira-relay --mode transport`, WSS на высоком порту, self-signed + pin, QAD если UDP открыт | `mailbox` — отдельный opt-in в Advanced (чужие данные на диске); класс выше `candidate` только после 72 ч uptime | `client` | нет: residential-ephemeral; home relay для других — только по opt-in или при блокировке anchor |

Инварианты для всех ролей: только между Aira-endpoint'ами (нет exit — AP-1, §5.5.2), допуск по сетевому
токену, лимиты per-client и глобальные, `/healthz` + `.well-known/aira-relay.json`, версия ≥
`min_relay_version` каталога. Роли `relay`/`mailbox` чат-идентичность **не используют**: iroh-relay
идентифицируется URL + pin, mailbox-сервис — хоп-`EndpointId`. Android исключён из ролей `relay`/`mailbox`/`hop`
(решение F9).

**Допуск по сетевому токену (план: M20 заглушка → M22).** В iroh отправитель всегда идёт на home relay
*получателя*, поэтому `access.allowlist`/`shared_token` для сообщества непригодны: клиент должен быть допущен
на **любой** relay сети, а relay должен проверять это **офлайн**.

```rust
/// Выдаёт anchor: `POST https://relays.<domain>/token` (адаптивный PoW, rate-limit по EndpointId/IP).
/// Срок 24 ч, продление за 2 ч до истечения; отзыв = короткий срок + denylist в каталоге.
pub struct AiraRelayToken {
    pub v: u8,                   // 1
    pub endpoint_id: EndpointId, // == ClientRequest::endpoint_id(), доказан relay-handshake'ом
    pub not_before: u64,
    pub expires: u64,            // ≤ 24 ч
    pub scope: TokenScope,       // RELAY | MAILBOX | INTRO
    pub nonce: [u8; 16],
    pub sig: [u8; 64],           // Ed25519 ключом выдачи anchor (решение F6; pk — в каталоге; v: 2 — ML-DSA позже)
}
```

Проверка — во встроенном `AccessControl::on_connect`: подпись, срок, `endpoint_id`, `scope`, denylist
каталога; отказ доходит до клиента как `RelayStatus::auth_denied_reason` (iroh 1.2). Stock `iroh-relay` без
Aira-кода — `access.http.url → https://relays.<domain>/relay-auth` (anchor проверяет за него; менее приватно,
«не рекомендуется»). До M22: `access.shared_token = ["<протокольная метка>"]` — метка, **не секрет** (бинарь
открыт). Остаточный риск: модифицированный клиент с валидным токеном гоняет свой iroh-трафик между своими
узлами — закрывается только квотами (`client_rx_bps` 2 MB/s, `max_clients`, месячный лимит в токене), не
криптографией.

**Один home relay на endpoint → резервирование.** У iroh ровно один home relay на endpoint; «N home relay» не
существует; при падении relay актор переподключается бесконечно (backoff ≤ 16 с), а pkarr-запись продолжает
рекламировать мёртвый URL (iroh #4476). Поэтому (план, M20/M21):

1. **Watchdog** в `net_task`: `home_relay_status()` = `Disconnected` > 30 с или `auth_denied` →
   `Endpoint::remove_relay(url)` → re-home на следующий из `RelayMap` → републикация pkarr → `insert_relay`
   после backoff; событие IPC `NetStatus { home_relay, class, since }`.
2. **2–3 `RelayRef` разных операторов** в приглашении и контакт-записи (аналог NIP-65). Отправитель при
   ошибке `connect()` — повторный pkarr-lookup → следующий URL → `pending` + mailbox. Окно недоставки ≈ 1–2 мин,
   потерь нет.
3. N-of-M применимо только к **mailbox** (N = 2 депозита из 2–3 relay, дедуп по `envelope_id`, §6.3b), не к
   транспорту.

```rust
/// Ссылка на relay в приглашении / контакте / каталоге. Никогда не содержит IP.
pub struct RelayRef {
    pub url: RelayUrl,                    // iroh-relay (транспорт); для голого IP — https://203.0.113.5:8443
    pub endpoint_id: Option<EndpointId>,  // aira-relay (mailbox) на этом же хосте, если есть
    pub class: RelayClass,                // Anchor | Server | ServerPinned | Client
    pub pin: Option<[u8; 32]>,            // SPKI SHA-256 для self-signed (класс server-pinned / client)
}
```

`RelayMap` клиента = **только свои 1–2 relay** (anchor + выбранный); каталог сообщества хранится отдельной
структурой: `net_report` iroh шлёт пробы на relay из карты (до 5 для QAD, HTTPS-пробы — на все), и каждый
relay из `RelayMap` узнаёт IP клиента.

**Relay без домена — self-signed + pin.** Let's Encrypt по IP через `tokio-rustls-acme` (форк n0)
недостижим (только `Identifier::Dns`); поддомены `<id>.r.<domain>` операторам **не выдаём** (решение F2).
Оператор без домена печатает pin при `aira-relay init`, pin попадает в `RelayEntry` каталога / `RelayRef`
приглашения; клиент — `CaTlsConfig::custom_server_cert_verifier` («SNI/IP → ожидаемый SPKI из каталога или
контакта, иначе webpki»); поле `ca_tls_config` в `AiraPreset` закладывается в M20. Браузерный клиент (M14)
такие relay использовать не может.

**`push_allowlist`.** Push-URL mailbox (`NotificationEndpoint::UnifiedPush { url }`) — единственный
outbound/SSRF-вектор relay. Разрешены только хосты из `push_allowlist` (по умолчанию push-шлюз проекта +
`ntfy.sh`), без редиректов, без приватных/loopback-диапазонов, пустое тело, ≤ 1 запрос/мин на коробку; в
`--mode transport` push и ACME отсутствуют в коде. Правило ревью: новых `reqwest`/`connect` в `aira-relay` нет.

**Лимиты.** `[limits] accept_conn_limit/accept_conn_burst` в iroh-relay ≤ 1.2.0 **не реализованы** (no-op) —
лимит соединений делается в nginx (`stream`: `limit_conn`; вариант B: `limit_req`) + fail2ban, а в
`aira-relay` — свой accept-лимит и `max_clients` в `AccessControl::on_connect` (M21). Работает только
per-client token bucket на входящие байты `client.rx` (anchor: 2 MB/s, burst 8 MB). Глобального cap полосы у
iroh-relay нет — для роли `relay` в клиенте динамический `set_client_rate_limit(total / active)` + месячный
объём (M24a.2).

**Логи без IP.** iroh-relay оборачивает каждое соединение в `info_span!("conn", peer = %peer_addr)` — IP
клиента попадает в каждую строку уровня `info`. Дефолт `RUST_LOG=warn` (unit / Docker), в `aira-relay`
`[log] client_ips = false`; пункт в `docs/RELAY.md` и `PRIVACY.md` (решение B13).

**Деплой на mail-сервере (решение B1, M20): вариант A** — nginx `stream { ssl_preread }`, SNI
`relay.<domain>` → `127.0.0.1:8443` насквозь (TLS терминирует relay, Let's Encrypt через TLS-ALPN-01,
быстрый exporter-handshake работает), **UDP 7842 открыт** (QAD), 9090 только localhost; второй anchor на VPS в
другом регионе (бюджет — открыто, B2/F10). Полный план с конфигами —
`.claude/docs/audit-2026-09/relay-deploy-plan.md`; вариант B (TLS на nginx) — `cert_mode = "Reloading"`.

**Discovery на своём домене (план, M20).** `iroh-dns-server` на `dns.<domain>` (pkarr по HTTPS `/pkarr`, без
NS-делегирования на старте; `[mainline] enabled = false`). Клиент — `crates/aira-net/src/preset.rs`:

```rust
pub struct AiraPreset {
    pub relays: Vec<RelayRef>,            // снапшот каталога: anchor ×2
    pub relay_auth_token: Option<String>, // AiraRelayToken (M22)
    pub pkarr_relay: Option<Url>,         // https://dns.<domain>/pkarr
    pub dns_origin: Option<String>,
    pub publish_direct_addrs: bool,       // false: AddrFilter::relay_only()
    pub n0_fallback: bool,                // false: публичные relay/DNS n0 не используются
    pub ca_tls_config: CaTlsConfig,       // embedded(); pin-верификатор — M24a.1
}
```

### 5.2 Peer Discovery

Два механизма:

**a) Прямое добавление:**

> ⚠️ ML-DSA-65 публичный ключ = 1 952 байта = ~3 904 hex символа.
> Это **невозможно** ввести вручную (в отличие от 64-символьного Tox ID).

**Форматы обмена ключами (от простого к сложному):**

> **Per-contact pseudonyms (§12.6):** каждый invitation link содержит
> уникальный **pseudonym pubkey**, деривированный из MasterSeed через
> монотонный counter (BIP-32 модель). Получатель видит только pseudonym —
> невозможно связать два invitation link одного пользователя.
>
> Выданные псевдонимы **хранятся**: `GetInvitation` возвращает стабильную ссылку (сейчас
> `GetMyAddress` генерирует новый псевдоним на каждый вызов — правится в M19 п.12); новый
> псевдоним — по явному запросу. Ранее выданные invitation links остаются валидными до `expires_at`.

1. **QR-код** — сканирование камерой при встрече. QR несёт **сырые байты** `postcard(InvitationLink)`
   (byte-mode; текст URI на 33 % длиннее и в Version 40-L (2 953 B) не помещается). (План, M19b.)

2. **Invitation link** (план, M19b; формат v2):

   ```
   aira://add/<base64url(postcard(InvitationLink))>
   ```

   ```rust
   // crates/aira-net/src/discovery.rs
   pub struct InvitationLink {
       pub version: u8,                 // 1, первое поле — для миграций формата
       pub pseudonym_pk: Vec<u8>,       // ML-DSA-65 pseudonym pubkey, 1 952 B
       pub relays: Vec<RelayRef>,       // 2–3 relay разных операторов (§5.1.1); без IP
       pub endpoint_id: EndpointId,     // чат-EndpointId; прямых адресов нет (hide_ip)
       pub fingerprint_hint: [u8; 8],   // BLAKE3(pseudonym_pk)[..8] — для сверки на экране
       pub expires_at: Option<u64>,
       // M22: stamp: Option<ContactStamp> — tier для незнакомцев (§11B.1)
       pub sig: Vec<u8>,                // pseudonym-ключом над всеми полями выше
   }
   ```

   Копируется через буфер обмена, мессенджер, email. При открытии Aira показывает fingerprint
   для верификации. Подпись защищает `relays`/`endpoint_id` от подмены в незащищённом канале
   (иначе трафик уйдёт на чужой `EndpointId`, который провалит handshake — DoS, не компрометация).

   > ⚠️ **Размер (открыто, решить в M19b).** Без `sig` ≈ 2,3 KB postcard — в QR byte-mode влезает.
   > Подпись ML-DSA-65 (3 309 B) — нет. Варианты: `sig` — Ed25519-подключом, детерминированно
   > выведенным из псевдонима (64 B), либо QR без подписи (подпись только в текстовой ссылке).
   > Декодер base64url — канонический, с лимитом длины (сейчас принимает неканонические строки).

3. **Short fingerprint** — для устной верификации:
   `BLAKE3(pseudonym_pk)[..8]` → 16 hex символов (например, `a7f3-b2c1-e4d5-9f0a`).
   НЕ используется для добавления (коллизии!), только для подтверждения
   что обе стороны видят один ключ. Полная верификация — Safety Number ≥ 128 бит (`/verify`, M19b).

4. **Intro-mailbox v2** (план, M21; заменяет «relay-assisted exchange» с одноразовыми токенами) —
   первый контакт без общего секрета: Alice кладёт `ContactRequest` (§13.2) в intro-коробку Bob'а на его
   mailbox relay (`aira/relay/intro/v2` по `pseudonym_pk` из ссылки). Принимается только `ContactRequest` с
   **PoW ≥ 20 бит** над `relay_nonce ‖ request` (+ `slot`, M22), rate limit по `EndpointId`; intro-коробки —
   только на relay класса `anchor`/`server`. Bob забирает запрос при следующем `Retrieve` и решает
   Accept / Reject / Block.

```
CLI:
  /invite          → показывает QR в терминале (sixel/kitty) + invitation link
  /add <link>      → добавить по invitation link
  /add --scan      → сканировать QR (если есть камера)
  /requests        → входящие contact requests (Accept / Reject / Block)
```

**b) DHT — после релиза (решение владельца A3).** В релизе discovery = **pkarr через собственный
`iroh-dns-server`** (§5.1.1): endpoint публикует подписанную своим `EndpointId` запись `_iroh.<z32>` с
relay-URL (только relay, IP не публикуется), контакт резолвит по `EndpointId` из invitation link.
Отображение «ML-DSA pseudonym → `EndpointId`» живёт в подписанной ссылке и в контакт-записи, не в сети.
Публичные сервисы n0 (`dns.iroh.link`, relay n0) не используются (`n0_fallback = false`): метаданные третьей
стороне, поддержка 0.9x заканчивается 30.09.2026. Kademlia/mainline-DHT (запись `ML-DSA_pubkey → EndpointId`
с подписью, anti-Sybil §11B.4) — кандидат после 1.0; модуль `DeviceRecord` («DHT multidevice records»)
удаляется или уходит за фичу `dht`.

### 5.3 Каталог relay и якоря проекта

«Bootstrap-нод» как отдельной сущности нет: точки входа = **якоря проекта** и **подписанный каталог relay**
(план, M24a.1; до него — снапшот anchor ×2 в бинаре, M20).

**Якоря проекта:** anchor-relay (§5.1.1) — снапшот в бинаре (anchor + `server` на момент сборки); всегда в
`RelayMap`, никогда не исключаются автоматически (только понижаются в ранге). Для Aira Onion (§5.5) — 3–5
нод-хопов проекта, используются **только если у клиента нет других точек входа**; ожидаемо заблокированы в
strict-странах, нужны для первого запуска вне их.

**Каталог (signed relay list):**

```rust
// aira-core::catalog (postcard + JSON-зеркало для людей)
pub struct RelayCatalog {
    pub version: u32,
    pub issued_at: u64, pub expires_at: u64,       // ≤ 7 дней; просроченный используется, но client-класс не запрашивается
    pub min_client_version: Version, pub min_relay_version: Version,
    pub strict_countries: Vec<CountryCode>,         // авто-hidden / гейт роли relay (§5.5.10)
    pub relays: Vec<RelayEntry>,
    pub denylist: Vec<EndpointId>,
    pub next_signing_key: Option<Vec<u8>>,          // ротация: новый ключ объявляется за релиз до использования
    pub signature: Vec<u8>,                         // ML-DSA-65
}
pub struct RelayEntry {
    pub url: RelayUrl, pub mailbox_endpoint_id: Option<EndpointId>,
    pub class: RelayClass,                          // anchor | server | server-pinned (client — не в файле)
    pub services: Services,                         // IROH_RELAY | QAD | MAILBOX | INTRO | ONION_HOP
    pub region: String, pub operator_id: [u8; 32],  // хэш ключа оператора
    pub pin: Option<[u8; 32]>,
    pub limits: RelayLimits,                        // client_rx_bps, envelope_max
    pub first_seen: u64, pub uptime_30d: u8, pub contact: Option<String>,
}
```

- **Подпись:** один офлайн-ключ ML-DSA-65 владельца на старте, **2-of-3 к 1.0** (решение F1); публичный
  ключ вшит в бинарь; подпись — ручной шаг релиза каталога (раз в неделю или по событию).
- **Распространение:** (1) снапшот в бинаре; (2) `GET https://relays.<domain>/catalog.v1` с
  `If-None-Match`; (3) зеркало на GitHub Releases — только fallback (в цензурируемых странах блокируется);
  (4) ALPN `aira/2/catalog` на anchor — клиент, дотянувшийся до любого relay, получает каталог без HTTPS к
  домену проекта; (5) записи `client`-класса **не в файле** — выдаются брокером anchor по
  аутентифицированному запросу «3 client-relay рядом» (≤ 3 за запрос, rate limit по токену) — против
  перечисления residential-IP. Обновление на клиенте — раз в сутки и при старте.
- **Регистрация:** `RelayAnnounce` (подпись оператора + PoW 20 бит + ≤ 5 записей на `operator_id`) →
  `candidate` → 72 ч активных проверок anchor'ом (`/healthz`, WSS-handshake, QAD, `RelayHello`) с ≥ 99 %
  успехов → `server`; 3 подряд неуспешных проверки → `down`; 24 ч `down` → удаление. Ручной `denylist` в
  подписанном каталоге.
- **Не в каталоге:** поддомены операторам не выдаются (свой домен либо IP + pin, F2); открытые relay
  (`access = "everyone"`) не допускаются (F7); **hidden-ноды (§5.5) в каталог не попадают** никогда.
- **Выбор на клиенте:** home relay и 2–3 mailbox-relay — не более одного на `operator_id`, IPv4 `/24`,
  IPv6 `/48`; ранжирование `uptime_30d` × latency `net_report`; локальный health-score (`relay_stats`:
  ok / fail / ewma_rtt / backoff), автоисключение после 3 подряд ошибок на 1 ч → ×2 до 24 ч; телеметрия на
  anchor не отправляется.

### 5.4 Протокол поверх iroh (ALPN)

Протокол v2 (M19a) без совместимости с 0.3.x (решение A2); `aira/1/*` удаляются.

```rust
// crates/aira-net/src/lib.rs
pub const ALPN_CHAT: &[u8]      = b"aira/2/chat";
pub const ALPN_HANDSHAKE: &[u8] = b"aira/2/handshake";
pub const ALPN_FILE: &[u8]      = b"aira/2/file";
pub const ALPN_HOP: &[u8]       = b"aira/2/hop";      // Aira Onion, §5.5 (план, M24b)

// crates/aira-relay (план, M21): b"aira/2/relay" — mailbox v2; `aira/1/relay` удаляется вместе с aira-net/src/relay.rs
// anchor (план, M24a.1):         b"aira/2/catalog"
```

`RelayServer` v1 в роутере клиента **не регистрируется** (M19): иначе каждый клиент — открытый mailbox без
аутентификации. ALPN и параметры TLS читаются любым наблюдателем из QUIC Initial (RFC 9001) —
переименование не прячет протокол; обфускация первого хопа — §5.5.10 / §11A (M24c).

### 5.5 Aira Onion — скрытие IP и анти-паразитный форвардинг (план, M24b–M24d)

Рабочее имя «Aira Onion» (имя фичи в UI/спеке — открытое решение владельца, C11). Полный дизайн,
прецеденты и числа — `.claude/docs/audit-2026-09/onion-antiabuse.md`; здесь — нормативная часть.
Порядок: M24b Onion v1 (до 1.0, решение C4) → M24c мосты/обфускация (до 1.0 для strict-стран) →
M24d mix-профиль (после 1.0).

#### 5.5.1 Постановка и обещания

Постановка владельца: (1) протокол нельзя превратить в паразитирующий прокси — ни слив чужого трафика
через relay, ни выход в интернет, ни mailbox как хранилище, ни чужой трафик с IP пользователя; (2) IP
скрывать от собеседника, оператора relay, провайдера/DPI, глобального наблюдателя; (3) **все пиры — хопы**
(как I2P), не только opt-in серверы. Вывод аудита: (1) и (3) — одно требование. Паразитный прокси
возникает не от того, *кто* форвардит, а от четырёх свойств сети: выход в интернет; хоп соединяется с
адресом из пакета; большие нетарифицированные кадры; форвардеров мало. Их закрывают инварианты §5.5.2.

**Обещания по четырём наблюдателям** — единственно допустимые формулировки для README / THREAT_MODEL /
PRIVACY (решение B12): это **устойчивость, не невидимость**; слово «невзламываемый» не употребляется.

| Наблюдатель | Сегодня (v0.3.x) | После M19/M20 (`hide_ip`) | После M24b (onion) | После M24d (mix) |
|---|---|---|---|---|
| Собеседник | видит IP при любом прямом соединении | **IP скрыт**: relay-only, ссылка без IP; direct — per-contact opt-in | то же + не видит ваш relay/guard | то же |
| Оператор одного relay / хопа / mailbox | IP + `EndpointId` + коробки | IP + `EndpointId` (один relay видит всё, кроме содержимого) | видит **либо** ваш IP (guard), **либо** mailbox (H), никогда связку; корреляция по времени требует сговора G + H | сговор G + H не даёт корреляции без долгих наблюдений |
| Провайдер / ТСПУ | QUIC v1 к relay/пирам (фингерпринт версии), SNI relay в WSS, ALPN `aira/*` в Initial | то же (WSS:443 на свой домен — блокируется по SNI/IP) | вход через резидентные мосты без каталога; после M24c — датаграммы без сигнатуры | то же |
| Глобальный пассивный наблюдатель | всё | всё (тайминг / объёмы) | корреляция по времени возможна (как в Tor) | Poisson-микширование + cover-петли; анонимность ограничена размером активного множества |
| Sybil-оператор многих хопов | н/п | н/п | guard-персистентность, разнообразие /16 и AS, вес по uptime; всё же дешевле, чем в Tor | то же |

#### 5.5.2 Анти-паразитные инварианты (нормативно)

**ЛЮБОЙ форвардящий код — хоп, mailbox, роль `relay` в клиенте, standalone `aira-relay` — ОБЯЗАН соблюдать:**

- **AP-1 Нет выхода.** Нет операции «соединись с host:port». Терминал любого маршрута — mailbox v2
  (`Deposit`) на ноде Aira или SURB-ответ. Файлы, превью, всё внешнее — никогда через хоп.
- **AP-2 Следующий хоп — только из своей таблицы.** Ячейка несёт `next: EndpointId`; адрес хоп берёт из
  собственной таблицы нод / через свой relay, **не** из ячейки (`TransportAddr::Ip` в ячейке невалиден).
  Реализация — `EndpointHooks::before_connect` (iroh 1.2) отклоняет адреса не из таблицы; иначе хоп —
  распылитель QUIC Initial по чужим IP (reflection / сканирование).
- **AP-3 Ячейки маленькие и фиксированные.** 1 024 B полезных; «потока» через хоп не существует;
  64 KB конверт = 64 ячейки, 1 GB = миллион ячеек с PoW-тарифом.
- **AP-4 Каждый байт тарифицирован.** Форвардинг только под `key_id`, выданным за PoW; у ключа бюджет байт
  и скорость; у ноды — `share`; fair queuing (DRR) между ключами; сложность PoW растёт с нагрузкой ноды
  (Tor hspow) — под давлением платят те, кто давит.
- **AP-5 Хоп не отвечает за содержимое и не является источником.** Хоп общается только с нодами Aira;
  авторизация депозита — подпись `sender_sk` внутри ячейки, поэтому mailbox лимитирует по
  `sender_pk`/коробке, **не** по IP / `EndpointId` хопа.
- **AP-6 Хранилище — только зарегистрированные коробки.** Без `Register` владельца коробка не создаётся;
  регистраций ≤ 20/сутки на ноду; квоты 10 MB / 100 конвертов / 7 дней; бюджет хранилища ноды
  (`storage_budget`, 0 у клиентов по умолчанию).
- **AP-7 Ёмкость растёт с нагрузкой.** Форвардинг включён у всех, у кого он безопасен; ноды паразита внутри
  сети тоже форвардят (иначе не получат скидку к PoW, §5.5.5) — I2P-модель, 20 лет без банка и токена.

Честно нерешаемое: паразит может написать своё приложение поверх ячеек (C2 ботнета через mailbox) —
неотличимо от пользователя (E2E). AP-3/4/6 держат это в классе «медленно и дорого», AP-1/2/5 гарантируют,
что добровольцы не становятся ни источником, ни выходом.

#### 5.5.3 Роли, классы, две идентичности

Роли одной ноды (флаги `NodeRecord.caps`): `client` (всегда), `hop` (форвардер ячеек), `mailbox` (хост
коробок v2), `bridge` (нелистингуемая точка входа для контактов), `relay` (встроенный iroh-relay, §5.1.1).

| Класс | Кто | hop | mailbox | bridge | листинг в peer exchange |
|---|---|---|---|---|---|
| `server` | standalone `aira-relay` | да | да | да | да (если не hidden) |
| `desktop-public` | публичный IP или NAT с `mapping_varies_by_dest = false` (iroh `net_report`), unmetered, не на батарее | **да по умолчанию** (opt-out) | да (бюджет диска; opt-in) | да | да, кроме strict-стран |
| `desktop-nat` | достижим только через свой relay (symmetric NAT) | да, вес ×0.3 | нет | да | да, кроме strict-стран |
| `laptop-battery` | на батарее / metered | да, share ×0.25 | нет | да | да |
| `mobile` | Android (iOS исключён) | **нет** (решение C7) | нет | нет | нет |
| `hidden` (модификатор) | strict-страна (авто, §5.5.10) или выбор пользователя | только для контактов и их маршрутов | только для контактов | да | **нет** |

**Две iroh-идентичности, два `Endpoint` в одном демоне (решение C5):** чат-`EndpointId` (из seed,
известен контактам) и **хоп-`EndpointId`** — случайный при установке, локальный секрет, не из seed,
ротируется по кнопке. Причина: запись хопа содержит способ дойти до ноды; будь она подписана чат-ключом,
любой контакт нашёл бы ваш IP в peer exchange. Цена — второе relay-соединение (relay и так ваш guard).
Хоп-ключи KEM (`hop_x25519`, `hop_mlkem_ek`) — тоже локальные, ротация раз в неделю
(`docs/KEY_CONTEXTS.md`, «Исключения: не-KDF ключи»).

#### 5.5.4 Запись ноды и её распространение

```rust
// crates/aira-onion
pub struct NodeRecord {
    pub version: u8,                    // 1
    pub hop_id: EndpointId,             // хоп-идентичность (Ed25519, iroh)
    pub hop_x25519: [u8; 32],           // KEM-ключи хопа для HopSetup
    pub hop_mlkem_ek: [u8; 1184],       // ML-KEM-768 encapsulation key
    pub class: NodeClass,
    pub caps: Caps,                     // hop | mailbox | bridge | relay
    pub relay_urls: Vec<RelayUrl>,      // как дойти до NAT-хопа — без IP
    pub share_hint_kbps: u16,           // объявленная полоса форвардинга
    pub obfs_psk_hint: Option<[u8; 8]>, // есть ли мост-обфускация (M24c); сам PSK — только контактам
    pub stamp: Option<ContactStamp>,    // tier (M22, §5.5.13)
    pub issued_at: u64, pub expires_at: u64, // 24 ч
    pub sig: [u8; 64],                  // Ed25519 по hop_id над всем выше
}
```

≈ 1,4 KB (ML-KEM ek доминирует). Каналы распространения — **без глобального каталога**:

1. **Invitation link / QR** — не запись (не влезет), а `bridge_hint = hop_id ‖ relay_url` (≈ 80 B)
   одного–двух хопов приглашающего (его guard или он сам как bridge); первое соединение — к нему, он отдаёт
   свою `NodeRecord` и до 8 соседних.
2. **E2E-канал с контактом** — `PlainPayload::BridgeOffer(NodeRecord + obfs_psk)`: контакт делится своим
   мостом/хопом (darknet Hyphanet, private bridge Tor). Единственный канал для `hidden`-нод.
3. **Peer exchange** по уже построенному маршруту: `GetPeers { n ≤ 8 }` под `key_id` (то есть за PoW), не
   чаще 1/ч на ключ; отдаются только `listed`-ноды, которые отдающий **сам успешно использовал** за 24 ч
   (proof-by-use против Sybil-листинга).
4. **Якоря проекта** (§5.3) — только если пусто.
5. pkarr (свой `iroh-dns-server`) — опционально, только relay-URL хоп-ключа, никогда для `hidden`.

#### 5.5.5 Установление ключа с хопом (`HopSetup`)

Клиент (любая роль) открывает iroh-соединение с хопом по ALPN `aira/2/hop` (напрямую или, для NAT-хопа,
через его `relay_urls`) и **раз в сутки на хоп** делает:

```
HopSetup {
    key_id:      [u8; 8],                             // случайный, выбирает клиент
    kem:         HybridCt,                            // X25519 eph pk (32) ‖ ML-KEM-768 ct (1088) — kem.rs::hybrid_encaps
    pow:         { nonce: u64, bits: u8, slot: u32 }, // над hop_id ‖ key_id ‖ BLAKE3(kem) ‖ slot; slot = 10-мин окно
    want:        Budget { bytes: u32, rate_kbps: u16 },
    guard_proof: Option<NodeRecord + sig>,            // ТОЛЬКО первому хопу (guard)
}
→ HopSetupOk { bytes, rate_kbps, expires_at, next_bits } | Busy { bits_required }
```

- `ss = hybrid_decaps(..)`; `k_hop = derive_key("aira/hop/key/v1", ss)`; подключи `aira/hop/fwd/v1`,
  `aira/hop/back/v1`, `aira/hop/surb/v1`; привязка PoW — `aira/hop/pow/v1`. Постквантово: ML-KEM раз в
  сутки, а не в каждой ячейке (упрощение Outfox с кэшем ключа — ячейка не таскает 1 088-байтный ct).
- Состояние хопа на ключ ≈ 100 B (`k_hop`, `bytes_left`, token bucket, окно anti-replay 1 024 бит по
  counter, `expires`); таблица ≤ 50 000 ключей (≈ 5 MB), LRU; вытесненный ключ → ячейка молча дропается →
  клиент делает `HopSetup` заново (без потери сообщений: доставка подтверждается ответом H).
- `slot` из другого окна невалиден → precomputation / replay невозможны (та же правка, что для
  `ContactRequest`, M22).
- **Адаптивная сложность** (Tor hspow): `bits = 16 + f(заполнение таблицы, утилизация share)`, до 24;
  при > 95 % — `Busy`. Легитимному чату ≈ 4 ключа в сутки (2 хопа × 2 направления).
- **Бюджеты (AP-4):** на ключ — **8 MB / 24 ч, 16 KB/s**, одна очередь; на ноду — `share`: desktop
  **32 KB/s исходящих, 3 GB/мес** (решение C10; I2P отдаёт 48 KB/s), `laptop-battery` ×0.25, настраивается;
  DRR между ключами; при перегрузке — `Busy` новым и пропорциональное урезание существующим. Счётчик
  «вы помогли сети на N MB» показывается пользователю (C10).
- **Мягкая взаимность на guard'е (AP-7).** Клиент, предъявивший guard'у свою свежую `NodeRecord` с
  `caps.hop = 1` и подписью, получает базовую сложность; без неё — `+4 бита` (×16 работы: ≈ 0,2 с desktop,
  ≈ 1 с телефон — терпимо для мобильных, которые хопами не бывают). Guard и так видит IP клиента.
  **На middle-хопах `guard_proof` запрещён** — иначе middle узнаёт, чей это маршрут. Ноды, объявившие себя
  хопом и не форвардящие, выпадают из peer exchange (proof-by-use) и теряют скидку. Скидку без роли `hop`
  даёт `ContactStamp` (§5.5.13).

#### 5.5.6 Ячейка (`Cell v1`)

Фиксированный размер на проводе **1 280 B** = 3 слоя заголовка × 80 B + 1 024 B payload + 16 B тег.

```
Cell  { layers: [Layer; 3], payload: [u8; 1040] }   // всегда три слоя (guard, middle, терминал); в fast-профиле middle фиктивный
Layer (80 B) = key_id 8 ‖ counter 8 ‖ cmd 1 ‖ next_hop 32 (EndpointId; нули у терминала) ‖ pad 15 ‖ tag 16
```

- **Хоп:** находит `key_id`, проверяет `counter` по окну anti-replay, AEAD-расшифровывает **свой** слой
  (nonce = counter, AAD = позиция слоя), сдвигает слои (на место третьего кладёт псевдослучайный блок из
  `k_hop`, чтобы длина не выдавала позицию — приём Sphinx), снимает свой keystream с payload, списывает
  1 280 B с бюджета ключа, отправляет `next_hop` по своей таблице (AP-2). Payload на middle не разбирается.
- **Терминал** (H или адресат SURB): проверяет тег payload, читает `cmd` и тело: `Deposit { mailbox_id,
  frag, envelope_part }`, `Register`, `Retrieve`, `Ack`, `GetPeers`, `Wake`, `Drop` (cover).
- **Фрагментация:** конверт ≤ 64 KB → ≤ 64 ячеек `{ frag_id 8, idx u8, total u8 }` в payload; H собирает,
  неполный фрагмент через 60 с дропается. Текст с паддингом 256–512 B (§6.6) = 1 ячейка, 4 KB = 4 ячейки;
  накладные ≈ 25 %.
- **Ответы:** обратное состояние **30 с** — хоп помнит `(key_id → входящее соединение)` и гонит ответные
  ячейки назад по тем же ключам (`aira/hop/back/v1`) — дешевле пачек SURB на каждый retrieve. **SURB**
  (Loopix-style, однократные, 1 ячейка) — только для асинхронного `Wake`: получатель оставляет у H запас из
  16 SURB при `Register`/`Retrieve`, H тратит один на каждое «пришло письмо».
- **Известное ограничение — tagging-атака:** guard портит payload, сговорившийся H видит битый тег в тот же
  момент; требует сговора G + H; смягчается персистентностью guard и cover-петлями mix-профиля (Loopix
  детектирует активные атаки петлями). В THREAT_MODEL — честно.

#### 5.5.7 Маршрут и профили

```
S ── G_s ── M_s ──▶ H ◀── M_r ── G_r ── R
      выбирает S             выбирает R;   H = хост mailbox v2, выбран R (2–3 реплики, §6.3b)
```

- **Deposit:** S → G_s → M_s → H; терминальный слой = `Deposit` с подписью `sender_sk` (§6.3b), H проверяет
  по зарегистрированному `sender_pk`. H видит только M_s. Никто не видит и S, и адресата.
- **Register / Retrieve / Ack:** R → G_r → M_r → H, ответ назад по обратному состоянию. H видит только M_r.
- **Push:** H → `Wake` по SURB → R делает `Retrieve`. Задержка «оба онлайн» ≈ 1–3 с.
- Композиция SimpleX (первый хоп — отправителя, второй — получателя) и Veilid (safety route + private route)
  с mailbox в точке склейки; rendezvous-схема Tor не нужна — mailbox уже есть (M21).
- **Профили** (на аккаунт, с переопределением на контакт): `fast` — S→G_s→H, R→G_r→H (guard видит H, задержка
  минимальна); **`standard` — по умолчанию** (решение C8); `mix` — standard + §5.5.11; `direct` — per-contact
  opt-in (§5.1).
- Контакт-запись: `mailboxes: Vec<MailboxRef { hop_id, relay_urls, mailbox_id }>` (§6.3b), никогда IP;
  смена H — подписанный `MailboxMigration` (§11B.5.1).

#### 5.5.8 Guard'ы, разнообразие, Sybil, churn

- **Guard'ы:** 2 активных + 1 запасной из нод с uptime-оценкой ≥ 0,9 за 7 дней (клиент ведёт локальную
  историю успехов), держатся 30 дней. Guard узнаёт IP клиента — один и тот же долго, а не 100 случайных нод в
  неделю.
- **Разнообразие:** G, M, H — разные /16 и (если есть данные) разные AS / операторы; для `hidden`-клиента —
  не из своей страны (правило I2P hidden mode).
- **Sybil дешевле, чем в Tor** (нет измерения полосы авторитетами): (а) листинг только proof-by-use;
  (б) вес по uptime; (в) guard-персистентность ограничивает окно наблюдения; (г) mailbox-хосты выбирает
  получатель из *своего* опыта, не из чужого списка. Сговор G_s + H → корреляция по времени — граница
  `standard`, закрывает `mix`.
- **Churn:** ячейки stateless, обратное состояние живёт 30 с; нет ответа от H за 5 с → повтор другим маршрутом
  (новый M, тот же G); H недоступен → следующая реплика; хопы `desktop-nat` — вес ×0.3.

#### 5.5.9 Файлы по профилям

Хоп переносит только ячейки; «потока» нет по построению (AP-3). Решение владельца C9 — медленная полоса +
`direct` с предупреждением (таблица дублируется в §6.22):

| Профиль | ≤ 64 KB (inline в конверте) | ≤ 10 MB | > 10 MB |
|---|---|---|---|
| `direct` (per-contact opt-in; IP раскрыт этому контакту) | конверт | iroh-blobs напрямую | iroh-blobs напрямую |
| hide-IP (relay-only, M19/M20) | конверт | iroh-blobs через iroh-relay (relay видит обе стороны) | то же |
| `standard` / `mix` (M24b) | ячейки | «медленная полоса»: ячейки в mailbox H (квота 10 MB), марка PoW 20 бит на MB, 16 KB/s → 10 MB ≈ 11 мин | **недоступно**; UI предлагает `direct` с предупреждением |

Медленная полоса нарочно непривлекательна для массового трафика (AP-4) и закрывает бытовой случай —
фото / голосовые ≤ 10 MB. Blob всегда шифротекст per-file ключом (§6.2).

#### 5.5.10 Против перечисления и блокировок

1. **Нет глобального каталога** (§5.5.4): peer exchange отдаёт ≤ 8 нод за ключ в час; перечисление
   opennet стоит ~1 ключ (PoW) на 8 нод и часы времени (при 1 млн нод ≈ 7 CPU-часов при 20 битах) — это
   **дёшево для государства**, как краулинг Tox / Tor-консенсуса. Поэтому:
2. **Opennet и darknet одновременно** (Hyphanet): листингуются только `desktop-public` / `server` вне
   strict-стран — их и так можно найти. Пользователи strict-стран автоматически `hidden`: не в листинге,
   форвардят только для контактов, входят в сеть через **мосты от контактов** (`BridgeOffer`) или из
   invitation link. Перечислить darknet можно только инфильтрацией социального графа. Строго: «все пиры
   форвардят, но не все перечислимы».
3. **Определение strict-страны** — не GeoIP-база в бинарнике, а: локаль + часовой пояс ОС + страна публичного
   IP от *своего* relay (`X-Aira-Country` в ответе `/token`) + явный выбор в онбординге с объяснением.
   Список `strict_countries` — в подписанном каталоге (§5.3), старт — список I2P (RU, CN, IR, …); override
   через Advanced с предупреждением (решение F5). **Состав списка и кто его ведёт — открыто (C6).**
4. **Транспорт первого хопа (план, M24c).** Прямой QUIC iroh фингерпринтится ТСПУ (версия `00 00 00 01`;
   правило описано для UDP/443, iroh слушает случайный порт — отсрочка, не защита); ALPN и TLS-параметры
   читаются из QUIC Initial любым наблюдателем (RFC 9001: ключи Initial выводятся из открытого DCID).
   Обфускация датаграмм через `CustomTransport` iroh 1.x (`bind → CustomEndpoint { watch_local_addrs,
   create_sender, poll_recv }`, фича `unstable-custom-transports`): каждая датаграмма QUIC →
   `AEAD(k_obfs, nonce ‖ padding_len ‖ datagram)` без открытых полей, случайная длина, опционально
   «junk»-пакеты в начале (AmneziaWG). `k_obfs = derive_key("aira/bridge/obfs/v1", psk_моста)`; PSK — в
   `BridgeOffer` / ссылке; для листингуемых хопов — публичный из записи (защита от сигнатур, но не от
   активного зондирования — честно, как «режим 2» §11A). Это **единственная** корректная точка встраивания
   обфускации в iroh; байтовые обёртки `transport/*` удалены (§11A), идея сохраняется здесь.
5. **Relay-путь (WSS:443):** SNI = домен relay и JA4 rustls — блокируются по домену / фингерпринту; для relay
   сообщества — фронтирование через настоящий веб-сервер (WebTunnel-подход). Клиент в strict-стране
   предпочитает мосты-хопы по UDP, relay — только через мосты.
6. **Урок Snowflake:** транспорт мостов должен быть заменяемым (DTLS-фингерпринт Snowflake прожил до
   03.2026); `CustomTransport` даёт это без изменения onion-слоя.

#### 5.5.11 Mix-профиль (Loopix; план, M24d)

Каждый хоп задерживает ячейку на `Exp(λ)` (среднее 0,5 с; конфиг); клиент шлёт cover-петли (ячейка через
3 хопа и назад по SURB, `cmd = Drop`) с частотой 1 ячейка / 2 с, H тоже гоняет петли; реальный трафик
неотличим от cover. Цена: ≈ 0,65 KB/s ≈ **1,7 GB/мес** на клиента и 2–4 с задержки; **только desktop**;
анонимность против глобального наблюдателя ограничена числом одновременно активных mix-клиентов (Loopix:
гарантии зависят от λ и размера множества). Включается на аккаунт; контакты в `fast` от этого не выигрывают.

#### 5.5.12 Матрица видимости (`standard`, без сговора)

| Кто | IP отправителя | IP получателя | `mailbox_id` | время / размер | содержимое |
|---|---|---|---|---|---|
| G_s (guard S) | **да** | нет | нет | да | нет |
| M_s | нет (видит G_s) | нет | нет | да | нет |
| H (mailbox) | нет (видит M_s) | нет (видит M_r) | **да** | да | нет |
| M_r | нет | нет (видит G_r) | нет | да | нет |
| G_r (guard R) | нет | **да** | нет | да | нет |
| iroh-relay G_s / G_r (если NAT) | да | — | нет | да | нет |
| провайдер S | да (свой) | нет | нет | да, к какому IP (мост) | нет |
| собеседник | **нет** | — | да | да | да |

#### 5.5.13 `ContactStamp` как tier

`ContactStamp { epoch, bits, nonce }` — hashcash `BLAKE3("aira/contact-stamp/v1" ‖ pseudonym_pk ‖ epoch ‖
bits ‖ nonce)` (план, M22; §11B.1, §13.2): истекает (epoch = неделя), считается per-pseudonym (не линкует
псевдонимы), не меняет ключ и seed (после восстановления пересчитывается в фоне), проверяется кем угодно
офлайн. В сети даёт tier: скидка к базовой сложности `HopSetup` (альтернатива `guard_proof` для нод без
роли `hop`), приоритет в очередях `ContactRequest` незнакомцев и регистраций mailbox; поле в
`InvitationLink`, `ContactRequest`, `NodeRecord`. Настоящий уровень доверия — граф и поведение: контакт >
контакт контакта > незнакомец со штампом > без; для хопов — наблюдаемый uptime (proof-by-use).

#### 5.5.14 Где это живёт в коде

- `crates/aira-onion` (новый, `#![deny(unsafe_code)]`, без iroh): `NodeRecord`, `HopSetup`, `Cell`,
  слоение / снятие слоёв, SURB, фрагментация, бюджеты и PoW-верификация; proptest (roundtrip слоёв, «после
  снятия слоя длина не меняется», anti-replay) и fuzz (`Cell`, `NodeRecord`, `HopSetup` — внешние данные по
  определению).
- `crates/aira-net/src/hop.rs`: `HopHandler: ProtocolHandler` на ALPN `aira/2/hop`, таблица ключей (LRU,
  окна), обратное состояние 30 с, DRR между ключами, share-бюджет, `EndpointHooks::before_connect` (AP-2),
  второй `Endpoint` для хоп-идентичности, peer exchange, uptime-история.
- `crates/aira-relay`: тот же `HopHandler` + mailbox v2, принимающий `Deposit` из ячеек; `surb_stock`.
- `crates/aira-daemon`: профили (`fast` / `standard` / `mix`, `direct` per-contact), hidden mode, бюджеты в
  settings, IPC `GetNetStatus { role, share_used, keys, guards }`; UI — экран Network (роль, share, guard'ы,
  счётчик помощи сети).
- `docs/KEY_CONTEXTS.md`: `aira/hop/{key,fwd,back,surb,pow}/v1`, `aira/bridge/obfs/v1`; хоп-идентичность и
  KEM-ключи хопа — локальный RNG, **не** из seed (задокументировано как исключение).
- Тесты M24b: 5 демонов in-process (S, G, M, H, R) — доставка; «H не знает IP S и R» (assert по
  логам / статусу); «хоп не соединяется с IP из ячейки»; бюджет исчерпан → `Busy`; replay → drop; churn
  (убить M посреди передачи).

**Открытые решения владельца:** состав и ведение strict-списка стран (C6); имя фичи в UI / спеке (C11).
Принятые: `hide_ip` по умолчанию (A6), второй `Endpoint` под хоп (C5), мобильные — только клиент (C7),
профиль `standard` (C8), файлы — медленная полоса + `direct` (C9), share 32 KB/s / 3 GB/мес и счётчик (C10),
M24b до 1.0 (C4), таблица обещаний вместо «невзламываемый» (B12).

---
