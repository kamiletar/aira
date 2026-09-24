# SPEC §11+11A+11B: Модель угроз, DPI, DDoS

[← Индекс](../SPEC.md)

---

## 11. Модель угроз

Публичные документы — `docs/THREAT_MODEL.md` (таблица обещаний по четырём наблюдателям, статусы
«код / M<N>») и `docs/PRIVACY.md` («что видит каждый наблюдатель»); **спека — нормативный источник**,
при расхождении правится документ. Обновлено 24.09.2026 по аудиту 2026-09 и решениям владельца.

| Угроза                                                     | Митигация                                           |
| ---------------------------------------------------------- | --------------------------------------------------- |
| Пассивное прослушивание трафика сейчас                     | QUIC TLS 1.3 + ChaCha20-Poly1305                    |
| Quantum adversary (сбор трафика сейчас, расшифровка потом) | ML-KEM-768 гибридный KEM                            |
| Подделка идентичности                                      | ML-DSA-65 подпись, TOFU model                       |
| Компрометация одного сообщения                             | Triple Ratchet (SPQR) forward secrecy               |
| PQ атака на ongoing messages (не только handshake)         | SPQR: PQ ratchet каждые ~50 сообщений               |
| Memory safety exploits                                     | Safe Rust, zeroize                                  |
| Metadata (кто с кем общается)                              | Pairwise mailbox v2 по направлению (§6.3b), relay-only endpoint (`hide_ip`, §5.1), onion 2+M+2 (§5.5, M24b), padding |
| Traffic analysis (длина сообщений)                         | Padding до фиксированных блоков 256-4096 байт; onion — ячейки 1 280 B (M24b) |
| MITM при первом соединении                                 | Safety Numbers, TOFU + out-of-band верификация      |
| Утечка IP собеседнику / в invitation link                  | `hide_ip = true`: `clear_ip_transports()`, ссылка без IP, pkarr только relay (§5.1); direct — per-contact opt-in |
| Атака на якоря / каталог relay                             | Подписанный каталог (ML-DSA-65; 2-of-3 к 1.0), TOFU для контактов, точки входа без глобального каталога (§5.3, §5.5.10) |
| Спам / массовые Contact Request                            | PoW адаптивный 16→28 бит с `server_nonce ‖ slot`, rate limiting, block list, `ContactStamp` (п. 11B.1, §13) |
| Flood в групповых чатах                                    | Rate limit 30 msg/min, admin-only invites           |
| DPI / блокировка протокола                                 | `hide_ip` + iroh-relay WSS:443 на своём домене (M20); мосты с PSK-обфускацией датаграмм через `CustomTransport` (M24c, п. 11A) |
| Активное зондирование (active probing)                     | PSK-мосты: без PSK мост не отвечает как Aira (M24c); REALITY-fallback на чужой сайт исключён |
| QUIC Initial / ALPN читаемы DPI (RFC 9001)                 | Обфускация датаграмм первого хопа (`aira/bridge/obfs/v1`, M24c); переименование ALPN не помогает |
| DDoS / connection exhaustion                               | Connection tiers, puzzles, rate limiting (п.11B)    |
| CPU exhaustion через крипто                                | Adaptive puzzles перед PQ handshake                 |
| Sybil среди relay / хопов                                  | Каталог: 72 ч испытания, PoW на announce, ≤ 5 записей/оператор, denylist; хопы: proof-by-use, guard-персистентность, разнообразие /16 + AS (§5.3, §5.5.8); DHT — после релиза (п. 11B.4) |
| Relay flooding                                             | Регистрация коробок владельцем, квоты на коробку и конверт, TTL на конверт, `Register` ≤ 20/сутки, intro PoW (п. 11B.5) |
| Паразитный прокси через relay / хопы (exit, слив чужого трафика, mailbox как хранилище, чужой трафик с IP пользователя) | Инварианты AP-1…AP-7 — обязательны для любого форвардящего кода (§5.5.2) |
| Перечисление relay / хопов и блокировка списка             | Нет глобального каталога, мосты через контакты (`BridgeOffer`), hidden mode для strict-стран (§5.5.10) |
| Корреляция по времени guard + mailbox (сговор)             | Mix-профиль: Poisson-задержки + cover-петли (M24d); до него — честно в `docs/THREAT_MODEL.md` как граница `standard` |
| Tagging-атака guard + H (onion)                            | Требует сговора; guard-персистентность, cover-петли mix; честно в `docs/THREAT_MODEL.md` (§5.5.6) |
| Amplification attack                                       | QUIC 3x limit, подписанные deposits, AP-2 (хоп не шлёт по адресу из ячейки) |
| Eclipse attack (изоляция ноды)                             | Subnet / operator diversity, anchor connections (п. 11B.7) |
| Push-URL mailbox как SSRF / exit relay                     | `push_allowlist`, без редиректов и приватных диапазонов (§5.1.1, M21) |
| Оператор relay хранит IP клиентов (логи)                   | `RUST_LOG=warn`, `[log] client_ips = false`; `docs/PRIVACY.md` «что видит оператор» |
| Файлы через iroh-blobs открытым содержимым (не PQ)         | Per-file ключ из ratchet, blob = шифротекст, хэш от шифротекста (§6.2, M19a) |
| Доказательство авторства сообщения третьей стороне         | Deniability: симметричные MAC, нет подписей (6.20)  |
| Скомпрометированный ключ                                   | Key revocation, уведомление контактов (6.18); DHT-часть — после релиза |
| Link preview утечка IP                                     | Превью генерирует отправитель, не получатель (6.12); при `hide_ip` — opt-in |
| Typing indicator как метаданные активности                 | Opt-out per-contact, rate limit (п. 6.15)           |

Scope по версиям: onion-маршрутизация (Aira Onion, §5.5) — **M24b (план, до 1.0)**; mix-профиль против
глобального наблюдателя — **M24d (после 1.0)**. До M24b формулировка: «IP скрыт от собеседника (relay-only);
от оператора вашего relay — нет».

**Таблица обещаний.** Единственно допустимые формулировки для README, `docs/THREAT_MODEL.md`,
`docs/PRIVACY.md` и статей — по четырём наблюдателям (полная таблица — §5.5.1; решение владельца B12):

| Наблюдатель | Обещание после M19/M20 | После M24b | После M24d |
|---|---|---|---|
| Собеседник | IP скрыт (relay-only, ссылка без IP); direct — по вашему выбору для конкретного контакта | + не видит ваш relay / guard | то же |
| Оператор одного relay / хопа / mailbox | видит ваш IP и `EndpointId`, не содержимое | видит **либо** IP, **либо** mailbox — никогда связку | сговор двух операторов не даёт корреляции по времени без долгих наблюдений |
| Провайдер / DPI | видит зашифрованный трафик к relay (SNI / QUIC v1) — **устойчивость к блокировкам, не невидимость** | вход через резидентные мосты; после M24c — без сигнатуры | то же |
| Глобальный пассивный наблюдатель | ничего не обещаем | корреляция по времени возможна (как в Tor) | Poisson-микширование + cover-трафик, с оговорками о размере активного множества |

Правило: слово **«невзламываемый»** (и «анонимный» до M24b) в документах и коде не употребляется —
это приглашение для аудиторов и репутационный риск при первом же timing-исследовании.

---

## 11A. Защита от DPI и цензуры

> **Решение владельца 24.09.2026 (A13):** модули `aira-net/src/transport/*` (REALITY, «obfs4», mimicry/CPS,
> CDN, Tor) **удалены из `main`**. Они не были подключены к iroh (байтовые потоки vs QUIC-датаграммы),
> не собирались в CI с апреля и криптографически несостоятельны: «obfs» без секрета (ключ из открытых
> nonce), REALITY с открытым 8-байтным префиксом, replay в окне ±60 с и статическим session key, mimicry с
> length-prefix перед фейковым заголовком, CDN/Tor — заглушки (net-audit §8). При этом GUI/CLI позволяли
> выбрать любой режим, а трафик не менялся. Обфускация возвращается в M24c как `CustomTransport`;
> до M24c `SetTransportMode ≠ direct` → `DaemonResponse::Error("not supported in this release")`, выбор в UI скрыт.

### 11A.1 Модель угрозы

DPI-системы (ТСПУ в РФ, GFW в Китае, NessFW в Иране) анализируют трафик
на нескольких уровнях:

| Уровень        | Что видит DPI                   | Как блокирует                              |
| -------------- | ------------------------------- | ------------------------------------------ |
| IP/Port        | Destination IP + порт           | Блокировка IP, портов                      |
| Протокол       | QUIC headers, SNI в TLS         | Блокировка по сигнатуре протокола          |
| Статистика     | Размер/время пакетов            | ML-классификация (CNN/LSTM)                |
| Active probing | Ответы на нестандартные запросы | Подключается к серверу, проверяет протокол |

**Факты (2022–2026), от которых считаем:**

- ТСПУ фингерпринтит QUIC v1 по байтам версии `00 00 00 01` на UDP/443 при размере ≥ 1 001 B
  (Xue et al., IMC'22). iroh слушает случайный порт — это отсрочка, не защита: правило расширяемо на любые порты.
- **QUIC Initial расшифровываем любым наблюдателем**: ключи Initial выводятся из открытого DCID и известной
  соли (RFC 9001 §5.2, «no confidentiality against on-path»). ALPN `aira/2/*`, SNI и transport parameters
  читаются из первого же пакета; переименование ALPN не прячет протокол.
- SNI-блокировка WSS к relay по домену; **ECH заблокирован в РФ с 11.2024**; JA4 rustls отличим от браузеров
  (переставленные cipher suites uTLS не заменяют).
- Фингерпринт транспорта живёт месяцы, но не годы: Snowflake DTLS — до 03.2026; Moat-bridges Tor блокировались
  в РФ в 12.2021, 11.2024, 03.2026. Транспорт мостов должен быть заменяемым.

### 11A.2 Режимы → статус

Вместо «Pluggable Transport Stack» (§11A.2–11A.5 прежней редакции — удалены):

| Режим | Что это | Статус |
|---|---|---|
| `direct` | прямой QUIC iroh, message padding (§6.6) | **реализовано** — единственный `TransportMode` в коде |
| `hide_ip` (relay-only) | endpoint без IP-транспортов (`clear_ip_transports()`), весь трафик через iroh-relay (§5.1) | план, **M19/M20** (по умолчанию) |
| iroh-relay по WSS:443 на своём домене | «режим 2»: трафик выглядит как HTTPS к `relay.<domain>`; вариант A деплоя (§5.1.1) | план, **M20**. Ограничение: SNI = домен relay и JA4 rustls → блокируется по домену / фингерпринту; для relay сообщества — фронтирование настоящим веб-сервером (WebTunnel-подход) |
| Мосты с PSK-обфускацией датаграмм | `CustomTransport` iroh 1.x (фича `unstable-custom-transports`): `AEAD(k_obfs, nonce ‖ padding_len ‖ datagram)`, случайная длина, junk-пакеты; PSK из `BridgeOffer` / ссылки; `k_obfs = derive_key("aira/bridge/obfs/v1", psk)` | план, **M24c** (до 1.0 для strict-стран). Без PSK мост не отвечает как Aira — защита от активного зондирования; с публичным PSK листингуемого хопа — только от сигнатур |
| Hidden mode + мосты от контактов | вход через `BridgeOffer`, нода не листингуется, relay только через мост (§5.5.10) | план, M24c |
| REALITY / obfs4 / mimicry (CPS) / CDN / Tor (arti) / Snowflake | — | **удалены из кода** (решение владельца 24.09); после 1.0 возможны только как реализации `CustomTransport`; REALITY (TCP-прокси с fallback на чужой сайт) исключён |

### 11A.6 Интеграция с iroh: `CustomTransport` (план, M24c)

Реальный API iroh 1.x — `iroh::endpoint::transports` (фича `unstable-custom-transports`; API нестабилен,
версию iroh фиксировать):

```rust
// iroh 1.2, socket/transports/custom.rs (упрощённо)
pub trait CustomTransport: Send + Sync + 'static {
    /// Поднимает транспорт; iroh получает endpoint с датаграммным интерфейсом
    fn bind(&self) -> io::Result<Arc<dyn CustomEndpoint>>;
}
pub trait CustomEndpoint: Send + Sync {
    /// «Адреса» этого транспорта (для моста — идентификатор моста, не IP)
    fn watch_local_addrs(&self) -> Watcher<Vec<CustomAddr>>;
    /// Отправка датаграмм
    fn create_sender(&self) -> Box<dyn CustomSender>;
    /// Приём датаграмм
    fn poll_recv(&self, cx: &mut Context<'_>, bufs: &mut [IoSliceMut<'_>], metas: &mut [RecvMeta])
        -> Poll<io::Result<usize>>;
}
```

Это **датаграммы, не байтовые потоки**: QUIC живёт в UDP-датаграммах, поэтому обёртки над
`AsyncRead + AsyncWrite` (старый трейт `AiraTransport`) к iroh неприменимы по построению. Мост Aira =
`CustomTransport`, который шифрует каждую датаграмму PSK-ключом и шлёт её на UDP-адрес моста; на стороне
моста — обратная операция и передача в локальный iroh-endpoint (роль `bridge`, §5.5.3). Транспорт заменяем
без изменения onion-слоя (урок Snowflake).

### 11A.7 Зависимости

```toml
# M24c
iroh = { version = "1.2", features = ["unstable-custom-transports"] }
# ptrs / arti-client / hysteria2 — не используются (удалены вместе с transport/*; optional-deps
# reqwest, rustls, tokio-rustls, webpki-roots, rcgen, tokio-socks уходят из aira-net)
```

### 11A.8 UX

Выбор транспорта из UI **убран до M24c** (сейчас `SetTransportMode ≠ direct` → `Error("not supported")`,
пункт скрыт). Вместо него — профили и мост от контакта:

```
Settings → Network
  Профиль:   privacy (по умолчанию: hide_ip, relay-only; после M24b — onion standard)
             fast    (прямые соединения с контактами, которым вы это разрешили)
  Мост:      «получить мост от контакта» (BridgeOffer) / вставить из ссылки        — M24c
  Регион:    авто-hidden по strict-списку; override в Advanced с предупреждением     — M24c
```

Per-contact: «Разрешить прямое соединение с этим контактом» (раскрывает IP этому контакту).
CLI: `/net profile <privacy|fast>`, `/bridge add <offer>`; `/transport <mode>` удалена.

---

## 11B. Защита от DDoS и флуда

В P2P мессенджере каждая нода — и клиент, и сервер. Нет центральной
инфраструктуры для поглощения DDoS. Защита строится на трёх принципах:
**приоритизация контактов**, **adaptive cost** и **graceful degradation**.

### 11B.1 Connection Tiers — приоритизация соединений

Все входящие соединения делятся на уровни:

```
Tier 1 — Verified contacts (в контакт-листе)
  → Без ограничений, максимальный приоритет
  → Никогда не дропаются при перегрузке

Tier 2 — Known peers (были handshake, не в контактах)
  → Rate limit: 100 msg/min, 10 connections
  → Дропаются при перегрузке после Tier 3

Tier 3+ — Strangers with ContactStamp (незнакомец с действующим штампом; план, M22)
  → Rate limit как у Tier 3, но приоритет в очереди ContactRequest / intro-mailbox
    и скидка к базовой сложности HopSetup (§5.5.13)

Tier 3 — Strangers (неизвестные ноды)
  → Rate limit: 5 msg/min, 2 connections
  → PoW обязателен для любого взаимодействия
  → Первыми дропаются при перегрузке
```

```rust
// aira-net/src/ratelimit.rs

use governor::{Quota, RateLimiter};
use std::num::NonZeroU32;

pub struct PeerLimits {
    pub contacts: Quota,     // unlimited (u32::MAX / sec)
    pub known: Quota,        // 100/min
    pub strangers: Quota,    // 5/min
}

impl Default for PeerLimits {
    fn default() -> Self {
        Self {
            contacts: Quota::per_second(NonZeroU32::MAX),
            known: Quota::per_minute(NonZeroU32::new(100).unwrap()),
            strangers: Quota::per_minute(NonZeroU32::new(5).unwrap()),
        }
    }
}
```

> ⚠️ `PeerLimits`/`PeerTier`/`ConnectionManager` есть в коде, но ни к чему не подключены (мёртвый код);
> точка подключения — `EndpointHooks::{before_connect, after_handshake}` iroh 1.2 (M22), та же, что
> инвариант AP-2 для хопов.

**`ContactStamp` — tier для незнакомцев** (план, M22; аудит §5.3.1, решение владельца C16 — вместо идеи
«уровень надёжности по префиксу ключа», см. п. 11B.10):

```rust
// aira-core/src/spam.rs
/// Hashcash-штамп над псевдонимом. Проверяется кем угодно офлайн.
pub struct ContactStamp {
    pub epoch: u32,   // неделя; валидны текущая и предыдущая
    pub bits: u8,     // ведущие нули
    pub nonce: u64,
}
// valid ⇔ leading_zeros(BLAKE3("aira/contact-stamp/v1" ‖ pseudonym_pk ‖ epoch ‖ bits ‖ nonce)) ≥ bits
```

- **Истекает** (epoch = неделя) — приоритет нельзя купить навсегда; **per-pseudonym** — не линкует псевдонимы
  (§12.6); **не меняет ключ и seed** — после восстановления из фразы пересчитывается в фоне; мобильный
  выбирает меньший `bits`.
- Прикладывается к `InvitationLink`, `ContactRequest` (§13.2) и `NodeRecord` хопа (§5.5.4); UI — бейдж
  «дорогой контакт» без цифр.
- Настоящий уровень доверия даёт не вычисление, а граф и поведение: контакт (Tier 1) > контакт контакта
  (интродукция) > незнакомец со штампом > незнакомец без штампа; для хопов — наблюдаемый uptime.

### 11B.2 Adaptive Client Puzzles

Перед PQ handshake незнакомая нода должна решить puzzle. Сложность
адаптируется к текущей нагрузке:

```
Нагрузка < 50%:  puzzle 16 бит (≈ 10 мс)
Нагрузка 50-80%: puzzle 20 бит (≈ 0,1–0,2 с)
Нагрузка 80-95%: puzzle 24 бит (≈ 2–3 с)
Нагрузка > 95%:  puzzle 28 бит (≈ 30–50 с) + отклонение Tier 3
```

> ⚠️ **Времена — оценка, пересчитать по criterion-бенчу M19a.** Прежняя таблица (16 бит ≈ 1 мс … 28 бит ≈ 4 с)
> была занижена в 5–10×: реальный однопоточный BLAKE3 на коротком входе ≈ 5–10 MH/s → 16 бит ≈ 10 мс,
> 20 ≈ 0,1–0,2 с, 24 ≈ 2–3 с, 28 ≈ 30–50 с на desktop; телефон ×5, WASM ×3–5. Та же функция сложности и
> `slot` (10-минутное окно) — общая для `ContactRequest`, intro-mailbox и `HopSetup` (M22).

```rust
pub struct AdaptivePuzzle {
    /// Текущая сложность (ведущие нули в BLAKE3 хэше)
    pub difficulty: u8,
    /// Серверный nonce (предотвращает precomputation)
    pub server_nonce: [u8; 16],
    /// Timestamp (puzzle истекает через 30 секунд)
    pub issued_at: u64,
    /// M22: slot = 10-минутное окно — решение из другого окна невалидно (replay)
    pub slot: u32,
}

impl AdaptivePuzzle {
    pub fn verify(&self, client_nonce: u64) -> bool {
        let now = timestamp_secs();
        if now - self.issued_at > 30 { return false; } // expired
        let hash = blake3::hash(&[
            &self.server_nonce[..],
            &self.slot.to_le_bytes(),
            &client_nonce.to_le_bytes(),
        ].concat());
        leading_zeros(hash.as_bytes()) >= self.difficulty as u32
    }
}
```

> ⚠️ Текущий `ContactRequest::to_pow_bytes = from ‖ message ‖ difficulty` (`spam.rs`) не содержит nonce
> получателя и времени — одно решение переиспользуется бесконечно (precomputation / replay). В M22 —
> `recipient_pubkey ‖ server_nonce ‖ slot ‖ request`.

**Почему это работает:** легитимный пользователь решает puzzle один раз
при добавлении контакта. Атакующий должен решать для каждого соединения,
и стоимость растёт экспоненциально при увеличении нагрузки.

**PQ crypto НЕ является DoS вектором:** ML-KEM decapsulation ~0.05ms
(быстрее RSA в 14x), ML-DSA verify — ~0.3ms. Puzzle перед handshake
стоит дороже самой криптографии.

### 11B.3 QUIC-level защита

iroh/QUIC предоставляет встроенные механизмы:

```rust
// aira-net/src/endpoint.rs — конфигурация QUIC (план, M19)

let mut transport = quinn::TransportConfig::default();
// Ограничение потоков на соединение
transport.max_concurrent_bidi_streams(16u32.into());
transport.max_concurrent_uni_streams(32u32.into());
// Ограничение буферов
transport.receive_window(256u32.into());        // 256 KB
transport.send_window(256u64.into());           // 256 KB
transport.stream_receive_window(64u32.into());  // 64 KB per stream
// Таймауты
transport.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
// Retry tokens — address validation до выделения ресурсов
transport.retry_token_lifetime(Duration::from_secs(15));
```

> ⚠️ **В коде эти лимиты не выставлены** (M19): `AiraEndpoint::bind` использует дефолты QUIC-стека,
> `read_framed` выделяет 256 KB по заголовку (128 стримов × 256 KB = 32 MB на соединение), число
> соединений не ограничено, и нет ни одного таймаута (connect, `read_framed`, ответ на handshake, запрос
> к relay). M19: connect 5 с / idle 30 с / ответ relay 10 с; 16/32 стрима; окна 256/64 KB; инкрементальное
> выделение буфера.

**Amplification limit:** QUIC ограничивает ответ до 3x размера запроса
до подтверждения адреса (Retry token). Атакующий не может использовать
ноду как усилитель.

### 11B.4 DHT anti-Sybil (после релиза)

DHT — **после релиза** (решение владельца A3); discovery в релизе = pkarr через собственный
`iroh-dns-server` (§5.2b). Ниже — требования к DHT, если она появится; anti-Sybil для хопов Aira Onion —
§5.5.8 (proof-by-use, guard-персистентность, вес по uptime), для каталога relay — §5.3.

DHT — наиболее уязвимый компонент к Sybil-атаке (атакующий создаёт
тысячи фейковых нод и заполняет таблицу маршрутизации):

**Митигации:**

a) **IP diversity:** максимум 2 ноды из одной /16 подсети в routing table.
Атакующий с одного диапазона IP не может занять всю таблицу.

b) **Signed DHT records:** каждая запись `ML-DSA_pubkey → EndpointId` подписана
ML-DSA ключом. Фейковые записи отбрасываются при проверке подписи.

c) **PoW для DHT publish:** публикация записи в DHT требует PoW (16 бит).
Подтверждение записи другими нодами — без PoW (бесплатно).

d) **TTL + refresh:** записи истекают через 24 часа. Нода должна
переопубликовать. Устаревшие записи автоматически удаляются.

e) **Fallback на direct add:** DHT опционален. Если DHT скомпрометирован —
пользователи обмениваются ключами напрямую (invitation link / QR).

f) **Anchor connections:** daemon поддерживает 3-5 долгоживущих соединений
с проверенными нодами (якоря проекта + контакты). Это предотвращает
eclipse attack — полную изоляцию ноды фейковыми пирами.

### 11B.5 Relay anti-flood (mailbox v2; план, M21)

Relay хранит зашифрованные конверты для офлайн пользователей (§6.3b). Защита строится на
**регистрации коробок владельцем и квотах**, а не на PoW на депозит:

```
На коробку:
  - Register только с подписью owner_sk (+ токен scope: MAILBOX); без Register коробки нет (AP-6)
  - 100 конвертов / 10 MB (вытеснение старых → owner видит пропуск по seq)
  - конверт ≤ 64 KB (MAX_ENVELOPE_SIZE, §6.22)
  - TTL 7 дней на конверт (received_at), не на коробку
  - Deposit — подпись sender_sk[dir] + relay_nonce; PoW не нужен

На клиента (EndpointId / токен):
  - Register ≤ 20/сутки
  - Deposit ≤ 100 целей за запрос; N ≤ 3 реплик на конверт
  - intro-mailbox: только ContactRequest с PoW ≥ 20 бит над relay_nonce ‖ slot ‖ request
    (адаптивно до 28), rate limit по EndpointId; только на anchor / server

На relay:
  - total cap 1 GB (при N-of-2 эффективная ёмкость вдвое ниже)
  - GC каждый час: expired конверты; при переполнении — коробки без Retrieve дольше всего
  - max_clients + accept-лимит в AccessControl (accept_conn_limit iroh-relay — no-op), nginx limit_conn
  - push: только push_allowlist, ≤ 1/мин на коробку, без редиректов / приватных диапазонов
  - лимиты публикуются в RelayHello.limits и .well-known/aira-relay.json
```

```rust
pub struct RelayQuota {
    pub max_envelope: usize,            // 64 KB — из aira-core MAX_ENVELOPE_SIZE
    pub max_mailbox_size: usize,        // 10 MB
    pub max_envelopes_per_mailbox: u32, // 100
    pub envelope_ttl: Duration,         // 7 дней на конверт
    pub registers_per_day: u32,         // 20 на EndpointId
    pub intro_pow_min_bits: u8,         // 20 (адаптивно до 28)
    pub total_storage_cap: usize,       // 1 GB
    pub max_clients: u32,
    pub push_allowlist: Vec<String>,
}
```

Депозит от onion-хопа (M24b): лимиты считаются по `sender_pk` / коробке, **не** по IP / `EndpointId`
депозитора (AP-5) — хоп нельзя и незачем наказывать за чужой депозит.

**Бюджеты хопов** (план, M24b; нормативно — §5.5.5):

```
На ключ (key_id, выдан за PoW через HopSetup, живёт 24 ч):
  - 8 MB / 24 ч, 16 KB/s, одна очередь; окно anti-replay 1 024 бит по counter
  - PoW: base 16 бит + f(заполнение таблицы, утилизация share), до 24; > 95 % → Busy
  - slot = 10-мин окно (precomputation / replay невозможны)
  - ≤ 8 ключей на источник у guard'а — «1 GB через сеть» = ≥ 125 ключей с ≥ 16 источников,
    ≥ 17 ч на одном ключе; каждый байт стоит сети ×3

На ноду (share):
  - desktop unmetered: 32 KB/s исходящих на форвардинг, 3 GB/мес (настраивается; решение C10)
  - laptop-battery: ×0.25; desktop-nat: вес ×0.3 при выборе; mobile: 0 (только клиент)
  - DRR между ключами; при перегрузке — Busy новым, пропорциональное урезание существующим
  - таблица ключей ≤ 50 000 (≈ 5 MB), LRU

PoW-ключи и скидки:
  - guard_proof (своя NodeRecord с caps.hop) — базовая сложность; без него +4 бита; ЗАПРЕЩЁН на middle
  - ContactStamp (п. 11B.1) — скидка вместо guard_proof для нод без роли hop
  - ноды, объявившие hop и не форвардящие, выпадают из peer exchange (proof-by-use)
```

### 11B.5.1 Relay protocol versioning и миграция

> ⚠️ Урок SimpleXMQ: v1 → v2 несовместимы, миграция требует
> деплоя нового сервера и потери всех mailbox'ов на старом.
> ⚠️ В коде (mailbox v1) ничего из этого раздела нет — утверждение «заложено в wire format»
> прежней редакции было неверным. Реализуется в M21 сразу как v2; v1 (`aira/1/relay`) удаляется
> без совместимости (в проде его никто не использует).

**Версионирование relay протокола:**

```rust
pub const RELAY_PROTOCOL_VERSION: u16 = 2;

/// Handshake relay ↔ client (первое сообщение relay → клиент, §6.3b)
pub struct RelayHello {
    pub protocol_version: u16,          // 2
    pub supported_versions: Vec<u16>,
    pub capabilities: RelayCapabilities,
    pub relay_nonce: [u8; 32],          // challenge на сессию — во все подписи запросов
    pub catalog_class: RelayClass,      // anchor | server | server-pinned | client (§5.3)
    pub operator_id: [u8; 32],          // хэш ключа оператора — правило «разные операторы» (п. 11B.7)
    pub min_client_version: Version,    // клиент отклоняет relay ниже min_relay_version каталога
    pub limits: RelayLimits,            // envelope_max, per-box, ttl — источник правды для клиента
}

bitflags! {
    pub struct RelayCapabilities: u32 {
        const STORE_FORWARD = 1 << 0;
        const PUSH_NOTIFY   = 1 << 1;  // UnifiedPush по push_allowlist
        const INTRO         = 1 << 2;  // intro-mailbox (только anchor / server)
        const ONION_HOP     = 1 << 3;  // M24b
        const MULTI_DEVICE  = 1 << 4;  // M26 (device_id в Register)
    }
}
```

**Миграция при смене хоста коробок:**

1. Пользователь (owner) выбирает новый mailbox-хост из каталога (другой оператор, §5.3)
2. Регистрирует коробки на новом хосте (`Register`, те же `mailbox_id`)
3. Отправляет контактам подписанное сообщение `MailboxMigration { mailboxes: Vec<MailboxRef>, issued_at }`
   (E2E, внутри чата; прежнее имя — `RelayMigration`)
4. Контакты обновляют `MailboxConfig.mailboxes` для этого контакта
5. Старый хост продолжает работать N дней (grace period), owner делает `Retrieve` с обоих
6. После grace period — `Delete` на старом хосте

**Отказоустойчивость:** коробки живут на **2–3 хостах разных операторов** одновременно (`MailboxConfig.mailboxes`,
§6.3b); отправитель депонирует N-of-2, получатель забирает со всех с дедупом по `envelope_id`. Если один
хост упал, сообщения доходят через второй. Транспортный iroh-relay резервируется иначе — re-home по
watchdog (§5.1.1), у iroh один home relay на endpoint.

### 11B.6 Flood protection в личных чатах

Даже контакт может начать спамить (compromised device, malware):

```
Per-contact rate limits (настраиваемые):
  Default:    500 msg/min (высокий лимит для нормального использования)
  Файлы:     10 file offers/min
  Typing:    60 typing events/min

Превышение → автоматический cooldown:
  1x:  предупреждение пользователю
  3x:  mute на 5 минут
  10x: автоматический mute на 1 час + уведомление

Команда: /mute <contact> [duration] — ручной mute
```

### 11B.7 Eclipse attack prevention

Eclipse attack — атакующий заполняет все соединения ноды своими
пирами, изолируя жертву от реальной сети.

**Митигации:**

a) **Subnet diversity:** максимум 2 peer из одной /16 подсети.
Одновременно: минимум 3 разных /16 в connection table.

b) **Anchor connections:** 3-5 соединений с якорями проекта (anchor-relay, §5.3)
и проверенными контактами. Эти соединения никогда не вытесняются.

c) **Connection table protection:** новые ноды не могут вытеснить
долгоживущие соединения. Eviction policy: приоритет по возрасту
соединения, tier, и subnet diversity.

d) **Мониторинг:** daemon логирует аномалии (резкий рост новых
соединений, потеря всех anchor'ов). Уведомление пользователю.

e) **Разные операторы и AS для relay и хопов:** home relay и 2–3 mailbox-хоста — не более одного
на `operator_id` (из `RelayHello` / каталога), IPv4 `/24`, IPv6 `/48` (§5.3); guard, middle и H одного
onion-маршрута — разные /16 и (если есть данные) разные AS, для `hidden`-клиента — не из своей страны
(§5.5.8); якоря проекта — минимум два региона. Один оператор не должен видеть и вход, и выход маршрута.

### 11B.8 Graceful degradation

При перегрузке нода деградирует предсказуемо:

```
Load Level  | Действие
------------|-----------------------------------------------
< 50%       | Нормальная работа
50-70%      | Увеличение puzzle difficulty для Tier 3
70-85%      | Отклонение новых Tier 3 соединений
85-95%      | Отклонение новых Tier 2 + файлы только от Tier 1
> 95%       | Только Tier 1 (контакты), все остальные — отклонение
            | + уведомление пользователю "Under attack"
```

Метрики нагрузки: CPU usage + active connections + memory + bandwidth.

### 11B.9 Зависимости

```toml
# Rate limiting
governor = "0.8"          # GCRA rate limiter (keyed, atomic)
```

### 11B.10 Стоимость identity

Вердикт аудита (§5.3, §5.3.1) и решение владельца 24.09 (C12, C16): **PoW на ключ — grinding identity /
fingerprint, «уровень надёжности по префиксу ключа» — не делаем.** Причины:

1. **Амортизация:** одна identity = бесконечный спам после единственного платежа; бот-ферма платит один раз
   (на GPU в 50–1000× дешевле, чем жертва на телефоне) и дальше бесплатна.
2. **DDoS relay от identity не зависит:** iroh-relay / QUIC атакуют пакетами с бесплатных Ed25519
   `EndpointId`; ML-DSA identity в этом пути не участвует.
3. **Детерминизм seed → identity:** grinding должен быть детерминированным перебором `counter` от seed, иначе
   фраза не восстанавливает аккаунт — значит при каждом восстановлении пользователь снова ждёт минуты
   (ML-DSA-65 keygen ≈ 50–100 µs → 24 бита ≈ 20–30 мин на десктопе, телефон ×5–10).
4. **Контакты не видят identity-ключ:** по §12.6 каждому контакту выдаётся свой псевдоним; общий префикс у
   псевдонимов одного человека **линкует** их.
5. **Видимый префикс ломает верификацию:** пользователи сверяют fingerprint по первым символам; одинаковые
   «дорогие» префиксы дают бесплатную похожесть (vanity-адреса onion v3). Fingerprint должен быть случайным.
6. **Приоритет по цене ключа — купленный навсегда приоритет** для фермы; Tor отверг такой дизайн ради
   адаптивного per-connection PoW (hspow).

**Вместо этого — цена каждого действия + contact-first (§13.1):** адаптивный PoW с `server_nonce ‖ slot` на
`ContactRequest`, intro-mailbox и `HopSetup` (общая функция сложности, M22); `Register` ≤ 20/сутки;
квоты relay (п. 11B.5); tiers (п. 11B.1). Публично проверяемый сигнал стоимости — **`ContactStamp`**
(п. 11B.1): штамп над псевдонимом, истекает, не меняет ключ. Argon2id 256 MB на seed остаётся защитой фразы
от brute force, не anti-Sybil. Privacy Pass rate-limited tokens (issuer = relay) — после релиза.

---

> §12 «Групповые чаты» — `spec/14-groups.md`.
