# SPEC §11+11A+11B: Модель угроз, DPI, DDoS

[← Индекс](../SPEC.md)

---

## 11. Модель угроз

Файл `docs/THREAT_MODEL.md` должен покрывать:

| Угроза                                                     | Митигация                                           |
| ---------------------------------------------------------- | --------------------------------------------------- |
| Пассивное прослушивание трафика сейчас                     | QUIC TLS 1.3 + ChaCha20-Poly1305                    |
| Quantum adversary (сбор трафика сейчас, расшифровка потом) | ML-KEM-768 гибридный KEM                            |
| Подделка идентичности                                      | ML-DSA-65 подпись, TOFU model                       |
| Компрометация одного сообщения                             | Triple Ratchet (SPQR) forward secrecy               |
| PQ атака на ongoing messages (не только handshake)         | SPQR: PQ ratchet каждые ~50 сообщений               |
| Memory safety exploits                                     | Safe Rust, zeroize                                  |
| Metadata (кто с кем общается)                              | Pairwise relay mailboxes, padding                   |
| Traffic analysis (длина сообщений)                         | Padding до фиксированных блоков 256-4096 байт       |
| MITM при первом соединении                                 | Safety Numbers, TOFU + out-of-band верификация      |
| Атака на bootstrap ноды                                    | Signed peer records, TOFU для контактов             |
| Спам / массовые Contact Request                            | PoW (20 бит), rate limiting, block list             |
| Flood в групповых чатах                                    | Rate limit 30 msg/min, admin-only invites           |
| DPI / блокировка протокола                                 | Pluggable transports, protocol mimicry (п. 11A)     |
| Активное зондирование (active probing)                     | REALITY-like: fallback на легитимный сайт           |
| DDoS / connection exhaustion                               | Connection tiers, puzzles, rate limiting (п.11B)    |
| CPU exhaustion через крипто                                | Adaptive puzzles перед PQ handshake                 |
| DHT poisoning / Sybil                                      | IP diversity, signed records, PoW (п. 11B.4)        |
| Relay flooding                                             | Per-identity квоты, ring buffer, PoW (п. 11B.5)     |
| Amplification attack                                       | QUIC 3x limit, authenticated deposits               |
| Eclipse attack (изоляция ноды)                             | Subnet diversity, anchor connections (п. 11B.7)     |
| Доказательство авторства сообщения третьей стороне         | Deniability: симметричные MAC, нет подписей (6.20)  |
| Скомпрометированный ключ                                   | Key revocation + DHT, уведомление контактов (6.18)  |
| Link preview утечка IP                                     | Превью генерирует отправитель, не получатель (6.12) |
| Typing indicator как метаданные активности                 | Opt-out per-contact, rate limit (п. 6.15)           |

Вне scope v0.1: полная анонимность на уровне сети (onion routing).

---

## 11A. Защита от DPI и цензуры

### 11A.1 Модель угрозы

DPI-системы (ТСПУ в РФ, GFW в Китае, NessFW в Иране) анализируют трафик
на нескольких уровнях:

| Уровень        | Что видит DPI                   | Как блокирует                              |
| -------------- | ------------------------------- | ------------------------------------------ |
| IP/Port        | Destination IP + порт           | Блокировка IP, портов                      |
| Протокол       | QUIC headers, SNI в TLS         | Блокировка по сигнатуре протокола          |
| Статистика     | Размер/время пакетов            | ML-классификация (CNN/LSTM)                |
| Active probing | Ответы на нестандартные запросы | Подключается к серверу, проверяет протокол |

### 11A.2 Архитектура: Pluggable Transport Stack

Вдохновлено ptrs (Rust PT framework) и AmneziaWG 2.0. Каждый слой
независимо конфигурируем:

```
┌──────────────────────────────────────────────────┐
│  aira-core: зашифрованные сообщения (ChaCha20)   │
├──────────────────────────────────────────────────┤
│  Padding Layer: все пакеты → фиксированный размер│
│  (16 KB, как SimpleX Chat)                       │
├──────────────────────────────────────────────────┤
│  Obfuscation Layer (pluggable):                  │
│  • none      — прямой QUIC (без цензуры)         │
│  • obfs4/o5  — рандомизация (ptrs крейт)         │
│  • mimicry   — мимикрия под DNS/QUIC/SIP         │
│  • reality   — мимикрия под TLS к реальному сайту│
│  • hysteria2 — маскировка под HTTP/3             │
├──────────────────────────────────────────────────┤
│  Transport Layer (pluggable):                    │
│  • direct    — прямое UDP соединение             │
│  • relay     — через iroh relay (WebSocket/TLS)  │
│  • cdn       — через Cloudflare Worker / CDN     │
│  • tor       — через Tor (arti)                  │
│  • snowflake — через ephemeral WebRTC peers      │
└──────────────────────────────────────────────────┘
```

### 11A.3 Режимы для разных уровней цензуры

**Режим 1 — Без цензуры (по умолчанию):**

- Прямой QUIC, message padding
- Минимальный overhead

**Режим 2 — Умеренная цензура (Россия, Турция):**

- obfs4/o5 обфускация через ptrs
- CDN relay (Cloudflare Worker) как fallback
- iroh relay через WebSocket+TLS (выглядит как обычный HTTPS)

**Режим 3 — Тяжёлая цензура (Китай, Иран):**

- REALITY-like мимикрия: соединение выглядит как TLS к apple.com/bing.com
- Провал аутентификации → трафик проксируется к реальному сайту
  (active probing не обнаружит протокол)
- Или: Tor через Snowflake/WebTunnel
- Или: Protocol mimicry в стиле AmneziaWG CPS (Custom Protocol Signature)

### 11A.4 Protocol Mimicry (вдохновлено AmneziaWG 2.0)

CPS (Custom Protocol Signature) — система мимикрии пакетов под
легитимные протоколы. Каждый пакет получает заголовок, неотличимый
для DPI от целевого протокола:

```rust
// aira-net/src/transport/mimicry.rs

pub enum MimicryProfile {
    /// Без мимикрии — стандартный QUIC
    None,
    /// Пакеты выглядят как DNS запросы/ответы
    Dns,
    /// Пакеты выглядят как QUIC/HTTP/3 к легитимному серверу
    Quic { sni: String },
    /// Пакеты выглядят как SIP (VoIP звонки)
    Sip,
    /// Пакеты выглядят как STUN (WebRTC NAT traversal)
    Stun,
    /// Кастомная сигнатура (CPS формат)
    Custom(CpsSignature),
}

/// CPS — Custom Protocol Signature (как в AmneziaWG 2.0)
pub struct CpsSignature {
    /// Шаблон: <b 0xHEX> <t> <r N> <rc N> <rd N>
    pub template: Vec<CpsToken>,
    /// Допустимый диапазон размеров пакетов
    pub size_range: (usize, usize),
}

pub enum CpsToken {
    /// Фиксированные байты (magic number протокола)
    Bytes(Vec<u8>),
    /// Текущий timestamp (4 bytes)
    Timestamp,
    /// N случайных байтов
    Random(usize),
    /// N случайных ASCII alphanumeric
    RandomAlphaNum(usize),
    /// N случайных цифр
    RandomDigits(usize),
}
```

**Как работает:**

1. Исходящий пакет оборачивается в CPS-заголовок перед отправкой
2. DPI видит пакет, соответствующий сигнатуре DNS/QUIC/SIP
3. Принимающая сторона снимает CPS-заголовок и обрабатывает QUIC пакет
4. Параметры CPS синхронизируются при handshake

### 11A.5 REALITY-like Transport (защита от active probing)

TCP-level selective proxy — самый эффективный метод против GFW-уровня DPI.
Сервер действует как **TCP-прокси**: парсит ClientHello, проверяет Session ID,
и либо обслуживает Aira клиента, либо прозрачно проксирует к реальному бэкенду.

```
Клиент                     Сервер Aira                   Реальный сайт (apple.com)
  |                           |                              |
  |--- TLS ClientHello ------>| (SNI: apple.com)             |
  |   Session ID[0..8] =     |                              |
  |   BLAKE3("aira/reality/  |                              |
  |    sid/0", PSK)[0..8]    |                              |
  |                           |-- Парсинг Session ID ---     |
  |                           |                              |
  | [Аира клиент — short_id верен]:                          |
  |<-- TLS ServerHello -------|  (ephemeral self-signed cert)|
  |<-- TLS Certificate -------|  (клиент: AcceptAnyCert)    |
  |--- TLS Finished --------->|                              |
  |   [TLS 1.3 туннель]      |                              |
  |--- [0xA1][nonce][MAC] --->|  Аира аутентификация        |
  |<-- [0xA2][nonce] ---------|  (BLAKE3-MAC + PSK)         |
  |=== Аира данные (XOR) ===>|  Framed XOR keystream       |
  |                           |                              |
  | [Active probe — short_id неверен]:                       |
  |                           |--- ClientHello (forward) --->|
  |                           |<--- ServerHello + Cert ------|
  |<-- (TCP proxy) -----------|<--- (TCP proxy) ------------|
  |   DPI видит настоящий     |   tokio::io::copy_bidi      |
  |   apple.com трафик        |                              |
```

**Архитектура:**

1. **ClientHello parsing** — сервер парсит TLS Record Layer на уровне TCP,
   извлекает Session ID (байты 44..76 сырого TLS record)
2. **Short ID** — первые 8 байт `BLAKE3("aira/reality/sid/0", PSK)`,
   клиент внедряет их в Session ID поле ClientHello
3. **Аутентификация** — если short_id верен, сервер генерирует ephemeral
   self-signed cert (`rcgen`), завершает TLS 1.3 handshake, затем
   Aira BLAKE3-MAC аутентификация внутри TLS туннеля
4. **Active probing fallback** — если short_id неверен, сервер открывает
   TCP к реальному бэкенду (apple.com:443), пересылает ClientHello и
   запускает `copy_bidirectional` — пробер получает настоящий apple.com

**Криптография:**

- Browser fingerprint mimicry (Chrome/Firefox/Safari cipher suite ordering)
- `AcceptAnyCertVerifier` на клиенте — TLS только для DPI камуфляжа,
  аутентификация через PSK + BLAKE3-MAC
- Session ID patching — перехват сырых TLS байтов для внедрения short_id
- KDF контексты: `aira/reality/sid/0`, `aira/reality/auth/0`,
  `aira/reality/session/0`

**Защита от угроз:**

| Угроза | Митигация |
|--------|-----------|
| Passive DPI | TLS 1.3 ClientHello с browser fingerprint |
| Active probing | Настоящий apple.com контент через TCP proxy |
| SNI/IP mismatch | Пробер подтверждает: IP отвечает как apple.com |
| Replay attack | Timestamp ±60s + random nonce |
| Session ID brute force | 8 байт = 2^64 вариантов, BLAKE3 KDF |

### 11A.6 Интеграция с iroh

iroh поддерживает `CustomTransport` trait — произвольная обёртка
над async streams. Интеграция:

```rust
// aira-net/src/transport/mod.rs

pub trait AiraTransport: Send + Sync {
    /// Оборачивает исходящее соединение в выбранный транспорт
    async fn wrap_outbound(
        &self,
        stream: impl AsyncRead + AsyncWrite + Send,
        target: &NodeId,
    ) -> Result<impl AsyncRead + AsyncWrite + Send>;

    /// Принимает входящее соединение
    async fn accept_inbound(
        &self,
        stream: impl AsyncRead + AsyncWrite + Send,
    ) -> Result<impl AsyncRead + AsyncWrite + Send>;
}

// Реализации:
pub struct DirectTransport;       // без обфускации
pub struct Obfs4Transport;        // ptrs obfs4/o5
pub struct MimicryTransport;      // CPS protocol mimicry
pub struct RealityTransport;      // REALITY-like TLS camouflage
pub struct TorTransport;          // через arti
pub struct CdnRelayTransport;     // через Cloudflare Worker
```

### 11A.7 Зависимости

```toml
# Pluggable transports
ptrs = "0.8"              # obfs4/o5 (pure Rust PT framework)

# Опциональные (feature flags):
# arti-client = "0.27"   # Tor transport (feature = "tor")
# hysteria2 = "0.1"      # Hysteria 2 QUIC masquerade (feature = "hysteria")
```

### 11A.8 UX

```
> aira config transport

  Режим транспорта:
    [1] Прямой (без обфускации) — лучшая скорость
    [2] Обфускация (obfs4) — умеренная цензура
    [3] Мимикрия (QUIC/DNS/SIP) — продвинутая цензура
    [4] REALITY — максимальная защита от DPI
    [5] Tor — максимальная анонимность

> 3

  Мимикрия под:
    [1] DNS запросы
    [2] QUIC/HTTP/3
    [3] SIP (VoIP)
    [4] STUN (WebRTC)

> 2
  ✓ Транспорт: мимикрия под QUIC/HTTP/3
  Для собеседника настройка применится автоматически.
```

CLI команда: `/transport <mode>` — переключение режима

---

## 11B. Защита от DDoS и флуда

В P2P мессенджере каждая нода — и клиент, и сервер. Нет центральной
инфраструктуры для поглощения DDoS. Защита строится на трёх принципах:
**приоритизация контактов**, **adaptive cost** и **graceful degradation**.

### 11B.1 Connection Tiers — приоритизация соединений

Все входящие соединения делятся на 3 уровня:

```
Tier 1 — Verified contacts (в контакт-листе)
  → Без ограничений, максимальный приоритет
  → Никогда не дропаются при перегрузке

Tier 2 — Known peers (были handshake, не в контактах)
  → Rate limit: 100 msg/min, 10 connections
  → Дропаются при перегрузке после Tier 3

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

### 11B.2 Adaptive Client Puzzles

Перед PQ handshake незнакомая нода должна решить puzzle. Сложность
адаптируется к текущей нагрузке:

```
Нагрузка < 50%:  puzzle 16 бит (~1 ms)
Нагрузка 50-80%: puzzle 20 бит (~16 ms)
Нагрузка 80-95%: puzzle 24 бит (~256 ms)
Нагрузка > 95%:  puzzle 28 бит (~4 сек) + отклонение Tier 3
```

```rust
pub struct AdaptivePuzzle {
    /// Текущая сложность (ведущие нули в BLAKE3 хэше)
    pub difficulty: u8,
    /// Серверный nonce (предотвращает precomputation)
    pub server_nonce: [u8; 16],
    /// Timestamp (puzzle истекает через 30 секунд)
    pub issued_at: u64,
}

impl AdaptivePuzzle {
    pub fn verify(&self, client_nonce: u64) -> bool {
        let now = timestamp_secs();
        if now - self.issued_at > 30 { return false; } // expired
        let hash = blake3::hash(&[
            &self.server_nonce[..],
            &client_nonce.to_le_bytes(),
        ].concat());
        leading_zeros(hash.as_bytes()) >= self.difficulty as u32
    }
}
```

**Почему это работает:** легитимный пользователь решает puzzle один раз
при добавлении контакта. Атакующий должен решать для каждого соединения,
и стоимость растёт экспоненциально при увеличении нагрузки.

**PQ crypto НЕ является DoS вектором:** ML-KEM decapsulation ~0.05ms
(быстрее RSA в 14x), ML-DSA verify — ~0.3ms. Puzzle перед handshake
стоит дороже самой криптографии.

### 11B.3 QUIC-level защита

iroh/QUIC предоставляет встроенные механизмы:

```rust
// aira-net/src/endpoint.rs — конфигурация QUIC

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

**Amplification limit:** QUIC ограничивает ответ до 3x размера запроса
до подтверждения адреса (Retry token). Атакующий не может использовать
ноду как усилитель.

### 11B.4 DHT anti-Sybil

DHT — наиболее уязвимый компонент к Sybil-атаке (атакующий создаёт
тысячи фейковых нод и заполняет таблицу маршрутизации):

**Митигации:**

a) **IP diversity:** максимум 2 ноды из одной /16 подсети в routing table.
Атакующий с одного диапазона IP не может занять всю таблицу.

b) **Signed DHT records:** каждая запись `ML-DSA_pubkey → NodeId` подписана
ML-DSA ключом. Фейковые записи отбрасываются при проверке подписи.

c) **PoW для DHT publish:** публикация записи в DHT требует PoW (16 бит).
Подтверждение записи другими нодами — без PoW (бесплатно).

d) **TTL + refresh:** записи истекают через 24 часа. Нода должна
переопубликовать. Устаревшие записи автоматически удаляются.

e) **Fallback на direct add:** DHT опционален. Если DHT скомпрометирован —
пользователи обмениваются ключами напрямую (hex-строка / QR).

f) **Anchor connections:** daemon поддерживает 3-5 долгоживущих соединений
с проверенными нодами (bootstrap + контакты). Это предотвращает
eclipse attack — полную изоляцию ноды фейковыми пирами.

### 11B.5 Relay anti-flood

Relay хранит зашифрованные конверты для офлайн пользователей. Защита:

```
Per-identity квоты:
  - 10 MB max на mailbox (ring buffer — старые вытесняются)
  - 100 сообщений max на mailbox
  - 30 deposits/min на отправителя
  - PoW (16 бит) на каждый deposit от не-контактов

Per-relay лимиты:
  - 1 GB total storage cap
  - GC каждые 6 часов: удаление expired (TTL 7 дней)
  - Приоритет: mailbox'ы с недавним retrieve > заброшенные
```

```rust
pub struct RelayQuota {
    pub max_mailbox_size: usize,        // 10 MB
    pub max_messages_per_mailbox: u32,  // 100
    pub deposit_rate: Quota,            // 30/min
    pub pow_difficulty: u8,             // 16 бит для не-контактов
    pub total_storage_cap: usize,       // 1 GB
    pub ttl: Duration,                  // 7 дней
}
```

### 11B.5.1 Relay protocol versioning и миграция

> ⚠️ Урок SimpleXMQ: v1 → v2 несовместимы, миграция требует
> деплоя нового сервера и потери всех mailbox'ов на старом.

**Версионирование relay протокола:**

```rust
pub const RELAY_PROTOCOL_VERSION: u16 = 1;

/// Handshake relay ↔ client
pub struct RelayHello {
    pub protocol_version: u16,
    pub supported_versions: Vec<u16>,
    pub capabilities: RelayCapabilities,
}

bitflags! {
    pub struct RelayCapabilities: u32 {
        const STORE_FORWARD = 1 << 0;
        const PUSH_NOTIFY   = 1 << 1;  // v0.3
        const MULTI_DEVICE  = 1 << 2;  // v0.3
    }
}
```

**Миграция при смене relay:**

1. Пользователь выбирает новый relay
2. Регистрирует mailbox на новом relay (с тем же `mailbox_id`)
3. Отправляет контактам подписанное сообщение `RelayMigration { new_relay_id }`
4. Контакты обновляют relay для этого mailbox
5. Старый relay продолжает работать N дней (grace period)
6. После grace period — mailbox на старом relay удаляется

**Отказоустойчивость:** пользователь может зарегистрировать один mailbox
на **нескольких relay** одновременно. Отправитель пробует по приоритету.
Это критично для надёжности — если один relay упал, сообщения доходят
через второй.

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

b) **Anchor connections:** 3-5 hardcoded соединений с bootstrap нодами
и проверенными контактами. Эти соединения никогда не вытесняются.

c) **Connection table protection:** новые ноды не могут вытеснить
долгоживущие соединения. Eviction policy: приоритет по возрасту
соединения, tier, и subnet diversity.

d) **Мониторинг:** daemon логирует аномалии (резкий рост новых
соединений, потеря всех anchor'ов). Уведомление пользователю.

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

---

## 12. Групповые чаты (v0.2)
