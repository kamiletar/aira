# SPEC §4: Криптографическая схема

[← Индекс](../SPEC.md)

---

### 4.1 Идентичность пользователя

Каждый пользователь имеет **Identity Keypair**:

- Алгоритм: **ML-DSA-65** (FIPS 204, Dilithium)
- Публичный ключ = адрес пользователя (как в Tox)
- Отображается пользователю как hex-строка или QR-код
- Ключи выводятся детерминистично из **seed-фразы** (см. п. 4.8)
- Крейт: `ml-dsa` из RustCrypto

```rust
// aira-core/src/identity.rs
pub struct Identity {
    pub verifying_key: ml_dsa::VerifyingKey<ml_dsa::MlDsa65>,
    signing_key: zeroize::Zeroizing<ml_dsa::SigningKey<ml_dsa::MlDsa65>>,
    /// Master seed для деривации всех ключей (зашифрован в storage)
    master_seed: zeroize::Zeroizing<[u8; 32]>,
}
```

### 4.2 Key Agreement (сессионные ключи)

Используется **гибридный KEM** для защиты от "harvest now, decrypt later".

**Конструкция combiner** следует рекомендациям IETF
`draft-ounsworth-cfrg-kem-combiners` — каждый KEM-секрет хэшируется
отдельно перед комбинированием:

```
SharedSecret = BLAKE3-KDF(
    context = "aira/hybrid-kem/1",
    input   = counter || BLAKE3(X25519_secret) || BLAKE3(MLKEM768_secret)
              || X25519_ct || MLKEM768_ct
)
```

Где `counter = 0x00000001` (32-bit LE), `*_ct` — публичные ciphertext/DH
values (binding к конкретному обмену, защита от re-binding attacks).

> ⚠️ **Почему не простая конкатенация** `BLAKE3(x25519 || mlkem || ctx)`:
> IETF combiner draft требует domain separation каждого компонента.
> Простая конкатенация не имеет формального security proof для гибридных
> KEM. Включение ciphertext'ов в KDF — стандартная практика (Signal PQXDH,
> X-Wing draft-connolly-cfrg-xwing).

- **X25519** — классический ECDH (защита от атак сегодня)
- **ML-KEM-768** — постквантовый KEM (защита от квантового компьютера)
- Оба должны быть скомпрометированы одновременно, чтобы атака удалась
- Крейт: `ml-kem` из RustCrypto, `x25519-dalek`

### 4.3 Симметричное шифрование

- **ChaCha20-Poly1305** (256-бит ключ, квантово-устойчив)
- Крейт: `chacha20poly1305` из RustCrypto

### 4.4 Forward Secrecy — Triple Ratchet (SPQR)

**Triple Ratchet** по модели Signal SPQR (Sparse Post-Quantum Ratchet,
Eurocrypt 2025) — два ratchet работают параллельно:

```
┌──────────────────────────────────────────────────┐
│  Classical Double Ratchet (X25519)                │
│  • DH ratchet при каждом обмене сообщениями       │
│  • Symmetric chain ratchet для каждого сообщения  │
├──────────────────────────────────────────────────┤
│  PQ Ratchet (ML-KEM-768)                         │
│  • KEM ratchet каждые N сообщений (sparse)       │
│  • ML-KEM encapsulation/decapsulation            │
├──────────────────────────────────────────────────┤
│  Key mixing: session_key = KDF(classical ‖ pq)   │
│  Каждое сообщение защищено обоими ratchet'ами     │
└──────────────────────────────────────────────────┘
```

**Почему не просто Double Ratchet:**

- Классический DR защищает ongoing messages только X25519
- Если квантовый компьютер скомпрометирует X25519 — все сообщения
  после handshake раскрыты (PQ защита только на этапе X3DH-PQ)
- Triple Ratchet смешивает PQ + классику на каждое сообщение

**Частота PQ ratchet (важно — отличие от paper):**

Paper "Triple Ratchet" (ePrint 2025/078, Dodis et al.) описывает отправку
KEM-chunk с **каждым** сообщением. Aira использует **sparse** подход:
PQ ratchet шагает при **смене направления диалога** (как в Signal SPQR
deployment) или каждые **N сообщений в одном направлении** (N = 50 по
умолчанию, настраивается). Это осознанный trade-off:

- ML-KEM-768 encapsulation = ~1088 байт CT на каждый шаг
- Каждое сообщение: +1088 байт overhead (неприемлемо для мобильных)
- Sparse (каждые ~50 или при смене направления): ~2% overhead

> Paper также предлагает **Katana** — кастомный KEM, на ~40% эффективнее
> ML-KEM-768 для ratcheting. Оценить для v0.2 как bandwidth optimization.

**Wire format:** `EncryptedEnvelope` содержит опциональный PQ ciphertext:

```rust
pub struct EncryptedEnvelope {
    pub nonce: [u8; 12],
    pub counter: u64,
    pub ciphertext: Vec<u8>,
    /// PQ KEM ciphertext (присутствует при шаге PQ ratchet)
    pub pq_kem_ct: Option<Vec<u8>>,
}
```

Между шагами PQ ratchet — классический DR. Ключи смешиваются
через KDF, поэтому атакующий должен сломать оба.

**Деградация:** если один из ratchet'ов не поддерживается (старый клиент) —
сессия работает только на классическом DR. Но не может быть принудительно
понижена атакующим (SPQR property).

- Реализовать самостоятельно поверх примитивов из п. 4.2-4.3
- Reference: Signal SPQR paper (Eurocrypt 2025, USENIX Security 2025)

**MAX_SKIP DoS protection:**

Атакующий может отправить сообщение с `counter = 100_000`, заставляя
получателя вычислить 100,000 промежуточных chain keys. Без ограничения
это DoS вектор (CPU + memory exhaustion).

```rust
/// Максимальное количество пропущенных сообщений в одном chain step
const MAX_SKIP: u64 = 1000;

// При получении EncryptedEnvelope:
if envelope.counter > current_counter + MAX_SKIP {
    return Err(RatchetError::TooManySkipped {
        requested: envelope.counter,
        current: current_counter,
        max_skip: MAX_SKIP,
    });
}
```

- MAX_SKIP = 1000 — достаточно для нормального out-of-order (сетевые
  задержки, relay буферизация), но блокирует DoS
- Пропущенные message keys хранятся в памяти с TTL = 24 часа, затем GC
- При SessionReset (§4.9) — все пропущенные ключи уничтожаются

### 4.5 Handshake (PQXDH)

Адаптация Signal PQXDH — расширение X3DH с PQ KEM:

```
Alice                                    Bob
  |                                       |
  | --- [Identity_A, Ephemeral_KEM_CT] -> |
  |                                       | (Bob decapsulates, derives root key)
  | <- [Identity_B, Ephemeral_KEM_CT] -- |
  |                                       |
  | ---- [Encrypted: "Hello"] ----------> |
  |       (Triple Ratchet activated)      |
```

### 4.5.1 Handshake и MTU fragmentation

> ⚠️ **Критично:** суммарный размер handshake пакета превышает MTU.

**Размеры PQ ключей (FIPS 203/204):**

| Компонент | Размер |
|-----------|--------|
| ML-KEM-768 ciphertext | 1,088 байт |
| ML-KEM-768 public key | 1,184 байт |
| ML-DSA-65 public key | 1,952 байт |
| ML-DSA-65 signature | 3,309 байт |
| ML-DSA-65 private key | 4,032 байт (хранение) |
| **Handshake пакет (суммарно)** | **~6,400+ байт** |

Типичный MTU: 1,500 байт (Ethernet), 1,280 байт (IPv6 minimum).
Handshake превышает MTU в **4-5 раз**.

**Стратегия:**

QUIC фрагментирует CRYPTO frames автоматически — handshake разбивается
на несколько QUIC пакетов. Однако:

- Многие мобильные операторы **блокируют фрагментированные UDP пакеты**
- Корпоративные файрволы могут дропать UDP с таймаутом 30-60 сек

**Решение (на уровне aira-net):**

1. Handshake разбивается на **несколько ALPN-протокольных сообщений**
   (не полагаемся только на QUIC CRYPTO fragmentation)
2. Первый пакет ≤ 1200 байт (QUIC Initial requirement)
3. PQ ключевой материал отправляется в follow-up QUIC streams
4. При провале UDP — автоматический fallback на iroh WebSocket relay
   (HTTP/1.1 over TLS, проходит через корпоративные прокси)

```
Handshake (chunked):
  Msg 1 (≤1200B): Identity_A hash + X25519 ephemeral + capabilities
  Msg 2: ML-KEM-768 ciphertext (1088B)
  Msg 3: ML-DSA-65 signature (3309B)
  Msg 4: ML-DSA-65 public key (1952B) [если не кэширован]
```

### 4.6 Хэширование и KDF

- **BLAKE3** для всего (быстрее SHA-3, не уязвим к length extension)
- Крейт: `blake3`

### 4.7 Ключи в памяти

- Все секретные ключи в `zeroize::Zeroizing<_>` — автоочистка при Drop
- Крейт: `zeroize`

### 4.8 Seed-фраза и детерминистичная деривация ключей

Аккаунт создаётся из **seed-фразы** (24 слова, BIP-39 wordlist). Это
единственный секрет, который пользователю нужно сохранить для полного
восстановления аккаунта на любом устройстве.

**Схема деривации:**

```
Seed Phrase (24 words, BIP-39 wordlist)
    ↓ Argon2id(phrase, salt="aira-master-v1-m256", m=256MB, t=3, p=4)  [desktop]
    ↓ Argon2id(phrase, salt="aira-master-v1-m64",  m=64MB,  t=4, p=4)  [mobile]
Master Seed (32 bytes)
    ↓ BLAKE3-KDF(context="aira/identity/0")
ML-DSA-65 Signing Key (identity)
    ↓ BLAKE3-KDF(context="aira/x25519/0")
X25519 Static Key
    ↓ BLAKE3-KDF(context="aira/mlkem/0")
ML-KEM-768 Decapsulation Key
    ↓ BLAKE3-KDF(context="aira/storage/0")
Storage Encryption Key (для redb)
```

**Почему Argon2id, а не PBKDF2:**

- Seed-фраза — 24 слова из словаря 2048 — перебираема при утечке
- Argon2id — memory-hard, GPU/ASIC resistant
- Крейт: `argon2`

**Адаптивные параметры:**

| Платформа | m (memory) | t (iterations) | p (parallelism) | Salt |
|-----------|-----------|----------------|-----------------|------|
| Desktop   | 256 MB    | 3              | 4               | `aira-master-v1-m256` |
| Mobile    | 64 MB     | 4              | 4               | `aira-master-v1-m64`  |

- OWASP минимум: m=19MB; IETF RFC 9106: m=64MB — mobile параметры
  соответствуют стандарту
- 256MB на устройстве с 1-2GB RAM = OOM kill (iOS/Android)
- **Параметры закодированы в salt** — при восстановлении seed на другой
  платформе daemon пробует оба набора параметров автоматически
- Desktop (256MB) и mobile (64MB) параметры дают **один и тот же**
  Master Seed, если salt совпадает. Поэтому каждый набор параметров
  имеет уникальный salt

**Нюанс ML-DSA:** `ml-dsa` крейт генерирует ключи из 32-байтного seed
через внутренний `expandA` / `expandS`. Нужно убедиться что API принимает
внешний seed (xi-seed в FIPS 204). Если нет — использовать деривированный
seed как источник для `ChaChaRng` и передать в keygen.

**Суффикс `/0`** в контексте деривации — номер поколения ключа. Позволяет
ротацию ключей в будущем (инкремент `/1`, `/2`, ...) без смены seed-фразы.

### 4.9 Session Reset (перезапуск сессии)

**Проблема:** ratchet state может быть потерян — переустановка приложения,
восстановление из бэкапа без ratchet states, повреждение storage. Без явного
механизма сессия "зависает": стороны не могут расшифровать сообщения друг друга.

> ⚠️ Это нельзя добавить потом без breaking change в протоколе.
> Опыт Matrix и Wire: отсутствие session reset → накапливающиеся
> "undecryptable" сообщения, которые пользователи не могут исправить.

**Решение — `SessionReset` как специальный PlainPayload:**

```rust
pub enum PlainPayload {
    // ... остальные варианты
    /// Запрос на полный сброс и перезапуск сессии через PQXDH
    SessionReset {
        /// Причина сброса (для отображения пользователю)
        reason: SessionResetReason,
        /// Новый ephemeral ключ для нового handshake
        new_kem_pk: Vec<u8>,
    },
}

pub enum SessionResetReason {
    /// Потеря ratchet state (переустановка, восстановление)
    StateLost,
    /// Пользователь явно запросил сброс
    UserRequested,
    /// Автоматическое обнаружение рассинхронизации
    OutOfSync { last_valid_counter: u64 },
}
```

**Процесс:**

```
Alice (потеряла ratchet state)        Bob
  |                                    |
  | --- SessionReset { StateLost } --> |
  |     (зашифровано последним         |
  |      известным ключом или          |
  |      plaintext если ключей нет)    |
  |                                    | ⚠ UI: "Alice переустановила Aira.
  |                                    |    Ключи безопасности изменились."
  | <-- HandshakeInit (новый PQXDH) -- |
  | --- HandshakeAck ----------------> |
  | <---- Encrypted (новый ratchet) -- |
```

**Безопасность:**

- После reset — Safety Number меняется, пользователь видит уведомление
- Старая история остаётся (если была), но новые сообщения в новом ratchet
- Если обе стороны потеряли ключи — любая из них инициирует reset
- Автодетекция: если N подряд сообщений не расшифровываются → предложить reset

```
CLI: /reset-session <contact>
  ⚠ Это сбросит ключи шифрования с Alice.
  После сброса верифицируйте Safety Number.
  Продолжить? [y/N]
```

```rust
// aira-core/src/seed.rs

pub struct MasterSeed(zeroize::Zeroizing<[u8; 32]>);

impl MasterSeed {
    /// Создать из seed-фразы (24 слова)
    /// Восстановить из seed-фразы (24 слова).
    ///
    /// BIP-39: 24 words = 256 bits entropy + 8-bit SHA-256 checksum.
    /// Checksum ОБЯЗАТЕЛЬНО проверяется — предотвращает опечатки.
    /// Поддерживается только English wordlist (стандарт BIP-39).
    ///
    /// ВАЖНО: Aira использует Argon2id вместо стандартного BIP-39
    /// PBKDF2-SHA512. Seed-фразы Aira НЕ совместимы с крипто-кошельками.
    pub fn from_phrase(phrase: &str) -> Result<Self, SeedError> {
        let entropy = bip39_decode(phrase)?; // validates checksum internally
        let mut seed = [0u8; 32];
        argon2id_hash(&entropy, b"aira-master-v1-m256", &mut seed)?;
        Ok(Self(zeroize::Zeroizing::new(seed)))
    }

    /// Сгенерировать новую seed-фразу
    pub fn generate() -> (String, Self) {
        let entropy = rand::random::<[u8; 32]>();
        let phrase = bip39_encode(&entropy);
        let seed = Self::from_phrase(&phrase).unwrap();
        (phrase, seed)
    }

    /// Деривировать ключ для конкретной цели
    pub fn derive(&self, context: &str) -> zeroize::Zeroizing<[u8; 32]> {
        let mut out = [0u8; 32];
        blake3::derive_key(context, &self.0, &mut out);
        zeroize::Zeroizing::new(out)
    }
}
```

**UX при первом запуске:**

```
> aira init

  Создать новый аккаунт или восстановить?
    [1] Новый аккаунт
    [2] Восстановить из seed-фразы

> 1

  ⚠ Запишите seed-фразу и храните в безопасном месте!
  Это единственный способ восстановить аккаунт.

  abandon ability able about above absent
  absorb abstract absurd abuse access accident
  achieve acid acoustic acquire across act
  adapt add admit adult advance advice

  Введите фразу для подтверждения: _

  ✓ Аккаунт создан
  Ваш публичный ключ: 7f3a...b2c1
```
