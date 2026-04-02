# SPEC §13: Защита от спама

[← Индекс](../SPEC.md)

---

## 13. Защита от спама

### 13.1 Модель: contact-first

В P2P мессенджере без сервера нет централизованного модератора. Защита
строится на принципе: **нельзя отправить сообщение незнакомцу без его
согласия**.

### 13.2 Механизмы

**a) Contact Request (v0.1):**

```
Alice хочет написать Bob:
  1. Alice отправляет ContactRequest (подписанный ML-DSA):
     - свой публичный ключ
     - короткое сообщение (≤ 256 байт, plaintext)
     - Proof-of-Work (см. ниже)
  2. Bob видит запрос, решает: Accept / Reject / Block
  3. Accept → обмен handshake (п. 4.5), начало чата
  4. Reject → Alice уведомляется
  5. Block → все будущие запросы от Alice отбрасываются
```

**b) Proof-of-Work для Contact Request:**

- Для отправки запроса нужно вычислить `BLAKE3(request || nonce)` с N
  ведущими нулевыми битами
- Сложность: ~1 секунда на обычном CPU (≈20 бит)
- Предотвращает массовую рассылку запросов ботами
- Не влияет на обычных пользователей (разовая задержка)

```rust
// aira-core/src/spam.rs

pub struct ContactRequest {
    pub from: PubKey,
    pub message: String,          // ≤ 256 bytes
    pub pow_nonce: u64,
    pub pow_difficulty: u8,       // required leading zero bits
    pub signature: MlDsaSignature,
}

impl ContactRequest {
    pub fn verify_pow(&self) -> bool {
        let hash = blake3::hash(&self.to_pow_bytes());
        leading_zeros(hash.as_bytes()) >= self.pow_difficulty as u32
    }
}
```

**c) Rate limiting (v0.1):**

- Daemon отбрасывает > 10 Contact Request / минуту от разных ключей
- 3 запроса от одного ключа / час = автоматический временный бан (1 час)
- Уведомление пользователю о заблокированных запросах

**d) Репутация контактов (v0.2):**

- Контакт, добавленный вручную (по hex-ключу) = доверенный
- Контакт через Contact Request = обычный
- Заблокированный = все пакеты от него отбрасываются на уровне сети
- "Friend-of-friend" discovery: Bob рекомендует Alice контакт Carol
  (подписанный voucher) — Carol получает сниженный PoW

### 13.3 Защита от спама в группах (v0.2)

- Только Admin может добавлять участников
- Участник не может приглашать без роли Admin
- Flood protection: > 30 сообщений/минуту от одного участника = mute на 5 мин

---

