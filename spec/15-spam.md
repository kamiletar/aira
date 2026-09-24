# SPEC §13: Защита от спама

[← Индекс](../SPEC.md)

---

## 13. Защита от спама

> **Статус на 2026-09:** `aira-core/src/spam.rs` (`ContactRequest`, `verify_pow`/`solve_pow`,
> `RateLimiter`) существует, но **вне `aira-core` не используется**: `Message::ContactRequest` в
> wire нет, handshake без puzzle, PoW считается над `request ‖ nonce` без привязки к получателю
> и времени — переигрывается (C7). Подключение — **Milestone 22** (после M19a, где
> `ContactRequest` и верификатор переписываются под v2; §16.1). Этот файл — единственный источник
> §13 (дубликат в `spec/14-groups.md` удалён).

### 13.1 Модель: contact-first

В P2P мессенджере без сервера нет централизованного модератора. Защита
строится на принципе: **нельзя отправить сообщение незнакомцу без его
согласия**.

Незнакомец (нет 1:1-сессии) может достучаться до пользователя ровно двумя путями, и оба стоят PoW:

1. **Напрямую** — `Message::ContactRequest` по iroh-соединению на `EndpointId` из invitation link
   (§12.6.5); соединение — Tier 3 (§11B.1): adaptive puzzle перед handshake + PoW запроса.
2. **Через intro-mailbox** на mailbox relay (§6.3b, M21 п.4): коробка `aira/relay/intro/v2` по
   `pseudonym_pk` получателя принимает **только** `ContactRequest` с PoW ≥ 20 бит над
   `relay_nonce ‖ request`, rate limit по EndpointId депозитора; получатель забирает при
   следующем retrieve. Это единственное место PoW на relay.

Любой другой пакет от незнакомца (`Ratchet`, `FileOffer`, `GroupControl`) отбрасывается **до
расшифровки**: у получателя нет сессии с этим `EndpointId` (M19). Заблокированный контакт
(§6.19) — silent drop без проверки PoW.

### 13.2 Механизмы

**a) Contact Request (M22):**

```
Alice хочет написать Bob:
  1. Alice отправляет ContactRequest (подписанный ML-DSA псевдонимом):
     - свой pseudonym pubkey и InvitationLink-данные (EndpointId, relays) — как ответить
     - короткое сообщение (≤ 256 байт, plaintext)
     - Proof-of-Work (см. ниже) и опционально ContactStamp (tier)
  2. Bob видит запрос (/requests, событие ContactRequestReceived), решает: Accept / Reject / Block
  3. Accept → handshake PQXDH (п. 4.5), начало чата
  4. Reject → Alice уведомляется
  5. Block → все будущие запросы от Alice отбрасываются без проверки PoW
```

**b) Proof-of-Work для Contact Request (v2 — M19a п.5 / M22):**

PoW считается **не** над `request ‖ nonce` (v1: решённый один раз запрос можно слать любому
получателю сколько угодно раз), а над

```
BLAKE3( recipient_pubkey ‖ server_nonce ‖ issued_at ‖ slot ‖ request_bytes ‖ pow_nonce )
```

- `recipient_pubkey` — pseudonym pubkey получателя (из его ссылки): работа привязана к адресату;
- `server_nonce`, `issued_at` — puzzle получателя (`AdaptivePuzzle`, §11B.2) при прямом
  соединении; для intro-mailbox их роль играет `relay_nonce` relay (M21 п.4). Puzzle истекает
  через 30 с — precomputation невозможна;
- `slot` — 10-минутное окно времени (`unix_secs / 600`): PoW из другого окна невалиден → replay
  невозможен. Та же привязка и та же функция в `spam.rs` используются для `HopSetup`
  (§5.5, M24b) и intro-mailbox — одна реализация адаптивной сложности (M22);
- `pow_difficulty` задаёт **верификатор** (получатель или relay), не отправитель; ниже
  `min_difficulty` — отклонение без расчёта.

Сложность **адаптивная, 16 → 28 бит** по нагрузке верификатора (§11B.2; ориентиры однопоточно:
16 бит ≈ 10 мс, 20 ≈ 0,2 с, 24 ≈ 3 с, 28 ≈ 50 с — пересчитываются по бенчу M19a). Прежняя
фиксированная «≈ 20 бит ≈ 1 с» — нижняя ступень под нагрузкой. Обычного пользователя это не
задевает: разовая задержка при добавлении контакта; массовую рассылку ботами делает дорогой.

```rust
// aira-core/src/spam.rs — v2 (M19a п.5 / M22)

pub struct ContactRequest {
    pub from: PubKey,                 // pseudonym pubkey (§12.6), NOT identity key
    pub link: InvitationLink,         // EndpointId, relays — как дойти до отправителя
    pub message: String,              // ≤ 256 bytes
    pub stamp: Option<ContactStamp>,  // tier (см. c)
    pub pow: Pow,                     // { nonce: u64, difficulty: u8, slot: u32 }
    pub signature: MlDsaSignature,    // pseudonym key над исходными байтами всех полей (§6.16.1)
}

impl ContactRequest {
    /// `min_difficulty` и puzzle задаёт верификатор; проверка привязана к получателю и slot.
    pub fn verify_pow(&self, recipient_pk: &[u8], puzzle: &AdaptivePuzzle, min_difficulty: u8) -> bool {
        let hash = blake3::hash(&self.to_pow_bytes(recipient_pk, puzzle));
        self.pow.difficulty >= min_difficulty
            && puzzle.is_fresh() && self.pow.slot == current_slot()
            && leading_zeros(hash.as_bytes()) >= self.pow.difficulty as u32
    }
}
```

**c) `ContactStamp` — tier для незнакомцев (M22 п.4, решение владельца C16):**

`ContactStamp { epoch, bits, nonce }` — hashcash
`BLAKE3("aira/contact-stamp/v1" ‖ pseudonym_pk ‖ epoch ‖ bits ‖ nonce)` с `bits` ведущими нулями.
Проверяется кем угодно офлайн; **истекает** (epoch = неделя — приоритет нельзя купить навсегда);
считается per-pseudonym (не линкует псевдонимы); **не меняет ключ и seed** (после восстановления
пересчитывается в фоне). Поле в `InvitationLink`, `ContactRequest`, `NodeRecord` хопа (M24b).
Даёт **tier в очередях** (§11B.1): запросы со штампом обрабатываются раньше и с меньшим PoW под
нагрузкой, без штампа — последними; то же для `HopSetup` и регистрации mailbox. UI — бейдж
«дорогой контакт» без цифр. Идея «уровень надёжности по префиксу ключа (QQQQQ…)» отклонена
(аудит §5.3.1): grinding ломает детерминизм seed → identity. Настоящий уровень надёжности — граф
и поведение: контакт > контакт контакта > незнакомец со штампом > без штампа.

**d) Rate limiting (M22, `spam.rs::RateLimiter`):**

- Daemon отбрасывает > 10 Contact Request / минуту от разных ключей
- 3 запроса от одного ключа / час = автоматический временный бан (1 час)
- На relay: intro-mailbox — лимит по EndpointId депозитора (M21 п.4)
- Уведомление пользователю о заблокированных запросах

**e) Репутация контактов:**

- Контакт, добавленный по invitation link (`/add <uri>`, QR при встрече) = доверенный (Tier 1)
- Контакт через Contact Request = обычный
- Заблокированный = silent drop на входе (§6.19), без PoW-проверки
- "Friend-of-friend" discovery: Bob рекомендует Alice контакт Carol
  (подписанный voucher) — Carol получает сниженный PoW. После беты

### 13.3 Защита от спама в группах (M25; в бете группы отключены)

- Только Admin может добавлять участников (проверяется на приёме `GroupControl`, §12.5)
- Участник не может приглашать без роли Admin
- Членство только среди контактов — незнакомец не может попасть в группу (§12.3)
- Flood protection: > 30 сообщений/минуту от одного участника = mute на 5 мин

---

