# SPEC §6.16-6.18: Протокол — расширяемость, профили, удаление аккаунта

[← Индекс](../SPEC.md)

---

### 6.16 Расширяемость протокола

`PlainPayload::Unknown { type_id, data }` позволяет добавлять новые
типы сообщений без breaking change:

- Старый клиент получает `Unknown` → показывает "Обновите Aira
  чтобы увидеть это сообщение"
- `type_id` — зарезервированные диапазоны:
  - 0-999: core protocol (зарезервировано)
  - 1000-9999: official extensions
  - 10000+: community extensions
- `data` — произвольные байты, интерпретация зависит от `type_id`
- Capability negotiation (п. 6.4) сообщает какие type_id поддерживаются

### 6.16.1 Правила расширения wire format (postcard)

> ⚠️ **postcard кодирует enum discriminants позиционно** (не по имени).
> Нарушение этих правил = несовместимость между версиями клиентов.

**Обязательные правила для всех enum'ов в proto.rs:**

1. **Append-only:** новые варианты добавляются ТОЛЬКО в конец enum
2. **Нет удалений:** удалённые варианты заменяются на `_DeprecatedN(Vec<u8>)`
3. **Нет перестановок:** порядок вариантов фиксирован навсегда
4. **Нет вставок в середину:** новый вариант между существующими = breaking change
5. **Неизвестный вариант ≠ `Unknown`.** postcard **не** превращает неизвестный discriminant в
   `PlainPayload::Unknown`: клиент v2, получив вариант, добавленный позже (пусть даже в конец
   enum по правилу 1), получит **ошибку десериализации всего `PlainPayload`** — а значит, всего
   сообщения. `Unknown { type_id, data }` защищает только когда **отправитель сам** завернул новый
   тип в него. Отсюда правило: варианты для будущих фич резервируются **заранее**, в M19a, пока
   формат v2 не разошёлся по клиентам — `PlainPayload::GroupMessage(EncryptedGroupEnvelope)`
   (§12.4, M25), `Pin` (§6.23), `Profile` (§6.17), `Revocation` (§6.18), варианты Aira Onion
   (`BridgeOffer`, §5.5) — по списку M19a п.1; тело до реализации — заглушка. Либо новый тип едет
   только внутри `Unknown { type_id, data }` с зарезервированным `type_id`. То же для транспортного
   `Message`: `ContactRequest` (§13), `Ack { counter }` (§6.14) резервируются в M19a. Golden-байты
   (`tests/vectors/wire_v2/*.bin`) фиксируют каждый вариант

**CI enforcement:**

```rust
// tests/wire_compat.rs — snapshot-тест wire format
#[test]
fn wire_format_stability() {
    // Сериализовать каждый вариант PlainPayload, Message, CipherSuite
    // Сравнить с эталонными байтами в tests/fixtures/wire_snapshots/
    // При изменении — тест падает, требует осознанного обновления snapshot
}
```

**Миграция:** при необходимости изменить формат — использовать новый
`CipherSuite` или `protocol_version`, который переключает на обновлённый
набор enum'ов (а не модифицирует существующие)

**Подписание postcard-сериализованных структур:**

> ⚠️ postcard **не гарантирует каноническую сериализацию**. Одна и та же
> структура может быть сериализована по-разному на разных платформах
> (например, `usize` на 32-bit vs 64-bit). Это критично для подписей.

**Правило:** при подписании (ML-DSA) всегда подписывать **исходные байты**
сериализованной структуры, а не ре-сериализовать после десериализации.
Подпись привязана к конкретным байтам, не к семантическому содержимому.

```rust
// ✅ Правильно: подписываем исходные байты
let bytes = postcard::to_allocvec(&profile)?;
let signature = signing_key.sign(&bytes);
// Отправляем bytes + signature

// ✅ Правильно: проверяем подпись на полученных байтах
verifying_key.verify(&received_bytes, &signature)?;
let profile: UserProfile = postcard::from_bytes(&received_bytes)?;

// ❌ Неправильно: ре-сериализация может дать другие байты
let profile: UserProfile = postcard::from_bytes(&received_bytes)?;
let re_serialized = postcard::to_allocvec(&profile)?;
verifying_key.verify(&re_serialized, &signature)?; // МОЖЕТ СЛОМАТЬСЯ
```

**Типы, которые нельзя использовать в подписываемых структурах:**
`usize`, `isize` (зависят от платформы). Использовать `u32`/`u64` явно

### 6.17 Профили пользователей (M28; `is_bot` — M27)

> Статус 2026-09: `UserProfile` в коде нет (`grep UserProfile` → 0); в бете — только локальный
> alias контакта, `/profile` — заглушка и убирается из справки. Вариант `PlainPayload::Profile`
> резервируется в M19a (§6.16.1 п.5). Флаг `is_bot` — §17A, M27.

Каждый пользователь имеет публичный профиль, подписанный ML-DSA:

```rust
#[derive(Serialize, Deserialize)]
pub struct UserProfile {
    /// Отображаемое имя (≤ 64 символов)
    pub display_name: Option<String>,
    /// Аватар (JPEG, ≤ 32 KB, max 256x256)
    pub avatar: Option<Vec<u8>>,
    /// Текстовый статус (≤ 140 символов)
    pub status: Option<String>,
    /// Признак бота — клиенты отображают "[BOT]" (см. п. 17A)
    pub is_bot: bool,
    /// Версия профиля (инкрементируется при обновлении)
    pub version: u32,
    /// Подпись всех полей ML-DSA ключом
    pub signature: Vec<u8>,
}
```

- Профиль передаётся при handshake и Contact Request
- Обновления профиля — подписанное сообщение контактам
- Контакт может переопределить display_name локальным alias'ом
- Аватар хранится локально у контакта, не на relay
- В группах: отображается display_name из профиля

### 6.18 Удаление аккаунта / отзыв ключа (после M20/M21)

> Статус 2026-09: не реализовано (`KeyRevocation` в коде нет; CLI `/delete-account` печатает
> «Type YES» и подтверждение не обрабатывает — команда убирается из справки). Требует отзыва в
> discovery и на mailbox relay — после M20/M21; вариант `PlainPayload::Revocation` резервируется в
> M19a. «DHT» ниже читать как «pkarr/DNS-запись identity через свой `iroh-dns-server` (§5.1.1)»;
> DHT — после релиза (решение A3).

Механизм безвозвратного уничтожения identity:

```
/delete-account

  ⚠ Это действие НЕОБРАТИМО!
  Все контакты будут уведомлены. Ваш ключ будет отозван.
  Введите "DELETE" для подтверждения: _

Процесс:
  1. Публикация KeyRevocation в pkarr/DNS-записи identity (§5.1.1) и на своих mailbox relay
     (подписана ML-DSA — доказывает что владелец ключа сам отозвал)
  2. Отправка RevocationNotice всем контактам
  3. Удаление всех ratchet states
  4. Zeroize master_seed и всех ключей в памяти
  5. Уничтожение локальной базы данных (перезапись random bytes)
  6. Удаление конфигурации
```

```rust
#[derive(Serialize, Deserialize)]
pub struct KeyRevocation {
    pub pubkey: PubKey,
    pub reason: RevocationReason,
    pub revoked_at: u64,
    /// Подпись отзываемым ключом (proof of ownership)
    pub signature: Vec<u8>,
}

pub enum RevocationReason {
    /// Пользователь удалил аккаунт
    AccountDeleted,
    /// Ключ скомпрометирован
    KeyCompromised,
    /// Ротация на новый ключ
    KeyRotated { new_pubkey: PubKey },
}
```

- KeyRevocation публикуется в pkarr-записи (после релиза — и в DHT) и хранится 90 дней
- Ноды при обнаружении RevocationReason::KeyCompromised —
  автоматически блокируют старый ключ
- KeyRotated — контакты могут автоматически обновить ключ
  (если новый ключ деривирован из того же seed, п. 4.8)

