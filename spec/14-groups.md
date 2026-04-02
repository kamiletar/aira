# SPEC §12: Групповые чаты (v0.2)

[← Индекс](../SPEC.md)

---

## 12. Групповые чаты (v0.2)

### 12.1 Протокол: Sender Keys + Group Ratchet

**Почему не MLS (RFC 9420):** MLS требует Delivery Service (центральный сервер
для ordering), что противоречит P2P архитектуре. MLS также чрезмерно сложен
для небольших групп.

**Почему не простой fan-out:** fan-out (отправка каждому участнику отдельно)
не масштабируется — N участников = N шифрований на каждое сообщение.

**Выбор: Sender Keys** (как в Signal Groups):

```
Создатель группы:
  1. Генерирует GroupId = random [u8; 32]
  2. Генерирует свой Sender Key (ChaCha20 chain key)
  3. Отправляет Sender Key каждому участнику через 1-на-1 канал (E2E)

Участник при вступлении:
  1. Получает список участников + их Sender Keys (через 1-на-1)
  2. Генерирует свой Sender Key
  3. Раздаёт свой Sender Key всем участникам (через 1-на-1)

Отправка сообщения в группу:
  1. Шифрует сообщение своим Sender Key (одно шифрование!)
  2. Отправляет всем участникам (fan-out зашифрованного пакета)
  3. Ratchet Sender Key вперёд (forward secrecy)
```

### 12.2 Структуры данных

```rust
// aira-core/src/group.rs

pub struct Group {
    pub id: [u8; 32],
    pub name: String,
    pub members: Vec<GroupMember>,
    pub created_by: PubKey,
    pub created_at: u64,
}

pub struct GroupMember {
    pub pubkey: PubKey,
    pub sender_key: SenderKeyState,
    pub role: GroupRole,
    pub joined_at: u64,
}

pub enum GroupRole {
    Admin,    // может добавлять/удалять участников
    Member,   // только чтение/запись сообщений
}

pub struct SenderKeyState {
    pub chain_key: zeroize::Zeroizing<[u8; 32]>,
    pub counter: u64,
}
```

### 12.3 Ограничения v0.2

- Максимум 100 участников в группе
- Только Admin добавляет/удаляет участников
- При удалении участника — все пересоздают Sender Keys
- Нет редактирования/удаления сообщений
- Оффлайн участник получает пропущенные сообщения через локальную очередь

### 12.3.1 Известные ограничения безопасности Sender Keys

> ⚠️ Осознанный trade-off, задокументированный как известное ограничение.

**Нет Post-Compromise Security (PCS):** если ключ участника
скомпрометирован, атакующий может читать все сообщения группы
до следующей ротации Sender Keys (при удалении/добавлении участника).
В отличие от pairwise Double Ratchet, Sender Keys **не восстанавливаются
автоматически** при каждом сообщении.

**Forward Secrecy:** обеспечивается — ratchet Sender Key вперёд
после каждого сообщения. Прошлые сообщения защищены.

**Сравнение с альтернативами:**

| Свойство | Sender Keys (v0.2) | MLS (RFC 9420, v0.4+) | Fan-out DR |
|----------|-------------------|-----------------------|-----------|
| PCS | Нет (до ротации) | Да (каждый commit) | Да |
| Forward Secrecy | Да | Да | Да |
| Масштабируемость | O(1) шифрование | O(log N) | O(N) |
| Сложность | Низкая | Высокая | Низкая |
| Требует DS | Нет | Да (ordering) | Нет |

**План:** оценить переход на MLS в v0.4+ (требует решения проблемы
Delivery Service в P2P контексте — см. открытые вопросы §18)

### 12.4 Causal Ordering в группах

**Проблема:** Alice и Bob отправляют сообщения одновременно. Carol видит их
в одном порядке, Dave — в другом. В P2P нет центрального сервера для ordering.

> Урок Matrix: без causal ordering пользователи видят бессвязные разговоры.
> Retrofitting невозможен — меняет формат каждого группового сообщения.

**Решение — DAG-lite через `parent_id`:**

```rust
// aira-core/src/group_proto.rs

pub struct GroupMessage {
    pub group_id: [u8; 32],
    pub from: PubKey,
    pub payload: PlainPayload,
    pub id: [u8; 16],
    /// ID предыдущего сообщения в группе от этого же отправителя
    /// (causal link — мой last known message)
    pub parent_id: Option<[u8; 16]>,
    pub timestamp: u64,
}
```

**Алгоритм отображения:**

```
При получении GroupMessage:
  1. Если parent_id = None → первое сообщение, добавить в конец
  2. Если parent_id известен → вставить после него
  3. Если parent_id неизвестен (пропущено) →
     a. Показать placeholder "загрузка..."
     b. Запросить пропущенное у отправителя
     c. Timeout 10 сек → показать out-of-order с маркером "⚠ порядок нарушен"
```

**Ограничения (намеренно простое решение):**

- `parent_id` — только цепочка каждого отправителя, не глобальный DAG
- Не гарантирует идентичный порядок у всех (eventual consistency)
- Достаточно для чата — строгий порядок нужен только для reply (п. 6.8)
- Строгий глобальный порядок (MLS / vector clocks) — v0.4+

### 12.5 Протокол ротации Sender Key

Раздел 12.3 упоминает PCS при удалении участника, но не специфицирует протокол.
Отсутствие явного протокола — источник несогласованности состояния группы.

**Триггеры ротации:**

- Участник добавлен → новый Sender Key от добавившего Admin
- Участник удалён → все участники генерируют новые Sender Keys (PCS)
- Участник покинул группу (`/leave`) → то же что и удаление

```rust
pub enum GroupControl {
    /// Admin добавляет участника
    AddMember {
        new_member: PubKey,
        /// Зашифрованные Sender Keys всех участников для нового
        /// member_keys[i] = encrypt(members[i].sender_key, new_member_pubkey)
        member_keys: Vec<(PubKey, Vec<u8>)>,
    },
    /// Admin удаляет участника — инициирует ротацию
    RemoveMember {
        removed: PubKey,
    },
    /// Ответ на RemoveMember — новый Sender Key от каждого участника
    SenderKeyUpdate {
        /// Новый Sender Key, зашифрованный для каждого оставшегося участника
        keys: Vec<(PubKey, Vec<u8>)>,
    },
}
```

**Протокол при удалении участника:**

```
Admin удаляет Bob (offline):
  1. Admin отправляет RemoveMember { removed: Bob } всем (включая Bob)
  2. Каждый участник генерирует новый SenderKeyState
  3. Каждый отправляет SenderKeyUpdate через 1-на-1 каналы ко всем участникам
  4. До получения SenderKeyUpdate от участника X — сообщения от X в старом ratchet

Офлайн-участник при reconnect:
  - Получает RemoveMember из pending queue
  - Генерирует новый Sender Key
  - Рассылает SenderKeyUpdate всем участникам
  - До этого момента — не может отправлять в группу, только получать

Timeout (участник не ответил N часов):
  - Daemon логирует, UI показывает "ожидание ключей от Carol..."
  - Admin может force-rotate (вычеркнуть Carol без её ключа) — данные от Carol
    до этого момента не дешифруются другими участниками (приемлемо)
```

**Инварианты безопасности:**

- Удалённый участник не получает `SenderKeyUpdate` → не может читать новые сообщения
- Новый участник не получает старые Sender Keys → не может читать историю (FS)
- Bob офлайн при удалении → получает `RemoveMember` при reconnect,
  знает что удалён, не может писать в группу

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

