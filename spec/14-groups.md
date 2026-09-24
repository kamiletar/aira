# SPEC §12: Групповые чаты (статус: библиотечный код M6 без доставки; протокол v2 — Milestone 25)

[← Индекс](../SPEC.md)

---

## 12. Групповые чаты (v2 — Milestone 25, после беты)

> ⚠️ **Статус на 2026-09** (аудит E, `.claude/docs/audit-2026-09/spec-remainder-audit.md` §1).
> В коде есть `aira-core/src/group.rs` (`SenderKeyState`/`SenderKeyReceiver`, `MAX_SKIP = 1000`),
> `group_proto.rs` (типы), таблицы `groups`/`group_messages`, IPC-запросы и экраны во всех четырёх
> клиентах — но **групповые сообщения не шифруются Sender Keys и не имеют wire-типа**:
> `SendGroupMessage` рассылает `PlainPayload::Text` каждому участнику как личное сообщение,
> включая себя (G1); внутри группы нет аутентификации отправителя — любой участник знает chain key
> любого, AEAD без AAD (G2); идентификаторы участников несогласованы (псевдоним у создателя,
> 1:1-ключ у получателя), control-сообщения адресуются в очередь несуществующего контакта (G3);
> sender-состояния не персистятся — после рестарта повторяется пара (key, nonce) (G4); ротация
> §12.5 реализована частично (G5); порядка и дедупликации нет (G6); `AcceptGroupInvite` — мёртвый
> IPC, работает только auto-accept (S1).
>
> **Решение владельца A11 (24.09.2026): в бете 0.5 группы отключены честно** — запросы
> `CreateGroup … AcceptGroupInvite` → `Error("groups are not available in this beta")`, входящий
> `PlainPayload::GroupControl` → `warn!` и игнор (остаётся только проверка длины ключа 32 Б),
> `/group`, `views/groups.rs`, FFI-методы и Android-экраны скрыты (§15.8 п.7). В релизном пути
> остаются только резервы формата: вариант `PlainPayload::GroupMessage(EncryptedGroupEnvelope)`
> и бит `GROUPS` (M19a, §6.4, §6.16.1 п.5), `Deposit { targets }` в mailbox v2 (M21 п.3, §6.5).
> Реализация — **M25 «Группы v2»** (3–4 недели: core 1 нед., демон 1,5 нед., клиенты 0,5 нед.,
> спека 2 дня); до 1.0 или после — решение C1 открыто (если после — отдельный аудит `group.rs`).
> «Groups-lite» (1:1 fan-out с тегом `group_id`) отвергнут: зафиксировал бы формат, который
> придётся ломать. Ниже — **целевой дизайн v2**; отличия текущего кода помечены «v1».

### 12.1 Протокол: Sender Keys + Group Ratchet

**Почему не MLS (RFC 9420):** MLS требует Delivery Service (центральный сервер
для ordering), что противоречит P2P архитектуре. MLS также чрезмерно сложен
для небольших групп.

**Почему не простой fan-out шифрования:** N участников = N шифрований на каждое сообщение.
Транспортный fan-out при этом остаётся — один и тот же конверт доставляется каждому участнику
(напрямую по его 1:1-сессии или одним `Deposit { targets }` на relay, §12.3).

**Выбор: Sender Keys** (как в Signal Groups, `SenderKeyDistributionMessage`):

```
Создатель группы:
  1. Генерирует GroupId = random [u8; 32], epoch = 0
  2. Генерирует свой Sender Key = (chain key, signing key)          ← signing key: G2, решение C2
  3. Отправляет Sender Key каждому участнику через 1-на-1 канал (E2E, GroupControl)

Участник при вступлении:
  1. Получает список участников + их Sender Keys ТЕКУЩЕЙ эпохи (через 1-на-1, от Admin)
  2. Генерирует свой Sender Key
  3. Раздаёт свой Sender Key всем участникам сам (через 1-на-1), не через Admin (S1)

Отправка сообщения в группу:
  1. Шифрует сообщение своим chain key (одно шифрование!) с
     AAD = group_id ‖ sender_id ‖ epoch ‖ counter; nonce выводится локально
     derive_nonce(msg_key, counter) и НЕ передаётся (S6); подписывает конверт
     своим signing key (G2)
  2. Сохраняет продвинутое состояние (chain key, counter) в group_sender_states
     ДО отправки (G4) — то же правило, что для ratchet-снапшота 1:1 (M19)
  3. Отправляет всем участникам: онлайн — по 1:1-сессии контакта; офлайн — один
     Deposit { targets: [mailbox участника…] } на relay (§6.5, M21)
  4. Ratchet chain key вперёд (forward secrecy)
```

**v1 (в коде):** `SenderKeyState::encrypt` возвращает `(counter, nonce, ciphertext)` без AAD и
подписи, nonce едет по проводу и берётся с провода при расшифровке; вне `aira-core` ни один
символ не используется; таблицы `group_sender_states` нет.

**Решение C2 (открыто, к M25) — чем подписывать конверт:**

| | **A. ML-DSA-65 групповым псевдонимом (§12.6)** | **B. Ed25519 signing key внутри Sender Key** |
|---|---|---|
| Размер на сообщение | 3 309 Б подписи | 64 Б |
| Стойкость | постквантовая | классическая |
| Плюсы | ключ уже есть (псевдоним участника), лишний ключ раздавать не нужно; «PQ везде» без оговорок | как в Signal Sender Keys; дёшево по трафику и CPU (100 участников × сообщение); ключ ротируется с эпохой — окно подделки ограничено |
| Минусы | ×10–50 к размеру короткого сообщения; 100 × 3,3 KB на relay за одно сообщение; медленная верификация на телефоне | подделка требует **активной** атаки в реальном времени квантовым противником — HNDL к подписям неприменим (конфиденциальность даёт AEAD с PQ-раздачей ключей по 1:1-каналу), но аутентификация групп не PQ |

Рекомендация аудита — **B + AAD** сейчас, A — позже как опция (бит `GROUPS_PQ_SIG`). При B
ML-DSA-псевдоним остаётся идентификатором участника и подписывает редкие `GroupControl` /
`PseudonymRotation` (через 1:1-канал). Контекст signing key — `aira/group/sender-sign` (имя
предложено; фиксируется в `docs/KEY_CONTEXTS.md` в M25).

### 12.2 Структуры данных

```rust
// aira-storage/src/types.rs — целевая схема v2 (M25); v1 помечено

pub struct GroupInfo {
    pub id: [u8; 32],
    pub name: String,
    pub members: Vec<GroupMemberInfo>,
    pub created_by: Vec<u8>,          // групповой псевдоним создателя (§12.6)
    pub created_at: u64,
    pub epoch: u32,                   // v2: текущая эпоха ключей (§12.5)
}

pub struct GroupMemberInfo {
    pub pseudonym_pk: Vec<u8>,        // групповой псевдоним участника (ML-DSA-65, §12.6); v1: `pubkey`
    pub contact_id: u64,              // v2: 1:1-контакт, через сессию которого идут control-сообщения
                                      //     и доставка (G3). Таблица pseudonym_pk → contact_id для
                                      //     чужих псевдонимов (v1 ищет только свои: pseudonyms::find_by_pubkey)
    pub display_name: String,
    pub role: GroupRole,              // Admin | Member
    pub joined_at: u64,
    pub epoch: u32,                   // v2: эпоха, с которой участник получил ключи
    // v1: pub sender_chain_key: [u8; 32] — НАЧАЛЬНЫЙ chain key в записи участника, не
    //     продвигается; временная схема, удаляется в M25 (состояние — в group_sender_states)
}

// aira-core/src/group.rs — состояния Sender Key; в v2 персистентны per (group_id, member) (M25)
pub struct SenderKeyState {            // наш ключ в группе
    chain_key: Zeroizing<[u8; 32]>,
    counter: u64,
    // v2: signing_key (решение C2)
}
pub struct SenderKeyReceiver {         // ключ каждого другого участника
    chain_key: Zeroizing<[u8; 32]>,
    next_counter: u64,
    skipped_keys: BTreeMap<u64, Zeroizing<[u8; 32]>>,   // ≤ MAX_SKIP = 1000, TTL 24 ч
    // v2: verifying_key
}
// Таблица group_sender_states: (group_id, member_index) → Zeroizing(SenderKeyState | SenderKeyReceiver);
// запись после каждого шага — ДО отправки и после расшифровки. Без этого (v1): компрометация БД
// раскрывает начальный ключ (все прошлые сообщения отправителя), после рестарта receiver
// стартует с counter 0 и не догоняет > MAX_SKIP, отправитель повторяет keystream (G4).

pub const MAX_GROUP_MEMBERS: usize = 100;
```

### 12.3 Ограничения v2

- Максимум 100 участников в группе (`MAX_GROUP_MEMBERS`)
- Только Admin добавляет/удаляет участников — проверяется **на приёме** `GroupControl` (S1)
- Членство — только среди контактов (contact-first, §13, M22): каждый участник доставляет
  напрямую по 1:1-сессии, поэтому пригласить можно только того, с кем есть контакт
- При удалении участника — все пересоздают Sender Keys (новая эпоха, §12.5)
- Нет редактирования/удаления сообщений (M28 добавит по аналогии с 1:1)
- **Офлайн-участник** получает пропущенные сообщения через mailbox relay v2 (§6.5, M21):
  отправитель делает один `Deposit { targets }` — тело конверта хранится на relay один раз,
  ссылки N (`targets.len() ≤ 100`), квота отправителя считает N. Группа из 100 «болтливых»
  участников (100 сообщений/день) даёт ≈ 10 000 ссылок/день на relay — входит в модель квот
  M21 и community-relay (M24a). Control-сообщения (§12.5) для офлайн-участников — тоже через
  relay; без M21 «участник получает `RemoveMember` из очереди» не работает
- TTL (§6.7) per-group — как per-chat (v1 хранит `ttl_secs: None`, G7)

### 12.3.1 Известные ограничения безопасности Sender Keys

> ⚠️ Осознанный trade-off, задокументированный как известное ограничение.

**Нет Post-Compromise Security (PCS):** если ключ участника
скомпрометирован, атакующий может читать все сообщения группы
до следующей ротации Sender Keys (при удалении/добавлении участника).
В отличие от pairwise Double Ratchet, Sender Keys **не восстанавливаются
автоматически** при каждом сообщении.

**Forward Secrecy:** обеспечивается ratchet'ом chain key после каждого сообщения — **при
условии, что продвинутое состояние сохранено на диске** (`group_sender_states`, M25). В v1
хранится только начальный chain key, поэтому at rest прошлые сообщения не защищены (G4).

**Аутентификация отправителя:** только с подписью конверта и AAD (G2, решение C2). Без них
(v1) любой участник, зная chain key жертвы, шифрует под него и ставит `from = жертва`.

**Сравнение с альтернативами:**

| Свойство | Sender Keys (v2) | MLS (RFC 9420) | Fan-out DR |
|----------|-------------------|-----------------------|-----------|
| PCS | Нет (до ротации) | Да (каждый commit) | Да |
| Forward Secrecy | Да | Да | Да |
| Масштабируемость | O(1) шифрование | O(log N) | O(N) |
| Сложность | Низкая | Высокая | Низкая |
| Требует DS | Нет | Да (ordering) | Нет |

**План:** оценить переход на MLS после 1.0 (требует решения проблемы
Delivery Service в P2P контексте — см. открытые вопросы §18)

### 12.4 Causal Ordering, порядок и дедупликация в группах

**Проблема:** Alice и Bob отправляют сообщения одновременно. Carol видит их
в одном порядке, Dave — в другом. В P2P нет центрального сервера для ordering.

> Урок Matrix: без causal ordering пользователи видят бессвязные разговоры.
> Retrofitting невозможен — меняет формат каждого группового сообщения.

**Решение — DAG-lite через `parent_id`:**

```rust
// aira-core/src/group_proto.rs — v1 (в коде) → v2 (M25)

pub struct GroupMessage {
    pub group_id: [u8; 32],
    pub from: Vec<u8>,              // v1: pseudonym pubkey — 1 952 Б в КАЖДОМ сообщении
                                    // v2: sender_id: [u8; 16] = BLAKE3(pseudonym_pk)[..16]
    pub payload: Vec<u8>,           // postcard(MessageMeta) — тот же plaintext, что в 1:1 (§6.7)
    pub id: [u8; 16],               // случайный; дедуп по нему (seen_message_ids)
    pub parent_id: Option<[u8; 16]>,// causal link — мой предыдущий id в этой группе
    pub counter: u64,               // sender-key counter (v1 дублирует его и здесь, и в конверте)
    pub timestamp: u64,             // микросекунды; только для отображения, порядок по нему не строится
}

/// Конверт на проводе — v2 (M25). Вариант `PlainPayload::GroupMessage(EncryptedGroupEnvelope)`
/// резервируется в M19a (§6.16.1 п.5); до M25 тело — заглушка.
pub struct EncryptedGroupEnvelope {
    pub group_id: [u8; 32],
    pub sender_id: [u8; 16],        // v1: from: Vec<u8>
    pub epoch: u32,                 // v2
    pub counter: u64,
    // v1: pub nonce: [u8; 12] — в v2 nonce не передаётся: derive_nonce(msg_key, counter) (S6)
    pub ciphertext: Vec<u8>,        // AEAD(msg_key, nonce, postcard(GroupMessage),
                                    //      aad = group_id ‖ sender_id ‖ epoch ‖ counter)
    pub signature: Vec<u8>,         // v2: подпись над aad ‖ ciphertext (решение C2)
}
```

**Алгоритм отображения:**

```
При получении EncryptedGroupEnvelope:
  0. Проверить подпись и AAD; расшифровать SenderKeyReceiver'ом (sender_id, epoch);
     сохранить состояние; дедуп по GroupMessage.id
  1. Если parent_id = None → первое сообщение, добавить в конец
  2. Если parent_id известен → вставить после него
  3. Если parent_id неизвестен (пропущено) →
     a. Показать placeholder "загрузка..."
     b. Запросить пропущенное у отправителя
     c. Timeout 10 сек → показать out-of-order с маркером "⚠ порядок нарушен"
```

**Хранение (M25):** ключ `group_messages` = `(group_id, member_index, counter)` вместо
`(group_id, timestamp_micros)` — в v1 два сообщения в одну микросекунду затирают друг друга,
а порядок строится по подделываемому timestamp отправителя (G6).

**Ограничения (намеренно простое решение):**

- `parent_id` — только цепочка каждого отправителя, не глобальный DAG
- Не гарантирует идентичный порядок у всех (eventual consistency)
- Достаточно для чата — строгий порядок нужен только для reply (п. 6.8)
- Строгий глобальный порядок (MLS / vector clocks) — после 1.0

### 12.5 Протокол ротации Sender Key (эпохи)

Отсутствие явного протокола — источник несогласованности состояния группы. В v2 у группы есть
`epoch: u32`; каждое добавление, удаление и выход участника начинает новую эпоху.

**Триггеры ротации (epoch += 1):**

- Участник добавлен → новый участник получает ключи **текущей** эпохи (продвинутые или свежие),
  не начальные (G5); остальные получают его ключ от него самого
- Участник удалён → все участники генерируют новые Sender Keys (PCS)
- Участник покинул группу (`Leave`) → то же, что и удаление (v1 ротацию не запускает, G5)

```rust
// aira-core/src/group_proto.rs — v1 (в коде); v2 = + epoch: u32 во всех вариантах (M25).
// Все варианты едут внутри 1:1-ratchet-сессии контакта (PlainPayload::GroupControl):
// отправитель известен по сессии, а не по полю в сообщении.
pub enum GroupControl {
    /// Создатель приглашает участников
    CreateGroup {
        group_id: [u8; 32],
        name: String,
        members: Vec<Vec<u8>>,          // псевдонимы всех начальных участников, включая создателя
        creator_sender_key: Vec<u8>,    // chain key создателя (v2: + signing_pk)
    },
    /// Admin добавляет участника
    AddMember {
        group_id: [u8; 32],
        new_member: Vec<u8>,
        sender_keys: Vec<(Vec<u8>, Vec<u8>)>, // (pseudonym_pk, key) — ТОЛЬКО в копии для new_member
    },
    /// Admin удаляет участника — инициирует ротацию
    RemoveMember { group_id: [u8; 32], removed: Vec<u8> },
    /// Участник раздаёт свой новый Sender Key (новая эпоха)
    SenderKeyUpdate { group_id: [u8; 32], new_key: Vec<u8> /* v2: + signing_pk, epoch */ },
    /// Участник покидает группу
    Leave { group_id: [u8; 32] },
}
```

**Правила приёма (S1, G3):**

- `CreateGroup` принимается только от контакта и требует явного `AcceptGroupInvite` от
  пользователя (auto-accept v1 убран); создатель = отправитель 1:1-сессии, роль Admin
  выставляется у всех участников одинаково
- `AddMember` / `RemoveMember` — только от участника с ролью Admin в текущем состоянии группы
- `sender_keys` в `AddMember` — только для `new_member` (ключи существующих участников текущей
  эпохи); существующие участники получают ключ нового участника **от него самого**
  (`SenderKeyUpdate`), а не от Admin. Ключ, пришедший не от владельца псевдонима, игнорируется —
  иначе любой отправитель `AddMember` перезаписывает чужие ключи (v1)
- Длина ключа — ровно 32 Б, короткие не дополняются нулями (v1 дополнял)
- До получения `SenderKeyUpdate` своей эпохи от участника X — сообщения от X в старом ratchet
  (только приём); сам участник **не может писать** в группу, пока не разослал ключ новой эпохи

**Протокол при удалении участника:**

```
Admin удаляет Bob (offline):
  1. Admin отправляет RemoveMember { removed: Bob, epoch: n+1 } всем (включая Bob)
  2. Каждый участник генерирует новый SenderKeyState эпохи n+1
  3. Каждый отправляет SenderKeyUpdate через 1-на-1 каналы ко всем оставшимся участникам
  4. До получения SenderKeyUpdate от участника X — сообщения от X в старом ratchet

Офлайн-участник при reconnect:
  - Получает RemoveMember с relay (§6.3b, M21) / из очереди
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
- Новый участник не получает старые Sender Keys (прошлых эпох и не продвинутые начальные) →
  не может читать историю (FS)
- Bob офлайн при удалении → получает `RemoveMember` при reconnect,
  знает что удалён, не может писать в группу
- Никто, кроме владельца псевдонима, не может установить его Sender Key у других участников

### 12.6 Per-Group Pseudonyms (Unlinkable Identity)

> Аналогия: Bitcoin HD wallets (BIP-32) — из одного seed деривируются
> неограниченно много несвязанных адресов. Тот же принцип для идентичности.
>
> Ссылки: [Lattice HD Wallets (ML-DSA)](https://eprint.iacr.org/2026/380),
> [MIMI Metadata Minimalization](https://datatracker.ietf.org/doc/html/draft-kohbrok-mimi-metadata-minimalization-02),
> [BIP-32](https://en.bitcoin.it/wiki/BIP_0032)

**Проблема:** один ML-DSA-65 публичный ключ (`aira/identity/0`) используется
как идентификатор везде. Наблюдатель, видящий участника в двух группах,
тривиально связывает идентичности по совпадающему `from: PubKey`.

**Решение: per-context pseudonym keys.** Каждая группа и каждый контакт
получает уникальную ключевую пару (ML-DSA-65 + X25519 + ML-KEM-768),
деривированную из MasterSeed через монотонный counter.

#### 12.6.1 Деривация (BIP-32 модель)

```
MasterSeed (32 bytes)
  ├── aira/pseudonym/0/signing   → ML-DSA-65 keypair (контакт Alice)
  ├── aira/pseudonym/0/x25519    → X25519 keypair
  ├── aira/pseudonym/0/mlkem     → ML-KEM-768 keypair
  ├── aira/pseudonym/1/signing   → ML-DSA-65 keypair (группа "Work")
  ├── aira/pseudonym/1/x25519    → X25519 keypair
  ├── aira/pseudonym/1/mlkem     → ML-KEM-768 keypair
  ├── aira/pseudonym/2/signing   → ML-DSA-65 keypair (контакт Bob)
  └── ...
```

- `<counter>` — монотонно возрастающий u32 (hardened derivation)
- Counter не несёт семантики: mapping counter→context хранится в storage
- Один counter = один контекст (группа или контакт)
- Ротация pseudonym = counter++ (новый keypair для того же контекста)
- **Раскладка по устройствам (D3, M19 Phase A п.7):** `counter = (device_index << 28) | local`
  — 16 слотов × 2^28. Без этого два устройства с одним seed выдали бы `aira/pseudonym/0/*`
  разным контекстам (один keypair в двух контекстах — нарушение key isolation); после restore
  бэкапа `local ≥ max + 1`

**Почему counter, а не scope-based (BLAKE3(seed, group_id)):**

- Scope-based встраивает `group_id` в KDF-контекст → при компрометации seed
  атакующий перебирает известные group_id и проверяет принадлежность
  pseudonym к конкретной группе
- Scope-based не позволяет ротацию pseudonym без смены группы
- Для контактов нет "contact_id" до первого обмена ключами
- Counter — проверенная модель (BIP-32, 13 лет в production у Bitcoin)

#### 12.6.2 UX-флоу при создании группы

```
Admin создаёт группу "Project Alpha":
  1. UI запрашивает: "Выберите псевдоним для группы «Project Alpha»"
  2. Admin вводит display name (например, "Alex")
  3. Daemon инкрементирует counter, деривирует новый pseudonym keypair
  4. GroupMember.pseudonym_pk = новый ML-DSA pubkey
  5. GroupMember.display_name = "Alex"
```

#### 12.6.3 UX-флоу при добавлении в группу

```
Alice добавляют в группу "Work Chat":
  1. Alice получает AddMember invite через 1-на-1 канал с Admin
  2. UI запрашивает: "Вас пригласили в группу «Work Chat».
     Выберите псевдоним для этой группы:"
  3. Alice вводит display name
  4. Daemon деривирует новый pseudonym keypair (counter++)
  5. Alice отправляет свой pseudonym pubkey и Sender Key всем участникам
     через 1-на-1 каналы (SenderKeyUpdate) — не через Admin (S1)
```

#### 12.6.4 Изменения в структурах данных

См. §12.2: `GroupMemberInfo.pseudonym_pk` (per-group ML-DSA pseudonym, NOT identity key),
`GroupMessage.from`/`sender_id` — псевдоним (в v2 — его 16-байтный хэш), не identity pubkey.

- Sender Key distribution идёт по 1:1-сессии с контактом, стоящим за псевдонимом (`contact_id`)
- `AddMember.new_member` → pseudonym pubkey нового участника

#### 12.6.5 Обмен контактами с pseudonyms

При обмене контактами каждый invitation link содержит **уникальный
pseudonym pubkey**, а не identity key:

```
v1 (спека 0.4):  aira://add/<base64url(pseudonym_pubkey)>#<fingerprint>
v2 (M19 п.12 / M19b п.4):
  aira://add/<base64url(postcard(InvitationLink {
      version, pseudonym_pk, endpoint_id, relays: Vec<RelayRef> (2–3),
      fingerprint_hint, expires_at, stamp: Option<ContactStamp>, sig }))>
```

- `GetInvitation` выдаёт **стабильный** псевдоним для ссылки (выданные хранятся); новый —
  по явному запросу пользователя. Прежнее правило «каждый вызов `/mykey` — новый псевдоним»
  отменено: оно растило таблицу псевдонимов при каждом показе адреса (B5); нелинкуемость
  сохраняется — отдельная ссылка выдаётся по запросу
- Ссылка не содержит IP (решение A7): `EndpointId` + relay URL; QR — byte-mode (postcard),
  ссылка подписана и имеет срок действия
- Каждый контакт видит уникальный pubkey пользователя; два invitation link нелинкуемы
- `ContactRequest.from` = pseudonym pubkey; `ContactStamp` — §13.2, M22

#### 12.6.6 Раскрытие связи — PseudonymLink (опционально)

Пользователь может **по желанию** раскрыть доверенному контакту,
что два его pseudonym — это один человек:

```rust
pub struct PseudonymLink {
    pub pseudonym_a: PubKey,
    pub pseudonym_b: PubKey,
    /// Cross-signature: подписано ключом pseudonym_a
    pub sig_a: MlDsaSignature,
    /// Cross-signature: подписано ключом pseudonym_b
    pub sig_b: MlDsaSignature,
}
```

- Отправляется через 1-на-1 E2E канал
- Полностью опционально — пользователь решает, кому раскрывать
- Верификация: проверить обе подписи над каноническим `(pseudonym_a, pseudonym_b)` —
  над исходными байтами (§6.16.1); в v1 типы есть, проверки подписей нет (M25)

#### 12.6.7 Ротация pseudonym в группе

Пользователь может сменить pseudonym в группе (новый display name +
новый keypair):

```
Alice ротирует pseudonym в группе "Work Chat":
  1. Daemon деривирует новый pseudonym keypair (counter++)
  2. Alice подписывает PseudonymRotation { old_pubkey, new_pubkey }
     старым ключом
  3. Alice отправляет PseudonymRotation + SenderKeyUpdate через
     1-на-1 каналы ко всем участникам
  4. Участники обновляют GroupMember для Alice
```

#### 12.6.8 Storage

```
Таблица pseudonyms:
  counter (u32) → {
    pseudonym_pubkey: PubKey,
    context_type: "contact" | "group",
    context_id: [u8; 32],  // group_id или BLAKE3(contact_pseudonym_pubkey)
    display_name: String,
    created_at: u64,
  }

Таблица pseudonym_counter:
  "current" → u32  // следующий local-счётчик; полный counter = (device_index << 28) | local

Таблица pseudonym_contacts (M25):
  pseudonym_pk (чужой) → contact_id   // маршрутизация control-сообщений участнику
```

#### 12.6.9 Модель угроз

| Угроза | Защита |
|--------|--------|
| Кросс-групповая корреляция участника | Разные pseudonym keys в каждой группе |
| Корреляция через invitation links | Каждый link — уникальный pseudonym |
| Утечка identity из group metadata | Identity pubkey нигде не фигурирует в группе |
| Компрометация одного pseudonym | Не раскрывает другие (KDF isolation, разные counters) |
| Компрометация seed + перебор group_id | Counter не содержит group_id → перебор бесполезен |
| Relay видит состав группы | Нет групповой коробки: fan-out в pairwise-коробки (`Deposit { targets }`) |
| Подделка сообщения участником от имени другого | Подпись конверта + AAD (v2, C2) |

#### 12.6.10 Safety Numbers с pseudonyms

Safety Number (§6.9) вычисляется по **pseudonym pubkey**, не по identity key.

**Для 1-на-1 контактов:**

```
safety_number(my_pseudonym_for_bob, bob_pseudonym_for_me, version)
```

Каждая пара контактов имеет уникальный Safety Number, привязанный
к конкретным pseudonyms. При ротации pseudonym — Safety Number меняется,
контакт получает уведомление.

**Для групп:**

Каждый участник группы имеет **один** pseudonym, видимый **всем** участникам
этой группы (один counter = одна группа). Safety Number в группе вычисляется
попарно: между моим pseudonym для этой группы и pseudonym каждого участника:

```
safety_number(my_group_pseudonym, alice_group_pseudonym, version)
safety_number(my_group_pseudonym, bob_group_pseudonym, version)
```

> **Важно:** group pseudonym ≠ contact pseudonym. Alice, с которой я общаюсь
> 1-на-1, имеет один pseudonym для меня. Та же Alice в группе "Work" имеет
> другой pseudonym. Safety Numbers будут разные — это ожидаемое поведение,
> обеспечивающее unlinkability.

---

Защита от спама (contact-first, PoW, flood protection в группах) — см. [§13](15-spam.md).
