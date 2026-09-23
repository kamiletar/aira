# Остаток спеки: группы §12, мультидевайс §14, Bot API §17A, прочие фичи §6.x — аудит (2026-09-23, HEAD 7726b46, v0.3.5)

> Задание E фазы 3 аудита. Ветка `claude/vigilant-sagan-9kta8v`. Только Read/Grep/Glob/git log; cargo не запускался.
> Не дублирует: статус M1–M17 (`spec-drift-audit.md`), C1–C7 (`core-audit.md`), S1/S5/S6/S15 (`security-compliance-audit.md`),
> §6.5 и §8.1 главного документа `../release-audit-2026-09.md`. Здесь — только новое и решения «что к 1.0 / что после».
> Нумерация находок: G — группы, D — мультидевайс, B — Bot API, F — прочие фичи §6.x/i18n/Tauri.

## 0. Резюме

**Вердикт.** Три «расширения» спеки — группы §12, мультидевайс §14, Bot API §17A — в коде существуют как криптопримитивы, IPC-запросы и экраны во всех клиентах, но **ни одно не доставляет данные и не готово к бете**: групповые сообщения не шифруются Sender Keys и не имеют wire-типа (fan-out 1:1-текста без признака группы, G1), внутри группы нет аутентификации отправителя (G2), идентификаторы участников несогласованы, и control-сообщения адресованы «в никуда» (G3), sender-состояния не персистятся → потеря FS на диске и повтор (key, nonce) после рестарта (G4); «привязка устройства» — локальная запись без синхронизации (D1); Bot SDK — клиент демона пользователя, а не «нода со своим seed» (B1), и после wiring не получит ни одного текста из-за трёх несовместимых форматов `MessageReceived.payload` между демоном, CLI, GUI и ботом (B2). Рекомендация: **в бете 0.5 отключить все три честно** (§15.8 п.6), в релизном пути оставить только дешёвые резервы (≈4 дня суммарно), а реализацию вынести в M25 (группы v2, 3–4 нед., желательно до 1.0, чтобы аудит покрыл `group.rs`), M26 (мультидевайс v2, 4–6 нед., после 1.0), M27 (Bot API v2); **M24 зарезервирован** за темой владельца «community relays + onion».

**Два блокера плана, которые надо править до старта M19:** (1) **D2** — M19 Phase A п.6 «iroh SecretKey детерминированно из seed» даёт двум устройствам один `EndpointId` и делает мультидевайс невозможным без re-keying всех ссылок → `aira/iroh/secret/<device_index>` с индексом 0 (0,5 дня); (2) **B2** — M19 п.11 переиспользует `handle_incoming_payload`, который эмитит сырой UTF-8 для текста, тогда как CLI ждёт `MessageMeta`, а бот — `PlainPayload` → входящие тексты не отобразятся; нужен единый контракт `MessageMeta` по проводу и в IPC. Рядом — **D3**: счётчик псевдонимов per-БД даст одинаковые ключи в разных контекстах на двух устройствах — разбить `u32` по `device_index` до массовой выдачи псевдонимов в M19b.

**Прочие фичи §6.x:** к бете обязательны и сейчас сломаны — disappearing messages (F1: `expires_at` ставится только в `mark_read`, который никто не вызывает — TTL никогда не срабатывает) и блокировка (F2: `/block` = `RemoveContact`, поле `blocked` нигде не проверяется); `/verify` — заглушка (Safety Numbers в клиентах нет); семь CLI-команд — заглушки в справке (F3); реакции/edit/delete/receipts/typing/pin/search/профили/удаление аккаунта — только типы в `proto.rs` (не мешают бете); движок i18n (fluent, en/ru, 33 ключа) не подключён ни к одному клиенту. Tauri (§15.9) не противоречит M19b, но спека нигде не говорит, что **бета выходит только с минимальными клиентами (egui/CLI)**, а M9.6 C/D/E для egui противоречит заморозке §15.8 — решение владельца.

**Спека как документ:** 33 точечные правки (§5): версия «0.2 | апрель 2026» → 0.5, дубликат §13 в `spec/14-groups.md:406-471` удалить, §12/§14/§17A привести к коду и к решениям (подпись в Sender Keys, Sesame vs handoff, «SDK для собственного демона»), §8/§9/§7 синхронизировать со списком IPC/команд/таблиц, §6.16.1 дополнить предупреждением о позиционных enum postcard (неизвестный вариант ≠ `Unknown`), §6.4 `Features` = `handshake.rs`.

**Размещение:** M24 community relays/onion (резерв; должен учесть групповой fan-out `Deposit{targets}` и per-device коробки), M25 группы v2, M26 мультидевайс v2, M27 Bot API v2, M28 «дешёвые фичи §6.x»; порядок после беты: M16 → M25 → M17 → (M24 параллельно) → 1.0 → M26 → M28 → M15 → M27 → M14. Правки M18–M23 — §6.1/§6.3.

## 1. Группы (§12, M6)

### 1.1 Что реализовано

| Слой | Что есть | Evidence | Качество |
|---|---|---|---|
| aira-core `group.rs` (411 стр.) | `SenderKeyState` (chain key + counter, `encrypt`), `SenderKeyReceiver` (`decrypt` со skipped keys, `MAX_SKIP = 1000`, replay по counter), `MAX_GROUP_MEMBERS = 100`; контексты `aira/group/chain-advance`, `aira/group/message-key` | group.rs:32,36,103-113,165-206,212-216; docs/KEY_CONTEXTS.md:63-68 | works (криптоядро), 9 unit-тестов; **вне core не используется ни один символ** (grep `SenderKeyReceiver\|EncryptedGroupEnvelope` по workspace → 0 вне aira-core) |
| aira-core `group_proto.rs` (300 стр.) | `GroupRole`, `GroupMessage{group_id, from, payload, id, parent_id, counter, timestamp}`, `EncryptedGroupEnvelope{group_id, from, counter, nonce, ciphertext}`, `GroupControl::{CreateGroup, AddMember, RemoveMember, SenderKeyUpdate, Leave}`, `PseudonymLink`, `PseudonymRotation` | group_proto.rs:29-45, 54-65, 74-122, 134-162 | типы + 7 serde-roundtrip тестов; кода проверки подписей `PseudonymLink/Rotation` нет |
| wire | **единственный групповой тип на проводе — `PlainPayload::GroupControl`** (proto.rs:79). Варианта для `EncryptedGroupEnvelope`/`GroupMessage` нет ни в `Message` (proto.rs:11-20), ни в `PlainPayload` (:35-87) | proto.rs | групповое сообщение физически нечем передать |
| aira-storage | таблицы `groups`, `group_messages` (lib.rs:64-66), `pseudonyms`/`pseudonym_counter` (:72-74); `GroupInfo`, `GroupMemberInfo{pubkey, display_name, role, joined_at, sender_chain_key: [u8;32]}` (types.rs:59-88); CRUD groups.rs; `store_group_message` по ключу `(group_id, timestamp_micros)` (groups.rs:149) | | works; **хранится только начальный chain key**, состояние receiver'а не персистится (см. G4) |
| aira-daemon | IPC: `CreateGroup/GetGroups/GetGroupInfo/SendGroupMessage/GetGroupHistory/GroupAddMember/GroupRemoveMember/LeaveGroup/AcceptGroupInvite/GetPseudonyms/GetPseudonym/FindPseudonym` (types.rs:85-155); обработчики handler.rs:354-609; приём `handle_incoming_group_control` :680-833; события `GroupMessageReceived/GroupMemberJoined/GroupMemberLeft/GroupInvite` (types.rs:337-369) | | works-but-rough; `GroupMessageReceived` **демоном никогда не эмитится** (grep: только потребители в cli/gui/ffi/bot); `AcceptGroupInvite` не вызывается ни одним клиентом (grep → 0) — работает только auto-accept (S1) |
| клиенты | CLI `/group create|list|info|add|remove|leave` (commands.rs:52-64, main.rs:472-596); GUI `views/groups.rs` (219 стр.) + `GuiCommand::{CreateGroup,…}` (gui/ipc.rs:59-75); FFI `create_group…leave_group` (ffi/runtime.rs:217-305); Android `GroupsScreen.kt`, `GroupChatScreen.kt` | | UI есть во всех четырёх клиентах — при том, что доставки нет (см. §4 про §15.8 «минимальные клиенты») |
| тесты | core 9 + 7; daemon 8 групповых из 14 (handler.rs:985-1426); интеграционного «3 ноды» нет (известно) | | unit только; `handle_incoming_group_control_create_stores_group` проходит на предпосылке, которую production-код не выполняет (G3) |

Коммиты: b6daea6/8ca5e7f (03.04.2026, §12.6), 8a55219/c37c4e3/12ef481 (04.04.2026, sender keys + приём control). После 04.04 групповой код не менялся.

### 1.2 Находки (новые; S1/S5/S6 — см. security-compliance-audit.md)

#### G1 — HIGH — Групповые сообщения не шифруются Sender Keys и не имеют wire-типа
- **Evidence:** `handle_send_group_message` handler.rs:441-477: сохраняет plaintext в `group_messages` (:460), затем `let payload = PlainPayload::Text(text.to_string())` и `pending::enqueue` **каждому** `group.members` (:464-470), включая собственную запись отправителя (:466-467 — фильтра `!= created_by` нет). `SenderKeyState::encrypt` вне core не вызывается; `EncryptedGroupEnvelope` нигде не конструируется. На приёме ветки `GroupMessage` нет: `PlainPayload::Text` от контакта попадает в 1:1-историю (:635-652) без `group_id`.
- **Последствие:** «группы» = рассылка 1:1-текстов без признака группы; §12.1 (Sender Keys, одно шифрование) существует только как библиотека. После M19 wiring участники увидят групповые сообщения как личные от каждого отправителя. Sender keys генерируются и раздаются (`CreateGroup/AddMember/SenderKeyUpdate`), но никогда не применяются.
- **Исправление:** M19a — зарезервировать вариант `PlainPayload::GroupMessage(EncryptedGroupEnvelope)` (append-only, §6.16.1) и бит `GROUPS` в `features`; M25 — шифрование через `SenderKeyState`, приём через `SenderKeyReceiver` per (group, sender), событие `GroupMessageReceived`.
- **Milestone:** M19a (резерв варианта) / M25 (реализация).

#### G2 — HIGH — Нет аутентификации отправителя внутри группы (любой участник может подделать сообщение от любого)
- **Evidence:** все участники хранят chain key каждого отправителя (`GroupMemberInfo.sender_chain_key`, types.rs:70; раздача открытым текстом внутри `GroupControl`, group_proto.rs:84,96,114). `EncryptedGroupEnvelope` (group_proto.rs:54-65) не содержит подписи; AEAD без AAD: group.rs:230-235 `cipher.encrypt(nonce.into(), plaintext)` — `group_id`, `from`, `counter` не аутентифицированы.
- **Последствие:** участник, зная chain key жертвы, шифрует под него и ставит `from = жертва` — остальные примут как её сообщение; `group_id`/`counter` можно переставлять между группами/сообщениями. В Signal Sender Keys каждый sender key несёт signing key, и каждое сообщение подписано — §12.1 это опускает.
- **Исправление (M25):** (а) AAD = `group_id ‖ from ‖ counter` (и nonce выводить локально — S6); (б) подпись каждого конверта: либо per-group pseudonym ML-DSA-65 (3 309 Б на сообщение — тяжело, но PQ), либо per-sender-key Ed25519 signing key, раздаваемый вместе с chain key (64 Б, классическая стойкость; подделка требует активной атаки в реальном времени, HNDL не применим) — решение владельца; (в) `from` = 8–16-байтный member-id вместо 1 952-байтного pubkey в каждом сообщении. §12.1 переписать.
- **Milestone:** M25.

#### G3 — HIGH — Идентификаторы участников несогласованы: псевдоним у создателя vs 1:1-ключ у получателя; доставка control по псевдониму невозможна
- **Evidence:** создатель кладёт в `members[0]` свой групповой псевдоним и `created_by = our_pubkey` (handler.rs:373-394, :412) и шлёт его в `CreateGroup.members` (:429). Получатель определяет создателя как `is_creator = pk == sender_pubkey` — это ключ 1:1-канала (:699), который никогда не равен псевдониму → у приглашённого создатель не Admin, `creator_sender_key` теряется, `created_by = sender_pubkey` (:725) — ключ, которого нет в `members`. Тест проходит только потому, что кладёт 1:1-ключ в `members` (handler.rs:1091-1097 `members: vec![sender_pk.clone(), my_pk.clone()]`). Далее `enqueue_group_control` пишет в очередь `contact_id(recipient_pubkey)` (:314-316), где recipient — псевдоним участника, не контакт: очередь для несуществующего контакта; `pseudonyms::find_by_pubkey` (pseudonyms.rs:92-109) ищет только **наши** псевдонимы — mapping «чужой псевдоним → контакт» отсутствует.
- **Последствие:** даже после M19 приглашения/обновления ключей адресованы «в никуда»; роль Admin у создателя не устанавливается у остальных (усугубляет S1).
- **Исправление (M25):** модель участника = `{member_pseudonym_pk, contact_id (для маршрутизации через 1:1-сессию), role, epoch}`; создатель на приёме берётся из `sender_pubkey` явно; таблица `pseudonym_pk → contact_id` для чужих псевдонимов.
- **Milestone:** M25.

#### G4 — MEDIUM — Forward secrecy Sender Keys не сохраняется на диске; после рестарта — повтор (key, nonce)
- **Evidence:** в storage только начальный `sender_chain_key: [u8;32]` (types.rs:70), он не продвигается; `SenderKeyState` создаётся заново в :385, :599, :791 и сохраняется только `chain_key_bytes()`; `SenderKeyReceiver` (`next_counter`, `skipped_keys`) не персистится (таблицы нет, grep → 0). Nonce детерминирован: `derive_nonce(msg_key, counter)` (group.rs:219-227).
- **Последствие:** (а) компрометация БД раскрывает начальный ключ → все прошлые сообщения отправителя расшифровываемы (§12.3.1 «прошлые сообщения защищены» неверно at rest); (б) после рестарта receiver стартует с counter 0 и не сможет догнать > `MAX_SKIP = 1000` (group.rs:36,187) — постоянный отказ; (в) после рестарта отправитель снова шифрует с counter 0 тем же chain key → **повтор keystream ChaCha20-Poly1305** для разных plaintext (та же пара key/nonce).
- **Исправление (M25):** таблица `group_sender_states (group_id, member) → Zeroizing(SenderKeyState|SenderKeyReceiver)`, запись после каждого шага до отправки (то же правило, что M19 п.8 для ratchet-снапшота).
- **Milestone:** M25 (обязательно до любой доставки групп).

#### G5 — MEDIUM — Протокол ротации §12.5 реализован частично
- **Evidence:** `AddMember` отдаёт новому участнику **начальные** ключи существующих (`handle_group_add_member` :509-514 берёт `sender_chain_key` из БД — см. G4) — инвариант §12.5 «новый участник не получает старые Sender Keys» нарушен; ротации при `AddMember` у существующих участников нет; `Leave` (:821-831) ротацию не запускает (§12.5: «покинул = то же, что удаление»); состояния «нельзя писать до `SenderKeyUpdate`», таймаута и force-rotate (§12.5) нет; `RemoveMember` ротирует только наш ключ (:790-800).
- **Исправление (M25):** epoch per group; при AddMember раздавать текущие (продвинутые) или свежие ключи; ротация при Leave; блокировка отправки до подтверждения ключей эпохи.
- **Milestone:** M25.

#### G6 — MEDIUM — Порядок/дедупликация групповых сообщений (§12.4) отсутствуют
- **Evidence:** `GroupMessage.parent_id`/`id` (group_proto.rs:38-40) никем не заполняются и не читаются; `store_group_message` ключ `(group_id, timestamp_micros)` (groups.rs:149) — два сообщения в одну микросекунду перезаписывают друг друга (`insert` = replace), порядок по timestamp отправителя (подделываемый); `seen_message_ids` в групповом пути не используется.
- **Исправление (M25):** ключ `(group_id, member_index, counter)`, DAG-lite по `parent_id`, dedup по `id`.
- **Milestone:** M25.

#### G7 — LOW — Мелкие функциональные дефекты групп
- CLI `/group create`: `hex::decode(m).unwrap_or_else(|_| m.as_bytes().to_vec())` (cli/main.rs:475) — не-hex alias превращается в мусорный pubkey, поиска по alias нет.
- `AcceptGroupInvite` (types.rs:132) — мёртвый IPC (auto-accept в :737-739, S1); клиенты его не вызывают.
- Групповая история без TTL: `ttl_secs: None` (handler.rs:455) — §6.7 «per-chat» на группы не распространяется.
- **Milestone:** M25.

#### G8 — LOW — Флаги capabilities расходятся со спекой и не имеют бита GROUPS
- **Evidence:** spec/05-protocol-versioning.md:36-47 `Features { TRIPLE_RATCHET=1<<0, DISAPPEARING_MSG=1<<1, REACTIONS=1<<2, REPLY=1<<3, FILE_TRANSFER=1<<4, GROUPS=1<<5, … PIN=1<<10 }`; код handshake.rs:28-34 только `PQ_RATCHET=1<<0, FILE_TRANSFER=1<<1, DISAPPEARING=1<<2` — биты FILE_TRANSFER/DISAPPEARING не совпадают со спекой.
- **Исправление:** M19a (wire v2 фиксирует биты): привести код и §6.4 к одному списку, зарезервировать `GROUPS`, `MULTIDEVICE`, `BOT`.
- **Milestone:** M19a.

### 1.3 Зависимость от протокола v2 (M19a) и mailbox v2 (M21)

- **M19a.** `GroupControl` едет внутри `PlainPayload` внутри ratchet-конверта → wire v2 (`Message::Ratchet{header, envelope}`, AAD) его не ломает. Но: (1) для групповых сообщений нужен слот в `PlainPayload` — добавить в v2 **сейчас** как резерв, потому что postcard кодирует discriminant позиционно и **неизвестный вариант у старого клиента = ошибка десериализации всего сообщения**, а не `PlainPayload::Unknown` (§6.16.1 это не защищает — `Unknown{type_id,data}` работает только если отправитель сам завернул в него); (2) групповой AEAD — AAD + локальный nonce (S6) + подпись (G2) — можно сделать в M25, формат конверта до M25 не «замораживается», т.к. группы в бете отключены; (3) бит `GROUPS` в `features` (G8).
- **M21 (mailbox v2, две коробки на пару).** Групповой fan-out через relay = N депозитов одного конверта в N pairwise-коробок (у каждой свой `sender_key[dir]` → N подписей). Группа из 100: 99 депозитов ≤ 64 KB на сообщение; квоты M21 (100 конвертов / 10 MB на коробку, 1 GB cap) выдерживают, но «болтливая» группа (100 сообщений/день) даёт 9 900 конвертов/день на relay и 99 QUIC-депозитов с телефона на каждое сообщение. Рекомендация — **зарезервировать в протоколе M21** `Deposit { targets: Vec<(mailbox_id, sender_sig)>, envelope }` (тело хранится один раз, ссылки N; `targets.len() ≤ 100`; квота отправителя считает N) — даже если fan-out не используется до M25. «Групповая коробка» (id из группового секрета) — отвергнуть: relay увидит состав группы (§12.6 unlinkability).

### 1.4 Рекомендация и объём

**Группы — не в 1.0-бете.** В M19/M19b групповые пути **отключить честно** (§15.8 п.6): `CreateGroup/SendGroupMessage/…` → `Error("groups are not available in this beta")`; входящий `PlainPayload::GroupControl` → `warn!` и игнор (снимает S1 с релизного пути; оставить только дешёвую проверку длины ключа = 32 Б); `/group`, `views/groups.rs`, FFI-методы и Android-экраны скрыть или пометить «недоступно». Обоснование: то, что есть, — не Sender Keys (G1), небезопасно (G2, G4, S1) и не маршрутизируется (G3); «groups-lite» (1:1 fan-out с тегом group_id) зафиксировал бы формат, который придётся ломать.

**M25 «Группы v2» после беты, 3–4 недели:** core 1 нед. (подписанный конверт + AAD + локальный nonce, персистентные состояния, epoch-ротация, fuzz `fuzz_group_decrypt`/`GroupControl`), демон 1,5 нед. (модель участника с `contact_id`, авторизация Admin (S1), state machine ротации, fan-out через mailbox v2, тест «3 демона»), клиенты 0,5 нед. (accept-invite UI, групповой чат), спека §12 — 2 дня. Зависимости: M19 (сеть), M21 (офлайн-доставка control-сообщений, иначе §12.5 «офлайн-участник получает RemoveMember из очереди» не работает), M22 (contact-first — членство только среди контактов).

## 2. Мультидевайс (§14, M8)

### 2.1 Что реализовано

| Слой | Что есть | Evidence | Качество |
|---|---|---|---|
| aira-core `device.rs` (483) | `DeviceInfo`, `DeviceGroup` (`MAX_DEVICES = 5`, add/remove/primary), `derive_device_id(seed, index)` [`aira/device/id`], `derive_sync_key(seed)` [`aira/device/sync-key`], `generate_link_code(seed, ts)`/`verify_link_code` (6 цифр, окно 5 мин + предыдущее) [`aira/device/link-code`] | device.rs:31,184-191,198-200,209-245 | works; 19 тестов; **вне core не используется ничего**, кроме `generate_link_code/verify_link_code` (grep) |
| aira-core `sync.rs` (364) | `SyncItem::{ContactAdded, ContactRemoved, Message, RatchetState, SettingChanged, GroupUpdate}`, `SyncBatch`, `SyncState`, `encode/decode_sync_batch` (ChaCha20-Poly1305 под статичным sync-key, случайный 96-бит nonce, без AAD) | sync.rs:31-104,139-179 | works; 10 тестов; вне core не используется (grep → 0) |
| aira-net | `DeviceRecord/DeviceEntry` (подписанная «DHT»-запись) | discovery.rs:64-144 | не используется (известно) |
| aira-storage | таблицы `devices`, `sync_log` (lib.rs:68-70); `save/load/list/remove_device`, `save_sync_entry/get_sync_entries_since` | devices.rs:22-185 | works; `save_sync_entry` демоном не вызывается |
| aira-daemon | `GenerateLinkCode` → код из seed; `LinkDevice{code, device_name}` → `verify_link_code` → `device_id = derive_key("aira/device/id-from-code", code)` → запись `DeviceInfo{node_id: vec![], priority: 2}`; `GetDevices`; `UnlinkDevice`; события `DeviceLinked/DeviceUnlinked/SyncCompleted` (types.rs:371-390) | handler.rs:190-251 | stub: события демоном не эмитятся (grep — только тесты types.rs и потребители), `node_id` не заполняется (:208), лимит 5 не проверяется (:218) |
| клиенты | CLI `/link`, `/devices`, `/unlink` (cli/main.rs:597-663); GUI Settings «Linked devices» (gui/views/settings.rs:93-155); FFI `get_devices/generate_link_code/unlink_device` (ffi/runtime.rs:307-340); Android — экрана нет (grep по kotlin → 0) | | UI есть, за ним пусто |
| тесты | `tests/multidevice.rs` — 6, все чистый core; `ratchet_state_handoff` — serde roundtrip с фейковыми ключами (известно, test-coverage-audit) | | M8 п.6 не закрыт |

### 2.2 Находки

#### D1 — HIGH — «Привязка» устройства — локальная запись, ничего не передаётся и не синхронизируется
- **Evidence:** код привязки выводится из seed (device.rs:209-225) → проверяющее устройство уже владеет seed; `LinkDevice` (handler.rs:194-225) только пишет строку в `devices` **своей** БД; второе устройство об этом не знает. Шаги §14.3a 3–5 (защищённый канал, передача контактов/ratchet-состояний/pending, регистрация NodeId) отсутствуют: `node_id: vec![]` (:208, комментарий «Populated when device announces» — такого кода нет), `sync_log` никем не пишется, `encode_sync_batch`/`derive_sync_key`/`DeviceGroup`/`derive_device_id` вне core не вызываются.
- **Последствие:** §14 реализован на уровне примитивов; M8 п.1–4 — заглушки. Пользователь видит «Device linked», но второе устройство продолжает жить как отдельная нода с тем же identity (и — см. D2/D3 — конфликтует с первым).
- **Исправление:** M25 (после 1.0), дизайн ниже; в M19b — скрыть/пометить UI.
- **Milestone:** M25.

#### D2 — BLOCKER (плана: M19 Phase A п.6) — M19 Phase A п.6 «iroh SecretKey детерминированно из seed» делает мультидевайс невозможным без re-keying всех пользователей
- **Evidence:** spec/18-milestones.md:559-561 «Решение: детерминированно из seed (стабильный `EndpointId`, простая доставка) — по умолчанию». Два устройства с одним seed → один `EndpointId` → одна pkarr-запись (последний публикующий побеждает), QUIC-пиры неразличимы. `EndpointId` попадёт в каждый `InvitationLink`/контакт-запись (M19 п.12).
- **Исправление (дёшево, в M19 Phase A):** контекст `aira/iroh/secret/<device_index>` с `device_index = 0` по умолчанию (в `settings`), `docs/KEY_CONTEXTS.md`; `derive_device_id(seed, index)` (device.rs:184) — источник `device_id` вместо `aira/device/id-from-code` (закрывает C9/S20). M25 добавляет индексы 1..4 без миграции.
- **Milestone:** M19 Phase A.

#### D3 — HIGH (key isolation) — Счётчик псевдонимов per-БД: два устройства выдадут одинаковые псевдонимные ключи в разных контекстах
- **Evidence:** `pseudonyms::next_counter` (pseudonyms.rs:22-32) стартует с 0 в каждой БД; ключи `aira/pseudonym/<counter>/{signing,x25519,mlkem}` (seed.rs:310-314). Ноутбук выдаст counter 0 контакту A, телефон — counter 0 группе X → **один keypair в двух контекстах** (нарушение §12.6.1 «один counter = один контекст» и правила key isolation), потеря unlinkability (один pubkey у двух сторон). Та же проблема после restore бэкапа (уже в M19 Phase A п.4).
- **Исправление:** до массовой выдачи псевдонимов (M19b `GetInvitation`) разбить u32: `counter = (device_index << 28) | local` (16 слотов × 2^28) — зафиксировать в KEY_CONTEXTS.md и `pseudonym_counter`; M25 использует слоты.
- **Milestone:** M19 Phase A / M19b.

#### D4 — MEDIUM (дизайн) — Handoff ratchet-состояния (§14.3c) несовместим с mailbox v2 (M21) в том виде, как он спроектирован
- **Evidence:** M21 п.2: `mailbox_id[dir]`, `owner_key[dir]` выводятся из pairwise `shared_secret` (spec/18:694-697) → одна коробка на (пара, направление) независимо от устройства. При handoff оба устройства делают `Retrieve/Ack` одной коробки: первый `Ack` удаляет конверты, второй их не увидит; расхождение ratchet-состояний = необратимый отказ (skipped keys между устройствами не помогают).
- **Варианты:** (a) Sesame-стиль (Signal): сессия и коробка на каждую **пару устройств** (Bob держит N ratchet'ов с N устройствами Alice; никаких пересылок секретов ratchet между устройствами; sync — только сообщения/контакты); (b) единая сессия + «активное устройство» с арендой + полная пересылка каждого входящего конверта + снапшот до ack — хрупко офлайн. Рекомендация — (a); чтобы это было представимо в M21, `Register` должен нести `device_id`/`EndpointId` владельца коробки (одна коробка = одно устройство), а contact-запись — список устройств контакта (`DeviceRecord` из discovery.rs:64-144 переиспользовать как подписанный список в pkarr/InvitationLink).
- **Milestone:** M21 (поле в Register), M25 (реализация).

#### D5 — MEDIUM — Link-code: 20 бит энтропии, канал не определён, код ничего не доказывает
- **Evidence:** 6 десятичных цифр (device.rs:224), окно 5–10 мин, без лимита попыток (handler.rs:195; ct-сравнение — известно core-audit low). Поскольку код выводится из seed, он доказывает лишь «у нас один seed» — что и так требуется §14.5.
- **Что решить в спеке:** модель (i) seed на обоих устройствах → привязка = обмен `EndpointAddr + device_index + отпечаток` через QR (byte-mode, как в M19b); одноразовый секрет **не** из seed (случайный, в QR) для взаимной аутентификации канала sync; модель (ii) «вторичное устройство без seed» (Signal provisioning) невозможна при детерминированном identity из seed — исключить явно.
- **Milestone:** M25 (спека §14.3 — в правки §5 этого отчёта).

#### D6 — LOW — Мелкое
- `MAX_DEVICES` только в core `DeviceGroup::add` (device.rs:104); демон пишет в storage напрямую (handler.rs:218) — лимита нет; `UnlinkDevice` primary допускается (понятия primary в демоне нет).
- Два определения `DeviceInfo` (aira-core device.rs:51 и aira-storage types.rs:129) — дубль.
- `SyncItem::Message.contact_key` смешивает pubkey контакта и `group_id` (sync.rs:48-49); `encode_sync_batch` без AAD/`from_device` в AAD — batch можно переадресовать между устройствами (низкий риск: один ключ на все устройства).
- **Milestone:** M25.

#### D7 — LOW (спека) — Термины и ссылки §14 устарели
- §14.2/§14.3 «iroh NodeId» → `EndpointId` (iroh 1.x); §14.3a п.5 и §14.4 «DHT» → pkarr/DNS (уже release-audit §6.5.2 п.9); §14.5 «отвязка = ротация prekeys» — prekeys в коде нет (C5), в v2 — `SignedPrekeyBundle` per device.
- **Milestone:** правки спеки (§5 этого отчёта).

### 2.3 Рекомендация и объём

**Мультидевайс — после 1.0 (M25, 4–6 недель).** В релизном пути только резервы: D2 (per-device iroh secret, M19 Phase A), D3 (разбиение счётчика псевдонимов, M19 Phase A/M19b), D4 (`device_id` в `Register` M21). В M19b: `GenerateLinkCode/LinkDevice/UnlinkDevice` → `Error("multi-device is not available in this beta")`, скрыть Settings «Linked devices», `/link /devices /unlink`, FFI. Контексты `aira/device/*` оставить.

Состав M25: решение (a)/(b) из D4; per-device `EndpointId` + `DeviceRecord` в pkarr и в `InvitationLink`; ALPN `aira/2/sync` между своими устройствами (взаимная аутентификация по seed-derived ключу + одноразовый QR-секрет); sync контактов/сообщений/настроек (ratchet-секреты — не синхронизировать при (a)); `SignedPrekeyBundle` per device на relay (M19a п.4 расширить); тест «2 устройства + 1 контакт, сообщение приходит на оба».

## 3. Bot API (§17A, M6A, aira-bot)

### 3.1 Что есть

- `crates/aira-bot`: `lib.rs` 219 + `runner.rs` 206 + `context.rs` 163 + `examples/echo.rs` 38 = 626 строк. Трейт `Bot` (7 RPITIT-методов: `on_message`, `on_group_message`, `on_contact_online/offline`, `on_group_member_joined/left`, `on_group_invite`, lib.rs:101-168), `BotContext` (`reply`, `send_group_message`, `my_address`, `contacts`, `history`, `send_file`, context.rs:44-151), `run_bot` (runner.rs:42-49: `DaemonClient::connect()` → event loop → `dispatch`, Ctrl+C). 11 тестов, ни одного с живым демоном (известно). `docs/BOT_SDK.md` соответствует коду (не спеке).
- Зависимости: `aira_daemon::client::DaemonClient::connect()` → `~/.aira/daemon.sock` / `\\.\pipe\aira-daemon` (client.rs:187-199) — тот же сокет, что у CLI/GUI; data dir демона жёстко `$HOME/.aira` / `%LOCALAPPDATA%\aira` (daemon/main.rs:33-56), флагов/переменных для второго экземпляра нет.
- Блокер №0: бот получает события только от `handle_incoming_payload` (handler.rs:621), который в production никем не вызывается → сегодня бот не получит ни одного сообщения по определению; `reply()` пишет в redb (`SendMessage`, handler.rs:61-75).

### 3.2 Находки

#### B1 — HIGH (модель) — Спека §17A «бот = отдельная нода со своим seed» vs код: SDK управляет демоном пользователя
- **Evidence:** spec/19-quality.md:80-89 «Бот имеет свой seed, свои ключи, свой ratchet state… не может прочитать чужие сообщения»; код: `run_bot` подключается к сокету демона текущего пользователя (runner.rs:43, client.rs:187-199), `my_address()` = `GetMyAddress` = **новый псевдоним пользователя** (handler.rs:77-95). `BOT_SDK.md:94` честно: «тот же IPC-протокол, что и CLI».
- **Последствие:** бот = процесс с полным доступом к переписке владельца демона (плюс `ExportBackup`, `Shutdown`); модель угроз §17A.5 неверна. Отдельная identity для бота невозможна на той же учётной записи (нет `--data-dir/--socket`).
- **Исправление:** (1) переписать §17A под «automation SDK для собственного демона» (правки в §5); (2) M19b/M26: `aira-daemon --data-dir <dir> --socket <path>` + `AIRA_DATA_DIR` — тогда «бот со своим seed» = отдельный демон, SDK не меняется (≈1 день).
- **Milestone:** спека — сейчас; `--data-dir` — M19b (дёшево) или M26.

#### B2 — BLOCKER (плана: M19 Phase B п.11) — Формат `MessageReceived.payload` несовместим между демоном и всеми тремя клиентами; текст до бота не дойдёт
- **Evidence:** демон для `PlainPayload::Text` эмитит **сырой UTF-8** (`payload_bytes: text.into_bytes()` handler.rs:641; событие :648-651), для прочих вариантов — postcard-байты `PlainPayload` (:660, :667-670); сам декодирует вход как `PlainPayload` (:628-629), хотя по §6.7 сообщение оборачивается в `MessageMeta` (spec/06:14-26); `SendMessage` хранит `text.into_bytes()` без `MessageMeta` (:66); `MessageMeta` в production не конструируется нигде (grep → только тесты cli/app.rs:496,522). Клиенты: CLI ждёт postcard(`MessageMeta`) (cli/app.rs:399-400, тесты :502-507), GUI пробует `MessageMeta`, затем `PlainPayload` (gui/state.rs:598-608), бот — только `PlainPayload` (bot/runner.rs:135-142). Спека §8: `MessageReceived { from, payload: PlainPayload }` (spec/10:27).
- **Последствие:** после M19 wiring входящий текст (сырые байты) не распарсится ни в CLI, ни в GUI («<invalid payload>»), ни в боте (`extract_text` → `None`, `on_message` не вызывается): первый байт текста трактуется как discriminant enum. Ранее не отмечалось.
- **Исправление:** M19 Phase B п.11 — единый контракт: по проводу `MessageMeta` (id/ttl/reply_to обязательны для §6.7/§6.8/§6.14), в IPC `MessageReceived { from, message: StoredMessage }` где `payload_bytes = postcard(MessageMeta)`, `SendMessage` оборачивает в `MessageMeta`; golden-байты IPC (test-coverage §1.4); бот/CLI/GUI — одна функция декодирования в `aira-ipc` (§14.0).
- **Milestone:** M19 Phase B (+ M19a: формат `MessageMeta` как единственный plaintext ratchet-конверта).

#### B3 — MEDIUM (безопасность) — Аутентификации и scope'ов у ботов нет
- **Evidence:** любой локальный процесс = бот (известно, M19b п.3 добавляет token/peer-cred); после M19b SDK **не сможет подключиться**, пока не научится читать `<data_dir>/ipc.token` — в плане M19b аira-bot не упомянут. Scope'ов нет: бот может `ImportBackup/ExportBackup/Shutdown/SetTtl`; broadcast событий всем IPC-клиентам (ipc.rs форвардер) — бот видит и события GUI.
- **Исправление:** M19b — `DaemonClient::connect_with_token(path)` в `aira_daemon::client`, SDK читает токен; M26 — scoped tokens (`reply-only`, `read-only`) либо (проще) отдельный демон на бота (B1).
- **Milestone:** M19b (токен в SDK), M26 (scopes).

#### B4 — LOW (спека↔код) — API §17A.2/17A.4/17A.6 расходится с кодом
- `#[async_trait]` (spec/19:107-121) → RPITIT `impl Future + Send`, трейт не object-safe (lib.rs:96-99); `on_contact_added`, `on_command` отсутствуют; `BotContext.daemon` публичное поле → приватный `Arc<DaemonClient>`; `history()` возвращает `StoredMessage.payload_bytes` с неопределённой кодировкой (B2); `aira-daemon --bot my_bot.wasm` (spec/19:157-166) и WASM sandbox §17A.6 — нет (wasmtime отсутствует в Cargo.toml); `is_bot` требует `UserProfile` §6.17, которого в коде нет (grep `UserProfile` → 0); rate limit §11B.6 «500 msg/min» ничем не обеспечен.
- **Milestone:** правки спеки (§5); функционал — M26.

#### B5 — LOW — `my_address()` создаёт запись псевдонима при каждом вызове
- **Evidence:** handler.rs:77-95 → `derive_pseudonym_pubkey` → `pseudonyms::store` (:340-348): бот, опрашивающий адрес, растит таблицу `pseudonyms` и счётчик (u32).
- **Исправление:** закрывается M19 п.12 (`GetInvitation` со стабильным псевдонимом); в SDK — `my_invitation()` вместо `my_address()`.
- **Milestone:** M19/M19b.

### 3.3 Нужен ли к 1.0 и вариант «минимальный Bot API после M19»

К 1.0 Bot API **не нужен** (не в чеклисте беты §6.6.7, не влияет на аудит ядра). Но SDK ломается дважды по ходу релизного пути (B2 формат событий, B3 токен), поэтому дешевле держать его зелёным по мере M19/M19b, чем чинить после:

1. **M19 Phase B п.11** — единый формат `MessageReceived` (B2); бот: `extract_text` → `MessageMeta`. (входит в M19)
2. **M19b п.3** — `DaemonClient::connect_with_token`, SDK читает токен; `aira-daemon --data-dir/--socket` + `AIRA_DATA_DIR` (B1, ≈1 день; даёт «бот со своим seed» без изменений SDK).
3. **M19 п.12** — `ctx.my_invitation()` → `aira://add/…` (B5).
4. `run_bot`: reconnect с backoff (переиспользовать логику GUI Bridge) — опционально, 0,5 дня.
5. Спека §17A и `BOT_SDK.md` переписаны под модель «клиент демона» с честным списком «нет: is_bot, sandbox, группы».

Итого ≈3–5 дней внутри M19/M19b. **M27 «Bot API v2» после 1.0 (1–2 нед. + sandbox):** `UserProfile.is_bot` (§6.17), scoped IPC tokens, `on_command`, группы (после M25), wasmtime-sandbox — отдельно.

## 4. Прочие фичи §6.7–6.18, i18n, Tauri (§15)

### 4.1 Таблица статуса

Обозначения: **тип** — только тип в `proto.rs`; **stub** — команда есть, делает только `set_status`.

| § | Фича | Wire-тип | Демон | Клиенты | Статус | К бете (M23)? |
|---|---|---|---|---|---|---|
| 6.7 | Disappearing | `MessageMeta.ttl` (proto.rs:94) — по проводу не ходит (B2) | `SetTtl` (types.rs:44), GC-таск `delete_expired` (main.rs:171, ffi/runtime.rs:108); `expires_at` ставится **только** в `messages::mark_read` (messages.rs:119-123), который демон/FFI **не вызывают** (grep → 0) → таймер никогда не стартует, `delete_expired` ничего не находит | CLI `/disappear` → `SetTtl` (main.rs:351-362); GUI — нет | частично (**F1, MEDIUM**: TTL фактически не работает) | **да** (обещано §6.7 v0.1): M19 Phase B — `mark_read` при `GetHistory`/открытии чата + `ttl` в `MessageMeta` по проводу |
| 6.8 | Реакции/ответы | `Reaction`, `MessageMeta.reply_to` | ветки нет (`_ =>` raw store :655-672) | только рендер (cli/app.rs:421, gui/state.rs:576); отправки нет | тип | нет (после беты; дёшево, класс M16) |
| 6.9 | Safety Numbers | `safety.rs` (core) | IPC-запроса нет | CLI `/verify` → stub «coming in M6» (main.rs:454-456); GUI — нет; `safety_number` вне core не вызывается | stub | **да** — §15.8 п.2 «сверка отпечатков — обязательный минимум»; уже в M19a п.6/M19b п.4, добавить IPC `GetSafetyNumber{contact}` |
| 6.10 | Export/import | — | `ExportBackup/ImportBackup` (backup.rs VERSION 1) | CLI `/export /import`; GUI identity.rs:79-87 | works (без groups/devices/pseudonyms — M19 Phase A п.4) | да |
| 6.11 | Медиа (фото/аудио/видео) | `MediaPayload` | нет (`SendFile` → `FileStart`) | рендер `[media]` | тип | нет; голосовые — M15 после беты |
| 6.12 | Link preview | `LinkPreviewPayload` | нет | рендер url | тип | нет |
| 6.13 | Edit/Delete | `Edit`, `Delete` | ветки нет | рендер; «↑ — редактировать последнее» (§9) нет | тип | нет |
| 6.14 | Receipts | `ReceiptPayload{Delivered,Read,Played}` | не отправляются; `read_at` не ставится | рендер `[receipt]` | тип | Delivered — как транспортный `DeliveryState` (M19 п.11), не как §6.14; Read/Played — после беты |
| 6.15 | Typing | `Typing(bool)` | нет | рендер | тип | нет |
| 6.16 | Unknown/расширяемость | `Unknown{type_id,data}` | — | рендер «update Aira» | тип; ⚠️ неизвестный discriminant postcard = ошибка десериализации, не `Unknown` (см. §1.3) | **да** (M19a): правило «новые типы — только через `Unknown{type_id}` или явный tag» в §6.16.1 |
| 6.17 | Профили | `UserProfile` — в коде нет | нет | CLI `/profile` — stub (main.rs:461-464) | нет | нет (alias-only в бете); `is_bot` → M26 |
| 6.18 | Удаление аккаунта | `KeyRevocation` — нет | нет | CLI `/delete-account` — только статус «Type YES» (main.rs:416-418), подтверждение не обрабатывается; GUI «Reset identity» чистит keychain/vault | нет | нет (требует revocation в pkarr/relay → после M20/M21) |
| 6.19 | Block | `ContactInfo.blocked` + `contacts::set_blocked` (contacts.rs:143) | не используется; входящие от blocked не фильтруются | CLI `/block` = **`RemoveContact`** (main.rs:399-408) — удаляет контакт вместо блокировки; `/unblock` — stub (:413-415) | некорректно (**F2, MEDIUM**) | **да** (§15.8 п.2 «блокировка — обязательный минимум»): IPC `BlockContact/UnblockContact`, drop входящих и handshake от blocked (M19 Phase B), UI M19b |
| 6.21 | Dedup | — | dedup.rs | — | works (ключ — M19 Phase A п.3) | да |
| 6.22 | Лимиты | `MAX_ENVELOPE_SIZE` | ratchet | — | works (M19b п.4) | да |
| 6.23 | Pin | типа `Pin` нет | нет | нет | нет | нет |
| 6.24 | Поиск | — | нет | CLI `/search` — stub (main.rs:468-470) | нет | нет |
| 6.25 | Разметка | — | — | — | нет (M16) | нет |
| 11B.6 | Mute | — | нет | CLI `/mute` — stub (main.rs:457-460) | нет | нет |
| 9.1 | i18n | `aira_core::i18n::I18n` (fluent), `locales/{en,ru}/main.ftl` — 33 ключа (i18n.rs:24 `SUPPORTED_LOCALES = ["en","ru"]`) | — | **ни CLI, ни GUI, ни FFI не используют `I18n`** (grep `i18n\|I18n` вне core → 0); CLI `/lang` — stub (main.rs:465-467); строки hardcoded | движок есть, не подключён | нет (M9.6 Phase C после беты — решено); для беты убрать `/lang` из справки или честная заглушка «English only» |

**F1 (MEDIUM, M19 Phase B)** — disappearing messages не удаляются: `expires_at` только в `mark_read` (messages.rs:119-123), вызовов нет. Спека §6.7 обещает v0.1. **F2 (MEDIUM, M19 Phase B/M19b)** — `/block` удаляет контакт, `blocked` нигде не проверяется; §6.19 и §15.8 п.2 требуют silent drop. **F3 (LOW)** — семь CLI-команд-заглушек (`/verify /mute /unblock /profile /lang /search /delete-account`) видны в справке и автодополнении (commands.rs:83-99): по §15.8 п.6 — честная строка «not available» или удалить из справки до реализации.

### 4.2 Обязательный минимум для беты из этой таблицы

По §15.8 п.2 («личность и seed, переписка 1-на-1, файлы, сверка отпечатков, блокировка») к бете нужны: 6.7 (F1), 6.9 (`GetSafetyNumber` + UI), 6.10, 6.19 (F2), 6.21, 6.22, 6.16 (правило расширения). Всё остальное — типы в `proto.rs` без реализации; это не мешает бете при условии, что клиенты не показывают мёртвые команды.

### 4.3 §15 Tauri v2 (коммит 971e038) vs M19b (egui) — противоречие?

Прямого противоречия нет, но есть три несогласованности:

1. **Класс клиента беты.** §15.8 (spec/17:214-250) объявляет Tauri «полным» desktop-клиентом, а egui/CLI — «минимальными» с заморозкой фич. M17 (Tauri) перенесён после релизного пути (spec/18:770-771), значит **бета 0.5 выходит только с минимальными клиентами** — это нигде не сказано явно. Работа M19b п.4-5 над egui (QR/ссылка, contact requests, relay-статус) укладывается в «обязательный минимум навсегда» (§15.8 п.2) — противоречия нет. Но **M9.6 Phase C/D/E** (i18n на 10 языков, темы, UX polish для egui; spec/18:167-205, 768 «после беты») противоречит заморозке §15.8 п.1 — либо снять C/D/E для egui и перенести i18n/темы в Tauri-клиент (`letar`), либо признать egui полным клиентом. Решение владельца.
2. **Группы/устройства в минимальных клиентах.** egui (`views/groups.rs`, settings «Linked devices») и CLI (`/group`, `/link`) уже несут UI фич, которых нет в «минимуме» §15.8 и которые не работают (§1–2) — по §15.8 п.6 их надо скрыть. Порядок переноса в Tauri (M17 п.7, spec/18:388-390: «… → группы → голосовые (M15) → разметка (M16)») предполагает существующие группы — заменить на «группы после M25».
3. **Предпосылка §15.9 «Tauri линкует aira-core напрямую, демон не нужен»** требует библиотеки `aira-node` (SessionManager/handler/pending-дренаж) — она уже предложена в §14.0 для wasm (spec/18:800-802); M19 должен реализовать net_task именно как библиотеку `aira-node`, иначе M17 повторит wiring.

Что писать в спеку: в §16.1 — «Бета 0.5: desktop = egui (минимальный класс), CLI, Android preview; Tauri (M17) — между бетой и 1.0 либо после 1.0 (решение владельца)»; в §15.8 — явный список того, что минимальные клиенты **скрывают** до M25/M26 (группы, устройства, `/lang`, `/profile`, `/search`, `/mute`, `/pin`).

## 5. Правки спеки — точный список для одного коммита `docs(spec)`

Дополняет release-audit §6.5.3 (версии/даты, DERP, §6.3b iOS, §15.7, INSTALL/README — там; здесь не повторяются). Формат: файл:строки — что заменить → на что.

### 5.1 Версия и индекс
1. `SPEC.md:4` и `spec/01-overview.md:4` «Версия: 0.2 | Дата: апрель 2026 | Обновлено после исследования PQ/P2P ландшафта» → «Версия: 0.5 | Дата: сентябрь 2026 | Релизный путь M18–M23 (§16.1), пересмотр §12/§14/§17A по аудиту 2026-09».
2. `spec/20-appendix.md:57` «_Spec v0.4 — источники: RustCrypto ml-kem 0.2/ml-dsa 0.1, iroh 0.97 (n0), …» → «_Spec v0.5 — источники: RustCrypto ml-kem 0.3/ml-dsa 0.1.1, iroh 1.1 (n0), …» (остальной список без изменений; добавить «Signal Sender Keys (libsignal `SenderKeyDistributionMessage`)» и «Signal Sesame (multi-device)» как источники §12/§14).
3. `SPEC.md:46-52` таблица «Расширения (v0.2+)»: «§12 Групповые чаты (v0.2)» → «§12 Групповые чаты (v2 — M25, после беты)»; «§14 Мультидевайс (v0.3)» → «§14 Мультидевайс (M26, после 1.0)»; `SPEC.md:59` «§17+17A Качество кода + Bot API» → «… + Bot API (SDK для собственного демона; v2 — M27)».

### 5.2 Дубликат §13 в spec/14-groups.md
4. `spec/14-groups.md:406-471` (от `---` на :406 через `## 13. Защита от спама` :408 до конца файла) → удалить целиком; вместо этого одна строка после §12.6.10: «Защита от спама — см. [§13](15-spam.md)». Единственный источник §13.2 — `spec/15-spam.md` (правится в M22).

### 5.3 §12 Группы — привести к коду и к решениям аудита
5. `spec/14-groups.md:1` «# SPEC §12: Групповые чаты (v0.2)» и `:7` «## 12. Групповые чаты (v0.2)» → «(статус: библиотечный код M6 без доставки; протокол v2 — Milestone 25)». Добавить после `:7` блок «⚠️ Статус на 2026-09: в коде есть `group.rs`/`group_proto.rs`/storage/IPC/UI, но групповые сообщения не шифруются Sender Keys и не имеют wire-типа (аудит E, G1–G6); в бете 0.5 группы отключены».
6. `spec/14-groups.md:20-35` (§12.1 псевдокод) → добавить в «Создатель группы» п.2: «Генерирует Sender Key = (chain key, signing key)»; в «Отправка» п.1: «Шифрует своим chain key с AAD = group_id ‖ sender_id ‖ counter; подписывает конверт signing key (G2)»; п.3 → «Ratchet chain key вперёд; состояние (chain key, counter) сохраняется **до** отправки (G4)».
7. `spec/14-groups.md:39-66` (§12.2 структуры) → заменить на актуальные имена: `aira_storage::GroupInfo`, `GroupMemberInfo { pseudonym_pk, contact_id, display_name, role, joined_at, epoch }`, `aira_core::group::{SenderKeyState, SenderKeyReceiver}` (персистентные, per (group, member)); указать, что `sender_chain_key: [u8;32]` в записи участника — временная схема v1, удаляется в M25.
8. `spec/14-groups.md:74` «Оффлайн участник получает пропущенные сообщения через локальную очередь» → «… через mailbox relay v2 (§6.5, M21): N депозитов одного конверта (`Deposit { targets }`)».
9. `spec/14-groups.md:112-125` (§12.4 `GroupMessage`) → синхронизировать с `group_proto.rs:29-45` (поле `counter: u64`, `from: Vec<u8>` → в v2 `sender_id: [u8;16]`, `payload: Vec<u8>` = postcard(MessageMeta)); добавить `EncryptedGroupEnvelope { group_id, sender_id, counter, ciphertext, signature }` (nonce выводится локально — S6).
10. `spec/14-groups.md:157-176` (§12.5 `GroupControl`) → привести к `group_proto.rs:74-122` (`CreateGroup{group_id, name, members, creator_sender_key}`, `AddMember{group_id, new_member, sender_keys}`, `RemoveMember`, `SenderKeyUpdate{group_id, new_key}`, `Leave`) + добавить `epoch: u32` во все варианты и правило «ключи в `AddMember.sender_keys` — только для `new_member`; остальные участники получают ключ нового участника от него самого» (S1); триггеры ротации: Add/Remove/Leave (G5).
11. `spec/14-groups.md:300-313` (§12.6.5 формат ссылки `aira://add/<base64url(pseudonym_pubkey)>#<fingerprint>`) → «`aira://add/<base64url(postcard(InvitationLink { version, pseudonym_pk, endpoint_addr, relays, fingerprint_hint, expires_at, sig }))>` — см. M19 п.12/M19b»; `spec/03-network.md:43-49` («при каждом вызове `/mykey` — новый pseudonym») → «`GetInvitation` выдаёт **стабильный** псевдоним для ссылки; новый — по явному запросу (M19 п.12)».
12. `spec/13-threat-model.md:24` «Flood в групповых чатах | Rate limit 30 msg/min, admin-only invites» → добавить пометку «(M25; в бете группы отключены)».
13. `spec/05-protocol-versioning.md:36-47` `Features` → синхронизировать с `handshake.rs:28-34` в рамках M19a: единый список битов (`PQ_RATCHET=1<<0, FILE_TRANSFER=1<<1, DISAPPEARING=1<<2, GROUPS=1<<3 (резерв), MULTIDEVICE=1<<4 (резерв), …`) — в спеке и в коде одно и то же (G8).
14. `spec/07-protocol-extensibility.md:21-35` (§6.16.1) → добавить п.5: «postcard **не** превращает неизвестный discriminant в `Unknown`: клиент v2 при получении варианта, добавленного позже, получит ошибку десериализации всего `PlainPayload`. Поэтому варианты для будущих фич (`GroupMessage`, `Pin`, `Profile`, `Revocation`) резервируются в M19a заранее, либо новые типы едут только внутри `Unknown { type_id, data }`».

### 5.4 §14 Мультидевайс
15. `spec/16-multidevice.md:1,7` «(v0.3)» → «(Milestone 26, после 1.0; предпосылки в M19 Phase A/M21)»; добавить статус-блок: «в коде — примитивы `device.rs`/`sync.rs` и IPC-заглушка `LinkDevice` (локальная запись, без синхронизации — аудит E, D1); в бете отключено».
16. `spec/16-multidevice.md:17-25` (§14.2) «own iroh NodeId, own prekeys» → «own iroh `EndpointId` = `aira/iroh/secret/<device_index>` (M19 Phase A), own `SignedPrekeyBundle` (M19a п.4)»; «один seed → один Identity» дополнить: «псевдонимный счётчик разбит по устройствам: `counter = device_index << 28 | local` (D3)».
17. `spec/16-multidevice.md:29-41` (§14.3a) → переписать: п.1-2 «`/link` показывает QR = `{ EndpointAddr, device_index, одноразовый случайный секрет }`; на новом устройстве seed уже введён (§14.5)»; п.3 «канал ALPN `aira/2/sync`, взаимная аутентификация: seed-derived ключ + одноразовый секрет из QR»; п.4 «передаются контакты, настройки, история после link; **ratchet-состояния не передаются** (модель Sesame — п.14.3c)»; п.5 «DHT» → «pkarr-запись `DeviceRecord` (подписанный список устройств)». Удалить 6-значный код из seed как механизм (D5).
18. `spec/16-multidevice.md:50-55` (§14.3c) → заменить на решение D4: «Вариант A (рекомендуется): сессия на каждую пару устройств (Sesame); relay-коробка = пара устройств, `Register` несёт `device_id`; Вариант B: handoff с арендой — только если A отвергнут владельцем». `:57-70` (§14.4) «DHT запись» → «pkarr/DNS-запись (`iroh-dns-server`, M20)», `node_id` → `EndpointId`.
19. `spec/16-multidevice.md:72-78` (§14.5): «Отвязка устройства = ротация prekeys на остальных» → «= отзыв `SignedPrekeyBundle` устройства + новая `DeviceRecord`»; добавить «`MAX_DEVICES = 5` проверяется демоном, не только `DeviceGroup` (D6)».

### 5.5 §17A Bot API и docs/BOT_SDK.md
20. `spec/19-quality.md:76-99` (§17A.1) → «Модель v1 (реализована): бот = клиент IPC **собственного** демона пользователя — видит всю переписку этого демона, действует под его identity (`BOT_SDK.md`). Бот с отдельной identity = отдельный `aira-daemon --data-dir <dir>` со своим seed (M19b). Модель «бот-нода в процессе демона / WASM» — M27». Удалить утверждения «бот не может прочитать чужие сообщения» в текущей формулировке, оставить как свойство модели «отдельный демон».
21. `spec/19-quality.md:101-137` (§17A.2) → заменить на фактический API: `trait Bot` с RPITIT (`fn on_message(&self, ctx: &BotContext, msg: IncomingMessage) -> impl Future<Output = Result<(), BotError>> + Send`, не object-safe), 7 методов из `lib.rs:101-168`; `BotContext { client: Arc<DaemonClient> }` с методами `reply/send_group_message/my_address/contacts/history/send_file`; удалить `on_contact_added`/`on_command` или пометить «M27».
22. `spec/19-quality.md:139-155` (пример) → пример из `examples/echo.rs:12-30`. `:157-166` (§17A.4) → удалить `aira-daemon --bot my_bot.wasm`; оставить «отдельный бинарник + IPC; токен `<data_dir>/ipc.token` (M19b)». `:168-178` (§17A.5) → «`is_bot` — после появления `UserProfile` (§6.17, M27)»; «Rate limits… §11B.6» → «применяются демоном к сетевым пирам, не к IPC-клиенту». `:180-191` (§17A.6) → «M27+, не в 1.0».
23. `spec/19-quality.md:30-34` (fuzz-таргеты `Message`, `GroupMessage`) → фактические/плановые имена из test-coverage §3.2 (`fuzz_wire_message`, `fuzz_group_decrypt`, …); `.claude/rules/testing.md:60,83-84` — то же (известно).
24. `docs/BOT_SDK.md:97-101` «Ограничения (v0.2)» → добавить: «бот подключается к демону текущего пользователя и видит всю его переписку; отдельная identity = отдельный демон (`AIRA_DATA_DIR`); аутентификация IPC-токеном с M19b; `my_address()` сейчас создаёт новый псевдоним при каждом вызове — используйте `my_invitation()` (M19)»; в таблице методов `history()` — формат `payload_bytes` = postcard(`MessageMeta`) (после M19).

### 5.6 §8 IPC, §9 CLI, §7 Storage — синхронизация с кодом
25. `spec/10-daemon-ipc.md:17-33` → полный список `DaemonRequest` (29 вариантов, `types.rs:12-172`), `DaemonResponse`, `DaemonEvent` (`types.rs:299-390`) с пометками «M19: +GetInvitation/AddContact{uri}/Accept/RejectContact/SetRelays/GetRelays/GetNetStatus/BlockContact/UnblockContact/GetSafetyNumber; события DeliveryState/NetStatus/ContactRequestReceived»; `MessageReceived { from, payload: PlainPayload }` (:27) → `MessageReceived { from, message: StoredMessage }` где `payload_bytes = postcard(MessageMeta)` (B2); группы/устройства — «отключены в бете, M25/M26».
26. `spec/11-cli.md:26-41` команды → добавить `/group …`, `/link`, `/devices`, `/unlink` со статусом «скрыты до M25/M26»; пометить `/mute`, `/unblock`, `/profile`, `/lang`, `/search`, `/delete-account`, `/pin` как «не реализованы (заглушка/убрать из справки до реализации, §15.8 п.6)»; `/block` — «silent drop на входе (M19), не удаление контакта (F2)»; `/verify` — «M19b, ≥128 бит». `:81-166` (§9.1 i18n) → добавить «Статус: движок `aira_core::i18n` (en/ru, 33 ключа) не подключён ни к одному клиенту; подключение — после беты (M9.6 Phase C или Tauri-клиент, решение владельца)».
27. `spec/09-storage.md:12-29` → добавить таблицы `pending_messages`, `seen_message_ids`, `groups`, `group_messages`, `devices`, `sync_log`, `pseudonyms`, `pseudonym_counter` (`lib.rs:57-74`) и план M25 `group_sender_states`; `encrypt_value(storage_key, table, value)` (:49-56) → фактическая сигнатура без `table` + план AAD `table ‖ row_key` (M19 Phase A п.5).

### 5.7 §15/§16 клиенты и milestones
28. `spec/17-cross-platform.md:232-250` (§15.8 правила минимальных клиентов) → добавить п.7: «Минимальные клиенты **скрывают** до соответствующих milestones: группы (M25), устройства (M26), `/lang`, `/profile`, `/search`, `/mute`, `/pin`»; в §16.1 (`spec/18:416-419`) добавить строку «Бета 0.5: desktop = egui (минимальный класс) + CLI; Android — preview/доведён (решение 6); Tauri (M17) — после беты (до 1.0 или после — решение владельца)».
29. `spec/18-milestones.md:388-390` (M17 п.7 порядок переноса «… → группы → голосовые (M15) → разметка (M16)») → «… → группы (после M25) → …».
30. `spec/18-milestones.md:58-65` (M6), `:67-73` (M6A), `:84-91` (M8) → статус-строки: «M6: библиотека + IPC/UI без доставки; см. M25», «M6A: SDK для собственного демона; см. M27», «M8: примитивы; см. M26».
31. `spec/18-milestones.md:167-205, 768` (M9.6 Phase C/D/E для egui) → либо снять (заморозка §15.8), либо оставить с пометкой «только если egui остаётся полным клиентом» — решение владельца.
32. Правки M18–M23 из §6.3 ниже — в тот же коммит или в отдельный `docs(spec): M19–M21 reservations for groups/multidevice/bots`.

### 5.8 docs/KEY_CONTEXTS.md
33. Добавить: `aira/iroh/secret/<device_index>` (D2), раскладку счётчика псевдонимов (D3), `aira/device/id-from-code` с пометкой «удаляется в пользу `derive_device_id`» (известно), для §12 — «Group AEAD AAD = group_id ‖ sender_id ‖ counter; nonce = derive_nonce(msg_key, counter) локально» и контекст signing-key sender key (`aira/group/sender-sign` — имя предложено, зафиксировать в M25).

## 6. Размещение в релизном пути (M23 vs M24+)

### 6.1 Вывод: ничего из §12/§14/§17A в бету не входит; в релизный путь входят только резервы

Аргументы: (1) ни одна из трёх подсистем не доставляет данные — группы шлют 1:1-текст без признака группы (G1), устройства — локальная запись (D1), бот не получит ни одного события до M19 (блокер №0) и не распарсит текст после (B2); (2) групповой код в текущем виде небезопасен (G2, G4, S1) и потребует другого wire-формата; (3) внешний аудит 1.0 (M23 «Для 1.0») должен покрывать ту криптографию, которая реально включена — включать в бету код, который заменяется, значит платить за аудит дважды; (4) §15.8 п.6 требует честную заглушку вместо половинчатой реализации.

**Что остаётся в M18–M23 (дешёвые резервы, чтобы M24+ не ломали протокол v2 и базу):**

| Где | Что | Зачем | Объём |
|---|---|---|---|
| M19a п.1 | вариант `PlainPayload::GroupMessage(EncryptedGroupEnvelope)` зарезервирован (тело может быть заглушкой), биты `GROUPS/MULTIDEVICE` в `features` (G1, G8); `MessageMeta` — единственный plaintext ratchet-конверта (B2) | postcard-позиционные enum: позже добавить без поломки v2-клиентов нельзя (§6.16.1) | 0,5 дня |
| M19a п.4 | `SignedPrekeyBundle` — с полем `device_id` | D4/M26 без смены формата bundle | 0,1 дня |
| M19a п.6 | `derive_device_id(seed, index)` вместо `id-from-code` (C9/S20 — уже в плане) | D2 | — |
| M19 Phase A п.6 | iroh SecretKey = `aira/iroh/secret/<device_index>`, `device_index = 0` в settings | D2 — иначе мультидевайс = re-keying всех адресов | 0,5 дня |
| M19 Phase A (новый п.7) | `pseudonym_counter`: `counter = device_index << 28 \| local`; restore ставит `local ≥ max+1` (п.4 уже) | D3 | 0,5 дня |
| M19 Phase B п.9 | групповые запросы → `Error("groups are not available in this beta")`; `PlainPayload::GroupControl` на входе → `warn!` + игнор; проверка длины ключа 32 Б остаётся | снимает S1 с пути беты; G3 не чинится сейчас | 0,5 дня (вместо 2–3 дней на S1) |
| M19 Phase B п.11 | единый формат `MessageReceived`/`SendMessage` через `MessageMeta`; `mark_read` при выдаче истории (F1); `BlockContact/UnblockContact` + drop на входе (F2); `GetSafetyNumber` (§6.9) | обещания §6.7/§6.9/§6.19 v0.1 и «обязательный минимум» §15.8 | 1–1,5 дня |
| M19 Phase C п.16 | «Группа из трёх демонов» → **перенести в M25** | тест без реализации невозможен | — |
| M19b | скрыть/пометить UI групп и устройств (egui `views/groups.rs`, settings «Linked devices», CLI `/group /link /devices /unlink`, FFI, Android `GroupsScreen`); CLI-заглушки F3 — убрать из справки; `DaemonClient::connect_with_token` + чтение токена в aira-bot; `aira-daemon --data-dir/--socket` (B1, B3) | честный UI беты; SDK не ломается | 1 день |
| M21 п.3 | `Register { …, device_id }`; `Deposit { targets: Vec<(mailbox_id, sig)>, envelope }` с `targets.len() ≤ 100` (или явно «v2.1») | групповой fan-out и per-device коробки без смены relay-протокола | 0,5 дня в дизайне, ≈1 день в коде |
| M23 | README/INSTALL/known limitations: «группы, мультидевайс, боты — после беты»; THREAT_MODEL: строка про группы «не реализовано» | ожидания пользователей | — |

### 6.2 Новые milestones после беты (нумерация — предложение)

Владелец параллельно ведёт тему «onion-маршрутизация + community relays» (`community-relays.md`, `onion-antiabuse.md`) — она первая претендует на номер после M23, потому что опирается прямо на M20/M21 и на инфраструктуру релиза. Резервирую **M24** за ней; здесь не проектируется, только зависимости.

| M | Тема | Зависимости | Объём | Версия |
|---|---|---|---|---|
| **M24** | Community relays + onion (резерв, дизайн — отдельные отчёты) | M20 (свой iroh-relay), M21 (aira-relay v2), M22 (PoW/квоты на intro-mailbox). **Учесть из этого отчёта:** групповой fan-out `Deposit{targets}` (§1.3) — нагрузка на community-relay = N× на сообщение; per-device коробки (D4) — число коробок на пользователя × устройства; обе величины входят в модель квот/анти-abuse community-relay | по отчётам F | 0.6.x |
| **M25** | Группы v2 (Sender Keys с подписью + AAD, персистентные состояния, epoch-ротация, модель участника с `contact_id`, авторизация Admin (S1), fan-out через mailbox v2, 3-daemon тест; §12 переписан) | M19a (резерв варианта), M21 (`Deposit{targets}`, офлайн-control), M22 (contact-first); **не** зависит от M24 | 3–4 нед. | 0.6.x → в 1.0, если владелец хочет «группы» в 1.0 (аудит покроет `group.rs`) |
| **M26** | Мультидевайс v2 (Sesame per-device сессии или handoff — решение D4; per-device `EndpointId`/`DeviceRecord` в pkarr и InvitationLink; ALPN `aira/2/sync`; QR-привязка с одноразовым секретом; sync контактов/сообщений/настроек; `SignedPrekeyBundle` per device) | M19 (D2/D3 резервы), M20 (pkarr), M21 (`device_id` в Register), M19a п.4; M25 не обязателен, но `GroupUpdate` sync-item без M25 пуст | 4–6 нед. | после 1.0 (1.1): меняет модель сессий → повторный аудит ядра |
| **M27** | Bot API v2 (`UserProfile.is_bot` §6.17, scoped IPC-токены, `on_command`, группы для ботов, wasmtime-sandbox опционально) | M19b (токен, `--data-dir`), M25 для групповых ботов | 1–2 нед. (+ sandbox отдельно) | после 1.0 |
| **M28** | «Дешёвые фичи §6.x»: реакции/ответы, edit/delete, read/played receipts, typing, pin, search, mute, профили без is_bot | M19 (MessageMeta по проводу), M19a (резерв вариантов `Pin/Profile`) | 2–3 нед. суммарно, дробится | 0.6.x / 1.x |

Порядок после беты (совмещение с уже решённым «M16 → M15 → M17 → M14»): **M16 (1 нед.) → M25 группы v2 → M17 Tauri (в п.7 переносит группы уже рабочими) → M24 community relays (параллельно с M25/M17, другой человек/агент) → 1.0 после внешнего аудита → M26 мультидевайс → M28 → M15 → M27 → M14.** Если владелец решит «1.0 без групп», M25 уходит за 1.0 и потребует отдельного аудита `group.rs` (небольшой: ~600 строк core).

### 6.3 Правки текста spec/18-milestones.md M18–M23 (сводно, для переноса)

- **M19a п.1:** «+ зарезервировать `PlainPayload::GroupMessage(EncryptedGroupEnvelope)` и биты `GROUPS`/`MULTIDEVICE` в `features`; единый список битов в §6.4 и `handshake.rs`; plaintext ratchet-конверта = `postcard(MessageMeta)` всегда».
- **M19a п.4:** «`SignedPrekeyBundle { device_id, x25519, mlkem_ek, sig, expires }`».
- **M19 Phase A п.6:** «iroh `SecretKey` = `seed.derive("aira/iroh/secret/<device_index>")`, `device_index = 0` в settings (мультидевайс M26 использует 1..4); per-device случайный ключ — не нужен».
- **M19 Phase A новый п.7:** «`pseudonym_counter`: `counter = (device_index << 28) | local`; restore — `local ≥ max(local)+1`».
- **M19 Phase B п.9:** «`SendMessage` → `MessageMeta{payload, ttl, id, reply_to}` → ratchet-encrypt…; групповые запросы (`CreateGroup … AcceptGroupInvite`) в бете → `Error("groups are not available in this beta")`, `enqueue_group_control`/`handle_send_group_message` не подключаются; входящий `PlainPayload::GroupControl` → `warn!` + игнор (S1 закрывается отключением, полная авторизация — M25)».
- **M19 Phase B п.11:** «`MessageReceived { from, message: StoredMessage }` (payload_bytes = postcard(MessageMeta)); `messages::mark_read` при `GetHistory`/открытии чата (иначе TTL §6.7 не срабатывает); `BlockContact/UnblockContact` + drop входящих и handshake от `blocked`; `GetSafetyNumber { contact }` (§6.9)».
- **M19 Phase C п.16:** удалить («Группа из трёх демонов» → M25).
- **M19b п.4:** «+ CLI: убрать из справки/автодополнения заглушки `/verify`(до реализации) `/mute /unblock /profile /lang /search /delete-account`; скрыть `/group /link /devices /unlink`; GUI — скрыть `views/groups.rs`, Settings «Linked devices»; FFI/Android — `GroupsScreen`/device-методы возвращают `Unsupported`».
- **M19b п.3:** «+ `aira_daemon::client::DaemonClient::connect_with_token(path)`; aira-bot читает `<data_dir>/ipc.token`; `aira-daemon --data-dir <dir> [--socket <path>]` и `AIRA_DATA_DIR` (второй экземпляр для бота со своим seed)».
- **M21 п.3:** «`Register { mailbox_id, owner_pk, sender_pk, device_id, notification_endpoint, ttl_hint }`; `Deposit { targets: Vec<(mailbox_id, sender_sig)>, envelope }`, `targets.len() ≤ 100`, квота отправителя считает `targets.len()`».
- **M23 п.3/п.7:** «известные ограничения беты: группы, мультидевайс, боты, реакции/receipts/typing/профили — после беты (M24–M28)».
- **«Пересмотр M9.6 и M14–17»:** добавить абзац «M24–M28» из §6.2 и порядок после беты.

## 7. Не проверено

- `cargo build/test/clippy` не запускались; выводы о поведении при wiring (M19) — по коду, сеть в демоне отсутствует.
- `habr_article.md` в клоне отсутствует (untracked у владельца) — публичные утверждения о группах/мультидевайсе/ботах не сверены.
- Android: прочитан только список Kotlin-файлов и grep; логика `GroupsScreen.kt`/`GroupChatScreen.kt`/`AiraRepository.kt` не читалась; экрана устройств нет по grep.
- GUI `views/groups.rs` и CLI `main.rs:472-663` — прочитаны по grep/фрагментам, не построчно; `AcceptGroupInvite` отсутствует во всех клиентах — по grep.
- `aira-net/src/discovery.rs:100-144` (`DeviceRecord::sign/verify`) не читалось — статус «не используется» по grep.
- Тесты `handler.rs:1234-1310` (`sender_key_update`, `leave`) и `:1499-1560` (link/pseudonyms) прочитаны частично.
- Утверждение «postcard: неизвестный discriminant → ошибка десериализации» — из семантики позиционного кодирования (§6.16.1 спеки), не подтверждено тестом.
- Сравнение с Signal Sender Keys (signing key на sender key) и Sesame — по памяти, без сверки с исходниками libsignal.
- `raw/*.json` прошлых агентов, монорепо `letar`, отчёты `community-relays.md`/`onion-antiabuse.md` (пишутся параллельно) не читались.
- Оценки объёма (недели) — экспертные, без разбивки по задачам.
