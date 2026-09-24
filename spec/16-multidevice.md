# SPEC §14: Мультидевайс (Milestone 26, после 1.0)

[← Индекс](../SPEC.md)

---

## 14. Мультидевайс — работа на нескольких устройствах (M26, после 1.0; предпосылки в M19 Phase A / M19a / M21)

> ⚠️ **Статус на 2026-09** (аудит E §2): в коде — примитивы `aira-core/src/device.rs`
> (`DeviceGroup`, `derive_device_id`, `derive_sync_key`, link-code) и `sync.rs` (`SyncBatch`,
> `SyncItem`), таблицы `devices`/`sync_log`, IPC `GenerateLinkCode/LinkDevice/GetDevices/UnlinkDevice`,
> экраны в CLI/GUI/FFI. «Привязка» — локальная запись в **своей** БД: ничего не передаётся и не
> синхронизируется, `node_id` пуст, события `DeviceLinked/SyncCompleted` не эмитятся, `sync.rs` вне
> core не вызывается (D1). **В бете 0.5 отключено** (решение A11): запросы →
> `Error("multi-device is not available in this beta")`, UI скрыт (§15.8 п.7); контексты
> `aira/device/*` остаются. Реализация — **M26 «Мультидевайс v2»** (4–6 недель, после 1.0 — меняет
> модель сессий → повторный аудит ядра). В релизный путь входят только резервы, без которых M26
> потребовал бы re-keying всех пользователей: D2, D3, D4 (§14.2, §14.3c).

### 14.1 Проблема

Triple Ratchet (SPQR) привязан к конкретной сессии между двумя устройствами.
Если Alice имеет телефон и ноутбук — это два разных ratchet state для Bob.
Bob должен знать, на какое устройство отправлять.

### 14.2 Архитектура: Device Group

```
Alice Identity (ML-DSA-65, из seed-фразы)
  ├── Device 0 (laptop): own iroh EndpointId, own SignedPrekeyBundle, device_index = 0
  ├── Device 1 (phone):  own iroh EndpointId, own SignedPrekeyBundle, device_index = 1
  └── Device 2 (tablet): own iroh EndpointId, own SignedPrekeyBundle, device_index = 2
```

**Ключевой принцип:** один seed → один Identity, но каждое устройство имеет свой транспортный
ключ и свои prekeys:

- **iroh `SecretKey` per-device** = `seed.derive("aira/iroh/secret/<device_index>")`
  (M19 Phase A п.6, решение A8; `device_index = 0` в `settings` до M26; `docs/KEY_CONTEXTS.md`).
  Один ключ «детерминированно из seed» дал бы двум устройствам один `EndpointId`: одна
  pkarr-запись (последний публикующий побеждает), неразличимые QUIC-пиры — и этот `EndpointId`
  уже разошёлся бы в каждом `InvitationLink` (D2). Индексы 1..4 M26 добавляет без миграции
- **Хоп-идентичность** (роль `hop` в Aira Onion, §5.5; решение C5) — **не из seed**: ключ из
  локального RNG, второй `Endpoint` в том же демоне; в device group не входит и не
  синхронизируется. Иначе контакт нашёл бы IP устройства в записях хопов
- **`SignedPrekeyBundle { device_id, x25519, mlkem_ek, sig, expires }`** per device (M19a п.4) —
  поле `device_id` резервируется сразу, чтобы M26 не менял формат bundle
- `device_id = derive_device_id(seed, device_index)` (контекст `aira/device/id`); контекст v1
  `aira/device/id-from-code` (id из link-кода, `handler.rs`) удаляется
- **Псевдонимный счётчик разбит по устройствам** (D3, M19 Phase A п.7):
  `counter = (device_index << 28) | local` — 16 слотов × 2^28 (§12.6.1). Без этого ноутбук и
  телефон выдали бы `aira/pseudonym/0/*` разным контекстам — один keypair в двух контекстах,
  нарушение key isolation и потеря unlinkability

### 14.3 Синхронизация

**a) Linked Devices Protocol (M26):**

Модель — **seed вводится на каждом устройстве** (§14.5: seed = proof of ownership). Модель
«вторичное устройство без seed» (Signal provisioning) при детерминированном identity из seed
невозможна — исключена явно (D5).

```
Привязка нового устройства:
  1. На Device A: /link — QR (byte-mode, postcard) = { EndpointAddr_A (EndpointId + relay URL,
     без IP — A7), device_index_A, одноразовый СЛУЧАЙНЫЙ секрет S (32 байта, не из seed) }
  2. На Device B (seed уже введён, свой device_index выбран из свободных): сканирует QR
  3. Канал ALPN `aira/2/sync`: взаимная аутентификация — обе стороны знают seed-derived ключ
     (`aira/device/sync-key`) И одноразовый секрет S из QR. S нужен, чтобы владелец копии seed
     (например, старое скомпрометированное устройство) не подключился к sync без физического QR
  4. Device A → Device B: контакты (pubkeys, aliases, endpoint_addr, relays), настройки, история
     после link (старая — опционально); ratchet-состояния НЕ передаются (модель Sesame, §14.3c)
  5. Device B попадает в DeviceRecord (подписанный identity список устройств), запись
     публикуется в pkarr/DNS (§5.1.1, iroh-dns-server); контакты узнают о новом устройстве
     при следующем resolve
```

6-значный код из seed (`generate_link_code`, v1) как механизм убран (D5): 20 бит энтропии, канал
не определён, и доказывает он лишь «у нас один seed» — что и так требуется.

**b) Синхронизация сообщений между устройствами (M26):**

- Каждое сообщение (отправленное и полученное) реплицируется на все
  linked devices через зашифрованный канал `aira/2/sync`
- `SyncBatch` шифруется `aira/device/sync-key` с AAD = `from_device ‖ to_device ‖ seq`
  (v1 — статичный ключ без AAD, batch переадресуем между устройствами, D6)
- CRDT-подобный merge: (contact_id, timestamp, device_id) → message; конфликты невозможны
  (append-only)
- `SyncItem::Message.contact_key` — отдельные поля для контакта и `group_id` (v1 смешивает, D6)

**c) Сессии и ratchet — решение C3 (открыто; определяет `Register { device_id }` в M21 п.3):**

| | **Вариант A — сессия на каждую пару устройств (Sesame, Signal)** — рекомендация аудита | **Вариант B — единая сессия + handoff с арендой** (прежний текст §14.3c) |
|---|---|---|
| Сессии | Bob держит N ratchet'ов с N устройствами Alice; каждое устройство шифрует само | одна сессия на контакт; «активное устройство» = последнее отправившее; state передаётся при переключении |
| Mailbox v2 (§6.5) | коробка = пара **устройств**: `Register` несёт `device_id`; отправитель делает `Deposit { targets }` на все устройства контакта | одна коробка на пару identity; оба устройства делают `Retrieve/Ack` одной коробки — первый `Ack` удаляет конверты, второй их не увидит (D4) |
| Sync между своими устройствами | контакты, сообщения, настройки; **секреты ratchet не пересылаются** | полная пересылка каждого входящего конверта + снапшот ratchet до ack — хрупко офлайн; расхождение состояний = необратимый отказ (skipped keys не спасают) |
| Цена | ×N трафика отправителя (N ≤ 5), N bundle на relay, N Safety Numbers на контакт | сложная state machine аренды, гонки при офлайне |
| Контакт-запись | `DeviceRecord` `{ device_id, endpoint_id, prekey_bundle, priority }[]`, подписанный identity — тип уже есть в `aira-net/src/discovery.rs` | без изменений |

**Рекомендация — A.** Следствие для релизного пути: `Register { mailbox_id, owner_pk, sender_pk,
device_id, … }` в M21, `SignedPrekeyBundle.device_id` в M19a; в бете `device_id` = устройство 0.
Если владелец выберет B — `device_id` в `Register` остаётся (коробку регистрирует активное
устройство), но добавляется протокол аренды.

### 14.4 Запись identity для мультидевайс (pkarr/DNS, не DHT)

```
identity_pubkey (ML-DSA-65) → DeviceRecord {
    devices: [
        { device_id, endpoint_id: iroh_EndpointId_0, priority: 1, prekey_bundle, last_seen },
        { device_id, endpoint_id: iroh_EndpointId_1, priority: 2, prekey_bundle, last_seen },
    ],
    signature: ML-DSA_sign(devices)
}
```

Публикуется как pkarr-запись через собственный `iroh-dns-server` (§5.1.1, M20; DHT — после
релиза, решение A3) и в сокращённом виде — в `InvitationLink` (устройства приглашающего). Bob
отправляет на все устройства Alice (вариант A) или на устройство с наивысшим приоритетом
(вариант B). `DeviceRecord` из `discovery.rs` (v1, «DHT-запись») переиспользуется как есть.

### 14.5 Ограничения

- Максимум 5 linked devices (`MAX_DEVICES = 5`) — проверяется **демоном** при `LinkDevice`,
  не только в `DeviceGroup::add` (D6)
- Seed-фраза нужна на каждом устройстве (proof of ownership); одноразовый секрет QR — для
  аутентификации канала sync
- Отвязка устройства = отзыв его `SignedPrekeyBundle` + публикация новой `DeviceRecord` без него
  (контакты перестают ему писать); при варианте A его ratchet-сессии просто умирают, ротировать
  ключи на остальных устройствах не нужно. (v1 «ротация prekeys на остальных» — prekeys в коде
  нет, C5 аудита ядра)
- Primary device отвязать нельзя без передачи роли (v1 допускает, D6)
- История сообщений НЕ синхронизируется полностью (только новые после link)
  — полная синхронизация через export/import бэкапа
- Android — только клиент сети (не хоп, не relay, §5.5), но полноценное устройство группы
- Два определения `DeviceInfo` (`aira-core/device.rs` и `aira-storage/types.rs`) — объединить (D6)

---

