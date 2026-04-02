# SPEC §14: Мультидевайс (v0.3)

[← Индекс](../SPEC.md)

---

## 14. Мультидевайс — работа на нескольких устройствах (v0.3)

### 14.1 Проблема

Triple Ratchet (SPQR) привязан к конкретной сессии между двумя устройствами.
Если Alice имеет телефон и ноутбук — это два разных ratchet state для Bob.
Bob должен знать, на какое устройство отправлять.

### 14.2 Архитектура: Device Group

```
Alice Identity (ML-DSA, из seed-фразы)
  ├── Device A (laptop):  own iroh NodeId, own prekeys
  ├── Device B (phone):   own iroh NodeId, own prekeys
  └── Device C (tablet):  own iroh NodeId, own prekeys
```

**Ключевой принцип:** один seed → один Identity, но каждое устройство
имеет свой транспортный ключ (iroh NodeId) и свои prekeys.

### 14.3 Синхронизация

**a) Linked Devices Protocol:**

```
Привязка нового устройства:
  1. На Device A: /link — генерирует одноразовый QR/код
  2. На Device B: /link <code> — сканирует
  3. Устройства устанавливают защищённый канал (seed-derived shared key)
  4. Device A отправляет Device B:
     - Список контактов (pubkeys + aliases)
     - Текущие ratchet states (зашифрованные)
     - Pending messages
  5. Device B регистрирует свой NodeId в DHT под тем же Identity
```

**b) Синхронизация сообщений между устройствами:**

- Каждое сообщение (отправленное и полученное) реплицируется на все
  linked devices через зашифрованный канал
- Используется CRDT-подобный merge: (contact_id, timestamp, device_id) → message
- Конфликты невозможны (сообщения append-only)

**c) Ratchet state sync:**

- Только одно устройство ведёт ratchet с конкретным контактом в данный момент
- "Active device" для контакта = последнее, откуда отправлено сообщение
- Другие устройства получают копию через device sync канал
- При переключении устройства — ratchet state передаётся

### 14.4 DHT запись для мультидевайс

```
ML-DSA_pubkey → {
    devices: [
        { node_id: iroh_NodeId_A, priority: 1, last_seen: ts },
        { node_id: iroh_NodeId_B, priority: 2, last_seen: ts },
    ],
    signature: ML-DSA_sign(devices)
}
```

Bob отправляет сообщение Alice на устройство с наивысшим приоритетом
(или на все, если broadcast mode).

### 14.5 Ограничения

- Максимум 5 linked devices
- Seed-фраза нужна для привязки (proof of ownership)
- Отвязка устройства = ротация prekeys на остальных
- История сообщений НЕ синхронизируется полностью (только новые после link)
  — полная синхронизация через export/import бэкапа

---

