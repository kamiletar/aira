# Хранилище (aira-storage)

> Полная спека: SPEC.md §7

## База данных

**redb** — pure Rust, embedded, без unsafe в публичном API.

## Таблицы

| Таблица | Ключ | Значение | Назначение |
|---------|------|---------|-----------|
| `contacts` | ML-DSA pubkey | ContactInfo (postcard) | Контакт-лист |
| `messages` | (contact_id, timestamp_µs) | StoredMessage | История сообщений |
| `sessions` | contact pubkey | RatchetState (encrypted) | Triple Ratchet состояния |
| `pending_messages` | (contact_id, seq) | EncryptedEnvelope | Очередь отправки |
| `seen_message_ids` | message_id [u8; 16] | timestamp_secs | Dedup окно 24ч |
| `settings` | &str | &[u8] | Настройки приложения |
| `groups` | group_id | GroupInfo | Групповые чаты |
| `group_messages` | (group_id, timestamp) | StoredMessage | История групп |

## Защита БД

Storage key = `BLAKE3-KDF(master_seed, "aira/storage/0")` — из seed-фразы.
Key кэшируется в памяти daemon (zeroized при shutdown).
Опционально: хранить в OS keychain (`keyring` крейт).

## Message Deduplication (SPEC.md §6.21)

При каждом входящем сообщении:
1. Проверить `seen_message_ids` по `MessageMeta.id`
2. Дубликат → silent drop
3. Новое → записать в `seen_message_ids` с текущим timestamp
4. GC: удалять записи старше 24 часов при каждом запуске

```rust
pub const DEDUP_WINDOW_SECS: u64 = 24 * 60 * 60;
```

## Паттерны работы с redb

```rust
// Запись
let write_txn = db.begin_write()?;
{
    let mut table = write_txn.open_table(CONTACTS)?;
    table.insert(pubkey_bytes, &serialized)?;
}
write_txn.commit()?;

// Чтение
let read_txn = db.begin_read()?;
let table = read_txn.open_table(CONTACTS)?;
let value = table.get(pubkey_bytes)?;
```
