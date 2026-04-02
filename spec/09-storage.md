# SPEC §7: Хранилище (aira-storage)

[← Индекс](../SPEC.md)

---

## 7. Хранилище (aira-storage)

База данных: **redb** (pure Rust, embedded, без unsafe в публичном API)

```rust
// Таблицы
const CONTACTS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("contacts");
    // key: ML-DSA pubkey bytes
    // value: postcard(ContactInfo)

const MESSAGES: TableDefinition<(u64, u64), &[u8]> =
    TableDefinition::new("messages");
    // key: (contact_id, timestamp_micros)
    // value: postcard(StoredMessage)

const SESSIONS: TableDefinition<&[u8], &[u8]> =
    TableDefinition::new("sessions");
    // key: contact pubkey
    // value: postcard(RatchetState) — зашифровано master key

const SETTINGS: TableDefinition<&str, &[u8]> =
    TableDefinition::new("settings");
```

### 7.1 Защита базы данных

- Storage key = `BLAKE3-KDF(master_seed, "aira/storage/0")` — деривируется
  из seed-фразы (см. п. 4.8)
- Storage key кэшируется в памяти daemon'а (zeroized при shutdown)
- Опционально: storage key хранится в OS keychain (keyring крейт),
  чтобы не вводить seed-фразу при каждом запуске

**Механизм шифрования (application-level):**

redb не поддерживает встроенное шифрование. Используется application-level
шифрование values перед записью:

```rust
// aira-storage/src/encrypted.rs

/// Шифрует value перед записью в redb
pub fn encrypt_value(storage_key: &[u8; 32], table: &str, value: &[u8]) -> Vec<u8> {
    // Уникальный nonce per-write: BLAKE3(storage_key || table || counter)
    let nonce = derive_nonce(storage_key, table, counter);
    chacha20poly1305::encrypt(storage_key, &nonce, value)
}

/// Расшифровывает value после чтения из redb
pub fn decrypt_value(storage_key: &[u8; 32], table: &str, encrypted: &[u8]) -> Result<Vec<u8>> {
    let (nonce, ciphertext) = split_nonce_ct(encrypted);
    chacha20poly1305::decrypt(storage_key, &nonce, ciphertext)
}
```

**Trade-offs:**

- Ключи таблиц (pubkey, timestamps) **не зашифрованы** — допустимо для
  локальной БД (атакующий с доступом к файлу видит pubkey контактов,
  но не содержимое сообщений и ratchet state)
- Альтернатива для v0.3 (mobile): оценить SQLCipher (полное шифрование
  включая индексы, аудированное решение, используется Mozilla/Microsoft)
- Ratchet states (таблица `sessions`) — критичны, шифруются обязательно

---
