---
paths: "crates/aira-core/**", "crates/aira-storage/**", "crates/aira-net/**", "crates/aira-relay/**", "crates/aira-onion/**", "crates/aira-daemon/**"
---

# Правила безопасности — Aira

## Ключевые принципы

### 1. Изоляция ключей (Key Isolation) — обязательно

Каждый ключ используется **ровно в одном** криптографическом контексте.
Нарушение этого правила — блокирующее замечание при code review.

```rust
// ✅ Уникальный контекст для каждой цели
let identity_key = seed.derive("aira/identity/0");  // ML-DSA signing
let storage_key  = seed.derive("aira/storage/0");   // DB encryption

// ❌ ЗАПРЕЩЕНО: один ключ в двух контекстах
let key = seed.derive("aira/key");
sign_with(&key, data);       // НЕПРАВИЛЬНО — тот же ключ
encrypt_with(&key, data);    // НЕПРАВИЛЬНО — context overlap!
```

Все KDF-контексты задокументированы в `docs/KEY_CONTEXTS.md`.
Пример ошибки: Threema (USENIX Security 2023) — cross-protocol key reuse.

### 2. Нет unsafe в aira-core и aira-storage

```rust
// Начало каждого файла в aira-core / aira-storage:
#![deny(unsafe_code)]
```

В других крейтах — только с `// SAFETY:` комментарием:

```rust
// SAFETY: the slice is valid for the duration of the call,
// and we have exclusive access guaranteed by the borrow checker.
unsafe { ... }
```

### 3. Zeroize секретов в памяти

```rust
// ✅ Все секретные ключи через Zeroizing — автоочистка при Drop
use zeroize::Zeroizing;
let secret: Zeroizing<[u8; 32]> = seed.derive("aira/x25519/0");

// ❌ Секрет без zeroize — остаётся в памяти после освобождения
let secret: [u8; 32] = seed.derive_raw("aira/x25519/0");
```

### 4. Валидация размеров (DoS protection)

```rust
// Перед обработкой любого внешнего пакета (SPEC.md §6.22)
const MAX_ENVELOPE_SIZE: usize = 65_536; // 64 KB

if envelope.ciphertext.len() > MAX_ENVELOPE_SIZE {
    return Err(AiraError::MessageTooLarge { size: envelope.ciphertext.len() });
}
```

### 5. Нет unwrap() в production коде

```rust
// ❌ Паника в production
let result = operation().unwrap();

// ✅ Передача ошибки наверх
let result = operation()?;

// ✅ В тестах — допустимо
#[test]
fn test_something() {
    let result = operation().unwrap(); // OK в тестах
}
```

### 6. Constant-time операции

```rust
// ❌ Обычное сравнение для MAC — timing attack
if computed_mac == expected_mac { ... }

// ✅ Constant-time сравнение
use subtle::ConstantTimeEq;
if computed_mac.ct_eq(&expected_mac).into() { ... }
```

### 7. Секреты не попадают в Debug и логи

```rust
// ❌ derive(Debug) на типе с ключами — снапшот уйдёт в tracing/паники
#[derive(Debug)]
pub struct RatchetSnapshot { root_key: [u8; 32], ... }

// ✅ Ручной Debug с [REDACTED]
impl fmt::Debug for RatchetSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RatchetSnapshot").field("root_key", &"[REDACTED]").finish()
    }
}
```

Seed-фраза, ratchet-ключи, link-code, relay-токены — никогда в `tracing`, IPC-логах и сообщениях об ошибках.
IP собеседников и EndpointId — не выше `debug`.

### 8. Форвардинг чужих данных (relay, хопы, mailbox) — инварианты AP

Любой код, который переносит или хранит чужие данные (`aira-relay`, `aira-onion`, `hop.rs`, роли relay/mailbox в клиенте),
обязан соблюдать `spec/03-network.md` §5.5:

- **AP-1** нет выхода в интернет: терминал маршрута — только mailbox/нода Aira; ни одного `connect(host:port)` по данным из пакета;
- **AP-2** следующий хоп — только `EndpointId` из собственной таблицы, адрес из ячейки невалиден;
- **AP-3** ячейки фиксированного размера, без потоков;
- **AP-4** каждый байт под ключом с бюджетом (PoW-допуск, share ноды, fair queuing);
- **AP-5** хоп не источник и не отвечает за содержимое; mailbox лимитирует по sender/owner, не по IP хопа;
- **AP-6** хранилище только по `Register` владельца, квоты и TTL;
- **AP-7** форвардинг включён по умолчанию там, где безопасен (desktop unmetered), выключен на мобильных/metered, hidden mode в strict-странах.

Клиент **никогда** не регистрирует `RelayServer`/mailbox без явного opt-in пользователя. Push-URL mailbox — только по allowlist (SSRF).

### 9. IP пользователя

`hide_ip = true` по умолчанию (endpoint без IP-транспортов); invitation link и pkarr — без IP; хоп-идентичность — отдельный
локальный ключ, не из seed; RelayMap клиента — только свои relay (net_report раздаёт IP всем relay из списка).

## Чеклист перед code review

- [ ] Нет пересечений KDF-контекстов (docs/KEY_CONTEXTS.md актуален)
- [ ] Нет `unsafe` без `// SAFETY:` комментария в aira-core/aira-storage
- [ ] Все секреты через `Zeroizing<_>`
- [ ] Входящие пакеты проверяются по размеру (64 KB для envelope)
- [ ] Нет `unwrap()` в production путях
- [ ] MAC/хэш сравнения через constant-time (subtle crate)
- [ ] Fuzz targets обновлены при изменении парсинга
- [ ] Типы с секретами — ручной `Debug` с `[REDACTED]`, нет секретов в `tracing`
- [ ] Форвардящий код соблюдает AP-1…AP-7; нет `connect` по адресу из пакета
- [ ] Нет IP в invitation link / pkarr / логах выше `debug`
