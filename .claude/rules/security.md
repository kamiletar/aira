---
paths: "crates/aira-core/**", "crates/aira-storage/**"
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

## Чеклист перед code review

- [ ] Нет пересечений KDF-контекстов (docs/KEY_CONTEXTS.md актуален)
- [ ] Нет `unsafe` без `// SAFETY:` комментария в aira-core/aira-storage
- [ ] Все секреты через `Zeroizing<_>`
- [ ] Входящие пакеты проверяются по размеру (64 KB для envelope)
- [ ] Нет `unwrap()` в production путях
- [ ] MAC/хэш сравнения через constant-time (subtle crate)
- [ ] Fuzz targets обновлены при изменении парсинга
