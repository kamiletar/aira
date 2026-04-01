---
paths: "crates/**/*.rs"
---

# Правила для unsafe кода

## aira-core и aira-storage

В этих крейтах **полностью запрещён** unsafe код:

```rust
// В начале каждого файла:
#![deny(unsafe_code)]
```

Если возникает необходимость — это сигнал переосмыслить архитектуру.

## Другие крейты

Unsafe допустим только при наличии:

```rust
// ✅ Обязательный SAFETY комментарий
// SAFETY: we have exclusive access to the buffer,
// the pointer is valid and properly aligned,
// and the lifetime is bounded by 'a.
let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
```

**Запрещено:**

```rust
// ❌ Unsafe без объяснения
unsafe { std::slice::from_raw_parts(ptr, len) }
```

## Зависимости с unsafe

- `zeroize` — допустимо, нужен для безопасной очистки памяти
- `iroh` — допустимо, транспортный уровень
- Новые крейты с `unsafe` — требуют обоснования в PR

## Проверка

```bash
# Найти все unsafe блоки
grep -rn "unsafe" crates/ --include="*.rs"

# Убедиться что аудит зависимостей проходит
cargo audit
```
