# Debug — Отладка проблем

Найди и исправь баг систематически.

## Шаги

1. **Воспроизведи** проблему с минимальным тест-кейсом
2. **Добавь трассировку:**
   ```rust
   tracing::debug!("state: {:?}", state);
   // Запуск: AIRA_LOG=aira=debug cargo test -- --nocapture
   ```
3. **Найди root cause** — проследи через слои (CLI → daemon → core → net → storage)
4. **Исправь** — минимальное изменение
5. **Напиши регрессионный тест:**
   ```rust
   #[test]
   fn regression_issue_N() {
       // Тест который воспроизводит баг
   }
   ```
6. **Проверь:** `cargo test`, `cargo clippy -- -D warnings`

## Crypto-специфичная отладка

```rust
// Трассировка ratchet операций (только в debug build!)
#[cfg(debug_assertions)]
tracing::trace!("ratchet step: counter={}, key_material={:x?}", counter, &key[..4]);
```

⚠️ Никогда не логируй полные ключи в production (только первые 4 байта для диагностики).

## Частые проблемы

| Симптом | Вероятная причина |
|---------|-----------------|
| Decryption failed | Ratchet desync — проверь счётчики |
| Handshake timeout | iroh NAT traversal — попробуй relay |
| DB locked | Два daemon процесса — killall aira-daemon |
| Seed derivation wrong | KDF context string опечатка |

## После исправления

1. Убедись тест зелёный: `cargo test`
2. Коммит: `fix(scope): описание бага`
