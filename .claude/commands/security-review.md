# Security Review — Аудит криптографического кода

Проведи полный аудит безопасности изменённого кода.

## Когда использовать

- После изменений в `crates/aira-core/src/crypto/`
- После изменений в `crates/aira-core/src/ratchet.rs`
- После изменений в `crates/aira-core/src/handshake.rs`
- Перед каждым milestone release

## Шаги

1. **Запусти security-auditor агент** для автоматических проверок
2. **Вручную проверь** новые KDF-контексты в `docs/KEY_CONTEXTS.md`
3. **Проверь** что все `Zeroizing<_>` обёртки на месте
4. **Проверь** constant-time операции (subtle crate)
5. **Запусти** `cargo audit` и `cargo deny check`

## Критерии прохождения

- 0 критичных находок от security-auditor
- Все KDF-контексты задокументированы
- `cargo audit` без уязвимостей
- Нет `unsafe` в aira-core / aira-storage
