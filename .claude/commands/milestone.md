# Milestone — Реализация milestone из SPEC.md

Реализуй следующий (или указанный) milestone из SPEC.md §16.

## Аргументы

`/milestone [номер]` — номер milestone (1-13). Без аргумента — следующий незавершённый.

## Процесс

1. **Прочитай** SPEC.md §16 — список задач milestone
2. **Прочитай** связанные секции спеки (крипто, протокол, и т.д.)
3. **Проверь** что предыдущий milestone завершён
4. **Создай** ветку: `git checkout -b milestone/M<N>-<name>`
5. **Реализуй** каждую задачу из списка milestone
6. **После каждого файла** — запусти тесты: `cargo test -p <crate>`
7. **Обнови** `Cargo.toml` workspace version
8. **Коммит** с сообщением: `feat(core): implement Milestone N — <description>`

## Принципы реализации

- TDD: сначала тест (падает), потом код (проходит)
- Минимальный код для прохождения тестов
- Обязательные тесты (SPEC.md §17): детерминистичность, деградация, fuzz targets
- `#![deny(unsafe_code)]` в aira-core и aira-storage
- Никаких `unwrap()` в production коде

## Чеклист завершения milestone

- [ ] Все задачи из SPEC.md §16.M<N> реализованы
- [ ] `cargo test` проходит для всех затронутых крейтов
- [ ] `cargo clippy -- -D warnings` без ошибок
- [ ] `cargo fmt` применён
- [ ] Версия в `Cargo.toml` обновлена
- [ ] Если изменились public API — docstrings обновлены
- [ ] Если новые KDF-контексты — `docs/KEY_CONTEXTS.md` обновлён
