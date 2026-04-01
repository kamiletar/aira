---
paths: "crates/**/*.rs", "tests/**"
---

# Правила тестирования — Aira

## TDD методология

1. **Red** — напиши тест, который падает
2. **Green** — напиши минимальный код для прохождения
3. **Refactor** — улучши код, сохраняя тесты зелёными

## Unit тесты (cargo test)

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_derivation_is_deterministic() {
        // Same phrase → same keys on any machine
        let (phrase, seed1) = MasterSeed::generate();
        let seed2 = MasterSeed::from_phrase(&phrase).unwrap();
        assert_eq!(seed1.derive("aira/identity/0").as_ref(),
                   seed2.derive("aira/identity/0").as_ref());
    }
}
```

## Property-based тесты (proptest)

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn padding_roundtrip(data: Vec<u8>) {
        let padded = pad_message(&data);
        let unpadded = unpad_message(&padded).unwrap();
        prop_assert_eq!(data, unpadded);
    }
}
```

## Fuzz тесты (cargo-fuzz)

Обязательно для всех парсеров внешних данных:

```rust
// fuzz/fuzz_targets/parse_message.rs
#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    // Не должно паниковать ни на каких входных данных
    let _ = postcard::from_bytes::<aira_core::proto::Message>(data);
});
```

Запуск: `cargo fuzz run parse_message`

## Интеграционные тесты

```rust
// tests/integration/two_nodes.rs
// Поднимает две ноды in-process и проверяет сквозную доставку
#[tokio::test]
async fn two_nodes_exchange_message() {
    let (alice, bob) = spawn_test_nodes().await;
    alice.send_to(bob.identity(), "hello").await.unwrap();
    let msg = bob.receive().await.unwrap();
    assert_eq!(msg.text(), "hello");
}
```

## Команды

```bash
cargo test                          # все тесты
cargo test -p aira-core             # только core
cargo test -- --nocapture           # с выводом println!
cargo test -- crypto::tests         # конкретный модуль
cargo fuzz run parse_message        # фаззинг парсера
cargo fuzz run parse_group_message  # фаззинг группового протокола
```

## Обязательные тесты по milestone

Каждый milestone должен иметь:
- Unit тесты для каждой новой функции
- Тест детерминистичности (seed → одинаковые ключи на разных машинах)
- Тест на невалидные входные данные (не должны паниковать)
- Интеграционный тест сквозного сценария
