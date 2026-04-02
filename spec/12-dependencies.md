# SPEC §10: Зависимости (Cargo.toml workspace)

[← Индекс](../SPEC.md)

---

## 10. Зависимости (Cargo.toml workspace)

```toml
[workspace.dependencies]
# Async runtime
tokio = { version = "1", features = ["full"] }

# Networking (iroh ~1.0, вышел из RC-серии 0.97+)
iroh = "0.97"             # QUIC (noq) + NAT traversal + relay
iroh-blobs = "0.99"       # BLAKE3 content-addressed file transfer

# Post-quantum crypto — см. п. 10.1 «Стратегия крипто-бэкендов»
# Фаза 1 (разработка): RustCrypto — pure Rust, быстрая итерация
ml-kem = "0.2"            # FIPS 203 — ML-KEM-768 (stable)
ml-dsa = "0.1"            # FIPS 204 — ML-DSA-65 (≥0.1.0-rc.4, fix GHSA-5x2r-hc65-25f9)
# Фаза 2 (production): aws-lc-rs — FIPS 140-3 валидированный
# aws-lc-rs = "1.16"      # ML-KEM + ML-DSA + seed-based keygen

# Классический компонент гибридного KEM
x25519-dalek = { version = "2", features = ["static_secrets"] }

# Симметрика
chacha20poly1305 = "0.10"

# Хэширование и KDF
blake3 = "1"

# Seed phrase & KDF
argon2 = "0.5"              # memory-hard KDF для seed-фразы

# Zeroization
zeroize = { version = "1", features = ["derive"] }

# Сериализация
serde = { version = "1", features = ["derive"] }
postcard = { version = "1", features = ["alloc"] }

# База данных
redb = "2"

# TUI
ratatui = "0.29"
crossterm = "0.28"

# i18n (Mozilla Fluent)
fluent = "0.16"
fluent-bundle = "0.15"
unic-langid = "0.9"
rust-embed = "8"            # встраивание .ftl файлов в бинарник

# Rate limiting & DoS protection
governor = "0.8"            # GCRA rate limiter (keyed, atomic)

# Pluggable transports / DPI resistance
ptrs = "0.8"                # obfs4/o5 (pure Rust PT framework)
# arti-client = "0.27"     # Tor (feature = "tor")
# hysteria2 = "0.1"        # Hysteria 2 (feature = "hysteria")

# Ошибки
thiserror = "2"
anyhow = "1"

# Логирование
tracing = "0.1"
tracing-subscriber = "0.3"

# GUI (desktop)
eframe = "0.29"
egui = "0.29"

# Кроссплатформенные утилиты
notify-rust = "4"         # OS уведомления (Linux/macOS/Windows)
keyring = "3"             # OS keychain
tray-icon = "0.19"        # системный трей
uniffi = "0.28"           # FFI биндинги (Android)
```

### 10.1 Стратегия крипто-бэкендов

> ⚠️ **На апрель 2026 ни один pure-Rust PQ крейт не прошёл независимый
> security audit.** ml-dsa имел уязвимость GHSA-5x2r-hc65-25f9
> (принимались подписи с дублированными hint indices) — **исправлено
> в 0.1.0-rc.4+**. ml-kem (0.2.3) стабильнее, но тоже без аудита.
> CI обязательно включает `cargo audit` для раннего обнаружения.

**Фаза 1 — Разработка и тестирование (v0.1-v0.2):**

- RustCrypto `ml-kem` + `ml-dsa` — pure Rust, простая компиляция,
  быстрая итерация, WASM-совместимость
- Абстрагировать крипто через trait'ы (`CryptoProvider`), чтобы
  бэкенд можно было заменить без переписывания логики

**Фаза 2 — Production (v0.3+):**

- `aws-lc-rs` — единственная FIPS 140-3 валидированная библиотека
  с ML-KEM + ML-DSA. Поддерживает `PqdsaKeyPair::from_seed()`
- Минус: не pure Rust (C-обёртка aws-lc), требует cmake
- Плюс: production-hardened, используется AWS (KMS, S3, CloudFront)

**Альтернатива для high-assurance:**

- `libcrux` (Cryspen) — формально верифицирован через hax + F*,
  но все крейты < 0.1 (pre-release)

```rust
// aira-core/src/crypto/mod.rs — абстракция крипто-бэкенда

pub trait CryptoProvider {
    type SigningKey;
    type VerifyingKey;
    type KemDecapsKey;
    type KemEncapsKey;

    fn keygen_from_seed(seed: &[u8; 32]) -> (Self::SigningKey, Self::VerifyingKey);
    fn sign(key: &Self::SigningKey, msg: &[u8]) -> Vec<u8>;
    fn verify(key: &Self::VerifyingKey, msg: &[u8], sig: &[u8]) -> bool;
    fn kem_encaps(pk: &Self::KemEncapsKey) -> (Vec<u8>, [u8; 32]);
    fn kem_decaps(sk: &Self::KemDecapsKey, ct: &[u8]) -> [u8; 32];
}

// Реализации:
pub mod rustcrypto;  // ml-kem + ml-dsa (фаза 1)
// pub mod awslc;    // aws-lc-rs (фаза 2)
```

---
