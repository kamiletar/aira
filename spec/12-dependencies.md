# SPEC §10: Зависимости (Cargo.toml workspace)

[← Индекс](../SPEC.md)

---

## 10. Зависимости (Cargo.toml workspace)

> **Целевые версии — Milestone 18** (bridge-релиз v0.4.0, дедлайн 30.09.2026: n0 отключает
> публичные relay для iroh 0.9x; решение A5 — iroh **1.2.0** от 09.09.2026).
> **До M18 в коде (v0.3.5):** `iroh 0.97` / `iroh-blobs 0.99` / `ml-dsa 0.0.4` / `ml-kem 0.2` /
> `rust-version 1.82` / `egui 0.29` / `aws-lc-rs 1.16 (unstable)`. Порядок миграции и
> snapshot-векторы с тега v0.3.5 (расхождение VK = релиз-блокер) — §16.1 M18.

```toml
[workspace.package]
version = "0.4.0"           # M18; 0.4.x — M19–M22; 0.5.0-beta.N — M23; 1.0 — после внешнего аудита
edition = "2021"
rust-version = "1.91"       # MSRV (M18); stable в CI пинится rust-toolchain.toml
license = "MIT OR Apache-2.0"   # LICENSE-MIT / LICENSE-APACHE в корне (условие SignPath)

# Линты на весь workspace (M18, решение A15); в каждом крейте — `[lints] workspace = true`
[workspace.lints.clippy]
all = "warn"
pedantic = "warn"
unwrap_used = "deny"
panic = "deny"
todo = "deny"
expect_used = "warn"
indexing_slicing = "warn"
[workspace.lints.rust]
unsafe_code = "deny"        # после замены unsafe в aira-gui на String::zeroize() (S3);
                            # aira-core и aira-storage — уже #![deny(unsafe_code)]

[workspace.dependencies]
# Async runtime
tokio = { version = "1", features = ["full"] }

# Networking — iroh 1.2 (QUIC + NAT traversal; presets::Minimal + свой AiraPreset, §5.1.1)
iroh = "1.2"
iroh-blobs = "0.103"        # BLAKE3 content-addressed file transfer (blob = ciphertext, §6.2)
# iroh-relay = { version = "1.2", features = ["server"] }
#   ТОЛЬКО в crates/aira-relay (M21/M24a): встроенный transport-relay. Клиенты не линкуют.
# discovery: pkarr через собственный iroh-dns-server (M20); DHT — после релиза (решение A3)

# Post-quantum crypto — см. п. 10.1 «Стратегия крипто-бэкендов»
# Фаза 1 (разработка): RustCrypto — pure Rust
ml-kem = { version = "0.3.2", features = ["deterministic", "zeroize"] }  # FIPS 203 — ML-KEM-768
ml-dsa = { version = "0.1.1", features = ["zeroize"] }                   # FIPS 204 — ML-DSA-65
# Фаза 2 (production): aws-lc-rs — FIPS 140-3 валидированный (feature `fips`)
# aws-lc-rs = "1.18"       # без `unstable` (M18); PQ-TLS (`pq-tls`) — после релиза

# Классический компонент гибридного KEM
x25519-dalek = { version = "2", features = ["static_secrets", "reusable_secrets"] }

# Симметрика
chacha20poly1305 = "0.10"

# Хэширование и KDF
blake3 = "1"

# Seed phrase & KDF
argon2 = "0.5"              # memory-hard KDF для seed-фразы (только Desktop-профиль, A4)
sha2 = "0.10"               # BIP-39 checksum

# Zeroization, constant-time
zeroize = { version = "1", features = ["derive"] }
subtle = "2"                # ct_eq для MAC/транскриптов

# RNG
rand = "0.8"                # не смешивать rand 0.8 / 0.9 в crypto/rustcrypto.rs (A16)
getrandom = "0.4"

# Сериализация
serde = { version = "1", features = ["derive"] }
postcard = { version = "1", features = ["alloc"] }
base64 = "0.22"             # base64url для invitation link (канонический, cap 4 KB)

# База данных
redb = "2"                  # 2.6 для беты; redb 4 (формат файла, wasm32) — с решением C13 (M14)

# TUI
ratatui = "0.29"
crossterm = "0.28"

# i18n (Mozilla Fluent) — движок есть, к клиентам не подключён (§9.1)
fluent = "0.16"
fluent-bundle = "0.15"
unic-langid = "0.9"
rust-embed = "8"            # встраивание .ftl файлов в бинарник

# Rate limiting & DoS protection — остаётся (§11B.1 tiers, §13 RateLimiter; M22)
governor = "0.8"            # GCRA rate limiter (keyed, atomic)

# Ошибки
thiserror = "2"
anyhow = "1"

# Логирование
tracing = "0.1"
tracing-subscriber = "0.3"

# GUI (desktop, минимальный класс §15.8)
eframe = "0.36"             # M19b (решение D4): закрывает advisories quick-xml через egui 0.29
egui = "0.36"
egui_extras = { version = "0.36", features = ["image"] }
qrcode = "0.14"             # QR «Share my link» (M19b)

# Кроссплатформенные утилиты
notify-rust = "4"           # OS уведомления (Linux/macOS/Windows)
keyring = { version = "3", features = ["windows-native", "apple-native", "sync-secret-service"] }
                            # M19b: без platform-features компилируется mock in-memory store
tray-icon = "0.19"          # системный трей
uniffi = { version = "0.28", features = ["cli"] }   # FFI биндинги (Android)
```

**Удалено вместе с `transport/*` (M19b, решение A13):** `ptrs` (obfs4), `arti-client` (Tor),
`hysteria2`, `rustls`/`tokio-rustls`/`webpki-roots`/`rcgen` (REALITY), `tokio-socks` (Tor SOCKS),
`reqwest` (CDN-fallback). Обфускация возвращается в M24c как датаграммный `CustomTransport`
iroh 1.2, а не как байтовые обёртки; REALITY исключён.

**Dev-dependencies и инструменты:** `proptest = "1"`, `arbitrary` + `libfuzzer-sys` (fuzz-крейты
`crates/*/fuzz`, M18 п.7), `cargo-audit`, `cargo-deny`, `cargo-auditable`, `cargo-cyclonedx`
(SBOM, M23), `cargo-llvm-cov`. Фичи `test-utils` (`MasterSeed::from_raw`) — вместо
`Platform::Mobile` (решение A4).

### 10.1 Стратегия крипто-бэкендов

> ⚠️ **Ни один pure-Rust PQ крейт не прошёл независимый security audit.** ml-dsa до
> 0.1.0-rc.4 имел уязвимость GHSA-5x2r-hc65-25f9 (принимались подписи с дублированными hint
> indices); релизные `ml-dsa 0.1.1` / `ml-kem 0.3.2` (M18) закрывают известные advisories
> pre-release версий (`cargo audit` не видит GHSA для ml-dsa — только Dependabot, §8.4 аудита).
> CI обязательно включает `cargo audit` и `cargo deny` как блокирующие джобы (M18).
> После M18 `decode_kem_encaps_key` валидирует EK (FIPS 203 §7.2) — тесты на невалидный EK/CT.

**Фаза 1 — Разработка и бета (0.4.x–0.5):**

- RustCrypto `ml-kem` + `ml-dsa` — pure Rust, простая компиляция,
  быстрая итерация, WASM-совместимость
- Абстрагировать крипто через trait'ы (`CryptoProvider`), чтобы
  бэкенд можно было заменить без переписывания логики

**Фаза 2 — Production (1.0+):**

- `aws-lc-rs` — единственная FIPS 140-3 валидированная библиотека
  с ML-KEM + ML-DSA. Поддерживает `PqdsaKeyPair::from_seed()`
- Минус: не pure Rust (C-обёртка aws-lc), требует cmake
- Плюс: production-hardened, используется AWS (KMS, S3, CloudFront)
- В коде уже есть `crypto/awslc.rs` (M13) за фичей `fips`, `compat-test` сверяет оба бэкенда
  на одном seed; при bump ml-kem/ml-dsa правится `awslc.rs`

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
pub mod rustcrypto;  // ml-kem + ml-dsa (фаза 1, default)
pub mod awslc;       // aws-lc-rs (фаза 2, feature = "fips")
```

---
