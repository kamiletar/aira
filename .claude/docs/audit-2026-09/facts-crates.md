# Факты crates.io (проверено 2026-09-07 через API)

| crate | в Cargo.lock | latest stable | дата | заметка |
|---|---|---|---|---|
| ml-dsa | 0.1.0-rc.5 (Cargo.toml: rc.4, НЕ закоммичен) | **0.1.1** | 2026-06-05 | rust 1.85; deps: hybrid-array 0.4, signature 3, module-lattice 0.2.3, shake 0.1; features zeroize/pkcs8/getrandom |
| ml-kem | 0.2.3 | **0.3.2** | 2026-05-10 | deps sha3 ^0.11, rand_core 0.10, kem 0.3 |
| sha3 | 0.11.0-rc.6 (ломает сборку: keccak::p1600) | 0.12.0 | 2026-05-15 | |
| keccak | 0.1.6 + 0.2.0 | 0.2.2 | 2026-08-21 | |
| iroh | 0.97.0 | **1.1.0** | 2026-08-25 | 1.0.0 = 2026-06-15; rust 1.91; QUIC = `noq` (не quinn); getrandom 0.4, rand 0.10, ed25519-dalek 3 |
| iroh-relay | 0.97.0 | **1.1.0** | 2026-08-25 | feature `server`: tokio-rustls-acme, tokio-websockets, ws_stream_wasm (браузер) |
| iroh-blobs | 0.99.0 | 0.103.0 | 2026-06-15 | |
| iroh-gossip | — | 0.101.0 | 2026-06-15 | |
| redb | 2.6.3 | 4.2.0 | 2026-08-17 | |
| redb-opfs | — | **НЕТ на crates.io (404)** | GitHub wireapp/redb-opfs, последнее обновление 2025-09-25 | риск для M14.4 |
| argon2 | 0.5.3 | 0.6.0 | 2026-08-27 | |
| x25519-dalek | 2.0.1 | 3.0.0 | 2026-07-06 | |
| chacha20poly1305 | 0.10.1 | 0.11.0 | 2026-08-05 | |
| egui/eframe | 0.29.1 | 0.36.1 | 2026-08-07 | |
| tauri | — | 2.11.5 | 2026-07-01 | |
| uniffi | 0.28.3 | 0.32.0 | 2026-06-30 | |
| quinn | — | 0.11.11 | | iroh 1.x на noq |
| rustls | — | 0.23.43 | | |
| tokio | — | 1.53.1 | | |
| aws-lc-rs | 1.16 | 1.18.1 | 2026-09-01 | |
| pkarr | — | 8.0.1 | 2026-08-31 | |
| wasm-bindgen | — | 0.2.128 | 2026-09-04 | |

Toolchain на машине: rustc 1.94.1 (2026-03-25). Workspace rust-version = 1.82.

## Сборка
`cargo check --workspace --all-targets` с незакоммиченным bump ml-dsa → **FAIL**: `sha3 0.11.0-rc.6` не находит `keccak::p1600` (9 ошибок). Причина: ml-dsa rc.5 → sha3 rc.6 несовместим с keccak 0.2.0 в lock.
Правильный путь: ml-dsa = "0.1.1" (стабильная), заодно ml-kem = "0.3" (оба на hybrid-array 0.4 / RustCrypto новое поколение).

## GitHub (проверено 2026-09-07)
- repo kamiletar/aira public, 1 star, last push 2026-07-30
- Releases: v0.3.4 и v0.3.5 (оба 2026-04-10). v0.3.5 assets: MSI, DMG (arm64+x86_64), AppImage, tar.gz ×3, zip, APK + sha256
- CI на main (run 30501538193, head 971e038, 2026-07-30): **FAILURE** — job Clippy (cargo clippy -D warnings) и job Security Audit (cargo audit) упали; Format и Test — success.

## Проверки HEAD (971e038) локально 2026-09-07, rustc 1.94.1, worktree
- cargo clippy --workspace --all-targets -D warnings: **exit 0** (в CI 07-30 упал — вероятно, более новый stable toolchain с новыми lint'ами; проверить в CI логах)
- cargo test --workspace: **435 passed, 0 failed** (14 бинарей; core 107, net 42, daemon 50+3, gui 37 (+3 ignored), cli 69, storage ?, ffi 9, bot 11, multidevice 6)
- cargo audit: **17 vulnerabilities, 12 warnings, exit 1**:
  - quinn-proto 0.11.14 RUSTSEC-2026-0185 (high 7.5, remote memory exhaustion) → ≥0.11.15 (iroh 1.x на noq — уходит с апгрейдом iroh)
  - hickory-proto 0.25.2 RUSTSEC-2026-0118 (unbounded loop, NO FIX в 0.25) и -0119 (O(n²)) → 0.26.1 (iroh 1.1 тянет hickory-resolver 0.26)
  - h2 0.4.13 RUSTSEC-2026-0258 → ≥0.4.16; crossbeam-epoch 0.9.18 RUSTSEC-2026-0204 → ≥0.9.20
  - rustls-webpki 0.103.10: RUSTSEC-2026-0098/0099/0104 → ≥0.103.13
  - quick-xml 0.30/0.37/0.38/0.39 (4 версии!) RUSTSEC-2026-0194/0195 high → ≥0.41 (скорее всего egui/winit/xml deps)
  - webbrowser 1.2.0 RUSTSEC-2026-0257 → ≥1.2.2
  - warnings: ttf-parser unmaintained, anyhow/event-listener/lru/memmap2/rand unsound, yanked: der 0.8.0, pkarr 5.0.4, spin 0.9.8/0.10.0
- cargo deny check: см. deny log (wildcard warnings для path deps в aira-bot)

## Эксперименты с bump (worktree HEAD, 2026-09-07)
- **A: ml-dsa = "0.1.1" при iroh 0.97 → НЕ РАЗРЕШАЕТСЯ**: iroh-base 0.97 пинит `digest = "=0.11.0-rc.10"`, а ml-dsa 0.1.1 → shake 0.1 → digest ^0.11 (стабильные 0.11.2/0.11.3). Вывод: апгрейд ml-dsa ЗАБЛОКИРОВАН до апгрейда iroh на 1.x (iroh-base 1.1.0 digest не тянет). Milestone 9.6 Phase A нельзя сделать отдельно от миграции iroh.
- **B: ml-kem = "0.3.2" → фича `deterministic` удалена** (доступны: alloc, default, getrandom, hazmat, pem, pkcs8, zeroize) — seed-based keygen надо переписать под новый API.
- iroh-blobs 0.103.0 требует iroh ^1.0.0; iroh-gossip 0.101.0 — iroh ^1. iroh-base 1.1: ed25519-dalek 3.x, curve25519-dalek 5.x, getrandom 0.4, zeroize ^1.9.

## API новых PQ-крейтов (docs.rs, 2026-09-07)
- ml-dsa 0.1.1: `SigningKey::<MlDsa65>::from_seed(&Seed)` — детерминированный keygen из 32-байтного seed (FIPS 204 Alg. 6 KeyGen_internal); `as_seed()/to_seed()`; трейты `KeyInit, KeyExport, Keypair, Signer, Verifier` (signature 3.x), `Generate` при feature rand_core; `SignatureEncoding`. Типы `EncodedVerifyingKey`, `EncodedSignature`, `ExpandedSigningKeyBytes`.
- ml-kem 0.3.2: `MlKem768::generate_keypair()` (нужна feature getrandom); **Seed = 64 байта** (d‖z) — «ML-KEM seeds are decapsulation (private) keys, consistently 64 bytes»; `DecapsulationKey768`/`EncapsulationKey768`; трейты `kem::{Encapsulate, Decapsulate, Kem}` (kem 0.3); `KeyEncoding`/`ExpandedKeyEncoding` deprecated → новая кодировка. Feature `deterministic` удалена — детерминированный keygen через Seed-тип.

- **C: iroh 1.1 + iroh-blobs 0.103 + ml-dsa 0.1.1 + ml-kem 0.3.2 → зависимости РАЗРЕШАЮТСЯ.** Компиляция падает только в aira-core: 15 ошибок, все в crates/aira-core/src/crypto/rustcrypto.rs (+2 вывода типов в handshake.rs:82,195 как следствие):
  - `ml_dsa::KeyGen` / `MlDsa65::key_gen_internal(&seed)` → `SigningKey::<MlDsa65>::from_seed(&Seed)`
  - `key.sign_deterministic(msg, &[])` → `Signer::sign` / `try_sign` (0.1: детерминированный режим по умолчанию, hedged через rand_core)
  - `ml_kem::KemCore`, `MlKem768::generate_deterministic(&d,&z)` → Seed 64 байта (d‖z) → `DecapsulationKey768::from_seed`-подобный API
  - `ml_kem::EncodedSizeUser`, `ml_kem::Encoded::<..>` → новая кодировка ключей (`KeyEncoding` deprecated)
  Ошибки aira-net/daemon по iroh 1.1 API ещё не показаны (сборка остановилась на core). Оценка: миграция PQ-API — 1 файл, ~день.
- **D: только iroh 1.1 + iroh-blobs 0.103 (PQ-крейты старые) → разрешается; компиляция: всего 3 ошибки в crates/aira-net/src/endpoint.rs** (`Endpoint::empty_builder` удалён в 1.x + 2 вывода типов). Крейты выше (daemon/ffi/gui/cli) не дошли до проверки из-за падения aira-net — их ошибки неизвестны, но aira-net = единственный прямой потребитель iroh (daemon использует обёртки). Оценка: миграция iroh 0.97→1.1 — 1–3 дня, API уже почти совпадает (EndpointId/EndpointAddr в 0.97 уже переименованы).
