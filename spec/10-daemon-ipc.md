# SPEC §8: Daemon и IPC

[← Индекс](../SPEC.md)

---

## 8. Daemon и IPC

**aira-daemon** работает как фоновый процесс, **aira-cli** — тонкий
клиент, общающийся с daemon через Unix socket / Named pipe (Windows).

```
aira-daemon (сетевой стек, крипто, storage)
      ↕  IPC (postcard over Unix socket)
aira-cli    aira-gui (future)
```

IPC API — простой request/response + event stream:

```rust
pub enum DaemonRequest {
    SendMessage { to: PubKey, text: String },
    SendFile { to: PubKey, path: PathBuf },
    GetHistory { contact: PubKey, limit: u32 },
    AddContact { pubkey: PubKey, alias: String },
    GetMyAddress,
    // ...
}

pub enum DaemonEvent {
    MessageReceived { from: PubKey, payload: PlainPayload },
    FileProgress { id: [u8; 16], bytes_received: u64 },
    ContactOnline(PubKey),
    ContactOffline(PubKey),
}
```

### 8.1 CPU-intensive операции в async runtime

> ⚠️ ML-KEM decapsulation (~0.05ms), ML-DSA verify (~0.3ms) — быстрые.
> Но Argon2id (m=256MB, t=3) и ML-DSA keygen — **блокирующие операции**
> длительностью 1-10 секунд. Выполнение в tokio task заблокирует executor.

**Правило:** все CPU-heavy крипто-операции выполняются через
`tokio::task::spawn_blocking`:

```rust
// aira-daemon/src/crypto_tasks.rs

/// Argon2id KDF — блокирующая операция (1-10 сек)
pub async fn derive_master_seed(phrase: &str) -> Result<MasterSeed> {
    let phrase = phrase.to_string();
    tokio::task::spawn_blocking(move || {
        MasterSeed::from_phrase(&phrase)
    }).await?
}

/// ML-DSA keygen — блокирующая операция (~50ms)
pub async fn generate_identity(seed: &MasterSeed) -> Result<Identity> {
    let seed = seed.clone();
    tokio::task::spawn_blocking(move || {
        Identity::from_seed(&seed)
    }).await?
}
```

**Быстрые операции** (< 1ms) выполняются inline в async task:
ML-KEM encaps/decaps, ChaCha20 encrypt/decrypt, BLAKE3 hash, ratchet step

---
