# Key Derivation Contexts

Canonical list of all KDF context strings used in Aira.

> **Rule:** Each context string maps to exactly ONE key used for exactly ONE purpose.
> Adding a new context MUST be done here first, before writing code.
> Reusing a context for a different purpose is a SECURITY VULNERABILITY.

## Master Seed → Subkeys

| Context string          | Algorithm    | Purpose                  | File                         |
|-------------------------|--------------|--------------------------|------------------------------|
| `aira/identity/0`       | ML-DSA-65    | Identity signing key     | `aira-core/src/identity.rs`  |
| `aira/x25519/0`         | X25519       | ECDH component of KEM    | `aira-core/src/kem.rs`       |
| `aira/mlkem/0`          | ML-KEM-768   | PQ KEM component         | `aira-core/src/kem.rs`       |
| `aira/storage/0`        | ChaCha20-P1305 | DB encryption key      | `aira-storage/src/lib.rs`    |

## Session-Derived Keys

| Derivation                            | Purpose                  | File                        |
|---------------------------------------|--------------------------|-----------------------------|
| `BLAKE3(shared_secret ‖ "mailbox")`   | Relay mailbox ID         | `aira-net/src/relay.rs`     |
| `BLAKE3(X25519_ss ‖ MLKEM_ss ‖ ctx)` | Hybrid session root key  | `aira-core/src/kem.rs`      |

## Generation Suffix

The `/0` suffix in context strings is the key generation number.
Key rotation (without changing the seed phrase) increments it: `/0` → `/1` → `/2` ...

## Adding a New Context

1. Add a row to this table
2. Choose a unique string (namespace with `aira/<purpose>/<generation>`)
3. Never use the same string in two different code paths
4. Get a code review that explicitly checks this table
