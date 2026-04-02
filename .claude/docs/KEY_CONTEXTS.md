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

## KEM Internal Derivation

| Context string          | Purpose                            | File                                |
|-------------------------|------------------------------------|-------------------------------------|
| `aira/kem-keygen-d`     | ML-KEM-768 seed component d        | `aira-core/src/crypto/rustcrypto.rs`|
| `aira/kem-keygen-z`     | ML-KEM-768 seed component z        | `aira-core/src/crypto/rustcrypto.rs`|
| `aira/hybrid-kem/v1`    | Hybrid KEM combiner (IETF-style)   | `aira-core/src/kem.rs`              |

## Session-Derived Keys

| Context string                    | Purpose                    | File                          |
|-----------------------------------|----------------------------|-------------------------------|
| `aira/session/root/v1`            | Session root key           | `aira-core/src/handshake.rs`  |
| `aira/session/init-to-resp/v1`    | Initiator→Responder chain  | `aira-core/src/handshake.rs`  |
| `aira/session/resp-to-init/v1`    | Responder→Initiator chain  | `aira-core/src/handshake.rs`  |

## Ratchet Keys

| Context string                | Purpose                      | File                         |
|-------------------------------|------------------------------|------------------------------|
| `aira/chain/advance`          | Symmetric chain ratchet step | `aira-core/src/ratchet.rs`   |
| `aira/chain/message-key`      | Message key from chain key   | `aira-core/src/ratchet.rs`   |
| `aira/ratchet/root`           | DH ratchet root key update   | `aira-core/src/ratchet.rs`   |
| `aira/ratchet/chain`          | DH ratchet chain key derive  | `aira-core/src/ratchet.rs`   |
| `aira/ratchet/pq-mix`         | PQ secret mixing into root   | `aira-core/src/ratchet.rs`   |
| `aira/ratchet/pq-init`        | Initial PQ KEM keypair seed  | `aira-core/src/ratchet.rs`   |
| `aira/ratchet/pq-rekey`       | PQ KEM rekey seed            | `aira-core/src/ratchet.rs`   |

## Relay / Network

| Derivation                            | Purpose                  | File                        |
|---------------------------------------|--------------------------|-----------------------------|
| `BLAKE3(shared_secret ‖ "mailbox")`   | Relay mailbox ID         | `aira-net/src/relay.rs`     |

## Generation Suffix

The `/0` suffix in context strings is the key generation number.
Key rotation (without changing the seed phrase) increments it: `/0` → `/1` → `/2` ...

## Adding a New Context

1. Add a row to this table
2. Choose a unique string (namespace with `aira/<purpose>/<generation>`)
3. Never use the same string in two different code paths
4. Get a code review that explicitly checks this table
