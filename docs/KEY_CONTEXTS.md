# KDF Key Contexts — Aira

Все контексты для `blake3::derive_key()`. Каждый ключ используется ровно в одном контексте (Key Isolation).
Нарушение — блокирующее замечание на code review (`.claude/rules/security.md`).

**Совместимость бэкендов:** все контексты идентичны для RustCrypto (default) и aws-lc-rs (`--features=fips`).
Одинаковый seed → одинаковые ключи → совместимые сообщения между бэкендами.

**Статус:** `код` — есть в коде (HEAD, v0.3.x); `план (M<N>)` — вводится в указанном milestone
(`spec/18-milestones.md` §16.1); `удаляется (M<N>)` — есть в коде, убирается в milestone.
Обновлено 24.09.2026 по аудиту 2026-09 (`spec-remainder-audit.md` §5.8, `onion-antiabuse.md` §5.11,
`net-audit.md` §7–8, `release-audit-2026-09.md` §4.3).

## Master Seed Derivation

| Контекст | Назначение | Крейт | Статус |
|----------|-----------|-------|--------|
| `aira/identity/0` | ML-DSA-65 identity signing key | aira-core/identity | код |
| `aira/x25519/0` | X25519 static DH key | aira-core/handshake | код |
| `aira/mlkem/0` | ML-KEM-768 KEM key (input to kem_keygen) | aira-core/handshake | код |
| `aira/storage/0` | Storage encryption key | aira-storage | код |
| `aira/iroh/secret/<device_index>` | iroh `SecretKey` чат-endpoint'а (Ed25519 `EndpointId`), per-device; index 0 сейчас (аудит §8.5 D2). Это **чат**-идентичность; хоп-идентичность — не из seed (см. «Исключения») | aira-core/seed → aira-net | план (M19) |

## ML-KEM Internal (seed splitting)

| Контекст | Назначение | Крейт | Статус |
|----------|-----------|-------|--------|
| `aira/kem-keygen-d` | ML-KEM-768 deterministic keygen: seed d | aira-core/crypto | код |
| `aira/kem-keygen-z` | ML-KEM-768 deterministic keygen: seed z | aira-core/crypto | код |

## Hybrid KEM

| Контекст | Назначение | Крейт | Статус |
|----------|-----------|-------|--------|
| `aira/hybrid-kem/v1` | X25519+ML-KEM IETF-style combiner | aira-core/kem | код |

## Handshake Session Keys

| Контекст | Назначение | Крейт | Статус |
|----------|-----------|-------|--------|
| `aira/session/root/v1` | Session root key from combined secrets | aira-core/handshake | код |
| `aira/session/init-to-resp/v1` | Directional chain key: initiator→responder | aira-core/handshake | код |
| `aira/session/resp-to-init/v1` | Directional chain key: responder→initiator | aira-core/handshake | код |

## Double Ratchet (1-on-1)

| Контекст | Назначение | Крейт | Статус |
|----------|-----------|-------|--------|
| `aira/chain/advance` | Symmetric chain key advancement | aira-core/ratchet | код |
| `aira/chain/message-key` | Per-message encryption key | aira-core/ratchet | код |
| `aira/ratchet/root` | Root key after DH ratchet step | aira-core/ratchet | код |
| `aira/ratchet/chain` | Chain key after DH ratchet step | aira-core/ratchet | код |

## PQ Ratchet (SPQR)

| Контекст | Назначение | Крейт | Статус |
|----------|-----------|-------|--------|
| `aira/ratchet/pq-mix` | Mix PQ shared secret into root key | aira-core/ratchet | код |
| `aira/ratchet/pq-init` | Initial PQ keypair seed from root key | aira-core/ratchet | код |
| `aira/ratchet/pq-rekey` | PQ rekey seed after ratchet step | aira-core/ratchet | код |

## Files (iroh-blobs)

| Контекст | Назначение | Крейт | Статус |
|----------|-----------|-------|--------|
| `aira/file/key/v2` | Per-file ключ из состояния ratchet сессии (вход: секрет сессии ‖ `file_id`); blob iroh-blobs = шифротекст, `FileStart.hash` — от шифротекста (spec §6.2; решение владельца A12). Сейчас blob идёт открытым содержимым под классическим TLS iroh | aira-core/ratchet → aira-net/blobs | план (M19a) |

## Device Management (Multidevice)

| Контекст | Назначение | Крейт | Статус |
|----------|-----------|-------|--------|
| `aira/device/id` | Device ID derivation (per-index), `derive_device_id` | aira-core/device | код |
| `aira/device/sync-key` | Device-to-device sync encryption key | aira-core/device | код |
| `aira/device/link-code` | One-time linking code material | aira-core/device | код |
| `aira/device/id-from-code` | Device ID из link-кода при `LinkDevice` | **aira-daemon/handler.rs:200** — единственный `derive_key` вне aira-core (нарушение правила «KDF только в core») | код; M19a — перенести в aira-core; в мультидевайсе v2 (M26) заменяется `derive_device_id` (`aira/device/id` + index) |

## Group Sender Keys

| Контекст | Назначение | Крейт | Статус |
|----------|-----------|-------|--------|
| `aira/group/chain-advance` | Group sender key chain advancement | aira-core/group | код |
| `aira/group/message-key` | Per-message group encryption key | aira-core/group | код |
| `aira/group/sender-sign` | Ed25519 signing key per sender key — подпись групповых конвертов (решение C2: Ed25519 per sender key + AAD, PQ-вариант позже). Group AEAD: AAD = `group_id ‖ sender_id ‖ counter`, nonce = `derive_nonce(msg_key, counter)` локально. **Имя предложено** — зафиксировать в M25 | aira-core/group | план (M25) |

## Relay (mailbox)

| Контекст | Назначение | Крейт | Статус |
|----------|-----------|-------|--------|
| `aira/relay/mailbox/v1` | Pairwise mailbox ID (одна коробка на пару, без направления) | aira-net/relay | код; **удаляется (M21)** вместе с `aira-net/src/relay.rs` и ALPN `aira/1/relay`, без совместимости (решение A2) |
| `aira/relay/mailbox/v2/<dir>` | Mailbox ID по направлению из shared secret PQXDH; `dir` = `A→B` / `B→A` по лексикографическому порядку pubkeys — две коробки на пару (решение A1; spec §6.3b, §6.5) | aira-core → aira-relay | план (M21) |
| `aira/relay/owner/v2/<dir>` | Seed Ed25519 owner-ключа коробки направления (`Register` / `Retrieve` / `Ack` / `Delete`); relay видит только pk | aira-core | план (M21) |
| `aira/relay/sender/v2/<dir>` | Seed Ed25519 sender-ключа коробки направления (`Deposit`, в т.ч. через onion-хоп); relay видит только pk | aira-core | план (M21) |
| `aira/relay/intro/v2` | ID intro-коробки по `pseudonym_pk` получателя — первый контакт, только `ContactRequest` с PoW ≥ 20 бит | aira-core → aira-relay | план (M21) |
| `aira/relay/envelope-id/v2` | Домен BLAKE3-хэша заголовка конверта (`sender ‖ counter ‖ nonce`) — `envelope_id` для дедупа N-of-2 при `Retrieve` с нескольких хостов. Не секрет и не ключ; в таблице для уникальности домена | aira-core/dedup | план (M21) |

## Anti-abuse

| Контекст | Назначение | Крейт | Статус |
|----------|-----------|-------|--------|
| `aira/contact-stamp/v1` | Hashcash-штамп `BLAKE3(ctx ‖ pseudonym_pk ‖ epoch ‖ bits ‖ nonce)` с ведущими нулями — tier для незнакомцев (spec §11B.1, §5.5.13); epoch = неделя, per-pseudonym, ключ и seed не меняет (решение C16) | aira-core/spam | план (M22) |

## Aira Onion (hop, spec §5.5)

| Контекст | Назначение | Крейт | Статус |
|----------|-----------|-------|--------|
| `aira/hop/key/v1` | `k_hop` из shared secret `HopSetup` (hybrid KEM X25519 + ML-KEM-768, `kem.rs::hybrid_encaps`), раз в сутки на хоп | aira-onion | план (M24b) |
| `aira/hop/fwd/v1` | Подключ прямого направления: AEAD слоя ячейки + keystream payload (nonce = counter, AAD = позиция слоя) | aira-onion | план (M24b) |
| `aira/hop/back/v1` | Подключ обратного направления — ответные ячейки по обратному состоянию (30 с) | aira-onion | план (M24b) |
| `aira/hop/surb/v1` | Ключи одноразовых SURB (`Wake`, cover-петли `Drop`) | aira-onion | план (M24b) |
| `aira/hop/pow/v1` | Привязка PoW `HopSetup`: над `hop_id ‖ key_id ‖ BLAKE3(kem) ‖ slot` (slot = 10-мин окно) | aira-onion | план (M24b) |

## Bridges (spec §11A, M24c)

| Контекст | Назначение | Крейт | Статус |
|----------|-----------|-------|--------|
| `aira/bridge/obfs/v1` | `k_obfs` из PSK моста — AEAD каждой QUIC-датаграммы в `CustomTransport` (`nonce ‖ padding_len ‖ datagram`); PSK из `BridgeOffer` / ссылки | aira-net/bridge | план (M24c) |

## Pseudonym Keys (Unlinkable Identity, BIP-32 style)

> Per-context pseudonym keypairs (§12.6). Counter — монотонный u32 (hardened
> derivation). Mapping counter→context хранится в storage. Counter не содержит
> group_id/contact_id — при компрометации seed перебор невозможен.
>
> **Раскладка счётчика (план, до M19b; аудит §8.5 D3):** `pseudonym_counter = device_index << 28 | local`.
> Сейчас счётчик per-БД (`storage/pseudonyms.rs`): два устройства одного seed получают одинаковые контексты
> `aira/pseudonym/<n>/*` — нарушение Key Isolation. Счётчик входит в backup v2 (после restore не сбрасывается).

| Контекст | Назначение | Крейт | Статус |
|----------|-----------|-------|--------|
| `aira/pseudonym/<counter>/signing` | Per-context ML-DSA-65 signing key | aira-core/seed | код |
| `aira/pseudonym/<counter>/x25519` | Per-context X25519 DH key | aira-core/seed | код |
| `aira/pseudonym/<counter>/mlkem` | Per-context ML-KEM-768 KEM key (input to kem_keygen) | aira-core/seed | код |

## Transport Layer (DPI Resistance) — удаляется

> Решение владельца 24.09.2026 (A13): `aira-net/src/transport/*` удаляется из `main` в M18 вместе с
> фичами `obfs4/mimicry/cdn/reality/tor` и optional-зависимостями. Контексты формально изолированы, но
> ничего не защищали: «obfs» выводил ключ из nonce, идущих по проводу открыто; REALITY — статический
> session key на PSK (two-time pad как слой) и открытый 8-байтный префикс (net-audit §8). Обфускация
> возвращается как `aira/bridge/obfs/v1` (M24c).

| Контекст | Назначение | Крейт | Статус |
|----------|-----------|-------|--------|
| `aira/obfs/session/0` | Obfuscation session key (XOR keystream) | aira-net/transport | код; **удаляется (M18)** |
| `aira/reality/sid/0` | REALITY short ID derivation from PSK | aira-net/transport | код; **удаляется (M18)** |
| `aira/reality/auth/0` | REALITY authentication MAC key derivation | aira-net/transport | код; **удаляется (M18)** |
| `aira/reality/session/0` | REALITY session key derivation | aira-net/transport | код; **удаляется (M18)** |

## Исключения: не-KDF ключи (не из seed)

Следующие ключи **намеренно не выводятся из master seed** и не восстанавливаются из фразы — это
осознанное исключение из правила «всё из seed», а не пропуск в таблице:

| Ключ | Источник | Почему не из seed | Крейт | Статус |
|------|----------|-------------------|-------|--------|
| Хоп-идентичность (`hop_id` — iroh `SecretKey` второго `Endpoint`) | локальный CSPRNG при установке; хранится в settings; ротация по кнопке | `NodeRecord` хопа содержит способ дойти до ноды (relay URL / IP). Будь хоп-ключ выведен из seed или связан с чат-ключом, любой контакт нашёл бы IP пользователя в peer exchange — рушится «скрыть IP от собеседника» (spec §5.5.3; решение C5) | aira-daemon / aira-net/hop | план (M24b) |
| KEM-ключи хопа (`hop_x25519`, `hop_mlkem_ek`) | локальный CSPRNG, ротация раз в неделю | та же причина; forward secrecy ключей хопа независимо от seed | aira-onion | план (M24b) |
| Ключ роли `relay` в клиенте (self-signed TLS встроенного iroh-relay) | локальный CSPRNG, отдельный процесс `aira-relay --mode transport` | relay идентифицируется URL + pin, не identity пользователя (spec §5.1.1) | aira-relay | план (M24a.2) |
| Ключ выдачи токенов допуска (anchor, Ed25519) и ключ подписи каталога (ML-DSA-65; 2-of-3 к 1.0) | офлайн у владельца проекта | инфраструктурные, не пользовательские (spec §5.1.1, §5.3; решения F1, F6) | aira-relay --catalog | план (M22 / M24a.1) |
| `aira-gui/password-vault/v1` | пароль пользователя, Argon2id | см. раздел ниже | aira-gui | код |

## GUI Password Vault (опциональная защита ключа паролем)

> Не использует BLAKE3 KDF — этот контекст изолирован от всех остальных и
> выводит ключ из **пароля пользователя** через Argon2id. Это единственная
> точка в кодовой базе, где seed/vault key зависит не от master seed, а от
> пользовательского ввода. Поэтому важно явно документировать контекст,
> чтобы не смешать его с другими.

| Контекст | Назначение | Крейт | KDF |
|----------|-----------|-------|-----|
| `aira-gui/password-vault/v1` | Шифрование seed phrase пользовательским паролем | aira-gui/password_vault | Argon2id m=128MB, t=3, p=1 |

**Формат:** `SeedVault { version: u8 = 1, salt: [u8; 16], nonce: [u8; 12], ciphertext: Vec<u8> }`, сериализация через postcard, AEAD — ChaCha20-Poly1305. Salt и nonce случайные per-vault. Ключ `derive_key(password, salt)` — 32 байта. Версия `1` позволяет миграцию при смене параметров.

**Rationale:** m=128MB (vs m=256MB у `aira-core/seed.rs`) — vault unlock вызывается на каждом старте GUI, нужна интерактивная задержка ~1 сек, а не 3. Это всё ещё GPU-устойчиво.
