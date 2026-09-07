# Security-compliance аудит workspace (2026-09-07, HEAD d001981, v0.3.5)

> Фаза 3, задание A. Проверка кода восьми крейтов (`aira-core`, `aira-storage`, `aira-net`, `aira-daemon`,
> `aira-cli`, `aira-gui`, `aira-ffi`, `aira-bot`) по чеклисту `.claude/rules/security.md` и `docs/KEY_CONTEXTS.md`.
> Не дублирует `core-audit.md`, `daemon-storage-audit.md`, `clients-audit.md` и `release-audit-2026-09.md`
> §2.5 / §4.1a — на уже известные находки даются ссылки, ниже только новое или уточнённое.
> Только чтение (Read/Grep/Glob, `cat`/`sed`), cargo не запускался. Все строки — по HEAD d001981.

## 0. Резюме

Формальный чеклист `rules/security.md` выполняется **в ядре**: `#![deny(unsafe_code)]` стоит в `aira-core` и
`aira-storage`, в production-путях всего workspace нет ни одного `unwrap()`/`panic!`/`unreachable!`/`todo!`
(девять `expect()` — все на константах и инвариантах инициализации, не на внешних данных), все долгоживущие
ключи (seed, X25519, ML-KEM dk, ML-DSA sk, root/chain-ключи, storage-ключ, obfs/reality-ключи) обёрнуты в
`Zeroizing`/`ZeroizeOnDrop`, все 30 KDF-контекстов из `KEY_CONTEXTS.md` найдены в коде и не пересекаются
(единственное расхождение — `aira/device/id-from-code`, уже в `core-audit.md`), все сетевые/IPC-рамки
проверяют длину **до** аллокации (256 KB кадр, 1 MiB IPC, 64 KB envelope, u16-кадры транспортов), RNG везде
`rand::thread_rng()` (OsRng-seeded), `subtle::ct_eq` используется там, где сравнивается MAC.

За пределами ядра дисциплина держится на людях, а не на линтерах: `deny(clippy::unwrap_used)` есть только в
`aira-core`; `unsafe` в `aira-gui` (4 из 6 мест — без `// SAFETY:`) применяется для зануления `String`, хотя
`zeroize` уже умеет это безопасно; seed-фраза и BIP-39-энтропия проходят через plain `String`/`Vec<u8>`
в `aira-core::seed`, `aira-daemon/main.rs` и `aira-ffi` (0 использований `zeroize` при объявленной
зависимости); `RatchetSnapshot`, `SenderKeyState`/`SenderKeyReceiver`, `SyncItem`, `GroupControl` выводят
`derive(Debug)` с секретами внутри; в workspace **нет ни одного** вызова `set_permissions`/`mode()` —
БД, backup-файл, каталог downloads и Unix-сокет создаются с правами по umask.

Две находки выходят за рамки «стиля» и требуют плана: **(S1, HIGH)** входящие `GroupControl`
(`aira-daemon/src/handler.rs:688-819`) не проверяют авторизацию отправителя — любой участник (а для
`CreateGroup` — любой контакт) может добавить/удалить членов и **перезаписать sender-chain-ключи других
участников** в нашем хранилище, что позволяет подделывать групповые сообщения от их имени; короткий ключ
молча дополняется нулями. **(S2, HIGH внутри своей threat-model)** транспорт REALITY (`feature = "reality"`,
не в default, не подключён): статичный сессионный ключ на всех сессиях (повтор keystream), replay
auth-кадра в окне 60 с без кэша nonce, неаутентифицированный ответ сервера и `short_id` в открытом виде до
TLS — активный пробер, повторив перехваченный клиентский пролог, отличает Aira-сервер от fallback-сайта,
т.е. ломает ту самую защиту от active probing, ради которой REALITY существует.

Новых безусловных релиз-блокеров не найдено; S1 становится блокером, если групповые чаты входят в 1.0
(решение — задание E). Остальное распределено по M19a/M19/M19b/M21/M22/M23 (§9).

### Чеклист `rules/security.md` → статус

| Пункт чеклиста | Статус | Где |
|---|---|---|
| Нет пересечений KDF-контекстов, KEY_CONTEXTS.md актуален | ⚠️ 30/30 контекстов совпадают; 1 недокументированный (`aira/device/id-from-code`, известно), `aira/reality/session/0` даёт статичный ключ на все сессии (S2) | §6 |
| Нет `unsafe` без `// SAFETY:` в aira-core/aira-storage | ✅ в core/storage `unsafe` нет (`deny(unsafe_code)`); ⚠️ в aira-gui 4 `unsafe` без SAFETY (S3) | §1 |
| Все секреты через `Zeroizing<_>` | ⚠️ ключи — да; seed-фраза/энтропия, message keys групп, промежуточные буферы — нет (S4, S6, S15) | §3 |
| Входящие пакеты проверяются по размеру (64 KB envelope) | ✅ все точки входа с сети/IPC ограничены до аллокации; ⚠️ локальные входы (invite-URI, backup import) без лимита (S13) | §4 |
| Нет `unwrap()` в production-путях | ✅ 0 `unwrap`; 9 `expect` на константах; ⚠️ линтер `unwrap_used` только в aira-core (S10) | §2 |
| MAC/хэш-сравнения через constant-time | ✅ единственный MAC (reality) — `subtle`; link-code `==` известно (core-audit) | §5 |
| Fuzz targets обновлены при изменении парсинга | ❌ 2 таргета на 15+ парсеров внешних данных (известно частично, полный список §8) | §8 |

### Сводная таблица находок

| # | Sev | Находка | Где | Milestone |
|---|---|---|---|---|
| S1 | HIGH | Входящие `GroupControl` без авторизации отправителя; перезапись чужих sender-ключей; нулевое дополнение ключа | `aira-daemon/src/handler.rs:688-819` | M19 (Phase B, до wiring групп) |
| S2 | HIGH | REALITY: статичный session key, replay auth 60 с, ответ сервера без MAC, short_id в открытом виде, AcceptAnyCert | `aira-net/src/transport/reality.rs:336-346, 385-396, 505-516, 541-575, 588-590, 707-715` | M22 / исключить из релиза |
| S3 | MEDIUM | `unsafe` без `// SAFETY:` в aira-gui (4), заменимо на `String::zeroize()` (все 5 мест gui) | `aira-gui/src/onboarding.rs:103`, `state.rs:78,82,86`, `views/settings.rs:462-468`, `views/unlock.rs:112-113` | M19b |
| S4 | MEDIUM | Seed-фраза и BIP-39-энтропия без `Zeroizing` в core/daemon/ffi/gui | `aira-core/src/seed.rs:123-141,190-223,262-267`, `aira-daemon/src/main.rs:85-98`, `aira-ffi/src/runtime.rs:56-66`, `aira-gui/src/keychain.rs:170-177` | M19a + M19b |
| S5 | MEDIUM | `derive(Debug)` на типах с секретами (RatchetSnapshot, SenderKeyState/Receiver, SyncItem, GroupControl) | `aira-core/src/ratchet.rs:125`, `group.rs:54,128`, `sync.rs:30-80`, `group_proto.rs:73-120` | M19a |
| S6 | MEDIUM | group.rs: message keys и skipped keys plain, нет `Drop` с zeroize, `Clone` на состоянии | `aira-core/src/group.rs:128-137, 212-216` | M19a |
| S7 | MEDIUM | `let _ = delete_account(..)`/`clear_all()`/`delete_seed_phrase()` — seed может остаться в OS keychain после reset/включения пароля | `aira-gui/src/keychain.rs:110,134`, `ipc.rs:755,796` | M19b |
| S8 | MEDIUM | Нулевой hardening прав: `~/.aira`, `aira.redb`, `downloads`, backup-файл, Unix-сокет — по umask | `aira-daemon/src/main.rs:107-110,130-131`, `ipc.rs:76-83`, `aira-storage/src/backup.rs:114` | M19b (расширить п.3) |
| S9 | MEDIUM | obfs/mimicry: `chunk_len as u16` при 65 536 байт → длина 0 → разрыв/десинхронизация; partial header теряет байты | `aira-net/src/transport/obfs.rs:273-276,327-332`, `mimicry.rs:417-422` | M19 Phase B (если транспорты подключаются) / M22 |
| S10 | LOW | Линт-гэп: `deny(clippy::unwrap_used)` только в core; нет `[workspace.lints]` | `crates/*/src/lib.rs`, `Cargo.toml` | M23 |
| S11 | LOW | `let _ =` на security/consistency-значимых `Result` (auto-accept invite, enqueue, GC TTL в ffi) | `aira-daemon/src/handler.rs:470,739,909`, `aira-ffi/src/runtime.rs:85,108,115` | M19 / M19b |
| S12 | LOW | relay: неограниченное число mailbox'ов, `Ack.counters` без cap, `Retrieve` отдаёт всё одним ответом (> 256 KB кадра) | `aira-net/src/relay.rs:231,265-297` | M21 |
| S13 | LOW | invite-URI: без лимита длины, base64url принимает неканонические хвосты | `aira-net/src/discovery.rs:53-61,185-211` | M19b |
| S14 | LOW | `now_secs + ttl` без saturating (ttl из IPC/FFI) | `aira-storage/src/messages.rs:123` | M19 |
| S15 | LOW | Промежуточные буферы с производными ключами не зануляются | `aira-core/src/device.rs:186-190,214-216` | M19a |
| S16 | LOW | `std::mem::forget(tag)` — утечка temp-tags iroh-blobs, блобы не собираются | `aira-net/src/blobs.rs:86,103` | M19 Phase B |
| S17 | LOW | 9 `expect()` на константах/инвариантах — заменить на const/let-else | см. §2 | M23 |
| S18 | LOW | `String::from_utf8_unchecked` — единственный `unsafe` в aira-net, заменим на safe | `aira-net/src/discovery.rs:181-182` | M19b |
| S19 | INFO | Логи: только `debug!(%remote_id)`; секреты не логируются | `aira-net/src/protocol.rs:56,132` | — |
| S20 | LOW | KEY_CONTEXTS.md: добавить `id-from-code` (известно), пометить `reality/session/0` как «per-PSK, не per-session», подготовить `relay/mailbox/v2` | `docs/KEY_CONTEXTS.md` | M19a / M21 |

## 1. `unsafe` и `#![deny(unsafe_code)]`

**Линты.** `#![deny(unsafe_code)]` — crate-level в `crates/aira-core/src/lib.rs:19` и
`crates/aira-storage/src/lib.rs:19` (этого достаточно; `aira-core/src/i18n.rs:10` дублирует на уровне модуля —
безвредно). `allow(unsafe_code)` и `forbid` нигде нет. В остальных шести крейтах запрета нет.

**Все `unsafe` в workspace (6 мест, все вне core/storage):**

| Файл:строка | Код | `// SAFETY:` | Корректность | Замена |
|---|---|---|---|---|
| `aira-gui/src/onboarding.rs:103` | `for b in unsafe { self.import_input.as_bytes_mut() } { *b = 0; }` | ❌ нет | 0x00 — валидный UTF-8, корректно | `use zeroize::Zeroize; self.import_input.zeroize();` |
| `aira-gui/src/state.rs:78` | то же для `password_input` | ❌ нет | корректно | `zeroize()` |
| `aira-gui/src/state.rs:82` | то же для `confirm_input` | ❌ нет | корректно | `zeroize()` |
| `aira-gui/src/state.rs:86` | то же для `old_password_input` | ❌ нет | корректно | `zeroize()` |
| `aira-gui/src/views/settings.rs:462-468` | `fn scrub(s: &mut String)` | ✅ «overwriting valid UTF-8 with 0x00 produces valid ASCII» | корректно | `zeroize()` |
| `aira-gui/src/views/unlock.rs:112-113` | аналогично | ✅ | корректно | `zeroize()` |
| `aira-net/src/discovery.rs:181-182` | `// SAFETY: B64 table contains only ASCII bytes` + `unsafe { String::from_utf8_unchecked(out) }` | ✅ | корректно (таблица ASCII) | собирать `String` через `push(char)` или `String::from_utf8(out).map_err(..)?` |

**S3 (MEDIUM, M19b).** Четыре `unsafe` без `// SAFETY:` в `aira-gui` — прямое нарушение
`rules/security.md` §2 («В других крейтах — только с `// SAFETY:`»). Последствие функционально нулевое
(код корректен), но: (а) прецедент ручного `as_bytes_mut()` под `String` — при будущей замене 0x00 на
случайные байты станет UB; (б) `zeroize` 1.x реализует `Zeroize for String` (обнуляет весь capacity, затем
`clear()`), т.е. цель достигается без `unsafe`. Исправление: во всех пяти местах gui — `s.zeroize()`;
после этого и S18 — `#![forbid(unsafe_code)]` во всех крейтах, кроме тех, где unsafe реально нужен
(на сегодня — ни одного), либо `[workspace.lints.rust] unsafe_code = "deny"` (M23, S10).
Заодно спека `spec/01-overview.md:18` («100% safe Rust, `unsafe` только в явно аргументированных …»)
станет правдой буквально.

**S18 (LOW, M19b).** `aira-net/src/discovery.rs:181-182` — единственный `unsafe` в сетевом крейте, ради
экономии одной проверки при кодировании invite-ссылки. Заменить на safe-вариант (см. таблицу).

## 2. `unwrap()/expect()/panic!/unreachable!/[]` в non-test путях

Метод: `awk` по каждому файлу до первого `#[cfg(test)]` (в workspace `cfg(test)` везде стоит в конце файла;
исключение `aira-core/src/crypto/awslc.rs:21` — `cfg(test)`-константа, не модуль), затем ручная проверка
каждого совпадения. `unimplemented!`, `todo!`, `unreachable!`, `debug_assert` — **0** в workspace.
`unwrap()` в production-путях — **0** во всех восьми крейтах (для daemon/storage это уже отмечено в
`daemon-storage-audit.md` [info]).

| Крейт | `expect()` в prod | Где | Оценка |
|---|---|---|---|
| aira-core | 1 | `i18n.rs:179` `.expect("en is valid")` — парсинг константной локали | безопасно (константа) |
| aira-net | 3 | `ratelimit.rs:29,34` `NonZeroU32::new(100/5).expect("nonzero")`; `transport/tor.rs:74` `.expect("default socks5 addr is valid")` | константы; заменить на `NonZeroU32::new(..).unwrap()` в `const` или `SocketAddr::from(([127,0,0,1], 9050))` |
| aira-gui | 5 | `ipc.rs:651` `self.seed.as_ref().expect("seed set above")`; `main.rs:68` (tracing directive), `:116` (tokio runtime), `:119` (thread spawn); `tray.rs:81` `.expect("valid 16x16 icon")` | инварианты инициализации; `ipc.rs:651` — переписать через `let Some(seed) = .. else { return }` |
| aira-daemon, aira-storage, aira-ffi, aira-bot, aira-cli | 0 | — | ✅ |
| compat_tests.rs | n/a | за `feature = "compat-test"` | тестовый код |

**По границам, которые задание просило проверить отдельно:**

- **daemon IPC** (`aira-daemon/src/ipc.rs`, `handler.rs`, `client.rs`): паник нет; все ошибки → `DaemonResponse::Error(String)`.
  Индексация — только после `min()`/проверок длины (`handler.rs:711-712,766-767,811-813`; `cli/main.rs:136-138`
  `payload[..payload.len().min(100)]`).
- **net парсинг** (`connection.rs:59-71`, `relay.rs`, `discovery.rs`, `transport/*`): паник нет; индексы фиксированных
  массивов (`reality.rs:511 resp[0]`, `obfs.rs:278 filled[pos], filled[pos+1]` после `pos + 2 > filled.len()` проверки).
- **storage redb** (`aira-storage/src/*.rs`): только `?`, `SystemTime::now().duration_since(..).unwrap_or_default()`.
- **ffi границы** (`aira-ffi/src/runtime.rs:56-404`, `types.rs`, `callbacks.rs`): паник нет; все `Vec<u8>` → `[u8;32]`
  через `try_into().map_err(..)` (`:393-404`); ошибки → `FfiError` (`uniffi::Error`). Поведение uniffi 0.28 при панике
  внутри экспортированной функции (catch_unwind → `InternalException`) по сгенерированному коду **не проверено** (§10).

**Арифметика и `as`-касты на недоверенных данных** (проверены все `+`/`*`/`as` рядом с сетевыми/IPC значениями):

- **S14 (LOW, M19).** `aira-storage/src/messages.rs:123` `msg.expires_at = Some(now_secs + ttl)` — `ttl` приходит из
  `DaemonRequest::SetTtl { ttl_secs: Option<u64> }` (IPC) и `AiraRuntime::set_ttl` (Kotlin). `u64::MAX` → паника
  в debug, wrap в release → `expires_at` маленький → сообщение удаляется первым же TTL-GC. Исправление:
  `now_secs.saturating_add(ttl)` + верхняя граница TTL (например, ≤ 365 дней) на границе IPC.
- **S9 (MEDIUM, см. §7.3).** `aira-net/src/transport/obfs.rs:332` `(chunk_len as u16)` и `mimicry.rs:422`
  `chunk_len as u16` при `chunk_len = buf.len().min(MAX_FRAME_PAYLOAD)` = 65 536 (`MAX_FRAME_PAYLOAD: usize = 65_536`,
  `obfs.rs:34`, `mimicry.rs:27`) → заголовок длины **0**. `reality.rs:840` этой ошибки не имеет (`.min(usize::from(u16::MAX))`).
- Безопасно: `seed.rs:204 idx as u16` (≤ 2047), `connection.rs:66 len as usize` после `len > MAX_FRAME_SIZE`,
  `relay.rs:244 total_bytes + env_size` (обе величины ограничены), `pseudonyms.rs:27 current + 1` (u32, локально),
  `spam.rs:165 now_secs + RATE_BAN_DURATION_SECS`, `handler.rs:360 member_pubkeys.len() + 1`.

**S10 (LOW, M23).** `#![deny(clippy::unwrap_used)]` есть только в `aira-core/src/lib.rs:25`; остальные крейты — лишь
`cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, …))` без `deny` в prod. Нулевое число `unwrap` держится
дисциплиной. `[workspace.lints]` в `Cargo.toml` отсутствует (в `[profile.release]` — `lto`, `strip`, без `panic`, что для
uniffi правильно). Рекомендация: `[workspace.lints.clippy] unwrap_used = "deny", expect_used = "warn", panic = "deny",
indexing_slicing = "warn", unimplemented = "deny", todo = "deny"` + `[lints] workspace = true` в каждом крейте, с
`#![cfg_attr(test, allow(...))]`. Делать **после** отката незакоммиченного diff владельца в `Cargo.toml` (M18), чтобы
не смешать правки.

**S17 (LOW, M23).** Девять `expect()` выше перевести на `const` (`NonZeroU32::new(100).unwrap()` допустим в `const`
с `#[allow]`), `SocketAddr::from(..)` и `let-else`; тогда `expect_used = "deny"` можно включить целиком.

## 3. Zeroize секретов

### 3.1 Таблица: секрет → тип → статус

| Секрет | Где живёт | Обёртка | Статус |
|---|---|---|---|
| Master seed (32 B после Argon2id) | `aira-core/src/seed.rs:75-76` `MasterSeed(Zeroizing<[u8;32]>)` `#[derive(ZeroizeOnDrop)]`, без `Debug` | ✅ | ✅ |
| BIP-39 фраза (String) | `seed.rs:123-128` `generate() -> (String, Self)`, `:138-141` `generate_phrase_only() -> String`; `aira-daemon/src/main.rs:85-98` `seed_phrase: String` + `phrase = seed_phrase.clone()`; `aira-ffi/src/runtime.rs:56` `seed_phrase: String`; `aira-gui/src/keychain.rs:170-177` `try_get -> Option<String>` | ❌ plain `String` | **S4** |
| BIP-39 энтропия (32 B, «пред-Argon2» корень) | `seed.rs:190-223` `bip39_decode -> Vec<u8>` (`Ok(entropy.to_vec())`), `bits: [u8;33]` `:208`, `indices: Vec<u16>` `:197`; `:262-267` `rand_entropy() -> [u8;32]` | ❌ | **S4** |
| Argon2 промежуточные | `seed.rs:100-113` `from_phrase_with_platform` (выход в `Zeroizing`) | ✅ выход | ⚠️ вход — см. выше |
| Производные ключи `derive()` | `seed.rs:148-150` `-> Zeroizing<[u8;32]>`; `PseudonymSeeds` `:288-296` `ZeroizeOnDrop` | ✅ | ✅ |
| X25519 static/ephemeral | `x25519-dalek` (`StaticSecret`/`EphemeralSecret`, default feature `zeroize`); `RatchetSnapshot::send_dh_secret_bytes` зануляется в `Drop` (`ratchet.rs:148-163`) | ✅ | ✅ (Drop сессии — известно core-audit «Drop RatchetSession не затирает ML-KEM dk и X25519 secret явно») |
| ML-KEM dk, ML-DSA sk | trait `CryptoProvider` требует `SigningKey: ZeroizeOnDrop`, `KemDecapsKey: ZeroizeOnDrop` (`crypto/mod.rs:30,32`); `ml-kem`/`ml-dsa` с feature `zeroize` (root `Cargo.toml:28-29` — **незакоммиченный diff владельца, проверить после отката в M18**); `awslc.rs:34-47,57-71` — `Zeroizing` | ✅ | ✅ (условно — M18) |
| Hybrid shared secret | `kem.rs:32,117-133` `Zeroizing`, `kdf_input` тоже `Zeroizing` | ✅ | ✅ |
| Session keys | `handshake.rs:40-49` `SessionKeys` — поля `Zeroizing`, без `Debug`; `:297-314` | ✅ | ✅ |
| Root/chain keys ratchet | `RatchetSession` — `Zeroizing`/`Drop` (`ratchet.rs:563-575`); skipped message keys `SkippedKeys = HashMap<([u8;32],u64),[u8;32]>` (`:116`) plain, но зануляются в `Drop` (`:570-573`) | ✅ | ✅ |
| Message keys ratchet | `chain_ratchet -> ([u8;32],[u8;32])` (`ratchet.rs:57-61`) — plain локальные, живут до конца функции | ⚠️ | LOW (обернуть в `Zeroizing`, консистентность) |
| Group chain/message keys | `group.rs:54-58,128-132` `chain_key: Zeroizing`; **но** `skipped_keys: HashMap<u64,([u8;32],[u8;12])>` (`:136`) plain, `chain_ratchet` (`:212-216`) plain, у `SenderKeyReceiver`/`SenderKeyState` нет `Drop`, есть `Clone` | ❌ | **S6** |
| Storage key | `aira-storage/src/lib.rs:125-128` `storage_key: Zeroizing<[u8;32]>`, без `Debug`; `key() -> &[u8;32]` (`:171`) | ✅ | ✅ |
| Пароль vault (GUI) | `password_vault.rs:108-135,147-167` — plaintext результата `Zeroizing`; поля ввода — `String` с ручным занулением (S3) | ✅/⚠️ | S3 |
| Link-code | `device.rs:209-225` — `input: [u8;40]` с `code_material` (производный ключ) не зануляется; `derive_device_id` `context_material` (`:186-190`) — то же | ❌ | **S15** (LOW) |
| Obfs session key | `obfs.rs:150-157` ручной `Zeroize` | ✅ | ✅ |
| REALITY PSK / session key | `reality.rs:98-107` `psk: Zeroizing<[u8;32]>` + ручной `Debug` `[REDACTED]`; `:588-590` `Zeroizing` | ✅ | ✅ (но см. S2) |
| Relay-токены | не существуют (auth отсутствует, M21) | n/a | — |
| Backup plaintext | `backup.rs:128-150` import: расшифрованный блоб — plain `Vec<u8>` до `postcard` | ⚠️ | LOW, учесть в backup v2 (M19 Phase A) |

### 3.2 S4 (MEDIUM, M19a + M19b) — seed-фраза и энтропия без Zeroizing

Доказательства:

- `aira-core/src/seed.rs:123-128`:
  `pub fn generate() -> Result<(String, Self), AiraError> { let entropy: [u8; 32] = rand_entropy(); let phrase = bip39_encode(&entropy); … Ok((phrase, seed)) }`
  — `entropy` (root-секрет до Argon2) и `phrase` — plain, освобождаются без затирания.
- `seed.rs:190-223` `fn bip39_decode(phrase: &str) -> Result<Vec<u8>, AiraError>` … `Ok(entropy.to_vec())` —
  копия энтропии в heap без `Zeroizing`; `bits: [u8;33]` (`:208`) и `indices` (`:197`) — на стеке/heap без затирания.
- `seed.rs:262-267` `fn rand_entropy() -> [u8; 32]` — возвращает по значению, копии на стеке.
- `aira-daemon/src/main.rs:85-98`: `let seed_phrase = std::env::var("AIRA_SEED")…?;` … `let phrase = seed_phrase.clone();
  tokio::task::spawn_blocking(move || … from_phrase(&phrase))` — две копии фразы (`seed_phrase` живёт до конца `main`),
  ни одна не зануляется; `zeroize` в daemon вне тестов не используется (grep: 0).
- `aira-ffi/src/runtime.rs:56` `pub fn new(data_dir: String, seed_phrase: String)` → `:65` `from_phrase(&seed_phrase)` —
  `seed_phrase` дропается как обычная `String`; в `aira-ffi` `zeroize` объявлен в `Cargo.toml`, использований 0.
  Плюс на стороне Kotlin `String` иммутабельна и живёт до GC — затереть её невозможно в принципе.
- `aira-gui/src/keychain.rs:170-177` `fn try_get(account) -> Result<Option<String>, _>` — фраза из OS keychain
  возвращается plain `String`, оборачивается в `Zeroizing` только вызывающим (`:74-100`); промежуточная копия не затирается.

Последствие: фраза/энтропия остаются в освобождённой памяти процесса (core dump, swap, `/proc/<pid>/mem` при том же uid,
memory-dump на Android) — при том, что `MasterSeed` сам аккуратно `ZeroizeOnDrop`. Это ровно то, от чего правило §3
`rules/security.md` и защищает.

Исправление (M19a, API core): `generate() -> Result<(Zeroizing<String>, Self), _>`, `generate_phrase_only() -> Zeroizing<String>`,
`bip39_decode(..) -> Result<Zeroizing<[u8;32]>, _>` с `Zeroizing`-обёртками на `bits`/`indices`, `rand_entropy() -> Zeroizing<[u8;32]>`,
`bip39_encode(&Zeroizing<[u8;32]>)`. Затем (M19b): daemon — `Zeroizing<String>` + `std::env::remove_var("AIRA_SEED")`
сразу после чтения (до полного отказа от env-транспорта, который уже запланирован в M19b п.2); ffi —
`let seed_phrase = Zeroizing::new(seed_phrase);` первой строкой `new()` и **перевести параметр на `Vec<u8>`/`ByteArray`**
(Kotlin `CharArray`/`ByteArray` можно затереть, `String` — нет), провижининг через Android Keystore-обёртку;
gui — `try_get -> Option<Zeroizing<String>>`. Спека M19b п.5 уже говорит «seed_phrase через Zeroizing — сейчас 0 вхождений
zeroize в aira-ffi» — дополнить формой параметра (bytes) и core-API.

### 3.3 S5 (MEDIUM, M19a) — `derive(Debug)` на типах с секретами

| Тип | Строка | Что попадёт в `{:?}` |
|---|---|---|
| `RatchetSnapshot` | `aira-core/src/ratchet.rs:125` `#[derive(Debug, Serialize, Deserialize)]` | `root_key`, `send_chain_key`, `send_dh_secret_bytes`, `recv_chain_key`, `pq_dk_bytes`, `skipped_entries` — **вся сессия** |
| `SenderKeyState` | `group.rs:54` `#[derive(Debug, Clone, Serialize, Deserialize)]` | `chain_key` (Zeroizing печатает содержимое) |
| `SenderKeyReceiver` | `group.rs:128` то же | `chain_key`, `skipped_keys` (message keys) |
| `SyncItem::RatchetState { snapshot_bytes }` | `sync.rs:30-80` | сериализованный snapshot |
| `GroupControl::{CreateGroup, AddMember, SenderKeyUpdate}` | `group_proto.rs:73-120` | sender chain keys (`creator_sender_key`, `sender_keys`, `new_key`) |
| `DaemonRequest::LinkDevice { code }` | `aira-daemon/src/types.rs:11` | 6-значный код (5 мин) — LOW |

Сегодня это **латентный** риск: grep по `{:?}`/`?var` в production-путях находит только `debug!(%remote_id)` (S19) и
`format!("{msg:?}")` в тесте `aira-bot/src/lib.rs:191`. Но один `tracing::debug!(?snapshot)` при отладке M19 — и ключи
сессии в логе. GUI уже показывает правильный паттерн: ручной `Debug` с `"[REDACTED]"` для `GuiCommand`
(`aira-gui/src/ipc.rs:200-236`), `OnboardingState` (`onboarding.rs:51-71`), `RealityConfig` (`reality.rs:98-107`),
`SpawnError` (`daemon_manager.rs:86-93`). Исправление: ручные `impl Debug` с редактированием секретных полей для
пяти типов выше; `SenderKeyReceiver` — убрать `Clone` или обосновать. Для `GroupControl` — `Debug` печатает длины,
не байты.

### 3.4 S6 (MEDIUM, M19a) — group.rs: message keys без zeroize

`aira-core/src/group.rs:136` `skipped_keys: std::collections::HashMap<u64, ([u8; 32], [u8; 12])>` — до `MAX_SKIP = 1000`
(`:36`) message keys plain в heap; `:212-216` `fn chain_ratchet(chain_key: &[u8; 32]) -> ([u8; 32], [u8; 32])` — plain;
у `SenderKeyReceiver`/`SenderKeyState` **нет `impl Drop`** (в отличие от `RatchetSession`, `ratchet.rs:563-575`, где
skipped keys зануляются). `derive(Clone)` (`:54,:128`) плодит копии состояния. Исправление: `skipped_keys: HashMap<u64, Zeroizing<[u8;32]>>`
(nonce хранить не нужно — он детерминирован `derive_nonce(msg_key, counter)`, `:219-227`), `chain_ratchet -> (Zeroizing, Zeroizing)`,
`impl Drop` / `#[derive(ZeroizeOnDrop)]` с `#[zeroize(skip)]` на счётчиках.

### 3.5 S7 (MEDIUM, M19b) — seed может остаться в OS keychain

`aira-gui/src/keychain.rs:107-112`:
`entry.set_password(phrase.as_str())?; let _ = delete_account(ACCOUNT_VAULT);` и `:130-136`
`entry.set_password(&encoded)?; let _ = delete_account(ACCOUNT_PLAIN);`; `load_seed` (`:74-100`) предпочитает vault.
`aira-gui/src/ipc.rs:755` `let _ = crate::keychain::clear_all();` (Reset identity из экрана пароля) и `:796`
`let _ = crate::keychain::delete_seed_phrase();` (Reset identity из main loop).

Последствия: (1) «Включить пароль» → vault записан, plain-удаление упало → **plain seed остаётся в keychain**, защита
паролем иллюзорна; (2) «Отключить пароль» → plain записан, vault-удаление упало → при следующем запуске `load_seed`
берёт **vault** со старым паролем — пользователь заблокирован старым паролем, которого «уже нет»; (3) «Reset identity»
молча не удалил seed → пользователь считает идентичность стёртой, seed лежит в keychain. Исправление: удалять
**до** записи нового и пробрасывать ошибку в UI (`GuiUpdate::KeychainUnavailable`), после reset — верифицировать
`load_seed() == None`; в keychain-тестах (сейчас `#[ignore]`) — сценарий «delete падает».
Учесть при замене keyring mock на platform features (clients-audit блокер, M19b п.1).

### 3.6 Секреты в логах / IPC / FFI

- Логи: секреты не логируются (grep `tracing::(debug|info|warn|error)!` по всем крейтам; см. S19).
- IPC (`DaemonRequest`): фраза через IPC не ходит (демон получает её из env — известно); `LinkDevice{code}` — 6 цифр;
  `ExportBackup{path}` — файл шифруется storage-ключом (`backup.rs:49-116`), т.е. привязан к seed ✅.
- GUI → IPC-bridge: `GuiCommand::CompleteOnboarding{phrase: Zeroizing<String>}` только в процессе (mpsc) ✅;
  `bootstrap` держит `self.seed: Option<Zeroizing<String>>` всё время работы для respawn демона (`ipc.rs:586,880-914`) —
  задокументированный компромисс, исчезнет вместе с env-транспортом (M19b п.2).
- FFI: `AiraRuntime::new(data_dir, seed_phrase: String)` — фраза пересекает JNI как Java `String` (S4).
  `FfiError` несёт `msg: String` из `e.to_string()` — `AiraError`/`StorageError` Display не содержат ключей (проверено по
  `thiserror`-строкам в `aira-core/src/proto.rs:206-239`, `aira-storage/src/lib.rs:84-102`).

## 4. Лимиты размеров на входе

Все точки входа, где внешние байты превращаются в структуры (`postcard::from_bytes` non-test: 14 мест) и где длина
из сети/IPC влияет на аллокацию:

| Точка входа | Лимит | До аллокации/десериализации? | Файл:строка | Статус |
|---|---|---|---|---|
| iroh-кадр (chat/handshake/file) | `MAX_FRAME_SIZE = 256*1024` | ✅ `if len > MAX_FRAME_SIZE { return Err }` до `vec![0u8; len as usize]` | `aira-net/src/connection.rs:22,59-71` | ✅ |
| Envelope (ratchet decrypt) | `MAX_ENVELOPE_SIZE` 64 KB | после десериализации `Message`, до AEAD | `aira-core/src/ratchet.rs:322-327` | ✅ (десериализацию защищает кадр 256 KB) |
| Relay deposit | `max_envelope_size` 64 KB, 100 конвертов, 10 MB/mailbox | после десериализации `RelayRequest` | `aira-net/src/relay.rs:106-116,219-228,233-246` | ✅ по envelope; ❌ нет cap на число mailbox'ов (`:231 or_insert_with(Mailbox::new)`), `Ack.counters: Vec<u64>` без cap (`:281-291`, `counters.contains` O(n·m)); `Retrieve` (`:265-279`) отдаёт до 100×64 KB = 6.4 MB одним `RelayResponse` — больше `MAX_FRAME_SIZE`, `write_framed` (`connection.rs:29-38`) вернёт ошибку → **S12** (M21) |
| IPC сервер | `MAX_IPC_MSG_SIZE` 1 MiB | ✅ до аллокации | `aira-daemon/src/ipc.rs:18-30` | ✅ |
| IPC клиент | 1 MiB | ✅ | `aira-daemon/src/client.rs:176-181` | ✅ |
| obfs-кадр | u16, `len == 0 \|\| len > 65_536` | ✅ до `Vec::with_capacity(len)` | `obfs.rs:278-288` | ✅ (но S9) |
| mimicry-кадр | u16 header (отбрасывается кусками 4096), u16 payload `> MAX_FRAME_PAYLOAD` | ✅ до `with_capacity` | `mimicry.rs:289-317,337-347` | ✅ (но S9) |
| REALITY ClientHello / auth-кадр | ≤ 16 KB / фиксированные размеры | ✅ | `reality.rs:189,505-509,527-540` | ✅ |
| HandshakeInit/Ack | только кадр 256 KB; `Vec<u8>` поля без собственных лимитов | — | `aira-core/src/proto.rs:155-162` | известно (core-audit, «тестовое покрытие… fuzz») |
| Incoming `GroupControl::CreateGroup.members` / `AddMember` | **нет** (MAX_GROUP_MEMBERS проверяется только для локального `CreateGroup`, `handler.rs:360`) | — | `aira-daemon/src/handler.rs:688-716,744-779` | ❌ часть **S1** |
| Invite-URI | нет лимита; `base64url_decode` аллоцирует `s.len()*3/4` | локальный ввод пользователя (paste/QR) | `aira-net/src/discovery.rs:53-61,185-186` | ⚠️ **S13** |
| Backup import | `std::fs::read` без лимита → decrypt → `postcard` | локальный файл | `aira-storage/src/backup.rs:128-150` | ⚠️ LOW, учесть в backup v2 (M19 Phase A) |
| Файл на отправку | `MAX_FILE_SIZE` 4 GB, но **целиком в память** (`tokio::fs::read` / `std::fs::read` в синхронном handler) | — | `aira-net/src/blobs.rs:22,70`, `handler.rs:895` | известно (daemon-storage-audit [medium]) |
| Sync batch | min 28 байт; верх — кадр | — | `aira-core/src/sync.rs:164-179` | ✅ |
| GUI/CLI/bot парсинг событий демона | 1 MiB IPC | доверенный демон | `aira-gui/src/state.rs:600,604`, `aira-cli/src/app.rs:384,400`, `aira-bot/src/runner.rs:136` | ✅ |
| Storage decrypt | значения из собственной БД | — | `aira-storage/src/encrypted.rs`, `contacts/groups/messages/pseudonyms.rs` | ✅ (AAD — известно §4.1a) |

`Vec::with_capacity`/`vec![0; n]` с `n` из сети **без предварительной проверки** — не найдено.

**S13 (LOW, M19b).** `discovery.rs:53-61` `from_uri`: `strip_prefix("aira://add/")` → `base64url_decode` →
`postcard::from_bytes` без лимита длины; `base64url_decode` (`:185-211`, `buf &= (1 << bits) - 1`) принимает
неканонические хвостовые биты и произвольную длину, не кратную 4 → одна и та же ссылка имеет много строковых
представлений (мешает дедупу/сравнению «та же ссылка?», даёт канал для fingerprinting источника ссылки). Исправление
при внедрении QR/invite (M19b п.4): cap 4 KB на URI, отклонять ненулевые хвостовые биты и недопустимые длины,
проверять `pseudonym_pk.len()` и `endpoint_addr_bytes.len()` после декодирования.

## 5. Constant-time сравнения

| Сравнение | Где | Как | Оценка |
|---|---|---|---|
| REALITY `short_id` | `reality.rs:394` `constant_time_eq_slice` | `subtle::ConstantTimeEq` (`:597-600`) | ✅ |
| REALITY auth MAC | `reality.rs:543` `constant_time_eq_32` | `subtle` (`:592-595`) | ✅; порядок (MAC → timestamp) правильный |
| AEAD-теги (ChaCha20-Poly1305) | `ratchet.rs:75-88`, `group.rs`, `encrypted.rs`, `sync.rs`, `password_vault.rs` | внутри `chacha20poly1305` (ct по контракту крейта) | ✅ |
| ML-DSA verify | `rustcrypto.rs`/`awslc.rs` | внутри крейтов | ✅ |
| Link code | `device.rs:234,240` `String ==` | не ct | известно (core-audit «verify_link_code сравнивает через String ==») |
| BIP-39 checksum | `seed.rs:219` `stored_checksum != computed_checksum` | не ct | n/a — локальный ввод, атакующий не наблюдает время |
| Group skipped nonce | `group.rs:174` `stored_nonce != *nonce` | не ct | n/a — nonce публичный |
| pubkey/`group_id`/`device_id` | `handler.rs`, `groups.rs` | `==` | n/a — публичные идентификаторы |

`subtle` объявлен в `aira-net/Cargo.toml` и используется только в `reality.rs`; в `aira-gui/src/theme.rs` (упомянут во
вводной) `subtle` **нет** — слово встречается в комментарии «subtle blue undertone» (`theme.rs:14`). Других MAC/hash-сравнений
в workspace нет. После M19a (SIGMA-binding, AAD-заголовок) появятся новые сравнения транскриптов — закладывать `ct_eq` сразу.

## 6. KEY_CONTEXTS.md vs код, nonce, AAD, RNG

### 6.1 Контексты (30 в документе ↔ 30 в коде)

| Контекст | Файл:строка | Назначение | Совпадает с doc |
|---|---|---|---|
| `aira/identity/0` | `aira-core/src/identity.rs:33` | ML-DSA identity seed | ✅ |
| `aira/x25519/0` | `handshake.rs:77,190`; `kem.rs:164` (test) | static X25519 | ✅ |
| `aira/mlkem/0` | `handshake.rs:78,191` | static ML-KEM seed | ✅ |
| `aira/storage/0` | `aira-daemon/src/main.rs:101`; `aira-ffi/src/runtime.rs:68` | DB key | ✅ |
| `aira/kem-keygen-d`, `aira/kem-keygen-z` | `crypto/rustcrypto.rs:51-52`; `crypto/awslc.rs:131-132` | ML-KEM d/z из seed | ✅ |
| `aira/hybrid-kem/v1` | `kem.rs:23,133` | combiner | ✅ (спека `aira/hybrid-kem/1` — известно, core-audit [low]) |
| `aira/session/root/v1`, `…/init-to-resp/v1`, `…/resp-to-init/v1` | `handshake.rs:298-301` | session keys | ✅ |
| `aira/chain/advance`, `aira/chain/message-key` | `ratchet.rs:58-59` | symmetric ratchet | ✅ |
| `aira/ratchet/root`, `aira/ratchet/chain` | `ratchet.rs:98-99` | DH ratchet | ✅ |
| `aira/ratchet/pq-mix`, `aira/ratchet/pq-init`, `aira/ratchet/pq-rekey` | `ratchet.rs:110,217,388` | PQ step | ✅ (сам PQ-шаг — core-audit high) |
| `aira/device/id`, `aira/device/sync-key`, `aira/device/link-code` | `device.rs:34,37,40` → `:187,199,211` | multidevice | ✅ |
| `aira/device/id-from-code` | `aira-daemon/src/handler.rs:200` | device id из link-code | ❌ **нет в doc** (известно, core-audit [medium]); контекст живёт в daemon, а не в core — при фиксе перенести в `aira-core::device` |
| `aira/group/chain-advance`, `aira/group/message-key` | `group.rs:213-214` | sender keys | ✅ |
| `aira/relay/mailbox/v1` | `aira-net/src/relay.rs:28,86` | mailbox id | ✅ (M21 вводит `…/v2/<dir>` — обновить doc) |
| `aira/pseudonym/<counter>/{signing,x25519,mlkem}` | `seed.rs:312-314` `format!(..)` | псевдонимы | ✅ динамический; `counter: u32` в десятичной записи + фиксированный суффикс → коллизий нет |
| `aira/obfs/session/0` | `obfs.rs:28` | XOR keystream key из **публичных** nonce (`:104-116`) | ✅ (по дизайну — только обфускация) |
| `aira/reality/sid/0`, `aira/reality/auth/0`, `aira/reality/session/0` | `reality.rs:49,52,55` | short id / MAC key / session key | ✅ строки; ⚠️ семантика `session/0` — см. S2 |
| `aira-gui/password-vault/v1` | `password_vault.rs:24` (комментарий) | Argon2id m=128 MB t=3 p=1 | документарный, не BLAKE3-контекст ✅ |

Двойного использования одного ключа в двух контекстах не найдено. Отдельная проверка вводной «`aira/1/*`» —
это ALPN (`aira-net/src/lib.rs:41-44`: `aira/1/chat|file|handshake|relay`), не KDF ✅.

### 6.2 Nonce-схемы, AAD, RNG

| Место | Nonce | AAD | Оценка |
|---|---|---|---|
| Ratchet AEAD | `derive_nonce(msg_key, counter)` (`ratchet.rs:64-72`) — уникален per key | нет | известно (core-audit blocker «заголовок не аутентифицирован») |
| Group AEAD | `derive_nonce(msg_key, counter)` (`group.rs:219-227`); в in-order пути используется nonce **с провода** (`:201`), в skipped — сохранённый (`:174`) | нет | ⚠️ nonce с провода избыточен: при известном ключе он детерминирован — выводить локально и не доверять полю (устраняет один attacker-controlled вход); войдёт в M19a wire v2 |
| Storage | random 96-bit `thread_rng` (`encrypted.rs:29-44`) | нет | известно (core-audit [low] birthday, §4.1a AAD) |
| Sync batch | random 96-bit под sync key (`sync.rs:139-156`) | нет | известно |
| Obfs keystream | `BLAKE3(key ‖ direction ‖ counter)` (`obfs.rs:183-191`), ключ per-session из nonce обеих сторон | — | ✅ для обфускации |
| REALITY keystream | `key ‖ dir ‖ counter` (`reality.rs:707-715`), **ключ = `derive_key("aira/reality/session/0", psk)` статичен** (`:588-590`, вызовы `:367,:418`) | — | ❌ **S2(a)** |
| Password vault | random salt + nonce `thread_rng` (`password_vault.rs:108-135`) | — | ✅ |

RNG: единственный источник — `rand::thread_rng()` (rand 0.8: ChaCha12, seed из OsRng, периодический reseed):
`seed.rs:265`, `ratchet.rs:213,425`, `handshake.rs:84,232`, `kem.rs:51`, `rustcrypto.rs:59-63` (`encapsulate(&mut thread_rng)`),
`group.rs:66-73`, `padding.rs:48`, `util.rs`, `encrypted.rs`, `sync.rs`, `obfs.rs:73`, `reality.rs:563`, `handler.rs:80-84,368`,
`password_vault.rs`. Тестовых/детерминированных RNG в prod нет ✅. После M18 (iroh 1.1) вероятен `rand 0.9` рядом с 0.8 —
проверить `cargo tree -d -i rand` и что `thread_rng` не подменён `SmallRng`.

### 6.3 S2 (HIGH в threat-model DPI, M22 / исключить из релиза) — транспорт REALITY

Область: `aira-net/src/transport/reality.rs`, только с `--features reality` (`aira-net/Cargo.toml`: `default = []`),
`TransportSecrets.reality_psk` (`transport/mod.rs:210-214`) нигде не персистится и не читается из settings, транспорт к
iroh не подключён (`create_transport`, `mod.rs:401-466`; демон хранит только строку режима, `handler.rs:836-860`).
Т.е. **в релизной сборке кода нет**, но `spec/13-threat-model.md:160-215` описывает REALITY как рабочую защиту от DPI и
active probing, и `docs/KEY_CONTEXTS.md:93-95` фиксирует его контексты.

Дефекты (по коду):

- **(a) Статичный session key.** `reality.rs:588-590` `fn derive_session_key_from_auth(psk) -> Zeroizing<[u8;32]> { derive_key(REALITY_SESSION_CONTEXT, psk) }`
  — не зависит ни от клиентского nonce (`:474-516`), ни от серверного (`:563`). Keystream `key ‖ dir ‖ counter` (`:707-715`)
  **идентичен во всех сессиях под одним PSK** → XOR двух перехваченных сессий = XOR их открытых текстов (классическое
  повторное использование nonce). Практический ущерб ограничен тем, что внутри — QUIC/iroh (TLS 1.3) + E2E-ratchet,
  но сам слой REALITY не даёт конфиденциальности, которую декларирует §13.
- **(b) Replay auth-кадра.** Сервер проверяет MAC (`:541-545`) и `|now − ts| ≤ 60 с` (`:547-558`), **кэша nonce нет** →
  любой перехваченный клиентский пролог (short_id + TLS + auth) воспроизводится 60 с и получает валидный ответ.
- **(c) Ответ сервера без MAC.** `:560-572` — `magic ‖ random(32)`; клиент проверяет только `resp[0] == MAGIC` (`:511`).
  Серверный nonce никуда не подмешивается → взаимной аутентификации нет, MITM с любым сертификатом (клиент —
  `AcceptAnyCertVerifier`, `fingerprint.rs:99-134`, `build_reality_client_config :164-177`
  `.dangerous().with_custom_certificate_verifier`) проходит как «сервер».
- **(d) short_id в открытом виде до TLS.** `:336-346` `stream.write_all(&short_id)` — 8 байт `BLAKE3("aira/reality/sid/0", PSK)`
  — статичный маркер всех клиентов данного сервера в первых байтах TCP-потока. Это готовая DPI-сигнатура; в исходном
  REALITY (Xray) short id прячется в TLS `session_id` ClientHello, а здесь `SessionIdPatcher`/`ClientHelloParser`
  помечены `dead_code` (`:1-4`).
- Итог для threat-model: активный пробер, повторив перехваченный пролог (b+d), получает `AUTH_RESPONSE_MAGIC` вместо
  fallback-сайта (`proxy_to_backend :429-469`, причём `fallback_addr` в `create_transport` всегда `None` → `mod.rs:445`)
  — сервер **отличим**, что и есть поражение цели REALITY.

Исправление (если оставлять): session key = `derive_key("aira/reality/session/1", psk ‖ client_nonce ‖ server_nonce)`,
серверный ответ = `MAC(auth_key, server_nonce ‖ client_nonce)`, кэш client-nonce на 2×drift, short_id внутри TLS ClientHello
(реанимировать `SessionIdPatcher`), fallback обязателен; плюс тесты на replay и на различие keystream двух сессий.
Альтернатива (рекомендуется для 1.0): исключить `reality`/`obfs4`/`mimicry`/`cdn`/`tor` из релизных сборок
(они и так не в `default`), в `spec/13-threat-model.md` пометить REALITY «экспериментально, не входит в 1.0», в
`KEY_CONTEXTS.md` — примечание к `aira/reality/session/0`. Milestone: M22 (anti-abuse/DPI) или после релиза — решение владельца.

## 7. Прочее

### 7.1 S1 (HIGH, M19 Phase B) — входящие `GroupControl` без авторизации отправителя

`aira-daemon/src/handler.rs:680-833` `handle_incoming_group_control(storage, seed, sender_pubkey, control, event_tx)`
вызывается для любого `PlainPayload::GroupControl` из `handle_incoming_payload` (`:621-674`), `sender_pubkey` — идентичность
1:1-канала. Проверки, которых нет:

- **`CreateGroup` (`:688-742`)** от **любого** отправителя создаёт группу в нашей БД с произвольным `members` (лимит
  `MAX_GROUP_MEMBERS` есть только для локального `CreateGroup`, `:360`), затем **автоматически принимает приглашение**:
  `:737-739` `// Auto-accept … let _ = handle_accept_group_invite(storage, seed, group_id, "", sender_pubkey);` —
  мы деривируем псевдоним и рассылаем свой `SenderKeyUpdate` всем перечисленным `members`, включая незнакомых. Любой
  контакт (после M22 — любой, кто прошёл contact-request) может создавать у нас группы и заставлять слать ключи
  произвольным адресатам (spam/enumeration).
- **`AddMember` (`:744-779`)** — роль отправителя не проверяется (не Admin); `sender_keys: Vec<(pk, key)>` применяется ко
  **всем** существующим участникам: `:764-768` `for (pk, chain_key_bytes) in sender_keys { if let Some(member) = group.members.iter_mut().find(|m| m.pubkey == *pk) { … member.sender_chain_key[..len].copy_from_slice(..) } }`.
  Любой участник может перезаписать у нас `sender_chain_key` **другого** участника ключом, который знает он сам.
  Путь приёма `GroupMessage` в демоне ещё не написан — `handle_incoming_payload` (`:631-672`) не имеет ветки
  `PlainPayload::GroupMessage`, она попадает в `_ =>` (`:655-672`) и сохраняется **сырыми байтами в 1:1-историю
  отправителя** (отдельный функциональный дефект для M19 Phase B). Когда в M19 приём будет подключён по спеке
  (`SenderKeyReceiver::from_chain_key(member.sender_chain_key)` по полю `from`), подменённый ключ означает, что
  атакующий отправляет сообщения с `from = жертва`, зашифрованные под подменённый ключ, и мы отображаем их как
  сообщения жертвы — **подделка групповых сообщений**; побочно — DoS (настоящие сообщения жертвы перестают
  расшифровываться). `spec/14-groups.md:71` («Только Admin добавляет/удаляет участников») код не выполняет.
- **`RemoveMember` (`:781-803`)** — любой участник удаляет любого (в т.ч. админа) и инициирует ротацию.
- **`SenderKeyUpdate` (`:805-819`)** — обновляет только ключ самого отправителя ✅ (это правильно).
- **Длина ключа.** `:711-712`, `:766-767`, `:811-813` `let len = X.len().min(32); key[..len].copy_from_slice(&X[..len]);` —
  ключ короче 32 байт молча дополняется нулями (1-байтный «ключ» → 31 нуль), длиннее — усекается. Нужно `!= 32 → Err`.

Отсутствие сети (§4.1a) делает это пока недостижимым, но M19 Phase B подключает именно этот путь. Исправление
(до wiring `GroupControl`): (1) `CreateGroup` — только событие `GroupInviteReceived`, без записи в БД и без auto-accept,
пока пользователь не вызовет `AcceptGroupInvite` (UI уже умеет); cap `members.len() ≤ MAX_GROUP_MEMBERS`;
(2) `AddMember`/`RemoveMember` — требовать `role == Admin` у `sender_pubkey` по нашей копии группы; `sender_keys`
принимать **только** для `new_member` (ключи остальных приходят от них самих через `SenderKeyUpdate`);
(3) все sender-key поля — ровно 32 байта; (4) тесты: «AddMember от Member отклонён», «sender_keys для чужого pk
игнорируется», «CreateGroup не создаёт группу без accept», «ключ 31 байт отклонён». Спека `spec/14-groups.md`
(роли Admin/Member) это уже требует — код отстаёт.

### 7.2 S8 (MEDIUM, M19b п.3 расширить) — права на файлы и сокеты

Grep по workspace: `set_permissions | PermissionsExt | \.mode\( | OpenOptions | security_descriptor | SO_PEERCRED | peer_cred` —
**0 совпадений**. Всё создаётся с правами по umask (обычно 0755/0644):

- `aira-daemon/src/main.rs:107-110` `std::fs::create_dir_all(&dir)?; … Storage::open(&db_path, ..)` → `~/.aira/aira.redb`
  (`aira-storage/src/lib.rs:140` `Database::create(path)`) — БД зашифрована, но метаданные/размер/структура таблиц читаемы,
  а `pending_messages` — plaintext (daemon-storage-audit [high]) → **любой локальный пользователь читает очередь отправки**.
- `main.rs:130-131` каталог `downloads` — принятые файлы читаемы всем.
- `aira-storage/src/backup.rs:114` `std::fs::write(path, &file_data)?` — backup 0644 (зашифрован storage-ключом; всё же 0600).
- `aira-daemon/src/ipc.rs:76-83` `remove_file(&socket_path)` … `UnixListener::bind(&socket_path)?` — сокет 0755 → любой
  локальный пользователь получает полный контроль над демоном (IPC без auth — известно, daemon-storage-audit [high];
  здесь — конкретика для фикса).
- Windows: `%APPDATA%`-каталоги наследуют ACL профиля (user-only) ✅; named pipe с `first_pipe_instance(false)`
  (`ipc.rs:181-183`) — известно.
- Android (`aira-ffi/src/runtime.rs:72-89`) — app-private dir, sandbox ОС ✅.

Исправление: `DirBuilder::new().mode(0o700)` для `~/.aira`, `OpenOptions::new().mode(0o600)` для backup и `.redb`
(redb принимает `File`? — если нет, `set_permissions` после `create`), `set_permissions(socket, 0o600)` сразу после
`bind` (плюс SO_PEERCRED из M19b п.3), `downloads` 0700. Тест на Unix: после старта демона `stat` файлов = 0600/0700.

### 7.3 S9 (MEDIUM) и прочие функциональные дефекты транспортов

- `obfs.rs:327-332` `let chunk_len = buf.len().min(MAX_FRAME_PAYLOAD); … let len_bytes = (chunk_len as u16).to_le_bytes();`
  при записи ровно 65 536 байт → заголовок `0` → приёмник `:280` `if len == 0 || len > MAX_FRAME_PAYLOAD { return Err(InvalidData) }`
  → соединение рвётся на **любой записи ≥ 64 KiB** (передача файлов). `mimicry.rs:417-422` — та же ошибка; приёмник
  `:355-370` примет пустой кадр, а 65 536 байт данных прочитает как следующие заголовки → десинхронизация.
  Фикс: `MAX_FRAME_PAYLOAD = 65_535` (как в `reality.rs:840`) + тест на запись 65 536 байт.
- `obfs.rs:272-277` «Partial length header — … we just skip this byte and retry next poll. `break`» — байт(ы) уже
  прочитаны из `inner` и теряются → десинхронизация на TCP-фрагментации. Нужен буфер «хвоста» как в mimicry
  (`MimicryPendingFrame::PayloadLen { buf, pos }`).
- `mimicry.rs` — целостности нет вообще (по дизайну, как и obfs) — не должен фигурировать в спеке как «защита».
- `blobs.rs:86,103` **S16** `std::mem::forget(tag)` — temp-tags iroh-blobs никогда не дропаются → блобы не собираются GC,
  диск/память растут с каждой отправкой. Фикс в M19 Phase B: хранить `TempTag` в `TransferManager` до завершения передачи,
  затем `tag.hash()` → permanent tag или drop.

Милстоун: если транспорты подключаются к iroh в M19 Phase B — там; иначе M22 (DPI) вместе с решением по S2.

### 7.4 S11 (LOW) — `let _ =` на значимых `Result`

| Место | Что игнорируется | Последствие |
|---|---|---|
| `handler.rs:739` | `handle_accept_group_invite` | приглашение «принято» без ключей (уходит вместе с S1) |
| `handler.rs:464-471`, `:909` | `pending::enqueue` при fan-out групп / отправке файла | сообщение/файл молча не поставлены в очередь (перекрывается daemon-storage «очередь pending без лимитов…»; добавить `warn!`) |
| `aira-ffi/src/runtime.rs:85,108,115` | `dedup::gc_expired`, `messages::delete_expired` | TTL-сообщения могут **не удаляться** без единого сигнала (на Android нет stderr демона) → `tracing::warn!` + счётчик ошибок в событие |
| `aira-daemon/src/ipc.rs:76` | `remove_file(socket)` | ок (stale) |
| `aira-gui/src/keychain.rs:110,134`, `ipc.rs:755,796` | удаление seed | **S7** |
| `aira-ffi/src/runtime.rs:361` | `shutdown_tx.try_send` | ок |

### 7.5 S15 (LOW, M19a) — промежуточные буферы с производными ключами

`aira-core/src/device.rs:186-190` `let mut context_material = [0u8; 36]; … copy_from_slice(base.as_ref()) … blake3::hash(&context_material)`
и `:214-216` `let mut input = [0u8; 40]; input[..32].copy_from_slice(code_material.as_ref())` — производные ключи
(`aira/device/id`, `aira/device/link-code`) копируются в незануляемые стековые массивы. Знание `aira/device/id`-ключа
позволяет перечислить все device-id пользователя; знание link-code-ключа — предсказывать коды. Обернуть в
`Zeroizing<[u8; N]>` (две строки).

### 7.6 Логирование и PII (S19, INFO)

`aira-net/src/protocol.rs:56,132` `debug!(%remote_id, …)` — EndpointId пира на уровне debug; `aira-daemon/src/main.rs:111`
`info!("database opened at {}", db_path.display())` — путь. Секреты, тексты сообщений, pubkey контактов в логах не
встречаются. Рекомендация: в релизных сборках default-фильтр `info`, `remote_id` — только в `trace` или укороченный.

### 7.7 Временные файлы, backup, прочее

- Временных файлов нет (blobs in-memory, redb пишет in-place).
- `aira-ffi/src/runtime.rs:137-158` `set_event_listener` при повторном вызове (rebind Activity) спавнит ещё одну forwarding-задачу,
  старая продолжает жить со старым listener → дублирование callback'ов/утечка (не security, но заметно на Android) — M19b.
- Panic hook только в `aira-cli/src/main.rs:109-114`; демон/GUI при панике печатают стек в stderr (secrets в стеке не
  форматируются — `Debug` не вызывается; после S5 риск исчезнет и для будущих `{:?}`).

## 8. Парсеры без fuzz (список)

Есть: `crates/aira-core/fuzz/fuzz_targets/fuzz_parse_message.rs` (`PlainPayload`, `EncryptedEnvelope`),
`fuzz_decode_keys.rs` (ML-KEM ek / ML-DSA vk). Корневого `fuzz/` нет, CI фаззинг не запускает (задание D).
Известная часть — core-audit «fuzz не покрывает Message/Handshake/Group/Snapshot». Полный список внешних входов без таргета:

| Парсер | Файл | Вход от | Milestone |
|---|---|---|---|
| `HandshakeInit` / `HandshakeAck` (+ `finish`/`respond` целиком, не только postcard) | `aira-core/src/handshake.rs` | сеть | M19a (уже в плане) |
| `MessageHeader` + `RatchetSession::decrypt` (после wire v2) | `ratchet.rs:300-365` | сеть | M19a |
| `GroupMessage`, `GroupControl`, `PseudonymLink`, `PseudonymRotation` | `group_proto.rs`, `handler.rs:680-833` | сеть | M19a / M19 |
| `SyncItem` / `decode_sync_batch` | `sync.rs:164-179` | сеть (устройства) | M19a |
| `RatchetSnapshot` из БД (полу-доверенный: БД читаема при S8) | `ratchet.rs:125-146` | диск | M19 Phase A |
| `InvitationLink::from_uri` + `base64url_decode` | `aira-net/src/discovery.rs:53-61,185-211` | пользователь/QR | M19b |
| `DeviceRecord` | `discovery.rs:88-147` | DHT (после релиза) | — |
| `RelayRequest` / `RelayResponse` | `relay.rs:33-70` | сеть | M21 (в плане) |
| `DaemonRequest` (IPC сервер) / `DaemonResponse`, `DaemonEvent` (клиенты) | `ipc.rs:28`, `client.rs:184`, `aira-gui/src/state.rs:600,604`, `aira-cli/src/app.rs:384,400`, `aira-bot/src/runner.rs:136` | локальный сокет (после M19b — аутентифицированный) | M19b |
| `backup::import` (MAGIC/VERSION/blob → decrypt → postcard) | `aira-storage/src/backup.rs:128-150` | файл пользователя | M19 Phase A (backup v2) |
| `decrypt_value` + per-table `from_bytes` | `aira-storage/src/encrypted.rs`, `contacts/groups/messages/pseudonyms.rs` | диск | M19 Phase A |
| `ObfsStream::poll_read`, `MimicryStream::poll_read`, `ClientHelloParser`, auth-кадр REALITY | `transport/obfs.rs:230-311`, `mimicry.rs:260-404`, `reality.rs:180-330,520-575` | сеть (DPI-путь) | M22 |
| `MasterSeed::from_phrase` (BIP-39) | `seed.rs:190-224` | пользователь | M19a (дёшево, детерминированно) |
| `TransportMode::from_str` | `transport/mod.rs:216-284` | IPC | M19b |
| `padding::unpad_message` | `padding.rs:60-66` | сеть (после AEAD) | M19a |

Минимальный набор к релизу: handshake, ratchet decrypt (wire v2), group_proto + `handle_incoming_group_control`,
sync, RelayRequest, IPC `DaemonRequest`, backup import, invite-URI. Каждый — `fuzz_target!` без паники + запуск в CI
(`cargo fuzz run <t> -- -max_total_time=60`, M23).

## 9. Задачи по милстоунам

**M18 (iroh 1.1 + ml-dsa/ml-kem, до 30.09.2026):**
- После отката `Cargo.toml`/`Cargo.lock` владельца убедиться, что `ml-kem`/`ml-dsa` остаются с feature `zeroize`
  (root `Cargo.toml:28-29`) и `x25519-dalek` — с default `zeroize`; `cargo tree -i zeroize` как проверка.
- `cargo tree -d -i rand`: если iroh 1.1 тянет rand 0.9 — убедиться, что `thread_rng` в core остаётся OsRng-seeded
  (§6.2), не смешивать `rand_core` 0.6/0.9 в `crypto/rustcrypto.rs:59-63`.

**M19a (протокол v2 в aira-core):**
- S4: `seed.rs:123-141,190-223,262-267` — `Zeroizing` на фразу/энтропию/`bits`/`indices`; API `generate() -> (Zeroizing<String>, Self)`.
- S5: ручной `Debug` с `[REDACTED]` для `RatchetSnapshot` (`ratchet.rs:125`), `SenderKeyState`/`SenderKeyReceiver` (`group.rs:54,128`),
  `SyncItem` (`sync.rs:30-80`), `GroupControl` (`group_proto.rs:73-120`).
- S6: `group.rs:136` `skipped_keys` → `Zeroizing`, `:212-216` `chain_ratchet` → `Zeroizing`, `impl Drop`; убрать `Clone` или обосновать;
  nonce группового сообщения выводить локально (`:201`), не брать с провода.
- S15: `device.rs:186-190,214-216` — `Zeroizing`; `ratchet.rs:57-61` `chain_ratchet` → `Zeroizing` (консистентность).
- S20: `docs/KEY_CONTEXTS.md` — добавить `aira/device/id-from-code` (и перенести деривацию из `handler.rs:200` в `aira-core::device`),
  примечание к `aira/reality/session/0`.
- §8: fuzz-таргеты handshake / ratchet decrypt / group_proto / sync / BIP-39 / unpad.
- Проверить, что новые сравнения транскриптов (SIGMA-binding, AAD) идут через `subtle::ct_eq` (§5).

**M19 (сеть в демоне):**
- Phase A (storage): S14 `messages.rs:123` `saturating_add` + cap TTL на IPC; backup v2 — лимит размера импорта и `Zeroizing`
  на расшифрованный блоб (`backup.rs:128-150`); fuzz на `backup::import` и per-table decode.
- Phase B (net_task): **S1** — авторизация `GroupControl` (`handler.rs:688-819`): без auto-accept, Admin-проверка для
  AddMember/RemoveMember, `sender_keys` только для `new_member`, ключи ровно 32 байта, cap `members`; добавить ветку
  `PlainPayload::GroupMessage` в `handle_incoming_payload` (`:631-672` — сейчас группы падают в `_ =>` и пишутся сырыми
  байтами в 1:1-историю); S16 `blobs.rs:86,103`;
  S11 `warn!` вместо `let _ =` (`handler.rs:470,909`); S9 — если obfs/mimicry подключаются здесь, иначе M22.
- Phase C (тесты): сценарии из S1 (4 теста), «запись 65 536 байт через obfs/mimicry», «TTL = u64::MAX».

**M19b (клиенты):**
- S3: `aira-gui/src/onboarding.rs:103`, `state.rs:78,82,86`, `views/settings.rs:462-468`, `views/unlock.rs:112-113` → `String::zeroize()`;
  S18 `discovery.rs:181-182` → safe; затем `forbid(unsafe_code)` во всех крейтах.
- S4: `aira-daemon/src/main.rs:85-98` (`Zeroizing<String>` + `remove_var`), `aira-ffi/src/runtime.rs:56-66` (`Zeroizing`, параметр
  как bytes, Android Keystore), `aira-gui/src/keychain.rs:170-177` (`Option<Zeroizing<String>>`) — расширить п.5.
- S7: `keychain.rs:107-136` порядок delete→write + проброс ошибок; `ipc.rs:755,796` — ошибку в UI; тест «delete падает».
- S8: расширить п.3 (IPC-аутентификация) правами на `~/.aira` 0700, `aira.redb`/backup 0600, сокет 0600, `downloads` 0700;
  тест `stat` на Unix.
- S13: cap URI 4 KB, канонический base64url, проверка длин полей `InvitationLink` (п.4 QR/invite).
- fuzz `DaemonRequest` (IPC) и `TransportMode::from_str`; `set_event_listener` — отменять предыдущую задачу (`runtime.rs:137-158`);
  S11 — `warn!` на GC в `runtime.rs:85,108,115`.

**M21 (aira-relay mailbox v2):**
- S12: `max_mailboxes` (глобально и per-IP/per-owner), `Ack.counters.len() ≤ max_envelopes`, `Retrieve` с `limit`/cursor так,
  чтобы ответ помещался в `MAX_FRAME_SIZE` (`connection.rs:22`), общий cap 1 GB — уже в плане.
- KEY_CONTEXTS.md: `aira/relay/mailbox/v2/<dir>`; `v1` пометить deprecated.
- fuzz `RelayRequest` — уже в плане; добавить `RelayResponse` для клиента.

**M22 (anti-abuse / DPI):**
- S2: решение «переработать REALITY (per-session key, MAC ответа, nonce-кэш, short_id в ClientHello, обязательный fallback)»
  или «исключить из 1.0 + пометить §13 экспериментальным». S9 obfs/mimicry framing (если не сделано в M19).
- Contact-request gate перед `CreateGroup` от незнакомцев (связка с S1).

**M23 (release hardening / CI):**
- S10/S17: `[workspace.lints]` (`unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `unsafe_code`), `[lints] workspace = true`
  во всех крейтах; `cargo fuzz` smoke в CI; `cargo audit`/`deny` блокирующие (уже в плане).
- Проверка релизной сборки: `aira-net` без `reality/obfs4/mimicry/cdn/tor`; default-фильтр логов `info` (S19).

## 10. Не проверено

- `cargo build`/`test`/`clippy` не запускались (правило задания) — все выводы по чтению кода; незакоммиченный diff
  `Cargo.toml`/`Cargo.lock` владельца (bump ml-dsa rc.4) не анализировался на предмет features.
- Сгенерированный uniffi 0.28 код и Kotlin-сторона (`android/`): поведение при панике (catch_unwind → `InternalException`),
  как хранится/передаётся seed в Kotlin, ProGuard — вне области (clients-audit, задание E/D).
- Реализация `keyring` для каждой платформы (mock — известно), реальные ACL Windows Credential Manager / macOS Keychain.
- Внутренности `iroh` (zeroize `SecretKey`, права на файлы iroh-blobs store) — iroh 0.97 будет заменён в M18.
- `reality.rs:900-1136` (по всей видимости тесты), `mimicry.rs::generate_header`, `awslc.rs:175-339` (кодирование dk),
  `aira-cli/src/commands.rs`, большинство `aira-gui/src/views/*` кроме welcome/settings/unlock, `aira-bot` кроме `runner.rs`/`lib.rs`,
  `transport/tor.rs` после :168 — прочитаны частично или не прочитаны; по grep паник/unsafe/секретов там нет.
- Поведение redb при `Database::create` на существующем файле с чужими правами; возможность передать `File` с 0600.
- `password_vault.rs` — параметры Argon2id (m=128 MiB) на слабых машинах и обработка OOM (уровень UX).
- Timing-каналы вне явных сравнений (например, `BIP39_WORDS.iter().position` в `seed.rs:199-202` — линейный поиск по
  словарю зависит от слова; локальный ввод, не эксплуатируемо удалённо).
- Спека `spec/14-groups.md` (роли/права) сверялась только по памяти предыдущих фаз; точные формулировки прав Admin —
  задание E.
