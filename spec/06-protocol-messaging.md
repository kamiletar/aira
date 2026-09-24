# SPEC §6.7-6.15: Протокол — сообщения, реакции, receipts

[← Индекс](../SPEC.md)

---

### Статус §6.7–6.24 на 2026-09 и что входит в бету

Источник — аудит E (`.claude/docs/audit-2026-09/spec-remainder-audit.md` §4). Обозначения:
**тип** — только тип в `proto.rs`, у демона и клиентов ветки нет; **stub** — команда есть, только
пишет статус. Решение владельца C15: в бете сверх обязательного минимума §15.8 п.2 — только TTL и
block; остальное — **M28 «дешёвые фичи §6.x»** (после `MessageMeta` по проводу в M19 и резерва
вариантов `PlainPayload` в M19a, §6.16.1 п.5).

| § | Фича | Код (v0.3.5) | Статус | Бета (M23)? |
|---|---|---|---|---|
| 6.7 | Disappearing | `MessageMeta.ttl` по проводу не ходит; `SetTtl`, GC `delete_expired` есть; `expires_at` ставится только в `messages::mark_read`, который никто не вызывает → таймер никогда не стартует (F1) | частично | **да** — M19 Phase B: `MessageMeta` по проводу, `mark_read` при `GetHistory`/открытии чата |
| 6.8 | Реакции / ответы | `Reaction`, `MessageMeta.reply_to`; только рендер | тип | нет — M28 |
| 6.9 | Safety Numbers | `safety.rs` в core; IPC-запроса нет; `/verify` — stub | stub | **да** — `GetSafetyNumber { contact }` (M19a п.6 / M19b), обязательный минимум §15.8 п.2 |
| 6.10 | Export / import | `ExportBackup/ImportBackup`, backup `VERSION = 1` | реализовано | да; `VERSION = 2` (M19 Phase A п.4) |
| 6.11 | Медиа (фото/аудио/видео) | `MediaPayload`; `SendFile` → `FileStart` | тип | нет — M28 (фото), голосовые — M15 |
| 6.12 | Link preview | `LinkPreviewPayload` | тип | нет — M28; в `hide_ip` — opt-in |
| 6.13 | Edit / Delete | `Edit`, `Delete`; рендер | тип | нет — M28 |
| 6.14 | Receipts | `ReceiptPayload`; не отправляются, `read_at` не ставится | тип | Delivered — как транспортный `DeliveryState` (M19 п.11); Read/Played — M28 |
| 6.15 | Typing | `Typing(bool)` | тип | нет — M28 |
| 6.16 | Unknown / расширяемость | `Unknown { type_id, data }`; ⚠️ неизвестный discriminant postcard = ошибка десериализации, не `Unknown` | тип | **да** — правило §6.16.1 п.5, резерв вариантов в M19a |
| 6.17 | Профили | `UserProfile` в коде нет; `/profile` — stub | нет | нет — alias-only; профили M28, `is_bot` M27 |
| 6.18 | Удаление аккаунта | `KeyRevocation` нет; `/delete-account` не обрабатывает подтверждение | нет | нет — после M20/M21 (revocation в pkarr/relay) |
| 6.19 | Block | `ContactInfo.blocked`, `contacts::set_blocked` есть, нигде не проверяются; `/block` = `RemoveContact` — удаляет контакт (F2); `/unblock` — stub | некорректно | **да** — M19 Phase B: `BlockContact/UnblockContact` (отдельные запросы, не `RemoveContact`), silent drop входящих и handshake от `blocked`; UI M19b (§6.19) |
| 6.21 | Dedup | `dedup.rs`, окно 24 ч | реализовано | да; ключ `BLAKE3(sender ‖ counter ‖ nonce)` — M19 Phase A п.3 |
| 6.22 | Лимиты | `MAX_ENVELOPE_SIZE` в ratchet | реализовано | да; проверка на границе IPC/UI — M19b п.4 |
| 6.23 | Pin | нет | нет | нет — M28 |
| 6.24 | Поиск | `/search` — stub | нет | нет — M28 |
| 11B.6 | Mute | `/mute` — stub | нет | нет — M28 |
| 9.1 | i18n | движок `aira_core::i18n` (fluent, en/ru, 33 ключа) не подключён ни к одному клиенту; `/lang` — stub | не подключено | нет — English only в бете (§9.1) |

Правило беты (§15.8 п.6–7): команды и экраны нереализованных фич не показываются — честная строка
«not available», а не половинчатая реализация.

### 6.7 Disappearing messages (v0.1 — работает после M19)

Автоудаление сообщений через заданное время:

```rust
pub enum PlainPayload {
    Text(String),
    Action(String),
    // ... остальные варианты
}

/// Обёртка с метаданными сообщения — ЕДИНСТВЕННЫЙ plaintext ratchet-конверта (M19a)
/// и формат payload_bytes в storage и IPC (M19): один контракт для провода, демона,
/// CLI, GUI и бота (в v0.3.5 — три несовместимых формата, аудит B2)
pub struct MessageMeta {
    pub payload: PlainPayload,
    /// Время жизни сообщения (None = навсегда)
    pub ttl: Option<Duration>,
    /// ID сообщения (для реакций, ответов, receipts)
    pub id: [u8; 16],
    /// ID сообщения, на которое отвечаем
    pub reply_to: Option<[u8; 16]>,
}
```

- TTL устанавливается per-chat (настройка: 30с / 5мин / 1ч / 1д / 7д / off) — `SetTtl` (§8)
- `ttl` едет по проводу внутри `MessageMeta`; получатель хранит `ttl_secs` в `StoredMessage`
- **Таймер начинается после прочтения, не после отправки:** `expires_at = read_at + ttl`
  выставляется в `messages::mark_read`. Демон вызывает `mark_read` **при выдаче истории**
  (`GetHistory`) / открытии чата клиентом — в v0.3.5 `mark_read` не вызывался нигде, поэтому TTL
  никогда не срабатывал (F1; M19 Phase B п.11). Read receipt (§6.14) — отдельный механизм, после беты
- `now + ttl` — saturating (u64::MAX из IPC не должен паниковать, M19 Phase A)
- Daemon удаляет из redb по расписанию (GC-таск `delete_expired`)
- UI показывает оставшееся время
- Группы: TTL per-group — M25 (§12.3); v1 хранит групповые сообщения без TTL

### 6.8 Реакции и ответы (M28)

```rust
pub enum PlainPayload {
    Text(String),
    Action(String),
    /// Реакция на сообщение
    Reaction { message_id: [u8; 16], emoji: String },
    /// ... остальные варианты
}
```

- Emoji ограничено одним Unicode codepoint (без пользовательских стикеров)
- Reply: `reply_to` в `MessageMeta` — клиент показывает цитату
- Реакции на уже удалённое (disappearing) сообщение — игнорируются
- Статус: типы есть, отправки и обработки нет (только рендер) — M28

### 6.9 Верификация ключей — Safety Numbers (бета, M19a/M19b)

TOFU (Trust On First Use) уязвим к MITM при первом соединении. Для
верификации добавляется **Safety Number** (как в Signal):

```rust
/// Safety Number computation — итеративный хэш с version binding.
/// Аналог Signal (5200 итераций SHA-512), адаптирован под BLAKE3.
///
/// Итерации замедляют brute-force поиск коллизий при отображении
/// 256-bit хэша в виде 60 десятичных цифр (~200 бит).
/// Version binding гарантирует смену Safety Number при обновлении
/// криптографических алгоритмов.
pub fn safety_number(
    key_a: &PubKey,
    key_b: &PubKey,
    protocol_version: u16,
) -> String {
    // Compute fingerprint for each key independently (like Signal)
    let fp_a = fingerprint(key_a, protocol_version);
    let fp_b = fingerprint(key_b, protocol_version);
    // Sort and concatenate for display
    let (first, second) = if key_a < key_b { (fp_a, fp_b) } else { (fp_b, fp_a) };
    format_as_digits(&first, 30) + &format_as_digits(&second, 30)
}

fn fingerprint(key: &PubKey, version: u16) -> [u8; 32] {
    let mut hash = [0u8; 32];
    hash.copy_from_slice(blake3::hash(key.as_bytes()).as_bytes());
    for _ in 0..5200 {
        let mut input = Vec::with_capacity(2 + 32 + key.as_bytes().len());
        input.extend_from_slice(&version.to_le_bytes());
        input.extend_from_slice(&hash);
        input.extend_from_slice(key.as_bytes());
        hash.copy_from_slice(blake3::hash(&input).as_bytes());
    }
    hash
}
```

- Оба пира вычисляют одинаковый Safety Number — функция симметрична к порядку ключей
  (сортировка выше; решение A22), ≥ 128 бит стойкости
- Вычисляется по **pseudonym**-ключам пары (§12.6.10), `protocol_version = 2`
- Сравнение: вслух при встрече, или QR-кодом
- IPC: `GetSafetyNumber { contact }` (§8); CLI: `/verify <contact>`; GUI — карточка контакта
  (M19b). В v0.3.5 `safety.rs` вне core не вызывается, `/verify` — заглушка
- При смене ключа контакта — уведомление + автоматический reset trust

### 6.10 Export/import аккаунта (v0.1)

Seed-фраза восстанавливает ключи, но не контакты, историю и настройки.

```
/export → aira-backup-2026-04-01.aira.enc

Содержимое (зашифровано storage key):
  - contacts.postcard     — список контактов с alias'ами (v2: + endpoint_addr, relays)
  - settings.postcard     — настройки (TTL, relay, hide_ip, device_index, etc.)
  - ratchet_states/       — текущие ratchet state для каждого контакта
  - messages/ (optional)  — история сообщений
  - v2 (M19 Phase A п.4): groups, group_messages, devices, pseudonyms, pseudonym_counter

/import aira-backup-2026-04-01.aira.enc
  → запросит seed-фразу для расшифровки
```

- Seed-фраза нужна для восстановления storage key (п. 4.8)
- Бэкап НЕ содержит seed-фразу или master key
- История опциональна (может быть большой); лимит размера при импорте (решение A19)
- Формат и версии — §7.2; после restore псевдонимный счётчик продолжается с `max + 1`

### 6.11 Медиа-сообщения (M28; голосовые — M15)

Отличие от file transfer: медиа отображается inline с превью.

- **Изображения:** отправитель генерирует JPEG thumbnail (≤ 10KB,
  макс 320x320) и включает в `MediaPayload`. Получатель видит
  превью мгновенно, полное изображение скачивает через iroh-blobs.
- **Голосовые заметки:** `MediaType::Audio` с `duration_secs`.
  Формат: Opus в OGG контейнере. Макс длительность: 15 минут.
- **Видео:** `MediaType::Video` с thumbnail + duration + dimensions.
  Формат: H.264/H.265 в MP4. Макс размер: 100 MB.
- **Шифрование файлов:** файлы ≥ 1 MB через iroh-blobs шифруются **per-file ключом из ratchet**
  (§6.2, M19a, решение A12): blob = ciphertext, в `MediaPayload.hash` / `FileStart.hash` — хэш
  ciphertext, ключ — внутри зашифрованного сообщения. Без этого содержимое шло бы под
  классическим TLS iroh и было бы доступно любому, кто знает хэш. В hidden-профилях (§5.5.9)
  файлы ≤ 10 MB — «медленной полосой» через хопы, крупнее — direct с предупреждением

Приватность: thumbnail включён в зашифрованное сообщение —
relay/сеть видят только размер конверта, не содержимое.

### 6.12 Link previews (M28)

Когда пользователь отправляет URL, клиент может сгенерировать превью:

- **Генерирует отправитель** (не получатель!) — получатель НЕ делает
  HTTP запрос к серверу ссылки, чтобы не раскрывать IP/активность
- Отправитель скачивает Open Graph метаданные (title, description, image)
- Thumbnail: JPEG ≤ 10KB, включён в `LinkPreviewPayload`
- **В профиле `hide_ip` (по умолчанию, §5.5) и в hidden mode превью — opt-in, по умолчанию
  выключено:** генерация превью = HTTP-запрос отправителя к серверу ссылки со своего IP, что
  обходит relay-only режим и раскрывает IP владельцу сайта (M19b). Включивший превью получает
  предупреждение в настройках
- **Opt-out** остаётся и в обычном профиле: настройка "не генерировать link previews" (privacy mode)

### 6.13 Редактирование и удаление сообщений (M28)

```
Редактирование:
  Alice отправляет: Edit { message_id: <id>, new_text: "исправленный текст" }
  Bob обновляет сообщение в UI, показывает "(ред.)"

Удаление:
  Alice отправляет: Delete { message_id: <id> }
  Bob удаляет сообщение из UI, показывает "сообщение удалено"
```

**Ограничения:**

- Редактировать/удалять можно только свои сообщения
- Окно редактирования: 24 часа после отправки
- Удаление — "мягкое": tombstone остаётся в истории (контакт видел
  оригинал, нечестно делать вид что сообщения не было)
- В disappearing чатах: Edit/Delete не продлевают TTL
- Статус: типы есть, обработки нет; `↑` в CLI для редактирования — M28

### 6.14 Delivery и Read receipts (Delivered — M19; Read/Played — M28)

Раздельные статусы доставки:

```
Отправлено  → [✓]   (локально сохранено; DeliveryState::Sent / Queued / Relayed)
Доставлено  → [✓✓]  (DeliveryState::Delivered — по Message::Ack { counter } от устройства)
Прочитано   → [✓✓]  (ReceiptStatus::Read — пользователь открыл чат)
Воспроизвед.→ [▶✓]  (ReceiptStatus::Played — для аудио/видео)
```

> Статус: в бете «доставлено» — транспортное событие `DeliveryState { id, Sent | Queued | Relayed |
> Delivered }` (M19 п.11, по `Message::Ack { counter }`, который также нужен для dequeue после
> подтверждения), а не receipt по этому разделу. `ReceiptPayload::{Delivered, Read, Played}` как
> зашифрованные сообщения — M28.

- Read receipt — уведомление контакта; таймер disappearing messages (п. 6.7) стартует по
  локальному `mark_read`, независимо от того, отправляется ли receipt
- **Privacy:** read receipts можно отключить per-contact или глобально.
  Если отключены — отправляется только Delivered, не Read.
- Receipts — отдельные зашифрованные сообщения (не metadata)

### 6.15 Typing indicators — приватность (M28)

`Typing(bool)` раскрывает паттерны активности (когда пользователь
печатает, думает, переписывает).

- **По умолчанию: включены** (ожидаемый UX)
- **Настройка:** отключаемы глобально или per-contact
- Если отключены — `Typing` сообщения не отправляются
- **Не** отправляются в disappearing чатах с TTL < 5 минут
  (слишком детальная утечка активности)
- Rate limit: максимум 1 Typing event / 3 секунды
- Через relay (`hide_ip`, mailbox) typing не депонируется — только по живому соединению

