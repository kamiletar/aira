# SPEC §18-20: Открытые вопросы, соглашения, глоссарий

[← Индекс](../SPEC.md)

---

## 18. Открытые вопросы для обсуждения

1. **iroh EndpointId vs ML-DSA Identity** — стоит ли сделать ML-DSA ключ
   транспортной идентичностью, заменив Ed25519? Требует форка iroh или
   ожидания поддержки PQ в iroh. Пока: транспортный ключ устройства — `aira/iroh/secret/<device_index>`
   (§14.2), хоп-идентичность — отдельный локальный ключ (§5.5); связь с identity — через подписанный
   транскрипт handshake, включающий `EndpointId` обеих сторон (M19a).

2. ~~**Bootstrap нода** — self-hosted только или публичные? Нужен механизм
   обновления списка bootstrap нод без обновления бинарника.~~
   **Закрыт (аудит 2026-09, решения A3/F1/F2):** bootstrap-нод и списка «в бинарнике» нет.
   Discovery = pkarr-записи через собственный `iroh-dns-server` + свой iroh-relay на домене проекта
   (§5.1.1, M20); DHT — после релиза. Каталог relay сообщества (§5.3, M24a.1) подписан офлайн-ключом
   ML-DSA-65 (2-of-3 к 1.0), обновляется вместе с релизами и через `.well-known/aira-relay.json`;
   операторам без домена — IP + pin сертификата. Клиент держит в `RelayMap` только свои 1–2 relay
   (B3), каталог используется отдельно.

3. **Имена пользователей** — только псевдонимы в контакт-листе у каждого
   клиента, или глобальный namespace? Рекомендую локальные псевдонимы (проще,
   нет доверенной третьей стороны). В бете — только локальный alias (§6.17 — M28).

4. **Key Transparency / AKD (после 1.0)** — Safety Numbers (п. 6.9) решают задачу
   верификации между двумя людьми. Но как проверить что все контакты видят
   одинаковый публичный ключ (защита от targeted MITM только для одного пира)?

   Варианты:
   - **Auditable Key Directory (Signal KT)** — прозрачный журнал всех ключей,
     любой может проверить. Требует доверенного сервера — противоречит P2P.
   - **Gossip verification** — контакты "сплетничают" об увиденных ключах.
     Если Bob видит другой ключ Alice чем Carol — обнаружение MITM.
   - **Консистентность через pkarr/DNS** — подписанная запись identity с историей версий;
     ноды сравнивают версии (прежде — «DHT-based»).

   Рекомендация: оставить в открытых вопросах, решить после 1.0.

5. **IPFS для persistent file delivery** — сейчас файлы требуют оба пира
   онлайн (relay хранит только хэш, не файл; файлы ≤ 10 MB в hidden-профиле идут «медленной
   полосой» через хопы — §5.5.9). Опциональный IPFS-пиннинг мог бы
   позволить скачать файл пока отправитель офлайн. Требует:
   - Шифрование файла сессионным ключом перед публикацией (per-file ключ §6.2 уже есть)
   - Явное согласие пользователя (файл становится доступен на IPFS)
   - Нарушает pure P2P модель — должно быть строго opt-in

### 18.1 Открытые решения владельца (на 24.09.2026)

Сводный список и статус ответов — `.claude/docs/audit-2026-09/owner-decisions.md`
(16 решений принято 24.09, остальные — по рекомендации аудита). Открыто:

- **C1** — группы v2 (M25) до 1.0 (+3–4 нед., аудит покроет `group.rs`) или после с отдельным аудитом
- **C2** — подпись групповых конвертов: ML-DSA-65 псевдонимом или Ed25519 per sender key (§12.1, к M25)
- **C3** — модель мультидевайса: per-device сессии (Sesame) или handoff с арендой (§14.3c;
  определяет `Register { device_id }` в M21)
- **C6** — strict-список стран для авто-hidden mode и кто его ведёт (§5.5, к M24c)
- **C11** — имя фичи: «Aira Onion» / «скрытый маршрут»
- **C13** — браузер (§15.5, к M14): несовместимость БД 0.3.x, iOS Safari «не поддерживается»,
  seed между сессиями — vault, `aira-ipc`/`aira-node` выделяются в M19
- **B2/F10** — бюджет второго anchor-VPS и `relays.<domain>` (каталог/токены/проба) до беты
- **D1** — настройки GitHub-репозитория (rulesets `main`/`v*`, Dependabot, secret scanning) —
  действие владельца, не решение

---

## 19. Соглашения для Claude Code агента

- Язык кода: Rust edition 2021
- Язык комментариев в коде: английский
- Язык документации (README, SPEC): русский или английский
- Ветки: только `main` + PR (решение D9, 24.09.2026); `feat/*`, `fix/*` — рабочие ветки под PR;
  `dev` и `milestone/*` убраны из правил и CI; теги `v*` — через CI-job `verify`, ruleset на
  `main`/`v*`
- Коммиты: conventional commits (`feat:`, `fix:`, `chore:`, `docs:`)
- При добавлении крейта — проверить дату последнего коммита и количество
  скачиваний на crates.io
- При изменении крипто-кода — обязательно добавить/обновить тесты
- Не использовать `todo!()` без GitHub issue номера в комментарии

---

## 20. Глоссарий

| Термин | Значение |
|---|---|
| **Transport relay (iroh-relay)** | Сервер iroh (WebSocket/TLS 443 + QAD udp/7842), через который идут QUIC-пакеты пиров за NAT и в режиме `hide_ip`; сообщения не хранит. Свой — на домене проекта (§5.1.1, M20); anchor-relay проекта, community-server-relay, client-relay (§5.1.1, §5.3, M24a) |
| **Mailbox relay (`aira-relay`)** | Отдельный процесс/бинарник `crates/aira-relay` (M21): store-and-forward зашифрованных конвертов в pairwise-коробках (§6.3b, §6.5), intro-mailbox для `ContactRequest` (§13.1), push wake-up. С M24a — один бинарь со встроенным iroh-relay (`--mode full\|transport\|mailbox`) |
| **Mailbox (коробка)** | Очередь конвертов на mailbox relay для одного направления одной пары (`aira/relay/mailbox/v2/<dir>`); две коробки на пару (§6.5). В варианте A мультидевайса — одна на пару устройств (§14.3c) |
| **Hop (хоп)** | Нода, форвардящая onion-ячейки Aira Onion (§5.5, M24b) по своей таблице ключей (`HopSetup`); никогда не источник и не exit (инварианты AP-1…AP-7, §5.5.2). По умолчанию — desktop-ноды на unmetered-сети (share ×0.25 на батарее); мобильные — только клиент. Хоп-идентичность — второй `Endpoint`, ключ из локального RNG, не из seed |
| **Bridge (мост)** | Нелистингуемая точка входа для контактов (M24c): хоп или relay, известный только по invitation link (`bridge_hint`) или через E2E-канал контакта (`BridgeOffer`), с обфускацией первого хопа (`CustomTransport` iroh 1.2, `aira/bridge/obfs/v1`). Ответ на блок-листы: нет глобального каталога, который можно заблокировать целиком (§5.5.10) |
| **Hidden mode (скрытый режим)** | Модификатор класса ноды в strict-стране (авто по списку C6) или по выбору пользователя: не публикуется в peer exchange, не принимает чужие маршруты, форвардит только для контактов, не соединяется с нодами своей страны (модель I2P hidden mode); override — через Advanced с предупреждением (F5) |
| **`hide_ip`** | Настройка сети, по умолчанию `true` (решение A6): только relay-транспорты (`clear_ip_transports()`), прямые соединения — per-contact opt-in; invitation link без IP (A7); link previews — opt-in (§6.12) |
| **Профили сети** | `direct-per-contact` / `fast` (1+M+1) / `standard` (2+M+2, по умолчанию после M24b) / `mix` (Loopix, M24d) — вместо режимов транспорта §11A v1 (obfs4/mimicry/REALITY/Tor удалены) |
| **`ContactStamp`** | Hashcash-штамп над `pseudonym_pk ‖ epoch ‖ bits ‖ nonce` (§13.2c, M22): истекает (epoch = неделя), per-pseudonym, не меняет ключ и seed; даёт tier в очередях запросов незнакомцев, `HopSetup` и регистрации mailbox — не «уровень доверия» |
| **Pseudonym (псевдоним)** | Per-context keypair (ML-DSA-65 + X25519 + ML-KEM-768) из seed по счётчику `aira/pseudonym/<counter>/*`, `counter = (device_index << 28) \| local` (§12.6); контакты и группы видят псевдоним, не identity key |
| **`InvitationLink`** | `aira://add/<base64url(postcard(…))>` — стабильный псевдоним + `EndpointId` + 2–3 `RelayRef` + `fingerprint_hint` + `expires_at` + `ContactStamp` + подпись (§5.2, §12.6.5); QR в byte-mode; без IP |
| **`RelayRef`** | `{ url, endpoint_id, class, pin }` — ссылка на relay в приглашении и контакт-записи; 2–3 у разных операторов; `pin` — для relay без домена |
| **`MessageMeta`** | Единственный plaintext ratchet-конверта и формат `payload_bytes` в storage/IPC (`{ payload: PlainPayload, ttl, id, reply_to }`, §6.7) — один контракт для провода, демона, CLI, GUI и бота (M19) |
| **Эпоха (группы)** | Номер поколения Sender Keys группы; растёт при Add/Remove/Leave; входит в AAD конверта (§12.5) |

---

_Spec v0.5 — источники: RustCrypto ml-kem 0.3/ml-dsa 0.1.1, iroh 1.2 (n0), aws-lc-rs FIPS 140-3,
Signal PQXDH + SPQR (Eurocrypt 2025), Signal Sender Keys (libsignal `SenderKeyDistributionMessage`)
и Sesame (multi-device), SimpleX Chat (pairwise queues, private routing), I2P (participating
tunnels, hidden mode), Loopix/Nym (mix), Tor (hspow, bridges), Snowflake, Project Eleven PQC Rust
survey (July 2025), noq QUIC announcement (March 2026), NIST FIPS 203/204/205 (August 2024),
Threema protocol analysis (USENIX Security 2023), Meta Messenger E2EE design (2023),
Signal Key Transparency (2024), Matrix causal ordering lessons,
SoK multi-device messaging (IACR 2021), Wire MLS adoption retrospective_
