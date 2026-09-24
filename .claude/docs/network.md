# Сетевой слой (aira-net, aira-relay, aira-onion)

> Полная спека: `spec/03-network.md` (§5, §5.1.1, §5.5), `spec/13-threat-model.md` (§11, §11A, §11B).
> Актуальное состояние кода и планы — `.claude/docs/release-audit-2026-09.md` §3, §4, §8.2, §8.6, §8.7.
> Решения владельца 24.09.2026 — `.claude/docs/audit-2026-09/owner-decisions.md`.

## Что есть в коде (v0.3.5) и что запланировано

| Компонент | Код сейчас | План |
|---|---|---|
| iroh | 0.97, `presets::N0` (публичные relay n0 — отключаются для 0.9x **30.09.2026**) | **1.2** (M18), свой `AiraPreset` + собственный iroh-relay/iroh-dns-server (M20) |
| Endpoint в демоне | **не поднимается** (блокер №0: `SendMessage` пишет только в redb) | M19: `net_task`, `SessionManager`, `pending_drain` |
| Скрытие IP | endpoint с IP-транспортами, hole punching раскрывает IP контакту | **`hide_ip = true` по умолчанию**: `clear_ip_transports()`, direct — per-contact opt-in; invitation link без IP (M19/M19b) |
| Relay store-and-forward | `relay.rs` mailbox v1 без аутентификации, in-memory; `build_router` регистрирует `RelayServer` в **каждом клиенте** | удалить из клиента (M19); `aira-relay` mailbox v2 (M21): две коробки на пару, owner/sender-ключи, seq, квоты, intro-mailbox с PoW |
| DPI-транспорты `transport/*` | obfs/mimicry/cdn/reality/tor — не встраиваются в iroh, не собираются в CI, криптографически несостоятельны | **удаляются в M18** (решение владельца); обфускация возвращается как датаграммный `CustomTransport` iroh для мостов (M24c) |
| Community relays | — | M24a.1 каталог + server-relay, M24a.2 роли relay/mailbox в клиенте (opt-in) |
| Onion-маршрутизация | — | M24b Aira Onion v1 (все пиры — хопы), M24d mix-профиль |

## Две сущности «relay» — не путать

- **iroh-relay** — stateless транспорт (WebSocket/TLS + QAD, без STUN); держит соединения, не данные; нужен всем за NAT и браузеру.
- **aira-relay** — mailbox v2 (store-and-forward для офлайн-получателя); один бинарь со встроенным iroh-relay, режимы `--mode full|transport|mailbox` (M21).
- У iroh ровно **один home relay на endpoint**; при падении — бесконечный backoff и стейл pkarr (issue n0-computer/iroh#4476) → watchdog re-home + 2–3 `RelayRef` у контакта.

## Скрытие IP и анти-паразитный форвардинг (M24b–M24d)

Дизайн — `.claude/docs/audit-2026-09/onion-antiabuse.md`. Ключевые правила:

- **Все пиры форвардят** (desktop unmetered — по умолчанию, ноутбук на батарее — share ×0.25, мобильные — только клиент, strict-страны — hidden mode).
- **Две iroh-идентичности**: чат-EndpointId из seed, хоп-EndpointId из локального RNG (иначе контакт найдёт IP в записях хопов).
- **Инварианты AP-1…AP-7** обязательны для любого форвардящего кода: нет exit; следующий хоп только из своей таблицы (никогда из адреса в пакете); ячейки фиксированные 1 KB; каждый байт под PoW-ключом с бюджетом; хоп никогда не источник; хранилище только по регистрации; ёмкость растёт с нагрузкой.
- Маршрут `S → G_s → M_s → H(mailbox) ← M_r ← G_r ← R`; профили fast / standard (дефолт) / mix.
- Глобального каталога relay/хопов нет (иначе блок-лист РКН): invitation link, `BridgeOffer` от контактов, rate-limited peer exchange, hidden mode.

## DoS защита (Connection Tiers, §11B)

| Tier | Кто | Лимиты |
|------|-----|--------|
| 1 | Контакты | Без ограничений |
| 2 | Известные пиры | 100 msg/min |
| 3 | Незнакомцы | 5 msg/min + адаптивный PoW (16→28 бит, `slot`) |

`ContactStamp` (hashcash над pseudonym_pk, истекает) даёт tier незнакомцу — M22. PoW на создание ключа **не делаем** (аудит §5.3).
`ratelimit.rs`/`ConnectionManager` в коде есть, но нигде не подключены (M22).

## ALPN

Код сейчас: `aira/1/{chat,file,handshake,relay}`. Релизный протокол v2: `aira/2/{chat,handshake,file,hop}`, `aira/2/relay` (aira-relay); `aira/1/relay` удаляется.

## Что iroh раскрывает (проверено по исходникам 1.2.0)

- `Endpoint::addr()` содержит LAN- и публичные IP → в invitation link класть только `EndpointAddr::new(id).with_relay_url(url)`.
- pkarr по умолчанию публикует только relay (`AddrFilter::relay_only`).
- `net_report` шлёт пробы до 5 relay из RelayMap → RelayMap клиента = свои 1–2 relay.
- QUIC Initial (ALPN, TLS-параметры) читаем любым наблюдателем (RFC 9001); ТСПУ фингерпринтит QUIC v1.
- iroh-relay: `accept_conn_limit/burst` не реализованы (только `client.rx`); IP клиента попадает в `info_span!` логов → `RUST_LOG=warn`.
