# Community relays: standalone `aira-relay`, режим relay в клиенте, резервирование — аудит (2026-09-23)

> Тема F фазы 3 аудита. HEAD `7726b46`, ветка `claude/vigilant-sagan-9kta8v`, workspace v0.3.5.
> Контекст: `../release-audit-2026-09.md` §3, §4.3, §5, §6.4, §8.2, §8.6; `relay-deploy-plan.md`, `pow-antiabuse.md`, `net-audit.md`.
> Граница с темой G (`onion-antiabuse.md`): onion-слой здесь не проектируется, только упоминается как роль; анти-паразитные
> ограничения (а)–(д) из постановки владельца встроены в архитектуру и проверены явно (§6.3).
> Статус: **готово** (2026-09-24). Разделы: 0 резюме · 1 прецеденты · 2 факты iroh-relay 1.2.0 · 3 UX оператора · 4 режим клиента · 5 резервирование · 6 угрозы и ограничения (а)–(д) · 7 код · 8 архитектура и правки планов · 9 не проверено.

## 0. Резюме

**Вердикт.** Два продукта владельца укладываются в одну архитектуру с тремя ролями — anchor-relay проекта, community-server-relay (VPS/домашний сервер) и client-relay (desktop с публичным IP) — при трёх жёстких условиях, которые диктует сам iroh 1.2 и прецеденты (Snowflake, SimpleX, chatmail, Nostr): (1) **один бинарь `aira-relay`** со встроенным `iroh-relay` (библиотечный `Server::spawn` + собственный `AccessControl`), mailbox v2, ACME, `/healthz`/метриками и регистрацией в подписанном каталоге — а не два systemd-юнита, как сейчас в M20/M21; (2) **допуск по сетевому подписанному токену**, который любой relay проверяет офлайн (в iroh отправитель всегда идёт на home relay получателя, поэтому токен должен быть общесетевым, а `shared_token`/`allowlist` для сообщества непригодны); (3) **client-relay (opt-in роль `relay` поверх дефолтной `hop`, тема G) = «Snowflake для Aira»**: только транспорт (iroh-relay + QAD); роль `mailbox` — отдельный opt-in в Advanced (решение владельца, §8.1); self-signed сертификат + pin, эфемерная запись через брокер, отдельный процесс и отдельный ключ, по умолчанию выключен на мобильных/metered/в «строгих» странах, с экраном согласия о публикации IP.

**Главное ограничение резервирования:** у iroh **ровно один home relay на endpoint** (`socket/transports/relay/actor.rs:910-919`), «N home relay» не существует, а при падении relay клиент бесконечно переподключается и продолжает рекламировать мёртвый URL (issue #4476, открыт). Поэтому резервирование транспорта = быстрый re-home по watchdog (30 с) + републикация адреса + список 2–3 relay в записи контакта (аналог NIP-65), а N-of-M применимо только к mailbox (N=2 из 2–3 relay разных операторов, дедуп по `envelope_id`). Client-класс никогда не получает mailbox и не становится home relay без явного opt-in — иначе нестабильность residential-узлов превращается в потерю доставки.

**Что нового по сравнению с предыдущими отчётами:** `accept_conn_limit/accept_conn_burst` в iroh-relay ≤ 1.2.0 **не реализованы** (план M20 п.4 опирается на no-op); `cert_mode = "Reloading"` есть в 1.2.0 (закрывает вопрос hot-reload из `relay-deploy-plan.md`); relay «на голом IP» невозможен через ACME (форк `tokio-rustls-acme` знает только `Identifier::Dns`, LE IP-сертификаты не достижимы) — только self-signed + pin через `CaTlsConfig::custom_server_cert_verifier`; push-URL mailbox v2 — единственный outbound/SSRF-вектор relay и нуждается в allowlist (ограничение (а)); в registry уже iroh/iroh-relay **1.2.0**, план говорит 1.1.

**Что должно попасть до беты** (иначе после релиза ломается формат): `RelayRef`-список в `InvitationLink`/`ContactInfo`/`MailboxConfig` (M19b/M21), `RelayHello` с классом/оператором/`min_client_version` (M21), токен допуска и его заглушка (M20 → M22), `push_allowlist` (M21). Сам каталог, server-relay сообщества и client-режим — **Milestone 24a «Community relays»** после беты (фаза M24a.1 — каталог и server-relay ≈ 2–3 недели, фаза M24a.2 — opt-in роли `relay`/`mailbox` в клиенте ≈ 3 недели; M24b–M24d — темы G: Aira Onion v1, мосты/обфускация, mix-профиль), плюс ≈ 3–4 недели сверх M21 на standalone-продукт (Docker/musl, `init/doctor/register`, `docs/RELAY.md`).

**Блокеров релиза в этой теме нет.** Условные: без правок §8.3–8.5 до беты — миграция форматов после релиза; блокер плана «RelayServer в каждом клиенте» (net-audit §6) остаётся в силе и здесь подтверждён как антипример client-relay.

### 0.1 Топ-находки

| # | Severity | Находка | Доказательство | Последствие | Исправление | Milestone |
|---|---|---|---|---|---|---|
| 1 | HIGH | Один home relay на endpoint; при падении — бесконечный backoff и стейл pkarr-запись | `iroh-1.2.0/src/socket/transports/relay/actor.rs:9, 326-354, 392-399, 910-919`; `net_report.rs:791-815`; issue n0-computer/iroh #4476 (открыт, 2026-08-17) | «резервирование client-relay» как N-of-M home relay невозможно; падение нестабильного relay = 1–2 мин недоставки и стейл-адрес | watchdog `home_relay_status` → `remove_relay`/re-home/републикация; список 2–3 `RelayRef` у контакта с повторным lookup; client-класс — home relay только opt-in; тест на #4476 | M20 (watchdog, тест), M21 (RelayRef), M24a.1 |
| 2 | HIGH | Схема допуска (в): сетевой токен `AiraRelayToken` с офлайн-проверкой в `AccessControl` | `iroh-relay-1.2.0/src/server.rs:224-233, 256-278, 285-310, 350-357`; `main.rs:160-197` (CLI: только everyone/allowlist/denylist/http/shared_token) | без токена любой iroh-endpoint использует relay сообщества; `shared_token` в open-source бинаре — не секрет; `allowlist` не масштабируется; отправитель должен быть допущен на **любой** relay | выдача токенов на anchor (`POST /token`, PoW, 24 ч, scope, привязка к EndpointId), проверка во встроенном `AccessControl`; `access.http.url → /relay-auth` для stock iroh-relay; denylist в каталоге | M20 (заглушка), **M22** |
| 3 | HIGH | Push-URL mailbox v2 — единственный outbound/SSRF-вектор relay (ограничение (а)) | аудит §4.3 `NotificationEndpoint::UnifiedPush { url }`; `spec/04-protocol-wire.md:222-236` | relay сообщества можно заставить слать HTTP на произвольные хосты (exit/SSRF/скан) | `push_allowlist`, запрет редиректов/приватных диапазонов, пустое тело, лимит частоты; в `--mode transport` push/ACME отсутствуют в коде | **M21** |
| 4 | HIGH | Relay без домена: LE IP-сертификаты недостижимы, нужен self-signed + pin | `n0-computer/tokio-rustls-acme` `src/acme.rs` `enum Identifier { Dns(String) }` (main, 2026-09-23); `iroh-relay-1.2.0/src/tls.rs:11-135` (`CaTlsConfig` один на endpoint; `custom_server_cert_verifier` — «advanced»); LE IP GA 2026-01-15 только `shortlived` | client-relay и «server на голом IP» требуют pin-верификатора в клиенте; браузерные клиенты такие relay использовать не могут; `AiraPreset` без поля `ca_tls_config` не расширяем | `RelayEntry.pin`/`RelayRef.pin` (SPKI SHA-256) в каталоге и приглашении; верификатор «SNI/IP → pin, иначе webpki»; поле в `AiraPreset` заложить в M20 | M20 (поле), **M24a.1** |
| 5 | MEDIUM | `[limits] accept_conn_limit/accept_conn_burst` — no-op в iroh-relay ≤ 1.2.0 | `iroh-relay-1.2.0/src/server.rs:486-503` («Not currently implemented»), нет использований в `server/http_server.rs` | M20 п.4 и `relay-deploy-plan.md` Этап 3 считают флуд соединениями ограниченным — он не ограничен | nginx `limit_conn`/`limit_req` (вариант A/B) + fail2ban; в `aira-relay` — свой accept-лимит и `max_clients` в `AccessControl` | **M20** (текст), M21 |
| 6 | MEDIUM | Список relay должен попасть в `InvitationLink`/`ContactInfo`/`MailboxConfig` до беты | `crates/aira-net/src/discovery.rs:20-25` (нет relay-полей); `spec/18-milestones.md:547-549, 711-713` | иначе ввод каталога/N-of-2 после релиза ломает формат приглашений и контактов | `RelayRef { url, endpoint_id, class, pin }` ×2–3, единое поле; правило «разные операторы» | M19b п.4, **M21** п.7 |
| 7 | MEDIUM | Client-relay — отдельный процесс, не библиотека в демоне | `iroh-relay-1.2.0/Cargo.toml [features] server` (≈15 доп. зависимостей); `crates/aira-daemon/src/main.rs:100-160` (демон держит seed/ratchet) | входящий порт в процессе с секретами; рост поверхности атаки демона; падение relay роняет мессенджер | `aira-relay --mode transport` как супервизируемый дочерний процесс; CI-guard «daemon не линкует `iroh-relay/server`, ffi не зависит от `aira-relay`» | M24a.2 |
| 8 | MEDIUM | Один бинарь `aira-relay` вместо двух юнитов; в `release.yml` нет musl/aarch64/Docker | `spec/18-milestones.md:657-661, 691-693`; `.github/workflows/release.yml:23-32, 57, 264-270` | два процесса и два конфига — барьер для энтузиаста; нет образа = нет сообщества | встроить `iroh-relay` через `Server::spawn` (`server.rs:691`, пример `iroh-1.2.0/src/test_utils.rs:51-84`); musl x86_64/aarch64 + `ghcr.io` multi-arch + attestation; `deploy/`, `docs/RELAY.md` | **M21** |
| 9 | MEDIUM | Ограничение (г) требует данных, которых у клиента нет: страна и metered | `iroh-1.2.0/src/net_report/report.rs:18-38` (нет страны); FFI `crates/aira-ffi/src/runtime.rs:33,95` | без списка «строгих стран» и страны по IP режим либо предложат в РФ/КНР, либо никому | `strict_countries` в подписанном каталоге + `X-Aira-Country` из `/token` + локаль; Android — cfg-исключение | M22 (данные), M24a.2 |
| 10 | LOW | `cert_mode = "Reloading"` есть в CLI 1.2.0 | `iroh-relay-1.2.0/src/main.rs:63-67, 673-684` | вариант B из `relay-deploy-plan.md` не нуждается в deploy-hook на рестарт | в M20 п.3 вариант B → `Reloading` | M20 |
| 11 | LOW | В registry iroh/iroh-relay 1.2.0 (2026-09-09), план — 1.1 | `~/.cargo/registry/src/*/iroh-1.2.0/Cargo.toml`; GitHub release v1.2.0 (#4501 `auth_denied_reason`) | `auth_denied_reason` нужен для UX отказа в допуске | `iroh = "1.2"`, `iroh-relay = "1.2"` | M18 |
| 12 | LOW | Спека: `bootstrap/` в структуре репо не существует; §5.3 «signed update» списка нод; §20 вопрос про bootstrap | `spec/17-cross-platform.md:196`; `spec/03-network.md:85-89`; `spec/20-appendix.md:13` | устаревшие термины и открытый вопрос, закрываемые каталогом | `deploy/`; §5.3 → «каталог relay»; §20 п.2 закрыть ссылкой на §8.1 | M20 п.8 / M24a.1 |

## 1. Прецеденты (community-run инфраструктура)

Источники: веб-страницы прочитаны 2026-09-23 (WebSearch/WebFetch через прокси; часть доменов заблокирована egress-прокси — такие факты помечены «по памяти/сниппет» и вынесены в §9). Дата в скобках — дата публикации источника, если известна.

| Проект | Как поднимается relay сообществом | Как relay попадают к пользователям | Резервирование / нестабильность | Ограничение абьюза («не прокси») | Урок для Aira |
|---|---|---|---|---|---|
| **Delta Chat / chatmail** | `cmdeploy` (pyinfra) на «ssh-reachable host»: ставит Postfix, Dovecot, OpenDKIM, nginx, filtermail, acmetool (TLS), **iroh-relay**; «zero state» — письма авто-удаляются, метаданные не собираются (README `github.com/chatmail/relay`, 2026) | Публичный список `chatmail.at/relays` (~15 relay в 2026: nine.testrun.org — дефолтный onboarding, mehl.cloud, chat.adminforge.de, …); **часть relay намеренно не публикуется** — «some countries tried to block published relays» (сниппет поиска, 2026). `cmrelayinfo` (hpk42, 2026) машинно снимает возможности каждого relay: iroh relay URL, TURN, `maxsmtprecipients`, storage quota | С релиза 2026-03-31 («Zero metadata»): **несколько relay на профиль**, «if one relay goes offline, is blocked, or disappears, your contacts can still reach you through another one»; смена relay доносится до контактов автоматически (сниппет delta.chat, 2026-03-31). Onboarding пытается настроить **3 relay сразу** (chatmail/core #8707); «autorelays» помечаются длиной пароля 23 (PR #8701, временный хак) | filtermail принимает только OpenPGP-шифрованные письма с корректным DKIM; strict TLS; лимиты отправки на пользователя; relay — только MTA, никакого выхода в интернет | Один командный деплой + публичный каталог с явно «неопубликованными» relay + 2–3 relay на identity + машинно-читаемый документ возможностей relay |
| **SimpleX SMP/XFTP** | `smp-server init -y -l --fqdn=smp1.example.com --password=…` (или `--ip`), install-скрипт / Docker / Linode; systemd; daily CSV-статистика; `[INFORMATION]` — веб-страница оператора (docs/SERVER.md, 2026) | Адрес сервера **несёт pin**: `smp://<fingerprint>[:<password>]@<host>[,<onion>]` — fingerprint офлайн-CA, домен и публичный PKI **не нужны**; адреса серверов входят в ссылки-приглашения | Preset-операторы SimpleX Chat Ltd + Flux (v6.2, 2024-12); приложение **намеренно берёт серверы разных операторов** в каждой связи (private routing); пользователю рекомендуют self-host + preset для «crowd cover» | «Server password» гейтит **только создание очередей**; Conditions of use для preset-операторов; логи не хранить, in-memory рекомендуется | Pin в адресе (решает «relay на голом IP»), пароль создания ≈ токен допуска Aira, правило «разные операторы на одну identity» |
| **Nostr** | Любой relay-софт; NIP-11 — JSON «relay information document» на том же URL: `limitation.{max_message_length, auth_required, payment_required, restricted_writes, min_pow_difficulty, …}`, `contact`, `software`, `version`, `terms_of_service`, `relay_countries` (nips/11.md, 2026) | NIP-65 kind:10002 — список relay пользователя с маркерами `read`/`write`, **«2–4 relay каждой категории»**, outbox-модель: пишем в write-relay автора, читаем упоминания из read-relay (nips/65.md) | Избыточность = список 2–4; клиенты «spread kind:10002 to as many relays as viable» | Спам решают paid relays, NIP-42 auth, WoT — не PoW | Список relay в записи identity (наш pkarr/InvitationLink) + документ возможностей relay (`/.well-known/aira-relay.json`) |
| **Tor: Snowflake (standalone proxy)** | Один бинарь/Docker; флаги `-capacity`, `-broker`, `-relay` (default `wss://snowflake.torproject.net/`), **`-allowed-relay-hostname-pattern`** (default `snowflake.torproject.net$`), `-nat-probe-server`, `-ephemeral-ports-range`, `-summary-interval`, `-unsafe-logging`, `-allow-non-tls-relay` (pkg.go.dev, snowflake/v2/proxy, 2026) | Брокер сводит клиентов с прокси; прокси **не публикуются списком** | Прокси эфемерны по определению; NAT-типирование: прокси проверяется probe-сервером за symmetric NAT → `unrestricted`/`restricted`; брокер даёт restricted-клиентам только unrestricted-прокси (Snowflake paper 2024; arXiv 2609.12242) | **Жёстко зашитое назначение**: прокси соединяется только с Tor bridge, никогда с произвольным хостом: «If a client could cause a Snowflake proxy to make a WebSocket connection to any IP address, then people would misuse Snowflake proxies to attack third-party WebSocket applications» (tor-talk, 2021); прокси — entry, не exit → «unlikely… face liabilities» | Модель «побыть прокси одной кнопкой» = наш client-relay: фиксированное множество назначений, `capacity`, NAT-проба, никаких списков с residential-IP в открытом виде |
| **Tor bridges / rdsys** | Bridge = обычный relay с флагом | BridgeDB→rdsys раздаёт бриджи «ведрами» через https/email/moat, чтобы цензор не перечислил все (blog.torproject.org; moat сворачивается, 2024–2025) | — | — | Каталог relay для стран с цензурой должен раздаваться дозированно/out-of-band, не одним публичным файлом |
| **Tox** | `tox-bootstrapd.conf`: `enable_tcp_relay = true`, `tcp_relay_ports = [443, 3389, 33445]` («443 (https) and 3389 (rdp) ports are very common among nodes»), `keys_file_path` «like a password» (TokTok/c-toxcore, 2026) | Публичный список `nodes.tox.chat` (JSON, статус UDP/TCP на каждый узел; страница заблокирована прокси — по памяти); требование: «highly available, static IP/domain, static port, static key» | Нет резервирования на уровне протокола — pseudo-offline, главная жалоба пользователей | Bootstrap-нода не хранит данных; TCP relay — только транспорт | TCP-relay как отдельный флаг; в публичный список — только узлы со стабильным адресом; статус-страница |
| **Session / Oxen** | Service node = стейк **15 000 OXEN → 25 000 SESH** (docs.oxen.io / token.getsession.org, 2025–2026); swarm-хранилище по pubkey получателя | Список узлов — из блокчейна | Swarm = несколько копий | Экономический Sybil-барьер | Не применимо (у Aira нет токена) → Sybil-барьер = история uptime + разнообразие операторов + ручное продвижение в класс `server` |
| **Matrix (continuwuity)** | v26.8.1 (2026-08-22), Rust; open registration требует флага `yes_i_am_very_very_sure_i_want_an_open_registration_server_prone_to_abuse` + compile-фичи | Партнёрские community-homeserver'ы (federated.nexus и др.) | Федерация | «Открыто по умолчанию» = абьюз — регистрация гейтится | Community relay с `access = "everyone"` в каталог не пускать |
| **Yggdrasil** | Любой узел с публичным адресом добавляет строку в git-репо `yggdrasil-network/public-peers` (файлы по регионам/странам) + машинно-читаемый `pubpeers` | Git-репо; «pick peers as close to you geographically as possible» | Клиент держит несколько пиров | — | Git-каталог работает, но ручной; география/регион — обязательное поле записи |
| **Tailscale DERP** | `derper` флаги: `-hostname`, `-certmode manual|letsencrypt`, **`-acme-ip-certs`** (LE-сертификаты на IP), `-stun-port 3478`, **`-verify-clients` / `-verify-client-url`** (admission controller), `-mesh-with` / `-mesh-psk-file` (mesh внутри региона), `-accept-connection-limit/-burst` (derper.go, main, 2026) | DERP map от координационного сервера; кастомная map с `OmitDefaultRegions`, `HomeParams.RegionScore` | Home DERP по latency; при падении узла — другой узел региона (mesh), при падении региона — следующий регион (сниппет docs, 2026) | Только форвардинг WireGuard между узлами tailnet; verify-clients | Admission-URL = `access.http.url` iroh-relay; mesh у iroh-relay **нет** (§2) — резервирование только на клиенте |
| **iroh (n0)** | `iroh-relay --features server`, Docker `n0computer/iroh-relay`; managed relays n0 с 06/2026 аутентифицированы по умолчанию (rcan-токены) — см. `relay-deploy-plan.md` | Публичные relay n0 — «development and hobby», 0.9x отключаются 30.09.2026 | Docs `add-a-relay`: «run at least two relays in different geographic regions… clients try multiple relays automatically»; «each relay handles up to 60,000 concurrent connections» (сниппет, 2026). **Issue #4476 (открыт, 2026-08-17, 1.0.3)**: после re-home клиент «wedged in connecting», без retry/fallback, pkarr-запись продолжает рекламировать мёртвый relay | `access` (allowlist/denylist/shared_token/http), `[limits]` | См. §2 — факты по исходникам 1.2.0 |
| **I2P (hidden mode)** | — | — | — | «Strict countries» (42 страны; критерий Freedom House: Civil Liberties ≤ 16 или Internet Freedom ≤ 39): роутер **автоматически** уходит в hidden mode — не публикует routerInfo, не принимает participating tunnels, не соединяется напрямую с роутерами своей страны (i2p.www, restrictive-countries) | Готовый прецедент для ограничения (г): режим relay по умолчанию выключен в «строгих» странах |
| **Let's Encrypt IP-сертификаты** | GA **2026-01-15**: сертификаты на IPv4/IPv6 только в профиле `shortlived` (6 дней / 160 ч), валидация только `http-01`/`tls-alpn-01` (dns-01 недоступен) (сниппеты letsencrypt.org, 2026) | — | — | — | Теоретически «relay на голом IP с публичным сертификатом» возможен, но ACME-клиент iroh-relay этого не умеет (§2, F2.3); sslip.io/nip.io — **не выход**: намеренно вне PSL, квота LE на sslip.io (50 000/нед) исчерпывается (issue cunnie/sslip.io #108) |

**Сводный вывод по прецедентам.** Все живые «community-relay» сети сходятся к пяти вещам: (1) один командный деплой с встроенным TLS (cmdeploy/acmetool, smp-server init, derper letsencrypt); (2) адрес relay несёт **pin** или relay доступен по домену — третьего не дано; (3) **2–4 relay на identity** в самой записи identity (NIP-65, Delta multi-transport, SimpleX preset-операторы), а не «один home relay»; (4) допуск гейтится дешёвым секретом/токеном (SMP password, derper `-verify-clients`, n0 rcan) — «открытый relay» считается ошибкой (continuwuity, chatmail-unlisted); (5) эфемерные волонтёрские прокси (Snowflake) **никогда** не открывают произвольных соединений и не публикуются поимённо, а сводятся брокером с учётом NAT-типа.

## 2. Факты iroh / iroh-relay (сверено по исходникам в `~/.cargo/registry`)

В `~/.cargo/registry/src/index.crates.io-*/` лежат **iroh 1.2.0, iroh-relay 1.2.0, iroh-base 1.2.0, iroh-dns 1.3.0, pkarr 5.0.4, portmapper 0.15.0** (а не 1.1, как в плане M18/M20) плюс iroh 0.97.0 из текущего `Cargo.lock`. Всё ниже сверено по 1.2.0 (`R = ~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f`). GitHub Releases: v1.2.0 опубликован 2026-09-09 (тег 2026-09-11), из relay-значимого — только `RelayStatus::auth_denied_reason` (#4501), breaking changes не заявлены (страница релиза, прочитана 2026-09-23). Факты из `relay-deploy-plan.md` (порты, режимы cert, форма `[limits]`, маршруты) в 1.2.0 подтверждаются; ниже — только новое или уточнённое.

### 2.1 Серверная часть (`iroh-relay --features server`)

- **Конфиг** (`iroh-relay-1.2.0/src/main.rs:92-158`): `enable_relay` (false → «holepunching-only relay servers»: только QAD, никакого форвардинга — `:96-104`), `http_bind_addr`, `tls`, `enable_quic_addr_discovery` (требует `tls`), `limits`, `enable_metrics`, `metrics_bind_addr`, `key_cache_capacity`, `access`.
- **Допуск** (`main.rs:160-197`): `access = "everyone"` | `access.allowlist = [EndpointId]` | `access.denylist` | `access.http.url` (+ `bearer_token`; POST с `X-Iroh-Endpoint-Id`, ответ `200` + текст `true`) | `access.shared_token = ["…"]` (Bearer-заголовок или `?token=`; env `IROH_RELAY_ACCESS_TOKEN` заменяет весь список; «does not support revocation other than updating the config and restarting», README). CLI-бинарь **не умеет** ничего сложнее этих четырёх режимов.
- **TLS** (`main.rs:395-457`): `cert_mode = "Manual" | "LetsEncrypt" | "Reloading"` — `Reloading` есть в 1.2.0 (`main.rs:63-67`, ветка `:673-684`: `reloading_resolver(…, DEFAULT_CERT_RELOAD_INTERVAL)` → `CertConfig::Manual` с перезагружаемым резолвером). Это **закрывает открытый вопрос `relay-deploy-plan.md` §«Открытые вопросы»** («перезагружает ли Manual сертификаты без рестарта»): для варианта B (TLS-терминация nginx, certbot) ставить `cert_mode = "Reloading"`, deploy-hook на рестарт не нужен. `hostname` — строка или список (`:411-412`, `string_or_seq`) → несколько имён в одном сертификате. `dangerous_http_only` — только для `--dev`.
- **[limits]** (`main.rs:506-536`): `accept_conn_limit`, `accept_conn_burst`, `client.rx.{bytes_per_second, max_burst_bytes}`. ⚠️ **F2.1 [MEDIUM]** — в библиотеке: `// TODO: accept_conn_limit and accept_conn_burst are not currently implemented` (`iroh-relay-1.2.0/src/server.rs:486`), поля документированы как «Not currently implemented, setting this has no effect» (`server.rs:489-503`); ни одного использования в `server/http_server.rs`. Работает только per-client token-bucket на **входящие байты** (`ClientRateLimit`, `server.rs:505-524`; live-обновление `RelayService::set_client_rate_limit`, `server/http_server.rs:940`). *Последствие:* `accept_conn_limit = 50.0 / accept_conn_burst = 200` из `relay-deploy-plan.md` Этап 3 и M20 п.4 (`spec/18-milestones.md:668-669`) **ничего не ограничивают**; флуд соединениями на anchor-relay гасится только QUIC/TLS-стеком и ОС. *Исправление:* в M20 — `limit_conn`/`limit_req` в nginx `stream`/`http` (вариант A/B) + fail2ban по логам; в `aira-relay` (M21) — встроенный `AccessControl` с подсчётом соединений на EndpointId и глобальным лимитом accept/с (см. 2.2). Целевой milestone: **M20** (правка текста п.4) / **M21** (реализация).
- **Маршруты** (`http.rs:13-15`, `server.rs:738-740, 824, 1172`): `/relay` (+ `/derp`), `/ping`, `/healthz`, `/generate_204`. **Метрики** (`server/metrics.rs:18-144`): `bytes_sent/recv`, `send_packets_*`, `accepts`, `disconnects`, `unique_client_keys`, `bytes_rx_ratelimited_total`, `conns_rx_ratelimited_total`, `qad_*`, `http_connections*` — этого достаточно для операторского дашборда без своих метрик.
- **Логи**: сервер оборачивает каждое соединение в `info_span!("conn", peer = %peer_addr)` (`iroh-relay-1.2.0/src/server/http_server.rs:499`) — **IP клиента попадает в логи на уровне `info`**. Для `docs/RELAY.md`: дефолт `RUST_LOG=warn` (или `iroh_relay=warn`); в `aira-relay` фильтр по умолчанию `warn` для `iroh_relay::server`, `info` — только для отладки; `[log] client_ips = false` в конфиге (§3.2) означает именно это.
- **Mesh между relay отсутствует**: `grep -ri mesh iroh-relay-1.2.0/src` пуст. Relay форвардит кадры **только между клиентами, подключёнными к нему** (в отличие от Tailscale DERP `-mesh-with`). Следствие для резервирования — §5.

### 2.2 Встраивание relay-сервера в свой бинарь (основа для `aira-relay`)

- `iroh_relay::server::Server::spawn(ServerConfig)` (`server.rs:691`); `ServerConfig { relay: Option<RelayConfig>, quic: Option<QuicConfig>, metrics_addr }` (`:111-123`); `RelayConfig { http_bind_addr, tls: Option<TlsConfig>, limits, key_cache_capacity, access: Arc<dyn DynAccessControl> }` (`:127-147`); `TlsConfig::new(addr, CertConfig)` (`:462-480`); `CertConfig::LetsEncrypt { acme_config, server_config_builder } | Manual { server_config }` (`:527-545`); `AcmeConfig::letsencrypt(prod).domains(..).contact(["mailto:…"]).cache_path(..)` (`:548-609`); `QuicConfig::new(addr)` берёт TLS из `RelayConfig::tls`, без TLS «the QUIC server will fail to spawn» (`:430-445`). Минимальный рабочий пример встраивания с self-signed сертификатом — `iroh-1.2.0/src/test_utils.rs:51-84` (`iroh_relay::server::testing::self_signed_tls_certs_and_config()`).
- **Кастомный допуск** — трейт `AccessControl` (`server.rs:285-310`): `async fn on_connect(&ClientRequest) -> Access` + `on_disconnect(EndpointId, ConnectionId)`; `Access::Deny { reason: Option<String> }` (`:350-357`), причина доходит до клиента как `RelayStatus::auth_denied_reason()` (`iroh-1.2.0/src/endpoint.rs:1976`). `ClientRequest` даёт `endpoint_id()` — **уже доказанный relay-handshake'ом** (`:224-233`), `protocol_version()`, `uri()`, `query_pairs()`, `headers()`, `auth_token()` (Bearer или `?token=`, `:256-278`); `ConnectionId` + `on_disconnect` позволяют считать одновременные соединения на EndpointId (`:150-176`, `OnDisconnectGuard :360-378`). ⇒ **F2.2 [INFO, ключевой факт]**: встроив iroh-relay как библиотеку, `aira-relay` может проверять **подписанный токен допуска Aira офлайн** (по публичному ключу из каталога) без `access.http.url` и без внешнего сервиса — это и есть схема (в) в §6.3.

### 2.3 Клиентская часть (iroh 1.2.0)

- **Один home relay на endpoint.** `RelayMode::{Disabled, Default, Staging, Custom(RelayMap)}` (`endpoint.rs:1985-1995`); `Endpoint::insert_relay/remove_relay` на лету (`:992-1011`); `home_relay_status()` → `Vec<RelayStatus>` с `last_error`/`auth_denied_reason` (`:1384-1401`); `online()` = хотя бы один home relay подключён (`:1366-1380`). Home relay выбирает net_report: минимальная latency за окно `MAX_AGE` с «липкостью» — старый relay сохраняется, если новый не лучше чем на треть (`net_report.rs:791-815`); если отчёт пуст — остаёмся на текущем (`socket.rs:1962-1965`). Актор home relay «never exits» и переподключается с экспоненциальным backoff **10 мс → 16 с, jitter, без предела попыток** (`socket/transports/relay/actor.rs:9, 326-354, 392-399`); не-home relay закрываются после 60 с простоя (`:68`); ping каждые 15 с (`:74`). ⇒ **F2.4 [HIGH для дизайна резервирования]**: «N home relay одновременно» в iroh **не существует**; отправитель всегда идёт на **home relay получателя** (`RelaySendItem { remote_endpoint, url: "The home relay of the remote endpoint" }`, `actor.rs:910-919`). Следствия: (1) резервирование транспорта = быстрый re-home + републикация адреса, а не N-of-M; (2) любой клиент Aira должен быть допущен на **любой** relay сети (токен допуска — сетевой, не per-relay); (3) открытый issue #4476 (клиент «wedged in connecting» после re-home, стейл pkarr-запись) — именно сценарий падения нестабильного relay, нужен собственный watchdog (§5.3).
- **Несколько relay-URL в адресе — есть в модели данных**: `EndpointAddr.addrs: BTreeSet<TransportAddr>`, `TransportAddr::Relay(RelayUrl)`, `relay_urls()` (`iroh-base-1.2.0/src/endpoint_addr.rs:42-57, 147`); в DNS/pkarr-записи `EndpointData::add_relay_url` «unless it already existed», `relay_urls()` (`iroh-dns-1.3.0/src/endpoint_info.rs:110-152`). `PkarrPublisher` публикует по умолчанию только relay-адреса (`AddrFilter::relay_only`, `address_lookup/pkarr.rs:22, 168, 210-216`). Использует ли `socket` второй relay-URL получателя как fallback при недоступности первого — **не проверено** (§9, тест в M20).
- **Что клиент знает о своей достижимости**: `net_report()` (только с фичей `unstable-net-report`, `endpoint.rs:1404-1451`) → `Report { udp_v4, udp_v6, mapping_varies_by_dest_ipv4/v6, preferred_relay, relay_latency, global_v4, global_v6, captive_portal }` (`net_report/report.rs:18-38`) — публичный адрес из QAD и признак симметричного NAT; portmapper (UPnP/PCP/NAT-PMP, фича `portmapper` по умолчанию; `portmapper-0.15.0/README.md:4`) активируется автоматически (`socket.rs:704, 800, 893`); `add_external_addr/remove_external_addr` (`endpoint.rs:1013-1033`). ⇒ **F2.6 [INFO]**: iroh **не** умеет проверить, что TCP-порт WSS-relay достижим снаружи (QAD — UDP), и не даёт NAT-типа в терминах Snowflake — для режима «стать relay» нужна своя проба «connect-back» с anchor (§4.1).
- **Верификация TLS relay** — `CaTlsConfig` (`iroh-relay-1.2.0/src/tls.rs:11-135`): `embedded()` (webpki), `platform()` (ОС; «extra roots… ignored on Android»), `custom_roots()`, `custom_server_cert_verifier(callback)` («advanced feature… may lead to insecure connections»), `insecure_skip_verify()` («only in tests»). Конфиг **один на endpoint** (`Builder::ca_tls_config`, `endpoint.rs:720`) и общий для relay, pkarr и DoH. ServerName берётся из `url.host_str()` (`client/tls.rs:107-110`) — IP-литерал даёт `ServerName::IpAddress`, `RelayUrl` — просто `Url` (`iroh-base-1.2.0/src/relay_url.rs:21, 38-41`), т.е. `https://203.0.113.5:8443` как relay технически допустим. ⇒ **F2.3 [HIGH для client-relay и «relay без домена»]**: pin self-signed сертификата возможен только через `custom_server_cert_verifier` с логикой «по SNI/IP → ожидаемый SPKI из подписанного каталога, иначе — webpki», а публичный LE-сертификат на IP **недостижим**: `tokio-rustls-acme` 0.9 (форк n0, `main`, прочитан 2026-09-23) имеет `enum Identifier { Dns(String) }`, строки `profile` и `"ip"` в `src/acme.rs` отсутствуют — ни профиля `shortlived`, ни IP-идентификаторов (в отличие от `derper -acme-ip-certs`).
- **Лимитов полосы на весь relay нет** — только per-client rx (`ClientRateLimit`) ⇒ **F2.5 [MEDIUM]** для client-relay: глобальный cap реализовывать самим (динамический `set_client_rate_limit(total / active)` + отказ в `on_connect` сверх `max_clients`) — §4.3.
- **Версии**: план M18/M20 говорит «iroh 1.1»; в registry уже 1.2.0 (MSRV 1.91, `iroh-1.2.0/Cargo.toml`). Wire-совместимость 1.x гарантирована n0 (`relay-deploy-plan.md`), но фиксировать в Cargo.toml стоит `iroh = "1.2"`, `iroh-relay = "1.2"` — **F2.7 [LOW]**, M18.

### 2.4 Что из этого следует для трёх ролей relay

| Возможность | Anchor / community-server (домен) | Server без домена (голый IP) | Client-relay (домашний ПК) |
|---|---|---|---|
| TLS | ACME TLS-ALPN-01 встроен (`CertConfig::LetsEncrypt`) | self-signed + pin в каталоге (кастомный верификатор у клиента) | то же, pin + короткий TTL записи |
| QAD (UDP 7842) | да | да (TLS есть) | да, если UDP-порт открыт; иначе `enable_relay`-only невозможен (QAD требует TLS, форвардинг — нет) |
| Допуск | встроенный `AccessControl` с токеном Aira | то же | то же (токен проверяется офлайн) |
| Лимиты | per-client rx + свой accept/conn-лимит | то же | + глобальный cap полосы/клиентов (своя реализация) |
| Метрики | 9090 localhost + `/healthz` | то же | локальная сводка в UI, метрик-порт закрыт |

## 3. Standalone `aira-relay`: UX оператора-энтузиаста

### 3.1 Что это за продукт и где живёт

- **Один бинарь `aira-relay`** = iroh-relay (встроенный как библиотека, `iroh-relay/server`, §2.2) + mailbox v2 (M21) + intro-mailbox + `/healthz` + Prometheus + ACME + регистрация в каталоге. Один процесс, один конфиг, один systemd-юнит — вместо двух юнитов из `relay-deploy-plan.md` Этап 4 и M20 п.2 / M21 п.1 (`spec/18-milestones.md:657-661, 691-693`). Аргументы: оператор-энтузиаст не должен знать, что «iroh-relay» и «aira-relay» — разные вещи; один ACME-сертификат на оба сервиса; один порт 443 (`/relay` — iroh, mailbox — по iroh-QUIC через тот же relay/QAD, дополнительных портов нет — аудит §4.3); один канал обновлений. Режимы: `--mode full` (по умолчанию), `--mode transport` (только iroh-relay, без хранилища — для VPS без диска и для client-relay), `--mode mailbox` (если оператор уже держит stock `iroh-relay`).
- **Крейт `crates/aira-relay` в этом репозитории** — по правилу §15.9 «Rust и ядро — в этом репозитории» (`spec/17-cross-platform.md:273-282`, коммит `971e038`); M21 п.1 уже заводит его для mailbox — расширяем, отдельный репозиторий не нужен. Зависимости: `aira-core` (типы конвертов, KDF-контексты mailbox v2), `iroh`/`iroh-relay` (server), `redb`; **не** зависит от `aira-net` (в нём клиентский код и `transport/*`) и от `aira-storage`. Отдельный `Cargo.lock`-профиль не нужен — версия workspace общая, релизные assets — отдельные.
- **Формат дистрибуции** (по образцу iroh-relay/SimpleX/chatmail): (1) бинарь в GitHub Releases для `x86_64-unknown-linux-musl` и `aarch64-unknown-linux-musl` (static, без glibc-зависимостей — для старых VPS и Raspberry Pi) + sha256 + attestation (`actions/attest-build-provenance`, аудит §6.6.5) — сейчас `release.yml` собирает только `aira-cli/daemon/gui` под 4 desktop-таргета (`.github/workflows/release.yml:23-32, 57`), aarch64-Linux и musl нет; (2) Docker-образ `ghcr.io/kamiletar/aira-relay:<semver>` (distroless/alpine, `EXPOSE 443/tcp 7842/udp`, volume `/var/lib/aira-relay`, `docker-compose.yml` в `deploy/`), тег `latest` **не** публиковать (n0 сами советуют version-lock); (3) deb/rpm/nix/AUR — после беты, только если появится сопровождающий. Docker-образ — **обязателен**: это самый частый путь энтузиаста (все три прецедента chatmail/SimpleX/iroh дают образ).

### 3.2 Целевой UX оператора (сценарий «VPS за 15 минут»)

```
# 1. Установка (одна из): 
curl -fsSL https://<domain>/relay/install.sh | sh        # ставит /usr/local/bin/aira-relay + systemd unit + пользователя
docker compose -f deploy/docker-compose.yml up -d           # или контейнер

# 2. Инициализация — интерактивно или неинтерактивно
aira-relay init --hostname relay.example.org --contact admin@example.org \
                --mode full --data-dir /var/lib/aira-relay [--yes]
#   → генерирует relay-ключи (iroh SecretKey → EndpointId mailbox-сервиса; ключ оператора),
#     пишет /etc/aira-relay/config.toml, печатает EndpointId и fingerprint оператора

# 3. Самопроверка ДО запуска и после
aira-relay doctor
#   ✓ DNS: relay.example.org → 203.0.113.5 (A), 2001:db8::5 (AAAA)
#   ✓ tcp/443 слушается, снаружи достижим (проверка через anchor connect-back API)
#   ✓ udp/7842 достижим (QAD-проба с anchor)
#   ✓ ACME: сертификат выдан, истекает через 89 дней
#   ✗ clock skew 47 s — включите NTP (иначе токены допуска будут отклоняться)
#   ✓ диск: 38 GB свободно, mailbox cap 1 GB
#   ✓ версия 0.6.2 — актуальна (каталог: min 0.6.0)

# 4. Запуск и регистрация в каталоге сообщества (opt-in)
systemctl enable --now aira-relay
aira-relay register --region eu-central --contact mailto:admin@example.org
#   → подписанный ключом оператора RelayAnnounce уходит на anchor; статус "candidate",
#     через 72 ч успешных проверок → класс "server" в подписанном каталоге

# 5. Эксплуатация
aira-relay status          # uptime, клиенты, полоса, коробки, класс в каталоге, версия
aira-relay backup /path    # снапшот redb mailbox (шифрованный, с ключом relay) — опционально
aira-relay update-check    # сравнение с каталогом; печатает предупреждение об устаревании
curl --fail https://relay.example.org/healthz ; curl -s 127.0.0.1:9090/metrics
```

Конфиг `/etc/aira-relay/config.toml` (генерируется `init`, все поля с дефолтами):

```toml
[relay]                       # iroh-relay
hostname   = "relay.example.org"   # или отсутствует при cert = "self-signed" (голый IP)
https_bind = "[::]:443"
quic_bind  = "[::]:7842"           # QAD; закрыть = клиенты за NAT хуже пробивают
cert       = "acme"                # "acme" | "manual" (пути) | "self-signed" (pin печатается в init)
contact    = "mailto:admin@example.org"
[mailbox]                     # aira-relay v2 (M21); отсутствует в --mode transport
enabled    = true
data_dir   = "/var/lib/aira-relay"
total_cap  = "1 GB"; per_box = "10 MB"; per_box_msgs = 100; envelope_max = "64 KB"; ttl = "7d"
push_allowlist = ["https://push.<domain>/", "https://ntfy.sh/"]   # см. §6.3 (а) — единственный outbound
[access]
mode        = "aira-token"         # "aira-token" (сетевой токен, §6.3) | "private-token" (свой список) | "everyone" (не попадает в каталог)
catalog_key = "<hex pk>"           # ключ подписи каталога/токенов (вшит по умолчанию)
[limits]
max_clients       = 5000           # отказ в on_connect сверх лимита
client_rx_bps     = 2_000_000; client_rx_burst = 8_000_000
accept_per_second = 50; accept_burst = 200   # своя реализация (F2.1)
[catalog]
announce = true; anchor = "https://relays.<domain>"; region = "eu-central"
[metrics]
bind = "127.0.0.1:9090"
[log]
client_ips = false                 # фильтр warn для iroh_relay::server: IP клиента иначе попадает в info_span (http_server.rs:499)
```

### 3.3 Что требует домена и портов, а что работает на голом IP

| Вариант | Нужно | Класс в каталоге | Комментарий |
|---|---|---|---|
| Домен + 443/tcp + 7842/udp (+80 не нужен: TLS-ALPN-01) | A/AAAA-запись, открытые порты, ACME (встроен) | `server` (после 72 ч) | Рекомендуемый; полностью совпадает с `relay-deploy-plan.md` вариант A, но без nginx, если 443 свободен |
| Домен, 443 занят (webmail и т.п.) | nginx `stream ssl_preread` (вариант A) или TLS-терминация nginx (вариант B, `cert = "manual"` + reloading) | `server` | Это случай mail-сервера проекта (M20) |
| Голый IP (VPS без домена, домашний сервер с статическим IP) | `cert = "self-signed"`; `init` печатает pin (SHA-256 SPKI); порт любой (по умолчанию 8443 + 7842/udp) | `server-pinned` | Клиенты принимают pin только из **подписанного каталога** или из invitation-ссылки (private relay); браузерные клиенты (M14) такой relay использовать **не могут** (WebSocket в браузере не даёт pinning) |
| Динамический IP / за NAT с UPnP | то же + регистрация с коротким TTL | `client` (эфемерный) | Это и есть режим клиента (§4); standalone-бинарь в этом случае запускается демоном |
| Поддомен проекта `<id>.r.<domain>` → IP оператора | DNS-сервис проекта с API (вопрос владельцу №2) | `server` | Даёт LE-сертификат без своего домена (TLS-ALPN-01 на IP оператора); ответственность за DNS-зону — на проекте |

### 3.4 Документация оператора — `docs/RELAY.md` (структура)

1. **Что это и что это НЕ** — «relay не является прокси в интернет»: форвардит только зашифрованные кадры между подключёнными Aira-endpoint'ами, хранит только шифротекст конвертов ≤ 64 KB до 7 дней, **не открывает исходящих соединений** кроме ACME, регистрации в каталоге и push-allowlist; что оператор *видит* (IP и EndpointId клиентов, время, объёмы, идентификаторы коробок) и что *не видит* (содержимое, идентичности ML-DSA, кто с кем — только через IP-корреляцию). Это же — источник для `PRIVACY.md` (M23 п.3).
2. Требования (ОС, 1 vCPU/512 MB для transport, диск для mailbox, порты, домен/IP, NTP).
3. Быстрый старт: Docker / бинарь + systemd (юнит из `relay-deploy-plan.md` Этап 4 + `AmbientCapabilities=CAP_NET_BIND_SERVICE`).
4. TLS: ACME, manual, self-signed+pin (когда что).
5. Лимиты и квоты (что означают, как подобрать под канал; полоса ×2 при relay-трафике файлов).
6. Абьюз-политика и юрисдикция: аналогия с Tor bridge/Snowflake (не exit), контакт для жалоб, что делать при DMCA/запросах (нечего выдать), «не юридическая консультация».
7. Регистрация в каталоге, классы, снятие с публикации (`aira-relay register --withdraw`), «непубличный relay» (для сообществ в цензурируемых странах — раздача URL+pin через invitation-ссылки, прецедент chatmail-unlisted / Tor rdsys).
8. Обновление и совместимость: политика версий (ниже), `update-check`, Docker без `latest`.
9. Бэкап mailbox (по желанию — конверты и так живут 7 дней; ключ relay = потеря EndpointId → перерегистрация).
10. Мониторинг: `/healthz`, метрики, алерты; логирование без IP по умолчанию (встроенный iroh-relay пишет IP клиента в `info_span!("conn", peer = …)`, `server/http_server.rs:499` — поэтому `RUST_LOG=warn` по умолчанию, `info` только для отладки).

### 3.5 Версионирование и совместимость клиент ↔ relay

- Транспорт: wire-протокол iroh 1.x стабилен (n0), версия relay-протокола согласуется WebSocket-субпротоколом (`relay-deploy-plan.md`); политика — relay держит **ту же minor iroh, что и клиенты, или новее**.
- Mailbox: `RelayHello { protocol_version: 2, supported, capabilities }` (M21 п.3); **каталог несёт `min_relay_version`** — клиент не выбирает relay старее, а `aira-relay` при старте и раз в сутки сравнивает себя с каталогом и пишет `WARN: deprecated, upgrade by <date>`; при `protocol_version` ниже минимального anchor снимает relay из каталога автоматически (де-листинг вместо «сломанной сети»).
- Совместимость: `aira-relay N.x` обслуживает клиентов `N.(x-1)…N.(x+1)`; anchor обновляется первым; breaking изменения mailbox — только с новым ALPN (`aira/3/relay`) и grace-периодом в каталоге (урок SimpleXMQ v1→v2, `spec/13-threat-model.md:466-467`).
- Авто-обновление: **не встраивать** (relay с правом самообновления = supply-chain-вектор); Docker — `watchtower` по желанию оператора, пакеты — через менеджер; `update-check` + метрика `aira_relay_outdated 1` для алерта.
- Документ возможностей relay (аналог NIP-11 / `cmrelayinfo`): `GET https://<relay>/.well-known/aira-relay.json` → `{ version, protocol_versions, services: ["iroh-relay","mailbox","intro"], limits, region, operator_contact, catalog_class, pin }` — подписан ключом relay; каталог-сервис сверяет его при проверках.

### 3.6 Объём работ (без client-mode)

| Задача | Оценка |
|---|---|
| Крейт, встраивание iroh-relay server, конфиг TOML, `init/run/status/doctor` (проверки DNS/портов через anchor API, clock, ACME) | 5–7 дней |
| `AccessControl` с токеном Aira + accept/conn-лимиты + метрики | 3 дня (сам токен-сервис — M22) |
| Mailbox v2 внутри того же процесса | входит в M21 (2–3 недели) |
| `register`/`withdraw`, `RelayAnnounce`, `.well-known/aira-relay.json` | 2 дня relay + 4–5 дней каталог-сервис на anchor (§5.6) |
| Docker (multi-arch), musl-сборки, `release.yml`, attestation, `deploy/` | 3 дня |
| `docs/RELAY.md`, `install.sh`, compose, systemd | 2–3 дня |
| Итого сверх M21 | **≈ 3–4 недели** одного разработчика |

## 4. Режим «стать relay» в клиенте

> Терминология после решения владельца по теме G (§8.1): «стать relay» = opt-in роль `relay` (и, отдельно, opt-in роль `mailbox`) поверх дефолтной роли `hop`; всё ниже про «client-relay» читать как «desktop-нода с включённой ролью `relay`». Идентичность этих ролей — хоп-EndpointId из локального RNG, не чат-EndpointId из seed.

### 4.1 Как клиент понимает, что он может быть relay

Что даёт iroh (§2.3): `net_report` → `global_v4/global_v6` (публичный адрес по QAD), `mapping_varies_by_dest_*` (симметричный NAT), `udp_v4/v6`; portmapper — есть ли UPnP/PCP/NAT-PMP; локальные адреса интерфейсов. Чего **не даёт**: достижимость **TCP**-порта снаружи (relay для клиентов — WSS/TCP), стабильность адреса во времени, NAT-тип в терминах Snowflake. Поэтому:

1. **Кандидат** (пассивно, без UI): desktop-платформа (§4.5), не metered-сеть, страна не в «строгом» списке (§4.4), демон работает ≥ 24 ч суммарно, и одно из: `global_v4 == адрес интерфейса` (публичный IP без NAT) **или** `global_v6` есть и не temporary **или** portmapper получил маппинг. Адрес стабилен ≥ 24 ч (история в `settings`).
2. **Активная проба** (после согласия пользователя на «проверить»): демон запускает `aira-relay --mode transport --bind [::]:<порт> --cert self-signed` как дочерний процесс, затем просит anchor: `POST https://relays.<domain>/probe { url: "https://203.0.113.5:8443", pin, token }` — anchor делает TLS+WebSocket handshake `/relay` (и QAD-пробу на UDP) и возвращает `{ reachable_v4, reachable_v6, rtt_ms, observed_ip }`. Требовать успех с двух anchor (mail-сервер + VPS, M20 п.7) — защита от ложноположительного результата через один путь. Повторять каждый час и при смене сети (`netmon`): residential-IP меняются (DHCP), при изменении — перерегистрация или остановка.
3. Аналог Snowflake `-nat-probe-server`: без прошедшей пробы режим не включается вовсе, вместо «включил и не работает».

### 4.2 UX opt-in (что показать, какие риски объяснить — ограничение (д))

Приложение **предлагает один раз** (не-модальная карточка в Settings → Network, плюс тихое уведомление «Похоже, у вас публичный IP — можно помочь сети»), не «наг-скрин». Экран согласия — обязательные пункты (формулировки для локализации):

- «Ваш публичный IP-адрес и порт будут **опубликованы в открытом каталоге relay**. Его увидит любой пользователь Aira, ваш провайдер и государство. Не включайте на рабочей сети или сети, которой не владеете.»
- «Через ваш компьютер будет проходить **только зашифрованный трафик** других пользователей Aira **между узлами Aira**; вы не можете его прочитать, выбрать или отфильтровать. Ваш узел никогда не открывает соединений к сайтам или другим сервисам от чужого имени — это не VPN и не выходной узел.» (аналогия: Tor bridge / Snowflake, не exit — §1)
- «Видны объёмы и время: кто-то, наблюдающий за вашим каналом, может считать, что вы участвуете в сети Aira.»
- «Риски: рост трафика (лимит по умолчанию N ГБ/мес), возможные DDoS-попытки на ваш IP, вопросы провайдера (residential-тарифы часто запрещают «серверы»).»
- «Юридически: мы не даём юридической консультации; в некоторых странах ретрансляция чужого трафика ограничена — режим недоступен там по умолчанию (§4.4).»
- Ползунки лимитов (§4.3) прямо на экране согласия; кнопка «Остановить» — всегда в один клик, статус в трее (`relay: 12 clients, 1.3 MB/s`).
- Что публикуется: IP:порт, pin сертификата, регион (по IP, не точнее страны), **не** публикуется ничто из identity (ключ ролей `relay`/`mailbox` отдельный от identity — по решению владельца это хоп-EndpointId из локального RNG, второй `Endpoint` в демоне (§8.1), не KDF от seed; в `docs/KEY_CONTEXTS.md` — запись «не деривируется»; смена ПК = новый relay, без связи с пользователем).
- Пользователь видит статистику и «сколько людей вы помогли соединить» — единственная «награда» (Snowflake показывает счётчик; никаких токенов).

### 4.3 Лимиты ресурсов (ограничение (б) — обязательны и настраиваемы)

| Параметр | Дефолт | Реализация |
|---|---|---|
| Максимум одновременных клиентов | 50 | `AccessControl::on_connect` → `Deny` сверх лимита; счёт по `ConnectionId` |
| Полоса (сумма rx) | 5 Мбит/с (или 25 % измеренного uplink) | глобальный token-bucket над `set_client_rate_limit(total/active)` (F2.5); измерение — при пробе |
| Месячный объём | 20 ГБ | счётчик в `settings`, при достижении — `withdraw` до следующего месяца |
| Расписание | только на питании от сети (ноутбук), не при metered-сети, опционально «только когда я не за компьютером» | системные API (§4.5) |
| Хранилище | **0** — mailbox в client-relay нет (§4.6) | режим `--mode transport` |
| Исходящие соединения | только anchor (регистрация/проба) | в коде client-mode нет `push_allowlist`, ACME и `access.http` |

Все дефолты — в одном файле констант (`crates/aira-relay/src/limits.rs`), по правилу «константы вместо magic numbers».

### 4.4 Когда режим выключен и не предлагается (ограничение (г))

- **Мобильные — исключены на этапе компиляции**: `aira-ffi`/Android не линкует `aira-relay` вовсе (сейчас FFI использует из `aira-net` только `BlobStore` — `crates/aira-ffi/src/runtime.rs:33, 95`); FGS `dataSync` ограничен 6 ч/сутки (аудит §4.1), батарея, CGNAT у операторов — relay на телефоне бессмысленен и вреден.
- **Metered-сети**: Windows `NetworkInformation.GetInternetConnectionProfile().GetConnectionCost()`, macOS `NWPathMonitor.isExpensive/isConstrained`, Linux NetworkManager `Metered` (D-Bus) — при `metered` режим ставится на паузу, предложение не показывается.
- **Страны с цензурой**: список «строгих» стран по I2P-критерию (Freedom House CL ≤ 16 или IF ≤ 39; у I2P 42 стран) хранится в каталоге (обновляемый, подписанный), определение — по стране, которую anchor видит по IP клиента при выдаче токена (`X-Aira-Country` в ответе; без GeoIP-базы на клиенте) + системная локаль/таймзона как второй сигнал. В этих странах: режим не предлагается и **выключен по умолчанию**; включить можно только через Advanced с отдельным предупреждением (I2P hidden mode переопределить нельзя — Aira даёт override, потому что для сообществ в таких странах residential-relay — как раз способ обойти блокировку anchor; это решение владельца, §9).
- **Браузер/WASM (M14)**: не применимо.
- Дополнительно выключать: при активном VPN-интерфейсе (IP не «свой»), при обнаружении CGNAT (100.64/10 на интерфейсе или `mapping_varies`).

### 4.5 Desktop: безопасность демона с открытым портом, firewall, UPnP

- **Процессная модель**: relay — **отдельный процесс** `aira-relay` (тот же бинарь, что у оператора, поставляется в desktop-пакете рядом с `aira-daemon`; `docs/INSTALL.md:8-16` — «три бинарника», станет четыре), запускается и супервизируется демоном по IPC-команде `SetRelayMode { enabled, limits }`. Демон **не** линкует `iroh-relay/server` (лишние ~15 зависимостей: `tokio-websockets`, `tokio-rustls-acme`, `clap`, `dashmap`, `rcgen`… — `iroh-relay-1.2.0/Cargo.toml [features] server`), не открывает входящих портов в своём процессе, где лежат seed и ratchet-состояния. Падение relay-процесса не роняет мессенджер; права — тот же пользователь, но отдельный рабочий каталог `~/.aira/relay/` без доступа к `aira.redb` (в Linux можно `systemd-run --user` с `ProtectHome=read-only` + `ReadWritePaths`).
- **Открытый порт**: только WSS (TCP) и, если пробился, QAD (UDP); все входящие — TLS-сессии к iroh-relay-серверу, у которого с 1.0.2 fuzz-парсеры и `panic=abort`-фикс; версия ≥ 1.0.2 обязательна (`relay-deploy-plan.md`). Bind на `[::]` только после успешной пробы; до этого — `127.0.0.1`.
- **Firewall/UPnP/NAT-PMP**: Windows — `netsh advfirewall firewall add rule` при установке (MSI) или запрос UAC при включении режима; macOS — Application Firewall спросит при первом `listen` (подписанный бинарь — иначе диалог каждый раз, аргумент в пользу notarization M23 п.2); Linux — ничего не делаем автоматически, `doctor` подсказывает `ufw allow`. UPnP/PCP/NAT-PMP: переиспользовать `portmapper` (уже в iroh) для маппинга TCP-порта relay — крейт умеет UPnP/PCP/NAT-PMP (`portmapper-0.15.0/README.md:4`), нужно проверить поддержку TCP-маппинга (§9).
- **Порт**: случайный высокий по умолчанию (не 443 — на десктопе занят/требует прав), публикуется в каталоге вместе с IP; для DPI-сценариев residential-relay на нестандартном порту всё равно выглядит как TLS.

### 4.6 Что предоставляет client-relay: только iroh-relay (рекомендация)

| Сервис | В client-relay? | Почему |
|---|---|---|
| iroh-relay (форвардинг + QAD) | **да** | stateless, хранит только соединения; выключил — потерял только текущие сессии, клиенты re-home'ятся (§5) |
| mailbox v2 | **по умолчанию нет**; opt-in в Advanced по решению владельца (§8.1), класс в каталоге — только после 72 ч uptime | stateful: чужие конверты на домашнем ПК (7 дней), обязательство хранить, бэкапы, юридика «хранение», исчезновение relay = потеря недоставленных писем у всех, кто на него положился; N-of-M только маскирует это ценой 2–3× трафика |
| intro-mailbox | нет | тот же аргумент + PoW-верификация под нагрузкой на домашнем ПК |
| onion-hop | **роль зарезервирована**, по умолчанию выкл. | дизайн в теме G (`onion-antiabuse.md`); флаг `services.ONION_HOP` в записи каталога |
| pkarr/DNS | нет | anchor-функция |

Итого: client-relay = «Aira Snowflake»: эфемерный, только транспорт, только между Aira-узлами, с pin и коротким TTL записи. Основная ценность — **не** ёмкость (у одного VPS её больше, чем у сотни домашних ПК), а **устойчивость к блокировкам anchor** (residential-IP блокировать дорого — ровно логика Snowflake) и NAT-traversal для пользователей рядом (QAD с близкого узла). Из этого следует и приоритет: сначала standalone-relay (§3) и каталог (§5.6), client-mode — после беты.

## 5. Нестабильность и резервирование

### 5.1 Классы доступности

| Класс | Кто | Обещание | Как попадает в класс | Как выбывает |
|---|---|---|---|---|
| `anchor` | relay проекта (mail-сервер + VPS в другом регионе, M20 п.7) | лучшее из возможного, обновляется первым, всегда в `RelayMap` клиента | вшит в бинарь (снапшот каталога) | никогда автоматически (только новым релизом каталога) |
| `server` | community-relay с доменом и ACME (§3.3) | «серверный» uptime; в каталоге с историей | `register` → `candidate` → 72 ч проверок anchor'ом с ≥ 99 % успехов и клиентской версией ≥ `min_relay_version` → `server` | 3 подряд неуспешных проверки (каждые 5 мин) → флаг `down`; 24 ч `down` → удаление; 30 дней без `announce`-обновления → удаление |
| `server-pinned` | community-relay на голом IP (self-signed + pin) | как `server`, но не для браузера | как `server` + pin в записи | как `server` |
| `client` | desktop-клиент с публичным IP (§4) | **никакого**: residential-ephemeral, может исчезнуть в любой момент | `announce` каждые 10 мин с pin и результатом пробы (§4.1); запись живёт 30 мин без обновления | молча по TTL; клиенты не хранят его в долгую |

Правила использования классов на клиенте: home relay по умолчанию — из `anchor`/`server`/`server-pinned` (ранжирование: latency net_report × health-score); `client`-класс — только (а) по явному opt-in «использовать relay сообщества» или (б) как fallback, когда ни один `anchor`/`server` не отвечает ≥ 2 мин (сценарий блокировки anchor). Mailbox — только `anchor`/`server`/`server-pinned` (§4.6).

### 5.2 Health-scoring и история uptime на клиентах

- Новая таблица `relay_stats` в `aira-storage` (или ключи `settings` `relay/stats/<url>`): `{ class, ok, fail, consecutive_fail, ewma_rtt_ms, last_ok_at, last_fail_at, backoff_until, auth_denied_reason? }`.
- Источники сигнала: `Endpoint::home_relay_status()` (`Connected`/`Disconnected { last_error }`, `auth_denied_reason`) — для собственного home relay; результат `connect()` к контакту через его relay-URL — для чужих relay; результат `Register/Deposit/Retrieve` — для mailbox-relay; latency из `net_report.relay_latency` (фича `unstable-net-report` — включить в `aira-net`, это единственный источник RTT).
- Автоисключение: `consecutive_fail ≥ 3` → `backoff_until = now + 1 ч`, далее ×2 до 24 ч; `anchor` не исключается никогда (только понижается в ранге); `auth_denied_reason` = «токен истёк» → обновить токен, не наказывать relay.
- Телеметрия на anchor **не отправляется** (приватность; это отличие от Snowflake-брокера) — активные проверки делает сам каталог-сервис (§5.6); опционально в Advanced: «сообщать о недоступных relay» (без IP пользователя — через сам relay-транспорт).

### 5.3 Смена home relay, республикация адреса, обход #4476

Ограничение iroh (F2.4): один home relay; отправитель идёт на home relay получателя; при падении home relay актор бесконечно переподключается с backoff ≤ 16 с, а pkarr-запись продолжает рекламировать старый URL (issue #4476, открыт). Дизайн:

1. **Watchdog в `net_task`** (M19/M20): если `home_relay_status()` показывает `Disconnected` > 30 с (или `auth_denied`) → `Endpoint::remove_relay(url)` (временно) → net_report выбирает `preferred_relay` среди оставшихся → home relay меняется → `PkarrPublisher` републикует адрес (проверить, что публикация срабатывает по смене home relay — §9) → через `backoff` вернуть relay в `RelayMap` через `insert_relay`. Событие `NetStatus { home_relay, class, since }` в IPC (M19 п.11).
2. **На стороне отправителя**: contact-запись хранит `relays: Vec<RelayRef>` (M19 Phase A п.1 уже вводит поле) — при ошибке `connect()` через первый URL → повторный pkarr-lookup (свежая запись) → попытка через следующий URL из списка контакта → `pending` + mailbox. Использует ли iroh несколько `TransportAddr::Relay` из `EndpointAddr` сам — не проверено (§9); если нет — ротация URL вручную между попытками.
3. **Окно недоставки** = обнаружение (ping 15 с + 30 с watchdog) + републикация + TTL кэша у контакта (pkarr TTL 30 с по умолчанию iroh-dns-server, `relay-deploy-plan.md`) ≈ 1–2 мин. Всё это время сообщения лежат в `pending`/mailbox — потери нет, только задержка. Для `client`-класса это приемлемо, для `anchor` — редкость.
4. Тест (M20): два in-process relay (`iroh::test_utils::run_relay_server` ×2), endpoint A homed на relay 1, B шлёт → убить relay 1 → A re-home на relay 2 ≤ 60 с, B доставляет после повторного lookup; регресс-тест на #4476.

### 5.4 Mailbox: N-of-M депозит и дедуп

- **M = 2–3 relay на получателя, N = 2 депозита** (аналог Delta Chat «3 relay при onboarding», NIP-65 «2–4»): владелец коробок (получатель, тот, кто делает `Register` в v2) выбирает свои M relay из каталога — **разные операторы** (SimpleX-правило), ни одного `client`-класса — и сообщает контактам (InvitationLink → `MailboxConfig.relays`, обновление — подписанный `RelayMigration`, §11B.5.1).
- Отправитель при недоставке напрямую: `Deposit` параллельно в первые N доступных relay из списка (таймаут 10 с на каждый), успех = хотя бы один `DepositOk`; остальные — best-effort. Получатель делает `Retrieve` со всех M, дедуп по `envelope_id = BLAKE3("aira/relay/envelope-id/v2" ‖ header)` (тот же ключ, что `dedup.rs` M19 п.3 — `BLAKE3(sender ‖ counter ‖ nonce)`), `Ack` на каждом relay по его `seq`.
- Цена: ×N исходящего трафика на конверт (≤ 64 KB — терпимо; файлы через relay не идут), ×N хранилища на relay сети (учитывать в `total_cap` 1 GB — при N=2 эффективная ёмкость anchor вдвое ниже). Мера против злоупотребления «N» как усилителя хранения: `N ≤ 3` зашито в клиенте, а relay ограничивает `Register` ≤ 20/сутки на EndpointId (M21 п.5).
- Порядок: `seq` присваивает каждый relay независимо → порядок восстанавливается по ratchet-`counter` после расшифровки (skipped keys, `MAX_SKIP = 1000`), не по `seq`.

### 5.5 Список relay в приглашении, контакте, pkarr

- `InvitationLink` (`crates/aira-net/src/discovery.rs:20-25`) получает `relays: Vec<RelayRef>` где `RelayRef { url, endpoint_id: Option<EndpointId> /* mailbox */, class, pin: Option<[u8;32]> }` (~80–120 байт на запись, 2–3 записи; ссылка и так ≈ 2,8 KB — M19b п.4 переводит QR в byte-mode). Подписывается вместе с остальными полями (M19b п.4 «version/fingerprint_hint/expires_at/подпись»).
- Contact-запись: `ContactInfo.relays` (M19 Phase A п.1) + `MailboxConfig.relays` (M21 п.7) — одно поле, не два.
- pkarr: iroh публикует **только home relay** (`relay=<url>` в TXT `_iroh.<z32>`), это транспорт; список mailbox-relay в pkarr **не публикуем** (лимит pkarr-пакета ≈ 1 KB — по памяти, §9.2; и это лишняя связь identity ↔ relay для наблюдателя) — он живёт только у контактов.
- Приватные relay: `RelayRef` в приглашении может нести relay, которого нет в каталоге (URL + pin) — способ раздать residential/непубличные relay внутри сообщества (аналог bridge-line Tor, chatmail-unlisted).

### 5.6 Каталог relay (signed relay list)

- **Формат** (`aira-core::catalog`, postcard + JSON-зеркало для людей): `RelayCatalog { version: u32, issued_at, expires_at (≤ 7 дней), min_client_version, min_relay_version, strict_countries: Vec<CountryCode>, relays: Vec<RelayEntry>, denylist: Vec<EndpointId>, next_signing_key: Option<pk>, signature }`; `RelayEntry { url, mailbox_endpoint_id: Option<EndpointId>, class, services: bitflags { IROH_RELAY, QAD, MAILBOX, INTRO, ONION_HOP }, region, operator_id: [u8;32] /* hash ключа оператора */, pin: Option<[u8;32]>, limits: { client_rx_bps, envelope_max }, first_seen, uptime_30d: u8 (%), contact: Option<String> }`.
- **Подпись**: ML-DSA-65 ключом каталога проекта (согласуется с PQ-позицией проекта; 3,3 KB подписи на файл — не проблема), публичный ключ вшит в бинарь; ротация через `next_signing_key` (новый ключ объявляется за один релиз до использования). Держать ключ офлайн, подпись — ручной шаг релиза каталога (раз в неделю или по событию); альтернатива 2-of-3 — вопрос владельцу.
- **Раздача**: (1) снапшот в бинаре (anchor + `server` на момент сборки); (2) `GET https://relays.<domain>/catalog.v1` (anchor) с `If-None-Match`; (3) зеркало на GitHub Releases/raw (может быть заблокировано в цензурируемых странах — только fallback); (4) через сам iroh — ALPN `aira/2/catalog` на anchor-mailbox-endpoint: клиент, который дотянулся до любого relay, получает каталог без HTTPS к домену проекта; (5) записи `client`-класса **не в файле**, а выдаются anchor-брокером по аутентифицированному запросу «дай 3 client-relay рядом» (не более 3 за запрос, rate limit по токену) — ограничивает перечисление residential-IP (урок Snowflake/rdsys), при этом пользователь-оператор всё равно предупреждён, что адрес публичен (д).
- **Обновление на клиенте**: раз в сутки + при старте, если `expires_at` близко; просроченный каталог продолжает использоваться (лучше старый список, чем никакой), но `client`-класс не запрашивается.
- **Сервис каталога на anchor** (новый маленький HTTP-сервис рядом с `aira-relay`, часть того же бинаря `aira-relay --catalog`): приём `RelayAnnounce` (подписан ключом оператора, PoW 20 бит, лимит 5 записей на `operator_id`), активные проверки (`/healthz`, WSS-handshake `/relay` с тестовым EndpointId, QAD-проба, `RelayHello` mailbox, `.well-known/aira-relay.json`), state-машина классов (§5.1), выдача подписанного каталога (подпись офлайн → сервис выдаёт последний подписанный файл; автоматическая подпись только для `client`-брокера краткоживущим ключом делегирования, если владелец согласится).

### 5.7 Fallback на якорный relay и разнообразие операторов

- `anchor` всегда в `RelayMap` и никогда не исключается; при полной недоступности community-relay сеть деградирует до «как в M20» без действий пользователя.
- При выборе home relay и M mailbox-relay: не более одного relay на `operator_id`, не более одного на IPv4 `/24` и IPv6 `/48` (зеркало правила §11B.4 «IP diversity» для DHT); ранжирование `uptime_30d` × latency.
- Sybil в каталоге: `candidate` → `server` только через 72 ч наблюдений + PoW на announce + лимит записей на оператора; `client`-класс не может стать home relay без opt-in, а mailbox — никогда; при подозрении — ручной `denylist` в подписанном каталоге. Этого достаточно для беты; экономика (стейк) не рассматривается.

## 6. Модель угроз (включая анти-паразитные ограничения (а)–(д))

### 6.1 Злонамеренный community-relay

| Что может | Почему | Что уже закрывает | Что добавить (milestone) |
|---|---|---|---|
| Видеть IP и EndpointId обеих сторон, время и объёмы кадров; строить граф «кто с кем» среди тех, чей home relay — он | relay форвардит кадры `src → dst EndpointId` (протокол iroh-relay); для mailbox — `mailbox_id`, размеры, время `Deposit/Retrieve` | E2E (ratchet) + TLS iroh между endpoint'ами — содержимое недоступно; pairwise mailbox v2: owner/sender-псевдонимы на коробку (аудит §4.3) — relay не связывает коробки одного пользователя по ключам | v2.1 из §4.3: случайный EndpointId на relay-сессию для mailbox-операций (иначе relay связывает коробки по EndpointId); home relay по умолчанию только `anchor`/`server` (проверенные операторы), `client` — opt-in (§5.1); **PRIVACY.md**: честно «relay видит IP, EndpointId, время, объёмы» (M23) |
| Дропать / задерживать кадры и конверты выборочно | у relay полный контроль над форвардингом | ack по `seq` и `DeliveryState` (M19/M21) — клиент видит недоставку | N-of-2 mailbox (§5.4); health-score и автоисключение (§5.2); re-home по watchdog (§5.3) — M21/M24a.1 |
| Подменить / прочитать | — | невозможно: QUIC/TLS 1.3 между endpoint'ами поверх relay, ratchet поверх | — |
| Отказать в допуске конкретному EndpointId (цензура на relay) | `Access::Deny` | `auth_denied_reason` виден клиенту (iroh 1.2) | клиент логирует, понижает relay, переходит на другой (§5.2) |
| Отдавать стейл/пустой mailbox | — | `seq` монотонен на relay | N-of-2: расхождение между relay → пометка relay как подозрительного (M24a.1) |

### 6.2 Sybil-relay и утечка IP оператора

- **Sybil**: дешёвые EndpointId + VPS ⇒ атакующий заводит десятки relay, чтобы стать home relay/mailbox для многих и собрать метаданные. Митигации: классы с историей (72 ч → `server`), PoW + лимит 5 записей на `operator_id` при announce, правило «разные операторы, разные /24 и /48» при выборе (§5.7), ручной denylist в подписанном каталоге, `client`-класс никогда не получает mailbox и не становится home relay без opt-in. Остаточный риск: терпеливый атакующий с несколькими операторскими ключами и ASN — принимается для беты (у SimpleX/Nostr ответа тоже нет, кроме репутации операторов).
- **IP оператора**: для `server` — как у любого сервера (домен → IP); для `client` — residential-IP пользователя становится публичным (д): согласие (§4.2), выдача только брокером по 3 штуки (§5.6), TTL 30 мин, отдельный relay-ключ, не связанный с identity, и рекомендация «лучше VPS». Полностью убрать риск нельзя — это и есть осознанный риск, который владелец принял.

### 6.3 Анти-паразитные ограничения (а)–(д) — как встроены и как проверяются

| Ограничение | Механизм | Где применяется | Проверка (тест/ревью) | Milestone |
|---|---|---|---|---|
| **(а)** relay/клиент-relay никогда не открывает соединений к произвольным хостам (нет exit) | iroh-relay по конструкции форвардит только между **подключёнными** к нему endpoint'ами; исходящие у процесса `aira-relay`: ACME (LE), `RelayAnnounce`/проба к anchor (фиксированный URL из каталога), push-уведомления mailbox — **единственный вектор SSRF/exit**: `NotificationEndpoint::UnifiedPush { url }` (аудит §4.3) → `push_allowlist` в конфиге (по умолчанию push-шлюз проекта + `ntfy.sh`), запрет редиректов, запрет приватных/loopback-диапазонов, пустое тело, ≤ 1 запрос/мин на коробку; в `--mode transport` (client-relay) push и ACME отсутствуют в коде вовсе (cfg-гейт), исходящих кроме anchor нет | `aira-relay` (M21), client-mode (M24a.2) | unit-тест валидатора push-URL (allowlist, redirect, RFC1918/ULA/loopback); интеграционный тест «relay в netns без egress, кроме anchor — работает»; чеклист ревью «новых `reqwest`/`connect` в aira-relay нет» | M21 / M24a.2 |
| **(б)** квоты полосы/соединений/хранилища на client-relay обязательны и настраиваемы | `max_clients`, глобальный token-bucket над `set_client_rate_limit`, месячный объём, расписание (§4.3); хранилища нет (§4.6); значения — в UI и `config.toml`, дефолты — константы `limits.rs` | client-mode | тесты лимитера; тест «51-й клиент получает `Deny`»; тест «при 20 ГБ → withdraw» | M24a.2 |
| **(в)** community iroh-relay закрыт от чужого (не-Aira) iroh-трафика | **Сетевой токен допуска**: `AiraRelayToken { v: 1, endpoint_id, not_before, expires (24 ч), scope: RELAY \| MAILBOX \| INTRO, nonce }`, подпись **Ed25519** ключом выдачи anchor (публичный ключ — в каталоге; Ed25519, а не ML-DSA — токен идёт в HTTP-заголовке при каждом relay-соединении, компрометация ключа = только абьюз/DoS, не конфиденциальность; ML-DSA-вариант — поле `v: 2` позже). Relay проверяет **офлайн** в `AccessControl::on_connect`: подпись, срок, `endpoint_id == ClientRequest::endpoint_id()` (доказан relay-handshake'ом — `server.rs:224-233`), scope, denylist из каталога. Выдача: `POST https://relays.<domain>/token` на anchor с PoW (adaptive, M22) и rate-limit по EndpointId/IP; продление за 2 ч до истечения; браузер (M14) — тот же токен в `?token=` (короткий срок делает утечку в логи терпимой). Операторам stock `iroh-relay` — `access.http.url` → `https://relays.<domain>/relay-auth` (anchor проверяет токен за них; менее приватно, документировать как «не рекомендуется»). Отзыв = короткий срок + denylist. Это заменяет и `access.shared_token` (секрет в open-source-бинаре — не секрет; оставить как «протокольная метка» в M20 до появления токенов), и `allowlist` (не масштабируется) | anchor (выдача), все relay (проверка) | тест «endpoint без токена → `Deny`»; «токен с чужим endpoint_id → `Deny`»; «истёкший → `auth_denied_reason` у клиента и автопродление»; fuzz парсера токена | M20 (shared_token как заглушка) → **M22** (выдача + проверка) |
| **(в′)** остаточный риск: модифицированный клиент с валидным токеном гоняет **свой** iroh-трафик между своими узлами через relay сообщества | не закрывается криптографией: relay не различает ALPN внутри QUIC | per-client `client_rx_bps` (2 MB/s), `max_clients`, месячные квоты на EndpointId в токене (anchor выдаёт токены с `scope` и лимитом), стоимость токена — PoW; relay-side метрика `bytes_rx_ratelimited_total`/`conns_rx_ratelimited_total` для алертов оператора; iroh сам уводит ~95 % байт напрямую | документировать в RELAY.md как принятый риск | M22 |
| **(г)** relay-режим в клиенте по умолчанию выключен на мобильных, metered-сетях и в странах с цензурой | Android — нет кода (cfg); metered — системные API; страны — `strict_countries` в подписанном каталоге + страна по IP от anchor при выдаче токена + локаль; override только в Advanced с предупреждением (§4.4) | client-mode | тест матрицы `should_offer_relay(platform, metered, country, ip_kind)`; ревью: `aira-ffi` не зависит от `aira-relay` | M24a.2 |
| **(д)** IP оператора client-relay публикуется — осознанный риск, объяснённый в UX | экран согласия (§4.2) с явными пунктами; статус в трее; «Остановить» в один клик; брокерная выдача вместо публичного списка; отдельный relay-ключ | client-mode UI (Tauri/letar + минимальный переключатель в egui) | UX-ревью текста; тест «без согласия relay-процесс не стартует» | M24a.2 |

### 6.4 Злоупотребление хранилищем и полосой

- Mailbox как «бесплатное хранилище»: `Register` только с подписью owner + токен со `scope: MAILBOX`; конверт ≤ 64 KB, 100/10 MB на коробку, 1 GB cap, TTL 7 дней на конверт, `Register` ≤ 20/сутки, вытеснение коробок без `Retrieve` (M21 п.5; аудит §5.3 таблица) — хранить что-то ценное невозможно (7 дней, 10 MB, только шифротекст, который relay не отдаст без owner-подписи, но и не гарантирует).
- Полоса: per-client rx-лимит iroh-relay + свои accept/conn-лимиты (F2.1) + токен; anchor: `[limits.client.rx] bytes_per_second = 2_000_000` из M20 остаётся.
- DoS на residential client-relay: лимиты + мгновенная остановка + TTL 30 мин записи (IP быстро исчезает из выдачи) + брокер выдаёт не более 3 адресов на запрос.
- DoS на выдачу токенов (anchor `/token`): adaptive PoW (M22, §11B.2), rate-limit по IP (здесь per-IP допустим — это HTTP, не relay), кэш выданных токенов.

### 6.5 Что уже закрывает mailbox v2 и что добавить в его дизайн

Закрывает (аудит §4.3): регистрация коробки владельцем (нет флуда «коробки по факту депозита»), owner/sender-псевдонимы на коробку и направление, relay-nonce против replay, квоты и TTL на конверт, intro-mailbox с PoW, push без содержимого.
Добавить: (1) `MailboxConfig.relays` = 2–3 `RelayRef` разных операторов без `client`-класса; (2) N-of-2 депозит + `envelope_id` для дедупа; (3) `RelayHello` ← `catalog_class`, `operator_id`, `min_client_version`; (4) `Register/Deposit/Retrieve` под токеном со `scope`; (5) `push_allowlist` + анти-SSRF; (6) `.well-known/aira-relay.json` как источник правды о лимитах relay для клиента (не hardcode 64 KB/100 — клиент читает лимиты relay и не шлёт лишнего); (7) intro-mailbox только на `anchor`/`server`.

## 7. Что в коде уже есть / мешает (path:line)

Всё, что ниже — HEAD `7726b46`; с тега v0.3.5 исходники не менялись (только docs-коммиты).

| Где (path:line) | Что есть | Значение для community-relay | Действие / milestone |
|---|---|---|---|
| `crates/aira-net/src/relay.rs:147-152, 231, 311-339` | `RelayServer` — in-memory mailbox v1 как `ProtocolHandler` на `aira/1/relay`; коробка создаётся при первом `Deposit` (`:231`), auth нет | Это **случайный «relay в каждом клиенте»** — ровно то, чего client-mode делать не должен (mailbox на домашнем ПК, без allowlist/квот/токена). Переиспользовать нечего, кроме констант квот и сценария теста (net-audit §2, таблица) | удалить вместе с ALPN в M21 п.1; в M19 п.7 не регистрировать (уже в §16.1-заметке спеки) |
| `crates/aira-net/src/protocol.rs:178-195` | `build_router(…, relay_server: Arc<RelayServer>, …)` регистрирует mailbox-relay в роутер клиента | блокер плана из net-audit §6 | M19 п.7: убрать параметр |
| `crates/aira-net/src/endpoint.rs:57-62` | ALPN `RELAY` анонсируется всегда | клиент заявляет relay-сервис, которого не должно быть | M19 |
| `crates/aira-net/src/endpoint.rs:77-81` | `presets::N0` в проде, `empty_builder` в тестах; `RelayMode` не упоминается; `bind(Option<SecretKey>)` без конфига | `AiraPreset` (M20 п.6) должен принимать **список relay из каталога** (снапшот в бинаре + обновление), `relay_auth_token` (заглушка `shared_token` → токен M22), `ca_tls_config` с pin-верификатором для `server-pinned`/`client` (иначе такие relay не подключить) | M20 (структура), M24a.1 (pin-верификатор) |
| `crates/aira-net/src/endpoint.rs:17-23` | QUIC-лимиты клиента | к relay-серверу не относятся (у iroh-relay свои) | — |
| `crates/aira-net/src/ratelimit.rs:24-38` | `limiter_for_tier` — не keyed, создаётся на каждый вызов | для relay нужен `governor::RateLimiter::keyed` по EndpointId — внутри `AccessControl` aira-relay, не здесь | M22 п.2 (клиент), M21 (relay) |
| `crates/aira-net/src/connection.rs:78-86` | `PeerTier { Verified, Known, Stranger }` | может отобразиться на `scope`/tier токена (контакты — без puzzle) | M22 |
| `crates/aira-net/src/discovery.rs:20-25` | `InvitationLink { pseudonym_pk, endpoint_addr_bytes }` — без relay-списка, без версии/подписи | добавить `relays: Vec<RelayRef>` (§5.5) вместе с version/expires/подписью из M19b п.4 | M19b п.4 + M21 п.7 |
| `crates/aira-net/tests/relay_offline.rs:17-88, 104-148` | deposit → retrieve → ack по реальным QUIC-соединениям; квота | шаблон интеграционных тестов `crates/aira-relay/tests/` (N-of-2, токен, `Deny`) | M21 |
| `crates/aira-daemon/src/main.rs:100-160` | сеть не поднимается, конфига сети нет | точка для `NetConfig` из каталога + `SetRelayMode` супервизора client-relay | M19/M20, M24a.2 |
| `crates/aira-daemon/src/handler.rs:19, 121-122, 835-859` | единственная «сетевая настройка» — `transport/mode` в `settings`, валидируется `TransportMode::from_str` | образец для `relay/mode`, `relay/limits`, `relay/consent_at`; транспорты удаляются в M19b — ключ можно переиспользовать под `relay/*` | M24a.2 |
| `crates/aira-daemon/src/types.rs:73-78` | `SetTransportMode { mode } / GetTransportMode` | добавить `SetRelayMode { enabled, limits } / GetRelayStatus` + событие `RelayStatus { clients, bytes, state }`; `SetRelays/GetRelays/GetNetStatus` уже в M19 п.12 | M24a.2 |
| `crates/aira-storage/src/settings.rs:1-3, 126-128` | ключ `relay/url` встречается только в doc-комментарии и тесте | схема ключей `relay/*` и таблица `relay_stats` (§5.2) — в миграцию схемы БД (M19 Phase A вводит `schema_version`) | M19 Phase A (резерв), M24a.1 |
| `crates/aira-gui/src/views/settings.rs:30-52` | ComboBox «Transport Mode» → `SetTransportMode` | место для раздела «Network»: список relay и статус (M19b п.5) + переключатель «Стать relay» (в egui — минимальный клиент: только тумблер и лимиты; полный экран согласия — Tauri/letar) | M19b п.5, M24a.2 |
| `crates/aira-cli/src/main.rs:436-451` | `/transport <mode>` | `/relay` (M19b п.5) + `/relay serve on|off` | M24a.2 |
| `crates/aira-ffi/src/runtime.rs:33, 95` | из `aira-net` используется только `BlobStore` | Android не получает relay-режима by construction; закрепить: `aira-ffi` не зависит от `aira-relay` (CI-guard `cargo tree -p aira-ffi | grep -c aira-relay == 0`) | M24a.2 |
| `docs/KEY_CONTEXTS.md:74` | `aira/relay/mailbox/v1` | заменить на v2-контексты (M21 п.2); роли `relay`/`mailbox` используют **хоп-EndpointId** (второй `Endpoint` из локального RNG — решение владельца, §8.1), не из seed; задокументировать как «не деривируется» | M21, M24a.2 |
| `Cargo.toml:2-11, 20, 27-28` | members без `aira-relay`; `rust-version = "1.82"`; `iroh = "0.97"` | добавить `crates/aira-relay`; MSRV 1.91; `iroh = "1.2"`, `iroh-relay = { version = "1.2", features = ["server"] }` только в aira-relay | M18 (версии), M21 (крейт) |
| `.github/workflows/release.yml:23-32, 57, 264-270` | 4 desktop-таргета + Android; собираются только `aira-cli/daemon/gui` | добавить `aira-relay` для `x86_64/aarch64-unknown-linux-musl` + Docker multi-arch → ghcr.io + attestation | M21/M22 |
| `docs/INSTALL.md:8-16` | «три бинарника» | четвёртый `aira-relay` в desktop-пакете (client-mode) + ссылка на `docs/RELAY.md` | M23/M24a.2 |
| `spec/03-network.md:85-89` | «bootstrap ноды… список зашит в бинарник, обновляется через signed update» | это и есть зародыш подписанного каталога relay (§5.6); переписать в терминах relay/pkarr (M20 п.8 уже требует) | M20 п.8 |
| `spec/17-cross-platform.md:196` | каталог `bootstrap/` в структуре репо — не существует | заменить на `deploy/` (compose, systemd, install.sh) | M21 |
| `spec/20-appendix.md:13` | открытый вопрос «Bootstrap нода — self-hosted только или публичные?» | закрывается этой архитектурой: anchor проекта + community `server` + `client` | M24a.1 (правка спеки) |
| `spec/13-threat-model.md:464-502` | §11B.5.1 multi-relay регистрация, `RelayMigration`, grace-period | согласуется с §5.4; дополнить классами и N-of-2 | M21 п.9 |

## 8. Архитектура «community relays» и правки планов

### 8.1 Архитектура «community relays» — таблица ролей

| Роль | Кто держит | iroh-relay (транспорт + QAD) | mailbox v2 / intro | onion-hop | Каталог / pkarr / токены | Класс | Обещание доступности |
|---|---|---|---|---|---|---|---|
| **Anchor relay проекта** | mail-сервер + VPS (M20/M21) | да, домен, ACME, 443 + 7842/udp | да (полные квоты) + intro-mailbox | роль возможна (дизайн — тема G) | **выдаёт токены**, держит каталог и брокер `client`-записей, active-checks, pkarr (`iroh-dns-server`), push-шлюз | `anchor` | целевой 99,5 %; всегда в `RelayMap` |
| **Server relay сообщества** | энтузиаст с VPS/домашним сервером, домен (или голый IP + pin) | да | да (по желанию оператора, `--mode transport` без него); intro — только `anchor`/`server` | опционально, флаг `ONION_HOP` (G) | регистрируется в каталоге, проверяет токены офлайн | `server` / `server-pinned` | измеряется каталогом (uptime_30d), 72 ч испытательный срок |
| **Desktop-нода с opt-in ролью `relay`** (поверх дефолтной роли `hop`, тема G) | desktop-клиент с публичным IP; роль `relay` — opt-in | да (WSS на высоком порту, self-signed + pin, QAD если UDP открыт) | **нет** | по умолчанию нет | эфемерная запись через брокер (TTL 30 мин), проверяет токены офлайн | `client` | нет; home relay только по opt-in/при блокировке anchor |

Инварианты для всех ролей: только между Aira-endpoint'ами (нет exit), допуск по сетевому токену, лимиты per-client и глобальные, `/healthz` + `.well-known/aira-relay.json`, версия ≥ `min_relay_version` каталога.

**Согласование с темой G (решение владельца в этой сессии, `onion-antiabuse.md` §5.1).** Роль `hop` (форвардер onion-ячеек) включена **по умолчанию** у всех desktop-нод на unmetered-сети (opt-out), у ноутбука на батарее — с урезанной долей, у мобильных — выключена; hidden mode (I2P strict countries) — автоматически. Opt-in остаются только роли **`relay`** (встроенный iroh-relay — нужны сертификат/pin и публичный адрес) и **`mailbox`** (чужие данные на диске). Всё, что в этом отчёте названо «client-relay» / «режим „стать relay“», — это opt-in роль `relay` поверх дефолтного `hop`. Роль `mailbox` на клиентской ноде по решению владельца тоже opt-in (Advanced, с предупреждением о хранении чужих данных); в каталоге её mailbox получает класс `server`/`server-pinned` только после 72 ч uptime — до этого контакты его не выберут (§5.1), т.е. защита пользователей регулируется классом, а не запретом. У ноды **две iroh-идентичности**: чат-EndpointId из seed и хоп-EndpointId из локального RNG (второй `Endpoint` в демоне); роли `relay`/`mailbox` чат-идентичность **не используют**: iroh-relay идентифицируется URL + pin, mailbox-сервис — хоп-EndpointId. Нумерация милстоунов: **M24a** — community relays (этот отчёт; фазы M24a.1 и M24a.2), M24b Aira Onion v1, M24c мосты/обфускация через iroh CustomTransport, M24d mix-профиль; M25 группы v2, M26 мультидевайс v2, M27 Bot API, M28 §6.x.

### 8.2 Правки в дизайн mailbox v2 (аудит §4.3)

1. `MailboxConfig.relays: Vec<RelayRef>` (2–3, разные `operator_id`, без `client`-класса) — единое поле с `ContactInfo.relays` (M19 Phase A п.1); `RelayRef { url, endpoint_id, class, pin }`.
2. Депозит N-of-2 параллельно + `envelope_id = BLAKE3("aira/relay/envelope-id/v2" ‖ header)` для дедупа при `Retrieve` с нескольких relay; порядок — по ratchet-`counter`, не по `seq`.
3. `RelayHello` ← `catalog_class`, `operator_id`, `min_client_version`; клиент отклоняет relay ниже `min_relay_version` каталога.
4. `Register/Deposit/Retrieve/Delete` — под токеном допуска со `scope: MAILBOX`; intro-mailbox — `scope: INTRO` + PoW как в M21 п.4.
5. `NotificationEndpoint::UnifiedPush { url }` — только из `push_allowlist`, без редиректов и приватных диапазонов (ограничение (а)).
6. Лимиты relay читаются клиентом из `.well-known/aira-relay.json`, константы 64 KB/100/10 MB — дефолты, не догма.
7. v2.1 «случайный EndpointId на relay-сессию» — поднять приоритет: при community-relay это единственное, что мешает оператору связать коробки одного пользователя.

### 8.3 Правки M20 (`spec/18-milestones.md:648-682`)

- п.2: «iroh-relay v1.1.0» → **1.2.0** (в registry уже 1.2.0; ≥ 1.0.2 обязательно по-прежнему).
- п.3 вариант B: `cert_mode = "Reloading"` вместо `"Manual"` + certbot deploy-hook (F2.7, `main.rs:673-684`).
- п.4: **`accept_conn_limit`/`accept_conn_burst` в iroh-relay ≤ 1.2.0 не реализованы** (`server.rs:486-503`) — лимит соединений делать в nginx (`stream`: `limit_conn`; вариант B: `limit_req`) и/или в `aira-relay` (`AccessControl`); `access = "everyone"` → `access.shared_token = ["<протокольная метка aira-v2>"]` как заглушка до M22 с явной оговоркой «не секрет».
- п.6 `AiraPreset`: relay-список берётся из **снапшота каталога** (`aira-core::catalog`, anchor ×2), поле `relay_auth_token`, поле `ca_tls_config` (пока `embedded()`; pin-верификатор — M24a.1); `home_relay_status()` → `DaemonEvent::NetStatus` + watchdog re-home (§5.3, 30 с); включить фичу `unstable-net-report` для latency/`global_v4`.
- Новый п.9 — тест: два `run_relay_server`, kill одного → re-home ≤ 60 с, доставка после повторного lookup (регресс на #4476); тест «второй relay-URL в `EndpointAddr` используется/не используется» (закрывает §9).
- п.7: «второй relay на VPS» остаётся; добавить: оба anchor — в снапшот каталога, DNS `relays.<domain>` для каталога/токенов/пробы.

### 8.4 Правки M21 (`spec/18-milestones.md:684-718`)

- п.1: `aira-relay` = **один бинарь** со встроенным iroh-relay (`iroh-relay/server`), mailbox v2, intro, `/healthz`, метриками, ACME; режимы `--mode full|transport|mailbox`; systemd-юнит **один** (заменяет отдельный `iroh-relay` из M20 на mail-сервере — M20 остаётся как «поднять stock iroh-relay сейчас», M21 переводит на `aira-relay`); `deploy/` (compose, systemd, `install.sh`); `release.yml`: musl x86_64/aarch64 + Docker `ghcr.io/kamiletar/aira-relay` (без `latest`) + attestation.
- п.3: `RelayHello` ← `catalog_class, operator_id, min_client_version`; `envelope_id`; N-of-2 (§5.4).
- п.5: квоты — плюс `max_clients`, accept-лимит, `push_allowlist`.
- п.6: push только по allowlist (а).
- п.7: `MailboxConfig.relays` 2–3 разных операторов; `deposit` N-of-2; `Retrieve` со всех + дедуп.
- п.8 тесты: + «deposit без токена/с чужим endpoint_id → Deny», «N-of-2: один relay мёртв — доставлено», «дубликат с двух relay — один в истории», «push на URL вне allowlist → отказ», fuzz токена и `RelayAnnounce`.
- п.9 спека: + `docs/RELAY.md` v1 (§3.4), `spec/03-network.md` §5.1.2 «Роли relay» (таблица §8.1), `spec/20-appendix.md:13` закрыть.
- Оценка M21: +1 неделя к «2–3 неделям» за счёт встраивания iroh-relay, Docker и RELAY.md (см. §3.6).

### 8.5 Правки M22 (`spec/18-milestones.md:720-739`)

- п.3 «опционально `access.http.url`» → **обязательно**: сервис выдачи токенов `POST /token` на anchor (PoW adaptive из п.1–2, rate-limit по IP/EndpointId, срок 24 ч, `scope`) + `AiraAccess` (верификатор в `aira-relay`, офлайн по ключу из каталога) + `access.http.url` → `/relay-auth` как путь для stock `iroh-relay`; denylist EndpointId в каталоге.
- Новый пункт: `strict_countries` и `X-Aira-Country` в ответе `/token` (данные для (г)).
- Тесты: без токена → `Deny`; чужой endpoint_id → `Deny`; истёкший → `auth_denied_reason` + автопродление у клиента.

### 8.6 Правки M23

- п.3: `PRIVACY.md` — раздел «Что видит оператор relay (anchor / сообщества / клиент-relay)»; `docs/THREAT_MODEL.md` — §6 этого отчёта; `INSTALL.md` — ссылка на `RELAY.md` («хотите помочь сети — поднимите relay»).
- п.7: в release notes беты — «community relays: standalone `aira-relay` доступен; режим relay в клиенте — после беты».

### 8.7 Milestone 24a — «Community relays» (после M23, v0.5.x → v0.6.0; фазы M24a.1 и M24a.2)

**M24a.1 — Каталог и server-relay сообщества (2–3 недели; зависит от M21, M22)**

1. `aira-core::catalog`: формат `RelayCatalog/RelayEntry` (§5.6), подпись ML-DSA-65, `next_signing_key`, снапшот в бинаре, парсер с fuzz-таргетом.
2. Сервис каталога в `aira-relay --catalog` на anchor: `RelayAnnounce` (подпись оператора + PoW 20 бит + лимит 5/оператор), active-checks (5 мин), state-машина классов (§5.1), выдача подписанного файла, брокер `client`-записей (≤ 3 на запрос, по токену), `strict_countries`.
3. `aira-relay register/withdraw/doctor/status/update-check`, `.well-known/aira-relay.json`, `cert = "self-signed"` + печать pin (класс `server-pinned`).
4. Клиент: загрузка/проверка каталога (сутки, `expires_at`), `relay_stats` + health-score + backoff (§5.2), выбор home relay и M mailbox-relay с правилом разных операторов и /24,/48 (§5.7), pin-верификатор в `ca_tls_config` (`custom_server_cert_verifier`: SNI/IP → pin из каталога или `RelayRef` контакта, иначе webpki), `RelayRef` в `InvitationLink`, UI «Network → Relays» (список, класс, статус, «использовать relay сообщества» opt-in), CLI `/relay`.
5. Тесты: подпись/просрочка/`next_signing_key` каталога; state-машина классов (проптест по последовательности проверок); «relay другого оператора выбран для второй коробки»; «pin не совпал → соединение отклонено»; e2e: три in-process relay (anchor + 2 server), падение одного, доставка через второй.
6. Документы: `docs/RELAY.md` v2 (регистрация, классы), `spec/03-network.md` §5.5 «Каталог relay», `spec/13` §11B.5.2 «Community relays», `PRIVACY.md`.

**M24a.2 — Opt-in роли `relay` и `mailbox` в клиенте поверх дефолтной роли `hop` (≈ 3 недели; зависит от M24a.1, M19b п.5, M17 для полного UI; хоп-EndpointId — общий с M24a.2)**

1. `aira-relay --mode transport --bind … --cert self-signed --announce-ephemeral` (cfg-гейт: без mailbox/ACME/push), лимиты §4.3 (`limits.rs`), глобальный token-bucket над `set_client_rate_limit`, `max_clients` в `AccessControl`.
2. Демон: детектор кандидата (`net_report`: `global_v4/v6`, `mapping_varies`, portmapper; стабильность адреса 24 ч; metered; страна; платформа), IPC `SetRelayMode/GetRelayStatus`, супервизор дочернего процесса (перезапуск, остановка при изменении сети/metered/батарее), проба через anchor `POST /probe` с двух anchor, `announce` каждые 10 мин, `withdraw` при остановке.
3. Anchor: `POST /probe` (TLS+WS `/relay` + QAD к кандидату, ответ `reachable_v4/v6, rtt, observed_ip`), rate-limit по токену.
4. UI: экран согласия (§4.2, тексты в Fluent), лимиты, статистика, трей; egui — тумблер + лимиты; Tauri/letar — полный экран. Firewall-подсказки (`doctor`), UPnP/NAT-PMP TCP-маппинг через `portmapper` (проверить поддержку TCP — §9).
5. CI-guard: `aira-ffi` не зависит от `aira-relay`; `aira-daemon` не линкует `iroh-relay/server`.
6. Тесты: матрица `should_offer_relay`; «без согласия процесс не стартует»; «metered → пауза»; «51-й клиент → Deny»; «20 ГБ → withdraw»; e2e с anchor-пробой на loopback.

Порядок в релизном пути: `… → M23 (бета) → M24a.1 → M24a.2`, далее темы G (M24b Aira Onion v1, M24c мосты/обфускация через iroh CustomTransport, M24d mix-профиль) и M25 группы v2, M26 мультидевайс v2, M27 Bot API, M28 §6.x; ни одна часть M24a не блокирует бету, но **§8.3–8.5 правки M20–M22 нужны до беты**, иначе каталог/токены придётся вводить с ломкой формата (relay-URL в контактах, `RelayHello`).

### 8.8 Вопросы владельцу

1. **Кто подписывает каталог**: один офлайн-ключ ML-DSA-65 у владельца (просто) или 2-of-3 (владелец + два доверенных оператора; сложнее, но каталог не умирает с одним ключом)? Где хранится, как часто подписывается (еженедельно / по событию)? Допустима ли автоматическая подпись `client`-брокера краткоживущим делегированным ключом?
2. **Домен для операторов**: давать ли поддомены `<id>.r.<domain>` с A-записью на IP оператора (нужен DNS-сервис с API рядом с `iroh-dns-server`; плюс: LE-сертификат без своего домена и без pin; минус: репутация домена проекта, зона как цель) — или ограничиться «свой домен либо голый IP + pin»?
3. **Mailbox на клиентской ноде**: владелец оставил как opt-in (§8.1); рекомендация — прятать в Advanced, не предлагать проактивно и не давать класс выше `candidate` до 72 ч uptime. Подтвердить.
4. **Client-relay как home relay**: только opt-in/при блокировке anchor (рекомендация) или по умолчанию для всех?
5. **Override (г) в «строгих» странах**: разрешать включение через Advanced с предупреждением (рекомендация — да, ради сообществ под блокировкой) или запретить, как I2P?
6. **Ключ токенов допуска**: Ed25519 (рекомендация, компактно) или сразу ML-DSA-65 (PQ-последовательно, +3,3 KB на соединение)?
7. **Открытые relay** (`access = "everyone"`) — в каталог не пускать (рекомендация) или пускать с пометкой?
8. **Абьюз-контакт и юридика**: кто отвечает на жалобы по anchor; текст для RELAY.md §6 («не exit», аналогия Tor bridge, «не юридическая консультация») — согласовать.
9. Android: подтвердить исключение из relay-режима навсегда (не «пока»).
10. Бюджет: второй anchor-VPS и `relays.<domain>` (каталог/токены/проба) — до беты (M20 п.7 уже требует VPS).

## 9. Не проверено / открытые вопросы владельцу

### 9.1 Не проверено (сеть/инструменты)

- **Заблокированы egress-прокси** (WebFetch → `EGRESS_BLOCKED`): `docs.iroh.computer`, `www.iroh.computer` (post-mortem падения relay n0 — не прочитан), `tailscale.com`, `simplex.chat`, `geti2p.net`/`i2p.net`, `letsencrypt.org`, `chatmail.at`, `delta.chat`, `support.delta.chat`, `fosdem.org`, `community.torproject.org`, `nodes.tox.chat`. Использованы зеркала на GitHub (`simplex-chat/docs/SERVER.md`, `i2p/i2p.www`, `tailscale/cmd/derper/derper.go`, `TokTok/c-toxcore`, `chatmail/relay` README, `nostr-protocol/nips`, `n0-computer/tokio-rustls-acme`) и pkg.go.dev (Snowflake proxy). Факты по chatmail `cmdeploy init/run/dns/test`, Tox `nodes.tox.chat` (`status_tcp`), Snowflake «entry, не exit» и Delta Chat multi-transport — **из сниппетов поиска и по памяти**; критичные выводы отчёта на них не опираются.
- `cargo build/test` не запускались (правило задания); строки кода — по чтению файлов HEAD `7726b46`.
- `tokio-rustls-acme`: проверен `main` на GitHub (форк n0), а не исходник релиза 0.9.0 (в registry его нет). Вероятность, что 0.9.0 умеет IP-идентификаторы при их отсутствии в `main`, — нулевая, но формально не сверено.
- Let's Encrypt IP-сертификаты: ограничения (`shortlived`, http-01/tls-alpn-01, IPv4+IPv6) — из сниппетов, первоисточник заблокирован.

### 9.2 Не проверено (поведение iroh — нужны тесты в M20)

- Использует ли `iroh::socket` **второй** `TransportAddr::Relay` из `EndpointAddr` получателя как fallback, если первый relay не отвечает (модель данных позволяет — `iroh-base endpoint_addr.rs:42-57`; логика выбора пути не читалась).
- Публикует ли `PkarrPublisher` новую запись **автоматически при смене home relay** (ожидаемо — publisher подписан на изменения адреса; не сверено по `address_lookup/pkarr.rs`).
- Делает ли отправитель повторный address-lookup при неудаче соединения через стейл relay-URL (issue #4476 говорит, что пиры «follow the stale record»).
- `portmapper` 0.15: поддержка маппинга **TCP**-порта (нужно для WSS client-relay; README заявляет UPnP/PCP/NAT-PMP без уточнения протокола).
- Лимит размера pkarr-пакета (~1000 байт) — по памяти спецификации pkarr; в `pkarr-5.0.4` константа не найдена быстрым grep'ом.
- Поведение `Endpoint::online()`/`home_relay_status()` при `Access::Deny` на **всех** relay (ожидаемо — `auth_denied_reason` на каждом и `online()` не завершается).
- iroh-dns-server pkarr TTL 30 с — из `relay-deploy-plan.md`, повторно не сверялось.

### 9.3 Не проверено (платформы/UX)

- Точные API metered-сети (Windows `GetConnectionCost`, macOS `NWPathMonitor.isExpensive`, NetworkManager `Metered`) — по памяти; поведение в Tauri/egui-обёртках не проверялось.
- Диалог Application Firewall macOS для неподписанного бинаря при `listen` — по памяти.
- Число «строгих стран» I2P (42) — из сводки зеркала; сам список нужно взять из `i2p.www` при реализации (г).
- Объёмы работ (§3.6, §8.7) — экспертная оценка без прототипа.

### 9.4 Решения владельца — см. §8.8 (10 вопросов)
