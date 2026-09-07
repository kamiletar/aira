# iroh 1.1 и self-hosted iroh-relay на mail-сервере — результат исследования (2026-09-07)

> Источник: агент research:iroh-relay (raw: `raw/acd324dbc071a4ff4.json`). Краткая выжимка — в `../release-audit-2026-09.md` §3.2–3.3.

## Резюме

Aira сидит на iroh 0.97.0 (Cargo.toml:27, Cargo.lock:3849) и использует presets::N0 (crates/aira-net/src/endpoint.rs:80) — т.е. публичные relay/DNS n0. По официальной политике n0 публичные relay для клиентов v0.9x/rc отключаются 30 сентября 2026, а сами публичные relay объявлены «development and hobby use only», rate-limited, без SLA, видят метаданные (IP/время/объёмы) и «не рекомендуются для sensitive data». Для приватного мессенджера, идущего в релиз, это означает: (1) миграция на iroh 1.1.0 (2026-08-25, MSRV 1.91, QUIC=noq) — обязательное условие, она же разблокирует ml-dsa 0.1.1 (facts-crates.md, эксперимент A); (2) свой iroh-relay 1.1 (feature server) рядом с mail-сервером. iroh-relay — stateless, хранит только соединения, не данные («relays are stateless. They don't store your application data»), трафик E2E-зашифрован; store-and-forward mailbox из spec §6.3b/§6.5/§11B.5 — это отдельный сервис Aira (ALPN crate::alpn::RELAY, endpoint.rs:61), а не iroh-relay. Транспорт relay с 0.91 — только WebSocket (`/relay`), STUN в 1.x нет — его заменил QAD (QUIC address discovery, UDP 7842, требует TLS). Порты по умолчанию 80/443/7842udp/9090 конфликтуют с веб-частью mail-сервера по 80/443; рабочее решение — nginx `stream` + `ssl_preread` (SNI-passthrough relay.example.org → 127.0.0.1:8443), relay сам получает Let's Encrypt через TLS-ALPN-01; запасной вариант — терминация TLS на nginx (handshake relay имеет challenge-fallback, когда TLS-exporter недоступен, тот же путь используется в браузерах). Discovery на своём домене: presets::Minimal + PkarrPublisher::builder(url) + PkarrResolver::builder(url) (без NS-делегирования, только HTTPS) и опционально DnsAddressLookup + iroh-dns-server 1.1 (порт 53 + /pkarr + /dns-query). Браузер (M14): iroh 1 с default-features=false, только relay по wss://host/relay, auth-token через `?token=`. Статистика n0: ~9 из 10 сетевых конфигураций дают прямое соединение, ~95 % байт идёт напрямую; 0.96/0.97 имели регрессию hole punching, исправленную в 0.98.

## Факты (с источниками)

- [high, 2026-09-07] iroh 1.0.0 опубликован 2026-06-15, 1.1.0 — 2026-08-25; все 1.x требуют rust 1.91; 0.98.2 (2026-04-28) — rust 1.89. Aira: iroh 0.97.0 (Cargo.toml:27, Cargo.lock:3849-3850).  
  <https://crates.io/api/v1/crates/iroh>
- [high, 2026-06-15] Публичные relay n0: поддержка клиентов v0.9x и v1.0.0-rcX заканчивается 30 сентября 2026; v0.35x — 31 декабря 2026; v1.0 — до End of Life. Wire-breaking изменения relay получают новые URL.  
  <https://www.iroh.computer/blog/v1>
- [high, 2026-06-15] iroh 1.0 гарантирует стабильность wire-протокола и API: endpoint v1 совместим с любым другим v1 независимо от minor-версии; за 30 дней на публичных relay создано >200 млн endpoint'ов; «normal to see 95% of data transferred in a connection pass directly».  
  <https://www.iroh.computer/blog/v1>
- [high, 2026-09-07] Публичные relay: «suitable for development and hobby use only», без SLA, официально поддерживается только последний stable iroh, rate-limited, «relays can see connection metadata: source and destination IP addresses, connection times, and the amount of data transferred. We recommend against using public relays for sensitive or confidential data».  
  <https://docs.iroh.computer/iroh-services/relays/public.md>
- [high, 2026-09-07] Точные rate-limit'ы публичных relay не публикуются и меняются; лимит применяется per-connection (token bucket rx: bytes_per_second, max_burst_bytes); клиент получает уведомление о троттлинге (iroh ≥1.0.4).  
  <https://docs.iroh.computer/relays/rate-limiting.md>
- [high, 2026-09-07] Relay stateless и не хранит данные приложения: «Unlike traditional servers, relay servers are stateless. They don't store your application data; they just facilitate connections», трафик E2E-зашифрован и relay его не читает.  
  <https://docs.iroh.computer/concepts/relays>
- [high, 2026-09-07] Статистика NAT traversal: «roughly 9 out of 10 networking conditions allow a direct connection»; реализация детерминированная; при неудаче — fallback на relay.  
  <https://docs.iroh.computer/concepts/nat-traversal>
- [high, 2026-04-17] iroh 0.96 и 0.97 содержали регрессии hole punching («Connections that used to punch through would sometimes sit on the relay»), исправлено в 0.98.0 (2026-04-17); 0.98 также добавил pluggable crypto backends, rate-limiting hooks в router и relay protocol v2 с version negotiation.  
  <https://www.iroh.computer/blog/iroh-0-98-0-getting-back-to-traversing-nats>
- [high, 2025-07] С iroh 0.91 единственный транспорт до relay — WebSocket (raw TCP удалён); аутентификация клиента relay использует TLS keying material exporter (RFC 5705, идея из RFC 9729).  
  <https://www.iroh.computer/blog/iroh-0-91-0-the-last-relay-break>
- [high, 2026-08-25] Relay handshake имеет два механизма: заголовок с подписью TLS-exporter-материала (быстрый, 0 RTT) и явный ServerChallenge/ClientAuth. Exporter «is not available in browsers» и «might break when there's an HTTPS proxy» — тогда используется challenge fallback (handshake.rs:1-26, :284, :448, тест test_handshake_challenge_fallback :790).  
  <https://raw.githubusercontent.com/n0-computer/iroh/v1.1.0/iroh-relay/src/protos/handshake.rs>
- [high, 2026-05-07] Breaking changes 1.0.0-rc.0: MSRV 1.91; удалены Incoming::local_ip, PathWatcher/PathInfo, ConnectionInfo (→ WeakConnectionHandle), Builder::transport_bias; iroh::endpoint::transports закрыт feature `unstable-custom-transports`; DhtAddressLookup → крейт iroh-mainline-address-lookup, MdnsAddressLookup → iroh-mdns-address-lookup, protocol::AccessLimit → iroh-util; iroh-relay: удалены CertConfig::Reloading, TlsConfig::quic_bind_addr, ClientBuilder::query_param (→ auth_token); добавлен AcmeConfig; AccessConfig::Restricted получает &ClientRequest; iroh-dns-server: модули приватные, ZoneStoreOptions → StoreConfig.  
  <https://www.iroh.computer/blog/iroh-1-0-0-rc-0>
- [high, 2026-06-15] v1.0.0 changelog: iroh-relay — Bearer-token access control без внешнего сервиса (#4326), несколько hostname для Let's Encrypt (#4337), CaRootsConfig→CaTlsConfig (#4300), happy-eyeballs IPv4/IPv6 (#4299); «Update relay urls to 1.0 stable» (#4341).  
  <https://github.com/n0-computer/iroh/releases/tag/v1.0.0>
- [high, 2026-07-06] iroh 1.0.2 (2026-07-06): уязвимость relay-сервера — кадр короче endpoint id вызывал panic (relay собирается с panic=abort → любой клиент ронял сервер); фикс #4389; добавлен fuzz парсеров relay; добавлен live-update rate limit `relay_service.set_client_rate_limit(...)` (#4381). Self-hosted relay должен быть ≥1.0.2.  
  <https://www.iroh.computer/blog/iroh-1-0-2>
- [high, 2026-08-25] v1.0.3 (2026-07-20): в n0 preset добавлен pkarr resolver (#4412); v1.1.0 (2026-08-25): метрики relay-соединений (#4477), relay сообщает клиентам о rate-limit (#4455), breaking — сериализация CustomAddr (#4465).  
  <https://github.com/n0-computer/iroh/releases>
- [high, 2026-08-25] Endpoint API 1.1: `Endpoint::empty_builder()` отсутствует (используется в crates/aira-net/src/endpoint.rs:78 — единственные 3 ошибки компиляции при bump до iroh 1.1 + iroh-blobs 0.103 по эксперименту D); пресеты в iroh/src/endpoint/presets.rs: Empty (:37, ничего не ставит, bind() упадёт), Minimal (:59, только crypto provider), N0 (:113 — PkarrPublisher::n0_dns + PkarrResolver::n0_dns + DnsAddressLookup::n0_dns вне браузера + default_relay_mode, :125-136), N0DisableRelay (:175). Форма: `Endpoint::bind(preset)` или `Endpoint::builder(preset)...bind()`.  
  <https://raw.githubusercontent.com/n0-computer/iroh/v1.1.0/iroh/src/endpoint/presets.rs>
- [high, 2026-08-25] Features iroh 1.1.0: default = [metrics, fast-apple-datapath, portmapper, tls-ring]; альтернатива tls-aws-lc-rs (при обоих — предпочитается ring); test-utils (in-process relay `iroh::test_utils::run_relay_server()`), platform-verifier, qlog, unstable-custom-transports, unstable-net-report.  
  <https://raw.githubusercontent.com/n0-computer/iroh/v1.1.0/iroh/Cargo.toml>
- [high, 2026-09-07] Свой relay на клиенте: `Endpoint::builder(presets::N0).relay_mode(RelayMode::Custom(RelayMap::from_iter([url1, url2])))` или `RelayMode::custom([...])`; `RelayConfig::new(url, Option<RelayQuicConfig>)`, `RelayQuicConfig::new(port)` (по умолчанию 7842), `RelayMap::with_auth_token` / `RelayConfig::with_auth_token` (relay_map.rs:154,232-307); `Endpoint::remove_relay(&RelayUrl)`.  
  <https://docs.iroh.computer/deployment/dedicated-infrastructure>
- [high, 2026-09-07] Свой discovery: `Endpoint::builder(presets::Minimal).address_lookup(PkarrPublisher::builder("https://my-dns-server.example/pkarr")).address_lookup(DnsAddressLookup::builder("my-dns-server.example"))`; оба пира должны публиковать/резолвить на одном сервере; по умолчанию PkarrPublisher публикует только home relay URL, IP — через `.addr_filter(AddrFilter::unfiltered())`. Публичный dns.iroh.link — rate-limited, без гарантий uptime.  
  <https://docs.iroh.computer/connecting/dns-discovery>
- [high, 2026-08-25] `PkarrResolver::builder(pkarr_relay: Url)` (iroh/src/address_lookup/pkarr.rs:507) резолвит по HTTP GET /pkarr — NS-делегирование домена не требуется; константы N0_DNS_PKARR_RELAY_PROD = https://dns.iroh.link/pkarr (:127), STAGING (:134).  
  <https://raw.githubusercontent.com/n0-computer/iroh/v1.1.0/iroh/src/address_lookup/pkarr.rs>
- [high, 2026-08-25] iroh-relay 1.1.0 (crates.io 2026-08-25) feature `server` тянет tokio-rustls-acme, tokio-websockets, rustls-cert-reloadable-resolver, clap, toml; default = [metrics, tls-ring]; альтернатива tls-aws-lc-rs. Сборка: `cargo build --profile optimized-release --package iroh-relay --features server`.  
  <https://raw.githubusercontent.com/n0-computer/iroh/v1.1.0/iroh-relay/Cargo.toml>
- [high, 2026-08-25] Порты по умолчанию iroh-relay (defaults.rs): HTTP 80, HTTPS 443, QUIC/QAD UDP 7842 («QUIC» на клавиатуре телефона), metrics 9090; key cache по умолчанию на 1M клиентов ≈56 MB. STUN-констант в 28 файлах iroh-relay/src нет — STUN заменён QAD; `EXPOSE 3478/udp` в docker/Dockerfile и `-p 3478:3478/udp` в docker/README.md — устаревшие.  
  <https://raw.githubusercontent.com/n0-computer/iroh/v1.1.0/iroh-relay/src/defaults.rs>
- [high, 2026-08-25] Config iroh-relay 1.1 (main.rs:88-215, 394-534): enable_relay (default true; false → только QAD-сервер для hole punching), http_bind_addr (default [::]:80, --dev [::]:3340), [tls]{https_bind_addr (default :443), quic_bind_addr (default :7842), hostname (строка или список), cert_mode = 'Manual'|'LetsEncrypt', cert_dir, manual_cert_path (default <cert_dir>/default.crt), manual_key_path (default.key), prod_tls (default true), contact}, enable_quic_addr_discovery (default false, требует [tls]), [limits]{accept_conn_limit: f64, accept_conn_burst: usize, client.rx.bytes_per_second: u32, client.rx.max_burst_bytes: u32}, enable_metrics (default true), metrics_bind_addr (default :9090), key_cache_capacity, access. При наличии [tls] все relay-сервисы живут на https_bind_addr, на http_bind_addr остаётся только captive portal (:113-117).  
  <https://raw.githubusercontent.com/n0-computer/iroh/v1.1.0/iroh-relay/src/main.rs>
- [high, 2026-08-25] Access control iroh-relay: `access = "everyone"` (default); `access.allowlist = [endpoint-id...]`; `access.denylist`; `access.shared_token = ["token-a"]` (клиент шлёт `Authorization: Bearer` или `?token=`; env IROH_RELAY_ACCESS_TOKEN; без отзыва кроме рестарта); `access.http.url` + `access.http.bearer_token` (POST с заголовком X-Iroh-Endpoint-Id, ответ 200 + текст `true`; env IROH_RELAY_HTTP_BEARER_TOKEN). Env IROH_RELAY_ACME_URL / IROH_RELAY_ACME_CA переопределяют ACME directory/CA.  
  <https://raw.githubusercontent.com/n0-computer/iroh/v1.1.0/iroh-relay/README.md>
- [high, 2026-08-25] Маршруты relay: WebSocket `/relay` (и `/derp` для совместимости) — http.rs:13, http_server.rs:329; `/ping` (RELAY_PROBE_PATH, http.rs:15); `/generate_204` — по HTTPS для net_report-проб и по plain HTTP как captive-portal (server.rs:16, :824, :1172); `GET /healthz` (server.rs:740). Версия протокола согласуется через WebSocket subprotocol (http_server.rs:558-620).  
  <https://raw.githubusercontent.com/n0-computer/iroh/v1.1.0/iroh-relay/src/http.rs>
- [high, 2026-08-25] Клиент relay (client.rs:268-275, :392-420): URL = relay_url с path `/relay` и схемой ws/wss; auth-token нативно — заголовок `Authorization: Bearer`, под wasm — query `?token=` (:157-158, :407-411); в браузере соединение через ws_stream_wasm::WsMeta::connect с subprotocol-списком версий.  
  <https://raw.githubusercontent.com/n0-computer/iroh/v1.1.0/iroh-relay/src/client.rs>
- [high, 2026-09-07] Официальная страница self-hosted relay: документация опций не опубликована («peek in the source code … main.rs»); минимальный config: http_bind_addr='[::]:80', [tls] https_bind_addr='[::]:443', hostname, cert_mode='LetsEncrypt', cert_dir='/var/lib/iroh-relay/certs', contact; запуск `iroh-relay -c config.toml`; health: `curl --fail https://relay.example.org/healthz`; бинарники — GitHub releases, образ — n0computer/iroh-relay.  
  <https://docs.iroh.computer/iroh-services/relays/self-hosted.md>
- [high, 2026-08-25] Release v1.1.0 assets: iroh-relay-v1.1.0-{x86_64,aarch64}-unknown-linux-{gnu,musl}.tar.gz, -apple-darwin, -pc-windows-msvc.zip и те же для iroh-dns-server; файлов checksum среди assets нет.  
  <https://github.com/n0-computer/iroh/releases/tag/v1.1.0>
- [high, 2026-09-07] Docker Hub n0computer/iroh-relay: теги v1.1.0 и latest (2026-08-25, amd64+arm64, ~15.3 MB), v1.0.3, v1.0.2, v1.0.1, v1.0.0; образ alpine, ENTRYPOINT /iroh-relay, запуск `docker run -v cfg:/config/iroh-relay.conf -p 443:443 ... n0computer/iroh-relay:latest --config /config/iroh-relay.conf`.  
  <https://hub.docker.com/r/n0computer/iroh-relay/tags>
- [high, 2026-09-07] Let's Encrypt в iroh-relay реализован через tokio-rustls-acme: «validation mechanism used is TLS-ALPN-01 OR HTTP-01 … TLS-ALPN-01 is used by default and recommended»; при TLS-терминирующем прокси предлагается HTTP-01 (но в конфиге iroh-relay такой опции нет — остаётся cert_mode='Manual').  
  <https://raw.githubusercontent.com/FlorianUekermann/rustls-acme/main/rustls-acme/src/lib.rs>
- [high, 2026-09-07] Рекомендации n0 по своему relay: ставить рядом с пользователями, для production минимум два relay в разных регионах (клиенты автоматически fail-over по списку), «Each relay handles up to 60,000 concurrent connections».  
  <https://docs.iroh.computer/add-a-relay>
- [high, 2026-09-07] Managed relay n0 (Iroh Services) с июня 2026 аутентифицированы по умолчанию (rcan capability token в `Authorization: Bearer`, токен 30 дней), self-hosted — «iroh is unopinionated», строишь свою схему; крейт iroh-services 1.0.0.  
  <https://www.iroh.computer/blog/authenticated-relays>
- [high, 2026-08-25] iroh-dns-server 1.1.0: pkarr relay + DNS-сервер; сервисы: DNS UDP/TCP, HTTP(S) `/pkarr` GET/PUT и `/dns-query` (DoH); config.prod.toml: pkarr_put_rate_limit='smart', [https] port=443 domains cert_mode='lets_encrypt', [dns] port=53 default_soa default_ttl=30 origins rr_a rr_ns, [mainline] enabled=false; образ n0computer/iroh-dns-server (53/udp, 9090).  
  <https://raw.githubusercontent.com/n0-computer/iroh/v1.1.0/iroh-dns-server/README.md>
- [high, 2026-09-07] Браузер: iroh компилируется в wasm, нужно `iroh = { version = "1", default-features = false }` (теряется metrics); прямых соединений нет — весь трафик через relay по WebSocket, E2E-шифрование сохраняется; npm-пакет n0 не публикует — рекомендуют свой wasm-bindgen-обёрточный крейт; iroh-gossip поддерживает браузер с 0.33.  
  <https://docs.iroh.computer/languages/wasm-browser>
- [high, 2025-02] iroh в браузере — «relay only» режим, hole punching невозможен без WebRTC/WebTransport; QAD появился на relay в 0.32 как замена STUN для определения публичного адреса.  
  <https://www.iroh.computer/blog/iroh-0-32-0-browser-alpha-qad-and-n0-future>
- [high, 2026-09-07] Спека Aira: store-and-forward relay с pairwise mailbox — spec/04-protocol-wire.md:192-235 (§6.3b, TTL 7 дней, relay = iroh NodeId), spec/05-protocol-versioning.md:61-75 (§6.5 mailbox_id = BLAKE3(shared_secret‖'mailbox')), spec/13-threat-model.md:436-503 (§11B.5 квоты 10 MB/100 msg/30 deposits/min, PoW 16 бит, §11B.5.1 версионирование и multi-relay); ALPN RELAY зарегистрирован в crates/aira-net/src/endpoint.rs:61. spec/03-network.md:16 всё ещё говорит «DERP-серверы» (устаревший термин).  
  <C:/web/aira/spec/04-protocol-wire.md>
- [high, 2026-09-07] Аудит HEAD 971e038: quinn-proto 0.11.14 RUSTSEC-2026-0185 (high), hickory-proto 0.25.2 RUSTSEC-2026-0118/0119 (без фикса в 0.25) — уходят с апгрейдом iroh 1.x (noq, hickory-resolver 0.26); апгрейд ml-dsa 0.1.1 при iroh 0.97 не разрешается (iroh-base 0.97 пинит digest =0.11.0-rc.10).  
  <C:/Users/Kami/AppData/Local/Temp/claude/C--web-aira/099428dc-2d91-4436-8543-4bf51c9d4475/scratchpad/facts-crates.md>

## Следствия для Aira

- Жёсткий дедлайн: релиз на iroh 0.97 невозможен — публичные relay n0 перестанут обслуживать 0.9x-клиентов 30.09.2026; кроме того 0.97 несёт известную регрессию hole punching (исправлена в 0.98) и RUSTSEC-2026-0185 в quinn-proto. Миграция на iroh 1.1.0 (+ iroh-blobs 0.103) — блокер №1 и предпосылка для ml-dsa 0.1.1 / ml-kem 0.3 (Milestone 9.6 Phase A).
- Код-объём миграции сети мал: единственный прямой потребитель iroh — aira-net (+ daemon через обёртки); эксперимент D дал 3 ошибки в crates/aira-net/src/endpoint.rs (Endpoint::empty_builder удалён → presets::Minimal/Empty). Но `presets::N0` на строке 80 надо заменить собственным пресетом Aira (relay_mode = RelayMode::Custom(RelayMap) + PkarrPublisher/PkarrResolver/DnsAddressLookup на своём домене), иначе релизные клиенты продолжат ходить через n0 (метаданные, rate limit, без SLA).
- Две разные сущности «relay» — надо развести в спеке и коде: (a) iroh-relay — stateless WebSocket/QAD-сервер, не хранит ничего, нужен всем клиентам за NAT и всем браузерным клиентам; (b) Aira mailbox relay (spec §6.3b/§6.5/§11B.5, ALPN RELAY) — store-and-forward, отдельный iroh-endpoint со своим EndpointId, который сам подключается к iroh-relay. Оба могут жить на одном mail-сервере, но это два процесса/юнита. spec/03-network.md:16 («DERP») и Milestone 2 нужно переписать в этих терминах.
- STUN (3478) в iroh 1.x нет — hole punching держится на QAD (UDP 7842 + TLS на relay). Если relay развернуть без [tls] (за TLS-терминирующим nginx), QAD выключается и клиенты за NAT теряют способ узнать свой публичный адрес через ЭТОТ relay → почти всё пойдёт через relay. Значит на mail-сервере обязательно открывать UDP 7842 и давать relay сертификат (ACME сам или Manual из certbot).
- Браузерная версия (M14) технически проста со стороны сервера: тот же iroh-relay, endpoint wss://relay.example.org/relay, auth-token только через `?token=` (утечёт в логи прокси) — shared_token для браузера бессмыслен как секрет; для WASM брать `iroh = { version = "1", default-features = false }` и предусмотреть, что N0-подобный пресет в браузере не включает DnsAddressLookup (только PkarrResolver по HTTPS).
- Discovery без DNS-делегирования: PkarrPublisher + PkarrResolver на https://dns.example.org/pkarr (iroh-dns-server 1.1) достаточно для Aira; DnsAddressLookup + порт 53 + NS-запись — опционально (даёт резолв через обычный DNS, полезно для DPI-устойчивости, но требует делегирования поддомена на mail-сервер).
- Access control relay напрямую стыкуется с темой PoW/anti-DDoS: `access.http.url` даёт callout с X-Iroh-Endpoint-Id на сервис Aira, который может пускать только идентичности, прошедшие PoW-регистрацию (§11B.2), а `[limits]` + live `set_client_rate_limit` закрывают flood на уровне байт. allowlist/denylist по EndpointId — для бана.
- Самая свежая безопасная версия relay — ≥1.0.2 (preauth DoS до неё); держать relay на той же minor, что и клиенты (wire v1 стабилен, но n0 обновляет relay в течение 24 ч после релиза и советует version-locking для production).
- Второй relay (дешёвый VPS в другом регионе) нужен не «когда-нибудь», а до релиза: клиенты iroh делают автоматический fail-over по списку RelayMap, а mail-сервер — единая точка отказа и для почты, и для мессенджера; для §11B.5.1 (multi-relay mailbox) это же требование.

## Рекомендуемый план деплоя

## Пошаговый план (для передачи Sonnet 5)

### Этап 0 — миграция iroh 0.97 → 1.1.0 (блокер, 1–3 дня)
1. Cargo.toml: `iroh = "1.1"`, `iroh-blobs = "0.103"`, `rust-version = "1.91"`; заодно `ml-dsa = "0.1.1"`, `ml-kem = "0.3"` (см. facts-crates.md, эксперимент C: 15 ошибок только в crates/aira-core/src/crypto/rustcrypto.rs).
2. crates/aira-net/src/endpoint.rs:78 `Endpoint::empty_builder()` → `Endpoint::builder(presets::Minimal)` (тесты); :80 `presets::N0` → собственный пресет `AiraPreset` (см. этап 3). Проверить `iroh::endpoint::CaTlsConfig` (переименовано из CaRootsConfig) и `QuicTransportConfig` (rc-0 breaking list).
3. Тесты: feature `test-utils` у iroh → `iroh::test_utils::run_relay_server().await` + `.ca_tls_config(CaTlsConfig::insecure_skip_verify())`.
4. `cargo audit` должен потерять quinn-proto/hickory 0.25 находки.

### Этап 1 — DNS и порты на mail-сервере
- A/AAAA `relay.example.org` → IP mail-сервера. (Опционально позже `dns.example.org` для iroh-dns-server.)
- Firewall: открыть `tcp/443` (уже открыт для почты/webmail) и **`udp/7842`** (QAD). НЕ открывать 9090 (metrics), 3340, 8443. 3478/udp не нужен (STUN нет).
  `ufw allow 7842/udp`

### Этап 2 — установка iroh-relay 1.1.0
- Бинарник: `iroh-relay-v1.1.0-x86_64-unknown-linux-gnu.tar.gz` из https://github.com/n0-computer/iroh/releases/tag/v1.1.0 (checksum-файлов нет → либо собрать из тега `cargo build --profile optimized-release -p iroh-relay --features server`, либо docker `n0computer/iroh-relay:v1.1.0` по digest). Положить в `/usr/local/bin/iroh-relay`.
- `useradd -r -s /usr/sbin/nologin iroh-relay`; `mkdir -p /etc/iroh-relay /var/lib/iroh-relay/certs; chown iroh-relay /var/lib/iroh-relay -R`.

### Этап 3 — вариант A (рекомендуемый): nginx stream + SNI-passthrough, relay сам получает Let's Encrypt (TLS-ALPN-01)
`/etc/iroh-relay/config.toml`:
```toml
# iroh-relay 1.1.0 — все top-level ключи ДО первой [таблицы]
enable_relay = true
http_bind_addr = "127.0.0.1:3340"      # порт 80 занят nginx; снаружи plain-HTTP не нужен
enable_quic_addr_discovery = true      # QAD = замена STUN; требует [tls]
enable_metrics = true
metrics_bind_addr = "127.0.0.1:9090"   # Prometheus только локально
key_cache_capacity = 65536
access = "everyone"                    # позже: access.http.url = "https://api.example.org/relay-auth" (PoW-гейт)

[tls]
https_bind_addr = "127.0.0.1:8443"     # сюда nginx stream отдаёт TLS насквозь по SNI
quic_bind_addr = "[::]:7842"           # UDP напрямую, без прокси
hostname = "relay.example.org"
cert_mode = "LetsEncrypt"              # tokio-rustls-acme, TLS-ALPN-01 через passthrough
cert_dir = "/var/lib/iroh-relay/certs"
contact = "postmaster@example.org"
prod_tls = true

[limits]
accept_conn_limit = 50.0               # новых соединений/с
accept_conn_burst = 200
[limits.client.rx]
bytes_per_second = 2000000             # 2 MB/s на клиента через relay
max_burst_bytes = 8000000
```
`/etc/nginx/nginx.conf` (блок `stream` на верхнем уровне, рядом с `http {}`; существующие HTTPS-vhost'ы webmail/autodiscover переезжают с 443 на 127.0.0.1:8444):
```nginx
stream {
    map $ssl_preread_server_name $relay_backend {
        relay.example.org   127.0.0.1:8443;   # iroh-relay (TLS не терминируется, ACME TLS-ALPN-01 проходит)
        default             127.0.0.1:8444;   # прежний https (webmail, autoconfig, ACME http-01 не затрагивается: он на :80)
    }
    server {
        listen 443;
        listen [::]:443;
        ssl_preread on;
        proxy_pass $relay_backend;
        proxy_connect_timeout 5s;
        proxy_timeout 1h;                     # долгоживущие WebSocket
    }
}
# в http {}: server { listen 127.0.0.1:8444 ssl; ... } — при необходимости real IP через proxy_protocol
```
Плюсы: relay видит TLS напрямую → работает быстрый exporter-handshake (0 RTT), ACME без certbot-хуков, QAD и HTTPS на одном сертификате. Минус: webmail теряет реальный client IP, если не включить `proxy_protocol` (`listen 127.0.0.1:8444 ssl proxy_protocol; set_real_ip_from 127.0.0.1; real_ip_header proxy_protocol;`).

### Этап 3′ — вариант B (если stream-переезд неприемлем): TLS на nginx, relay с Manual-сертификатом
config.toml как выше, но `cert_mode = "Manual"`, `manual_cert_path = "/etc/letsencrypt/live/relay.example.org/fullchain.pem"`, `manual_key_path = "/etc/letsencrypt/live/relay.example.org/privkey.pem"` (дать группе iroh-relay право чтения; certbot deploy-hook `systemctl restart iroh-relay`). nginx `http`:
```nginx
server {
    listen 443 ssl http2; server_name relay.example.org;
    ssl_certificate     /etc/letsencrypt/live/relay.example.org/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/relay.example.org/privkey.pem;
    location / {                               # /relay (WebSocket), /ping, /generate_204, /healthz
        proxy_pass https://127.0.0.1:8443;
        proxy_ssl_server_name on; proxy_ssl_name relay.example.org;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header Sec-WebSocket-Protocol $http_sec_websocket_protocol;  # согласование версии relay-протокола
        proxy_buffering off; proxy_read_timeout 1h; proxy_send_timeout 1h;
    }
}
```
Клиенты пойдут по challenge-fallback (+1 RTT) — штатно, тот же путь у браузеров. QAD по-прежнему на UDP 7842 напрямую.

### Этап 4 — systemd
`/etc/systemd/system/iroh-relay.service`:
```ini
[Unit]
Description=iroh-relay 1.1 (Aira)
After=network-online.target
Wants=network-online.target

[Service]
User=iroh-relay
Group=iroh-relay
ExecStart=/usr/local/bin/iroh-relay --config-path /etc/iroh-relay/config.toml
Environment=RUST_LOG=info
Restart=always
RestartSec=2
LimitNOFILE=131072
StateDirectory=iroh-relay
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/iroh-relay

[Install]
WantedBy=multi-user.target
```
(Флаг: README использует `--config-path=`, docs — `-c`; проверить `iroh-relay --help`.) Все порты >1024 → capabilities не нужны. Проверка: `curl --fail https://relay.example.org/healthz`, `curl -s localhost:9090/metrics | head`, с клиента `iroh` 1.1 — `Endpoint::online()` и в логах `relay: connected`.

### Этап 5 — discovery на своём домене (iroh-dns-server 1.1.0, тот же сервер или VPS)
Минимально (без порта 53): `config.toml` с `[https] port = 8445 domains = ["dns.example.org"] cert_mode = "manual"` (или SNI `dns.example.org` → 127.0.0.1:8445 в том же `stream map`), `[dns] port = 5353` (не публиковать), `[mainline] enabled = false`, `pkarr_put_rate_limit = "smart"`. Клиенты используют только `PkarrPublisher::builder("https://dns.example.org/pkarr")` + `PkarrResolver::builder(...)`. Полный вариант с `DnsAddressLookup::builder("dns.example.org")` требует `[dns] port = 53` и NS-делегирования `dns.example.org` на этот IP — отложить.

### Этап 6 — клиент Aira
1. `crates/aira-net/src/preset.rs`: `AiraPreset { relays: Vec<RelayUrl>, pkarr_relay: Url, dns_origin: Option<String>, relay_token: Option<String> }`, реализующий трейт пресетов iroh (метод `apply(self, builder) -> Builder`, см. presets.rs:113-136 — n0 сами советуют копировать N0): crypto provider ring; `.relay_mode(RelayMode::Custom(RelayMap::from_iter(relays)))` (+ `.with_auth_token` при shared_token); `.address_lookup(PkarrPublisher::builder(pkarr_relay))`, `.address_lookup(PkarrResolver::builder(pkarr_relay))`, под `#[cfg(not(wasm_browser))]` — `DnsAddressLookup::builder(origin)` если задан.
2. Конфиг daemon (`~/.config/aira/config.toml`): `[network] relays = ["https://relay.example.org"] pkarr_relay = "https://dns.example.org/pkarr"`; дефолты вшиты в бинарник; переключатель `use_n0_fallback = false` (по умолчанию выключен — приватность).
3. Интеграционный тест: in-process relay (`test-utils`) + два endpoint'а с `AiraPreset` → обмен по ALPN CHAT.
4. Спека: spec/03-network.md §5 — заменить «DERP» на «iroh-relay (WebSocket + QAD)», отделить от «Aira mailbox relay»; spec/18 Milestone 2/14.3 — обновить.

### Этап 7 — эксплуатация
- Второй relay на VPS в другом регионе (тот же config, свой hostname) — до релиза.
- Prometheus на 127.0.0.1:9090; алерт на рост relay-трафика (`[limits]` подрезает).
- Обновление relay в течение суток после релиза iroh (minor совместимы по wire); минимум 1.0.2.
- Позже: `access.http.url` → сервис Aira, пропускающий только EndpointId, прошедшие PoW-регистрацию (тема 3).

## Риски

- Срок: 23 дня до отключения публичных relay для 0.9x (30.09.2026) — любые релизные сборки на 0.97 «умрут» для клиентов за NAT; миграция должна идти первой, до relay/offline/PoW/браузера.
- Полный объём ошибок компиляции aira-daemon/ffi/gui/cli при iroh 1.1 неизвестен (эксперимент D остановился на aira-net); оценка 1–3 дня может вырасти из-за rc-0 breaking (ConnectionInfo → WeakConnectionHandle, PathWatcher, transports под unstable-feature — затрагивает pluggable transports obfs4/reality/cdn из спеки).
- Один relay на mail-сервере = единая точка отказа для почты и мессенджера; relay-URL — «credential you can't revoke»: попав в публичный клиент, он будет использоваться чужим трафиком (n0 прямо об этом пишут) — без access.http/limits возможен DDoS/абьюз, а полоса mail-сервера и его IP-репутация пострадают.
- QAD требует UDP 7842 наружу; часть хостеров/фаерволов режет UDP — тогда hole punching деградирует и весь трафик пойдёт через relay (расход канала сервера ×2 на каждое сообщение/файл).
- Вариант A (stream/ssl_preread) меняет существующую конфигурацию nginx mail-сервера (перенос vhost'ов на 8444, потеря client IP без proxy_protocol) — регрессии для webmail/autodiscover; вариант B теряет exporter-fast-path и требует certbot-хука на рестарт relay (hot-reload Manual-сертификатов не подтверждён).
- Официальная документация опций iroh-relay не публикуется («peek in main.rs»); формат TOML может измениться в 1.2+; docker README/Dockerfile содержат устаревшие порты (3478) — легко скопировать неверную конфигурацию.
- Shared-token не защищает браузерных клиентов (токен в `?token=` URL, попадает в логи прокси) и не отзывается без рестарта; allowlist по EndpointId не масштабируется — реальная защита только через access.http + PoW-регистрацию.
- Self-hosted pkarr/DNS: без NS-делегирования резолв только по HTTPS к dns.example.org — единая точка блокировки DPI (тема §11A); при DNS-варианте порт 53 на mail-сервере и делегирование поддомена — дополнительная поверхность.
- Аудит: релизные assets iroh без checksum — цепочка поставки relay-бинарника требует сборки из тега или pin по docker digest.
- Публичные relay/dns n0 как fallback в клиенте — утечка метаданных (IP, время, объёмы) третьей стороне; если оставить N0-fallback «на всякий случай», это противоречит threat model §11.

## Открытые вопросы

- Какой веб-сервер и ОС на mail-серверe (nginx/apache/caddy, systemd?), какие сервисы уже держат 80/443 (webmail, autodiscover, ACME http-01) и доступен ли UDP 7842 у хостера — от этого зависит выбор варианта A/B.
- Точное имя трейта пресетов и сигнатура `apply` в iroh 1.1 (presets.rs:113-182) и флаг CLI конфига (`--config-path` по README vs `-c` по docs) — проверить при реализации.
- Перезагружает ли cert_mode='Manual' сертификаты без рестарта (в deps есть rustls-cert-reloadable-resolver, но CertConfig::Reloading удалён в 1.0).
- Сколько одновременных клиентов/полосы ожидается на релизе — для sizing relay (n0: до 60k соединений на relay; key cache 1M ≈ 56 MB) и для выбора `[limits]`.
- Публиковать ли прямые IP клиентов в pkarr (`AddrFilter::unfiltered()`) — ускоряет прямые соединения, но раскрывает IP всем, кто знает EndpointId (конфликт с §11).
- Как совместить Aira mailbox relay (§6.3b) и iroh-relay на одной машине: отдельный бинарник `aira-relay` или режим daemon `--relay`; регистрируется ли он в pkarr под своим EndpointId.
- Стоит ли использовать `access.http` уже в v1 (привязка к PoW-регистрации, тема 3) или начать с `everyone` + `[limits]` и добавить позже — нужен дизайн endpoint'а /relay-auth.
- Собирается ли aira-net под wasm с iroh 1.1 default-features=false и tokio-фичами из M14.3, и как в браузере выглядит relay-only handshake через nginx (Sec-WebSocket-Protocol проброс).
- Список актуальных URL публичных relay 1.0 (#4341 «Update relay urls to 1.0 stable») — нужен только если решено оставить n0-fallback как опцию.
