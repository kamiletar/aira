# Аудит D — CI/CD и supply chain против требований релиза 2026

> Фаза 3 аудита готовности к релизу. Дата: 2026-09-24 (UTC). HEAD `7726b46` (ветка `claude/vigilant-sagan-9kta8v` = `origin/main`), workspace v0.3.5.
> Главный документ: `.claude/docs/release-audit-2026-09.md` (§1, §6.6.5–§6.6.7, §8.4). Требования площадок с источниками — `release-2026-requirements.md`; клиентские/Android-находки — `clients-audit.md`; CI-тесты — `test-coverage-audit.md` §6. Здесь — только то, чего в них нет: реальное состояние `.github/workflows/*`, `deny.toml`, `.cargo/audit.toml`, скриптов упаковки и управления репозиторием, сверенное с чеклистами §6.6.5/§6.6.7 и разложенное по M18–M23.
>
> Источники фактов: файлы репозитория (path:line), GitHub API репозитория `kamiletar/aira` (релизы, runs, логи jobs — через MCP), `git ls-remote` по репозиториям actions (полные SHA тегов, снято 2026-09-24), crates.io API (версии инструментов), README actions/attest, cargo-deny docs, runner-images (через WebFetch на github.com). `docs.github.com` и `github.blog` заблокированы egress-прокси — соответствующие утверждения помечены «не проверено онлайн».
>
> Статус: **готово** (2026-09-24). Разделы: 0 резюме · 1 workflow · 2 release.yml · 3 android.yml · 4 deny/audit · 5 репозиторий · 6 внешние факты · 7 таблица требований · 8 наброски yml · 9 милстоуны/вопросы · 10 не проверено.

## 0. Резюме

1. **CI-гейты на `main` красные с 2026-04-10 (6 из последних 8 runs) и красные сегодня** (run `35933020292`, 2026-09-23): job **Security Audit — 18 уязвимостей** (было 17 в фазе 1; добавился `rustls 0.23.37` RUSTSEC-2026-0285 от 14.09 → ≥0.23.45), job **Clippy — 2 ошибки от нового stable 1.98** (`discovery.rs:155` `chunks_exact_to_as_chunks`, `relay.rs:112` `duration_suboptimal_units`); в июле на 1.97 падали три *других* строки. Причина структурная: `dtolnay/rust-toolchain@stable` без `rust-toolchain.toml` при `#![warn(clippy::pedantic)]` + `-D warnings` — каждый релиз clippy ломает CI. Из 18 уязвимостей 12 уходят с iroh 1.1 (M18: quinn-proto, hickory-proto ×2, crossbeam-epoch, и часть quick-xml), 5 — обычным `cargo update` (rustls, rustls-webpki ×3, h2, webbrowser), **quick-xml ×4 версии (8 записей)** требуют апгрейда egui/rfd/notify-rust-стека или временного ignore с обоснованием и сроком.
2. **Supply chain workflow'ов не соответствует ни одному пункту §6.6.5:** все 8 actions приколоты плавающими тегами (`@v4`/`@v2`/`@stable`), ни одного SHA; `ci.yml`/`android.yml` без блока `permissions`; `release.yml` даёт `contents: write` всем jobs на трёх ОС, при этом токен остаётся в `.git/config` (`persist-credentials` по умолчанию) в job, который **скачивает и исполняет непроверенный код**: `linuxdeploy` из `releases/download/continuous/` и `linuxdeploy-plugin-gtk.sh` из `raw/master` без checksum (`release.yml:127-131`). Нет `--locked` ни в одном `cargo`-вызове; релизные сборки берут `Swatinem/rust-cache`. Нет Dependabot/Renovate, нет schedule-прогона audit (уязвимость rustls от 14.09 лежала незамеченной до сегодняшнего случайного push).
3. **Релизные артефакты: только `.sha256`-сайдкары, загружаемые тем же job рядом с файлом** — защита от порчи, не от подмены. Нет `SHA256SUMS`, подписи (minisign/cosign), attestations, SBOM, cargo-auditable; нет проверки «тег ↔ версия Cargo.toml ↔ versionName»; релиз публикуется сразу как stable/latest (для `0.5.0-beta.N` это сломает сайт `aira.letar.best`, который берёт latest). `if-no-files-found: ignore` + четыре `|| true` — пропавший DMG/AppImage не остановит релиз. AppImage собирается на ubuntu-24.04 (glibc 2.39) — на Ubuntu 22.04, который обещает `INSTALL.md:105`, не запустится (по памяти о версиях glibc, см. §10).
4. **Android в CI:** NDK 26.1 (нужен r28: на ubuntu-24.04 предустановлен `28.2.13676358`), `cargo-ndk` без версии, **Gradle-обёртки нет** (`gradlew`/`gradle-wrapper.jar` отсутствуют, есть только `gradle-wrapper.properties`) → `gradle assembleRelease` идёт системным Gradle образа раннера (сегодня 9.7.1 при AGP 8.7.0); `android.yml` не запускался с 2026-04-10 из-за `paths`-фильтра, а `release.yml` делает `needs: [build, android]` — тихая поломка Android заблокирует весь desktop-релиз на теге. Подпись APK (известный блокер) — здесь расписано, что именно нужно в CI: secrets, `environment` с ревьюером, `apksigner verify`, публикация SHA-256 отпечатка сертификата (нужна и для Android developer verification, и для F-Droid).
5. **deny.toml/.cargo/audit.toml:** 9 из 22 игнорируемых advisories относятся к 8 крейтам, которых **нет в Cargo.lock** (instant, derivative, yaml-rust — два ID, gdkwayland-sys, gdkx11, gdkx11-sys, atk3, rsa) — cargo-deny 0.20 печатает `unused-ignored-advisory`; ещё 10 — «unmaintained» транзитивных крейтов, которые правильно гасятся одной настройкой `unmaintained = "workspace"`, а не списком; обоснование RUSTSEC-2025-0144 («v0.3.6») устарело; комментарий про «cargo-deny 0.19+ схему» неточен. `publish = false` не выставлен ни в одном крейте (`cargo metadata`), поэтому `wildcards` пришлось опустить до `warn`. Лицензии: allow-список согласован с MIT/Apache-2.0-дистрибуцией (MPL-2.0 file-level, OFL/UFL — встраивание шрифтов допустимо), но проверка идёт **только по default-фичам** (`[graph]` нет): `fips`/`compat-test` (aws-lc-sys, лицензия с компонентом OpenSSL) и DPI-фичи вне проверки. 0 git-зависимостей, `unknown-registry/unknown-git = deny` ✓. Дублей: 101 из 797 имён (12,7 %), 14 — семейство windows-*.
6. **Управление репозиторием:** нет `LICENSE-MIT`/`LICENSE-APACHE` (при `license = "MIT OR Apache-2.0"` и публичных релизах с апреля — **новая находка, блокер для любого публичного тега, включая v0.4.0 из M18, и для заявки в SignPath**), нет README/SECURITY/CONTRIBUTING/CHANGELOG/CODEOWNERS/шаблонов issue/PR, нет `.github/dependabot.yml`, все 50 коммитов без подписи, ветка `dev` из `ci.yml` на origin не существует. Branch/tag protection, дефолтные права `GITHUB_TOKEN`, Dependabot alerts, private vulnerability reporting — вопросы владельцу (§9.3).
7. **Что уже хорошо:** `Cargo.lock` v4 в git, 0 git-deps, `[sources]` deny, `profile.release` с `strip/lto/codegen-units=1`, `cargo-wix --version 0.3.9 --locked`, `fail-fast: false`, `pull_request` (не `pull_request_target`), secrets не используются вовсе, WiX 3.14 всё ещё в образе windows-2025, NDK 28.2 и Rust 1.98.1 предустановлены на ubuntu-24.04, attestations бесплатны для публичных репо.
8. **Разбивка по милстоунам (детали §9):** M18 — CI-гварды (toolchain-пин, `--locked`, SHA-пины + Dependabot, `permissions`/`persist-credentials`, чистка deny/audit, `cargo update`, LICENSE + README-заглушка **до тега v0.4.0**, MSRV-job, schedule-audit, verify-version job); M19b — Android-пакет CI (keystore/apksigner/NDK 28/wrapper/decoupling); M21 — `aira-relay` в матрице релиза; M23 — подпись/attestations/SBOM/auditable/SHA256SUMS/prerelease-канал/пин раннеров/контейнер glibc/Scorecard. ⚠️ В задании фазы 3 подпись/attestations/SBOM отнесены к «M22 релизная инфраструктура», а в `spec/18-milestones.md` M22 = Anti-abuse, M23 = Release hardening (п.2, п.4). Отчёт следует спеке (M23) и предлагает владельцу выделить параллельный трек «M22-infra» (§9.4), поскольку у этой работы нет зависимостей от кода M19–M21.

**Блокеры (для чеклиста беты §6.6.7):**

| # | Блокер | Где | Куда |
|---|---|---|---|
| B1 | CI-гейты красные: 18 vulns (`cargo audit`), clippy на stable 1.98 | `ci.yml:37,53-62`; job `107423723908`, `107423723873` | M18 |
| B2 | Релизный APK не подписан (известно) — в CI нет keystore/apksigner | `release.yml:225-236`, `build.gradle.kts:23-32` | M19b |
| B3 | Нет LICENSE-файлов и README при публичной дистрибуции под «MIT OR Apache-2.0» | `Cargo.toml:18`; `ls /` — файлов нет | M18 (до v0.4.0) |
| B4 | Непроверенный код в релизном job с write-токеном (linuxdeploy `continuous` + plugin из `master`) | `release.yml:11-12,127-131`; `checkout@v4` без `persist-credentials: false` | M18 |

## 1. Текущее состояние по workflow

В `.github/workflows/` ровно три файла: `ci.yml` (63 строки), `android.yml` (151), `release.yml` (271). Других (`schedule`, `codeql`, `scorecard`, `dependabot`) нет. Ни один workflow не использует `secrets.*` (grep пуст) — единственный токен везде `GITHUB_TOKEN`.

### 1.1 Сводная таблица

| Параметр | ci.yml | android.yml | release.yml |
|---|---|---|---|
| Триггеры | `push: [main, dev]`, `pull_request: [main, dev]` (`ci.yml:3-7`); `dev` на origin **нет** (`git ls-remote --heads` → только `main`); нет `schedule`/`workflow_dispatch` | `push: [main, dev, "milestone/M10-*"]` + `paths` только `crates/aira-ffi/**`, `mobile/android/**`, сам файл (`android.yml:3-14`) | `push: tags: ['v*']` (`release.yml:3-5`) — любой, кто может пушить теги |
| `pull_request_target` | нет ✓ | нет ✓ | — |
| `permissions` | **нет блока** → дефолт репозитория (не проверить, §9.3) | **нет блока** | `contents: write` на уровне workflow → **все** jobs, включая матрицу сборки на 3 ОС (`release.yml:11-12`) |
| `persist-credentials` | по умолчанию `true` | `true` | `true` — токен с правом записи лежит в `.git/config` во время `wget`/`brew`/`cargo install` |
| Пины actions | `actions/checkout@v4`, `dtolnay/rust-toolchain@stable`, `Swatinem/rust-cache@v2` — теги/ветки, **0 SHA** | + `android-actions/setup-android@v3`, `actions/setup-java@v4`, `gradle/actions/setup-gradle@v4`, `actions/upload-artifact@v4`, `actions/download-artifact@v4` | + `softprops/action-gh-release@v2` |
| Toolchain | плавающий `stable` (сегодня на раннерах 1.98.1); `rust-toolchain.toml` **нет**; `rust-version = "1.82"` (`Cargo.toml:20`) нигде не проверяется | тот же | тот же — релиз собирается тем rustc, который окажется stable в день тега |
| Кэш | `Swatinem/rust-cache@v2` в clippy/test (`ci.yml:31,45`) — без `save-if`; scope PR-веток изолирован ✓ | нет | `Swatinem/rust-cache@v2` с `key: release-<target>` (`release.yml:42-44,165-167`) — релиз восстанавливает кэш из `main` |
| `--locked` | **нигде** (`ci.yml:37,51`) | нигде (`android.yml:55,76,80,147,150`) | нигде (`release.yml:56,179,184,198-199`) |
| Проверки | `fmt --check` ✓; `clippy --workspace --all-targets -D warnings` (без `--all-features`); `cargo test --workspace` (doc-тесты входят ✓; без `--all-features` — 65 тестов не бегут, см. test-coverage §6); `cargo install cargo-audit cargo-deny` + `cargo audit` + `cargo deny check` | `cargo test -p aira-ffi`, `cargo clippy -p aira-ffi` (дубль ci.yml) | **тестов нет** (test-coverage §6) |
| ОС/таргеты | только `ubuntu-latest` (= 24.04) | ubuntu-latest; `aarch64-linux-android`, `x86_64-linux-android` | ubuntu-latest / macos-latest ×2 (aarch64 + x86_64 кросс) / windows-latest; android |
| MSRV / wasm32 / fuzz / coverage | нет / нет / нет / нет | — | — |
| `timeout-minutes`, `concurrency` | нет / нет | нет / нет | нет / нет |
| Секреты | — | — | — (для подписи APK понадобятся, §2.6) |

### 1.2 Что реально происходит в CI (по логам GitHub)

- Последние 8 runs `CI` на `main`: 4 failure подряд 10.04 (runs 24233285116, 24238102379, 24238858550, 24239257029), затем 3 success (24240041693, 24240941159, 24242641487 — «green up» + deny/audit fix), затем **failure 30.07 (30501538193)** и **failure 23.09 (35933020292)**. Format и Test — зелёные в обоих последних.
- **Clippy 30.07 (job 90742065183, clippy 1.97):** 3 ошибки `duration_suboptimal_units` — `crates/aira-net/src/endpoint.rs:21`, `relay.rs:112`, `relay.rs:113`. **Clippy 23.09 (job 107423723873, clippy 1.98):** 2 ошибки — `crates/aira-net/src/discovery.rs:155` (`chunks_exact_to_as_chunks`, новый lint 1.98) и `relay.rs:112`; `endpoint.rs:21` и `relay.rs:113` больше не флагуются. Локально у владельца на 1.94.1 — exit 0 (release-audit §1). Вывод: набор падающих lint'ов меняется от версии к версии, потому что pedantic-lint'ы включены как `warn` во всех крейтах, а `-D warnings` превращает их в ошибки.
- **Security Audit 23.09 (job 107423723908):** `cargo audit` → **`error: 18 vulnerabilities found!`, `12 allowed warnings`**, база 1267 advisories, 933 крейта в lock. Полный список — §4.2. Установка `cargo-audit 0.22.2` + `cargo-deny 0.20.2` из исходников заняла ~7,5 мин (2m58 + 4m25 в логе) — на каждом прогоне.
- Лог каждого job предупреждает: `Node.js 20 is deprecated … actions/checkout@v4 … forced to run on Node.js 24` — checkout v4 живёт на устаревшем runtime.
- `Android Build` последний раз бежал **2026-04-10** (run 24238858549, success). Все изменения после (spec-only) фильтром `paths` не покрыты — и любое изменение в `aira-core`/`aira-net`/`Cargo.lock` тоже не покрывается (§3).
- `Release` v0.3.5 (run 24240945283, 10.04): success, 18 assets (tar.gz ×3, zip, MSI, DMG ×2, AppImage, APK + 9 `.sha256`), автор `github-actions[bot]`, тело релиза — только `**Full Changelog**` (нет CHANGELOG). Run 24240327275 на том же теге до фикса — failure (MSI/AppImage), т.е. тег `v0.3.5` **переставлялся** (два release-run на одном имени тега) — практика, которую после включения attestations/immutable releases повторить нельзя.

### 1.3 Находки по §1 (то, чего нет в предыдущих отчётах)

**HIGH — H3. Actions без SHA-пинов.** Все `uses:` — мутабельные теги (`ci.yml:17,18,27,28,31,43-45,57,58`; `android.yml:36,39,47,59,70,73,86,97,100,106,112,118,124,131,141,144`; `release.yml:36,38,42,141,159,161,165,173,205,223,239,251,254,260`). Последствие: компрометация тега upstream (прецедент tj-actions/changed-files, март 2025) = исполнение чужого кода в наших jobs, в release.yml — с `contents: write`. Исправление: SHA-пин с комментарием версии (таблица §6.1) + `.github/dependabot.yml` с экосистемой `github-actions` (§8.3). → **M18**.

**HIGH — H2. Права токена.** `ci.yml`/`android.yml` без `permissions` (наследуют настройку репозитория, которую здесь проверить нельзя); `release.yml:11-12` даёт `contents: write` сборочным jobs, которым нужен только `contents: read`. Исправление: `permissions: {}` на уровне workflow; `contents: read` в jobs; `contents: write` + `id-token: write` + `attestations: write` только в job `release`; `persist-credentials: false` во всех `checkout` (ни один шаг не делает `git push`). → **M18**.

**HIGH — H4. Нет `--locked`, релиз с кэшем.** Без `--locked` cargo молча перерезолвит граф, если `Cargo.toml` разошёлся с `Cargo.lock` — ровно ситуация с незакоммиченным bump `ml-dsa = "0.1.0-rc.4"` у владельца (release-audit §0.2): такой коммит соберётся в CI с другим lock, чем в репозитории. Релиз с `rust-cache` (`release.yml:42,165`) переиспользует объектники из кэша `main` — невоспроизводимо и добавляет кэш в trust boundary. Исправление: `--locked` во всех `cargo build/test/clippy/ndk`; в release.yml кэш убрать; в ci.yml `save-if: ${{ github.ref == 'refs/heads/main' }}`. → **M18** (`--locked`), **M23** (кэш релиза).

**HIGH — H8. Ничто не мешает выпустить релиз с красного/непроверенного состояния.** Тег `v*` — единственный триггер (`release.yml:3-5`); `scripts/release.sh:58-59` пушит `HEAD` прямо в `main` и тег, минуя PR и CI (`cargo check` в `release.sh:47` — не тесты); версия живёт в трёх местах: `Cargo.toml:15` (её берёт cargo-wix через `$(var.Version)`, `crates/aira-gui/wix/main.wxs:35`), `build.gradle.kts:17-18` (перезаписывается sed'ом на теге, `release.yml:213-220`) и имя тега (имена файлов, Info.plist). Рассинхрон = MSI с ProductVersion 0.3.5 в файле `aira-0.4.0-setup.msi`. Исправление: job `verify` (тег == `Cargo.toml` version == `versionName`; тег — annotated и предок `main`; `cargo metadata --locked`), `environment: release` с required reviewer, ruleset на теги `v*` (только владелец) — §8.2. → **M18** (verify), **M23** (environment/ruleset).

**MEDIUM — M2. Audit-инструменты компилируются на каждом прогоне и плавают по версиям** (`ci.yml:59-60`): ~7,5 мин, версия `cargo install` = «что сейчас последнее». `cargo audit` без `--deny yanked` (3 yanked-крейта проходят как warning). Нет `schedule` — advisories всплывают только при push. Исправление: `EmbarkStudios/cargo-deny-action@v2.1.1` (бинарь, ~10 с), `taiki-e/install-action` с `tool: cargo-audit@0.22.2`; `cargo audit --deny yanked`; `schedule: cron` ежедневно для job `audit`. → **M18**.

**MEDIUM — M3. Матрица CI — только Linux; нет MSRV, wasm32, `concurrency`, `timeout-minutes`.** Релиз собирает Windows/macOS, но `cargo test` на них не запускался никогда (нужно для keychain-тестов M19b п.1); `rust-version` не проверяется (после M18 — 1.91); guard `cargo check -p aira-core --target wasm32-unknown-unknown` для M14.0 отсутствует. Стоимость Windows/macOS-раннеров на каждый PR — вопрос владельцу (§9.3). → **M18** (msrv, wasm32 как `continue-on-error`), **M23** (ОС-матрица блокирующая).

**MEDIUM — M17. Node 20 deprecation.** `actions/checkout@v4`, `upload/download-artifact@v4`, `setup-java@v4`, `setup-android@v3`, `setup-gradle@v4` — старые мажоры на Node 20; GitHub принудительно запускает их на Node 24 (warning в каждом логе). Актуальные мажоры: checkout v7, upload-artifact v7, download-artifact v8, setup-java v6, setup-android v4, gradle/actions v6, action-gh-release v3 (§6.1). → **M18** вместе с SHA-пинами.

**MEDIUM — M9. Нет Dependabot/Renovate.** Ни `.github/dependabot.yml`, ни `renovate.json`. Без него SHA-пины «протухают», cargo/gradle-обновления только вручную, а **Dependabot alerts (GitHub Advisory DB, GHSA) — единственный инструмент, который видит два из трёх дефектов ml-dsa 0.0.4**: GHSA-h37v-hp6w-2pp8 (`use_hint` off-by-one, валидная подпись не проходит; исправлено в 0.1.0-rc.5; **в RustSec отсутствует** — в `crates/ml-dsa` advisory-db лежит только RUSTSEC-2025-0144) и CVE-2026-24850. Конфиг — §8.3. → **M18**.

**LOW — M16. Мёртвые ссылки на ветки.** `dev` (`ci.yml:5,7`; `android.yml:5,11`) не существует; `milestone/M10-*` (`android.yml:5`) — исторический. Пуши в `milestone/*` CI не запускают — работа по M18–M23 получит CI только через PR в `main`. Исправление: `push: branches: [main]`, `pull_request:` без фильтра веток (или `+ 'milestone/**'`). → **M18**.

**LOW — L6. `rust-version` наследует только aira-gui** (`crates/aira-gui/Cargo.toml:8`); остальные 7 крейтов без `rust-version` (`cargo metadata`: `rust-version=None`). MSRV-job и `cargo msrv` увидят только GUI. Исправление: `rust-version.workspace = true` во все крейты при bump до 1.91. → **M18**.

## 2. release.yml — матрица, подпись, attestations, SBOM, воспроизводимость, APK

### 2.1 Матрица и упаковка (что есть)

| Цель | Раннер (сегодня) | Шаги | Артефакты |
|---|---|---|---|
| `x86_64-unknown-linux-gnu` | `ubuntu-latest` = Ubuntu 24.04.5 (glibc 2.39, по памяти) | apt gtk/xdo/xcb; `cargo build --release --target … -p aira-cli -p aira-daemon -p aira-gui` (`release.yml:56-57`); tar.gz + `shasum`; `bundle-appimage.sh` через linuxdeploy | `aira-<v>-x86_64-unknown-linux-gnu.tar.gz`, `Aira-<v>-x86_64.AppImage` |
| `aarch64-apple-darwin`, `x86_64-apple-darwin` | `macos-latest` = **macOS 26 arm64** (runner-images README, 2026-09-24); x86_64 — кросс-сборка на arm64 | build; tar.gz; `brew install create-dmg \|\| true`; `bundle-macos.sh` — `.app` вручную, `xattr -cr`, create-dmg/hdiutil | tar.gz ×2, `Aira-<v>-{arm64,x86_64}.dmg` |
| `x86_64-pc-windows-msvc` | `windows-latest` = Windows Server 2025 (в образе **WiX Toolset 3.14.1.8722** — путь `release.yml:98` пока валиден) | build; `Compress-Archive` zip; `cargo install cargo-wix --version 0.3.9 --locked` ✓; `cargo wix -p aira-gui --no-build … --target x86_64-pc-windows-msvc` | zip, `aira-<v>-setup.msi` |
| Android | ubuntu-latest | §3 | `aira-<v>-android.apk` (**unsigned**) |
| `release` | ubuntu-latest | `download-artifact merge-multiple` → `softprops/action-gh-release@v2` с `generate_release_notes: true` | GitHub Release, non-draft, non-prerelease |

Не собирается: `aarch64-unknown-linux-gnu` (Raspberry/ARM-серверы — важно для `aira-relay` M21), `x86_64-unknown-linux-musl` (статический relay-бинарь для Docker), `.deb`/`.rpm` (§15.7 спеки обещает AppImage/.deb), `.aab`. Из `docs/INSTALL.md`/`release.md` следует, что план — только эти четыре desktop-таргета; расхождение `release.md:32` («`x86_64-apple-darwin` на `macos-13`») с `release.yml:28-30` (`macos-latest`) — doc drift (LOW).

### 2.2 Стрип/оптимизация/воспроизводимость

- `[profile.release] opt-level = 3, lto = true, codegen-units = 1, strip = true` (`Cargo.toml:137-141`) — хорошая база; `panic = "abort"` не задан (для GUI/демона допустимо оставить unwind).
- **Воспроизводимость: ноль из списка §6.6.5.** В `release.yml` нет `SOURCE_DATE_EPOCH`, `--remap-path-prefix`/`trim-paths`, фиксированных `CARGO_HOME`/`CARGO_TARGET_DIR`, пина toolchain, `--locked`; есть кэш (`release.yml:42-44`). Путь `/home/runner/work/aira/aira/...` попадает в panic-строки бинаря (видно по логам компиляции). Для беты достаточно «базового набора» (§8.2: `SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)`, `RUSTFLAGS=--remap-path-prefix=$GITHUB_WORKSPACE=/build`, `CARGO_INCREMENTAL=0`, пин toolchain, без кэша) — это делает независимую пересборку реалистичной; верифицированная воспроизводимость с независимой ко-подписью (как у SimpleX) — 1.0 (спека M23 «для 1.0»). → **MEDIUM M12, M23/1.0**.

### 2.3 Checksums, подпись, attestations, SBOM, auditable

| Требование §6.6.5 | Сейчас | Оценка |
|---|---|---|
| sha256 | per-file `.sha256` (Unix: `shasum -a 256 x > x.sha256`, `release.yml:72`; Windows: ручной формат `hash  name`, `:87-88`) — загружаются **тем же job** рядом с файлом | защищает от порчи при скачивании, **не от подмены**: кто может заменить asset, заменит и сайдкар. Нужен единый `SHA256SUMS` + независимая подпись/attestation |
| Подпись Windows (Authenticode) | нет; `INSTALL.md:30-31` обещает «~$300/год, в плане на v0.4» — устарело (SignPath Foundation бесплатно, §6.6.1) | владелец: заявка в SignPath (нужны LICENSE + README + история релизов — B3) |
| Подпись macOS (codesign + notarization) | нет: `bundle-macos.sh:79` `xattr -cr`, ни `codesign`, ни `notarytool`, ни hardened runtime/entitlements; `Info.plist.template:27` `LSMinimumSystemVersion 10.13` — фикция (Rust-таргеты по умолчанию macOS 11 для aarch64) | владелец: $99/год; иначе честно в INSTALL.md (см. M13 — текущий обход «правый клик → Open» на Sequoia+ **не работает**, §6.6.2) |
| Подпись Android | нет (`release.yml:233` `app-release-unsigned.apk`) | §2.6 |
| Attestations (`actions/attest-build-provenance`) | нет | §2.4 |
| cargo-auditable | нет (`cargo build`, не `cargo auditable build`) | §2.5 |
| SBOM (CycloneDX) | нет | §2.5 |
| Подпись checksums (minisign/GPG/cosign) | нет | рекомендация: minisign-ключ офлайн у владельца — тот же ключ потом нужен Tauri updater (M17, требует minisign); cosign keyless — альтернатива без ключа |
| Immutable releases / tag protection | тег v0.3.5 переставлялся (два release-run на одном имени, §1.2) | после attestations так нельзя: provenance привязана к SHA; ruleset на `v*` — вопрос владельцу |

**HIGH — H6.** Совокупно: у пользователя нет способа отличить оригинальный asset от подменённого. Исправление (M23, §8.2): `SHA256SUMS` в job `release`; `actions/attest-build-provenance` с `subject-checksums: SHA256SUMS` (один вызов на все файлы; лимит 1024 subjects — README actions/attest); `actions/attest-sbom`; `cargo auditable`; опционально `SHA256SUMS.minisig`. Проверка пользователем: `gh attestation verify aira-0.5.0-beta.1-x86_64-unknown-linux-gnu.tar.gz --owner kamiletar` (в INSTALL.md).

### 2.4 Attestations — что именно нужно (факты 2026-09-24)

- Public repo → Sigstore Public Good, бесплатно на всех планах (README `actions/attest-build-provenance`, проверено).
- `actions/attest-build-provenance` v4 = обёртка над `actions/attest`; актуальный тег `v4.2.2` → commit `4d101475d8b20a2381f78447822ac1eab6504dd8`.
- Права job (README `actions/attest`, проверено): `id-token: write`, `attestations: write`, **`artifact-metadata: write`** (третье — новое, в старых примерах его нет); для контейнеров ещё `packages: write`. `subject-path` принимает glob и список; `subject-checksums` — файл формата `shasum`; ≤ 1024 subjects за вызов.
- **Уровень SLSA:** спека M23 п.4 пишет «SLSA L3». По документации GitHub (источники в `release-2026-requirements.md` §20; сама `docs.github.com` сейчас недоступна — **не проверено онлайн**) attestation в обычном workflow даёт **SLSA v1.0 Build L2**; **L3** — только когда сборка и attestation выполняются в **reusable workflow**, который вызывающий workflow не может подделать (страница «Using artifact attestations and reusable workflows to achieve SLSA v1 Build Level 3»). Для беты — L2 честно; reusable-паттерн — 1.0 (вопрос владельцу §9.3).
- `slsa-framework/slsa-github-generator` (`v2.1.0` → `f7dd8c54c2067bafc12ca7a55595d5ee9b75204a`) — альтернатива L3 «из коробки» для generic-артефактов; тяжелее, чем нативные attestations. Не рекомендую до 1.0.

### 2.5 cargo-auditable и SBOM

- `cargo-auditable` **0.7.6** (crates.io, 2026-09-13): `cargo auditable build --release --locked …` вместо `cargo build` — встраивает список зависимостей в секцию бинаря (<4 КБ; ELF/PE/Mach-O; wasm с 0.6.3). Проверка: `cargo audit bin target/…/aira-daemon` — единственный способ узнать, **какие из 18 lock-уязвимостей реально в бинаре** (например, `quinn-proto` тянется через optional `reqwest/http3` — в lock есть, в бинаре, вероятно, нет; см. §10). Совместимо со `strip = true`? — секция `.dep-v0` не strip'ается как debug-info, но **проверить на первом прогоне** (§10). Для Android `.so` — работает через `cargo ndk … auditable build`? — не проверено; для APK SBOM брать из `cargo cyclonedx -p aira-ffi --target aarch64-linux-android`.
- `cargo-cyclonedx` **0.5.9** (2026-03-19): `cargo cyclonedx --format json --describe binaries --spec-version 1.5 --target <triple>` — по SBOM на бинарь, без dev-deps; в workspace создаёт `bom.json` рядом с каждым `Cargo.toml`. Прикладывать `aira-<v>-<target>.cdx.json` к релизу + `actions/attest-sbom@v4.1.0` (`c604332985a26aa8cf1bdc465b92731239ec6b9e`). Альтернатива `cargo-sbom` 0.10.0 (SPDX) — не нужна.
- `cargo-vet` 0.10.2 (2026-01-13) — по спеке для 1.0; не трогать до беты.

### 2.6 APK: где теряется подпись и что нужно

- Цепочка: `gradle assembleRelease` (`release.yml:227`) → `build.gradle.kts:23-32` `buildTypes.release` **без `signingConfig`** → AGP выпускает `app-release-unsigned.apk` → `release.yml:233-235` копирует как `aira-<v>-android.apk`. Любой Android отвергнет установку (`INSTALL_PARSE_FAILED_NO_CERTIFICATES`) — clients-audit уже квалифицирует как blocker; здесь — что делать в CI.
- **Минимум (M19b п.10):** (1) keystore создаёт владелец офлайн (`keytool -genkeypair -keyalg RSA -keysize 4096 -validity 10950 …` или EC P-256), **бэкап в двух местах**, пароли в менеджере — потеря ключа = невозможность обновлений и повторная developer verification; (2) GitHub → Settings → Environments → `android-release` с required reviewer (владелец) и environment-secrets `ANDROID_KEYSTORE_B64`, `ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_ALIAS`, `ANDROID_KEY_PASSWORD`; job `android` объявляет `environment: android-release` — секреты недоступны без approve, форки их не видят; (3) в job: `base64 -d > "$RUNNER_TEMP/release.jks"`, `signingConfigs.release` в `build.gradle.kts` читает `System.getenv(...)` (или `apksigner sign --ks … --ks-pass env:ANDROID_KEYSTORE_PASSWORD --v2-signing-enabled true --v3-signing-enabled true` после `zipalign`); (4) **`apksigner verify --verbose --print-certs aira-<v>-android.apk`** как шаг CI, вывод SHA-256 отпечатка в summary; (5) `shred -u "$RUNNER_TEMP/release.jks"`; (6) опубликовать отпечаток в `docs/ANDROID_SIGNING.md`/README — он нужен пользователям, F-Droid (`AllowedAPKSigningKeys`) и **Android Developer Console** (developer verification регистрирует package name + отпечаток сертификата, §6.6.4 — значит ключ должен существовать **до** регистрации, и ротация после регистрации требует обновления там).
- Подпись v3.1 с lineage (`apksigner rotate`) — при первой ротации; сейчас не нужна.
- `versionCode = major*10000 + minor*100 + patch` (`release.yml:215-216`, `release.sh:41-42`) игнорирует pre-release: `0.5.0-beta.1` и `0.5.0-beta.2` получат **один и тот же** 500 — Play такое отвергает, sideload-обновление между бетами возможно, но неотличимо. Схема `major*1_000_000 + minor*10_000 + patch*100 + N` (N = номер беты, 99 для финала). → LOW, M19b.
- `.gitignore:21-27` не содержит `*.jks`/`*.keystore` — добавить до появления keystore на машинах разработчиков. → LOW, M19b.

### 2.7 Остальные находки release.yml

**HIGH — H1 (B4). Непроверенный код из сети в релизном job.** `release.yml:127-131`: `wget https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-x86_64.AppImage` (тег `continuous` перезаписывается при каждой сборке upstream) и `wget https://github.com/linuxdeploy/linuxdeploy-plugin-gtk/raw/master/linuxdeploy-plugin-gtk.sh` (shell-скрипт с `master`, исполняется linuxdeploy как плагин), без checksum, в job с `contents: write` и persisted-токеном; плюс `brew install create-dmg` (`:114`) и `cargo install cargo-ndk` (`:170`) без версий. Последствие: компрометация любого из upstream = код в AppImage Aira и/или push/релиз в `kamiletar/aira`. Исправление: linuxdeploy — фиксированный релизный тег + `sha256sum -c`; `linuxdeploy-plugin-gtk.sh` — **вендорить** в `packaging/linux/` (MIT, ~300 строк) и ревьюить diff при обновлении; `cargo install cargo-ndk@4.1.2 --locked`; `persist-credentials: false`; `contents: read` в job. → **M18** (дёшево, 30 минут).

**MEDIUM — M5. AppImage не запустится на «Ubuntu 22.04+», как обещает INSTALL.md.** linuxdeploy не бандлит glibc; бинарь, собранный на ubuntu-24.04, требует glibc ≥ 2.39 (Ubuntu 24.04+, Debian 13, Fedora 40+). `INSTALL.md:104-105` «Ubuntu 22.04+ … ничего дополнительно ставить не нужно» — неверно; tar.gz-бинари — та же проблема. Исправление: собирать Linux-таргет в `container: ubuntu:22.04` (glibc 2.35) на раннере ubuntu-24.04 (linuxdeploy внутри контейнера — `APPIMAGE_EXTRACT_AND_RUN=1`, FUSE не нужен), проверять `objdump -T aira-gui | grep -o 'GLIBC_[0-9.]*' | sort -V | tail -1` как шаг CI, писать минимальную glibc в release notes. Версии glibc — по памяти (§10). → **M23** (желательно уже к v0.4.0, раз bridge-релиз тоже публикует AppImage).

**MEDIUM — M6. Плавающие раннеры.** `macos-latest` уже macOS 26 (Xcode 26 SDK), `windows-latest` = Server 2025, `ubuntu-latest` = 24.04 — меняются без предупреждения. Пин: `ubuntu-24.04`, `macos-15`, `windows-2025` (`macos-14` помечен deprecated). Задать `MACOSX_DEPLOYMENT_TARGET=11.0` явно и привести `LSMinimumSystemVersion` в `Info.plist.template:27` в соответствие (10.13 → 11.0). → **M23**.

**MEDIUM — M7. Тихая потеря артефактов.** `if-no-files-found: ignore` (`release.yml:153`), `mv … 2>/dev/null || true` (`:118-119,137-138`), `brew install … || true` (`:114`), `apt-get install libfuse2 || true` (`:133`). Релиз опубликуется с неполным набором assets, и никто не узнает (сайт `aira.letar.best` покажет карточку без ссылки). Исправление: `if-no-files-found: error`, явные `test -f` после каждого bundle-шага, финальный шаг в `release` со списком ожидаемых файлов по таргетам. → **M23**.

**MEDIUM — M8. Канал pre-release.** `softprops/action-gh-release@v2` без `prerelease`/`draft`/`make_latest` (`release.yml:260-262`): `v0.5.0-beta.1` станет «Latest» и уедет на сайт всем. Исправление: `prerelease: ${{ contains(github.ref_name, '-') }}`, `make_latest: ${{ !contains(github.ref_name, '-') }}`, `draft: true` для ручной проверки перед публикацией; актуальный `v3.0.3` → `efb35369e0ad2afab669f228072c1b0d510eae64`. Сайт: `getLatestRelease()` (`release.md:70`) — уточнить, что API `releases/latest` pre-release не возвращает (штатное поведение GitHub), т.е. с `prerelease: true` сайт не сломается. → **M23**.

**MEDIUM — M11. MSI и pre-release-версии.** `cargo wix` берёт версию из `Cargo.toml` (`main.wxs:35` `$(var.Version)`); Windows Installer требует числовой `ProductVersion` x.y.z — как cargo-wix 0.3.9 переживёт `0.5.0-beta.1`, **не проверено** (§10). Заложить `cargo wix --install-version "${VERSION%%-*}"` и помнить, что две беты получат один ProductVersion (MajorUpgrade не сработает без `AllowSameVersionUpgrades`). → **M23**.

**LOW — M10. Инъекция через выражение.** `"${{ github.ref_name }}"` подставляется в pwsh (`release.yml:78,94`); тег `v*` может содержать `"` или `$(…)`. Пушить теги могут только коллабораторы, поэтому LOW; заменить на `$env:GITHUB_REF_NAME`. → **M23**.

**LOW — L1.** В архивах нет `LICENSE-*`/`README`/`CHANGELOG` (`release.yml:63-72,78-88`) — winget/portable-пользователи получают бинари без лицензии. → **M23** (после B3).

**LOW — L4.** `release.md` расходится с yml (раннер macOS Intel, состав jobs). → **M23**.

## 3. android.yml — NDK, cargo-ndk, ABI, proguard, Gradle

Что уже сказано в `clients-audit.md` (не повторяю): нет `signingConfigs`, нет `proguard-rules.pro` при `isMinifyEnabled = true` (R8 сломает JNA/UniFFI), FGS `dataSync` 6 ч, FCM без google-services, `targetSdk 35` (нужен 36 к 31.08.2026, §6.6.4), 16 KB alignment. Ниже — CI-механика.

| Параметр | Значение | Оценка |
|---|---|---|
| NDK | `ANDROID_NDK_VERSION: "26.1.10909125"` (r26b; `android.yml:18`, `release.yml:9`) через `android-actions/setup-android@v3` (докачивает ~1 ГБ) | на ubuntu-24.04 предустановлены `27.3.13750724 (default)`, **`28.2.13676358`**, `29.0.14206865` (runner-images, проверено) → `28.2.13676358` (r28c): 16 KB `max-page-size` по умолчанию (§6.6.4), без докачки |
| cargo-ndk | `cargo install cargo-ndk` без версии (`android.yml:44`, `release.yml:170`); актуальная **4.1.2** (2025-08-09) | `cargo install cargo-ndk@4.1.2 --locked` или `taiki-e/install-action`; `-o jniLibs` вместо ручных `cp` (`release.yml:187-194`) |
| `--platform 26` | = `minSdk 26` ✓ | оставить |
| ABI | `arm64-v8a` + `x86_64` (эмулятор) ✓; `armeabi-v7a`/`x86` — нет | для 2026 достаточно; `.aab` (§15.7 спеки) не собирается — Play не в бете, ок |
| Gradle | **`gradlew`/`gradle-wrapper.jar` в репо нет** (есть только `gradle/wrapper/gradle-wrapper.properties` → 8.11.1); `gradle assembleDebug/Release` = системный Gradle образа (`android.yml:128`, `release.yml:227`); `gradle/actions/setup-gradle@v4` без `gradle-version` (по докам — «wrapper», которого нет) | сегодня в образе **Gradle 9.7.1** при AGP 8.7.0 (`mobile/android/build.gradle.kts:3`) — совместимость AGP 8.7 с Gradle 9.x **не проверена** (§10); в апреле сборка прошла на другом Gradle. Исправление: `gradle wrapper --gradle-version 8.11.1` → закоммитить `gradlew`, `gradlew.bat`, `gradle/wrapper/gradle-wrapper.jar`; `gradle/actions/setup-gradle@v6.3.0` (`9c971963bec38e04b3d30dcc455b5382be2fdbfb`) — валидирует checksum jar'а; вызывать `./gradlew --no-daemon` |
| JDK | Temurin 17 (`android.yml:99-103`) ✓; `setup-java@v4` → v5.7.0/v6.0.1 (Node 24) | ок |
| Триггеры | `paths` только `crates/aira-ffi/**`, `mobile/android/**` (`android.yml:6-9,12-14`) | **MEDIUM M4**: aira-ffi зависит от aira-core/net/storage/daemon — их изменения (и `Cargo.lock`) Android-сборку не запускают; последний run 2026-04-10; в `release.yml:248` `needs: [build, android]` → тихая поломка Android заблокирует desktop-релиз на теге |
| `rust-tests` job | `cargo test -p aira-ffi` + clippy (`android.yml:137-150`) | дубль `ci.yml` (`--workspace` покрывает aira-ffi) — удалить |
| `uniffi-bindgen` | host-сборка debug `.so` → `generate --library` → Kotlin (`android.yml:75-83`) ✓ | в release.yml то же (`:196-202`) ✓ |
| Артефакты | debug APK как artifact ✓ | ок |

**Исправления (→ M19b Android-пакет, кроме отмеченного):**
1. В `ci.yml` добавить лёгкий job `android-check`: `cargo ndk -t arm64-v8a --platform 26 -- check -p aira-ffi --locked` (с rust-cache, ~2–3 мин) на каждый PR — ловит поломки cdylib под Android до тега. → **M18** (иначе M18-миграция iroh 1.1 может сломать Android незаметно).
2. `release.yml`: отвязать desktop от Android — `release` зависит только от `build`; Android-assets прикладываются шагом `if: needs.android.result == 'success'` (или отдельный workflow `release-android.yml` на тот же тег с `environment: android-release`). Пока APK не подписан — **убрать его из assets** уже в v0.4.0 (одна строка), чтобы не публиковать заведомо неустанавливаемый файл (вопрос владельцу — спека §16.1 п.6).
3. NDK `28.2.13676358`, `cargo-ndk@4.1.2 --locked`, wrapper + `setup-gradle@v6`, `./gradlew`, `apksigner verify`, `proguard-rules.pro`, `targetSdk 36` — по спеке M19b п.9–11 с версиями из этой таблицы.
4. `android.yml`: убрать `paths`-фильтр (или расширить на `crates/**`, `Cargo.lock`, `Cargo.toml`), убрать `milestone/M10-*` и `dev`, удалить `rust-tests`, добавить `permissions: contents: read`, `timeout-minutes: 45`.

## 4. deny.toml и .cargo/audit.toml — advisories, лицензии, sources, дубли

### 4.1 Текущие 18 уязвимостей (`cargo audit`, job 107423723908, 2026-09-23) и пути закрытия

Цепочки — по `Cargo.lock` (обратные зависимости построены скриптом по `dependencies = [...]`; lock включает optional-зависимости всех фич, поэтому «в lock» ≠ «в бинаре»).

| Крейт (в lock) | Advisory → фикс | Цепочка до workspace | Чем закрывается |
|---|---|---|---|
| crossbeam-epoch 0.9.18 | RUSTSEC-2026-0204 → ≥0.9.20 | moka ← hickory-resolver 0.25 ← iroh 0.97 | `cargo update -p crossbeam-epoch` (сразу) или iroh 1.1 |
| h2 0.4.13 | 2026-0258 → ≥0.4.16 | hickory-proto; hyper 1.9 ← hyper-rustls ← reqwest 0.12.28 ← iroh 0.97 / aira-net (`cdn`) | `cargo update -p h2` (сразу) |
| hickory-proto 0.25.2 | 2026-0119 → ≥0.26.1; **2026-0118 — фикса в 0.25 нет** (код переехал в hickory-net 0.26; проверено в advisory-db) | hickory-resolver 0.25.2 ← iroh 0.97 | только iroh 1.1 (hickory 0.26 — по facts-crates; не перепроверено) → **M18** |
| quick-xml 0.30.0 | 2026-0194, 2026-0195 (7.5 high) → ≥0.41.0 | zbus_xml 4.0.0 ← zbus 4.4 ← accesskit_unix ← accesskit_winit ← egui-winit 0.29 ← eframe | egui/eframe 0.36 (accesskit/zbus 5) — версия quick-xml там **не проверена** |
| quick-xml 0.37.5 | то же | tauri-winrt-notification 0.7.2 ← notify-rust 4.12 ← aira-cli, aira-gui (только Windows) | bump notify-rust или временный ignore |
| quick-xml 0.38.4 | то же | plist 1.8 ← netdev 0.40 ← netwatch 0.15 ← iroh 0.97 | iroh 1.1 (новый netdev — не проверено) |
| quick-xml 0.39.2 | то же | wayland-scanner 0.31.10 ← wayland-client ← ashpd ← rfd 0.15; ← smithay-client-toolkit ← winit 0.30 ← egui-winit | build-time генератор протоколов (не runtime); bump winit/rfd — не проверено |
| quinn-proto 0.11.14 | 2026-0185 (7.5) → ≥0.11.15 | quinn 0.11.9 ← reqwest 0.12.28 (optional `http3`) ← iroh 0.97 / aira-net `cdn` | `cargo update -p quinn-proto` (сразу); в бинаре, вероятно, нет — подтвердит `cargo audit bin` после cargo-auditable (§10) |
| rustls 0.23.37 | **2026-0285** (5.3, 2026-09-14) → ≥0.23.45 | iroh 0.97; aira-net (`reality`) | `cargo update -p rustls` (сразу) |
| rustls-webpki 0.103.10 | 2026-0098, -0099 → ≥0.103.12; -0104 → ≥0.103.13 | rustls; iroh; rustls-platform-verifier | `cargo update -p rustls-webpki` (сразу) |
| webbrowser 1.2.0 | 2026-0257 → ≥1.2.2 | egui-winit 0.29 ← eframe | `cargo update -p webbrowser` (сразу) |

Итого: 6 записей закрываются `cargo update` без изменения `Cargo.toml` (можно **сегодня**, отдельным коммитом `chore(deps)`), 4 — iroh 1.1 (M18), 8 (quick-xml ×4 версии × 2 ID) — апгрейд GUI-стека (egui 0.29 → 0.36 не входит в релизный путь) **или** временный ignore с обоснованием и сроком (§4.6). Спека M18 п.8 обещает только «quinn-proto / hickory-proto / ml-dsa» — недостаточно для зелёного `audit`.

12 «allowed warnings» (не блокируют, но видны): unmaintained `ttf-parser` 2026-0192 (egui-шрифты); unsound `anyhow` 1.0.102 2026-0190 (в логе cargo-deny собирается с anyhow 1.0.104 — `cargo update` снимает), `event-listener` 5.4.1 2026-0221, `lru` 0.12.5/0.16.3 2026-0253, `memmap2` 0.9.10 2026-0186 (0.9.11 есть), `rand` 0.8.5/0.9.2 2026-0097 («custom logger using rand::rng()» — Aira использует `tracing`, не затрагивает); yanked: `der` 0.8.0, `pkarr` 5.0.4, `spin` 0.9.8 и 0.10.0 (`cargo update` подберёт не-yanked; der/pkarr — через iroh 0.97 → уйдут с M18).

### 4.2 Ревизия ignore-списка (22 записи в `deny.toml:38-72`, зеркало в `.cargo/audit.toml:7-38`)

| ID | Крейт | В Cargo.lock | Тип | Вердикт |
|---|---|---|---|---|
| RUSTSEC-2025-0144 | ml-dsa 0.0.4 | да | vuln, timing | оставить до M18; обоснование «Scheduled for v0.3.6» (`deny.toml:42`, `audit.toml:9-10`) устарело → «M18, дедлайн 30.09.2026»; удалить в M18 (спека п.8). Формулировка «signing is not called on an attacker-influenced schedule» после M19 (handshake по сети) перестанет быть верной — ещё один довод не тянуть |
| 2024-0370 | proc-macro-error 0.4.12 (genawaiter ← bao-tree ← iroh-blobs), 1.0.4 (glib-macros/gtk3-macros) | да | unmaintained | заменить настройкой `unmaintained = "workspace"` |
| 2024-0384 | instant | **нет** | unmaintained | удалить (unused) |
| 2024-0388 | derivative | **нет** | unmaintained | удалить |
| 2024-0436 | paste 1.0.15 (ratatui, uniffi, accesskit_windows, metal, netlink) | да | unmaintained | настройка |
| 2025-0141, 2024-0320 | yaml-rust | **нет** | unmaintained | удалить (2 ID) |
| 2024-0412/0413/0414/0415/0419/0420/0421 | atk, atk-sys, gdk, gdk-sys, gtk, gtk-sys, gtk3-macros 0.18 (tray-icon 0.19 → libappindicator 0.9 → gtk 0.18) | да | unmaintained | настройка; реальный фикс — tray-icon без libappindicator (ksni/zbus) — после беты |
| 2024-0416/0417/0418/0422 | gdkwayland-sys, gdkx11, gdkx11-sys, atk3 | **нет** | unmaintained | удалить (4 ID) |
| 2023-0089 | atomic-polyfill 1.0.3 (heapless 0.7 ← postcard 1.1.3) | да | unmaintained | настройка; postcard 1.1 → heapless 0.8 когда выйдет |
| 2023-0071 | rsa | **нет** | vuln (Marvin) | удалить — крейта в графе нет |
| 2024-0429 | glib 0.18.5 | да | unsound (`VariantStrIter`) | оставить с `reason`: только через tray-icon; Aira `Variant` не использует |
| 2026-0002 | lru 0.12.5 (ratatui) | да | unsound (IterMut) | оставить с `reason`; добавить 2026-0253 (тот же lru) если решено гасить unsound-warnings |

Итог: 9 из 22 ID — мусор (cargo-deny 0.20 с дефолтом `unused-ignored-advisory = "warn"` печатает предупреждение на каждый), 10 — заменяются одной настройкой, 3 остаются. В `.cargo/audit.toml` комментарий `# See deny.toml for the full rationale` (`audit.toml:14`) — обоснования per-entry нет ни там, ни там (кроме 0144).

### 4.3 Конфигурация cargo-deny — что неточно и что добавить

Сверено с актуальной документацией cargo-deny (`docs/src/checks/advisories/cfg.md`, `bans/cfg.md`, WebFetch 2026-09-24):

- Комментарий `deny.toml:35-37` («cargo-deny 0.19+: vulnerability/unmaintained/yanked/notice moved to [graph]…») неверен: ключи `vulnerability`, `unsound`, `notice` **удалены** (все vulnerability-advisories — всегда ошибки, гасятся только через `ignore`), `yanked` остался (default **`warn`**), `unmaintained` остался (default **`"all"`**, значения `all | workspace | transitive | none`), появились `unused-ignored-advisory` (default `warn`) и `maximum-db-staleness` (`P90D`).
- **Добавить:** `[advisories] unmaintained = "workspace"` (unmaintained только для прямых зависимостей — снимает 10 ignore), `yanked = "deny"` (3 yanked-крейта сейчас проходят), `ignore` в объектной форме `{ id = "RUSTSEC-…", reason = "…" }`.
- **`[bans]`:** `wildcards = "warn"` (`deny.toml:31`) с комментарием «Revisit when we set `publish = false`» — по докам `allow-wildcard-paths = true` разрешает path-зависимости **в private (`publish = false`) крейтах**; ни один из 8 крейтов `publish = false` не выставил (`cargo metadata --no-deps`: `publish=None` везде). Исправление: `publish = false` во все `crates/*/Cargo.toml` (на crates.io не публикуемся) + `allow-wildcard-paths = true` + `wildcards = "deny"`. `multiple-versions = "warn"` — оставить (101 дубль из 797 имён, 12,7 %; топ: семейство windows-* — 14 имён по 2–6 версий, quick-xml ×4, winnow ×3, toml_edit ×3, hybrid-array ×3, getrandom ×3, hashbrown ×3; RustCrypto rc-дубли digest/sha2/pkcs8/der/spki/signature уйдут с M18); `skip-tree = [{ crate = "windows-sys" }]` уменьшит шум.
- **`[graph]` отсутствует** → проверка по default-фичам. Вне проверки: `fips`/`compat-test` (aws-lc-rs → aws-lc-sys; лицензионное выражение содержит компонент `OpenSSL` — **не проверено**, allow-список его не содержит), `cdn` (reqwest с default-features → native-tls/openssl-sys), `reality`/`tor`. После удаления DPI-транспортов (M19b, net-audit) — `[graph] all-features = true`; до этого — `features = ["aira-core/fips"]` хотя бы для лицензий.
- `db-urls` — дефолт, можно убрать. `[sources] unknown-registry = "deny"`, `unknown-git = "deny"` ✓; git-зависимостей в lock 0 ✓, все источники `crates.io-index` ✓.

### 4.4 Лицензии — совместимость с дистрибуцией MIT OR Apache-2.0

Allow-список `deny.toml:4-21` (MIT, Apache-2.0 [+LLVM-exception], BSD-2/3, ISC, Unicode-DFS-2016, Unicode-3.0, CC0-1.0, Zlib, Unlicense, MPL-2.0, BSL-1.0, OFL-1.1, LicenseRef-UFL-1.0, CDLA-Permissive-2.0) — все пермиссивные или file-level copyleft:

- **MPL-2.0** (webpki-roots, option-ext): copyleft на уровне файла — бинарная дистрибуция допустима, исходники MPL-файлов доступны на crates.io; не «заражает» MIT/Apache. ОК.
- **OFL-1.1 / LicenseRef-UFL-1.0** (шрифты egui, `epaint_default_fonts`): встраивание шрифта в приложение разрешено; ограничения — не продавать шрифт отдельно, сохранять лицензию, при модификации не использовать Reserved Font Name. Нужно включать тексты OFL/UFL в дистрибутив (сейчас — нет, L1). Собственные шрифты в `crates/aira-gui/assets/` (Inter ×2 — OFL, JetBrainsMono — OFL) — их лицензии тоже должны ехать в архив/AppImage/MSI.
- **CDLA-Permissive-2.0** (webpki-root-certs, Mozilla CA bundle) — пермиссивная. ОК.
- Aira-собственная лицензия: **тексты MIT и Apache-2.0 отсутствуют** (B3) — `cargo about`/SBOM не смогут корректно атрибутировать `aira-*`.
- Локально `cargo deny check licenses` не запускался (инструмент не установлен) — результат на текущем lock **не проверен**; по commit-message `2a41b8b` на 2026-04-10 было `licenses ok`.

### 4.5 Что менять в файлах (deliverable «в»)

`.cargo/audit.toml` — целевой список после M18 (до M18 — плюс RUSTSEC-2025-0144 с обновлённым обоснованием):

```toml
# cargo-audit configuration. Держать в синхроне с deny.toml [advisories].ignore.
[advisories]
ignore = [
    # unsound в транзитивных крейтах, код на нашем пути не исполняется:
    "RUSTSEC-2024-0429", # glib 0.18 VariantStrIter — только tray-icon→libappindicator→gtk3; Aira Variant не использует; уйдёт с tray-icon без gtk3
    "RUSTSEC-2026-0002", # lru 0.12 IterMut — ratatui 0.29; напрямую не используем; уйдёт с ratatui 0.30
    "RUSTSEC-2026-0253", # lru 0.12/0.16 LruCache::pop panic-safety — то же; 0.16 через iroh-relay (проверить после iroh 1.1)
    # ВРЕМЕННО, только если после iroh 1.1 + `cargo update` quick-xml ≥0.41 не резолвится (срок: до bump egui/eframe 0.36, не позже 2026-12-31):
    # "RUSTSEC-2026-0194", # quick-xml: quadratic attrs — парсит локальный plist/D-Bus introspection/wayland XML, не сетевой ввод
    # "RUSTSEC-2026-0195", # quick-xml: NsReader allocation — то же
]
```

`deny.toml` — изменения:

```toml
[graph]
all-features = true            # после удаления DPI-транспортов (M19b); до этого: features = ["aira-core/fips"]

[advisories]
unmaintained = "workspace"     # unmaintained только для прямых зависимостей
yanked = "deny"                # der 0.8.0 / pkarr 5.0.4 / spin — сейчас проходят как warn
unused-ignored-advisory = "deny"
ignore = [
    { id = "RUSTSEC-2024-0429", reason = "glib VariantStrIter unsound; only via tray-icon→gtk3, Variant API unused" },
    { id = "RUSTSEC-2026-0002", reason = "lru IterMut unsound; ratatui transitive, lru not used directly" },
    { id = "RUSTSEC-2026-0253", reason = "lru pop() panic-safety; same" },
]

[bans]
multiple-versions = "warn"
wildcards = "deny"
allow-wildcard-paths = true    # требует publish = false во всех crates/*/Cargo.toml
skip-tree = [{ crate = "windows-sys" }]
```

Плюс `publish = false` в восьми `crates/*/Cargo.toml` и `rust-version.workspace = true` (L6). Всё — **M18** (config), `[graph] all-features` — **M19b**.

## 5. Управление репозиторием

| Элемент | Статус (HEAD 7726b46, origin) | Действие | Milestone |
|---|---|---|---|
| `LICENSE-MIT`, `LICENSE-APACHE` (или `LICENSE`) | **отсутствуют** при `license = "MIT OR Apache-2.0"` (`Cargo.toml:18`) и двух публичных релизах | добавить оба текста + `license-file` не нужен (SPDX-выражение уже есть); упоминание в README; включать в архивы (L1). Без них SignPath/Certum OSS/F-Droid/winget-заявки не пройдут | **M18, до тега v0.4.0** (B3) |
| `README.md` | отсутствует (спека M19b п.6) | заглушка в M18 (название, статус «pre-release, сети нет», ссылки на INSTALL/SPEC/SECURITY), полный — M19b | M18/M19b |
| `SECURITY.md` | нет | по спеке M23 п.3; включить GitHub «Private vulnerability reporting» (вопрос владельцу) | M23 |
| `CHANGELOG.md` | нет; release notes = автогенерация (`generate_release_notes: true`) | Keep-a-Changelog + job `verify` проверяет наличие секции версии | M23 |
| `CONTRIBUTING.md` | нет | минимум: DCO/лицензия вклада («MIT OR Apache-2.0»), правила коммитов из `.claude/rules/git.md`, запрет секретов | M23 |
| `CODEOWNERS` | нет | `* @kamiletar`; `.github/** deny.toml .cargo/** Cargo.lock @kamiletar` — с required review в ruleset даёт защиту CI-конфигов | M23 |
| Шаблоны issue/PR | нет (спека M23 п.7 — bug report) | `bug_report.yml`, `security` → SECURITY.md, PR-шаблон с чеклистом из `security.md` | M23 |
| `.github/dependabot.yml` | нет | §8.3 (actions weekly, cargo weekly grouped, gradle weekly) | M18 |
| `rust-toolchain.toml` | нет | §8.1 | M18 |
| Ветки | origin: только `main` (+ рабочая `claude/*`); `dev` из ci.yml не существует; `.claude/rules/git.md` описывает `dev`/`feat/*`/`milestone/*` | привести ci.yml к реальности (M16); ветку `dev` либо завести, либо убрать из правил | M18 |
| Теги/релизы | `v0.3.4`, `v0.3.5` (оба 2026-04-10; annotated ✓; `v0.3.5` → `851ec91`, предок HEAD ✓); тег v0.3.5 переставлялся между двумя release-run | ruleset на `v*`: create только владелец, update/delete запрещены; после attestations теги immutable | M23 (owner) |
| Подпись коммитов | 0 из 50 (`git log %G?` = N) | опционально: SSH-signing (`gpg.format ssh`) + ruleset «require signed commits»; для соло-проекта — по желанию | 1.0 |
| Branch protection / rulesets на `main` | **не проверить из клона** | вопрос владельцу: required checks (fmt/clippy/test/audit), linear history, no force-push, require PR | M18 (owner) |
| Дефолтные права `GITHUB_TOKEN` | не проверить | Settings → Actions → Workflow permissions → **Read repository contents**; «Allow GitHub Actions to create PRs» — off | M18 (owner) |
| Разрешённые actions | не проверить | «Allow actions by GitHub + verified creators + список pinned» | M18 (owner) |
| Fork PR approval | не проверить | «Require approval for all outside collaborators» | M18 (owner) |
| Dependabot alerts / security updates / secret scanning + push protection / private vulnerability reporting | не проверить | включить все четыре (бесплатно для public) | M18 (owner) |
| Сайт `aira.letar.best` (`release.md:64-72`) | читает latest release | убедиться, что pre-release не подхватывается как latest и что карточки проверяют наличие asset (M7) | M23 |

## 6. Внешние факты (проверено 2026-09-24, если не сказано иначе)

### 6.1 SHA-пины actions (`git ls-remote --tags`, peeled commit для annotated тегов; перед применением перепроверить)

| Action | Сейчас в yml | Актуальный тег | Commit SHA для пина |
|---|---|---|---|
| actions/checkout | `@v4` (Node 20, deprecated) | v7.0.1 (есть v6.0.3 `df4cb1c069e1874edd31b4311f1884172cec0e10`) | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| actions/upload-artifact | `@v4` | v7.0.1 | `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` |
| actions/download-artifact | `@v4` | v8.0.1 | `3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c` |
| dtolnay/rust-toolchain | `@stable` (ветка) | `master` = тег `v1`; ветки `1.91.0` `8d8cc9a8e0d47b64af669de71110e76860d6afbd`, `1.98.1` `ce678459e9fc7500d337468f904b95f1b5c10b5e` | `02cb101ec7c40f2c49e1d9714d64511d8e1b74de` (+ `with: toolchain:`) — или не использовать вовсе, см. §8.1 |
| Swatinem/rust-cache | `@v2` | v2.9.2 | `6323deb102c322ba6fcbdcafc7e3dddab59af2b6` |
| softprops/action-gh-release | `@v2` | v3.0.3 (v2.6.2 `3bb12739c298aeb8a4eeaf626c5b8d85266b0e65`) | `efb35369e0ad2afab669f228072c1b0d510eae64` |
| android-actions/setup-android | `@v3` | v4.0.4 | `be39fa834029ff78f1a44aa3bb0819b8fc2bd8fd` |
| actions/setup-java | `@v4` | v6.0.1 (v5.7.0 `b6effb05e454b25005698d916606bdc6ffcbf961`) | `de7274f081f381c8f8158605e0321c36c376e2e6` |
| gradle/actions (setup-gradle, wrapper-validation) | `@v4` | v6.3.0 | `9c971963bec38e04b3d30dcc455b5382be2fdbfb` |
| actions/attest-build-provenance | — | v4.2.2 | `4d101475d8b20a2381f78447822ac1eab6504dd8` |
| actions/attest-sbom | — | v4.1.0 | `c604332985a26aa8cf1bdc465b92731239ec6b9e` |
| EmbarkStudios/cargo-deny-action | — | v2.1.1 | `3c6349835b2b7b196a839186cb8b78e02f7b5f25` |
| taiki-e/install-action | — | v2.87.19 | `7623a79cdfecb99d681017af368ca353d9f49bb5` |
| rustsec/audit-check | — | v2.0.0 | `69366f33c96575abad1ee0dba8212993eecbe998` |
| step-security/harden-runner | — | v2.21.1 | `e14015d583714f6e62063499dc959a02595150a1` |
| ossf/scorecard-action | — | v2.4.4 | `2d1146689b8cda280b9bc96326124645441f03bc` |
| slsa-framework/slsa-github-generator | — | v2.1.0 | `f7dd8c54c2067bafc12ca7a55595d5ee9b75204a` |
| sigstore/cosign-installer | — | v4.1.2 | `6f9f17788090df1f26f669e9d70d6ae9567deba6` |
| actions/dependency-review-action | — | v5.0.0 | `a1d282b36b6f3519aa1f3fc636f609c47dddb294` |

### 6.2 Инструменты (crates.io API)

| Инструмент | Версия | Дата | Для чего |
|---|---|---|---|
| cargo-audit | 0.22.2 | 2026-06-05 | audit job; `cargo audit bin` для auditable-бинарей |
| cargo-deny | 0.20.2 | 2026-07-09 | лицензии/bans/advisories (та же, что ставится в CI сейчас) |
| cargo-auditable | 0.7.6 | 2026-09-13 | `cargo auditable build` (M23) |
| cargo-cyclonedx | 0.5.9 | 2026-03-19 | SBOM (M23) |
| cargo-vet | 0.10.2 | 2026-01-13 | 1.0 |
| cargo-ndk | 4.1.2 | 2025-08-09 | Android (M19b) |
| cargo-wix | 0.3.9 | 2025-03-13 | MSI (уже запинен ✓) |
| cargo-fuzz | 0.13.2 | 2026-06-09 | fuzz job (M19a) |
| cargo-llvm-cov | 0.9.1 | 2026-09-06 | coverage (M23, test-coverage §) |
| cargo-binstall | 1.23.0 | 2026-09-05 | быстрая установка вместо компиляции |
| cargo-semver-checks / cargo-hack / cargo-msrv | 0.50.0 / 0.6.45 / 0.19.3 | — | не нужны до 1.0 |

### 6.3 Раннеры GitHub (runner-images README, 2026-09-24)

- `ubuntu-latest` = Ubuntu 24.04.5; Gradle **9.7.1**; NDK 27.3.13750724 (default), **28.2.13676358**, 29.0.14206865; Build-Tools до 37.0.0; Java 17 (default), 21, 25; Rust 1.98.1, rustup 1.29.1; Node 22/24; libfuse2 в списке не значится (release.yml ставит `|| true`).
- `windows-latest` = Windows Server 2025 (`windows-2025`, `windows-2025-vs2026`); **WiX Toolset 3.14.1.8722** есть; Rust 1.98.1; VS 2022 17.14; Java 17 default.
- `macos-latest` = **macOS 26 arm64**; `macos-15` доступен; `macos-14` deprecated; `macos-13` (Intel) в таблице отсутствует → x86_64-apple-darwin только кросс-сборкой (как сейчас).
- `ubuntu-22.04` и `windows-2022` ещё в таблице, дат retirement в README нет.

### 6.4 Attestations, cargo-deny, advisories

- `actions/attest`: permissions `id-token: write`, `attestations: write`, `artifact-metadata: write`; `subject-path` glob/список; `subject-checksums` (shasum-формат); ≤ 1024 subjects; public repo → Sigstore Public Good; проверка — `gh attestation verify`. Уровень SLSA README не называет; L2 vs L3 (reusable workflow) — из документации GitHub, **не проверено онлайн** (docs.github.com заблокирован).
- cargo-deny `[advisories]`: `yanked` default `warn`; `unmaintained` default `all` (`all|workspace|transitive|none`); `unsound` default `workspace`; `unused-ignored-advisory` default `warn`; `vulnerability/unsound/notice`-ключи удалены. `[bans]`: `multiple-versions` default `warn`, `wildcards` default `warn`, `allow-wildcard-paths` — private (publish=false) крейты.
- RustSec `crates/ml-dsa` содержит **только** RUSTSEC-2025-0144. GHSA-h37v-hp6w-2pp8 (ml-dsa ≤0.1.0-rc.4, `use_hint` off-by-one → валидная подпись не верифицируется, CVSS 5.5, без CVE) в RustSec **не зеркалируется** → `cargo audit`/`cargo deny` его не видят; видит Dependabot (GitHub Advisory DB). CVE-2026-24850 (спека M18) — не проверял.
- hickory-proto RUSTSEC-2026-0118: patched versions — нет; unaffected `>= 0.26.0-beta.1`.
- gradle/actions setup-gradle: без `gradle-version` использует **wrapper** проекта (которого у Aira нет); валидирует checksum `gradle-wrapper.jar`; `dependency-graph: generate-and-submit` даёт Dependabot alerts для Gradle-зависимостей (нужен `contents: write` — только в отдельном job на `main`).
- OpenSSF Scorecard: `publish_results: true` требует `id-token: write` только у scorecard-job, без top-level `env`, только ubuntu; SARIF в Code scanning через `github/codeql-action/upload-sarif`.

## 7. Таблица требований §6.6.5 / §6.6.7 → статус → действие → milestone

Нумерация «M23» — по `spec/18-milestones.md` (Release hardening); в задании фазы 3 эти же пункты названы «M22 релизная инфраструктура» — см. §9.4.

| # | Требование (§6.6.5 / §6.6.7) | Статус сейчас (доказательство) | Что сделать | Milestone |
|---|---|---|---|---|
| 1 | CI зелёный; `cargo audit`/`cargo deny`/clippy — блокирующие jobs на актуальном stable (§6.6.7 п.1) | **красный**: 18 vulns (job 107423723908), clippy 1.98 — 2 ошибки (job 107423723873); jobs есть, но не «required» (branch protection — не проверить) | `rust-toolchain.toml` + MSRV-job; `cargo update` (6 записей) + iroh 1.1 (4) + решение по quick-xml (8); починить `discovery.rs:155`, `relay.rs:112`; cargo-deny-action/install-action вместо `cargo install`; `schedule`; required checks в ruleset (owner) | **M18** |
| 2 | Supply chain workflow'ов: SHA-пины, least-privilege permissions, без persisted credentials, Dependabot (§6.6.5 подразумевает) | 0 SHA-пинов; `permissions` нет / `contents: write` везде (`release.yml:11`); `persist-credentials` default; Dependabot нет | таблица §6.1; `permissions: {}` + per-job; `persist-credentials: false`; `.github/dependabot.yml` (§8.3) | **M18** |
| 3 | `--locked`, `--all-features` (spec §17), без кэша в релизе | `--locked` нигде; `--all-features` нигде (test-coverage §6); `rust-cache` в release.yml:42,165 | `--locked` везде; `--all-features` на Linux (после/с удалением транспортов); релиз без кэша | **M18** (`--locked`, all-features Linux) / **M23** (кэш) |
| 4 | Непроверенные загрузки в релизе (linuxdeploy continuous, plugin master, brew, cargo install без версий) | `release.yml:114,127-131,170` | пин тега + sha256; вендорить `linuxdeploy-plugin-gtk.sh`; `cargo-ndk@4.1.2 --locked` | **M18** |
| 5 | Подпись Android: keystore + `apksigner verify` (§6.6.7 п.2) | нет (`release.yml:233`, `build.gradle.kts:23-32`) | §2.6: environment `android-release`, 4 секрета, signingConfig/apksigner, verify, отпечаток в docs; до готовности — убрать APK из assets | **M19b** (решение владельца: доводить или preview) |
| 6 | Windows: SignPath Foundation / Certum OSS (п.2) | нет; INSTALL.md обещает «$300/год, v0.4» | заявка в SignPath (нужны B3 LICENSE + README); в release.yml — шаг отправки MSI/exe в SignPath pipeline (их action/CLI) после одобрения; иначе честно в INSTALL.md | **M23** (owner) |
| 7 | macOS: Developer ID + notarization (п.2) | нет (`bundle-macos.sh:79` только `xattr -cr`) | `codesign --options runtime --entitlements` (network client) + `notarytool submit --wait` + `stapler`; секреты `APPLE_CERT_P12_B64`, `APPLE_CERT_PASSWORD`, `APPLE_ID`, `APPLE_TEAM_ID`, `APPLE_APP_PASSWORD` в environment `release`; иначе INSTALL.md: путь через System Settings (не «правый клик → Open») | **M23** (owner, $99) |
| 8 | sha256 (п.4) | per-file `.sha256` тем же job | единый `SHA256SUMS` в job `release` (+ оставить сайдкары для сайта) | **M23** |
| 9 | GitHub attestations (п.4) | нет | `actions/attest-build-provenance@v4.2.2` с `subject-checksums: SHA256SUMS`; permissions `id-token/attestations/artifact-metadata: write`; INSTALL.md: `gh attestation verify … --owner kamiletar`; уровень — SLSA L2 (L3 = reusable workflow, 1.0) | **M23** |
| 10 | cargo-auditable (п.4) | нет | `cargo auditable build --release --locked` во всех сборках (desktop + `cargo ndk … auditable build` — проверить); `cargo audit bin` как шаг | **M23** |
| 11 | SBOM CycloneDX (п.4) | нет | `cargo cyclonedx --format json --describe binaries --target <t>` per-target; `actions/attest-sbom@v4.1.0`; файл `aira-<v>-<target>.cdx.json` в assets | **M23** |
| 12 | Подпись чексумм (minisign/cosign) — сверх чеклиста, нужна для Tauri updater M17 и для пользователей без `gh` | нет | minisign-ключ офлайн у владельца (пароль в менеджере, бэкап ×2), `SHA256SUMS.minisig` подписывается **локально** при публикации (draft → publish) либо cosign keyless в CI | **M23** (owner) |
| 13 | Версия ↔ тег ↔ Gradle ↔ MSI; релиз с зелёного main; environment с approve | нет проверок; `release.sh` пушит в main мимо PR; тег переставлялся | job `verify` (§8.2); `environment: release` с required reviewer; ruleset на `v*` | **M18** (verify) / **M23** |
| 14 | Pre-release канал `0.5.0-beta.N`, шаблон bug report (п.7) | релиз всегда stable/latest; шаблонов нет | `prerelease`/`make_latest`/`draft`; `.github/ISSUE_TEMPLATE/bug_report.yml` | **M23** |
| 15 | Документы: README, SECURITY, THREAT_MODEL, PRIVACY, CHANGELOG, INSTALL (п.3) + **LICENSE** | всё отсутствует, кроме INSTALL (устарел в 3 местах, M13) | LICENSE + README-заглушка — M18 (до v0.4.0); остальное — M23; INSTALL.md: Sequoia-обход, SignPath, glibc, Android-статус, `gh attestation verify` | **M18 / M19b / M23** |
| 16 | Android: targetSdk 36, NDK r28, proguard, FGS, без FCM, 16 KB (п.5) | targetSdk 35, NDK 26.1, proguard нет, Gradle без wrapper (9.7.1 системный) | §3: NDK `28.2.13676358`, `cargo-ndk@4.1.2`, wrapper 8.11.1 + setup-gradle v6, proguard, targetSdk 36; android-check в ci.yml | **M19b** (android-check — M18) |
| 17 | Схема версии БД (п.6) | вне CI | — | M19 |
| 18 | Reproducible builds (для 1.0): `trim-paths`, `SOURCE_DATE_EPOCH`, пин toolchain, независимая проверка | ничего | базовый набор в release.yml v2 (§8.2) — M23; docker-скрипт `scripts/reproduce.sh` + независимая пересборка — 1.0 | **M23** (база) / **1.0** |
| 19 | cargo-vet с импортом Mozilla/Google (1.0) | нет | после беты | 1.0 |
| 20 | OS-матрица тестов, coverage, fuzz в CI (§8.3 аудита, M19a п.7) | только ubuntu; fuzz-крейт не компилируется | `test` на ubuntu/windows/macos; `fuzz-build` nightly; `cargo llvm-cov` порог для aira-core | **M18** (матрица не блокирующая) / **M19a** (fuzz) / **M23** (блокирующая + coverage) |
| 21 | wasm32 guard (M14.0, аудит §7 п.7) | нет | job `wasm32`: `cargo check -p aira-core --target wasm32-unknown-unknown --locked`, `continue-on-error: true` до M14.0 | **M18** |
| 22 | Scorecard / harden-runner (опционально) | нет | `scorecard.yml` (weekly + push main) с badge; `harden-runner` `egress-policy: audit` в release jobs → `block` с allowlist к 1.0 | **M23** / 1.0 |
| 23 | Linux-совместимость AppImage/tar.gz (glibc) | сборка на 24.04, INSTALL обещает 22.04+ | `container: ubuntu:22.04` для Linux-таргета; проверка `GLIBC_` в CI; минимальная glibc в release notes | **M23** (желательно к v0.4.0) |
| 24 | `aira-relay` (M21) в релизе | крейта нет | таргеты `x86_64-unknown-linux-gnu` + `aarch64-unknown-linux-gnu` (+ musl для docker), контейнер `ghcr.io/kamiletar/aira-relay` с attestation и SBOM, systemd unit в tar.gz | **M21** |

## 8. Наброски (в репозиторий не записаны)

### 8.1 `rust-toolchain.toml` (корень) — единый источник toolchain

```toml
# Один toolchain для dev/CI/release. Bump — осознанным коммитом chore(config): rust 1.x.y
# (проверить clippy pedantic-lint'ы). MSRV задаётся отдельно: Cargo.toml [workspace.package] rust-version.
[toolchain]
channel = "1.98.1"          # текущий stable на раннерах (2026-09-24); после M18 minimum 1.91
components = ["rustfmt", "clippy"]
profile = "minimal"
targets = ["wasm32-unknown-unknown"]   # для job wasm32 (M14.0)
```

`rustup` (1.28.1+; на раннерах 1.29.1) сам ставит toolchain из файла при первом `cargo`/`rustup toolchain install`, поэтому `dtolnay/rust-toolchain` становится не нужен; если оставлять — `dtolnay/rust-toolchain@02cb101ec7c40f2c49e1d9714d64511d8e1b74de` с `with: toolchain: <из файла>`.

### 8.2 `ci.yml` v2

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: "23 4 * * *"            # ежедневный audit: новые advisories всплывают без push
  workflow_dispatch:

permissions: {}                      # least privilege: каждый job запрашивает своё

concurrency:
  group: ci-${{ github.ref }}
  cancel-in-progress: ${{ github.event_name == 'pull_request' }}

env:
  CARGO_TERM_COLOR: always
  CARGO_INCREMENTAL: 0
  RUSTFLAGS: "-D warnings"
  APT_DEPS: libgtk-3-dev libxdo-dev libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev

jobs:
  fmt:
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    permissions: { contents: read }
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with: { persist-credentials: false }
      - run: rustup toolchain install            # читает rust-toolchain.toml
      - run: cargo fmt --all -- --check

  clippy:
    runs-on: ubuntu-24.04
    timeout-minutes: 30
    permissions: { contents: read }
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with: { persist-credentials: false }
      - run: rustup toolchain install
      - uses: Swatinem/rust-cache@6323deb102c322ba6fcbdcafc7e3dddab59af2b6 # v2.9.2
        with: { save-if: "${{ github.ref == 'refs/heads/main' }}" }
      - run: sudo apt-get update && sudo apt-get install -y $APT_DEPS
      # --all-features: fips/compat-test (cmake есть на раннере) + DPI-фичи до их удаления (M19b)
      - run: cargo clippy --workspace --all-targets --all-features --locked -- -D warnings

  clippy-next:                       # раннее предупреждение о lint'ах следующего stable; не блокирует
    runs-on: ubuntu-24.04
    timeout-minutes: 30
    continue-on-error: true
    permissions: { contents: read }
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with: { persist-credentials: false }
      - run: rustup toolchain install beta --profile minimal --component clippy
      - run: sudo apt-get update && sudo apt-get install -y $APT_DEPS
      - run: cargo +beta clippy --workspace --all-targets --locked -- -D warnings

  test:
    strategy:
      fail-fast: false
      matrix:
        include:
          - { os: ubuntu-24.04,  features: "--all-features" }   # 65 feature-gated тестов (test-coverage §6)
          - { os: windows-2025,  features: "" }                  # без fips (aws-lc-sys: cmake/nasm) до проверки
          - { os: macos-15,      features: "" }                  # keychain-тесты M19b п.1
    runs-on: ${{ matrix.os }}
    timeout-minutes: 45
    permissions: { contents: read }
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with: { persist-credentials: false }
      - run: rustup toolchain install
      - uses: Swatinem/rust-cache@6323deb102c322ba6fcbdcafc7e3dddab59af2b6 # v2.9.2
        with: { save-if: "${{ github.ref == 'refs/heads/main' }}" }
      - if: runner.os == 'Linux'
        run: sudo apt-get update && sudo apt-get install -y $APT_DEPS
      - run: cargo test --workspace --locked ${{ matrix.features }}

  msrv:
    runs-on: ubuntu-24.04
    timeout-minutes: 30
    permissions: { contents: read }
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with: { persist-credentials: false }
      - id: msrv
        run: echo "v=$(sed -n 's/^rust-version *= *"\(.*\)"/\1/p' Cargo.toml)" >> "$GITHUB_OUTPUT"
      - run: rustup toolchain install ${{ steps.msrv.outputs.v }} --profile minimal
      - run: sudo apt-get update && sudo apt-get install -y $APT_DEPS
      - run: cargo +${{ steps.msrv.outputs.v }} check --workspace --all-targets --locked

  wasm32:                            # guard для M14.0; до готовности ядра — не блокирует
    runs-on: ubuntu-24.04
    timeout-minutes: 20
    continue-on-error: true
    permissions: { contents: read }
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with: { persist-credentials: false }
      - run: rustup toolchain install
      - run: cargo check -p aira-core --target wasm32-unknown-unknown --locked

  android-check:                     # ловит поломку cdylib под Android до тега (release.yml needs android)
    runs-on: ubuntu-24.04
    timeout-minutes: 30
    permissions: { contents: read }
    env: { ANDROID_NDK_HOME: /usr/local/lib/android/sdk/ndk/28.2.13676358 }   # предустановлен в образе
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with: { persist-credentials: false }
      - run: rustup toolchain install && rustup target add aarch64-linux-android
      - uses: taiki-e/install-action@7623a79cdfecb99d681017af368ca353d9f49bb5 # v2.87.19
        with: { tool: cargo-ndk@4.1.2 }
      - uses: Swatinem/rust-cache@6323deb102c322ba6fcbdcafc7e3dddab59af2b6 # v2.9.2
        with: { save-if: "${{ github.ref == 'refs/heads/main' }}" }
      - run: cargo ndk -t arm64-v8a --platform 26 -- check -p aira-ffi --locked

  audit:
    runs-on: ubuntu-24.04
    timeout-minutes: 15
    permissions: { contents: read }
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with: { persist-credentials: false }
      - uses: EmbarkStudios/cargo-deny-action@3c6349835b2b7b196a839186cb8b78e02f7b5f25 # v2.1.1
        with: { command: check, arguments: --all-features }
      - uses: taiki-e/install-action@7623a79cdfecb99d681017af368ca353d9f49bb5 # v2.87.19
        with: { tool: cargo-audit@0.22.2 }
      - run: cargo audit --deny yanked          # unsound/unmaintained — warning, не блокируют

  fuzz-build:                        # по test-coverage §3.3; после починки fuzz/Cargo.toml (M18 п.7)
    runs-on: ubuntu-24.04
    timeout-minutes: 30
    permissions: { contents: read }
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with: { persist-credentials: false }
      - run: rustup toolchain install nightly --profile minimal
      - uses: taiki-e/install-action@7623a79cdfecb99d681017af368ca353d9f49bb5 # v2.87.19
        with: { tool: cargo-fuzz@0.13.2 }
      - run: cd crates/aira-core/fuzz && cargo +nightly fuzz build
```

### 8.3 `release.yml` v2 (desktop; Android — отдельный job с environment)

```yaml
name: Release

on:
  push:
    tags: ["v*"]

permissions: {}

env:
  CARGO_TERM_COLOR: always
  CARGO_INCREMENTAL: 0
  APT_DEPS: libgtk-3-dev libxdo-dev libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev

jobs:
  verify:                            # тег ↔ версии ↔ main ↔ lock (H8)
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    permissions: { contents: read }
    outputs:
      version: ${{ steps.v.outputs.version }}
      prerelease: ${{ steps.v.outputs.prerelease }}
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with: { persist-credentials: false, fetch-depth: 0 }
      - id: v
        env: { TAG: "${{ github.ref_name }}" }
        run: |
          set -euo pipefail
          VERSION="${TAG#v}"
          CARGO_V=$(sed -n 's/^version *= *"\(.*\)"/\1/p' Cargo.toml | head -1)
          GRADLE_V=$(sed -n 's/.*versionName *= *"\(.*\)".*/\1/p' mobile/android/app/build.gradle.kts)
          [ "$VERSION" = "$CARGO_V" ]  || { echo "tag $TAG != Cargo.toml $CARGO_V"; exit 1; }
          [ "$VERSION" = "$GRADLE_V" ] || { echo "tag $TAG != versionName $GRADLE_V"; exit 1; }
          git merge-base --is-ancestor "$GITHUB_SHA" origin/main || { echo "tag not on main"; exit 1; }
          [ "$(git cat-file -t "$TAG")" = "tag" ] || { echo "tag must be annotated"; exit 1; }
          grep -q "^## \[$VERSION\]" CHANGELOG.md || { echo "no CHANGELOG entry"; exit 1; }
          cargo metadata --locked --format-version 1 >/dev/null
          echo "version=$VERSION" >> "$GITHUB_OUTPUT"
          case "$VERSION" in *-*) echo "prerelease=true" ;; *) echo "prerelease=false" ;; esac >> "$GITHUB_OUTPUT"

  build:
    needs: verify
    strategy:
      fail-fast: false
      matrix:
        include:
          - { target: x86_64-unknown-linux-gnu, runner: ubuntu-24.04, container: "ubuntu:22.04" }  # glibc 2.35 baseline
          - { target: aarch64-apple-darwin,     runner: macos-15 }
          - { target: x86_64-apple-darwin,      runner: macos-15 }
          - { target: x86_64-pc-windows-msvc,   runner: windows-2025 }
    runs-on: ${{ matrix.runner }}
    container: ${{ matrix.container }}   # пусто = без контейнера
    timeout-minutes: 90
    permissions: { contents: read }
    env:
      MACOSX_DEPLOYMENT_TARGET: "11.0"
      RUSTFLAGS: "--remap-path-prefix=${{ github.workspace }}=/build"
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with: { persist-credentials: false }
      - run: rustup toolchain install && rustup target add ${{ matrix.target }}
      - uses: taiki-e/install-action@7623a79cdfecb99d681017af368ca353d9f49bb5 # v2.87.19
        with: { tool: cargo-auditable@0.7.6,cargo-cyclonedx@0.5.9 }
      - name: Reproducibility env
        shell: bash
        run: echo "SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)" >> "$GITHUB_ENV"
      # без Swatinem/rust-cache: релиз собирается с нуля
      - if: runner.os == 'Linux'
        run: apt-get update && apt-get install -y build-essential pkg-config $APT_DEPS libfuse2 file  # в контейнере без sudo
      - name: Build (auditable)
        shell: bash
        run: cargo auditable build --release --locked --target ${{ matrix.target }} -p aira-cli -p aira-daemon -p aira-gui
      - name: SBOM
        shell: bash
        run: cargo cyclonedx --format json --describe binaries --target ${{ matrix.target }} -p aira-daemon -p aira-gui -p aira-cli
      - name: Package + installers      # tar.gz/zip + LICENSE-* README CHANGELOG внутри; MSI/DMG/AppImage как сейчас,
        shell: bash                     # но linuxdeploy — фиксированный тег + sha256sum -c, plugin из packaging/linux/
        run: ./scripts/package.sh "${{ matrix.target }}" "${{ needs.verify.outputs.version }}"
      - name: Sanity                    # артефакты на месте; glibc baseline (Linux)
        shell: bash
        run: ./scripts/check-artifacts.sh "${{ matrix.target }}" "${{ needs.verify.outputs.version }}"
      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: aira-${{ matrix.target }}
          path: dist/
          if-no-files-found: error

  android:                             # включается решением владельца (§16.1 п.6); до подписи — не запускать
    needs: verify
    if: vars.ANDROID_RELEASE == 'true'
    runs-on: ubuntu-24.04
    timeout-minutes: 60
    environment: android-release       # required reviewer; секреты только здесь
    permissions: { contents: read }
    env:
      ANDROID_NDK_HOME: /usr/local/lib/android/sdk/ndk/28.2.13676358
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with: { persist-credentials: false }
      - run: rustup toolchain install && rustup target add aarch64-linux-android x86_64-linux-android
      - uses: taiki-e/install-action@7623a79cdfecb99d681017af368ca353d9f49bb5 # v2.87.19
        with: { tool: cargo-ndk@4.1.2 }
      - run: cargo ndk -t arm64-v8a -t x86_64 --platform 26 -o mobile/android/app/src/main/jniLibs -- build -p aira-ffi --release --locked
      - run: cargo build -p aira-ffi --locked && cargo run -p aira-ffi --bin uniffi-bindgen --locked -- generate --library target/debug/libaira_ffi.so --language kotlin --out-dir mobile/android/app/src/main/kotlin/
      - uses: actions/setup-java@de7274f081f381c8f8158605e0321c36c376e2e6 # v6.0.1
        with: { java-version: "17", distribution: temurin }
      - uses: gradle/actions/setup-gradle@9c971963bec38e04b3d30dcc455b5382be2fdbfb # v6.3.0 (валидирует gradle-wrapper.jar)
      - name: Keystore
        env: { KS_B64: "${{ secrets.ANDROID_KEYSTORE_B64 }}" }
        run: echo "$KS_B64" | base64 -d > "$RUNNER_TEMP/release.jks"
      - name: Build signed APK
        working-directory: mobile/android
        env:
          AIRA_KEYSTORE: ${{ runner.temp }}/release.jks
          AIRA_KEYSTORE_PASSWORD: ${{ secrets.ANDROID_KEYSTORE_PASSWORD }}
          AIRA_KEY_ALIAS: ${{ secrets.ANDROID_KEY_ALIAS }}
          AIRA_KEY_PASSWORD: ${{ secrets.ANDROID_KEY_PASSWORD }}
        run: ./gradlew --no-daemon assembleRelease       # signingConfigs.release читает AIRA_* из env
      - name: Verify signature
        run: |
          APK=mobile/android/app/build/outputs/apk/release/app-release.apk
          "$ANDROID_HOME/build-tools/36.0.0/apksigner" verify --verbose --print-certs "$APK" | tee -a "$GITHUB_STEP_SUMMARY"
          mkdir -p dist && cp "$APK" "dist/aira-${{ needs.verify.outputs.version }}-android.apk"
      - run: shred -u "$RUNNER_TEMP/release.jks"
        if: always()
      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with: { name: aira-android, path: dist/, if-no-files-found: error }

  release:
    needs: [verify, build, android]
    if: always() && needs.build.result == 'success' && (needs.android.result == 'success' || needs.android.result == 'skipped')
    runs-on: ubuntu-24.04
    timeout-minutes: 20
    environment: release               # required reviewer = ручной approve перед публикацией
    permissions:
      contents: write
      id-token: write
      attestations: write
      artifact-metadata: write
    steps:
      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1
        with: { path: dist, merge-multiple: true }
      - name: SHA256SUMS
        working-directory: dist
        run: sha256sum $(ls | grep -v -E '\.sha256$|\.cdx\.json$') > SHA256SUMS && cat SHA256SUMS
      - uses: actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8 # v4.2.2
        with: { subject-checksums: dist/SHA256SUMS }
      - uses: actions/attest-sbom@c604332985a26aa8cf1bdc465b92731239ec6b9e # v4.1.0
        with:
          subject-path: dist/aira-*-x86_64-unknown-linux-gnu.tar.gz   # по одному вызову на пару бинарь/SBOM
          sbom-path: dist/aira-*-x86_64-unknown-linux-gnu.cdx.json
      # опционально: SHA256SUMS.minisig подписывается владельцем локально перед publish (draft)
      - uses: softprops/action-gh-release@efb35369e0ad2afab669f228072c1b0d510eae64 # v3.0.3
        with:
          draft: true                                        # публикует владелец после проверки
          prerelease: ${{ needs.verify.outputs.prerelease }}
          make_latest: ${{ needs.verify.outputs.prerelease == 'false' }}
          generate_release_notes: true
          body_path: RELEASE_NOTES.md                        # из CHANGELOG-секции (шаг verify может извлечь)
          files: |
            dist/*
```

Замечания к наброску: `scripts/package.sh`/`check-artifacts.sh` — вынос существующих inline-шагов (`release.yml:59-138`) с добавлением проверок `test -f` и `objdump -T … GLIBC_`; для Windows `cargo wix … --install-version "${VERSION%%-*}"`; при `container:` на Linux `dtolnay`/`rustup` ставятся внутри контейнера, `APPIMAGE_EXTRACT_AND_RUN=1` для linuxdeploy; `actions/attest-sbom` — по одному вызову на артефакт (лимит — один `sbom-path` на вызов); `harden-runner` (`e14015d5…`) первым шагом каждого job с `egress-policy: audit` — после набора allowlist перевести в `block`.

### 8.4 `.github/dependabot.yml`

```yaml
version: 2
updates:
  - package-ecosystem: github-actions
    directory: /
    schedule: { interval: weekly, day: monday }
    labels: [deps, ci]
  - package-ecosystem: cargo
    directory: /
    schedule: { interval: weekly, day: monday }
    open-pull-requests-limit: 5
    groups:
      minor-and-patch:
        update-types: [minor, patch]
    ignore:
      - dependency-name: "iroh*"          # мажоры iroh — вручную (M18/M20)
        update-types: [version-update:semver-major]
  - package-ecosystem: gradle
    directory: /mobile/android
    schedule: { interval: weekly, day: monday }
```

(Dependabot **alerts** и security updates включаются в Settings → Security — вопрос владельцу; без alerts GHSA-only-дефекты вроде ml-dsa `use_hint` невидимы.)

### 8.5 `scorecard.yml` (M23, опционально)

```yaml
name: Scorecard
on:
  schedule: [{ cron: "30 5 * * 1" }]
  push: { branches: [main] }
permissions: read-all
jobs:
  analysis:
    runs-on: ubuntu-24.04
    permissions: { security-events: write, id-token: write, contents: read, actions: read }
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with: { persist-credentials: false }
      - uses: ossf/scorecard-action@2d1146689b8cda280b9bc96326124645441f03bc # v2.4.4
        with: { results_file: results.sarif, results_format: sarif, publish_results: true }
      - uses: github/codeql-action/upload-sarif@<sha>   # пин при внедрении
        with: { sarif_file: results.sarif }
```

## 9. Задачи по милстоунам, правки спеки, вопросы владельцу

### 9.1 Задачи (что именно и где)

**M18 — CI-гварды (0,5–1 день внутри M18; всё без зависимостей от кода iroh):**
1. `rust-toolchain.toml` (§8.1); `rust-version = "1.91"` + `rust-version.workspace = true` во всех крейтах; починить clippy 1.98: `crates/aira-net/src/discovery.rs:155` (`as_chunks::<3>()`), `relay.rs:112` (`Duration::from_hours(168)` или `#[allow(clippy::duration_suboptimal_units)]`, если MSRV не позволяет).
2. `chore(deps)`: `cargo update -p rustls -p rustls-webpki -p h2 -p crossbeam-epoch -p webbrowser -p quinn-proto -p anyhow -p memmap2` (снимает 6 vuln-записей до миграции iroh); yanked — `cargo update -p spin`; остальное — с iroh 1.1; решение по quick-xml (§4.5).
3. `deny.toml`/`.cargo/audit.toml` по §4.5; `publish = false` ×8.
4. `ci.yml` v2 (§8.2) минимум: `--locked`, SHA-пины, `permissions`, `persist-credentials: false`, `concurrency`, `timeout-minutes`, `schedule` для audit, `msrv`, `wasm32` (non-blocking), `android-check`, cargo-deny-action + install-action; `push: [main]`, `pull_request` без `dev`.
5. `release.yml` минимум для bridge-релиза v0.4.0: `permissions: {}` + per-job, `persist-credentials: false`, `--locked`, linuxdeploy по тегу + sha256, `linuxdeploy-plugin-gtk.sh` в `packaging/linux/`, `cargo-ndk@4.1.2 --locked`, job `verify` (тег ↔ версии), `if-no-files-found: error`, **APK убрать из assets** (или оставить с пометкой «unsigned, не устанавливается» — решение владельца), `prerelease`-логика для `-`-версий.
6. `LICENSE-MIT`, `LICENSE-APACHE`, `README.md`-заглушка — **до** `git tag v0.4.0`; `.github/dependabot.yml` (§8.4).
7. Владелец в Settings: Workflow permissions → read; Dependabot alerts/security updates; secret scanning + push protection; private vulnerability reporting; ruleset `main` (required checks fmt/clippy/test/audit/msrv, no force-push) и `v*` (только владелец).

**M19a:** fuzz-job (`fuzz-build`, test-coverage §3.3) после починки `crates/aira-core/fuzz/Cargo.toml`.

**M19b — Android-пакет (CI-часть):** environment `android-release` + 4 секрета; `signingConfigs.release` из env (`AIRA_KEYSTORE*`); `apksigner verify --print-certs` + отпечаток в `docs/ANDROID_SIGNING.md`; NDK `28.2.13676358` (`ANDROID_NDK_HOME` из образа, без `setup-android`), `cargo-ndk@4.1.2`, `-o jniLibs`; Gradle wrapper 8.11.1 закоммитить + `setup-gradle@v6`; `proguard-rules.pro`; `targetSdk 36`; `versionCode` с pre-release; `.gitignore` `*.jks *.keystore`; `android.yml`: снять `paths`, удалить `rust-tests`, `permissions`; decoupling android от desktop-релиза; `[graph] all-features = true` после удаления транспортов; `--all-features` в test/clippy на Linux.

**M21:** `aira-relay` в матрице (`x86_64`/`aarch64-unknown-linux-gnu`, musl для контейнера), контейнер `ghcr.io/kamiletar/aira-relay` (`docker/build-push-action` по SHA, `provenance: true`, `sbom: true`, `packages: write`), tar.gz с systemd unit; SBOM/attestation как для desktop.

**M23 — Release hardening (CI-часть, §7 п.5–15, 18, 22–23):** `release.yml` v2 целиком (§8.3): контейнер `ubuntu:22.04`, пин раннеров, без кэша, `SOURCE_DATE_EPOCH`/`remap-path-prefix`, `cargo auditable`, `cargo cyclonedx`, `SHA256SUMS` + attest-build-provenance + attest-sbom, `environment: release`, `draft`/`prerelease`/`make_latest`, `check-artifacts.sh`, LICENSE/README/CHANGELOG в архивах, `MACOSX_DEPLOYMENT_TARGET`, `--install-version` для MSI, `$env:GITHUB_REF_NAME`; подпись Windows (SignPath) / macOS (codesign+notarytool) по решению владельца; minisign `SHA256SUMS.minisig`; `scorecard.yml` + `harden-runner audit`; документы (SECURITY, CHANGELOG, CONTRIBUTING, CODEOWNERS, шаблоны, INSTALL.md с `gh attestation verify`, Sequoia, glibc); ОС-матрица тестов — блокирующая; `cargo llvm-cov`.

**1.0:** reusable release workflow (SLSA L3) или slsa-github-generator; `scripts/reproduce.sh` (docker, пин toolchain/CARGO_HOME) + независимая пересборка; `cargo vet` с импортом mozilla/google; `harden-runner block`; signed commits/tags; winget/Homebrew tap после подписи.

### 9.2 Правки `spec/18-milestones.md` (формулировки для внесения)

- **§16.1 (после списка решений):** добавить решение 9 — «Где CI-инфраструктура релиза: внутри M23 (по спеке) или отдельным параллельным треком «M22-infra» (подпись/attestations/SBOM не зависят от M19–M21 и могут идти с M19b)».
- **M18 п.8** заменить на: «CI: `rust-toolchain.toml` (stable запинен), `--locked` во всех cargo-вызовах, SHA-пины actions + `.github/dependabot.yml`, `permissions: {}` + per-job, `persist-credentials: false`, `schedule` для audit, job `msrv` (1.91), `wasm32` (non-blocking), `android-check`; `cargo update` для rustls/rustls-webpki/h2/crossbeam-epoch/webbrowser/quinn-proto до миграции; `cargo audit` должен потерять quinn-proto/hickory-proto/ml-dsa **и** остальные из 18 (quick-xml — решение: egui-bump или временный ignore до 2026-12-31); починить clippy 1.98 (`discovery.rs:155`, `relay.rs:112`); удалить из ignore RUSTSEC-2025-0144 и 9 unused-ID, `unmaintained = "workspace"`, `yanked = "deny"`, `publish = false` + `allow-wildcard-paths`; linuxdeploy по тегу + sha256, plugin-скрипт вендорить; job `verify` тег↔версии; `if-no-files-found: error`.»
- **M18 п.9 (документы):** добавить «`LICENSE-MIT` + `LICENSE-APACHE` + `README.md` (заглушка) — обязательно до тега v0.4.0; APK в assets v0.4.0 не публиковать (или пометить unsigned)».
- **M19b п.10:** дополнить конкретикой §2.6 (environment `android-release`, секреты `ANDROID_KEYSTORE_B64/PASSWORD`, `ANDROID_KEY_ALIAS/PASSWORD`, `apksigner verify --print-certs`, отпечаток в `docs/ANDROID_SIGNING.md`, бэкап keystore ×2, ключ до регистрации developer verification).
- **M19b п.11:** «NDK r28» → «`28.2.13676358` из образа ubuntu-24.04 (`ANDROID_NDK_HOME`, без `setup-android`), `cargo-ndk@4.1.2 --locked`, Gradle wrapper 8.11.1 закоммитить (`gradlew`, `gradle-wrapper.jar`) + `gradle/actions/setup-gradle@v6`, `./gradlew`; `android.yml` без `paths`-фильтра; в `release.yml` Android не блокирует desktop; `versionCode` с pre-release-номером».
- **M21 п.1:** добавить «`aira-relay` в матрицу release.yml: linux x86_64 + aarch64 tar.gz с systemd unit, контейнер `ghcr.io/kamiletar/aira-relay` с provenance/SBOM».
- **M23 п.1:** добавить «ОС-матрица тестов (ubuntu/windows/macos) блокирующая; coverage-порог aira-core».
- **M23 п.4** заменить на: «`release.yml` v2: `SHA256SUMS` + `actions/attest-build-provenance@v4` (`subject-checksums`; permissions `id-token`/`attestations`/`artifact-metadata: write`) — это **SLSA Build L2** (L3 требует reusable workflow — 1.0); `cargo auditable build`; SBOM `cargo cyclonedx --describe binaries` + `actions/attest-sbom`; сборка Linux в контейнере ubuntu:22.04 (glibc 2.35), раннеры запинены (`ubuntu-24.04`/`macos-15`/`windows-2025`), без rust-cache, `SOURCE_DATE_EPOCH` + `--remap-path-prefix`; `environment: release` с approve; `draft`/`prerelease`/`make_latest`; опционально `SHA256SUMS.minisig` (ключ владельца, тот же для Tauri updater M17); `scorecard.yml`, `harden-runner`; INSTALL.md — `gh attestation verify`, обход Gatekeeper через System Settings, минимальная glibc».
- **M23 п.3:** добавить `CONTRIBUTING.md`, `CODEOWNERS`, шаблоны issue/PR; п.7 — «tag ruleset `v*`, теги не переставлять».
- **«Для 1.0»:** добавить «reusable release-workflow (SLSA L3)», «`harden-runner` block», «signed tags».

### 9.3 Вопросы владельцу

1. **Настройки репозитория** (не видны из клона): дефолтные права `GITHUB_TOKEN` (read?), список разрешённых actions, approval для fork-PR, ruleset/branch protection на `main` (required checks?), tag protection `v*`, Dependabot alerts/security updates, secret scanning + push protection, private vulnerability reporting, 2FA.
2. **Бюджет и заявки** (спека п.7–8 + новое): Apple Developer $99 (notarization); SignPath Foundation (нужны LICENSE + README + релизы — B3 первым); Android developer verification $25 + ID — **ключ подписи должен существовать до регистрации**; кто хранит keystore и minisign-ключ (офлайн, бэкап ×2)?
3. **Android в v0.4.0 и бете:** убрать APK из assets до подписи (рекомендация) или публиковать unsigned с пометкой?
4. **quick-xml ×4:** временный ignore со сроком (рекомендация для bridge-релиза) или блокировать M18 на bump egui 0.29 → 0.36?
5. **Windows/macOS-раннеры на каждый PR** (~+15–25 мин, бесплатно для public repo, но очередь) или только на `main`/тегах?
6. **Linux baseline:** контейнер `ubuntu:22.04` (glibc 2.35) — или объявить «Ubuntu 24.04+/glibc ≥ 2.39» и поправить INSTALL.md?
7. **Нумерация:** CI-инфраструктура релиза в M23 (как в спеке) или отдельный трек «M22-infra» параллельно M19b (как в задании фазы 3)?
8. **SLSA:** L2 для беты (нативные attestations) — достаточно? L3 (reusable workflow) — к 1.0?
9. **`environment: release` с ручным approve** перед публикацией каждого релиза — приемлемо для соло-владельца (даёт паузу на проверку draft и подпись `SHA256SUMS.minisig`)?
10. **Ветка `dev`:** завести (как в `.claude/rules/git.md`) или убрать из правил и CI?

### 9.4 О расхождении «M22» в задании и спеке

Задание фазы 3 описывает «M22 релизная инфраструктура (подпись, CI, SBOM)», в `spec/18-milestones.md:720-739` M22 = Anti-abuse, а всё перечисленное — M23 п.2/п.4 (`:741-759`). Отчёт раскладывает по спеке (M18 → M19b → M21 → M23), но подчёркивает: у подписи/attestations/SBOM/verify-job нет зависимостей от кода M19–M21 и от сети; их можно и стоит делать параллельно с M19b (нужны только решения владельца по бюджету и секретам), чтобы к M23 остались только документы и финальная проверка. Если владелец предпочтёт отдельный номер — «M22-infra» между M21 и M22 без изменения содержания.

## 10. Не проверено

- **Локально не запускались** `cargo deny check`, `cargo audit`, `cargo build/test`, `cargo ndk`, `gradle` (инструменты/зависимости не установлены по условиям задания): результат `licenses`/`bans` на текущем lock, реальная сборка `--all-features` на Windows/macOS (aws-lc-sys: cmake/nasm; reqwest `cdn` → openssl-sys), поведение `cargo wix` с `0.5.0-beta.1`, работа `cargo auditable` со `strip = true` и через `cargo ndk`.
- **Что реально в бинарях:** попадают ли quinn/reqwest/openssl/hickory в релизные бинари (lock ≠ бинарь) — ответит `cargo audit bin` после cargo-auditable или `ldd`/`otool -L` на релизных файлах v0.3.5 (не скачивал).
- **Совместимость AGP 8.7.0 ↔ Gradle 9.7.1** (образ ubuntu-24.04) и сам факт, что Android-сборка сегодня проходит (последний прогон 2026-04-10). Не проверял, что делает AGP при отсутствии `proguard-rules.pro` (ошибка или игнор) — релиз v0.3.5 APK собрался, значит игнор или файл был; clients-audit уже фиксирует отсутствие файла.
- **Версии glibc** образов (24.04 → 2.39, 22.04 → 2.35) — по памяти; проверка — `ldd --version` в CI.
- **SLSA L2 vs L3** для нативных attestations — по документации GitHub из `release-2026-requirements.md` §20; `docs.github.com` и `github.blog` недоступны через прокси.
- **hickory-resolver 0.26 в графе iroh 1.1**, новый `netdev`/quick-xml в iroh 1.1, quick-xml в egui 0.36/winit/rfd — не резолвил (зависимости не скачаны); источник — `facts-crates.md`.
- **CVE-2026-24850 для ml-dsa** (спека M18) — не искал; проверен только GHSA-h37v-hp6w-2pp8.
- **Лицензионное выражение `aws-lc-sys`** (компонент OpenSSL) и `ring 0.17.14` (`Apache-2.0 AND ISC`?) — по памяти; проверится первым `cargo deny check` с `all-features`.
- **Настройки репозитория GitHub** (permissions, rulesets, alerts) — недоступны без admin-API; вопросы в §9.3.
- **cargo-ndk и 16 KB:** README cargo-ndk 16 KB не упоминает; опора — NDK r28 выравнивает по умолчанию (§6.6.4, requirements §33); проверка в CI: `readelf -lW libaira_ffi.so | grep LOAD` (Align 0x4000).
- **`rustup toolchain install` без аргументов** читает `rust-toolchain.toml` (rustup ≥ 1.28) — по памяти о changelog rustup; альтернатива в §8.1 — `dtolnay/rust-toolchain` по SHA.
- Даты retirement `ubuntu-22.04`/`windows-2022`/`macos-14` — README runner-images дат не содержит.
- `Duration::from_hours/from_mins` в MSRV 1.91 — не проверял; при сомнении — `#[allow]`.
- SHA-пины в §6.1 сняты `git ls-remote` 2026-09-24 — перед внесением в yml перепроверить (`git ls-remote --tags https://github.com/<owner>/<repo> <tag>`), Dependabot дальше поддержит.
