# Release Pipeline

> Аудит CI/supply chain (24.09.2026): `.claude/docs/audit-2026-09/ci-supply-chain-audit.md` (наброски `ci.yml` v2 / `release.yml` v2 — §8 отчёта).
> Решения владельца: только `main` + PR, теги через CI-job `verify`; SignPath + minisign (без Apple $99 и Android verification);
> Linux-сборки в контейнере ubuntu:22.04; CI-гварды в M18, подпись/attestations/SBOM — трек «M22-infra».

## Состояние на 24.09.2026

- CI на `main` **красный с 10.04.2026**: `cargo audit` — 18 advisories (6 закрываются `cargo update`, 4 — iroh 1.x, 8 — quick-xml через egui/rfd/notify-rust → ignore со сроком до M19b), clippy — stable 1.98 без `rust-toolchain.toml`.
- Нет `LICENSE-MIT`/`LICENSE-APACHE` и `README.md` при `license = "MIT OR Apache-2.0"` — до тега v0.4.0 (условие SignPath).
- `release.yml`: `contents: write` всем jobs при persisted-токене и исполнение непроверенного `linuxdeploy` (`continuous` + plugin из `master`); 0 SHA-пинов; нет `--locked`, `permissions`, Dependabot, `SHA256SUMS`, attestations, SBOM.
- Android: APK не подписан; `android.yml` не бегал с 10.04 (`paths`), Gradle-обёртки нет, NDK 26.1; в бете — preview без APK.

## Workflows (текущие)

### CI (`.github/workflows/ci.yml`)

Триггеры: push в `main` (`dev` — убрать, ветки нет) и PR. Jobs: `fmt`, `clippy`, `test` (`--workspace` без `--all-features`), `audit` (`cargo audit` + `cargo deny check`, собираются каждый прогон ~7,5 мин).

Linux jobs ставят системные зависимости egui: `libgtk-3-dev`, `libxdo-dev`, `libxcb-*`.

### Release (`.github/workflows/release.yml`)

Триггер: тег `v*`. Матрица desktop: linux x86_64 (`ubuntu-24.04` → glibc 2.39, **не запустится на 22.04** — перейти на контейнер ubuntu:22.04), macOS aarch64/x86_64, windows x86_64; архивы `aira-{VERSION}-{TARGET}.{tar.gz|zip}` с `.sha256`-сайдкарами. Android-job зависит от desktop-релиза (decoupling — M19b).

### Android CI (`.github/workflows/android.yml`)

Отдельный workflow для debug-сборок на изменения FFI/mobile.

## Целевой pipeline (M18 + трек M22-infra)

1. **M18 (гварды):** `rust-toolchain.toml`, `--locked` везде, SHA-пины actions + `dependabot.yml`, `permissions: {}` + per-job, `persist-credentials: false`, schedule-audit, jobs `msrv` (1.91) / `wasm32` (non-blocking) / `android-check`, `cargo update` для 6 advisories, чистка `deny.toml`/`.cargo/audit.toml` + `publish = false` + `[graph]`, linuxdeploy по тегу + вендоринг plugin, job `verify` (тег ↔ `Cargo.toml` ↔ CI зелёный на `main`), `if-no-files-found: error`, LICENSE + README.
2. **M22-infra:** `SHA256SUMS` + `actions/attest-build-provenance` (SLSA L2; L3 = reusable workflow к 1.0), `cargo auditable`, SBOM (`cargo cyclonedx` + `attest-sbom`), minisign-подпись assets, SignPath Foundation для Windows, контейнер ubuntu:22.04, пин раннеров (`ubuntu-24.04`/`macos-15`/`windows-2025`), `MACOSX_DEPLOYMENT_TARGET=11.0`, без rust-cache в релизе, `SOURCE_DATE_EPOCH`/remap, `environment: release` с ручным approve, `draft`/`prerelease`/`make_latest` (канал `0.5.0-beta.N`), scorecard/harden-runner.
3. **M21:** `aira-relay` в матрице (musl x86_64/aarch64) + Docker-образ ghcr.io с provenance/SBOM.
4. **macOS без notarization** (решение владельца) — честно в INSTALL.md (запуск через System Settings).

## How to Release

```bash
./scripts/release.sh <version>
```

Скрипт обновляет версию в workspace `Cargo.toml` и Android, коммитит `chore: release vX.Y.Z`, ставит тег и пушит. **После M18** тег ставится только на зелёный `main` через PR + job `verify`; тег не переставляется (v0.3.5 переставлялся — больше нельзя).

## Website Integration

Сайт `aira.letar.best` (репозиторий `lena/apps/aira-web`) берёт последний релиз из GitHub Releases API (ISR 1 ч):
`src/lib/github.ts`, `src/app/_components/hero.tsx`, `src/app/_components/download-section.tsx`. Pre-release `0.5.0-beta.N` не должен становиться `latest` для сайта.

## Archive Naming Convention

```
aira-{VERSION}-{TARGET}.{ext}
aira-{VERSION}-{TARGET}.{ext}.sha256   # + общий SHA256SUMS с M22-infra
```

## Version Scheme

- `0.1.x` — M1–M5 (CLI MVP); `0.2.x` — M6–M7; `0.3.x` — M8–M13
- `0.4.x` — M18–M22 (bridge-релизы без обещания совместимости)
- `0.5.0-beta.N` — M23 (публичная бета: egui + CLI, Android preview)
- `0.6.x` — M24–M28; `1.0` — после внешнего аудита
