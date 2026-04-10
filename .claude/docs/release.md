# Release Pipeline

## Overview

Aira uses GitHub Actions for CI/CD with automated cross-platform builds.

## Workflows

### CI (`.github/workflows/ci.yml`)

Triggers on push to `main`/`dev` and PRs. Four parallel jobs:

| Job | What it does |
|-----|-------------|
| `fmt` | `cargo fmt --all -- --check` |
| `clippy` | `cargo clippy --workspace --all-targets -- -D warnings` |
| `test` | `cargo test --workspace` |
| `audit` | `cargo audit` + `cargo deny check` |

Linux jobs install system deps for egui: `libgtk-3-dev`, `libxdo-dev`, `libxcb-*`.

### Release (`.github/workflows/release.yml`)

Triggers on tag push `v*`. Builds for 4 targets:

| Target | Runner | Archive |
|--------|--------|---------|
| `x86_64-unknown-linux-gnu` | `ubuntu-latest` | `.tar.gz` |
| `aarch64-apple-darwin` | `macos-latest` | `.tar.gz` |
| `x86_64-apple-darwin` | `macos-13` | `.tar.gz` |
| `x86_64-pc-windows-msvc` | `windows-latest` | `.zip` |

Each archive contains: `aira` (CLI), `aira-daemon`, `aira-gui` + SHA256 checksum.

Creates a GitHub Release with auto-generated release notes from conventional commits.

### Android (`.github/workflows/android.yml`)

Separate workflow for Android FFI builds. Triggers on FFI/mobile path changes.

## How to Release

```bash
./scripts/release.sh <version>
# Example: ./scripts/release.sh 0.4.0
```

The script:
1. Updates `version` in workspace `Cargo.toml` (all crates inherit it)
2. Runs `cargo check` to update `Cargo.lock`
3. Commits: `chore: release v0.4.0`
4. Creates annotated tag `v0.4.0`
5. Pushes commit + tag → triggers release workflow

## Website Integration

The release website at `aira.letar.best` (repo: `lena/apps/aira-web`) fetches
the latest release from GitHub Releases API with 1-hour ISR cache.

Key files:
- `src/lib/github.ts` — GitHub API utility (`getLatestRelease()`)
- `src/app/_components/hero.tsx` — dynamic version badge
- `src/app/_components/download-section.tsx` — per-platform download cards

## Archive Naming Convention

```
aira-{VERSION}-{TARGET}.{ext}
aira-{VERSION}-{TARGET}.{ext}.sha256
```

Example: `aira-0.4.0-x86_64-unknown-linux-gnu.tar.gz`

## Version Scheme

- `0.1.x` — Milestones 1-5 (CLI MVP)
- `0.2.x` — Milestones 6-7 (Groups + DPI)
- `0.3.x` — Milestones 8-13 (Multi-device + GUI + Mobile)
