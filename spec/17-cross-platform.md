# SPEC §15: Кроссплатформенность и GUI

[← Индекс](../SPEC.md)

---

## 15. Кроссплатформенность и GUI

### 15.1 Стратегия: общее ядро + платформенные клиенты

```
┌─────────────────────────────────────────────────────────────────┐
│                    aira-core (pure Rust)                       │
│  крипто, протокол, ratchet, группы, spam — ВСЕ платформы        │
├─────────────────────────────────────────────────────────────────┤
│                    aira-net (Rust + iroh)                      │
│  сеть, NAT traversal, relay — ВСЕ платформы                     │
├─────────────────────────────────────────────────────────────────┤
│                    aira-storage (Rust + redb)                  │
│  локальная БД — ВСЕ платформы                                   │
├─────────────────────────────────────────────────────────────────┤
│                    aira-daemon (Rust + tokio)                  │
│  фоновый процесс — desktop (Linux/macOS/Windows)                │
│  встроенный в app — mobile (Android)                             │
├──────────┬──────────┬──────────┬─────────────────────────────────┤
│  CLI     │ Desktop  │ Android  │  Web (future)                   │
│ ratatui  │  egui    │ Kotlin + │  WASM + egui                    │
│          │          │ UniFFI   │                                 │
└──────────┴──────────┴──────────┴─────────────────────────────────┘
```

### 15.2 Desktop: Linux, macOS, Windows (v0.1 CLI → v0.3 GUI)

**v0.1 — CLI (ratatui):**

- Единый бинарник, работает везде где есть терминал
- `aira-daemon` + `aira-cli` общаются через IPC:
  - Linux/macOS: Unix domain socket (`~/.aira/daemon.sock`)
  - Windows: Named pipe (`\\.\pipe\aira-daemon`)

**v0.3 — Desktop GUI (egui/eframe):**

- Pure Rust, один исходный код → бинарник для каждой ОС
- egui рендерит через wgpu (Vulkan/Metal/DX12) — нативная
  производительность, нет WebView
- GUI общается с daemon через тот же IPC что и CLI
- Системный трей: daemon работает в фоне, GUI открывается по клику

```rust
// crates/aira-gui/src/main.rs
// Один исходник → cargo build для каждой платформы

fn main() {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([400.0, 600.0])
            .with_icon(load_icon()),
        ..Default::default()
    };
    eframe::run_native("aira", options, Box::new(|_| Ok(Box::new(App::new()))));
}
```

**Особенности по ОС:**

|             | Linux                      | macOS              | Windows                    |
| ----------- | -------------------------- | ------------------ | -------------------------- |
| IPC         | Unix socket                | Unix socket        | Named pipe                 |
| Автозапуск  | systemd user service       | LaunchAgent        | Registry / Task Scheduler  |
| Уведомления | libnotify / D-Bus          | NSUserNotification | Windows Toast              |
| Keychain    | Secret Service (GNOME/KDE) | macOS Keychain     | Windows Credential Manager |
| Трей        | libappindicator            | NSStatusItem       | Shell_NotifyIcon           |

Крейты: `notify-rust` (уведомления), `keyring` (OS keychain), `tray-icon` (системный трей)

**GUI-жесты (egui + Android):**

- **Свайп вправо по сообщению** — reply (цитирование). Заполняет
  `reply_to` в `MessageMeta`. UI показывает превью цитируемого
  сообщения над textarea. Esc/клик по крестику — отмена.
- В TUI (ratatui): `/reply` или выбор сообщения курсором + `r`

### 15.3 Android (v0.3)

**Архитектура:** Kotlin UI + Rust core через **UniFFI** (Mozilla)

```
┌─────────────────────────────┐
│  Kotlin UI (Jetpack Compose)│  — нативный Material You
├─────────────────────────────┤
│  UniFFI binding layer       │  — автогенерация Kotlin ↔ Rust
├─────────────────────────────┤
│  aira-core + net + storage│  — .so библиотека (ARM64/x86_64)
│  daemon встроен в app       │  — нет отдельного процесса
└─────────────────────────────┘
```

- **UniFFI** генерирует Kotlin биндинги из Rust интерфейсов автоматически
- Daemon не отдельный процесс — встроен в app, работает через Android
  Foreground Service (чтобы ОС не убивала)
- Push-уведомления: **UnifiedPush** (децентрализованный, без Google) или
  Firebase FCM как fallback — relay отправляет "wake-up" нотификацию,
  содержимое сообщения НЕ проходит через push-сервер
- Storage: redb работает на Android (обычный файл в app sandbox)
- Target: `aarch64-linux-android`, `x86_64-linux-android` (эмулятор)

```toml
# Cargo.toml для Android .so
[lib]
crate-type = ["cdylib"]

[dependencies]
uniffi = "0.28"
```

### ~~15.4 iOS~~ — ИСКЛЮЧЁН

> iOS исключён из проекта. Причины:
> - iOS убивает фоновые сетевые соединения через ~30 сек
> - VPN/Network Extension ограничен 25MB RAM — недостаточно для PQ крипто
> - Briar (P2P мессенджер) отказался от iOS по тем же причинам
> - SimpleX Chat теряет ~10% push-уведомлений из-за iOS memory limits
> - Apple не позволяет long-lived P2P connections в фоне
>
> Если iOS потребуется в будущем — потребуется отдельный thin-client,
> полностью зависящий от relay (фактически клиент-серверная архитектура)

### 15.5 Web (future, после v0.3)

- `aira-core` компилируется в **WASM** (уже no_std-совместимый)
- egui + eframe имеют WASM backend из коробки
- Сеть: iroh WASM поддержка (через WebTransport / WebSocket relay)
- Storage: IndexedDB через `idb` крейт
- **Ограничения:** нет прямого UDP (только через relay), производительность
  Argon2id в WASM ниже (~3-5x медленнее)

### 15.6 Структура репозитория (обновлённая)

```
aira/
├── Cargo.toml                # workspace
├── crates/
│   ├── aira-core/          # протокол, крипто — все платформы
│   ├── aira-net/           # сетевой слой + pluggable transports
│   ├── aira-storage/       # хранилище — все платформы
│   ├── aira-daemon/        # фоновый процесс — desktop
│   ├── aira-cli/           # TUI — desktop
│   ├── aira-gui/           # egui GUI — desktop (Linux/macOS/Windows)
│   ├── aira-bot/           # Bot SDK — библиотека для написания ботов (v0.2)
│   └── aira-ffi/           # UniFFI биндинги — mobile (Android)
├── mobile/
│   └── android/              # Kotlin + Jetpack Compose
├── locales/                  # i18n — Fluent .ftl файлы
│   ├── en/                   # English (базовый)
│   ├── ru/                   # Русский
│   └── .../                  # другие языки
├── bootstrap/                # bootstrap-ноды
├── docs/
└── tests/
    └── integration/
```

### 15.7 Матрица CI/CD

| Платформа     | Target                     | Артефакт             | CI                                    |
| ------------- | -------------------------- | -------------------- | ------------------------------------- |
| Linux x86_64  | `x86_64-unknown-linux-gnu` | AppImage / .deb      | GitHub Actions                        |
| macOS ARM     | `aarch64-apple-darwin`     | .dmg / .app          | GitHub Actions (macOS runner)         |
| macOS Intel   | `x86_64-apple-darwin`      | .dmg / .app          | GitHub Actions (macOS runner)         |
| Windows       | `x86_64-pc-windows-msvc`   | .msi / portable .exe | GitHub Actions (Windows runner)       |
| Android ARM64 | `aarch64-linux-android`    | .apk / .aab          | GitHub Actions + NDK                  |
| ~~iOS ARM64~~ | ~~`aarch64-apple-ios`~~    | ~~.ipa~~             | ~~ИСКЛЮЧЁН~~ (см. §15.4)             |
| Web (WASM)    | `wasm32-unknown-unknown`   | static site          | GitHub Actions                        |

---

