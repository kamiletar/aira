# Aira — руководство по установке

> ⚠️ **Статус 0.3.5: pre-release без сети.** Сообщения сохраняются локально и не доставляются собеседнику —
> сетевой слой подключается к демону в релизном пути M18–M23 (`spec/18-milestones.md` §16.1). Ставьте для
> знакомства с интерфейсом, не для переписки.

Все инсталляторы собираются через GitHub Actions и публикуются на
странице [Releases](https://github.com/kamiletar/aira/releases). Для
каждой платформы есть два варианта: **installer** (рекомендуется для
большинства) и **portable archive** (для продвинутых пользователей).

## Что входит

Все инсталляторы содержат три бинарника:

- **`aira-gui`** — графический клиент (egui/eframe). Основное приложение.
- **`aira-daemon`** — фоновый процесс, который держит P2P-соединение и
  хранит историю. GUI запускает его автоматически.
- **`aira`** — ratatui CLI для терминала. Опционально, для power users.

При первом запуске GUI создаст или импортирует 24-слово BIP-39 seed phrase
и сохранит её в OS keychain. В настройках можно включить дополнительную
защиту паролем.

---

## Windows

### Рекомендуется: MSI installer

1. Скачай `aira-0.3.5-setup.msi` со страницы релиза.
2. Двойной клик.
3. **SmartScreen предупреждение:** Windows покажет "Windows protected
   your PC". Это нормально — бинарники пока не подписаны; подпись через
   SignPath Foundation (бесплатно для open source) запланирована к бете.
   Нажми **More info → Run anyway**.
4. Следуй шагам мастера. По умолчанию установка в
   `C:\Program Files\Aira\`.
5. После установки в Start Menu появится ярлык **Aira**.

### Удаление

Параметры Windows → Приложения → Aira → Удалить.

### Portable версия (без установки)

Скачай `aira-0.3.5-x86_64-pc-windows-msvc.zip`, распакуй в любую папку,
запусти `aira-gui.exe`.

---

## macOS

### Рекомендуется: .dmg

Отдельные сборки для Apple Silicon (M1/M2/M3/M4) и Intel.

1. Скачай соответствующий файл:
   - Apple Silicon: `Aira-0.3.5-arm64.dmg`
   - Intel: `Aira-0.3.5-x86_64.dmg`
2. Двойной клик → перетащи **Aira** в **Applications**.
3. **Gatekeeper предупреждение:** macOS скажет "Aira.app cannot be
   opened because the developer cannot be verified". Apple Developer ID и
   notarization **не планируются** до 1.0 (решение проекта, сентябрь 2026);
   на macOS Sequoia+ обход — через System Settings → Privacy & Security → Open Anyway.

   **Обход:** Правый клик на Aira.app → **Open** → **Open** в диалоге.
   После первого раза macOS запомнит решение.

   Альтернатива из терминала:
   ```bash
   xattr -dr com.apple.quarantine /Applications/Aira.app
   ```

### Удаление

Перетащи **Aira** из Applications в Trash. История и ключи останутся в
keychain и `~/Library/Application Support/aira` — удали их вручную если
нужно полное удаление.

### Portable версия

`aira-0.3.5-aarch64-apple-darwin.tar.gz` или
`aira-0.3.5-x86_64-apple-darwin.tar.gz`. Распакуй в папку, запусти
`./aira-gui`.

---

## Linux

### Рекомендуется: AppImage

Один файл, работает на любом дистрибутиве, не требует root.

1. Скачай `Aira-0.3.5-x86_64.AppImage`.
2. Сделай исполняемым:
   ```bash
   chmod +x Aira-0.3.5-x86_64.AppImage
   ```
3. Запусти:
   ```bash
   ./Aira-0.3.5-x86_64.AppImage
   ```
4. (Опционально) Добавь в меню приложений через
   [appimaged](https://github.com/probonopd/go-appimage) или вручную.

### Зависимости

AppImage содержит GTK3 и его зависимости, но **сборки 0.3.5 собраны на
Ubuntu 24.04 и требуют glibc ≥ 2.39** (Ubuntu 24.04+, Fedora 40+, Arch,
Debian 13). На Ubuntu 22.04 / Debian 12 они не запустятся; сборка в
контейнере 22.04 запланирована (трек M22-infra).

На старых системах может потребоваться FUSE 2:
```bash
# Ubuntu/Debian
sudo apt install libfuse2
```

### Удаление

Удали файл `.AppImage`. Данные хранятся в `~/.aira/` и OS keychain
(Secret Service через gnome-keyring или KWallet).

### Portable версия

`aira-0.3.5-x86_64-unknown-linux-gnu.tar.gz`. Содержит raw бинарники.
Потребуются системные библиотеки GTK3:
```bash
sudo apt install libgtk-3-0 libxdo3
```

---

## Android

Скачай `aira-0.3.5-android.apk` и установи. Требует разрешения "Установка
из неизвестных источников".

**Примечание:** APK 0.3.5 **не подписан вообще** (в релизе лежит
`app-release-unsigned.apk`) — большинство современных Android его не установит.
Android — preview: в бете 0.5 APK не публикуется до появления подписи и
онбординга (Android-пакет M19b). Ждите подписанного релиза.

---

## Безопасность

1. **Не запускай бинарники от не-официальных зеркал.** Всегда проверяй
   SHA256 из соответствующего `.sha256` файла в Release:
   ```bash
   sha256sum -c Aira-0.3.5-x86_64.AppImage.sha256
   # Windows:
   certutil -hashfile aira-0.3.5-setup.msi SHA256
   ```
2. **Seed phrase нельзя восстановить.** Запиши 24 слова на бумаге и
   храни в безопасном месте. Потеря фразы = потеря всех контактов и
   истории переписки.
3. **Password protection опциональна.** Если включишь в Settings →
   Security, будешь вводить пароль на каждом старте GUI. Забыл пароль →
   только Reset identity и Import из записанной seed phrase.

---

## Отчёт о проблемах

- Баги: https://github.com/kamiletar/aira/issues
- Спецификация: [SPEC.md](../SPEC.md)
- Milestone 9.5 (этот инсталлятор): [spec/18-milestones.md](../spec/18-milestones.md#milestone-95)
- Что видят relay и собеседник: [PRIVACY.md](PRIVACY.md); модель угроз: [THREAT_MODEL.md](THREAT_MODEL.md)
- Уязвимости: [SECURITY.md](../SECURITY.md)
