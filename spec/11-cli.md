# SPEC §9: CLI (aira-cli)

[← Индекс](../SPEC.md)

---

## 9. CLI (aira-cli)

TUI на **ratatui**. Минимальный клиент (§15.8): переписка 1-на-1, файлы, сверка отпечатков,
блокировка — и ничего сверх этого до соответствующих milestones. Минимальный UX:

```
┌─ aira ─────────────────────────────────────────────────────┐
│ Contacts          │ Alice [online]                            │
│ > Alice ●         │                                           │
│   Bob             │  [10:42] Alice: привет!                   │
│   Carol           │  [10:43] You: привет                      │
│                   │  [10:43] Alice: как дела?                 │
│                   │                                           │
│                   │ > _                                        │
│ [A]dd [D]el [Q]uit│ /file /clear /info                        │
└───────────────────┴───────────────────────────────────────────┘
```

**Команды беты (реализованы или входят в M19/M19b):**

- `/add <uri> [alias]` — добавить контакт по invitation link `aira://add/…` (M19 п.12; в v0.3.5 —
  по hex-ключу, что для ML-DSA-ключа в 1952 байта непригодно, §5.2)
- `/invite` — показать свою ссылку-приглашение и QR в терминале (`GetInvitation`, стабильный
  псевдоним, без IP; M19b п.4). Заменяет `/mykey`, который выдавал **новый** псевдоним при
  каждом вызове (B5)
- `/requests [accept|reject <n>]` — входящие contact requests (`ContactRequestReceived`,
  `AcceptContact/RejectContact`; M19b п.4, PoW/tier — M22)
- `/file <path>` — отправить файл
- `/me <action>` — действие от третьего лица (`* Alice делает что-то`)
- `/verify [contact]` — показать Safety Number (`GetSafetyNumber`, §6.9, ≥ 128 бит). В v0.3.5 —
  заглушка «coming in M6»; до реализации (M19b) убирается из справки
- `/disappear <time>` — автоудаление (30s/5m/1h/1d/7d/off) → `SetTtl`; таймер реально сработает
  после M19 (F1, §6.7)
- `/export [path]` — экспорт зашифрованного бэкапа
- `/import <path>` — импорт бэкапа (запросит seed-фразу)
- `/block <contact>` / `/unblock <contact>` — `BlockContact` / `UnblockContact` (M19 Phase B / M19b):
  контакт остаётся в списке, входящие и handshake от него — silent drop (§6.19).
  ⚠️ В v0.3.5 `/block` вызывает `RemoveContact` (удаляет контакт), `/unblock` — заглушка (F2)
- `/relay` — список relay и статус сети (`GetRelays` / `SetRelays` / `GetNetStatus`; M19b п.5)
- `/info` — версия, статус сети (`NetStatus`: home relay, `hide_ip`, очередь), capabilities

**Убрано:**

- `/transport <mode>` (direct/obfs4/mimicry/reality/tor) — транспорты `transport/*` удалены
  (решение A13, M19b); при неизменном трафике команда лишь создавала иллюзию защиты. Режимы обхода
  блокировок — профили сети (§11A v2: iroh-relay на своём домене, мосты M24c, Aira Onion M24b),
  не команда клиента

**Не реализовано — не показывать в справке и автодополнении до реализации (§15.8 п.6):**

- `/mute <contact> [duration]` — M28 (§11B.6)
- `/profile [name|avatar|status]` — M28 (§6.17); в бете только локальный alias
- `/delete-account` — после M20/M21 (§6.18: нужен отзыв в pkarr и на relay); сейчас печатает
  «Type YES» и подтверждение не обрабатывает
- `/lang <code>` — движок i18n не подключён (§9.1); бета — English only
- `/search <query>` — M28 (§6.24)
- `/pin` — M28 (§6.23); команды в коде нет

**Скрыты в бете (реализация после беты):**

- `/group create|list|info|add|remove|leave` — группы v2, M25 (§12); демон отвечает
  `Error("groups are not available in this beta")`
- `/link [code]`, `/devices`, `/unlink <id>` — мультидевайс v2, M26 (§14)

**Горячие клавиши (textarea в фокусе):**

- `↑` (при пустой textarea) — редактирование последнего своего сообщения (`Edit`, §6.13) — **M28**;
  в v0.3.5 нет
- `Esc` — отмена редактирования / возврат к обычному вводу
- `Ctrl+F` / `/search <query>` — поиск по истории (локальный) — **M28**
- `Tab` — автодополнение команд (`/fi` → `/file`) и контактов; список — только команды беты
- `Ctrl+W` — переключение между панелью контактов и чатом

**Поведение ввода:**

- `Enter` — отправить сообщение
- `Shift+Enter` (GUI) / `Alt+Enter` (TUI) — новая строка в сообщении
- Многострочный ввод отображается с переносом в textarea
- Длина текста проверяется до отправки (`MAX_ENVELOPE_SIZE`, M19b п.4)

**Черновики (drafts):**

- При переключении между контактами — набранный текст сохраняется как
  черновик (in-memory, не отправляется, не шифруется)
- При возврате к контакту — черновик загружается обратно в textarea
- Черновики НЕ сохраняются при перезапуске (только in-memory)

**Непрочитанные сообщения:**

- Каждый контакт показывает badge с количеством непрочитанных
- При открытии чата — автоскролл к первому непрочитанному сообщению; открытие чата =
  `GetHistory` → `mark_read` в демоне (старт TTL, §6.7)
- Маркер "Новые сообщения" разделяет прочитанные и непрочитанные

**Уведомления (desktop):**

- OS-нативные уведомления через `notify-rust`
- Показывают: имя контакта + превью текста (≤ 100 символов)
- **Privacy mode:** превью скрыто, показывается только "Новое сообщение"
- Per-contact настройка: включены / выключены / mute на N часов (mute — M28)
- Звук: системный или отключен (настройка)

### 9.1 Мультиязычность (i18n)

> **Статус на 2026-09:** движок `aira_core::i18n` (fluent, `locales/{en,ru}/main.ftl`, 33 ключа,
> `SUPPORTED_LOCALES = ["en", "ru"]`) существует, но **не подключён ни к одному клиенту** — строки
> CLI/GUI/FFI hardcoded, `/lang` — заглушка. Бета — English only (`/lang` из справки убрать).
> Подключение — после беты: либо M9.6 Phase C для egui, либо только в Tauri-клиенте (`letar`),
> поскольку egui — минимальный класс с заморозкой интерфейсных фич (§15.8) — решение владельца.

Все строки интерфейса (CLI, GUI, мобильные клиенты) локализуемы.

**Подход: Fluent (Mozilla Project)**

```
# locales/en/main.ftl
contacts-title = Contacts
message-placeholder = Type a message...
status-online = online
status-offline = offline
add-contact = Add contact
verify-prompt = Compare this Safety Number with { $contact }:
disappearing-set = Messages will disappear after { $time }
seed-warning = Write down your seed phrase and keep it safe!
file-transfer = Sending { $filename } ({ $size })...
```

```
# locales/ru/main.ftl
contacts-title = Контакты
message-placeholder = Введите сообщение...
status-online = в сети
status-offline = не в сети
add-contact = Добавить контакт
verify-prompt = Сравните Safety Number с { $contact }:
disappearing-set = Сообщения удалятся через { $time }
seed-warning = Запишите seed-фразу и храните в безопасном месте!
file-transfer = Отправка { $filename } ({ $size })...
```

**Почему Fluent, а не gettext/i18n-embed:**

- Создан Mozilla для Firefox — battle-tested
- Поддерживает плюрализацию, пол, числовые форматы из коробки
- Крейт `fluent-rs` — pure Rust, no_std-совместимый
- `.ftl` файлы легко переводить (человекочитаемый формат)
- Используется в Firefox, Thunderbird, и Servo

**Реализация:**

```rust
// aira-core/src/i18n.rs

use fluent::{FluentBundle, FluentResource};
use unic_langid::LanguageIdentifier;

pub struct I18n {
    bundle: FluentBundle<FluentResource>,
    locale: LanguageIdentifier,
}

impl I18n {
    pub fn new(locale: &str) -> Self {
        let lang: LanguageIdentifier = locale.parse().unwrap_or("en".parse().unwrap());
        let ftl = load_ftl(&lang); // из embedded ресурсов или файловой системы
        let resource = FluentResource::try_new(ftl).expect("valid FTL");
        let mut bundle = FluentBundle::new(vec![lang.clone()]);
        bundle.add_resource(resource).expect("no conflicts");
        Self { bundle, locale: lang }
    }

    pub fn t(&self, id: &str) -> String {
        let msg = self.bundle.get_message(id).expect("message exists");
        let pattern = msg.value().expect("has value");
        self.bundle.format_pattern(pattern, None, &mut vec![]).to_string()
    }
}
```

> Псевдокод выше с `unwrap`/`expect` — иллюстрация; в production-коде — `Result` и fallback на `en`
> (§17, `clippy::unwrap_used = deny`).

**Языки беты:** English (en); файлы ru есть, но не подключены
**Языки после беты:** Русский (ru), затем Español (es), 中文 (zh), العربية (ar), Deutsch (de),
Français (fr), 日本語 (ja), Português (pt), हिन्दी (hi)

**Seed-фраза:** BIP-39 wordlist существует на ~10 языках. Пользователь
выбирает язык seed-фразы при генерации. Внутренне хранится как entropy,
отображение зависит от выбранного языка wordlist. (В коде — только English wordlist.)

**Определение языка:**

1. Явная настройка (`/lang ru` или config)
2. Переменная окружения `LANG` / `LC_MESSAGES`
3. OS locale (Android: `Locale.getDefault()`)
4. Fallback: English

---
