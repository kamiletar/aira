# SPEC §9: CLI (aira-cli)

[← Индекс](../SPEC.md)

---

## 9. CLI (aira-cli)

TUI на **ratatui**. Минимальный UX:

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

Команды:

- `/add <pubkey>` — добавить контакт
- `/file <path>` — отправить файл
- `/me <action>` — действие от третьего лица (`* Alice делает что-то`)
- `/mykey` — показать свой публичный ключ (для sharing)
- `/verify <contact>` — показать Safety Number для верификации ключей
- `/disappear <time>` — включить автоудаление (30s/5m/1h/1d/7d/off)
- `/export [path]` — экспорт зашифрованного бэкапа
- `/import <path>` — импорт бэкапа (запросит seed-фразу)
- `/transport <mode>` — режим транспорта (direct/obfs4/mimicry/reality/tor)
- `/mute <contact> [duration]` — заглушить контакт
- `/block <contact>` — заблокировать контакт (silent drop, п. 6.19)
- `/unblock <contact>` — разблокировать контакт
- `/profile [name|avatar|status]` — редактировать свой профиль (п. 6.17)
- `/delete-account` — безвозвратное удаление аккаунта (п. 6.18)
- `/info` — версия, статус сети, relay, capabilities
- `/lang <code>` — сменить язык интерфейса (en/ru/es/zh/ar/...)

**Горячие клавиши (textarea в фокусе):**

- `↑` (при пустой textarea) — редактирование последнего своего сообщения.
  Текст сообщения загружается в textarea, Enter отправляет `Edit`.
  Esc отменяет редактирование. Работает аналогично Discord/Slack/Telegram Desktop.
- `Esc` (при непустой textarea в режиме редактирования) — отмена, возврат
  к обычному вводу
- `Ctrl+F` / `/search <query>` — поиск по истории сообщений (локальный)
- `Tab` — автодополнение команд (`/fi` → `/file`) и контактов
- `Ctrl+W` — переключение между панелью контактов и чатом

**Поведение ввода:**

- `Enter` — отправить сообщение
- `Shift+Enter` (GUI) / `Alt+Enter` (TUI) — новая строка в сообщении
- Многострочный ввод отображается с переносом в textarea

**Черновики (drafts):**

- При переключении между контактами — набранный текст сохраняется как
  черновик (in-memory, не отправляется, не шифруется)
- При возврате к контакту — черновик загружается обратно в textarea
- Черновики НЕ сохраняются при перезапуске (только in-memory)

**Непрочитанные сообщения:**

- Каждый контакт показывает badge с количеством непрочитанных
- При открытии чата — автоскролл к первому непрочитанному сообщению
- Маркер "Новые сообщения" разделяет прочитанные и непрочитанные

**Уведомления (desktop):**

- OS-нативные уведомления через `notify-rust`
- Показывают: имя контакта + превью текста (≤ 100 символов)
- **Privacy mode:** превью скрыто, показывается только "Новое сообщение"
- Per-contact настройка: включены / выключены / mute на N часов
- Звук: системный или отключен (настройка)

### 9.1 Мультиязычность (i18n)

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

**Языки v0.1:** English (en), Русский (ru)
**Языки v0.2:** + Español (es), 中文 (zh), العربية (ar), Deutsch (de),
Français (fr), 日本語 (ja), Português (pt), हिन्दी (hi)

**Seed-фраза:** BIP-39 wordlist существует на ~10 языках. Пользователь
выбирает язык seed-фразы при генерации. Внутренне хранится как entropy,
отображение зависит от выбранного языка wordlist.

**Определение языка:**

1. Явная настройка (`/lang ru` или config)
2. Переменная окружения `LANG` / `LC_MESSAGES`
3. OS locale (Android: `Locale.getDefault()`)
4. Fallback: English

---
