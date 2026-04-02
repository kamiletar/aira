# Aira CLI — Русская локализация
# See SPEC.md §9.1

# Список контактов
contacts-title = Контакты
status-online = в сети
status-offline = не в сети
add-contact = Добавить контакт
no-contacts = Нет контактов. Используйте /add <pubkey> чтобы добавить.

# Чат
message-placeholder = Введите сообщение...
no-messages = Нет сообщений.
new-messages-divider = Новые сообщения

# Команды
cmd-add-usage = Использование: /add <pubkey> [alias]
cmd-file-usage = Использование: /file <path>
cmd-verify-prompt = Сравните Safety Number с { $contact }:
cmd-disappear-set = Сообщения удалятся через { $time }.
cmd-disappear-off = Исчезающие сообщения отключены.
cmd-export-done = Бэкап сохранён в { $path }.
cmd-import-done = Бэкап успешно импортирован.
cmd-mykey-label = Ваш публичный ключ:
cmd-info-version = Версия: { $version }
cmd-block-done = { $contact } заблокирован.
cmd-unblock-done = { $contact } разблокирован.
cmd-mute-done = { $contact } заглушен.
cmd-delete-confirm = Вы уверены? Это безвозвратно удалит ваш аккаунт. Введите YES для подтверждения.
cmd-unknown = Неизвестная команда: { $cmd }

# Передача файлов
file-sending = Отправка { $filename } ({ $size })...
file-complete = Файл сохранён: { $path }
file-error = Ошибка передачи: { $error }

# Уведомления
notification-title = Aira
notification-new-message = Новое сообщение
notification-from = Сообщение от { $contact }

# Ошибки
error-daemon-connect = Не удалось подключиться к демону. Он запущен?
error-no-contact = Контакт не выбран.

# Seed-фраза
seed-warning = Запишите seed-фразу и храните в безопасном месте!

# Статус-бар
status-editing = Редактирование сообщения
status-normal = Готов
