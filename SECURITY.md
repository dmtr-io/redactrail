# Политика безопасности

## Поддерживаемые версии

| Версия | Поддерживается |
|---|---|
| 0.1.x | да |

Проект до 1.0. Исправления безопасности выходят в последней версии 0.1.x.

## Как сообщить об уязвимости

**Не открывайте публичный issue** для проблемы безопасности.

Используйте приватный отчёт GitHub: репозиторий → **Security** →
**Report a vulnerability**. Если это недоступно — свяжитесь с мейнтейнером
через профиль, указанный в репозитории.

В отчёте укажите:

- версию и ОС;
- шаги воспроизведения или минимальный запрос;
- последствия: что утекает, что обходится, что раскрывается;
- логи без секретов и персональных данных.

Гарантированного срока ответа нет: проект ведёт один мейнтейнер. Я стараюсь
ответить по возможности и обычно в течение недели; если проблема критическая,
напишите об этом в самом отчёте. Триаж и согласованное раскрытие — после
исправления. Bug bounty нет.

## Что входит в охват

- обход маскирования: значение уходит провайдеру открытым;
- обход структурных проверок: запрос проходит без проверки формы;
- утечка при разворачивании: секрет или закрытый ключ возвращается в ответе;
- проблемы админки: обход аутентификации, CSRF, раскрытие токена, доступ
  из сети;
- аудит, раскрывающий значения без явного клика;
- кеш, возвращающий находки для другого текста или политики.

## Что не входит

- качество эвристик на произвольном тексте (обычный issue с синтетическим
  примером);
- поведение `api.deepseek.com` или локального хоста модели;
- ошибки конфигурации, выставившей админку в сеть;
- уязвимости, требующие уже скомпрометированной локальной учётной записи.

## Модель безопасности

- Прокси слушает только `127.0.0.1`.
- Админка слушает `127.0.0.1:8788` и не предназначена для сети.
- Телеметрии нет. Значения не пишутся на диск; журнал аудита хранит классы,
  хеши и хвосты псевдонимов.
- Псевдонимы разворачиваются только в том запросе, который их создал.
  Секреты (`private_key`, `secret_token`, `secret_assign`) не разворачиваются
  никогда.
- Локальный хост модели получает уже замаскированный текст; держите его на
  доверенной машине.

Полная модель угроз — [docs/threat-model.md](docs/threat-model.md).

## Отказ от ответственности

Проект распространяется **«как есть» (AS IS)**, без явных или подразумеваемых
гарантий. Вы используете его **на свой страх и риск**. В пределах, допускаемых
применимым правом, автор не несёт ответственности за любые убытки, утечки
данных, сбои, потерю прибыли или нарушения требований законодательства,
связанные с использованием проекта или невозможностью его использовать.

Прокси снижает риск, но **не гарантирует** защиту персональных данных.
Ответственность за соблюдение 152-ФЗ, GDPR и иных требований остаётся на
операторе, который использует инструмент.

---

## English summary

Supported: 0.1.x. Report vulnerabilities privately via GitHub Security
Advisories (repository → Security → Report a vulnerability); do not open a
public issue. In scope: masking/structural bypasses, restore leaks, admin auth
/ CSRF / token exposure, audit value disclosure, cache poisoning. Out of scope:
heuristic quality on arbitrary text, upstream provider and local model behavior,
misconfiguration, and attacks requiring a compromised local account.

There is no SLA: reports are handled on a best-effort basis, usually within a
week. Triage and coordinated disclosure follow once a fix is ready.

The project is provided **AS IS**, without warranties, and you use it at your
own risk. To the extent permitted by law, the author is not liable for damages,
data leaks, failures or legal violations arising from its use. The proxy reduces
risk but does not guarantee compliance; the operator remains responsible for
152-FZ, GDPR and similar requirements.

The proxy and admin listen on loopback only; there is no telemetry. Values are
not persisted, secrets are never restored, and the local audit model receives
masked text. See [docs/threat-model.md](docs/threat-model.md).
