"""Детерминированные детекторы: ПДн, реквизиты, секреты и двоичные блобы.

Каждое правило — пара «форма + проверка». Форма задаётся регулярным выражением,
проверка — контрольной суммой или структурой (`checksums.py`). Правило без
проверки допускается только там, где форма сама по себе однозначна (e-mail,
заголовок PEM-ключа).

Модуль не знает про маскировку и блокировку: он возвращает находки с классом,
а решение принимает `policy.py`. Это позволяет менять политику, не переписывая
детекторы, и тестировать их отдельно.

Смещения находок — всегда в исходном тексте, в символах Python (кодовых точках).
Регулярные выражения не нормализуют текст: юникод-дефисы и неразрывные пробелы
включены в шаблоны явно, чтобы не сдвигать координаты.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import cached_property
from typing import Callable, Iterable, Sequence

from . import checksums
from .detections import Finding

#: Дефисы, которые встречаются в скопированном из Word тексте.
_DASH = "\\-\u2010\u2011\u2012\u2013\u2014\u2015"
#: Пробелы, которые не ломают номер: обычный, неразрывный, узкий неразрывный.
_SPACE = " \u00a0\u202f\u2009"

_DIGIT_ONLY = re.compile(r"\D")

Validator = Callable[[str], bool]


def _digits(value: str) -> str:
    return _DIGIT_ONLY.sub("", value)


def _phone_ok(value: str) -> bool:
    number = _digits(value)
    return len(number) == 11 and number[0] in "78"


def _kpp_ok(value: str) -> bool:
    return checksums.kpp_ok(value)


def _bik_ok(value: str) -> bool:
    return checksums.bik_ok(value)


def _account_ok(value: str) -> bool:
    return len(_digits(value)) == 20


@dataclass(frozen=True)
class Rule:
    """Одно правило детектора.

    ``span`` — что именно закрывать находкой: всё совпадение (``"match"``) или
    только группу ``group`` (``"group"``). Второе нужно там, где смысл несёт
    число, а слово-подсказка («КПП», «БИК») служит лишь контекстом.

    ``precheck`` — подстроки, без которых правило заведомо не сработает. Проверка
    идёт по заранее опущенному в нижний регистр тексту и стоит на два порядка
    дешевле регулярного выражения. Для прокси это существенно: правила про
    паспорт, КПП и БИК в типичном запросе не встречаются вообще.
    """

    name: str
    pattern: re.Pattern[str]
    validator: Validator | None = None
    group: int = 0
    span: str = "match"
    precheck: tuple[str, ...] = ()
    #: Обрезка хвоста у значения (пробелы, точки): маска не должна съедать точку.
    clean: Callable[[str], str] | None = None

    def __post_init__(self) -> None:
        if self.span not in ("match", "group"):
            raise ValueError(f"{self.name}: span={self.span!r}")
        if self.span == "group" and self.group == 0:
            raise ValueError(f"{self.name}: span='group' требует group > 0")

    def may_match(self, lowered: str) -> bool:
        """Быстрая проверка: стоит ли запускать правило на этом тексте."""
        if not self.precheck:
            return True
        if len(self.precheck) == 1:
            return self.precheck[0] in lowered
        return self._precheck_re.search(lowered) is not None

    @cached_property
    def _precheck_re(self) -> re.Pattern[str]:
        return re.compile("|".join(re.escape(fragment) for fragment in self.precheck))


def _pattern(source: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(source, flags)


# --- Персональные данные -------------------------------------------------

_EMAIL = _pattern(
    r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}"
)

_PHONE = _pattern(
    rf"(?<![\d+])"
    rf"(?:\+7|8)[{_SPACE}\({_DASH}]{{0,2}}"
    rf"\d{{3}}[{_SPACE}\){_DASH}]{{0,2}}"
    rf"\d{{3}}[{_SPACE}{_DASH}]{{0,2}}"
    rf"\d{{2}}[{_SPACE}{_DASH}]{{0,2}}"
    rf"\d{{2}}"
    rf"(?!\d)"
)

_PASSPORT = _pattern(
    rf"(?i)\bпаспорт\w*\s*(?:серия|сер\.?)?\s*[:№]?\s*"
    rf"(\d{{2}}[{_SPACE}]?\d{{2}})\s*(?:№|N|номер|no\.?)?\s*(\d{{6}})(?!\d)"
)

_DOB = _pattern(
    rf"(?i)\b(?:дата\s+рождения|д\.\s?р\.|родил(?:ся|ась)|род\.)\s*[:{_DASH}]?\s*"
    rf"(\d{{1,2}}[.\-/]\d{{1,2}}[.\-/]\d{{2,4}}"
    rf"|\d{{1,2}}\s+[а-яё]+\s+\d{{4}})"
)

#: Дата, после которой стоит «г.р.» — частая форма в анкетах и выписках.
_DOB_AFTER = _pattern(
    rf"(\d{{1,2}}[.\-/]\d{{1,2}}[.\-/]\d{{4}})\s*(?:г\.\s?р\.|года\s+рождения)"
)

#: «ФИО иванов петр сергеевич» — метка снимает требование заглавных букв.
_FIO_LABEL = _pattern(
    r"(?i)\b(?:фио|ф\.\s?и\.\s?о\.?)\s*[:\-]?\s*"
    r"([а-яёa-z][а-яёa-z'\-]{1,}(?:\s+[а-яёa-z][а-яёa-z'\-]{1,}){1,2})"
)

#: «адрес питер, малевича 2в» — тип улицы и город не обязательны, если есть метка.
#: Останавливаемся перед пометками вроде «тел.» и «номер», иначе адрес съедает телефон.
_ADDRESS_LABEL = _pattern(
    r"(?i)\b(?:адрес|проживает|прописан[аы]?|зарегистрирован[аы]?)\s*[:\-]?\s*"
    r"([^\n;]{4,76}?)"
    r"(?=\s*(?:[;\n]|$|\b(?:тел|телефон|моб|номер|почта|e-?mail|инн|снилс|паспорт|огрн|"
    r"получател\w*|клиент\w*|плательщик\w*|грузополучател\w*|отправ\w*|кому|фио|контакт\w*)\b))"
)

#: «ИНН 7712345670» — метка снимает проверку контрольной суммы.
_INN_LABEL = _pattern(r"(?i)\bинн\b\s*[:№]?\s*(\d{10}|\d{12})(?!\d)")


def _fio_label_ok(value: str) -> bool:
    words = value.split()
    return len(words) >= 2 and all(word.replace("-", "").isalpha() for word in words)


def _dob_after_ok(value: str) -> bool:
    match = re.fullmatch(r"(\d{1,2})[.\-/](\d{1,2})[.\-/](\d{4})", value)
    if not match:
        return False
    day, month, year = (int(part) for part in match.groups())
    return 1 <= day <= 31 and 1 <= month <= 12 and 1900 <= year <= 2100


def _address_label_ok(value: str) -> bool:
    return any(char.isdigit() for char in value) and len(value.strip()) >= 6


def _address_clean(value: str) -> str:
    return value.strip().rstrip(".,;:")

_USER_PATH = _pattern(
    r"(?i)(?:[A-Z]:\\{1,2}(?:Users|Пользователи)\\{1,2}|/home/|/Users/)"
    r"([^\\/\s\"'<>|]+)"
)

#: Логин без пути: `ivan.petrov`, `a.kuznetsova`. Это не файл и не домен.
_LOGIN = _pattern(
    r"(?i)(?<![\w./\\@-])([a-z][a-z0-9]{2,20}\.[a-z][a-z0-9]{2,20})(?![\w./\\@-])"
)
_LOGIN_STOP = frozenset(
    {
        "doc", "docx", "xls", "xlsx", "pdf", "txt", "md", "json", "csv", "py", "js",
        "ts", "tsx", "html", "htm", "xml", "yaml", "yml", "log", "zip", "rar", "png",
        "jpg", "jpeg", "gif", "svg", "exe", "dll", "ini", "cfg", "toml", "lock",
        "com", "ru", "org", "net", "io", "dev", "local", "example", "test", "su",
    }
)


def _login_ok(value: str) -> bool:
    """Отсечь файлы и домены: `report.docx`, `example.com` — не логин."""
    left, _, right = value.casefold().partition(".")
    return bool(left and right) and not left.isdigit() and not right.isdigit() and right not in _LOGIN_STOP

# --- Реквизиты с контекстом ----------------------------------------------

_KPP = _pattern(r"(?i)\bКПП\b\s*[:№]?\s*(\d{4}[0-9A-Za-z]{2}\d{3})")
_BIK = _pattern(r"(?i)\bБИК\b\s*[:№]?\s*(\d{9})(?!\d)")
_ACCOUNT = _pattern(
    rf"(?i)\b(?:р/с|р\.\s?с\.?|расч[её]тн\w*\s+сч[её]т|лицев\w*\s+сч[её]т|"
    rf"сч[её]т\s*№)\s*[:№]?\s*(\d{{20}})(?!\d)"
)

# --- Секреты --------------------------------------------------------------

_PRIVATE_KEY = _pattern(
    r"-----BEGIN (?:[A-Z0-9 ]{0,40} )?PRIVATE KEY-----"
)

_SECRET_TOKEN = _pattern(
    r"(?:"
    r"AKIA[0-9A-Z]{16}"
    r"|ASIA[0-9A-Z]{16}"
    r"|gh[pousr]_[A-Za-z0-9]{30,}"
    r"|github_pat_[A-Za-z0-9_]{30,}"
    r"|xox[baprs]-[A-Za-z0-9\-]{10,}"
    r"|(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}"
    r"|sk-[A-Za-z0-9\-_]{32,}"
    r"|AIza[0-9A-Za-z\-_]{35}"
    r"|eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"
    r"|(?i:Bearer)\s+[A-Za-z0-9\-._~+/]{16,}=*"
    r")"
)

_SECRET_ASSIGN_TOKEN = _pattern(
    r"(?i)\b(?:api[_-]?key|apikey|access[_-]?key|secret[_-]?key|"
    r"client[_-]?secret|auth[_-]?token|token|secret)\b"
    r"\s*[:=]\s*[\"']?[A-Za-z0-9\-_+/.]{12,}[\"']?"
)

_SECRET_ASSIGN_PASSWORD = _pattern(
    r"(?i)\b(?:password|passwd|pwd|пароль)\b\s*[:=]\s*[\"']?[^\s\"',;]{3,}[\"']?"
)

# --- Двоичные и закодированные данные ------------------------------------

_BLOB = _pattern(r"[A-Za-z0-9+/]{512,}+={0,2}")


RULES: tuple[Rule, ...] = (
    Rule("private_key", _PRIVATE_KEY, precheck=("-----begin",)),
    Rule("secret_token", _SECRET_TOKEN, precheck=("akia", "asia", "ghp_", "github_pat_",
                                                  "xox", "sk_", "sk-", "aiza", "eyj", "bearer")),
    Rule("secret_assign", _SECRET_ASSIGN_TOKEN, precheck=("key", "token", "secret")),
    Rule("secret_assign", _SECRET_ASSIGN_PASSWORD, precheck=("password", "passwd", "pwd", "пароль")),
    Rule("blob", _BLOB),
    Rule("user", _USER_PATH, group=1, span="group", precheck=("users", "/home/", "пользователи")),
    Rule("user", _LOGIN, _login_ok, group=1, span="group", precheck=(".",)),
    Rule("phone", _PHONE, _phone_ok, precheck=("+7", "8")),
    Rule("email", _EMAIL, precheck=("@",)),
    Rule("passport", _PASSPORT, precheck=("паспорт",)),
    Rule("dob", _DOB, precheck=("рождени", "родил", "д.р", "д. р")),
    Rule(
        "dob",
        _DOB_AFTER,
        _dob_after_ok,
        group=1,
        span="group",
        precheck=("г.р", "г. р", "года рождения"),
    ),
    Rule(
        "person",
        _FIO_LABEL,
        _fio_label_ok,
        group=1,
        span="group",
        precheck=("фио", "ф.и.о", "ф. и. о"),
    ),
    Rule(
        "address",
        _ADDRESS_LABEL,
        _address_label_ok,
        group=1,
        span="group",
        precheck=("адрес", "проживает", "прописан", "зарегистрирован"),
        clean=_address_clean,
    ),
    Rule("inn", _INN_LABEL, group=1, span="group", precheck=("инн",)),
    Rule("kpp", _KPP, _kpp_ok, group=1, span="group", precheck=("кпп",)),
    Rule("bik", _BIK, _bik_ok, group=1, span="group", precheck=("бик",)),
    Rule("account", _ACCOUNT, _account_ok, group=1, span="group", precheck=("сч", "р/с", "р.с")),
)

#: Номера разбираются одним проходом: ИНН, СНИЛС, ОГРН и карта отличаются
#: длиной и контрольной суммой, а не формой. Четыре отдельных регулярных
#: выражения по одному и тому же тексту стоили больше, чем весь остальной разбор.
_NUMBER_RUN = _pattern(
    rf"(?<!\d)\d[\d{_SPACE}{_DASH}]{{6,32}}\d(?!\d)"
)


def _number_findings(text: str) -> list[Finding]:
    """Классифицировать числовые цепочки: ИНН, СНИЛС, ОГРН, карта."""
    findings: list[Finding] = []
    for match in _NUMBER_RUN.finditer(text):
        value = match.group(0)
        number = _digits(value)
        length = len(number)
        start, end = match.span(0)

        if length == 10 and checksums.inn10_ok(number):
            findings.append(Finding(start, end, "inn", value))
        elif length == 12:
            if checksums.inn12_ok(number):
                findings.append(Finding(start, end, "inn", value))
        elif length == 11 and checksums.snils_ok(number):
            findings.append(Finding(start, end, "snils", value))

        if length in (13, 15) and checksums.ogrn_ok(number):
            findings.append(Finding(start, end, "ogrn", value))
        if 13 <= length <= 19 and checksums.luhn_ok(number):
            findings.append(Finding(start, end, "card", value))
    return findings


def find_entities(
    text: str, rules: Sequence[Rule] = RULES, lowered: str | None = None
) -> list[Finding]:
    """Прогнать все правила по тексту и вернуть находки без разрешения пересечений.

    Пересечения здесь не разрешаются: «12 цифр, прошедшие Луну» — это и карта,
    и, возможно, ИНН. Какое действие важнее, знает политика, поэтому решение
    принимает `scan.scan_text`, а не детектор.
    """
    findings: list[Finding] = []
    findings.extend(_number_findings(text))
    if lowered is None:
        lowered = text.casefold() if any(rule.precheck for rule in rules) else text
    for rule in rules:
        if not rule.may_match(lowered):
            continue
        for match in rule.pattern.finditer(text):
            value = match.group(rule.group) if rule.group else match.group(0)
            if not value:
                continue
            if rule.validator is not None and not rule.validator(value):
                continue
            if rule.span == "group":
                start, end = match.span(rule.group)
            else:
                start, end = match.span(0)
            if rule.clean is not None:
                cleaned = rule.clean(value)
                if cleaned != value:
                    value = cleaned
                    end = start + len(value)
            findings.append(Finding(start, end, rule.name, value))
    # Один и тот же участок мог найтись двумя правилами (метка «ИНН» и числовая
    # эвристика): оставляем первое совпадение, иначе значение маскируется дважды.
    seen: set[tuple[int, int, str]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.start, finding.end, finding.klass)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def marker_findings(
    text: str, patterns: Sequence[re.Pattern[str]] | None
) -> list[Finding]:
    """Находки класса ``marker`` по правилам из политики (позиция грифа)."""
    if not patterns:
        return []
    findings: list[Finding] = []
    seen: set[tuple[int, int]] = set()
    for pattern in patterns:
        named = "m" in pattern.groupindex
        for match in pattern.finditer(text):
            start, end = match.span("m") if named else match.span(0)
            if (start, end) in seen:
                continue
            seen.add((start, end))
            findings.append(Finding(start, end, "marker", text[start:end]))
    return findings


def nonprintable_ratio(text: str) -> float:
    """Доля символов, которые не являются печатными.

    Используется в M2 как дополнительный признак блоба: текст с большим числом
    управляющих символов — это, скорее всего, двоичные данные, а не сообщение.
    """
    if not text:
        return 0.0
    bad = sum(1 for char in text if not char.isprintable() and char not in "\n\r\t")
    return bad / len(text)


def iter_rule_names() -> Iterable[str]:
    for rule in RULES:
        yield rule.name
