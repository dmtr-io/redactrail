"""Детектор ФИО, организаций и адресов в свободном тексте — офлайн, без модели.

Как работает:

1. Текст режется на токены (слова, инициалы, числа, знаки) с координатами.
2. Слова классифицируются по словарям `ru_names.py`; словоформы
   («Иванову», «Петровны», «Анне») сводятся к словарной форме отсечением
   окончаний, иначе в живом тексте ловились бы только именительные падежи.
3. ФИО собирается из соседних токенов: фамилия + имя + отчество, фамилия +
   инициалы, имя + отчество, одиночная фамилия.
4. Организации и адреса ищутся по формам («ООО «Ромашка»», «ул. Ленина, д. 15»)
   с проверкой контекста: «г.», «д.», «с.» без подтверждения не считаются адресом.

Точность важнее полноты только в одном месте: одиночная фамилия вне адресного
контекста и одиночное имя маскируются, потому что «Иванову поручили» — это
реальный человек. Ложное срабатывание стоит одного псевдонима в тексте, пропуск —
утечки.

Модуль возвращает `Finding` с классом `person`, `org` или `address`; решение
о маскировке принимает политика.
"""

from __future__ import annotations

import re
from functools import lru_cache
from typing import Iterable, NamedTuple, Sequence

from . import ru_names
from .detections import Finding

# --- Токенизация ----------------------------------------------------------

_TOKEN_RE = re.compile(
    r"[А-ЯЁA-Z]\.(?:\s?[А-ЯЁA-Z]\.)?"
    r"|[А-ЯЁA-Z][а-яёa-z\-]*"
    r"|[а-яёa-z\-]+"
    r"|\d+[а-яёa-z]?(?:[/\-]\d+[а-яёa-z]?)?"
    r"|[^\s]"
)


class Token(NamedTuple):
    start: int
    end: int
    text: str
    kind: str  # init | word | num | punct

    @property
    def is_capitalized(self) -> bool:
        return bool(self.text) and self.text[0].isupper()


def tokenize(text: str) -> list[Token]:
    """Разбить текст на токены. Пробелы токенами не считаются.

    Инициалы («И.», «И.И.», «И. И.») — один токен: для детектора ФИО это единый
    элемент, а не буква, точка и пробел.
    """
    tokens: list[Token] = []
    for match in _TOKEN_RE.finditer(text):
        chunk = match.group(0)
        if len(chunk) > 1 and chunk.endswith("."):
            kind = "init"
        elif chunk[0].isdigit():
            kind = "num"
        elif len(chunk) == 1 and not chunk.isalnum():
            kind = "punct"
        else:
            kind = "word"
        tokens.append(Token(match.start(), match.end(), chunk, kind))
    return tokens


_WORD_ENDINGS = ("", "а", "я", "ь", "й", "ы", "и", "е", "у", "ю", "ой", "ей", "ом", "ем", "ам", "ям")


def _candidates(word: str) -> Iterable[str]:
    """Словарные формы, которые могли дать словоформу в тексте.

    Отсечение одного-двух последних символов с добавлением типового окончания
    покрывает падежи и женские формы: «Иванову» → «иванов», «Анне» → «анна»,
    «Петровны» → «петровна».
    """
    for cut in (1, 2):
        if len(word) - cut < 3:
            continue
        stem = word[:-cut]
        for ending in _WORD_ENDINGS:
            yield stem + ending


def _build_exact_kinds() -> dict[str, str]:
    """Словарь «точная словоформа → класс» с приоритетом классов."""
    kinds: dict[str, str] = {}
    for word in ru_names.FIRST_NAMES:
        kinds[word] = "name"
    for word in ru_names.PATRONYMICS:
        kinds[word] = "patronymic"
    for word in ru_names.SURNAMES:
        kinds.setdefault(word, "surname")
    for word in ru_names.ADJECTIVAL_SURNAMES:
        kinds[word] = "surname_adj"
    return kinds


_EXACT_KINDS = _build_exact_kinds()


@lru_cache(maxsize=1 << 16)
def _kind_of_low(low: str) -> str:
    """Класс слова: точное совпадение, затем падежные формы, затем «другое»."""
    kind = _EXACT_KINDS.get(low)
    if kind is not None:
        return "other" if low in ru_names.NOT_SURNAMES else kind
    for candidate in _candidates(low):
        kind = _EXACT_KINDS.get(candidate)
        if kind is None or candidate in ru_names.NOT_SURNAMES:
            continue
        return kind
    return "other"


def is_surname(word: str) -> bool:
    return _kind_of_low(word.casefold()) == "surname"


def is_adjectival_surname(word: str) -> bool:
    return _kind_of_low(word.casefold()) == "surname_adj"


def is_first_name(word: str) -> bool:
    return _kind_of_low(word.casefold()) == "name"


def is_patronymic(word: str) -> bool:
    return _kind_of_low(word.casefold()) == "patronymic"


#: Фамильное окончание с падежным хвостом. Проверяется на самом слове, а не на
#: «обрезанном» стеме: иначе «слово» превращалось бы в «слов» и давало фамилию.
_SURNAME_TAIL_RE = re.compile(
    r"(?:"
    r"(?:ов|ев|ёв|ин|ын)(?:а|у|ым|е|ой|ых|ыми)?"
    r"|(?:ск|цк)(?:ий|ая|ую|им|ом|ой|их|ими)"
    r"|(?:енко|чук)"
    r"|(?:ук|юк)(?:а|у|ом|е)?"
    r"|ян(?:а|у|ом|е)?"
    r"|ич(?:а|у|ем|е)?"
    r"|(?:дзе|швили)"
    r"|[бвгджзклмнпрстфхцчшщьй]ко"
    r")$"
)


@lru_cache(maxsize=1 << 16)
def _surname_by_suffix_low(low: str) -> bool:
    if len(low) < 5:
        return False
    if low in ru_names.NOT_SURNAMES or low in ru_names.COMMON_NON_SURNAMES:
        return False
    return bool(_SURNAME_TAIL_RE.search(low))


def _surname_by_suffix(word: str) -> bool:
    """Фамилия вне словаря, распознанная по окончанию.

    Применяется только к слову с заглавной буквы: одиночное «Петровский»
    в «Петровский район» фамилией не считается.
    """
    return _surname_by_suffix_low(word.casefold())


# --- Адреса ---------------------------------------------------------------

_MAJOR_PREFIXES = (
    "ул", "улица", "пр-т", "просп", "проспект", "пер", "переулок", "ш", "шоссе",
    "бул", "бульвар", "наб", "набережная", "пл", "площадь", "проезд", "туп", "тупик",
    "мкр", "мкр-н", "микрорайон", "г", "город", "пгт", "пос", "посёлок", "поселок",
    "дер", "деревня", "село", "обл", "область", "район", "квартал",
)
_SUB_PREFIXES = (
    "д", "дом", "кв", "квартира", "корп", "корпус", "стр", "строение", "оф",
    "офис", "лит", "литер", "пом", "помещение", "эт", "этаж", "подъезд",
    "владение", "влд",
)
_STREET_PREFIXES = frozenset(
    {"ул", "улица", "пр-т", "просп", "проспект", "пер", "переулок", "ш", "шоссе",
     "бул", "бульвар", "наб", "набережная", "пл", "площадь", "проезд", "туп", "тупик",
     "мкр", "мкр-н", "микрорайон", "квартал"}
)
_ALL_PREFIXES = frozenset(_MAJOR_PREFIXES) | frozenset(_SUB_PREFIXES)

#: Слова, на которых адрес заведомо заканчивается: «ул. Ленина закрыта на ремонт».
_ADDRESS_STOP_WORDS = frozenset(
    """
    и а но или же ли бы не как где что это при за из об о от до для по на в с
    со к у около возле рядом напротив являются является находится находился
    расположен расположена расположено закрыт закрыта закрыто открыт открыта
    """.split()
)

#: Сколько слов может быть в названии улицы или населённого пункта.
_ADDRESS_MAX_WORDS = 6


def _prefix_end(text: str, token: Token) -> int | None:
    """Если токен — адресный префикс, вернуть позицию сразу после него.

    Короткие формы («г», «ул», «д») без точки не считаются префиксом: иначе
    обычные слова и предлоги превращались бы в адреса.
    """
    low = token.text.casefold()
    if low not in _ALL_PREFIXES:
        return None
    end = token.end
    if end < len(text) and text[end] == ".":
        end += 1
    elif len(low) < 4:
        return None
    if end >= len(text) or text[end] not in " \t\u00a0":
        return None
    return end


def find_addresses(text: str, tokens: Sequence[Token] | None = None) -> list[Finding]:
    """Найти адреса со номером дома: «г. Москва, ул. Ленина, д. 15, кв. 3».

    Адрес без номера дома не считается адресом. «Улица Строителей» — ориентир,
    а не адрес доставки: маскировать его нечего, а ложное срабатывание мешает
    читать текст. Это же правило убирает ложные адреса из оборотов вида
    «ул. Ленина закрыта на ремонт».
    """
    tokens = tokens if tokens is not None else tokenize(text)
    findings: list[Finding] = []
    index = 0
    total = len(tokens)
    while index < total:
        token = tokens[index]
        if token.kind != "word":
            index += 1
            continue
        if token.text.casefold() not in _MAJOR_PREFIXES:
            index += 1
            continue
        prefix_end = _prefix_end(text, token)
        if prefix_end is None:
            index += 1
            continue

        cursor = index + 1
        # Точка от сокращения («г.», «ул.») — часть префикса, а не конец адреса.
        if cursor < total and tokens[cursor].kind == "punct" and tokens[cursor].text == ".":
            cursor += 1
        end: int | None = None
        has_number = False
        words = 0
        while cursor < total:
            current = tokens[cursor]
            if current.kind == "punct":
                if current.text == ",":
                    cursor += 1
                    continue
                break
            if current.kind == "word":
                low = current.text.casefold()
                if low in _ALL_PREFIXES and _prefix_end(text, current) is not None:
                    cursor += 1
                    if (
                        cursor < total
                        and tokens[cursor].kind == "punct"
                        and tokens[cursor].text == "."
                    ):
                        cursor += 1
                    continue
                if low in _ADDRESS_STOP_WORDS:
                    break
                words += 1
                if words > _ADDRESS_MAX_WORDS:
                    break
                end = current.end
                cursor += 1
                continue
            if current.kind == "num":
                has_number = True
                end = current.end
                cursor += 1
                continue
            break

        if end is not None and has_number:
            findings.append(
                Finding(token.start, end, "address", text[token.start : end])
            )
            index = cursor
            continue
        index += 1
    return findings


# --- Организации ----------------------------------------------------------

_LEGAL_FORM_PATTERN = (
    r"ООО|ОАО|ЗАО|ПАО|АО|ИП|ФГУП|ГУП|МУП|АНО|НКО|НП|ТСЖ|ЖСК|"
    r"Фонд[а-яё]*|ФОНД[А-ЯЁ]*"
)
#: После юридической формы название может состоять из слов в нижнем регистре
#: («ООО Северный ветер»), но продолжение фразы к названию не относится.
_ORG_STOP_WORDS = (
    r"отгрузил\w*|подписал\w*|подтвердил\w*|сообщил\w*|направил\w*|выполнил\w*|"
    r"принял\w*|является|находится|расположен\w*|действует|и|в|на|по|с|от|до|"
    r"для|при|за|из|о|об|не|как|что|это|со|к|у"
)
_ORG_RE = re.compile(
    r"(?<![\w\-])(?:" + _LEGAL_FORM_PATTERN + r")(?=[\s«»\"“”])"
    r"\s*(?:[«\"“][^»\"”\n]{1,80}[»\"”]"
    r"|[А-ЯЁA-Z][\w\-]*(?:\s+(?!(?:" + _ORG_STOP_WORDS + r")\b)[\w\-]+){0,4})"
)


def find_orgs(text: str) -> list[Finding]:
    return [
        Finding(match.start(), match.end(), "org", match.group(0))
        for match in _ORG_RE.finditer(text)
    ]


# --- ФИО ------------------------------------------------------------------

_STOP_AFTER_SURNAME = frozenset({"район", "района", "область", "области", "улица", "проспект"})


def _gap_is_space(text: str, left: Token, right: Token) -> bool:
    gap = text[left.end : right.start]
    return gap.strip() == "" or gap.strip() == "," or gap.strip() == "."


def _classify_word(low: str) -> str:
    return _kind_of_low(low)


def _classify(token: Token) -> str:
    if token.kind == "init":
        return "initial"
    if token.kind != "word" or not token.text[0].isupper():
        return "other"
    return _classify_word(token.text.casefold())


#: Слова перед фамилией, которые переводят её в нарицательное: «династии Романовых».
_NOT_A_PERSON_CONTEXT = frozenset(
    {"династия", "династии", "династию", "династией", "род", "рода", "роду", "клана", "клан"}
)

#: Падежные формы улиц: «на улице Соколова» — это топоним, а не человек.
_STREET_CONTEXT_WORDS = frozenset(
    {
        "улица", "улицы", "улице", "улицу", "улицей",
        "проспект", "проспекта", "проспекте", "проспекту",
        "переулок", "переулка", "переулке",
        "площадь", "площади", "площадью",
        "набережная", "набережной", "набережную",
        "шоссе", "бульвар", "бульвара", "бульваре",
        "проезд", "проезда", "проезде", "тупик", "тупика",
    }
)


def _previous_word(tokens: Sequence[Token], index: int) -> int | None:
    """Индекс ближайшего слова слева, пропуская точку от сокращения («ул. Пушкина»)."""
    cursor = index - 1
    while cursor >= 0:
        if tokens[cursor].kind in ("word", "init"):
            return cursor
        if tokens[cursor].kind == "punct" and tokens[cursor].text == ".":
            cursor -= 1
            continue
        return None
    return None


def _inside(token: Token, spans: Sequence[Finding]) -> bool:
    return any(span.start <= token.start and token.end <= span.end for span in spans)


def find_persons(
    text: str,
    excluded: Sequence[Finding] = (),
    tokens: Sequence[Token] | None = None,
) -> list[Finding]:
    """Найти ФИО в тексте, пропуская слова внутри адресов и названий организаций."""
    tokens = tokens if tokens is not None else tokenize(text)
    count = len(tokens)
    # Классифицируются только заглавные слова и инициалы: остальные не могут
    # быть частью ФИО, а текст на 100 КБ содержит тысячи служебных слов.
    kinds = [""] * count
    for index in range(count):
        token = tokens[index]
        if token.kind == "init":
            kinds[index] = "init"
        elif token.kind == "word" and token.text[0].isupper():
            kinds[index] = _classify_word(token.text.casefold())
    candidates = [index for index, kind in enumerate(kinds) if kind]
    findings: list[Finding] = []

    def emit(start_index: int, end_index: int) -> None:
        start = tokens[start_index].start
        end = tokens[end_index].end
        if _inside(tokens[start_index], excluded):
            return
        findings.append(Finding(start, end, "person", text[start:end]))

    for index in candidates:
        kind = kinds[index]
        token = tokens[index]
        if kind == "init":
            # «И. И. Иванов»: инициалы перед фамилией.
            cursor = index + 1
            while cursor < count and tokens[cursor].kind == "init":
                cursor += 1
            if cursor < count and tokens[cursor].kind == "word" and tokens[cursor].text[0].isupper():
                if kinds[cursor] == "surname" or (
                    kinds[cursor] in ("", "other") and _surname_by_suffix(tokens[cursor].text)
                ):
                    emit(index, cursor)
            continue

        surname_like = kind in ("surname", "surname_adj") or (
            kind in ("", "other") and _surname_by_suffix(token.text)
        )
        if not surname_like:
            continue

        # Фамилия + (имя | отчество | инициалы), до трёх токенов.
        cursor = index + 1
        collected = 0
        last = index
        while cursor < count and collected < 2:
            nxt = tokens[cursor]
            if not _gap_is_space(text, tokens[last], nxt):
                break
            if nxt.kind == "init":
                collected += 1
                last = cursor
                cursor += 1
                continue
            if kinds[cursor] in ("name", "patronymic"):
                collected += 1
                last = cursor
                cursor += 1
                continue
            break
        if collected:
            emit(index, last)
            continue

        # «Лев Толстой», «Анне Леонидовне Фоминой»: фамилия после имени или отчества.
        previous_index = _previous_word(tokens, index)
        if (
            previous_index is not None
            and kinds[previous_index] in ("name", "patronymic", "init")
            and _gap_is_space(text, tokens[previous_index], token)
        ):
            emit(previous_index, index)
            continue

        # Одиночная фамилия-прилагательное («Толстой полосой», «Белый дом») без
        # имени рядом — это не человек, а обычное слово.
        if kind == "surname_adj":
            continue

        # Одиночная фамилия: маскируется, если это не адресный контекст
        # и не название («Петровский район»).
        followed = tokens[index + 1].text.casefold() if index + 1 < count else ""
        if followed in _STOP_AFTER_SURNAME:
            continue
        if previous_index is not None:
            previous_low = tokens[previous_index].text.casefold()
            if previous_low in _ALL_PREFIXES or previous_low in _STREET_CONTEXT_WORDS:
                continue
            if previous_low in _NOT_A_PERSON_CONTEXT:
                continue
        emit(index, index)

    # «Иван Петрович» без фамилии.
    for index in candidates:
        kind = kinds[index]
        if index + 1 >= count or not kinds[index + 1]:
            continue
        neighbour = kinds[index + 1]
        if (kind == "name" and neighbour == "patronymic") or (
            kind == "patronymic" and neighbour == "name"
        ):
            if _gap_is_space(text, tokens[index], tokens[index + 1]):
                emit(index, index + 1)

    # Одиночное имя маскируется: «Ивану поручили» — это человек.
    for index in candidates:
        if kinds[index] == "name":
            emit(index, index)

    return _coalesce(text, findings)


def _coalesce(text: str, findings: Sequence[Finding]) -> list[Finding]:
    """Слить соприкасающиеся находки одного класса, разделённые только пробелом.

    Без этого «Иванов» и «Иван Иванович», найденные по отдельности, дали бы два
    псевдонима подряд вместо одного.
    """
    if not findings:
        return []
    ordered = sorted(findings, key=lambda f: (f.start, -f.length))
    merged = [ordered[0]]
    for finding in ordered[1:]:
        last = merged[-1]
        if finding.start <= last.end and finding.klass == last.klass:
            merged[-1] = Finding(
                last.start, max(last.end, finding.end), last.klass, text[last.start : max(last.end, finding.end)]
            )
        elif finding.start > last.end and text[last.end : finding.start].strip() == "" and finding.klass == last.klass:
            merged[-1] = Finding(
                last.start, finding.end, last.klass, text[last.start : finding.end]
            )
        else:
            merged.append(finding)
    return merged


def find_lowercase_persons(text: str, tokens: Sequence[Token] | None = None) -> list[Finding]:
    """ФИО строчными и со смешанным регистром: «иван петрович», «Иван петрович».

    Пары, где оба слова с заглавной, разбирает `find_persons`; здесь — случаи, где
    хотя бы одно слово строчное. В чатах и логах их хватает: «пётр петрович» — это
    человек, а не нарицательное. Опора только на словари (имя, отчество, фамилия),
    поэтому обычный текст не страдает: без совпадения по словарю правила нет.
    """
    tokens = tokens if tokens is not None else tokenize(text)
    findings: list[Finding] = []
    for index in range(len(tokens) - 1):
        first, second = tokens[index], tokens[index + 1]
        if first.kind != "word" or second.kind != "word":
            continue
        if not _gap_is_space(text, first, second):
            continue
        if first.text[0].isupper() and second.text[0].isupper():
            # Такие пары уже разобраны в find_persons: второй проход дал бы дубли.
            continue
        low_first = first.text.casefold()
        low_second = second.text.casefold()
        if low_first in ru_names.SURNAMES and low_second in ru_names.FIRST_NAMES:
            last = index + 1
            if last + 1 < len(tokens):
                patronymic = tokens[last + 1]
                if (
                    patronymic.kind == "word"
                    and patronymic.text.casefold() in ru_names.PATRONYMICS
                    and _gap_is_space(text, tokens[last], patronymic)
                ):
                    last += 1
        elif low_first in ru_names.FIRST_NAMES and low_second in ru_names.PATRONYMICS:
            # «Иван Петрович петрович»: имя с заглавной, отчество строчными.
            last = index + 1
        else:
            continue
        start = tokens[index].start
        end = tokens[last].end
        findings.append(Finding(start, end, "person", text[start:end]))
    return findings


def find_ner(text: str) -> list[Finding]:
    """Все находки NER: адреса, организации, ФИО (без слов внутри адресов и организаций)."""
    tokens = tokenize(text)
    addresses = find_addresses(text, tokens)
    orgs = find_orgs(text)
    findings = list(addresses)
    findings.extend(orgs)
    excluded = list(addresses) + list(orgs)
    persons = find_persons(text, excluded, tokens)
    # Проход по строчным и смешанным парам может пересечься с «одиночным именем»
    # из find_persons: без _coalesce получилось бы «иван» + «иван петрович».
    persons.extend(
        finding
        for finding in find_lowercase_persons(text, tokens)
        if not any(span.start <= finding.start and finding.end <= span.end for span in excluded)
    )
    findings.extend(_coalesce(text, persons))
    return findings
