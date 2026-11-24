"""Ночной аудит сессий: ищем то, что правила пропустили.

Логика:

1. Прочитать события сессий DSH (`~/.dsh/sessions`, zstd) и вытащить текстовые блоки.
2. Вырезать из них то, что правила уже нашли: вместо значения — метка класса
   (`<PERSON>`, `<PHONE>`). Тогда модель видит только непокрытое и не может
   «найти» уже замаскированное.
3. Спросить локальную модель (`llama.cpp`, `response_format: json_object`), есть ли
   в остатке персональные данные, и получить цитаты.
4. В отчёт писать только классы, хеши и длины цитат. **Никаких значений.**

Отчёт: `audit/review-YYYY-MM-DD.json`. Модель «чисто» не считается гарантией:
отчёт — повод пополнить правила, а не замена им.

Файлы сессий сжаты zstd в формате с таблицей кадров; читаем через
`compression.zstd` (Python 3.14+). Для запуска аудита нужен Python 3.14 или
`zstd` в PATH — прокси и тесты остаются на 3.12.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from functools import lru_cache
from itertools import islice
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Mapping, Sequence

from . import scan
from .detections import apply_mask
from .policy import DEFAULT_REVIEW_URL, Policy, load_policy
from .winutil import hidden_kwargs
from .runtime import enable_utf8_output

DEFAULT_SESSIONS = Path.home() / ".dsh" / "sessions"
DEFAULT_BASE_URL = DEFAULT_REVIEW_URL
DEFAULT_MODEL = "qwen2.5-coder-7b-instruct-q4_k_m"
MIN_CHARS = 20
MAX_CHUNK_CHARS = 6000
#: Сколько символов перекрытия между фрагментами: сущность на стыке не теряется.
CHUNK_OVERLAP = 400
#: Сколько предложений держать в очереди: старые решённые уходят, когда очередь растёт.
MAX_SUGGESTIONS = 500
#: Версия файла курсора: какие события сессий уже проверены.
CURSOR_VERSION = 1
#: Метки, которыми мы сами заменили найденное: модель не должна считать их находками.
_PLACEHOLDER = re.compile(r"^<[A-Z_]+(_\d+)?(:\d+)?>$")
#: Имя поля или типа блока внутри `where`: «поле 'output_config'», «тип 'video'».
_DETAIL_RE = re.compile(r"(?:ключ|поле|тип|роль)\s+'([^']+)'")
#: Имена, которые санитайзер уже принимает: предлагать их к разрешению бессмысленно.
_KNOWN_SAFE = frozenset({"name", "description", "input_schema", "defer_loading"})
#: Классы, для которых цитата-идентификатор — не персональные данные.
IDENTIFIER_CLASSES = frozenset({"person", "org", "address"})
#: Строчный ASCII-токен без пробелов: имя файла, каталога, переменной, код.
_IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")


def looks_like_identifier(quote: str) -> bool:
    """Похоже на технический идентификатор, а не на имя человека или организации.

    ``dsh-runtimes``, ``anonymous-user-id``, ``config.json`` — имена файлов,
    каталогов и переменных. Для person/org/address такие цитаты — шум модели,
    а не пропуск правил. ``Smith-Jones`` под правило не попадает: регистр —
    признак имени.
    """
    token = str(quote).strip()
    if not token or " " in token:
        return False
    if not _IDENTIFIER_RE.match(token):
        return False
    return any(char in token for char in "-_.")

SYSTEM_PROMPT = (
    "Ты аудитор приватности. Тебе дают фрагмент рабочего журнала, в котором уже "
    "заменены известные персональные данные на метки вида <PERSON_1>, <PHONE_2>.\n"
    "Число после двоеточия — сколько символов исходного значения скрыто: "
    "<PERSON_1:6> — шесть символов. Если вплотную к метке стоит текст, который мог "
    "быть частью того же значения (отчество, хвост адреса, лишние цифры телефона), "
    "это пропуск — сообщи о нём отдельной находкой.\n"
    "Найди то, что осталось незамеченным: ФИО, телефоны, адреса, e-mail, паспорт, "
    "СНИЛС, ИНН, ОГРН, номера счетов и карт, названия организаций, логины, "
    "токены, ключи, пароли и иную персональную или конфиденциальную информацию.\n"
    "Имена файлов, каталогов, путей, переменных, полей и другие технические "
    "идентификаторы (например, dsh-runtimes или anonymous-user-id) персональными "
    "данными не являются — о них не сообщай.\n"
    "Ответ — строго JSON без пояснений: "
    '{"findings": [{"category": "person", "quote": "точная подстрока текста"}], "clean": true}\n'
    "Цитата обязана быть дословной подстрокой текста. Если ничего не найдено — "
    '{"findings": [], "clean": true}. Не выдумывай данные.'
)


class ReviewError(RuntimeError):
    """Аудит невозможен: нет декомпрессора, недоступна модель и т. п."""


@lru_cache(maxsize=1)
def _python314() -> list[str] | None:
    """Интерпретатор, у которого есть ``compression.zstd`` (3.14+).

    Админка штатно запускается на 3.12 из бандла DSH, а сессии DSH сжаты zstd:
    без запасного интерпретатора восстановление фразы и аудит упирались бы в
    отсутствие декомпрессора. `py -3.14` есть на машинах с установленным 3.14.
    """
    import shutil
    import subprocess

    for command in (["py", "-3.14"], ["python3.14"], ["python"]):
        binary = shutil.which(command[0])
        if not binary:
            continue
        try:
            check = subprocess.run(
                [binary, *command[1:], "-c", "import compression.zstd"],
                capture_output=True,
                timeout=20,
                **hidden_kwargs(),
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if check.returncode == 0:
            return [binary, *command[1:]]
    return None


def decompress_session(path: Path) -> bytes:
    """Прочитать файл сессии: обычный JSONL или zstd с таблицей кадров."""
    if path.suffix != ".zstd":
        return path.read_bytes()
    try:  # Python 3.14+
        from compression.zstd import ZstdFile  # type: ignore[import-not-found]

        with ZstdFile(path, "rb") as handle:
            return handle.read()
    except ImportError:
        pass
    import shutil
    import subprocess

    binary = shutil.which("zstd")
    if binary:
        result = subprocess.run([binary, "-dc", str(path)], capture_output=True, **hidden_kwargs())
        if result.returncode == 0:
            return result.stdout
    interpreter = _python314()
    if interpreter:
        code = (
            "import sys, compression.zstd as z;"
            "sys.stdout.buffer.write(z.ZstdFile(sys.argv[1], 'rb').read())"
        )
        try:
            result = subprocess.run([*interpreter, "-c", code, str(path)], capture_output=True, timeout=300, **hidden_kwargs())
        except (OSError, subprocess.SubprocessError):
            result = None
        if result is not None and result.returncode == 0:
            return result.stdout
    raise ReviewError(
        "не читается zstd-сессия: нужен Python 3.14+ (compression.zstd), zstd в PATH "
        "или запуск админки через admin.cmd"
    )


def session_lines(path: Path) -> list[str]:
    """Строки событий сессии без пустых: номер строки — единица курсора аудита."""
    data = decompress_session(path)
    # utf-8-sig: файл, сохранённый с BOM, иначе не разберётся и «потеряет» все события.
    return [line for line in data.decode("utf-8-sig", "replace").splitlines() if line.strip()]


def _texts_of_event(event: object) -> Iterator[str]:
    """Текстовые блоки одного события сессии."""
    if not isinstance(event, dict):
        return
    kind = event.get("type")
    if kind == "system/message":
        return
    payload = event.get("data")
    if not isinstance(payload, dict):
        return
    blocks: Sequence[Any] = ()
    if kind == "user/message":
        blocks = payload.get("content") or ()
    elif kind in ("assistant/message", "tool/result"):
        message = payload.get("message")
        if isinstance(message, dict):
            blocks = message.get("content") or ()
    for block in blocks:
        if not isinstance(block, dict):
            continue
        if isinstance(block.get("text"), str):
            yield block["text"]
        elif block.get("type") == "tool-call" and isinstance(block.get("arguments"), str):
            # Аргументы инструмента — тоже текст, и в них бывают пути и имена.
            yield block["arguments"]


def texts_from_lines(
    lines: Sequence[str], since_ms: int | None = None, start_line: int = 0
) -> Iterator[tuple[int, str]]:
    """Текст события вместе с номером его строки: по номеру двигается курсор."""
    for number in range(max(0, int(start_line)), len(lines)):
        try:
            event = json.loads(lines[number])
        except json.JSONDecodeError:
            continue
        if since_ms is not None:
            stamp = event.get("time") if isinstance(event, dict) else None
            if isinstance(stamp, (int, float)) and stamp < since_ms:
                continue
        for text in _texts_of_event(event):
            yield number, text


def session_texts_with_lines(
    path: Path, since_ms: int | None = None, start_line: int = 0
) -> Iterator[tuple[int, str]]:
    """То же, что ``session_texts``, но с номерами строк событий."""
    yield from texts_from_lines(session_lines(path), since_ms, start_line)


def session_texts(path: Path, since_ms: int | None = None) -> Iterator[str]:
    """Текстовые блоки из событий сессии: сообщения, размышления, результаты инструментов.

    Системный промпт пропускается: это шаблон DSH, он огромный и одинаковый в каждой
    сессии, а персональных данных там нет — только пути, которые и так маскируются.
    ``since_ms`` отсекает события старше периода: файл мог измениться сегодня, а
    разговор внутри — недельной давности.
    """
    for _, text in session_texts_with_lines(path, since_ms):
        yield text


def _prefix_digest(lines: Sequence[str], count: int) -> str:
    """Отпечаток первых ``count`` строк: доказательство, что файл не переписан.

    Сессии DSH только дописываются, поэтому префикс обработанных событий не меняется.
    Если отпечаток не сошёлся, файл переписали (или обрезали) — курсор по нему
    недействителен, и аудит начинает файл заново.
    """
    if count <= 0:
        return ""
    return hashlib.sha256("\n".join(lines[:count]).encode("utf-8")).hexdigest()[:16]


def load_cursor(path: Path | str | None) -> dict[str, dict]:
    """Курсор аудита: относительный путь сессии → ``{events, digest}``."""
    if not path:
        return {}
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    files = data.get("files") if isinstance(data, dict) else None
    if not isinstance(files, dict):
        return {}
    return {str(key): value for key, value in files.items() if isinstance(value, dict)}


def save_cursor(path: Path | str | None, files: Mapping[str, Mapping[str, Any]]) -> None:
    """Записать курсор атомарно: половина файла хуже его отсутствия."""
    if not path:
        return
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "v": CURSOR_VERSION,
        "saved_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "files": {str(key): dict(value) for key, value in files.items()},
    }
    temp = target.with_suffix(target.suffix + ".tmp")
    temp.write_text(json.dumps(payload, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    os.replace(temp, target)


def chunks_with_offsets(text: str) -> list[tuple[int, str]]:
    """Длина на фрагменты и вернуть смещение каждого в исходном тексте."""
    if len(text) <= MAX_CHUNK_CHARS:
        return [(0, text)]
    step = MAX_CHUNK_CHARS - CHUNK_OVERLAP
    chunks: list[tuple[int, str]] = []
    start = 0
    while start < len(text):
        chunks.append((start, text[start : start + MAX_CHUNK_CHARS]))
        if start + MAX_CHUNK_CHARS >= len(text):
            break
        start += step
    return chunks


def split_chunks(text: str) -> list[str]:
    """Фрагменты без смещений (нужно админке и тестам)."""
    return [chunk for _, chunk in chunks_with_offsets(text)]


def read_block(sessions_root: Path, item: Mapping[str, Any]) -> str | None:
    """Прочитать текстовый блок сессии по ссылке из предложения."""
    root = sessions_root.resolve()
    relative = str(item.get("file") or "")
    path = (root / relative).resolve()
    try:
        path.relative_to(root)
    except (ValueError, OSError):
        return None
    index = int(item.get("chunk") or 0)
    try:
        texts = list(islice(session_texts(path), index + 1))
    except Exception:  # noqa: BLE001 - битая сессия не должна ронять вызов
        return None
    if index >= len(texts):
        return None
    return texts[index]


def find_quote(sessions_root: Path, item: Mapping[str, Any]) -> str | None:
    """Найти исходную цитату по длине и хешу: хеш считается по исходному тексту."""
    raw = read_block(sessions_root, item)
    if raw is None:
        return None
    length = int(item.get("length") or 0)
    digest = str(item.get("hash") or "")
    if length <= 0 or length > len(raw) or not digest:
        return None
    # Смещение (если известно) проверяем первым: короткие хвосты вроде «7» иначе
    # находились бы в первом же подходящем месте блока.
    offset = int(item.get("offset") or -1)
    if 0 <= offset <= len(raw) - length:
        candidate = raw[offset : offset + length]
        if hashlib.sha256(candidate.encode("utf-8")).hexdigest()[:16] == digest:
            return candidate
    for start in range(0, len(raw) - length + 1):
        candidate = raw[start : start + length]
        if hashlib.sha256(candidate.encode("utf-8")).hexdigest()[:16] == digest:
            return candidate
    return None


def mask_with_map(text: str, policy: Policy) -> tuple[str, list[int], list[int], int]:
    """Маскировать известное, сохранив карту «символ маски → исходный участок».

    Метки нумеруются по значению: два разных человека в одном блоке получат
    `<PERSON_1>` и `<PERSON_2>`, один и тот же — один номер. Возвращает маску,
    для каждого её символа начало и конец исходного участка, и число находок.
    """
    findings = scan.detect(text, policy)
    maskable = sorted(
        (finding for finding in findings if not policy.is_block(finding.klass)),
        key=lambda finding: finding.start,
    )
    counters: dict[str, dict[str, int]] = {}
    pieces: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    position = 0
    for finding in maskable:
        if finding.start < position:
            continue  # пересечение уже закрыто
        between = text[position : finding.start]
        pieces.append(between)
        starts.extend(range(position, finding.start))
        ends.extend(range(position + 1, finding.start + 1))
        per_class = counters.setdefault(finding.klass, {})
        if finding.value not in per_class:
            per_class[finding.value] = len(per_class) + 1
        # Двоеточие и длина — «покрытие»: модель видит, сколько символов скрыто,
        # и может заметить, что рядом остался хвост того же значения. Значений
        # в метке нет, только длина.
        covered = finding.end - finding.start
        label = f"<{finding.klass.upper()}_{per_class[finding.value]}:{covered}>"
        pieces.append(label)
        starts.extend([finding.start] * len(label))
        ends.extend([finding.end] * len(label))
        position = finding.end
    tail = text[position:]
    pieces.append(tail)
    starts.extend(range(position, len(text)))
    ends.extend(range(position + 1, len(text) + 1))
    return "".join(pieces), starts, ends, len(maskable)


def mask_known(text: str, policy: Policy) -> tuple[str, int]:
    """Заменить известные находки метками классов; вернуть текст и число находок."""
    masked, _, _, known = mask_with_map(text, policy)
    return masked, known


#: Классы, у которых «продолжение» значения — цифры: телефон, счёт, ИНН и т. п.
DIGIT_CLASSES = frozenset(
    {"phone", "account", "card", "inn", "snils", "ogrn", "kpp", "bik", "passport"}
)
#: Классы, у которых «продолжение» — буквы: имя, организация, адрес.
LETTER_CLASSES = frozenset({"person", "org", "address"})
#: Сколько символов соседнего участка считать хвостом, а не соседним словом.
BOUNDARY_RUN = 40
#: Метка маски в тексте: `<PERSON_1:6>` (класс, номер, покрытие).
_LABEL_RE = re.compile(r"<([A-Z_]+)_(\d+)(?::(\d+))?>")
def find_boundaries(
    raw: str, masked: str, starts: Sequence[int], ends: Sequence[int]
) -> list[dict]:
    """Найти маски, у которых соседний символ выглядит продолжением значения.

    Сравниваются не значения, а классы символов: буква вплотную к маске имени,
    организации или адреса и цифра вплотную к маске телефона, счёта, ИНН и т. п.
    Пробел или знак препинания — нормальная граница и разрывом не считается.
    Возвращает словари с классом, стороной, хешем и смещением соседнего участка.
    """
    found: list[dict] = []
    seen: set[tuple[str, str, str, int]] = set()
    for match in _LABEL_RE.finditer(masked):
        klass = match.group(1).lower()
        if klass in DIGIT_CLASSES:
            checker, kind = str.isdigit, "digit"
        elif klass in LETTER_CLASSES:
            checker, kind = str.isalpha, "letter"
        else:
            continue
        raw_start = starts[match.start()]
        raw_end = ends[match.end() - 1]
        if raw_start < 0 or raw_end <= raw_start or raw_end > len(raw):
            continue
        for side, begin in (("before", raw_start), ("after", raw_end)):
            if side == "before":
                cursor = begin - 1
                while cursor >= 0 and begin - cursor <= BOUNDARY_RUN and checker(raw[cursor]):
                    cursor -= 1
                start, stop = cursor + 1, begin
            else:
                cursor = begin
                while cursor < len(raw) and cursor - begin < BOUNDARY_RUN and checker(raw[cursor]):
                    cursor += 1
                start, stop = begin, cursor
            if stop <= start:
                continue
            piece = raw[start:stop]
            digest = hashlib.sha256(piece.encode("utf-8")).hexdigest()[:16]
            key = (klass, side, digest, len(piece))
            if key in seen:
                continue
            seen.add(key)
            found.append(
                {
                    "class": klass,
                    "side": side,
                    "kind": kind,
                    "hash": digest,
                    "length": len(piece),
                    "offset": start,
                }
            )
    return found


@dataclass
class ReviewFinding:
    """Одна находка модели: класс и хеш цитаты. Значение не хранится."""

    session: str
    category: str
    digest: str
    length: int
    chunk: int
    part: int = 0
    source: str = ""
    index: int = 0


def block_detail(where: str) -> str | None:
    """Достать из места блокировки имя поля или типа: «поле 'output_config'»."""
    match = _DETAIL_RE.search(where or "")
    return match.group(1) if match else None


def block_suggestions(directory: Path, days: int = 7, policy: Policy | None = None) -> list[dict]:
    """Предложения по журналу блокировок: разрешить поле, тип блока или роль.

    Детерминированный разбор без модели. Уже разрешённое в политике не предлагаем,
    иначе очередь заполняется тем, что и так работает.
    """
    allowed_fields: set[str] = set()
    allowed_blocks: set[str] = set()
    allowed_roles: set[str] = set()
    if policy is not None:
        allowed_fields = set(policy.request.allowed_fields)
        allowed_blocks = set(policy.request.allowed_block_types)
        allowed_roles = set(policy.request.allowed_roles)
    cutoff = date.today() - timedelta(days=days)
    groups: dict[tuple[str, str, str], int] = {}
    for path in sorted(directory.glob("blocks-*.jsonl")):
        day = _file_date(path)
        if day is None or day < cutoff:
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        for line in lines:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            klass = str(record.get("class") or "")
            where = str(record.get("where") or "")
            detail = block_detail(where)
            if klass not in ("unknown_field", "unknown_block") or not detail:
                continue
            if detail in _KNOWN_SAFE:
                continue  # санитайзер это уже принимает
            if "роль" in where:
                kind, allowed = "add_allowed_role", allowed_roles
            elif klass == "unknown_field":
                kind, allowed = "add_allowed_field", allowed_fields
            else:
                kind, allowed = "add_allowed_block", allowed_blocks
            if detail in allowed:
                continue  # уже разрешено — предлагать нечего
            key = (kind, detail, klass)
            groups[key] = groups.get(key, 0) + 1
    items: list[dict] = []
    for (kind, detail, klass), count in groups.items():
        identifier = "b-" + hashlib.sha256(f"{kind}:{detail}".encode("utf-8")).hexdigest()[:10]
        items.append(
            {
                "id": identifier,
                "class": klass,
                "kind": kind,
                "payload": detail,
                "verdict": "частое срабатывание",
                "count": count,
                "window": f"поле или тип: {detail}",
                "action": f"разрешить {detail}",
            }
        )
    return items


def merge_suggestions(directory: Path, day: str, items: Sequence[dict]) -> int:
    """Добавить предложения в файл дня, не дублируя по id. Возвращает число новых."""
    if not items:
        return 0
    path = directory / f"suggestions-{day}.json"
    existing: list[dict] = []
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(loaded, list):
            existing = [item for item in loaded if isinstance(item, dict)]
    except (OSError, json.JSONDecodeError):
        existing = []
    known = {str(item.get("id")) for item in existing}
    added = 0
    for item in items:
        if str(item.get("id")) in known:
            continue
        known.add(str(item.get("id")))
        existing.append(item)
        added += 1
    directory.mkdir(parents=True, exist_ok=True)
    if len(existing) > MAX_SUGGESTIONS:
        existing = existing[-MAX_SUGGESTIONS:]
    path.write_text(json.dumps(existing, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return added


def _file_date(path: Path) -> date | None:
    match = re.search(r"(\d{4}-\d{2}-\d{2})", path.name)
    if not match:
        return None
    try:
        return date.fromisoformat(match.group(1))
    except ValueError:
        return None


def _write_suggestions(
    report: ReviewReport, directory: Path, findings_by_session: list[dict]
) -> int:
    """Сложить находки аудита в очередь: только ссылки, без значений."""
    items: list[dict] = []
    for finding in findings_by_session:
        # id учитывает файл: одинаковый текст в разных сессиях — разные находки.
        identity = f"{finding['file']}:{finding['chunk']}:{finding['hash']}"
        identifier = "r-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:12]
        items.append(
            {
                "id": identifier,
                "class": finding["class"],
                "kind": "missed_pii",
                "verdict": "пропуск правил",
                "count": 1,
                "window": "найдено моделью в сессии; значение по клику",
                "action": "посмотреть значение и добавить правило",
                "file": finding["file"],
                "chunk": finding["chunk"],
                "part": finding.get("part", 0),
                "hash": finding["hash"],
                "length": finding["length"],
            }
        )
    return merge_suggestions(directory, report.day, items)


@dataclass
class ReviewReport:
    day: str
    model: str
    run_id: str = ""
    started_at: str = ""
    finished_at: str = ""
    sessions: int = 0
    chunks: int = 0
    masked_known: int = 0
    cancelled: bool = False
    #: Человеческая курсор: сколько событий пропущено как уже проверенные.
    resumed: bool = False
    skipped_events: int = 0
    findings: list[ReviewFinding] = field(default_factory=list)
    boundaries: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "id": self.run_id,
            "date": self.day,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "model": self.model,
            "sessions": self.sessions,
            "chunks": self.chunks,
            "masked_known": self.masked_known,
            "cancelled": self.cancelled,
            "resumed": self.resumed,
            "skipped_events": self.skipped_events,
            "findings": [
                {
                    "session": finding.session,
                    "class": finding.category,
                    "hash": finding.digest,
                    "length": finding.length,
                    "chunk": finding.chunk,
                    "part": finding.part,
                }
                for finding in self.findings
            ],
            "boundaries": self.boundaries,
            "errors": self.errors,
        }


class LocalReviewer:
    """Клиент llama.cpp/OpenAI-совместимого эндпоинта."""

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        model: str = DEFAULT_MODEL,
        timeout: int = 180,
    ) -> None:
        self.base_url = base_url
        self.model = model
        self.timeout = timeout

    @property
    def models_url(self) -> str:
        base = self.base_url.rstrip("/")
        if base.endswith("/chat/completions"):
            return base[: -len("/chat/completions")] + "/models"
        return base + "/models"

    def available(self) -> list[str]:
        """Какие модели предлагает хост. Нужно, чтобы не запускать заведомо битый прогон."""
        request = urllib.request.Request(self.models_url, method="GET")
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                data = json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, OSError, json.JSONDecodeError) as error:
            raise ReviewError(f"хост модели недоступен: {error}") from error
        entries = data.get("data") or data.get("models") or []
        names: list[str] = []
        for item in entries:
            if isinstance(item, dict):
                name = item.get("id") or item.get("name")
                if name:
                    names.append(str(name))
        return names

    def ensure_available(self) -> None:
        """Проверить, что нужная модель есть на хосте, и назвать доступные."""
        names = self.available()
        if self.model in names:
            return
        raise ReviewError(
            f"модели {self.model!r} нет на хосте; доступны: {', '.join(names) or 'ничего'}"
        )

    def ask_json(self, text: str, system_prompt: str = SYSTEM_PROMPT) -> dict:
        """Один запрос к модели, ответ — объект JSON (для правил, не для находок)."""
        payload = {
            "model": self.model,
            "temperature": 0,
            "max_tokens": 600,
            "stream": False,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": text},
            ],
        }
        request = urllib.request.Request(
            self.base_url,
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, OSError, json.JSONDecodeError) as error:
            raise ReviewError(f"модель недоступна: {error}") from error
        try:
            content = body["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as error:
            raise ReviewError(f"неожиданный ответ модели: {body!r:.200}") from error
        return parse_json_object(content)

    def ask(self, text: str) -> list[dict]:
        data = self.ask_json(text)
        items = data.get("findings") if isinstance(data, dict) else None
        if not isinstance(items, list):
            return []
        return meaningful_findings(
            [
                {
                    "category": str(item.get("category") or "unknown")[:40],
                    "quote": item.get("quote") or "",
                }
                for item in items
                if isinstance(item, dict)
            ]
        )


def meaningful_findings(items: Sequence[dict]) -> list[dict]:
    """Убрать мусор: заглушки (`<EMAIL>`) и слишком короткие «цитаты»."""
    result: list[dict] = []
    for item in items:
        quote = str(item.get("quote") or "").strip()
        if len(quote) < 4 or not any(char.isalnum() for char in quote):
            continue
        if _PLACEHOLDER.match(quote):
            continue
        if str(item.get("category")) in IDENTIFIER_CLASSES and looks_like_identifier(quote):
            continue  # идентификатор, а не имя
        result.append({"category": str(item.get("category") or "unknown")[:40], "quote": quote})
    return result


def parse_json_object(content: str) -> dict:
    """Достать JSON-объект из ответа модели; код-блоки и мусор вокруг допускаются."""
    text = content.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end < start:
        return {}
    try:
        data = json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def parse_findings(content: str) -> list[dict]:
    """Разобрать ответ модели; код-блоки и мусор вокруг JSON допускаются."""
    data = parse_json_object(content)
    items = data.get("findings") if isinstance(data, dict) else None
    if not isinstance(items, list):
        return []
    result: list[dict] = []
    for item in items:
        if isinstance(item, dict) and isinstance(item.get("quote"), str) and item["quote"].strip():
            result.append(
                {
                    "category": str(item.get("category") or "unknown")[:40],
                    "quote": item["quote"],
                }
            )
    return result


def session_files(root: Path, days: int = 7) -> list[Path]:
    cutoff = time.time() - days * 86400
    files: list[Path] = []
    for path in root.rglob("session.*.jsonl*"):
        try:
            if path.stat().st_mtime >= cutoff:
                files.append(path)
        except OSError:
            continue
    return sorted(files)


def _resume_line(entry: Mapping[str, Any] | None, lines: Sequence[str], resume: bool) -> int:
    """С какой строки продолжать: 0 — файл не трогали или курсор не сошёлся."""
    if not resume or not entry:
        return 0
    try:
        done = int(entry.get("events") or 0)
    except (TypeError, ValueError):
        return 0
    digest = str(entry.get("digest") or "")
    if 0 < done <= len(lines) and _prefix_digest(lines, done) == digest:
        return done
    return 0


def run_review(
    sessions_root: Path,
    policy: Policy,
    reviewer: Callable[[str], list[dict]] | None,
    days: int = 7,
    limit: int = 0,
    per_session: int = 0,
    report_dir: Path | None = None,
    model: str = DEFAULT_MODEL,
    should_stop: Callable[[], bool] | None = None,
    on_progress: Callable[[int], None] | None = None,
    cursor_path: Path | None = None,
    resume: bool = False,
) -> ReviewReport:
    """Человеческая по всем сессиям за период.

    ``limit=0`` и ``per_session=0`` означают «без ограничения»: по умолчанию
    проверяется весь текст. Остановить долгий прогон можно через ``should_stop``.

    ``cursor_path`` — файл, где запоминается, какие события сессий уже проверены.
    ``resume=True`` пропускает их; ``resume=False`` проверяет всё окно заново, но
    всё равно обновляет курсор, чтобы следующее «продолжить» не повторяло работу.
    """
    report = ReviewReport(
        day=date.today().isoformat(),
        model=model,
        run_id=uuid.uuid4().hex[:12],
        started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
    )
    files = session_files(sessions_root, days)
    report.sessions = len(files)
    processed = 0
    suggestions: list[dict] = []
    boundaries: list[dict] = []

    cursor_in = load_cursor(cursor_path)
    cursor_out: dict[str, dict] = dict(cursor_in)

    seen_findings: set[tuple[str, int, str]] = set()
    since_ms = int((time.time() - days * 86400) * 1000) if days else None
    for path in files:
        session_name = hashlib.sha256(path.parent.name.encode("utf-8")).hexdigest()[:12]
        try:
            relative = str(path.relative_to(sessions_root))
        except ValueError:
            relative = path.name
        try:
            lines = session_lines(path)
        except ReviewError as error:
            report.errors.append(f"{session_name}: {error}")
            continue
        start_line = _resume_line(cursor_in.get(relative), lines, resume)
        if start_line:
            report.resumed = True
            report.skipped_events += start_line
        used = 0
        index = -1
        last_done = start_line - 1
        try:
            # Идём по всему файлу, но проверяем только строки после курсора:
            # index текста остаётся сквозным, и идентификаторы находок не «съезжают».
            for number, current in texts_from_lines(lines, since_ms, 0):
                index += 1
                if number < start_line:
                    continue
                if report.cancelled:
                    break
                if (limit and processed >= limit) or (per_session and used >= per_session):
                    break
                if len(current.strip()) < MIN_CHARS:
                    last_done = number
                    continue
                masked, starts, ends, known = mask_with_map(current, policy)
                report.masked_known += known
                boundaries += [
                    {**item, "session": session_name, "file": relative, "chunk": index}
                    for item in find_boundaries(current, masked, starts, ends)
                ]
                stopped = False
                for part, (offset, chunk) in enumerate(chunks_with_offsets(masked)):
                    if report.cancelled:
                        stopped = True
                        break
                    if (limit and processed >= limit) or (per_session and used >= per_session):
                        stopped = True
                        break
                    if should_stop is not None and should_stop():
                        report.cancelled = True
                        stopped = True
                        break
                    report.chunks += 1
                    processed += 1
                    used += 1
                    if on_progress is not None:
                        on_progress(processed)
                    if reviewer is None:
                        continue
                    try:
                        findings = reviewer(chunk)
                    except ReviewError as error:
                        report.errors.append(f"{session_name}: {error}")
                        continue
                    for item in findings:
                        quote = item["quote"]
                        position = chunk.find(quote)
                        if position < 0:
                            continue  # модель выдумала цитату — пропускаем
                        if item["category"] not in policy.actions:
                            continue  # класс вне политики: url, mcp и прочее
                        if len(quote) < 4:
                            continue  # «abc», «xyz» — обрывки, не сущности
                        if item["category"] in IDENTIFIER_CLASSES and looks_like_identifier(quote):
                            continue  # dsh-runtimes, anonymous-user-id — не ПДн
                        first = offset + position
                        last = first + len(quote) - 1
                        if last >= len(starts):
                            continue
                        # Исходный участок: если цитата захватила метку, берём всё значение.
                        raw_start = starts[first]
                        raw_end = ends[last]
                        if raw_end <= raw_start:
                            continue
                        raw_quote = current[raw_start:raw_end]
                        digest = hashlib.sha256(raw_quote.encode("utf-8")).hexdigest()[:16]
                        if (session_name, index, digest) in seen_findings:
                            continue
                        seen_findings.add((session_name, index, digest))
                        report.findings.append(
                            ReviewFinding(
                                session=session_name,
                                category=item["category"],
                                digest=digest,
                                length=len(raw_quote),
                                chunk=index,
                                part=part,
                            )
                        )
                        suggestions.append(
                            {
                                "class": item["category"],
                                "file": relative,
                                "chunk": index,
                                "part": part,
                                "hash": digest,
                                "length": len(raw_quote),
                            }
                        )
                if stopped:
                    break
                last_done = number
        except ReviewError as error:
            report.errors.append(f"{session_name}: {error}")
        if last_done >= start_line:
            cursor_out[relative] = {
                "events": last_done + 1,
                "digest": _prefix_digest(lines, last_done + 1),
            }

    report.boundaries = boundaries
    save_cursor(cursor_path, cursor_out)
    if report_dir is not None:
        report.finished_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        report_dir.mkdir(parents=True, exist_ok=True)
        # Имя уникально: повторный прогон за день не затирает предыдущий отчёт.
        target = report_dir / f"review-{report.day}-{report.run_id}.json"
        target.write_text(
            json.dumps(report.as_dict(), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        _write_suggestions(report, report_dir, suggestions)
    return report


def main(argv: list[str] | None = None) -> int:
    enable_utf8_output()
    parser = argparse.ArgumentParser(description="Ночной аудит сессий DSH")
    parser.add_argument("--sessions", default=str(DEFAULT_SESSIONS))
    parser.add_argument("--days", type=int, default=7)
    parser.add_argument("--limit", type=int, default=0, help="0 — весь текст")
    parser.add_argument("--per-session", type=int, default=0, help="0 — вся сессия")
    parser.add_argument("--out", default="audit")
    parser.add_argument("--policy", default=None)
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--no-llm", action="store_true", help="только извлечь и замаскировать, без модели")
    parser.add_argument(
        "--resume",
        action="store_true",
        help="продолжить с места остановки: проверять только новые события",
    )
    parser.add_argument(
        "--cursor",
        default=None,
        help="файл курсора; по умолчанию state/audit-cursor.json рядом с каталогом отчётов",
    )
    args = parser.parse_args(argv)

    policy = load_policy(args.policy)
    reviewer: Callable[[str], list[dict]] | None = None
    if not args.no_llm:
        client = LocalReviewer(args.base_url, args.model)
        client.ensure_available()  # иначе прогон молча закончится ошибками
        reviewer = client.ask
    cursor = Path(args.cursor) if args.cursor else Path(args.out).resolve().parent / "state" / "audit-cursor.json"
    try:
        report = run_review(
            Path(args.sessions),
            policy,
            reviewer,
            days=args.days,
            limit=args.limit,
            per_session=args.per_session,
            report_dir=Path(args.out),
            model=args.model,
            cursor_path=cursor,
            resume=args.resume,
        )
    except ReviewError as error:
        print(f"[review] {error}", file=sys.stderr)
        return 2
    print(
        f"[review] сессий {report.sessions}, фрагментов {report.chunks}, "
        f"замаскировано правилами {report.masked_known}, находок модели {len(report.findings)}, "
        f"разрывов маски {len(report.boundaries)}, "
        f"ошибок {len(report.errors)}"
        + (f", пропущено по курсору событий {report.skipped_events}" if report.resumed else "")
    )
    for finding in report.findings[:20]:
        print(f"  {finding.category:12} {finding.digest} len={finding.length} session={finding.session}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
