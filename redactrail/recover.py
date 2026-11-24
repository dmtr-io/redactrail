"""Восстановление фразы блокировки по отпечатку из журнала.

Журнал блокировок намеренно не хранит значений: у записи есть класс,
``hash = sha256(value)[:16]``, длина и место в запросе (README: «ничего лишнего
на диске»). Поэтому показать значение «как есть» нельзя — его можно найти:
перечитать тексты сессий и отыскать в них подстроку нужной длины с тем же
отпечатком.

Два прохода:

1. **правила** — те же детекторы, что работали в прокси: находка с совпавшим
   отпечатком сразу даёт значение и класс;
2. **перебор** — если правила с тех пор изменились, проверяются все подстроки
   нужной длины. Перебор дороже, поэтому ограничен бюджетом символов и длиной
   находки.

Найденное значение живёт только в ответе админки: в журналы оно не попадает.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePath
from typing import Any, Mapping

from . import review, scan
from .policy import Policy

#: Сколько символов суммарно разрешено просмотреть за один клик.
DEFAULT_MAX_CHARS = 20_000_000
#: Находки длиннее не перебираем: это уже не «слово или фраза».
MAX_PHRASE_CHARS = 400
#: Радиус окна вокруг находки, символы.
CONTEXT_RADIUS = 200


class RecoverError(RuntimeError):
    """Фразу восстановить нельзя: нет отпечатка, нет сессий или не нашлось."""


@dataclass(frozen=True)
class Match:
    """Одно место, где фраза встретилась: сессия и окно вокруг неё."""

    session: str
    context: str


@dataclass(frozen=True)
class Recovered:
    """Найденная фраза и места, где она встретилась.

    Одна и та же фраза может стоять в разных письмах: журнал хранит только
    отпечаток, поэтому точное место неизвестно. Показываем несколько окон —
    человек узнаёт своё по контексту.
    """

    value: str
    context: str
    session: str
    how: str
    matches: tuple[Match, ...] = ()


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _needle(record: Mapping[str, Any]) -> tuple[str, int]:
    digest = str(record.get("hash") or "").strip()
    try:
        length = int(record.get("length") or 0)
    except (TypeError, ValueError):
        length = 0
    return digest, length


def _block_time(record: Mapping[str, Any]) -> datetime | None:
    """Время блокировки: журнал пишет UTC, но принимаем и наивную строку."""
    raw = str(record.get("time") or "").strip()
    if not raw:
        return None
    try:
        moment = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment


def session_files(root: Path, record: Mapping[str, Any] | None = None) -> list[Path]:
    """Файлы сессий, ближайшие по времени к блокировке — первыми."""
    files = [path for path in root.rglob("session*.jsonl*") if path.is_file()]
    moment = _block_time(record or {})
    if moment is None:
        return sorted(files)
    target = moment.timestamp()
    return sorted(files, key=lambda path: abs(path.stat().st_mtime - target))


def _context(text: str, start: int, end: int, policy: Policy) -> str:
    """Окно вокруг находки: остальные находки заменены метками классов."""
    low = max(0, start - CONTEXT_RADIUS)
    high = min(len(text), end + CONTEXT_RADIUS)
    piece = text[low:high]
    pieces: list[str] = []
    cursor = 0
    for finding in scan.detect(piece, policy):
        if finding.start == start - low and finding.end == end - low:
            continue
        if finding.start < cursor:
            continue
        pieces.append(piece[cursor : finding.start])
        pieces.append(f"<{finding.klass}>")
        cursor = finding.end
    pieces.append(piece[cursor:])
    return "".join(pieces).strip()


def _label(path: Path, root: Path) -> str:
    try:
        return str(PurePath(path).relative_to(root))
    except ValueError:
        return path.name


def find_phrase(
    record: Mapping[str, Any],
    sessions_root: Path | str,
    policy: Policy,
    *,
    max_chars: int = DEFAULT_MAX_CHARS,
    max_matches: int = 3,
) -> Recovered:
    """Найти в сессиях фразу, давшую запись журнала блокировок.

    ``record`` — строка ``blocks-*.jsonl``: ``class``, ``hash``, ``length``,
    ``where``, ``time``. ``RecoverError`` вместо ``None``: админке нужна
    причина, по которой значение не показано.
    """
    digest, length = _needle(record)
    if not digest or length <= 0:
        raise RecoverError("у записи нет хеша и длины: это структурная блокировка, значения у неё нет")
    if length > MAX_PHRASE_CHARS:
        raise RecoverError(f"длина находки {length} символов: такой перебор не делается")

    root = Path(sessions_root)
    if not root.is_dir():
        raise RecoverError(f"каталог сессий не найден: {root}")
    files = session_files(root, record)
    if not files:
        raise RecoverError(f"в каталоге сессий нет файлов: {root}")

    scanned = 0
    seen = 0
    failure: str | None = None
    value = ""
    how = ""
    matches: list[Match] = []

    def remember(session: str, context: str) -> bool:
        """Собрать окно; True — когда мест уже достаточно и можно вернуть ответ."""
        if any(match.context == context for match in matches):
            return False
        matches.append(Match(session=session, context=context))
        return len(matches) >= max_matches

    def result() -> Recovered:
        first = matches[0]
        return Recovered(
            value=value,
            context=first.context,
            session=first.session,
            how=how,
            matches=tuple(matches),
        )

    for path in files:
        try:
            texts = list(review.session_texts(path))
        except review.ReviewError as error:
            # Декомпрессора нет вовсе: остальные файлы прочитаются так же.
            failure = str(error)
            break
        except OSError:
            continue
        seen += 1
        session = _label(path, root)
        for text in texts:
            if length > len(text):
                continue
            scanned += len(text)
            for finding in scan.detect(text, policy):
                if len(finding.value) == length and _digest(finding.value) == digest:
                    value = finding.value
                    how = how or "правило"
                    if remember(session, _context(text, finding.start, finding.end, policy)):
                        return result()
            for start in range(len(text) - length + 1):
                piece = text[start : start + length]
                if _digest(piece) == digest:
                    value = piece
                    how = how or "перебор"
                    if remember(session, _context(text, start, start + length, policy)):
                        return result()
            if matches and scanned >= max_chars:
                return result()
            if scanned >= max_chars:
                raise RecoverError(
                    f"не нашлось: просмотрено {seen} сессий, {scanned} символов — "
                    "дальше не ищем, чтобы клик не занимал минуты"
                )

    if matches:
        return result()
    if failure:
        raise RecoverError(failure)
    raise RecoverError(
        f"фраза не найдена: просмотрено {seen} сессий ({scanned} символов). "
        "Возможно, запрос шёл не из DSH или сессия уже удалена"
    )
