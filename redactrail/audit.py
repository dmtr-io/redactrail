"""Журнал запросов и счётчики: что замаскировано и что заблокировано.

Пишется только статистика: классы находок, количество, размер запроса, режим.
Значений и фрагментов текста здесь нет и быть не может — иначе журнал сам стал
бы утечкой. Этого достаточно, чтобы ответить на вопросы «работает ли маскировка»
и «что чаще всего срабатывает», не раскрывая содержимого.

Два счётчика по классам отвечают на разные вопросы:

* ``masked`` — сколько раз сработало правило в этом запросе;
* ``new`` — какие псевдонимы встретились **впервые за сутки**. Псевдоним
  (`[[PERSON_AB12CD34EF]]`) стабилен для значения, поэтому сумма ``new`` по дню
  даёт число разных замаскированных значений, а не число срабатываний. Без него
  сводка «за сегодня» умножалась бы на число запросов: DSH пересылает всю
  переписку в каждом запросе, и одни и те же имена считались бы заново.

В ``new`` попадает только хвост псевдонима (10 hex-символов), без класса в тексте
и без значения: восстановить значение по нему нельзя.

Формат: JSONL, строка на событие, поле ``v`` — версия схемы строки. Дозапись идёт
одним ``os.write`` с ``O_APPEND`` под блокировкой: строки не перемешаются, даже если
пишут несколько потоков. Устаревшие файлы удаляются целиком по дате в имени.
"""

from __future__ import annotations

import json
import os
import re
import threading
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Iterable, Mapping

#: Версия схемы строки журнала. Меняется, когда меняется набор полей.
#: 2 — появилось поле ``new``: впервые встреченные псевдонимы за сутки.
RECORD_VERSION = 2
#: Версии, которые журнал ещё принимает при проверке: старые файлы не переписываем.
SUPPORTED_VERSIONS = (1, 2)

_DATE_IN_NAME = re.compile(r"(\d{4}-\d{2}-\d{2})")


def _token_suffix(token: str) -> str:
    """Хвост псевдонима: ``[[PERSON_AB12CD34EF]]`` → ``AB12CD34EF``.

    В журнал идёт только он. Этого достаточно, чтобы не посчитать одно значение
    дважды, но недостаточно, чтобы восстановить само значение.
    """
    return str(token).rsplit("_", 1)[-1].rstrip("]")

#: Сколько на файл. `O_APPEND` не гарантирует атомарность записи между
#: потоками на Windows, поэтому внутри процесса дозапись сериализуется.
_APPEND_LOCKS: dict[str, threading.Lock] = {}
_APPEND_LOCKS_GUARD = threading.Lock()


def _new_pairs(record: Mapping[str, object]) -> dict[str, list[str]]:
    """Поле ``new`` записи: класс → хвосты псевдонимов, встреченных впервые."""
    raw = record.get("new")
    if not isinstance(raw, Mapping):
        return {}
    result: dict[str, list[str]] = {}
    for klass, values in raw.items():
        if not isinstance(values, list):
            continue
        items = [str(value) for value in values if isinstance(value, str) and value]
        if items:
            result[str(klass)] = items
    return result


def _lock_for(path: Path) -> threading.Lock:
    key = str(path)
    with _APPEND_LOCKS_GUARD:
        lock = _APPEND_LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _APPEND_LOCKS[key] = lock
        return lock


def append_line(path: Path, line: str) -> None:
    """Дописать строку одним системным вызовом: без разрывов и без перезаписи."""
    data = line.encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    with _lock_for(path):
        descriptor = os.open(
            path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_BINARY", 0)
        )
        try:
            os.write(descriptor, data)
        finally:
            os.close(descriptor)


def _record_date(path: Path) -> date | None:
    match = _DATE_IN_NAME.search(path.name)
    if not match:
        return None
    try:
        return date.fromisoformat(match.group(1))
    except ValueError:
        return None


def prune_audit(directory: Path, retention_days: int) -> list[Path]:
    """Удалить журналы старше ``retention_days``. Возвращает список удалённых файлов.

    Удаляется файл целиком — это и есть честное «забыть»: в базе для того же
    пришлось бы делать ``VACUUM``, а здесь достаточно убрать файл за дату.
    """
    if retention_days <= 0 or not directory.exists():
        return []
    today = date.today()
    removed: list[Path] = []
    for path in sorted(directory.glob("*.jsonl")) + sorted(directory.glob("suggestions-*.json")) + sorted(
        directory.glob("review-*.json")
    ):
        day = _record_date(path)
        if day is None:
            continue
        if (today - day).days > retention_days:
            try:
                path.unlink()
                removed.append(path)
            except OSError:
                continue
    return removed


@dataclass
class RequestStats:
    requests: int = 0
    blocked: int = 0
    bytes: int = 0
    masked: dict[str, int] = field(default_factory=dict)
    blocked_classes: dict[str, int] = field(default_factory=dict)
    #: Сколько **разных** значений замаскировано: первые встречи псевдонимов.
    unique: dict[str, int] = field(default_factory=dict)

    def add_masked(self, classes: Mapping[str, int]) -> None:
        for klass, count in classes.items():
            self.masked[klass] = self.masked.get(klass, 0) + count

    def add_unique(self, classes: Mapping[str, int]) -> None:
        for klass, count in classes.items():
            self.unique[klass] = self.unique.get(klass, 0) + count

    def add_blocked(self, klass: str) -> None:
        self.blocked += 1
        self.blocked_classes[klass] = self.blocked_classes.get(klass, 0) + 1


class AuditJournal:
    """Счётчики в памяти плюс суточный JSONL на диске."""

    def __init__(self, directory: Path | str | None = None, retention_days: int = 30) -> None:
        self.directory = Path(directory) if directory else None
        self.retention_days = retention_days
        self.stats = RequestStats()
        self.started = datetime.now(timezone.utc).isoformat(timespec="seconds")
        self._lock = threading.Lock()
        #: Псевдонимы, уже встречавшиеся сегодня: класс → хвосты токенов.
        self._seen: dict[str, set[str]] = {}
        self._seen_day: date | None = None

    def prune(self) -> list[Path]:
        if self.directory is None:
            return []
        return prune_audit(self.directory, self.retention_days)

    def seed(self) -> dict[str, int]:
        """Восстановить счётчики из сегодняшнего журнала после перезапуска.

        Заодно собираем уже встречавшиеся псевдонимы: иначе после рестарта
        значение, замаскированное до него, посчиталось бы новым и диаграмма
        «разных значений» завысила бы числа.
        """
        if self.directory is None:
            return {}
        self._seen = {}
        self._seen_day = date.today()
        path = self.directory / f"{self._seen_day.isoformat()}.jsonl"
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            return {}
        for line in lines:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(record, dict):
                continue
            self.stats.requests += 1
            self.stats.bytes += int(record.get("bytes") or 0)
            self.stats.add_masked(record.get("masked") or {})
            fresh = _new_pairs(record)
            if fresh:
                self.stats.add_unique({klass: len(values) for klass, values in fresh.items()})
                for klass, values in fresh.items():
                    self._seen.setdefault(klass, set()).update(values)
            if record.get("blocked"):
                self.stats.add_blocked(str(record["blocked"]))
        return dict(self.stats.masked)

    def record(
        self,
        mode: str,
        classes: Mapping[str, int],
        blocked: str | None = None,
        payload_bytes: int = 0,
        tokens: Mapping[str, Iterable[str]] | None = None,
    ) -> None:
        with self._lock:
            today = date.today()
            if self._seen_day != today:
                # Граница суток: счётчики «разных значений» начинают день заново.
                self._seen = {}
                self._seen_day = today
            new: dict[str, list[str]] = {}
            if tokens:
                for klass, values in tokens.items():
                    key = str(klass)
                    seen = self._seen.setdefault(key, set())
                    fresh = sorted({_token_suffix(token) for token in values} - seen)
                    if fresh:
                        seen.update(fresh)
                        new[key] = fresh
            self.stats.requests += 1
            self.stats.bytes += payload_bytes
            self.stats.add_masked(classes)
            if new:
                self.stats.add_unique({klass: len(values) for klass, values in new.items()})
            if blocked:
                self.stats.add_blocked(blocked)
            if self.directory is None:
                return
            record = {
                "v": RECORD_VERSION,
                "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "mode": mode,
                "bytes": payload_bytes,
                "masked": dict(classes),
                "new": new,
                "blocked": blocked,
            }
            path = self.directory / f"{today.isoformat()}.jsonl"
            append_line(path, json.dumps(record, ensure_ascii=False) + "\n")

    def snapshot(self) -> dict:
        with self._lock:
            stats = self.stats
            return {
                "started": self.started,
                "requests": stats.requests,
                "blocked": stats.blocked,
                "bytes": stats.bytes,
                "masked": dict(sorted(stats.masked.items())),
                "unique": dict(sorted(stats.unique.items())),
                "blocked_classes": dict(sorted(stats.blocked_classes.items())),
            }
