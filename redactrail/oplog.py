"""Журнал событий: запуск, перезагрузка политики, сохранения, запуски аудита.

Пишется JSONL в `state/*.log`, ротация по размеру. В отличие от аудита запросов,
здесь нет данных из запросов — только события и их параметры: когда стартовали,
какой режим, сколько фрагментов обработано, куда сохранён бэкап.

Смысл — ответить на вопрос «оно вообще работало?» без раскопок в консоли: файл
читается глазами и грепается, а админка показывает хвост.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .audit import append_line

DEFAULT_MAX_BYTES = 512 * 1024
DEFAULT_BACKUPS = 3


class OpLog:
    """Длина в файл с ротацией: .log, .log.1, .log.2."""

    def __init__(
        self,
        path: Path | str,
        max_bytes: int = DEFAULT_MAX_BYTES,
        backups: int = DEFAULT_BACKUPS,
    ) -> None:
        self.path = Path(path)
        self.max_bytes = max_bytes
        self.backups = backups

    def _rotate(self) -> None:
        if not self.path.exists() or self.path.stat().st_size < self.max_bytes:
            return
        for index in range(self.backups - 1, 0, -1):
            source = self.path.with_name(f"{self.path.name}.{index}")
            target = self.path.with_name(f"{self.path.name}.{index + 1}")
            if source.exists():
                os.replace(source, target)
        os.replace(self.path, self.path.with_name(f"{self.path.name}.1"))

    def write(self, event: str, **fields: Any) -> None:
        record = {
            "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "event": event,
        }
        record.update({key: value for key, value in fields.items() if value is not None})
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._rotate()
            append_line(self.path, json.dumps(record, ensure_ascii=False) + "\n")
        except OSError:
            return  # журнал не должен ронять прокси или админку

    def tail(self, limit: int = 20) -> list[dict]:
        """Последние события: сначала текущий файл, при нехватке — предыдущие."""
        events: list[dict] = []
        for path in self._files():
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except OSError:
                continue
            for line in lines[-limit:]:
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(record, dict):
                    events.append(record)
        return events[-limit:]

    def _files(self) -> Iterator[Path]:
        """Старые файлы сначала, текущий в конце."""
        for index in range(self.backups, 0, -1):
            yield self.path.with_name(f"{self.path.name}.{index}")
        yield self.path
