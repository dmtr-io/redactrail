"""Настройка консоли: вывод на русском не должен падать на чужой кодировке."""

from __future__ import annotations

import sys


def enable_utf8_output() -> None:
    """Перевести stdout/stderr в UTF-8, сохранив работу без консоли.

    На Windows кодировка консоли зависит от локали: cp866, cp1251, cp1252.
    Текст с кириллицей не кодируется в cp1252 и печать падает. Свои сообщения
    пишем в UTF-8 с заменой непередаваемых символов — так команда не падает
    ни в русской консоли, ни в английской, ни при перенаправлении в файл.
    `pythonw.exe` консоли не имеет, там поток бывает `None` — это не ошибка.
    """
    for stream in (sys.stdout, sys.stderr):
        if stream is None:
            continue
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            continue
