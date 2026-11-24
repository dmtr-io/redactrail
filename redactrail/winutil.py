"""Windows: скрыть консольные окна у фоновых процессов.

Админка и прокси работают через `pythonw.exe`, у которого нет консоли. Если
запустить из него `schtasks`, `taskkill`, `powershell` или `zstd` без флагов,
Windows создаёт короткоживущее консольное окно — оно мигает при каждом
обращении админки к статусу задач.
"""

from __future__ import annotations

import subprocess
import sys


def hidden_kwargs() -> dict[str, object]:
    """Аргументы `subprocess` для запуска без окна. На других ОС — пусто."""
    if sys.platform != "win32":
        return {}
    kwargs: dict[str, object] = {}
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    if flags:
        kwargs["creationflags"] = flags
    startupinfo = getattr(subprocess, "STARTUPINFO", None)
    if startupinfo is not None:
        info = startupinfo()
        info.dwFlags |= getattr(subprocess, "STARTF_USESHOWWINDOW", 0)
        info.wShowWindow = getattr(subprocess, "SW_HIDE", 0)
        kwargs["startupinfo"] = info
    return kwargs
