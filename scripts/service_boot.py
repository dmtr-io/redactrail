"""Точка входа для автозапуска: `pythonw.exe` без окна, ошибки — в `state/service.log`.

Задачи планировщика (`scripts/install-autostart.ps1`) запускают не модуль напрямую,
а этот файл: у `pythonw.exe` нет консоли, поэтому traceback импорта или старта иначе
пропал бы бесследно. Здесь он пишется в журнал, а код возврата остаётся ненулевым,
чтобы `RestartCount` в задаче имел шанс перезапустить процесс.
"""

from __future__ import annotations

import importlib
import os
import sys
import traceback
from datetime import datetime
from pathlib import Path


def _write_error(root: Path, text: str) -> None:
    path = root / "state" / "service.log"
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(text)
    except OSError:
        return


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: service_boot.py <module> [args...]", file=sys.stderr)
        return 2
    module_name, *args = sys.argv[1:]
    root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(root))
    # Относительные пути (state/, audit/) считаются от корня проекта.
    os.chdir(root)
    try:
        module = importlib.import_module(module_name)
        return int(module.main(args) or 0)
    except SystemExit:
        raise
    except BaseException:  # noqa: BLE001 - автозапуск не должен падать молча
        _write_error(
            root,
            f"\n[{datetime.now():%Y-%m-%d %H:%M:%S}] {module_name} {' '.join(args)}\n"
            f"{traceback.format_exc()}",
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
