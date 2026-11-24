"""Перезапуск прокси через супервизор автозапуска.

Автозапуск проекта — задача планировщика `redactrail-supervisor`:
`scripts/supervise.ps1` раз в 10 секунд проверяет порты 8787/8788 и поднимает
`run.cmd`/`admin.cmd`, если те упали. Служба для этого не нужна: служба обязана
отвечать менеджеру служб рукопожатием (иначе `sc create` даёт ошибку 1053), а
планировщику достаточно факта запуска процесса.

Отсюда простая семантика кнопки в админке: «перезапустить прокси» — завершить
процесс, слушающий 8787. Супервизор заметит это в пределах своего цикла и поднимет
`run.cmd` заново. Админка на 8788 при этом остаётся жива и успевает показать отчёт.
Убивать сам супервизор нельзя: его дочерние процессы он не останавливает, а новый
экземпляр увидит занятые порты и ничего не сделает.
"""

from __future__ import annotations

import os
import subprocess
import time
from typing import Any
from urllib.error import URLError
from urllib.request import urlopen

from .winutil import hidden_kwargs

#: Основная задача автозапуска: единый процесс `python -m redactrail.app`.
#: Имя совпадает с `scripts/install-autostart.ps1`.
SUPERVISOR_TASK = "redactrail"
#: Задача ночного аудита: её достаточно показать в админке.
AUDIT_TASK = "redactrail-audit"
PROXY_PORT = 8787
PROXY_HEALTH_URL = f"http://127.0.0.1:{PROXY_PORT}/health"
#: Супервизор проверяет порты раз в 10 секунд; ждём с запасом на старт `run.cmd`.
RESTART_WAIT_S = 30.0
POLL_INTERVAL_S = 0.5
COMMAND_TIMEOUT_S = 20.0


def available() -> bool:
    """Планировщик и taskkill есть только на Windows."""
    return os.name == "nt"


def health(url: str = PROXY_HEALTH_URL, timeout: float = 1.0) -> dict[str, Any]:
    """Проверить `/health` прокси. Ошибка связи — не исключение, а поле `reachable`."""
    try:
        with urlopen(url, timeout=timeout) as response:  # noqa: S310 - только локальные адреса
            body = response.read(512).decode("utf-8", "replace")
        return {"url": url, "reachable": True, "status": response.status, "body": body}
    except (URLError, OSError, ValueError) as error:
        return {"url": url, "reachable": False, "error": str(error)[:120]}


def _run(command: list[str]) -> subprocess.CompletedProcess[str] | None:
    """Запустить команду без оболочки. Ошибки запуска — не исключение, а `None`."""
    if not available():
        return None
    try:
        return subprocess.run(  # noqa: S603 - аргументы фиксированы, shell=True не используется
            command,
            capture_output=True,
            text=True,
            # Кодировка консоли не совпадает с локалью: `schtasks` и `taskkill`
            # пишут в OEM-кодировке (866), а локаль может быть 1251 или 1252.
            # Декодируем всегда как UTF-8 с заменой: ASCII (`Running`, PID) не
            # страдает, а битые байты не роняют поток чтения. Нам из вывода нужны
            # только код возврата и ASCII, поэтому замена безопаснее падения.
            encoding="utf-8",
            errors="replace",
            timeout=COMMAND_TIMEOUT_S,
            check=False,
            **hidden_kwargs(),
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _powershell(script: str) -> subprocess.CompletedProcess[str] | None:
    """Однострочный вызов PowerShell: разбор локализованного текста не нужен."""
    return _run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script])


def task_installed(name: str = SUPERVISOR_TASK) -> bool:
    """Зарегистрирована ли задача. Проверяется код возврата: текст вывода локализован."""
    result = _run(["schtasks", "/Query", "/TN", name])
    return bool(result is not None and result.returncode == 0)


def task_running(name: str = SUPERVISOR_TASK) -> bool:
    """Работает ли задача сейчас. `State` — перечисление, его имя от локали не зависит."""
    result = _powershell(f"(Get-ScheduledTask -TaskName '{name}').State")
    if result is None or result.returncode != 0:
        return False
    return "Running" in result.stdout


def start_task(name: str = SUPERVISOR_TASK) -> bool:
    result = _run(["schtasks", "/Run", "/TN", name])
    return bool(result is not None and result.returncode == 0)


def proxy_pid(port: int = PROXY_PORT) -> int | None:
    """PID процесса, слушающего порт прокси. Нет процесса — `None`, а не исключение."""
    result = _powershell(
        f"(Get-NetTCPConnection -LocalPort {port} -State Listen -ErrorAction SilentlyContinue "
        "| Select-Object -First 1 -ExpandProperty OwningProcess)"
    )
    if result is None or result.returncode != 0:
        return None
    text = (result.stdout or "").strip()
    return int(text) if text.isdigit() else None


def stop_process(pid: int) -> bool:
    """Завершить процесс и его потомков (`/T`)."""
    result = _run(["taskkill", "/PID", str(pid), "/T", "/F"])
    return bool(result is not None and result.returncode == 0)


def restart_proxy(wait_seconds: float = RESTART_WAIT_S) -> dict[str, Any]:
    """Перезапустить прокси, оставив супервизор работать.

    Возвращает отчёт для админки: что было до, какие действия удалось сделать,
    что стало после. Если автозапуск не установлен, процесс не трогаем: гасить
    прокси, которому некому подняться, — хуже, чем не перезапускать его вовсе.
    """
    before = health()
    report: dict[str, Any] = {
        "task": SUPERVISOR_TASK,
        "installed": task_installed(SUPERVISOR_TASK),
        "before": before,
        "actions": [],
    }
    if not report["installed"]:
        report["ok"] = bool(before["reachable"])
        report["hint"] = "автозапуск не установлен: scripts/install-autostart.ps1"
        return report

    if not task_running(SUPERVISOR_TASK) and start_task(SUPERVISOR_TASK):
        report["actions"].append("start_supervisor")

    pid = proxy_pid()
    if pid is None:
        if before["reachable"]:
            # Прокси отвечает, но процесс не найден: запрос `Get-NetTCPConnection`
            # не выполнился (права, политика). Врать про успешный перезапуск нельзя.
            report["actions"].append("pid_unknown")
            report["after"] = health()
            report["ok"] = False
            report["hint"] = "не удалось определить процесс на 8787: проверьте права на Get-NetTCPConnection"
            return report
        # Прокси уже лежит: супервизор поднимет его в пределах своего цикла.
        report["actions"].append("wait_supervisor")
    elif stop_process(pid):
        report["actions"].append("restart_proxy")
    else:
        report["actions"].append("stop_failed")
        report["after"] = health()
        report["ok"] = False
        return report

    deadline = time.monotonic() + max(0.0, wait_seconds)
    after = health()
    while not after["reachable"] and time.monotonic() < deadline:
        time.sleep(POLL_INTERVAL_S)
        after = health()

    report["after"] = after
    report["ok"] = bool(after["reachable"])
    if not report["ok"]:
        report["hint"] = "прокси не ответил: смотрите state/supervisor.log и state/proxy.log"
    return report
