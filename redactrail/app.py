"""Единый процесс: прокси и админка в одном приложении.

Зачем: при автозапуске не должно быть ни консольных окон, ни вкладки браузера.
`pythonw.exe -m redactrail.app` поднимает оба HTTP-сервера в одном процессе,
пишет журнал в `state/app.log` и работает до выхода пользователя/остановки.

Админка по-прежнему доступна по `http://127.0.0.1:8788/`, но браузер открывается
только вручную — приложение его не запускает.

Кнопка «Перезапустить прокси» в админке в едином режиме не убивает процесс
(это означало бы убить и админку): политика перечитывается автоматически, а для
смены кода приложение нужно запустить заново.
"""

from __future__ import annotations

import argparse
import os
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Any

from . import __version__, admin, proxy, services

DEFAULT_PROXY_PORT = 8787
DEFAULT_ADMIN_PORT = 8788
DEFAULT_UPSTREAM = "https://api.deepseek.com"


def _log(root: Path, message: str) -> None:
    """Короткий журнал приложения; не должен ронять процесс."""
    try:
        path = root / "state" / "app.log"
        path.parent.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        with path.open("a", encoding="utf-8") as handle:
            handle.write(f"{stamp} {message}\n")
    except OSError:
        pass


def build_servers(
    proxy_port: int = DEFAULT_PROXY_PORT,
    admin_port: int = DEFAULT_ADMIN_PORT,
    root: str | Path = ".",
    upstream: str = DEFAULT_UPSTREAM,
    policy_path: str | Path | None = None,
    audit_dir: str | Path | None = None,
) -> tuple[proxy.ProxyServer, admin.AdminServer]:
    """Собрать оба сервера, ничего не запуская. Удобно для тестов."""
    root_path = Path(root).resolve()
    os.environ["REDACTRAIL_UNIFIED"] = "1"
    proxy_server = proxy.build_server(
        port=proxy_port,
        upstream=upstream,
        policy_path=policy_path,
        key_path=root_path / "state" / "secret.key",
        audit_dir=audit_dir or (root_path / "audit"),
    )
    admin_server = admin.build_server(port=admin_port, root=root_path)
    return proxy_server, admin_server


def serve(server: Any, name: str) -> threading.Thread:
    """Запустить сервер в фоновом потоке."""

    def run() -> None:
        try:
            server.serve_forever(poll_interval=0.25)
        except Exception as error:  # noqa: BLE001 - процесс не должен молча замереть
            _log(Path(".").resolve(), f"{name}: поток упал: {type(error).__name__}: {error}")

    thread = threading.Thread(target=run, name=name, daemon=True)
    thread.start()
    return thread


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="redactrail: прокси и админка одним процессом")
    parser.add_argument("--root", default=".", help="каталог проекта (policy.json, state, audit)")
    parser.add_argument("--proxy-port", type=int, default=DEFAULT_PROXY_PORT)
    parser.add_argument("--admin-port", type=int, default=DEFAULT_ADMIN_PORT)
    parser.add_argument("--upstream", default=DEFAULT_UPSTREAM)
    parser.add_argument("--policy", default=None)
    parser.add_argument("--audit-dir", default=None)
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    _log(root, f"app start {__version__} proxy={args.proxy_port} admin={args.admin_port}")
    proxy_server, admin_server = build_servers(
        proxy_port=args.proxy_port,
        admin_port=args.admin_port,
        root=root,
        upstream=args.upstream,
        policy_path=args.policy,
        audit_dir=args.audit_dir,
    )
    stop = threading.Event()

    def shutdown(_signum: int | None = None, _frame: Any = None) -> None:
        stop.set()

    for name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        if hasattr(signal, name):
            try:
                signal.signal(getattr(signal, name), shutdown)
            except (ValueError, OSError):
                pass

    threads = [serve(proxy_server, "proxy"), serve(admin_server, "admin")]
    _log(root, f"app ready proxy={args.proxy_port} admin={args.admin_port}")
    try:
        while not stop.wait(0.5):
            if not all(thread.is_alive() for thread in threads):
                _log(root, "app stop: поток сервера завершился")
                break
    except KeyboardInterrupt:
        pass
    finally:
        for server in (proxy_server, admin_server):
            try:
                server.shutdown()
                server.server_close()
            except Exception:  # noqa: BLE001 - остановка не должна мешать выходу
                pass
        _log(root, "app stop")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
