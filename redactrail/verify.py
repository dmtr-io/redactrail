"""Проверка утечек: прогон planted-значений через прокси к локальной заглушке.

Ничего не уходит в интернет: «провайдер» — локальный HTTP-сервер, который записывает
тело запроса. Команда печатает, что реально ушло: значение в открытом виде (`LEAK`)
или псевдоним (`clean`). Код возврата 1, если хоть одно значение утекло.

    python -m redactrail.verify
    python -m redactrail.verify --policy policy.json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import threading
from dataclasses import dataclass
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import checksums
from .proxy import build_server

#: Соответствие класса детектора префиксу псевдонима.
PREFIX = {
    "person": "PERSON",
    "phone": "PHONE",
    "email": "EMAIL",
    "inn": "INN",
    "snils": "SNILS",
    "card": "CARD",
    "secret_assign": "SECRET_ASSIGN",
    "secret_token": "SECRET_TOKEN",
    "marker": "MARKER",
}


@dataclass
class Case:
    name: str
    klass: str
    text: str
    planted: str


@dataclass
class Row:
    name: str
    klass: str
    leaked: bool
    token_seen: bool


def _valid_inn() -> str:
    for digit in range(10):
        candidate = "771234567" + str(digit)
        if checksums.inn10_ok(candidate):
            return candidate
    raise RuntimeError("не удалось подобрать валидный ИНН")


def _valid_snils() -> str:
    for tail in range(100):
        candidate = "112233445" + f"{tail:02d}"
        if checksums.snils_ok(candidate):
            return candidate
    raise RuntimeError("не удалось подобрать валидный СНИЛС")


def cases() -> list[Case]:
    phone = "+7 999 123-45-67"
    hidden_phone = phone[:4] + "\u200b" + phone[4:]
    return [
        Case("ФИО", "person", "Клиент Иван Петров, добрый день.", "Иван Петров"),
        Case("телефон", "phone", "Звоните " + phone + " после обеда.", phone),
        Case("телефон ZW", "phone", "Звоните " + hidden_phone + " после обеда.", phone),
        Case("почта", "email", "Пишите на ivanov@example.com.", "ivanov@example.com"),
        Case("ИНН", "inn", f"ИНН {_valid_inn()} в договоре.", _valid_inn()),
        Case("СНИЛС", "snils", f"СНИЛС {_valid_snils()}.", _valid_snils()),
        Case("карта", "card", "Оплата с 4111111111111111.", "4111111111111111"),
        Case("секрет", "secret_assign", "token = sk-live-" + "A" * 24, "sk-live-" + "A" * 24),
        Case("маркер", "marker", "КОНФИДЕНЦИАЛЬНО\nтекст письма", "КОНФИДЕНЦИАЛЬНО"),
    ]


class _Capture(BaseHTTPRequestHandler):
    """Заглушка провайдера: запоминает тело, отвечает по-антроповски."""

    protocol_version = "HTTP/1.1"
    bodies: list[str] = []

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        self.bodies.append(self.rfile.read(length).decode("utf-8", "replace"))
        payload = {
            "id": "msg_verify",
            "type": "message",
            "role": "assistant",
            "model": "verify",
            "content": [{"type": "text", "text": "ok"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 1, "output_tokens": 1},
        }
        body = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:
        return


def _request(port: int, text: str) -> bytes:
    connection = HTTPConnection("127.0.0.1", port, timeout=30)
    body = {
        "model": "deepseek-flash",
        "max_tokens": 8,
        "messages": [{"role": "user", "content": [{"type": "text", "text": text}]}],
    }
    connection.request(
        "POST",
        "/v1/messages",
        body=json.dumps(body, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    response = connection.getresponse()
    data = response.read()
    connection.close()
    return data


def run(
    policy_path: str | Path | None = None,
    workdir: Path | None = None,
    mode: str | None = "strict",
) -> list[Row]:
    """Прогнать все случаи. Возвращает строки отчёта; исключения не глотает."""
    base = workdir or Path("tmp")
    base.mkdir(parents=True, exist_ok=True)
    work = base / f"verify-{os.getpid()}"
    work.mkdir(parents=True, exist_ok=True)
    _Capture.bodies = []
    capture = ThreadingHTTPServer(("127.0.0.1", 0), _Capture)
    capture_port = capture.server_address[1]
    proxy = build_server(
        port=0,
        upstream=f"http://127.0.0.1:{capture_port}",
        policy_path=policy_path,
        key_path=work / "secret.key",
        audit_dir=work / "audit",
        mode=mode,
    )
    threading.Thread(target=capture.serve_forever, daemon=True).start()
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    rows: list[Row] = []
    try:
        for case in cases():
            _Capture.bodies.clear()
            _request(proxy.server_address[1], case.text)
            body = _Capture.bodies[-1] if _Capture.bodies else ""
            leaked = case.planted in body
            if case.klass.startswith("secret"):
                token_seen = "[[SECRET" in body
            else:
                token_seen = "[[" + PREFIX.get(case.klass, case.klass.upper()) + "_" in body
            rows.append(Row(case.name, case.klass, leaked, token_seen))
    finally:
        proxy.shutdown()
        proxy.server_close()
        capture.shutdown()
        capture.server_close()
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Проверка утечек через локальную заглушку")
    parser.add_argument("--policy", default=None)
    args = parser.parse_args(argv)

    rows = run(args.policy)
    print(f"{'случай':12} {'класс':16} {'значение':10} {'псевдоним':10}")
    for row in rows:
        print(
            f"{row.name:12} {row.klass:16} "
            f"{'LEAK' if row.leaked else 'clean':10} {'да' if row.token_seen else 'нет':10}"
        )
    leaks = [row for row in rows if row.leaked]
    missing = [row for row in rows if not row.token_seen]
    if leaks:
        print(f"\nУТЕЧКИ: {', '.join(row.name for row in leaks)}", file=sys.stderr)
    if missing:
        print(f"не найдены псевдонимы: {', '.join(row.name for row in missing)}", file=sys.stderr)
    print(f"\nитог: случаев {len(rows)}, утечек {len(leaks)}")
    return 0 if not leaks else 1


if __name__ == "__main__":
    raise SystemExit(main())
