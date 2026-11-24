"""HTTP-транспорт прокси: 127.0.0.1 → api.deepseek.com, с маскировкой и разворотом.

Что делает:

* принимает `POST /v1/messages`, прогоняет тело через `sanitizer`, отдаёт блокировку
  как `HTTP 400` в формате ошибки Anthropic (агент видит причину, авторизация не сбрасывается);
* пропускает поток SSE прозрачно для `text` и `thinking`;
* буферизует `tool_use` до `content_block_stop`, разворачивает псевдонимы в аргументах
  и отдаёт блок одним `input_json_delta` (иначе инструмент получит `[[PERSON_…]]`);
* блокирует `/v1/files` и неизвестные пути;
* пишет журнал блокировок без значений (класс, `sha256`, место).

Конфигурация — аргументы командной строки или переменные окружения. Прокси слушает
только `127.0.0.1`: наружу он не выставляется, аутентификации на loopback нет.

Осознанное ограничение первого приближения: `restore.text` (разворот псевдонимов в
тексте ответа) ещё не реализован — при `restore.text: true` прокси пишет предупреждение
и отдаёт текст как есть. Токены в тексте безопасны, а включение требует holdback-буфера.
"""

from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.client import HTTPConnection, HTTPSConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

from . import __version__, scan
from .audit import RECORD_VERSION, AuditJournal, append_line
from .oplog import OpLog
from .policy import Policy, load_policy
from .pseudonym import Pseudonymizer, load_or_create_key
from .sanitizer import BlockedRequest, BlockEvent, Sanitizer, restore_json, restore_tokens

DEFAULT_PORT = 8787
DEFAULT_UPSTREAM = "https://api.deepseek.com"
MAX_BODY_BYTES = 16 * 1024 * 1024
BLOCK_LOG_LIMIT = 200

#: Блокировки структуры (а не содержимого): их пишем в журнал из транспорта,
#: потому что санитайзер поднимает их до проверки текста.
STRUCTURAL_BLOCKS = frozenset({"unknown_field", "unknown_block", "image", "document", "oversize", "number"})


@dataclass
class BlockLog:
    """Кольцевой журнал блокировок: только классы, хеши и место, без значений."""

    capacity: int = BLOCK_LOG_LIMIT
    directory: Path | None = None
    events: list[dict] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def add(self, event: BlockEvent, decision: str) -> None:
        record = {
            "v": RECORD_VERSION,
            "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "class": event.klass,
            "hash": event.value_hash,
            "length": event.length,
            "where": event.where,
            "decision": decision,
        }
        with self._lock:
            self.events.append(record)
            if len(self.events) > self.capacity:
                del self.events[: len(self.events) - self.capacity]
            if self.directory is not None:
                self._append(record)

    def _append(self, record: Mapping[str, Any]) -> None:
        assert self.directory is not None
        path = self.directory / f"blocks-{datetime.now().date().isoformat()}.jsonl"
        append_line(path, json.dumps(record, ensure_ascii=False) + "\n")


class SseRestorer:
    """Пересборка потока SSE: текст — с разворотом, `tool_use` — после накопления.

    Модель присылает текст кусками, и псевдоним может прийти разорванным
    («[[PER» + «SON_ABCD1234]]»). Поэтому хвост текста придерживается на длину
    самого длинного токена этой таблицы: пока неясно, собирается ли токен, отдавать
    рано. На `content_block_stop` остаток отдаётся с разворотом.
    """

    def __init__(self, table: Mapping[str, Any], restore_text: bool = False) -> None:
        self.table = table
        self.restore_text = restore_text
        self._buffering: set[int] = set()
        self._partial: dict[int, str] = {}
        self._text_buffers: dict[int, str] = {}
        #: Какой вид дельты отдавать для блока: текст или размышления.
        self._delta_kinds: dict[int, tuple[str, str]] = {}
        #: Придерживаем столько символов, сколько может занять самый длинный токен.
        self._holdback = max((len(token) for token in table), default=0) if restore_text else 0

    def handle(self, event: str | None, data: str) -> list[str]:
        try:
            payload = json.loads(data) if data else None
        except json.JSONDecodeError:
            return [self._frame(event, data)]

        if isinstance(payload, dict):
            kind = payload.get("type")
            index = payload.get("index")
            if kind == "content_block_start" and isinstance(index, int):
                block = payload.get("content_block") or {}
                if block.get("type") == "tool_use":
                    self._buffering.add(index)
                    self._partial[index] = ""
                elif block.get("type") == "text" and self.restore_text:
                    self._text_buffers[index] = ""
                    self._delta_kinds[index] = ("text_delta", "text")
                elif block.get("type") == "thinking" and self.restore_text:
                    self._text_buffers[index] = ""
                    self._delta_kinds[index] = ("thinking_delta", "thinking")
            elif kind == "content_block_delta" and isinstance(index, int):
                delta = payload.get("delta") or {}
                delta_type = delta.get("type")
                if index in self._buffering and delta_type == "input_json_delta":
                    self._partial[index] += str(delta.get("partial_json", ""))
                    return []
                if delta_type in ("text_delta", "thinking_delta") and self.restore_text:
                    if index not in self._text_buffers:
                        self._text_buffers[index] = ""
                        self._delta_kinds[index] = (
                            ("thinking_delta", "thinking")
                            if delta_type == "thinking_delta"
                            else ("text_delta", "text")
                        )
                    kind, field = self._delta_kinds.get(index, ("text_delta", "text"))
                    return self._text_delta(index, str(delta.get(field, "")), kind, field)
            elif kind == "content_block_stop" and isinstance(index, int):
                if index in self._buffering:
                    return self._flush_tool(index, event, data)
                if index in self._text_buffers:
                    return self._flush_text(index, event, data)
        return [self._frame(event, data)]

    def _text_delta(self, index: int, text: str, kind: str = "text_delta", field: str = "text") -> list[str]:
        """Отдать безопасную часть текста: хвост на длину токена остаётся в буфере.

        Границу сдвигаем к последнему «[[»: иначе можно разрезать начало токена,
        и в поток уйдёт «[[PER» отдельно от «SON_…]]».
        """
        buffer = self._text_buffers[index] + text
        release = max(0, len(buffer) - self._holdback)
        # Если граница попадает внутрь ещё не закрытого «[[…» (включая одиночную «[»),
        # сдвигаем её к началу этой скобки.
        head = buffer[:release]
        start = head.rfind("[")
        if start != -1 and "]]" not in buffer[start:release]:
            # Отступаем к началу всей серии «[»: иначе первая скобка уйдёт в поток.
            while start > 0 and buffer[start - 1] == "[":
                start -= 1
            release = start
        if not release:
            self._text_buffers[index] = buffer
            return []
        head, tail = buffer[:release], buffer[release:]
        self._text_buffers[index] = tail
        restored = restore_tokens(head, self.table)
        if not restored:
            return []
        return [
            self._frame(
                "content_block_delta",
                json.dumps(
                    {
                        "type": "content_block_delta",
                        "index": index,
                        "delta": {"type": kind, field: restored},
                    },
                    ensure_ascii=False,
                ),
            )
        ]

    def _flush_text(self, index: int, event: str | None, data: str) -> list[str]:
        tail = self._text_buffers.pop(index, "")
        kind, field = self._delta_kinds.pop(index, ("text_delta", "text"))
        frames: list[str] = []
        restored = restore_tokens(tail, self.table) if tail else ""
        if restored:
            frames.append(
                self._frame(
                    "content_block_delta",
                    json.dumps(
                        {
                            "type": "content_block_delta",
                            "index": index,
                            "delta": {"type": kind, field: restored},
                        },
                        ensure_ascii=False,
                    ),
                )
            )
        frames.append(self._frame(event, data))
        return frames

    def _flush_tool(self, index: int, event: str | None, data: str) -> list[str]:
        self._buffering.discard(index)
        raw = self._partial.pop(index, "")
        restored = self._restore(raw)
        frames: list[str] = []
        if restored:
            frames.append(
                self._frame(
                    "content_block_delta",
                    json.dumps(
                        {
                            "type": "content_block_delta",
                            "index": index,
                            "delta": {"type": "input_json_delta", "partial_json": restored},
                        },
                        ensure_ascii=False,
                    ),
                )
            )
        frames.append(self._frame(event, data))
        return frames

    def _restore(self, raw: str) -> str:
        if not raw:
            return ""
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return raw
        restored = restore_json(parsed, self.table)
        return json.dumps(restored, ensure_ascii=False)

    @staticmethod
    def _frame(event: str | None, data: str) -> str:
        if event:
            return f"event: {event}\ndata: {data}\n\n"
        return f"data: {data}\n\n"


class ProxyServer(ThreadingHTTPServer):
    daemon_threads = True
    #: Второй экземпляр должен падать с ошибкой, а не делить порт с первым:
    #: иначе запросы обслуживает старый процесс со старой политикой.
    allow_reuse_address = False

    def __init__(
        self,
        address: tuple[str, int],
        upstream: str,
        policy: Policy,
        pseudonymizer: Pseudonymizer,
        audit_dir: Path | None = None,
    ) -> None:
        super().__init__(address, ProxyHandler)
        parts = urlsplit(upstream)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError(f"неверный upstream: {upstream!r}")
        self.upstream = upstream
        self.scheme = parts.scheme
        self.host = parts.hostname
        self.port = parts.port or (443 if parts.scheme == "https" else 80)
        self.base_path = parts.path.rstrip("/")
        self.policy = policy
        self.pseudonymizer = pseudonymizer
        self.block_log = BlockLog(directory=audit_dir)
        self.oplog = OpLog(audit_dir.parent / "state" / "proxy.log") if audit_dir else None
        self.audit = AuditJournal(directory=audit_dir, retention_days=policy.limits.retention_days)
        self.audit.prune()
        self.audit.seed()
        self.sanitizer = Sanitizer(policy, pseudonymizer, on_block=self._on_block)
        self._log(
            "proxy_start",
            port=address[1],
            upstream=upstream,
            mode=policy.mode,
            policy=str(policy.source) if policy.source else None,
            retention_days=policy.limits.retention_days,
        )
        self._policy_path = Path(policy.source) if policy.source else None
        self._mode_override: str | None = None
        self._policy_lock = threading.Lock()
        try:
            self._policy_mtime = self._policy_path.stat().st_mtime if self._policy_path else None
        except OSError:
            self._policy_mtime = None
        state_root = audit_dir.parent if audit_dir.name == "audit" else audit_dir
        self._state_dir = state_root / "state" if audit_dir else None
        self._cache_path = self._state_dir / "cache.json" if self._state_dir else None
        self._cache_dump_at = 0.0

    def dump_cache_stats(self, force: bool = False) -> None:
        """Положить статистику кеша детекции в state/cache.json для админки.

        Не чаще раза в секунду: файл нужен для отображения, а не как журнал.
        """
        if self._cache_path is None:
            return
        now = time.time()
        if not force and now - self._cache_dump_at < 1.0:
            return
        self._cache_dump_at = now
        payload = {
            "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            **scan.cache_stats(),
        }
        try:
            self._cache_path.parent.mkdir(parents=True, exist_ok=True)
            temporary = self._cache_path.with_suffix(".tmp")
            temporary.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
            os.replace(temporary, self._cache_path)
        except OSError:
            pass

    def _log(self, event: str, **fields) -> None:
        if self.oplog is not None:
            self.oplog.write(event, **fields)

    def refresh_policy(self) -> None:
        """Перечитать `policy.json`, если файл изменился.

        Правка политики — обычное дело при разборе ложных срабатываний, и
        требовать перезапуска процесса нельзя: агент не должен простаивать.
        Ошибка в новом файле не роняет прокси — остаётся прежняя политика.
        """
        if self._policy_path is None:
            return
        try:
            mtime = self._policy_path.stat().st_mtime
        except OSError:
            return
        if mtime == self._policy_mtime:
            return
        with self._policy_lock:
            if mtime == self._policy_mtime:
                return
            try:
                policy = load_policy(self._policy_path)
            except Exception as error:  # noqa: BLE001 - плохой файл не повод падать
                print(f"[redactrail] политика не перезагружена: {error}", file=sys.stderr)
                self._log("policy_reload_failed", error=str(error))
                self._policy_mtime = mtime
                return
            if self._mode_override:
                policy = policy.with_mode(self._mode_override)
            self.policy = policy
            self.sanitizer = Sanitizer(policy, self.pseudonymizer, on_block=self._on_block)
            self._policy_mtime = mtime
            self._log("policy_reload", mode=policy.mode)
            print("[redactrail] политика перезагружена", file=sys.stderr)

    def _on_block(self, event: BlockEvent) -> None:
        self.block_log.add(event, decision=self.policy.mode)

    def connection_for(self) -> HTTPConnection:
        if self.scheme == "https":
            return HTTPSConnection(self.host, self.port, timeout=300, context=ssl.create_default_context())
        return HTTPConnection(self.host, self.port, timeout=300)


class ProxyHandler(BaseHTTPRequestHandler):
    server: ProxyServer

    protocol_version = "HTTP/1.1"
    server_version = f"redactrail/{__version__}"

    # --- маршруты -----------------------------------------------------

    def _route(self) -> str:
        """Путь без префикса базового URL DSH (`/anthropic`)."""
        path = urlsplit(self.path).path
        if path == "/anthropic":
            return "/"
        if path.startswith("/anthropic/"):
            return path[len("/anthropic") :]
        return path

    def do_GET(self) -> None:  # noqa: N802 - имя задано BaseHTTPRequestHandler
        route = self._route()
        if route == "/health":
            self._send_json(200, {"status": "ok", "mode": self.server.policy.mode})
            return
        if route == "/stats":
            snapshot = self.server.audit.snapshot()
            snapshot["cache"] = scan.cache_stats()
            self._send_json(200, snapshot)
            return
        if route in ("/models", "/v1/models"):
            # Каталог моделей — служебные данные провайдера, не пользовательский текст.
            self._forward_get()
            return
        self._send_blocked(404, "unknown_field", "неизвестный путь")

    def do_POST(self) -> None:  # noqa: N802
        route = self._route()
        if route.startswith("/v1/files"):
            self._send_blocked(400, "document", "файлы и вложения не отправляются")
            return
        if route not in ("/v1/messages", "/v1/messages/count_tokens"):
            self._send_blocked(404, "unknown_field", "неизвестный путь")
            return
        self._handle_messages()

    def do_PUT(self) -> None:  # noqa: N802
        self._send_blocked(404, "unknown_field", "неизвестный метод")

    do_DELETE = do_PUT
    do_PATCH = do_PUT

    # --- основной обработчик ------------------------------------------

    def _handle_messages(self) -> None:
        self.server.refresh_policy()
        body = self._read_body()
        if body is None:
            return
        try:
            payload = json.loads(body)
        except json.JSONDecodeError as error:
            self._send_blocked(400, "unknown_field", f"тело не JSON: {error.msg}")
            return
        if not isinstance(payload, dict):
            self._send_blocked(400, "unknown_field", "тело должно быть объектом")
            return

        try:
            result = self.server.sanitizer.sanitize(payload)
        except BlockedRequest as blocked:
            self.server.audit.record(self.server.policy.mode, {}, blocked.klass, len(body))
            self.server.dump_cache_stats()
            if blocked.klass in STRUCTURAL_BLOCKS:
                self.server.block_log.add(
                    BlockEvent(
                        klass=blocked.klass, where=blocked.where, value="", value_hash="", length=0, window=""
                    ),
                    decision=self.server.policy.mode,
                )
            self._send_blocked(400, blocked.klass, blocked.as_message())
            return
        except Exception as error:  # noqa: BLE001 - fail-closed: лучше отказ, чем утечка
            self.server.block_log.add(
                BlockEvent(klass="internal", where="proxy", value="", value_hash="", length=0, window=""),
                decision="error",
            )
            self._send_blocked(500, "internal", f"ошибка санитайзера: {error.__class__.__name__}")
            return

        stream = bool(payload.get("stream"))
        self.server.audit.record(
            self.server.policy.mode, result.classes, None, len(body), tokens=result.tokens
        )
        self.server.dump_cache_stats()
        self._forward(result.payload, result.table, stream)

    def _read_body(self) -> bytes | None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._send_blocked(400, "unknown_field", "неверный Content-Length")
            return None
        if length <= 0:
            self._send_blocked(400, "unknown_field", "пустое тело запроса")
            return None
        if length > MAX_BODY_BYTES:
            self._send_blocked(400, "oversize", "тело запроса слишком велико")
            return None
        return self.rfile.read(length)

    # --- пересылка -----------------------------------------------------

    def _forward(self, payload: Mapping[str, Any], table: Mapping[str, Any], stream: bool) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        parts = urlsplit(self.path)
        upstream_path = self.server.base_path + parts.path
        if parts.query:
            upstream_path += "?" + parts.query
        headers = self._upstream_headers(len(data))
        connection = self.server.connection_for()
        try:
            connection.request("POST", upstream_path, body=data, headers=headers)
            response = connection.getresponse()
        except OSError as error:
            self._send_blocked(502, "internal", f"провайдер недоступен: {error}")
            return

        try:
            if response.status >= 400:
                self._relay_error(response)
                return
            if stream and (response.getheader("Content-Type") or "").startswith("text/event-stream"):
                self._relay_stream(response, table)
            else:
                self._relay_json(response, table)
        finally:
            try:
                connection.close()
            except OSError:
                pass

    def _forward_get(self) -> None:
        parts = urlsplit(self.path)
        upstream_path = self.server.base_path + parts.path
        if parts.query:
            upstream_path += "?" + parts.query
        headers: dict[str, str] = {}
        for key, value in self.headers.items():
            if key.lower() in ("host", "content-length", "connection", "accept-encoding", "transfer-encoding"):
                continue
            headers[key] = value
        headers["Connection"] = "close"
        connection = self.server.connection_for()
        try:
            connection.request("GET", upstream_path, headers=headers)
            response = connection.getresponse()
            body = response.read()
            self._send_bytes(
                response.status,
                response.getheader("Content-Type") or "application/json",
                body,
            )
        except OSError as error:
            self._send_blocked(502, "internal", f"провайдер недоступен: {error}")
        finally:
            try:
                connection.close()
            except OSError:
                pass

    def _upstream_headers(self, length: int) -> dict[str, str]:
        headers: dict[str, str] = {}
        for key, value in self.headers.items():
            lower = key.lower()
            if lower in ("host", "content-length", "connection", "accept-encoding", "transfer-encoding"):
                continue
            headers[key] = value
        headers["Content-Length"] = str(length)
        headers["Connection"] = "close"
        return headers

    def _relay_stream(self, response, table: Mapping[str, Any]) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        restorer = SseRestorer(table, restore_text=self.server.policy.restore.text)
        event: str | None = None
        data_lines: list[str] = []
        try:
            while True:
                raw_line = response.readline()
                if not raw_line:
                    break
                line = raw_line.decode("utf-8", errors="replace").rstrip("\r\n")
                if not line:
                    if data_lines or event:
                        for frame in restorer.handle(event, "\n".join(data_lines)):
                            self.wfile.write(frame.encode("utf-8"))
                        self.wfile.flush()
                    event, data_lines = None, []
                    continue
                if line.startswith("event:"):
                    event = line[6:].strip()
                elif line.startswith("data:"):
                    data_lines.append(line[5:].lstrip())
                # комментарии «:» и id игнорируются
            if data_lines or event:
                for frame in restorer.handle(event, "\n".join(data_lines)):
                    self.wfile.write(frame.encode("utf-8"))
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            self.close_connection = True

    def _relay_json(self, response, table: Mapping[str, Any]) -> None:
        body = response.read()
        content_type = response.getheader("Content-Type") or "application/json"
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError:
            self._send_bytes(response.status, content_type, body)
            return
        restored = restore_json(parsed, table)
        self._send_json(200, restored, content_type=content_type)

    def _relay_error(self, response) -> None:
        body = response.read()
        content_type = response.getheader("Content-Type") or "application/json"
        self._send_bytes(response.status, content_type, body)

    # --- ответы --------------------------------------------------------

    def _send_blocked(self, status: int, klass: str, message: str) -> None:
        if not message.startswith("[redactrail]"):
            message = f"[redactrail] {message}"
        body = {
            "type": "error",
            "error": {"type": "invalid_request_error" if status == 400 else "api_error",
                      "message": message},
        }
        self._send_json(status, body)

    def _send_json(self, status: int, payload: Any, content_type: str = "application/json") -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._send_bytes(status, content_type, body)

    def _send_bytes(self, status: int, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass
        self.close_connection = True

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        # Ничего не логируем: тело запроса и пути содержат данные пользователя.
        return


def build_server(
    port: int = DEFAULT_PORT,
    upstream: str = DEFAULT_UPSTREAM,
    policy_path: str | Path | None = None,
    key_path: str | Path = "state/secret.key",
    audit_dir: str | Path | None = "audit",
    mode: str | None = None,
) -> ProxyServer:
    policy = load_policy(policy_path)
    if mode:
        policy = policy.with_mode(mode)
    pseudonymizer = Pseudonymizer(load_or_create_key(key_path))
    directory = Path(audit_dir) if audit_dir else None
    server = ProxyServer(("127.0.0.1", port), upstream, policy, pseudonymizer, directory)
    server._mode_override = mode
    return server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Локальный прокси-маскировщик для DSH")
    parser.add_argument("--port", type=int, default=int(os.environ.get("REDACTRAIL_PORT", DEFAULT_PORT)))
    parser.add_argument("--upstream", default=os.environ.get("REDACTRAIL_UPSTREAM", DEFAULT_UPSTREAM))
    parser.add_argument("--policy", default=os.environ.get("REDACTRAIL_POLICY"))
    parser.add_argument("--state", default=os.environ.get("REDACTRAIL_KEY", "state/secret.key"))
    parser.add_argument("--audit-dir", default=os.environ.get("REDACTRAIL_AUDIT", "audit"))
    parser.add_argument("--mode", choices=("strict", "audit", "off"), default=None)
    args = parser.parse_args(argv)

    server = build_server(
        port=args.port,
        upstream=args.upstream,
        policy_path=args.policy,
        key_path=args.state,
        audit_dir=args.audit_dir,
        mode=args.mode,
    )
    host, port = server.server_address[:2]
    print(f"[redactrail] {__version__}: http://{host}:{port} → {args.upstream} (режим {server.policy.mode})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("[redactrail] остановлен")
    finally:
        server._log("proxy_stop", requests=server.audit.stats.requests)
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
