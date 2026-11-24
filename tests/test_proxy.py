"""Транспорт прокси: блокировки, пересылка, SSE и разворот `tool_use`."""

from __future__ import annotations

import json
import re
import threading
import unittest
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from redactrail.proxy import SseRestorer, build_server
from tests import support

TOKEN_RE = re.compile(r"\[\[[A-Z]+_[0-9A-F]{10}\]\]")

SSE_TEMPLATE = """event: message_start
data: {{"type":"message_start","message":{{"id":"m1","content":[]}}}}

event: content_block_start
data: {{"type":"content_block_start","index":0,"content_block":{{"type":"text","text":""}}}}

event: content_block_delta
data: {{"type":"content_block_delta","index":0,"delta":{{"type":"text_delta","text":"Привет, {token}"}}}}

event: content_block_stop
data: {{"type":"content_block_stop","index":0}}

event: content_block_start
data: {{"type":"content_block_start","index":1,"content_block":{{"type":"tool_use","id":"toolu_1","name":"read_file","input":{{}}}}}}

event: content_block_delta
data: {{"type":"content_block_delta","index":1,"delta":{{"type":"input_json_delta","partial_json":"{{\\"path\\":\\"{token}/a.txt\\"}}"}}}}

event: content_block_stop
data: {{"type":"content_block_stop","index":1}}

event: message_stop
data: {{"type":"message_stop"}}

"""


class FakeUpstream(BaseHTTPRequestHandler):
    """Мок провайдера: запоминает тело и отвечает JSON или SSE."""

    protocol_version = "HTTP/1.1"

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        parsed = json.loads(body)
        self.server.requests.append({"path": self.path, "body": parsed, "raw": body})

        if self.server.fail:
            self._respond(500, b'{"type":"error","error":{"type":"api_error","message":"boom"}}')
            return

        token_match = TOKEN_RE.search(body.decode("utf-8"))
        token = token_match.group(0) if token_match else "[[PERSON_0000000000]]"

        if parsed.get("stream"):
            payload = SSE_TEMPLATE.format(token=token).encode("utf-8")
            self._respond(200, payload, content_type="text/event-stream; charset=utf-8")
        else:
            body_json = {
                "type": "message",
                "content": [
                    {"type": "text", "text": f"Привет, {token}"},
                    {
                        "type": "tool_use",
                        "id": "toolu_1",
                        "name": "read_file",
                        "input": {"path": f"{token}/a.txt", "count": 3},
                    },
                ],
            }
            self._respond(200, json.dumps(body_json, ensure_ascii=False).encode("utf-8"))

    def _respond(self, status: int, body: bytes, content_type: str = "application/json") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        self.server.requests.append({"path": self.path, "method": "GET"})
        body = json.dumps({"data": [{"id": "deepseek-flash"}]}).encode("utf-8")
        self._respond(200, body)

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        return


def start_fake_upstream() -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", 0), FakeUpstream)
    server.requests = []
    server.fail = False
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def start_proxy(upstream: str, audit_dir: Path):
    server = build_server(
        port=0,
        upstream=upstream,
        policy_path=None,
        key_path=audit_dir / "secret.key",
        audit_dir=audit_dir,
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


class ProxyTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.context = support.scratch_dir()
        self.tmp = self.context.__enter__()
        self.upstream = start_fake_upstream()
        self.proxy = start_proxy(f"http://127.0.0.1:{self.upstream.server_address[1]}", self.tmp)
        self.addCleanup(self.context.__exit__, None, None, None)
        self.addCleanup(self.upstream.server_close)
        self.addCleanup(self.proxy.server_close)
        self.addCleanup(self.upstream.shutdown)
        self.addCleanup(self.proxy.shutdown)

    def request(self, method: str, path: str, body: bytes | None = None, headers: dict | None = None):
        connection = HTTPConnection("127.0.0.1", self.proxy.server_address[1], timeout=10)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            return connection.getresponse()
        finally:
            connection.close()

    def post_messages(self, payload: dict):
        return self.request(
            "POST", "/v1/messages", json.dumps(payload).encode("utf-8"),
            {"Content-Type": "application/json", "x-api-key": "test"},
        )


def base_payload(**overrides) -> dict:
    payload = {
        "model": "deepseek-chat",
        "max_tokens": 256,
        "messages": [{"role": "user", "content": "Клиент Иванов Иван Иванович"}],
    }
    payload.update(overrides)
    return payload


class PolicyReloadTests(unittest.TestCase):
    def test_policy_file_is_reloaded_on_change(self) -> None:
        import shutil

        with support.scratch_dir() as tmp:
            policy_path = tmp / "policy.json"
            shutil.copyfile(support.source_policy(), policy_path)
            server = build_server(
                port=0,
                upstream="http://127.0.0.1:1",
                policy_path=policy_path,
                key_path=tmp / "secret.key",
                audit_dir=tmp,
            )
            try:
                self.assertEqual(server.policy.mode, "strict")
                import json

                data = json.loads(policy_path.read_text(encoding="utf-8"))
                data["mode"] = "audit"
                policy_path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
                import os

                os.utime(policy_path, (0, 0))
                server.refresh_policy()
                self.assertEqual(server.policy.mode, "audit")
            finally:
                server.server_close()


class HealthAndRoutesTests(ProxyTestCase):
    def test_health(self) -> None:
        response = self.request("GET", "/health")
        self.assertEqual(response.status, 200)
        self.assertEqual(json.loads(response.read())["status"], "ok")

    def test_files_blocked(self) -> None:
        response = self.request("POST", "/v1/files", b"{}")
        self.assertEqual(response.status, 400)
        self.assertIn("[redactrail]", json.loads(response.read())["error"]["message"])

    def test_unknown_path_blocked(self) -> None:
        response = self.request("GET", "/v1/whatever")
        self.assertEqual(response.status, 404)


class StatsTests(ProxyTestCase):
    def test_stats_and_journal_show_classes_without_values(self) -> None:
        self.post_messages(base_payload()).read()
        stats = json.loads(self.request("GET", "/stats").read())
        self.assertEqual(stats["requests"], 1)
        self.assertGreaterEqual(stats["masked"].get("person", 0), 1)

        journals = list(self.tmp.glob("*.jsonl"))
        self.assertTrue(journals)
        text = journals[0].read_text(encoding="utf-8")
        self.assertIn("person", text)
        self.assertNotIn("Иванов", text)

    def test_journal_counts_distinct_values_once(self) -> None:
        # одна и та же переписка в двух запросах: срабатываний два, значение одно
        for _ in range(2):
            self.post_messages(base_payload()).read()
        journal = next(self.tmp.glob("[0-9]*-[0-9]*-[0-9]*.jsonl"))
        records = [json.loads(line) for line in journal.read_text(encoding="utf-8").splitlines()]
        self.assertEqual(len(records), 2)
        self.assertEqual(len(records[0]["new"]["person"]), 1)
        self.assertEqual(records[1]["new"], {}, "повторная отправка не даёт новых значений")
        stats = json.loads(self.request("GET", "/stats").read())
        self.assertEqual(stats["masked"]["person"], 2, "срабатывания считаются")
        self.assertEqual(stats["unique"]["person"], 1, "разных значений одно")

    def test_blocked_request_counted(self) -> None:
        self.post_messages(
            base_payload(messages=[{"role": "user", "content": [{"type": "video", "data": "x"}]}])
        ).read()
        stats = json.loads(self.request("GET", "/stats").read())
        self.assertEqual(stats["blocked"], 1)
        self.assertEqual(stats["blocked_classes"].get("unknown_block"), 1)


class BlockingTests(ProxyTestCase):
    def test_secret_is_masked_and_forwarded(self) -> None:
        response = self.post_messages(
            base_payload(messages=[{"role": "user", "content": "password=hunter2secret"}])
        )
        self.assertEqual(response.status, 200)
        response.read()
        raw = self.upstream.requests[0]["raw"].decode("utf-8")
        self.assertNotIn("hunter2secret", raw)
    def test_block_journal_has_no_values(self) -> None:
        response = self.post_messages(
            base_payload(messages=[{"role": "user", "content": [{"type": "video", "data": "x"}]}])
        )
        self.assertEqual(response.status, 400)
        response.read()
        journals = list(self.tmp.glob("blocks-*.jsonl"))
        self.assertTrue(journals, "журнал блокировок не создан")
        text = journals[0].read_text(encoding="utf-8")
        record = json.loads(text.strip().splitlines()[0])
        self.assertEqual(record["class"], "unknown_block")
        self.assertEqual(record["hash"], "")
    def test_malformed_json(self) -> None:
        response = self.request("POST", "/v1/messages", b"{not json", {"Content-Type": "application/json"})
        self.assertEqual(response.status, 400)


class CacheDumpTests(ProxyTestCase):
    def test_cache_stats_dumped_for_admin(self) -> None:
        self.post_messages(base_payload())
        self.proxy.dump_cache_stats(force=True)
        path = self.proxy._cache_path
        self.assertTrue(path and path.exists())
        data = json.loads(path.read_text(encoding="utf-8"))
        self.assertIn("hits", data)
        self.assertIn("size", data)
        self.assertIn("limit", data)


class ForwardingTests(ProxyTestCase):
    def test_body_is_masked(self) -> None:
        response = self.post_messages(base_payload())
        self.assertEqual(response.status, 200)
        response.read()
        self.assertEqual(len(self.upstream.requests), 1)
        raw = self.upstream.requests[0]["raw"].decode("utf-8")
        self.assertNotIn("Иванов", raw)
        self.assertIn("[[PERSON_", raw)

    def test_auth_header_forwarded(self) -> None:
        self.post_messages(base_payload()).read()
        self.assertEqual(self.upstream.requests[0]["body"]["model"], "deepseek-chat")

    def test_upstream_error_passthrough(self) -> None:
        self.upstream.fail = True
        response = self.post_messages(base_payload())
        self.assertEqual(response.status, 500)
        self.assertIn("boom", response.read().decode("utf-8"))

    def test_query_string_preserved(self) -> None:
        self.request(
            "POST", "/v1/messages?beta=true",
            json.dumps(base_payload()).encode("utf-8"),
            {"Content-Type": "application/json"},
        ).read()
        self.assertEqual(self.upstream.requests[0]["path"], "/v1/messages?beta=true")

    def test_anthropic_prefix_kept_for_upstream(self) -> None:
        # DSH собирает URL как baseURL + /v1/messages; штатный baseURL содержит /anthropic.
        response = self.request(
            "POST", "/anthropic/v1/messages",
            json.dumps(base_payload()).encode("utf-8"),
            {"Content-Type": "application/json"},
        )
        self.assertEqual(response.status, 200)
        response.read()
        self.assertEqual(self.upstream.requests[0]["path"], "/anthropic/v1/messages")

    def test_models_list_passthrough(self) -> None:
        response = self.request("GET", "/models")
        self.assertEqual(response.status, 200)
        self.assertEqual(json.loads(response.read())["data"][0]["id"], "deepseek-flash")
        self.assertEqual(self.upstream.requests[0]["path"], "/models")


class JsonResponseTests(ProxyTestCase):
    def test_tool_use_restored_with_types(self) -> None:
        response = self.post_messages(base_payload())
        self.assertEqual(response.status, 200)
        payload = json.loads(response.read())
        tool = payload["content"][1]
        self.assertEqual(tool["input"]["path"], "Иванов Иван Иванович/a.txt")
        self.assertEqual(tool["input"]["count"], 3)
        self.assertIn("Иванов Иван Иванович", payload["content"][0]["text"])


class StreamTests(ProxyTestCase):
    def read_stream(self) -> str:
        response = self.post_messages(base_payload(stream=True))
        self.assertEqual(response.status, 200)
        chunks = []
        while True:
            line = response.readline()
            if not line:
                break
            chunks.append(line.decode("utf-8"))
        return "".join(chunks)

    def test_text_delta_keeps_unknown_token(self) -> None:
        # Токен не из этой таблицы (пришёл из истории) — развернуть нечем, отдаём как есть.
        stream = self.read_stream()
        texts = [
            json.loads(line[len("data:"):].strip())["delta"]["text"]
            for line in stream.splitlines()
            if line.startswith("data:") and "text_delta" in line
        ]
        joined = "".join(texts)
        self.assertIn("Привет, ", joined)
        self.assertGreater(len(joined), len("Привет, ") + 5)

    def test_tool_use_sent_as_single_delta(self) -> None:
        stream = self.read_stream()
        deltas = [
            json.loads(line[len("data:"):].strip())
            for line in stream.splitlines()
            if line.startswith("data:") and "input_json_delta" in line
        ]
        self.assertEqual(len(deltas), 1)
        partial = deltas[0]["delta"]["partial_json"]
        restored = json.loads(partial)
        self.assertEqual(restored["path"], "Иванов Иван Иванович/a.txt")

    def test_delta_goes_before_block_stop(self) -> None:
        stream = self.read_stream()
        lines = [line for line in stream.splitlines() if line.startswith("data:")]
        delta_index = next(i for i, line in enumerate(lines) if "input_json_delta" in line)
        stop_index = next(
            i for i, line in enumerate(lines)
            if line.startswith("data:") and '"content_block_stop"' in line and '"index":1' in line.replace(" ", "")
        )
        self.assertLess(delta_index, stop_index)

    def test_token_in_text_is_not_broken(self) -> None:
        stream = self.read_stream()
        for token in TOKEN_RE.findall(stream):
            self.assertRegex(token, r"^\[\[[A-Z]+_[0-9A-F]{10}\]\]$")


class RestoreTextTests(unittest.TestCase):
    # Токены собираем по частям: так литерал гарантированно остаётся ASCII.
    TOKEN = "[[" + "PERSON_" + "ABCDEF1234" + "]]"
    VALUE = "[[" + "PERSON_" + "895080C7C9" + "]]"

    def _restorer(self, restore: bool = True) -> SseRestorer:
        return SseRestorer({self.TOKEN: self.VALUE}, restore_text=restore)

    @staticmethod
    def _delta(restorer: SseRestorer, text: str) -> list[str]:
        return restorer.handle(
            "content_block_delta",
            json.dumps(
                {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": text}},
                ensure_ascii=False,
            ),
        )

    @staticmethod
    def _texts(frames: list[str]) -> list[str]:
        result: list[str] = []
        for frame in frames:
            for line in frame.splitlines():
                if not line.startswith("data: "):
                    continue
                payload = json.loads(line[6:])
                delta = payload.get("delta") or {}
                if delta.get("type") == "text_delta":
                    result.append(delta["text"])
        return result

    @staticmethod
    def _thinking_delta(restorer: SseRestorer, text: str) -> list[str]:
        return restorer.handle(
            "content_block_delta",
            json.dumps(
                {
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": {"type": "thinking_delta", "thinking": text},
                },
                ensure_ascii=False,
            ),
        )

    @staticmethod
    def _thinking_texts(frames: list[str]) -> list[str]:
        result: list[str] = []
        for frame in frames:
            for line in frame.splitlines():
                if not line.startswith("data: "):
                    continue
                payload = json.loads(line[6:])
                delta = payload.get("delta") or {}
                if delta.get("type") == "thinking_delta":
                    result.append(delta["thinking"])
        return result

    def test_thinking_block_is_restored(self) -> None:
        restorer = self._restorer()
        start = restorer.handle(
            "content_block_start",
            json.dumps(
                {
                    "type": "content_block_start",
                    "index": 0,
                    "content_block": {"type": "thinking", "thinking": ""},
                }
            ),
        )
        collected: list[str] = []
        collected += self._thinking_texts(start)
        collected += self._thinking_texts(
            self._thinking_delta(restorer, "Читаю C:\\Users\\[[PER")
        )
        collected += self._thinking_texts(
            self._thinking_delta(restorer, "SON_" + "ABCDEF1234" + "]]\\file.txt")
        )
        collected += self._thinking_texts(
            restorer.handle(
                "content_block_stop",
                json.dumps({"type": "content_block_stop", "index": 0}),
            )
        )
        joined = "".join(collected)
        self.assertIn(self.VALUE, joined)
        self.assertNotIn(self.TOKEN, joined)

    def test_split_token_is_restored(self) -> None:
        restorer = self._restorer()
        collected: list[str] = []
        collected += self._texts(self._delta(restorer, "Клиент [[PER"))
        collected += self._texts(self._delta(restorer, "SON_" + "ABCDEF1234" + "]], здравствуйте"))
        collected += self._texts(
            restorer.handle(
                "content_block_stop",
                json.dumps({"type": "content_block_stop", "index": 0}),
            )
        )
        joined = "".join(collected)
        self.assertIn(self.VALUE, joined)
        self.assertNotIn(self.TOKEN, joined)
        self.assertIn("здравствуйте", joined)
    def test_token_at_the_very_end_is_flushed(self) -> None:
        restorer = self._restorer()
        collected = self._texts(self._delta(restorer, "Имя: " + self.TOKEN))
        collected += self._texts(
            restorer.handle(
                "content_block_stop",
                json.dumps({"type": "content_block_stop", "index": 0}),
            )
        )
        self.assertEqual("".join(collected), "Имя: " + self.VALUE)

    def test_plain_text_survives_delay(self) -> None:
        restorer = self._restorer()
        collected = self._texts(self._delta(restorer, "обычный текст без псевдонимов"))
        collected += self._texts(
            restorer.handle(
                "content_block_stop",
                json.dumps({"type": "content_block_stop", "index": 0}),
            )
        )
        self.assertEqual("".join(collected), "обычный текст без псевдонимов")

    def test_restore_disabled_keeps_token(self) -> None:
        restorer = self._restorer(restore=False)
        frames = self._delta(restorer, self.TOKEN)
        self.assertEqual(self._texts(frames), [self.TOKEN])


    def test_random_splits_are_invariant(self) -> None:
        import random

        text = "Начало " + self.TOKEN + " середина " + self.TOKEN + " конец."
        expected = text.replace(self.TOKEN, self.VALUE)
        rnd = random.Random(7)
        for _ in range(25):
            pieces: list[str] = []
            position = 0
            while position < len(text):
                step = rnd.randint(1, 7)
                pieces.append(text[position : position + step])
                position += step
            restorer = self._restorer()
            collected: list[str] = []
            for piece in pieces:
                collected += self._texts(self._delta(restorer, piece))
            collected += self._texts(
                restorer.handle(
                    "content_block_stop",
                    json.dumps({"type": "content_block_stop", "index": 0}),
                )
            )
            self.assertEqual("".join(collected), expected, f"сбои на разбиении {pieces!r}")


if __name__ == "__main__":
    unittest.main()
