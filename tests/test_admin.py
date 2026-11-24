"""Админка ревью: доступ, очередь, решения, применение правок."""

from __future__ import annotations

import json
import threading
import unittest
from http.client import HTTPConnection
from pathlib import Path
from unittest import mock

from redactrail import scan, services
from redactrail.policy import load_policy
from datetime import date

from redactrail.admin import build_server
from tests import support

#: Фикстуры привязаны к сегодняшней дате: журналы читаются по date.today().
TODAY = date.today().isoformat()

TOKEN = "test-token-123"


def prepare_root(tmp: Path) -> Path:
    import shutil

    # [[PERSON_4939D9FFD4]] политика, а не живая: пользователь меняет настройки в админке,
    # и тесты не должны от этого зависеть.
    shutil.copyfile(support.source_policy(), tmp / "policy.json")
    policy = json.loads((tmp / "policy.json").read_text(encoding="utf-8"))
    policy["mode"] = "strict"
    policy.setdefault("actions", {})
    policy["actions"].update({"image": "block", "document": "block", "marker": "mask"})
    for klass in ("private_key", "secret_token", "secret_assign"):
        policy["actions"][klass] = "mask"
    sessions = tmp / "sessions" / "demo"
    sessions.mkdir(parents=True)
    (sessions / "session.v4.jsonl").write_text(
        json.dumps(
            {
                "type": "user/message",
                "data": {"content": [{"type": "text", "text": "Клиент Иванов Иван Иванович, телефон +7 999 123-45-67."}]},
            },
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    policy["review"] = {
        "base_url": "http://127.0.0.1:1/v1/chat/completions",
        "model": "test-model",
        "sessions": str(tmp / "sessions"),
        "days": 7,
        "limit": 5,
        "per_session": 5,
    }
    (tmp / "policy.json").write_text(json.dumps(policy, ensure_ascii=False, indent=2), encoding="utf-8")
    audit = tmp / "audit"
    audit.mkdir()
    suggestions = [
        {
            "id": "s1",
            "class": "marker",
            "kind": "remove_marker",
            "payload": "конфиденциально",
            "count": 12,
            "verdict": "бойлерплейт",
            "window": "…внизу письма: [[PERSON_1C2D]] — конфиденциально…",
            "action": "убрать из маркеров",
        },
        {
            "id": "s2",
            "class": "inn",
            "kind": "add_allow",
            "payload": {"name": "order_number", "pattern": "\\b7712345678\\b", "classes": ["inn"]},
            "count": 4,
            "verdict": "ложное срабатывание",
            "window": "заказ № 7712345678",
            "action": "кандидат в allow-лист",
        },
    ]
    (audit / f"suggestions-{TODAY}.json").write_text(
        json.dumps(suggestions, ensure_ascii=False), encoding="utf-8"
    )
    (audit / f"blocks-{TODAY}.jsonl").write_text(
        json.dumps({"time": "2026-11-19T12:09:16+00:00", "class": "marker", "hash": "abc", "where": "messages[4]"})
        + "\n",
        encoding="utf-8",
    )
    (audit / f"{TODAY}.jsonl").write_text(
        json.dumps({"mode": "strict", "bytes": 100, "masked": {"person": 3}, "blocked": None}) + "\n",
        encoding="utf-8",
    )
    state = tmp / "state"
    state.mkdir()
    (state / "review-candidates.json").write_text(
        json.dumps({"s2": "7712345678"}, ensure_ascii=False), encoding="utf-8"
    )
    return tmp


class Response:
    def __init__(self, status: int, headers, body: bytes) -> None:
        self.status = status
        self.headers = headers
        self.body = body

    @property
    def text(self) -> str:
        return self.body.decode("utf-8")

    def json(self):
        return json.loads(self.body)


class AdminTests(unittest.TestCase):
    def setUp(self) -> None:
        self.context = support.scratch_dir()
        self.root = prepare_root(self.context.__enter__())
        self.server = build_server(port=0, root=self.root, token=TOKEN)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.context.__exit__, None, None, None)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        # тесты не должны опрашивать реальный планировщик Windows
        installed = mock.patch.object(services, "task_installed", return_value=False)
        installed.start()
        self.addCleanup(installed.stop)

    def request(self, method: str, path: str, headers: dict | None = None, body: bytes | None = None) -> Response:
        connection = HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=10)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            return Response(response.status, response.getheaders(), response.read())
        finally:
            connection.close()

    def auth(self, **extra) -> dict:
        return {"X-Admin-Token": TOKEN, **extra}

    def test_read_allowed_from_loopback_without_token(self) -> None:
        # локальному браузеру разрешено читать без токена: cookie может не прийти
        response = self.request("GET", "/api/state")
        self.assertEqual(response.status, 200)
        self.assertIn("mode", response.json())

    def test_mutation_without_token_denied(self) -> None:
        self.assertEqual(self.request("POST", "/api/suggestions/s1/accept").status, 403)

    def test_mutation_allowed_from_same_origin(self) -> None:
        origin = f"http://127.0.0.1:{self.server.server_address[1]}"
        response = self.request("POST", "/api/suggestions/s1/accept", {"Origin": origin})
        self.assertEqual(response.status, 200)

    def test_token_query_sets_cookie_and_serves_page(self) -> None:
        response = self.request("GET", f"/?token={TOKEN}")
        self.assertEqual(response.status, 200)
        self.assertIn("redactrail", response.text)
        header = dict(response.headers).get("Set-Cookie", "")
        self.assertIn("admin_token=", header)

    def test_wrong_token_401(self) -> None:
        self.assertEqual(self.request("GET", f"/?token=nope").status, 401)

    def test_state_lists_suggestions_and_stats(self) -> None:
        response = self.request("GET", "/api/state", self.auth())
        self.assertEqual(response.status, 200)
        data = response.json()
        self.assertEqual(len(data["suggestions"]), 2)
        self.assertEqual(data["pending"], 2)
        self.assertEqual(data["stats"]["masked"]["person"], 3)
        self.assertEqual(data["mode"], "strict")

    def test_candidate_value_only_for_allow(self) -> None:
        ok = self.request("GET", "/api/candidates/s2", self.auth())
        self.assertEqual(ok.status, 200)
        self.assertEqual(ok.json()["value"], "7712345678")
        denied = self.request("GET", "/api/candidates/s1", self.auth())
        self.assertEqual(denied.status, 403)

    def test_accept_and_reject_are_recorded(self) -> None:
        self.assertEqual(self.request("POST", "/api/suggestions/s1/accept", self.auth()).status, 200)
        self.assertEqual(self.request("POST", "/api/suggestions/s2/reject", self.auth()).status, 200)
        decisions = json.loads((self.root / "state" / "review-decisions.json").read_text(encoding="utf-8"))
        self.assertEqual(decisions, {"s1": "accepted", "s2": "rejected"})

    def test_foreign_origin_rejected(self) -> None:
        response = self.request(
            "POST",
            "/api/suggestions/s1/accept",
            self.auth(Origin="https://evil.example"),
        )
        self.assertEqual(response.status, 403)

    def test_unknown_suggestion_404(self) -> None:
        self.assertEqual(self.request("POST", "/api/suggestions/zz/accept", self.auth()).status, 404)

    def test_apply_changes_policy_with_backup(self) -> None:
        self.request("POST", "/api/suggestions/s1/accept", self.auth())
        self.request("POST", "/api/suggestions/s2/accept", self.auth())
        before = json.loads((self.root / "policy.json").read_text(encoding="utf-8"))
        self.assertIn("конфиденциально", before["markers"])

        response = self.request("POST", "/api/policy/apply", self.auth())
        self.assertEqual(response.status, 200)
        data = response.json()
        self.assertTrue(data["backup"])
        self.assertTrue(Path(data["backup"]).exists())
        self.assertTrue(data["diff"])

        after = json.loads((self.root / "policy.json").read_text(encoding="utf-8"))
        self.assertNotIn("конфиденциально", after["markers"])
        names = [rule["name"] for rule in after["allow"]]
        self.assertIn("order_number", names)

    def test_settings_change_mode_and_images(self) -> None:
        body = json.dumps({"mode": "audit", "images_blocked": False, "secrets": "block"}).encode("utf-8")
        response = self.request(
            "POST", "/api/settings", self.auth(**{"Content-Type": "application/json"}), body=body
        )
        self.assertEqual(response.status, 200)
        data = response.json()
        self.assertEqual(data["settings"]["mode"], "audit")
        self.assertFalse(data["settings"]["images_blocked"])
        self.assertEqual(data["settings"]["secrets"], "block")
        self.assertTrue(Path(data["backup"]).exists())

        policy = json.loads((self.root / "policy.json").read_text(encoding="utf-8"))
        self.assertEqual(policy["mode"], "audit")
        self.assertEqual(policy["actions"]["image"], "allow")
        self.assertEqual(policy["actions"]["secret_assign"], "block")

    def test_settings_reject_bad_mode(self) -> None:
        body = json.dumps({"mode": "whatever"}).encode("utf-8")
        response = self.request(
            "POST", "/api/settings", self.auth(**{"Content-Type": "application/json"}), body=body
        )
        self.assertEqual(response.status, 400)

    def test_state_exposes_settings(self) -> None:
        data = self.request("GET", "/api/state", self.auth()).json()
        self.assertEqual(data["settings"]["mode"], "strict")
        self.assertTrue(data["settings"]["images_blocked"])
        self.assertIn("budget_ms", data["settings"])

    def test_processes_reports_all_parts(self) -> None:
        data = self.request("GET", "/api/processes", self.auth()).json()
        self.assertIn("admin", data)
        self.assertIn("proxy", data)
        self.assertIn("model", data)
        self.assertIn("audit", data)
        self.assertIn("journal", data)
        self.assertIsInstance(data["proxy"]["reachable"], bool)  # зависит от живой среды
        self.assertEqual(data["review"]["model"], "test-model")
        self.assertEqual(data["journal"]["retention_days"], 30)

    def test_review_status_and_run_without_llm(self) -> None:
        import time

        status = self.request("GET", "/api/review/status", self.auth()).json()
        self.assertEqual(status["state"], "idle")

        body = json.dumps({"no_llm": True, "limit": 1}).encode("utf-8")
        started = self.request(
            "POST", "/api/review/run", self.auth(**{"Content-Type": "application/json"}), body=body
        )
        self.assertEqual(started.status, 200)

        deadline = time.time() + 5
        state = "running"
        while time.time() < deadline and state == "running":
            time.sleep(0.1)
            state = self.request("GET", "/api/review/status", self.auth()).json()["state"]
        self.assertEqual(state, "done")
        self.assertTrue(list((self.root / "audit").glob("review-*.json")))

    def test_review_settings_saved(self) -> None:
        body = json.dumps({"review": {"model": "другая-модель", "limit": 7}}).encode("utf-8")
        response = self.request(
            "POST", "/api/settings", self.auth(**{"Content-Type": "application/json"}), body=body
        )
        self.assertEqual(response.status, 200)
        policy = json.loads((self.root / "policy.json").read_text(encoding="utf-8"))
        self.assertEqual(policy["review"]["model"], "другая-модель")
        self.assertEqual(policy["review"]["limit"], 7)

    def test_model_probe_lists_models(self) -> None:
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                body = b'{"data": [{"id": "m1"}, {"id": "m2"}]}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args) -> None:  # noqa: A002
                return

        fake = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=fake.serve_forever, daemon=True).start()
        self.addCleanup(fake.server_close)
        self.addCleanup(fake.shutdown)

        policy = json.loads((self.root / "policy.json").read_text(encoding="utf-8"))
        policy["review"]["base_url"] = f"http://127.0.0.1:{fake.server_address[1]}/v1/chat/completions"
        (self.root / "policy.json").write_text(json.dumps(policy, ensure_ascii=False), encoding="utf-8")

        data = self.request("GET", "/api/processes", self.auth()).json()
        self.assertTrue(data["model"]["reachable"])
        self.assertEqual(data["model"]["models"], ["m1", "m2"])

    def test_admin_path_bootstraps_cookie(self) -> None:
        response = self.request("GET", "/admin")
        self.assertEqual(response.status, 303)
        header = dict(response.headers).get("Set-Cookie", "")
        self.assertIn("admin_token=", header)
        cookie = header.split(";", 1)[0]
        page = self.request("GET", "/", {"Cookie": cookie})
        self.assertEqual(page.status, 200)
        self.assertIn("redactrail", page.text)

    def test_admin_path_rejects_foreign_origin(self) -> None:
        response = self.request("GET", "/admin", {"Origin": "https://evil.example"})
        self.assertEqual(response.status, 401)

    def test_root_without_token_serves_page(self) -> None:
        response = self.request("GET", "/")
        self.assertEqual(response.status, 200)
        self.assertIn("data-section=", response.text)

    def test_page_keeps_js_escapes(self) -> None:
        # PAGE — обычная Python-строка: одиночный \n внутри JS превратился бы
        # в реальный перевод строки и сломал скрипт (страница осталась бы пустой).
        from redactrail.admin import PAGE

        self.assertIn("join('\\n')", PAGE)
        self.assertIn("data-section=", PAGE)

    def test_page_has_no_raw_newline_inside_js_strings(self) -> None:
        import re

        from redactrail.admin import PAGE

        # ищем join(' или split(' с настоящим переводом строки внутри кавычек
        self.assertIsNone(re.search(r"(join|split)\('[^']*\n[^']*'\)", PAGE))

    def test_applied_rule_covers_matching_finding(self) -> None:
        digest = "abc123def456"
        finding = {
            "id": "r-abc",
            "class": "phone",
            "kind": "missed_pii",
            "hash": digest,
            "length": 10,
            "window": "найдено моделью",
            "action": "посмотреть",
        }
        pattern = r"(?<!\d)5\d{9}(?!\d)"
        rule = {
            "id": "rp-abc",
            "class": "phone",
            "kind": "rule_patch",
            "verdict": "сужено",
            "count": 1,
            "window": "pattern: " + pattern,
            "action": "проверить",
            "payload": {"class": "phone", "pattern": pattern, "flags": ""},
            "evidence": {"hash": digest, "length": 10},
        }
        (self.root / "audit" / f"suggestions-{TODAY}.json").write_text(
            json.dumps([finding, rule], ensure_ascii=False), encoding="utf-8"
        )
        self.request("POST", "/api/suggestions/rp-abc/accept", self.auth())
        self.request("POST", "/api/policy/apply", self.auth())
        data = self.request("GET", "/api/state", self.auth()).json()
        by_id = {item["id"]: item for item in data["suggestions"]}
        self.assertEqual(by_id["rp-abc"]["decision"], "applied")
        self.assertEqual(by_id["r-abc"]["decision"], "covered")
        self.assertEqual(data["pending"], 0)

    def test_rule_patch_apply_writes_extra_rule(self) -> None:
        pattern = r"[a-z]\.[a-z]{5,10}"
        card = {
            "id": "rp-abc",
            "class": "user",
            "kind": "rule_patch",
            "verdict": "предложено моделью",
            "count": 1,
            "window": "pattern: " + pattern,
            "action": "проверить и принять правило",
            "payload": {
                "class": "user",
                "pattern": pattern,
                "flags": "",
                "explanation": "логин",
                "confidence": 0.8,
            },
        }
        (self.root / "audit" / f"suggestions-{TODAY}.json").write_text(
            json.dumps([card], ensure_ascii=False), encoding="utf-8"
        )
        self.request("POST", "/api/suggestions/rp-abc/accept", self.auth())
        data = self.request("POST", "/api/policy/apply", self.auth()).json()
        self.assertIn("applied", data, data)
        policy = json.loads((self.root / "policy.json").read_text(encoding="utf-8"))
        self.assertTrue(any(rule["pattern"] == pattern for rule in policy["extra_rules"]))
        loaded = load_policy(self.root / "policy.json")
        findings = scan.detect("Логин a.demenko в проекте", loaded)
        self.assertTrue([finding for finding in findings if finding.klass == "user"])

    def test_dashboard_includes_cache_stats(self) -> None:
        (self.root / "state").mkdir(exist_ok=True)
        (self.root / "state" / "cache.json").write_text(
            json.dumps(
                {"hits": 30, "misses": 70, "size": 5, "limit": 32, "time": "2026-11-23T20:00:00+03:00"}
            ),
            encoding="utf-8",
        )
        data = self.request("GET", "/api/dashboard", self.auth()).json()
        self.assertEqual(data["cache"]["hits"], 30)
        self.assertEqual(data["cache"]["hit_rate"], 30.0)
        self.assertEqual(data["cache"]["limit"], 32)
        state = self.request("GET", "/api/state", self.auth()).json()
        self.assertEqual(state["cache"]["hits"], 30)
        self.assertIn("cacheInfo", self.request("GET", "/", self.auth()).text)

    def test_audit_suggestion_shows_value_from_session(self) -> None:
        import hashlib

        quote = "телефон"
        suggestion = {
            "id": "r-abc-0",
            "class": "phone",
            "kind": "missed_pii",
            "verdict": "пропуск правил",
            "file": "demo/session.v4.jsonl",
            "chunk": 0,
            "hash": hashlib.sha256(quote.encode("utf-8")).hexdigest()[:16],
            "length": len(quote),
        }
        (self.root / "audit" / f"suggestions-{TODAY}.json").write_text(
            json.dumps([suggestion], ensure_ascii=False), encoding="utf-8"
        )
        # Политику меняем после прогона: на показ значения это влиять не должно.
        policy = json.loads((self.root / "policy.json").read_text(encoding="utf-8"))
        policy["mode"] = "audit"
        policy["actions"]["person"] = "block"
        (self.root / "policy.json").write_text(json.dumps(policy, ensure_ascii=False), encoding="utf-8")
        response = self.request("GET", "/api/candidates/r-abc-0", self.auth())
        self.assertEqual(response.status, 200)
        self.assertEqual(response.json()["value"], quote)

    def test_dashboard_has_hours_runs_and_logs(self) -> None:
        data = self.request("GET", "/api/dashboard", self.auth()).json()
        self.assertEqual(len(data["hourly"]), 24)
        self.assertIn("audit_runs", data)
        self.assertIn("logs", data)
        self.assertIn("last_request", data)
        if data["last_request"]:
            self.assertIn("masked", data["last_request"])
        self.assertIsInstance(data["proxy"]["reachable"], bool)

    def test_admin_log_records_start_and_settings(self) -> None:
        body = json.dumps({"mode": "audit"}).encode("utf-8")
        self.request("POST", "/api/settings", self.auth(**{"Content-Type": "application/json"}), body=body)
        log_path = self.root / "state" / "admin.log"
        text = log_path.read_text(encoding="utf-8")
        self.assertIn("admin_start", text)
        self.assertIn("settings_saved", text)

    def test_audit_run_is_saved_to_history(self) -> None:
        import time

        body = json.dumps({"no_llm": True, "limit": 1}).encode("utf-8")
        self.request("POST", "/api/review/run", self.auth(**{"Content-Type": "application/json"}), body=body)
        deadline = time.time() + 5
        while time.time() < deadline:
            status = self.request("GET", "/api/review/status", self.auth()).json()
            if status["state"] != "running":
                break
            time.sleep(0.1)
        runs = self.request("GET", "/api/dashboard", self.auth()).json()["audit_runs"]
        self.assertTrue(runs)
        self.assertEqual(runs[-1]["state"], "done")
        self.assertIn("chunks", runs[-1]["summary"])

    def test_check_text_masks_without_storing(self) -> None:
        text = "Пишите на a.b@example.com, телефон +7 999 123-45-67"
        body = json.dumps({"text": text}, ensure_ascii=False).encode("utf-8")
        response = self.request(
            "POST", "/api/check", self.auth(**{"Content-Type": "application/json"}), body=body
        )
        self.assertEqual(response.status, 200)
        data = response.json()
        self.assertIn("<EMAIL_1>", data["masked"])
        self.assertIn("<PHONE_1>", data["masked"])
        self.assertNotIn("a.b@example.com", data["masked"])
        self.assertEqual(data["classes"].get("email"), 1)
        self.assertIsNone(data["blocked"])

        log_text = (self.root / "state" / "admin.log").read_text(encoding="utf-8")
        self.assertIn("check_text", log_text)
        self.assertNotIn("a.b@example.com", log_text)

    def test_check_text_rejects_oversize(self) -> None:
        body = json.dumps({"text": "x" * 20001}).encode("utf-8")
        response = self.request(
            "POST", "/api/check", self.auth(**{"Content-Type": "application/json"}), body=body
        )
        self.assertEqual(response.status, 400)

    def test_page_formats_times_in_local_zone(self) -> None:
        from redactrail.admin import PAGE

        # журнал хранит UTC; таблица обязана показывать местное время, а не строку как есть
        self.assertIn("function fmtTime(", PAGE)
        self.assertIn("fmtTime(b.time, true)", PAGE)
        self.assertNotIn("b.time||'').slice", PAGE)

    def test_review_status_shows_last_run_after_restart(self) -> None:
        runs = self.root / "state" / "audit-runs.jsonl"
        runs.write_text(
            json.dumps(
                {
                    "started": "2026-11-19T10:00:00",
                    "finished": "2026-11-19T10:01:00",
                    "state": "done",
                    "summary": {"chunks": 2, "findings": 1, "errors": 0},
                }
            )
            + "\n",
            encoding="utf-8",
        )
        data = self.request("GET", "/api/review/status", self.auth()).json()
        self.assertEqual(data["last_run"]["state"], "done")
        self.assertEqual(data["last_run"]["summary"]["findings"], 1)

    def test_review_status_reports_cursor(self) -> None:
        cursor = self.root / "state" / "audit-cursor.json"
        cursor.write_text(
            json.dumps(
                {
                    "v": 1,
                    "files": {
                        "demo/session.v4.jsonl": {"events": 12, "digest": "abc"},
                        "demo/other.v4.jsonl": {"events": 3, "digest": "def"},
                    },
                }
            ),
            encoding="utf-8",
        )
        data = self.request("GET", "/api/review/status", self.auth()).json()
        self.assertEqual(data["cursor"]["sessions"], 2)
        self.assertEqual(data["cursor"]["events"], 15)

    def test_review_run_passes_resume_flag(self) -> None:
        with mock.patch.object(type(self.server.state), "start_review", return_value=True) as start:
            response = self.request(
                "POST",
                "/api/review/run",
                self.auth(**{"Content-Type": "application/json"}),
                body=json.dumps({"resume": True, "no_llm": True}).encode("utf-8"),
            )
        self.assertEqual(response.status, 200)
        self.assertTrue(response.json()["started"])
        self.assertTrue(start.call_args.kwargs.get("resume"), "галочка доходит до запуска")

    def test_review_run_without_resume_is_full(self) -> None:
        with mock.patch.object(type(self.server.state), "start_review", return_value=True) as start:
            self.request(
                "POST",
                "/api/review/run",
                self.auth(**{"Content-Type": "application/json"}),
                body=b"{}",
            )
        self.assertFalse(start.call_args.kwargs.get("resume"))

    def test_block_review_produces_suggestion_and_applies_it(self) -> None:
        blocks = self.root / "audit" / f"blocks-{TODAY}.jsonl"
        blocks.write_text(
            json.dumps(
                {
                    "v": 1,
                    "time": "2026-11-19T12:00:00+00:00",
                    "class": "unknown_field",
                    "where": "messages[0]: поле 'x_new_field'",
                    "hash": "abc",
                    "length": 13,
                    "decision": "strict",
                }
            )
            + "\n",
            encoding="utf-8",
        )

        response = self.request(
            "POST", "/api/blocks/review", self.auth(**{"Content-Type": "application/json"}), body=b"{}"
        )
        self.assertEqual(response.status, 200)
        self.assertEqual(response.json()["added"], 1)

        suggestions = [
            item
            for item in self.request("GET", "/api/state", self.auth()).json()["suggestions"]
            if item.get("kind") == "add_allowed_field"
        ]
        self.assertEqual(len(suggestions), 1)
        self.assertEqual(suggestions[0]["kind"], "add_allowed_field")
        self.assertEqual(suggestions[0]["payload"], "x_new_field")

        self.request("POST", f"/api/suggestions/{suggestions[0]['id']}/accept", self.auth())
        changes = self.request("GET", "/api/state", self.auth()).json()["changes"]
        self.assertEqual(changes[0]["action"], "add_allowed_field")

        applied = self.request(
            "POST", "/api/policy/apply", self.auth(**{"Content-Type": "application/json"}), body=b"{}"
        )
        self.assertEqual(applied.status, 200)
        policy = json.loads((self.root / "policy.json").read_text(encoding="utf-8"))
        self.assertIn("x_new_field", policy["request"]["allowed_fields"])

    def test_block_suggest_endpoint(self) -> None:
        body = json.dumps(
            {"where": "messages[1][2]: тип 'video'", "class": "unknown_block"}
        ).encode("utf-8")
        response = self.request(
            "POST", "/api/blocks/suggest", self.auth(**{"Content-Type": "application/json"}), body=body
        )
        self.assertEqual(response.status, 200)
        self.assertEqual(response.json()["detail"], "video")

    def test_hourly_uses_local_time(self) -> None:
        from datetime import datetime as dt

        stamp = "2026-11-23T01:30:00+00:00"
        journal = self.root / "audit" / f"{TODAY}.jsonl"
        journal.write_text(
            journal.read_text(encoding="utf-8")
            + json.dumps({"v": 1, "time": stamp, "bytes": 1, "masked": {}, "blocked": None})
            + "\n",
            encoding="utf-8",
        )
        data = self.request("GET", "/api/dashboard", self.auth()).json()
        expected = dt.fromisoformat(stamp).astimezone().hour
        self.assertEqual(data["hourly"][expected]["requests"], 1)
        self.assertEqual(data["stats"]["day"], TODAY)

    def test_stats_separate_unique_values_from_occurrences(self) -> None:
        # DSH пересылает всю переписку в каждом запросе: «masked» растёт с каждым
        # запросом, а «unique» — только когда значение встретилось впервые.
        journal = self.root / "audit" / f"{TODAY}.jsonl"
        journal.write_text(
            "\n".join(
                json.dumps(record, ensure_ascii=False)
                for record in (
                    {"v": 2, "time": "2026-11-23T09:00:00+00:00", "masked": {"person": 5}, "new": {"person": ["AAAAAAAAAA"]}, "bytes": 10},
                    {"v": 2, "time": "2026-11-23T09:00:05+00:00", "masked": {"person": 5}, "new": {}, "bytes": 10},
                    {"v": 2, "time": "2026-11-23T09:01:00+00:00", "masked": {"person": 4, "phone": 1}, "new": {"person": ["BBBBBBBBBB"], "phone": ["CCCCCCCCCC"]}, "bytes": 10},
                )
            )
            + "\n",
            encoding="utf-8",
        )
        stats = self.request("GET", "/api/state", self.auth()).json()["stats"]
        self.assertEqual(stats["masked"]["person"], 14, "срабатывания считаются как раньше")
        self.assertEqual(stats["unique"]["person"], 2, "разных значений два")
        self.assertEqual(stats["unique"]["phone"], 1)
        self.assertFalse(stats["unique_partial"], "все строки уже со схемой v2")

    def test_stats_mark_partial_day_when_old_records_present(self) -> None:
        journal = self.root / "audit" / f"{TODAY}.jsonl"
        journal.write_text(
            json.dumps({"v": 1, "time": "2026-11-23T08:00:00+00:00", "masked": {"person": 4}, "bytes": 10})
            + "\n"
            + json.dumps({"v": 2, "time": "2026-11-23T09:00:00+00:00", "masked": {"person": 5}, "new": {"person": ["AAAAAAAAAA"]}, "bytes": 10})
            + "\n",
            encoding="utf-8",
        )
        stats = self.request("GET", "/api/state", self.auth()).json()["stats"]
        self.assertTrue(stats["unique_partial"], "часть дня до обновления — числа неполные")
        self.assertEqual(stats["unique"]["person"], 1)

    def test_stats_fall_back_to_masked_without_new_field(self) -> None:
        journal = self.root / "audit" / f"{TODAY}.jsonl"
        journal.write_text(
            json.dumps({"v": 1, "time": "2026-11-23T09:00:00+00:00", "masked": {"person": 3}, "bytes": 10}) + "\n",
            encoding="utf-8",
        )
        stats = self.request("GET", "/api/state", self.auth()).json()["stats"]
        self.assertEqual(stats["unique"], {}, "старые строки без new не дают уникальных чисел")
        self.assertEqual(stats["masked"]["person"], 3)

    def test_suggestions_are_deduplicated_across_days(self) -> None:
        today = self.root / "audit" / f"suggestions-{TODAY}.json"
        yesterday = self.root / "audit" / "suggestions-2000-01-01.json"
        items = json.loads(today.read_text(encoding="utf-8"))
        old = dict(items[0])
        old["verdict"] = "старая копия"
        yesterday.write_text(json.dumps([old], ensure_ascii=False), encoding="utf-8")

        data = self.request("GET", "/api/state", self.auth()).json()
        ids = [item["id"] for item in data["suggestions"]]
        self.assertEqual(len(ids), len(set(ids)), "один id — одна строка очереди")
        self.assertEqual(len(ids), len(items))
        row = next(item for item in data["suggestions"] if item["id"] == old["id"])
        self.assertEqual(row["verdict"], items[0]["verdict"], "побеждает более поздняя запись")

    def test_apply_without_acceptance_changes_nothing(self) -> None:
        before = json.loads((self.root / "policy.json").read_text(encoding="utf-8"))
        response = self.request("POST", "/api/policy/apply", self.auth())
        self.assertEqual(response.status, 200)
        after = json.loads((self.root / "policy.json").read_text(encoding="utf-8"))
        self.assertEqual(before, after)

    def test_processes_reports_autostart_tasks(self) -> None:
        data = self.request("GET", "/api/processes", self.auth()).json()
        autostart = data["autostart"]
        self.assertEqual(autostart["supervisor"]["task"], services.SUPERVISOR_TASK)
        self.assertEqual(autostart["audit"]["task"], services.AUDIT_TASK)
        self.assertFalse(autostart["supervisor"]["installed"])
        self.assertIsInstance(autostart["available"], bool)

    def test_restart_proxy_requires_token(self) -> None:
        self.assertEqual(self.request("POST", "/api/proxy/restart").status, 403)

    def test_restart_proxy_returns_report_and_logs(self) -> None:
        report = {
            "task": services.SUPERVISOR_TASK,
            "installed": True,
            "before": {"reachable": False},
            "after": {"reachable": True, "body": '{"status": "ok"}'},
            "actions": ["start"],
            "ok": True,
        }
        with mock.patch.object(services, "restart_proxy", return_value=report):
            response = self.request("POST", "/api/proxy/restart", self.auth())
        self.assertEqual(response.status, 200)
        self.assertTrue(response.json()["ok"])
        self.assertEqual(response.json()["actions"], ["start"])
        log_text = (self.root / "state" / "admin.log").read_text(encoding="utf-8")
        self.assertIn("proxy_restart", log_text)


    def test_rules_view_lists_policy_and_detectors(self) -> None:
        data = self.request("GET", "/api/rules", self.auth()).json()
        self.assertEqual(data["mode"], "strict")
        self.assertIn("phone", data["actions"])
        self.assertIn("коммерческая тайна", data["markers"])
        self.assertTrue(data["allow"])
        self.assertTrue(data["detectors"])
        self.assertIn("allowed_fields", data["request"])
        self.assertIn("chunk_chars", data["limits"])
        self.assertIn("extra_rules", data)
        self.assertIn("rulesExtra", self.request("GET", "/", self.auth()).text)

    def help_body(self, payload: dict) -> bytes:
        return json.dumps(payload, ensure_ascii=False).encode("utf-8")

    def test_rules_save_writes_policy_with_backup_and_keeps_other_sections(self) -> None:
        current = self.request("GET", "/api/rules", self.auth()).json()
        markers = list(current["markers"]) + ["служебное"]
        response = self.request(
            "POST",
            "/api/rules",
            self.auth(**{"Content-Type": "application/json"}),
            body=self.help_body({"markers": markers}),
        )
        self.assertEqual(response.status, 200)
        data = response.json()
        self.assertTrue(Path(data["backup"]).exists())
        self.assertTrue(data["diff"])
        self.assertIn("служебное", data["rules"]["markers"])

        policy = json.loads((self.root / "policy.json").read_text(encoding="utf-8"))
        self.assertIn("служебное", policy["markers"])
        self.assertEqual(policy["actions"], current["actions"])
        self.assertEqual(policy["review"], current["review"])
        self.assertEqual(policy["request"], current["request"])

    def test_rules_save_changes_action_and_request_lists(self) -> None:
        current = self.request("GET", "/api/rules", self.auth()).json()
        actions = dict(current["actions"])
        actions["marker"] = "block"
        request = dict(current["request"])
        request["allowed_roles"] = request["allowed_roles"] + ["tool"]
        response = self.request(
            "POST",
            "/api/rules",
            self.auth(**{"Content-Type": "application/json"}),
            body=self.help_body({"actions": actions, "request": request}),
        )
        self.assertEqual(response.status, 200)
        policy = json.loads((self.root / "policy.json").read_text(encoding="utf-8"))
        self.assertEqual(policy["actions"]["marker"], "block")
        self.assertIn("tool", policy["request"]["allowed_roles"])

    def test_rules_save_rejects_bad_regex_and_leaves_policy(self) -> None:
        before = (self.root / "policy.json").read_text(encoding="utf-8")
        response = self.request(
            "POST",
            "/api/rules",
            self.auth(**{"Content-Type": "application/json"}),
            body=self.help_body({"allow": [{"name": "broken", "pattern": "([a-z", "classes": ["*"]}]}),
        )
        self.assertEqual(response.status, 400)
        self.assertIn("плохой шаблон", response.json()["error"])
        self.assertEqual((self.root / "policy.json").read_text(encoding="utf-8"), before)

    def test_rules_save_rejects_unknown_section(self) -> None:
        response = self.request(
            "POST",
            "/api/rules",
            self.auth(**{"Content-Type": "application/json"}),
            body=self.help_body({"detectors": []}),
        )
        self.assertEqual(response.status, 400)
        self.assertIn("неизвестные разделы", response.json()["error"])

    def test_rules_save_requires_token(self) -> None:
        response = self.request(
            "POST",
            "/api/rules",
            {"Content-Type": "application/json"},
            body=self.help_body({"mode": "strict"}),
        )
        self.assertEqual(response.status, 403)

    def session_phone(self):
        """Телефон из подготовленной сессии и запись журнала для него."""
        import hashlib

        from redactrail import scan
        from redactrail.policy import load_policy

        path = self.root / "sessions" / "demo" / "session.v4.jsonl"
        event = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
        text = event["data"]["content"][0]["text"]
        policy = load_policy(self.root / "policy.json")
        finding = next(item for item in scan.detect(text, policy) if item.klass == "phone")
        record = {
            "class": "phone",
            "hash": hashlib.sha256(finding.value.encode("utf-8")).hexdigest()[:16],
            "length": len(finding.value),
        }
        return record, finding.value

    def test_block_value_recovers_phrase_from_sessions(self) -> None:
        record, value = self.session_phone()
        response = self.request(
            "POST",
            "/api/blocks/value",
            self.auth(**{"Content-Type": "application/json"}),
            body=self.help_body(record),
        )
        self.assertEqual(response.status, 200)
        data = response.json()
        self.assertEqual(data["value"], value)
        self.assertTrue(data["matches"])
        self.assertEqual(data["matches"][0]["session"], str(Path("demo") / "session.v4.jsonl"))
        log = (self.root / "state" / "admin.log").read_text(encoding="utf-8")
        self.assertIn("block_value", log)
        self.assertNotIn(value, log, "значение не должно попадать в журнал")

    def test_block_value_explains_structural_block(self) -> None:
        response = self.request(
            "POST",
            "/api/blocks/value",
            self.auth(**{"Content-Type": "application/json"}),
            body=self.help_body({"class": "unknown_field", "hash": "", "length": 0}),
        )
        self.assertEqual(response.status, 404)
        self.assertIn("структурная", response.json()["error"])

    def test_block_value_requires_token(self) -> None:
        response = self.request(
            "POST",
            "/api/blocks/value",
            {"Content-Type": "application/json"},
            body=self.help_body({"class": "phone", "hash": "a" * 16, "length": 11}),
        )
        self.assertEqual(response.status, 403)


if __name__ == "__main__":
    unittest.main()
