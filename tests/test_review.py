"""Аудит сессий: извлечение текста, маскировка известного, отчёт без значений."""

from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path

from redactrail import review
from redactrail.policy import load_policy
from tests import support

EVENTS = [
    {"type": "session", "data": {"id": "s1"}},
    {"type": "user/message", "data": {"content": [{"type": "text", "text": "Клиент Иванов Иван Иванович, звоните."}]}},
    {
        "type": "user/message",
        "data": {"content": [{"type": "text", "text": "Проект Сириус-7 стартует в пятницу."}]},
    },
    {
        "type": "assistant/message",
        "data": {"message": {"content": [{"type": "reasoning", "text": "думаю про Иванов Иван Иванович"}]}},
    },
    {
        "type": "tool/result",
        "data": {"message": {"content": [{"type": "text", "text": "путь C:\\Users\\user\\a.txt"}]}},
    },
    {"type": "step/start", "data": {}},
]


def write_session(root: Path, name: str = "session-x") -> Path:
    directory = root / "--G-project--" / name
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "session.v4.jsonl"
    path.write_text(
        "\n".join(json.dumps(event, ensure_ascii=False) for event in EVENTS) + "\n",
        encoding="utf-8",
    )
    return path


class ReviewDefaultsTests(unittest.TestCase):
    def test_review_url_has_single_default_source(self) -> None:
        from redactrail import policy

        self.assertEqual(review.DEFAULT_BASE_URL, policy.DEFAULT_REVIEW_URL)
        self.assertEqual(policy.ReviewSettings().base_url, policy.DEFAULT_REVIEW_URL)


class ExtractionTests(unittest.TestCase):
    def test_texts_from_all_message_types(self) -> None:
        with support.scratch_dir() as tmp:
            path = write_session(tmp)
            texts = list(review.session_texts(path))
            joined = "\n".join(texts)
            self.assertIn("Иванов Иван Иванович", joined)
            self.assertIn("думаю про", joined)
            self.assertIn("C:\\Users\\user", joined)

    def test_system_prompt_is_skipped(self) -> None:
        with support.scratch_dir() as tmp:
            directory = tmp / "--G-project--" / "session-x"
            directory.mkdir(parents=True)
            path = directory / "session.v4.jsonl"
            path.write_text(
                json.dumps(
                    {
                        "type": "system/message",
                        "data": {"message": {"content": [{"type": "text", "text": "You are an AI agent"}]}},
                    }
                )
                + "\n"
                + json.dumps(
                    {
                        "type": "user/message",
                        "data": {"content": [{"type": "text", "text": "Клиент Иван"}]},
                    },
                    ensure_ascii=False,
                )
                + "\n",
                encoding="utf-8",
            )
            texts = list(review.session_texts(path))
            self.assertFalse(any("AI agent" in text for text in texts))
            self.assertTrue(any("Клиент" in text for text in texts))

    def test_mask_known_replaces_person(self) -> None:
        policy = load_policy()
        masked, count = review.mask_known("Клиент Иванов Иван Иванович звонил", policy)
        self.assertGreaterEqual(count, 1)
        # Метка несёт покрытие: сколько символов значения скрыто.
        self.assertIn("<PERSON_1:", masked)
        self.assertIn(f":{len('Иванов Иван Иванович')}>", masked)
        self.assertNotIn("Иванов Иван Иванович", masked)

    def test_placeholders_are_numbered_by_value(self) -> None:
        policy = load_policy()
        masked, _ = review.mask_known(
            "Клиент Иванов Иван Иванович, второй Иван Петров, снова Иванов Иван Иванович",
            policy,
        )
        self.assertIn("<PERSON_1:", masked)
        self.assertIn("<PERSON_2:", masked)
        self.assertEqual(masked.count("<PERSON_1:"), 2)

    def test_events_older_than_period_are_skipped(self) -> None:
        with support.scratch_dir() as tmp:
            root = tmp / "sessions"
            directory = root / "--G-project--" / "old"
            directory.mkdir(parents=True)
            old_time = 1_600_000_000_000  # сентябрь 2020
            new_time = 2_000_000_000_000
            lines = [
                json.dumps(
                    {"type": "user/message", "time": old_time, "data": {"content": [{"type": "text", "text": "старое сообщение"}]}},
                    ensure_ascii=False,
                ),
                json.dumps(
                    {"type": "user/message", "time": new_time, "data": {"content": [{"type": "text", "text": "новое сообщение"}]}},
                    ensure_ascii=False,
                ),
            ]
            path = directory / "session.v4.jsonl"
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            texts = list(review.session_texts(path, since_ms=1_900_000_000_000))
            self.assertEqual(texts, ["новое сообщение"])

    @unittest.skipIf(sys.version_info < (3, 14), "zstd читается только Python 3.14+")
    def test_zstd_requires_reader(self) -> None:
        with support.scratch_dir() as tmp:
            path = tmp / "x.jsonl.zstd"
            path.write_bytes(b"not a zstd stream")
            with self.assertRaises(review.ReviewError):
                review.decompress_session(path)


class ParseTests(unittest.TestCase):
    def test_placeholders_are_not_findings(self) -> None:
        items = [
            {"category": "email", "quote": "<EMAIL>"},
            {"category": "person", "quote": "Смитом"},
        ]
        self.assertEqual(review.meaningful_findings(items), [{"category": "person", "quote": "Смитом"}])

    def test_plain_json(self) -> None:
        items = review.parse_findings('{"findings": [{"category": "inn", "quote": "123"}], "clean": false}')
        self.assertEqual(items, [{"category": "inn", "quote": "123"}])

    def test_fenced_json(self) -> None:
        items = review.parse_findings('```json\n{"findings": [{"category": "phone", "quote": "+7 999"}]}\n```')
        self.assertEqual(items[0]["quote"], "+7 999")

    def test_garbage(self) -> None:
        self.assertEqual(review.parse_findings("не JSON"), [])
        self.assertEqual(review.parse_findings('{"findings": "нет"}'), [])


class RunReviewTests(unittest.TestCase):
    def test_noise_categories_and_short_quotes_are_ignored(self) -> None:
        policy = load_policy()

        def reviewer(chunk: str) -> list[dict]:
            return [
                {"category": "url", "quote": "https://example.com"},
                {"category": "person", "quote": "abc"},
                {"category": "person", "quote": "Сириус-7"},
            ]

        with support.scratch_dir() as tmp:
            root = tmp / "sessions"
            root.mkdir()
            write_session(root)
            report = review.run_review(root, policy, reviewer, days=7, limit=10)
            self.assertEqual(len(report.findings), 1)
            self.assertEqual(report.findings[0].category, "person")
            self.assertEqual(report.findings[0].length, len("Сириус-7"))

    def test_report_has_hashes_not_values(self) -> None:
        policy = load_policy()
        # [[PERSON_DD7A1F23F4]] цитата, которой правила не знают: она остаётся в тексте
        # после маскировки и именно её модель должна найти.
        quote = "Сириус-7"
        seen: list[str] = []

        def reviewer(chunk: str) -> list[dict]:
            seen.append(chunk)
            return [
                {"category": "org", "quote": quote},
                {"category": "person", "quote": "выдуманная цитата"},
            ]

        with support.scratch_dir() as tmp:
            root = tmp / "sessions"
            root.mkdir()
            write_session(root)
            out = tmp / "audit"
            report = review.run_review(root, policy, reviewer, days=7, limit=10, report_dir=out)
            self.assertEqual(report.sessions, 1)
            self.assertGreaterEqual(report.chunks, 1)
            self.assertEqual(len(report.findings), 1)  # выдуманная цитата отброшена
            self.assertEqual(
                report.findings[0].digest, hashlib.sha256(quote.encode("utf-8")).hexdigest()[:16]
            )
            self.assertTrue(seen)
            # в модель уходит текст с метками, а не значения
            self.assertIn("<PERSON_1:", seen[0])

            report_file = next(out.glob("review-*.json"))
            text = report_file.read_text(encoding="utf-8")
            self.assertNotIn("Иванов Иван Иванович", text)
            self.assertIn("findings", text)

            suggestion_file = next(out.glob("suggestions-*.json"))
            suggestions = json.loads(suggestion_file.read_text(encoding="utf-8"))
            self.assertEqual(len(suggestions), 1)
            self.assertEqual(suggestions[0]["kind"], "missed_pii")
            self.assertEqual(suggestions[0]["hash"], hashlib.sha256(quote.encode("utf-8")).hexdigest()[:16])
            self.assertIn("session-x", suggestions[0]["file"])
            self.assertTrue(suggestions[0]["file"].endswith("session.v4.jsonl"))
            self.assertNotIn(quote, suggestion_file.read_text(encoding="utf-8"))

    def test_suggestions_queue_is_capped(self) -> None:
        with support.scratch_dir() as tmp:
            findings = [
                {"class": "person", "file": "s/x.jsonl", "chunk": i, "hash": f"h{i}", "length": 3}
                for i in range(review.MAX_SUGGESTIONS + 10)
            ]
            report = review.ReviewReport(day="2026-11-19", model="m")
            added = review._write_suggestions(report, tmp, findings)
            self.assertEqual(added, review.MAX_SUGGESTIONS + 10)
            saved = json.loads((tmp / "suggestions-2026-11-19.json").read_text(encoding="utf-8"))
            self.assertEqual(len(saved), review.MAX_SUGGESTIONS)
            self.assertEqual(saved[-1]["chunk"], review.MAX_SUGGESTIONS + 9)

    def test_long_block_is_split_not_truncated(self) -> None:
        long_text = "начало " + "x" * 13000 + " Смитом"
        chunks = review.split_chunks(long_text)
        self.assertGreaterEqual(len(chunks), 3)
        self.assertTrue(all(len(chunk) <= review.MAX_CHUNK_CHARS for chunk in chunks))
        self.assertTrue(chunks[-1].endswith("Смитом"))

    def test_long_block_tail_is_audited(self) -> None:
        policy = load_policy()
        seen: list[str] = []

        def reviewer(chunk: str) -> list[dict]:
            seen.append(chunk)
            return [{"category": "person", "quote": "Смитом"}] if "Смитом" in chunk else []

        with support.scratch_dir() as tmp:
            root = tmp / "sessions"
            directory = root / "--G-project--" / "long"
            directory.mkdir(parents=True)
            text = "логин a.demenko " + ("слово " * 2200) + "Смитом"
            (directory / "session.v4.jsonl").write_text(
                json.dumps({"type": "user/message", "data": {"content": [{"type": "text", "text": text}]}}, ensure_ascii=False)
                + "\n",
                encoding="utf-8",
            )
            out = tmp / "audit"
            report = review.run_review(root, policy, reviewer, days=7, limit=10, report_dir=out)
            self.assertGreaterEqual(report.chunks, 3)
            self.assertEqual(len(report.findings), 1)
            suggestion = json.loads(next(out.glob("suggestions-*.json")).read_text(encoding="utf-8"))[0]
            self.assertGreaterEqual(suggestion["part"], 1)

    def test_report_has_id_and_times_unique_per_run(self) -> None:
        policy = load_policy()
        with support.scratch_dir() as tmp:
            root = tmp / "sessions"
            root.mkdir()
            write_session(root)
            out = tmp / "audit"
            first = review.run_review(root, policy, lambda chunk: [], days=7, limit=5, report_dir=out)
            second = review.run_review(root, policy, lambda chunk: [], days=7, limit=5, report_dir=out)
            self.assertNotEqual(first.run_id, second.run_id)
            files = sorted(out.glob("review-*.json"))
            self.assertEqual(len(files), 2)
            for path in files:
                data = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(len(data["id"]), 12)
                self.assertTrue(data["started_at"])
                self.assertTrue(data["finished_at"])
                self.assertIn(data["id"], path.name)

    def test_zero_limit_audits_everything(self) -> None:
        policy = load_policy()
        with support.scratch_dir() as tmp:
            root = tmp / "sessions"
            root.mkdir()
            write_session(root)
            report = review.run_review(root, policy, None, days=7, limit=0, per_session=0)
            # в фикстуре четыре текстовых блока: два сообщения, размышление, вывод инструмента
            self.assertEqual(report.chunks, 4)
            self.assertFalse(report.cancelled)

    def test_cancel_does_not_count_fragment(self) -> None:
        policy = load_policy()
        with support.scratch_dir() as tmp:
            root = tmp / "sessions"
            root.mkdir()
            write_session(root)
            report = review.run_review(
                root,
                policy,
                lambda chunk: [],
                days=7,
                limit=0,
                per_session=0,
                should_stop=lambda: True,
            )
            self.assertTrue(report.cancelled)
            self.assertEqual(report.chunks, 0)  # отмена до обработки — счётчик не растёт

    def test_same_text_in_different_sessions_is_not_lost(self) -> None:
        policy = load_policy()
        seen: list[str] = []

        def reviewer(chunk: str) -> list[dict]:
            seen.append(chunk)
            # логин, а не ФИО: класс user, иначе сработал бы фильтр идентификаторов
            return [{"category": "user", "quote": "a.demenko"}] if "a.demenko" in chunk else []

        with support.scratch_dir() as tmp:
            root = tmp / "sessions"
            for name in ("one", "two"):
                directory = root / "--G-project--" / name
                directory.mkdir(parents=True)
                (directory / "session.v4.jsonl").write_text(
                    json.dumps(
                        {
                            "type": "user/message",
                            "data": {"content": [{"type": "text", "text": "логин a.demenko в проекте"}]},
                        },
                        ensure_ascii=False,
                    )
                    + "\n",
                    encoding="utf-8",
                )
            out = tmp / "audit"
            report = review.run_review(root, policy, reviewer, days=7, limit=0, report_dir=out)
            self.assertEqual(len(report.findings), 2)
            suggestions = json.loads(next(out.glob("suggestions-*.json")).read_text(encoding="utf-8"))
            self.assertEqual(len(suggestions), 2)
            self.assertEqual(len({item["id"] for item in suggestions}), 2)

    def test_overlap_does_not_duplicate_findings(self) -> None:
        policy = load_policy()
        quoted = "Смитом"
        filler = "слово " * 1200  # ~7200 символов: гарантированно два фрагмента
        text = filler[:5800] + " " + quoted + " " + filler

        def reviewer(chunk: str) -> list[dict]:
            return [{"category": "person", "quote": quoted}] if quoted in chunk else []

        with support.scratch_dir() as tmp:
            root = tmp / "sessions"
            directory = root / "--G-project--" / "long"
            directory.mkdir(parents=True)
            (directory / "session.v4.jsonl").write_text(
                json.dumps(
                    {"type": "user/message", "data": {"content": [{"type": "text", "text": text}]}},
                    ensure_ascii=False,
                )
                + "\n",
                encoding="utf-8",
            )
            report = review.run_review(root, policy, reviewer, days=7, limit=0)
            self.assertGreater(report.chunks, 1)
            self.assertEqual(len(report.findings), 1)

    def test_tool_call_arguments_are_audited(self) -> None:
        with support.scratch_dir() as tmp:
            root = tmp / "sessions"
            directory = root / "--G-project--" / "tools"
            directory.mkdir(parents=True)
            (directory / "session.v4.jsonl").write_text(
                json.dumps(
                    {
                        "type": "assistant/message",
                        "data": {
                            "message": {
                                "content": [
                                    {"type": "text", "text": "открываю файл"},
                                    {
                                        "type": "tool-call",
                                        "name": "read_file",
                                        "arguments": '{"path": "C:\\\\work\\\\[[FILE_94E3E960AB]]\\\\a.txt"}',
                                    },
                                ]
                            }
                        },
                    },
                    ensure_ascii=False,
                )
                + "\n",
                encoding="utf-8",
            )
            texts = list(review.session_texts(directory / "session.v4.jsonl"))
            self.assertTrue(any("read_file" not in text and "path" in text for text in texts))

    def test_short_quotes_are_filtered(self) -> None:
        items = [
            {"category": "person", "quote": "и"},
            {"category": "person", "quote": "a"},
            {"category": "person", "quote": "  "},
            {"category": "person", "quote": "Смит"},
            {"category": "person", "quote": "<USER_1>"},
        ]
        self.assertEqual(review.meaningful_findings(items), [{"category": "person", "quote": "Смит"}])

    def test_no_llm_mode_counts_chunks(self) -> None:
        policy = load_policy()
        with support.scratch_dir() as tmp:
            root = tmp / "sessions"
            root.mkdir()
            write_session(root)
            report = review.run_review(root, policy, None, days=7, limit=10)
            self.assertGreaterEqual(report.chunks, 1)
            self.assertEqual(report.findings, [])

    def test_unreadable_session_reported(self) -> None:
        policy = load_policy()
        with support.scratch_dir() as tmp:
            root = tmp / "sessions"
            (root / "d").mkdir(parents=True)
            (root / "d" / "session.x.jsonl.zstd").write_bytes(b"broken")
            report = review.run_review(root, policy, None, days=7, limit=10)
            if sys.version_info < (3, 14):
                self.assertTrue(report.errors)


class CursorTests(unittest.TestCase):
    """Курсор: «продолжить» не перечитывает проверенное, полный прогон обновляет отметку."""

    def prepare(self, tmp: Path) -> tuple[Path, Path]:
        root = tmp / "sessions"
        root.mkdir()
        path = write_session(root)
        return root, path

    def append_event(self, path: Path, text: str) -> None:
        event = {"type": "user/message", "data": {"content": [{"type": "text", "text": text}]}}
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, ensure_ascii=False) + "\n")

    def test_resume_skips_audited_events(self) -> None:
        policy = load_policy()
        with support.scratch_dir() as tmp:
            root, path = self.prepare(tmp)
            cursor = tmp / "state" / "audit-cursor.json"

            first = review.run_review(root, policy, None, days=7, limit=0, cursor_path=cursor)
            self.assertEqual(first.chunks, 4)
            self.assertFalse(first.resumed)
            self.assertTrue(cursor.exists(), "курсор сохраняется даже без --resume")

            second = review.run_review(
                root, policy, None, days=7, limit=0, cursor_path=cursor, resume=True
            )
            self.assertEqual(second.chunks, 0, "всё уже проверено")
            self.assertTrue(second.resumed)
            self.assertGreater(second.skipped_events, 0)

            self.append_event(path, "Новый клиент Иванов Иван Иванович звонит сегодня.")
            third = review.run_review(
                root, policy, None, days=7, limit=0, cursor_path=cursor, resume=True
            )
            self.assertEqual(third.chunks, 1, "проверяется только новое событие")
            entries = review.load_cursor(cursor)
            self.assertEqual(next(iter(entries.values()))["events"], 7, "курсор сдвинулся за новое")

    def test_resume_restarts_when_file_rewritten(self) -> None:
        policy = load_policy()
        with support.scratch_dir() as tmp:
            root, path = self.prepare(tmp)
            cursor = tmp / "state" / "audit-cursor.json"
            review.run_review(root, policy, None, days=7, limit=0, cursor_path=cursor)

            # тот же путь и то же число строк, но содержимое другое: отпечаток не сойдётся
            rewritten = list(EVENTS)
            rewritten[0] = {"type": "session", "data": {"id": "other"}}
            path.write_text(
                "\n".join(json.dumps(event, ensure_ascii=False) for event in rewritten) + "\n",
                encoding="utf-8",
            )
            report = review.run_review(
                root, policy, None, days=7, limit=0, cursor_path=cursor, resume=True
            )
            self.assertGreater(report.chunks, 0, "файл перечитан заново")
            self.assertFalse(report.resumed)

    def test_full_run_refreshes_cursor(self) -> None:
        policy = load_policy()
        with support.scratch_dir() as tmp:
            root, path = self.prepare(tmp)
            cursor = tmp / "state" / "audit-cursor.json"
            review.run_review(root, policy, None, days=7, limit=0, cursor_path=cursor)
            self.append_event(path, "Ещё один клиент Иванов Иван Иванович пишет письмо.")

            full = review.run_review(root, policy, None, days=7, limit=0, cursor_path=cursor)
            self.assertGreater(full.chunks, 4, "полный прогон проверяет всё окно")
            resumed = review.run_review(
                root, policy, None, days=7, limit=0, cursor_path=cursor, resume=True
            )
            self.assertEqual(resumed.chunks, 0, "после полного прогона новых событий нет")

    def test_limit_moves_cursor_only_past_processed(self) -> None:
        policy = load_policy()
        with support.scratch_dir() as tmp:
            root, _ = self.prepare(tmp)
            cursor = tmp / "state" / "audit-cursor.json"
            total = review.run_review(root, policy, None, days=7, limit=0).chunks
            self.assertEqual(total, 4)

            partial = review.run_review(root, policy, None, days=7, limit=1, cursor_path=cursor)
            self.assertEqual(partial.chunks, 1)
            entries = review.load_cursor(cursor)
            self.assertEqual(len(entries), 1)
            self.assertEqual(next(iter(entries.values()))["events"], 2, "одна строка с текстом")

            rest = review.run_review(
                root, policy, None, days=7, limit=0, cursor_path=cursor, resume=True
            )
            self.assertEqual(rest.chunks, total - 1, "продолжение не повторяет проверенное")

    def test_cursor_tolerates_broken_file(self) -> None:
        with support.scratch_dir() as tmp:
            cursor = tmp / "state" / "audit-cursor.json"
            cursor.parent.mkdir(parents=True)
            cursor.write_text("{ broken", encoding="utf-8")
            self.assertEqual(review.load_cursor(cursor), {})
            self.assertEqual(review.load_cursor(None), {})
            review.save_cursor(cursor, {"a": {"events": 3, "digest": "x"}})
            self.assertEqual(review.load_cursor(cursor)["a"]["events"], 3)


class ModelAvailabilityTests(unittest.TestCase):
    def test_available_and_missing_model(self) -> None:
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                body = b'{"data": [{"id": "good-model"}, {"id": "other"}]}'
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args) -> None:
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        import threading

        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        base = f"http://127.0.0.1:{server.server_address[1]}/v1/chat/completions"

        review.LocalReviewer(base, "good-model").ensure_available()
        with self.assertRaises(review.ReviewError) as caught:
            review.LocalReviewer(base, "bad-model").ensure_available()
        self.assertIn("good-model", str(caught.exception))


class BlockSuggestionTests(unittest.TestCase):
    def test_skips_already_allowed_and_suggests_new(self) -> None:
        policy = load_policy()
        with support.scratch_dir() as tmp:
            (tmp / "blocks-2026-11-19.jsonl").write_text(
                json.dumps(
                    {
                        "v": 1,
                        "time": "2026-11-19T10:00:00+00:00",
                        "class": "unknown_field",
                        "where": "messages[0]: роль 'system'",
                        "hash": "",
                        "length": 0,
                        "decision": "strict",
                    }
                )
                + "\n"
                + json.dumps(
                    {
                        "v": 1,
                        "time": "2026-11-19T10:01:00+00:00",
                        "class": "unknown_field",
                        "where": "messages[0]: поле 'x_new_field'",
                        "hash": "",
                        "length": 0,
                        "decision": "strict",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            items = review.block_suggestions(tmp, days=7, policy=policy)
            self.assertEqual([item["payload"] for item in items], ["x_new_field"])
            self.assertEqual(items[0]["kind"], "add_allowed_field")


class IdentifierFilterTests(unittest.TestCase):
    """Технические идентификаторы — не ПДн, очередь ими не забивается."""

    def test_identifier_heuristic(self) -> None:
        for value in ("dsh-runtimes", "anonymous-user-id", "config.json", "user_id"):
            self.assertTrue(review.looks_like_identifier(value), value)
        for value in ("Smith-Jones", "Смит", "john"):
            self.assertFalse(review.looks_like_identifier(value), value)

    def test_audit_drops_identifier_quotes(self) -> None:
        policy = load_policy()
        with support.scratch_dir() as tmp:
            root = tmp / "sessions"
            directory = root / "--G-project--" / "s"
            directory.mkdir(parents=True)
            text = "Каталог dsh-runtimes лежит рядом с python, а anonymous-user-id — просто метка в конфиге."
            (directory / "session.v4.jsonl").write_text(
                json.dumps(
                    {"type": "user/message", "data": {"content": [{"type": "text", "text": text}]}},
                    ensure_ascii=False,
                )
                + "\n",
                encoding="utf-8",
            )

            def reviewer(chunk: str) -> list[dict]:
                return [
                    {"category": "person", "quote": "dsh-runtimes"},
                    {"category": "person", "quote": "anonymous-user-id"},
                ]

            report = review.run_review(root, policy, reviewer, days=7, limit=0)
            self.assertEqual(report.findings, [], "идентификаторы не должны стать находками")


if __name__ == "__main__":
    unittest.main()
