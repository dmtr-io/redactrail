"""Журнал: версия схемы, безопасная дозапись, ретенция, восстановление счётчиков."""

from __future__ import annotations

import json
import os
import threading
import unittest
from datetime import date, timedelta

from redactrail.audit import AuditJournal, RECORD_VERSION, append_line, prune_audit
from tests import support


class AppendTests(unittest.TestCase):
    def test_line_has_version_and_is_readable(self) -> None:
        with support.scratch_dir() as tmp:
            journal = AuditJournal(tmp, retention_days=30)
            journal.record("strict", {"person": 2}, None, 100)
            lines = (tmp / f"{date.today().isoformat()}.jsonl").read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 1)
            record = json.loads(lines[0])
            self.assertEqual(record["v"], RECORD_VERSION)
            self.assertEqual(record["masked"]["person"], 2)
            self.assertEqual(record["bytes"], 100)

    def test_concurrent_writes_do_not_interleave(self) -> None:
        with support.scratch_dir() as tmp:
            path = tmp / "x.jsonl"

            def writer(index: int) -> None:
                for _ in range(50):
                    append_line(path, json.dumps({"n": index, "pad": "x" * 200}) + "\n")

            threads = [threading.Thread(target=writer, args=(i,)) for i in range(4)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            lines = path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 200)
            for line in lines:
                json.loads(line)  # каждая строка целая

    def test_prune_removes_only_old_files(self) -> None:
        with support.scratch_dir() as tmp:
            old_day = (date.today() - timedelta(days=40)).isoformat()
            fresh_day = date.today().isoformat()
            (tmp / f"{old_day}.jsonl").write_text("{}\n", encoding="utf-8")
            (tmp / f"blocks-{old_day}.jsonl").write_text("{}\n", encoding="utf-8")
            (tmp / f"suggestions-{old_day}.json").write_text("[]", encoding="utf-8")
            (tmp / f"{fresh_day}.jsonl").write_text("{}\n", encoding="utf-8")

            removed = prune_audit(tmp, 30)
            self.assertEqual(len(removed), 3)
            self.assertFalse((tmp / f"{old_day}.jsonl").exists())
            self.assertTrue((tmp / f"{fresh_day}.jsonl").exists())

    def test_prune_keeps_everything_when_retention_zero(self) -> None:
        with support.scratch_dir() as tmp:
            old = (date.today() - timedelta(days=5)).isoformat()
            (tmp / f"{old}.jsonl").write_text("{}\n", encoding="utf-8")
            self.assertEqual(prune_audit(tmp, 0), [])
            self.assertTrue((tmp / f"{old}.jsonl").exists())


class SeedTests(unittest.TestCase):
    def test_seed_restores_counters(self) -> None:
        with support.scratch_dir() as tmp:
            journal = AuditJournal(tmp, retention_days=30)
            journal.record("strict", {"person": 2, "phone": 1}, None, 100)
            journal.record("strict", {}, "marker", 50)

            restarted = AuditJournal(tmp, retention_days=30)
            restarted.seed()
            snapshot = restarted.snapshot()
            self.assertEqual(snapshot["requests"], 2)
            self.assertEqual(snapshot["bytes"], 150)
            self.assertEqual(snapshot["masked"], {"person": 2, "phone": 1})
            self.assertEqual(snapshot["blocked"], 1)

    def test_new_tokens_are_written_once(self) -> None:
        with support.scratch_dir() as tmp:
            journal = AuditJournal(tmp, retention_days=30)
            tokens = {
                "person": {"[[PERSON_AAAAAAAAAA]]", "[[PERSON_BBBBBBBBBB]]"},
                "phone": {"[[PHONE_CCCCCCCCCC]]"},
            }
            journal.record("strict", {"person": 3, "phone": 1}, None, 100, tokens=tokens)
            journal.record("strict", {"person": 3, "phone": 1}, None, 100, tokens=tokens)
            path = tmp / f"{date.today().isoformat()}.jsonl"
            lines = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(sorted(lines[0]["new"]["person"]), ["AAAAAAAAAA", "BBBBBBBBBB"])
            self.assertEqual(lines[1]["new"], {}, "повтор не должен считаться новым значением")
            snapshot = journal.snapshot()
            self.assertEqual(snapshot["masked"], {"person": 6, "phone": 2})
            self.assertEqual(snapshot["unique"], {"person": 2, "phone": 1})

    def test_seed_remembers_seen_tokens(self) -> None:
        with support.scratch_dir() as tmp:
            journal = AuditJournal(tmp, retention_days=30)
            journal.record("strict", {"person": 1}, None, 10, tokens={"person": {"[[PERSON_AAAAAAAAAA]]"}})

            restarted = AuditJournal(tmp, retention_days=30)
            restarted.seed()
            self.assertEqual(restarted.snapshot()["unique"], {"person": 1})
            restarted.record("strict", {"person": 1}, None, 10, tokens={"person": {"[[PERSON_AAAAAAAAAA]]"}})
            path = tmp / f"{date.today().isoformat()}.jsonl"
            last = json.loads(path.read_text(encoding="utf-8").splitlines()[-1])
            self.assertEqual(last["new"], {}, "значение было до перезапуска — оно не новое")

    def test_broken_line_is_skipped(self) -> None:
        with support.scratch_dir() as tmp:
            path = tmp / f"{date.today().isoformat()}.jsonl"
            path.write_text('{"v": 1, "masked": {"person": 1}, "bytes": 5}\n{ broken\n', encoding="utf-8")
            journal = AuditJournal(tmp, retention_days=30)
            journal.seed()
            self.assertEqual(journal.snapshot()["requests"], 1)


if __name__ == "__main__":
    unittest.main()
