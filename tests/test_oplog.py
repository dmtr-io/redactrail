"""Журнал событий: запись, хвост, ротация."""

from __future__ import annotations

import json
import unittest

from redactrail.oplog import OpLog
from tests import support


class OpLogTests(unittest.TestCase):
    def test_write_and_tail(self) -> None:
        with support.scratch_dir() as tmp:
            log = OpLog(tmp / "admin.log")
            log.write("admin_start", port=8788, version="1.0.0")
            log.write("review_start", limit=10)
            tail = log.tail(10)
            self.assertEqual([item["event"] for item in tail], ["admin_start", "review_start"])
            self.assertEqual(tail[0]["port"], 8788)

    def test_tail_reads_previous_files(self) -> None:
        with support.scratch_dir() as tmp:
            log = OpLog(tmp / "admin.log", max_bytes=120, backups=2)
            for index in range(10):
                log.write("event", index=index, pad="x" * 40)
            tail = log.tail(30)
            self.assertGreaterEqual(len(tail), 5)
            self.assertEqual(tail[-1]["index"], 9)

    def test_broken_line_skipped(self) -> None:
        with support.scratch_dir() as tmp:
            path = tmp / "admin.log"
            path.write_text('{"time": "x", "event": "ok"}\n{ битый\n', encoding="utf-8")
            tail = OpLog(path).tail(5)
            self.assertEqual(tail[0]["event"], "ok")

    def test_rotation_keeps_limit(self) -> None:
        with support.scratch_dir() as tmp:
            log = OpLog(tmp / "admin.log", max_bytes=200, backups=2)
            for index in range(30):
                log.write("event", index=index, pad="y" * 50)
            files = sorted(path.name for path in tmp.iterdir())
            self.assertIn("admin.log", files)
            self.assertLessEqual(len(files), 3)  # текущий + два бэкапа
            self.assertGreater(log.path.stat().st_size, 0)

    def test_write_failure_is_swallowed(self) -> None:
        with support.scratch_dir() as tmp:
            blocker = tmp / "blocker"
            blocker.write_text("x", encoding="utf-8")
            log = OpLog(blocker / "x.log")  # родитель — файл, каталог не создать
            log.write("event")
            self.assertEqual(log.tail(5), [])


if __name__ == "__main__":
    unittest.main()
