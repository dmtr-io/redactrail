"""Проверка журналов: битые строки и несоответствия схеме."""

from __future__ import annotations

import json
import unittest
from datetime import date

from redactrail import audit_check
from tests import support


def write_journal(directory, lines) -> None:
    path = directory / f"{date.today().isoformat()}.jsonl"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


class CheckTests(unittest.TestCase):
    def test_clean_journal_has_no_issues(self) -> None:
        with support.scratch_dir() as tmp:
            write_journal(
                tmp,
                [
                    json.dumps({"v": 1, "time": "2026-11-19T10:00:00+00:00", "masked": {"person": 2}, "bytes": 10}),
                    json.dumps({"v": 1, "time": "2026-11-19T10:01:00+00:00", "masked": {}, "blocked": "marker"}),
                ],
            )
            report = audit_check.run(tmp)
            self.assertTrue(report.ok)
            self.assertEqual(report.lines, 2)

    def test_broken_json_is_reported(self) -> None:
        with support.scratch_dir() as tmp:
            write_journal(tmp, ['{"v": 1, "time": "x", "masked": {}}', "{ битый"])
            report = audit_check.run(tmp)
            self.assertFalse(report.ok)
            self.assertIn("битый JSON", report.issues[0].problem)

    def test_missing_version_is_legacy_not_issue(self) -> None:
        with support.scratch_dir() as tmp:
            write_journal(tmp, [json.dumps({"time": "x", "masked": {"person": 1}})])
            report = audit_check.run(tmp)
            self.assertTrue(report.ok)
            self.assertEqual(report.legacy, 1)

    def test_missing_required_field(self) -> None:
        with support.scratch_dir() as tmp:
            write_journal(tmp, [json.dumps({"v": 1, "masked": {}})])
            problems = " ".join(issue.problem for issue in audit_check.run(tmp).issues)
            self.assertIn("нет поля time", problems)

    def test_unknown_version(self) -> None:
        with support.scratch_dir() as tmp:
            write_journal(tmp, [json.dumps({"v": 99, "time": "x", "masked": {}})])
            problems = " ".join(issue.problem for issue in audit_check.run(tmp).issues)
            self.assertIn("версия 99", problems)

    def test_bad_masked_count(self) -> None:
        with support.scratch_dir() as tmp:
            write_journal(tmp, [json.dumps({"v": 1, "time": "x", "masked": {"person": "много"}})])
            problems = " ".join(issue.problem for issue in audit_check.run(tmp).issues)
            self.assertIn("masked[person] не число", problems)

    def test_blocks_journal_uses_its_own_schema(self) -> None:
        with support.scratch_dir() as tmp:
            (tmp / "blocks-2026-11-19.jsonl").write_text(
                json.dumps(
                    {
                        "v": 1,
                        "time": "2026-11-19T10:00:00+00:00",
                        "class": "marker",
                        "hash": "abc",
                        "where": "messages[0]",
                        "length": 3,
                        "decision": "block",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            self.assertTrue(audit_check.run(tmp).ok)

    def test_blocks_journal_without_class_is_an_issue(self) -> None:
        with support.scratch_dir() as tmp:
            (tmp / "blocks-2026-11-19.jsonl").write_text(
                json.dumps({"v": 1, "time": "x", "hash": "abc", "where": "m"}) + "\n", encoding="utf-8"
            )
            problems = " ".join(issue.problem for issue in audit_check.run(tmp).issues)
            self.assertIn("нет поля class", problems)

    def test_missing_directory(self) -> None:
        with support.scratch_dir() as tmp:
            report = audit_check.run(tmp / "нет-такого")
            self.assertFalse(report.ok)

    def test_cli_exit_codes(self) -> None:
        with support.scratch_dir() as tmp:
            write_journal(tmp, [json.dumps({"v": 1, "time": "x", "masked": {}})])
            self.assertEqual(audit_check.main(["--dir", str(tmp), "--quiet"]), 0)
            write_journal(tmp, ["{ битый"])
            self.assertEqual(audit_check.main(["--dir", str(tmp), "--quiet"]), 1)


if __name__ == "__main__":
    unittest.main()
