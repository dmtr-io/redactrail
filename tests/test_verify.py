"""Проверка утечек: чистый прогон и обнаружение утечки в режиме off."""

from __future__ import annotations

import io
import json
import sys
import unittest
from contextlib import redirect_stdout

from redactrail import verify
from tests import support


class VerifyTests(unittest.TestCase):
    def test_clean_run_has_no_leaks(self) -> None:
        with support.scratch_dir() as tmp:
            rows = verify.run(workdir=tmp)
            self.assertGreaterEqual(len(rows), 8)
            self.assertFalse([row for row in rows if row.leaked], "значения утекли")
            self.assertFalse([row for row in rows if not row.token_seen], "нет псевдонимов")

    def test_mode_off_is_detected_as_leak(self) -> None:
        with support.scratch_dir() as tmp:
            policy = json.loads(support.source_policy().read_text(encoding="utf-8"))
            policy["mode"] = "off"
            sabotage = tmp / "policy-off.json"
            sabotage.write_text(json.dumps(policy, ensure_ascii=False), encoding="utf-8")
            rows = verify.run(policy_path=sabotage, workdir=tmp / "work", mode=None)
            self.assertTrue(any(row.leaked for row in rows))

    def test_cli_reports_success(self) -> None:
        with support.scratch_dir() as tmp:
            self.assertEqual(verify.main(["--policy", str(support.source_policy())]), 0)

    def test_cli_survives_cp1252_console(self) -> None:
        # Английская консоль Windows (cp1252) не умеет кириллицу: команда должна
        # перевести вывод в UTF-8, а не упасть с UnicodeEncodeError.
        buffer = io.BytesIO()
        stream = io.TextIOWrapper(buffer, encoding="cp1252")
        with support.scratch_dir(), redirect_stdout(stream):
            self.assertEqual(verify.main(["--policy", str(support.source_policy())]), 0)
            sys.stdout.flush()
        self.assertIn("случай", buffer.getvalue().decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
