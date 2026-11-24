"""Проверка утечек: чистый прогон и обнаружение утечки в режиме off."""

from __future__ import annotations

import json
import unittest

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


if __name__ == "__main__":
    unittest.main()
