"""Восстановление фразы блокировки по hash+length из сессий."""

from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

from redactrail import recover, scan
from redactrail.policy import Policy
from tests import support

PHONE_TEXT = "Клиент, телефон +7 916 000-00-01."


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def detect_one(text: str, klass: str) -> str:
    """Значение находки класса — то, что прокси положил бы в журнал блокировок."""
    for finding in scan.detect(text, Policy()):
        if finding.klass == klass:
            return finding.value
    raise AssertionError(f"детектор не нашёл {klass} в {text!r}")


def session_line(*texts: str) -> str:
    """Событие сессии DSH с текстовыми блоками."""
    return (
        json.dumps(
            {
                "type": "user/message",
                "data": {"content": [{"type": "text", "text": text} for text in texts]},
            },
            ensure_ascii=False,
        )
        + "\n"
    )


class RecoverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.context = support.scratch_dir()
        self.root = self.context.__enter__()
        self.addCleanup(self.context.__exit__, None, None, None)
        self.workspace = self.root / "sessions" / "demo"
        self.workspace.mkdir(parents=True)
        self.policy = Policy()

    def write_session(self, *lines: str, name: str = "session.v4.jsonl") -> Path:
        path = self.workspace / name
        path.write_text("".join(lines), encoding="utf-8")
        return path

    def test_rule_pass_finds_marker(self) -> None:
        self.write_session(session_line("коммерческая тайна\nСлужебная записка."))
        record = {
            "class": "marker",
            "hash": digest("коммерческая тайна"),
            "length": len("коммерческая тайна"),
            "time": "2026-11-19T12:09:16+00:00",
            "where": "messages[4][0][0]",
        }
        found = recover.find_phrase(record, self.root / "sessions", self.policy)
        self.assertEqual(found.value, "коммерческая тайна")
        self.assertEqual(found.how, "правило")
        self.assertIn("коммерческая тайна", found.context)
        self.assertEqual(found.session, str(Path("demo") / "session.v4.jsonl"))

    def test_context_masks_neighbour_findings(self) -> None:
        phone = detect_one(PHONE_TEXT, "phone")
        text = f"телефон {phone}, гриф: коммерческая тайна"
        self.write_session(session_line(text))
        record = {
            "class": "marker",
            "hash": digest("коммерческая тайна"),
            "length": len("коммерческая тайна"),
            "time": "2026-11-19T12:09:16+00:00",
        }
        found = recover.find_phrase(record, self.root / "sessions", self.policy)
        self.assertEqual(found.value, "коммерческая тайна")
        self.assertNotIn(phone, found.context, "соседний телефон должен быть замаскирован")
        self.assertIn("<phone>", found.context)

    def test_brute_pass_finds_phrase_without_rule(self) -> None:
        # такой строки нет ни в одном правиле детекторов: только перебор
        self.write_session(session_line("артикул XQ-7731, остальное неважно"))
        record = {"class": "marker", "hash": digest("XQ-7731"), "length": len("XQ-7731")}
        found = recover.find_phrase(record, self.root / "sessions", self.policy)
        self.assertEqual(found.value, "XQ-7731")
        self.assertEqual(found.how, "перебор")

    def test_structural_record_has_no_value(self) -> None:
        record = {"class": "unknown_field", "hash": "", "length": 0, "where": "messages[1]: роль 'system'"}
        with self.assertRaises(recover.RecoverError) as caught:
            recover.find_phrase(record, self.root / "sessions", self.policy)
        self.assertIn("структурная", str(caught.exception))

    def test_phrase_not_found_reports_scanned_sessions(self) -> None:
        self.write_session(session_line("совсем другой текст"))
        record = {"class": "marker", "hash": digest("нет такой фразы"), "length": 16}
        with self.assertRaises(recover.RecoverError) as caught:
            recover.find_phrase(record, self.root / "sessions", self.policy)
        self.assertIn("не найдена", str(caught.exception))

    def test_missing_sessions_dir(self) -> None:
        record = {"class": "phone", "hash": digest("79991234567"), "length": 11}
        with self.assertRaises(recover.RecoverError) as caught:
            recover.find_phrase(record, self.root / "nope", self.policy)
        self.assertIn("каталог сессий не найден", str(caught.exception))

    def test_too_long_finding_refused(self) -> None:
        record = {"class": "blob", "hash": "a" * 16, "length": recover.MAX_PHRASE_CHARS + 1}
        with self.assertRaises(recover.RecoverError) as caught:
            recover.find_phrase(record, self.root / "sessions", self.policy)
        self.assertIn("перебор", str(caught.exception))

    def test_budget_limits_scan(self) -> None:
        self.write_session(session_line("x" * 500))
        record = {"class": "marker", "hash": digest("absent"), "length": 6}
        with self.assertRaises(recover.RecoverError) as caught:
            recover.find_phrase(record, self.root / "sessions", self.policy, max_chars=100)
        self.assertIn("символов", str(caught.exception))

    def test_sessions_ordered_by_time(self) -> None:
        early = self.write_session(session_line("нет"), name="session-early.jsonl")
        late = self.write_session(session_line("нет"), name="session-late.jsonl")
        import os

        os.utime(early, (1000, 1000))
        os.utime(late, (2000, 2000))
        record = {"time": "1970-01-01T00:16:40+00:00"}
        ordered = recover.session_files(self.root / "sessions", record)
        self.assertEqual(ordered[0], early)
        self.assertEqual(ordered[-1], late)

    def test_several_places_reported(self) -> None:
        self.write_session(
            session_line("коммерческая тайна\nпервое письмо"),
            session_line("коммерческая тайна\nвторое письмо"),
        )
        record = {"class": "marker", "hash": digest("коммерческая тайна"), "length": len("коммерческая тайна")}
        found = recover.find_phrase(record, self.root / "sessions", self.policy)
        self.assertGreaterEqual(len(found.matches), 2)
        self.assertEqual(found.matches[0].session, found.session)
        self.assertEqual(found.context, found.matches[0].context)

    def test_phone_recovered_by_rule(self) -> None:
        phone = detect_one(PHONE_TEXT, "phone")
        self.write_session(session_line(f"Клиент, телефон {phone}."))
        record = {"class": "phone", "hash": digest(phone), "length": len(phone)}
        found = recover.find_phrase(record, self.root / "sessions", self.policy)
        self.assertEqual(found.value, phone)
        self.assertEqual(found.how, "правило")


if __name__ == "__main__":
    unittest.main()
