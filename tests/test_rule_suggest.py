"""Правила, предложенные моделью: политика, сканер, валидация и очередь."""

from __future__ import annotations

import hashlib
import json
import unittest

from redactrail import rule_suggest, scan
from redactrail.policy import load_policy, policy_from_dict
from tests import support

VALUE = "a.demenko"
GENERAL_PATTERN = r"[a-z]\.[a-z]{5,10}"
EXTRA_POLICY = {
    "extra_rules": [
        {"name": "eight", "class": "phone", "pattern": r"8[\s-]?800[\s-]?\d{3}[\s-]?\d{4}"}
    ]
}


class ExtraRuleTests(unittest.TestCase):
    def setUp(self) -> None:
        scan._CACHE.clear()

    def test_extra_rule_catches_phone(self) -> None:
        policy = policy_from_dict(EXTRA_POLICY)
        number = "8" + "800" + "555" + "35" + "35"
        findings = scan.detect("Звоните " + number + " сегодня", policy)
        self.assertTrue([finding for finding in findings if finding.klass == "phone"])
        self.assertEqual(len(policy.extra_rules), 1)

    def test_unknown_class_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            policy_from_dict({"extra_rules": [{"name": "x", "class": "нет", "pattern": "x"}]})

    def test_bad_regex_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            policy_from_dict({"extra_rules": [{"name": "x", "class": "phone", "pattern": "("}]})

    def test_fingerprint_changes_with_extra_rule(self) -> None:
        first = policy_from_dict({})
        second = policy_from_dict(EXTRA_POLICY)
        self.assertNotEqual(first.fingerprint, second.fingerprint)


class ValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = load_policy()

    def test_generalizing_pattern_is_accepted(self) -> None:
        self.assertIsNone(
            rule_suggest.validate_pattern(GENERAL_PATTERN, "", VALUE, self.policy, "user")
        )

    def test_literal_value_is_rejected(self) -> None:
        reason = rule_suggest.validate_pattern(VALUE, "", VALUE, self.policy, "user")
        self.assertIn("дословно", reason or "")

    def test_pattern_matching_safe_sample_is_rejected(self) -> None:
        reason = rule_suggest.validate_pattern(r"(?i).+", "", VALUE, self.policy, "user")
        self.assertIn("разрешённое", reason or "")

    def test_pattern_not_matching_example_is_rejected(self) -> None:
        reason = rule_suggest.validate_pattern(r"^\+7\d+$", "", VALUE, self.policy, "user")
        self.assertIn("не находит", reason or "")


class ProposeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = load_policy()

    def _item(self, root, text):
        directory = root / "sessions" / "--G-project--" / "one"
        directory.mkdir(parents=True)
        (directory / "session.v4.jsonl").write_text(
            json.dumps(
                {"type": "user/message", "data": {"content": [{"type": "text", "text": text}]}},
                ensure_ascii=False,
            )
            + "\n",
            encoding="utf-8",
        )
        digest = hashlib.sha256(VALUE.encode("utf-8")).hexdigest()[:16]
        return {
            "id": "r-1",
            "class": "user",
            "kind": "missed_pii",
            "file": "sessions/--G-project--/one/session.v4.jsonl",
            "chunk": 0,
            "hash": digest,
            "length": len(VALUE),
        }

    def test_propose_writes_card_without_value(self) -> None:
        with support.scratch_dir() as tmp:
            item = self._item(tmp, "Логин " + VALUE + " в проекте")
            card, reason = rule_suggest.propose(
                item,
                self.policy,
                tmp,
                lambda prompt: {"pattern": GENERAL_PATTERN, "flags": "", "explanation": "логин", "confidence": 0.8},
            )
            self.assertIsNone(reason)
            self.assertEqual(card["kind"], "rule_patch")
            self.assertIn(GENERAL_PATTERN, card["window"])
            self.assertNotIn(VALUE, json.dumps(card, ensure_ascii=False))

    def test_literal_proposal_is_skipped(self) -> None:
        with support.scratch_dir() as tmp:
            item = self._item(tmp, "Логин " + VALUE + " в проекте")
            card, reason = rule_suggest.propose(
                item,
                self.policy,
                tmp,
                lambda prompt: {"pattern": VALUE, "flags": "", "confidence": 0.9},
            )
            self.assertIsNone(card)
            self.assertIn("дословно", reason or "")


if __name__ == "__main__":
    unittest.main()
