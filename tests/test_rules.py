"""Правила политики: снимок для экрана и валидированная правка."""

from __future__ import annotations

import json
import unittest

from redactrail import rules
from redactrail.policy import load_policy, policy_from_dict
from tests import support


def base_policy() -> dict:
    return json.loads(support.source_policy().read_text(encoding="utf-8"))


class RulesViewTests(unittest.TestCase):
    def setUp(self) -> None:
        self.raw = base_policy()
        self.policy = policy_from_dict(self.raw)
        self.view = rules.rules_view(self.policy, self.raw)

    def test_all_sections_present(self) -> None:
        for key in ("mode", "actions", "markers", "allow", "request", "limits", "restore", "review"):
            self.assertIn(key, self.view)
        self.assertEqual(self.view["sections"], list(rules.SECTIONS))

    def test_actions_cover_known_classes(self) -> None:
        self.assertEqual(self.view["actions"]["phone"], "mask")
        self.assertIn("unknown_field", self.view["actions"])
        self.assertIn("phone", self.view["classes"])
        self.assertIn("secret_assign", self.view["classes"])
        self.assertEqual(self.view["actions_allowed"], ["mask", "block", "allow"])

    def test_allow_rules_are_plain_data(self) -> None:
        names = [rule["name"] for rule in self.view["allow"]]
        self.assertIn("guid", names)
        guid = next(rule for rule in self.view["allow"] if rule["name"] == "guid")
        self.assertIsInstance(guid["pattern"], str)
        self.assertEqual(guid["classes"], ["*"])

    def test_detector_rules_are_read_only_view(self) -> None:
        names = {rule["name"] for rule in self.view["detectors"]}
        self.assertIn("phone", names)
        self.assertIn("email", names)
        phone = next(rule for rule in self.view["detectors"] if rule["name"] == "phone")
        self.assertIn("\\d", phone["pattern"])
        self.assertIn("+7", phone["precheck"])

    def test_review_section_is_exposed(self) -> None:
        self.assertIn("model", self.view["review"])
        self.assertNotIn("review", rules.SECTIONS)


class ApplyEditsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.raw = base_policy()

    def test_markers_replaced(self) -> None:
        merged = rules.apply_edits(self.raw, {"markers": ["конфиденциально", "  ДСП  ", "ДСП", ""]})
        self.assertEqual(merged["markers"], ["конфиденциально", "ДСП"])
        self.assertEqual(policy_from_dict(merged).markers, ("конфиденциально", "ДСП"))

    def test_actions_changed(self) -> None:
        actions = dict(self.raw["actions"])
        actions["marker"] = "block"
        merged = rules.apply_edits(self.raw, {"actions": actions})
        self.assertEqual(policy_from_dict(merged).action_for("marker"), "block")

    def test_allow_rule_added(self) -> None:
        allow = list(self.raw["allow"]) + [
            {"name": "order_number", "pattern": "\\b7712345678\\b", "classes": ["inn"]}
        ]
        merged = rules.apply_edits(self.raw, {"allow": allow})
        policy = policy_from_dict(merged)
        self.assertEqual(len(policy.allow), len(self.raw["allow"]) + 1)
        self.assertEqual(policy.allow[-1].name, "order_number")

    def test_request_field_allowed(self) -> None:
        request = dict(self.raw["request"])
        request["allowed_fields"] = list(request["allowed_fields"]) + ["x_new_field"]
        merged = rules.apply_edits(self.raw, {"request": request})
        self.assertIn("x_new_field", policy_from_dict(merged).request.allowed_fields)

    def test_limits_and_restore(self) -> None:
        merged = rules.apply_edits(
            self.raw, {"limits": {"chunk_chars": 8000, "request_chars": 100000}, "restore": {"text": True}}
        )
        policy = policy_from_dict(merged)
        self.assertEqual(policy.limits.chunk_chars, 8000)
        self.assertTrue(policy.restore.text)

    def test_unknown_sections_ignored_by_view_but_rejected_by_edit(self) -> None:
        merged = rules.apply_edits(self.raw, {"mode": "audit"})
        # остальные разделы не тронуты
        self.assertEqual(merged["markers"], self.raw["markers"])
        self.assertEqual(merged["review"], self.raw["review"])
        with self.assertRaises(ValueError) as caught:
            rules.apply_edits(self.raw, {"detectors": []})
        self.assertIn("неизвестные разделы", str(caught.exception))

    def test_bad_regex_rejected(self) -> None:
        allow = [{"name": "broken", "pattern": "([a-z", "classes": ["*"]}]
        with self.assertRaises(ValueError) as caught:
            rules.apply_edits(self.raw, {"allow": allow})
        self.assertIn("плохой шаблон", str(caught.exception))

    def test_duplicate_allow_name_rejected(self) -> None:
        allow = [
            {"name": "same", "pattern": "a", "classes": ["*"]},
            {"name": "same", "pattern": "b", "classes": ["*"]},
        ]
        with self.assertRaises(ValueError) as caught:
            rules.apply_edits(self.raw, {"allow": allow})
        self.assertIn("уже занято", str(caught.exception))

    def test_bad_action_rejected(self) -> None:
        actions = dict(self.raw["actions"])
        actions["phone"] = "ignore"
        with self.assertRaises(ValueError) as caught:
            rules.apply_edits(self.raw, {"actions": actions})
        self.assertIn("ожидается одно из", str(caught.exception))

    def test_bad_class_name_rejected(self) -> None:
        with self.assertRaises(ValueError) as caught:
            rules.apply_edits(self.raw, {"actions": {"Плохой Класс": "mask"}})
        self.assertIn("имя класса", str(caught.exception))

    def test_empty_request_list_rejected(self) -> None:
        request = dict(self.raw["request"])
        request["allowed_roles"] = []
        with self.assertRaises(ValueError) as caught:
            rules.apply_edits(self.raw, {"request": request})
        self.assertIn("не может быть пустым", str(caught.exception))

    def test_request_chars_below_chunk_rejected(self) -> None:
        with self.assertRaises(ValueError) as caught:
            rules.apply_edits(self.raw, {"limits": {"chunk_chars": 50000, "request_chars": 1000}})
        self.assertIn("request_chars", str(caught.exception))

    def test_limit_out_of_range_rejected(self) -> None:
        with self.assertRaises(ValueError) as caught:
            rules.apply_edits(self.raw, {"limits": {"retention_days": 10_000}})
        self.assertIn("допустимо", str(caught.exception))

    def test_marker_too_long_rejected(self) -> None:
        with self.assertRaises(ValueError) as caught:
            rules.apply_edits(self.raw, {"markers": ["я" * (rules.MAX_MARKER_CHARS + 1)]})
        self.assertIn("длиннее", str(caught.exception))

    def test_restore_must_be_bool(self) -> None:
        with self.assertRaises(ValueError) as caught:
            rules.apply_edits(self.raw, {"restore": {"text": "yes"}})
        self.assertIn("true или false", str(caught.exception))

    def test_bad_mode_rejected(self) -> None:
        with self.assertRaises(ValueError) as caught:
            rules.apply_edits(self.raw, {"mode": "paranoid"})
        self.assertIn("неизвестный режим", str(caught.exception))

    def test_empty_edit_rejected(self) -> None:
        with self.assertRaises(ValueError) as caught:
            rules.apply_edits(self.raw, {})
        self.assertIn("нечего сохранять", str(caught.exception))

    def test_live_policy_still_valid_after_edits(self) -> None:
        # правка не должна ломать живую политику: грузим как прокси при старте
        merged = rules.apply_edits(self.raw, {"markers": ["коммерческая тайна"]})
        policy = policy_from_dict(merged)
        self.assertEqual(policy.markers, ("коммерческая тайна",))
        self.assertTrue(policy.allow)


class RepairLivePolicyTests(unittest.TestCase):
    def test_editor_fixes_broken_marker_list(self) -> None:
        # сценарий «в policy.json остался один маркер — вернём остальные»
        self.raw = base_policy()
        self.raw["markers"] = ["коммерческая тайна"]
        markers = rules.rules_view(policy_from_dict(self.raw), self.raw)["markers"]
        merged = rules.apply_edits(self.raw, {"markers": markers + ["для служебного пользования"]})
        self.assertEqual(policy_from_dict(merged).markers[-1], "для служебного пользования")

    def test_load_policy_file_round_trip(self) -> None:
        policy = load_policy(support.source_policy())
        view = rules.rules_view(policy)
        merged = rules.apply_edits(base_policy(), {"markers": view["markers"]})
        self.assertEqual(policy_from_dict(merged).markers, policy.markers)


if __name__ == "__main__":
    unittest.main()
