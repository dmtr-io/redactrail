"""Политика: загрузка, валидация, режимы, маркеры, allow-список."""

from __future__ import annotations

import unittest

from redactrail import policy as policy_module
from redactrail.policy import Policy, load_policy, policy_from_dict


class DefaultPolicyTests(unittest.TestCase):
    def test_repository_policy_loads(self) -> None:
        loaded = load_policy()
        self.assertEqual(loaded.mode, "strict")
        self.assertTrue(loaded.source and loaded.source.endswith(("policy.json", "policy.example.json")))

    def test_builtin_defaults(self) -> None:
        builtin = Policy()
        self.assertEqual(builtin.action_for("person"), "mask")
        self.assertEqual(builtin.action_for("private_key"), "mask")
        self.assertEqual(builtin.action_for("marker"), "mask")
        self.assertFalse(builtin.is_block("secret_token"))
        self.assertFalse(builtin.is_block("phone"))

    def test_marker_pattern(self) -> None:
        patterns = Policy().marker_patterns
        self.assertTrue(patterns)

        def found(text: str) -> bool:
            return any(pattern.search(text) for pattern in patterns)

        # Гриф: отдельная строка или слова-подсказки.
        self.assertTrue(found("Коммерческая тайна"))
        self.assertTrue(found("ДСП"))
        self.assertTrue(found("Пометка: ДСП"))
        self.assertTrue(found("На документе штамп «конфиденциально»"))
        # Перечисление слов в документации — не гриф.
        self.assertFalse(found("это коммерческая тайна, и вот почему"))
        self.assertFalse(found("маркер | «коммерческая тайна», «ДСП» | block"))
        self.assertFalse(found("конфиденциальность повышена"))

    def test_empty_markers(self) -> None:
        self.assertEqual(Policy(markers=()).marker_patterns, ())
        self.assertIsNone(Policy(markers=()).marker_pattern)


class ValidationTests(unittest.TestCase):
    def test_unknown_mode(self) -> None:
        with self.assertRaises(ValueError):
            policy_from_dict({"mode": "paranoid"})

    def test_unknown_action(self) -> None:
        with self.assertRaises(ValueError):
            policy_from_dict({"actions": {"person": "delete"}})

    def test_bad_allow_regex(self) -> None:
        with self.assertRaises(ValueError):
            policy_from_dict({"allow": [{"name": "x", "pattern": "([", "classes": ["*"]}]})

    def test_allow_entry_without_name(self) -> None:
        with self.assertRaises(ValueError):
            policy_from_dict({"allow": [{"pattern": "x"}]})

    def test_limits_are_checked(self) -> None:
        with self.assertRaises(ValueError):
            policy_from_dict({"limits": {"chunk_chars": 500}})

    def test_missing_file_with_explicit_path(self) -> None:
        with self.assertRaises(FileNotFoundError):
            load_policy("нет-такого-файла.json")


class PolicyBehaviourTests(unittest.TestCase):
    def test_actions_merge_with_defaults(self) -> None:
        custom = policy_from_dict({"actions": {"phone": "allow"}})
        self.assertEqual(custom.action_for("phone"), "allow")
        self.assertEqual(custom.action_for("person"), "mask")
        self.assertFalse(custom.is_block("private_key"))

    def test_with_mode_keeps_rules(self) -> None:
        original = load_policy()
        audit = original.with_mode("audit")
        self.assertEqual(audit.mode, "audit")
        self.assertEqual(audit.actions, original.actions)
        self.assertEqual(audit.markers, original.markers)
        self.assertEqual(audit.allow, original.allow)

    def test_allow_rule_covers_classes(self) -> None:
        loaded = load_policy()
        by_name = {rule.name: rule for rule in loaded.allow}
        self.assertTrue(by_name["guid"].covers("person"))
        self.assertFalse(by_name["url"].covers("email"))
        self.assertTrue(by_name["url"].covers("phone"))

    def test_mask_classes(self) -> None:
        self.assertIn("person", Policy().mask_classes())
        self.assertIn("private_key", Policy().mask_classes())


if __name__ == "__main__":
    unittest.main()
