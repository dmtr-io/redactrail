"""Сборка: детекторы + политика + псевдонимы на уровне текста."""

from __future__ import annotations

import unittest

from redactrail import scan
from redactrail.detections import BLOCK
from redactrail.policy import Policy, load_policy
from redactrail.pseudonym import Pseudonymizer
from tests import support


class DetectTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = load_policy()

    def test_finds_mixed_entities(self) -> None:
        text = "Иванов Иван Иванович, +7 999 123-45-67, ivanov@example.ru"
        classes = {f.klass for f in scan.detect(text, self.policy)}
        self.assertTrue({"person", "phone", "email"} <= classes, classes)

    def test_secret_is_masked_not_blocked(self) -> None:
        text = "конфиг: password=hunter2secret"
        findings = scan.detect(text, self.policy)
        self.assertIn("secret_assign", {f.klass for f in findings})
        self.assertFalse(scan.blocked(findings, self.policy))
    def test_marker_is_masked(self) -> None:
        findings = scan.detect("пометка ДСП", self.policy)
        self.assertIn("marker", {f.klass for f in findings})
        self.assertFalse(scan.blocked(findings, self.policy))
    def test_unknown_mode_does_not_change_detection(self) -> None:
        text = "Иванов Иван"
        strict = scan.detect(text, self.policy)
        audit = scan.detect(text, self.policy.with_mode("audit"))
        self.assertEqual([(f.start, f.end, f.klass) for f in strict], [(f.start, f.end, f.klass) for f in audit])

    def test_finding_offsets_match_text(self) -> None:
        text = "Пишите Иванову И.И. на ivanov@example.ru"
        for finding in scan.detect(text, self.policy):
            self.assertEqual(text[finding.start : finding.end], finding.value)


class AllowTests(unittest.TestCase):
    def test_card_inside_url_is_allowed(self) -> None:
        text = "https://example.ru/order/4111111111111111"
        permissive = Policy()
        self.assertIn("card", {f.klass for f in scan.detect(text, permissive)})
        self.assertNotIn("card", {f.klass for f in scan.detect(text, load_policy())})

    def test_guid_is_allowed(self) -> None:
        text = "Заказ 550e8400-e29b-41d4-a716-446655440000 создан"
        self.assertEqual(scan.detect(text, load_policy()), [])

    def test_allow_never_hides_secret(self) -> None:
        text = "https://example.ru/x?password=hunter2secret"
        findings = scan.detect(text, load_policy())
        self.assertIn("secret_assign", {f.klass for f in findings})
        self.assertFalse(scan.blocked(findings, load_policy()))
    def setUp(self) -> None:
        context = support.scratch_dir()
        self.tmp = context.__enter__()
        self.addCleanup(context.__exit__, None, None, None)
        self.pseudonymizer = Pseudonymizer.from_key_file(self.tmp / "secret.key")
        self.policy = load_policy()

    def test_masks_and_returns_table(self) -> None:
        text = "Позвоните Иванову Ивану Ивановичу на +7 999 123-45-67"
        masked, table = scan.mask_text(text, self.policy, self.pseudonymizer)
        self.assertNotIn("Иванову", masked)
        self.assertNotIn("999", masked)
        self.assertIn("[[PERSON_", masked)
        self.assertIn("[[PHONE_", masked)
        self.assertEqual(len(table), 2)
        restored = masked
        for token, value in table.items():
            restored = restored.replace(token, value)
        self.assertEqual(restored, text)

    def test_mask_is_deterministic(self) -> None:
        text = "Иванов Иван Иванович"
        first, _ = scan.mask_text(text, self.policy, self.pseudonymizer)
        second, _ = scan.mask_text(text, self.policy, self.pseudonymizer)
        self.assertEqual(first, second)

    def test_blocking_fragment_is_left_untouched(self) -> None:
        # Маркер по-прежнему блокирующий: его не маскируем, но остальное — да.
        text = "пометка ДСП и Иванов Иван"
        masked, table = scan.mask_text(text, self.policy, self.pseudonymizer)
        self.assertIn("ДСП", masked)
        self.assertNotIn("Иванов", masked)
        self.assertTrue(table)


class ChunkingTests(unittest.TestCase):
    def test_entity_on_chunk_boundary_is_found(self) -> None:
        policy = load_policy()
        size = policy.limits.chunk_chars
        prefix = "а" * (size - 10)
        text = prefix + " +7 999 123-45-67 " + "б" * 1000
        classes = {f.klass for f in scan.detect(text, policy)}
        self.assertIn("phone", classes)

    def test_every_finding_is_inside_text(self) -> None:
        policy = load_policy()
        text = ("Иванов Иван Иванович писал письма. " * 800) + "+7 999 123-45-67"
        for finding in scan.detect(text, policy):
            self.assertLessEqual(finding.end, len(text))
            self.assertGreaterEqual(finding.start, 0)


class CacheTests(unittest.TestCase):
    def setUp(self) -> None:
        scan._CACHE.clear()
        with scan._CACHE_LOCK:
            scan._CACHE_STATS.update({"hits": 0, "misses": 0})

    def test_second_call_is_cached(self) -> None:
        policy = load_policy()
        text = "тел +7 999 123-45-67"
        first = scan.detect(text, policy)
        second = scan.detect(text, policy)
        self.assertEqual(first, second)
        stats = scan.cache_stats()
        self.assertEqual(stats["misses"], 1)
        self.assertEqual(stats["hits"], 1)

    def test_policy_change_invalidates_cache(self) -> None:
        policy = load_policy()
        text = "тел +7 999 123-45-67"
        scan.detect(text, policy)
        scan.detect(text, policy.with_mode("audit"))
        self.assertEqual(scan.cache_stats()["misses"], 2)


class RedactionTests(unittest.TestCase):
    def test_secret_is_not_restored(self) -> None:
        policy = load_policy()
        pseudonymizer = Pseudonymizer.from_key_file("state/secret.key")
        secret = "api_key=sk-live-" + "A" * 24
        masked, table = scan.mask_text(secret, policy, pseudonymizer)
        self.assertNotIn("sk-live", masked)
        self.assertTrue(masked.startswith("[["))
        self.assertIn("SECRET", masked)
        self.assertEqual(table, {})  # значение не должно попасть в таблицу разворота

    def test_person_is_restored(self) -> None:
        policy = load_policy()
        pseudonymizer = Pseudonymizer.from_key_file("state/secret.key")
        masked, table = scan.mask_text("Клиент Иванов Иван Иванович", policy, pseudonymizer)
        self.assertTrue(table)


if __name__ == "__main__":
    unittest.main()
