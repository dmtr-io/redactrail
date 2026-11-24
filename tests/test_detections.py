"""Разрешение пересечений находок: блокировка важнее, хвосты не теряются."""

from __future__ import annotations

import unittest

from redactrail.detections import BLOCK, MASK, Finding, apply_mask, merge

ACTIONS = {"person": MASK, "address": MASK, "secret_token": BLOCK, "phone": MASK}


class FindingTests(unittest.TestCase):
    def test_rejects_negative_start(self) -> None:
        with self.assertRaises(ValueError):
            Finding(-1, 3, "person")

    def test_rejects_reversed_span(self) -> None:
        with self.assertRaises(ValueError):
            Finding(5, 3, "person")

    def test_length_and_overlap(self) -> None:
        a = Finding(0, 5, "person")
        b = Finding(4, 8, "person")
        self.assertEqual(a.length, 5)
        self.assertTrue(a.overlaps(b))
        self.assertFalse(a.overlaps(Finding(5, 6, "person")))


class MergeTests(unittest.TestCase):
    def test_block_wins_over_mask(self) -> None:
        mask = Finding(0, 20, "person")
        block = Finding(5, 10, "secret_token")
        result = merge([mask, block], ACTIONS)
        # Блокировка в середине: хвосты маскированной находки сохраняются,
        # иначе текст вокруг секрета остался бы открытым.
        self.assertEqual(
            [(f.start, f.end, f.klass) for f in result],
            [(0, 5, "person"), (5, 10, "secret_token"), (10, 20, "person")],
        )

    def test_longer_mask_wins(self) -> None:
        short = Finding(0, 6, "person")
        long = Finding(0, 20, "address")
        self.assertEqual(merge([short, long], ACTIONS), [long])

    def test_disjoint_sorted(self) -> None:
        result = merge([Finding(10, 12, "phone"), Finding(0, 3, "person")], ACTIONS)
        self.assertEqual([(f.start, f.end) for f in result], [(0, 3), (10, 12)])

    def test_touching_spans_do_not_merge(self) -> None:
        result = merge([Finding(0, 3, "person"), Finding(3, 6, "person")], ACTIONS)
        self.assertEqual(len(result), 2)

    def test_empty(self) -> None:
        self.assertEqual(merge([], ACTIONS), [])


class ApplyMaskTests(unittest.TestCase):
    def test_replaces_spans(self) -> None:
        text = "Иванов Иван звонил с +7 999 123-45-67"
        person = text.index("Иванов Иван")
        phone = text.index("+7 999")
        findings = [
            Finding(person, person + len("Иванов Иван"), "person"),
            Finding(phone, len(text), "phone"),
        ]
        masker = lambda finding: f"<{finding.klass}>"  # noqa: E731
        self.assertEqual(apply_mask(text, findings, masker), "<person> звонил с <phone>")

    def test_overlapping_findings_rejected(self) -> None:
        with self.assertRaises(ValueError):
            apply_mask("abcdef", [Finding(0, 3, "person"), Finding(2, 5, "phone")], lambda f: "X")


if __name__ == "__main__":
    unittest.main()
