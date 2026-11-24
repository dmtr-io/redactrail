"""Детектор разрывов маски: сосед маски и хвоста того же рода."""

from __future__ import annotations

import json
import unittest

from redactrail import review


def masked_pair(prefix: str, value: str, tail: str, label: str):
    """Собрать сырой и замаскированный тексты вместе с картой символов."""
    raw = prefix + value + tail
    masked = prefix + label + tail
    starts = list(range(len(prefix)))
    ends = [index + 1 for index in range(len(prefix))]
    value_start, value_end = len(prefix), len(prefix) + len(value)
    for _ in label:
        starts.append(value_start)
        ends.append(value_end)
    for index in range(len(tail)):
        starts.append(value_end + index)
        ends.append(value_end + index + 1)
    return raw, masked, starts, ends


class BoundaryTests(unittest.TestCase):
    def test_letter_tail_after_person_mask(self) -> None:
        raw, masked, starts, ends = masked_pair(
            "Клиент ", "Иванову", "ский звонит", "<PERSON_1:4>"
        )
        found = review.find_boundaries(raw, masked, starts, ends)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["class"], "person")
        self.assertEqual(found[0]["side"], "after")
        self.assertEqual(found[0]["kind"], "letter")
        self.assertEqual(found[0]["length"], 4)
        self.assertEqual(found[0]["offset"], len(raw) - len("ский звонит"))

    def test_digit_tail_after_phone_mask(self) -> None:
        raw, masked, starts, ends = masked_pair(
            "тел. ", "9991234567", "7", "<PHONE_1:10>"
        )
        found = review.find_boundaries(raw, masked, starts, ends)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["side"], "after")
        self.assertEqual(found[0]["kind"], "digit")
        self.assertEqual(found[0]["length"], 1)

    def test_digit_before_mask(self) -> None:
        raw, masked, starts, ends = masked_pair(
            "8", "9991234567", "", "<PHONE_1:10>"
        )
        found = review.find_boundaries(raw, masked, starts, ends)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["side"], "before")
        self.assertEqual(found[0]["offset"], 0)

    def test_space_and_punctuation_are_normal_borders(self) -> None:
        raw, masked, starts, ends = masked_pair(
            "Клиент ", "Иванову", ", звонит", "<PERSON_1:4>"
        )
        self.assertEqual(review.find_boundaries(raw, masked, starts, ends), [])
        raw, masked, starts, ends = masked_pair(
            "тел. ", "9991234567", " добрый", "<PHONE_1:10>"
        )
        self.assertEqual(review.find_boundaries(raw, masked, starts, ends), [])

    def test_coverage_labels_are_not_findings(self) -> None:
        kept = review.meaningful_findings(
            [
                {"class": "person", "quote": "<PERSON_1:6>"},
                {"class": "person", "quote": "Смитом"},
            ]
        )
        self.assertEqual([item["quote"] for item in kept], ["Смитом"])

    def test_report_carries_boundaries_without_values(self) -> None:
        report = review.ReviewReport(day="2026-11-24", model="test")
        report.boundaries.append(
            {
                "class": "person",
                "side": "after",
                "kind": "letter",
                "hash": "abc123",
                "length": 4,
                "offset": 11,
                "session": "s1",
                "file": "demo/session.v4.jsonl",
                "chunk": 0,
            }
        )
        data = report.as_dict()
        self.assertEqual(len(data["boundaries"]), 1)
        self.assertEqual(data["boundaries"][0]["class"], "person")
        self.assertEqual(data["boundaries"][0]["hash"], "abc123")
        self.assertNotIn("Смит", json.dumps(data, ensure_ascii=False))


if __name__ == "__main__":
    unittest.main()
