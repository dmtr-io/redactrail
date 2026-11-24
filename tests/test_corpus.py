"""Расширенный корпус бенчмарка: размер, разметка и отсутствие плейсхолдеров."""

from __future__ import annotations

import json
import pathlib
import unittest

CORPUS = pathlib.Path("tests/corpus/pii_bench.jsonl")


class CorpusTests(unittest.TestCase):
    def setUp(self) -> None:
        self.rows = [json.loads(line) for line in CORPUS.read_text(encoding="utf-8").splitlines() if line.strip()]

    def test_size(self) -> None:
        self.assertGreaterEqual(len(self.rows), 150)

    def test_entities_exist_in_text(self) -> None:
        for row in self.rows:
            for entity in row.get("entities", []):
                self.assertIn(entity["value"], row["text"], row["id"])

    def test_values_are_not_placeholders(self) -> None:
        for row in self.rows:
            for entity in row.get("entities", []):
                self.assertFalse(
                    entity["value"].startswith("[["),
                    f"{row['id']}: в корпус попал плейсхолдер",
                )

    def test_required_classes_present(self) -> None:
        classes = {entity["class"] for row in self.rows for entity in row.get("entities", [])}
        for klass in ("person", "phone", "email", "inn", "snils", "passport", "address", "user"):
            self.assertIn(klass, classes)


if __name__ == "__main__":
    unittest.main()
