"""Псевдонимы: стабильность, необратимость, нормализация, ключ на диске."""

from __future__ import annotations

import unittest

from redactrail import pseudonym
from tests import support


class TokenTests(unittest.TestCase):
    def setUp(self) -> None:
        context = support.scratch_dir()
        self.tmp = context.__enter__()
        self.addCleanup(context.__exit__, None, None, None)
        self.key_path = self.tmp / "state" / "secret.key"
        self.pseudonymizer = pseudonym.Pseudonymizer.from_key_file(self.key_path)

    def test_stable_within_process(self) -> None:
        first = self.pseudonymizer.token("person", "Иванов Иван Иванович")
        second = self.pseudonymizer.token("person", "Иванов Иван Иванович")
        self.assertEqual(first, second)

    def test_stable_across_instances_with_same_key(self) -> None:
        other = pseudonym.Pseudonymizer.from_key_file(self.key_path)
        self.assertEqual(
            self.pseudonymizer.token("person", "Иванов Иван Иванович"),
            other.token("person", "Иванов Иван Иванович"),
        )

    def test_different_key_gives_different_token(self) -> None:
        other_path = self.tmp / "other.key"
        other = pseudonym.Pseudonymizer.from_key_file(other_path)
        self.assertNotEqual(
            self.pseudonymizer.token("person", "Иванов"),
            other.token("person", "Иванов"),
        )

    def test_classes_do_not_collide(self) -> None:
        self.assertNotEqual(
            self.pseudonymizer.token("person", "Иванов"),
            self.pseudonymizer.token("org", "Иванов"),
        )

    def test_token_format(self) -> None:
        import re

        token = self.pseudonymizer.token("person", "Иванов Иван")
        self.assertRegex(token, r"^\[\[PERSON_[0-9A-F]{10}\]\]$")
        self.assertIsNone(re.search("Иванов", token))

    def test_normalization_of_names(self) -> None:
        first = self.pseudonymizer.token("person", "Иванов  Иван")
        second = self.pseudonymizer.token("person", "иванов иван")
        self.assertEqual(first, second)

    def test_normalization_of_phones(self) -> None:
        for value in ("+7 999 123-45-67", "8 (999) 123 45 67", "89991234567"):
            with self.subTest(value=value):
                self.assertEqual(
                    self.pseudonymizer.token("phone", "+7 999 123-45-67"),
                    self.pseudonymizer.token("phone", value),
                )

    def test_empty_value_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.pseudonymizer.token("person", "   ")

    def test_unknown_class_rejected(self) -> None:
        with self.assertRaises(KeyError):
            self.pseudonymizer.token("secret_weapon", "x")

    def test_table_maps_token_back_to_value(self) -> None:
        table = self.pseudonymizer.table([("person", "Иванов Иван"), ("phone", "+7 999 123-45-67")])
        self.assertEqual(len(table), 2)
        self.assertIn("Иванов Иван", table.values())


class ExpandTests(unittest.TestCase):
    def test_expand_known_and_keep_unknown(self) -> None:
        table = {"[[PERSON_AAAAAAAAAA]]": "Иванов Иван"}
        text = '{"path": "[[PERSON_AAAAAAAAAA]]/file.txt", "note": "[[ORG_BBBBBBBBBB]]"}'
        expanded = pseudonym.expand_tokens(text, table)
        self.assertIn("Иванов Иван", expanded)
        self.assertIn("[[ORG_BBBBBBBBBB]]", expanded)


class KeyFileTests(unittest.TestCase):
    def test_creates_key_of_32_bytes(self) -> None:
        with support.scratch_dir() as tmp:
            path = tmp / "state" / "secret.key"
            key = pseudonym.load_or_create_key(path)
            self.assertEqual(len(key), 32)
            self.assertEqual(path.read_bytes(), key)
            self.assertEqual(pseudonym.load_or_create_key(path), key)

    def test_truncated_key_rejected(self) -> None:
        with support.scratch_dir() as tmp:
            path = tmp / "secret.key"
            path.write_bytes(b"short")
            with self.assertRaises(ValueError):
                pseudonym.load_or_create_key(path)

    def test_short_key_rejected_by_constructor(self) -> None:
        with self.assertRaises(ValueError):
            pseudonym.Pseudonymizer(b"1234567890")


if __name__ == "__main__":
    unittest.main()
