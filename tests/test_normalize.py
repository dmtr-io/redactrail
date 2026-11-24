"""Нормализация ввода: невидимые символы и полноширинные формы не обходят детекторы."""

from __future__ import annotations

import unittest

from redactrail import scan
from redactrail.policy import load_policy
from redactrail.pseudonym import Pseudonymizer
from tests import support

PHONE = "+7 999 123-45-67"
EMAIL = "ivanov@example.com"
ZW = "\u200b"


class NormalizationTests(unittest.TestCase):
    def setUp(self) -> None:
        scan._CACHE.clear()

    def test_zero_width_inside_phone(self) -> None:
        policy = load_policy()
        text = "звоните " + PHONE.replace("999", "9" + ZW + "99") + " сейчас"
        phones = [finding for finding in scan.detect(text, policy) if finding.klass == "phone"]
        self.assertTrue(phones)
        self.assertIn(ZW, text[phones[0].start : phones[0].end])

    def test_bidi_override_inside_email(self) -> None:
        policy = load_policy()
        text = "пишите " + EMAIL.replace("@", "\u202e@") + "."
        emails = [finding for finding in scan.detect(text, policy) if finding.klass == "email"]
        self.assertTrue(emails)

    def test_fullwidth_digits_phone(self) -> None:
        policy = load_policy()
        fullwidth = "＋７ ９９９ １２３ ４５ ６７"
        text = "тел " + fullwidth
        phones = [finding for finding in scan.detect(text, policy) if finding.klass == "phone"]
        self.assertTrue(phones)
        self.assertIn("７", text[phones[0].start : phones[0].end])

    def test_plain_text_is_not_copied(self) -> None:
        normalized, mapping = scan.normalize_with_map("обычный текст без трюков")
        self.assertIsNone(mapping)
        self.assertEqual(normalized, "обычный текст без трюков")

    def test_zw_chars_removed_from_mask_result(self) -> None:
        policy = load_policy()
        with support.scratch_dir() as tmp:
            pseudonymizer = Pseudonymizer.from_key_file(tmp / "secret.key")
            text = "звоните " + PHONE.replace("999", "9" + ZW + "99")
            masked, table = scan.mask_text(text, policy, pseudonymizer)
            self.assertNotIn(ZW, masked)
            self.assertTrue(table)


if __name__ == "__main__":
    unittest.main()
