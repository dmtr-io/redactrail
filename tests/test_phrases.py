"""Реальные формулировки из анкет: нижний регистр, метки, дата после «г.р.»."""

from __future__ import annotations

import unittest

from redactrail import scan
from redactrail.admin import AdminState
from redactrail.policy import load_policy
from redactrail.pseudonym import Pseudonymizer, load_or_create_key
from tests import support


def classes(text: str) -> list[str]:
    policy = load_policy()
    return [finding.klass for finding in scan.detect(text, policy)]


class PhrasesTests(unittest.TestCase):
    def test_lowercase_fio_without_label(self) -> None:
        findings = scan.detect("иванов петр сергеевич пришел", load_policy())
        persons = [finding for finding in findings if finding.klass == "person"]
        self.assertTrue(persons)
        self.assertEqual(persons[0].value, "иванов петр сергеевич")

    def test_lowercase_fio_after_fio_label(self) -> None:
        findings = scan.detect("фио иванов петр сергеевич", load_policy())
        persons = [finding for finding in findings if finding.klass == "person"]
        self.assertTrue(persons)
        self.assertIn("иванов петр сергеевич", persons[0].value.lower())

    def test_capitalized_fio_after_label(self) -> None:
        findings = scan.detect("ФИО: Иванов Петр Сергеевич", load_policy())
        self.assertTrue([f for f in findings if f.klass == "person"])

    def test_dob_after_gr(self) -> None:
        findings = scan.detect("17.01.1995 г.р.", load_policy())
        self.assertTrue([f for f in findings if f.klass == "dob"])

    def test_dob_before_label(self) -> None:
        findings = scan.detect("дата рождения 17.01.1995", load_policy())
        self.assertTrue([f for f in findings if f.klass == "dob"])

    def test_address_after_label(self) -> None:
        findings = scan.detect("адрес питер, малевича 2в", load_policy())
        addresses = [f for f in findings if f.klass == "address"]
        self.assertTrue(addresses)
        self.assertIn("2в", addresses[0].value)

    def test_inn_by_label_without_checksum(self) -> None:
        findings = scan.detect("ИНН 7712345670", load_policy())
        self.assertTrue([f for f in findings if f.klass == "inn"])

    def test_short_number_is_not_inn(self) -> None:
        # 7 цифр — не ИНН: у него 10 или 12 цифр
        findings = scan.detect("инн 5553322", load_policy())
        self.assertFalse([f for f in findings if f.klass == "inn"])

    def test_address_does_not_swallow_phone_on_same_line(self) -> None:
        text = "адрес питер, малевича 2в номер тел. +7 999 123-45-67"
        findings = scan.detect(text, load_policy())
        classes = {finding.klass for finding in findings}
        self.assertIn("address", classes)
        self.assertIn("phone", classes)
        address = next(finding for finding in findings if finding.klass == "address")
        self.assertNotIn("тел", address.value)
        self.assertTrue(address.value.endswith("2в"))

    def test_address_stops_before_recipient(self) -> None:
        from redactrail import ru_names

        surname = sorted(ru_names.SURNAMES)[0].capitalize()
        name = sorted(ru_names.FIRST_NAMES)[0].capitalize()
        address_text = "пр. Мира, д. 12, кв. 3"
        person = surname + " " + name
        text = "адрес: " + address_text + ", получатель " + person + "."
        findings = scan.detect(text, load_policy())
        address = next(finding for finding in findings if finding.klass == "address")
        self.assertNotIn("получатель", address.value)
        self.assertTrue([finding for finding in findings if finding.klass == "person"])

    def test_address_strips_trailing_period(self) -> None:
        findings = scan.detect("адрес питер, малевича 2в.", load_policy())
        address = next(finding for finding in findings if finding.klass == "address")
        self.assertEqual(address.value, "питер, малевича 2в")

    def test_two_names_get_different_tokens(self) -> None:
        with support.scratch_dir() as tmp:
            policy = load_policy()
            pseudonymizer = Pseudonymizer.from_key_file(tmp / "secret.key")
            text = "Клиент иванов петр сергеевич, второй петров иван сергеевич."
            masked, table = scan.mask_text(text, policy, pseudonymizer)
            persons = [token for token in table if token.startswith("[[PERSON_")]
            self.assertEqual(len(persons), 2)
            self.assertEqual(len(set(persons)), 2)
            self.assertNotIn("иванов", masked.lower())
            self.assertNotIn("петров", masked.lower())


class CheckPreviewTests(unittest.TestCase):
    def test_preview_numbers_distinct_values(self) -> None:
        with support.scratch_dir() as tmp:
            (tmp / "policy.json").write_text(
                (support.source_policy()).read_text(encoding="utf-8"), encoding="utf-8"
            )
            state = AdminState(tmp)
            result = state.check_text("фио иванов петр сергеевич; фио петров иван сергеевич")
            self.assertIn("<PERSON_1>", result["masked"])
            self.assertIn("<PERSON_2>", result["masked"])
            self.assertEqual(result["classes"].get("person"), 2)


if __name__ == "__main__":
    unittest.main()
