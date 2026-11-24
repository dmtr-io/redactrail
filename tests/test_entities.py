"""Детерминированные детекторы на синтетических примерах."""

from __future__ import annotations

import unittest

from redactrail import entities


def findings(text: str):
    return entities.find_entities(text)


def classes(text: str) -> set[str]:
    return {finding.klass for finding in findings(text)}


def values(text: str, klass: str) -> list[str]:
    return [finding.value for finding in findings(text) if finding.klass == klass]


class PhoneTests(unittest.TestCase):
    def test_formats(self) -> None:
        for text in (
            "Телефон: +7 999 123-45-67",
            "Звонить 8(495)1234567",
            "номер 8 916 555 44 33 в подписи",
            "тел. +7(999)123-45-67",
        ):
            with self.subTest(text=text):
                self.assertEqual(len(values(text, "phone")), 1, text)

    def test_rejects_short_and_unusual(self) -> None:
        for text in ("Заказ № 8-4512", "код 12345678901", "версия 1.2.3"):
            with self.subTest(text=text):
                self.assertNotIn("phone", classes(text))


class EmailTests(unittest.TestCase):
    def test_finds(self) -> None:
        self.assertEqual(values("Пишите на ivanov@example.ru.", "email"), ["ivanov@example.ru"])

    def test_does_not_touch_plain_words(self) -> None:
        self.assertNotIn("email", classes("схема два-на-два"))


class InnTests(unittest.TestCase):
    def test_ten_digits(self) -> None:
        self.assertEqual(values("ИНН 7707083893", "inn"), ["7707083893"])

    def test_twelve_digits(self) -> None:
        self.assertEqual(values("ИНН 500100732259", "inn"), ["500100732259"])

    def test_broken_checksum_ignored_without_label(self) -> None:
        self.assertNotIn("inn", classes("7707083894"))
        self.assertNotIn("inn", classes("500100732258"))

    def test_label_masks_even_broken_checksum(self) -> None:
        # «ИНН» — явная метка: маскируем, даже если контрольная сумма не сходится
        self.assertIn("inn", classes("ИНН 7707083894"))


class SnilsTests(unittest.TestCase):
    def test_formatted(self) -> None:
        self.assertEqual(values("СНИЛС 112-233-445 95", "snils"), ["112-233-445 95"])

    def test_contiguous(self) -> None:
        self.assertEqual(values("11223344595", "snils"), ["11223344595"])

    def test_broken_ignored(self) -> None:
        self.assertNotIn("snils", classes("112-233-445 94"))


class OgrnTests(unittest.TestCase):
    def test_valid(self) -> None:
        self.assertEqual(values("ОГРН 1027700132195", "ogrn"), ["1027700132195"])
        self.assertEqual(values("304500116000157", "ogrn"), ["304500116000157"])

    def test_broken_ignored(self) -> None:
        self.assertNotIn("ogrn", classes("1027700132196"))


class CardTests(unittest.TestCase):
    def test_with_spaces(self) -> None:
        self.assertEqual(values("карта 4111 1111 1111 1111", "card"), ["4111 1111 1111 1111"])

    def test_broken_luhn_ignored(self) -> None:
        self.assertNotIn("card", classes("4111 1111 1111 1112"))


class PassportAndBirthDateTests(unittest.TestCase):
    def test_passport(self) -> None:
        self.assertEqual(values("паспорт 45 06 №123456", "passport"), ["паспорт 45 06 №123456"])

    def test_birth_date(self) -> None:
        found = values("дата рождения 12.03.1985", "dob")
        self.assertEqual(len(found), 1)
        self.assertIn("12.03.1985", found[0])

    def test_plain_date_is_not_birth_date(self) -> None:
        self.assertNotIn("dob", classes("согласовано 12.03.2024, сумма 145 000 руб."))


class UserPathTests(unittest.TestCase):
    def test_windows_path(self) -> None:
        self.assertEqual(values(r"файл C:\Users\user\AppData\Local\a.json", "user"), ["user"])

    def test_unix_path(self) -> None:
        self.assertEqual(values("файл /home/ivan/project/a.py", "user"), ["ivan"])

    def test_path_without_login_untouched(self) -> None:
        self.assertNotIn("user", classes(r"каталог C:\Program Files\Orca"))

    def test_login_without_path(self) -> None:
        self.assertEqual(values("Приняли на работу ivan.petrov, оклад", "user"), ["ivan.petrov"])

    def test_filename_is_not_login(self) -> None:
        self.assertEqual(values("отчёт report.docx лежит рядом", "user"), [])

    def test_domain_is_not_login(self) -> None:
        self.assertEqual(values("сайт example.com открыт", "user"), [])


class BankDetailsTests(unittest.TestCase):
    def test_kpp(self) -> None:
        self.assertEqual(values("КПП 770701001", "kpp"), ["770701001"])

    def test_bik(self) -> None:
        self.assertEqual(values("БИК 044525225", "bik"), ["044525225"])

    def test_account(self) -> None:
        self.assertEqual(
            values("р/с 40702810100000000123", "account"), ["40702810100000000123"]
        )

    def test_bare_nine_digits_are_not_bik(self) -> None:
        self.assertNotIn("bik", classes("артикул 044525225"))


class SecretTests(unittest.TestCase):
    def test_private_key(self) -> None:
        self.assertIn("private_key", classes("-----BEGIN RSA PRIVATE KEY-----"))

    def test_tokens(self) -> None:
        samples = (
            "AKIAIOSFODNN7EXAMPLE",
            "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8",
            "xoxb-123456789012-abcdefghij",
            "sk_live_" + "1234567890abcdefghijklmn",
            "AIzaSyA1234567890abcdefghijklmnopqrstuv",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        )
        for sample in samples:
            with self.subTest(sample=sample[:12]):
                self.assertIn("secret_token", classes(f"значение {sample} в конфиге"))

    def test_bearer(self) -> None:
        self.assertIn("secret_token", classes("Authorization: Bearer abcdefghijklmnop1234567890"))

    def test_assignments(self) -> None:
        for text in ("password=hunter2secret", "api_key = 0123456789abcdef", "пароль: qwerty123"):
            with self.subTest(text=text):
                self.assertIn("secret_assign", classes(text))

    def test_ordinary_code_is_not_secret(self) -> None:
        for text in ("token = get_token()", "api_key = os.environ['KEY']"):
            with self.subTest(text=text):
                self.assertNotIn("secret_assign", classes(text))


class BlobTests(unittest.TestCase):
    def test_long_base64(self) -> None:
        self.assertIn("blob", classes("data: " + "QUJD" * 200))

    def test_short_base64_is_fine(self) -> None:
        self.assertNotIn("blob", classes("data: " + "QUJD" * 10))


class NonprintableTests(unittest.TestCase):
    def test_ratio(self) -> None:
        self.assertEqual(entities.nonprintable_ratio("обычный текст"), 0.0)
        self.assertGreater(entities.nonprintable_ratio("a\x00b\x01c"), 0.3)


if __name__ == "__main__":
    unittest.main()
