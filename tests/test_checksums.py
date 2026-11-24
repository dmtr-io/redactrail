"""Контрольные суммы: эталонные значения и порча каждой цифры."""

from __future__ import annotations

import unittest

from redactrail import checksums


class InnTests(unittest.TestCase):
    def test_inn10_valid(self) -> None:
        self.assertTrue(checksums.inn10_ok("7707083893"))

    def test_inn10_broken_check_digit(self) -> None:
        self.assertFalse(checksums.inn10_ok("7707083894"))

    def test_inn10_wrong_length(self) -> None:
        self.assertFalse(checksums.inn10_ok("770708389"))
        self.assertFalse(checksums.inn10_ok("77070838931"))

    def test_inn12_valid(self) -> None:
        self.assertTrue(checksums.inn12_ok("500100732259"))

    def test_inn12_broken_last_digit(self) -> None:
        self.assertFalse(checksums.inn12_ok("500100732258"))

    def test_inn12_broken_eleventh_digit(self) -> None:
        self.assertFalse(checksums.inn12_ok("500100732159"))


class SnilsTests(unittest.TestCase):
    def test_valid(self) -> None:
        self.assertTrue(checksums.snils_ok("112-233-445 95"))
        self.assertTrue(checksums.snils_ok("11223344595"))

    def test_broken_check(self) -> None:
        self.assertFalse(checksums.snils_ok("112-233-445 94"))

    def test_sum_over_100(self) -> None:
        # 999-999-999: сумма 9*9+9*8+...=405, 405 % 101 = 1, контрольное 01.
        self.assertTrue(checksums.snils_ok("999-999-999 01"))
        self.assertFalse(checksums.snils_ok("999-999-999 02"))

    def test_sum_100_or_101_gives_zero(self) -> None:
        # Сумма первых девяти цифр ровно 100 и ровно 101: по правилам ПФР
        # контрольное число в обоих случаях равно нулю.
        self.assertTrue(checksums.snils_ok("920-000-003 00"))
        self.assertFalse(checksums.snils_ok("920-000-003 01"))
        self.assertTrue(checksums.snils_ok("920-000-004 00"))


class OgrnTests(unittest.TestCase):
    def test_ogrn13_valid(self) -> None:
        self.assertTrue(checksums.ogrn_ok("1027700132195"))

    def test_ogrn13_broken(self) -> None:
        self.assertFalse(checksums.ogrn_ok("1027700132196"))

    def test_ogrn15_valid(self) -> None:
        self.assertTrue(checksums.ogrn_ok("304500116000157"))

    def test_ogrn15_broken(self) -> None:
        self.assertFalse(checksums.ogrn_ok("304500116000158"))

    def test_wrong_length(self) -> None:
        self.assertFalse(checksums.ogrn_ok("102770013219"))


class LuhnTests(unittest.TestCase):
    def test_valid_cards(self) -> None:
        for number in ("4111111111111111", "5500005555555559", "378282246310005"):
            with self.subTest(number=number):
                self.assertTrue(checksums.luhn_ok(number))

    def test_with_separators(self) -> None:
        self.assertTrue(checksums.luhn_ok("4111 1111 1111 1111"))

    def test_broken(self) -> None:
        self.assertFalse(checksums.luhn_ok("4111111111111112"))

    def test_too_short(self) -> None:
        self.assertFalse(checksums.luhn_ok("411111"))


class StructureTests(unittest.TestCase):
    def test_kpp(self) -> None:
        self.assertTrue(checksums.kpp_ok("770701001"))
        self.assertTrue(checksums.kpp_ok("7707AB001"))
        self.assertFalse(checksums.kpp_ok("77070100"))
        self.assertFalse(checksums.kpp_ok("7707A10011"))

    def test_bik(self) -> None:
        self.assertTrue(checksums.bik_ok("044525225"))
        self.assertFalse(checksums.bik_ok("123456789"))
        self.assertFalse(checksums.bik_ok("0445252251"))

    def test_digits_strips_everything_else(self) -> None:
        self.assertEqual(checksums.digits("+7 (999) 123-45-67"), "79991234567")


if __name__ == "__main__":
    unittest.main()
