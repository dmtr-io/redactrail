"""Контрольные суммы российских реквизитов и алгоритм Луна.

Все функции принимают строку и возвращают ``bool``. Сами по себе они не решают,
маскировать ли число: это делает `entities.py`, который сначала находит кандидата
по форме, а потом проверяет его здесь. Отдельный модуль нужен, чтобы проверки
можно было тестировать на эталонных значениях без запуска регулярных выражений.

Источники алгоритмов: приказ ФНС о порядке формирования ИНН (10 и 12 знаков),
постановление ПФР о СНИЛС (11 знаков), приказ Росстата об ОГРН (13 и 15 знаков),
ISO/IEC 7812 (алгоритм Луна для платёжных карт).
"""

from __future__ import annotations

import re

_DIGITS = re.compile(r"\D")


def digits(value: str) -> str:
    """Оставить только десятичные цифры."""
    return _DIGITS.sub("", value)


def _weights(seq: str, table: tuple[int, ...]) -> int:
    return sum(int(ch) * w for ch, w in zip(seq, table))


def inn10_ok(value: str) -> bool:
    """ИНН юридического лица: 10 цифр, одна контрольная.

    Контрольное число — сумма произведений цифр на веса 2 4 10 3 5 9 4 6 8,
    остаток от деления на 11, затем остаток от деления на 10.
    """
    number = digits(value)
    if len(number) != 10:
        return False
    expected = _weights(number[:9], (2, 4, 10, 3, 5, 9, 4, 6, 8)) % 11 % 10
    return expected == int(number[9])


def inn12_ok(value: str) -> bool:
    """ИНН физлица или ИП: 12 цифр, две контрольные.

    Первая контрольная считается по весам 7 2 4 10 3 5 9 4 6 8 на первые 10 цифр,
    вторая — по весам 3 7 2 4 10 3 5 9 4 6 8 на первые 11 цифр.
    """
    number = digits(value)
    if len(number) != 12:
        return False
    first = _weights(number[:10], (7, 2, 4, 10, 3, 5, 9, 4, 6, 8)) % 11 % 10
    second = _weights(number[:11], (3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8)) % 11 % 10
    return first == int(number[10]) and second == int(number[11])


def snils_ok(value: str) -> bool:
    """СНИЛС: 11 цифр, из них последние две — контрольное число.

    Сумма первых девяти цифр на веса 9 8 7 6 5 4 3 2 1; если она меньше 100,
    контрольное число равно сумме; если равна 100 или 101 — нулю; иначе берётся
    остаток от деления на 101, а остаток 100 заменяется нулём.
    """
    number = digits(value)
    if len(number) != 11:
        return False
    total = _weights(number[:9], (9, 8, 7, 6, 5, 4, 3, 2, 1))
    if total < 100:
        check = total
    elif total in (100, 101):
        check = 0
    else:
        remainder = total % 101
        check = 0 if remainder == 100 else remainder
    return check == int(number[9:])


def ogrn_ok(value: str) -> bool:
    """ОГРН (13) и ОГРНИП (15).

    Первые 12 (14) цифр как число, остаток от деления на 11 (13),
    младшая цифра остатка — контрольная.
    """
    number = digits(value)
    if len(number) == 13:
        expected = int(number[:12]) % 11 % 10
    elif len(number) == 15:
        expected = int(number[:14]) % 13 % 10
    else:
        return False
    return expected == int(number[-1])


def luhn_ok(value: str) -> bool:
    """Алгоритм Луна для номеров банковских карт.

    Цифры справа налево: каждая вторая умножается на два, и если произведение
    больше девяти, из него вычитается девять. Сумма всех цифр должна делиться на 10.
    """
    number = digits(value)
    if not 12 <= len(number) <= 19:
        return False
    total = 0
    for index, char in enumerate(reversed(number)):
        digit = int(char)
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def kpp_ok(value: str) -> bool:
    """КПП: 4 цифры, 2 знака кода причины (цифры или латинские буквы), 3 цифры.

    Контрольной суммы нет, проверяется только форма: 9 символов.
    """
    text = value.strip().upper()
    if len(text) != 9:
        return False
    return text[:4].isdigit() and text[4:6].isalnum() and text[6:].isdigit()


def bik_ok(value: str) -> bool:
    """БИК: 9 цифр, первые две — код территории по справочнику ЦБ (04 или 05).

    Контрольной суммы нет; ограничение на префикс отсекает случайные числа
    из девяти цифр, которых в текстах много (артикулы, номера заказов).
    """
    number = digits(value)
    if len(number) != 9:
        return False
    return number[:2] in {"04", "05"}
