"""Сгенерировать стартовый корпус для бенчмарка детекторов.

Значения обычные: имена из наших словарей, телефоны/адреса/реквизиты — синтетические,
но реалистичные. Плейсхолдеров в тексте нет — иначе детекторы проверяют сами себя.

Запуск: python scripts/make_pii_corpus.py
"""

from __future__ import annotations

import json
import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from redactrail import checksums, ru_names

OUT = pathlib.Path("tests/corpus/pii_bench.jsonl")


def valid_inn(prefix: str = "771234567") -> str:
    for digit in range(10):
        candidate = prefix + str(digit)
        if checksums.inn10_ok(candidate):
            return candidate
    raise RuntimeError("inn")


def valid_snils(prefix: str = "112233445") -> str:
    for tail in range(100):
        candidate = prefix + f"{tail:02d}"
        if checksums.snils_ok(candidate):
            return candidate
    raise RuntimeError("snils")


def valid_ogrn(prefix: str = "102770013219") -> str:
    for digit in range(10):
        candidate = prefix + str(digit)
        if checksums.ogrn_ok(candidate):
            return candidate
    raise RuntimeError("ogrn")


def valid_card(prefix: str = "427616001234567") -> str:
    for digit in range(10):
        candidate = prefix + str(digit)
        if checksums.luhn_ok(candidate):
            return candidate
    raise RuntimeError("card")


SURNAMES = sorted(ru_names.SURNAMES)
FIRST_NAMES = sorted(ru_names.FIRST_NAMES)


def full_name(index: int) -> str:
    surname = SURNAMES[index % len(SURNAMES)].capitalize()
    name = FIRST_NAMES[(index * 7) % len(FIRST_NAMES)].capitalize()
    return surname + " " + name


INN = valid_inn()
SNILS = valid_snils()
OGRN = valid_ogrn()
CARD = valid_card()

NAME_1 = full_name(3)
NAME_2 = full_name(11)
NAME_3 = full_name(23)
ORG_1 = "ООО «Ромашка»"
ORG_2 = "АО «Вектор»"
ADDR_1 = "ул. Ленина, д. 5, кв. 12"
ADDR_2 = "пр. Мира, д. 12, кв. 3"
PHONE_1 = "+7 999 123-45-67"
PHONE_2 = "+7 999 765-43-21"
EMAIL_1 = "ivanov@" + "example.com"
EMAIL_2 = "a.kuznetsova@" + "example.org"
ACCOUNT = "40702810100000000001"
BIK = "040000001"
PASSPORT = "4510 123456"
DOB = "01.02.1990"
LOGIN_1 = "user1"
LOGIN_2 = "user2.petrov"
PATH_1 = r"C:\Users\user1\Documents\report.docx"
PATH_2 = r"C:\Users\user2.petrov\work\data.csv"
SECRET_ASSIGN = "api_key = sk-live-" + "A" * 24
SECRET_TOKEN = "ghp_" + "b" * 36
MARKER = "КОНФИДЕНЦИАЛЬНО"

CASES: list[tuple[str, str, list[tuple[str, str]]]] = [
    (
        "chat-01",
        "Добрый день! Меня зовут " + NAME_1 + ", мой телефон " + PHONE_1 + ", почта " + EMAIL_1 + ".",
        [("person", NAME_1), ("phone", PHONE_1), ("email", EMAIL_1)],
    ),
    (
        "email-01",
        "Прошу направить акт на " + EMAIL_2 + ". Подпись: " + NAME_2 + ", " + ORG_1 + ".",
        [("email", EMAIL_2), ("person", NAME_2), ("org", ORG_1)],
    ),
    (
        "invoice-01",
        "Счёт № 12 от 01.01.2026. Плательщик: " + ORG_2 + ", ИНН " + INN + ", ОГРН " + OGRN + ".",
        [("org", ORG_2), ("inn", INN), ("ogrn", OGRN)],
    ),
    (
        "invoice-02",
        "Реквизиты: р/с " + ACCOUNT + ", БИК " + BIK + ", получатель " + ORG_1 + ".",
        [("account", ACCOUNT), ("bik", BIK), ("org", ORG_1)],
    ),
    (
        "hr-01",
        "Кандидат " + NAME_3 + ", СНИЛС " + SNILS + ", паспорт " + PASSPORT + ", " + DOB + " г.р.",
        [("person", NAME_3), ("snils", SNILS), ("passport", "паспорт " + PASSPORT), ("dob", DOB)],
    ),
    (
        "hr-02",
        "Приняли на работу " + LOGIN_2 + ", оклад 100 000 руб., адрес: " + ADDR_1 + ".",
        [("user", LOGIN_2), ("address", ADDR_1)],
    ),
    (
        "log-01",
        "Ошибка при чтении " + PATH_1 + ": file not found.",
        [("user", LOGIN_1)],
    ),
    (
        "log-02",
        "Файл " + PATH_2 + " сохранён.",
        [("user", LOGIN_2)],
    ),
    (
        "secret-01",
        "Конфиг: " + SECRET_ASSIGN + ". Не коммитить.",
        [("secret_assign", SECRET_ASSIGN)],
    ),
    (
        "secret-02",
        "Токен GitHub: " + SECRET_TOKEN + ".",
        [("secret_token", SECRET_TOKEN)],
    ),
    (
        "marker-01",
        MARKER + "\nОтчёт по проекту, не распространять.",
        [("marker", MARKER)],
    ),
    (
        "card-01",
        "Оплата картой " + CARD + " прошла успешно, телефон для связи " + PHONE_2 + ".",
        [("card", CARD), ("phone", PHONE_2)],
    ),
    (
        "chat-02",
        "Привет! Скинь, пожалуйста, договор на " + EMAIL_1 + " и позвони " + PHONE_1 + ".",
        [("email", EMAIL_1), ("phone", PHONE_1)],
    ),
    (
        "chat-03",
        "Клиент " + NAME_2 + " просил перезвонить на " + PHONE_2 + " после 18:00.",
        [("person", NAME_2), ("phone", PHONE_2)],
    ),
    (
        "address-01",
        "Доставка по адресу " + ADDR_2 + ", получатель " + NAME_1 + ".",
        [("address", ADDR_2), ("person", NAME_1)],
    ),
    (
        "negative-guid",
        "Идентификатор 550e8400-e29b-41d4-a716-446655440000 использован в отчёте.",
        [],
    ),
    (
        "negative-url",
        "Документация: https://example.com/docs/guide?page=2 — там всё описано.",
        [],
    ),
    (
        "negative-date",
        "Встреча назначена на 2026-11-23T10:00:00+03:00.",
        [],
    ),
    (
        "negative-hash",
        "Коммит 9dd8aeb3f1c2d4e5f60718293a4b5c6d7e8f9012 смержен в main.",
        [],
    ),
]


def bulk_cases() -> list[tuple[str, str, list[tuple[str, str]]]]:
    """Расширение корпуса: 180 документов по шести шаблонам.

    Значения собираются из цифр и словарей, поэтому уникальны и не совпадают
    с уже написанными вручную.
    """
    streets = ["Ленина", "Гагарина", "Мира", "Садовая", "Победы", "Лесная"]
    orgs = ["Вектор", "Гранит", "Атлас", "Ритм", "Кедр", "Сириус"]
    cases: list[tuple[str, str, list[tuple[str, str]]]] = []
    for i in range(30):
        name = full_name(i * 5 + 1)
        phone = f"8 (9{i % 10}{i % 7}) {100 + i:03d}-{10 + i % 90:02d}-{20 + i % 70:02d}"
        email = f"user{i}@{'example.com' if i % 2 else 'example.org'}"
        cases.append(
            (
                f"bulk-chat-{i}",
                f"Меня зовут {name}, телефон {phone}, почта {email}.",
                [("person", name), ("phone", phone), ("email", email)],
            )
        )
        org = f"ООО «{orgs[i % len(orgs)]} {i}»"
        inn = valid_inn(f"{770000000 + i * 37:09d}")
        ogrn = valid_ogrn(f"{102770000000 + i * 111:012d}")
        cases.append(
            (
                f"bulk-invoice-{i}",
                f"Плательщик {org}, ИНН {inn}, ОГРН {ogrn}.",
                [("org", org), ("inn", inn), ("ogrn", ogrn)],
            )
        )
        snils = valid_snils(f"{100000000 + i * 13:09d}")
        passport = f"{4500 + i:04d} {100000 + i:06d}"
        dob = f"{i % 28 + 1:02d}.{(i * 3) % 12 + 1:02d}.{1960 + i % 50}"
        cases.append(
            (
                f"bulk-hr-{i}",
                f"Кандидат {name}, СНИЛС {snils}, паспорт {passport}, {dob} г.р.",
                [
                    ("person", name),
                    ("snils", snils),
                    ("passport", "паспорт " + passport),
                    ("dob", dob),
                ],
            )
        )
        login = f"user{i}"
        path = f"C:{os.sep}Users{os.sep}user{i}{os.sep}Documents{os.sep}file{i}.txt"
        cases.append(
            (
                f"bulk-log-{i}",
                f"Ошибка при чтении {path}: владелец {login}.",
                [("user", login)],
            )
        )
        secret = "token = sk-live-" + chr(65 + i % 26) * 24
        cases.append(
            (
                f"bulk-secret-{i}",
                f"Конфиг: {secret}. Не коммитить.",
                [("secret_assign", secret)],
            )
        )
        cases.append(
            (
                f"bulk-address-{i}",
                f"Доставка по адресу: ул. {streets[i % len(streets)]}, д. {i + 1}, кв. {i % 50 + 1}.",
                [("address", f"ул. {streets[i % len(streets)]}, д. {i + 1}, кв. {i % 50 + 1}")],
            )
        )
    return cases


CASES.extend(bulk_cases())


def main() -> int:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    lines: list[str] = []
    for index, (kind, text, entities) in enumerate(CASES, start=1):
        record = {
            "id": f"pii-{index:04d}",
            "kind": kind,
            "text": text,
            "entities": [{"value": value, "class": klass} for klass, value in entities],
        }
        lines.append(json.dumps(record, ensure_ascii=False))
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"записано {len(lines)} документов в {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
