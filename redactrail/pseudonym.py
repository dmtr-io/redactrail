"""Псевдонимы на HMAC: одно значение — один токен, обратного словаря нет.

Идея: `[[PERSON_1A2B3C4D5E]]` — это первые 10 hex-символов от
`HMAC-SHA256(ключ, класс + "\0" + нормализованное значение)`. Свойства, которые
нам нужны:

* **Стабильность.** Одно и то же ФИО в разных запросах даёт один и тот же токен,
  поэтому модель не путается, а `tool_use` можно развернуть обратно.
* **Необратимость.** В токене нет значения, а ключ лежит в `state/secret.key`.
  Без ключа словарь не восстановить перебором: пространство имён и телефонов
  мало, но перебор всё равно требует ключа, а не токена.
* **Разделение классов.** Класс входит в HMAC, поэтому «Иванов» как человек
  и «Иванов» в названии организации не совпадут.

Ключ создаётся один раз (`load_or_create_key`). Его потеря не ломает работу,
но все псевдонимы становятся новыми — это описано в README.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import unicodedata
from pathlib import Path
from typing import Iterable, Mapping

#: Короткие читаемые префиксы. Модель видит только их, остальное — хеш.
PREFIXES: dict[str, str] = {
    "person": "PERSON",
    "org": "ORG",
    "address": "ADDRESS",
    "phone": "PHONE",
    "email": "EMAIL",
    "snils": "SNILS",
    "inn": "INN",
    "ogrn": "OGRN",
    "kpp": "KPP",
    "bik": "BIK",
    "account": "ACCOUNT",
    "card": "CARD",
    "passport": "PASSPORT",
    "dob": "DOB",
    "user": "USER",
    "login": "USER",
    "private_key": "KEY",
    "secret_token": "TOKEN",
    "secret_assign": "SECRET",
    "blob": "BLOB",
    "marker": "MARKER",
}

#: Классы, у которых значение сравнивается по цифрам: «+7 999 123-45-67»
#: и «89991234567» — один и тот же телефон.
_DIGIT_ONLY = {
    "phone",
    "snils",
    "inn",
    "ogrn",
    "kpp",
    "bik",
    "account",
    "card",
    "passport",
    "dob",
}

_NON_DIGIT = re.compile(r"\D")
_WHITESPACE = re.compile(r"\s+")
_TOKEN = re.compile(r"\[\[([A-Z]+)_([0-9A-F]{10})\]\]")

DEFAULT_KEY_PATH = Path("state") / "secret.key"
KEY_BYTES = 32
TOKEN_HEX = 10


def normalize_value(klass: str, value: str) -> str:
    """Привести значение к виду, в котором оно считается одинаковым.

    Для номеров остаются только цифры; для имён, организаций и адресов —
    NFKC, схлопнутые пробелы и регистр без различия. Этого достаточно, чтобы
    «Иванов  Иван» и «иванов иван» получили один токен.
    """
    text = unicodedata.normalize("NFKC", value).strip()
    if klass in _DIGIT_ONLY:
        digits = _NON_DIGIT.sub("", text)
        if klass == "phone" and len(digits) == 11:
            # «+7 999 …» и «8 999 …» — один и тот же номер: отбрасываем код страны.
            return digits[1:]
        return digits
    text = _WHITESPACE.sub(" ", text)
    return text.casefold()


def load_or_create_key(path: Path | str = DEFAULT_KEY_PATH) -> bytes:
    """Прочитать ключ HMAC или создать его с правами только для владельца.

    Файл пишется атомарно: сначала во временный файл рядом, затем переименование.
    На Windows `chmod` управляет только признаком «только чтение», поэтому ACL
    выставляется отдельно (это делает `run.ps1` на этапе эксплуатации); здесь
    файл всё равно лежит вне репозитория и закрыт `.gitignore`.
    """
    key_path = Path(path)
    if key_path.exists():
        data = key_path.read_bytes()
        if len(data) < KEY_BYTES:
            raise ValueError(
                f"ключ {key_path} повреждён: {len(data)} байт вместо {KEY_BYTES}"
            )
        return data[:KEY_BYTES]

    key_path.parent.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        try:
            os.chmod(key_path.parent, 0o700)
        except OSError:  # pragma: no cover - файловая система без режимов
            pass

    key = secrets.token_bytes(KEY_BYTES)
    temp_path = key_path.with_suffix(key_path.suffix + ".tmp")
    descriptor = os.open(
        temp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0), 0o600
    )
    try:
        os.write(descriptor, key)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temp_path, key_path)
    return key


class Pseudonymizer:
    """Выдаёт стабильные токены для значений и разворачивает их по таблице запроса."""

    def __init__(self, key: bytes) -> None:
        if len(key) < KEY_BYTES:
            raise ValueError("ключ короче 32 байт")
        self._key = bytes(key)

    @classmethod
    def from_key_file(cls, path: Path | str = DEFAULT_KEY_PATH) -> "Pseudonymizer":
        return cls(load_or_create_key(path))

    def token(self, klass: str, value: str) -> str:
        """Токен для значения. Одинаковые значения дают одинаковый токен."""
        prefix = PREFIXES.get(klass)
        if prefix is None:
            raise KeyError(f"неизвестный класс псевдонима: {klass}")
        normalized = normalize_value(klass, value)
        if not normalized:
            raise ValueError("пустое значение нельзя замаскировать псевдонимом")
        digest = hmac.new(
            self._key,
            f"{klass}\x00{normalized}".encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return f"[[{prefix}_{digest[:TOKEN_HEX].upper()}]]"

    def table(self, pairs: Iterable[tuple[str, str]]) -> dict[str, str]:
        """Таблица запроса «токен → исходное значение» для разворота в `tool_use`.

        Хранится только в памяти на время запроса: на диск значения не попадают.
        """
        result: dict[str, str] = {}
        for klass, value in pairs:
            result[self.token(klass, value)] = value
        return result


def expand_tokens(text: str, table: Mapping[str, str]) -> str:
    """Развернуть известные токены обратно. Нужно только для аргументов `tool_use`."""

    def replace(match: re.Match[str]) -> str:
        token = match.group(0)
        return table.get(token, token)

    return _TOKEN.sub(replace, text)
