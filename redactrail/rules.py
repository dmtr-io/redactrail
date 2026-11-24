"""Правила политики: показать всё, что решает судьбу запроса, и принять правку.

Админка до сих пор показывала правила клочками: режим и три переключателя в
«Настройках», маркеры и allow-список — только через очередь предложений. Здесь
один снимок всей политики плюс валидированная запись.

Редактируется всё, что лежит в `policy.json`, кроме раздела `review` — он про
аудит и живёт в «Процессах». Только чтением показываются правила детекторов из
кода (`entities.RULES`): это регулярные выражения, которые меняются вместе с
тестами, а не в рантайме.

Запись не принимает «как есть»: сначала данные нормализуются, потом целиком
проверяются `policy_from_dict` — та же проверка, что при старте прокси. Ошибка
возвращается человеку текстом, а не превращается в политику с опечаткой.
"""

from __future__ import annotations

import re
from typing import Any, Mapping

from . import entities
from .detections import ACTIONS
from .policy import MODES, Policy, policy_from_dict

#: Разделы policy.json, которые принимает редактор.
SECTIONS = ("mode", "actions", "markers", "allow", "request", "limits", "restore")
REQUEST_KEYS = (
    "allowed_fields",
    "allowed_roles",
    "allowed_block_types",
    "blocked_block_types",
)

MAX_MARKERS = 500
MAX_MARKER_CHARS = 200
MAX_ALLOW_RULES = 200
MAX_PATTERN_CHARS = 2000
MAX_LIST_ITEMS = 200
MAX_ITEM_CHARS = 100
MAX_CLASSES = 200
#: Разумные границы лимитов: защита от опечатки вроде лишнего нуля.
LIMIT_RANGES: dict[str, tuple[int, int]] = {
    "chunk_chars": (1000, 200_000),
    "request_chars": (1000, 2_000_000),
    "budget_ms": (10, 5_000),
    "retention_days": (1, 3_650),
}
_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


def detector_rules() -> list[dict]:
    """Правила детекторов из кода — только для чтения."""
    rules: list[dict] = []
    for rule in entities.RULES:
        validator = getattr(rule.validator, "__name__", "")
        rules.append(
            {
                "name": rule.name,
                "pattern": rule.pattern.pattern,
                "precheck": list(rule.precheck),
                "span": rule.span,
                "group": rule.group,
                "validator": validator if rule.validator else "",
            }
        )
    return rules


def _known_classes(policy: Policy) -> list[str]:
    names = set(policy.actions)
    names.update(entities.iter_rule_names())
    names.update({"marker", "thinking", "image", "document", "unknown_field", "unknown_block", "oversize"})
    return sorted(names)


def rules_view(policy: Policy, raw: Mapping[str, Any] | None = None) -> dict:
    """Снимок политики для экрана «Правила»: значения плюс что допустимо."""
    return {
        "mode": policy.mode,
        "modes": list(MODES),
        "actions": dict(sorted(policy.actions.items())),
        "actions_allowed": list(ACTIONS),
        "classes": _known_classes(policy),
        "markers": list(policy.markers),
        "allow": [
            {
                "name": rule.name,
                "pattern": rule.pattern.pattern,
                "classes": list(rule.classes),
                "precheck": list(rule.precheck),
            }
            for rule in policy.allow
        ],
        "extra_rules": [
            {
                "name": rule.name,
                "class": rule.klass,
                "pattern": rule.pattern.pattern,
                "flags": rule.flags,
                "explanation": rule.explanation,
            }
            for rule in policy.extra_rules
        ],
        "request": {
            "allowed_fields": list(policy.request.allowed_fields),
            "allowed_roles": list(policy.request.allowed_roles),
            "allowed_block_types": list(policy.request.allowed_block_types),
            "blocked_block_types": list(policy.request.blocked_block_types),
        },
        "limits": {
            "chunk_chars": policy.limits.chunk_chars,
            "request_chars": policy.limits.request_chars,
            "budget_ms": policy.limits.budget_ms,
            "retention_days": policy.limits.retention_days,
        },
        "restore": {"text": policy.restore.text, "tool_use": policy.restore.tool_use},
        # Только чтение: правится в «Процессах», здесь — чтобы правила были в одном месте.
        "review": {
            "base_url": policy.review.base_url,
            "model": policy.review.model,
            "sessions": policy.review.sessions,
            "days": policy.review.days,
            "limit": policy.review.limit,
            "per_session": policy.review.per_session,
        },
        "detectors": detector_rules(),
        "sections": list(SECTIONS),
        "source": str(raw.get("source") or "") if raw else "",
    }


# --- нормализация правки ---------------------------------------------


def _mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{name}: ожидался объект")
    return value


def _text(value: Any, name: str, *, limit: int = MAX_ITEM_CHARS, empty: bool = False) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name}: ожидалась строка")
    text = value.strip()
    if not text and not empty:
        raise ValueError(f"{name}: пустое значение")
    if len(text) > limit:
        raise ValueError(f"{name}: длиннее {limit} символов")
    if "\n" in text or "\r" in text:
        raise ValueError(f"{name}: перевод строки недопустим")
    return text


def _text_list(value: Any, name: str, *, limit: int = MAX_LIST_ITEMS) -> list[str]:
    if not isinstance(value, list):
        raise ValueError(f"{name}: ожидался список строк")
    if len(value) > limit:
        raise ValueError(f"{name}: больше {limit} элементов")
    items: list[str] = []
    for index, item in enumerate(value, start=1):
        items.append(_text(item, f"{name}[{index}]"))
    if not items:
        raise ValueError(f"{name}: список не может быть пустым")
    return items


def _actions(value: Any) -> dict[str, str]:
    raw = _mapping(value, "actions")
    if not raw:
        raise ValueError("actions: нужен хотя бы один класс")
    if len(raw) > MAX_CLASSES:
        raise ValueError(f"actions: больше {MAX_CLASSES} классов")
    actions: dict[str, str] = {}
    for klass, action in raw.items():
        name = _text(klass, "actions: имя класса", limit=64)
        if not _NAME_RE.match(name):
            raise ValueError(f"actions[{name}]: имя класса — строчные латинские буквы, цифры и «_»")
        if action not in ACTIONS:
            raise ValueError(f"actions[{name}]: ожидается одно из {ACTIONS}")
        actions[name] = str(action)
    return actions


def _markers(value: Any) -> list[str]:
    if not isinstance(value, list):
        raise ValueError("markers: ожидался список строк")
    if len(value) > MAX_MARKERS:
        raise ValueError(f"markers: больше {MAX_MARKERS} фраз")
    markers: list[str] = []
    for index, item in enumerate(value, start=1):
        if not isinstance(item, str):
            raise ValueError(f"markers[{index}]: ожидалась строка")
        # Пустые строки в текстовом поле — обычное дело (хвостовой перевод строки).
        if not item.strip():
            continue
        phrase = _text(item, f"markers[{index}]", limit=MAX_MARKER_CHARS)
        if phrase not in markers:
            markers.append(phrase)
    return markers


def _allow(value: Any) -> list[dict]:
    if not isinstance(value, list):
        raise ValueError("allow: ожидался список правил")
    if len(value) > MAX_ALLOW_RULES:
        raise ValueError(f"allow: больше {MAX_ALLOW_RULES} правил")
    rules: list[dict] = []
    names: set[str] = set()
    for index, entry in enumerate(value, start=1):
        raw = _mapping(entry, f"allow[{index}]")
        name = _text(raw.get("name"), f"allow[{index}].name", limit=64)
        if not _NAME_RE.match(name):
            raise ValueError(f"allow[{index}].name: строчные латинские буквы, цифры и «_»")
        if name in names:
            raise ValueError(f"allow[{index}]: имя {name!r} уже занято")
        names.add(name)
        pattern = _text(raw.get("pattern"), f"allow[{index}].pattern", limit=MAX_PATTERN_CHARS)
        try:
            re.compile(pattern)
        except re.error as error:
            raise ValueError(f"allow[{index}] ({name}): плохой шаблон: {error}") from error
        classes = _text_list(raw.get("classes", ["*"]), f"allow[{index}].classes")
        precheck = raw.get("precheck") or []
        if not isinstance(precheck, list):
            raise ValueError(f"allow[{index}].precheck: ожидался список строк")
        rules.append(
            {
                "name": name,
                "pattern": pattern,
                "classes": classes,
                "precheck": [_text(item, f"allow[{index}].precheck") for item in precheck],
            }
        )
    return rules


def _request(value: Any) -> dict[str, list[str]]:
    raw = _mapping(value, "request")
    unknown = set(raw) - set(REQUEST_KEYS)
    if unknown:
        raise ValueError(f"request: неизвестные ключи: {', '.join(sorted(unknown))}")
    request: dict[str, list[str]] = {}
    for key in REQUEST_KEYS:
        if key in raw:
            request[key] = _text_list(raw[key], f"request.{key}")
    if not request:
        raise ValueError("request: нет ни одного списка")
    return request


def _limits(value: Any) -> dict[str, int]:
    raw = _mapping(value, "limits")
    unknown = set(raw) - set(LIMIT_RANGES)
    if unknown:
        raise ValueError(f"limits: неизвестные ключи: {', '.join(sorted(unknown))}")
    limits: dict[str, int] = {}
    for key, item in raw.items():
        try:
            number = int(item)
        except (TypeError, ValueError):
            raise ValueError(f"limits.{key}: ожидалось целое число") from None
        low, high = LIMIT_RANGES[key]
        if number < low or number > high:
            raise ValueError(f"limits.{key}: допустимо от {low} до {high}")
        limits[key] = number
    if "chunk_chars" in limits and "request_chars" in limits:
        if limits["request_chars"] < limits["chunk_chars"]:
            raise ValueError("limits.request_chars меньше limits.chunk_chars")
    return limits


def _restore(value: Any) -> dict[str, bool]:
    raw = _mapping(value, "restore")
    unknown = set(raw) - {"text", "tool_use"}
    if unknown:
        raise ValueError(f"restore: неизвестные ключи: {', '.join(sorted(unknown))}")
    restore: dict[str, bool] = {}
    for key, item in raw.items():
        if not isinstance(item, bool):
            raise ValueError(f"restore.{key}: ожидалось true или false")
        restore[key] = item
    return restore


def apply_edits(raw: Mapping[str, Any] | None, data: Mapping[str, Any]) -> dict:
    """Собрать новую политику из правки. ``ValueError`` — правка не годится.

    Возвращает словарь для записи в `policy.json`: исходные разделы сохраняются,
    присланные — заменяются целиком (список маркеров проще переписать, чем
    вычислять разницу).
    """
    if not isinstance(data, Mapping):
        raise ValueError("ожидался объект JSON")
    unknown = set(data) - set(SECTIONS)
    if unknown:
        raise ValueError(f"неизвестные разделы: {', '.join(sorted(unknown))}")
    if not data:
        raise ValueError("нечего сохранять")

    merged: dict[str, Any] = dict(raw or {})
    normalizers = {
        "mode": lambda value: _text(value, "mode", limit=8),
        "actions": _actions,
        "markers": _markers,
        "allow": _allow,
        "request": _request,
        "limits": _limits,
        "restore": _restore,
    }
    for key, value in data.items():
        merged[key] = normalizers[key](value)

    if "mode" in merged and merged["mode"] not in MODES:
        raise ValueError(f"неизвестный режим {merged['mode']!r}: ожидается один из {MODES}")

    # Та же проверка, что при старте прокси: плохая политика не должна лечь на диск.
    policy_from_dict(merged)
    return merged
