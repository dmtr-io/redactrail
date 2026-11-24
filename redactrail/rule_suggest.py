"""Предложения правил: модель смотрит пропуски и предлагает регулярку, решает человек.

Цикл:

1. Берём из очереди аудита находки `missed_pii` (только ссылки, без значений).
2. Достаём исходную цитату и её окружение, известное маскируем метками.
3. Просим модель предложить регулярку для этого класса.
4. Проверяем: компилируется, находит пример, не ловит разрешённое, не содержит
   сам пример дословно, не зависает.
5. Кладём в очередь как `rule_patch` — в политику попадает только по кнопке.

Автоматически ничего не применяется: правило — это код на каждом запросе.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from datetime import date
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from . import review
from .policy import Policy

#: Модели нужно объяснить, что регулярка обобщает, а не запоминает пример.
SYSTEM_PROMPT = (
    "Ты аналитик правил маскирования персональных данных. Тебе дают класс, пример "
    "значения, которое правила пропустили, и окружение. Предложи регулярное выражение "
    "Python re, которое ловит этот вид значений в других текстах. Требования: обобщай, "
    "не вставляй сам пример дословно; длина до 300 символов; без вложенных квантификаторов; "
    "не лови GUID, URL, ISO-даты и хеши. Ответ — только JSON: "
    '{"pattern": "...", "flags": "i", "explanation": "...", "confidence": 0.0}'
)

#: Что новое правило не должно ловить.
SAFE_SAMPLES: tuple[str, ...] = (
    "550e8400-e29b-41d4-a716-446655440000",
    "https://example.com/docs/guide?page=2",
    "2026-11-23T10:00:00+03:00",
    "9dd8aeb3f1c2d4e5f60718293a4b5c6d7e8f9012",
    "заказ № 123456",
    "версия 2.5.1",
    "цена 100 000 руб.",
)

#: Грубый признак катастрофического бэктрекинга.
DANGEROUS = re.compile(r"(\([^)]*[+*][^)]*\)[+*?])|(\[[^\]]*[+*][^\]]*\][+*?])")
ALLOWED_FLAGS = ("", "i", "m", "im", "mi")


def _compile(pattern: str, flags: str) -> re.Pattern[str]:
    bits = 0
    if "i" in flags:
        bits |= re.IGNORECASE
    if "m" in flags:
        bits |= re.MULTILINE
    return re.compile(pattern, bits)


def literal_fragments(value: str) -> list[str]:
    """Куски значения, которые нельзя вставлять в шаблон дословно."""
    return [chunk for chunk in re.findall(r"[0-9A-Za-zА-Яа-яЁё]{5,}", value)]


def validate_rule(
    pattern: str,
    flags: str,
    policy: Policy,
    klass: str,
    value: str | None = None,
) -> str | None:
    """Проверить правило; при известном примере — ещё и что оно его находит."""
    pattern = pattern.strip()
    if not 3 <= len(pattern) <= 300:
        return "длина шаблона вне 3..300"
    if flags not in ALLOWED_FLAGS:
        return "допустимы только флаги i и m"
    try:
        compiled = _compile(pattern, flags)
    except re.error as error:
        return f"шаблон не компилируется: {error}"
    if DANGEROUS.search(pattern):
        return "вложенные квантификаторы: риск зависания"
    if value is not None:
        if not compiled.search(value):
            return "шаблон не находит пример, ради которого предложен"
        lowered = pattern.casefold()
        for fragment in literal_fragments(value):
            if fragment.casefold() in lowered:
                return "шаблон содержит значение дословно"
    for sample in SAFE_SAMPLES:
        if compiled.search(sample):
            return f"шаблон ловит разрешённое: {sample}"
    for rule in policy.extra_rules:
        if rule.klass == klass and rule.pattern.pattern == pattern:
            return "такое правило уже есть"
    started = time.perf_counter()
    compiled.search("x" * 300 + (value or ""))
    if time.perf_counter() - started > 0.05:
        return "шаблон слишком медленный на тестовой строке"
    return None


def validate_pattern(
    pattern: str,
    flags: str,
    value: str,
    policy: Policy,
    klass: str,
) -> str | None:
    """Вернуть причину отказа или ``None``, если правило можно предлагать."""
    return validate_rule(pattern, flags, policy, klass, value=value)


def build_prompt(klass: str, value: str, context: str, policy: Policy) -> str:
    existing = [
        {"pattern": rule.pattern.pattern, "flags": rule.flags}
        for rule in policy.extra_rules
        if rule.klass == klass
    ]
    payload = {
        "class": klass,
        "missed_value": value,
        "context": context,
        "existing_extra_rules": existing,
    }
    return json.dumps(payload, ensure_ascii=False)


def _window(block: str, value: str, policy: Policy, width: int = 200) -> str | None:
    """Окружение пропуска: известное маскируем, сам пропуск оставляем."""
    masked, _ = review.mask_known(block, policy)
    position = masked.find(value)
    if position < 0:
        return None
    start = max(0, position - width)
    end = min(len(masked), position + len(value) + width)
    return masked[start:end]


def propose(
    item: Mapping[str, Any],
    policy: Policy,
    sessions_root: Path,
    ask: Callable[[str], dict],
) -> tuple[dict | None, str | None]:
    """Предложение по одному пропуску: (карточка, причина отказа)."""
    klass = str(item.get("class") or "")
    if klass not in policy.actions:
        return None, f"неизвестный класс {klass!r}"
    value = review.find_quote(sessions_root, item)
    if not value:
        return None, "не удалось перечитать значение"
    block = review.read_block(sessions_root, item)
    if block is None:
        return None, "блок сессии недоступен"
    context = _window(block, value, policy)
    if context is None:
        return None, "значение пересекается с уже замаскированным"

    started = time.perf_counter()
    response = ask(build_prompt(klass, value, context, policy))
    if not isinstance(response, Mapping):
        return None, "модель вернула не объект"
    pattern = str(response.get("pattern") or "").strip()
    flags = str(response.get("flags") or "")
    explanation = str(response.get("explanation") or "")[:300]
    try:
        confidence = float(response.get("confidence") or 0)
    except (TypeError, ValueError):
        confidence = 0.0
    reason = validate_pattern(pattern, flags, value, policy, klass)
    if reason is not None:
        return None, reason

    identity = hashlib.sha256(f"{klass}:{pattern}:{flags}".encode("utf-8")).hexdigest()[:12]
    card = {
        "id": "rp-" + identity,
        "class": klass,
        "kind": "rule_patch",
        "verdict": "предложено моделью",
        "count": 1,
        "window": f"pattern: {pattern}" + (f"  flags: {flags}" if flags else ""),
        "action": "проверить и принять правило",
        "payload": {
            "class": klass,
            "pattern": pattern,
            "flags": flags,
            "explanation": explanation,
            "confidence": round(max(0.0, min(1.0, confidence)), 2),
        },
        "evidence": {
            "file": item.get("file"),
            "chunk": item.get("chunk"),
            "hash": item.get("hash"),
            "length": item.get("length"),
        },
        "model_seconds": round(time.perf_counter() - started, 2),
    }
    return card, None


def suggest_rules(
    policy: Policy,
    sessions_root: Path,
    suggestions: Sequence[Mapping[str, Any]],
    ask: Callable[[str], dict],
    limit: int = 5,
    report_dir: Path | None = None,
) -> dict:
    """Пройти по пропускам и сложить предложения правил в очередь."""
    created: list[dict] = []
    skipped: list[dict] = []
    attempted = 0
    seen: set[str] = set()
    for item in suggestions:
        if len(created) >= limit:
            break
        if item.get("kind") != "missed_pii" or item.get("decision") not in (None, "pending"):
            continue
        evidence = str(item.get("hash") or "")
        if evidence and evidence in seen:
            continue
        seen.add(evidence)
        attempted += 1
        try:
            card, reason = propose(item, policy, sessions_root, ask)
        except review.ReviewError as error:
            skipped.append({"id": item.get("id"), "reason": str(error)})
            continue
        if card is None:
            skipped.append({"id": item.get("id"), "reason": reason})
            continue
        created.append(card)
    if report_dir is not None and created:
        review.merge_suggestions(report_dir, date.today().isoformat(), created)
    return {"created": len(created), "attempted": attempted, "skipped": skipped, "items": created}
