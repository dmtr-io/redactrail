"""Сборка: прогнать все детекторы, применить политику и выдать маскированный текст.

Это единственное место, где встречаются `entities.py`, `ner.py`, `policy.py`
и `pseudonym.py`. `sanitizer.py` (M2) будет обходить payload Anthropic и вызывать
`scan_text` на каждом текстовом блоке, поэтому контракт здесь простой:

* `detect(text, policy)` — что нашлось и как классифицировано, без изменения текста;
* `blocked(findings, policy)` — что запрещено отправлять;
* `mask_text(text, policy, pseudonymizer)` — готовый текст и таблица токенов
  на время запроса (для разворота в `tool_use`, M3).

Длинный текст режется на куски с перекрытием: регулярка, начатая в одном куске,
может закончиться в другом, а потерять находку на границе нельзя — это утечка.
"""

from __future__ import annotations

import hashlib
import re
import threading
import time
import unicodedata
from collections import OrderedDict
from typing import Sequence

from . import entities, ner
from .detections import BLOCK, Finding, apply_mask, merge
from .policy import Policy
from .pseudonym import Pseudonymizer

#: Классы, которые маскируются, но **не** разворачиваются в ответе: секрет не должен
#: возвращаться в чат, даже если модель его повторит.
REDACTED_CLASSES = frozenset({"private_key", "secret_token", "secret_assign"})

#: Кеш находок: агент пересылает всю историю каждый раз, и повторно сканировать
#: те же мегабайты незачем. Ключ — отпечаток политики + SHA-256 текста.
_CACHE: "OrderedDict[tuple[str, str], tuple[Finding, ...]]" = OrderedDict()
_CACHE_LOCK = threading.Lock()
_CACHE_SIZE = 32
_CACHE_STATS = {"hits": 0, "misses": 0}

#: Перекрытие кусков при разборе длинного текста, символы.
CHUNK_OVERLAP = 512


def _chunks(text: str, size: int, overlap: int) -> list[tuple[int, int]]:
    """Разбить текст на интервалы с перекрытием; последний кусок доходит до конца."""
    if len(text) <= size:
        return [(0, len(text))]
    step = max(size - overlap, 1)
    spans: list[tuple[int, int]] = []
    start = 0
    while start < len(text):
        end = min(start + size, len(text))
        spans.append((start, end))
        if end == len(text):
            break
        start += step
    return spans


def cache_stats() -> dict[str, int]:
    with _CACHE_LOCK:
        return {**_CACHE_STATS, "size": len(_CACHE), "limit": _CACHE_SIZE}


def detect(text: str, policy: Policy) -> list[Finding]:
    """Все находки в тексте с разрешёнными пересечениями и применённым allow-списком."""
    if not text:
        return []
    key = (policy.fingerprint, hashlib.sha256(text.encode("utf-8")).hexdigest())
    with _CACHE_LOCK:
        cached = _CACHE.get(key)
        if cached is not None:
            _CACHE_STATS["hits"] += 1
            _CACHE.move_to_end(key)
            return list(cached)
        _CACHE_STATS["misses"] += 1
    normalized, mapping = normalize_with_map(text)
    findings = _detect_raw(normalized, policy)
    if mapping is not None:
        findings = _map_back(findings, mapping, text)
    with _CACHE_LOCK:
        _CACHE[key] = tuple(findings)
        _CACHE.move_to_end(key)
        while len(_CACHE) > _CACHE_SIZE:
            _CACHE.popitem(last=False)
    return findings


#: Невидимые и полноширинные символы, которыми можно спрятать ПДн от регулярки.
_SUSPICIOUS = re.compile(
    "[\u00ad\u061c\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\uff00-\uffef]"
)


def normalize_with_map(text: str) -> tuple[str, list[int] | None]:
    """Убрать невидимые символы и свернуть полноширинные формы.

    Возвращает нормализованный текст и карту «индекс нормализованного → индекс
    исходного», чтобы маскировать оригинал, а не копию. Если подозрительных
    символов нет, возвращает исходный текст и ``None`` — быстрый путь без копии.
    """
    if not _SUSPICIOUS.search(text):
        return text, None
    chars: list[str] = []
    mapping: list[int] = []
    for index, char in enumerate(text):
        for expanded in unicodedata.normalize("NFKC", char):
            if unicodedata.category(expanded) == "Cf" and expanded not in ("\u200d",):
                continue  # zero-width space, bidi-переопределения и прочее
            chars.append(expanded)
            mapping.append(index)
    return "".join(chars), mapping


def _map_back(findings: Sequence[Finding], mapping: Sequence[int], text: str) -> list[Finding]:
    """Пересчитать находки нормализованного текста в координаты оригинала."""
    result: list[Finding] = []
    length = len(mapping)
    for finding in findings:
        if finding.start >= length:
            continue
        start = mapping[finding.start]
        last = min(finding.end - 1, length - 1)
        end = mapping[last] + 1
        if end <= start:
            continue
        result.append(Finding(start, end, finding.klass, text[start:end]))
    return result


def _detect_raw(text: str, policy: Policy) -> list[Finding]:
    findings: list[Finding] = []
    for start, end in _chunks(text, policy.limits.chunk_chars, CHUNK_OVERLAP):
        piece = text[start:end]
        lowered = piece.casefold()
        local: list[Finding] = []
        local.extend(entities.find_entities(piece, lowered=lowered))
        prefilter = policy.marker_prefilter
        if prefilter is not None and prefilter.search(lowered):
            local.extend(entities.marker_findings(piece, policy.marker_patterns))
        local.extend(ner.find_ner(piece))
        for rule in policy.extra_rules:
            for match in rule.pattern.finditer(piece):
                if match.end() > match.start():
                    local.append(
                        Finding(match.start(), match.end(), rule.klass, match.group(0))
                    )
        if start or end != len(text):
            local = [Finding(f.start + start, f.end + start, f.klass, f.value) for f in local]
        findings.extend(local)
    findings = _apply_allow(text, findings, policy)
    return merge(findings, policy.actions)


def _apply_allow(
    text: str, findings: Sequence[Finding], policy: Policy
) -> list[Finding]:
    """Выбросить находки, попавшие внутрь разрешённого участка (GUID, URL, ISO-дата).

    Разрешения никогда не действуют на блокирующие классы: исключение, случайно
    накрывшее секрет, не должно позволить секрету уйти.
    """
    if not policy.allow:
        return list(findings)
    pattern = policy.allow_pattern
    if pattern is None:
        return list(findings)
    dropped: set[int] = set()
    for match in pattern.finditer(text):
        rule = policy.allow_rule_by_group(match.lastgroup or "")
        if rule is None:
            continue
        start, end = match.span(0)
        for index, finding in enumerate(findings):
            if index in dropped:
                continue
            if policy.is_block(finding.klass):
                continue
            if rule.covers(finding.klass) and start <= finding.start and finding.end <= end:
                dropped.add(index)
    return [finding for index, finding in enumerate(findings) if index not in dropped]


def blocked(findings: Sequence[Finding], policy: Policy) -> list[Finding]:
    """Находки, которые политика запрещает отправлять."""
    return [finding for finding in findings if policy.is_block(finding.klass)]


def mask_text(
    text: str, policy: Policy, pseudonymizer: Pseudonymizer
) -> tuple[str, dict[str, str]]:
    """Заменить находки псевдонимами. Возвращает текст и таблицу «токен → значение».

    Если в тексте есть блокирующая находка, маскировать её бессмысленно: прокси
    всё равно отклонит запрос. Функция не бросает исключение сама — решение
    принимает вызывающий код, которому нужно сформировать понятную ошибку.
    """
    findings = detect(text, policy)
    table: dict[str, str] = {}

    def replacer(finding: Finding) -> str:
        token = pseudonymizer.token(finding.klass, finding.value)
        if finding.klass not in REDACTED_CLASSES:
            # Значение берём из оригинала: находка могла быть найдена в нормализованной
            # копии, где невидимые символы удалены.
            table[token] = text[finding.start : finding.end]
        return token

    masked = apply_mask(text, [f for f in findings if not policy.is_block(f.klass)], replacer)
    return masked, table


def timed_detect(text: str, policy: Policy) -> tuple[list[Finding], float]:
    """То же, что `detect`, но с замером времени — для профиля и теста бюджета."""
    started = time.perf_counter()
    findings = detect(text, policy)
    return findings, (time.perf_counter() - started) * 1000.0


def is_blocked_class(policy: Policy, klass: str) -> bool:
    return policy.action_for(klass) == BLOCK
