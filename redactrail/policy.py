"""Политика: какие классы что означают, что разрешено и что делать в каждом режиме.

Политика — единственное место, где принимается решение «маскировать или блокировать».
Детекторы только называют класс. Это разделение позволяет менять поведение
(`strict` → `audit` → `off`) и пополнять allow-список, не трогая код детекторов.

Конфигурация читается из `policy.json`. Ошибка в конфигурации — исключение при
запуске, а не молчаливый переход к значениям по умолчанию: прокси с неполной
политикой хуже, чем прокси, который не запустился.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path
from typing import Any, Mapping, Sequence

from .detections import ACTIONS, BLOCK, MASK

MODES = ("strict", "audit", "off")

#: Адрес локальной модели аудита. Публичный дефолт — localhost; рабочий хост
#: задаётся `REDACTRAIL_REVIEW_URL` или `review.base_url` в политике.
DEFAULT_REVIEW_URL = os.environ.get(
    "REDACTRAIL_REVIEW_URL", "http://127.0.0.1:11434/v1/chat/completions"
)

#: Классы без записи в конфигурации получают это действие.
DEFAULT_ACTIONS: dict[str, str] = {
    "person": MASK,
    "org": MASK,
    "address": MASK,
    "phone": MASK,
    "email": MASK,
    "snils": MASK,
    "inn": MASK,
    "ogrn": MASK,
    "kpp": MASK,
    "bik": MASK,
    "account": MASK,
    "card": MASK,
    "passport": MASK,
    "dob": MASK,
    "user": MASK,
    "thinking": MASK,
    "private_key": MASK,
    "secret_token": MASK,
    "secret_assign": MASK,
    "marker": MASK,
    "blob": MASK,
    "image": BLOCK,
    "document": BLOCK,
    "unknown_block": BLOCK,
    "unknown_field": BLOCK,
    "oversize": BLOCK,
}

DEFAULT_MARKERS: tuple[str, ...] = (
    "коммерческая тайна",
    "конфиденциально",
    "конфиденциальная информация",
    "для служебного пользования",
    "ДСП",
    "ноу-хау",
    "строго конфиденциально",
    "не для распространения",
    "for internal use only",
    "confidential",
    "strictly confidential",
    "trade secret",
    "under nda",
)


@dataclass(frozen=True)
class Limits:
    """Бюджеты из разделов 7 и 4 плана.

    ``chunk_chars`` — размер куска текста при разборе длинных блоков,
    ``request_chars`` — предел суммарной длины текста в одном запросе,
    ``budget_ms`` — сколько миллисекунд отводится детекторам на 100 КБ.
    """

    chunk_chars: int = 12_000
    request_chars: int = 200_000
    budget_ms: int = 100
    #: Сколько дней хранить журналы. Удаление целого файла — честное «забыть».
    retention_days: int = 30


@dataclass(frozen=True)
class Restore:
    """Что разворачиваем в ответе провайдера (PLAN §5)."""

    text: bool = False
    tool_use: bool = True


#: Поля запроса Anthropic Messages, которые прокси умеет разбирать.
DEFAULT_REQUEST_FIELDS: tuple[str, ...] = (
    "model",
    "messages",
    "system",
    "max_tokens",
    "temperature",
    "top_p",
    "top_k",
    "stop_sequences",
    "stream",
    "tools",
    "tool_choice",
    "metadata",
    "thinking",
    "output_config",
    "output_format",
    "service_tier",
    "container",
)

#: Типы контент-блоков, которые разбираются по смыслу.
DEFAULT_ALLOWED_BLOCKS: tuple[str, ...] = (
    "text",
    "thinking",
    "redacted_thinking",
    "tool_addition",
    "tool_removal",
    "tool_use",
    "tool_result",
)

#: Блоки, которые блокируются всегда: пиксели и вложения замаскировать нельзя.
DEFAULT_BLOCKED_BLOCKS: tuple[str, ...] = ("image", "document")


@dataclass(frozen=True)
class ReviewSettings:
    """Настройки ночного аудита: адрес и модель локального хоста, объём прохода.

    Живут в `policy.json` → `review`, чтобы их можно было менять из админки и
    видеть в одном месте с остальной политикой.
    """

    base_url: str = field(default_factory=lambda: DEFAULT_REVIEW_URL)
    model: str = "qwen2.5-coder-7b-instruct-q4_k_m"
    sessions: str = ""
    days: int = 7
    #: 0 — без ограничения: проверяем весь текст, а не первые N фрагментов.
    limit: int = 0
    per_session: int = 0


@dataclass(frozen=True)
class RequestSchema:
    """Структура запроса, которую прокси согласен разбирать.

    Всё, что не перечислено, блокируется (раздел 4 плана). Списки живут
    в `policy.json`, чтобы новое поле API можно было разрешить без правки кода.
    """

    allowed_fields: tuple[str, ...] = DEFAULT_REQUEST_FIELDS
    allowed_roles: tuple[str, ...] = ("user", "assistant", "system")
    allowed_block_types: tuple[str, ...] = DEFAULT_ALLOWED_BLOCKS
    blocked_block_types: tuple[str, ...] = DEFAULT_BLOCKED_BLOCKS


@dataclass(frozen=True)
class AllowRule:
    """Участок текста, внутри которого нечего искать: GUID, ISO-дата, URL, наш же токен."""

    name: str
    pattern: re.Pattern[str]
    classes: tuple[str, ...]
    precheck: tuple[str, ...] = ()

    def covers(self, klass: str) -> bool:
        return "*" in self.classes or klass in self.classes

    def may_match(self, lowered: str) -> bool:
        return not self.precheck or any(fragment in lowered for fragment in self.precheck)


@dataclass(frozen=True)
class ExtraRule:
    """Правило детектора из политики: добавка к встроенным, без их отключения."""

    name: str
    klass: str
    pattern: re.Pattern[str]
    flags: str = ""
    explanation: str = ""


@dataclass(frozen=True)
class Policy:
    """Набор правил на весь процесс: режим, действия, маркеры, исключения, лимиты."""

    mode: str = "strict"
    actions: Mapping[str, str] = field(default_factory=lambda: dict(DEFAULT_ACTIONS))
    markers: tuple[str, ...] = DEFAULT_MARKERS
    allow: tuple[AllowRule, ...] = ()
    limits: Limits = field(default_factory=Limits)
    restore: Restore = field(default_factory=Restore)
    request: RequestSchema = field(default_factory=RequestSchema)
    review: ReviewSettings = field(default_factory=ReviewSettings)
    extra_rules: tuple[ExtraRule, ...] = ()
    source: str | None = None

    def __post_init__(self) -> None:
        if self.mode not in MODES:
            raise ValueError(f"неизвестный режим {self.mode!r}, ожидается один из {MODES}")
        for klass, action in self.actions.items():
            if action not in ACTIONS:
                raise ValueError(f"класс {klass!r}: неизвестное действие {action!r}")
        if self.limits.chunk_chars < 1000:
            raise ValueError("chunk_chars меньше 1000: разбор станет бессмысленно медленным")
        if self.limits.retention_days < 1:
            raise ValueError("retention_days меньше 1: журнал удалялся бы сразу")
        if self.limits.request_chars < self.limits.chunk_chars:
            raise ValueError("request_chars меньше chunk_chars")

    def action_for(self, klass: str) -> str:
        return self.actions.get(klass, MASK)

    def is_block(self, klass: str) -> bool:
        return self.action_for(klass) == BLOCK

    @cached_property
    def marker_fragments(self) -> tuple[str, ...]:
        """Первые слова маркеров: по ним дешевле проверить, стоит ли искать вообще."""
        return tuple(marker.split()[0].casefold() for marker in self.markers if marker.split())

    @cached_property
    def marker_prefilter(self) -> re.Pattern[str] | None:
        """Одно выражение на первые слова всех маркеров — один проход вместо десятка."""
        fragments = self.marker_fragments
        if not fragments:
            return None
        return re.compile("|".join(re.escape(fragment) for fragment in fragments))

    @cached_property
    def allow_pattern(self) -> re.Pattern[str] | None:
        """Все allow-правила одним проходом: групп ``name`` в шаблонах нет."""
        if not self.allow:
            return None
        parts = [f"(?P<g{index}>{rule.pattern.pattern})" for index, rule in enumerate(self.allow)]
        return re.compile("|".join(parts))

    def allow_rule_by_group(self, group: str) -> AllowRule | None:
        if not group or not group.startswith("g"):
            return None
        try:
            return self.allow[int(group[1:])]
        except (ValueError, IndexError):
            return None

    @cached_property
    def marker_patterns(self) -> tuple[re.Pattern[str], ...]:
        """Маркеры в «позиции грифа»: начало строки или слова-подсказки.

        Слово «коммерческая тайна» в таблице документации — это не гриф
        документа. Поэтому маркер считается пометкой, только если он стоит
        отдельной строкой (возможно, в кавычках) или после слов «пометка»,
        «гриф», «штамп», «маркировка». Иначе собственная документация проекта
        блокировала бы каждый запрос.
        """
        if not self.markers:
            return ()
        alternatives = "|".join(
            re.escape(marker) for marker in sorted(self.markers, key=len, reverse=True)
        )
        line = re.compile(
            rf"(?im)^[ \t\-*|>#«\"']*(?P<m>{alternatives})[»\"']?[ \t]*(?=$|[.,;!?])"
        )
        context = re.compile(
            rf"(?i)(?:пометка|пометкой|гриф|грифа|штамп|маркировка|маркирован\w*)"
            rf"[ \t]*[:«\"'—-]?[ \t]*(?P<m>{alternatives})[»\"']?[ \t]*(?=$|[.,;!?])"
        )
        return (line, context)

    @cached_property
    def marker_pattern(self) -> re.Pattern[str] | None:
        """Совместимость: первое из правил маркеров (или ``None``)."""
        patterns = self.marker_patterns
        return patterns[0] if patterns else None

    def mask_classes(self) -> tuple[str, ...]:
        return tuple(k for k, v in self.actions.items() if v == MASK)

    @cached_property
    def fingerprint(self) -> str:
        """Короткий отпечаток политики: ключ для кеша детекции.

        Меняется при смене режима, действий, маркеров, allow-листа или лимитов —
        тогда кеш находок перестаёт быть валидным.
        """
        payload = {
            "mode": self.mode,
            "actions": sorted(self.actions.items()),
            "markers": list(self.markers),
            "allow": [
                [rule.name, rule.pattern.pattern, sorted(rule.classes)] for rule in self.allow
            ],
            "limits": [self.limits.chunk_chars, self.limits.request_chars, self.limits.budget_ms],
            "extra_rules": [
                [rule.name, rule.klass, rule.pattern.pattern, rule.flags]
                for rule in self.extra_rules
            ],
        }
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()[:16]

    def with_mode(self, mode: str) -> "Policy":
        return Policy(
            mode=mode,
            actions=self.actions,
            markers=self.markers,
            allow=self.allow,
            limits=self.limits,
            restore=self.restore,
            request=self.request,
            review=self.review,
            extra_rules=self.extra_rules,
            source=self.source,
        )


def _compile_allow(entry: Mapping[str, Any], index: int) -> AllowRule:
    if not isinstance(entry, Mapping):
        raise ValueError(f"allow[{index}] должен быть объектом")
    name = entry.get("name")
    pattern = entry.get("pattern")
    classes = entry.get("classes", ["*"])
    if not isinstance(name, str) or not name:
        raise ValueError(f"allow[{index}]: нет имени")
    if not isinstance(pattern, str) or not pattern:
        raise ValueError(f"allow[{index}]: нет шаблона")
    if not isinstance(classes, Sequence) or isinstance(classes, str):
        raise ValueError(f"allow[{index}]: classes должен быть списком")
    try:
        compiled = re.compile(pattern)
    except re.error as error:
        raise ValueError(f"allow[{index}] ({name}): плохой шаблон: {error}") from error
    raw_precheck = entry.get("precheck", [])
    if not isinstance(raw_precheck, Sequence) or isinstance(raw_precheck, str):
        raise ValueError(f"allow[{index}]: precheck должен быть списком")
    precheck = tuple(str(fragment).casefold() for fragment in raw_precheck if str(fragment))
    return AllowRule(
        name=name, pattern=compiled, classes=tuple(str(c) for c in classes), precheck=precheck
    )


def _parse_extra_rules(raw: Any, actions: Mapping[str, str]) -> tuple[ExtraRule, ...]:
    """Дополнительные правила детекторов: только добавление, с проверкой шаблона."""
    if raw is None:
        return ()
    if not isinstance(raw, Sequence) or isinstance(raw, str):
        raise ValueError("extra_rules должен быть списком")
    rules: list[ExtraRule] = []
    names: set[str] = set()
    for index, entry in enumerate(raw):
        if not isinstance(entry, Mapping):
            raise ValueError(f"extra_rules[{index}] должен быть объектом")
        name = str(entry.get("name") or "").strip()
        klass = str(entry.get("class") or "").strip()
        pattern = str(entry.get("pattern") or "")
        flags = str(entry.get("flags") or "")
        explanation = str(entry.get("explanation") or "")
        if not name:
            raise ValueError(f"extra_rules[{index}]: нет имени")
        if name in names:
            raise ValueError(f"extra_rules[{index}]: имя {name!r} повторяется")
        names.add(name)
        if klass not in actions:
            raise ValueError(f"extra_rules[{index}] ({name}): неизвестный класс {klass!r}")
        if not pattern:
            raise ValueError(f"extra_rules[{index}] ({name}): пустой шаблон")
        if len(pattern) > 300:
            raise ValueError(f"extra_rules[{index}] ({name}): шаблон длиннее 300 символов")
        if flags not in ("", "i", "m", "im", "mi"):
            raise ValueError(f"extra_rules[{index}] ({name}): допустимы только флаги i и m")
        try:
            compiled = re.compile(
                pattern, (re.IGNORECASE if "i" in flags else 0) | (re.MULTILINE if "m" in flags else 0)
            )
        except re.error as error:
            raise ValueError(f"extra_rules[{index}] ({name}): плохой шаблон: {error}") from error
        rules.append(
            ExtraRule(
                name=name,
                klass=klass,
                pattern=compiled,
                flags=flags,
                explanation=explanation[:300],
            )
        )
    return tuple(rules)


def policy_from_dict(data: Mapping[str, Any], source: str | None = None) -> Policy:
    """Собрать политику из разобранного JSON, проверив структуру."""
    if not isinstance(data, Mapping):
        raise ValueError("политика должна быть объектом JSON")

    mode = data.get("mode", "strict")
    actions = dict(DEFAULT_ACTIONS)
    raw_actions = data.get("actions", {})
    if not isinstance(raw_actions, Mapping):
        raise ValueError("actions должен быть объектом")
    for klass, action in raw_actions.items():
        if not isinstance(klass, str) or not klass:
            raise ValueError(f"actions: некорректное имя класса {klass!r}")
        if not isinstance(action, str) or action not in ACTIONS:
            raise ValueError(f"actions[{klass!r}]: ожидается одно из {ACTIONS}")
        actions[klass] = action

    raw_markers = data.get("markers", list(DEFAULT_MARKERS))
    if not isinstance(raw_markers, Sequence) or isinstance(raw_markers, str):
        raise ValueError("markers должен быть списком строк")
    markers = tuple(str(marker).strip() for marker in raw_markers if str(marker).strip())

    raw_allow = data.get("allow", [])
    if not isinstance(raw_allow, Sequence) or isinstance(raw_allow, str):
        raise ValueError("allow должен быть списком")
    allow = tuple(_compile_allow(entry, i) for i, entry in enumerate(raw_allow))

    raw_limits = data.get("limits", {})
    if not isinstance(raw_limits, Mapping):
        raise ValueError("limits должен быть объектом")
    limits = Limits(
        chunk_chars=int(raw_limits.get("chunk_chars", Limits().chunk_chars)),
        request_chars=int(raw_limits.get("request_chars", Limits().request_chars)),
        budget_ms=int(raw_limits.get("budget_ms", Limits().budget_ms)),
        retention_days=int(raw_limits.get("retention_days", Limits().retention_days)),
    )

    restore = _parse_restore(data.get("restore", {}))
    request = _parse_request(data.get("request", {}))
    review = _parse_review(data.get("review", {}))
    extra_rules = _parse_extra_rules(data.get("extra_rules"), actions)

    return Policy(
        mode=mode,
        actions=actions,
        markers=markers,
        allow=allow,
        limits=limits,
        restore=restore,
        request=request,
        review=review,
        extra_rules=extra_rules,
        source=source,
    )


def _parse_review(raw: Any) -> ReviewSettings:
    if not isinstance(raw, Mapping):
        raise ValueError("review должен быть объектом")
    defaults = ReviewSettings()

    def text(name: str, default: str) -> str:
        value = raw.get(name, default)
        if not isinstance(value, str):
            raise ValueError(f"review.{name} должен быть строкой")
        return value.strip()

    def number(name: str, default: int, minimum: int) -> int:
        value = int(raw.get(name, default))
        if value < minimum:
            raise ValueError(f"review.{name} меньше {minimum}")
        return value

    return ReviewSettings(
        base_url=text("base_url", defaults.base_url),
        model=text("model", defaults.model),
        sessions=text("sessions", defaults.sessions),
        days=number("days", defaults.days, 1),
        limit=number("limit", defaults.limit, 0),
        per_session=number("per_session", defaults.per_session, 0),
    )


def _string_tuple(value: Any, name: str) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, str):
        raise ValueError(f"{name} должен быть списком строк")
    items = tuple(str(item) for item in value if str(item))
    if not items:
        raise ValueError(f"{name} не может быть пустым")
    return items


def _parse_restore(raw: Any) -> Restore:
    if not isinstance(raw, Mapping):
        raise ValueError("restore должен быть объектом")
    text = raw.get("text", Restore().text)
    tool_use = raw.get("tool_use", Restore().tool_use)
    for name, value in (("restore.text", text), ("restore.tool_use", tool_use)):
        if not isinstance(value, bool):
            raise ValueError(f"{name} должен быть true или false")
    return Restore(text=text, tool_use=tool_use)


def _parse_request(raw: Any) -> RequestSchema:
    if not isinstance(raw, Mapping):
        raise ValueError("request должен быть объектом")
    defaults = RequestSchema()
    return RequestSchema(
        allowed_fields=_string_tuple(
            raw.get("allowed_fields", defaults.allowed_fields), "request.allowed_fields"
        ),
        allowed_roles=_string_tuple(
            raw.get("allowed_roles", defaults.allowed_roles), "request.allowed_roles"
        ),
        allowed_block_types=_string_tuple(
            raw.get("allowed_block_types", defaults.allowed_block_types),
            "request.allowed_block_types",
        ),
        blocked_block_types=_string_tuple(
            raw.get("blocked_block_types", defaults.blocked_block_types),
            "request.blocked_block_types",
        ),
    )


def default_policy_path() -> Path:
    """`policy.json` рядом с пакетом; если его нет — `policy.example.json`."""
    root = Path(__file__).resolve().parent.parent
    local = root / "policy.json"
    return local if local.exists() else root / "policy.example.json"


def load_policy(path: Path | str | None = None) -> Policy:
    """Прочитать политику с диска. Без пути берётся `policy.json` в корне проекта."""
    policy_path = Path(path) if path is not None else default_policy_path()
    if not policy_path.exists():
        if path is not None:
            raise FileNotFoundError(f"нет файла политики: {policy_path}")
        return Policy(source=None)
    with policy_path.open("r", encoding="utf-8") as handle:
        try:
            data = json.load(handle)
        except json.JSONDecodeError as error:
            raise ValueError(f"{policy_path}: некорректный JSON: {error}") from error
    return policy_from_dict(data, source=str(policy_path))
