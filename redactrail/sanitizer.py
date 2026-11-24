"""Санитайзер запроса Anthropic Messages: маскировка, блокировки, таблица разворота.

Модуль обходит payload по явной схеме и решает три задачи:

1. **Маскировать** свободный текст и аргументы инструментов, собрав таблицу
   «токен → исходное значение» на время запроса (её использует `proxy.py` в M3,
   чтобы развернуть `tool_use` в ответе).
2. **Блокировать** то, что политика запрещает отправлять: секреты, пометки,
   вложения, неизвестные поля и типы блоков, а также `thinking` с находками —
   подпись блока не переживёт переписывания текста.
3. **Не трогать** служебные поля: `cache_control`, схемы инструментов (кроме
   описаний), идентификаторы инструментов и моделей. Иначе ломается кеш промпта
   DSH и вызовы инструментов.

Всё, что не описано схемой, блокируется. Списки разрешённого живут в
`policy.json` → `request`, чтобы новое поле API можно было разрешить без правки
кода.

Значения в таблице хранятся с исходным типом: число, замаскированное в
`tool_use.input`, вернётся числом, а не строкой.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Sequence

from . import scan
from .detections import Finding, apply_mask
from .policy import Policy
from .pseudonym import Pseudonymizer

#: Подсказка человеку в тексте ошибки: что именно сделать.
HINTS: dict[str, str] = {
    "private_key": "удалите приватный ключ из контекста",
    "secret_token": "удалите токен из контекста",
    "secret_assign": "удалите пароль или ключ из контекста",
    "marker": "у документа пометка конфиденциальности — работайте с копией без неё",
    "blob": "в контексте двоичные или закодированные данные",
    "image": "изображения и вложения не отправляются",
    "document": "изображения и вложения не отправляются",
    "thinking": "в блоке размышлений найдены персональные данные — начните новый чат",
    "unknown_block": "неизвестный тип контент-блока",
    "unknown_field": "неизвестное поле или ключ в запросе",
    "oversize": "слишком длинный блок текста",
    "number": "числовой аргумент похож на персональные данные",
}

BLOCK_KEYS = frozenset({"private_key", "secret_token", "secret_assign", "marker", "blob"})


class BlockedRequest(Exception):
    """Запрос не должен уходить провайдеру."""

    def __init__(self, klass: str, where: str, finding: Finding | None = None) -> None:
        self.klass = klass
        self.where = where
        self.finding = finding
        hint = HINTS.get(klass, "")
        text = f"заблокировано: {klass} ({where})"
        if hint:
            text += f"; {hint}"
        super().__init__(text)

    def as_message(self) -> str:
        return f"[redactrail] {self}"


@dataclass(frozen=True)
class BlockEvent:
    """Событие для фонового ревью. Живёт в памяти, на диск значения не пишутся."""

    klass: str
    where: str
    value: str
    value_hash: str
    length: int
    window: str

    @classmethod
    def build(cls, text: str, finding: Finding, where: str, window: str) -> "BlockEvent":
        digest = hashlib.sha256(finding.value.encode("utf-8")).hexdigest()[:16]
        return cls(
            klass=finding.klass,
            where=where,
            value=finding.value,
            value_hash=digest,
            length=len(finding.value),
            window=window,
        )


@dataclass
class SanitizeResult:
    payload: dict
    table: dict[str, Any] = field(default_factory=dict)
    findings: int = 0
    classes: dict[str, int] = field(default_factory=dict)
    #: Токены по классам: стабильные псевдонимы значений. По ним видно, сколько
    #: **разных** значений замаскировано, а не сколько раз сработало правило.
    tokens: dict[str, set[str]] = field(default_factory=dict)


class Sanitizer:
    """Обход payload и решение по каждому блоку."""

    def __init__(
        self,
        policy: Policy,
        pseudonymizer: Pseudonymizer,
        on_block: Callable[[BlockEvent], None] | None = None,
    ) -> None:
        self.policy = policy
        self.pseudonymizer = pseudonymizer
        self.on_block = on_block
        self._table: dict[str, Any] = {}
        self._count = 0
        self._classes: dict[str, int] = {}
        self._tokens: dict[str, set[str]] = {}
        self._strict = policy.mode == "strict"

    # --- вход ---------------------------------------------------------

    def sanitize(self, payload: Mapping[str, Any]) -> SanitizeResult:
        """Вернуть очищенную копию payload и таблицу «токен → значение»."""
        self._table = {}
        self._count = 0
        self._classes = {}
        self._tokens = {}
        if self.policy.mode == "off":
            return SanitizeResult(dict(payload), {}, 0)
        if not isinstance(payload, Mapping):
            raise BlockedRequest("unknown_field", "тело запроса: ожидался объект")
        result = self._request(payload)
        return SanitizeResult(
            result,
            dict(self._table),
            self._count,
            dict(self._classes),
            {klass: set(tokens) for klass, tokens in self._tokens.items()},
        )

    # --- верхний уровень ----------------------------------------------

    def _request(self, payload: Mapping[str, Any]) -> dict:
        allowed = self.policy.request.allowed_fields
        for key in payload:
            if key not in allowed:
                raise BlockedRequest("unknown_field", f"поле {key!r}")
        result: dict[str, Any] = {}
        for key, value in payload.items():
            result[key] = self._dispatch_field(key, value)
        return result

    def _dispatch_field(self, key: str, value: Any) -> Any:
        handler = self._FIELD_HANDLERS.get(key)
        if handler is not None:
            return handler(self, value)
        return value

    # --- поля запроса -------------------------------------------------

    def _field_messages(self, value: Any) -> list:
        if not isinstance(value, list):
            raise BlockedRequest("unknown_field", "messages: ожидался список")
        allowed_roles = self.policy.request.allowed_roles
        result: list[dict] = []
        for index, message in enumerate(value):
            where = f"messages[{index}]"
            if not isinstance(message, Mapping):
                raise BlockedRequest("unknown_field", f"{where}: ожидался объект")
            extra = set(message) - {"role", "content"}
            if extra:
                raise BlockedRequest("unknown_field", f"{where}: ключ {sorted(extra)[0]!r}")
            role = message.get("role")
            if role not in allowed_roles:
                raise BlockedRequest("unknown_field", f"{where}: роль {role!r}")
            content = message.get("content")
            if isinstance(content, str):
                result.append({"role": role, "content": self._mask_text(content, where)})
            elif isinstance(content, list):
                blocks = [
                    self._block(block, f"{where}[{position}]")
                    for position, block in enumerate(content)
                ]
                result.append({"role": role, "content": blocks})
            else:
                raise BlockedRequest("unknown_field", f"{where}: content")
        return result

    def _field_system(self, value: Any) -> Any:
        if isinstance(value, str):
            return self._mask_text(value, "system")
        if isinstance(value, list):
            blocks: list[dict] = []
            for index, block in enumerate(value):
                where = f"system[{index}]"
                if not isinstance(block, Mapping) or block.get("type") != "text":
                    raise BlockedRequest("unknown_block", where)
                blocks.append(self._block(block, where, only=("text",)))
            return blocks
        raise BlockedRequest("unknown_field", "system: ожидалась строка или список")

    def _field_tools(self, value: Any) -> list:
        if not isinstance(value, list):
            raise BlockedRequest("unknown_field", "tools: ожидался список")
        result: list[dict] = []
        for index, tool in enumerate(value):
            where = f"tools[{index}]"
            if not isinstance(tool, Mapping):
                raise BlockedRequest("unknown_field", where)
            extra = set(tool) - {"name", "description", "input_schema", "cache_control", "type", "strict", "defer_loading"}
            if extra:
                raise BlockedRequest("unknown_field", f"{where}: ключ {sorted(extra)[0]!r}")
            item = dict(tool)
            if "name" in item:
                item["name"] = self._identifier(item["name"], f"{where}.name")
            if "description" in item:
                item["description"] = self._mask_text(str(item["description"]), f"{where}.description")
            if "input_schema" in item:
                item["input_schema"] = self._schema(item["input_schema"], f"{where}.input_schema")
            result.append(item)
        return result

    def _field_tool_choice(self, value: Any) -> Any:
        return self._identifiers(value, "tool_choice")

    def _field_metadata(self, value: Any) -> Any:
        if not isinstance(value, Mapping):
            raise BlockedRequest("unknown_field", "metadata: ожидался объект")
        result: dict[str, Any] = {}
        for key, item in value.items():
            if isinstance(item, str):
                result[key] = self._mask_text(item, f"metadata.{key}")
            elif isinstance(item, (int, float, bool)) or item is None:
                result[key] = item
            else:
                raise BlockedRequest("unknown_field", f"metadata.{key}")
        return result

    def _field_stop_sequences(self, value: Any) -> list:
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise BlockedRequest("unknown_field", "stop_sequences: ожидался список строк")
        return [self._mask_text(item, "stop_sequences") for item in value]

    def _field_thinking(self, value: Any) -> Any:
        return self._identifiers(value, "thinking")

    def _field_output_config(self, value: Any) -> Any:
        # {'effort': 'low' | 'high' | 'max'} — перечисление, свободного текста нет.
        return self._identifiers(value, "output_config")

    def _field_output_format(self, value: Any) -> Any:
        return self._schema(value, "output_format")

    def _field_container(self, value: Any) -> Any:
        return self._identifiers(value, "container")

    _FIELD_HANDLERS: dict[str, Callable[["Sanitizer", Any], Any]] = {
        "messages": _field_messages,
        "system": _field_system,
        "tools": _field_tools,
        "tool_choice": _field_tool_choice,
        "metadata": _field_metadata,
        "stop_sequences": _field_stop_sequences,
        "thinking": _field_thinking,
        "output_config": _field_output_config,
        "output_format": _field_output_format,
        "container": _field_container,
    }

    # --- контент-блоки ------------------------------------------------

    def _block(self, block: Any, where: str, only: Sequence[str] | None = None) -> dict:
        if not isinstance(block, Mapping):
            raise BlockedRequest("unknown_block", f"{where}: ожидался объект")
        block_type = block.get("type")
        request = self.policy.request
        if block_type in ("image", "document") and self.policy.action_for(str(block_type)) == "allow":
            # Фильтр вложений выключен в админке: блок идёт как есть.
            return dict(block)
        if block_type in request.blocked_block_types:
            raise BlockedRequest(str(block_type), where)
        if block_type not in request.allowed_block_types:
            raise BlockedRequest("unknown_block", f"{where}: тип {block_type!r}")
        if only is not None and block_type not in only:
            raise BlockedRequest("unknown_block", f"{where}: тип {block_type!r}")
        handler = self._BLOCK_HANDLERS.get(str(block_type))
        if handler is None:
            raise BlockedRequest("unknown_block", f"{where}: тип {block_type!r}")
        return handler(self, dict(block), where)

    def _block_text(self, block: dict, where: str) -> dict:
        self._allow_keys(block, {"type", "text", "cache_control", "citations"}, where)
        if not isinstance(block.get("text"), str):
            raise BlockedRequest("unknown_block", f"{where}: text")
        block["text"] = self._mask_text(block["text"], where)
        return block

    def _block_thinking(self, block: dict, where: str) -> dict:
        """Блок размышлений: маскируется как текст, если политика так велит.

        Живой прогон показал, что «блокировать thinking» делает сессию
        нерабочей: DSH пересылает прежние размышления в каждом запросе, и одно
        упоминание имени замораживает чат навсегда. По умолчанию поэтому
        маскируем текст, оставляя подпись как есть; секреты в размышлениях
        по-прежнему блокируются. Если провайдер отвергнет изменённый thinking
        из-за подписи, действие переключается в `policy.json`:
        `actions.thinking = "block"` (как было) или `"allow"`.
        """
        self._allow_keys(block, {"type", "thinking", "signature", "cache_control"}, where)
        thinking = block.get("thinking")
        if not isinstance(thinking, str):
            raise BlockedRequest("unknown_block", f"{where}: thinking")
        findings = scan.detect(thinking, self.policy)
        if not findings:
            return block

        action = self.policy.action_for("thinking")
        blocking = [finding for finding in findings if self.policy.is_block(finding.klass)]
        for finding in blocking:
            self._notify(thinking, finding, where)
            if self._strict:
                raise BlockedRequest(finding.klass, where, finding)
        if action == "block":
            finding = findings[0]
            self._notify(thinking, finding, where)
            if self._strict:
                raise BlockedRequest("thinking", where, finding)
            return block
        if action == "allow":
            return block

        maskable = [finding for finding in findings if not self.policy.is_block(finding.klass)]
        if maskable:
            self._count += len(maskable)
            for finding in maskable:
                self._count_class(finding.klass)
            block["thinking"] = apply_mask(thinking, maskable, self._token)
        return block

    def _block_redacted_thinking(self, block: dict, where: str) -> dict:
        self._allow_keys(block, {"type", "data"}, where)
        return block

    def _block_tool_reference(self, block: dict, where: str) -> dict:
        """`tool_addition` / `tool_removal`: активация объявленного инструмента по имени."""
        self._allow_keys(block, {"type", "tool", "cache_control"}, where)
        tool = block.get("tool")
        if not isinstance(tool, Mapping):
            raise BlockedRequest("unknown_block", f"{where}: tool")
        self._allow_keys(tool, {"type", "name"}, f"{where}.tool")
        if tool.get("type") != "tool_reference":
            raise BlockedRequest("unknown_block", f"{where}: тип ссылки {tool.get('type')!r}")
        if "name" in tool:
            self._identifier(tool["name"], f"{where}.tool.name")
        return block

    def _block_tool_use(self, block: dict, where: str) -> dict:
        self._allow_keys(block, {"type", "id", "name", "input", "cache_control"}, where)
        if "id" in block:
            block["id"] = self._identifier(block["id"], f"{where}.id")
        if "name" in block:
            block["name"] = self._identifier(block["name"], f"{where}.name")
        if "input" in block:
            block["input"] = self._input_value(block["input"], f"{where}.input")
        return block

    def _block_tool_result(self, block: dict, where: str) -> dict:
        self._allow_keys(block, {"type", "tool_use_id", "content", "is_error", "cache_control"}, where)
        if "tool_use_id" in block:
            block["tool_use_id"] = self._identifier(block["tool_use_id"], f"{where}.tool_use_id")
        content = block.get("content")
        if isinstance(content, str):
            block["content"] = self._mask_text(content, where)
        elif isinstance(content, list):
            block["content"] = [
                self._block(item, f"{where}[{index}]")
                for index, item in enumerate(content)
            ]
        elif content is not None:
            raise BlockedRequest("unknown_field", f"{where}: content")
        return block

    _BLOCK_HANDLERS: dict[str, Callable[["Sanitizer", dict, str], dict]] = {
        "text": _block_text,
        "thinking": _block_thinking,
        "redacted_thinking": _block_redacted_thinking,
        "tool_addition": _block_tool_reference,
        "tool_removal": _block_tool_reference,
        "tool_use": _block_tool_use,
        "tool_result": _block_tool_result,
    }

    def _allow_keys(self, block: Mapping[str, Any], keys: set[str], where: str) -> None:
        extra = set(block) - keys
        if extra:
            raise BlockedRequest("unknown_field", f"{where}: ключ {sorted(extra)[0]!r}")

    # --- значения -----------------------------------------------------

    def _input_value(self, value: Any, where: str) -> Any:
        if isinstance(value, str):
            return self._mask_text(value, where)
        if isinstance(value, bool) or value is None:
            return value
        if isinstance(value, (int, float)):
            return self._mask_number(value, where)
        if isinstance(value, list):
            return [self._input_value(item, where) for item in value]
        if isinstance(value, Mapping):
            return {
                str(key): self._input_value(item, f"{where}.{key}")
                for key, item in value.items()
            }
        raise BlockedRequest("unknown_field", f"{where}: тип {type(value).__name__}")

    def _mask_text(self, text: str, where: str) -> str:
        findings = scan.detect(text, self.policy)
        for finding in findings:
            if self.policy.is_block(finding.klass):
                self._notify(text, finding, where)
                if self._strict:
                    raise BlockedRequest(finding.klass, where, finding)
        maskable = [f for f in findings if not self.policy.is_block(f.klass)]
        if not maskable:
            return text
        self._count += len(maskable)
        return apply_mask(text, maskable, self._token)

    def _mask_number(self, value: int | float, where: str) -> Any:
        text = repr(value) if isinstance(value, float) else str(value)
        findings = scan.detect(text, self.policy)
        if not findings and text.isdigit() and len(text) == 11 and text[0] in "78":
            # В числовом поле телефон приходит без «+» и без пробелов: 79991234567.
            findings = [Finding(0, len(text), "phone", text)]
        if not findings:
            return value
        blocking = [f for f in findings if self.policy.is_block(f.klass)]
        if blocking:
            self._notify(text, blocking[0], where)
            if self._strict:
                raise BlockedRequest(blocking[0].klass, where, blocking[0])
            return value
        covered = sum(finding.length for finding in findings)
        if covered < len(text):
            # Часть числа похожа на ПДн: разрывать число на токен и хвост нельзя.
            self._notify(text, findings[0], where)
            if self._strict:
                raise BlockedRequest("number", where, findings[0])
            return value
        token = self.pseudonymizer.token(findings[0].klass, text)
        self._table[token] = value
        self._count += len(findings)
        self._count_class(findings[0].klass, len(findings))
        self._track_token(findings[0].klass, token)
        return token

    def _count_class(self, klass: str, amount: int = 1) -> None:
        self._classes[klass] = self._classes.get(klass, 0) + amount

    def _track_token(self, klass: str, token: str) -> None:
        """Запомнить токен: одинаковые псевдонимы означают одно и то же значение."""
        self._tokens.setdefault(klass, set()).add(token)

    def _token(self, finding: Finding) -> str:
        token = self.pseudonymizer.token(finding.klass, finding.value)
        self._table[token] = finding.value
        self._count_class(finding.klass)
        self._track_token(finding.klass, token)
        return token

    # --- служебные структуры -----------------------------------------

    def _schema(self, value: Any, where: str) -> Any:
        """Схема JSON: маскируются только человекочитаемые описания."""
        if isinstance(value, Mapping):
            return {
                str(key): (
                    self._mask_text(item, f"{where}.{key}")
                    if key in ("description", "title") and isinstance(item, str)
                    else self._schema(item, f"{where}.{key}")
                )
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [self._schema(item, where) for item in value]
        if isinstance(value, str):
            self._check_only(value, where)
        return value

    def _identifier(self, value: Any, where: str) -> Any:
        if isinstance(value, str):
            self._check_only(value, where)
        return value

    def _identifiers(self, value: Any, where: str) -> Any:
        """Идентификаторы и настройки: не маскируем, но секреты не пропускаем."""
        if isinstance(value, str):
            self._check_only(value, where)
            return value
        if isinstance(value, Mapping):
            return {key: self._identifiers(item, f"{where}.{key}") for key, item in value.items()}
        if isinstance(value, list):
            return [self._identifiers(item, where) for item in value]
        return value

    def _check_only(self, text: str, where: str) -> None:
        for finding in scan.detect(text, self.policy):
            if self.policy.is_block(finding.klass):
                self._notify(text, finding, where)
                if self._strict:
                    raise BlockedRequest(finding.klass, where, finding)

    # --- события ревью -------------------------------------------------

    def _notify(self, text: str, finding: Finding, where: str) -> None:
        if self.on_block is None:
            return
        self.on_block(BlockEvent.build(text, finding, where, self._window(text, finding)))

    def _window(self, text: str, finding: Finding, radius: int = 200) -> str:
        """Окно вокруг находки: остальные находки заменены классами, спорная — как есть."""
        start = max(0, finding.start - radius)
        end = min(len(text), finding.end + radius)
        piece = text[start:end]
        pieces: list[str] = []
        cursor = 0
        for local in scan.detect(piece, self.policy):
            if local.start == finding.start - start and local.end == finding.end - start:
                continue
            pieces.append(piece[cursor : local.start])
            pieces.append(f"<{local.klass}>")
            cursor = local.end
        pieces.append(piece[cursor:])
        return "".join(pieces)


def restore_tokens(text: str, table: Mapping[str, Any]) -> str:
    """Развернуть известные токены в строке. Нужно только для аргументов `tool_use`."""
    if not table:
        return text
    for token, value in table.items():
        if token in text:
            text = text.replace(token, str(value))
    return text


def restore_json(value: Any, table: Mapping[str, Any]) -> Any:
    """Развернуть токены в разобранном JSON с сохранением типов.

    Если строковое значение целиком является токеном, подставляется исходное
    значение как есть — число остаётся числом. Если токен лишь часть строки
    (путь `[[USER_…]]/file.txt`), подставляется текстовое представление.
    """
    if not table:
        return value
    if isinstance(value, str):
        if value in table:
            return table[value]
        for token, original in table.items():
            if token in value:
                value = value.replace(token, str(original))
        return value
    if isinstance(value, list):
        return [restore_json(item, table) for item in value]
    if isinstance(value, Mapping):
        return {key: restore_json(item, table) for key, item in value.items()}
    return value
