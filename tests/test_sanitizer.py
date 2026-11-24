"""Санитайзер payload Anthropic: маскировка, блокировки, служебные поля."""

from __future__ import annotations

import unittest
from dataclasses import replace
from pathlib import Path

from redactrail.policy import load_policy, policy_from_dict
from redactrail.pseudonym import Pseudonymizer
from redactrail.sanitizer import BlockedRequest, Sanitizer
from tests import support

_SCRATCH = None
_SCRATCH_PATH: Path | None = None


def setUpModule() -> None:
    global _SCRATCH, _SCRATCH_PATH
    _SCRATCH = support.scratch_dir()
    _SCRATCH_PATH = _SCRATCH.__enter__()


def tearDownModule() -> None:
    if _SCRATCH is not None:
        _SCRATCH.__exit__(None, None, None)


def make_sanitizer(mode: str = "strict", on_block=None) -> Sanitizer:
    assert _SCRATCH_PATH is not None
    pseudonymizer = Pseudonymizer.from_key_file(_SCRATCH_PATH / "secret.key")
    base = load_policy()
    # [[PERSON_4939D9FFD4]] настройки: живой policy.json меняется из админки, тесты — нет.
    actions = {**base.actions, "image": "block", "document": "block"}
    policy = replace(base, actions=actions).with_mode(mode)
    return Sanitizer(policy, pseudonymizer, on_block=on_block)


def payload(**overrides) -> dict:
    base = {
        "model": "deepseek-chat",
        "max_tokens": 512,
        "messages": [{"role": "user", "content": "Привет"}],
    }
    base.update(overrides)
    return base


class SystemTests(unittest.TestCase):
    def test_string_is_masked(self) -> None:
        instance = make_sanitizer()
        result = instance.sanitize(payload(system="Клиент Иванов Иван Иванович"))
        self.assertNotIn("Иванов", result.payload["system"])
        self.assertIn("[[PERSON_", result.payload["system"])

    def test_list_of_text_blocks(self) -> None:
        instance = make_sanitizer()
        result = instance.sanitize(
            payload(system=[{"type": "text", "text": "почта ivanov@example.ru"}])
        )
        block = result.payload["system"][0]
        self.assertEqual(block["type"], "text")
        self.assertIn("[[EMAIL_", block["text"])

    def test_tool_use_in_system_is_blocked(self) -> None:
        instance = make_sanitizer()
        with self.assertRaises(BlockedRequest) as ctx:
            instance.sanitize(payload(system=[{"type": "tool_use", "id": "x", "name": "n", "input": {}}]))
        self.assertEqual(ctx.exception.klass, "unknown_block")


class MessageTests(unittest.TestCase):
    def test_string_content(self) -> None:
        instance = make_sanitizer()
        result = instance.sanitize(
            payload(messages=[{"role": "user", "content": "звоните +7 999 123-45-67"}])
        )
        self.assertIn("[[PHONE_", result.payload["messages"][0]["content"])

    def test_blocks_and_cache_control(self) -> None:
        instance = make_sanitizer()
        result = instance.sanitize(
            payload(
                messages=[
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": "Иванов Иван", "cache_control": {"type": "ephemeral"}}
                        ],
                    }
                ]
            )
        )
        block = result.payload["messages"][0]["content"][0]
        self.assertEqual(block["cache_control"], {"type": "ephemeral"})
        self.assertIn("[[PERSON_", block["text"])

    def test_system_role_allowed(self) -> None:
        # DSH кладёт служебные сообщения прямо в messages с ролью system.
        instance = make_sanitizer()
        result = instance.sanitize(
            payload(messages=[{"role": "system", "content": "служебная заметка"}])
        )
        self.assertEqual(result.payload["messages"][0]["role"], "system")

    def test_unknown_role_blocked(self) -> None:
        instance = make_sanitizer()
        with self.assertRaises(BlockedRequest):
            instance.sanitize(payload(messages=[{"role": "tool", "content": "x"}]))

    def test_unknown_message_key_blocked(self) -> None:
        instance = make_sanitizer()
        with self.assertRaises(BlockedRequest) as ctx:
            instance.sanitize(payload(messages=[{"role": "user", "content": "x", "name": "y"}]))
        self.assertEqual(ctx.exception.klass, "unknown_field")


class ThinkingTests(unittest.TestCase):
    def test_clean_thinking_passes_unchanged(self) -> None:
        instance = make_sanitizer()
        block = {"type": "thinking", "thinking": "надо посчитать сумму", "signature": "abc"}
        result = instance.sanitize(
            payload(messages=[{"role": "assistant", "content": [block]}])
        )
        self.assertEqual(result.payload["messages"][0]["content"][0], block)

    def test_thinking_with_pii_is_masked(self) -> None:
        # Живой прогон: блокировать thinking нельзя — DSH пересылает прежние
        # размышления в каждом запросе, и сессия становится нерабочей.
        instance = make_sanitizer()
        block = {"type": "thinking", "thinking": "клиент Иванов Иван Иванович", "signature": "abc"}
        result = instance.sanitize(payload(messages=[{"role": "assistant", "content": [block]}]))
        masked = result.payload["messages"][0]["content"][0]
        self.assertIn("[[PERSON_", masked["thinking"])
        self.assertNotIn("Иванов", masked["thinking"])
        self.assertEqual(masked["signature"], "abc")

    def test_thinking_block_action_still_available(self) -> None:
        context = make_sanitizer()
        context.policy = context.policy.__class__(
            mode="strict",
            actions={**context.policy.actions, "thinking": "block"},
            markers=context.policy.markers,
            allow=context.policy.allow,
            limits=context.policy.limits,
            restore=context.policy.restore,
            request=context.policy.request,
        )
        block = {"type": "thinking", "thinking": "клиент Иванов Иван Иванович", "signature": "abc"}
        with self.assertRaises(BlockedRequest) as ctx:
            context.sanitize(payload(messages=[{"role": "assistant", "content": [block]}]))
        self.assertEqual(ctx.exception.klass, "thinking")

    def test_secret_in_thinking_is_masked(self) -> None:
        instance = make_sanitizer()
        block = {"type": "thinking", "thinking": "ключ AKIAIOSFODNN7EXAMPLE", "signature": "abc"}
        result = instance.sanitize(payload(messages=[{"role": "assistant", "content": [block]}]))
        thinking = result.payload["messages"][0]["content"][0]["thinking"]
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", thinking)
    def test_redacted_thinking_passes(self) -> None:
        instance = make_sanitizer()
        block = {"type": "redacted_thinking", "data": "ENCRYPTED"}
        result = instance.sanitize(payload(messages=[{"role": "assistant", "content": [block]}]))
        self.assertEqual(result.payload["messages"][0]["content"][0], block)


class AttachmentTests(unittest.TestCase):
    def test_image_allowed_when_filter_disabled(self) -> None:
        instance = make_sanitizer()
        base = instance.policy
        instance.policy = base.__class__(
            mode="strict",
            actions={**base.actions, "image": "allow", "document": "allow"},
            markers=base.markers,
            allow=base.allow,
            limits=base.limits,
            restore=base.restore,
            request=base.request,
        )
        block = {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "AAA"}}
        result = instance.sanitize(payload(messages=[{"role": "user", "content": [block]}]))
        self.assertEqual(result.payload["messages"][0]["content"][0], block)

    def test_image_blocked_by_default(self) -> None:
        instance = make_sanitizer()
        with self.assertRaises(BlockedRequest) as ctx:
            instance.sanitize(
                payload(messages=[{"role": "user", "content": [{"type": "image", "source": {}}]}])
            )
        self.assertEqual(ctx.exception.klass, "image")

    def test_document_blocked(self) -> None:
        instance = make_sanitizer()
        with self.assertRaises(BlockedRequest) as ctx:
            instance.sanitize(
                payload(messages=[{"role": "user", "content": [{"type": "document", "source": {}}]}])
            )
        self.assertEqual(ctx.exception.klass, "document")

    def test_unknown_block_type(self) -> None:
        instance = make_sanitizer()
        with self.assertRaises(BlockedRequest) as ctx:
            instance.sanitize(
                payload(messages=[{"role": "user", "content": [{"type": "video", "data": "x"}]}])
            )
        self.assertEqual(ctx.exception.klass, "unknown_block")

    def test_unknown_key_in_text_block(self) -> None:
        instance = make_sanitizer()
        with self.assertRaises(BlockedRequest) as ctx:
            instance.sanitize(
                payload(messages=[{"role": "user", "content": [{"type": "text", "text": "x", "meta": 1}]}])
            )
        self.assertEqual(ctx.exception.klass, "unknown_field")


class ToolTests(unittest.TestCase):
    def test_tool_reference_blocks_allowed(self) -> None:
        # DSH включает/выключает инструменты блоками tool_addition/tool_removal.
        instance = make_sanitizer()
        block = {"type": "tool_addition", "tool": {"type": "tool_reference", "name": "read_file"}}
        result = instance.sanitize(
            payload(messages=[{"role": "assistant", "content": [block]}])
        )
        self.assertEqual(result.payload["messages"][0]["content"][0], block)

    def test_defer_loading_allowed(self) -> None:
        instance = make_sanitizer()
        result = instance.sanitize(
            payload(
                tools=[
                    {
                        "name": "read_file",
                        "description": "Читает файл",
                        "input_schema": {"type": "object"},
                        "defer_loading": True,
                    }
                ]
            )
        )
        self.assertTrue(result.payload["tools"][0]["defer_loading"])

    def test_tool_description_masked_schema_numbers_preserved(self) -> None:
        instance = make_sanitizer()
        result = instance.sanitize(
            payload(
                tools=[
                    {
                        "name": "read_file",
                        "description": "Читает файл, автор Иванов Иван",
                        "input_schema": {
                            "type": "object",
                            "properties": {
                                "path": {"type": "string", "description": "путь к файлу"},
                                "limit": {"type": "integer", "minimum": 1, "maximum": 4096},
                            },
                            "required": ["path"],
                        },
                    }
                ]
            )
        )
        tool = result.payload["tools"][0]
        self.assertEqual(tool["name"], "read_file")
        self.assertIn("[[PERSON_", tool["description"])
        schema = tool["input_schema"]
        self.assertEqual(schema["properties"]["limit"], {"type": "integer", "minimum": 1, "maximum": 4096})
        self.assertEqual(schema["required"], ["path"])

    def test_tool_use_input_strings_masked(self) -> None:
        instance = make_sanitizer()
        result = instance.sanitize(
            payload(
                messages=[
                    {
                        "role": "assistant",
                        "content": [
                            {
                                "type": "tool_use",
                                "id": "toolu_1",
                                "name": "read_file",
                                "input": {"path": r"C:\Users\user\a.txt", "note": "Иванов Иван"},
                            }
                        ],
                    }
                ]
            )
        )
        block = result.payload["messages"][0]["content"][0]
        self.assertEqual(block["id"], "toolu_1")
        self.assertEqual(block["name"], "read_file")
        self.assertIn("[[USER_", block["input"]["path"])
        self.assertIn("[[PERSON_", block["input"]["note"])

    def test_tool_use_numbers_typed(self) -> None:
        instance = make_sanitizer()
        result = instance.sanitize(
            payload(
                messages=[
                    {
                        "role": "assistant",
                        "content": [
                            {
                                "type": "tool_use",
                                "id": "toolu_1",
                                "name": "lookup",
                                "input": {"phone": 79991234567, "order": 42, "ok": True},
                            }
                        ],
                    }
                ]
            )
        )
        data = result.payload["messages"][0]["content"][0]["input"]
        self.assertIsInstance(data["phone"], str)
        self.assertIn("[[PHONE_", data["phone"])
        self.assertEqual(result.table[data["phone"]], 79991234567)
        self.assertEqual(data["order"], 42)
        self.assertIs(data["ok"], True)

    def test_tool_result_nested_blocks(self) -> None:
        instance = make_sanitizer()
        result = instance.sanitize(
            payload(
                messages=[
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "tool_result",
                                "tool_use_id": "toolu_1",
                                "content": [
                                    {"type": "text", "text": "найдено: ivanov@example.ru"},
                                    {"type": "text", "text": "и Иванов И. И."},
                                ],
                            }
                        ],
                    }
                ]
            )
        )
        content = result.payload["messages"][0]["content"][0]["content"]
        self.assertIn("[[EMAIL_", content[0]["text"])
        self.assertIn("[[PERSON_", content[1]["text"])


class BlockingTests(unittest.TestCase):
    def test_secret_is_masked(self) -> None:
        instance = make_sanitizer()
        result = instance.sanitize(payload(messages=[{"role": "user", "content": "password=hunter2secret"}]))
        text = result.payload["messages"][0]["content"]
        self.assertNotIn("hunter2secret", text)
        self.assertIn("[[", text)
    def test_marker_is_masked(self) -> None:
        instance = make_sanitizer()
        result = instance.sanitize(payload(messages=[{"role": "user", "content": "пометка ДСП"}]))
        text = result.payload["messages"][0]["content"]
        self.assertNotIn("ДСП", text)
        self.assertIn("[[", text)
    def test_unknown_top_level_field(self) -> None:
        instance = make_sanitizer()
        with self.assertRaises(BlockedRequest) as ctx:
            instance.sanitize(payload(extra_field=1))
        self.assertEqual(ctx.exception.klass, "unknown_field")

    def test_error_message_is_human_readable(self) -> None:
        instance = make_sanitizer()
        with self.assertRaises(BlockedRequest) as ctx:
            instance.sanitize(payload(unknown_field_here=1))
        message = ctx.exception.as_message()
        self.assertIn("[redactrail]", message)
        self.assertIn("unknown_field", message)
    def test_audit_still_masks_marker(self) -> None:
        instance = make_sanitizer(mode="audit")
        result = instance.sanitize(payload(messages=[{"role": "user", "content": "пометка ДСП"}]))
        self.assertIn("[[MARKER_", result.payload["messages"][0]["content"])
    def test_audit_still_masks_pii(self) -> None:
        instance = make_sanitizer(mode="audit")
        result = instance.sanitize(payload(messages=[{"role": "user", "content": "Иванов Иван"}]))
        self.assertIn("[[PERSON_", result.payload["messages"][0]["content"])

    def test_off_returns_payload_unchanged(self) -> None:
        instance = make_sanitizer(mode="off")
        original = payload(messages=[{"role": "user", "content": "Иванов Иван"}])
        result = instance.sanitize(original)
        self.assertEqual(result.payload, original)
        self.assertEqual(result.findings, 0)


class IdempotencyTests(unittest.TestCase):
    def test_second_pass_changes_nothing(self) -> None:
        instance = make_sanitizer()
        original = payload(
            messages=[
                {"role": "user", "content": "Иванов Иван, +7 999 123-45-67, ivanov@example.ru"}
            ]
        )
        first = instance.sanitize(original)
        second = instance.sanitize(first.payload)
        self.assertEqual(first.payload, second.payload)
        self.assertEqual(second.findings, 0)


class TokenTrackingTests(unittest.TestCase):
    """Токены по классам: по ним считается число разных значений, а не срабатываний."""

    def test_repeated_value_gives_one_token(self) -> None:
        instance = make_sanitizer()
        text = "Иван Петров писал, Иван Петров звонил, снова +7 999 123-45-67."
        result = instance.sanitize(payload(messages=[{"role": "user", "content": text}]))
        self.assertEqual(result.classes["person"], 2, "срабатываний два")
        self.assertEqual(len(result.tokens["person"]), 1, "значение одно")

    def test_tokens_are_stable_between_requests(self) -> None:
        instance = make_sanitizer()
        text = "Иван Петров"
        first = instance.sanitize(payload(messages=[{"role": "user", "content": text}]))
        second = instance.sanitize(payload(messages=[{"role": "user", "content": text}]))
        self.assertEqual(first.tokens["person"], second.tokens["person"])

    def test_tokens_reset_between_requests(self) -> None:
        instance = make_sanitizer()
        instance.sanitize(payload(messages=[{"role": "user", "content": "Иван Петров"}]))
        empty = instance.sanitize(payload(messages=[{"role": "user", "content": "просто текст"}]))
        self.assertEqual(empty.tokens, {})


class ReviewHookTests(unittest.TestCase):
    def test_hook_gets_hash_and_masked_window(self) -> None:
        events = []
        instance = make_sanitizer(mode="audit", on_block=events.append)
        from redactrail.policy import Policy

        base = instance.policy
        instance.policy = Policy(
            mode="audit",
            actions={**base.actions, "marker": "block"},
            markers=base.markers,
            allow=base.allow,
            limits=base.limits,
            restore=base.restore,
            request=base.request,
        )
        text = "Клиент Иванов Иван Иванович, пометка ДСП, телефон +7 999 123-45-67"
        instance.sanitize(payload(messages=[{"role": "user", "content": text}]))
        self.assertTrue(events)
        event = events[0]
        self.assertEqual(event.klass, "marker")
        self.assertEqual(event.value, "ДСП")
        self.assertEqual(len(event.value_hash), 16)
        self.assertNotIn("Иванов Иван Иванович", event.window)
        self.assertIn("ДСП", event.window)
    def test_output_config_passes_through(self) -> None:
        # DSH шлёт {'effort': 'high'} при включённом рассуждении.
        instance = make_sanitizer()
        result = instance.sanitize(payload(output_config={"effort": "high"}))
        self.assertEqual(result.payload["output_config"], {"effort": "high"})

    def test_unknown_field_still_blocked(self) -> None:
        instance = make_sanitizer()
        with self.assertRaises(BlockedRequest) as ctx:
            instance.sanitize(payload(output_weird={"x": 1}))
        self.assertEqual(ctx.exception.klass, "unknown_field")
        self.assertIn("output_weird", str(ctx.exception))

    def test_restore_and_request_from_dict(self) -> None:
        policy = policy_from_dict(
            {
                "restore": {"text": True, "tool_use": False},
                "request": {"allowed_roles": ["user"]},
            }
        )
        self.assertTrue(policy.restore.text)
        self.assertFalse(policy.restore.tool_use)
        self.assertEqual(policy.request.allowed_roles, ("user",))

    def test_bad_restore_value(self) -> None:
        with self.assertRaises(ValueError):
            policy_from_dict({"restore": {"text": "yes"}})

    def test_empty_allowed_fields_rejected(self) -> None:
        with self.assertRaises(ValueError):
            policy_from_dict({"request": {"allowed_fields": []}})


if __name__ == "__main__":
    unittest.main()
