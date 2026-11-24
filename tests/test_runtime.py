"""Консольный вывод: кириллица не должна падать на cp1252."""

from __future__ import annotations

import io
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout

from redactrail.runtime import enable_utf8_output


class RuntimeTests(unittest.TestCase):
    def test_switches_streams_to_utf8(self) -> None:
        buffer = io.BytesIO()
        stream = io.TextIOWrapper(buffer, encoding="cp1252")
        other = io.BytesIO()
        error_stream = io.TextIOWrapper(other, encoding="cp1252")
        with redirect_stdout(stream), redirect_stderr(error_stream):
            enable_utf8_output()
            print("проверка")
            print("ошибка", file=sys.stderr)
            sys.stdout.flush()
            sys.stderr.flush()
        self.assertEqual(buffer.getvalue().decode("utf-8").strip(), "проверка")
        self.assertEqual(other.getvalue().decode("utf-8").strip(), "ошибка")

    def test_streams_without_reconfigure_are_ignored(self) -> None:
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            enable_utf8_output()
            print("без консоли")


if __name__ == "__main__":
    unittest.main()
