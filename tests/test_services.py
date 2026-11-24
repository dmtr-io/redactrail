"""Перезапуск прокси через супервизор: поведение без настоящего планировщика.

`schtasks`, PowerShell и `taskkill` подменяются: тесты не должны гасить реальный
прокси и зависеть от того, установлен ли автозапуск на машине.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import unittest
from unittest import mock

from redactrail import services


class FakeClock:
    """Часы без сна: `time.sleep` сдвигает `monotonic`, цикл ожидания проходит сразу."""

    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


def completed(code: int, stdout: str = "") -> mock.Mock:
    return mock.Mock(returncode=code, stdout=stdout, stderr="")


class HiddenConsoleTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "Windows only")
    def test_run_hides_console_window(self) -> None:
        with mock.patch.object(services.subprocess, "run", return_value=completed(0)) as run:
            services._run(["schtasks", "/Query"])
        kwargs = run.call_args.kwargs
        self.assertTrue(kwargs.get("creationflags", 0) & subprocess.CREATE_NO_WINDOW)


class TaskQueryTests(unittest.TestCase):
    def test_installed_when_schtasks_succeeds(self) -> None:
        with mock.patch.object(services, "_run", return_value=completed(0)) as run:
            self.assertTrue(services.task_installed("redactrail-supervisor"))
        run.assert_called_once_with(["schtasks", "/Query", "/TN", "redactrail-supervisor"])

    def test_not_installed_when_schtasks_fails(self) -> None:
        with mock.patch.object(services, "_run", return_value=completed(1)):
            self.assertFalse(services.task_installed("redactrail-supervisor"))

    def test_not_installed_when_schtasks_cannot_run(self) -> None:
        with mock.patch.object(services, "_run", return_value=None):
            self.assertFalse(services.task_installed("redactrail-supervisor"))

    def test_start_reports_code(self) -> None:
        with mock.patch.object(services, "_run", return_value=completed(0)):
            self.assertTrue(services.start_task("redactrail-supervisor"))
        with mock.patch.object(services, "_run", return_value=completed(1)):
            self.assertFalse(services.start_task("redactrail-supervisor"))

    def test_running_state_is_parsed_from_enum(self) -> None:
        with mock.patch.object(services, "_powershell", return_value=completed(0, "Running\n")):
            self.assertTrue(services.task_running("redactrail-supervisor"))
        with mock.patch.object(services, "_powershell", return_value=completed(0, "Ready\n")):
            self.assertFalse(services.task_running("redactrail-supervisor"))
        with mock.patch.object(services, "_powershell", return_value=completed(1)):
            self.assertFalse(services.task_running("redactrail-supervisor"))

    def test_proxy_pid_parsed_or_none(self) -> None:
        with mock.patch.object(services, "_powershell", return_value=completed(0, " 4242 \n")):
            self.assertEqual(services.proxy_pid(), 4242)
        with mock.patch.object(services, "_powershell", return_value=completed(0, "\n")):
            self.assertIsNone(services.proxy_pid())
        with mock.patch.object(services, "_powershell", return_value=completed(1)):
            self.assertIsNone(services.proxy_pid())


class RestartProxyTests(unittest.TestCase):
    def test_without_autostart_nothing_is_killed(self) -> None:
        with mock.patch.object(services, "health", return_value={"reachable": False}), (
            mock.patch.object(services, "task_installed", return_value=False)
        ), mock.patch.object(services, "proxy_pid") as pid, mock.patch.object(
            services, "stop_process"
        ) as stop:
            report = services.restart_proxy()
        self.assertFalse(report["ok"])
        self.assertEqual(report["actions"], [])
        self.assertIn("install-autostart", report["hint"])
        pid.assert_not_called()
        stop.assert_not_called()

    def test_running_supervisor_restarts_proxy_process(self) -> None:
        replies = [{"reachable": False}, {"reachable": False}, {"reachable": True, "body": "ok"}]
        clock = FakeClock()
        with mock.patch.object(services, "health", side_effect=replies), (
            mock.patch.object(services, "task_installed", return_value=True)
        ), mock.patch.object(services, "task_running", return_value=True), mock.patch.object(
            services, "start_task"
        ) as start, mock.patch.object(services, "proxy_pid", return_value=4242), mock.patch.object(
            services, "stop_process", return_value=True
        ) as stop, mock.patch.object(services, "time", clock):
            report = services.restart_proxy(wait_seconds=5)
        self.assertTrue(report["ok"])
        self.assertEqual(report["actions"], ["restart_proxy"])
        start.assert_not_called()
        stop.assert_called_once_with(4242)

    def test_stopped_supervisor_is_started_first(self) -> None:
        clock = FakeClock()
        with mock.patch.object(services, "health", return_value={"reachable": True}), (
            mock.patch.object(services, "task_installed", return_value=True)
        ), mock.patch.object(services, "task_running", return_value=False), mock.patch.object(
            services, "start_task", return_value=True
        ) as start, mock.patch.object(services, "proxy_pid", return_value=4242), mock.patch.object(
            services, "stop_process", return_value=True
        ), mock.patch.object(services, "time", clock):
            report = services.restart_proxy(wait_seconds=5)
        self.assertEqual(report["actions"], ["start_supervisor", "restart_proxy"])
        self.assertTrue(report["ok"])
        start.assert_called_once_with(services.SUPERVISOR_TASK)

    def test_dead_proxy_is_left_to_supervisor(self) -> None:
        clock = FakeClock()
        replies = [{"reachable": False}, {"reachable": True, "body": "ok"}]
        with mock.patch.object(services, "health", side_effect=replies), (
            mock.patch.object(services, "task_installed", return_value=True)
        ), mock.patch.object(services, "task_running", return_value=True), mock.patch.object(
            services, "start_task"
        ), mock.patch.object(services, "proxy_pid", return_value=None), mock.patch.object(
            services, "stop_process"
        ) as stop, mock.patch.object(services, "time", clock):
            report = services.restart_proxy(wait_seconds=5)
        self.assertEqual(report["actions"], ["wait_supervisor"])
        self.assertTrue(report["ok"])
        stop.assert_not_called()

    def test_unknown_pid_while_proxy_answers_is_reported(self) -> None:
        # прокси отвечает, но процесс не найден: Get-NetTCPConnection не сработал
        with mock.patch.object(services, "health", return_value={"reachable": True}), (
            mock.patch.object(services, "task_installed", return_value=True)
        ), mock.patch.object(services, "task_running", return_value=True), mock.patch.object(
            services, "start_task"
        ), mock.patch.object(services, "proxy_pid", return_value=None), mock.patch.object(
            services, "stop_process"
        ) as stop:
            report = services.restart_proxy()
        self.assertFalse(report["ok"])
        self.assertEqual(report["actions"], ["pid_unknown"])
        self.assertIn("Get-NetTCPConnection", report["hint"])
        stop.assert_not_called()

    def test_failed_kill_is_reported(self) -> None:
        with mock.patch.object(services, "health", return_value={"reachable": True}), (
            mock.patch.object(services, "task_installed", return_value=True)
        ), mock.patch.object(services, "task_running", return_value=True), mock.patch.object(
            services, "start_task"
        ), mock.patch.object(services, "proxy_pid", return_value=4242), mock.patch.object(
            services, "stop_process", return_value=False
        ):
            report = services.restart_proxy()
        self.assertFalse(report["ok"])
        self.assertIn("stop_failed", report["actions"])

    def test_wait_gives_up_and_reports_unreachable(self) -> None:
        clock = FakeClock()
        with mock.patch.object(services, "health", return_value={"reachable": False}), (
            mock.patch.object(services, "task_installed", return_value=True)
        ), mock.patch.object(services, "task_running", return_value=True), mock.patch.object(
            services, "start_task"
        ), mock.patch.object(services, "proxy_pid", return_value=4242), mock.patch.object(
            services, "stop_process", return_value=True
        ), mock.patch.object(services, "time", clock):
            report = services.restart_proxy(wait_seconds=2)
        self.assertFalse(report["ok"])
        self.assertFalse(report["after"]["reachable"])
        self.assertIn("supervisor.log", report["hint"])
        self.assertGreaterEqual(clock.now, 2)


class RunDecodingTests(unittest.TestCase):
    """Вывод команд декодируется без падения: кодировка консоли ≠ локаль."""

    def test_undecodable_bytes_are_replaced(self) -> None:
        # 0x98 не является началом UTF-8-последовательности, поэтому вывод
        # декодируется с заменой байта на U+FFFD в любой локали (в cp1252 этот
        # байт — «˜», в cp1251 не определён; фиксированная UTF-8-декодировка
        # убирает зависимость теста от кодировки машины).
        script = "import sys; sys.stdout.buffer.write(b'\\x98'); sys.stderr.buffer.write(b'\\x98')"
        with mock.patch.object(services, "available", return_value=True):
            result = services._run([sys.executable, "-c", script])
        self.assertIsNotNone(result)
        self.assertEqual(result.returncode, 0)
        self.assertIn("\ufffd", result.stdout)
        self.assertIn("\ufffd", result.stderr)

    @unittest.skipUnless(shutil.which("schtasks"), "schtasks нет в PATH")
    def test_real_schtasks_output_does_not_raise(self) -> None:
        # Настоящий `schtasks` с заведомо отсутствующей задачей: вывод локализован,
        # и именно такие строки («ОШИБКА: …») роняли декодирование.
        result = services._run(["schtasks", "/Query", "/TN", "redactrail-no-such-task"])
        self.assertIsNotNone(result, "schtasks не запустился — проверьте PATH")
        self.assertNotEqual(result.returncode, 0)

    def test_proxy_pid_tolerates_empty_output(self) -> None:
        with mock.patch.object(services, "_powershell", return_value=completed(0, None)):
            self.assertIsNone(services.proxy_pid())


if __name__ == "__main__":
    unittest.main()
