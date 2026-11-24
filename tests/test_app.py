"""Единый процесс: оба сервера в одном приложении, без браузера и окон."""

from __future__ import annotations

import http.client
import json
import os
import shutil
import unittest
from unittest import mock

from redactrail import app
from tests import support


def get(port: int, path: str) -> tuple[int, dict]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request("GET", path)
        response = connection.getresponse()
        body = response.read()
        return response.status, json.loads(body or b"{}")
    finally:
        connection.close()


class UnifiedAppTests(unittest.TestCase):
    def setUp(self) -> None:
        self.context = support.scratch_dir()
        self.root = self.context.__enter__()
        shutil.copy(support.source_policy(), self.root / "policy.json")
        self.proxy_server, self.admin_server = app.build_servers(0, 0, self.root)
        self.threads = [
            app.serve(self.proxy_server, "proxy"),
            app.serve(self.admin_server, "admin"),
        ]

    def tearDown(self) -> None:
        for server in (self.proxy_server, self.admin_server):
            server.shutdown()
            server.server_close()
        for thread in self.threads:
            thread.join(timeout=5)
        self.context.__exit__(None, None, None)

    def test_both_servers_run_in_one_process(self) -> None:
        proxy_port = self.proxy_server.server_address[1]
        admin_port = self.admin_server.server_address[1]
        status, health = get(proxy_port, "/health")
        self.assertEqual(status, 200)
        self.assertEqual(health["status"], "ok")
        status, state = get(admin_port, "/api/state")
        self.assertEqual(status, 200)
        self.assertIn("mode", state)

    def test_unified_mode_marks_environment(self) -> None:
        self.assertEqual(os.environ.get("REDACTRAIL_UNIFIED"), "1")

    def test_restart_reports_instead_of_killing_process(self) -> None:
        with mock.patch.dict(os.environ, {"REDACTRAIL_UNIFIED": "1"}):
            with mock.patch("redactrail.services.restart_proxy") as restart:
                report = self.admin_server.state.restart_proxy()
        restart.assert_not_called()
        self.assertTrue(report["unified"])
        self.assertFalse(report["restarted"])
        self.assertIn("политика", report["message"])


if __name__ == "__main__":
    unittest.main()
