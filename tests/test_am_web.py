from __future__ import annotations

import json
import tempfile
import threading
import unittest
from http.client import HTTPConnection
from pathlib import Path

from vanillatool_emulator import am_config as C
from vanillatool_emulator.am_web import WebServer, WebState

REPO_ROOT = Path(__file__).resolve().parents[1]
TARGET = str(REPO_ROOT / "game.dll")


class WebTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        state = WebState(Path(self.tmp.name) / "ws",
                         C.AutomaticOptions(target_exe=TARGET))
        self.httpd = WebServer(("127.0.0.1", 0), state)
        self.thread = threading.Thread(target=self.httpd.serve_forever,
                                       daemon=True)
        self.thread.start()
        self.port = self.httpd.server_address[1]

    def tearDown(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)

    def _request(self, method: str, path: str,
                 payload: dict | None = None) -> tuple[int, bytes]:
        conn = HTTPConnection("127.0.0.1", self.port, timeout=30)
        body = json.dumps(payload or {}).encode() if payload is not None else None
        headers = {"Content-Type": "application/json"} if body else {}
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        return resp.status, data

    def test_dashboard_and_state(self) -> None:
        status, body = self._request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(b"Automatic Run", body)
        status, body = self._request("GET", "/api/state")
        self.assertEqual(status, 200)
        state = json.loads(body)
        self.assertEqual(len(state["servers"]), 10)
        self.assertGreater(len(state["hive"]), 20)
        # Passwords are masked in state output.
        for row in state["accounts"]:
            self.assertNotIn("secret", json.dumps(row))

    def test_accounts_crud(self) -> None:
        status, body = self._request("POST", "/api/accounts",
                                     {"slot": "0", "Account": "demo",
                                      "Password": "secret", "Client": "EuroAion",
                                      "LoginAll": "1"})
        self.assertEqual((status, json.loads(body)["ok"]), (200, True))
        status, body = self._request("GET", "/api/state")
        accounts = json.loads(body)["accounts"]
        self.assertEqual(len(accounts), 1)
        self.assertEqual(accounts[0]["Password"], "***")
        status, _ = self._request("DELETE", "/api/accounts?slot=0")
        self.assertEqual(status, 200)
        status, body = self._request("GET", "/api/state")
        self.assertEqual(json.loads(body)["accounts"], [])

    def test_run_and_emulator_lifecycle(self) -> None:
        if not Path(TARGET).is_file():
            self.skipTest("game.dll not present")
        status, body = self._request("POST", "/api/run",
                                     {"target_exe": TARGET, "server": "EuroAion",
                                      "emulator_port": 0})
        self.assertEqual(status, 200)
        report = json.loads(body)
        self.assertTrue(report["ok"], report)
        # Persistent emulator start/stop on an ephemeral port.
        status, body = self._request(
            "POST", "/api/emulator/start",
            {"target_exe": TARGET, "server": "EuroAion",
             "emulator_host": "127.0.0.1", "emulator_port": 0,
             "version": "11.31", "orythm": "1", "prythm": "2",
             "account_manager_startup": True})
        self.assertEqual(status, 200)
        started = json.loads(body)
        self.assertTrue(started["ok"], started)
        status, body = self._request("GET", "/api/state")
        self.assertTrue(json.loads(body)["emulator"]["running"])
        status, _ = self._request("POST", "/api/emulator/stop", {})
        self.assertEqual(status, 200)


if __name__ == "__main__":
    unittest.main()
