from __future__ import annotations

import json
import threading
import unittest
from http.client import HTTPConnection

from vanillatool_emulator.protocol import decrypt_response, encrypt_client_field
from vanillatool_emulator.server import EmulatorConfig, EmulatorHTTPServer


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.config = EmulatorConfig(version="11.31-test")
        cls.httpd = EmulatorHTTPServer(("127.0.0.1", 0), cls.config)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.httpd.server_address[1]

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=2)

    def request(self, method: str, path: str, body: bytes | None = None, headers: dict[str, str] | None = None):
        connection = HTTPConnection("127.0.0.1", self.port, timeout=3)
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        payload = response.read()
        connection.close()
        return response.status, payload

    def test_auth_route_returns_decryptable_positive_fixture(self) -> None:
        identity = b"65-66-67-68-69-70_1234567".ljust(24, b"O")
        body = (
            "aN=" + encrypt_client_field(identity)
            + "&aU=fixture&aH=17123456&aC=deadbeef&aV=11.31"
        ).encode("ascii")
        status, payload = self.request(
            "POST",
            "/data/auth.php",
            body,
            {"Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(status, 200)
        marker = payload.decode("ascii").strip()
        self.assertTrue(marker.startswith("C:") and marker.endswith(";"))
        ciphertext = marker[2:-1]
        # The default PRythm is 2 (smallest value that enables the named
        # region checkboxes without tripping the >7 expiry check).
        self.assertEqual(decrypt_response(ciphertext, "17123456", identity), b"ORythm=1;PRythm=2;")

    def test_version_health_and_logging_routes(self) -> None:
        status, payload = self.request("GET", "/Updateless/Version.txt")
        self.assertEqual((status, payload), (200, b"11.31-test\r\n"))

        status, payload = self.request("GET", "/healthz")
        self.assertEqual(status, 200)
        health = json.loads(payload)
        self.assertEqual(health["service"], "vanillatool-emulator")
        self.assertGreaterEqual(health["requests"], 2)

        status, payload = self.request("GET", "/Log/log.php?ID=11.31-test")
        self.assertEqual((status, payload), (200, b"OK\r\n"))

    def test_dynamic_routes_are_fixtures_not_proxy(self) -> None:
        status, payload = self.request("POST", "/POST/", b"url=https%3A%2F%2Fexample.invalid")
        self.assertEqual((status, payload), (200, b"OK\r\n"))


if __name__ == "__main__":
    unittest.main()
