#!/usr/bin/env python3
import http.client
import json
import socket
import tempfile
import threading
import unittest
from pathlib import Path

from vanillatool_emulator import EmulatorConfig, EmulatorHTTPServer, SMTPServer


class EmulatorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.log = Path(self.temp.name) / "events.jsonl"
        self.config = EmulatorConfig(log_path=self.log, post_response=b"regex-match")
        self.http = EmulatorHTTPServer(("127.0.0.1", 0), self.config)
        self.http_thread = threading.Thread(target=self.http.serve_forever, daemon=True)
        self.http_thread.start()
        self.smtp = SMTPServer(("127.0.0.1", 0), self.config)
        self.smtp_thread = threading.Thread(target=self.smtp.serve_forever, daemon=True)
        self.smtp_thread.start()

    def tearDown(self):
        self.http.shutdown()
        self.http.server_close()
        self.smtp.shutdown()
        self.smtp.server_close()
        self.temp.cleanup()

    def connection(self):
        return http.client.HTTPConnection("127.0.0.1", self.http.server_address[1], timeout=3)

    def test_health_and_resource_version(self):
        conn = self.connection()
        conn.request("GET", "/healthz")
        response = conn.getresponse()
        self.assertEqual(response.status, 200)
        self.assertEqual(response.read(), b"ok\n")
        conn.request("GET", "/data/resourceversion.txt")
        response = conn.getresponse()
        self.assertEqual(response.status, 200)
        self.assertEqual(response.read(), b"7697274\n")
        conn.close()

    def test_post_is_recorded_and_form_is_exposed_in_log(self):
        conn = self.connection()
        body = b"name=alpha&body=hello+world"
        conn.request("POST", "/POST/", body=body, headers={"Content-Type": "application/x-www-form-urlencoded"})
        response = conn.getresponse()
        self.assertEqual(response.status, 200)
        self.assertEqual(response.read(), b"regex-match")
        conn.close()
        events = [json.loads(line) for line in self.log.read_text().splitlines()]
        self.assertEqual(events[-1]["path"], "/POST/")
        self.assertEqual(events[-1]["form"], {"name": ["alpha"], "body": ["hello world"]})
        self.assertEqual(events[-1]["body_base64"], "bmFtZT1hbHBoYSZib2R5PWhlbGxvK3dvcmxk")

    def test_fixture_serving(self):
        root = Path(self.temp.name) / "fixtures"
        root.mkdir()
        (root / "data" / "PIN").mkdir(parents=True)
        (root / "data" / "PIN" / "0.bmp").write_bytes(b"fixture")
        self.config.fixture_dir = root
        conn = self.connection()
        conn.request("GET", "/data/PIN/0.bmp")
        response = conn.getresponse()
        self.assertEqual(response.status, 200)
        self.assertEqual(response.read(), b"fixture")
        conn.request("GET", "/../events.jsonl")
        response = conn.getresponse()
        self.assertEqual(response.status, 404)
        response.read()
        conn.close()

    def test_smtp_accepts_and_records_message(self):
        with socket.create_connection(("127.0.0.1", self.smtp.server_address[1]), timeout=3) as sock:
            stream = sock.makefile("rwb", buffering=0)
            self.assertTrue(stream.readline().startswith(b"220"))
            stream.write(b"EHLO test\r\n")
            self.assertTrue(stream.readline().startswith(b"250-"))
            self.assertTrue(stream.readline().startswith(b"250 "))
            for command in (b"MAIL FROM:<a@example.test>\r\n", b"RCPT TO:<b@example.test>\r\n"):
                stream.write(command)
                self.assertTrue(stream.readline().startswith(b"250"))
            stream.write(b"DATA\r\n")
            self.assertTrue(stream.readline().startswith(b"354"))
            stream.write(b"Subject: test\r\n\r\nhello\r\n.\r\n")
            self.assertTrue(stream.readline().startswith(b"250"))
            stream.write(b"QUIT\r\n")
            self.assertTrue(stream.readline().startswith(b"221"))
        events = [json.loads(line) for line in self.log.read_text().splitlines()]
        smtp_events = [event for event in events if event["kind"] == "smtp"]
        self.assertEqual(len(smtp_events), 1)
        self.assertIn("Subject: test", smtp_events[0]["message"])


if __name__ == "__main__":
    unittest.main()
