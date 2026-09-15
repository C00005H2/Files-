#!/usr/bin/env python3
"""Offline HTTP/TCP emulator for the network surfaces in VanillaTool.

The emulator never makes outbound requests.  It is intended for controlled
analysis of the recovered executable and for replaying captured responses.
"""
from __future__ import annotations

import argparse
import base64
import json
import mimetypes
import os
import secrets
import socketserver
import sys
import threading
import time
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import parse_qs, urlsplit


DEFAULT_AUTH_RESPONSE = "ORythm=0;PRythm=0"
DEFAULT_CHAT_HTML = """<!doctype html>
<meta charset="utf-8">
<title>VanillaTool emulator</title>
<h1>VanillaTool network emulator</h1>
<p>This is an offline test endpoint. No request is forwarded to the Internet.</p>
"""


@dataclass
class EmulatorConfig:
    fixture_dir: Path | None = None
    resource_version: str = "7697274\n"
    auth_response: bytes = DEFAULT_AUTH_RESPONSE.encode()
    post_response: bytes = b""
    get_response: bytes = b""
    captcha_solution: str = "test-solution"
    log_path: Path | None = None
    log_lock: threading.Lock = field(default_factory=threading.Lock)
    captcha_results: dict[str, str] = field(default_factory=dict)

    def log(self, event: dict[str, Any]) -> None:
        """Append a JSON event without putting request bodies in normal stdout."""
        if self.log_path is None:
            return
        event = {"time": time.time(), **event}
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_lock:
            with self.log_path.open("a", encoding="utf-8") as stream:
                json.dump(event, stream, ensure_ascii=False)
                stream.write("\n")


class EmulatorHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], config: EmulatorConfig):
        super().__init__(address, EmulatorRequestHandler)
        self.config = config


class EmulatorRequestHandler(BaseHTTPRequestHandler):
    server: EmulatorHTTPServer
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: object) -> None:
        # Request logging is structured and opt-in; do not duplicate bodies in stderr.
        return

    @property
    def config(self) -> EmulatorConfig:
        return self.server.config

    def _request_event(self, body: bytes = b"") -> dict[str, Any]:
        split = urlsplit(self.path)
        headers = {key: value for key, value in self.headers.items()}
        event: dict[str, Any] = {
            "kind": "http",
            "client": self.client_address[0],
            "method": self.command,
            "path": split.path,
            "query": split.query,
            "headers": headers,
            "body_base64": base64.b64encode(body).decode("ascii"),
        }
        content_type = self.headers.get_content_type()
        if content_type == "application/x-www-form-urlencoded":
            event["form"] = {
                key: values for key, values in parse_qs(body.decode("utf-8", "replace"), keep_blank_values=True).items()
            }
        return event

    def _read_body(self) -> bytes:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        # Keep the analysis service bounded even if a malformed client claims a huge body.
        if length < 0 or length > 32 * 1024 * 1024:
            self.send_error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
            return b""
        return self.rfile.read(length)

    def _send_bytes(self, body: bytes, status: int = 200, content_type: str = "text/plain; charset=utf-8") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _fixture(self, path: str) -> bytes | None:
        root = self.config.fixture_dir
        if root is None:
            return None
        # URL paths are POSIX paths even on Windows.  Reject traversal and symlink escapes.
        relative = PurePosixPath(path.lstrip("/"))
        if ".." in relative.parts:
            return None
        candidate = (root / Path(*relative.parts)).resolve()
        try:
            candidate.relative_to(root.resolve())
        except ValueError:
            return None
        if not candidate.is_file():
            return None
        return candidate.read_bytes()

    def _get(self) -> None:
        split = urlsplit(self.path)
        path = split.path
        if path == "/healthz":
            self._send_bytes(b"ok\n")
            return
        if path == "/data/chat.html":
            self._send_bytes(DEFAULT_CHAT_HTML.encode(), content_type="text/html; charset=utf-8")
            return
        if path == "/data/resourceversion.txt":
            self._send_bytes(self.config.resource_version.encode())
            return
        if path in {"/data/auth.php", "/auth.php"}:
            self._send_bytes(self.config.auth_response)
            return
        if path == "/res.php":
            query = parse_qs(split.query, keep_blank_values=True)
            captcha_id = query.get("id", [""])[0]
            solution = self.config.captcha_results.get(captcha_id, self.config.captcha_solution)
            self._send_bytes(f"OK|{solution}".encode())
            return
        fixture = self._fixture(path)
        if fixture is not None:
            self._send_bytes(fixture, content_type=mimetypes.guess_type(path)[0] or "application/octet-stream")
            return
        self._send_bytes(b"not found\n", status=HTTPStatus.NOT_FOUND)

    def _post(self) -> None:
        body = self._read_body()
        self.config.log(self._request_event(body))
        split = urlsplit(self.path)
        path = split.path
        if path == "/healthz":
            self._send_bytes(b"ok\n")
            return
        if path in {"/in.php", "/2captcha/in.php"}:
            # 2captcha-compatible deterministic response for offline testing.
            captcha_id = secrets.token_hex(4)
            self.config.captcha_results[captcha_id] = self.config.captcha_solution
            self._send_bytes(f"OK|{captcha_id}".encode())
            return
        if path in {"/POST/", "/POST", "/post/"}:
            self._send_bytes(self.config.post_response)
            return
        if path in {"/data/auth.php", "/auth.php"}:
            self._send_bytes(self.config.auth_response)
            return
        self._send_bytes(b"not found\n", status=HTTPStatus.NOT_FOUND)

    def do_GET(self) -> None:  # noqa: N802 (stdlib API)
        self.config.log(self._request_event())
        self._get()

    def do_POST(self) -> None:  # noqa: N802 (stdlib API)
        self._post()


class SMTPHandler(socketserver.StreamRequestHandler):
    server: "SMTPServer"

    def _send(self, line: str) -> None:
        self.wfile.write((line + "\r\n").encode("ascii"))
        self.wfile.flush()

    def handle(self) -> None:
        config = self.server.config
        peer = f"{self.client_address[0]}:{self.client_address[1]}"
        self._send("220 vanilla-emulator ESMTP ready")
        message: list[str] = []
        in_data = False
        while True:
            raw = self.rfile.readline(1024 * 1024)
            if not raw:
                break
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            upper = line.upper()
            if in_data:
                if line == ".":
                    in_data = False
                    self._send("250 2.0.0 queued (offline emulator)")
                    config.log({"kind": "smtp", "peer": peer, "message": "\n".join(message)})
                    message.clear()
                elif line.startswith(".."):
                    message.append(line[1:])
                else:
                    message.append(line)
                continue
            if upper.startswith(("EHLO", "HELO")):
                self._send("250-vanilla-emulator")
                self._send("250 SIZE 33554432")
            elif upper.startswith("MAIL FROM:") or upper.startswith("RCPT TO:"):
                self._send("250 2.1.0 accepted")
            elif upper == "DATA":
                in_data = True
                self._send("354 End data with <CR><LF>.<CR><LF>")
            elif upper.startswith("RSET"):
                message.clear()
                self._send("250 2.0.0 reset")
            elif upper.startswith("QUIT"):
                self._send("221 2.0.0 bye")
                break
            else:
                # SMTP clients sometimes issue extensions we do not need to model.
                self._send("250 2.0.0 accepted")


class SMTPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address: tuple[str, int], config: EmulatorConfig):
        super().__init__(address, SMTPHandler)
        self.config = config


def _read_response(value: str | None, path: str | None) -> bytes:
    if value is not None and path is not None:
        raise ValueError("choose one of a literal response or a response file")
    if path is not None:
        return Path(path).read_bytes()
    return (value or "").encode("utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="127.0.0.1", help="HTTP bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="HTTP port (default: 8080)")
    parser.add_argument("--fixture-dir", type=Path, help="serve existing files below this directory")
    parser.add_argument("--resource-version", default="7697274\\n", help="resourceversion.txt body")
    parser.add_argument("--auth-response", default=DEFAULT_AUTH_RESPONSE, help="offline auth.php response")
    parser.add_argument("--auth-response-file", type=Path)
    parser.add_argument("--post-response", default="", help="response body for /POST/")
    parser.add_argument("--post-response-file", type=Path)
    parser.add_argument("--captcha-solution", default="test-solution")
    parser.add_argument("--log", type=Path, help="JSONL request log; no log file is written by default")
    parser.add_argument("--smtp-port", type=int, help="also listen as an offline SMTP server")
    parser.add_argument("--smtp-bind", help="SMTP bind address (defaults to --bind)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        auth = _read_response(args.auth_response, str(args.auth_response_file) if args.auth_response_file else None)
        post = _read_response(args.post_response, str(args.post_response_file) if args.post_response_file else None)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    config = EmulatorConfig(
        fixture_dir=args.fixture_dir.resolve() if args.fixture_dir else None,
        resource_version=args.resource_version.encode().decode("unicode_escape"),
        auth_response=auth,
        post_response=post,
        captcha_solution=args.captcha_solution,
        log_path=args.log,
    )
    http = EmulatorHTTPServer((args.bind, args.port), config)
    threads: list[threading.Thread] = []
    smtp: SMTPServer | None = None
    if args.smtp_port is not None:
        smtp = SMTPServer((args.smtp_bind or args.bind, args.smtp_port), config)
        thread = threading.Thread(target=smtp.serve_forever, name="smtp", daemon=True)
        thread.start()
        threads.append(thread)
        print(f"SMTP emulator listening on {args.smtp_bind or args.bind}:{smtp.server_address[1]}", flush=True)

    print(f"HTTP emulator listening on {args.bind}:{http.server_address[1]}", flush=True)
    try:
        http.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        http.shutdown()
        http.server_close()
        if smtp is not None:
            smtp.shutdown()
            smtp.server_close()
        for thread in threads:
            thread.join(timeout=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
