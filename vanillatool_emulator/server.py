"""HTTP server for the local Para's VanillaTool service emulator."""

from __future__ import annotations

from dataclasses import dataclass, field
import argparse
import json
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import ssl
import threading
from typing import Any
from urllib.parse import parse_qs, urlsplit

from .protocol import DEFAULT_STATIC_KEY, auth_response_for, parse_auth_form

LOG = logging.getLogger("vanillatool_emulator")


@dataclass
class EmulatorConfig:
    """Runtime policy for the emulated service."""

    version: str = "11.31"
    orythm: str = "1"
    prythm: str = "1"
    response_plaintext: str | None = None
    dynamic_response: str = "OK"
    static_key: bytes | None = None
    log_file: Path | None = None
    request_count: int = 0
    auth_count: int = 0
    logs: list[dict[str, Any]] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def record(self, entry: dict[str, Any]) -> None:
        with self._lock:
            self.request_count += 1
            self.logs.append(entry)
            # Keep the in-memory diagnostic endpoint bounded when the binary is
            # left running for a long time.
            if len(self.logs) > 1000:
                del self.logs[:-1000]
            if self.log_file is not None:
                self.log_file.parent.mkdir(parents=True, exist_ok=True)
                with self.log_file.open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps(entry, sort_keys=True) + "\n")


class EmulatorHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], config: EmulatorConfig):
        super().__init__(address, EmulatorRequestHandler)
        self.config = config


class EmulatorRequestHandler(BaseHTTPRequestHandler):
    """Handle only the known VanillaTool routes; never act as an open proxy."""

    server: EmulatorHTTPServer
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: object) -> None:
        LOG.info("%s - %s", self.address_string(), format % args)

    @property
    def config(self) -> EmulatorConfig:
        return self.server.config

    def _body(self) -> bytes:
        try:
            length = max(0, int(self.headers.get("Content-Length", "0")))
        except ValueError:
            length = 0
        # A request body is not expected to be large.  The cap prevents an
        # accidental upload from consuming unbounded memory.
        return self.rfile.read(min(length, 1024 * 1024))

    def _write(self, status: int, body: bytes | str, content_type: str = "text/plain; charset=utf-8") -> None:
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _record(self, method: str, path: str, body: bytes = b"", **extra: Any) -> None:
        split = urlsplit(path)
        query = parse_qs(split.query, keep_blank_values=True)
        entry: dict[str, Any] = {
            "method": method,
            "path": split.path,
            "query": {key: values[-1] for key, values in query.items()},
            "body_length": len(body),
        }
        entry.update(extra)
        self.config.record(entry)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        split = urlsplit(self.path)
        route = split.path.rstrip("/") or "/"
        self._record("GET", self.path)

        if route == "/Updateless/Version.txt":
            # InetRead accepts a trailing newline; the real file is a text
            # version marker rather than a JSON document.
            self._write(200, self.config.version + "\r\n")
            return
        if route == "/Log/log.php":
            self._write(200, "OK\r\n")
            return
        if route in {"/GET", "/GET/"}:
            self._write(200, self.config.dynamic_response + "\r\n")
            return
        if route in {"/", "/healthz"}:
            payload = {
                "service": "vanillatool-emulator",
                "version": self.config.version,
                "routes": [
                    "/data/auth.php",
                    "/Log/log.php",
                    "/Updateless/Version.txt",
                    "/POST/",
                ],
            }
            if route == "/healthz":
                with self.config._lock:
                    payload.update({"requests": self.config.request_count, "auth_requests": self.config.auth_count})
            self._write(200, json.dumps(payload, sort_keys=True) + "\n", "application/json; charset=utf-8")
            return
        self._write(404, "not found\n")

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        body = self._body()
        split = urlsplit(self.path)
        route = split.path.rstrip("/") or "/"

        if route == "/data/auth.php":
            self._handle_auth(body)
            return
        if route == "/Log/log.php":
            self._record("POST", self.path, body, body_preview=body[:512].decode("utf-8", errors="replace"))
            self._write(200, "OK\r\n")
            return
        if route in {"/POST", "/POST/"}:
            # The extracted dynamic helper has a generic _HTTPPost marker,
            # but the emulator intentionally does not fetch arbitrary URLs.
            # It returns a deterministic fixture instead.
            self._record("POST", self.path, body, dynamic=True)
            self._write(200, self.config.dynamic_response + "\r\n")
            return
        self._record("POST", self.path, body)
        self._write(404, "not found\n")

    def _handle_auth(self, body: bytes) -> None:
        try:
            request = parse_auth_form(body)
            with self.config._lock:
                self.config.auth_count += 1
            marker, identity = auth_response_for(
                request,
                orythm=self.config.orythm,
                prythm=self.config.prythm,
                static_key=self.config.static_key if self.config.static_key is not None else DEFAULT_STATIC_KEY,
                plaintext=self.config.response_plaintext,
            )
            self._record(
                "POST",
                self.path,
                body,
                auth=True,
                version=request.a_v,
                timestamp=request.a_h,
                identity=identity.decode("latin-1", errors="replace") if identity is not None else None,
            )
            self._write(200, f"C:{marker};\r\n")
        except Exception as exc:  # Keep the endpoint HTTP-compatible on bad fixtures.
            LOG.warning("auth fixture failed: %s", exc)
            self._record("POST", self.path, body, auth=True, error=str(exc))
            self._write(400, "invalid auth request\n")


def _read_key(value: str | None) -> bytes | None:
    if not value:
        return None
    value = value.strip()
    if value.startswith("0x"):
        value = value[2:]
    try:
        key = bytes.fromhex(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("--static-key-hex must be hexadecimal") from exc
    if len(key) != 32:
        raise argparse.ArgumentTypeError("--static-key-hex must contain 32 bytes")
    return key


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Local HTTP emulator for Para's VanillaTool -Rework- 11.31")
    parser.add_argument("--bind", default="0.0.0.0", help="address to listen on (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8080, help="HTTP port (default: 8080)")
    parser.add_argument("--version", default="11.31", help="text returned by /Updateless/Version.txt")
    parser.add_argument("--orythm", default="1", help="positive ORythm value in auth responses")
    parser.add_argument("--prythm", default="1", help="positive PRythm value in auth responses")
    parser.add_argument("--response", dest="response_plaintext", help="complete plaintext auth response, overriding ORythm/PRythm")
    parser.add_argument("--dynamic-response", default="OK", help="fixture returned by /POST/ and /GET/")
    parser.add_argument("--static-key-hex", type=_read_key, help="override the recovered 32-byte aN/aC key")
    parser.add_argument("--log-file", type=Path, help="append JSON request diagnostics to this file")
    parser.add_argument("--tls-cert", type=Path, help="PEM certificate; enables TLS when used with --tls-key")
    parser.add_argument("--tls-key", type=Path, help="PEM private key; enables TLS when used with --tls-cert")
    parser.add_argument("-v", "--verbose", action="store_true", help="enable request logging")
    return parser


def serve(args: argparse.Namespace) -> None:
    if bool(args.tls_cert) != bool(args.tls_key):
        raise SystemExit("--tls-cert and --tls-key must be supplied together")
    if not 0 <= args.port <= 65535:
        raise SystemExit("--port must be between 0 and 65535")

    config = EmulatorConfig(
        version=args.version,
        orythm=args.orythm,
        prythm=args.prythm,
        response_plaintext=args.response_plaintext,
        dynamic_response=args.dynamic_response,
        static_key=args.static_key_hex,
        log_file=args.log_file,
    )
    httpd = EmulatorHTTPServer((args.bind, args.port), config)
    if args.tls_cert and args.tls_key:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=args.tls_cert, keyfile=args.tls_key)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    scheme = "https" if args.tls_cert else "http"
    LOG.info("VanillaTool emulator listening at %s://%s:%d", scheme, args.bind, httpd.server_address[1])
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        LOG.info("shutting down")
    finally:
        httpd.server_close()


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING, format="%(asctime)s %(levelname)s %(message)s")
    serve(args)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
