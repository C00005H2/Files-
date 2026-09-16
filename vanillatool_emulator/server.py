"""HTTP server for the local Para's VanillaTool service emulator."""

from __future__ import annotations

from dataclasses import dataclass, field
import argparse
import io
import json
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import ssl
import threading
from typing import Any
from urllib.parse import parse_qs, urlsplit
import zipfile

from .account_manager import (
    account_manager_startup_response_text,
    missing_account_manager_profile_keys,
)
from .offsets import build_offsets_text, load_offsets_file
from .protocol import (
    DEFAULT_STATIC_KEY,
    ProtocolError,
    auth_response_for,
    decrypt_client_field,
    inspect_response_profile,
    parse_auth_form,
    response_text,
)

LOG = logging.getLogger("vanillatool_emulator")


@dataclass
class EmulatorConfig:
    """Runtime policy for the emulated service."""

    version: str = "11.31"
    orythm: str = "1"
    # A608AD0635E enables the six named-region checkboxes only when
    # PRythm > 1; 2 is the smallest non-expired value that makes the full
    # post-auth selection flow usable (the source treats values above 7 as
    # expired).
    prythm: str = "2"
    response_plaintext: str | None = None
    dynamic_response: str = "OK"
    # Offsets.txt body; None means "serve the built-in placeholder fixture".
    offsets_text: str | None = None
    static_key: bytes | None = None
    log_file: Path | None = None
    request_count: int = 0
    auth_count: int = 0
    logs: list[dict[str, Any]] = field(default_factory=list)
    # A23F9000A37 compares this plain-text marker with the local Icons
    # version.ini before it downloads the Google Drive resource archive.  The
    # stock local default is 0.10, so matching it keeps a healthy local
    # resource tree from being forced through the update path.  These fields
    # are appended after the original config fields to preserve positional
    # construction for callers of the initial emulator API.
    resource_version: str = "0.10"
    resource_archive: Path | None = None
    resource_tool: Path | None = None
    # A real client response contains the region/build-specific memory-offset
    # profile in addition to ORythm/PRythm.  Keep it as a file option so a
    # captured profile can be supplied without putting a long payload on a
    # command line.  This field is appended to preserve positional
    # construction for callers of the initial emulator API.
    response_file: Path | None = None
    # Generate a zero-valued Account Manager 5.43 startup profile.  This is a
    # parser/GUI fixture, not a real memory-offset or license profile.
    account_manager_startup: bool = False
    _resource_archive_cache: bytes | None = field(default=None, init=False, repr=False)
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

    def auth_response_text(self) -> str | None:
        """Return the configured plaintext auth payload, if one is supplied.

        The stock fixture intentionally contains only capability flags.  The
        executable's target-memory setup additionally consumes lines such as
        ``Name=...`` and ``%ProfileName=...`` from the decrypted response;
        those values are specific to the exact Aion build and cannot be
        invented safely by the generic emulator.  The explicit Account
        Manager startup mode is different: it supplies zero placeholders for
        the pre-GUI marker-presence check, but never claims to be a usable
        target-memory profile.
        """
        if self.response_plaintext is not None:
            return self.response_plaintext
        if self.response_file is not None:
            return self.response_file.read_text(encoding="utf-8")
        if self.account_manager_startup:
            return account_manager_startup_response_text(self.orythm, self.prythm)
        return None

    def auth_response_diagnostics(self) -> dict[str, object]:
        """Return non-sensitive diagnostics for the configured auth payload."""
        try:
            plaintext = self.auth_response_text()
            if plaintext is None:
                plaintext = response_text(self.orythm, self.prythm)
            diagnostics = inspect_response_profile(plaintext)
            missing = missing_account_manager_profile_keys(plaintext)
            diagnostics["account_manager_profile"] = {
                "status": "complete" if not missing else "missing",
                "missing": missing,
                "bootstrap_fixture": self.account_manager_startup,
            }
            return diagnostics
        except OSError as exc:
            return {
                "status": "error",
                "line_count": 0,
                "offset_key_count": 0,
                "prefix_counts": {},
                "missing_for_inject": ["Name"],
                "missing_profile_key": True,
                "feature_hints": {"inject": "blocked"},
                "account_manager_profile": {
                    "status": "error",
                    "missing": [],
                    "bootstrap_fixture": self.account_manager_startup,
                },
                "warnings": [f"cannot read auth response profile: {exc}"],
            }

    def resource_archive_bytes(self) -> bytes:
        """Return the deterministic archive used by the resource-update path.

        A real installation can point ``resource_archive`` at the vendor
        archive.  The built-in fixture is deliberately small: it is a valid
        ZIP and contains the two paths that A23F9000A37 uses as its completion
        markers.  It avoids making the emulator depend on Google Drive while
        still letting a machine that already has ``7za.exe`` complete the
        same extraction flow.
        """
        with self._lock:
            if self._resource_archive_cache is not None:
                return self._resource_archive_cache
            if self.resource_archive is not None:
                payload = self.resource_archive.read_bytes()
            else:
                stream = io.BytesIO()
                with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                    archive.writestr("Icons/GatherIcons", b"")
                    archive.writestr(
                        "Icons/version.ini",
                        f"[Main]\r\nversion={self.resource_version}\r\n".encode("ascii", errors="replace"),
                    )
                payload = stream.getvalue()
            self._resource_archive_cache = payload
            return payload


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

    def handle(self) -> None:
        """Treat an abandoned TLS socket as a normal client disconnect.

        Browsers and the AutoIt WinHTTP client can close an HTTPS connection
        while the threaded handler is waiting for the next keep-alive request.
        Python otherwise prints a full traceback for the expected
        ``WSAECONNRESET``/``SSLEOFError`` path, obscuring the useful auth
        diagnostics.
        """
        try:
            super().handle()
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError, ssl.SSLZeroReturnError, ssl.SSLEOFError, ssl.SSLSyscallError) as exc:
            LOG.debug("client closed TLS connection before the next request: %s", exc)

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

        if route in {"/Updateless/Version.txt", "/data/Updates/Version.txt"}:
            # InetRead accepts a trailing newline; the real file is a text
            # version marker rather than a JSON document.
            self._write(200, self.config.version + "\r\n")
            return
        if route == "/data/resourceversion.txt":
            # A23F9000A37 calls this helper with mode zero, so it expects the
            # response body itself to be a number-like text value.
            self._write(200, self.config.resource_version + "\r\n")
            return
        if route == "/Log/log.php" or route.startswith("/Upload/Log/"):
            # The Inject button performs a best-effort, synchronous GET to
            # /Log/log.php with ID/name/region query parameters before it
            # starts the local process/memory injection.  Accept the
            # /Upload/Log spelling too because neighboring client builds use
            # that deployment path.  The client does not parse the body, but
            # a fast deterministic 200 prevents an unavailable telemetry host
            # from delaying that UI path.
            self._write(200, "OK\r\n")
            return
        if route == "/Offsets.txt":
            # Fetched by the injected in-game scripts (fastscript.pscp and
            # the per-version bundles) to resolve memory offsets.  The
            # scripts spin in "#DO=60000 ... #UNTIL=%Var[Offset_Base_SubText],>0"
            # until Base_SubText is non-zero, so the body must contain a
            # "[section]" header followed by "Base_SubText=<non-zero>" for
            # the active client (see offsets.py for the mapping).
            body = self.config.offsets_text if self.config.offsets_text is not None else build_offsets_text()
            self._write(200, body, "text/plain; charset=utf-8")
            return
        if route in {"/GET", "/GET/", "/POST", "/POST/"}:
            self._write(200, self.config.dynamic_response + "\r\n")
            return
        if route == "/drive/v3/files/1jZJnBSuFlFFQzJUHQgybJ1DqhkLJXhFk":
            # This is the exact path embedded in A23F9000A37.  It is served as
            # a fixture rather than proxied to Google Drive.
            self._write(200, self.config.resource_archive_bytes(), "application/zip")
            return
        if route == "/data/7za.exe":
            if self.config.resource_tool is not None:
                try:
                    self._write(200, self.config.resource_tool.read_bytes(), "application/vnd.microsoft.portable-executable")
                except OSError as exc:
                    self._record("GET", self.path, error=str(exc), resource_tool=True)
                    self._write(404, "resource tool unavailable\n")
            else:
                # Do not return HTML with status 200: InetGet would save it as
                # 7za.exe and the client's later Run() call would fail less
                # clearly.  A caller needing a complete update supplies the
                # real tool with --resource-tool.
                self._write(404, "resource tool not configured\n")
            return
        if route in {"/", "/healthz"}:
            auth_profile = self.config.auth_response_diagnostics()
            payload = {
                "service": "vanillatool-emulator",
                "version": self.config.version,
                "resource_version": self.config.resource_version,
                "auth_response": auth_profile["status"],
                "auth_profile": auth_profile,
                "routes": [
                    "/data/auth.php",
                    "/data/resourceversion.txt",
                    "/Log/log.php",
                    "/Upload/Log/log.php",
                    "/Offsets.txt",
                    "/Updateless/Version.txt",
                    "/POST/",
                    "/GET/",
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
        if route == "/Log/log.php" or route.startswith("/Upload/Log/"):
            # Do not retain telemetry contents: neighboring client builds can
            # include account-related fields in this best-effort log upload.
            self._record("POST", self.path, body, telemetry=True)
            self._write(200, "OK\r\n")
            return
        if route in {"/POST", "/POST/", "/GET", "/GET/"}:
            # The extracted dynamic helper has generic _HTTPPost and
            # _HTTPGetVar markers.  Both are caller-supplied POST URLs in the
            # client; the emulator intentionally does not fetch arbitrary
            # destinations and returns a deterministic fixture instead.
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
            static_key = self.config.static_key if self.config.static_key is not None else DEFAULT_STATIC_KEY

            # aC is not needed to derive the response key, but it is part of
            # the live client contract.  Decode it here so diagnostics prove
            # that both encrypted request fields use the recovered key.  Keep
            # the endpoint permissive for hand-authored fixtures that omit or
            # intentionally fake hardware values.
            hardware: bytes | None
            try:
                hardware = decrypt_client_field(request.a_c, static_key)
            except ProtocolError:
                hardware = None

            plaintext = self.config.auth_response_text()
            profile_diagnostics = inspect_response_profile(
                plaintext if plaintext is not None else response_text(self.config.orythm, self.config.prythm)
            )
            if profile_diagnostics["status"] != "offset-profile":
                log = LOG.info if self.config.account_manager_startup else LOG.warning
                log(
                    "auth response is %s; target-memory features will not initialize",
                    profile_diagnostics["status"],
                )
            marker, identity = auth_response_for(
                request,
                orythm=self.config.orythm,
                prythm=self.config.prythm,
                static_key=static_key,
                plaintext=plaintext,
            )
            self._record(
                "POST",
                self.path,
                body,
                auth=True,
                version=request.a_v,
                timestamp=request.a_h,
                identity_decrypted=identity is not None,
                hardware_decrypted=hardware is not None,
                auth_profile_status=profile_diagnostics["status"],
                auth_profile_missing=profile_diagnostics["missing_for_inject"],
            )
            self._write(200, f"C:{marker};\r\n")
        except Exception as exc:  # Keep the endpoint HTTP-compatible on bad fixtures.
            LOG.warning("auth fixture failed: %s", exc)
            self._record("POST", self.path, body, auth=True, error=str(exc))
            self._write(400, "invalid auth request\n")


def _read_offsets_file(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return load_offsets_file(Path(value))
    except (OSError, ValueError) as exc:
        raise argparse.ArgumentTypeError(f"cannot load --offsets-file: {exc}") from exc


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
    parser.add_argument("--resource-version", default="0.10", help="text returned by /data/resourceversion.txt")
    parser.add_argument("--resource-archive", type=Path, help="ZIP served for the embedded Google Drive resource URL")
    parser.add_argument("--resource-tool", type=Path, help="7za.exe served by /data/7za.exe for a complete resource install")
    parser.add_argument("--orythm", default="1", help="non-expired ORythm value in auth responses")
    parser.add_argument(
        "--prythm",
        default="2",
        help="PRythm value in auth responses (default 2; values above 1 enable named regions)",
    )
    response_group = parser.add_mutually_exclusive_group()
    response_group.add_argument("--response", dest="response_plaintext", help="complete plaintext auth response, overriding ORythm/PRythm")
    response_group.add_argument("--response-file", type=Path, help="UTF-8 file containing the complete plaintext auth response")
    response_group.add_argument(
        "--account-manager-startup",
        action="store_true",
        help="use zero-valued Account Manager 5.43 pre-GUI markers (parser/GUI fixture only)",
    )
    parser.add_argument("--dynamic-response", default="OK", help="fixture returned by /POST/ and /GET/")
    parser.add_argument("--static-key-hex", type=_read_key, help="override the recovered 32-byte aN/aC key")
    parser.add_argument(
        "--offsets-file",
        type=_read_offsets_file,
        help="serve this file for /Offsets.txt instead of the built-in placeholder fixture",
    )
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
    if args.response_file is not None and not args.response_file.is_file():
        raise SystemExit(
            "--response-file does not exist: "
            f"{args.response_file}\n"
            "This option requires a real decrypted offset profile for the exact Aion build; "
            "the emulator does not generate that file automatically."
        )

    config = EmulatorConfig(
        version=args.version,
        resource_version=args.resource_version,
        resource_archive=args.resource_archive,
        resource_tool=args.resource_tool,
        orythm=args.orythm,
        prythm=args.prythm,
        response_plaintext=args.response_plaintext,
        response_file=args.response_file,
        account_manager_startup=args.account_manager_startup,
        dynamic_response=args.dynamic_response,
        static_key=args.static_key_hex,
        offsets_text=args.offsets_file,
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
