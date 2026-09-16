"""Original-EXE interop: make the *unmodified* Account Manager work.

No custom GUI here — this module is the invisible backend that lets the
original ``Para's Account Manager - ver. 5.43.exe`` run with its own GUI,
fully functional:

* a TLS emulator on port 443 answering the hard-coded
  ``https://subvanillatool.com/data/auth.php`` license call,
* the ``subvanillatool.com -> 127.0.0.1`` hosts redirect,
* self-signed certificate generation (openssl) + trust (certutil) helpers,
* background emulator lifecycle managed through a pidfile,
* launch + monitor of the original EXE with automatic teardown,
* ``check``: end-to-end proof that every integration point answers
  (TCP, TLS handshake, ``/healthz``, and a real encrypted auth round-trip).

The driver half is covered by :mod:`vanillatool_emulator.driver`: the
original EXE drops and maps its own ``udk.bin``/``udk_2.bin`` chain (the
mapper carries its own embedded provider payload, so no extra files are
needed), but the OS must be prepared once — ``driver prepare --apply``
(blocklist/HVCI off) + reboot — before the mapping can succeed.

Typical Windows run (elevated command prompt)::

    python -m vanillatool_emulator.interop setup --target-exe "Para's Account Manager - ver. 5.43.exe" --gen-cert --apply
    python -m vanillatool_emulator.driver prepare --apply
    ... reboot ...
    python -m vanillatool_emulator.interop launch --target-exe "Para's Account Manager - ver. 5.43.exe"

Everything is stdlib-only.  ``--port``/``--no-tls``/``--no-hosts`` exist so
the same code paths are testable on Linux/macOS without touching the real
hosts file or privileged ports.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from . import local as L
from . import protocol as P

DEFAULT_PORT = 443
DEFAULT_BINDCERT = Path("interop-cert.pem")
DEFAULT_BINDKEY = Path("interop-key.pem")
DEFAULT_PIDFILE = Path("interop-emulator.pid.json")
DEFAULT_LOGFILE = Path("interop-emulator.log")
AUTH_DOMAIN = "subvanillatool.com"
OPENSSL_CNF_NOTE = "Git for Windows bundles openssl.exe"


# ---------------------------------------------------------------------------
# Small building blocks
# ---------------------------------------------------------------------------


def openssl_available() -> str | None:
    """Return the openssl executable path, or None."""
    return shutil.which("openssl")


def generate_cert(cert: Path, key: Path, domain: str = AUTH_DOMAIN,
                  days: int = 825) -> tuple[bool, str]:
    """Create a self-signed cert+key with openssl.  ``(ok, detail)``."""
    openssl = openssl_available()
    if openssl is None:
        return False, f"openssl not found ({OPENSSL_CNF_NOTE}); cannot generate"
    if cert.is_file() and key.is_file():
        return True, f"already present: {cert}, {key}"
    cmd = [openssl, "req", "-x509", "-newkey", "rsa:2048",
           "-keyout", str(key), "-out", str(cert),
           "-days", str(days), "-nodes", "-subj", f"/CN={domain}",
           "-addext", f"subjectAltName=DNS:{domain}"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"openssl failed to start: {exc}"
    if proc.returncode != 0 or not (cert.is_file() and key.is_file()):
        err = (proc.stderr or proc.stdout or "").strip().splitlines()
        return False, f"openssl failed: {err[0] if err else 'unknown error'}"
    return True, f"generated {cert} + {key} (CN={domain}, {days}d)"


def trust_cert(cert: Path) -> tuple[bool, str]:
    """Trust ``cert`` in the Windows ROOT store via certutil."""
    if not sys.platform.startswith("win"):
        return False, "windows-only: trust the cert manually on this OS"
    if not L.is_admin():
        return False, "needs Administrator: re-run elevated"
    try:
        proc = subprocess.run(
            ["certutil", "-addstore", "-f", "ROOT", str(cert)],
            capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"certutil failed to start: {exc}"
    if proc.returncode != 0:
        err = ((proc.stderr or proc.stdout) or "").strip().splitlines()
        return False, f"certutil failed: {err[0] if err else 'unknown error'}"
    return True, f"trusted in ROOT store: {cert}"


def emulator_cmd(port: int, use_tls: bool, cert: Path | None, key: Path | None,
                 extra: list[str] | None = None,
                 am_startup: bool = True) -> list[str]:
    cmd = [sys.executable, "-m", "vanillatool_emulator.server",
           "--bind", "127.0.0.1", "--port", str(port), "--version", "5.43"]
    if am_startup:
        cmd.append("--account-manager-startup")
    if use_tls and cert and key:
        cmd += ["--tls-cert", str(cert), "--tls-key", str(key)]
    if extra:
        cmd += extra
    return cmd


def spawn_emulator(cmd: list[str], pidfile: Path, logfile: Path,
                   port: int, use_tls: bool) -> dict[str, Any]:
    """Start the emulator detached; write pidfile; return its record."""
    stop_emulator(pidfile)  # never stack two emulators on one pidfile
    logfile.parent.mkdir(parents=True, exist_ok=True)
    pidfile.parent.mkdir(parents=True, exist_ok=True)
    log_handle = open(logfile, "a", encoding="utf-8")
    popen_kwargs: dict[str, Any] = {"stdout": log_handle, "stderr": log_handle,
                                    "close_fds": True}
    if sys.platform.startswith("win"):
        popen_kwargs["creationflags"] = (getattr(subprocess, "DETACHED_PROCESS", 8)
                                         | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
    else:
        popen_kwargs["start_new_session"] = True
    proc = subprocess.Popen(cmd, **popen_kwargs)
    record = {"pid": proc.pid, "port": port, "tls": use_tls,
              "started": time.time(), "cmd": cmd}
    pidfile.write_text(json.dumps(record, indent=2), encoding="utf-8")
    return record


def emulator_alive(pidfile: Path) -> dict[str, Any] | None:
    """Return the pidfile record if its process still runs, else None."""
    try:
        record = json.loads(pidfile.read_text(encoding="utf-8"))
        pid = int(record.get("pid", 0))
    except (OSError, ValueError):
        return None
    if pid <= 0:
        return None
    if sys.platform.startswith("win"):
        try:
            proc = subprocess.run(["tasklist", "/FI", f"PID eq {pid}"],
                                  capture_output=True, text=True, timeout=15)
            if str(pid) not in (proc.stdout or ""):
                return None
        except (OSError, subprocess.SubprocessError):
            return None
    else:
        try:
            os.kill(pid, 0)
        except OSError:
            return None
    return record


def stop_emulator(pidfile: Path) -> bool:
    """Terminate the pidfile'd emulator.  True if none remains running."""
    record = emulator_alive(pidfile)
    if record is None:
        try:
            pidfile.unlink(missing_ok=True)
        except OSError:
            pass
        return True
    pid = int(record["pid"])
    if sys.platform.startswith("win"):
        subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"],
                       capture_output=True, timeout=30)
    else:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
    deadline = time.time() + 10
    while time.time() < deadline:
        if emulator_alive(pidfile) is None:
            break
        time.sleep(0.25)
    else:
        if not sys.platform.startswith("win"):
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
            time.sleep(0.5)
    try:
        pidfile.unlink(missing_ok=True)
    except OSError:
        pass
    return emulator_alive(pidfile) is None


def _connection(host: str, port: int, use_tls: bool) -> http.client.HTTPConnection:
    if not use_tls:
        return http.client.HTTPConnection(host, port, timeout=8)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return http.client.HTTPSConnection(host, port, timeout=8, context=context)


def wait_for_emulator(port: int, use_tls: bool,
                      timeout: float = 20.0) -> tuple[bool, str]:
    """Poll ``/healthz`` until it answers or the timeout expires."""
    deadline = time.time() + timeout
    last = "no attempt yet"
    while time.time() < deadline:
        try:
            conn = _connection("127.0.0.1", port, use_tls)
            conn.request("GET", "/healthz")
            resp = conn.getresponse()
            body = resp.read().decode("utf-8", "replace")
            conn.close()
            if resp.status == 200:
                return True, body.strip()[:200]
            last = f"HTTP {resp.status}"
        except (OSError, ssl.SSLError) as exc:
            last = f"{type(exc).__name__}: {exc}"
            time.sleep(0.4)
    return False, last


def auth_self_test(port: int, use_tls: bool) -> tuple[bool, str]:
    """Run a real encrypted auth round-trip against the emulator.

    Builds ``aN``/``aC`` exactly like the original EXE (static key + IV),
    posts to ``/data/auth.php``, and decrypts the ``C:<hex>;`` response
    with the dynamic key — the same bytes the original GUI exchanges.
    """
    identity = b"INTEROP-SELFTEST-0001".ljust(24, b"O")[:24]
    timestamp = "12345678"
    try:
        body = ("aN=" + P.encrypt_client_field(identity)
                + "&aU=" + P.CLIENT_IDENTIFIER
                + "&aH=" + timestamp
                + "&aC=" + P.encrypt_client_field(b"INTEROP-CPU:INTEROP-BIOS")
                + "&aV=5.43").encode("ascii")
        conn = _connection("127.0.0.1", port, use_tls)
        conn.request("POST", "/data/auth.php", body,
                     {"Content-Type": "application/x-www-form-urlencoded"})
        resp = conn.getresponse()
        payload = resp.read().decode("ascii", "replace")
        conn.close()
    except (OSError, ssl.SSLError) as exc:
        return False, f"request failed: {exc}"
    if resp.status != 200 or not payload.startswith("C:"):
        return False, f"unexpected response: HTTP {resp.status} {payload[:60]!r}"
    try:
        cipher = P.extract_response_ciphertext(payload)
        plain = P.decrypt_response(cipher, timestamp, identity)
    except P.ProtocolError as exc:
        return False, f"cannot decrypt response: {exc}"
    if b"ORythm=" in plain and b"PRythm=" in plain:
        head = plain.split(b"\n")[0][:60].decode("latin-1")
        return True, f"auth round-trip ok ({head}...)"
    return False, f"response lacks capability flags: {plain[:60]!r}"


# ---------------------------------------------------------------------------
# Reports (same shape as driver.py for consistent --json output)
# ---------------------------------------------------------------------------


def _report(command: str) -> dict[str, Any]:
    return {"command": command, "ok": True, "status": "",
            "checks": [], "warnings": [], "extra": {}}


def _add(report: dict[str, Any], name: str, status: str, detail: str = "",
         remediation: str = "") -> None:
    report["checks"].append({"name": name, "status": status,
                             "detail": detail, "remediation": remediation})
    if status == "fail":
        report["ok"] = False


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def cmd_setup(target_exe: Path | None, cert: Path, key: Path,
              gen_cert: bool, apply: bool, hosts_path: Path | None) -> dict[str, Any]:
    report = _report("setup")
    # 1. Target EXE exists.
    if target_exe is None:
        _add(report, "target", "skip", "no --target-exe given (setup only)")
    elif target_exe.is_file():
        _add(report, "target", "ok",
             f"{target_exe} ({target_exe.stat().st_size} bytes)")
        report["extra"]["target"] = str(target_exe)
    else:
        _add(report, "target", "fail", f"not found: {target_exe}",
             "point --target-exe at the original Account Manager exe")
    # 2. Certificate.
    if cert.is_file() and key.is_file():
        _add(report, "cert", "ok", f"{cert} + {key} present")
    elif gen_cert:
        ok, detail = generate_cert(cert, key)
        _add(report, "cert", "ok" if ok else "fail", detail)
    else:
        _add(report, "cert", "fail", f"missing {cert} / {key}",
             "re-run with --gen-cert (needs openssl) or pass --cert/--key")
    # 3. Trust (Windows ROOT store).
    if not apply:
        _add(report, "trust", "skip", "plan only (re-run with --apply)",
             "certutil -addstore -f ROOT " + str(cert))
    elif not cert.is_file():
        _add(report, "trust", "fail", "no cert to trust")
    else:
        ok, detail = trust_cert(cert)
        _add(report, "trust", "ok" if ok else "fail", detail)
    # 4. Hosts redirect.
    hosts = L.HostsManager(hosts_path)
    if hosts.is_redirected():
        _add(report, "hosts", "ok", f"{AUTH_DOMAIN} already redirected")
    elif not apply:
        _add(report, "hosts", "skip",
             f"plan only, would add: {hosts.apply_redirect(dry_run=True)}")
    elif not L.is_admin():
        _add(report, "hosts", "fail", "needs Administrator",
             "re-run elevated")
    else:
        try:
            line = hosts.apply_redirect()
            _add(report, "hosts", "ok", line)
        except OSError as exc:
            _add(report, "hosts", "fail", str(exc))
    report["extra"]["next"] = (
        "driver prepare --apply, reboot, then: interop launch --target-exe ...")
    report["status"] = ("Status: setup ready — prepare driver, reboot, launch"
                        if report["ok"] else "Status: Error 16")
    return report


def cmd_launch(target_exe: Path, cert: Path, key: Path, port: int,
               use_tls: bool, apply_hosts: bool, hosts_path: Path | None,
               pidfile: Path, logfile: Path, wait: bool,
               extra_emulator_args: list[str],
               am_startup: bool = True) -> dict[str, Any]:
    report = _report("launch")
    if not target_exe.is_file():
        _add(report, "target", "fail", f"not found: {target_exe}")
        report["status"] = "Status: Error 14"
        return report
    _add(report, "target", "ok", str(target_exe))
    if use_tls and not (cert.is_file() and key.is_file()):
        _add(report, "cert", "fail", f"missing {cert} / {key}",
             "run setup --gen-cert first")
        report["status"] = "Status: Error 16"
        return report
    if apply_hosts:
        hosts = L.HostsManager(hosts_path)
        if hosts.is_redirected():
            _add(report, "hosts", "ok", "already redirected")
        elif not L.is_admin():
            _add(report, "hosts", "fail", "needs Administrator for hosts file")
            report["status"] = "Status: Error 16"
            return report
        else:
            try:
                _add(report, "hosts", "ok", hosts.apply_redirect())
            except OSError as exc:
                _add(report, "hosts", "fail", str(exc))
                report["status"] = "Status: Error 16"
                return report
    else:
        _add(report, "hosts", "skip", "left as-is (--apply-hosts not given)")
    # Start the emulator and prove it answers before launching the EXE.
    cmd = emulator_cmd(port, use_tls, cert if use_tls else None,
                       key if use_tls else None, extra_emulator_args,
                       am_startup=am_startup)
    try:
        record = spawn_emulator(cmd, pidfile, logfile, port, use_tls)
    except OSError as exc:
        _add(report, "emulator", "fail", f"cannot spawn: {exc}")
        report["status"] = "Status: Error 21"
        return report
    ok, detail = wait_for_emulator(port, use_tls)
    scheme = "https" if use_tls else "http"
    if not ok:
        stop_emulator(pidfile)
        _add(report, "emulator", "fail",
             f"{scheme}://127.0.0.1:{port} never answered: {detail}",
             f"see {logfile}; port busy or cert unreadable?")
        report["status"] = "Status: Error 21"
        return report
    _add(report, "emulator", "ok",
         f"{scheme}://127.0.0.1:{port} pid={record['pid']}")
    report["extra"]["emulator"] = record
    # Launch the ORIGINAL exe — its own GUI is the interface from here on.
    try:
        proc = subprocess.Popen([str(target_exe)])
    except OSError as exc:
        stop_emulator(pidfile)
        _add(report, "launch", "fail", f"cannot start target: {exc}")
        report["status"] = "Status: Error 14"
        return report
    _add(report, "launch", "ok", f"{target_exe.name} pid={proc.pid}")
    report["extra"]["target_pid"] = proc.pid
    report["status"] = "Status: original EXE running — use its GUI"
    if wait:
        try:
            proc.wait()
        except KeyboardInterrupt:
            pass
        stopped = stop_emulator(pidfile)
        _add(report, "teardown", "ok" if stopped else "fail",
             "emulator stopped" if stopped else "emulator may still run")
        report["status"] = "Status: session ended"
    else:
        report["warnings"].append(
            f"emulator left running (pidfile {pidfile}); stop with: "
            "interop stop")
    return report


def cmd_stop(pidfile: Path) -> dict[str, Any]:
    report = _report("stop")
    if stop_emulator(pidfile):
        _add(report, "emulator", "ok", "stopped (or was not running)")
        report["status"] = "Status: emulator stopped"
    else:
        _add(report, "emulator", "fail", "process would not die",
             f"kill it manually; see {pidfile}")
        report["status"] = "Status: Error 21"
    return report


def cmd_status(pidfile: Path, port: int, use_tls: bool,
               hosts_path: Path | None) -> dict[str, Any]:
    report = _report("status")
    record = emulator_alive(pidfile)
    if record is None:
        _add(report, "emulator", "skip", "not running")
    else:
        _add(report, "emulator", "ok",
             f"pid={record['pid']} port={record.get('port')} tls={record.get('tls')}")
        report["extra"]["emulator"] = record
    hosts = L.HostsManager(hosts_path)
    _add(report, "hosts",
         "ok" if hosts.is_redirected() else "skip",
         f"{AUTH_DOMAIN} redirected" if hosts.is_redirected()
         else f"{AUTH_DOMAIN} not redirected")
    # Port probe (quick, non-fatal).
    sock = socket.socket()
    sock.settimeout(2)
    try:
        reachable = sock.connect_ex(("127.0.0.1", port)) == 0
    except OSError:
        reachable = False
    finally:
        sock.close()
    _add(report, f"port:{port}", "ok" if reachable else "skip",
         "listening" if reachable else "closed")
    report["status"] = ("Status: running" if record else "Status: stopped")
    return report


def cmd_check(port: int, use_tls: bool, target_exe: Path | None,
              device_name: str, require_driver: bool) -> dict[str, Any]:
    """End-to-end proof the original GUI will work.  Read-only."""
    report = _report("check")
    if target_exe is not None:
        if target_exe.is_file():
            _add(report, "target", "ok", str(target_exe))
        else:
            _add(report, "target", "fail", f"not found: {target_exe}")
    # TCP -> TLS -> /healthz -> auth round-trip.
    sock = socket.socket()
    sock.settimeout(3)
    try:
        reachable = sock.connect_ex(("127.0.0.1", port)) == 0
    except OSError:
        reachable = False
    finally:
        sock.close()
    if not reachable:
        _add(report, "tcp", "fail", f"127.0.0.1:{port} closed",
             "start the session first (interop launch)")
        report["status"] = "Status: Error 21"
        return report
    _add(report, "tcp", "ok", f"127.0.0.1:{port} open")
    ok, detail = wait_for_emulator(port, use_tls, timeout=8)
    _add(report, "tls+healthz" if use_tls else "healthz",
         "ok" if ok else "fail", detail)
    if not ok:
        report["status"] = "Status: Error 21"
        return report
    ok, detail = auth_self_test(port, use_tls)
    _add(report, "auth", "ok" if ok else "fail", detail,
         "" if ok else "the original EXE's license call would fail too")
    if not ok:
        report["status"] = "Status: Error 21"
        return report
    # Driver device (informational unless --require-driver).
    if device_name:
        runner = L.MapperRunner(Path.cwd())
        probe = runner.probe_device(device_name)
        if probe is None:
            _add(report, "driver", "skip", "probe is Windows-only")
        elif probe:
            _add(report, "driver", "ok", f"\\\\.\\{device_name} opens")
        elif require_driver:
            _add(report, "driver", "fail", f"\\\\.\\{device_name} absent",
                 "run driver load, or launch the EXE (it maps on demand)")
        else:
            _add(report, "driver", "warn", f"\\\\.\\{device_name} absent "
                 "(the EXE maps it on demand after driver prepare + reboot)")
    report["status"] = ("Status: original GUI will work"
                        if report["ok"] else "Status: Error 16")
    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Original-EXE interop: TLS emulator + hosts + cert + "
                    "launch/monitor for the unmodified Account Manager 5.43")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("setup", help="cert + trust + hosts (plan unless --apply)")
    p.add_argument("--target-exe", type=Path, default=None)
    p.add_argument("--cert", type=Path, default=DEFAULT_BINDCERT)
    p.add_argument("--key", type=Path, default=DEFAULT_BINDKEY)
    p.add_argument("--gen-cert", action="store_true")
    p.add_argument("--apply", action="store_true",
                   help="actually trust the cert + edit hosts (needs admin)")
    p.add_argument("--hosts-path", type=Path, default=None)
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("launch", help="start TLS emulator + launch original EXE")
    p.add_argument("--target-exe", type=Path, required=True)
    p.add_argument("--cert", type=Path, default=DEFAULT_BINDCERT)
    p.add_argument("--key", type=Path, default=DEFAULT_BINDKEY)
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument("--no-tls", action="store_true", help="plain HTTP (lab only)")
    p.add_argument("--apply-hosts", action="store_true")
    p.add_argument("--hosts-path", type=Path, default=None)
    p.add_argument("--pidfile", type=Path, default=DEFAULT_PIDFILE)
    p.add_argument("--logfile", type=Path, default=DEFAULT_LOGFILE)
    p.add_argument("--no-wait", action="store_true",
                   help="return after launch; emulator keeps running")
    p.add_argument("--orythm", default="1")
    p.add_argument("--prythm", default="2")
    p.add_argument("--no-am-startup", action="store_true")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("stop", help="stop the background emulator")
    p.add_argument("--pidfile", type=Path, default=DEFAULT_PIDFILE)
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("status", help="emulator/hosts/port status (read-only)")
    p.add_argument("--pidfile", type=Path, default=DEFAULT_PIDFILE)
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument("--hosts-path", type=Path, default=None)
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("check", help="end-to-end proof the original GUI will work")
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument("--no-tls", action="store_true")
    p.add_argument("--target-exe", type=Path, default=None)
    p.add_argument("--device-name", default="")
    p.add_argument("--require-driver", action="store_true")
    p.add_argument("--json", action="store_true")
    return parser


def _print(report: dict[str, Any], as_json: bool) -> None:
    if as_json:
        print(json.dumps(report, indent=2))
        return
    print(report["status"])
    for check in report["checks"]:
        mark = {"ok": "OK  ", "fail": "FAIL", "warn": "WARN", "skip": "SKIP"}[check["status"]]
        print(f"[{mark}] {check['name']}: {check['detail']}")
        if check["remediation"]:
            print(f"       -> {check['remediation']}")
    for warning in report.get("warnings", []):
        print(f"warning: {warning}")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "setup":
        report = cmd_setup(args.target_exe, args.cert, args.key,
                           args.gen_cert, args.apply, args.hosts_path)
    elif args.command == "launch":
        extra = ["--orythm", args.orythm, "--prythm", args.prythm]
        report = cmd_launch(args.target_exe, args.cert, args.key,
                            args.port, not args.no_tls, args.apply_hosts,
                            args.hosts_path, args.pidfile, args.logfile,
                            not args.no_wait, extra,
                            am_startup=not args.no_am_startup)
    elif args.command == "stop":
        report = cmd_stop(args.pidfile)
    elif args.command == "status":
        report = cmd_status(args.pidfile, args.port, True, args.hosts_path)
    elif args.command == "check":
        report = cmd_check(args.port, not args.no_tls, args.target_exe,
                           args.device_name, args.require_driver)
    else:  # pragma: no cover - argparse enforces choices
        raise SystemExit(f"unknown command {args.command}")
    _print(report, args.json)
    return 0 if report["ok"] else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
