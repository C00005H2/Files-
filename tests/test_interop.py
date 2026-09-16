from __future__ import annotations

import json
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from vanillatool_emulator import interop as I


REPO_ROOT = Path(__file__).resolve().parents[1]


def free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class CommandBuilderTests(unittest.TestCase):
    def test_emulator_cmd_tls_and_startup_flags(self) -> None:
        cmd = I.emulator_cmd(443, True, Path("c.pem"), Path("k.pem"))
        self.assertIn("--tls-cert", cmd)
        self.assertIn("--account-manager-startup", cmd)
        plain = I.emulator_cmd(8080, False, None, None, am_startup=False)
        self.assertNotIn("--tls-cert", plain)
        self.assertNotIn("--account-manager-startup", plain)
        self.assertIn("vanillatool_emulator.server", plain)


class CertTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("openssl"), "openssl not installed")
    def test_generate_cert_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cert, key = Path(tmp) / "c.pem", Path(tmp) / "k.pem"
            ok, detail = I.generate_cert(cert, key)
            self.assertTrue(ok, detail)
            self.assertTrue(cert.is_file() and key.is_file())
            ok2, detail2 = I.generate_cert(cert, key)
            self.assertTrue(ok2)
            self.assertIn("already present", detail2)

    def test_generate_cert_without_openssl_fails_cleanly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(I, "openssl_available", return_value=None):
                ok, detail = I.generate_cert(Path(tmp) / "c.pem", Path(tmp) / "k.pem")
            self.assertFalse(ok)
            self.assertIn("openssl", detail)

    @unittest.skipIf(sys.platform.startswith("win"), "non-Windows behaviour")
    def test_trust_cert_is_windows_only(self) -> None:
        ok, detail = I.trust_cert(Path("whatever.pem"))
        self.assertFalse(ok)
        self.assertIn("windows-only", detail)


class LifecycleTests(unittest.TestCase):
    def test_spawn_wait_stop(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            port = free_port()
            pidfile, logfile = Path(tmp) / "emu.pid", Path(tmp) / "emu.log"
            try:
                record = I.spawn_emulator(
                    I.emulator_cmd(port, False, None, None), pidfile, logfile,
                    port, False)
                self.assertGreater(record["pid"], 0)
                ok, _detail = I.wait_for_emulator(port, False, timeout=15)
                self.assertTrue(ok, _detail)
                self.assertIsNotNone(I.emulator_alive(pidfile))
            finally:
                self.assertTrue(I.stop_emulator(pidfile))
            self.assertIsNone(I.emulator_alive(pidfile))

    def test_stop_without_pidfile_is_ok(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertTrue(I.stop_emulator(Path(tmp) / "nope.pid"))


class LaunchTests(unittest.TestCase):
    def _dummy_target(self, tmp: str) -> Path:
        # A "target exe" that exits immediately (proves launch+monitor+teardown).
        target = Path(tmp) / ("dummy-target.bat" if sys.platform.startswith("win") else "dummy-target")
        if sys.platform.startswith("win"):
            target.write_text("@echo off\r\nexit /b 0\r\n", encoding="ascii")
        else:
            target.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
            target.chmod(target.stat().st_mode | stat.S_IEXEC)
        return target

    def test_launch_dummy_target_end_to_end(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            port = free_port()
            pidfile, logfile = Path(tmp) / "emu.pid", Path(tmp) / "emu.log"
            try:
                report = I.cmd_launch(
                    self._dummy_target(tmp), Path("c.pem"), Path("k.pem"),
                    port, False, False, None, pidfile, logfile, True, [])
            finally:
                I.stop_emulator(pidfile)
            self.assertTrue(report["ok"], report)
            self.assertEqual(report["status"], "Status: session ended")
            self.assertIsNone(I.emulator_alive(pidfile))  # teardown ran

    def test_launch_missing_target_leaves_nothing_running(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            port = free_port()
            pidfile = Path(tmp) / "emu.pid"
            report = I.cmd_launch(
                Path(tmp) / "nope.exe", Path("c.pem"), Path("k.pem"),
                port, False, False, None, pidfile, Path(tmp) / "emu.log",
                True, [])
            self.assertFalse(report["ok"])
            self.assertEqual(report["status"], "Status: Error 14")
            self.assertIsNone(I.emulator_alive(pidfile))


class CheckTests(unittest.TestCase):
    def test_check_passes_against_live_emulator(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            port = free_port()
            pidfile, logfile = Path(tmp) / "emu.pid", Path(tmp) / "emu.log"
            try:
                I.spawn_emulator(I.emulator_cmd(port, False, None, None),
                                 pidfile, logfile, port, False)
                self.assertTrue(I.wait_for_emulator(port, False, timeout=15)[0])
                report = I.cmd_check(port, False, None, "", False)
            finally:
                I.stop_emulator(pidfile)
            self.assertTrue(report["ok"], report)
            auth = next(c for c in report["checks"] if c["name"] == "auth")
            self.assertEqual(auth["status"], "ok")

    def test_check_closed_port_fails_fast(self) -> None:
        report = I.cmd_check(free_port(), False, None, "", False)
        self.assertFalse(report["ok"])
        self.assertEqual(report["status"], "Status: Error 21")

    @unittest.skipUnless(shutil.which("openssl"), "openssl not installed")
    def test_tls_auth_round_trip_proves_original_exe_path(self) -> None:
        # The exact bytes the unmodified EXE exchanges: TLS + encrypted
        # aN/aC POST + dynamic-key C:<hex>; response with ORythm/PRythm.
        with tempfile.TemporaryDirectory() as tmp:
            cert, key = Path(tmp) / "c.pem", Path(tmp) / "k.pem"
            self.assertTrue(I.generate_cert(cert, key)[0])
            port = free_port()
            pidfile, logfile = Path(tmp) / "emu.pid", Path(tmp) / "emu.log"
            try:
                I.spawn_emulator(I.emulator_cmd(port, True, cert, key),
                                 pidfile, logfile, port, True)
                self.assertTrue(I.wait_for_emulator(port, True, timeout=15)[0])
                ok, detail = I.auth_self_test(port, True)
                self.assertTrue(ok, detail)
                report = I.cmd_check(port, True, None, "", False)
                self.assertTrue(report["ok"], report)
                self.assertEqual(report["status"], "Status: original GUI will work")
            finally:
                I.stop_emulator(pidfile)


class SetupTests(unittest.TestCase):
    def test_setup_plan_touches_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            hosts = Path(tmp) / "hosts"
            hosts.write_text("127.0.0.1 localhost\n", encoding="utf-8")
            target = Path(tmp) / "am.exe"
            target.write_bytes(b"MZ-fake")
            report = I.cmd_setup(target, Path(tmp) / "c.pem", Path(tmp) / "k.pem",
                                 gen_cert=False, apply=False, hosts_path=hosts)
            self.assertEqual(hosts.read_text(encoding="utf-8"),
                             "127.0.0.1 localhost\n")
            names = {c["name"]: c["status"] for c in report["checks"]}
            self.assertEqual(names["target"], "ok")
            self.assertEqual(names["cert"], "fail")  # missing, no --gen-cert
            self.assertEqual(names["hosts"], "skip")  # plan only
            json.dumps(report)  # serialisable


class CliTests(unittest.TestCase):
    def test_status_and_stop_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pidfile = str(Path(tmp) / "emu.pid")
            proc = subprocess.run(
                [sys.executable, "-m", "vanillatool_emulator.interop",
                 "status", "--pidfile", pidfile, "--json"],
                capture_output=True, text=True, timeout=60, cwd=REPO_ROOT)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["command"], "status")


if __name__ == "__main__":
    unittest.main()
