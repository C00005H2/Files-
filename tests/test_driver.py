from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from vanillatool_emulator import driver as D
from vanillatool_emulator.local import PayloadStager


REPO_ROOT = Path(__file__).resolve().parents[1]
TEST_NAME = "AbCdEfGhIjK"


def staged_workdir(tmp: str) -> Path:
    workdir = Path(tmp) / "work"
    PayloadStager(REPO_ROOT).stage(workdir, only=("udk.bin", "udk_1.dll", "udk_2.bin"))
    PayloadStager(REPO_ROOT).patch_driver(workdir, TEST_NAME)
    return workdir


class AuditTests(unittest.TestCase):
    def test_audit_is_read_only_and_json_serialisable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workdir = staged_workdir(tmp)
            before = {p.name for p in workdir.iterdir()}
            report = D.audit_os(workdir, TEST_NAME)
            after = {p.name for p in workdir.iterdir()}
            self.assertEqual(before, after)  # nothing created/modified
            json.dumps(report.as_dict())  # must serialise
            names = [c.name for c in report.checks]
            self.assertIn("payloads", names)
            self.assertIn("device-name", names)

    def test_audit_flags_missing_payloads(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = D.audit_os(Path(tmp) / "empty", TEST_NAME)
            payloads = next(c for c in report.checks if c.name == "payloads")
            self.assertEqual(payloads.status, "fail")
            self.assertFalse(report.ok)

    def test_windows_helpers_degrade_off_windows(self) -> None:
        if sys.platform.startswith("win"):
            self.skipTest("non-Windows behaviour")
        self.assertEqual(D._reg_read(None, "k", "v"), (False, None))
        self.assertEqual(D._reg_write_hklm("k", "v", 0)[0], False)
        self.assertEqual(D._sc_query("RTCore64"), (False, "windows-only"))
        self.assertEqual(D._testsigning_state(), (None, "windows-only"))
        self.assertEqual(D.query_dos_devices(TEST_NAME), (False, "windows-only"))


class PrepareTests(unittest.TestCase):
    def test_plan_only_writes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            backup = Path(tmp) / "backup.json"
            report = D.prepare_os(apply=False, backup_path=backup)
            if sys.platform.startswith("win"):
                # Windows plan mode still records the backup of current state.
                self.assertTrue(backup.is_file() or not report.ok)
            else:
                self.assertFalse(backup.exists())
                self.assertTrue(all(c.status == "skip" for c in report.checks
                                    if c.name in ("blocklist", "hvci")))
            json.dumps(report.as_dict())


class LoadTests(unittest.TestCase):
    def test_load_simulated_marks_itself(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workdir = staged_workdir(tmp)
            report = D.load_driver(workdir, providers=[1, None])
            self.assertEqual(report.extra["device"], TEST_NAME)
            if sys.platform.startswith("win"):
                self.assertFalse(report.extra["simulated"])
            else:
                self.assertTrue(report.extra["simulated"])
                self.assertTrue(report.ok)  # sim maps + skips verify cleanly
                self.assertEqual(report.status, "Status: driver mapped..")
            # Every ladder step is recorded with its outcome.
            self.assertTrue(any(c.name.startswith("ladder:") for c in report.checks))

    def test_load_without_payloads_fails_fast(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = D.load_driver(Path(tmp) / "empty")
            self.assertFalse(report.ok)
            self.assertEqual(report.status, "Status: Error 14")

    def test_load_conflict_hint_surfaces_as_warning(self) -> None:
        # Force the simulated conflict path through the real entry point by
        # marking provider 1 unavailable via a patched run_ladder is not
        # possible (no such option), so emulate: single blocked provider can
        # only be observed through MapperRunner — instead assert the report
        # plumbing accepts ladder warnings end to end.
        with tempfile.TemporaryDirectory() as tmp:
            workdir = staged_workdir(tmp)
            with mock.patch.object(D.L.MapperRunner, "run_ladder") as ladder:
                step = mock.Mock()
                step.argv = ["-prv", "1", "-map", "udk_2.bin"]
                step.transcript = "[!] Unable to open vulnerable driver, x"
                step.outcome = "provider-unavailable"
                step.hint = "Status: Make sure MSI Afterburner is closed."
                fake = mock.Mock()
                fake.steps = [step]
                fake.mapped = False
                ladder.return_value = fake
                report = D.load_driver(workdir, providers=[1])
            self.assertFalse(report.ok)
            self.assertIn("Status: Make sure MSI Afterburner is closed.",
                          report.warnings)


class VerifyTests(unittest.TestCase):
    def test_verify_empty_name_fails(self) -> None:
        report = D.verify_loaded("")
        self.assertFalse(report.ok)
        self.assertEqual(report.status, "Status: Error 16")

    def test_verify_slot_name_mismatch_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workdir = staged_workdir(tmp)  # carries TEST_NAME
            report = D.verify_loaded("ZzZzZzZzZzZ", workdir)
            slot = next(c for c in report.checks if c.name == "slot-name")
            self.assertEqual(slot.status, "fail")
            self.assertFalse(report.ok)

    def test_verify_slot_name_match_passes_off_windows(self) -> None:
        if sys.platform.startswith("win"):
            self.skipTest("non-Windows behaviour")
        with tempfile.TemporaryDirectory() as tmp:
            workdir = staged_workdir(tmp)
            report = D.verify_loaded(TEST_NAME, workdir)
            # createfile/dosdevices skip off-Windows; slot-name decides.
            self.assertTrue(report.ok)


class CleanupTests(unittest.TestCase):
    def test_cleanup_removes_staged_loader_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workdir = staged_workdir(tmp)
            report = D.cleanup(workdir)
            self.assertTrue(report.ok)
            self.assertEqual(sorted(report.extra["removed"]),
                             ["udk.bin", "udk_1.dll", "udk_2.bin"])
            self.assertFalse((workdir / "udk_2.bin").exists())
            self.assertTrue(any("reboot" in w for w in report.warnings))


class CliTests(unittest.TestCase):
    def _run(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "vanillatool_emulator.driver", *args],
            capture_output=True, text=True, timeout=60, cwd=REPO_ROOT,
        )

    def test_audit_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc = self._run("audit", "--workdir", str(Path(tmp)),
                             "--device-name", TEST_NAME, "--json")
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["command"], "audit")
            self.assertIn("Status:", payload["status"])

    def test_load_providers_parsing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            staged_workdir(tmp)  # creates tmp/work
            proc = self._run("load", "--workdir", str(Path(tmp) / "work"),
                             "--providers", "1,default", "--json")
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["command"], "load")
            if not sys.platform.startswith("win"):
                self.assertTrue(payload["ok"])

    def test_verify_requires_device_name(self) -> None:
        proc = self._run("verify")
        self.assertNotEqual(proc.returncode, 0)


if __name__ == "__main__":
    unittest.main()
