from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from vanillatool_emulator import am_config as C
from vanillatool_emulator.am_workspace import (
    describe_target,
    list_accounts,
    prepare_workspace,
    random_device_name,
    read_logins,
    scan_ncguard_strings,
    validate_device_name,
    write_logins,
    build_default_logins,
)
from vanillatool_emulator.mapper import read_device_slots

REPO_ROOT = Path(__file__).resolve().parents[1]


class DeviceNameTests(unittest.TestCase):
    def test_random_shape(self) -> None:
        name = random_device_name(seed=1234)
        self.assertEqual(len(name), 11)
        self.assertTrue(name.isalpha())

    def test_validation(self) -> None:
        self.assertEqual(validate_device_name("AbCdEfGhIjK"), "AbCdEfGhIjK")
        for bad in ("short", "x" * 12, "AbCdEfGhIj1", ""):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    validate_device_name(bad)


class WorkspaceTests(unittest.TestCase):
    def test_recovery_copies_and_patches(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = prepare_workspace(Path(tmp) / "ws",
                                   settings={"fHide_UDK": "AbCdEfGhIjK"})
            self.assertEqual(len(ws.files), len(C.LOCAL_FILES))
            runtimes = {f.runtime for f in ws.files}
            self.assertIn("udk.bin", runtimes)
            self.assertIn("udk_1.dll", runtimes)
            self.assertIn("udk_2.bin", runtimes)
            self.assertIn("spk.exe", runtimes)
            # Driver copy slots carry the full patched paths.
            self.assertEqual(ws.driver_after,
                             ("\\Device\\AbCdEfGhIjK", "\\DosDevices\\AbCdEfGhIjK"))
            # Pristine payload untouched.
            pristine = (REPO_ROOT / "analysis" / "embedded_files" / "AM"
                         / "VanillaDrv_3.13.sys.dec").read_bytes()
            device, _ = read_device_slots(pristine)
            self.assertFalse(device.startswith("\\Device\\"))
            # Settings + ini staged.
            self.assertTrue((Path(tmp) / "ws" / "settings.json").is_file())
            parser = read_logins(Path(tmp) / "ws" / "logins.ini")
            self.assertIn("Delay", parser.sections())
            for key in C.DELAY_DEFAULTS:
                self.assertIn(key, parser["Delay"])

    def test_hide_rename_honoured(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = prepare_workspace(
                Path(tmp) / "ws",
                settings={"fHide_UDK": "AbCdEfGhIjK", "fHide_LR": "custom.exe"})
            runtimes = {f.runtime for f in ws.files}
            self.assertIn("custom.exe", runtimes)
            self.assertNotIn("lr.exe", runtimes)

    def test_missing_target_reported(self) -> None:
        info = describe_target("/nonexistent/aion.bin")
        self.assertFalse(info["exists"])

    def test_repo_target_audited_read_only(self) -> None:
        target = REPO_ROOT / "game.dll"
        if not target.is_file():
            self.skipTest("game.dll not present")
        info = describe_target(target)
        self.assertTrue(info["exists"])
        self.assertIn("mz_header", info)
        scan = scan_ncguard_strings(target)
        self.assertIn("hits", scan)
        self.assertIn("note", scan)


class LoginsTests(unittest.TestCase):
    def test_account_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "logins.ini"
            parser = build_default_logins()
            parser["Account"]["0"] = "demo"
            parser["Password"]["0"] = "secret"
            parser["Client"]["0"] = "EuroAion"
            write_logins(path, parser)
            rows = list_accounts(read_logins(path))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["Account"], "demo")


if __name__ == "__main__":
    unittest.main()
