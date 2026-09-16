from __future__ import annotations

import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from vanillatool_emulator.mapper import (
    DEFAULT_NAME_LENGTH,
    DEVICE_PATH_OFFSET,
    DEVICE_PATH_SIZE,
    DOS_DEVICE_PATH_OFFSET,
    DOS_DEVICE_PATH_SIZE,
    FAILURE_PREFIX_PATTERN,
    PROVIDERS,
    device_name,
    hint_for,
    patch_device_names,
    provider_pattern,
    read_device_slots,
    simulate,
)


def hint_conflict(transcript: str) -> str | None:
    """Apply both of AM's checks the way the client does; return the hint."""
    if not re.search(FAILURE_PREFIX_PATTERN, transcript):
        return None
    for name, hint in AM_HINTS.items():
        if re.search(provider_pattern(name), transcript):
            return hint
    return None


REPO_ROOT = Path(__file__).resolve().parents[1]
BUNDLED_DRIVER = REPO_ROOT / "analysis" / "embedded_files" / "AM" / "VanillaDrv_3.13.sys.dec"

# Account Manager 5.43 constants ($OS[59951..60047]), verbatim.
AM_HINTS = {
    "RTCore64": "Status: Make sure MSI Afterburner is closed.",
    "Gdrv": "Status: Make sure Gigabyte TOOLS is closed.",
    "ATSZIO64": "Status: Make sure ASUSTeK WinFlash utility is closed.",
}

TEST_NAME = "AbCdEfGhIjK"  # 11 chars, same shape as AM's random default


def make_driver() -> bytes:
    """A minimal victim-driver image with AM's patched device slots."""
    data = bytearray(BUNDLED_DRIVER.read_bytes()) if BUNDLED_DRIVER.is_file() else bytearray(13312)
    return patch_device_names(bytes(data), TEST_NAME)


class DriverSlotTests(unittest.TestCase):
    def test_patch_writes_utf16_full_paths(self) -> None:
        data = make_driver()
        device = data[DEVICE_PATH_OFFSET : DEVICE_PATH_OFFSET + DEVICE_PATH_SIZE]
        dos = data[DOS_DEVICE_PATH_OFFSET : DOS_DEVICE_PATH_OFFSET + DOS_DEVICE_PATH_SIZE]
        self.assertEqual(device.decode("utf-16-le"), "\\Device\\" + TEST_NAME)
        self.assertEqual(dos.decode("utf-16-le"), "\\DosDevices\\" + TEST_NAME)

    def test_read_round_trip(self) -> None:
        data = make_driver()
        self.assertEqual(read_device_slots(data), ("\\Device\\" + TEST_NAME, "\\DosDevices\\" + TEST_NAME))
        self.assertEqual(device_name(data), TEST_NAME)

    def test_patch_rejects_other_name_lengths(self) -> None:
        # AM's writer uses fixed 38/46-byte slots; its own default generator
        # produces 11 characters, so any other length would corrupt the image.
        for bad in ("short", "x" * 12):
            with self.subTest(name=bad):
                with self.assertRaises(ValueError):
                    patch_device_names(bytes(13312), bad)
        self.assertEqual(DEFAULT_NAME_LENGTH, 11)
        self.assertEqual(DEVICE_PATH_OFFSET, 8176)
        self.assertEqual(DOS_DEVICE_PATH_OFFSET, 8224)

    @unittest.skipUnless(BUNDLED_DRIVER.is_file(), "bundled driver artifact not present")
    def test_bundled_driver_carries_placeholder_slots(self) -> None:
        data = BUNDLED_DRIVER.read_bytes()
        self.assertEqual(len(data), 13312)
        device, dos = read_device_slots(data)
        # Pristine build: bare random placeholder names of full slot length.
        self.assertEqual(len(device), DEVICE_PATH_SIZE // 2)
        self.assertEqual(len(dos), DOS_DEVICE_PATH_SIZE // 2)
        self.assertFalse(device.startswith("\\Device\\"))


class TranscriptTests(unittest.TestCase):
    def test_success_transcript_matches_no_conflict_regexes(self) -> None:
        for slot in (None, 1, 2, 3):
            argv = ["-map", "udk_2.bin"] + (["-prv", str(slot)] if slot else [])
            with self.subTest(prv=slot):
                run = simulate(argv, driver_bytes=make_driver())
                self.assertEqual(run.exit_code, 0)
                self.assertEqual(run.outcome, "mapped")
                self.assertIsNone(run.conflict_hint())
                # AM only flags a conflict when BOTH its regexes match; the
                # provider banner line alone is normal KDU output, so the
                # decisive assertion is the absence of the failure prefix.
                self.assertFalse(re.search(FAILURE_PREFIX_PATTERN, run.transcript))
                self.assertIsNone(hint_conflict(run.transcript))
                self.assertEqual(run.device_name_value, TEST_NAME)

    def test_provider_conflict_transcript_triggers_client_regexes(self) -> None:
        for slot, provider in PROVIDERS.items():
            with self.subTest(provider=provider.name):
                run = simulate(
                    ["-prv", str(slot), "-map", "udk_2.bin"],
                    unavailable_providers={slot},
                    driver_bytes=make_driver(),
                )
                self.assertEqual(run.exit_code, 1)
                self.assertEqual(run.outcome, "provider-unavailable")
                # Both of AM's StringRegExp checks must fire.
                self.assertTrue(re.search(FAILURE_PREFIX_PATTERN, run.transcript))
                self.assertTrue(re.search(provider_pattern(provider.name), run.transcript))
                # ...and only the matching provider's line is present.
                for other in AM_HINTS:
                    if other != provider.name:
                        self.assertIsNone(re.search(provider_pattern(other), run.transcript))
                self.assertEqual(run.conflict_hint(), AM_HINTS[provider.name])
                self.assertEqual(hint_for(provider.name), AM_HINTS[provider.name])

    def test_missing_input_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run = simulate(["-map", str(Path(tmp) / "nope.bin")])
            self.assertEqual(run.exit_code, 1)
            self.assertIn("[!] Input file cannot be found, abort.", run.transcript)

    def test_usage_without_map(self) -> None:
        run = simulate(["-prv", "1"])
        self.assertEqual(run.exit_code, 2)
        self.assertIn("[?] Usage: kdu [Provider][Command]", run.transcript)

    def test_invalid_provider_falls_back_to_default(self) -> None:
        run = simulate(["-prv", "99", "-map", "udk_2.bin"], driver_bytes=make_driver())
        self.assertEqual(run.exit_code, 0)
        self.assertIn(
            "[!] Invalid provider id 99 specified, default will be used (0)",
            run.transcript,
        )


class CliTests(unittest.TestCase):
    def run_cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "vanillatool_emulator.mapper", *args],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT),
            timeout=30,
        )

    def test_cli_success_and_conflict(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            driver = Path(tmp) / "udk_2.bin"
            driver.write_bytes(make_driver())

            ok = self.run_cli("-prv", "1", "-map", str(driver))
            self.assertEqual(ok.returncode, 0)
            self.assertNotIn("Unable to open vulnerable driver", ok.stdout)

            blocked = self.run_cli("-prv", "2", "-map", str(driver), "--missing", "1,2")
            self.assertEqual(blocked.returncode, 1)
            self.assertIn("Unable to open vulnerable driver, ", blocked.stdout)
            self.assertIn('Provider: "Gigabyte", Name "Gdrv"', blocked.stdout)


if __name__ == "__main__":
    unittest.main()
