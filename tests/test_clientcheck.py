from __future__ import annotations

import json
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from vanillatool_emulator import clientcheck as C


REPO_ROOT = Path(__file__).resolve().parents[1]

# Tiny test RVAs (fake binaries, not the real 0x863F8/0x21A2DB).
TEST_RVAS = (0x1050, 0x10A0)
AMD64 = 0x8664
I386 = 0x14C


def make_fake_pe(path: Path, slot_rva: int, slot_content: bytes,
                 machine: int = AMD64, section_name: bytes = b".rdata") -> None:
    """Minimal PE: one section (vaddr 0x1000, raw at 0x200)."""
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    coff = struct.pack("<HHIIIHH", machine, 1, 0x5A5A5A5A, 0, 0, 0xF0, 0x22)
    opt = bytearray(0xF0)
    struct.pack_into("<H", opt, 0, 0x20B)
    section = struct.pack("<8sIIIIIIHHI", section_name[:8].ljust(8, b"\x00"),
                          0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x40000040)
    image = bytearray(0x400)
    image[0x00:0x40] = dos
    image[0x40:0x44] = b"PE\x00\x00"
    image[0x44:0x44 + 20] = coff
    image[0x58:0x58 + 0xF0] = opt
    image[0x148:0x148 + 40] = section
    raw = 0x200 + (slot_rva - 0x1000)
    image[raw:raw + len(slot_content)] = slot_content
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(bytes(image))


def make_fake_client(root: Path, aion_slot: bytes = b"NCGuard.dll\x00",
                     cry_slot: bytes = b"bin64\\NCGuard.dll\x00",
                     machine: int = AMD64) -> Path:
    make_fake_pe(root / "bin64" / "aion.bin", TEST_RVAS[0], aion_slot, machine)
    make_fake_pe(root / "bin64" / "CrySystem.dll", TEST_RVAS[1], cry_slot, machine)
    return root


def verdict(report: dict) -> dict[str, str]:
    return {c["name"]: c["status"] for c in report["checks"]}


class PeReaderTests(unittest.TestCase):
    def test_rva_conversion_and_slot_read(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "aion.bin"
            make_fake_pe(path, TEST_RVAS[0], b"NCGuard.dll\x00" + b"A" * 100)
            pe = C.parse_pe(path)
            self.assertEqual(pe["machine"], AMD64)
            self.assertEqual(C.rva_to_raw(pe["sections"], TEST_RVAS[0]), 0x250)
            slot = C.read_slot(path, TEST_RVAS[0])
            self.assertEqual(slot["via"], "rva")
            self.assertEqual(slot["text"], "NCGuard.dll")
            status, _detail = C.classify_slot(slot)
            self.assertEqual(status, "ok")

    def test_garbage_file_raises_pe_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "aion.bin"
            path.write_bytes(b"not a pe image" * 10)
            with self.assertRaises(C.PEError):
                C.parse_pe(path)


class CheckClientTests(unittest.TestCase):
    def test_matching_client_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = C.check_client(make_fake_client(Path(tmp)),
                                    slot_rvas=TEST_RVAS)
            self.assertTrue(report["ok"], report)
            self.assertEqual(report["status"],
                             "Status: client matches — patch will land")
            names = verdict(report)
            self.assertEqual(names["slot:aion.bin"], "ok")
            self.assertEqual(names["slot:CrySystem.dll"], "ok")
            self.assertEqual(report["extra"]["bypass_dll"], "Game.dll")
            self.assertEqual(report["extra"]["effects_flag"],
                             "EuroAion_AnimationEffects")
            json.dumps(report)  # serialisable

    def test_binary_slot_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = make_fake_client(Path(tmp),
                                    aion_slot=bytes(range(1, 100)))
            report = C.check_client(root, slot_rvas=TEST_RVAS)
            self.assertFalse(report["ok"])
            self.assertEqual(report["status"], "Status: Error 16")
            self.assertEqual(verdict(report)["slot:aion.bin"], "fail")

    def test_unmapped_rva_is_inconclusive_not_fail(self) -> None:
        # RVA outside the section table (packed binary / stub): the static
        # read proves nothing either way -> warn pointing at --live.
        with tempfile.TemporaryDirectory() as tmp:
            root = make_fake_client(Path(tmp))
            report = C.check_client(root, slot_rvas=(0x300, 0x310))
            names = verdict(report)
            self.assertEqual(names["slot:aion.bin"], "warn")
            slot = next(c for c in report["checks"]
                        if c["name"] == "slot:aion.bin")
            self.assertIn("inconclusive", slot["detail"])
            self.assertIn("--live", slot["remediation"])
            self.assertTrue(report["ok"])  # warns don't fail the run
            self.assertEqual(report["status"],
                             "Status: client uncertain — review warnings")

    def test_packer_sections_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make_fake_pe(root / "bin64" / "aion.bin", TEST_RVAS[0],
                         b"NCGuard.dll\x00", section_name=b".themida")
            make_fake_pe(root / "bin64" / "CrySystem.dll", TEST_RVAS[1],
                         b"NCGuard.dll\x00")
            report = C.check_client(root, slot_rvas=TEST_RVAS)
            self.assertEqual(verdict(report)["packed?"], "warn")
            diag = report["extra"]["diagnostics"]["aion.bin"]
            self.assertEqual(diag["packer_sections"], [".themida"])

    def test_scan_finds_module_strings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = make_fake_client(Path(tmp))
            hits = C.scan_bytes(root / "bin64" / "aion.bin")
            self.assertEqual(hits["NCGuard.dll"], [0x250])
            self.assertEqual(hits["Game.dll"], [])

    def test_entropy_basics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            flat = Path(tmp) / "flat.bin"
            flat.write_bytes(b"\x00" * 4096)
            self.assertEqual(C.image_entropy(flat), 0.0)
            self.assertEqual(C.image_entropy(Path(tmp) / "nope.bin"), -1.0)

    def test_missing_files_fail_fast(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = C.check_client(Path(tmp))
            self.assertFalse(report["ok"])
            self.assertEqual(report["status"], "Status: Error 14")

    def test_32bit_client_warns(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = C.check_client(make_fake_client(Path(tmp), machine=I386),
                                    slot_rvas=TEST_RVAS)
            names = verdict(report)
            self.assertEqual(names["arch"], "warn")
            self.assertEqual(report["status"],
                             "Status: client uncertain — review warnings")

    def test_server_bypass_table(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = make_fake_client(Path(tmp))
            america = C.check_client(root, server="Aion America",
                                     slot_rvas=TEST_RVAS)
            self.assertEqual(america["extra"]["bypass_dll"], "NCGuard.dll")
            retail = C.check_client(root, server="Aion EU", slot_rvas=TEST_RVAS)
            self.assertEqual(verdict(retail)["server-dll"], "warn")
            self.assertIn("assumed", retail["extra"]["bypass_dll"])


class LiveModeTests(unittest.TestCase):
    @unittest.skipIf(sys.platform.startswith("win"), "non-Windows behaviour")
    def test_live_is_windows_only_off_windows(self) -> None:
        live = C.live_read_slots("definitely-not-running-12345.exe")
        self.assertFalse(live["supported"])
        report = C.check_client_live("definitely-not-running-12345.exe")
        self.assertFalse(report["ok"])
        self.assertIn("windows-only", report["checks"][0]["detail"].lower())
        json.dumps(report)

    @unittest.skipUnless(sys.platform.startswith("win"), "Windows-only")
    def test_live_missing_process_fails_cleanly(self) -> None:
        report = C.check_client_live("definitely-not-running-12345.exe")
        self.assertFalse(report["ok"])
        self.assertEqual(report["checks"][0]["name"], "process")


class CliTests(unittest.TestCase):
    def test_cli_json_matches(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = make_fake_client(Path(tmp))
            # CLI uses the real RVAs, so the tiny fake will fail closed —
            # the point here is the CLI plumbing + JSON shape.
            proc = subprocess.run(
                [sys.executable, "-m", "vanillatool_emulator.clientcheck",
                 "--game-dir", str(root), "--server", "EuroAion", "--json"],
                capture_output=True, text=True, timeout=60, cwd=REPO_ROOT)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["command"], "clientcheck")
            self.assertFalse(payload["ok"])  # tiny fake, real RVAs unmapped


if __name__ == "__main__":
    unittest.main()
