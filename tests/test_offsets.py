from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from vanillatool_emulator.offsets import (
    REQUIRED_KEYS,
    build_offsets_text,
    load_offsets_file,
    parse_offsets_text,
    validate_offsets_text,
)


class OffsetsTests(unittest.TestCase):
    def test_placeholder_fixture_satisfies_the_script_wait_loop(self) -> None:
        body = build_offsets_text()
        # The scripts wait on "#UNTIL=%Var[Offset_Base_SubText],>0", so the
        # fixture must contain a section header and a non-zero Base_SubText.
        self.assertIn("[Offsets]", body)
        sections = parse_offsets_text(body)
        self.assertEqual(int(sections["Offsets"]["Base_SubText"]), 1)
        self.assertEqual(validate_offsets_text(body), {"Base_SubText": "1"})

    def test_load_offsets_file_normalizes_and_validates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Offsets.txt"
            path.write_bytes(b"[Game]\r\nBase_SubText=0x10\r\nExtra=AION.exe+0x1234\r\n")
            served = load_offsets_file(path)
            self.assertTrue(served.endswith("\r\n"))
            sections = parse_offsets_text(served)
            self.assertEqual(sections["Game"]["Extra"], "AION.exe+0x1234")

    def test_bodies_that_deadlock_the_wait_loop_are_rejected(self) -> None:
        for bad in (
            "Base_SubText=1",  # no [section] header
            "[Game]\r\nOther=2\r\n",  # required key missing
            "[Game]\r\nBase_SubText=0\r\n",  # would spin until timeout
        ):
            with self.subTest(body=bad):
                with self.assertRaises(ValueError):
                    validate_offsets_text(bad)
        with self.assertRaises(ValueError):
            build_offsets_text({"Base_SubText": "0"})

    def test_required_keys_documented(self) -> None:
        self.assertEqual(REQUIRED_KEYS, ("Base_SubText",))


if __name__ == "__main__":
    unittest.main()
