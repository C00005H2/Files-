from __future__ import annotations

import unittest

from vanillatool_emulator.account_manager import (
    ACCOUNT_MANAGER_PROFILE_KEYS,
    BOOTSTRAP_MARKER_VALUE,
    account_manager_startup_response_text,
    missing_account_manager_profile_keys,
)
from vanillatool_emulator.protocol import inspect_response_profile


class AccountManagerTests(unittest.TestCase):
    def test_startup_response_satisfies_every_pre_gui_marker(self) -> None:
        text = account_manager_startup_response_text()
        self.assertTrue(text.startswith("ORythm=1;PRythm=2;\n"))
        self.assertEqual(missing_account_manager_profile_keys(text), [])
        # Zero placeholders only: no real addresses are invented.
        self.assertNotIn("0x1", text)
        self.assertEqual(text.count(f"={BOOTSTRAP_MARKER_VALUE}\n"), len(ACCOUNT_MANAGER_PROFILE_KEYS))

    def test_missing_keys_report_names_only(self) -> None:
        self.assertEqual(
            missing_account_manager_profile_keys(None),
            list(ACCOUNT_MANAGER_PROFILE_KEYS),
        )
        partial = "UEU=0x0\nUNA=0x0\n"
        missing = missing_account_manager_profile_keys(partial)
        self.assertNotIn("UEU", missing)
        self.assertEqual(len(missing), len(ACCOUNT_MANAGER_PROFILE_KEYS) - 2)

    def test_capability_flags_are_diagnostics_not_memory_features(self) -> None:
        diagnostics = inspect_response_profile(account_manager_startup_response_text())
        self.assertEqual(diagnostics["status"], "capabilities-only")
        self.assertEqual(diagnostics["missing_for_inject"], ["Name"])

    def test_invalid_rythm_values_are_rejected(self) -> None:
        for kwargs in ({"orythm": "1;drop"}, {"prythm": "-1"}, {"orythm": ""}):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):
                    account_manager_startup_response_text(**kwargs)


if __name__ == "__main__":
    unittest.main()
