from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from vanillatool_emulator import am_config as C
from vanillatool_emulator.am_pipeline import (
    audit_target,
    check_environment,
    render_text_report,
    run_automatic,
    run_mapper_ladder,
    self_test_emulator,
)
from vanillatool_emulator.am_workspace import build_default_logins, write_logins

REPO_ROOT = Path(__file__).resolve().parents[1]
TARGET = str(REPO_ROOT / "game.dll")


class PipelineTests(unittest.TestCase):
    def test_environment_ok(self) -> None:
        opts = C.AutomaticOptions(target_exe=TARGET, emulator_port=0)
        # port 0 always binds; use a fixed free probe instead via check
        opts.emulator_port = 18080
        step = check_environment(opts)
        self.assertTrue(step.ok)

    def test_environment_rejects_bad_server(self) -> None:
        opts = C.AutomaticOptions(target_exe=TARGET, server="Nope",
                                  emulator_port=18081)
        step = check_environment(opts)
        self.assertFalse(step.ok)

    def test_mapper_ladder_success_and_conflict(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            from vanillatool_emulator.am_workspace import prepare_workspace
            ws = prepare_workspace(Path(tmp) / "ws",
                                   settings={"fHide_UDK": "AbCdEfGhIjK"})
            ok = run_mapper_ladder(ws, "")
            self.assertTrue(ok.ok)
            self.assertIn("-prv 1", ok.status)
            blocked = run_mapper_ladder(ws, "1,2,3")
            # default (no -prv) still maps, so overall ok; conflicts visible
            self.assertTrue(blocked.ok)
            hints = [a["hint"] for a in blocked.details["attempts"] if a["hint"]]
            self.assertEqual(len(hints), 3)

    def test_emulator_self_test(self) -> None:
        opts = C.AutomaticOptions()
        step = self_test_emulator(opts)
        self.assertTrue(step.ok, step.details)
        self.assertEqual(step.details["account_manager_markers_total"], 60)

    def test_full_run_dry(self) -> None:
        if not Path(TARGET).is_file():
            self.skipTest("game.dll not present")
        with tempfile.TemporaryDirectory() as tmp:
            opts = C.AutomaticOptions(target_exe=TARGET, server="EuroAion")
            report = run_automatic(opts, Path(tmp) / "ws")
            self.assertTrue(report.ok, [s.as_dict() for s in report.steps])
            self.assertEqual(len(report.steps), 6)
            text = render_text_report(report)
            self.assertIn("automatic run complete", text)
            self.assertTrue((Path(tmp) / "ws" / "report.json").is_file())

    def test_full_run_login_all(self) -> None:
        if not Path(TARGET).is_file():
            self.skipTest("game.dll not present")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "ws"
            root.mkdir()
            parser = build_default_logins()
            parser["Account"]["0"] = "demo"
            parser["Client"]["0"] = "EuroAion"
            parser["GameAccount"]["0"] = "g1"
            parser["LoginAll"]["0"] = "1"
            write_logins(root / "logins.ini", parser)
            opts = C.AutomaticOptions(target_exe=TARGET, login_all=True,
                                      settings={"LoginAllCap": "4"})
            report = run_automatic(opts, root)
            self.assertTrue(report.ok)
            launch = [s for s in report.steps if s.name == "launch"][0]
            self.assertEqual(launch.details["accounts_seen"], 1)

    def test_missing_target_fails_cleanly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            opts = C.AutomaticOptions(target_exe="/nonexistent/aion.bin")
            step = audit_target(opts)
            self.assertFalse(step.ok)
            report = run_automatic(opts, Path(tmp) / "ws")
            self.assertFalse(report.ok)

    def test_gui_layout_without_tk(self) -> None:
        from vanillatool_emulator.am_gui import describe_layout
        layout = describe_layout()
        self.assertIn("Automatic Run", layout["primary_action"])
        self.assertIn("AutoInject", layout["checkboxes"])


if __name__ == "__main__":
    unittest.main()
