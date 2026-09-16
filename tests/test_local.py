from __future__ import annotations

import json
import random
import tempfile
import unittest
from pathlib import Path

from vanillatool_emulator import local as L
from vanillatool_emulator.local import (
    AutoFlow,
    AutoOptions,
    HostsManager,
    LoginsStore,
    MapperRunner,
    PayloadStager,
    RegistryStore,
    ServerSupervisor,
)


REPO_ROOT = Path(__file__).resolve().parents[1]


class DeviceNameTests(unittest.TestCase):
    def test_random_name_shape(self) -> None:
        rng = random.Random(1234)
        name = L.random_device_name(rng=rng)
        self.assertEqual(len(name), 11)
        self.assertTrue(all(c.isalpha() for c in name))


class RegistryStoreTests(unittest.TestCase):
    def test_ensure_defaults_and_persistence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "registry.json"
            store = RegistryStore(path)
            created = store.ensure_defaults(rng=random.Random(7))
            self.assertIn("fHide_UDK", created)
            self.assertEqual(len(store.device_name()), 11)
            # Every default key exists now.
            for key in L.REGISTRY_DEFAULTS:
                self.assertIn(key, store.all())
            store.save()
            self.assertTrue(path.is_file())
            raw = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(raw["fHide_UDK"], store.device_name())

    def test_stray_status_string_is_repaired(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "registry.json"
            path.write_text(json.dumps({"fHide_UDK": "Injecting driver name.."}),
                            encoding="utf-8")
            store = RegistryStore(path)
            created = store.ensure_defaults(rng=random.Random(9))
            self.assertIn("fHide_UDK", created)
            self.assertNotEqual(store.device_name(), "Injecting driver name..")
            self.assertEqual(len(store.device_name()), 11)


class LoginsStoreTests(unittest.TestCase):
    def test_delay_defaults_cover_recovered_table(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = LoginsStore(Path(tmp) / "logins.ini")
            added = store.ensure_delay_defaults()
            self.assertEqual(len(added), len(L.DELAY_DEFAULTS))
            self.assertGreaterEqual(len(added), 39)
            # Spot-check values recovered from the resolved source.
            delays = store.delays()
            self.assertEqual(delays["GFL_AfterLauncherAppears"], "5550")
            self.assertEqual(delays["Purple_Startup"], "25000")
            self.assertEqual(delays["WaitForAionProcess"], "40000")
            store.save()
            again = LoginsStore(Path(tmp) / "logins.ini")
            self.assertEqual(again.ensure_delay_defaults(), {})

    def test_account_crud_and_client_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = LoginsStore(Path(tmp) / "logins.ini")
            store.set_account("alice", {"Server": "EuroAion", "Enabled": "True"})
            store.set_account("bob", {"Server": "Destiny", "Enabled": "False"})
            self.assertEqual(store.list_accounts(), ["alice", "bob"])
            self.assertEqual(store.get_account("alice")["Server"], "EuroAion")
            store.set_client_path("EuroAion Client Path", r"D:\Games\EuroAion")
            store.save()
            reloaded = LoginsStore(Path(tmp) / "logins.ini")
            self.assertIn("alice", reloaded.list_accounts())
            self.assertTrue(reloaded.delete_account("bob"))
            self.assertFalse(reloaded.delete_account("Delay"))
            self.assertNotIn("bob", reloaded.list_accounts())


class PayloadStagerTests(unittest.TestCase):
    def test_inventory_finds_required_payloads(self) -> None:
        stager = PayloadStager(REPO_ROOT)
        self.assertEqual(stager.missing_required(), [])
        by_name = {i.spec.staged_name: i for i in stager.inventory()}
        for name in ("udk.bin", "udk_1.dll", "udk_2.bin"):
            self.assertTrue(by_name[name].found, name)
            self.assertTrue(by_name[name].size_ok, name)

    def test_stage_and_patch_round_trip(self) -> None:
        stager = PayloadStager(REPO_ROOT)
        with tempfile.TemporaryDirectory() as tmp:
            report = stager.stage(tmp)
            self.assertEqual(report.missing, [])
            self.assertIn("udk_2.bin", report.staged)
            dev, dos = stager.patch_driver(tmp, "AbCdEfGhIjK")
            self.assertEqual(dev, "\\Device\\AbCdEfGhIjK")
            self.assertEqual(dos, "\\DosDevices\\AbCdEfGhIjK")
            self.assertEqual(stager.driver_device_name(tmp), "AbCdEfGhIjK")
            with self.assertRaises(ValueError):
                stager.patch_driver(tmp, "short")


class MapperRunnerTests(unittest.TestCase):
    def _staged(self, tmp: str) -> MapperRunner:
        PayloadStager(REPO_ROOT).stage(tmp, only=("udk_2.bin",))
        PayloadStager(REPO_ROOT).patch_driver(tmp, "AbCdEfGhIjK")
        return MapperRunner(tmp)

    def test_simulated_ladder_maps_first_available(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runner = self._staged(tmp)
            ladder = runner.run_ladder(force_simulated=True)
            self.assertTrue(ladder.mapped)
            self.assertEqual(ladder.steps[0].argv, ["-prv", "1", "-map", "udk_2.bin"])
            self.assertEqual(ladder.hints, [])

    def test_conflict_hints_match_client_strings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runner = self._staged(tmp)
            ladder = runner.run_ladder(unavailable=(1,), providers=[1],
                                       force_simulated=True)
            self.assertFalse(ladder.mapped)
            self.assertEqual(ladder.hints,
                             ["Status: Make sure MSI Afterburner is closed."])

    def test_probe_is_none_off_windows(self) -> None:
        import sys as _sys

        with tempfile.TemporaryDirectory() as tmp:
            runner = self._staged(tmp)
            probe = runner.probe_device("AbCdEfGhIjK")
            if _sys.platform.startswith("win"):
                self.assertIn(probe, (True, False))
            else:
                self.assertIsNone(probe)


class NcGuardTests(unittest.TestCase):
    def test_prepare_and_verify(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bin64 = root / "bin64"
            bin64.mkdir()
            (bin64 / "aion.bin").write_bytes(b"MZ-fake")
            (bin64 / "CrySystem.dll").write_bytes(b"MZ-fake")
            (root / "Data" / "World").mkdir(parents=True)
            (root / "Data" / "World" / "x_World.pak").write_bytes(b"pak")
            fake_source = root / "source_game.dll"
            fake_source.write_bytes(b"G" * 64)
            dest = L.prepare_game_dll(fake_source, bin64)
            self.assertTrue(dest.is_file())
            info = L.verify_game_dir(root)
            self.assertTrue(info["aion_bin"])
            self.assertTrue(info["cry_system"])
            self.assertTrue(info["game_dll"])
            self.assertTrue(info["world_pak"])
            self.assertEqual(info["ncguard_slots"]["aion.bin"], "0x863f8")
            self.assertEqual(info["ncguard_slots"]["CrySystem.dll"], "0x21a2db")


class HostsManagerTests(unittest.TestCase):
    def test_apply_and_restore_on_temp_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            hosts = Path(tmp) / "hosts"
            hosts.write_text("127.0.0.1 localhost\n", encoding="utf-8")
            manager = HostsManager(hosts)
            self.assertFalse(manager.is_redirected())
            line = manager.apply_redirect()
            self.assertIn("subvanillatool.com", line)
            self.assertTrue(manager.is_redirected())
            self.assertTrue(manager.backup_path().is_file())
            self.assertTrue(manager.restore())
            self.assertFalse(manager.is_redirected())


class SupervisorTests(unittest.TestCase):
    def test_start_stop_and_status(self) -> None:
        supervisor = ServerSupervisor()
        try:
            status = supervisor.start(bind="127.0.0.1", port=0,
                                      account_manager_startup=True)
            self.assertTrue(status.running)
            self.assertGreater(status.port, 0)
            current = supervisor.status()
            self.assertTrue(current.running)
            self.assertEqual(current.auth_requests, 0)
        finally:
            supervisor.stop()
        self.assertFalse(supervisor.running)


class AutoFlowTests(unittest.TestCase):
    def test_full_run_simulated_with_server(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp) / "work"
            game = Path(tmp) / "game"
            (game / "bin64").mkdir(parents=True)
            (game / "bin64" / "aion.bin").write_bytes(b"MZ")
            flow = AutoFlow(repo_root=REPO_ROOT)
            try:
                report = flow.run(AutoOptions(
                    workdir=workdir, game_dir=game, port=0,
                    force_simulated_mapping=True,
                    logins_path=workdir / "logins.ini",
                ))
            finally:
                flow.supervisor.stop()
            self.assertTrue(report.ok, [s for s in report.steps if not s["ok"]])
            self.assertIn("successfully", report.status)
            names = [s["step"] for s in report.steps]
            self.assertEqual(names, ["registry", "logins", "stage", "patch",
                                     "mapper", "gamedll", "hosts", "server",
                                     "target"])
            self.assertTrue((workdir / "udk.bin").is_file())
            self.assertTrue((workdir / "udk_2.bin").is_file())
            self.assertTrue((game / "bin64" / "game.dll").is_file())

    def test_bad_device_name_fails_fast(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            flow = AutoFlow(repo_root=REPO_ROOT)
            try:
                report = flow.run(AutoOptions(
                    workdir=Path(tmp) / "work", device_name_value="short",
                    start_server=False, run_mapping=False,
                    prepare_gamedll=False,
                ))
            finally:
                flow.supervisor.stop()
            self.assertFalse(report.ok)
            self.assertEqual(report.status, "Status: Error 16")


if __name__ == "__main__":
    unittest.main()
