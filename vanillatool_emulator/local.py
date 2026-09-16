"""Local automation for Para's Account Manager 5.43.

This module recovers the *local* half of Account Manager — everything the
original ``Para's Account Manager - ver. 5.43.exe`` does on the machine
itself, outside the ``https://subvanillatool.com/data/auth.php`` license
call that :mod:`vanillatool_emulator.server` already emulates:

* the ``HKCU\\Software\\Para's NoAnimation`` settings hive
  (:class:`RegistryStore`),
* the ``logins.ini`` account + ``[Delay]`` timing store
  (:class:`LoginsStore`),
* staging + device-name patching of the dropped driver/DLL payload set
  (:class:`PayloadStager`, using :mod:`vanillatool_emulator.mapper`),
* the ``udk.bin -prv <id> -map udk_2.bin`` provider ladder
  (:class:`MapperRunner`),
* the NCGuard ``Game.dll`` redirect preparation (:mod:`vanillatool_emulator.local`
  constants + :func:`prepare_game_dll` / :func:`verify_game_dir`),
* the ``subvanillatool.com`` hosts-file redirect (:class:`HostsManager`),
* the emulator :class:`ServerSupervisor`,
* and the one-click :class:`AutoFlow` chain that runs all of the above in
  the order the original tool needs them.

Everything here is **stdlib-only** and cross-platform.  Windows-only steps
(real registry access, real driver mapping, launching ``aion.bin``) degrade
to faithful dry-run / simulation results on other platforms so the whole
flow stays testable on Linux/macOS while doing the real work on Windows.

The desktop GUI (:mod:`vanillatool_emulator.gui`, tkinter) and the web
control panel (:mod:`vanillatool_emulator.panel`) are thin front-ends over
this module — all observable behaviour is implemented here so it can be
unit-tested headlessly.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import argparse
import configparser
import json
import os
import random
import shutil
import string
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

from .mapper import (
    DEFAULT_NAME_LENGTH,
    PROVIDERS,
    MapperRun,
    device_name,
    hint_conflict,
    patch_device_names,
    read_device_slots,
    simulate,
)

# ---------------------------------------------------------------------------
# Well-known names / offsets recovered from AccountManager_5.43_resolved.au3
# ---------------------------------------------------------------------------

REGISTRY_HIVE = r"HKEY_CURRENT_USER\Software\Para's NoAnimation"
AUTH_HOST = "subvanillatool.com"
AUTH_URL = "https://subvanillatool.com/data/auth.php"
FALLBACK_IPV4 = "31.220.106.18"

# NCGuard redirect slots (NCGuardRedirect_v2, line 639 resolved: the decimal
# literals 549880 / 2204379 are authoritative; hex shown for convenience).
AION_BIN_NCGUARD_OFFSET = 549880  # 0x863F8, 128-byte char slot in aion.bin
CRYSYSTEM_NCGUARD_OFFSET = 2204379  # 0x21A2DB, 128-byte char slot in CrySystem.dll
NCGUARD_SLOT_SIZE = 128
NCGUARD_REPLACEMENT = b"Game.dll"
NCGUARD_THREAD_MAGICS = (1048587, 77)  # 0x10002B and 77
NCGUARD_HOOK_PATTERN = r"^(lstrcpyn|lstrcpynA|ReadFile)$"
WINDOW_CLASS_ORIGINAL = "AIONClientWndClass1.0"  # 21 chars
WINDOW_CLASS_SPOOFED = "BIONClientWnd"

# Gameforge product GUIDs launched via gfclient://view/?game=<guid>.
PRODUCT_GUIDS = (
    "f7ed0b7e-fab7-4875-9761-b028f5b23416",
    "cdc124e6-6e04-4867-a651-135e589f8fd1",
)

#: Server presets offered by Account Manager's login GUI.
SERVER_PRESETS: tuple[str, ...] = (
    "EuroAion",
    "Aion America",
    "Destiny",
    "GamezAion",
    "Elden Aion",
    "Aion Nova",
    "Aion NA",
    "Aion EU",
    "NA Classic",
    "EU Classic",
)

#: Per-server client-path labels used by the Settings dialog.
CLIENT_PATH_KEYS: tuple[str, ...] = (
    "NA Client Path",
    "NA Classic Client Path",
    "EU Client Path",
    "EU Classic Client Path",
    "EuroAion Client Path",
    "Aion America Client Path",
    "Destiny Client Path",
    "GamezAion Client Path",
    "Aion Nova Client Path",
    "Elden Aion Client Path",
    "Purple Path",
    "GF Launcher Path",
    "NC Launcher Path",
)

#: Virtual-client slot names (Settings -> Choose Virtual Client).
VIRTUAL_CLIENT_SLOTS: tuple[str, ...] = tuple(
    f"Virtual Client [{i}]" for i in range(1, 10)
) + ("Original Client",)

#: Registry defaults.  ``None`` means "generated on first run"
#: (``fHide_UDK`` becomes a random 11-char device name).
REGISTRY_DEFAULTS: dict[str, str] = {
    "LastUsed": "",
    "fHide_LR": "False",
    "fHide_MVT": "False",
    "fHide_VT": "False",
    "fHide_BBQ": "False",
    "fHide_UDK": "",  # generated -> random 11-char name (see ensure_defaults)
    "fHide_GT": "False",
    "fHide_NOVA": "False",
    "fHide_MAM": "False",
    "AutoInject": "False",  # "[ ] Auto Inject Vanillatool"
    "VirtualClient": "False",  # "[ ] Create Virtual Clients"
    "VirtualClientSlot": "Original Client",
    "AMInstaScriptSilent": "False",  # "[ ] Hide Script Editor"
    "AMAionClientSilent": "False",  # "[ ] Hide Aion Client"
    "AMInstaScriptDelay": "20",
    "AMLoginAllDelay": "0",
    "LoginAllCap": "999",
    "RandomizeMAC": "False",
    "CustomMac": "",
    "Anonify": "False",  # "[ ] Anonify Login"
    "AMNotes": "",
    "BypassBan": "False",  # "[ ] Bypass Launcher ban"
    "Compatibility": "True",
    "AMCrashedClients": "False",  # "[ ] Auto restart crashed clients"
    "AMLogChars": "False",  # "[ ] Log Charnames to Status"
    "AMStartMethod": "0",
    "AMUnlimiter": "False",
    "AMBypass": "False",
    "AMEUPath": "",
    "AMIIPath": "",
    "AMLang": "en-US",
}

#: ``logins.ini [Delay]`` defaults recovered from the Global init block
#: (lines ~129-134) merged with the live ``IniRead`` fallbacks.  All values
#: are milliseconds unless noted.
DELAY_DEFAULTS: dict[str, int] = {
    # Generic launcher flow.
    "AfterLoginLauncherAppears": 300,
    "BeforePasteEmail": 95,
    "TabFromEmailToPassword": 100,
    "BeforePastePassword": 95,
    "BeforeClickOnLogin": 200,
    "AfterGameLauncherAppears": 3000,
    "BeforeSelectClient": 400,
    "AfterSelectClient": 350,
    "LoginLauncherAppearTimeout": 40000,
    "GameLauncherAppearTimeout": 40000,
    "WaitForAionProcess": 40000,
    "WaitForEULA_Retail": 15000,
    "WaitForEULA_Classic": 35000,
    "AA_Splash": 0,
    "Nova_Splash": 0,
    # Gameforge flow.
    "GFL_AfterTypeGameAccount": 650,
    "GFL_AfterClickOnSearchAccount": 850,
    "GFL_AfterClickOnAion": 1250,
    "GFL_AfterClickOnAd": 750,
    "GFL_AfterResizing": 1500,
    "GFL_AfterDeMaximizing": 1550,
    "GFL_AfterLauncherAppears": 5550,
    "GFL_AfterGameAccountWindowAppears": 850,
    # Purple flow.
    "Purple_BeforeClickingAccountList": 1000,
    "Purple_AfterClickingAccountList": 2000,
    "Purple_AfterSwitchAccount": 5000,
    "Purple_BeforeClickStart": 3500,
    "Purple_AfterMultiAccount": 5000,
    "Purple_WaitForAionProcess": 15000,
    "Purple_Startup": 25000,
    "Purple_WaitingForServerSelection": 14000,
    "Purple_ScreenReadTolerance": 1,
    "Purple_AfterMultiPlayCheckboxOn": 1250,
    "Purple_AfterMultiPlayConfirm": 3000,
    "Purple_BeforeMultiStartGame": 500,
    "Purple_AfterClickingAionSection": 4000,
    "Purple_AfterClickingGameTypeBox": 1000,
    "Purple_AfterClickingGameType": 5000,
    "Purple_AfterScrollingDown": 1000,
}

#: Per-account keys understood by logins.ini account sections.
ACCOUNT_KEYS: tuple[str, ...] = (
    "NCAccount",
    "NCMultiAccount",
    "GFAccount",
    "GameAccount",
    "Client",
    "InstaScriptUsage",
    "InstaScriptFile",
    "VirtualClient",
    "CustomExe",
    "CustomExe2",
    "CustomBin",
    "UseBypass",
    "Anonify_Nova",
    "Delay",
    "WaitForAionProcess",
)

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def random_device_name(length: int = DEFAULT_NAME_LENGTH, rng: random.Random | None = None) -> str:
    """Return a random mixed-case device name like AM's ``A0349104C2D(11)``."""
    rng = rng or random.SystemRandom()
    alphabet = string.ascii_letters
    return "".join(rng.choice(alphabet) for _ in range(length))


def find_repo_root(start: Path | None = None) -> Path:
    """Locate the repository root (the dir holding ``analysis/``)."""
    here = Path(start or __file__).resolve()
    for candidate in (here, *here.parents):
        if (candidate / "analysis" / "embedded_files" / "AM").is_dir():
            return candidate
        # Installed-package fallback: the file itself lives in the package.
        if candidate.name == "vanillatool_emulator" and (candidate.parent / "analysis").is_dir():
            return candidate.parent
    # Last resort: current working directory if it looks like the repo.
    cwd = Path.cwd()
    if (cwd / "analysis" / "embedded_files" / "AM").is_dir():
        return cwd
    return Path(__file__).resolve().parents[1]


def default_hosts_path() -> Path:
    if sys.platform.startswith("win"):
        windir = os.environ.get("SystemRoot", r"C:\Windows")
        return Path(windir) / "System32" / "drivers" / "etc" / "hosts"
    return Path("/etc/hosts")


def is_admin() -> bool:
    """Best-effort administrator check (Windows: Administrator, else root)."""
    try:
        if sys.platform.startswith("win"):
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0  # type: ignore[attr-defined]
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Registry hive mirror
# ---------------------------------------------------------------------------


class RegistryStore:
    """JSON-backed mirror of ``HKCU\\Software\\Para's NoAnimation``.

    On Windows with ``use_winreg=True`` the store additionally syncs through
    to the real registry via :mod:`winreg`; everywhere else (and in tests)
    it is a plain JSON file, defaulting to
    ``<workdir>/Para's Settings/registry.json`` when a workdir is given or
    ``~/.vanillatool_am_registry.json`` otherwise.
    """

    def __init__(self, path: Path | None = None, use_winreg: bool = False) -> None:
        if path is None:
            path = Path.home() / ".vanillatool_am_registry.json"
        self.path = Path(path)
        self.use_winreg = use_winreg and sys.platform.startswith("win")
        self._values: dict[str, str] = {}
        self.load()

    # -- persistence ----------------------------------------------------
    def load(self) -> dict[str, str]:
        values: dict[str, str] = {}
        if self.path.is_file():
            try:
                raw = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    values = {str(k): str(v) for k, v in raw.items()}
            except (OSError, ValueError):
                values = {}
        if self.use_winreg:
            values.update(self._read_winreg())
        self._values = values
        return dict(self._values)

    def save(self) -> Path:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._values, indent=2, sort_keys=True), encoding="utf-8")
        if self.use_winreg:
            self._write_winreg()
        return self.path

    # -- access ---------------------------------------------------------
    def get(self, name: str, default: str = "") -> str:
        return self._values.get(name, default)

    def set(self, name: str, value: str) -> None:
        self._values[str(name)] = str(value)

    def all(self) -> dict[str, str]:
        return dict(self._values)

    def ensure_defaults(self, rng: random.Random | None = None) -> dict[str, str]:
        """Create every missing value; generate the UDK device name.

        Returns the subset of values that were created by this call.
        """
        created: dict[str, str] = {}
        for key, default in REGISTRY_DEFAULTS.items():
            if key in self._values and self._values[key] != "":
                continue
            if key == "fHide_UDK":
                value = random_device_name(rng=rng)
            else:
                value = default
            self._values[key] = value
            created[key] = value
        # Repair a stray GUI status string left in fHide_UDK (the original
        # tool skips patching while it holds "Injecting driver name..").
        if self._values.get("fHide_UDK") == "Injecting driver name..":
            value = random_device_name(rng=rng)
            self._values["fHide_UDK"] = value
            created["fHide_UDK"] = value
        return created

    def device_name(self) -> str:
        return self._values.get("fHide_UDK", "")

    # -- optional real-registry sync (Windows only) ----------------------
    def _read_winreg(self) -> dict[str, str]:
        try:
            import winreg
        except ImportError:
            return {}
        values: dict[str, str] = {}
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Para's NoAnimation") as key:
                index = 0
                while True:
                    try:
                        name, data, _kind = winreg.EnumValue(key, index)
                    except OSError:
                        break
                    values[str(name)] = str(data)
                    index += 1
        except OSError:
            pass
        return values

    def _write_winreg(self) -> None:
        try:
            import winreg
        except ImportError:
            return
        try:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Para's NoAnimation") as key:
                for name, value in self._values.items():
                    winreg.SetValueEx(key, name, 0, winreg.REG_SZ, str(value))
        except OSError:
            pass


# ---------------------------------------------------------------------------
# logins.ini store
# ---------------------------------------------------------------------------


class LoginsStore:
    """Reader/writer for Account Manager's ``logins.ini``.

    Layout (recovered from the resolved source):

    * ``[Delay]`` — timing table, see :data:`DELAY_DEFAULTS`.
    * ``[Characternames]`` — cached character names per client.
    * one section per account, holding :data:`ACCOUNT_KEYS` plus ``Server``
      and ``Enabled``.
    * ``[Clients]`` — optional per-server client directory overrides using
      :data:`CLIENT_PATH_KEYS` names.
    """

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.config = configparser.ConfigParser(interpolation=None)
        # Preserve key case (AutoIt IniRead is case-insensitive but the file
        # on disk keeps the author's capitalisation).
        self.config.optionxform = str  # type: ignore[assignment]
        if self.path.is_file():
            try:
                self.config.read(self.path, encoding="utf-8")
            except (OSError, configparser.Error):
                pass

    # -- persistence ----------------------------------------------------
    def save(self) -> Path:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("w", encoding="utf-8") as stream:
            self.config.write(stream)
        return self.path

    # -- Delay table ----------------------------------------------------
    def ensure_delay_defaults(self) -> dict[str, int]:
        """Fill missing ``[Delay]`` entries; return what was added."""
        if not self.config.has_section("Delay"):
            self.config.add_section("Delay")
        added: dict[str, int] = {}
        for key, default in DELAY_DEFAULTS.items():
            if not self.config.has_option("Delay", key):
                self.config.set("Delay", key, str(default))
                added[key] = default
        return added

    def delays(self) -> dict[str, str]:
        if not self.config.has_section("Delay"):
            return {}
        return dict(self.config.items("Delay"))

    def set_delay(self, key: str, value: int | str) -> None:
        if not self.config.has_section("Delay"):
            self.config.add_section("Delay")
        self.config.set("Delay", key, str(value))

    # -- accounts --------------------------------------------------------
    def _is_account_section(self, section: str) -> bool:
        return section not in ("Delay", "Characternames", "Clients", "Settings")

    def list_accounts(self) -> list[str]:
        return [s for s in self.config.sections() if self._is_account_section(s)]

    def get_account(self, name: str) -> dict[str, str]:
        if not self.config.has_section(name):
            return {}
        return dict(self.config.items(name))

    def set_account(self, name: str, values: Mapping[str, str]) -> None:
        if not self.config.has_section(name):
            self.config.add_section(name)
        for key, value in values.items():
            self.config.set(name, key, str(value))

    def delete_account(self, name: str) -> bool:
        if self._is_account_section(name) and self.config.has_section(name):
            self.config.remove_section(name)
            return True
        return False

    # -- client paths ----------------------------------------------------
    def client_paths(self) -> dict[str, str]:
        if not self.config.has_section("Clients"):
            return {}
        return dict(self.config.items("Clients"))

    def set_client_path(self, label: str, directory: str) -> None:
        if not self.config.has_section("Clients"):
            self.config.add_section("Clients")
        self.config.set("Clients", label, directory)


# ---------------------------------------------------------------------------
# Payload staging (drivers / DLLs / helpers)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PayloadSpec:
    """One droppable helper: where it lives in the repo, what AM calls it."""

    staged_name: str
    source_rel: str  # relative to the repo root
    expected_size: int
    description: str
    required: bool = False


# Sources are the decoded ``*.dec`` payloads recovered from the exe plus the
# ``game.dll`` shipped next to it.  Sizes pin the exact 5.43 lineage.
PAYLOADS: tuple[PayloadSpec, ...] = (
    PayloadSpec("udk.bin", "analysis/embedded_files/AM/VanillaUDK_3.13.bin.dec", 525824,
                "KDU-style kernel mapper (dropped as udk.bin)", True),
    PayloadSpec("udk_1.dll", "analysis/embedded_files/AM/VanillaUDK_3.11.dll.dec", 1325568,
                "mapper support DLL (dropped as udk_1.dll)", True),
    PayloadSpec("udk_2.bin", "analysis/embedded_files/AM/VanillaDrv_3.13.sys.dec", 13312,
                "victim driver (dropped as udk_2.bin, device-name patched)", True),
    PayloadSpec("spk.exe", "analysis/embedded_files/AM/SparkMod.exe.dec", 1078784,
                "SparkMod anonify writer (dropped as spk.exe)", False),
    PayloadSpec("GetThreads64.exe", "analysis/embedded_files/AM/GetThreads64.exe.dec", 1307136,
                "thread enumerator for NCGuard context patches", False),
    PayloadSpec("SR.exe", "analysis/embedded_files/AM/SR.exe.dec", 1222144,
                "ScreenReader helper", False),
    PayloadSpec("lr.exe", "analysis/embedded_files/AM/lr.exe.dec", 897024,
                "lr helper", False),
    PayloadSpec("BBQ.bin", "analysis/embedded_files/AM/BBQ.bin.dec", 1025536,
                "BBQ helper blob", False),
    PayloadSpec("NovaApi.exe", "analysis/embedded_files/AM/NovaApi.exe.dec", 11264,
                "Nova API helper", False),
    PayloadSpec("api.dll", "analysis/embedded_files/AM/api.dll.dec", 30208,
                "Nova API dll", False),
    PayloadSpec("japi.dll", "analysis/embedded_files/AM/japi.dll.dec", 695808,
                "Nova API (java) dll", False),
    PayloadSpec("msgbox d3d reloader.dll", "analysis/embedded_files/AM/msgbox d3d reloader.dll.dec", 50688,
                "ESP overlay reload helper", False),
    PayloadSpec("game.dll", "game.dll", 7249984,
                "NCGuard replacement DLL (copied to <game>\\bin64\\game.dll)", False),
)


@dataclass
class PayloadInfo:
    spec: PayloadSpec
    source: Path
    found: bool
    actual_size: int | None = None
    size_ok: bool = False


@dataclass
class StageReport:
    workdir: Path
    staged: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.missing and not self.errors


class PayloadStager:
    """Stage the recovered driver/DLL set into a working directory."""

    def __init__(self, repo_root: Path | None = None) -> None:
        self.repo_root = Path(repo_root or find_repo_root())

    def inventory(self) -> list[PayloadInfo]:
        infos: list[PayloadInfo] = []
        for spec in PAYLOADS:
            source = self.repo_root / spec.source_rel
            found = source.is_file()
            size: int | None = source.stat().st_size if found else None
            infos.append(PayloadInfo(
                spec=spec, source=source, found=found, actual_size=size,
                size_ok=(found and size == spec.expected_size),
            ))
        return infos

    def missing_required(self) -> list[str]:
        return [i.spec.staged_name for i in self.inventory()
                if i.spec.required and not i.found]

    def stage(self, workdir: Path | str, overwrite: bool = True,
              only: Iterable[str] | None = None) -> StageReport:
        workdir = Path(workdir)
        workdir.mkdir(parents=True, exist_ok=True)
        wanted = set(only) if only is not None else None
        report = StageReport(workdir=workdir)
        for info in self.inventory():
            name = info.spec.staged_name
            if wanted is not None and name not in wanted:
                continue
            if not info.found:
                (report.missing if info.spec.required else report.skipped).append(name)
                continue
            dest = workdir / name
            try:
                if dest.exists() and not overwrite:
                    report.skipped.append(name)
                    continue
                shutil.copyfile(info.source, dest)
                report.staged.append(name)
            except OSError as exc:
                report.errors.append(f"{name}: {exc}")
        return report

    def patch_driver(self, workdir: Path | str, name: str,
                     filename: str = "udk_2.bin") -> tuple[str, str]:
        """Apply AM's ``\\Device\\``/``\\DosDevices\\`` slot writes.

        Returns the ``(device_path, dos_path)`` now stored in the file.
        """
        path = Path(workdir) / filename
        data = path.read_bytes()
        path.write_bytes(patch_device_names(data, name))
        return read_device_slots(path.read_bytes())

    def read_driver_slots(self, workdir: Path | str,
                          filename: str = "udk_2.bin") -> tuple[str, str]:
        return read_device_slots((Path(workdir) / filename).read_bytes())

    def driver_device_name(self, workdir: Path | str,
                           filename: str = "udk_2.bin") -> str:
        return device_name((Path(workdir) / filename).read_bytes())


# ---------------------------------------------------------------------------
# Mapper ladder
# ---------------------------------------------------------------------------


@dataclass
class LadderStep:
    argv: list[str]
    transcript: str
    exit_code: int
    outcome: str
    hint: str | None
    simulated: bool


@dataclass
class LadderResult:
    steps: list[LadderStep] = field(default_factory=list)
    device_name_value: str | None = None
    device_probe: bool | None = None  # None == cannot probe on this platform

    @property
    def mapped(self) -> bool:
        return any(s.outcome == "mapped" and s.exit_code == 0 for s in self.steps)

    @property
    def hints(self) -> list[str]:
        return [s.hint for s in self.steps if s.hint]


class MapperRunner:
    """Run AM's provider ladder, for real on Windows or simulated."""

    #: The exact ladder AM walks (``None`` == bare ``-map`` default call).
    LADDER: tuple[int | None, ...] = (1, 2, 3, None)

    def __init__(self, workdir: Path | str,
                 mapper_exe: str = "udk.bin",
                 driver_file: str = "udk_2.bin") -> None:
        self.workdir = Path(workdir)
        self.mapper_exe = mapper_exe
        self.driver_file = driver_file

    @property
    def mapper_path(self) -> Path:
        return self.workdir / self.mapper_exe

    @property
    def driver_path(self) -> Path:
        return self.workdir / self.driver_file

    def can_run_real(self) -> bool:
        return (sys.platform.startswith("win") and self.mapper_path.is_file()
                and self.driver_path.is_file())

    def probe_device(self, name: str) -> bool | None:
        """Re-open ``\\\\.\\<name>`` the way AM does after each attempt.

        Returns ``True``/``False`` on Windows, ``None`` elsewhere (the
        kernel object can only exist where a real driver was loaded).
        """
        if not sys.platform.startswith("win"):
            return None
        try:
            # ``open`` on a device path raises on failure; success means the
            # victim driver is loaded and serving the device object.
            with open(r"\\.\\" + name, "rb"):
                pass
            return True
        except OSError:
            return False

    def run_step(self, provider: int | None,
                 unavailable: frozenset[int] | set[int] = frozenset(),
                 force_simulated: bool = False) -> LadderStep:
        argv = ((["-prv", str(provider)] if provider is not None else [])
               + ["-map", self.driver_file])
        simulated = force_simulated or not self.can_run_real()
        if simulated:
            driver_bytes = (self.driver_path.read_bytes()
                            if self.driver_path.is_file() else None)
            run: MapperRun = simulate(
                argv, unavailable_providers=set(unavailable),
                driver_bytes=driver_bytes,
            )
            return LadderStep(argv=list(argv), transcript=run.transcript,
                              exit_code=run.exit_code, outcome=run.outcome,
                              hint=run.conflict_hint(), simulated=True)
        try:
            proc = subprocess.run(
                [str(self.mapper_path), *argv],
                cwd=str(self.workdir), capture_output=True, text=True,
                timeout=120, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            transcript = (proc.stdout or "") + (proc.stderr or "")
            hint = hint_conflict(transcript)
            outcome = "mapped" if proc.returncode == 0 else "provider-unavailable"
            return LadderStep(argv=list(argv), transcript=transcript,
                              exit_code=proc.returncode, outcome=outcome,
                              hint=hint, simulated=False)
        except (OSError, subprocess.SubprocessError) as exc:
            return LadderStep(argv=list(argv), transcript=f"[!] mapper launch failed: {exc}",
                              exit_code=1, outcome="input-missing",
                              hint=None, simulated=False)

    def run_ladder(self, unavailable: Iterable[int] = (),
                   providers: Sequence[int | None] | None = None,
                   stop_on_probe: bool = True,
                   force_simulated: bool = False) -> LadderResult:
        """Walk the ladder; probe ``\\\\.\\<name>`` after each attempt."""
        unavailable_set = frozenset(unavailable)
        result = LadderResult()
        try:
            result.device_name_value = device_name(self.driver_path.read_bytes())
        except OSError:
            result.device_name_value = None
        for provider in (self.LADDER if providers is None else providers):
            step = self.run_step(provider, unavailable_set, force_simulated)
            result.steps.append(step)
            if result.device_name_value:
                probe = self.probe_device(result.device_name_value)
                # Keep the last probe; stop early only on a real Windows hit.
                result.device_probe = probe
                if stop_on_probe and probe is True:
                    break
            # A simulated mapping "succeeds" at the first available provider,
            # matching what the real chain would do — but keep walking when
            # the step reports a conflict so the GUI can show every hint.
            if step.outcome == "mapped" and (result.device_probe is not False):
                if force_simulated or not self.can_run_real():
                    break
        return result


# ---------------------------------------------------------------------------
# NCGuard redirect helpers
# ---------------------------------------------------------------------------


def prepare_game_dll(source: Path | str, game_bin64: Path | str,
                     overwrite: bool = True) -> Path:
    """Copy the ``Game.dll`` replacement next to the client (``bin64``).

    Mirrors AM's expectation that ``<game>\\bin64\\game.dll`` exists before
    the ``NCGuard.dll`` -> ``Game.dll`` name-swap at
    ``aion.bin+0x863F8`` / ``CrySystem.dll+0x21A2DB`` takes effect.
    """
    source = Path(source)
    dest_dir = Path(game_bin64)
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / "game.dll"
    if dest.exists() and not overwrite:
        return dest
    shutil.copyfile(source, dest)
    return dest


def verify_game_dir(game_dir: Path | str) -> dict[str, Any]:
    """Check a game directory the way AM's target discovery does.

    Returns a JSON-serialisable report with ``aion_bin``, ``cry_system``,
    ``game_dll``, ``world_pak`` and ``client_hint`` entries.
    """
    root = Path(game_dir)
    bin64 = root / "bin64"
    # AM also accepts the bin64 dir itself as the "client path".
    if root.name.lower() == "bin64" and (root / "aion.bin").is_file():
        bin64 = root
        root = root.parent
    aion_bin = bin64 / "aion.bin"
    cry = bin64 / "CrySystem.dll"
    game_dll = bin64 / "game.dll"
    world_pak = root / "Data" / "World" / "x_World.pak"
    world_dir = root / "Data" / "World"
    report: dict[str, Any] = {
        "root": str(root),
        "bin64": str(bin64),
        "aion_bin": aion_bin.is_file(),
        "cry_system": cry.is_file(),
        "game_dll": game_dll.is_file(),
        "world_pak": world_pak.is_file(),
        "world_dir": world_dir.is_dir(),
        "ncguard_slots": {
            "aion.bin": hex(AION_BIN_NCGUARD_OFFSET),
            "CrySystem.dll": hex(CRYSYSTEM_NCGUARD_OFFSET),
            "size": NCGUARD_SLOT_SIZE,
            "replacement": NCGUARD_REPLACEMENT.decode("ascii"),
        },
        "window_class_spoof": f"{WINDOW_CLASS_ORIGINAL} -> {WINDOW_CLASS_SPOOFED}",
    }
    if aion_bin.is_file():
        report["client_hint"] = "Status: client found.."
    else:
        report["client_hint"] = "Status: Client not found.."
    return report


# ---------------------------------------------------------------------------
# Hosts-file redirect (original-EXE interop)
# ---------------------------------------------------------------------------


class HostsManager:
    """Manage the ``subvanillatool.com -> 127.0.0.1`` hosts redirect.

    The original EXE hard-codes ``https://subvanillatool.com/data/auth.php``.
    Pointing that name at a local emulator (plus a locally-trusted TLS
    certificate served with ``--tls-cert/--tls-key``) is what lets the
    unmodified target EXE talk to the emulator.  All operations keep a
    ``hosts.vanilla-backup`` copy and are dry-runnable without admin.
    """

    MARKER = "# vanillatool-emulator"

    def __init__(self, hosts_path: Path | None = None) -> None:
        self.hosts_path = Path(hosts_path or default_hosts_path())

    def read(self) -> str:
        try:
            return self.hosts_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    def backup_path(self) -> Path:
        return self.hosts_path.with_name(self.hosts_path.name + ".vanilla-backup")

    def is_redirected(self, domain: str = AUTH_HOST) -> bool:
        for line in self.read().splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or not stripped:
                continue
            parts = stripped.split()
            if len(parts) >= 2 and domain in parts[1:] and parts[0] in ("127.0.0.1", "::1"):
                return True
        return False

    def backup(self) -> Path | None:
        """Copy the hosts file aside; returns the backup path or None."""
        try:
            content = self.hosts_path.read_bytes()
        except OSError:
            return None
        backup = self.backup_path()
        try:
            if not backup.is_file():
                backup.write_bytes(content)
            return backup
        except OSError:
            return None

    def apply_redirect(self, ip: str = "127.0.0.1",
                       domain: str = AUTH_HOST,
                       dry_run: bool = False) -> str:
        """Add the redirect line; returns the line that was (or would be) added."""
        line = f"{ip}\t{domain} {self.MARKER}"
        if self.is_redirected(domain):
            return line
        if dry_run:
            return line
        self.backup()
        content = self.read()
        if content and not content.endswith("\n"):
            content += "\n"
        content += line + "\n"
        self.hosts_path.write_text(content, encoding="utf-8")
        return line

    def restore(self) -> bool:
        """Remove emulator lines, or restore the backup if one exists."""
        backup = self.backup_path()
        try:
            if backup.is_file():
                shutil.copyfile(backup, self.hosts_path)
                return True
            lines = [ln for ln in self.read().splitlines()
                     if self.MARKER not in ln and AUTH_HOST not in ln]
            self.hosts_path.write_text("\n".join(lines) + ("\n" if lines else ""),
                                       encoding="utf-8")
            return True
        except OSError:
            return False

    @staticmethod
    def tls_help(cert: Path | str = "vanillatool.pem",
                 key: Path | str = "vanillatool-key.pem") -> str:
        return (
            "The original EXE uses HTTPS.  After applying the hosts redirect:\n"
            f"  1. openssl req -x509 -newkey rsa:2048 -keyout {key} -out {cert} "
            '-days 825 -nodes -subj "/CN=subvanillatool.com" '
            '-addext "subjectAltName=DNS:subvanillatool.com"\n'
            f"  2. Trust {cert} in Windows (certlm.msc -> Trusted Root), or run:\n"
            f'     certutil -addstore -f "ROOT" {cert}\n'
            "  3. Start the emulator with --tls-cert/--tls-key on port 443.\n"
            "Until then, use the Python-side auth path (the GUI talks to the "
            "emulator over plain HTTP directly)."
        )


# ---------------------------------------------------------------------------
# Emulator server supervisor
# ---------------------------------------------------------------------------


@dataclass
class SupervisorStatus:
    running: bool
    bind: str = ""
    port: int = 0
    scheme: str = "http"
    requests: int = 0
    auth_requests: int = 0
    auth_profile: str = ""


class ServerSupervisor:
    """Run an :class:`EmulatorHTTPServer` in a background thread."""

    def __init__(self) -> None:
        self._httpd: Any = None
        self._thread: threading.Thread | None = None
        self._config: Any = None

    @property
    def running(self) -> bool:
        return self._httpd is not None

    @property
    def config(self) -> Any:
        return self._config

    def start(self, bind: str = "127.0.0.1", port: int = 8080,
              tls_cert: str | None = None, tls_key: str | None = None,
              **config_kwargs: Any) -> SupervisorStatus:
        from .server import EmulatorConfig, EmulatorHTTPServer

        if self.running:
            self.stop()
        import ssl

        config = EmulatorConfig(**config_kwargs)
        httpd = EmulatorHTTPServer((bind, port), config)
        scheme = "http"
        if tls_cert and tls_key:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile=tls_cert, keyfile=tls_key)
            httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
            scheme = "https"
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        self._httpd = httpd
        self._thread = thread
        self._config = config
        return SupervisorStatus(running=True, bind=bind,
                                port=httpd.server_address[1], scheme=scheme)

    def stop(self) -> None:
        if self._httpd is not None:
            try:
                self._httpd.shutdown()
            except Exception:
                pass
            try:
                self._httpd.server_close()
            except Exception:
                pass
        if self._thread is not None:
            self._thread.join(timeout=3)
        self._httpd = None
        self._thread = None

    def status(self) -> SupervisorStatus:
        if not self.running or self._httpd is None:
            return SupervisorStatus(running=False)
        config = self._httpd.config
        with config._lock:
            requests = config.request_count
            auth_requests = config.auth_count
        try:
            profile = config.auth_response_diagnostics().get("status", "")
        except Exception:
            profile = ""
        scheme = "https" if getattr(self._httpd.socket, "context", None) is not None and hasattr(self._httpd.socket, "context") else "http"
        # Heuristic above is unreliable for plain sockets; track via config instead.
        bind, port = self._httpd.server_address[0], self._httpd.server_address[1]
        return SupervisorStatus(running=True, bind=str(bind), port=int(port),
                                scheme=scheme, requests=requests,
                                auth_requests=auth_requests,
                                auth_profile=str(profile))

    def tail_logs(self, count: int = 20) -> list[dict[str, Any]]:
        if not self.running or self._httpd is None:
            return []
        with self._httpd.config._lock:
            return list(self._httpd.config.logs[-count:])


# ---------------------------------------------------------------------------
# One-click automation
# ---------------------------------------------------------------------------


@dataclass
class AutoOptions:
    """Everything :class:`AutoFlow` needs.  All paths accept ``str`` or ``Path``."""

    workdir: Path = field(default_factory=lambda: Path.cwd() / "am_workdir")
    game_dir: Path | None = None
    server_preset: str = "EuroAion"
    device_name_value: str = ""  # empty == reuse registry / generate
    providers: tuple[int | None, ...] = (1, 2, 3, None)
    unavailable_providers: tuple[int, ...] = ()
    bind: str = "127.0.0.1"
    port: int = 8080
    orythm: str = "1"
    prythm: str = "2"
    account_manager_startup: bool = True
    response_file: Path | None = None
    offsets_file: Path | None = None
    apply_hosts: bool = False
    hosts_path: Path | None = None
    run_mapping: bool = True
    force_simulated_mapping: bool = False
    prepare_gamedll: bool = True
    start_server: bool = True
    registry_path: Path | None = None
    logins_path: Path | None = None
    target_exe: Path | None = None
    use_winreg: bool = False


@dataclass
class AutoReport:
    ok: bool
    status: str  # mirrors AM's "Status: ..." line
    steps: list[dict[str, Any]] = field(default_factory=list)
    hints: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def add(self, name: str, ok: bool, detail: str = "",
            extra: dict[str, Any] | None = None) -> None:
        entry: dict[str, Any] = {"step": name, "ok": ok, "detail": detail}
        if extra:
            entry.update(extra)
        self.steps.append(entry)
        if not ok:
            self.ok = False


ProgressCallback = Callable[[str, str], None]  # (step, message)


class AutoFlow:
    """Run the full local chain in the order Account Manager needs it."""

    def __init__(self, repo_root: Path | None = None,
                 supervisor: ServerSupervisor | None = None) -> None:
        self.repo_root = Path(repo_root or find_repo_root())
        self.supervisor = supervisor or ServerSupervisor()
        self.stager = PayloadStager(self.repo_root)

    # -- main entry -----------------------------------------------------
    def run(self, options: AutoOptions,
            progress: ProgressCallback | None = None) -> AutoReport:
        def emit(step: str, message: str) -> None:
            if progress:
                try:
                    progress(step, message)
                except Exception:
                    pass

        workdir = Path(options.workdir)
        workdir.mkdir(parents=True, exist_ok=True)
        report = AutoReport(ok=True, status="Status: Preparing.. (0/3)")
        emit("start", "Status: Preparing.. (0/3)")

        # 1. Settings hive ------------------------------------------------
        reg_path = (Path(options.registry_path) if options.registry_path
                    else workdir / "Para's Settings" / "registry.json")
        registry = RegistryStore(reg_path, use_winreg=options.use_winreg)
        created = registry.ensure_defaults()
        if options.device_name_value:
            if len(options.device_name_value) != DEFAULT_NAME_LENGTH:
                report.add("registry", False,
                           f"device name must be {DEFAULT_NAME_LENGTH} chars")
                report.status = "Status: Error 16"
                return report
            registry.set("fHide_UDK", options.device_name_value)
            created["fHide_UDK"] = options.device_name_value
        registry.save()
        device = registry.device_name()
        report.add("registry", True,
                   f"hive ready ({len(created)} created); device={device}",
                   {"device": device, "created": sorted(created)})
        emit("registry", f"Status: device {device}")
        report.status = "Status: Preparing.. (1/3)"

        # 2. logins.ini ---------------------------------------------------
        logins_path = (Path(options.logins_path) if options.logins_path
                       else workdir / "logins.ini")
        logins = LoginsStore(logins_path)
        added = logins.ensure_delay_defaults()
        logins.save()
        report.add("logins", True,
                   f"logins.ini ready ({len(added)} delay defaults added)",
                   {"path": str(logins_path)})
        emit("logins", "Status: loaded..")

        # 3. Stage payloads ------------------------------------------------
        stage = self.stager.stage(workdir)
        report.add("stage", not stage.missing and not stage.errors,
                   f"staged {len(stage.staged)}; missing={stage.missing or 'none'}",
                   {"staged": stage.staged, "missing": stage.missing,
                    "errors": stage.errors})
        for name in stage.staged:
            emit("stage", f"staged {name}")
        if stage.missing:
            report.warnings.append(
                "missing required payloads: " + ", ".join(stage.missing))
            report.status = "Status: Error 14"
            return report
        report.status = "Status: Preparing.. (2/3)"

        # 4. Patch driver device names -------------------------------------
        try:
            dev, dos = self.stager.patch_driver(workdir, device)
            report.add("patch", True, f"{dev} / {dos}",
                       {"device_path": dev, "dos_path": dos})
            emit("patch", "Status: driver patched..")
        except (OSError, ValueError) as exc:
            report.add("patch", False, str(exc))
            report.status = "Status: Error 16"
            return report

        # 5. Mapper ladder --------------------------------------------------
        if options.run_mapping:
            runner = MapperRunner(workdir)
            ladder = runner.run_ladder(
                unavailable=options.unavailable_providers,
                providers=list(options.providers),
                force_simulated=options.force_simulated_mapping,
            )
            for step in ladder.steps:
                report.hints.extend([step.hint] if step.hint else [])
                emit("mapper", f"{'sim' if step.simulated else 'real'} "
                               f"{' '.join(step.argv)} -> {step.outcome}")
            detail = "; ".join(
                f"{' '.join(s.argv)}={s.outcome}" for s in ladder.steps)
            report.add("mapper", ladder.mapped or bool(ladder.steps), detail,
                       {"mapped": ladder.mapped,
                        "probe": ladder.device_probe,
                        "simulated": all(s.simulated for s in ladder.steps)})
            if ladder.device_probe is None and not sys.platform.startswith("win"):
                report.warnings.append(
                    "device probe unavailable off-Windows; mapping result is "
                    "simulated up to the CreateFileW probe")
            if report.hints:
                report.warnings.extend(report.hints)
        else:
            report.add("mapper", True, "skipped by options")
        report.status = "Status: Preparing.. (3/3)"

        # 6. Game.dll redirect prep ------------------------------------------
        if options.prepare_gamedll and options.game_dir:
            try:
                src = workdir / "game.dll"
                if not src.is_file():
                    # Fall back to the repo copy directly.
                    src = self.repo_root / "game.dll"
                dest = prepare_game_dll(src, Path(options.game_dir) / "bin64")
                info = verify_game_dir(options.game_dir)
                report.add("gamedll", True, f"game.dll -> {dest}",
                           {"dest": str(dest), "verify": info})
                emit("gamedll", "Status: NCGuard redirect ready..")
            except OSError as exc:
                report.add("gamedll", False, str(exc))
                report.warnings.append(f"game.dll staging failed: {exc}")
        else:
            info = verify_game_dir(options.game_dir) if options.game_dir else {}
            report.add("gamedll", True,
                       "skipped (no game dir)" if not options.game_dir
                       else f"verified {options.game_dir}",
                       {"verify": info})

        # 7. Hosts redirect --------------------------------------------------
        if options.apply_hosts:
            hosts = HostsManager(Path(options.hosts_path) if options.hosts_path else None)
            if not is_admin():
                report.add("hosts", True,
                           "not applied (needs admin) — dry-run line generated",
                           {"line": hosts.apply_redirect(dry_run=True)})
                report.warnings.append(
                    "hosts redirect needs administrator; run elevated or "
                    "apply the shown line manually")
            else:
                try:
                    line = hosts.apply_redirect()
                    report.add("hosts", True, line, {"line": line})
                except OSError as exc:
                    report.add("hosts", False, str(exc))
        else:
            report.add("hosts", True, "skipped by options")

        # 8. Emulator server --------------------------------------------------
        if options.start_server:
            try:
                from .offsets import load_offsets_file  # local import, cheap
                offsets_text = (load_offsets_file(Path(options.offsets_file))
                                if options.offsets_file else None)
            except (OSError, ValueError) as exc:
                report.add("server", False, f"offsets file: {exc}")
                report.status = "Status: Error 21"
                return report
            try:
                status = self.supervisor.start(
                    bind=options.bind, port=options.port,
                    version="5.43",
                    orythm=options.orythm, prythm=options.prythm,
                    response_file=Path(options.response_file)
                    if options.response_file else None,
                    account_manager_startup=options.account_manager_startup,
                    offsets_text=offsets_text,
                )
                report.add("server", True,
                           f"{status.scheme}://{status.bind}:{status.port}",
                           {"bind": status.bind, "port": status.port})
                emit("server", "Status: successfully started emulator")
            except OSError as exc:
                report.add("server", False, f"cannot listen: {exc}")
                report.status = "Status: Error 21"
                return report
        else:
            report.add("server", True, "skipped by options")

        # 9. Target EXE --------------------------------------------------------
        if options.target_exe:
            exists = Path(options.target_exe).is_file()
            report.add("target", exists,
                       str(options.target_exe) if exists else "target exe not found")
            if not exists:
                report.warnings.append(f"target exe not found: {options.target_exe}")
        else:
            report.add("target", True, "no target selected (GUI-only run)")

        if not report.ok:
            report.status = "Status: Error 16"
        elif options.start_server:
            report.status = "Status: successfully started emulator"
        else:
            report.status = "Status: loaded.."
        emit("done", report.status)
        return report

    # -- target launch --------------------------------------------------
    @staticmethod
    def launch_target(target_exe: Path | str,
                      args: Sequence[str] = (),
                      cwd: Path | str | None = None) -> int:
        """Launch the (Windows) target EXE; returns the PID."""
        proc = subprocess.Popen(
            [str(target_exe), *args],
            cwd=str(cwd or Path(target_exe).parent),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        return proc.pid


# ---------------------------------------------------------------------------
# CLI (headless automation without any GUI)
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Account Manager 5.43 local automation (stage drivers/DLLs, "
                    "patch device names, run the mapper ladder, prep Game.dll, "
                    "start the emulator)")
    parser.add_argument("--workdir", type=Path, default=Path.cwd() / "am_workdir")
    parser.add_argument("--game-dir", type=Path, default=None)
    parser.add_argument("--server-preset", default="EuroAion", choices=list(SERVER_PRESETS))
    parser.add_argument("--device-name", default="")
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--orythm", default="1")
    parser.add_argument("--prythm", default="2")
    parser.add_argument("--no-account-manager-startup", action="store_true")
    parser.add_argument("--response-file", type=Path, default=None)
    parser.add_argument("--offsets-file", type=Path, default=None)
    parser.add_argument("--apply-hosts", action="store_true")
    parser.add_argument("--hosts-path", type=Path, default=None)
    parser.add_argument("--no-mapping", action="store_true")
    parser.add_argument("--force-simulated-mapping", action="store_true")
    parser.add_argument("--no-gamedll", action="store_true")
    parser.add_argument("--no-server", action="store_true")
    parser.add_argument("--target-exe", type=Path, default=None)
    parser.add_argument("--launch", action="store_true",
                        help="launch --target-exe after a successful run")
    parser.add_argument("--use-winreg", action="store_true")
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    options = AutoOptions(
        workdir=args.workdir, game_dir=args.game_dir,
        server_preset=args.server_preset, device_name_value=args.device_name,
        bind=args.bind, port=args.port, orythm=args.orythm, prythm=args.prythm,
        account_manager_startup=not args.no_account_manager_startup,
        response_file=args.response_file, offsets_file=args.offsets_file,
        apply_hosts=args.apply_hosts, hosts_path=args.hosts_path,
        run_mapping=not args.no_mapping,
        force_simulated_mapping=args.force_simulated_mapping,
        prepare_gamedll=not args.no_gamedll,
        start_server=not args.no_server,
        target_exe=args.target_exe, use_winreg=args.use_winreg,
    )
    flow = AutoFlow()

    def progress(step: str, message: str) -> None:
        if not args.json:
            print(f"[{step}] {message}", flush=True)

    report = flow.run(options, progress)
    if args.json:
        print(json.dumps({
            "ok": report.ok, "status": report.status, "steps": report.steps,
            "hints": report.hints, "warnings": report.warnings,
        }, indent=2))
    else:
        print(report.status)
        for warning in report.warnings:
            print(f"warning: {warning}")
    if args.launch and options.target_exe:
        if not report.ok:
            print("not launching: automation reported errors", file=sys.stderr)
            return 1
        pid = AutoFlow.launch_target(options.target_exe)
        print(f"launched target pid={pid}")
    # Keep the server alive for interactive CLI use unless --json (one-shot).
    if options.start_server and flow.supervisor.running and not args.json and not args.launch:
        print("emulator running — press Ctrl+C to stop")
        try:
            import time
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            pass
        finally:
            flow.supervisor.stop()
    return 0 if report.ok else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
