"""Shared configuration for the Account Manager automatic GUI/pipeline.

This module centralises every Account Manager 5.43 option that the
automatic replacement needs to mirror:

* server/client presets (the login dropdown values),
* the ``HKCU\\Software\\Para's NoAnimation`` hive keys and their defaults,
* the ``logins.ini`` sections/keys the original reads,
* the delay-table defaults from the resolved script,
* the local-file map (``analysis/embedded_files/AM/*.dec`` -> runtime name).

All values here are recovered from ``analysis/AccountManager_5.43_resolved.au3``
and the decoded payload set.  Nothing here performs privileged work; it is a
pure data + validation layer used by the workspace preparer, the automatic
pipeline and both GUIs (desktop Tk and browser).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Identity / versions
# ---------------------------------------------------------------------------

APP_NAME = "Para's Account Manager - Automatic Lab"
APP_VERSION = "5.43-auto1"
EMULATOR_VERSION_DEFAULT = "11.31"
RESOURCE_VERSION_DEFAULT = "0.10"

HIVE_PATH = r"HKEY_CURRENT_USER\Software\Para's NoAnimation"

# ---------------------------------------------------------------------------
# Server / client presets
# ---------------------------------------------------------------------------

# Dropdown order from the resolved script:
#   "EuroAion|Aion America|Destiny|GamezAion|Elden Aion"  (+ NOVA / retail)
SERVERS: tuple[str, ...] = (
    "Aion NA",
    "Aion EU",
    "NA Classic",
    "EU Classic",
    "EuroAion",
    "Aion America",
    "Destiny",
    "GamezAion",
    "Aion Nova",
    "Elden Aion",
)

# Registry discovery roots used by the original (read-only in this tool).
REGISTRY_CLIENT_KEYS: tuple[tuple[str, str], ...] = (
    (r"HKEY_LOCAL_MACHINE\Software\Wow6432Node\plaync\AION", "BaseDir"),
    (r"HKEY_LOCAL_MACHINE\Software\Wow6432Node\plaync\AION_CLASSIC", "BaseDir"),
    (r"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\plaync\Purple", "BaseDir"),
)

BIN64_AION = "bin64/aion.bin"
WORLD_PAK = "Data/World/x_World.pak"

# ---------------------------------------------------------------------------
# Hive settings (HKCU mirror) and GUI checkboxes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HiveOption:
    """One persisted setting and its GUI presentation."""

    key: str
    label: str
    default: str
    kind: str = "bool"  # "bool" | "text" | "int"
    tooltip: str = ""


# Checkbox labels are the original "[ ] ..." strings (without the box).
HIVE_OPTIONS: tuple[HiveOption, ...] = (
    HiveOption("AutoInject", "Auto Inject Vanillatool", "False",
               tooltip="Original: auto-inject Vanillatool after NCGuard redirect. "
                       "Lab build: reports the inject plan only, never injects."),
    HiveOption("VirtualClient", "Create Virtual Clients", "False",
               tooltip="Create virtual-client copies of the game folder."),
    HiveOption("AMInstaScriptSilent", "Use InstaScript (silent)", "False"),
    HiveOption("AMAionClientSilent", "Hide Aion Client", "False"),
    HiveOption("AMCrashedClients", "Auto restart crashed clients", "False"),
    HiveOption("Anonify", "Anonify Login", "False"),
    HiveOption("RandomizeMAC", "Randomize MAC", "False"),
    HiveOption("Compatibility", "Use Compatibility mode", "False"),
    HiveOption("AMUnlimiter", "Use integrated UnLimiter", "False"),
    HiveOption("AMBypass", "Bypass Launcher ban", "False"),
    HiveOption("AMLogChars", "Log Charnames to Status", "False"),
    HiveOption("BypassBan", "Bypass Ban (alt)", "False"),
    HiveOption("AMStartMethod", "StartMethod flag", "False"),
    HiveOption("AMNotes", "Show Notes column", "True"),
    HiveOption("AMEUPath", "EU path override", "", kind="text"),
    HiveOption("AMLang", "Client language", "ENG", kind="text"),
    HiveOption("LastUsed", "Last used Vanillatool exe", "", kind="text"),
    HiveOption("AMLoginAllDelay", "Login All Delay (ms)", "3000", kind="int"),
    HiveOption("AMInstaScriptDelay", "InstaScript Delay (ms)", "1500", kind="int"),
    HiveOption("LoginAllCap", "Max Clients for Login All", "4", kind="int"),
    HiveOption("VirtualClientSlot", "Virtual Client Slot", "Original", kind="text"),
    HiveOption("fHide_LR", "Helper name: lr.exe", "lr.exe", kind="text"),
    HiveOption("fHide_BBQ", "Helper name: BBQ.bin", "BBQ.bin", kind="text"),
    HiveOption("fHide_GT", "Helper name: GT.exe", "GT.exe", kind="text"),
    HiveOption("fHide_NOVA", "Helper name: Nova.exe", "Nova.exe", kind="text"),
    HiveOption("fHide_MAM", "Helper name: MAM", "", kind="text"),
    HiveOption("fHide_UDK", "Driver device name (11 chars)", "", kind="text",
               tooltip="Random 11-char default is generated on first run, "
                       "exactly like the original."),
)

HIVE_DEFAULTS: dict[str, str] = {opt.key: opt.default for opt in HIVE_OPTIONS}

VIRTUAL_SLOTS: tuple[str, ...] = (
    "Original",
    "Virtual Client [1]", "Virtual Client [2]", "Virtual Client [3]",
    "Virtual Client [4]", "Virtual Client [5]", "Virtual Client [6]",
    "Virtual Client [7]", "Virtual Client [8]", "Virtual Client [9]",
)

# ---------------------------------------------------------------------------
# logins.ini schema
# ---------------------------------------------------------------------------

LOGIN_SECTIONS: tuple[str, ...] = (
    "Main", "Account", "Password", "NCAccount", "NCMultiAccount",
    "GFAccount", "GameAccount", "Client", "Notes", "LoginAll",
    "Delay", "Anonify", "Anonify_Nova", "Characternames",
)

PER_ACCOUNT_SECTIONS: tuple[str, ...] = (
    "Account", "Password", "NCAccount", "NCMultiAccount",
    "GFAccount", "GameAccount", "Client", "Notes", "LoginAll",
)

# Delay defaults recovered from the resolved script's IniRead fallbacks.
# (Only the timing value; the 4th IniRead arg in the original is garbage
# from the decompiler's Execute() folding and is ignored.)
DELAY_DEFAULTS: dict[str, int] = {
    # Gameforge launcher flow
    "GFL_AfterTypeGameAccount": 650,
    "GFL_AfterClickOnSearchAccount": 850,
    "GFL_AfterClickOnAion": 1250,
    "GFL_AfterClickOnAd": 750,
    "GFL_AfterResizing": 1500,
    "GFL_AfterDeMaximizing": 1550,
    "GFL_AfterLauncherAppears": 5550,
    "GFL_AfterGameAccountWindowAppears": 850,
    # Retail login flow
    "AfterLoginLauncherAppears": 3000,
    "BeforePasteEmail": 500,
    "TabFromEmailToPassword": 300,
    "BeforePastePassword": 500,
    "BeforeClickOnLogin": 800,
    "BeforeSelectClient": 800,
    "AfterSelectClient": 1200,
    "LoginLauncherAppearTimeout": 15000,
    "WaitForAionProcess": 15000,
    "WaitForEULA_Retail": 10000,
    "WaitForEULA_Classic": 10000,
    # Purple flow
    "Purple_Startup": 25000,
    "Purple_BeforeClickingAccountList": 1000,
    "Purple_AfterClickingAccountList": 2000,
    "Purple_AfterSwitchAccount": 5000,
    "Purple_BeforeClickStart": 3500,
    "Purple_AfterMultiAccount": 3000,
    "Purple_WaitForAionProcess": 1500,
    "Purple_WaitingForServerSelection": 14000,
    "Purple_ScreenReadTolerance": 1,
    "Purple_AfterMultiPlayCheckboxOn": 1250,
    "Purple_AfterMultiPlayConfirm": 3000,
    "Purple_BeforeMultiStartGame": 500,
    "Purple_AfterClickingAionSection": 4000,
    "Purple_AfterClickingGameTypeBox": 1000,
    "Purple_AfterClickingGameType": 5000,
    "Purple_AfterScrollingDown": 1000,
    # Nova flow
    "Nova_Splash": 0,
}

# ---------------------------------------------------------------------------
# Local-file map: decoded payload -> runtime filename
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LocalFile:
    """One helper file the original drops next to itself / in %TEMP%."""

    source: str  # filename under analysis/embedded_files/AM/
    runtime: str  # filename the original uses at runtime
    role: str
    hide_key: str | None = None  # hive key that can rename it
    required: bool = True


LOCAL_FILES: tuple[LocalFile, ...] = (
    LocalFile("VanillaUDK_3.13.bin.dec", "udk.bin",
              "KDU-style kernel mapper (emulated, never executed for real mapping)"),
    LocalFile("VanillaUDK_3.11.dll.dec", "udk_1.dll",
              "Mapper support library"),
    LocalFile("VanillaDrv_3.13.sys.dec", "udk_2.bin",
              "Victim driver image (device slots patched, never loaded)"),
    LocalFile("SparkMod.exe.dec", "spk.exe",
              "32Bit Writer helper for Gameforge sessions"),
    LocalFile("lr.exe.dec", "lr.exe",
              "Launcher reader helper", hide_key="fHide_LR"),
    LocalFile("SR.exe.dec", "SR.exe",
              "ScreenReader OCR helper for Purple automation"),
    LocalFile("BBQ.bin.dec", "BBQ.bin",
              "BBQ helper", hide_key="fHide_BBQ"),
    LocalFile("GetThreads64.exe.dec", "GetThreads64.exe",
              "Thread enumerator", hide_key="fHide_GT"),
    LocalFile("NovaApi.exe.dec", "Nova.exe",
              "Nova API helper", hide_key="fHide_NOVA"),
    LocalFile("api.dll.dec", "api.dll", "Nova API library"),
    LocalFile("japi.dll.dec", "japi.dll", "Nova API library"),
    LocalFile("msgbox d3d reloader.dll.dec", "msgbox d3d reloader.dll",
              "D3D reloader helper", required=False),
)

ICON_FILES: tuple[str, ...] = (
    "france.jpg.dec", "germany.jpg.dec", "uk.jpg.dec",
    "notes.jpg.dec", "settings.jpg.dec", "switch.jpg.dec",
)

# Expected decoded sizes (integrity check on recovery).
EXPECTED_SIZES: dict[str, int] = {
    "VanillaDrv_3.13.sys.dec": 13312,
    "VanillaUDK_3.13.bin.dec": 525824,
    "VanillaUDK_3.11.dll.dec": 1325568,
    "SparkMod.exe.dec": 1078784,
    "lr.exe.dec": 897024,
    "SR.exe.dec": 1222144,
    "BBQ.bin.dec": 1025536,
    "GetThreads64.exe.dec": 1307136,
    "NovaApi.exe.dec": 11264,
    "api.dll.dec": 30208,
    "japi.dll.dec": 695808,
}

# ---------------------------------------------------------------------------
# Auth / emulator defaults for the automatic run
# ---------------------------------------------------------------------------

AUTH_URL_PATH = "/data/auth.php"
DEFAULT_PRHYTHM = "2"  # smallest value enabling named regions, not expired
DEFAULT_ORYTHM = "1"

# NCGuard redirect audit: string swaps the original performs (reported only).
NCGUARD_SWAPS: tuple[tuple[str, str], ...] = (
    ("NCGuard.dll", "Game.dll"),
)

# Dangerous operations are never performed; these labels document that.
SAFETY_REFUSALS: tuple[str, ...] = (
    "kernel driver loading (udk.bin -map is emulated, never executed)",
    "process memory writing (WriteProcessMemory / NCGuard patching)",
    "DLL injection (LoadLibrary remote / d3dx9 proxy install)",
    "unattended hosts-file or registry writes",
)


@dataclass
class AutomaticOptions:
    """Everything the Automatic Run needs, from GUI or CLI."""

    target_exe: str = ""
    server: str = "EuroAion"
    emulator_host: str = "127.0.0.1"
    emulator_port: int = 8080
    version: str = EMULATOR_VERSION_DEFAULT
    orythm: str = DEFAULT_ORYTHM
    prythm: str = DEFAULT_PRHYTHM
    account_manager_startup: bool = True
    response_file: str = ""
    offsets_file: str = ""
    device_name: str = ""
    missing_providers: str = ""
    login_all: bool = False
    dry_run_launch: bool = True
    allow_hosts_write: bool = False
    settings: dict[str, str] = field(default_factory=dict)
    delays: dict[str, int] = field(default_factory=dict)

    def merged_settings(self) -> dict[str, str]:
        merged = dict(HIVE_DEFAULTS)
        merged.update(self.settings or {})
        return merged

    def merged_delays(self) -> dict[str, int]:
        merged = dict(DELAY_DEFAULTS)
        merged.update(self.delays or {})
        return merged

    def as_dict(self) -> dict[str, Any]:
        return {
            "target_exe": self.target_exe,
            "server": self.server,
            "emulator_host": self.emulator_host,
            "emulator_port": self.emulator_port,
            "version": self.version,
            "orythm": self.orythm,
            "prythm": self.prythm,
            "account_manager_startup": self.account_manager_startup,
            "response_file": self.response_file,
            "offsets_file": self.offsets_file,
            "device_name": self.device_name,
            "missing_providers": self.missing_providers,
            "login_all": self.login_all,
            "dry_run_launch": self.dry_run_launch,
            "allow_hosts_write": self.allow_hosts_write,
            "settings": self.merged_settings(),
            "delays": self.merged_delays(),
        }
