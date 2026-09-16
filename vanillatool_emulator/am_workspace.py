"""Workspace recovery for the Account Manager automatic build.

The original Account Manager keeps three kinds of local state:

1. helper binaries it ``FileInstall``\\ s next to itself / into ``%TEMP%``
   (``udk.bin``, ``udk_1.dll``, ``udk_2.bin``, ``spk.exe``, ``lr.exe``,
   ``SR.exe``, ``BBQ.bin``, ...),
2. the ``HKCU\\Software\\Para's NoAnimation`` settings hive,
3. ``logins.ini`` next to the exe (accounts + delay table).

This module recovers all three into a single, explicit, cross-platform
workspace directory (default ``.am_workspace/`` in the repository root)
instead of scattering files across ``%TEMP%``/registry:

* decoded payloads from ``analysis/embedded_files/AM/*.dec`` are copied to
  ``<workspace>/bin/<runtime name>`` with size verification,
* the victim-driver device slots in the ``udk_2.bin`` *copy* are patched to
  the configured 11-char device name (the pristine ``.dec`` is never touched),
* hive settings live in ``<workspace>/settings.json`` (on Windows the tool can
  optionally mirror them into the real registry, read-only by default),
* ``logins.ini`` lives in ``<workspace>/logins.ini`` with the full delay
  table pre-filled.

Nothing here loads drivers, writes process memory, or touches the game
installation.  It only stages *copies* for inspection and for the emulated
mapper ladder.
"""

from __future__ import annotations

import configparser
import hashlib
import json
import random
import shutil
import string
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import am_config as C
from .mapper import (
    DEFAULT_NAME_LENGTH,
    device_name as _read_device_name,
    patch_device_names,
    read_device_slots,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
EMBEDDED_AM = REPO_ROOT / "analysis" / "embedded_files" / "AM"
DEFAULT_WORKSPACE = REPO_ROOT / ".am_workspace"


def random_device_name(length: int = DEFAULT_NAME_LENGTH, seed: int | None = None) -> str:
    """Generate an 11-char A-Za-z device name like the original's default."""
    rng = random.Random(seed) if seed is not None else random.SystemRandom()
    alphabet = string.ascii_letters
    return "".join(rng.choice(alphabet) for _ in range(length))


def validate_device_name(name: str) -> str:
    name = (name or "").strip()
    if len(name) != DEFAULT_NAME_LENGTH:
        raise ValueError(f"device name must be exactly {DEFAULT_NAME_LENGTH} characters")
    if not name.isalpha() or not name.isascii():
        raise ValueError("device name must be ASCII letters only (A-Za-z)")
    return name


@dataclass
class WorkspaceFile:
    source: str
    runtime: str
    path: str
    size: int
    sha256: str
    role: str
    renamed_by: str | None = None


@dataclass
class Workspace:
    root: Path
    bin_dir: Path
    files: list[WorkspaceFile] = field(default_factory=list)
    settings: dict[str, str] = field(default_factory=dict)
    settings_path: Path | None = None
    logins_path: Path | None = None
    driver_before: tuple[str, str] | None = None
    driver_after: tuple[str, str] | None = None
    device_name_value: str = ""
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "root": str(self.root),
            "bin_dir": str(self.bin_dir),
            "files": [f.__dict__ for f in self.files],
            "settings_path": str(self.settings_path) if self.settings_path else "",
            "logins_path": str(self.logins_path) if self.logins_path else "",
            "driver_before": list(self.driver_before) if self.driver_before else [],
            "driver_after": list(self.driver_after) if self.driver_after else [],
            "device_name": self.device_name_value,
            "settings": self.settings,
            "notes": self.notes,
        }


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_settings_file(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(raw, dict):
        return {}
    return {str(k): str(v) for k, v in raw.items()}


def save_settings_file(path: Path, settings: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(settings, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def ensure_device_name(settings: dict[str, str], seed: int | None = None) -> tuple[dict[str, str], bool]:
    """Fill ``fHide_UDK`` with a random 11-char default when missing.

    Returns the (possibly new) settings dict and whether it was generated.
    """
    current = (settings.get("fHide_UDK") or "").strip()
    if len(current) == DEFAULT_NAME_LENGTH and current.isalpha():
        return settings, False
    updated = dict(settings)
    updated["fHide_UDK"] = random_device_name(seed=seed)
    return updated, True


def build_default_logins(delays: dict[str, int] | None = None) -> configparser.ConfigParser:
    """Create a ``logins.ini`` skeleton with the full delay table."""
    parser = configparser.ConfigParser()
    # Preserve key case exactly (original keys are case-sensitive).
    parser.optionxform = str  # type: ignore[method-assign]
    parser["Main"] = {"Accounts": "0", "Hidden": "0"}
    parser["Delay"] = {key: str(value) for key, value in (delays or C.DELAY_DEFAULTS).items()}
    for section in ("Account", "Password", "NCAccount", "NCMultiAccount",
                    "GFAccount", "GameAccount", "Client", "Notes", "LoginAll",
                    "Anonify", "Anonify_Nova", "Characternames"):
        parser[section] = {}
    return parser


def read_logins(path: Path) -> configparser.ConfigParser:
    parser = configparser.ConfigParser()
    parser.optionxform = str  # type: ignore[method-assign]
    if path.is_file():
        parser.read(path, encoding="utf-8")
    return parser


def write_logins(path: Path, parser: configparser.ConfigParser) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        parser.write(fh)


def list_accounts(parser: configparser.ConfigParser) -> list[dict[str, str]]:
    """Return per-slot account rows (slot ids are the ini keys)."""
    slots: set[str] = set()
    for section in C.PER_ACCOUNT_SECTIONS:
        if parser.has_section(section):
            slots.update(parser[section].keys())
    rows: list[dict[str, str]] = []
    for slot in sorted(slots, key=lambda s: (len(s), s)):
        row: dict[str, str] = {"slot": slot}
        for section in C.PER_ACCOUNT_SECTIONS:
            if parser.has_section(section):
                row[section] = parser[section].get(slot, "")
            else:
                row[section] = ""
        rows.append(row)
    return rows


def prepare_workspace(
    root: Path | str = DEFAULT_WORKSPACE,
    *,
    settings: dict[str, str] | None = None,
    delays: dict[str, int] | None = None,
    device_seed: int | None = None,
    ensure_logins: bool = True,
) -> Workspace:
    """Recover every local Account Manager file into ``root``.

    Steps:

    1. copy each ``*.dec`` payload to ``bin/<runtime name>`` (honouring
       ``fHide_*`` renames for helpers that support them),
    2. patch the ``udk_2.bin`` *copy's* device slots to the device name,
    3. write ``settings.json`` (hive mirror) and ``logins.ini`` skeleton.
    """
    root = Path(root)
    bin_dir = root / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)

    merged_settings = dict(C.HIVE_DEFAULTS)
    merged_settings.update(settings or {})
    merged_settings, generated = ensure_device_name(merged_settings, seed=device_seed)
    device = validate_device_name(merged_settings["fHide_UDK"])

    if not EMBEDDED_AM.is_dir():
        raise FileNotFoundError(f"embedded payloads not found: {EMBEDDED_AM}")

    ws = Workspace(root=root, bin_dir=bin_dir, settings=merged_settings,
                   device_name_value=device)
    if generated:
        ws.notes.append(f"generated random device name fHide_UDK={device}")

    for entry in C.LOCAL_FILES:
        src = EMBEDDED_AM / entry.source
        if not src.is_file():
            if entry.required:
                raise FileNotFoundError(f"missing required payload: {src}")
            ws.notes.append(f"optional payload missing, skipped: {entry.source}")
            continue
        data = src.read_bytes()
        expected = C.EXPECTED_SIZES.get(entry.source)
        if expected is not None and len(data) != expected:
            raise ValueError(
                f"{entry.source} size {len(data)} != expected {expected}; "
                "payload set does not match the analysed build"
            )
        runtime = entry.runtime
        renamed_by = None
        if entry.hide_key and merged_settings.get(entry.hide_key):
            candidate = merged_settings[entry.hide_key].strip()
            if candidate and candidate != runtime:
                # Keep it a bare filename (no directories / traversal).
                candidate = Path(candidate).name
                if candidate:
                    runtime = candidate
                    renamed_by = entry.hide_key
        dest = bin_dir / runtime
        # Patch the victim-driver copy's device slots; everything else is a
        # straight copy.
        if entry.runtime == "udk_2.bin":
            ws.driver_before = read_device_slots(data)
            data = patch_device_names(data, device)
            ws.driver_after = read_device_slots(data)
        dest.write_bytes(data)
        ws.files.append(WorkspaceFile(
            source=entry.source, runtime=runtime, path=str(dest),
            size=len(data), sha256=_sha256(data), role=entry.role,
            renamed_by=renamed_by,
        ))

    # Icons (non-critical cosmetics).
    icons_dir = bin_dir / "flags"
    for icon in C.ICON_FILES:
        src = EMBEDDED_AM / icon
        if src.is_file():
            dest = icons_dir / Path(icon).stem
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, dest)

    settings_path = root / "settings.json"
    save_settings_file(settings_path, merged_settings)
    ws.settings_path = settings_path

    logins_path = root / "logins.ini"
    if ensure_logins and not logins_path.is_file():
        write_logins(logins_path, build_default_logins(delays or C.DELAY_DEFAULTS))
        ws.notes.append("created logins.ini skeleton with full delay table")
    elif logins_path.is_file():
        # Backfill any missing delay keys so old files stay complete.
        parser = read_logins(logins_path)
        if not parser.has_section("Delay"):
            parser["Delay"] = {}
        missing = {k: str(v) for k, v in (delays or C.DELAY_DEFAULTS).items()
                   if k not in parser["Delay"]}
        if missing:
            for k, v in missing.items():
                parser["Delay"][k] = v
            write_logins(logins_path, parser)
            ws.notes.append(f"backfilled {len(missing)} missing delay key(s)")
    ws.logins_path = logins_path
    return ws


def describe_target(path: str | Path) -> dict[str, Any]:
    """Read-only audit of a target executable (never launches it)."""
    info: dict[str, Any] = {"path": str(path), "exists": False}
    p = Path(path) if str(path) else Path()
    if not str(path):
        info["error"] = "no target configured"
        return info
    info["exists"] = p.is_file()
    if not p.is_file():
        info["error"] = "file not found"
        return info
    try:
        size = p.stat().st_size
        info["size"] = size
        with p.open("rb") as fh:
            header = fh.read(4)
        info["mz_header"] = header[:2] == b"MZ"
        info["is_pe"] = header[:2] == b"MZ"
        # bin64 layout hints (aion.bin lives in <game>/bin64/).
        parent = p.parent
        info["parent_dir"] = str(parent)
        info["looks_like_bin64"] = parent.name.lower() == "bin64"
        game_root = parent.parent if info["looks_like_bin64"] else parent
        pak = game_root / C.WORLD_PAK.replace("/", str(Path().joinpath("x").parent)[0:0] or "/")
        # Normalise the pak path portably.
        pak = game_root.joinpath(*C.WORLD_PAK.split("/"))
        info["world_pak_present"] = pak.is_file()
        info["game_root_guess"] = str(game_root)
    except OSError as exc:
        info["error"] = str(exc)
    return info


def scan_ncguard_strings(path: str | Path, *, max_hits: int = 20) -> dict[str, Any]:
    """Scan a target file for NCGuard/Game.dll markers (read-only).

    The original *rewrites* these strings in process memory.  This tool only
    reports byte offsets so a lab operator can see what the original would do.
    """
    result: dict[str, Any] = {"path": str(path), "hits": [], "truncated": False}
    p = Path(path)
    if not p.is_file():
        result["error"] = "file not found"
        return result
    try:
        data = p.read_bytes()
    except OSError as exc:
        result["error"] = str(exc)
        return result
    if len(data) > 64 * 1024 * 1024:
        result["error"] = "file too large to scan (>64MiB)"
        return result
    for marker in (b"NCGuard.dll", b"NCGuard", b"Game.dll"):
        start = 0
        while len(result["hits"]) < max_hits:
            idx = data.find(marker, start)
            if idx < 0:
                break
            result["hits"].append({"marker": marker.decode("ascii"), "offset": idx,
                                   "offset_hex": hex(idx)})
            start = idx + 1
        if len(result["hits"]) >= max_hits:
            result["truncated"] = True
            break
    result["size"] = len(data)
    result["note"] = ("read-only audit: the lab build never patches these bytes; "
                      "offsets are reported for inspection only")
    return result


def read_device_name_of_copy(driver_copy: Path) -> str:
    return _read_device_name(driver_copy.read_bytes())
