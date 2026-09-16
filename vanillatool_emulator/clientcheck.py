"""Game-client compatibility check for Account Manager's memory patches.

Account Manager 5.43 never checks which game build it patches — it blindly
writes ``b"Game.dll"`` over two ``CHAR[128]`` module-name slots in the
running client (``aion.bin+0x863F8``, ``CrySystem.dll+0x21A2DB``, recovered
from ``NCGuardRedirect_v2``).  On the client build those numbers were taken
from, the slots hold the ``NCGuard.dll`` module-name string and the
NCGuard redirect works; on any other build the write lands elsewhere and
the bypass fails (or the client crashes).

This module answers that question *before* anything is launched: it reads
the installed client's binaries, converts the script's RVAs to file
offsets through the real section table, and classifies what the slots
actually contain::

    python -m vanillatool_emulator.clientcheck --game-dir "D:\\EuroAion"

Per-server bypass names (from the resolved script's server table): EuroAion,
Destiny, GamezAion and Elden Aion use the ``Game.dll`` redirect, Aion
America keeps ``NCGuard.dll``.  EuroAion additionally owns the only
per-server effects flag (``EuroAion_AnimationEffects`` in ``logins.ini``).

Stdlib-only, read-only (never writes to the client), headless-safe.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path
from typing import Any

from . import local as L

# Script RVAs (NCGuardRedirect_v2, resolved line 639/646-647).
AION_BIN_SLOT_RVA = L.AION_BIN_NCGUARD_OFFSET       # 549880 / 0x863F8
CRYSYSTEM_SLOT_RVA = L.CRYSYSTEM_NCGUARD_OFFSET     # 2204379 / 0x21A2DB
SLOT_SIZE = L.NCGUARD_SLOT_SIZE                     # 128
REPLACEMENT = L.NCGUARD_REPLACEMENT                 # b"Game.dll"

#: Bypass dll staged per server (resolved script, server table).  Servers
#: without an explicit entry are assumed to use the Game.dll redirect.
SERVER_BYPASS_DLLS: dict[str, str] = {
    "EuroAion": "Game.dll",
    "Aion America": "NCGuard.dll",
    "Destiny": "Game.dll",
    "GamezAion": "Game.dll",
    "Elden Aion": "Game.dll",
}

_MZ = b"MZ"
_PE = b"PE\x00\x00"
_IMAGE_FILE_MACHINE_AMD64 = 0x8664


class PEError(ValueError):
    """The file is not a parseable PE image."""


# ---------------------------------------------------------------------------
# Minimal PE reader (section table + machine + timestamp; stdlib only)
# ---------------------------------------------------------------------------


def parse_pe(path: Path) -> dict[str, Any]:
    """Return machine/timestamp/sections for a PE file.  Raises PEError."""
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise PEError(f"cannot read {path}: {exc}") from exc
    if len(data) < 0x40 or data[:2] != _MZ:
        raise PEError(f"{path.name}: no MZ header")
    (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
    if e_lfanew + 6 > len(data) or data[e_lfanew:e_lfanew + 4] != _PE:
        raise PEError(f"{path.name}: no PE signature at 0x{e_lfanew:X}")
    coff = e_lfanew + 4
    machine, n_sections, timestamp, _, _, opt_size, _ = struct.unpack_from(
        "<HHIIIHH", data, coff)
    sections: list[dict[str, Any]] = []
    off = coff + 20 + opt_size
    for _ in range(n_sections):
        if off + 40 > len(data):
            raise PEError(f"{path.name}: section table truncated")
        name = data[off:off + 8].rstrip(b"\x00").decode("ascii", "replace")
        vsize, vaddr, rawsz, rawptr = struct.unpack_from("<IIII", data, off + 8)
        sections.append({"name": name or "?", "vaddr": vaddr, "vsize": vsize,
                         "rawsz": rawsz, "rawptr": rawptr})
        off += 40
    return {"machine": machine, "timestamp": timestamp, "sections": sections,
            "size": len(data)}


def rva_to_raw(sections: list[dict[str, Any]], rva: int) -> int | None:
    """Convert an RVA to a file offset via the section table."""
    for section in sections:
        span = max(section["vsize"], section["rawsz"])
        if section["vaddr"] <= rva < section["vaddr"] + span:
            raw = section["rawptr"] + (rva - section["vaddr"])
            if raw < section["rawptr"] + section["rawsz"]:
                return raw
            return None  # in a BSS-style tail: no file bytes
    return None


def fingerprint(path: Path) -> dict[str, Any]:
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
        return {"size": path.stat().st_size,
                "sha256": digest.hexdigest(),
                "sha256_short": digest.hexdigest()[:16]}
    except OSError as exc:
        return {"size": -1, "error": str(exc)}


# ---------------------------------------------------------------------------
# Slot classification
# ---------------------------------------------------------------------------


def read_slot(path: Path, rva: int, size: int = SLOT_SIZE) -> dict[str, Any]:
    """Read the CHAR slot the script patches, via RVA or raw fallback."""
    info: dict[str, Any] = {"rva": rva, "via": "unmapped",
                            "raw_offset": None, "data": b"", "text": ""}
    try:
        pe = parse_pe(path)
    except PEError as exc:
        info["error"] = str(exc)
        return info
    raw = rva_to_raw(pe["sections"], rva)
    data = path.read_bytes()
    if raw is not None and raw + 1 <= len(data):
        info["via"] = "rva"
        info["raw_offset"] = raw
    elif rva + 1 <= len(data):
        # Fallback: treat the literal as a file offset (some builders log
        # raw offsets); the verdict always prefers the RVA mapping.
        raw = rva
        info["via"] = "raw-fallback"
        info["raw_offset"] = raw
    else:
        info["error"] = f"RVA 0x{rva:X} outside all sections and file size"
        return info
    blob = data[raw:raw + size]
    info["data"] = blob
    info["text"] = blob.split(b"\x00", 1)[0].decode("ascii", "replace")
    return info


def classify_slot(slot: dict[str, Any],
                  replacement: bytes = REPLACEMENT) -> tuple[str, str]:
    """Verdict for one slot: ``(ok|warn|fail, detail)``."""
    if slot.get("error"):
        return "fail", str(slot["error"])
    if not slot["data"]:
        return "fail", "slot unreadable"
    text: str = slot["text"]
    blob: bytes = slot["data"]
    printable = sum(32 <= b < 127 or b == 0 for b in blob)
    if printable < len(blob) * 0.9:
        return ("fail",
                f"slot holds binary data, not a module-name string "
                f"(via {slot['via']}, off 0x{slot['raw_offset']:X}): "
                f"{blob[:24].hex()}… — offsets do not match this client build")
    if "ncguard" in text.lower():
        return ("ok",
                f"{text!r} (via {slot['via']}, off 0x{slot['raw_offset']:X}) — "
                "the redirect will hit the NCGuard module-name string")
    if text.encode("ascii", "replace") == replacement:
        return ("warn",
                f"slot already contains {text!r} — a previous patch may "
                "still be in place (file-level, not memory)")
    return ("warn",
            f"slot holds {text!r} (via {slot['via']}, "
            f"off 0x{slot['raw_offset']:X}) — not the NCGuard string; "
            "the redirect target differs on this build")


# ---------------------------------------------------------------------------
# Client location
# ---------------------------------------------------------------------------


def detect_game_dir() -> Path | None:
    """Find the client via the plaync registry keys (Windows only)."""
    if not sys.platform.startswith("win"):
        return None
    try:
        import winreg
    except ImportError:
        return None
    for subkey, value in (r"Software\Wow6432Node\plaync\AION", "BaseDir"), \
                        (r"Software\Wow6432Node\plaync\AION_CLASSIC", "BaseDir"):
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey) as key:
                basedir, _ = winreg.QueryValueEx(key, value)
            candidate = Path(str(basedir))
            if (candidate / "bin64" / "aion.bin").is_file():
                return candidate
        except OSError:
            continue
    return None


# ---------------------------------------------------------------------------
# Report (same shape as driver.py / interop.py)
# ---------------------------------------------------------------------------


def check_client(game_dir: Path | str | None, server: str = "EuroAion",
                 slot_rvas: tuple[int, int] | None = None) -> dict[str, Any]:
    """Read-only compatibility verdict for the installed client.

    ``slot_rvas`` overrides ``(aion, crysystem)`` RVAs — test hook so unit
    tests can use tiny fake binaries instead of multi-MB images.
    """
    report: dict[str, Any] = {"command": "clientcheck", "ok": True,
                              "status": "", "checks": [], "warnings": [],
                              "extra": {"server": server}}
    rva_aion, rva_cry = slot_rvas or (AION_BIN_SLOT_RVA, CRYSYSTEM_SLOT_RVA)

    def add(name: str, status: str, detail: str = "",
            remediation: str = "") -> None:
        report["checks"].append({"name": name, "status": status,
                                 "detail": detail, "remediation": remediation})
        if status == "fail":
            report["ok"] = False

    if game_dir is None:
        found = detect_game_dir()
        if found is None:
            add("game-dir", "fail", "no client found",
                "pass --game-dir pointing at the installed client folder")
            report["status"] = "Status: Error 14"
            return report
        game_dir = found
    root = Path(game_dir)
    bin64 = root / "bin64"
    aion = bin64 / "aion.bin"
    cry = bin64 / "CrySystem.dll"
    missing = [str(p) for p in (aion, cry) if not p.is_file()]
    if missing:
        add("files", "fail", f"missing: {', '.join(missing)}",
            "point --game-dir at the client root (the folder holding bin64/)")
        report["status"] = "Status: Error 14"
        return report
    report["extra"]["game_dir"] = str(root)
    report["extra"]["fingerprint"] = {name: fingerprint(path) for name, path in
                                      (("aion.bin", aion), ("CrySystem.dll", cry))}
    add("files", "ok",
        f"aion.bin ({report['extra']['fingerprint']['aion.bin']['size']} B) + "
        f"CrySystem.dll ({report['extra']['fingerprint']['CrySystem.dll']['size']} B)")

    # Architecture: AM drives bin64; a 32-bit image cannot match the offsets.
    try:
        machine = parse_pe(aion)["machine"]
    except PEError as exc:
        add("arch", "fail", str(exc))
        report["status"] = "Status: Error 16"
        return report
    if machine == _IMAGE_FILE_MACHINE_AMD64:
        add("arch", "ok", "aion.bin is x64 (bin64 build, as AM expects)")
    else:
        add("arch", "warn", f"machine=0x{machine:04X}, not x64",
            "use the 64-bit client (EuroAion launcher: 64bit), the offsets "
            "were recovered for the bin64 build")
        report["warnings"].append("32-bit client: slot RVAs very likely differ")

    # The two slots the original EXE overwrites in memory.
    for label, path, rva in (("slot:aion.bin", aion, rva_aion),
                             ("slot:CrySystem.dll", cry, rva_cry)):
        slot = read_slot(path, rva)
        status, detail = classify_slot(slot)
        add(label, status, detail,
            "" if status == "ok" else
            "this client build differs from the one AM 5.43 targets; the "
            "NCGuard redirect needs re-located offsets for this build")

    # Server bypass selection (informational).
    bypass = SERVER_BYPASS_DLLS.get(server)
    if bypass is None:
        add("server-dll", "warn",
            f"{server} has no explicit entry — assuming Game.dll redirect",
            "if the bypass misbehaves on this server, its entry is the "
            "suspect")
        report["extra"]["bypass_dll"] = "Game.dll (assumed)"
    else:
        note = "" if bypass == "Game.dll" else \
            " (keeps the original name — no string redirect for this server)"
        add("server-dll", "ok", f"{server} -> {bypass}{note}")
        report["extra"]["bypass_dll"] = bypass
        if server == "EuroAion":
            report["extra"]["effects_flag"] = "EuroAion_AnimationEffects"

    if not report["ok"]:
        report["status"] = "Status: Error 16"
    elif any(c["status"] == "warn" for c in report["checks"]):
        report["status"] = "Status: client uncertain — review warnings"
    else:
        report["status"] = "Status: client matches — patch will land"
    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Check the installed Aion client against Account "
                    "Manager 5.43's hardcoded NCGuard patch slots (read-only)")
    parser.add_argument("--game-dir", type=Path, default=None,
                        help="client root (folder holding bin64/); if omitted, "
                             "auto-detect via the plaync registry keys")
    parser.add_argument("--server", default="EuroAion",
                        help="server preset for the bypass-dll lookup")
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = check_client(args.game_dir, args.server)
    if args.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        print(report["status"])
        for check in report["checks"]:
            mark = {"ok": "OK  ", "fail": "FAIL", "warn": "WARN",
                    "skip": "SKIP"}[check["status"]]
            print(f"[{mark}] {check['name']}: {check['detail']}")
            if check["remediation"]:
                print(f"       -> {check['remediation']}")
        for warning in report.get("warnings", []):
            print(f"warning: {warning}")
    return 0 if report["ok"] else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
