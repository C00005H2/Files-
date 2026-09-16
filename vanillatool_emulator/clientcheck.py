"""Game-client compatibility check for Account Manager's memory patches.

Account Manager 5.43 never checks which game build it patches — it blindly
writes ``b"Game.dll"`` over two ``CHAR[128]`` module-name slots in the
**running** client (``aion.bin+0x863F8``, ``CrySystem.dll+0x21A2DB``,
recovered from ``NCGuardRedirect_v2``).  On the client build those numbers
were taken from, the slots hold the ``NCGuard.dll`` module-name string and
the NCGuard redirect works; on any other build the write lands elsewhere.

Two modes (both read-only, never modify the client):

* static (default) — parses the installed binaries' PE section tables and
  reads the slots from the files.  Decisive for unpacked binaries, but
  packed clients (packer section table, compressed bytes) are honestly
  reported as *inconclusive* instead of failed::

    python -m vanillatool_emulator.clientcheck --game-dir "D:\\EuroAion"

* live (``--live``, Windows-only) — starts from a running client and reads
  the slots from process memory with ``ReadProcessMemory``, i.e. the exact
  address space Account Manager patches.  This is the definitive verdict
  for packed clients::

    python -m vanillatool_emulator.clientcheck --live --process aion.bin

Per-server bypass names (from the resolved script's server table): EuroAion,
Destiny, GamezAion and Elden Aion use the ``Game.dll`` redirect, Aion
America keeps ``NCGuard.dll``.  EuroAion additionally owns the only
per-server effects flag (``EuroAion_AnimationEffects`` in ``logins.ini``).

Stdlib-only, headless-safe.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from collections import Counter
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

#: Section names that betray a packer/protector (static reads untrustworthy).
PACKER_SECTION_HINTS = frozenset({
    ".themida", "themida", ".vmp", "vmp0", "vmp1", ".vmp1", ".vmp2",
    ".upx0", ".upx1", "upx0", "upx1", ".enigma", "enigma1", "enigma2",
    ".aspack", "aspack", ".ccg", ".securom", ".svkp", ".sforce",
    ".mpress", ".mpress1", ".mpress2", ".nsp0", ".nsp1", ".rmnet",
    ".taz", ".wwpack", ".pklite", ".petite",
})

_MZ = b"MZ"
_PE = b"PE\x00\x00"
_IMAGE_FILE_MACHINE_AMD64 = 0x8664
_SCAN_NEEDLES = (b"NCGuard.dll", b"Game.dll")


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


def raw_to_rva(sections: list[dict[str, Any]], raw: int) -> int | None:
    """Convert a file offset back to an RVA via the section table."""
    for section in sections:
        if section["rawptr"] <= raw < section["rawptr"] + section["rawsz"]:
            return section["vaddr"] + (raw - section["rawptr"])
    return None


def packer_indicators(pe: dict[str, Any]) -> list[str]:
    """Section names that suggest a packer/protector (possibly empty)."""
    hits = []
    for section in pe["sections"]:
        name = str(section["name"]).lower()
        if name in PACKER_SECTION_HINTS or name.startswith(
                (".vmp", "upx", ".themida", ".enigma", ".mpress")):
            hits.append(str(section["name"]))
    return hits


def _entropy(data: bytes) -> float:
    import math

    counts = Counter(data)
    total = len(data)
    return -sum(n / total * math.log2(n / total) for n in counts.values())


def image_entropy(path: Path, sample: int = 65536) -> float:
    """Shannon entropy of the first ``sample`` bytes (-1.0 on error)."""
    try:
        with open(path, "rb") as handle:
            data = handle.read(sample)
    except OSError:
        return -1.0
    return _entropy(data) if data else 0.0


def scan_bytes(path: Path, needles: tuple[bytes, ...] = _SCAN_NEEDLES,
               cap: int = 25) -> dict[str, Any]:
    """Locate interesting strings anywhere in the file (diagnostic)."""
    try:
        data = path.read_bytes()
    except OSError as exc:
        return {"error": str(exc)}
    out: dict[str, Any] = {}
    for needle in needles:
        offsets: list[int] = []
        start = 0
        while len(offsets) < cap:
            found = data.find(needle, start)
            if found < 0:
                break
            offsets.append(found)
            start = found + 1
        out[needle.decode("ascii")] = offsets
    return out


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


def _printable_ratio(blob: bytes) -> float:
    if not blob:
        return 0.0
    return sum(32 <= b < 127 or b == 0 for b in blob) / len(blob)


def classify_slot(slot: dict[str, Any],
                  replacement: bytes = REPLACEMENT) -> tuple[str, str]:
    """Verdict for one slot: ``(ok|warn|fail, detail)``.

    ``via == "rva"`` (static, section-mapped) and ``via == "live"``
    (process memory) are authoritative: binary content there is a true
    mismatch.  Anything else (raw fallback, unmapped) is *inconclusive* —
    the script's number is not covered by this image's section table, as
    happens with packed binaries and stub launchers.
    """
    if slot.get("error"):
        return "fail", str(slot["error"])
    if not slot.get("data"):
        return "fail", "slot unreadable"
    if slot.get("via") not in ("rva", "live"):
        blob: bytes = slot.get("data", b"")
        if _printable_ratio(blob) >= 0.9:
            hint = f"ASCII {slot.get('text', '')[:48]!r}"
        else:
            hint = f"binary {blob[:16].hex()}…"
        return ("warn",
                f"RVA 0x{slot['rva']:X} is outside this image's section "
                f"table — static read inconclusive (packed binary or stub "
                f"launcher?); raw-offset bytes: {hint}. Use --live on the "
                f"running client for the definitive verdict")
    text: str = slot.get("text", "")
    blob = slot.get("data", b"")
    where = (f"(via {slot['via']}, "
             f"{'base+0x%X' % slot['rva'] if slot['via'] == 'live' else 'off 0x%X' % slot.get('raw_offset', 0)})")
    if _printable_ratio(blob) < 0.9:
        return ("fail",
                f"slot holds binary data, not a module-name string {where}: "
                f"{blob[:24].hex()}… — offsets do not match this client build")
    if "ncguard" in text.lower():
        return ("ok",
                f"{text!r} {where} — "
                "the redirect will hit the NCGuard module-name string")
    if text.encode("ascii", "replace") == replacement:
        return ("warn",
                f"slot already contains {text!r} — a previous patch may "
                "still be in place (file-level, not memory)")
    return ("warn",
            f"slot holds {text!r} {where} — not the NCGuard string; "
            "the redirect target differs on this build")


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
        raw = rva
        info["via"] = "raw-fallback"
        info["raw_offset"] = raw
    else:
        info["error"] = (f"RVA 0x{rva:X} is outside all sections and the "
                         f"file ({len(data)} bytes)")
        return info
    blob = data[raw:raw + size]
    info["data"] = blob
    info["text"] = blob.split(b"\x00", 1)[0].decode("ascii", "replace")
    return info


# ---------------------------------------------------------------------------
# Live mode (Windows-only): read the running client's memory like AM does
# ---------------------------------------------------------------------------


def _win() -> Any | None:
    if not sys.platform.startswith("win"):
        return None
    try:
        import ctypes
        from ctypes import wintypes

        return ctypes, wintypes
    except ImportError:
        return None


def enable_debug_privilege() -> tuple[bool, str]:
    """Enable SeDebugPrivilege for this process (best effort, never raises).

    4.6-era GameGuard often permits memory reads from processes holding the
    debug privilege; without it even elevated readers get code 5.
    """
    mods = _win()
    if mods is None:
        return False, "windows-only"
    ctypes, wintypes = mods
    try:
        advapi32 = ctypes.windll.advapi32
        kernel32 = ctypes.windll.kernel32

        class LUID(ctypes.Structure):
            _fields_ = [("LowPart", wintypes.DWORD),
                        ("HighPart", wintypes.LONG)]

        class TOKEN_PRIVILEGES(ctypes.Structure):
            _fields_ = [("PrivilegeCount", wintypes.DWORD),
                        ("Luid", LUID),
                        ("Attributes", wintypes.DWORD)]

        token = wintypes.HANDLE()
        if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(),
                                         0x0020, ctypes.byref(token)):
            return False, "OpenProcessToken failed"
        try:
            luid = LUID()
            if not advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege",
                                                  ctypes.byref(luid)):
                return False, "SeDebugPrivilege not present in token"
            privs = TOKEN_PRIVILEGES(1, luid, 0x00000002)
            if not advapi32.AdjustTokenPrivileges(token, False,
                                                  ctypes.byref(privs),
                                                  ctypes.sizeof(privs),
                                                  None, None):
                return False, "AdjustTokenPrivileges failed"
            if kernel32.GetLastError() != 0:
                return False, "privilege not assigned to this account"
            return True, "SeDebugPrivilege enabled"
        finally:
            kernel32.CloseHandle(token)
    except (OSError, ValueError, AttributeError) as exc:
        return False, f"unexpected: {exc}"


def process_exe_path(pid: int) -> str | None:
    """Best-effort full image path of a process (None if shielded)."""
    mods = _win()
    if mods is None:
        return None
    ctypes, wintypes = mods
    try:
        kernel32 = ctypes.windll.kernel32
        kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE

        class MODULEENTRY32(ctypes.Structure):
            _fields_ = [("dwSize", wintypes.DWORD),
                        ("th32ModuleID", wintypes.DWORD),
                        ("th32ProcessID", wintypes.DWORD),
                        ("GlblcntUsage", wintypes.DWORD),
                        ("ProccntUsage", wintypes.DWORD),
                        ("modBaseAddr", ctypes.c_void_p),
                        ("modBaseSize", wintypes.DWORD),
                        ("hModule", wintypes.HMODULE),
                        ("szModule", ctypes.c_char * 256),
                        ("szExePath", ctypes.c_char * 260)]

        snapshot = kernel32.CreateToolhelp32Snapshot(0x00000018, pid)
        if snapshot == wintypes.HANDLE(-1).value:
            return None
        try:
            entry = MODULEENTRY32()
            entry.dwSize = ctypes.sizeof(MODULEENTRY32)
            if kernel32.Module32First(snapshot, ctypes.byref(entry)):
                return entry.szExePath.split(b"\x00", 1)[0].decode(
                    "ascii", "replace")
            return None
        finally:
            kernel32.CloseHandle(snapshot)
    except (OSError, ValueError, AttributeError):
        return None


def find_process_id(process_name: str) -> tuple[int | None, str]:
    """Locate a running process by exe name.  ``(pid|None, detail)``."""
    mods = _win()
    if mods is None:
        return None, "windows-only"
    ctypes, wintypes = mods
    kernel32 = ctypes.windll.kernel32
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE

    class PROCESSENTRY32(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD),
                    ("cntUsage", wintypes.DWORD),
                    ("th32ProcessID", wintypes.DWORD),
                    ("th32DefaultHeapID", ctypes.c_void_p),
                    ("th32ModuleID", wintypes.DWORD),
                    ("cntThreads", wintypes.DWORD),
                    ("th32ParentProcessID", wintypes.DWORD),
                    ("pcPriClassBase", wintypes.LONG),
                    ("dwFlags", wintypes.DWORD),
                    ("szExeFile", ctypes.c_char * 260)]

    snapshot = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
    if snapshot == wintypes.HANDLE(-1).value:
        return None, "cannot snapshot the process list"
    try:
        entry = PROCESSENTRY32()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
        ok = kernel32.Process32First(snapshot, ctypes.byref(entry))
        while ok:
            name = entry.szExeFile.split(b"\x00", 1)[0].decode(
                "ascii", "replace")
            if name.lower() == process_name.lower():
                return int(entry.th32ProcessID), f"pid {entry.th32ProcessID}"
            ok = kernel32.Process32Next(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)
    return None, f"{process_name} is not running"


def live_read_slots(process_name: str = "aion.bin",
                    targets: tuple[tuple[str, int], ...] | None = None,
                    size: int = SLOT_SIZE) -> dict[str, Any]:
    """Read patch slots from a running process's memory.

    Returns ``{"supported": bool, "pid": int|None, "modules": {...},
    "error": str}``; each module entry is ``{"base": int, "data": bytes,
    "text": str}`` or ``{"error": str}``.  Read-only.
    """
    result: dict[str, Any] = {"supported": True, "pid": None,
                              "modules": {}, "error": ""}
    mods = _win()
    if mods is None:
        result["supported"] = False
        result["error"] = "live mode is Windows-only"
        result["remediation"] = "use static --game-dir mode on this OS"
        return result
    if targets is None:
        targets = (("aion.bin", AION_BIN_SLOT_RVA),
                   ("CrySystem.dll", CRYSYSTEM_SLOT_RVA))
    ctypes, wintypes = mods
    kernel32 = ctypes.windll.kernel32
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE

    pid, detail = find_process_id(process_name)
    if pid is None:
        result["error"] = detail
        result["remediation"] = (
            f"start the client ({process_name}) and leave it running, "
            "then retry")
        return result
    result["pid"] = pid
    dbg_ok, dbg_detail = enable_debug_privilege()
    result["debug_privilege"] = {"enabled": dbg_ok, "detail": dbg_detail}
    exe_path = process_exe_path(pid)
    if exe_path:
        result["exe_path"] = exe_path
    handle = kernel32.OpenProcess(0x0400 | 0x0010, False, pid)  # QUERY + VM_READ
    if not handle:
        err = kernel32.GetLastError()
        result["error"] = (
            f"OpenProcess(pid {pid}) failed (code {err}): access denied — "
            "GameGuard shields the client process")
        result["remediation"] = (
            "re-run this console ELEVATED (right-click -> Run as "
            "administrator); 4.6-era GameGuard often allows elevated + "
            "SeDebugPrivilege reads. If still denied, the fallback is the "
            "original AM flow, whose kernel driver reads memory past "
            "user-mode handle protection")
        return result
    try:
        # Bitness guard: a 32-bit Python cannot address a 64-bit target.
        wow64 = wintypes.BOOL()
        target_wow64: bool | None = None
        if kernel32.IsWow64Process(handle, ctypes.byref(wow64)):
            target_wow64 = bool(wow64.value)
        if sys.maxsize < 2 ** 32 and target_wow64 is False:
            result["error"] = ("bitness mismatch: 32-bit Python cannot read "
                               "a 64-bit client")
            result["remediation"] = "re-run with 64-bit Python"
            return result
        result["target_wow64"] = target_wow64

        class MODULEENTRY32(ctypes.Structure):
            _fields_ = [("dwSize", wintypes.DWORD),
                        ("th32ModuleID", wintypes.DWORD),
                        ("th32ProcessID", wintypes.DWORD),
                        ("GlblcntUsage", wintypes.DWORD),
                        ("ProccntUsage", wintypes.DWORD),
                        ("modBaseAddr", ctypes.c_void_p),
                        ("modBaseSize", wintypes.DWORD),
                        ("hModule", wintypes.HMODULE),
                        ("szModule", ctypes.c_char * 256),
                        ("szExePath", ctypes.c_char * 260)]

        snapshot = kernel32.CreateToolhelp32Snapshot(0x00000018, pid)
        if snapshot == wintypes.HANDLE(-1).value:
            result["error"] = "cannot snapshot the process modules"
            return result
        try:
            bases: dict[str, int] = {}
            entry = MODULEENTRY32()
            entry.dwSize = ctypes.sizeof(MODULEENTRY32)
            ok = kernel32.Module32First(snapshot, ctypes.byref(entry))
            while ok:
                name = entry.szModule.split(b"\x00", 1)[0].decode(
                    "ascii", "replace").lower()
                if entry.modBaseAddr:
                    bases[name] = entry.modBaseAddr
                ok = kernel32.Module32Next(snapshot, ctypes.byref(entry))
        finally:
            kernel32.CloseHandle(snapshot)

        for module_name, rva in targets:
            base = bases.get(module_name.lower())
            if base is None:
                result["modules"][module_name] = {
                    "error": f"module {module_name} not loaded (yet?)"}
                continue
            buf = ctypes.create_string_buffer(size)
            read = ctypes.c_size_t(0)
            ok = kernel32.ReadProcessMemory(
                handle, ctypes.c_void_p(base + rva), buf, size,
                ctypes.byref(read))
            if not ok or read.value <= 0:
                result["modules"][module_name] = {
                    "error": f"ReadProcessMemory at base+0x{rva:X} failed "
                             f"(code {kernel32.GetLastError()})"}
                continue
            blob = bytes(buf.raw[:read.value])
            result["modules"][module_name] = {
                "base": base, "data": blob,
                "text": blob.split(b"\x00", 1)[0].decode("ascii", "replace")}
    finally:
        kernel32.CloseHandle(handle)
    return result


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
# Reports (same shape as driver.py / interop.py)
# ---------------------------------------------------------------------------


def _new_report(command: str, server: str) -> dict[str, Any]:
    return {"command": command, "ok": True, "status": "", "checks": [],
            "warnings": [], "extra": {"server": server}}


def _add_server_dll(report: dict[str, Any], server: str) -> None:
    bypass = SERVER_BYPASS_DLLS.get(server)
    if bypass is None:
        report["checks"].append({"name": "server-dll", "status": "warn",
                                 "detail": f"{server} has no explicit entry — "
                                           "assuming Game.dll redirect",
                                 "remediation": "if the bypass misbehaves on "
                                                "this server, its entry is "
                                                "the suspect"})
        report["extra"]["bypass_dll"] = "Game.dll (assumed)"
    else:
        note = "" if bypass == "Game.dll" else \
            " (keeps the original name — no string redirect for this server)"
        report["checks"].append({"name": "server-dll", "status": "ok",
                                 "detail": f"{server} -> {bypass}{note}",
                                 "remediation": ""})
        report["extra"]["bypass_dll"] = bypass
        if server == "EuroAion":
            report["extra"]["effects_flag"] = "EuroAion_AnimationEffects"


def _finish(report: dict[str, Any], ok_status: str) -> dict[str, Any]:
    if not report["ok"]:
        report["status"] = "Status: Error 16"
    elif any(c["status"] == "warn" for c in report["checks"]):
        report["status"] = "Status: client uncertain — review warnings"
    else:
        report["status"] = ok_status
    return report


def check_client(game_dir: Path | str | None, server: str = "EuroAion",
                 slot_rvas: tuple[int, int] | None = None) -> dict[str, Any]:
    """Static, read-only compatibility verdict for the installed client.

    ``slot_rvas`` overrides ``(aion, crysystem)`` RVAs — test hook so unit
    tests can use tiny fake binaries instead of multi-MB images.
    """
    report = _new_report("clientcheck", server)
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

    # Diagnostics: sections, packer hints, entropy, string scan.
    diagnostics: dict[str, Any] = {}
    packer_hits: dict[str, list[str]] = {}
    for label, path in (("aion.bin", aion), ("CrySystem.dll", cry)):
        try:
            pe = parse_pe(path)
        except PEError as exc:
            diagnostics[label] = {"pe": f"unparseable: {exc}"}
            continue
        hits = packer_indicators(pe)
        if hits:
            packer_hits[label] = hits
        scan = scan_bytes(path)
        candidates: dict[str, list[int | None]] = {}
        if isinstance(scan, dict):
            for needle, found in scan.items():
                if isinstance(found, list):
                    candidates[needle] = [raw_to_rva(pe["sections"], h)
                                          for h in found[:4]]
        diagnostics[label] = {
            "sections": [f"{s['name']}:{s['vsize']:#x}@{s['vaddr']:#x}"
                         for s in pe["sections"]],
            "packer_sections": hits,
            "entropy_sample": round(image_entropy(path), 3),
            "scan": scan,
            "scan_rva_candidates": candidates,
        }
    report["extra"]["diagnostics"] = diagnostics
    if packer_hits:
        detail = "; ".join(f"{k}: {','.join(v)}"
                           for k, v in packer_hits.items())
        add("packed?", "warn", f"packer sections detected ({detail}) — "
                               "static slots cannot be trusted",
            "use --live on the running client for the definitive verdict")
    else:
        add("packed?", "ok", "no known packer section names")
    for label in ("aion.bin", "CrySystem.dll"):
        diag = diagnostics.get(label, {})
        sections = diag.get("sections")
        if not isinstance(sections, list):
            add(f"diag:{label}", "warn", str(diag.get("pe", "no data")))
            continue
        names = ",".join(s.split(":")[0] for s in sections)
        scan = diag.get("scan", {})
        cands = diag.get("scan_rva_candidates", {})
        parts = []
        for needle in ("NCGuard.dll", "Game.dll"):
            found = scan.get(needle, []) if isinstance(scan, dict) else []
            rvas = cands.get(needle, []) if isinstance(cands, dict) else []
            if found:
                bits = []
                for raw, rva in zip(found[:4], (list(rvas) + [None] * 4)[:4]):
                    bits.append(f"raw0x{raw:X}"
                                + (f"/rva?0x{rva:X}" if rva is not None else ""))
                if len(found) > 4:
                    bits.append(f"+{len(found) - 4}")
                parts.append(f"{needle}@{','.join(bits)}")
            else:
                parts.append(f"{needle}@none")
        add(f"diag:{label}", "ok",
            f"sections=[{names}] entropy={diag.get('entropy_sample')} "
            f"scan: {'; '.join(parts)}")

    # The two slots the original EXE overwrites in memory.
    for label, path, rva in (("slot:aion.bin", aion, rva_aion),
                             ("slot:CrySystem.dll", cry, rva_cry)):
        slot = read_slot(path, rva)
        status, detail = classify_slot(slot)
        add(label, status, detail,
            "" if status == "ok" else
            "this client build differs from the one AM 5.43 targets; the "
            "NCGuard redirect needs re-located offsets for this build"
            if status == "fail" else
            "re-run with --live while the client is running")
    if any("inconclusive" in c["detail"] for c in report["checks"]):
        report["warnings"].append(
            "static verdict inconclusive — the definitive test is "
            "--live while the client is running (AM patches memory, not files)")

    _add_server_dll(report, server)
    return _finish(report, "Status: client matches — patch will land")


def check_client_live(process_name: str = "aion.bin",
                      server: str = "EuroAion",
                      slot_rvas: tuple[int, int] | None = None) -> dict[str, Any]:
    """Definitive verdict from the running client's memory (Windows-only)."""
    report = _new_report("clientcheck-live", server)
    rva_aion, rva_cry = slot_rvas or (AION_BIN_SLOT_RVA, CRYSYSTEM_SLOT_RVA)

    def add(name: str, status: str, detail: str = "",
            remediation: str = "") -> None:
        report["checks"].append({"name": name, "status": status,
                                 "detail": detail, "remediation": remediation})
        if status == "fail":
            report["ok"] = False

    live = live_read_slots(process_name,
                           (("aion.bin", rva_aion),
                            ("CrySystem.dll", rva_cry)))
    if not live["supported"]:
        add("live", "fail", str(live["error"]),
            str(live.get("remediation") or
                "use static --game-dir mode on this OS"))
        report["status"] = "Status: Error 16"
        return report
    if live["error"] and not live["modules"]:
        add("process", "fail", str(live["error"]),
            str(live.get("remediation") or
                f"start the client ({process_name}) and leave it running, "
                "then retry"))
        report["status"] = "Status: Error 16"
        return report
    arch = "x64" if sys.maxsize >= 2 ** 32 else "x86"
    detail = f"{process_name} pid={live['pid']} (this Python: {arch})"
    if live.get("exe_path"):
        detail += f" image={live['exe_path']}"
        report["extra"]["exe_path"] = live["exe_path"]
    if live.get("debug_privilege"):
        report["extra"]["debug_privilege"] = live["debug_privilege"]
    add("process", "ok", detail)
    report["extra"]["pid"] = live["pid"]
    for label, module in (("slot:aion.bin", "aion.bin"),
                          ("slot:CrySystem.dll", "CrySystem.dll")):
        entry = live["modules"].get(module, {})
        if entry.get("error"):
            add(label, "fail", str(entry["error"]))
            continue
        slot = {"rva": rva_aion if module == "aion.bin" else rva_cry,
                "via": "live", "data": entry["data"], "text": entry["text"],
                "base": entry["base"]}
        status, detail = classify_slot(slot)
        add(label, status,
            detail + f" [module base 0x{entry['base']:X}]",
            "" if status == "ok" else
            "this client build differs from the one AM 5.43 targets; the "
            "NCGuard redirect needs re-located offsets for this build")
    _add_server_dll(report, server)
    return _finish(report, "Status: client matches — patch will land")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _parse_rva(text: str) -> int:
    """argparse type: decimal or 0x-hex RVA."""
    try:
        return int(text, 0)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"not a number (decimal or 0x-hex): {text!r}") from None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Check the installed Aion client against Account "
                    "Manager 5.43's hardcoded NCGuard patch slots (read-only)")
    parser.add_argument("--game-dir", type=Path, default=None,
                        help="client root (folder holding bin64/); if omitted, "
                             "auto-detect via the plaync registry keys")
    parser.add_argument("--server", default="EuroAion",
                        help="server preset for the bypass-dll lookup")
    parser.add_argument("--live", action="store_true",
                        help="read slots from the RUNNING client's memory "
                             "(Windows-only, definitive for packed clients)")
    parser.add_argument("--process", default="aion.bin",
                        help="process name for --live (default aion.bin)")
    parser.add_argument("--rva-aion", type=_parse_rva, default=None,
                        help="override the aion.bin slot RVA (decimal or "
                             "0x-hex; probes relocated candidates)")
    parser.add_argument("--rva-cry", type=_parse_rva, default=None,
                        help="override the CrySystem.dll slot RVA (decimal or "
                             "0x-hex)")
    parser.add_argument("--json", action="store_true")
    return parser


def _print(report: dict[str, Any], as_json: bool) -> None:
    if as_json:
        print(json.dumps(report, indent=2, default=str))
        return
    print(report["status"])
    for check in report["checks"]:
        mark = {"ok": "OK  ", "fail": "FAIL", "warn": "WARN",
                "skip": "SKIP"}[check["status"]]
        print(f"[{mark}] {check['name']}: {check['detail']}")
        if check["remediation"]:
            print(f"       -> {check['remediation']}")
    for warning in report.get("warnings", []):
        print(f"warning: {warning}")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    overrides = None
    if args.rva_aion is not None or args.rva_cry is not None:
        overrides = (args.rva_aion if args.rva_aion is not None
                     else AION_BIN_SLOT_RVA,
                     args.rva_cry if args.rva_cry is not None
                     else CRYSYSTEM_SLOT_RVA)
    if args.live:
        report = check_client_live(args.process, args.server,
                                   slot_rvas=overrides)
    else:
        report = check_client(args.game_dir, args.server,
                              slot_rvas=overrides)
    _print(report, args.json)
    return 0 if report["ok"] else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
