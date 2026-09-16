"""Real OS driver loading for Account Manager 5.43's kernel chain.

The emulator + :mod:`vanillatool_emulator.mapper` reproduce the *contract*
of the driver step; :mod:`vanillatool_emulator.local` automates staging,
patching and the ladder.  This module closes the last gap: **actually
loading the patched ``udk_2.bin`` (VanillaDrv_3.13) into the running
Windows kernel** via the real ``udk.bin`` KDU-style mapper, then proving
the load with independent OS-level checks.

Pipeline (mirrors exactly what the original EXE does, but transparently):

1. ``audit``   — read-only pre-flight: admin rights, Windows build, Secure
   Boot, HVCI/DeviceGuard, ``VulnerableDriverBlocklistEnable``, TestSigning,
   conflicting vendor drivers (RTCore64/Gdrv/ATSZIO64), staged payloads,
   current device state.  Never changes anything.
2. ``prepare`` — applies the two registry tweaks Account Manager itself
   applies (blocklist ``=0``, HVCI ``Enabled=0``), with automatic backup and
   restore.  Needs admin, needs a reboot, and only runs with ``--apply``
   (otherwise it prints the plan).
3. ``load``    — runs the **real** ``udk.bin -prv <id> -map udk_2.bin``
   ladder as a child process (no simulation on Windows), then verifies.
4. ``verify``  — independent proof the driver is in the OS: ``\\\\.\\<name>``
   opens, ``QueryDosDevices`` resolves the DOS-device symlink, and the
   mapper transcript carries the success markers.
5. ``cleanup`` — removes staged files and optionally restores the registry
   backup.  A manually-mapped driver has no SCM service entry, so a reboot
   is the only full unload — the report says so honestly.

Everything is stdlib-only.  On non-Windows platforms every command degrades
to a structured, JSON-serialisable plan/result marked ``windows-only`` (or
an exact-transcript simulation for ``load``), so the whole module stays
unit-testable on Linux/macOS::

    python -m vanillatool_emulator.driver audit --workdir am_workdir
    python -m vanillatool_emulator.driver prepare --apply
    python -m vanillatool_emulator.driver load --workdir am_workdir
    python -m vanillatool_emulator.driver verify --device-name AbCdEfGhIjK
"""

from __future__ import annotations

from dataclasses import dataclass, field
import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from . import local as L
from .mapper import PROVIDERS

IS_WINDOWS = sys.platform.startswith("win")

# Registry locations Account Manager touches before mapping.
BLOCKLIST_KEY = r"SYSTEM\CurrentControlSet\Control\CI\Config"
BLOCKLIST_VALUE = "VulnerableDriverBlocklistEnable"
HVCI_KEY = r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
HVCI_VALUE = "Enabled"
SECUREBOOT_KEY = r"SYSTEM\CurrentControlSet\Control\SecureBoot\State"
SECUREBOOT_VALUE = "UEFISecureBootEnabled"

# Success markers the real mapper prints on a good mapping (also produced
# by mapper.simulate, so transcripts stay comparable).
SUCCESS_MARKERS = (
    "Successfully loaded victim driver",
    "Driver handler code modified",
    "DSE patch executed successfully",
)

CONFLICT_SERVICES = ("RTCore64", "Gdrv", "ATSZIO64", "GIO", "eneTechIo")


# ---------------------------------------------------------------------------
# Small Windows helpers (all degrade gracefully off-Windows / without admin)
# ---------------------------------------------------------------------------


def _reg_read(hive: Any, key_path: str, value: str) -> tuple[bool, Any]:
    """Return ``(found, data)`` for a registry value; never raises."""
    if not IS_WINDOWS:
        return False, None
    try:
        import winreg

        with winreg.OpenKey(hive, key_path) as key:
            data, _kind = winreg.QueryValueEx(key, value)
            return True, data
    except (OSError, ImportError):
        return False, None


def _reg_write_hklm(key_path: str, value: str, data: int) -> tuple[bool, str]:
    """Write a DWORD under HKLM; returns ``(ok, detail)``."""
    if not IS_WINDOWS:
        return False, "windows-only: no registry write performed"
    try:
        import winreg
    except ImportError:
        return False, "winreg unavailable"
    try:
        with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
            winreg.SetValueEx(key, value, 0, winreg.REG_DWORD, int(data))
        return True, f"HKLM\\{key_path}!{value}={data}"
    except PermissionError:
        return False, "access denied (need Administrator)"
    except OSError as exc:
        return False, f"registry write failed: {exc}"


def _sc_query(service: str) -> tuple[bool, str]:
    """Query one SCM service; returns ``(running_or_exists, detail)``."""
    if not IS_WINDOWS:
        return False, "windows-only"
    try:
        proc = subprocess.run(
            ["sc", "query", service], capture_output=True, text=True, timeout=15,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        if "FAILED 1060" in out or "does not exist" in out:
            return False, "not installed"
        if "RUNNING" in out:
            return True, "RUNNING"
        if "STOPPED" in out:
            return False, "installed but STOPPED"
        return False, out.strip().splitlines()[0] if out.strip() else "unknown"
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"sc query failed: {exc}"


def _testsigning_state() -> tuple[bool | None, str]:
    """Return ``(enabled|None, detail)`` for the TestSigning BCD flag."""
    if not IS_WINDOWS:
        return None, "windows-only"
    try:
        proc = subprocess.run(
            ["bcdedit", "/enum", "{current}"], capture_output=True, text=True,
            timeout=15, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        for line in out.splitlines():
            if "testsigning" in line.lower():
                return ("Yes" in line, line.strip())
        return False, "testsigning not present (default Off)"
    except (OSError, subprocess.SubprocessError) as exc:
        return None, f"bcdedit unavailable: {exc}"


def query_dos_devices(device_name: str) -> tuple[bool, str]:
    """Check ``<name>`` via ``QueryDosDevicesW``; ``(present, target)``.

    A loaded ``\\Device\\<name>`` + ``\\DosDevices\\<name>`` pair shows up
    here as a DOS-device symlink — an independent OS-level proof that does
    not depend on the mapper's own stdout.
    """
    if not IS_WINDOWS:
        return False, "windows-only"
    try:
        import ctypes

        buf = ctypes.create_unicode_buffer(32768)
        needed = ctypes.windll.kernel32.QueryDosDevicesW(
            device_name, buf, len(buf))
        if not needed:
            return False, "not present"
        raw = buf[:needed].split("\x00")
        targets = [entry for entry in raw if entry]
        return True, "; ".join(targets) if targets else "present (empty target)"
    except (OSError, AttributeError, ValueError) as exc:
        return False, f"QueryDosDevices failed: {exc}"


def windows_build() -> str:
    if not IS_WINDOWS:
        return f"non-windows ({sys.platform})"
    try:
        import platform

        return f"{platform.system()} {platform.release()} build {platform.version()}"
    except Exception:
        return "Windows (version unknown)"


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------


@dataclass
class Check:
    name: str
    status: str  # "ok" | "fail" | "warn" | "skip"
    detail: str = ""
    remediation: str = ""

    def as_dict(self) -> dict[str, str]:
        return {"name": self.name, "status": self.status,
                "detail": self.detail, "remediation": self.remediation}


@dataclass
class DriverReport:
    command: str
    ok: bool
    status: str  # AM-style "Status: ..." line
    checks: list[Check] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    def add(self, name: str, status: str, detail: str = "",
            remediation: str = "") -> None:
        self.checks.append(Check(name, status, detail, remediation))
        if status == "fail":
            self.ok = False

    def as_dict(self) -> dict[str, Any]:
        return {"command": self.command, "ok": self.ok, "status": self.status,
                "checks": [c.as_dict() for c in self.checks],
                "warnings": self.warnings, "extra": self.extra}


# ---------------------------------------------------------------------------
# audit — read-only pre-flight
# ---------------------------------------------------------------------------


def audit_os(workdir: Path | str = "am_workdir",
             device_name: str = "") -> DriverReport:
    """Read-only pre-flight for the OS load.  Never changes anything."""
    workdir = Path(workdir)
    report = DriverReport(command="audit", ok=True, status="Status: audit ok")
    report.extra["platform"] = sys.platform
    report.extra["build"] = windows_build()

    # 1. Platform gate — the OS load needs Windows x64.  Off-Windows the
    # audit is a *plan*: admin-ness of the lab box is irrelevant, so the
    # admin check is evaluated on the target instead of failed here.
    if not IS_WINDOWS:
        report.add("admin", "skip", "evaluated on the Windows target",
                   "run elevated there (right-click -> Run as administrator)")
        report.add("platform", "skip",
                   f"{sys.platform}: kernel load needs Windows x64; "
                   "use --json output as the load plan",
                   "run on the Windows target")
        # Still validate the portable half so lab runs are useful.
        _audit_portable(workdir, device_name, report)
        if any(c.status == "fail" for c in report.checks):
            report.status = "Status: Error 16"
        else:
            report.status = "Status: audit ok (plan only, non-Windows)"
        return report
    report.add("platform", "ok", windows_build())

    # 2. Admin rights (#RequireAdmin in the original tool).
    admin = L.is_admin()
    report.add("admin", "ok" if admin else "fail",
               "Administrator" if admin else "not elevated",
               "" if admin else "re-run elevated (right-click -> Run as administrator)")

    # 3. Secure Boot / HVCI / blocklist / TestSigning.
    import winreg

    found, sb = _reg_read(winreg.HKEY_LOCAL_MACHINE, SECUREBOOT_KEY, SECUREBOOT_VALUE)
    report.add("secure-boot", "warn" if (found and sb) else "ok",
               f"UEFISecureBootEnabled={sb}" if found else "key absent (legacy boot?)",
               "Secure Boot ON usually forces HVCI/blocklist back on; lab VMs often disable it"
               if (found and sb) else "")
    found, hvci = _reg_read(winreg.HKEY_LOCAL_MACHINE, HVCI_KEY, HVCI_VALUE)
    report.add("hvci", "ok" if (found and hvci == 0) else "warn",
               f"Enabled={hvci}" if found else "value absent (default varies)",
               "run `driver prepare --apply` (sets Enabled=0) + reboot" if hvci != 0 else "")
    found, block = _reg_read(winreg.HKEY_LOCAL_MACHINE, BLOCKLIST_KEY, BLOCKLIST_VALUE)
    report.add("driver-blocklist", "ok" if (found and block == 0) else "warn",
               f"VulnerableDriverBlocklistEnable={block}" if found else "value absent",
               "run `driver prepare --apply` (sets =0) + reboot" if block != 0 else "")
    ts, ts_detail = _testsigning_state()
    report.add("testsigning", "ok",
               ts_detail,
               "optional lab alternative: bcdedit /set testsigning on + reboot")

    # 4. Conflicting vendor drivers (AM shows "close <tool>" hints for these).
    for svc in CONFLICT_SERVICES:
        running, detail = _sc_query(svc)
        if running:
            hint = {p.name: p.client_hint for p in PROVIDERS.values()}.get(svc, "")
            report.add(f"conflict:{svc}", "fail", detail,
                       hint or f"stop/uninstall the {svc} owner tool, then retry")
        else:
            report.add(f"conflict:{svc}", "ok", detail)

    # 5. Portable half (payloads + device state).
    _audit_portable(workdir, device_name, report)

    fails = [c for c in report.checks if c.status == "fail"]
    warns = [c for c in report.checks if c.status == "warn"]
    if fails:
        report.status = "Status: Error 16"
    elif warns:
        report.status = "Status: audit ok with warnings"
        report.warnings.extend(f"{c.name}: {c.remediation}" for c in warns if c.remediation)
    return report


def _audit_portable(workdir: Path, device_name: str, report: DriverReport) -> None:
    stager = L.PayloadStager()
    missing = [name for name in ("udk.bin", "udk_1.dll", "udk_2.bin")
               if not (workdir / name).is_file()]
    if missing:
        report.add("payloads", "fail", f"missing in {workdir}: {', '.join(missing)}",
                   f"run `local --workdir {workdir}` to stage + patch first")
    else:
        try:
            dev, dos = stager.read_driver_slots(workdir)
            patched = dev.startswith("\\Device\\") and dos.startswith("\\DosDevices\\")
            report.add("payloads", "ok" if patched else "fail",
                       f"staged; slots: {dev} / {dos}",
                       "" if patched else "patch device names first (GUI: Patch device names)")
            if device_name and stager.driver_device_name(workdir) != device_name:
                report.add("device-name", "warn",
                           f"workdir holds {stager.driver_device_name(workdir)!r}, "
                           f"requested {device_name!r}",
                           "re-patch with the requested name or drop --device-name")
            else:
                report.add("device-name", "ok",
                           stager.driver_device_name(workdir) or "(unreadable)")
        except OSError as exc:
            report.add("payloads", "fail", str(exc), "re-stage the workdir")
    # Current OS state of the device (loaded already?).
    name = device_name or (stager.driver_device_name(workdir)
                           if (workdir / "udk_2.bin").is_file() else "")
    if name:
        probe = L.MapperRunner(workdir).probe_device(name)
        present, target = query_dos_devices(name)
        if probe is None:
            report.add("device-state", "skip",
                       "probe is Windows-only",
                       "run verify on the target")
        elif probe and present:
            report.add("device-state", "ok",
                       f"\\\\.\\{name} opens; DosDevices -> {target}")
        elif probe or present:
            report.add("device-state", "warn",
                       f"partial: CreateFile={probe} DosDevices={present} ({target})")
        else:
            report.add("device-state", "ok", f"{name} not loaded (clean slate)")


# ---------------------------------------------------------------------------
# prepare — AM's own registry tweaks, with backup/restore, opt-in apply
# ---------------------------------------------------------------------------


def prepare_os(apply: bool = False,
               backup_path: Path | str | None = None) -> DriverReport:
    """Plan (default) or apply (``--apply``) the OS preparation.

    The changes are exactly the two DWORDs Account Manager writes itself:
    ``VulnerableDriverBlocklistEnable=0`` and HVCI ``Enabled=0``.  Both need
    a reboot to take effect.  Previous values are backed up to JSON and can
    be restored with :func:`restore_os`.
    """
    report = DriverReport(command="prepare", ok=True,
                          status="Status: prepare plan ready")
    if backup_path is None:
        backup_path = Path.cwd() / "driver_prepare_backup.json"
    backup_path = Path(backup_path)
    report.extra["backup"] = str(backup_path)
    report.extra["reboot_required"] = True

    if not IS_WINDOWS:
        report.add("blocklist", "skip", "windows-only: would set ...\\CI\\Config!VulnerableDriverBlocklistEnable=0")
        report.add("hvci", "skip", "windows-only: would set ...\\HypervisorEnforcedCodeIntegrity!Enabled=0")
        report.status = "Status: prepare plan ready (windows-only)"
        return report

    import winreg

    if not L.is_admin():
        report.add("admin", "fail", "not elevated",
                   "re-run elevated to apply; without --apply this is plan-only")
        report.status = "Status: Error 16"
        return report

    targets = [
        ("blocklist", BLOCKLIST_KEY, BLOCKLIST_VALUE),
        ("hvci", HVCI_KEY, HVCI_VALUE),
    ]
    previous: dict[str, Any] = {}
    for label, key_path, value in targets:
        found, data = _reg_read(winreg.HKEY_LOCAL_MACHINE, key_path, value)
        previous[f"{key_path}!{value}"] = {"found": found, "data": data}
        if found and data == 0:
            report.add(label, "ok", f"{value}=0 already")
        elif not apply:
            report.add(label, "warn",
                       f"would set {value} {data!r} -> 0 (reboot required)",
                       "re-run with --apply, then reboot")
        else:
            ok, detail = _reg_write_hklm(key_path, value, 0)
            report.add(label, "ok" if ok else "fail", detail)

    # Persist the backup whenever we read real state (plan or apply).
    try:
        backup_path.write_text(json.dumps(previous, indent=2), encoding="utf-8")
        report.extra["backup_written"] = True
    except OSError as exc:
        report.warnings.append(f"backup write failed: {exc}")
        report.extra["backup_written"] = False

    if apply and report.ok:
        report.status = "Status: prepared — reboot, then load"
    elif not apply:
        report.status = "Status: prepare plan ready"
    else:
        report.status = "Status: Error 16"
    return report


def restore_os(backup_path: Path | str = "driver_prepare_backup.json") -> DriverReport:
    """Restore registry values saved by :func:`prepare_os`."""
    report = DriverReport(command="restore", ok=True, status="Status: restored")
    backup_path = Path(backup_path)
    if not IS_WINDOWS:
        report.add("restore", "skip", "windows-only")
        return report
    if not L.is_admin():
        report.add("admin", "fail", "not elevated", "re-run elevated")
        report.status = "Status: Error 16"
        return report
    try:
        previous = json.loads(backup_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        report.add("backup", "fail", f"cannot read {backup_path}: {exc}")
        report.status = "Status: Error 16"
        return report
    import winreg

    for dotted, info in previous.items():
        key_path, _, value = dotted.rpartition("!")
        try:
            if not info.get("found", False):
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path,
                                    0, winreg.KEY_SET_VALUE) as key:
                    winreg.DeleteValue(key, value)
                report.add(f"restore:{value}", "ok", "deleted (was absent)")
            else:
                with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                    winreg.SetValueEx(key, value, 0, winreg.REG_DWORD,
                                      int(info.get("data", 1)))
                report.add(f"restore:{value}", "ok", f"back to {info.get('data')}")
        except OSError as exc:
            report.add(f"restore:{value}", "fail", str(exc))
    if not report.ok:
        report.status = "Status: Error 16"
    else:
        report.warnings.append("reboot for the restored values to take effect")
    return report


# ---------------------------------------------------------------------------
# load — run the REAL mapper ladder and prove the driver is in the OS
# ---------------------------------------------------------------------------


def load_driver(workdir: Path | str = "am_workdir",
                providers: list[int | None] | None = None,
                timeout: int = 120) -> DriverReport:
    """Load the patched driver into the OS via the real ``udk.bin`` ladder.

    On Windows this executes the mapper child processes for real (never the
    transcript simulation) and then runs :func:`verify_loaded`.  Anywhere
    else it returns the exact-transcript simulation explicitly marked as
    such, so lab runs stay meaningful without pretending a load happened.
    """
    workdir = Path(workdir)
    report = DriverReport(command="load", ok=True, status="Status: driver mapped..")
    runner = L.MapperRunner(workdir)

    if not runner.driver_path.is_file() or not runner.mapper_path.is_file():
        report.add("payloads", "fail",
                   f"{workdir} lacks udk.bin/udk_2.bin",
                   f"run `local --workdir {workdir}` first")
        report.status = "Status: Error 14"
        return report
    try:
        device = runner and L.PayloadStager().driver_device_name(workdir)
    except (OSError, ValueError) as exc:
        report.add("device-name", "fail", str(exc), "re-patch the driver copy")
        report.status = "Status: Error 16"
        return report
    report.extra["device"] = device
    report.extra["simulated"] = not IS_WINDOWS

    ladder = runner.run_ladder(
        providers=list(providers) if providers is not None else [1, 2, 3, None],
        force_simulated=not IS_WINDOWS,
    )
    for step in ladder.steps:
        markers = [m for m in SUCCESS_MARKERS if m in step.transcript]
        report.add("ladder:" + " ".join(step.argv),
                   "ok" if step.outcome == "mapped" else "warn",
                   f"{step.outcome} (simulated={step.simulated}); "
                   f"markers={markers or 'none'}")
        if step.hint:
            report.warnings.append(step.hint)
    report.extra["transcripts"] = [
        {"argv": s.argv, "outcome": s.outcome, "exit_code": s.exit_code,
         "simulated": s.simulated, "hint": s.hint} for s in ladder.steps
    ]

    if not ladder.mapped:
        report.ok = False
        report.status = "Status: Error 16"
        report.warnings.append("no ladder step reported a mapping; "
                               "see hints above (close the conflicting tool and retry)")
        return report

    # Independent OS-level proof (or its honest non-Windows equivalent).
    verify = verify_loaded(device, workdir)
    report.checks.extend(verify.checks)
    report.warnings.extend(verify.warnings)
    report.ok = report.ok and verify.ok
    report.status = ("Status: driver mapped.." if report.ok
                     else "Status: Error 16")
    return report


# ---------------------------------------------------------------------------
# verify — independent OS-level proof of the load
# ---------------------------------------------------------------------------


def verify_loaded(device_name: str,
                  workdir: Path | str | None = None) -> DriverReport:
    """Prove ``device_name`` is loaded in the OS (three independent checks)."""
    report = DriverReport(command="verify", ok=True,
                          status="Status: driver verified in OS")
    report.extra["device"] = device_name
    if not device_name:
        report.add("device-name", "fail", "empty device name")
        report.status = "Status: Error 16"
        return report

    # 1. CreateFile on \\.\<name> (the exact probe AM performs).
    if workdir is not None:
        probe = L.MapperRunner(workdir).probe_device(device_name)
    else:
        probe = L.MapperRunner(Path.cwd()).probe_device(device_name)
    if probe is None:
        report.add("createfile", "skip",
                   "Windows-only; on the target expect the handle to open",
                   "run verify on the Windows target")
    elif probe:
        report.add("createfile", "ok", f"\\\\.\\{device_name} opened")
    else:
        report.add("createfile", "fail", f"\\\\.\\{device_name} did not open",
                   "driver is not loaded (run load) or the name mismatches the patch")

    # 2. QueryDosDevices symlink (independent of the mapper's stdout).
    present, target = query_dos_devices(device_name)
    if not IS_WINDOWS:
        report.add("dosdevices", "skip", "Windows-only")
    elif present and device_name.lower() in target.lower():
        report.add("dosdevices", "ok", f"{device_name} -> {target}")
    elif present:
        report.add("dosdevices", "warn", f"{device_name} -> {target} (target mismatch?)")
    else:
        report.add("dosdevices", "fail", f"{device_name}: {target}",
                   "driver is not loaded")

    # 3. Slot sanity: the workdir copy must carry the probed name.
    if workdir is not None and (Path(workdir) / "udk_2.bin").is_file():
        try:
            actual = L.PayloadStager().driver_device_name(Path(workdir))
            report.add("slot-name", "ok" if actual == device_name else "fail",
                       f"udk_2.bin carries {actual!r}",
                       "" if actual == device_name
                       else "re-patch udk_2.bin with the probed name")
        except (OSError, ValueError) as exc:
            report.add("slot-name", "fail", str(exc))
    else:
        report.add("slot-name", "skip", "no workdir copy to compare")

    if any(c.status == "fail" for c in report.checks):
        report.status = "Status: Error 16"
        report.ok = False
    return report


# ---------------------------------------------------------------------------
# cleanup — staged files + registry restore (reboot fully unloads)
# ---------------------------------------------------------------------------


def cleanup(workdir: Path | str = "am_workdir",
            restore_backup: Path | str | None = None,
            delete_workdir: bool = False) -> DriverReport:
    """Remove staged loader files; optionally restore the registry backup.

    A manually-mapped driver has no SCM entry, so neither ``sc delete`` nor
    this command can unload it — only a reboot does.  The report states that
    explicitly instead of pretending otherwise.
    """
    workdir = Path(workdir)
    report = DriverReport(command="cleanup", ok=True, status="Status: cleaned")
    removed: list[str] = []
    for name in ("udk.bin", "udk_1.dll", "udk_2.bin"):
        path = workdir / name
        try:
            if path.is_file():
                path.unlink()
                removed.append(name)
        except OSError as exc:
            report.add(f"remove:{name}", "fail", str(exc))
    report.extra["removed"] = removed
    if delete_workdir:
        import shutil

        try:
            shutil.rmtree(workdir, ignore_errors=False)
            report.extra["workdir_deleted"] = True
        except OSError as exc:
            report.add("workdir", "fail", str(exc))
    if restore_backup is not None:
        restored = restore_os(restore_backup)
        report.checks.extend(restored.checks)
        report.warnings.extend(restored.warnings)
        report.ok = report.ok and restored.ok
    report.warnings.append(
        "a manually-mapped driver stays resident until reboot; "
        "reboot to fully unload it from the OS")
    if not report.ok:
        report.status = "Status: Error 16"
    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Load Account Manager's patched driver into the Windows OS "
                    "(audit -> prepare -> load -> verify -> cleanup)")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("audit", help="read-only pre-flight (never changes anything)")
    p.add_argument("--workdir", type=Path, default=Path("am_workdir"))
    p.add_argument("--device-name", default="")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("prepare", help="plan/apply AM's registry tweaks (reboot needed)")
    p.add_argument("--apply", action="store_true",
                   help="actually write the registry (needs admin)")
    p.add_argument("--backup", type=Path, default=Path("driver_prepare_backup.json"))
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("restore", help="restore the prepare backup")
    p.add_argument("--backup", type=Path, default=Path("driver_prepare_backup.json"))
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("load", help="run the real mapper ladder and verify the load")
    p.add_argument("--workdir", type=Path, default=Path("am_workdir"))
    p.add_argument("--providers", default="1,2,3,default",
                   help="comma list, e.g. 1,2,3,default")
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("verify", help="prove the driver is loaded in the OS")
    p.add_argument("--device-name", required=True)
    p.add_argument("--workdir", type=Path, default=None)
    p.add_argument("--json", action="store_true")

    p = sub.add_parser("cleanup", help="remove staged files (+ optional registry restore)")
    p.add_argument("--workdir", type=Path, default=Path("am_workdir"))
    p.add_argument("--restore-backup", type=Path, default=None)
    p.add_argument("--delete-workdir", action="store_true")
    p.add_argument("--json", action="store_true")
    return parser


def _print(report: DriverReport, as_json: bool) -> None:
    if as_json:
        print(json.dumps(report.as_dict(), indent=2))
        return
    print(report.status)
    for check in report.checks:
        mark = {"ok": "OK  ", "fail": "FAIL", "warn": "WARN", "skip": "SKIP"}[check.status]
        print(f"[{mark}] {check.name}: {check.detail}")
        if check.remediation:
            print(f"       -> {check.remediation}")
    for warning in report.warnings:
        print(f"warning: {warning}")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "audit":
        report = audit_os(args.workdir, args.device_name)
    elif args.command == "prepare":
        report = prepare_os(apply=args.apply, backup_path=args.backup)
    elif args.command == "restore":
        report = restore_os(args.backup)
    elif args.command == "load":
        providers: list[int | None] = []
        for token in str(args.providers).split(","):
            token = token.strip().lower()
            if token in ("default", "none", ""):
                providers.append(None)
            else:
                providers.append(int(token))
        report = load_driver(args.workdir, providers or [1, 2, 3, None])
    elif args.command == "verify":
        report = verify_loaded(args.device_name, args.workdir)
    elif args.command == "cleanup":
        report = cleanup(args.workdir, args.restore_backup, args.delete_workdir)
    else:  # pragma: no cover - argparse enforces choices
        raise SystemExit(f"unknown command {args.command}")
    _print(report, args.json)
    return 0 if report.ok else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
