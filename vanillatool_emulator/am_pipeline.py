"""Automatic end-to-end pipeline: emulator + local files + target audit.

``AutomaticRun`` is the headless backend behind both GUIs (desktop Tk and
browser) and the ``am_cli`` command.  One call performs, in order, everything
the original Account Manager does at startup -- except the dangerous parts,
which are *emulated or audited read-only* instead of executed:

1. environment check (OS, privileges, ports),
2. workspace recovery (helper binaries, device-slot patch, settings, ini),
3. driver-mapper ladder (``mapper.simulate`` transcripts for -prv 1/2/3),
4. emulator self-test (auth round-trip, version, offsets, resources),
5. target audit (exe layout, NCGuard string scan, hosts/registry read-only),
6. launch plan (command line + Login-All simulation, dry-run by default).

Every step returns a structured ``StepResult``; the full run is serialisable
to JSON for the GUIs and the CLI.  No step loads a driver, writes process
memory, injects a DLL, or modifies the game install.
"""

from __future__ import annotations

import configparser
import ctypes
import json
import os
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field, asdict
from http.client import HTTPConnection
from pathlib import Path
from typing import Any, Callable

from . import am_config as C
from .account_manager import missing_account_manager_profile_keys
from .am_workspace import (
    DEFAULT_WORKSPACE,
    describe_target,
    list_accounts,
    prepare_workspace,
    read_logins,
    scan_ncguard_strings,
    write_logins,
)
from .mapper import PROVIDERS, hint_conflict, simulate
from .protocol import decrypt_response, encrypt_client_field, parse_auth_form
from .server import EmulatorConfig, EmulatorHTTPServer

LogFn = Callable[[str], None]


def _noop(_msg: str) -> None:
    pass


def is_admin() -> bool:
    try:
        if os.name == "nt":
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        return os.geteuid() == 0  # type: ignore[attr-defined]
    except Exception:
        return False


def port_free(host: str, port: int) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((host, port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


@dataclass
class StepResult:
    name: str
    ok: bool
    status: str  # mirrors the original "Status: ..." line
    details: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AutomaticReport:
    ok: bool
    status: str
    steps: list[StepResult] = field(default_factory=list)
    options: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {"ok": self.ok, "status": self.status,
                "options": {k: v for k, v in self.options.items()
                            if k not in {"settings", "delays"}},
                "settings": self.options.get("settings", {}),
                "steps": [s.as_dict() for s in self.steps]}


def check_environment(options: C.AutomaticOptions) -> StepResult:
    warnings: list[str] = []
    admin = is_admin()
    if os.name == "nt" and not admin:
        warnings.append("not running as Administrator; the original requires it "
                        "(#RequireAdmin). Lab steps still run, launch stays dry-run.")
    free = port_free(options.emulator_host, options.emulator_port)
    if not free:
        return StepResult("environment", False,
                          f"Status: emulator port {options.emulator_port} busy",
                          {"admin": admin, "os": os.name,
                           "host": options.emulator_host,
                           "port": options.emulator_port},
                          warnings)
    if options.server not in C.SERVERS:
        return StepResult("environment", False,
                          f"Status: unknown server preset {options.server!r}",
                          {"servers": list(C.SERVERS)}, warnings)
    return StepResult("environment", True, "Status: environment ok",
                      {"admin": admin, "os": os.name,
                       "python": sys.version.split()[0],
                       "host": options.emulator_host,
                       "port": options.emulator_port}, warnings)


def recover_workspace(options: C.AutomaticOptions, workspace_root: Path,
                      log: LogFn = _noop) -> tuple[StepResult, Any]:
    try:
        settings = dict(options.settings or {})
        if options.device_name:
            settings["fHide_UDK"] = options.device_name
        if options.server:
            settings["LastServer"] = options.server
        ws = prepare_workspace(
            workspace_root,
            settings=settings,
            delays=options.merged_delays(),
        )
        log(f"Status: recovered {len(ws.files)} local file(s) to {ws.bin_dir}")
        return StepResult(
            "workspace", True,
            f"Status: recovered {len(ws.files)} local file(s)",
            ws.as_dict(),
        ), ws
    except Exception as exc:  # keep pipeline JSON-safe
        return StepResult("workspace", False, f"Status: workspace failed: {exc}",
                          {"error": str(exc)}), None


def run_mapper_ladder(workspace: Any, missing: str,
                      log: LogFn = _noop) -> StepResult:
    unavailable: set[int] = set()
    for part in (missing or "").split(","):
        part = part.strip()
        if part:
            try:
                unavailable.add(int(part))
            except ValueError:
                return StepResult("mapper", False,
                                  f"Status: bad --missing-providers {missing!r}",
                                  {"error": f"not an int: {part!r}"})
    driver_copy = None
    if workspace is not None:
        for f in workspace.files:
            if f.runtime == "udk_2.bin" or f.source == "VanillaDrv_3.13.sys.dec":
                driver_copy = Path(f.path)
                break
    driver_bytes = driver_copy.read_bytes() if driver_copy and driver_copy.is_file() else None
    attempts: list[dict[str, Any]] = []
    chosen: int | None = None
    found = False
    for slot in (1, 2, 3, None):
        argv = ["-map", "udk_2.bin"] if slot is None else ["-prv", str(slot), "-map", "udk_2.bin"]
        run = simulate(argv, unavailable_providers=unavailable, driver_bytes=driver_bytes)
        hint = hint_conflict(run.transcript)
        label = "default" if slot is None else f"-prv {slot} ({PROVIDERS[slot].name})"
        attempts.append({
            "provider": label,
            "exit_code": run.exit_code,
            "outcome": run.outcome,
            "hint": hint,
            "transcript_tail": run.transcript.replace("\r\n", "\n").splitlines()[-3:],
        })
        log(f"Status: mapper {label}: {run.outcome}"
            + (f" -> {hint}" if hint else ""))
        if run.exit_code == 0 and not found:
            chosen = slot
            found = True
    if not found:
        return StepResult("mapper", False, "Status: all mapper providers blocked",
                          {"attempts": attempts,
                           "note": "emulated transcripts; real mapping needs a "
                                   "Windows kernel and is never attempted here"})
    label = "default" if chosen is None else f"-prv {chosen}"
    return StepResult("mapper", True, f"Status: mapper would use {label} (emulated)",
                      {"attempts": attempts, "chosen": chosen,
                       "device": workspace.device_name_value if workspace else "",
                       "note": "KDU transcript emulation only; no driver is loaded"})


def self_test_emulator(options: C.AutomaticOptions, log: LogFn = _noop) -> StepResult:
    """Boot a throwaway emulator instance and exercise every route."""
    config = EmulatorConfig(
        version=options.version,
        orythm=options.orythm,
        prythm=options.prythm,
        account_manager_startup=options.account_manager_startup,
    )
    if options.response_file:
        p = Path(options.response_file)
        if not p.is_file():
            return StepResult("emulator", False,
                              "Status: --response-file not found",
                              {"error": str(p)})
        config.response_file = p
        config.account_manager_startup = False
    if options.offsets_file:
        from .offsets import load_offsets_file
        try:
            config.offsets_text = load_offsets_file(Path(options.offsets_file))
        except (OSError, ValueError) as exc:
            return StepResult("emulator", False,
                              f"Status: bad offsets file: {exc}",
                              {"error": str(exc)})
    httpd = EmulatorHTTPServer(("127.0.0.1", 0), config)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    port = httpd.server_address[1]
    details: dict[str, Any] = {"port": port}
    warnings: list[str] = []
    try:
        def get(path: str) -> tuple[int, bytes]:
            conn = HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", path)
            resp = conn.getresponse()
            body = resp.read()
            conn.close()
            return resp.status, body

        def post_auth(identity: bytes, ts: str) -> tuple[int, bytes]:
            body = ("aN=" + encrypt_client_field(identity)
                    + f"&aU=781769&aH={ts}&aC="
                    + encrypt_client_field(b"CPU:BIOS") + "&aV=5.43").encode("ascii")
            conn = HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("POST", "/data/auth.php", body=body,
                         headers={"Content-Type": "application/x-www-form-urlencoded"})
            resp = conn.getresponse()
            payload = resp.read()
            conn.close()
            return resp.status, payload

        status, body = get("/Updateless/Version.txt")
        details["version_route"] = {"status": status, "body": body.decode("ascii", "replace").strip()}
        status, body = get("/Offsets.txt")
        details["offsets_route"] = {"status": status,
                                    "has_section": b"[" in body,
                                    "has_base": b"Base_SubText" in body}
        status, body = get("/data/resourceversion.txt")
        details["resource_version_route"] = {"status": status,
                                             "body": body.decode("ascii", "replace").strip()}

        identity = b"65-66-67-68-69-70_1234567".ljust(24, b"O")
        ts = "17123456"
        status, payload = post_auth(identity, ts)
        details["auth_status"] = status
        if status != 200:
            return StepResult("emulator", False, "Status: auth self-test failed",
                              details, warnings)
        marker = payload.decode("ascii").strip()
        cipher = marker[2:-1] if marker.startswith("C:") and marker.endswith(";") else ""
        plaintext = decrypt_response(cipher, ts, identity).decode("latin-1")
        details["auth_markers"] = {
            "has_orythm": "ORythm=" in plaintext,
            "has_prythm": "PRythm=" in plaintext,
            "length": len(plaintext),
        }
        missing = missing_account_manager_profile_keys(plaintext)
        details["account_manager_markers_missing"] = missing
        details["account_manager_markers_total"] = 60
        if missing and options.account_manager_startup:
            warnings.append(f"{len(missing)} pre-GUI marker(s) missing from fixture")
        if "expired" in plaintext.lower():
            return StepResult("emulator", False, "Status: fixture reports expired",
                              details, warnings)
        # Second request shape: the client re-auths before GUI creation.
        status2, _ = post_auth(identity, ts)
        details["second_auth_status"] = status2
        log("Status: emulator self-test ok (auth + version + offsets)")
        return StepResult("emulator", True, "Status: emulator self-test ok",
                          details, warnings)
    except Exception as exc:
        return StepResult("emulator", False, f"Status: emulator self-test error: {exc}",
                          {**details, "error": str(exc)}, warnings)
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=2)


def audit_target(options: C.AutomaticOptions, log: LogFn = _noop) -> StepResult:
    info = describe_target(options.target_exe)
    warnings: list[str] = []
    if not info.get("exists"):
        return StepResult("target", False,
                          "Status: target exe not found",
                          {"target": info,
                           "hint": "point Target EXE at bin64/aion.bin (or a copy) "
                                   "in the GUI / --target-exe"},
                          warnings)
    if not info.get("mz_header"):
        warnings.append("target does not start with MZ; not a Windows executable?")
    if not info.get("world_pak_present"):
        warnings.append("x_World.pak not found next to target; original checks "
                        "Data/World/x_World.pak")
    scan: dict[str, Any] = {}
    if info.get("size", 0) and info["size"] <= 64 * 1024 * 1024:
        scan = scan_ncguard_strings(options.target_exe)
        info["ncguard_scan"] = scan
        log(f"Status: NCGuard scan: {len(scan.get('hits', []))} hit(s) (read-only)")
    else:
        info["ncguard_scan"] = {"skipped": "file too large"}
    if os.name == "nt":
        info["registry_hint"] = (
            "read-only: HKLM\\Software\\Wow6432Node\\plaync\\AION[ _CLASSIC]\\BaseDir "
            "would be consulted on Windows; the lab build never writes it")
    else:
        info["registry_hint"] = "non-Windows host: registry discovery skipped"
    info["hosts_note"] = ("hosts-file fallback for subvanillatool.com is audited, "
                          "never written unless --allow-hosts-write with backup")
    log(f"Status: target ok: {options.target_exe}")
    return StepResult("target", True, "Status: target audit ok (read-only)",
                      {"target": info}, warnings)


def _build_launch_command(options: C.AutomaticOptions,
                          account: dict[str, str] | None) -> list[str]:
    cmd = [options.target_exe or "<target-exe>"]
    settings = options.merged_settings()
    # Faithful flag subset from the resolved script (planning only).
    if settings.get("Compatibility", "False") == "True":
        cmd = ["cmd", "/c", "set __COMPAT_LAYER=RUNASINVOKER &&"] + cmd
    cmd.append("-noauthgg")
    if account and account.get("GameAccount"):
        cmd.append(f"-authnToken:<redacted:{account.get('slot', '?')}>")
    slot = settings.get("VirtualClientSlot", "Original")
    if slot and slot != "Original":
        cmd.append(f"# virtual-slot: {slot}")
    return cmd


def plan_launch(options: C.AutomaticOptions, workspace_root: Path,
                log: LogFn = _noop) -> StepResult:
    logins_path = Path(workspace_root) / "logins.ini"
    parser = read_logins(logins_path)
    accounts = list_accounts(parser)
    settings = options.merged_settings()
    plan = {
        "server": options.server,
        "target": options.target_exe,
        "dry_run": options.dry_run_launch,
        "virtual_slot": settings.get("VirtualClientSlot", "Original"),
        "auto_inject_vanillatool": settings.get("AutoInject", "False"),
        "accounts_seen": len(accounts),
        "commands": [],
    }
    login_all = options.login_all and len(accounts) > 0
    if options.login_all and not accounts:
        return StepResult("launch", False,
                          "Status: Login All requested but logins.ini has no accounts",
                          plan)
    if login_all:
        cap = int(settings.get("LoginAllCap", "4") or "4")
        delay = int(settings.get("AMLoginAllDelay", "3000") or "3000")
        plan["login_all_cap"] = cap
        plan["login_all_delay_ms"] = delay
        for row in accounts[:cap]:
            cmd = _build_launch_command(options, row)
            plan["commands"].append({"slot": row.get("slot"), "client": row.get("Client"),
                                     "command": cmd})
            log(f"Status: Login All would start [{row.get('slot')}] ({row.get('Client')})")
    else:
        plan["commands"].append({"slot": None, "client": options.server,
                                 "command": _build_launch_command(options, None)})
    if settings.get("AutoInject") == "True":
        plan["auto_inject_note"] = (
            "Auto Inject Vanillatool is ON in options, but the lab build only "
            "reports the inject plan (d3dx9_30.dll hijack / LoadLibraryW) and "
            "never performs it")
        log("Status: Auto-Inject planned only (never executed)")
    if options.dry_run_launch:
        plan["note"] = ("dry-run: no process is started. Uncheck Dry-Run only on "
                        "Windows with an explicit target to launch plainly "
                        "(still without injection or patching).")
        return StepResult("launch", True, "Status: launch plan ready (dry-run)",
                          plan)
    # Real launch path: plain process start, Windows only, still no injection.
    if os.name != "nt":
        return StepResult("launch", False,
                          "Status: real launch is Windows-only; using dry-run",
                          plan)
    if not options.target_exe or not Path(options.target_exe).is_file():
        return StepResult("launch", False, "Status: cannot launch: target missing",
                          plan)
    try:
        # Launch the first command only, hidden, without any patching.
        first = plan["commands"][0]["command"]
        # Strip planning pseudo-args (virtual-slot comments, redacted tokens).
        real = [c for c in first if not c.startswith("# virtual-slot")]
        real = [c for c in real if "-authnToken:<redacted" not in c]
        creationflags = 0x08000000  # CREATE_NO_WINDOW
        proc = subprocess.Popen(real, creationflags=creationflags,
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL)
        plan["launched_pid"] = proc.pid
        log(f"Status: launched pid {proc.pid} (plain, no injection)")
        return StepResult("launch", True,
                          f"Status: launched pid {proc.pid} (no injection)", plan)
    except Exception as exc:
        return StepResult("launch", False, f"Status: launch failed: {exc}",
                          {**plan, "error": str(exc)})


def run_automatic(options: C.AutomaticOptions,
                  workspace_root: Path | str = DEFAULT_WORKSPACE,
                  log: LogFn | None = None) -> AutomaticReport:
    """Run the full automatic pipeline and return a JSON-safe report."""
    log = log or _noop
    workspace_root = Path(workspace_root)
    report = AutomaticReport(ok=True, status="Status: starting..",
                             options=options.as_dict())
    log("Status: starting automatic run..")

    env = check_environment(options)
    report.steps.append(env)
    if not env.ok:
        report.ok = False
        report.status = env.status
        return report

    ws_step, ws = recover_workspace(options, workspace_root, log)
    report.steps.append(ws_step)
    if not ws_step.ok:
        report.ok = False
        report.status = ws_step.status
        return report

    mapper_step = run_mapper_ladder(ws, options.missing_providers, log)
    report.steps.append(mapper_step)
    # Mapper conflicts are warnings, not fatal: the emulator/target path can
    # still be validated.  Mark overall ok=False only if NOTHING works.
    if not mapper_step.ok:
        report.steps[-1].warnings.append("continuing despite mapper conflict")

    emu_step = self_test_emulator(options, log)
    report.steps.append(emu_step)
    if not emu_step.ok:
        report.ok = False
        report.status = emu_step.status
        return report

    tgt_step = audit_target(options, log)
    report.steps.append(tgt_step)
    if not tgt_step.ok:
        # Target missing is fatal for a launch run, but the emulator +
        # workspace recovery already succeeded; surface clearly.
        report.ok = False
        report.status = tgt_step.status
        return report

    launch_step = plan_launch(options, workspace_root, log)
    report.steps.append(launch_step)
    if not launch_step.ok:
        report.ok = False
        report.status = launch_step.status
        return report

    if not mapper_step.ok:
        report.ok = False
        report.status = "Status: completed with mapper conflict (see hints)"
    else:
        report.status = "Status: automatic run complete"
    log(report.status)
    # Persist the report next to the workspace for the GUIs.
    try:
        (workspace_root / "report.json").write_text(
            json.dumps(report.as_dict(), indent=2) + "\n", encoding="utf-8")
        (workspace_root / "report.txt").write_text(
            render_text_report(report), encoding="utf-8")
    except OSError:
        pass
    return report


def render_text_report(report: AutomaticReport) -> str:
    lines = [f"{C.APP_NAME} {C.APP_VERSION}", report.status, ""]
    for step in report.steps:
        mark = "OK " if step.ok else "FAIL"
        lines.append(f"[{mark}] {step.name}: {step.status}")
        for warn in step.warnings:
            lines.append(f"      warn: {warn}")
    lines.append("")
    lines.append("Safety: " + "; ".join("no " + r for r in C.SAFETY_REFUSALS))
    return "\n".join(lines) + "\n"
