"""Headless CLI for the Account Manager automatic pipeline.

The GUIs (browser + desktop) are thin front-ends over :mod:`am_pipeline`;
this CLI exposes the same run for scripts and for machines without a display::

    # one-click automatic run (workspace + mapper + emulator + target + plan)
    python -m vanillatool_emulator.am_cli --auto --target-exe game.dll

    # ...with Login-All simulation over every account in logins.ini
    python -m vanillatool_emulator.am_cli --auto --target-exe game.dll --login-all

    # start only the persistent emulator a real client can point at
    python -m vanillatool_emulator.am_cli --serve --port 8080

    # start the browser GUI instead
    python -m vanillatool_emulator.am_web --port 8090
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import am_config as C
from .am_pipeline import render_text_report, run_automatic
from .am_workspace import DEFAULT_WORKSPACE


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Automatic Account Manager lab run (headless)")
    parser.add_argument("--auto", action="store_true",
                        help="run the full automatic pipeline once")
    parser.add_argument("--serve", action="store_true",
                        help="run the persistent emulator server instead")
    parser.add_argument("--workspace", type=Path, default=DEFAULT_WORKSPACE)
    parser.add_argument("--target-exe", default="",
                        help="target executable to audit (e.g. bin64/aion.bin)")
    parser.add_argument("--server", default="EuroAion",
                        help=f"server preset, one of: {', '.join(C.SERVERS)}")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--version", default=C.EMULATOR_VERSION_DEFAULT)
    parser.add_argument("--orythm", default=C.DEFAULT_ORYTHM)
    parser.add_argument("--prythm", default=C.DEFAULT_PRHYTHM)
    parser.add_argument("--response-file", default="")
    parser.add_argument("--offsets-file", default="")
    parser.add_argument("--no-startup-markers", action="store_true",
                        help="disable the 60 zero-placeholder pre-GUI markers")
    parser.add_argument("--device-name", default="")
    parser.add_argument("--missing-providers", default="",
                        help="comma-separated provider ids to treat as blocked")
    parser.add_argument("--login-all", action="store_true")
    parser.add_argument("--real-launch", action="store_true",
                        help="Windows only: plainly start the target (never injects). "
                             "Default is dry-run.")
    parser.add_argument("--json", action="store_true",
                        help="print the machine-readable JSON report")
    parser.add_argument("--set", action="append", default=[],
                        help="hive override KEY=VALUE (repeatable)")
    return parser


def _parse_set(items: list[str]) -> dict[str, str]:
    settings: dict[str, str] = {}
    for item in items:
        if "=" not in item:
            raise SystemExit(f"--set must be KEY=VALUE, got {item!r}")
        key, value = item.split("=", 1)
        key = key.strip()
        if key not in C.HIVE_DEFAULTS and key != "VirtualClientSlot":
            raise SystemExit(f"unknown setting {key!r}; "
                             f"known: {', '.join(sorted(C.HIVE_DEFAULTS))}")
        settings[key] = value.strip()
    return settings


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.serve and args.auto:
        raise SystemExit("use only one of --serve and --auto")
    if args.serve:
        from .server import EmulatorConfig, EmulatorHTTPServer
        config = EmulatorConfig(
            version=args.version, orythm=args.orythm, prythm=args.prythm,
            account_manager_startup=not args.no_startup_markers)
        if args.response_file:
            p = Path(args.response_file)
            if not p.is_file():
                raise SystemExit(f"--response-file not found: {p}")
            config.response_file = p
            config.account_manager_startup = False
        if args.offsets_file:
            from .offsets import load_offsets_file
            try:
                config.offsets_text = load_offsets_file(Path(args.offsets_file))
            except (OSError, ValueError) as exc:
                raise SystemExit(f"bad --offsets-file: {exc}")
        httpd = EmulatorHTTPServer((args.host, args.port), config)
        print(f"emulator listening on http://{args.host}:{httpd.server_address[1]}",
              flush=True)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            httpd.server_close()
        return 0

    if not args.auto:
        build_parser().print_help()
        return 2

    options = C.AutomaticOptions(
        target_exe=args.target_exe,
        server=args.server,
        emulator_host=args.host,
        emulator_port=args.port,
        version=args.version,
        orythm=args.orythm,
        prythm=args.prythm,
        account_manager_startup=not args.no_startup_markers,
        response_file=args.response_file,
        offsets_file=args.offsets_file,
        device_name=args.device_name,
        missing_providers=args.missing_providers,
        login_all=args.login_all,
        dry_run_launch=not args.real_launch,
        settings=_parse_set(args.set),
    )
    report = run_automatic(options, args.workspace, log=print)
    if args.json:
        print(json.dumps(report.as_dict(), indent=2))
    else:
        print()
        print(render_text_report(report))
    return 0 if report.ok else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
