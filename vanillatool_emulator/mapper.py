"""Emulation of the Account Manager "driver mapping" step.

Para's Account Manager 5.43 loads its kernel components through a local
process chain instead of an HTTP call:

1. It drops ``VanillaDrv_3.13.sys`` as ``udk_2.bin`` (the *victim* driver),
   ``VanillaUDK_3.11.dll`` as ``udk_1.dll`` and ``VanillaUDK_3.13.bin`` as
   ``udk.bin`` (a KDU-style kernel driver mapper).
2. Unless the configured device name equals the GUI status string, it
   patches two UTF-16LE device-path slots inside ``udk_2.bin``:
   ``\\Device\\<name>`` (38 bytes at offset 0x1FF0 / 8176) and
   ``\\DosDevices\\<name>`` (46 bytes at offset 0x2020 / 8224).  The name
   comes from ``HKCU\\Software\\Para's NoAnimation`` value ``fHide_UDK``
   and defaults to a random 11-character string.
3. It runs the mapper hidden with ``-prv <id> -map udk_2.bin``, walking a
   provider ladder: ``-prv 1`` (RTCore64, MSI Afterburner) -> ``-prv 2``
   (Gdrv, Gigabyte) -> ``-prv 3`` (ATSZIO64, ASUSTeK WinFlash) -> ``-map``
   without ``-prv`` (mapper default), re-opening ``\\.<name>`` after each
   attempt to see whether the victim driver got loaded.
4. It scans the merged stdout/stderr of the mapper for conflict lines and
   shows a user hint when a third-party vendor driver blocks the mapping:
   ``Status: Make sure MSI Afterburner is closed.``, ``Status: Make sure
   Gigabyte TOOLS is closed.`` or ``Status: Make sure ASUSTeK WinFlash
   utility is closed.``

This module reproduces that observable CLI contract: the argument syntax,
the transcript format Account Manager's ``StringRegExp`` checks parse, and
the device-name patch sites.  It cannot create a real ``\\.<device>``
kernel object from user mode, so a real Account Manager run still needs a
kernel for its final device probe; everything up to that probe is
emulated faithfully and deterministically.

Transcript note: the bundled VanillaUDK_3.13 binary prints the bare line
``[!] Unable to open vulnerable driver`` (no trailing comma), while
Account Manager 5.43's conflict regex is
``(?m)\\[\\!\\] Unable to open vulnerable driver\\, `` *with* a comma.
The emulator emits the comma form (plus a reason) so the client parser
actually matches.
"""

from __future__ import annotations

from dataclasses import dataclass
import argparse
import re
import sys
from pathlib import Path
from typing import Iterable, Mapping

# ---------------------------------------------------------------------------
# Victim-driver layout (VanillaDrv_3.13.sys / udk_2.bin)
# ---------------------------------------------------------------------------

VICTIM_DRIVER_SIZE = 13312
DEVICE_PATH_OFFSET = 0x1FF0  # 8176, patched by A24C8C02C50 call #1
DEVICE_PATH_SIZE = 38  # UTF-16LE "\\Device\\" + 11-char name
DOS_DEVICE_PATH_OFFSET = 0x2020  # 8224, patched by A24C8C02C50 call #2
DOS_DEVICE_PATH_SIZE = 46  # UTF-16LE "\\DosDevices\\" + 11-char name

DEFAULT_NAME_LENGTH = 11  # AM's default generator A0349104C2D(11)

_DEVICE_PREFIX = "\\Device\\"
_DOS_PREFIX = "\\DosDevices\\"

# ---------------------------------------------------------------------------
# Provider database (the ids are Account Manager's ``-prv`` slots)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Provider:
    """A vulnerable-provider driver entry, as named in the transcripts."""

    id: int
    name: str
    vendor: str
    # The exact GUI hint Account Manager shows when this provider conflicts.
    client_hint: str


PROVIDERS: Mapping[int, Provider] = {
    1: Provider(1, "RTCore64", "MSI Afterburner", "Status: Make sure MSI Afterburner is closed."),
    2: Provider(2, "Gdrv", "Gigabyte", "Status: Make sure Gigabyte TOOLS is closed."),
    3: Provider(3, "ATSZIO64", "ASUSTeK WinFlash", "Status: Make sure ASUSTeK WinFlash utility is closed."),
}

# Account Manager's own StringRegExp patterns (constants $OS[59951..60047]).
FAILURE_PREFIX_PATTERN = r"(?m)\[\!\] Unable to open vulnerable driver\, "


def provider_pattern(name: str) -> str:
    """Return the regex Account Manager uses to detect ``name`` conflicts."""
    return r'(?m)\[\+\] Provider: ".*?", Name "%s"' % name


def hint_for(provider_name: str) -> str | None:
    """Return the client GUI hint for a failing provider name, if any."""
    for provider in PROVIDERS.values():
        if provider.name == provider_name:
            return provider.client_hint
    return None


def hint_conflict(transcript: str) -> str | None:
    """Apply both of Account Manager's checks; return the hint it would show.

    The client flags a conflict only when the transcript contains *both* the
    failure prefix and the matching ``[+] Provider: ..., Name ...`` line.
    """
    if not re.search(FAILURE_PREFIX_PATTERN, transcript):
        return None
    for provider in PROVIDERS.values():
        if re.search(provider_pattern(provider.name), transcript):
            return provider.client_hint
    return None


# ---------------------------------------------------------------------------
# Device-name patch helpers
# ---------------------------------------------------------------------------


def _decode_slot(data: bytes, offset: int, size: int) -> str:
    return data[offset : offset + size].decode("utf-16-le", errors="replace").rstrip("\x00")


def read_device_slots(data: bytes) -> tuple[str, str]:
    """Return ``(device_path, dos_path)`` exactly as stored in the driver.

    AM-patched slots carry the full ``\\Device\\<name>`` /
    ``\\DosDevices\\<name>`` text; pristine builds contain a bare random
    placeholder of the same slot length instead.
    """
    return (
        _decode_slot(data, DEVICE_PATH_OFFSET, DEVICE_PATH_SIZE),
        _decode_slot(data, DOS_DEVICE_PATH_OFFSET, DOS_DEVICE_PATH_SIZE),
    )


def device_name(data: bytes) -> str:
    """Extract the configured device name from a (patched) victim driver."""
    device = read_device_slots(data)[0]
    if device.startswith(_DEVICE_PREFIX):
        return device[len(_DEVICE_PREFIX) :]
    return device


def patch_device_names(data: bytes, name: str) -> bytes:
    """Return a copy of ``data`` with both device slots set to ``name``.

    This reproduces the two ``A24C8C02C50`` writes: fixed-size slots, so
    ``name`` must be exactly 11 characters (Account Manager's default
    generator length); anything else would corrupt the driver image.
    """
    if len(name) != DEFAULT_NAME_LENGTH:
        raise ValueError(
            "device name must be exactly %d characters (got %d)" % (DEFAULT_NAME_LENGTH, len(name))
        )
    buffer = bytearray(data)
    device = (_DEVICE_PREFIX + name).encode("utf-16-le")
    dos = (_DOS_PREFIX + name).encode("utf-16-le")
    if len(device) != DEVICE_PATH_SIZE or len(dos) != DOS_DEVICE_PATH_SIZE:
        raise ValueError("patched slot sizes do not match the driver layout")
    buffer[DEVICE_PATH_OFFSET : DEVICE_PATH_OFFSET + DEVICE_PATH_SIZE] = device
    buffer[DOS_DEVICE_PATH_OFFSET : DOS_DEVICE_PATH_OFFSET + DOS_DEVICE_PATH_SIZE] = dos
    return bytes(buffer)


# ---------------------------------------------------------------------------
# Mapper transcript emulation
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class MapperRun:
    """Result of one emulated mapper invocation."""

    argv: tuple[str, ...]
    transcript: str
    exit_code: int
    outcome: str  # "mapped" | "provider-unavailable" | "input-missing" | "usage"
    provider: Provider | None = None
    driver_name: str | None = None
    device_name_value: str | None = None

    @property
    def failed(self) -> bool:
        return self.exit_code != 0

    def conflict_hint(self) -> str | None:
        """The client GUI hint this transcript triggers, if any."""
        if self.provider is None or self.outcome != "provider-unavailable":
            return None
        if re.search(FAILURE_PREFIX_PATTERN, self.transcript) and re.search(
            provider_pattern(self.provider.name), self.transcript
        ):
            return self.provider.client_hint
        return None


_USAGE = (
    "[?] Usage: kdu [Provider][Command]\r\n"
    "kdu -list         - List available providers\r\n"
    "kdu -prv id       - Optional, sets provider id to be used with rest of commands, default 0\r\n"
    "kdu -map filename - Map driver to the kernel and execute it entry point, this command have dependencies listed below\r\n"
)

_INPUT_MISSING = "[!] Input file cannot be found, abort."


def _parse_argv(argv: Iterable[str]) -> tuple[int | None, str | None, list[str]]:
    """Split ``-prv <id>`` and ``-map <file>`` out of the raw command line."""
    argv = list(argv)
    provider_id: int | None = None
    driver_path: str | None = None
    rest: list[str] = []
    index = 0
    while index < len(argv):
        token = argv[index]
        if token == "-prv" and index + 1 < len(argv):
            try:
                provider_id = int(argv[index + 1])
            except ValueError:
                provider_id = -1
            index += 2
        elif token == "-map" and index + 1 < len(argv):
            driver_path = argv[index + 1]
            index += 2
        else:
            rest.append(token)
            index += 1
    return provider_id, driver_path, rest


def _header(provider: Provider | None) -> list[str]:
    lines = ["KDU (Kernel Driver Utility)"]
    if provider is not None:
        lines += [
            "Base kernel driver utility. Provider # %d" % provider.id,
            "",
            '[+] Provider: "%s", Name "%s"' % (provider.vendor, provider.name),
        ]
    return lines


def _success_body(provider: Provider, driver_path: str, driver_device: str, ntoskrnl_base: int) -> list[str]:
    victim_base = ntoskrnl_base + 0x101B0000
    return [
        "[+] Selected provider: %d" % provider.id,
        "[+] MSFT Driver block list is disabled",
        '[+] Input driver file "%s" loaded' % driver_path,
        "[+] Executing pre-open callback for given provider",
        '[+] Driver device "\\\\.\\%s" has been opened successfully' % provider.name,
        '[+] Vulnerable driver "%s" loaded' % provider.name,
        '[+] Processing victim "%s" driver' % driver_device,
        "[+] Ntoskrnl.exe mapped at 0x%X" % ntoskrnl_base,
        "[+] Resolving kernel import for input driver",
        "[+] DSE flags (0x%X) value: 0x6, new value to be written: 0xE" % (ntoskrnl_base + 0x6302F8),
        "[+] DSE patch executed successfully",
        "[+] Looking for %s driver dispatch memory pages, please wait" % driver_device,
        "[+] Number of pages found: 2, modified: 2",
        "[+] Driver handler code modified",
        "[+] Successfully loaded victim driver",
        "[+] Query victim image information",
        "[+] Query victim loaded driver layout",
        "[+] Victim target address 0x%X" % victim_base,
        "[~] Shellcode result: NTSTATUS (0x00000000)",
        "[+] Victim released",
        "[+] Return value: 0. Bye-bye!",
    ]


def simulate(
    argv: Iterable[str],
    *,
    unavailable_providers: Iterable[int] = (),
    driver_bytes: bytes | None = None,
    ntoskrnl_base: int = 0xFFFFF8042A400000,
) -> MapperRun:
    """Emulate one ``udk.bin`` invocation.

    ``unavailable_providers`` lists provider ids whose vulnerable driver is
    treated as blocked/in use (e.g. MSI Afterburner holding RTCore64);
    requesting such a provider yields the conflict transcript that makes
    Account Manager show its "close <vendor> tool" hint.
    """
    argv = tuple(argv)
    unavailable = frozenset(unavailable_providers)
    provider_id, driver_path, rest = _parse_argv(argv)

    usage = MapperRun(
        argv,
        _USAGE + "[!] Input file not specified",
        2,
        "usage",
    )
    if driver_path is None or rest:
        return usage

    if driver_bytes is None:
        path = Path(driver_path)
        if not path.is_file():
            transcript = "\r\n".join([_INPUT_MISSING, "[+] Return value: 1. Bye-bye!"])
            return MapperRun(argv, transcript, 1, "input-missing")
        data = path.read_bytes()
    else:
        data = driver_bytes

    name = device_name(data)
    device_path = read_device_slots(data)[0]
    if not device_path.startswith(_DEVICE_PREFIX):
        # Pristine builds carry a bare placeholder name; the kernel-side
        # code treats the slot as the full path after AM's patch.
        device_path = _DEVICE_PREFIX + name

    provider: Provider | None = None
    lines: list[str]
    if provider_id is None:
        lines = ["[+] Selected provider: 0"]
    elif provider_id in PROVIDERS:
        provider = PROVIDERS[provider_id]
        lines = _header(provider) + ["[+] Selected provider: %d" % provider.id]
    else:
        lines = [
            "[+] Selected provider: 0",
            "[!] Invalid provider id %d specified, default will be used (0)" % provider_id,
        ]
    lines.append('[+] Input driver file "%s" loaded' % driver_path)

    if provider is not None and provider.id in unavailable:
        body = [
            "[+] Executing pre-open callback for given provider",
            "[!] Unable to open vulnerable driver, the driver may be blocked or already in use",
            "[+] Return value: 1. Bye-bye!",
        ]
        transcript = "\r\n".join(lines + body)
        return MapperRun(
            argv,
            transcript,
            1,
            "provider-unavailable",
            provider,
            driver_path,
            name,
        )

    effective = provider if provider is not None else Provider(0, "generic", "default", "")
    if provider is None:
        body = _success_body(effective, driver_path, device_path, ntoskrnl_base)
    else:
        body = _success_body(effective, driver_path, device_path, ntoskrnl_base)[2:]
    transcript = "\r\n".join(lines + body)
    return MapperRun(argv, transcript, 0, "mapped", provider, driver_path, name)


# ---------------------------------------------------------------------------
# Command line entry point
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="udk",
        description="Local emulation of Para's VanillaUDK_3.13 mapper (udk.bin) as invoked by Account Manager 5.43",
    )
    parser.add_argument("-prv", dest="provider", type=int, help="provider id (1=RTCore64, 2=Gdrv, 3=ATSZIO64)")
    parser.add_argument("-map", dest="driver", required=True, help="victim driver file (udk_2.bin)")
    parser.add_argument(
        "--missing",
        default="",
        help="comma-separated provider ids to treat as blocked/in use, e.g. --missing 1,2",
    )
    parser.add_argument(
        "--ntoskrnl-base",
        default="0xFFFFF8042A400000",
        help="ntoskrnl base address shown in the success transcript",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    missing = {int(part) for part in args.missing.split(",") if part.strip()}
    try:
        ntoskrnl_base = int(str(args.ntoskrnl_base), 16)
    except ValueError:
        raise SystemExit("--ntoskrnl-base must be hexadecimal") from None
    command = [] if args.provider is None else ["-prv", str(args.provider)]
    run = simulate(
        command + ["-map", args.driver],
        unavailable_providers=missing,
        ntoskrnl_base=ntoskrnl_base,
    )
    sys.stdout.write(run.transcript.replace("\r\n", "\n") + "\n")
    return run.exit_code


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
