"""Offsets.txt fixture helpers for the injected in-game scripts.

The client's injected scripts (``fastscript.pscp`` and the per-version
bundles) download ``/Offsets.txt`` from the service and parse an INI-like
body.  The extracted scripts wait for the feature offsets to arrive with a
bounded loop shaped like::

    #DO=60000
    ...
    #UNTIL=%Var[Offset_Base_SubText],>0

so a served body must contain at least one ``[section]`` header followed by
``Base_SubText=<non-zero>``; otherwise every injected feature spins until its
timeout before reporting failure.

The placeholder values produced by :func:`build_offsets_text` are
deliberately the smallest legal non-zero integers.  They keep the parser and
wait-loop boundary alive for local testing, but they are NOT real Aion
memory offsets and must not be used to drive process-memory features.  A
real per-build profile can be served with ``--offsets-file``; its shape is
validated by :func:`load_offsets_file`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Mapping
import re

SECTION_HEADER = re.compile(r"^\[(?P<name>[^\]]+)\]$")
ASSIGNMENT = re.compile(r"^(?P<key>[A-Za-z_][A-Za-z0-9_.]*)(?P<spaces>\s*)=(?P<value>.*)$")

# fastscript.pscp and the per-version in-game bundles park on this key until
# it is non-zero, so it is the one value the emulator must always provide.
REQUIRED_KEYS: tuple[str, ...] = ("Base_SubText",)

# Section written by build_offsets_text().  load_offsets_file() accepts any
# section names because the extracted scripts read their own section by name
# and ignore the rest.
SECTION_NAME = "Offsets"

# Smallest legal non-zero placeholders -- deliberately not real addresses.
PLACEHOLDER_VALUES: dict[str, str] = {"Base_SubText": "1"}


def parse_offsets_text(text: str) -> dict[str, dict[str, str]]:
    """Parse an INI-like Offsets.txt body into ``{section: {key: value}}``.

    A minimal parser is used instead of ``configparser`` because real
    profiles carry raw offset expressions (``0x...``, ``module+0x...``) that
    must be preserved verbatim, and section/key case matters to the scripts.
    """
    sections: dict[str, dict[str, str]] = {}
    current: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith((";", "#")):
            continue
        header = SECTION_HEADER.match(line)
        if header:
            current = header.group("name").strip()
            sections.setdefault(current, {})
            continue
        if current is None:
            # Tolerate a header-less body by collecting into a default
            # section; validation still requires a real header afterwards.
            current = ""
            sections.setdefault(current, {})
        assignment = ASSIGNMENT.match(line)
        if assignment:
            sections[current][assignment.group("key")] = assignment.group("value").strip()
    return sections


def _is_non_zero(value: str) -> bool:
    stripped = value.strip()
    if not stripped:
        return False
    try:
        return int(stripped, 0) != 0
    except ValueError:
        # Non-numeric expressions (e.g. "module+0x10") count as present.
        return stripped.lower() not in {"0", "0x0", "false", "no"}


def validate_offsets_text(text: str) -> dict[str, str]:
    """Validate a body and return the flat mapping that satisfies the scripts.

    Raises ``ValueError`` with a human-readable reason when the body could
    not keep the injected scripts' wait loop alive.
    """
    sections = parse_offsets_text(text)
    if not any(sections):
        raise ValueError("offsets body contains no [section] header")

    required: dict[str, str] = {}
    missing: list[str] = []
    zeroed: list[str] = []
    for key in REQUIRED_KEYS:
        for values in sections.values():
            if key in values:
                required[key] = values[key]
                break
        else:
            missing.append(key)
            continue
        if not _is_non_zero(required[key]):
            zeroed.append(key)

    if missing:
        raise ValueError("offsets body is missing required key(s): " + ", ".join(missing))
    if zeroed:
        raise ValueError(
            "offsets body sets required key(s) to zero, which keeps the "
            "injected scripts' wait loop spinning: " + ", ".join(zeroed)
        )
    return required


def build_offsets_text(values: Mapping[str, str] | None = None) -> str:
    """Return the built-in placeholder Offsets.txt body.

    ``values`` can override or add keys; a required key overridden to a
    zero value is rejected so the fixture can never deadlock the scripts.
    """
    merged = dict(PLACEHOLDER_VALUES)
    if values:
        merged.update({key: str(value) for key, value in values.items()})
        for key in REQUIRED_KEYS:
            if key in merged and not _is_non_zero(merged[key]):
                raise ValueError(f"{key} must be non-zero or the injected scripts will wait forever")
    lines = [f"[{SECTION_NAME}]"]
    lines.extend(f"{key}={merged[key]}" for key in sorted(merged))
    return "\r\n".join(lines) + "\r\n"


def load_offsets_file(path: Path) -> str:
    """Read, validate, and normalize an Offsets.txt file for serving.

    Line endings are normalized to CRLF (InetGet/InetRead keep them verbatim
    and the reference bodies use CRLF) and a trailing newline is ensured.
    """
    text = Path(path).read_text(encoding="utf-8")
    validate_offsets_text(text)
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = normalized.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return "\r\n".join(lines) + "\r\n"
