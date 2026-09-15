#!/usr/bin/env python3
"""Decode VanillaTool's string table and emit a useful network-oriented report.

The extracted AutoIt script calls A0200001905($OS[n]); that routine decodes each
hex byte pair with Dec()/Chr().  A0200001905_ initializes $OS with
StringSplit(FileRead(table), '!3{', 1), so the table is intentionally decoded
as one-based entries.

This is deliberately a small, dependency-free helper.  It does not execute
any AutoIt code.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Iterable

URL_RE = re.compile(r"(?:https?|ftp)://[^\s'\"]+", re.IGNORECASE)
HOST_RE = re.compile(r"(?<![A-Za-z0-9.-])(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?::\d+)?(?:/[^\s'\"]*)?")


def decode_table(path: Path) -> list[str]:
    raw = path.read_text(encoding="ascii", errors="strict")
    parts = raw.split("!3{")
    values = [""]
    for number, part in enumerate(parts[1:], 1):
        if len(part) % 2:
            raise ValueError(f"entry {number} has an odd number of hex digits")
        try:
            values.append(bytes.fromhex(part).decode("latin-1"))
        except ValueError as exc:
            raise ValueError(f"entry {number} is not hexadecimal") from exc
    return values


def network_strings(values: Iterable[str]) -> list[dict[str, object]]:
    found: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    for index, value in enumerate(values):
        for kind, regex in (("url", URL_RE), ("host", HOST_RE)):
            for match in regex.finditer(value):
                item = (kind, match.group(0))
                if item in seen:
                    continue
                seen.add(item)
                found.append({"kind": kind, "value": match.group(0), "table_index": index})
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("table", type=Path, help="extracted .au3.tbl file")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of a text report")
    parser.add_argument("--entry", type=int, action="append", help="print a decoded table entry")
    args = parser.parse_args()

    values = decode_table(args.table)
    if args.entry:
        for index in args.entry:
            if not 0 <= index < len(values):
                parser.error(f"table index out of range: {index}")
            print(f"{index}: {values[index]!r}")
        return 0

    report = {
        "entry_count": len(values) - 1,
        "network_strings": network_strings(values),
    }
    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print(f"decoded entries: {report['entry_count']}")
        for item in report["network_strings"]:
            print(f"{item['table_index']:5d} {item['kind']:4s} {item['value']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
