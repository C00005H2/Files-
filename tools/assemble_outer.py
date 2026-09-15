#!/usr/bin/env python3
"""Reassemble payload.exe from the Vanillatool outer script (offline).

The outer script carries the inner PE as 8,558 hex-string variables that are
concatenated in order::

    $UTJ = "0x4D5A9000..."      ; first chunk (PE headers, 0x-prefixed)
    $UXF = "1A2B3C..."          ; ... 8,557 more chunks ...
    $CWL [ 1 ] &= $UTJ
    $CWL [ 1 ] &= $UXF
    ... (8,558 appends total)

At runtime ``Binary($CWL[1])`` is written out as the payload.  This tool
repeats that concatenation and verifies the result:

  * size 8,557,568 bytes, starts with ``MZ``
  * sha256 ``5d1a3f4741ebc15c3747530081bd739787ddc69a3fbe2559b95e91bb331f0541``

Usage:
    python3 assemble_outer.py OUTER_SCRIPT.AU3 --out PAYLOAD.exe
"""

import argparse
import hashlib
import re
import sys

EXPECT_SIZE = 8557568
EXPECT_SHA256 = '5d1a3f4741ebc15c3747530081bd739787ddc69a3fbe2559b95e91bb331f0541'


def main() -> None:
    ap = argparse.ArgumentParser(description='outer-script payload assembler')
    ap.add_argument('script', help='outer script.au3')
    ap.add_argument('--out', required=True, help='payload.exe output')
    args = ap.parse_args()

    src = open(args.script, encoding='utf-8').read()

    chunks: dict[str, str] = {}
    for m in re.finditer(r'\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"(?:0x)?([0-9A-Fa-f]+)"', src):
        var, hexdata = m.group(1), m.group(2)
        if len(hexdata) >= 64:  # payload chunks are ~2000 chars; ignore short hex
            chunks[var] = hexdata
    order = re.findall(r'\$CWL\s*\[\s*1\s*\]\s*&=\s*\$([A-Za-z_][A-Za-z0-9_]*)', src)
    print(f'[+] chunk vars: {len(chunks)}, appends in order: {len(order)}', file=sys.stderr)

    missing = [v for v in order if v not in chunks]
    if missing:
        raise SystemExit(f'{len(missing)} chunks have no hex assignment, e.g. {missing[:5]}')

    payload = bytes.fromhex(''.join(chunks[v] for v in order))
    digest = hashlib.sha256(payload).hexdigest()
    print(f'[+] payload={len(payload)} bytes sha256={digest}', file=sys.stderr)
    if payload[:2] != b'MZ':
        raise SystemExit('payload does not start with MZ')
    if len(payload) != EXPECT_SIZE or digest != EXPECT_SHA256:
        raise SystemExit(f'ORACLE MISMATCH: want size={EXPECT_SIZE} '
                         f'sha256={EXPECT_SHA256[:16]}...{EXPECT_SHA256[-8:]}')
    print('[+] oracle match: size + sha256 verified', file=sys.stderr)
    open(args.out, 'wb').write(payload)
    print(f'[+] wrote {args.out}', file=sys.stderr)


if __name__ == '__main__':
    main()
