#!/usr/bin/env python3
"""Static triage for native/packed PEs (offline, stdlib-only).

Prints a PE summary (arch, link timestamp, sections) and dumps ASCII +
UTF-16 strings for inspection.  Used for components that are *not* AutoIt
decompilable in this kit:

  * ESP overlay DLL, driver kit (sys/dll/bin), NovaApi trio, d3d reloader,
    mouse-fix DLL (native code — string/import triage)
  * lr.exe / BBQ.bin / Unique-ID (UPX-NRV packed — surface strings +
    version resources only)
  * crackme.exe (packed/virtualized — surface strings)

Version resources are surfaced via UTF-16 strings from ``.rsrc``
(``FileDescription`` / ``FileVersion`` / ``ProductName``), which is how the
lr (Para's UnLimiter 1.2.8.0) and BBQ (Para's BBQ 1.2.1.0) identities were
established.  See ``docs/OFFLINE_RUNBOOK.md`` for the exact per-component
probe commands behind each report claim.

Usage:
    python3 triage.py FILE [FILE ...] [--strings DIR] [--grep PAT ...]
"""

import argparse
import datetime
import hashlib
import os
import re
import struct
import sys


def parse_pe(data: bytes):
    info = {'mz': data[:2] == b'MZ'}
    if not info['mz']:
        return info
    pe_off = struct.unpack_from('<I', data, 0x3C)[0]
    if data[pe_off:pe_off + 4] != b'PE\0\0':
        return info
    machine = struct.unpack_from('<H', data, pe_off + 4)[0]
    n_sec = struct.unpack_from('<H', data, pe_off + 6)[0]
    timestamp = struct.unpack_from('<I', data, pe_off + 8)[0]
    opt_size = struct.unpack_from('<H', data, pe_off + 20)[0]
    magic = struct.unpack_from('<H', data, pe_off + 24)[0]
    info.update({
        'machine': {0x14C: 'i386', 0x8664: 'x86-64'}.get(machine, hex(machine)),
        'timestamp': datetime.datetime.fromtimestamp(
            timestamp, tz=datetime.timezone.utc).strftime('%Y-%m-%d %H:%M UTC'),
        'pe32plus': magic == 0x20B,
        'sections': [],
    })
    sec_off = pe_off + 24 + opt_size
    for i in range(n_sec):
        entry = data[sec_off + i * 40: sec_off + (i + 1) * 40]
        if len(entry) < 40:
            break
        name, vsize, vaddr, rawsize, rawptr = struct.unpack('<8sIIII', entry[:24])
        info['sections'].append((name.rstrip(b'\0').decode('ascii', 'replace'),
                                 vsize, rawsize))
    return info


def strings_ascii(data: bytes, minimum: int = 5):
    return [m.group(0).decode('ascii')
            for m in re.finditer(rb'[\x20-\x7e]{%d,}' % minimum, data)]


def strings_utf16(data: bytes, minimum: int = 5):
    out = []
    pattern = rb'(?:[\x20-\x7e]\x00){%d,}' % minimum
    for m in re.finditer(pattern, data):
        out.append(m.group(0).decode('utf-16le'))
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description='static PE + strings triage')
    ap.add_argument('files', nargs='+', help='files to triage')
    ap.add_argument('--strings', help='write <name>.strings (ascii+utf16) here')
    ap.add_argument('--grep', action='append', default=[],
                    help='case-insensitive probe shown with context counts')
    args = ap.parse_args()

    if args.strings:
        os.makedirs(args.strings, exist_ok=True)

    for path in args.files:
        data = open(path, 'rb').read()
        print(f'=== {path} ({len(data)} bytes)')
        print(f'    sha256={hashlib.sha256(data).hexdigest()}')
        info = parse_pe(data)
        if not info.get('mz'):
            print('    not a PE')
            continue
        print(f"    arch={info.get('machine')} pe32+={info.get('pe32plus')} "
              f"link-time={info.get('timestamp')}")
        for name, vsize, rawsize in info.get('sections', []):
            print(f'    sec {name:10s} vsize={vsize:<10d} raw={rawsize}')
        asc = strings_ascii(data)
        uni = strings_utf16(data)
        print(f'    strings: {len(asc)} ascii, {len(uni)} utf16')
        for pat in args.grep:
            hits = [s for s in asc + uni if pat.lower() in s.lower()]
            print(f'    grep {pat!r}: {len(hits)}')
            for h in hits[:12]:
                print(f'      | {h[:150]}')
        if args.strings:
            base = re.sub(r'[^A-Za-z0-9._-]+', '_', os.path.basename(path))
            with open(os.path.join(args.strings, base + '.strings'), 'w',
                      encoding='utf-8') as fh:
                fh.write(f'# ascii ({len(asc)})\n')
                fh.write('\n'.join(asc))
                fh.write(f'\n# utf16 ({len(uni)})\n')
                fh.write('\n'.join(uni))
                fh.write('\n')


if __name__ == '__main__':
    main()
