#!/usr/bin/env python3
"""Decompile AutoIt EA06 script blobs (offline, vendored autoit_ripper).

Two input modes:

  * ``--rcdata BLOB`` — raw script-resource blob (as produced by
    ``upx_unpack.py`` for UPX-packed samples, where the blob lives in the
    compressed region and must be sliced out of the decompressed image).
  * ``--exe FILE`` — plain (non-UPX) AutoIt exe with a file-backed ``.rsrc``
    (Auto Update, Rename Processes, helper binaries): the biggest
    ``RT_RCDATA`` entry is used.

The upstream ``MAX_SCRIPT_SIZE`` (10 MB) guard is raised: the Vanillatool
outer script alone uncompresses to ~17 MB.

``autoit_ripper`` is vendored under ``vendor/`` (pure Python).  It imports
``pefile`` at module scope but the code path used here never touches it, so
a stub module is injected instead of vendoring the real dependency.
"""

import argparse
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'vendor'))

# --- stub out pefile (imported but unused by our code path) ---
import types


class _Stub:
    """Dummy for unevaluated annotations (pefile.PE etc.)."""

    def __init__(self, *a, **k):
        raise RuntimeError('stub pefile: this code path needs the real pefile')


_pe_stub = types.ModuleType('pefile')
_pe_stub.PE = _Stub
_pe_stub.ResourceDirData = _Stub
_pe_stub.Structure = _Stub


def _stub_getattr(name):
    raise RuntimeError(f'stub pefile has no {name}: this code path needs the real pefile')


_pe_stub.__getattr__ = _stub_getattr  # type: ignore[attr-defined]
_pe_stub.__path__ = []  # type: ignore[attr-defined]
sys.modules.setdefault('pefile', _pe_stub)

import autoit_ripper.decompress as _dec  # noqa: E402

_dec.MAX_SCRIPT_SIZE = 256 * 1024 * 1024

from autoit_ripper.autoit_unpack import AutoItVersion, parse_all  # noqa: E402
from autoit_ripper.utils import ByteStream  # noqa: E402


def parse_sections(data: bytes):
    if data[:2] != b'MZ':
        raise SystemExit('not a PE (no MZ)')
    pe_off = struct.unpack_from('<I', data, 0x3C)[0]
    n_sec = struct.unpack_from('<H', data, pe_off + 6)[0]
    opt_size = struct.unpack_from('<H', data, pe_off + 20)[0]
    sec_off = pe_off + 24 + opt_size
    out = []
    for i in range(n_sec):
        name, vsize, vaddr, rawsize, rawptr = struct.unpack(
            '<8sIIII', data[sec_off + i * 40: sec_off + i * 40 + 24])
        out.append({'name': name.rstrip(b'\0').decode('ascii', 'replace'),
                    'vsize': vsize, 'vaddr': vaddr,
                    'rawsize': rawsize, 'rawptr': rawptr})
    return out


def rcdata_from_exe(path: str) -> bytes:
    data = open(path, 'rb').read()
    sections = parse_sections(data)
    pe_off = struct.unpack_from('<I', data, 0x3C)[0]
    magic = struct.unpack_from('<H', data, pe_off + 24)[0]
    dd = pe_off + 24 + (112 if magic == 0x20B else 96) + 2 * 8
    rrva, _ = struct.unpack_from('<II', data, dd)
    rsrc = next(s for s in sections if s['name'] == '.rsrc')
    base = rsrc['rawptr']
    if rrva and rsrc['vaddr'] <= rrva < rsrc['vaddr'] + max(rsrc['vsize'], rsrc['rawsize']):
        base = rsrc['rawptr'] + (rrva - rsrc['vaddr'])

    def subdir(off):
        n_named, n_id = struct.unpack_from('<HH', data, base + off + 12)
        return [struct.unpack_from('<II', data, base + off + 16 + i * 8)
                for i in range(n_named + n_id)]

    blobs = []
    for type_id, type_ptr in subdir(0):
        if type_id != 10:  # RT_RCDATA
            continue
        for name_id, name_ptr in subdir(type_ptr & 0x7FFFFFFF):
            for _, lang_ptr in subdir(name_ptr & 0x7FFFFFFF):
                data_rva, size = struct.unpack_from(
                    '<II', data, base + (lang_ptr & 0x7FFFFFFF))
                blobs.append((size, name_id, data_rva))
    if not blobs:
        # Fallback: some helpers (GV, FS) store the EA06 blob outside
        # RT_RCDATA.  Carve it: 16 random bytes + b'AU3!EA06' + entries.
        # The parser is self-delimiting (stops at first non-FILE magic),
        # so carving to EOF is safe.
        at = data.find(b'AU3!EA06')
        if at < 16:
            raise SystemExit('no RT_RCDATA and no AU3!EA06 carve point')
        print(f'[+] no RCDATA; carved EA06 blob @{hex(at)}', file=sys.stderr)
        return data[at - 16:]
    size, name_id, data_rva = max(blobs)
    print(f'[+] RCDATA id={name_id & 0x7FFFFFFF} rva={hex(data_rva)} size={size}',
          file=sys.stderr)
    raw_off = None
    for s in sections:
        span = max(s['vsize'], s['rawsize'])
        if s['vaddr'] <= data_rva < s['vaddr'] + span and s['rawsize']:
            if data_rva + size > s['vaddr'] + s['rawsize']:
                break  # not file-backed (UPX-compressed region)
            raw_off = s['rawptr'] + (data_rva - s['vaddr'])
            break
    if raw_off is None:
        raise SystemExit('RCDATA is not file-backed; unpack with upx_unpack.py first')
    blob = data[raw_off:raw_off + size]
    if blob[0x10:0x18] != b'AU3!EA06':
        raise SystemExit(f'RCDATA magic mismatch: {blob[0x10:0x18]!r}')
    print('[+] RCDATA magic AU3!EA06 OK', file=sys.stderr)
    return blob


def safe_name(name: str) -> str:
    return re.sub(r'[^A-Za-z0-9._-]+', '_', name)


def main() -> None:
    ap = argparse.ArgumentParser(description='EA06 decompile driver')
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument('--rcdata', help='raw script-resource blob')
    src.add_argument('--exe', help='plain AutoIt exe (file-backed .rsrc)')
    ap.add_argument('--out', required=True, help='output directory')
    args = ap.parse_args()

    blob = open(args.rcdata, 'rb').read() if args.rcdata else rcdata_from_exe(args.exe)
    print(f'[+] blob={len(blob)} bytes', file=sys.stderr)
    if blob[0x10:0x18] != b'AU3!EA06':
        raise SystemExit(f'RCDATA magic mismatch: {blob[0x10:0x18]!r}')

    # parse_all consumes 16 bytes (checksum), then parses EA06 from +0x10.
    files = parse_all(ByteStream(blob[0x18:]), AutoItVersion.EA06)
    if not files:
        raise SystemExit('EA06 parse yielded no files')
    os.makedirs(args.out, exist_ok=True)
    print(f'[+] extracted {len(files)} files -> {args.out}', file=sys.stderr)
    with open(os.path.join(args.out, 'MANIFEST.txt'), 'w') as mf:
        for name, content in files:
            fn = safe_name(name)
            with open(os.path.join(args.out, fn), 'wb') as fh:
                fh.write(content)
            print(f'    {len(content):10d}  {name}', file=sys.stderr)
            mf.write(f'{len(content)}\t{name}\t{fn}\n')


if __name__ == '__main__':
    main()
