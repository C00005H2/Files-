#!/usr/bin/env python3
"""Unpack UPX-LZMA (method 14) Vanillatool executables (offline, stdlib-only).

Stock ``upx -d`` fails on these samples (nonstandard LZMA framing).  This tool
recovers the decompressed memory image plus the AutoIt script resource:

  1. Hand-rolled PE parse (sections only; no pefile dependency).
  2. ``UPX!`` PACKHEAD check: ``ver/fmt/method/level`` + ``u_len`` advisory.
     Only method 14 (LZMA) is supported; method 8 (NRV: Unique-ID, lr, BBQ)
     is triaged via surface strings (see runbook).
  3. UPX1 raw data = ``[2-byte header 0x18 0x03][raw LZMA1 stream]``.
     Stream parameters were recovered empirically: ``lc=3 lp=0 pb=0``,
     16 MB dictionary.  No end marker is stored, so the natural stream end
     (``N*``) is located by bisection (max input prefix that decodes cleanly).
  4. The image maps 1:1 to ``RVA = UPX0.VAddr + offset``.  The resource
     directory (in ``.rsrc``) is walked to the big ``RT_RCDATA`` blob, which
     is sliced out of the *image* (it lives in the compressed region).
     Sanity: blob[0x10:0x18] must be ``b'AU3!EA06'``.

Usage:
    python3 upx_unpack.py INPUT.exe --out IMAGE.bin --rcdata RCDATA.bin

Reference values (Vanillatool 11.31 outer): u_len field 15178221, natural
output 15186125 bytes, RCDATA id 1072 / 13904442 bytes @RVA 0x1348ac.
"""

import argparse
import lzma
import struct
import sys

LZMA_FILTER = {'id': lzma.FILTER_LZMA1, 'dict_size': 1 << 24,
               'lc': 3, 'lp': 0, 'pb': 0}


def parse_sections(data: bytes):
    if data[:2] != b'MZ':
        raise SystemExit('not a PE (no MZ)')
    pe_off = struct.unpack_from('<I', data, 0x3C)[0]
    if data[pe_off:pe_off + 4] != b'PE\0\0':
        raise SystemExit('not a PE (no PE sig)')
    n_sec = struct.unpack_from('<H', data, pe_off + 6)[0]
    opt_size = struct.unpack_from('<H', data, pe_off + 20)[0]
    sec_off = pe_off + 24 + opt_size
    sections = []
    for i in range(n_sec):
        entry = data[sec_off + i * 40: sec_off + (i + 1) * 40]
        name, vsize, vaddr, rawsize, rawptr = struct.unpack('<8sII II', entry[:24])
        sections.append({'name': name.rstrip(b'\0').decode('ascii', 'replace'),
                         'vsize': vsize, 'vaddr': vaddr,
                         'rawsize': rawsize, 'rawptr': rawptr})
    return sections


def rva_to_raw(sections, rva: int):
    for s in sections:
        span = max(s['vsize'], s['rawsize'])
        if s['vaddr'] <= rva < s['vaddr'] + span and s['rawsize']:
            return s['rawptr'] + (rva - s['vaddr'])
    return None


def resource_base(data: bytes, sections):
    """File offset of the resource directory (via data-directory RVA)."""
    pe_off = struct.unpack_from('<I', data, 0x3C)[0]
    magic = struct.unpack_from('<H', data, pe_off + 24)[0]
    dd = pe_off + 24 + (112 if magic == 0x20B else 96) + 2 * 8
    rrva, _ = struct.unpack_from('<II', data, dd)
    if rrva:
        off = rva_to_raw(sections, rrva)
        if off is not None:
            return off
    return next(s for s in sections if s['name'] == '.rsrc')['rawptr']


def find_rcdata(data: bytes, sections):
    """Walk the resource directory; return (id, rva, size) of script blob."""
    base = resource_base(data, sections)

    def subdir(off):
        n_named, n_id = struct.unpack_from('<HH', data, base + off + 12)
        out = []
        for i in range(n_named + n_id):
            rid, ptr = struct.unpack_from('<II', data, base + off + 16 + i * 8)
            out.append((rid & 0x7FFFFFFF, ptr))
        return out

    for type_id, type_ptr in subdir(0):
        if type_id != 10:  # RT_RCDATA
            continue
        for name_id, name_ptr in subdir(type_ptr & 0x7FFFFFFF):
            for _, lang_ptr in subdir(name_ptr & 0x7FFFFFFF):
                data_rva, size = struct.unpack_from('<II', data, base + (lang_ptr & 0x7FFFFFFF))
                return name_id, data_rva, size
    raise SystemExit('no RT_RCDATA found in .rsrc')


def decode_prefix(stream: bytes, n: int):
    """Decode stream[:n]; return bytes or None on corruption."""
    try:
        d = lzma.LZMADecompressor(format=lzma.FORMAT_RAW,
                                  filters=[dict(LZMA_FILTER)])
        return d.decompress(stream[:n])
    except lzma.LZMAError:
        return None


def main() -> None:
    ap = argparse.ArgumentParser(description='UPX-LZMA unpacker for Vanillatool exes')
    ap.add_argument('exe', help='packed input .exe')
    ap.add_argument('--out', required=True, help='decompressed image output')
    ap.add_argument('--rcdata', required=True, help='extracted script-resource blob')
    args = ap.parse_args()

    data = open(args.exe, 'rb').read()
    sections = parse_sections(data)
    print('[+] sections:', ' '.join(
        f"{s['name']}@{hex(s['rawptr'])}+{s['rawsize']}" for s in sections), file=sys.stderr)

    at = data.find(b'UPX!')
    if at < 0:
        raise SystemExit('UPX! PACKHEAD not found')
    ver, fmt, method, level = data[at + 4:at + 8]
    u_len = struct.unpack_from('<I', data, at + 16)[0]
    print(f'[+] PACKHEAD @{hex(at)} ver={ver} fmt={fmt} method={method} '
          f'level={level} u_len={u_len}', file=sys.stderr)
    if method != 14:
        raise SystemExit(f'unsupported UPX method {method} (only 14/LZMA; '
                         'use strings-triage for NRV samples)')

    upx0 = next(s for s in sections if s['name'] == 'UPX0')
    upx1 = next(s for s in sections if s['name'] == 'UPX1')
    raw = data[upx1['rawptr']: upx1['rawptr'] + upx1['rawsize']]
    print(f'[+] UPX1 raw={len(raw)} hdr={raw[:2].hex()}', file=sys.stderr)
    stream = raw[2:]

    full = decode_prefix(stream, len(stream))
    if full is not None:
        image, nstar = full, len(stream)
    else:  # bisect natural stream end
        lo, hi = 0, len(stream)
        image = b''
        while lo < hi:
            mid = (lo + hi + 1) // 2
            trial = decode_prefix(stream, mid)
            if trial is not None:
                lo, image = mid, trial
            else:
                hi = mid - 1
        nstar = lo
    print(f'[+] decoded image={len(image)} bytes (N*={nstar}, '
          f'stub-tail={len(stream) - nstar})', file=sys.stderr)

    name_id, rva, size = find_rcdata(data, sections)
    base = upx0['vaddr']
    off = rva - base
    print(f'[+] RCDATA id={name_id} rva={hex(rva)} size={size} '
          f'image-off={hex(off)} (base={hex(base)})', file=sys.stderr)
    blob = image[off:off + size]
    if len(blob) != size:
        raise SystemExit(f'RCDATA exceeds image ({len(blob)} != {size})')
    if blob[0x10:0x18] != b'AU3!EA06':
        raise SystemExit(f'RCDATA magic mismatch: {blob[0x10:0x18]!r}')
    print('[+] RCDATA magic AU3!EA06 OK', file=sys.stderr)

    open(args.out, 'wb').write(image)
    open(args.rcdata, 'wb').write(blob)
    print(f'[+] wrote {args.out} and {args.rcdata}', file=sys.stderr)


if __name__ == '__main__':
    main()
