#!/usr/bin/env python3
"""Emit analysis/data/gate_rounds.bin: the three password-dependent VM rounds in
a compact form the C oracle can interpret.

Layout (little endian):
  u32   magic  'GATE'
  16B   s4            state after the four constant salt rounds
  8B    C             the gate constant
  u32   n4            op count of round 4
  n4 * 7B             ops: u16 handler rva, then c1,c2,c3,c4,c5 as bytes
  u32   n5 / ops
  u32   n6 / ops
"""
import json, os, struct, sys

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, '..', 'data')
ABSORB = [(2, 36), (456, 491), (911, 945), (1365, 1400),
          (1820, 1854), (2274, 2309), (2729, 2763)]
GATE = 3779
# 0x1310 (STORE) only writes the window; round 6 contains no LOAD, so it cannot
# feed back into R and is emitted as a register-level no-op.
NEEDED = {0x10C0, 0x1180, 0x1020, 0x10E0, 0x1110, 0x1390, 0x1310}


def main():
    prog = json.load(open(os.path.join(DATA, 'vm_program.json')))
    tr = prog['trace']
    out = bytearray()
    out += b'GATE'
    out += bytes.fromhex('b238115829a5e09d1252eff01078ae83')   # s4 (reduce.py)
    out += bytes.fromhex('e6a0ef2284734165')                   # C
    total = 0
    for k in (4, 5, 6):
        lo = ABSORB[k][1] + 1
        hi = ABSORB[k + 1][0] if k + 1 < 7 else GATE
        ops = tr[lo:hi]
        # the absorb phase must be exactly R[i] ^= win[0x100+16k+i], i = 0..15 in
        # order; the C oracle relies on it, so assert it here.
        ab = tr[ABSORB[k][0]:ABSORB[k][1] + 1]
        lds = [t for t in ab if t[0] == 0x1220]
        addrs = [((t[4] << 8) | t[3]) for t in lds]
        assert addrs == [0x100 + 16 * k + i for i in range(16)], \
            f'round {k} absorb addresses differ: {[hex(a) for a in addrs]}'
        assert all(t[1] == 17 for t in lds), f'round {k} load targets: {[t[1] for t in lds]}'
        assert all(t[5] == 0 for t in lds), f'round {k} load xor imm nonzero'
        xors = [t[1] for t in ab if t[0] == 0x10C0]
        assert xors == list(range(16)), f'round {k} absorb xor targets: {xors}'
        used = {o[0] for o in ops}
        assert used <= NEEDED, f'round {k} uses unmodelled handlers: {used - NEEDED}'
        out += struct.pack('<I', len(ops))
        for o, c1, c2, c3, c4, c5 in ops:
            out += struct.pack('<H5B', o, c1, c2, c3, c4, c5)
        total += len(ops)
        print(f'round {k}: {len(ops)} ops, handlers {sorted(hex(x) for x in used)}')
    path = os.path.join(DATA, 'gate_rounds.bin')
    open(path, 'wb').write(bytes(out))
    print(f'wrote {path} ({len(out)} bytes, {total} ops)')


if __name__ == '__main__':
    main()
