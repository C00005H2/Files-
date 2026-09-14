#!/usr/bin/env python3
"""Exact algebraic reduction of the crackme gate.

The decoded VM program (analysis/data/vm_program.json) is seven rounds over a
16-byte register state R[0..15]:

    s0 = 0
    s(i+1) = P_i( s(i) XOR B(i) )        i = 0..6

    B0..B3 = constant keystream, window[0x100..0x13f]   (same every run)
    B4     = MAC(pw),              window[0x140..0x14f]
    B5     = buf40[16..31],        window[0x150..0x15f]
    B6     = buf40[32..39]|0x80|0*7, window[0x160..0x16f]

    gate (instructions 3779-3805):  R[0..7] == e6 a0 ef 22 84 73 41 65

P_0..P_5 are the same 419-op permutation; P_6 is 1015 ops.  All of them are
bijective on R[0..15], so the gate inverts in closed form:

    s6  = P6^-1(s7) XOR B6
    s5  = P^-1(s6)  XOR B5
    MAC = P^-1(s5)  XOR s4     s4 = P^3-ish constant from B0..B3

Only s7[0..7] are constrained; s7[8..15] = U is free.  So the MACs that pass
are exactly { required_mac(U) : U in 2^64 }.  Everything after that hinges on
inverting the sponge, which this script shows is the whole difficulty.
"""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vmmodel import VM

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, '..', 'data')
C = bytes.fromhex('e6a0ef2284734165')

# instruction ranges in the decoded program (verified: see main())
ABSORB = [(2, 36), (456, 491), (911, 945), (1365, 1400),
          (1820, 1854), (2274, 2309), (2729, 2763)]
GATE = 3779                     # first `set R[17],imm` of the 8 comparisons


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


class Perm:
    """A run of VM ops treated as a bijection on R[0..15]."""

    def __init__(self, ops):
        self.ops = [tuple(o) for o in ops]

    def __call__(self, s16):
        vm = VM(bytes(0x10000))
        vm.R = list(s16) + [0] * 16
        for ins in self.ops:
            vm.step(*ins)
        return bytes(x & 0xFF for x in vm.R[:16])

    def inv(self, s16):
        vm = VM(bytes(0x10000))
        vm.R = list(s16) + [0] * 16
        for ins in reversed(self.ops):
            vm.step_back(*ins)
        return bytes(x & 0xFF for x in vm.R[:16])


def build():
    prog = json.load(open(os.path.join(DATA, 'vm_program.json')))
    tr = prog['trace']
    perms = []
    for k in range(7):
        lo = ABSORB[k][1] + 1
        hi = ABSORB[k + 1][0] if k + 1 < 7 else GATE
        perms.append(Perm(tr[lo:hi]))
    tab = bytes.fromhex(prog['table_full'])
    B = [tab[0x100 + 16 * i:0x110 + 16 * i] for i in range(4)]
    return perms, B


def main():
    perms, B = build()
    print(f"P0..P5 op counts: {[len(p.ops) for p in perms[:6]]}  P6: {len(perms[6].ops)}")
    print(f"P0 == P1 == ... == P5: {all(p.ops == perms[0].ops for p in perms[:6])}")

    for _ in range(20):
        s = os.urandom(16)
        assert perms[0].inv(perms[0](s)) == s, 'P inverse failed'
        assert perms[6].inv(perms[6](s)) == s, 'P6 inverse failed'
    print("P^-1(P(x)) == x and P6^-1(P6(x)) == x on 20 random states each")

    s4 = bytes(16)
    for i in range(4):
        s4 = perms[i](xor(s4, B[i]))
    print(f"s4 = {s4.hex()}   (constant, from the salt blocks)")

    # forward cross-check against a real emulated run
    cap = sys.argv[1] if len(sys.argv) > 1 else '/tmp/pw_test123.json'
    d = json.load(open(cap))
    w = bytes.fromhex(d['captures']['vm_start']['window'])
    B4, B5, B6 = w[0x140:0x150], w[0x150:0x160], w[0x160:0x170]
    s = s4
    for i, b in enumerate((B4, B5, B6)):
        s = perms[4 + i](xor(s, b))
    emu = bytes.fromhex(''.join(c[7][c[3] * 16:c[3] * 16 + 2]
                               for c in d['captures']['cmps'] if c[1] == 0x1270))
    print(f"forward s7[0..7] = {s[:8].hex()}   emulator = {emu.hex()}   "
          f"{'MATCH' if s[:8] == emu else 'MISMATCH'}")
    assert s[:8] == emu

    # invert: required MAC for each choice of the free 8 bytes U
    def required_mac(U):
        s6 = xor(perms[6].inv(C + U), B6)
        s5 = xor(perms[5].inv(s6), B5)
        return xor(perms[4].inv(s5), s4)

    m = required_mac(bytes(8))
    # round-trip: feeding this MAC back through the forward path must give C
    s = perms[4](xor(s4, m))
    s = perms[5](xor(s, B5))
    s = perms[6](xor(s, B6))
    print(f"required_mac(U=0) = {m.hex()}   forward gives {s[:8].hex()} "
          f"{'== C OK' if s[:8] == C else 'MISMATCH'}")
    print(f"required_mac(U=C) = {required_mac(C).hex()}")
    print()
    print("pass  <=>  MAC(pw) == required_mac(U) for the free 8 bytes U = s7[8..15]")
    print("        (for len(pw) <= 15 the tail B5/B6 are constants, so U is the")
    print("         only freedom and there are exactly 2^64 admissible MACs)")
    print("MAC(pw) = sponge(buf40(pw)) : 1000 iterations of an 18-round keyed")
    print("permutation.  Recovering pw from a target MAC is a preimage problem.")


if __name__ == '__main__':
    main()
