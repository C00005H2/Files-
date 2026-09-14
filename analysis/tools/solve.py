#!/usr/bin/env python3
"""Backward solve of the crackme gate.

Stage 1  replay the captured trace and prove the Python VM is byte-exact.
Stage 2  slice the gate condition R[0..7] == C backwards through the program,
         propagating *requirements* (not just values) through the lossy ops
         (set / load / store), to obtain the window bytes the sponge must emit.
Stage 3  re-run forward from the solved window and check the gate passes.
"""
import json, struct, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vmmodel import VM, NAMES, WIN

GATE_C = bytes.fromhex('e6a0ef2284734165')


def load(path):
    d = json.load(open(path))
    d['trace'] = [tuple(t) for t in d['trace']]
    return d


# --------------------------------------------------------------------- stage 1
def stage1(d, quiet=False):
    tr = d['trace']
    vm = VM(bytes.fromhex(d['captures']['vm_start']['window']))
    ok = True
    cmps = {c[0]: c for c in d['captures']['cmps']}
    for i, ins in enumerate(tr):
        if i in cmps:
            _, hop, c1, c2, c3, c4, c5, Rhex = cmps[i]
            emuR = bytes.fromhex(Rhex)
            e1 = struct.unpack_from('<Q', emuR, c1 * 8)[0]
            good = vm.R[c1] == e1
            if hop == 0x1270:
                e2 = struct.unpack_from('<Q', emuR, c2 * 8)[0]
                good = good and vm.R[c2] == e2
                if not quiet:
                    print(f"  #{i:5d} cmpr  R[{c1}]=0x{vm.R[c1]:02x} R[{c2}]=0x{vm.R[c2]:02x}"
                          f"  emu 0x{e1:02x}/0x{e2:02x}  {'OK' if good else 'MISMATCH'}")
            elif not quiet:
                print(f"  #{i:5d} cmpi  R[{c1}]=0x{vm.R[c1]:02x} vs imm 0x{c2:x}"
                      f"  emu 0x{e1:02x}  {'OK' if good else 'MISMATCH'}")
            ok = ok and good
        vm.step(*ins)
    emuW = bytes.fromhex(d['captures']['exit']['window'])
    wsame = bytes(vm.S) == emuW
    if not quiet:
        print(f"  exit window identical: {wsame}  exitflag={vm.exitflag} acc={vm.acc}")
    return ok and wsame, vm


def gate_indices(tr):
    return [i for i, t in enumerate(tr) if t[0] == 0x1270]


# --------------------------------------------------------------------- stage 2
class Backward:
    """Requirement-propagating inverse execution of a handler prefix."""

    def __init__(self, R, S):
        self.R = list(R)
        self.S = bytearray(S)
        self.needR = set()
        self.needS = set()
        self.conflicts = []

    def reqR(self, k, v):
        if k in self.needR and self.R[k] != v:
            self.conflicts.append(('R', k, self.R[k], v))
        self.needR.add(k)
        self.R[k] = v

    def reqS(self, a, v):
        if a in self.needS and self.S[a] != v:
            self.conflicts.append(('S', a, self.S[a], v))
        self.needS.add(a)
        self.S[a] = v

    def back(self, op, c1, c2, c3, c4, c5):
        R, S = self.R, self.S
        # ---- ops whose destination is a register -------------------------
        if op in (0x1000, 0x1020, 0x1040, 0x1060, 0x10A0, 0x10C0, 0x10E0,
                  0x1110, 0x1180, 0x11C0, 0x11E0, 0x1200, 0x1220):
            if c1 not in self.needR:
                return                                   # result not needed
            v = R[c1]
            if op == 0x1000:                             # R[c1] = c2
                if v != c2:
                    self.conflicts.append(('set', c1, v, c2))
                self.needR.discard(c1)
            elif op == 0x1020:
                R[c1] = v ^ c2
            elif op == 0x1040:
                R[c1] = (v - c2) & 0xFF
            elif op == 0x1060:
                R[c1] = (v + c2) & 0xFF
            elif op == 0x10A0:                           # R[c1] = R[c2]
                self.reqR(c2, v)
                self.needR.discard(c1)
            elif op == 0x10C0:
                R[c1] = v ^ R[c2]
            elif op == 0x10E0:
                R[c1] = (v - R[c2]) & 0xFF
            elif op == 0x1110:
                R[c1] = (v + R[c2]) & 0xFF
            elif op == 0x1180:
                from vmmodel import rotr8
                R[c1] = rotr8(v, R[c2] & 7)
            elif op == 0x11C0:
                R[c1] = (~v) & 0xFF
            elif op == 0x11E0:
                R[c1] = (v - 1) & 0xFF
            elif op == 0x1200:
                R[c1] = (v + 1) & 0xFF
            elif op == 0x1220:                           # LOAD
                idx = (((c4 << 8) | c3) + (R[c2] & 0xFF)) & (WIN - 1)
                self.reqS(idx, v ^ c5)
                self.needR.discard(c1)
            return
        # ---- store -------------------------------------------------------
        if op == 0x1310:
            a = ((c3 << 8) | c2) & (WIN - 1)
            if a in self.needS:
                self.reqR(c1, S[a] ^ c4)
                self.needS.discard(a)
            return
        # ---- no-state ops ------------------------------------------------
        if op in (0x1270, 0x12A0, 0x12C0, 0x12E0, 0x1350, 0x1380, 0x1390):
            return
        raise ValueError(f'no inverse for 0x{op:x}')


def stage2(d, g0):
    tr = d['trace']
    win = bytes.fromhex(d['captures']['vm_start']['window'])
    vm = VM(win)
    for ins in tr[:g0]:
        vm.step(*ins)
    print(f"  pre-gate R[0..7] = {bytes(x & 0xff for x in vm.R[:8]).hex(' ')}")
    b = Backward(vm.R, vm.S)
    for i in range(8):
        b.reqR(i, GATE_C[i])
    for ins in reversed(tr[:g0]):
        b.back(*ins)
    return b, win


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else '/tmp/t123.json'
    quiet = '-q' in sys.argv
    d = load(path)
    print(f"== stage 1: replay validation ({len(d['trace'])} handlers, pw={d['password']!r})")
    ok, _ = stage1(d, quiet)
    print("  VALIDATION:", "PASS" if ok else "FAIL")
    if not ok:
        return
    g = gate_indices(d['trace'])
    print(f"== stage 2: backward slice from gate #{g[0]} (C={GATE_C.hex()})")
    b, win = stage2(d, g[0])
    print(f"  conflicts: {b.conflicts if b.conflicts else 'none'}")
    print(f"  required window bytes: {len(b.needS)}   required regs: {sorted(b.needR)}")
    need = sorted(b.needS)
    new = bytearray(win)
    for a in need:
        new[a] = b.S[a]
    # show grouped
    runs = []
    for a in need:
        if runs and a == runs[-1][1] + 1:
            runs[-1][1] = a
        else:
            runs.append([a, a])
    for s0, s1 in runs:
        print(f"   0x{s0:04x}..0x{s1:04x} ({s1-s0+1}B) "
              f"old {win[s0:s1+1].hex(' ')}")
        print(f"   {'':16s} new {bytes(new[s0:s1+1]).hex(' ')}")
    print("== stage 3: forward re-run with the solved window")
    vm = VM(bytes(new))
    for ins in d['trace'][:g[0]]:
        vm.step(*ins)
    got = bytes(x & 0xff for x in vm.R[:8])
    print(f"  R[0..7] = {got.hex(' ')}  want {GATE_C.hex()}  "
          f"{'GATE PASS' if got == GATE_C else 'GATE FAIL'}")
    json.dump({'password': d['password'], 'window': bytes(new).hex(),
               'need': need, 'gate': got.hex()},
              open(path + '.solved.json', 'w'))
    print("  wrote", path + '.solved.json')


if __name__ == '__main__':
    main()
