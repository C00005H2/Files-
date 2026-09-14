#!/usr/bin/env python3
"""End-to-end crackme verifier: password -> would the binary exit 0?

Everything here is derived from the binary (no external hints):

  * sponge.mac()          byte-exact model of the keystretcher/MAC at 0x65A0
  * TABLE                 the 64 constant bytes the VM absorbs in rounds 0-3,
                          read out of the emulated process (window[0x100..0x13f])
  * VM PROGRAM            the decoded handler stream (analysis/data/vm_program.json)
                          captured from the dispatcher; identical for every run
                          and every password (only the opcode<->handler shuffle
                          changes per run, the decoded program does not)
  * GATE                  R[0..7] == C, C = e6a0ef2284734165

Layout of the VM data window (base = 0x14002b7a0, i.e. the sponge output block):
  [0x080..0x0ff]  constant keystream          (not read before the gate)
  [0x100..0x13f]  constant keystream  = rounds 0-3 input
  [0x140..0x14f]  MAC(pw)             = round 4 input
  [0x150..0x15f]  buf40[16..31]       = round 5 input
  [0x160..0x16f]  buf40[32..39] | 0x80 | 0*7  = round 6 input
"""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sponge import mac as sponge_mac
from vmmodel import VM

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, '..', 'data')
GATE_C = bytes.fromhex('e6a0ef2284734165')


def _load():
    prog = json.load(open(os.path.join(DATA, 'vm_program.json')))
    return prog


PROG = None


def program():
    global PROG
    if PROG is None:
        PROG = _load()
    return PROG


def buf40(pw: bytes) -> bytes:
    """The 40-byte padded input buffer built by 0x9B80."""
    if not 1 <= len(pw) <= 39:
        raise ValueError('password length must be 1..39 (0xB072: len-1 <= 0x26)')
    b = bytearray(40)
    b[:len(pw)] = pw
    b[len(pw)] = 0x80
    return bytes(b)


def window(pw: bytes) -> bytes:
    """The VM data window contents at VM entry, for this password."""
    p = program()
    w = bytearray(0x10000)
    w[:0x200] = bytes.fromhex(p['table_full'])   # window[0x000..0x1ff] constants
    w[0x140:0x150] = sponge_mac(pw)[0]
    b = buf40(pw)
    w[0x150:0x168] = b[16:40]
    w[0x168] = 0x80
    return bytes(w)


def gate(pw: bytes):
    """Return (R[0..7] at the gate, MAC)."""
    p = program()
    vm = VM(window(pw))
    for ins in p['trace'][:p['gate']]:
        vm.step(*ins)
    return bytes(x & 0xFF for x in vm.R[:8]), sponge_mac(pw)[0]


def check(pw: bytes) -> bool:
    if not 1 <= len(pw) <= 39:
        return False
    g, _ = gate(pw)
    return g == GATE_C


if __name__ == '__main__':
    for arg in sys.argv[1:]:
        pw = arg.encode()
        g, m = gate(pw)
        print(f"{arg!r:34s} MAC={m.hex()} gate={g.hex()} "
              f"{'*** PASS ***' if g == GATE_C else 'fail'}")
