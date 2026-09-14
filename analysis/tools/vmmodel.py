#!/usr/bin/env python3
"""Byte-exact Python model of the crackme VM (dispatcher 0xB2A0, handlers 0x1000-0x1390).

Handler semantics (reverse engineered from .text, see disasm/vm_handlers.txt):

  0x1000  R[c1]  = c2                      set reg = imm
  0x1020  R[c1] ^= c2                      xor imm
  0x1040  R[c1]  = (R[c1] + c2) & 0xff     add imm (byte)
  0x1060  R[c1]  = (R[c1] - c2) & 0xff     sub imm (byte)
  0x1080  R[c1] &= c2                      and imm
  0x10a0  R[c1]  = R[c2]                   mov reg,reg
  0x10c0  R[c1] ^= R[c2]                   xor reg
  0x10e0  R[c1]  = (R[c1] + R[c2]) & 0xff  add reg (byte)
  0x1110  R[c1]  = (R[c1] - R[c2]) & 0xff  sub reg (byte)
  0x1140  R[c1] <<= (c2 & 31)              shl imm (qword)
  0x1160  R[c1] >>= (c2 & 31)              shr imm (qword)
  0x1180  R[c1]  = rotl8(R[c1], R[c2] & 7) rotate left by a *register* amount
  0x11c0  R[c1]  = ~R[c1] & 0xff           not (byte)
  0x11e0  R[c1]  = (R[c1] + 1) & 0xff      inc (byte)
  0x1200  R[c1]  = (R[c1] - 1) & 0xff      dec (byte)
  0x1220  R[c1]  = S[(c4<<8|c3) + (R[c2]&0xff)] ^ c5        LOAD
  0x1270  c0 = (R[c1] == R[c2])            cmp reg,reg
  0x12a0  c0 = (R[c1] == c2)               cmp reg,imm
  0x12c0  if not c0: exitflag |= 1         fail-accum
  0x12e0  if state148 != c1: exitflag |= 1 self-check
  0x1300  R[9] ^= rdtsc                    timing poison
  0x1310  S[(c3<<8)|c2] = (R[c1] & 0xff) ^ c4               STORE
  0x1350  if not c0: pc += c1  (pc > limit => acc = 1)      cond jump
  0x1380  acc = 1                          halt
  0x1390  nop

Every handler that appears in the real trace is *invertible*, so the model can
also be run backwards (see step_back) - that is what makes an analytic solve
possible instead of a search.
"""

MASK64 = (1 << 64) - 1

# handler rva -> name
NAMES = {
    0x1000: 'set', 0x1020: 'xori', 0x1040: 'addi', 0x1060: 'subi', 0x1080: 'andi',
    0x10A0: 'mov', 0x10C0: 'xorr', 0x10E0: 'addr', 0x1110: 'subr', 0x1140: 'shl',
    0x1160: 'shr', 0x1180: 'rol8', 0x11C0: 'not8', 0x11E0: 'inc8', 0x1200: 'dec8',
    0x1220: 'load', 0x1270: 'cmpr', 0x12A0: 'cmpi', 0x12C0: 'fail', 0x12E0: 'selfcheck',
    0x1300: 'rdtsc', 0x1310: 'store', 0x1350: 'cjmp', 0x1380: 'halt', 0x1390: 'nop',
}

WIN = 0x10000


def rotl8(v, k):
    k &= 7
    v &= 0xFF
    return v if k == 0 else ((v << k) | (v >> (8 - k))) & 0xFF


def rotr8(v, k):
    return rotl8(v, -k & 7)


class VM:
    """Replays a captured handler trace over (R, window)."""

    def __init__(self, window, R=None, state148=0, rdtsc=0x1122334455667788):
        self.S = bytearray(window)
        self.R = list(R) if R else [0] * 32
        self.c0 = 0
        self.exitflag = 0
        self.acc = 0
        self.state148 = state148
        self.rdtsc = rdtsc

    # ------------------------------------------------------------- forward
    def step(self, op, c1, c2, c3, c4, c5):
        R, S = self.R, self.S
        if op == 0x1000:
            R[c1] = c2
        elif op == 0x1020:
            R[c1] = (R[c1] ^ c2) & MASK64
        elif op == 0x1040:
            R[c1] = (R[c1] + c2) & 0xFF
        elif op == 0x1060:
            R[c1] = (R[c1] - c2) & 0xFF
        elif op == 0x1080:
            R[c1] = R[c1] & c2
        elif op == 0x10A0:
            R[c1] = R[c2]
        elif op == 0x10C0:
            R[c1] = (R[c1] ^ R[c2]) & MASK64
        elif op == 0x10E0:
            R[c1] = (R[c1] + R[c2]) & 0xFF
        elif op == 0x1110:
            R[c1] = (R[c1] - R[c2]) & 0xFF
        elif op == 0x1140:
            R[c1] = (R[c1] << (c2 & 31)) & MASK64
        elif op == 0x1160:
            R[c1] = (R[c1] >> (c2 & 31)) & MASK64
        elif op == 0x1180:
            R[c1] = rotl8(R[c1], R[c2] & 7)      # shift amount is R[c2], not imm
        elif op == 0x11C0:
            R[c1] = (~(R[c1] & 0xFF)) & 0xFF
        elif op == 0x11E0:
            R[c1] = ((R[c1] & 0xFF) + 1) & 0xFF
        elif op == 0x1200:
            R[c1] = ((R[c1] & 0xFF) - 1) & 0xFF
        elif op == 0x1220:
            idx = (((c4 << 8) | c3) + (R[c2] & 0xFF)) & (WIN - 1)
            R[c1] = S[idx] ^ c5
        elif op == 0x1270:
            self.c0 = 1 if R[c1] == R[c2] else 0
        elif op == 0x12A0:
            self.c0 = 1 if R[c1] == c2 else 0
        elif op == 0x12C0:
            if not self.c0:
                self.exitflag |= 1
        elif op == 0x12E0:
            if self.state148 != c1:
                self.exitflag |= 1
        elif op == 0x1300:
            R[9] = (R[9] ^ self.rdtsc) & MASK64
        elif op == 0x1310:
            S[((c3 << 8) | c2) & (WIN - 1)] = (R[c1] & 0xFF) ^ c4
        elif op == 0x1350:                    # pc jump - no R/S effect
            pass
        elif op == 0x1380:
            self.acc = 1
        elif op == 0x1390:
            pass
        else:
            raise ValueError(f'unknown handler 0x{op:x}')

    # ------------------------------------------------------------- backward
    def step_back(self, op, c1, c2, c3, c4, c5):
        """Invert one step: turn the post-state into a valid pre-state."""
        R, S = self.R, self.S
        if op == 0x1000:                      # value overwritten -> unconstrained
            R[c1] = 0
        elif op == 0x1020:
            R[c1] = (R[c1] ^ c2) & MASK64
        elif op == 0x1040:
            R[c1] = (R[c1] - c2) & 0xFF
        elif op == 0x1060:
            R[c1] = (R[c1] + c2) & 0xFF
        elif op == 0x10A0:
            R[c1] = 0
        elif op == 0x10C0:
            R[c1] = (R[c1] ^ R[c2]) & MASK64
        elif op == 0x10E0:
            R[c1] = (R[c1] - R[c2]) & 0xFF
        elif op == 0x1110:
            R[c1] = (R[c1] + R[c2]) & 0xFF
        elif op == 0x1180:
            R[c1] = rotr8(R[c1], R[c2] & 7)
        elif op == 0x11C0:
            R[c1] = (~(R[c1] & 0xFF)) & 0xFF
        elif op == 0x11E0:
            R[c1] = ((R[c1] & 0xFF) - 1) & 0xFF
        elif op == 0x1200:
            R[c1] = ((R[c1] & 0xFF) + 1) & 0xFF
        elif op == 0x1220:                    # LOAD: pre-value unconstrained
            R[c1] = 0
        elif op == 0x1310:                    # STORE: pre-value unconstrained
            S[((c3 << 8) | c2) & (WIN - 1)] = 0
        elif op in (0x1270, 0x12A0, 0x12C0, 0x12E0, 0x1350, 0x1380, 0x1390):
            pass
        else:
            raise ValueError(f'no inverse for handler 0x{op:x}')

    def run(self, trace, start=0, stop=None, backward=False):
        stop = len(trace) if stop is None else stop
        rng = range(stop - 1, start - 1, -1) if backward else range(start, stop)
        for i in rng:
            self.step_back(*trace[i]) if backward else self.step(*trace[i])
        return self
