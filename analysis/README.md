# crackme.exe — full reverse engineering

Target: `6aa4b6d3585e8875bcbebf80/crackme.exe` (50 688 bytes, PE32+ x64, ImageBase
`0x140000000`, EP `0xB580`, no import table — APIs are resolved by decrypted names).

Everything below was derived from the binary in this repository. No hints, no
patching, no external information.

---

## 1. Executive summary

| question | answer |
|---|---|
| Is the VM understood? | **Yes** — decoded and modelled byte-exactly in Python (7 915 / 7 915 handler calls reproduce the real CPU register file at every step). |
| Is the sponge understood? | **Yes** — byte-exact forward model *and* a working inverse of every round. |
| Is the success condition known exactly? | **Yes** — closed form, §5. |
| Is the condition verified end to end? | **Yes** — feeding the model's target MAC into the real binary makes it `ExitProcess(0)`. See §6. |
| Is the password known? | **No.** It is the preimage of a 128-bit keyed permutation chain under a 64-bit constraint. There is no algebraic route to it, and the search cost is ~2⁶⁴ evaluations of a 1 000-iteration sponge. §7. |

---

## 2. Control flow

```
0xB580  entry
0xB400+ anti-debug: window-name scan, PEB+2 BeingDebugged,
        PEB+0xBC NtGlobalFlag & 0x70, DRx, elapsed-time checks
        (GetTickCount64 / QueryPerformanceCounter deltas < 0x186a0 -> fail)
0x9B80  ReadConsoleW -> buf40[40] :  pw || 0x80 || 0x00...   (plain fill loop)
0xB072  length gate:  lea eax,[rdx-1]; cmp eax,0x26; ja fail
                      -> password length must be 1..39 or it returns 0 immediately.
                      There is no string comparison anywhere in the binary.
0x65A0  sponge / key-stretch, 1000 iterations -> 16-byte MAC
        r14 = 0x3e8 = 1000
        [rdi+0x140] = MAC                     (16 bytes)
        [rdi+0x150] = buf40[16..31]           (16 bytes, plaintext)
        [rdi+0x160] = buf40[32..39]           (8 bytes, plaintext)
        [rdi+0x168] = 0x80
0x6700  SIMD keystream generator -> 192 constant bytes at [rdi+0x80..0x13f]
        (guarded by `cmp dword [0x499b0], 6` — this is the PatchGuard hook:
         the code-checksum handlers must have run or the table stays zero)
0xB0B0  VM setup        0xB2A0  VM dispatch loop
```

## 3. The VM

Dispatcher `0xB2A0`. State base `0x2B650`; `R[k]` = `+0x28 + 8k`; `+0x0C` = PC;
`+0x08` = limit 23 505; `+0x10` = halt flag; `+0x18` = fail flag.

```
seed s0 = dword[0x2B670]
code_byte = ((s_i >> 16) & 0xff) ^ bytecode[pc]
s_{i+1}   = (s_i * 0x41c64e6d + 0x3039) mod 2^32          (MSVC LCG)
handler_idx = dword[rsp+0x20 + op*4]                       (shuffled per run)
arity       = dword[r14+0xC5E0 + 4*idx]  -> operands land at state+0xC1..
handler     = qword[r14+0xC650 + 8*idx],  rcx = state
```

The opcode→handler table is reshuffled on every run, but the *decoded* program is
identical for every run and every password (verified by diffing two independent
runs). Program: 7 915 handler calls, 23 505 bytecode bytes, straight line — the
only conditional jump is never taken.

**Data window** = `qword[state+0xD0]` = `0x14002B7A0`, 64 KiB. This is the block
the sponge writes into, so the VM reads the sponge output directly.

### Handler set (24 used)

```
0x1000 R[c1] = c2                 0x1140 R[c1] <<= (c2 & 31)
0x1020 R[c1] ^= c2                0x1160 R[c1] >>= (c2 & 31)
0x1040 R[c1] += c2                0x1180 R[c1] = rotl8(R[c1], R[c2] & 7)  <-- reg amount
0x1060 R[c1] -= c2                0x11C0 R[c1] = ~R[c1]
0x1080 R[c1] &= c2                0x11E0 R[c1]++      0x1200 R[c1]--
0x10A0 R[c1] = R[c2]              0x1220 LOAD  R[c1] = win[((c4<<8)|c3)+(R[c2]&0xff)] ^ c5
0x10C0 R[c1] ^= R[c2]             0x1270 c0 = (R[c1] == R[c2])
0x10E0 R[c1] += R[c2]             0x12A0 c0 = (R[c1] == c2)
0x1110 R[c1] -= R[c2]             0x12C0 if !c0: fail |= 1
                                  0x12E0 if dword[state+0x148] != c1: fail |= 1
0x1300 R[9] ^= rdtsc              0x1310 STORE win[(c3<<8)|c2] = (R[c1]&0xff) ^ c4
0x1350 if !c0: pc += c1           0x1380 halt   0x1390 nop
0x13A0/0x14A0/0x15B0..  code-checksum snapshots (the PatchGuard family)
```

Every handler that occurs is invertible, so `vmmodel.py` runs the program
backwards as well as forwards.

### Program shape

7 rounds over `R[0..15]`. Each round absorbs a 16-byte block from the window
(`load`+`xor` pairs) then applies a mixing permutation:

```
round  block        absorb      mixing ops
  0    win[0x100]     2..36        419
  1    win[0x110]   456..491       419
  2    win[0x120]   911..945       419
  3    win[0x130]  1365..1400      419
  4    win[0x140]  1820..1854      419     <- MAC
  5    win[0x150]  2274..2309      419     <- plaintext tail
  6    win[0x160]  2729..2763     1015     <- plaintext tail, then the gate
```

The mixing touches only `R[0..15]`; `R[16]` is a zero index register set once.
Mixing is add/sub/xor/not/shift plus `rotl8` by a *register* amount, so rotation
counts are data dependent.

**The gate** (instructions 3779–3805), read straight out of the program:

```
set R[17],0xe6 ; cmp R[17],R[0] ; fail
set R[17],0xa0 ; cmp R[17],R[1] ; fail
set R[17],0xef ; cmp R[17],R[2] ; fail
set R[17],0x22 ; cmp R[17],R[3] ; fail
set R[17],0x84 ; cmp R[17],R[4] ; fail
set R[17],0x73 ; cmp R[17],R[5] ; fail
set R[17],0x41 ; cmp R[17],R[6] ; fail
set R[17],0x65 ; cmp R[17],R[7] ; fail
```

so success ⇔ `R[0..7] == e6 a0 ef 22 84 73 41 65` ⇔ fail flag == 0.

What follows the gate is an epilogue (`win[0x100+i] = xor of win[0x00+i]`, a decoy
`cmp R[7],0x7b` that always passes, then halt). Its output at `win[0x180..0x1ff]`
is read by nothing: a full capstone xref scan of `.text` for rip-relative
references into `0x2B600–0x2B9FF` finds only six, all pointing at `0x2B628`/`0x2B630`
(the sponge's two round tables) and `0x2B638`/`0x2B640`.

### Window contents at VM entry

| range | content | varies with password |
|---|---|---|
| `0x000..0x07f` | zero | no |
| `0x080..0x13f` | 192-byte keystream, `dst[i] = ((0x13*i+0x6d)&0xff) ^ .rdata[0x510+i]` | **no** |
| `0x140..0x14f` | `MAC(pw)` | **yes** |
| `0x150..0x167` | `buf40[16..39]` (plaintext password tail) | **yes** |
| `0x168` | `0x80` | no |
| `0x169..0x16f` | zero | no |

The 192-byte table is constant across runs and passwords — it is a salt, not
key material. (This corrects the earlier note in this file that called it a
"224-byte key-stretch context" which the solver would have to model.)

## 4. The sponge (`0x65A0`)

```
prev = 0
repeat 1000 times:
    s = buf40[0..15] ^ prev                        # the password head, re-injected
    6 x f5e20(s, c)   c = 0..5
    f5c10(s, key = buf40[16..31], lb = 6)
    s[0..7] ^= buf40[32..39]
    6 x f5e20(s, c)   c = 0..5      (twice -> 18 rounds total)
    prev = s
MAC = prev
```

`f5e20` = 2 × `f60b0` + a pairwise rotate; `f60b0` is four
`rotr8`/`rotl8` + add/sub steps with the two constant tables

```
T1 = 6c9f1ab735e3487d51132bc78eb24f63
T2 = 51132bc78eb24f63c93bbd119443ebdf
```

`sponge.py` reproduces the MAC byte-exactly for every password tested;
`sponge_inv.py` inverts every round (self-tested), so the whole 18-round
permutation `A` is invertible.

Measured properties of the sponge:

* flipping any single head byte changes 15–16 of the 16 MAC bytes (all 16 for 15
  of the 16 positions); flipping key bytes changes all 16. No byte-lane weakness.
* 1 000 iterations produce 1 000 distinct states — no cycle, no fixed point, no
  convergence.
* `A` is **not** GF(2)-affine (`A(a^b) != A(a)^A(b)^A(0)`), order > 64,
  `A(A(x)) != x`.
* `MAC != A^1000(head)` and `MAC != A^1000(0) ^ head` — the head really is
  re-mixed every iteration, which is what makes it one-way.
* head ↦ MAC is a bijection.

## 5. The success condition, in closed form

Let `P₀..P₅` be the 419-op round permutation, `P₆` the 1 015-op last round, and
`B₀..B₆` the seven absorbed blocks. Then

```
s0 = 0
s(i+1) = P_i( s(i) XOR B(i) )
gate:  s7[0..7] == C,      C = e6a0ef2284734165
```

Every `P` is a bijection on 16 bytes, so this inverts:

```
s4  = P3(P2(P1(P0(B0)^B1)^B2)^B3)              (constant)
    = b238115829a5e09d1252eff01078ae83

s6      = P6^-1(s7)        XOR B6
s5      = P5^-1(s6)        XOR B5
MAC_req = P4^-1(s5)        XOR s4
```

`s7[0..7]` is pinned to `C`; `s7[8..15]` is free. Writing `U = s7[8..15]`:

```
required_mac(U=0000000000000000) = 11045e5eb14d48c63723eae8e06d70b2
required_mac(U=e6a0ef2284734165) = 9bb77ab46b75feab60615758ad127083
```

`reduce.py` derives all of this from the captured program and verifies the
round trip.

**Therefore:**

> `crackme.exe` accepts `pw` **iff** `Sponge(buf40(pw))` equals
> `required_mac(U)` for one of the 2⁶⁴ values of `U` (and for passwords longer
> than 16 bytes, the plaintext tail blocks `B5`/`B6` move with the password as
> well).

There are exactly 2⁶⁴ admissible MACs out of 2¹²⁸ — a 64-bit constraint.

## 6. End-to-end proof

`emu.py --inject-mac` overwrites `window[0x140..0x14f]` after the sponge has run
and before the VM starts. Feeding it the model's own answer:

```
$ python3 analysis/tools/emu.py test123 --inject-mac 11045e5eb14d48c63723eae8e06d70b2 -v
  [capture vm_start] MAC=cc32b406bbfcacc658bcf662cca61c23 ... trace=0
  [inject] wrote MAC 11045e5eb14d48c63723eae8e06d70b2 at 0x14002b8e0
  exit=0
password='test123' exit_code=0 handlers=7915
```

The unmodified binary returns **0** — success — for a password that is wrong,
purely because the MAC matches the value the model predicted. That closes the
loop on every layer: dispatcher decoding, handler semantics, window layout,
round boundaries, the permutation inverses and the gate polarity.

Control run, same password, real MAC: `exit_code=1`.

## 7. Why the password cannot be *derived*

The only thing left is `Sponge(buf40(pw)) = required_mac(U)`. Two directions, both
closed:

1. **Invert the sponge.** `u₀ = 0`, `u_{i+1} = F(u_i ^ head)`, `MAC = u₁₀₀₀`.
   Going backwards, `u₉₉₉ = F⁻¹(MAC) ^ head` — every step needs `head`, which is
   what we are looking for. There is no fixed point, no cycle and no GF(2)-linear
   structure to exploit (measured, §4). Cost: 2¹²⁸ for a 16-byte head.
2. **Search passwords.** 2⁶⁴ of the 2¹²⁸ MACs are accepted, so the expected cost
   is 2⁶⁴ candidate passwords, each 1 000 sponge iterations ≈ 2⁷⁸ operations.
   The keystretcher is doing exactly its job.

There is also nothing hidden to find: the `.text`/`.rdata`/`.data` string scan
yields only encrypted API names, `frida` and debugger names; the 1 162 program
immediates contain no printable run of 5 or more; `A⁻¹` of each table block is
not a padded password; the tables are a plain XOR of `.rdata` with a linear key.

**Conclusion:** the check is a genuine keyed-hash preimage, deliberately built so
that neither patching nor brute force works. The password is not recoverable from
the binary by analysis. What *is* recoverable — and is recovered here — is the
exact 128-bit value any accepted password's sponge output must take, plus a
verified ~10 ms oracle for testing candidates.

## 8. Files

| path | what |
|---|---|
| `tools/emu.py` | Unicorn harness: API stubs, anti-debug handling, handler trace, window capture. `--inject-mac`, `--snap-every`, `-o out.json` |
| `tools/vmmodel.py` | byte-exact VM model, forward (`step`) and backward (`step_back`) |
| `tools/sponge.py` | byte-exact sponge / MAC |
| `tools/sponge_inv.py` | inverse of every sponge round (self-tested) |
| `tools/reduce.py` | derives the round permutations, `s4`, `required_mac(U)`; verifies against a capture |
| `tools/verify.py` | password → verdict oracle (~10 ms) |
| `tools/solve.py` | stage-1 replay validation + backward requirement propagation |
| `tools/dasm.py` | capstone RVA disassembler: `dasm.py <rva> <len>` |
| `tools/make_fake_dll.py`, `work/fake.dll` | stub kernel32 (185 exports) for the harness |
| `data/vm_program.json` | the decoded 7 915-instruction program + constant table |
| `disasm/*.txt` | sponge and gate disassembly |

Reproduce:

```
python3 analysis/tools/emu.py test123 -o /tmp/t123.json      # ~0.3 s, full trace
python3 analysis/tools/reduce.py                             # closed form + proof
python3 analysis/tools/verify.py test123                     # oracle
python3 analysis/tools/emu.py test123 \
        --inject-mac 11045e5eb14d48c63723eae8e06d70b2 -v     # exit=0
```
