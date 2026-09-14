# crackme.exe reverse-engineering (C00005H2 "crack me")

Goal: recover the correct password for crackme.exe via legitimate RE (no patching, no external hints).

## STATUS
**Sponge MAC model is FULLY BYTE-EXACT and the GATE is fully decoded.** The remaining task is the
password search itself, which is blocked on a fast oracle (see "What's blocking the password search").

- `tools/sponge.py` computes `MAC(pw)` byte-exact for any password:
  - `test123  -> cc32b406bbfcacc658bcf662cca61c23`  (matches emulator)
  - `aaaaaaaa -> 8929fc1347a4b5db644e5ba5f47067cf`  (matches emulator)
- The success **gate** is `R[0..7] == C` where `C = E6 A0 EF 22 84 73 41 65` (8 handler-16/18
  checks). A full unicorn emulator (`tools/emu3.py`) is a valid oracle (~4 s/password) but the
  sponge MAC is only part of what the VM reads (see below).

## Architecture (verified in the emulator)
```
ReadConsoleW(pw)
  -> 0x9b80  builds buf40 = pw + 0x80 + zeros
  -> 0x65A0  sponge keystretcher, 1000 iterations (r14=0x3e8)
       writes MAC block + a 224-byte key-stretch context (see "Sponge output")
  -> 0xB0B0  VM setup (shuffle-per-run bytecode, dispatch table @ r14=0x4000)
  -> 0xB2A0  VM loop, ~15557 iterations (hot body 0xB310-0xB355)
  -> GATE    R[0..7] == C  (8 checks); fail => exitflag |= 1
  -> ExitProcess(1) on failure, ExitProcess(0) on success
```

## Sponge (0x65A0) — byte-exact model in tools/sponge.py
Per iteration (i = 0..999), with `prev` the previous iteration's state (prev=0 initially):
```
state = buf40[0..15] ^ prev            # Feistel feedback (0x6611-0x661a)
6 x 0x5E20(state, ctr=0..5)
0x5C10(state, key=buf40[16..31], lb=6) # state^=key then 6x 0x5E20
state[0..7] ^= buf40[32..39]           # (upper 8B ^= 0)
6 x 0x5E20(state, ctr=0..5)
prev = state
MAC = prev
```
- `0x5E20(state,cnt)` = `0x60B0(win0,cnt) + 0x60B0(win8,cnt) + pairwise-rot`.
- `0x60B0(s,win,off)`: swap s[win..win+3]<->s[win+4..win+7];
  `a'=rotl8(a+b,b&7)^T1[off%8]`; `b'=rotl8(b+D,c&7)`; `c'=rotl8(c-d,d&7)^T2[off%8]`;
  `d'=rotl8(c'+d,A&7)^T1[(off+3)%8]` (a,b,c,d=s[win..win+3], A=s[win+4], D=s[win+7]).
- `0x5C10(s,key,lb)`: `s ^= key`; `lb x (0x60B0(win0,lv) + 0x60B0(win8,lv) + pairwise-rot)`.
- Tables: `T1=6c9f1ab735e3487d51132bc78eb24f63`, `T2=51132bc78eb24f63c93bbd119443ebdf`.

### Sponge output (what the VM reads)
The sponge (rdi=0x2B7A0) writes, verified by post-sponge memory diff:
- `rdi+0x140` (0x2B8E0) MAC16  (= MAC, the 16-byte digest — modeled in sponge.py)
- `rdi+0x150` (0x2B8F0) key16  = buf40[16..31]
- `rdi+0x160` (0x2B900) tail8  = buf40[32..39]
- `rdi+0x168` (0x2B908) 0x80
- **`rdi+0x80..rdi+0x1DF` (0x2B820-0x2B8DF) a 224-byte key-stretch context** (written by the
  sponge epilogue XOR/PMADDWD/PSHUFB loop @0x6760-0x6920). **NOT yet modeled in Python.**

## The gate (see disasm/re_vm_gate.txt)
8 checks; before check i (i=0..7) the VM sets `R[17]=C[i]`, `c1=17`, `c2=i`:
- handler-16 @0x1270: `c0 = (R[c1] == R[c2])`  =>  `c0 = (C[i] == R[i])`
- handler-18 @0x12c0: `if !c0: exitflag |= 1`
=> **gate passes <=> R[0]==C[0] && ... && R[7]==C[7]**, `C = E6 A0 EF 22 84 73 41 65`.

R[0..7] is computed by the VM from the MAC block **and** the 224-byte context. It is not a simple
per-byte function of MAC[0..7] (no constant XOR/add fits the 3 captured data points).

### Ground truth (test123, FAIL)
- gate R[0..7] = `b2 e4 96 25 ed f6 0e 69`; R[17] = `e6 a0 ef 22 84 73 41 65` (=C, set per-check)
- MAC = `cc32b406bbfcacc658bcf662cca61c23`; acc set @0x1380; exitflag set @0x12c9 (x8)

## What's blocking the password search
The sponge MAC (16 B) is modeled, but the VM also reads the **224-byte key-stretch context**
(0x2B820-0x2B8DF). An oracle that injects only the MAC block (skipping the sponge) diverges from
the real binary, so it is invalid. Two paths to the password:
1. **Model the 224-byte context in Python** (decode the sponge epilogue @0x6760-0x6920) -> a valid
   fast oracle -> sweep a candidate list.
2. **Use the full emulator** (tools/emu3.py, ~4 s/pw) as the oracle and sweep a candidate list
   (slower, but no additional RE needed).

## Files
- `tools/sponge.py` — byte-exact sponge MAC model (self-test: 6 rounds + 2 full MACs).
- `tools/emu3.py` — the working unicorn harness (valid oracle).
- `tools/make_fake_dll.py` — builds the fake export-table DLL.
- `disasm/re_60b0.txt`, `re_5e20.txt`, `re_5c10.txt`, `re_65a0.txt` — sponge disassembly.
- `disasm/re_vm_gate.txt` — VM + gate + handler analysis.
