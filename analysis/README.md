# crackme.exe reverse-engineering (C00005H2 "crack me")

Goal: recover the correct password for crackme.exe via legitimate RE (no patching, no external hints).

## STATUS (as of this update)
**A working unicorn emulator now runs the binary end-to-end to the password prompt and checks the
password.** All 28 runtime-resolved APIs resolve, anti-debug checks pass, and the binary reads the
password via ReadConsoleW, runs the 1000-round sponge + VMP bytecode VM, and calls
`ExitProcess(0)` on success / `ExitProcess(1)` on failure. Common passwords (test123, aaaa, pass,
+25 more) all FAIL. The next step is to (a) capture a full ground-truth sponge trace for a known
password, (b) validate/fix the Python sponge model, and (c) sweep candidate passwords.

## How the emulator gets the binary running (the hard part)
The binary is a no-import PE that resolves its own APIs at runtime via a custom
`LoadLibraryW`/`GetProcAddress` (0x6DD0 module lookup + 0x6BA0 export walk). The emulator
(analysis/tools/emu3.py + make_fake_dll.py) fakes:
- A minimal PE32+ `fake.dll` at 0x77000000 with a real IMAGE_EXPORT_DIRECTORY (~185 exports, ASCII
  names, section file-offset == RVA) so 0x6BA0 can walk it.
- A TEB/PEB with a module list (kernel32.dll, ntdll.dll entries) so 0x6DD0 finds them.
- Trampolines at 0x78000000 + idx*0x40 for each API, dispatched by a single code hook.
- **CRITICAL:** trampoline fill must contain a NUL (`ud2` + 0x00*0x3e). 0xCC padding has no NUL and
  makes the resolver's forward-export NUL-scan (0x6C88–0x6D7E) run forever.
- **CRITICAL:** `OpenProcess` must return a nonzero handle (the binary calls
  `OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId())` and fails if it returns 0).
- **CRITICAL:** the binary executes `int3` (0xCC) anti-debug breakpoints; handle via a
  `UC_HOOK_INTR` handler that advances RIP past the 0xCC.
- The anti-debug TEB checks read `gs:[0x60]` (+2 BeingDebugged, +0xBC bits 4-6); a fake TEB at
  0x60001000 with those bytes = 0 passes.

## Verified findings
- **Pipeline:** password -> 0x80-pad to 40-byte buffer -> `0x65A0` 1000-round keystretcher
  ("sponge") -> 16-byte MAC -> VMP bytecode VM (loop 0xB2A0–0xB3E6) -> gate.
- **Success gate:** the VM sets an exitflag if `R[0..7] != C` where
  `C = [E6 A0 EF 22 84 73 41 65]` (VM steps 3781–3805). The VM returns `bl = (exitflag == 0)`;
  the caller does `ExitProcess(1 - bl)` (0 on success, 1 on failure).
- **Ground-truth MAC:** `test123 -> cc32b406bbfcacc658bcf662cca61c23` (captured live from the
  emulator's scratch+0x140, matches the statically-derived value). `aaaa -> f44249d71a7b7a9485e166b58c691f86`.
- **VM state layout** (base 0x2B650): +0x08 limit, +0x10 acc, +0x14 h (program counter),
  +0x28 R[0] (16-byte R array of dwords at +0x2C in the live dump), +0xB8 exitflag,
  +0xC0 c0, +0xC1..C5 c1–c5, +0xCC outpos, +0xD0 scratch ptr -> 0x2B7A0.
- **Sponge driver:** called with rcx = scratch (0x2B7A0); runs 1000 iterations (r14), each =
  6x 0x5E20 round + a key-mix; final 16-byte state = MAC, written to scratch+0x140.

## Sponge structure
- `0x60B0(s, t1, t2, off)`: swap s[off..off+3]<->s[off+4..off+7]; then
  `a'=rotl8(a+b, b&7)^t1[off]`; `b'=rotl8(b+D, c&7)`; `c'=rotl8(c-d, d&7)^t2[off]`;
  `d'=rotl8(c'+d, A&7)^t1[off+3]` (A=s[off+4], D=s[off+7] post-swap). **Verified byte-exact.**
- `0x5E20(state,t1,t2,cnt)`: 2x 0x60B0(off=cnt) + pairwise rots
  `for i in 0..7: s[8+i]=rotl8(s[8+i], s[i]&7); s[i]=rotl8(s[i], s[8+i]&7)`.
- `0x5C10(state,key,t1,t2)`: state^=key(16); loop(lb): 2x 0x60B0(off=lv) + same pairwise rots.
- `0x65A0` driver: state=buf[0..15]; 1000x { 6x 0x5E20(i=0..5); key-mix; 6x 0x5E20(i=0..5) };
  MAC=state.
- Tables: `t1@0x2B628 = 6c9f1ab735e3487d51132bc78eb24f63`, `t2@0x2B630 = 51132bc78eb24f63c93bbd119443ebdf`.

## Files
- `tools/emu3.py` — the working unicorn harness (copy of /home/user/emulator/emu3.py).
- `tools/make_fake_dll.py` — builds the fake export-table DLL.
- `tools/sponge.py` — Python model of the sponge (0x60B0 verified; full MAC pending validation).
- `disasm/re_60b0.txt`, `re_5e20.txt`, `re_5c10.txt`, `re_65a0.txt` — capstone disassembly.

## Next steps
1. Capture a full ground-truth sponge trace (driver buffer + per-iteration state) for a known
   password from the live emulator.
2. Validate/fix the Python sponge model against the live MAC.
3. Sweep candidate passwords (the MAC is one-way; the password is a short human string, so a
   targeted candidate list + the validated model is the path).
