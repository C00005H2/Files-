# Para's VanillaTool: why the injection fails (and why `Insert` does nothing)

Subject: `Para's Vanillatool -Rework- 11.31.exe`
(sha256 `34191c0753a8575b894d4bb02d49dc15f55aaaf5752d94e10aa336aa38abf28a`;
derived-artifact digests in §8)
Game side observed: `aion.bin` (x64) on the **EuroAion** private server, module list
supplied by the user (no `d3dx9_30.dll`, no `d3dx9_43.dll`, no `Game.dll`;
`euroaion.dll`, `clmods64.dll`, `crysystem.dll`, `RTSSHooks64.dll`,
`AcGenral.dll`/`AcLayers.dll` present).

All line numbers below refer to `inner_deob2.au3`, the de-obfuscated inner script
produced by `tools/recover/recover.py` (84,282 lines). Everything quoted is
reproducible from the repository plus that tool; nothing was guessed.

---

## 1. Answers up front

**Q: Why does pressing Insert do nothing?**
Because *Insert is not handled by the tool at all*. The only AutoIt-level hotkey in
the whole product is `{F10}` (pause toggle, `inner_deob2.au3:60922/60929`).
`Insert` lives inside the injected ESP module `VanillaEsp_v1.3.8.dll`: it is an entry
in that DLL's ImGui named-key table (`...LeftArrow…Home…End…Insert…Delete…`), polled
through its `user32!GetAsyncKeyState` import. The DLL is the thing that would draw the
ESP menu and react to Insert. **No DLL inside `aion.bin` ⇒ nobody is listening for
Insert.** Your module list proves the DLL is absent, so "Insert does nothing" and
"d3dx9_30.dll is not loaded" are the same failure.

**Q: Why is `d3dx9_30.dll` never loaded into the game?**
Two independent reasons, either of which is sufficient:

1. **The injection itself is structurally broken on modern Windows** (§3). The tool
   tries three methods (hook, remote thread, thread hijack); each one silently no-ops
   or loses a race, and every diagnostic `ConsoleWrite` is behind
   `If @Compiled = False` (`inner_deob2.au3:58227`), so a compiled build reports
   *nothing* — which is exactly the "nothing happens" symptom.
2. **Even a perfectly executed `LoadLibraryW` of that file would fail in your setup**:
   `VanillaEsp_v1.3.8.dll` has *hard static imports* on `d3dx9_43.dll`
   (`D3DXCreateTextureFromFileExA`, `D3DXVec3Project`, `D3DXGetImageInfoFromFileA`),
   on `d3d9.dll` (`Direct3DCreate9`) and on the VC++ 2015+ runtime
   (`MSVCP140.dll`, `VCRUNTIME140.dll`, `VCRUNTIME140_1.dll`, `api-ms-win-crt-*`).
   Dependency resolution for `LoadLibraryW("%TEMP%\d3dx9_30.dll")` uses the default
   search order — the *game executable's* directory, `System32`, … — and `%TEMP%` is
   not part of it. The DLL's delay-import directory is empty (RVA `0x0`), so this
   dependency is resolved at load time and cannot be satisfied lazily. Modern Windows
   does not ship D3DX9, and your private-server client clearly does not either (your
   list contains neither `d3dx9_43.dll` nor `d3dx9_30.dll`; had our module mapped,
   `d3dx9_43.dll` would have been dragged in with it). Your list *does* show a
   duplicate `version.dll` — a 152 kB one from the game folder shadowing the 40 kB
   system one — which proves the game directory is ahead of `System32` in this
   process' search order, so `d3dx9_43.dll` is missing from *both* places.
   Result: `ERROR_MOD_NOT_FOUND` (126), module never maps, the tool's own
   post-check (`EnumProcessModules`, `inner_deob2.au3:20562`) sees the failure, burns
   the two fallbacks, and goes quiet.

**Q: Is my auth emulator the cause?**
**No.** The emulator only answers the HTTPS service boundary
(`POST /data/auth.php`, `GET /Updateless/Version.txt`, `/Log/log.php`, `/POST/`, `/GET/`).
Your screenshot shows the parsed licence counters ("Retail 1 Day(s) remaining /
Private 2 Day(s) remaining"), i.e. the `ORythm`/`PRythm` values from *your* emulator
were accepted — auth is working. The injection path performs **zero network I/O**:
it is a purely local sequence of `VirtualAllocEx` / `WriteProcessMemory` /
`SetWindowsHookEx` / `CreateRemoteThread` / thread-context surgery followed by an
in-process `LoadLibraryW`. Nothing in §3 touches a socket.
One real (but unrelated) interaction to keep in mind: the *outer loader* rewrites
`C:\Windows\System32\drivers\etc\hosts` and kills/renames proxy and debugger
processes (`Charles.exe`, `mitmproxy.exe`, `Fiddler.exe`, `wireshark.exe`,
`IDApro.exe`, `ollydbg.exe`, inner script lines 9641–9661). If your emulator setup
depends on a hosts redirect or a local proxy, the loader can clobber it — that would
break a *later auth call*, never the injection.

---

## 2. What actually runs (four layers)

| # | Artifact | Container | Notes |
|---|----------|-----------|-------|
| L0 | `Para's Vanillatool -Rework- 11.31.exe` | UPX 4.21, method 14 (LZMA, dict 2²⁴, lc/lp/pb 3/0/0) → AutoIt 3 x64, EA06 container | loader stub, 17,330 lines, `#RequireAdmin` |
| L1 | loader stub script | hex-blob payload (8,558 chunks → 8,557,568 B) | writes the inner PE to `%TEMP%\{5E7D2FEC-DA12-4EF4-8DFC-15AC4BAB2107}\<name>` where the name comes from `HKCU\Software\Para's NoAnimation\fHide_VT`; runs it with `/ErrorStdOut setup="…" PID="…" Region="…" Script="…"`; panic key **Ctrl+Esc** kills child + deletes payload |
| L2 | inner PE | UPX + AutoIt, *SecureAu3*-obfuscated (91,165-entry hex string table) | the real tool: 88,053 token lines → 84,282 de-obfuscated lines; 17 `FileInstall` payloads |
| L3 | `VanillaEsp_v1.3.8.dll` (dropped as `d3dx9_30.dll`) | plain x64 PE, **no exports**, ImGui-based ESP | `Insert` menu toggle, `GetAsyncKeyState`, reads `\_ESP.ini`, expects `Game.dll` / `AIONClientWndClass1.0` |

Recovery keys (for the record): UPX packheader at file offset `0x3e0`;
EA06 content key `0x2477` (= checksum 0 + `au3_ResContent`);
AES-256-CBC IV `9324463837711294` for the *auth* codec (see `vanillatool_emulator`).

---

## 3. The injection path, method by method

Trigger (`inner_deob2.au3:4861-4870`): if the module is not already present in the
target PID, `FileInstall` drops the ESP DLL to `@TempDir & "\d3dx9_30.dll"` and calls
the injector `A597A40153F(hwnd, pid, @TempDir & "\d3dx9_30.dll")`.

### Method A — `SetWindowsHookEx` into anonymous memory (`A597A40153F`, line 12723)
```autoit
$shell = "0x" & "55" & "488BEC" & "4883EC20" & "48B9" & <ptr to path in target> _
        & "48B8" & <kernel32!LoadLibraryW> & "FFD0" & "4883C420" & "488BE5" & "5D" & "C3"
VirtualAllocEx(pid) x2            ; path string + shellcode, PAGE_EXECUTE_READWRITE
WriteProcessMemory x2
$hook = SetWindowsHookEx($WH, $shellcode_in_target, <ntdll handle>, <game GUI thread>)
Sleep(1000)
UnhookWindowsHookEx($hook)        ; line 59539 wrapper
```
Why it dies:
* `lpfn` points at `VirtualAllocEx` memory in the target, **not inside any mapped
  module**. `SetWindowsHookEx` is documented (and implemented) to map `hMod` into the
  target and call `lpfn` relative to it; a callback in anonymous RWX memory is never
  dispatched on current Windows — the call "succeeds" and nothing ever happens.
* Even if it were dispatched, the hook is removed after a fixed `Sleep(1000)`; a game
  thread that does not pump a hook-triggering message inside that second never runs
  the shellcode.

### Verification (`A2BEA30334F`, line 20562)
`EnumProcessModules` + module-name substring search in the target. This is what tells
the tool (silently) that method A failed — and what your external module list
independently confirms.

### Method B — `CreateRemoteThread(LoadLibraryA)` with a dangling argument
(`A317A302810`, line 70044)
```autoit
$p = VirtualAllocEx(pid, 4096, ...)
WriteProcessMemory($p, path_as_CHAR[])          ; ANSI this time
DllCall(..., "CreateRemoteThread", pid, 0,0, LoadLibraryA, $p, 0,0, ...)
DllCall(..., "VirtualFreeEx", pid, $p, 4096, 32768)   ; MEM_RELEASE, immediately
DllCall(..., "CloseHandle", thread)
```
The argument buffer is released **before the remote thread has been scheduled**.
`LoadLibraryA` then reads freed/unmapped memory: the load fails (or faults inside the
game, swallowed by the game's SEH). This is a race the tool loses almost always.
All its `ConsoleWrite("InjectDLL_Allocated: …")` traces are behind
`If @Compiled = False` — invisible in the shipped build.

### Method C — suspend-everything + RIP hijack ("InjectDLL_v3",
`A4C7A602A3C` line 69839 → `A117A802B01` line 58192)
```autoit
If $region = 1 Or $region = 5 Then Return        ; 69843-69845: skipped by design
suspend every game thread whose start address does not end in "3810"
loop: GetThreadContext(main thread) until
      EFlags = 582 And Rax in [4090,4110] And Rcx = 1368576
then SetThreadContext(Rip = shellcode); resume; "InjectDLL_v3 Success"
```
Why it dies:
* for two of the region slots it returns before doing anything;
* the wait condition hard-codes a syscall-number window (`Rax 4090..4110`) and a
  magic `Rcx` constant that only match the exact Windows build the author tested;
  on any other build the loop never converges;
* it suspends *foreign* threads too — with `RTSSHooks64.dll` (RivaTuner/Afterburner)
  and an AppCompat shim (`AcGenral.dll`/`AcLayers.dll`) inside your game process, both
  of which your module list shows, the thread set and the timing assumptions are
  further distorted.

Net: three methods, each individually unlikely to succeed on a current Windows 10/11
machine, no user-visible error for any of them.

---

## 4. Cross-check against your module list

The full `aion.bin` module dump (names, base addresses, sizes) was cross-checked
against the ESP DLL's PE headers. Import directory: RVA `0x1313dc`, size 400,
**19 modules**; the *delay-import* directory is RVA `0x0` / size 0 and the bound-import
directory is empty — so `d3dx9_43.dll` is a **hard, load-time** dependency: there is no
code path in which the DLL can map while `d3dx9_43.dll` is missing.

| Observation in `aion.bin` | Meaning for this analysis |
|---|---|
| no `d3dx9_30.dll` anywhere | injection never succeeded (all three methods failed or never ran) |
| no `d3dx9_43.dll` | the ESP DLL's hard static dependency is absent → even a correct `LoadLibraryW` returns 126 |
| `d3d9.dll` @ `0x7ffe4d630000` present | the API the ESP targets *is* available; D3D9 is not the blocker |
| no `Game.dll`, no `NCGuard.dll` | the ESP DLL's retail-client anchors are missing (see §5) |
| `clmods64.dll` @ `0x7ffe38280000` (24.4 MB, no description), `crysystem.dll` @ `0xae90000` (8.4 MB, described "AION GameClient"), `euroaion.dll` @ `0x7ffe6b390000` (172 kB) | private-server client: `aion.bin` itself is only 1.66 MB and is a stub, the real code moved into `clmods64.dll`/`crysystem.dll`. Every retail offset the ESP was built on is invalid here |
| **`version.dll` listed twice** — `0x7ffe6bc00000`, 152 kB, *no description*, and `0x7ffe8b890000`, 40 kB, "Version Checking and File Installation Libraries" | the EuroAion client ships a **local proxy `version.dll`** in the game folder that wins over `System32` (the real one is pulled in separately by another module). Two consequences: the game directory has precedence in this process' DLL search order, and the client already performs DLL proxying of its own |
| `DirectXApps_FOD.sdb` @ `0x7ff4fdd30000` (1.32 MB) **plus** `apphelp.dll`, `AcGenral.dll`, `AcLayers.dll` | a compatibility **shim database is mapped into the process** and shim layers are active. Shimmed processes get patched API behaviour and extra loader work — this distorts method A's 1-second hook window and method C's thread-set/register assumptions |
| `msvcp80.dll` @ `0x58a40000`, `msvcr80.dll` @ `0x58970000` (VC++ **2005** runtime) but **no `MSVCP140.dll` / `VCRUNTIME140.dll` / `VCRUNTIME140_1.dll`** | the game is VC++2005-era; the ESP DLL needs the **VC++ 2015–2022 x64** runtime (54 `MSVCP140` imports, 16 `VCRUNTIME140`, and `VCRUNTIME140_1!__CxxFrameHandler4` — i.e. built with VS2019+). Absence from the list is not proof it is not installed on disk, but nothing in this process has loaded it |
| `ucrtbase.dll` @ `0x7ffe90a90000` present | the 10 `api-ms-win-crt-*` imports are forwarders satisfied by the Universal CRT — this part of the dependency set is fine |
| `RTSSHooks64.dll` @ `0x2790000` (2.4 MB, low base = injected) | RivaTuner/MSI Afterburner overlay is already hooking inside the game; it competes for the same D3D9/present path and adds threads that method C will suspend |
| `igc64.dll`, `igd10um64gen11.dll`, `igd12dxva64.dll` **and** `nvppex.dll` (NVIDIA 582.66) | hybrid (Intel + NVIDIA) GPU machine; the D3D9 device the ESP would hook may belong to either stack |
| `dbghelp.dll`, `imagehlp.dll`, `sfc.dll`, `sfc_os.dll`, `amsi.dll`, `wldp.dll` | image/integrity and AMSI machinery is live in the process (typical for `clmods64.dll`-style protected clients); a foreign module appearing can be detected or torn down after the fact |
| `ws2_32.dll`, `mswsock.dll`, `IPHLPAPI.DLL`, `cryptnet.dll` | only the *game's* networking; nothing here belongs to the tool's injection path |

Reading of the whole list: it is exactly what you would see if the tool dropped
`%TEMP%\d3dx9_30.dll` and then every injection attempt failed — and, independently,
exactly what you would see if a load had been attempted and rejected at
`d3dx9_43.dll`. Both statements are true here; the missing `d3dx9_43.dll` is the one
that would still bite after the injector worked.

---

## 5. Even a successful load would not produce ESP on this client

`VanillaEsp_v1.3.8.dll` was written against retail Aion. Its string/data references
include: `Game.dll`, `NCGuard.dll`, `AIONClientWndClass1.0`,
`\Resource\Icons\skills_4.6.ini` / `skills_4.8.ini` / `skills_nova.ini`,
`\Resource\Icons\Maps\Retail\ZoneInfo.ini`, `\Resource\Icons\NPC.ini`, `\_ESP.ini`,
`\radar.cfg`, `C:\Windows\Fonts\sylfaen.ttf`, section names `[Settings]`
(`Font`, `Size`, `ShadowState`, `ShadowColor`, `IconScale`).

* It imports `GetModuleHandleA` but **not** `GetModuleFileName*`; its config/resource
  paths are relative, i.e. resolved against the **game process' current working
  directory**. The AutoIt GUI, however, writes `_ESP.ini` and the skills INIs into its
  own `Para's Settings\` directory. On a stock retail layout (tool installed inside
  the game folder) the two coincide; on your layout they do not.
* Module anchors (`Game.dll`, window class) do not exist in the EuroAion client
  (`clmods64.dll`/`crysystem.dll`/`euroaion.dll` instead), so base-address resolution
  fails and the ESP initialises to a disabled state — Insert would stay dead even
  after a successful load.
* The retail layout is not just renamed here, it is restructured: your `aion.bin` is a
  1.66 MB stub while 24.4 MB of `clmods64.dll` and 8.4 MB of `crysystem.dll` carry the
  client. The ESP's hard-coded offsets/signatures (its thread-hijack-style constants
  and `Game.dll`-relative lookups) have no counterpart in that layout.

---

## 6. Emulator interaction, precisely

* Implemented surface (repo `vanillatool_emulator/`): auth form
  (`aN`,`aU`,`aH`,`aC`,`aV`) → `C:<cipher>;` with `ORythm`/`PRythm`; `Version.txt`
  (`11.31`); telemetry; generic fixtures. Your screenshot's day counters prove the
  auth round-trip succeeded.
* The injection code (§3) contains no HTTP/DNS/wininet usage; failure modes are local.
* Caveat worth knowing: the **outer loader** maintains the hosts file and terminates
  MITM/debug tools (inner script 9641–9661). If your emulator relies on a
  hosts-file redirect or a local proxy, verify the hosts entries *after* a tool run;
  a clobbered redirect surfaces as an auth failure on the next start, not as an
  injection failure.

---

## 7. Confirmation checklist (ordered, cheapest first)

1. `dir <game>\bin64\d3dx9_43.dll` and `dir C:\Windows\System32\d3dx9_43.dll`. Your
   module list proves the game folder takes precedence (duplicate `version.dll`), so
   check both. This is a **diagnostic** step, not a cure: supplying the file removes
   the dependency blocker, but the three injection methods in §3 are broken
   independently, so `LoadLibraryW` may still never be called. Its value is that it
   isolates which of the two blockers you are hitting — with `d3dx9_43.dll` present,
   ProcMon will show a genuine `Load Image` attempt instead of a silent
   `NAME NOT FOUND`.
2. Check the VC++ 2015–2022 **x64** redistributable: the ESP DLL imports 54 functions
   from `MSVCP140.dll`, 16 from `VCRUNTIME140.dll` and
   `VCRUNTIME140_1!__CxxFrameHandler4`, while your process has only the VC++2005 pair
   (`msvcp80.dll`/`msvcr80.dll`) loaded. `ucrtbase.dll` is present, so the
   `api-ms-win-crt-*` half is already satisfied.
3. After clicking *Inject…*: `dir %TEMP%\d3dx9_30.dll` — confirms the drop happened.
4. Process Monitor, filter `Process Name = aion.bin`, path contains `d3dx9`: expect
   `NAME NOT FOUND` on `d3dx9_43.dll` (or a failed `Load Image`). Event Viewer →
   Application: side-by-side / error-1000 entries corroborate.
5. Close MSI Afterburner / RivaTuner (`RTSSHooks64.dll`) and clear the compatibility
   shim on `aion.bin` (`AcGenral/AcLayers`), then retry — both perturb methods A/C and
   any D3D9 hooking the ESP does after loading.
6. If the module finally appears but no menu: copy `Para's Settings\_ESP.ini` plus the
   `Resource\Icons\…` tree into the game folder (the DLL resolves them via CWD).
7. Try a different region checkbox: with region index 1 or 5 method C is skipped by
   design (`inner_deob2.au3:69843`).
8. For definitive attribution of *which* method ran: ProcMon shows the tool's
   `WriteProcessMemory`/thread creation against `aion.bin` and the (absent)
   `Load Image` of `d3dx9_30.dll` inside `aion.bin`; the compiled tool itself will
   never print anything.

---

## 8. Reproducing this analysis

```sh
pip install autoit-ripper pefile          # + gcc on PATH
python3 tools/recover/recover.py "Para's Vanillatool -Rework- 11.31.exe" /tmp/vt
```

Outputs: `outer_script.au3`, `payload.bin`, `inner_image.bin`, `inner_files/*`
(including `…VanillaEsp_v1.3.8.dll`), `inner_script.au3`, `inner_deob.au3`,
`inner_deob2.au3`. Reference digests produced during this analysis:

```
5d1a3f4741ebc15c3747530081bd739787ddc69a3fbe2559b95e91bb331f0541  payload.bin
0fa848e9631e0957f82f56c39c5bbcaa09979745970180f10d556fc1bf382eea  inner_image.bin
d268231a7c27f5e5943c6717256d16cd0812e3e3bc31b1d5e6bbcf6efbf93761  inner_files/…VanillaEsp_v1.3.8.dll
a36157d0fe443efdd90e2ff6385481389785f5dd45a7768ea52085642b66c42e  inner_deob2.au3
```

Key anchors in `inner_deob2.au3`: ESP drop + inject `4861-4870`; method A `12723`;
module check `20562`; `SetWindowsHookEx` wrapper `29388`; unhook wrapper `59539`;
method C wrapper `69839` (region skip `69843`); method B `70044` (`VirtualFreeEx`
race at `70059`); thread hijack `58192` ("InjectDLL_v3 Success" `58227`);
only AutoIt hotkey (`{F10}`) `60922/60929`.

The auth-side protocol (what the emulator fakes) is documented in the root `README.md`
and `vanillatool_emulator/`; it is orthogonal to everything above.
