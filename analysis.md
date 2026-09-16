# Reverse-engineering documentation — `game.dll` and the AION tooling

This document contains the deep static analysis of the workspace's `game.dll`, followed by the
pre-existing analysis of the two AutoIt tools. The `game.dll` conclusions below are based on the
exact file currently present in the repository, not on its filename or on assumptions about the
surrounding launcher. No executable code was run during this analysis.

---

## A. `game.dll` — deep static analysis

### A.1 Bottom line

`game.dll` is very likely a renamed, protected NCSoft AION game module rather than a custom
VanillaTool payload. The strongest indicators are:

* the raw version metadata identifies it as **AION GameClient**, internal name `NcSoft`, and
  original filename `NcSoft.DLL`;
* it exports the CryEngine-style `CreateGameInstance` and `CryModuleGetMemoryInfo` entry points;
* its resources contain NCSoft's `NcSoft.MacInfo` COM registration and type library;
* the file contains an Authenticode/PKCS#7 signature whose signed content hash matches the file
  exactly and whose leaf certificate subject is **NCsoft Corp.**;
* the PE timestamp, version, VC8 manifest, Bink/Awesomium dependencies, and import set are
  consistent with an old Windows AION client component.

This does **not** mean that loading the file is safe in an arbitrary directory. It is executable
native code with dynamic loading, networking, process enumeration, input hooks, anti-debugging
components, and a writable/executable custom section. It also does not prove that the surrounding
Account Manager is benign. It does mean that the evidence does not support describing this
particular file as an attacker-authored cheat DLL. A signed original DLL can still be deliberately
renamed and used by another loader.

**Confidence:** high for file identity, hashes, PE metadata, resources, imports, and signature;
medium for the protected-loader interpretation; low for exact post-unpack behavior because the
main code is not represented in ordinary raw PE sections.

### A.2 File identity, provenance, and integrity

| Property | Observed value |
|---|---|
| Workspace path | `game.dll` |
| Size | 7,249,984 bytes (6.91 MiB) |
| SHA-256 | `c4b5ad116928685c0cd443bdb301e9fe04655d1129e9f9acad8254f68cc1846d` |
| MD5 | `5cdfe531f964b5ab50d6ad4d772fcaf9` |
| PE format | PE32+, x86-64 (`IMAGE_FILE_MACHINE_AMD64`, `0x8664`) DLL |
| COFF timestamp | `0x54B3A055` — 2015-01-12 10:22:13 UTC |
| Export-directory timestamp | `0x54B39F30` — 2015-01-12 10:17:20 UTC |
| Image base | `0x10000000` |
| Entry point | RVA `0x195D94A`, preferred VA `0x1195D94A` |
| Linker | MSVC 8-era layout; manifest requests Microsoft VC80 CRT and ATL `8.0.50608.0` |
| Raw version | `FileDescription=AION GameClient`; `FileVersion=4515.0319.0112.8880` |
| Original filename | `NcSoft.DLL` |
| Company/copyright | `NCSoft`; `2006 (C) Copyright NCSoft Corporation. All Rights Reserved.` |
| PE checksum | Header value `0x006F52C9`; independently recomputed value matches |

The original filename is metadata, not a filesystem guarantee. Renaming `NcSoft.DLL` to
`game.dll` does not change the bytes and therefore does not invalidate an Authenticode signature.
It does, however, change how a game or loader resolves the module.

#### Authenticode evidence

The security directory is at file offset `0x6E9400`, size `0xC40`, with a PKCS#7 signed-data
blob. Its certificate chain contains:

* leaf: `C=KR, ... O=NCsoft Corp., CN=NCsoft Corp.`;
* issuer: `C=KR, O=SGssl, CN=SGTRUST CODE SIGNING CA`;
* issuer of that CA: `The USERTRUST Network / UTN-USERFirst-Object`.

The leaf is marked for code signing and has validity dates 2014-02-11 through 2017-02-10. The
certificate is therefore historical and expired as of the date of this report (2026-09-16); that
is a trust/validity issue, not evidence that the original bytes were modified. The SHA-1
Authenticode digest recovered from the signed content is
`4aae5354749087d629801d06376ddceb30ed4e8f`, and an independent PE Authenticode hash over the
file (excluding the checksum field and certificate table) produced the same value. The signature
is consequently internally consistent with this file.

### A.3 PE layout and the protected image model

The header declares 11 sections, but the first seven have no raw bytes on disk. The physically
present program material is concentrated in `.aion1`:

| Section | RVA | Virtual size | Raw offset | Raw size | Characteristics |
|---|---:|---:|---:|---:|---|
| `.text` | `0x001000` | `0xAAEA4C` | `0` | `0` | RX code |
| `TEXT` | `0xAB0000` | `0x0005C1` | `0` | `0` | RX code |
| `.rdata` | `0xAB1000` | `0x2E01F2` | `0` | `0` | read-only data |
| `.data` | `0xD92000` | `0x51DA60` | `0` | `0` | read/write data |
| `.pdata` | `0x12B0000` | `0x0957D8` | `0` | `0` | read-only exception data |
| `.tls` (virtual) | `0x1346000` | `0x000800` | `0` | `0` | read/write TLS area |
| `.aion0` | `0x1347000` | `0x1298C9` | `0` | `0` | RX custom code |
| `.tls` (raw) | `0x1471000` | `0x000030` | `0x400` | `0x200` | read/write TLS data |
| `.aion1` | `0x1472000` | `0x6E7870` | `0x600` | `0x6E7A00` | **RWX** custom section |
| `.reloc` | `0x1B5A000` | `0x74` | `0x6E8000` | `0x200` | relocation data |
| `.rsrc` | `0x1B5B000` | `0x1110` | `0x6E8200` | `0x1200` | resource data |

The header reports a virtual image size of `0x1B5D000` (28,692,480 bytes), versus the
7,249,984-byte file. `.aion1` alone has whole-section entropy about 7.926 bits/byte, with only
about 0.6% zero bytes. It contains short readable strings and import metadata interleaved with
high-entropy regions, which is consistent with a custom protection/packing layer rather than a
normal compiler-produced code section.

The result is important for reverse engineering: a normal file-to-RVA disassembler sees the
exported function RVAs `0x135500` and `0x11D950` inside virtual-only zero-backed sections, while
the entry point and TLS callback are in `.aion1`. The likely model is a loader/protected image that
runs from `.aion1`, reconstructs or decrypts code/data into the virtual-only ranges, and only then
makes the exported game routines usable. This is an inference from the section layout and control
flow, not a claim that every virtual-only byte is necessarily decrypted at runtime.

Additional protection indicators:

* `.aion1` is simultaneously readable, writable, and executable (`0xE0000060`), which is unusual
  for a normal game DLL and permits an unpacker or virtual machine to modify its own code;
* the PE has a TLS directory at RVA `0x195D080`, and its callback array contains one callback at
  preferred VA `0x11B503FD` followed by a null pointer; TLS code executes before the normal DLL
  entry point;
* the entry point begins with an indirect-looking jump graph and opaque/high-entropy data rather
  than a conventional MSVC prologue; the callback has the same protected layout;
* `SecureEngineSDK64.dll` is an explicit dependency (two ordinal imports), supporting a
  commercial protection/licensing/anti-tamper layer;
* `DllCharacteristics` is `0`, so this old build does not advertise modern `DYNAMIC_BASE`,
  `NX_COMPAT`, or Control Flow Guard flags, although it does carry a small relocation directory.

The exception directory claims a `.pdata` range of `0x957D8` bytes, but that section is also
raw-zero. This is another reason not to treat on-disk exception/unwind metadata as complete until
the image has been observed after its initialization path.

### A.4 Entry point, TLS, and directories

The relevant PE data directories are:

| Directory | RVA/offset | Size | Interpretation |
|---|---:|---:|---|
| Export | RVA `0x1B508C8` | `0xCC9` | export table in `.aion1` |
| Import | RVA `0x1B45218` | `0x1F4` | 24 import descriptors |
| Resource | RVA `0x1B5B000` | `0x1110` | registry/type-library resources and protected/irregular resource records |
| Exception | RVA `0x12B0000` | `0x957D8` | points into raw-zero `.pdata` |
| Security | **file offset `0x6E9400`** | `0xC40` | Authenticode certificate table; not an RVA |
| Base relocation | RVA `0x1B5A000` | `0x74` | 23 `DIR64` fixups plus alignment entries |
| TLS | RVA `0x195D080` | `0x38` | raw TLS pointers and callback list |
| IAT | RVA `0x19FD000` | `0x1800` | imported function address slots |

The TLS directory contains raw-data pointers for the second `.tls` section and an address-of-
callbacks pointer at `0x1195D0A8`. That array points to `0x11B503FD`. A static disassembly of
that address is intentionally unreliable because it immediately enters the protected jump/data
layout; it should be treated as an initialization callback, not as ordinary compiler output.

### A.5 Exports

The export table claims four entries and four names, but only three are coherent:

| Ordinal | RVA | Name | Assessment |
|---:|---:|---|---|
| 1 | `0xA5BC20` | `??4_Init_locks@std@@QEAAAEAV01@AEBV01@@Z` | MSVC C++ runtime helper |
| 2 | `0x135500` | `CreateGameInstance` | CryEngine-style game-module factory |
| 3 | `0x11D950` | `CryModuleGetMemoryInfo` | CryEngine-style memory-information API |
| 4 | `0x000000` | malformed binary-looking name | invalid/unused export record |

`CreateGameInstance` and `CryModuleGetMemoryInfo` are strong identity signals for a CryEngine
AION game component. The first export is a C++ runtime symbol, not a user-facing API. The fourth
name pointer lands in high-entropy bytes and its address is zero; it is best documented as a
malformed/protection artifact rather than a real callable export.

Because the first three function RVAs lie in sections with zero raw size, a static call to one of
them cannot be recovered from the file by simply seeking to `RVA == file offset`. The protected
initializer must be considered part of the load contract.

### A.6 Imported capability map

The binary has **24 import descriptors and 744 imported slots**. There are three separate
`KERNEL32.dll` descriptors. The counts below are descriptor totals, not proof that every API is
called on every execution path.

| Dependency | Imported slots | Capabilities suggested by the names |
|---|---:|---|
| `MSVCR80.dll` / `MSVCP80.dll` | 230 / 109 | VC8 C/C++ runtime, strings, streams, allocation, math, C++ exceptions, threads |
| `KERNEL32.dll` (three descriptors) | 126 + 1 + 6 | processes/threads, files, heaps, virtual memory, DLL loading, INI files, IO completion ports, locale/time, debug/error handling |
| `USER32.dll` / `IMM32.dll` / `GDI32.dll` | 47 / 18 / 7 | window/message loop, keyboard and mouse, clipboard, IME input, hooks, device contexts and bitmap rendering |
| `WS2_32.dll` / `MSWSOCK.dll` | 43 / 1 | sockets, overlapped/event networking, `AcceptEx`, send/receive and network event handling |
| `WININET.dll` | 14 | HTTP/Internet sessions, request headers, uploads, downloads, response queries |
| `CRYPT32.dll` / `LIBEAY32.dll` | 7 / 8 ordinal | certificate/object inspection and OpenSSL-style cryptographic services; ordinal names require the matching library build |
| `PSAPI.DLL` | 5 | enumerate processes and inspect process/module names and module lists |
| `ADVAPI32.dll` | 9 | registry read/write/create operations |
| `iphlpapi.dll` | 4 | adapter, IP-address, and TCP-table enumeration |
| `Awesomium.dll` | 70 | embedded browser, JavaScript objects/callbacks, rendering, cookies/cache, resource uploads and file chooser |
| `binkw64.dll` | 14 | Bink video/audio playback and frame rendering |
| `WINMM.dll` | 13 | waveform and mixer device enumeration/control |
| `SHELL32.dll` / `SHLWAPI.dll` | 3 / 1 | shell file operations, special folders, path existence |
| `ole32.dll` | 5 | COM initialization, object creation, task memory |
| `SecureEngineSDK64.dll` | 2 ordinal | protection/licensing SDK entry points |
| `sfc.dll` | 1 | `SfcIsFileProtected` system-file protection query |

Notable individual imports include `LoadLibraryA/W`, `GetProcAddress`, `VirtualAlloc`,
`CreateProcessA/W`, `OpenProcess`, `DeviceIoControl`, `SetWindowsHookExA`, `GetAsyncKeyState`,
clipboard functions, `EnumProcesses`, `GetModuleBaseName[A/W]`, and `IsDebuggerPresent`.
These are capabilities available to the module; the protected code may resolve additional APIs
at runtime.

Static negative evidence is also useful. The normal import table does **not** contain
`ReadProcessMemory`, `WriteProcessMemory`, `VirtualProtect`, `CreateRemoteThread`, an SCM driver
installation API, `WinHTTP`, or `URLDownloadToFile`. That lowers confidence in a conventional
user-mode injector or driver loader implemented directly through ordinary imports, but it is not
proof of absence because `GetProcAddress`, the protector, or device I/O can change the picture.
`OpenProcess`, PSAPI enumeration, keyboard hooks, and `DeviceIoControl` should not be interpreted
as malicious on their own; games, launchers, anti-cheat modules, and hardware-identification
components all use them.

### A.7 Resources and embedded identity

The resource area and raw resource payloads contain several unusually useful identity markers:

* `REGISTRY` is an `.rgs` script registering `NcSoft.MacInfo` and `NcSoft.MacInfo.1` under
  CLSID `{0F3B5FD9-0EB1-408B-8DD5-A3E98954BCC1}`, with `InprocServer32=%MODULE%` and apartment
  threading;
* `TYPELIB` begins with the `MSFT` type-library signature, names `NCSOFTLib`, `MacInfo`, and
  `IMacInfo`, and exposes the method names `GetMacInfo` and `GetPCInfo`; it was generated by
  MIDL 6.00.0366 on 2010-08-20;
* raw version data contains `AION GameClient`, `4515.0319.0112.8880`, `NcSoft.DLL`, `AION`, and
  `NCSoft`;
* the embedded assembly manifest requests the VC80 CRT and ATL assemblies, both version
  `8.0.50608.0`, for `amd64`;
* the signature contains NCSoft's company certificate as described above.

The custom section layout leaves some resource-directory pointers and raw resource blobs in an
unusual arrangement: ordinary `objdump` resource walking reports the named registry/type-library
records and an ID-6 record, while the raw version and manifest payloads are present at nearby
locations. This is consistent with the same protection/section-repacking issue seen elsewhere.
It is safer to record both the formal directory view and the raw payload evidence than to assume
that a generic resource parser has reconstructed the intended runtime tree.

### A.8 Reconstructed behavior model

The most defensible static model is:

1. Windows maps the PE, including the RWX `.aion1` section, the import table, and TLS data.
2. The TLS callback runs before the normal DLL entry point. Its code is in the protected custom
   region, so it likely performs protection checks and/or image initialization.
3. The entry point at `0x195D94A` enters a large jump-dispatch/opaque-predicate region. The
   `.aion1` stream mixes short jump fragments, symbol strings, import metadata, and high-entropy
   blocks rather than presenting a linear compiler code section.
4. Missing `.text`, `.rdata`, `.data`, `.pdata`, and `.aion0` raw bytes are likely reconstructed,
   decrypted, or otherwise materialized by that initialization path. This explains why the
   standard exports point into otherwise empty virtual ranges.
5. Once initialized, the module provides the CryEngine factory/memory exports and its AION game
   functionality: UI/browser support, video/audio, configuration, network communication,
   hardware/process inspection, and likely anti-tamper/licensing checks.

The import list and resources support steps 1, 2, and 5. Steps 3 and 4 are a high-confidence
explanation of the image layout, but exact algorithms, checks, URLs, and control-flow decisions
require a Windows memory snapshot after initialization or a controlled debugger trace. A raw
`objdump -D` of `.aion1` is not a valid semantic disassembly because data and protected code are
interleaved.

### A.9 Relationship to the Account Manager's `Game.dll` redirect

The AutoIt analysis later in this file documents an Account Manager routine that waits for AION
modules and overwrites two in-process NCGuard name slots with the literal `Game.dll`:

* `aion.bin + 0x863F8`;
* `CrySystem.dll + 0x21A2DB`.

That is behavior of the **loader/manager**, not provenance evidence for this DLL. For the exact
workspace artifact analyzed here, the more precise statement is:

* the manager attempts to cause the client to resolve a module named `Game.dll` instead of the
  original NCGuard name;
* this file is a 2015 x64 AION/NCSoft-signed game module with CryEngine-style exports, not a
  VanillaTool `d3dx9_30.dll` proxy or a kernel driver;
* successful use would depend on the target client's exact build, loader expectations, export ABI,
  and the presence of `Awesomium.dll`, `binkw64.dll`, VC80 runtimes, `LIBEAY32.dll`, and
  `SecureEngineSDK64.dll`;
* substituting it into an NCGuard resolution path can still be unsafe or incompatible. The signed
  identity of the file does not make the surrounding redirection or bypass safe.

This distinction corrects the shorthand description in the older section 6.2 below: calling the
workspace copy “the attacker's game.dll” is not supported by the file's own signature and version
metadata.

### A.10 Static risk assessment

| Observation | Security meaning |
|---|---|
| NCSoft Authenticode content hash matches | Strong evidence the bytes originated as a signed NCSoft artifact; certificate is expired today |
| RWX `.aion1`, high entropy, TLS callback, `SecureEngineSDK64.dll` | Significant protection/packing and anti-tamper complexity; static tools will under-report behavior |
| Networking, HTTP, sockets, crypto/cert APIs | The module can communicate and handle protected web/auth flows; no plain-text toolkit C2 domain was found |
| Process/module enumeration and debugger query | Could support client integration, anti-cheat, or anti-debug behavior; intent is not determined by imports |
| Hooks, clipboard, keyboard/mouse, Awesomium | Consistent with game UI/browser/input features, but warrants monitoring if loaded outside the game |
| `LoadLibrary*`, `GetProcAddress`, `VirtualAlloc`, `DeviceIoControl` | Dynamic extensibility and device interaction; inspect runtime calls before trusting deployment |
| No ordinary remote-memory-write/remote-thread imports | No static proof of a conventional injector in the visible import table; protected/dynamic code remains unresolved |

**Classification:** authentic-looking, protected AION/NCSoft user-mode DLL; operationally high risk to
load from a path controlled by an untrusted tool; not independently classified as malware or as the
VanillaTool payload from static evidence alone.

### A.11 Reproducibility and recommended next steps

The core observations can be reproduced without executing the DLL:

```text
sha256sum game.dll
objdump -f game.dll
objdump -h game.dll
objdump -p game.dll
strings -a -el -n 3 game.dll
openssl pkcs7 -inform DER -in extracted-certificate.der -print_certs -text -noout
```

For a complete behavioral report, use an isolated Windows VM and capture the module after its TLS
callback/entry-point initialization. Record the resolved memory map, changes to the zero-backed
sections, dynamically resolved APIs, child processes, registry/COM activity, files, sockets, and
loaded modules. Compare the in-memory exports against the three coherent EAT entries above. Do
not install the embedded COM registration, alter the hosts file, disable driver protections, or
run the Account Manager as part of ordinary triage.

---

## Existing Account Manager and VanillaTool report

All findings below were derived from the binaries themselves; extracted/deobfuscated sources and
payloads are preserved under `analysis/`. The separate static analysis of `game.dll` is in section A.

---

## 1. Executive summary

| | Para's Account Manager | Para's VanillaTool -Rework- |
|---|---|---|
| File | `Para's Account Manager - ver. 5.43.exe` | `Para's Vanillatool -Rework- 11.31.exe` |
| Size | 9,375,744 B | 14,708,224 B |
| MD5 | `986612dac013b140fe064e300820a21a` | `ddc30c842cf2e0ab3cdac8c09a46d142` |
| Packer | UPX 13/36 (Win64 PE), LZMA (method 14), filter 0x49 cto 0x25 | same |
| Native host | AutoIt v3.3.14 (EA06) interpreter, x64 | AutoIt v3.3.14 interpreter, x64 |
| Script | 1 stage, 11,250,357 B tokens / 0xE85D lines | **3 stages**: loader → hex-embedded PE (itself UPX'd AutoIt) → main script 16,655,405 B tokens / 0x157F5 lines (88,053 lines) |
| Build metadata | "Para's Account Manager - ver. 5.43.exe", 5.4.3.0, (c) Paraly, `#RequireAdmin` | stage2: 11.3.1.0 "(c) Paraly" (outer wrapper claims 11.31); original author path `F:\Documents\AutoIt\Autoit restart\GDI retest\Hack rework\...`, `#RequireAdmin` |
| Purpose | Multi-server AION account/launcher manager + NCGuard anti-cheat bypass + driver-based mapper infrastructure | Full AION bot/cheat (its own script engine, ESP overlay, skill rotations, flying/gather wizards) with the same license backend |
| License server | `https://subvanillatool.com/data/auth.php` (AES-256-CBC protocol) | same backend (`subvanillatool.com`, fallback IP `31.220.106.18` / IPv6 `2a02:4780:a:759:0:177b:3e9d:3` seen in stage-1) |
| Injection style | NCGuard anti-cheat DLL name-swap ("Game.dll"), kernel driver mapping (kdmapper-style), Gameforge client memory patching | `d3dx9_30.dll` proxy-DLL hijack (VanillaEsp overlay), direct `OpenProcess`/`WriteProcessMemory` game patching, remote `LoadLibraryW` |

Both tools share the vendor hive `HKCU\Software\Para's NoAnimation`, the same license
protocol, and much of the same helper-binary set.

---

## 2. Unpacking & script-recovery chain (validated recipes)

### 2.1 UPX layer
- PackHeader at file offset **0x3E0** (both exes): version 13, format 36 (Win64 PE), method 14
  (LZMA), level 10, filter **0x49** (`ctok32_e8e9_bswap_le`), cto **0x25**.
  - AM: `u_len=0x9777ED` (9,926,637), `c_len=0x8CAEFF`
  - VT: `u_len=0xE7A7ED` (15,181,805)
- Decompression: raw LZMA stream starting at **UPX1 section raw offset + 2**, parameters
  `lc=3 lp=0 pb=0 dict=1<<27`:
  ```python
  lzma.LZMADecompressor(format=lzma.FORMAT_RAW,
      filters=[{'id':lzma.FILTER_LZMA1,'lc':3,'lp':0,'pb':0,'dict_size':1<<27}])
  ```
- The CTO (call-trick) filter only affects code rel32s; the embedded a3x resource and payload
  bytes are **not** affected — no unfiltering is required for script extraction.
  Output = memory image (RVA = file offset + 0x1000, ImageBase 0x140000000).
- Helper artifacts: `/tmp/am_unc.bin`, `/tmp/vt_unc.bin` (regenerable from the exes).

### 2.2 AutoIt script/resource extraction (exact layout)
The compiled a3x lives as `RT_RCDATA → "SCRIPT"`; in the memory image the 16-byte magic
`A3 48 4B BE 98 6C 4A A9 99 4C 53 0A 86 D6 48 7D` + `AU3!EA06` is at:
- AM image offset **0x1209CC**, VT image offset **0x1338AC** (the same offset in the VT
  stage-2 image).

Record stream starts at `magic + 0x18 + 16` (24-byte magic/tag block + 16-byte data directory).
Each entry:

```
u32 'FILE'                LAME-decrypted with key 0x18EE      (LAME = AutoIt PRNG stream cipher)
u16len u32  len^0xADBC    subtype string, LAME key = len + 0xB33F, UTF-16LE
u16len u32  len^0xF820    name string,     LAME key = len + 0xF479, UTF-16LE
u8          isCompressed
u32         sc ^ 0x87BC   compressed size
u32         su ^ 0x87BC   uncompressed size
u32         crc ^ 0xA685  (not a real CRC32 in these builds)
16 B        timestamps
content     sc bytes,     LAME key 0x2477
```
Special subtype `>>>AUTOIT NO CMDEXECUTE<<<`: skip `1 byte` + `u32^0x87BC + 0x18` bytes.

**Every compressed record** (not only scripts) wraps its payload as
`'EA06' + u32be(uncompressed_size) + EA-LZMA bitstream`. Decode with
`decompress_default(ByteStream(body), unc, AutoItVersion.EA06)`
(bypass `decompress()`'s 10 MB `MAX_SCRIPT_SIZE` guard for the big scripts).
A few long-tail records (VT2 tbl/skills) need the bitstream zero-padded (~512 B) because the
compiler's stream ends a few bits short of what autoit_ripper's decoder requests.

`>>>AUTOIT SCRIPT<<<` records: the payload **is** the token stream (first u32 = line count),
decompiles directly with `autoit_ripper.opcodes.deassemble_script` (stock 3.3.14 EA06 opcodes:
0x00 keywords, 0x01 functions, 0x05 u32, 0x10 u64, 0x20 f64, 0x30–0x37 length-XORed UTF-16
strings, 0x40–0x58 operators, 0x7F EOL).

Working implementation: `/tmp/parse_a3x.py` (recipe above).

### 2.3 VanillaTool's three stages
1. **Stage 1 (outer exe)** — decompiled script is 99 % data: 8,610 variables (`$B`, `$C`, …)
   each holding ~2,000 hex chars. The code (last ~8.7k lines) concatenates 8,558 of them into
   `$CWL[1]`, `FileWrite`s it to `%TEMP%\<random>` and executes it — the blob is a **complete
   x64 PE (8,557,568 B, MD5 `364e419a75b453915d525804e656ff0a`)**, itself a UPX'd AutoIt exe
   (u_len 0x8E97ED). Rebuild: concatenate the blob assignments in `$CWL[1] &= $X` order,
   `bytes.fromhex` → `/tmp/VT_stage2.exe`.
2. **Stage 2 (dropped PE)** — unpacks (same UPX recipe, magic at image offset 0x1338AC) and
   contains the **main VanillaTool script** (`aut99D8.tmp.tok`, 16,655,405 tokens) plus its
   payload set (see §7).
3. **Stage 3 (main script)** — same obfuscation family as AM (`$OS[n]` constant table from
   `main v6.75_Release_stripped.au3.tbl`, split marker `!3{`, deobfuscation function
   `A0200001905` = hex-pairs → chars).

---

## 3. Obfuscation scheme (both tools)

1. **Identifier scrambling** — every variable/function renamed to `A<HexDigits>` blobs.
2. **Constant table** — string/number literals moved into a `FileInstall`ed table
   (`main 2.79_Release_stripped.au3.tbl` for AM, `main v6.75_...` for VT2):
   - table = hex-encoded constants separated by `|2{` (AM) / `!3{` (VT2);
   - at startup: `FileInstall(tbl, %TEMP%\<7 random a-z>)`, then
     `$OS = Execute(BinaryToString("0x…"))` (3 nested Execute layers) →
     `StringSplit(FileRead(tbl), '<marker>', 1)`; retried ×5;
   - code references constants as `A390000520A($OS[n])` (AM) / `A0200001905($OS[n])` (VT2)
     = hex-pairs → characters.
   - AM table: 62,686 parts, **all decode cleanly**. VT2 table: **91,165 parts, all decode
     cleanly** once extracted from the intact stream (the loader itself validates
     `$OS[0] >= 91164`).
   - Decoded banks: `/tmp/AM_OS.json`, `/tmp/VT2_OS.json` (workspace copies of resolved
     scripts: `analysis/*_resolved.au3`).
3. **ChrW/Chr arithmetic strings** — URLs and crypto constants assembled char-by-char from
   numeric globals.
4. **Self-referential crypto material** — the AES key/IV bytes are read from fixed offsets of
   the tool's *own* executable at startup (`FileOpen(@ScriptFullPath, 16)` + fixed offset +
   `StringRegExp('.{2}')` + `Chr(Dec(pair)-1)`): patching the file breaks the license crypto.

Deobfuscation tooling: literal inliner + local-variable resolver →
`analysis/AccountManager_5.43_resolved.au3` (59,485 lines),
`analysis/VanillaTool_stage2_main_resolved.au3` (88,053 lines).

---

## 4. Account Manager — initialization

1. `#RequireAdmin`; single-instance mutex; GUI build ("Para's Account Manager"), icon/flag
   `FileInstall`s into `%APPDATA%`-relative dir (`Execute(@AppDataDir) & "\...Para's..."`).
2. Settings hive `HKCU\Software\Para's NoAnimation`: `LastUsed`, `fHide_LR`, `fHide_MVT`,
   `fHide_VT`, `fHide_BBQ`, `fHide_UDK`, `AMLoginAllDelay`, `AMInstaScript*`,
   `VirtualClientSlot`, `CustomMac`, … — every helper toggle has a `fHide_*` value; missing
   values are created on first run (device-name default = **random A-Z/a-z string** via the
   internal RNG function, persisted under `fHide_UDK`).
3. `logins.ini` (per-account store next to the exe): `Delay`, `WaitForAionProcess`,
   `Purple_*`, `InstaScriptUsage`, `VirtualClient`, `CustomExe/Custom2/CustomBin`.
4. Update channel: Google Drive API
   (`googleapis.com/drive/v3/files/1ipfTih7ZmmYru-VCJCZkiprRvw-...`), `HttpSetUserAgent("Vanillatool")`.
5. Target discovery: `HKLM\Software\Wow6432Node\plaync\AION` / `AION_CLASSIC` value `BaseDir`
   → `\bin64\aion.bin`; supported servers (login presets): **EuroAion, Aion America, Destiny,
   GamezAion, Elden Aion**; `x_World.pak` presence check (`\Data\World\`).
6. Gameforge/Purple path: runs `PurpleLauncher.exe --allow-proxy --no-self-update
   --no-module-update --disable-auto-update --disable-role-check --lang en-US`, regex-parses
   `https://spark\.gameforge\.com/api/v[0-9]/product/(.*?)/...`, launches
   `gfclient://view/?game=<guid>` (two product GUIDs: `f7ed0b7e-…` and `cdc124e6-…`),
   waits for `gfclient.exe`, and can restore saved client sessions from
   `Para's Settings\GFL_Sessions\<account>` (DirRemove/DirCopy of
   `%LOCALAPPDATA%\Gameforge4d\GameforgeClient`).
7. Forces graphics defaults for stable injection: writes `SystemOptionGraphics.cfg`
   (`FULLSCREEN_HEIGHT "720"`, `USE_MG "0"`, `WINDOWFULLSCREEN "0"`, `FIXED_FRAME "0"`).
8. Auxiliary launchers: `AionLauncher "" /AuthProviderCode:"np" -litestep:9`, `ActiveLauncher.exe`.

---

## 5. Account Manager — license/auth protocol

Identical to the protocol implemented by the repo's own `vanillatool_emulator/protocol.py`
(the author's server protocol was reproduced 1:1 in AM):

- Endpoint: `POST https://subvanillatool.com/data/auth.php`
  (`winhttp.winhttprequest.5.1`, `Content-Type: application/x-www-form-urlencoded`).
- Machine id: 24-char id (padded to 24 with `'O'` if shorter).
- Form body:
  - `aN=` AES-256-CBC(machine-id) — hex, `StringTrimLeft(…, 2)` (strip `0x`)
  - `aU=` build/product tag
  - `aH=` first 8 chars of the unix timestamp string
  - `aC=` AES-256-CBC(`CPU_ID:BIOS_SERIAL`)
  - `aV=` version
- AES-256-CBC, PKCS#7. Static key = `bytes(range(15)) + b"0" + bytes(range(15)) + b"0"`
  (the 15 key bytes are derived at runtime from the exe's own bytes, §3.4);
  IV = `9324463837711294` (ASCII).
- Response: `C:<hex>;\r\n`; `<hex>` is decrypted with
  `StringLeft(timestamp(8,'0'-padded) & machine_id(24,'O'-padded), 32)` as key.
- Plaintext markers: `ORythm=<n>` and `PRythm=<n>` — license flags for the two products
  (Account-Manager side / VanillaTool side). `>0` → feature flags set; body containing
  `expired` → **"License expired"** error dialog; empty/invalid id → disable + cleanup.
- The emulator in `vanillatool_emulator/` implements this server side, including
  `/Updateless/Version.txt` (update check), `/Log/log.php?ID=<ver>` (telemetry) and
  `/POST/`, `/GET/` proxy routes.

---

## 6. Account Manager — driver mapping & injection

### 6.1 Vulnerable-driver mapping chain (`~line 41984` in resolved source)

`udk.bin` (VanillaUDK_3.13.bin) is a **KDU-style mapper** (its strings carry the classic
`kdu -list / -prv id / -map filename` usage banner, DSE patching, Zemana/AMD stagers).

1. Device name: `RegRead HKCU\Software\Para's NoAnimation ! fHide_UDK`; if missing it is
   created as a **random 11-character string** (generator `A0349104C2D(11)`). The patch step
   is skipped only when the variable holds the stray status string `"Injecting driver name.."`.
2. Drops payloads:
   - `VanillaDrv_3.13.sys` → `\<dir>\udk_2.bin` (the **victim/vulnerable driver**, 13,312 B)
   - `VanillaUDK_3.11.dll` → `udk_1.dll` (1,325,568 B, stored uncompressed — runtime support DLL)
   - `VanillaUDK_3.13.bin` → `udk.bin` (525,824 B — the manual mapper)
3. **Device-name patch** (writer `A24C8C02C50`): rewrites two fixed-size UTF-16LE slots in
   `udk_2.bin`:
   - offset **8176 (0x1FF0), 38 bytes** = `\Device\<name>` (8+11 chars)
   - offset **8224 (0x2020), 46 bytes** = `\DosDevices\<name>` (12+11 chars)
   The shipped `VanillaDrv_3.13.sys` carries bare random 19/23-char placeholder names in those
   slots (dev-build state); production runs always overwrite them with the prefixed form.
4. Runs the mapper hidden, walking a **provider ladder**, re-opening `\\.\ <name>` after each
   attempt (`CreateFileW` via kernel32; handle > 0 = victim driver loaded):
   1. `udk.bin -prv 1 -map udk_2.bin` → conflicts checked for **RTCore64** →
      hint `"Status: Make sure MSI Afterburner is closed."`
   2. `udk.bin -prv 2 -map udk_2.bin` → **Gdrv** → `"Status: Make sure Gigabyte TOOLS is closed."`
   3. `udk.bin -prv 3 -map udk_2.bin` → **ATSZIO64** → `"Status: Make sure ASUSTeK WinFlash utility is closed."`
   4. `udk.bin -map udk_2.bin` (mapper default provider), ATSZIO64 checked again
   Each attempt's stdout+stderr is merged and scanned with two StringRegExp patterns:
   `(?m)\[\!\] Unable to open vulnerable driver\, ` **and**
   `(?m)\[\+\] Provider: ".*?", Name "<driver>"` — both must match for the hint + `Exit`.
   (Note: the bundled 3.13 binary prints the failure line *without* the comma — AM 5.43's
   regex expects the comma form, i.e. the parser targets the mapper lineage it shipped with.)
5. Mapper internals (extracted strings): resolves `Ntoskrnl.exe` base
   ("Ntoskrnl.exe mapped at 0x%llX"), "Resolving kernel import for input driver", "Looking for
   %ws driver dispatch memory pages", "Driver handler code modified", "Successfully loaded
   victim driver", DSE-flag patching ("DSE patch executed successfully"), shellcode execution
   ("[~] Shellcode result: NTSTATUS (0x%lX)") — a **dispatch-table shellcode hook mapper**
   loading the victim driver through an already-loaded vulnerable driver, then mapping the
   actual payload through it.
6. `VanillaDrv_3.13.sys` (13,312 B): small kernel driver whose `\Device\`/`\DosDevices\`
   slots are the patch targets above; exposes the kernel r/w primitive used by the mapper.
7. `Status: Error 16` is Account Manager's **own** GUI message for a failed pre-check
   (displayed when the pre-flight function returns 0), not mapper output.

### 6.2 NCGuard (anti-cheat) bypass — `NCGuardRedirect_v2` (`~line 637`)
- Waits for `aion.bin` **and** `CrySystem.dll` to be loaded in the game process.
- Remote-reads two 128-byte char slots that hold the anti-cheat DLL name:
  - `aion.bin + 549880 (0x863F8)`
  - `CrySystem.dll + 2204379 (0x21A2DB)`
- Overwrites both with **`Game.dll`** → the client's loader resolves `Game.dll` instead of NCGuard.
  The workspace's 7,249,984 B x64 `game.dll` has custom `.aion0`/`.aion1`/`TEXT` sections, but its
  own metadata and matching Authenticode digest identify it as an NCSoft-signed AION GameClient
  module (see section A), not an attacker-authored payload. The manager's redirection behavior is
  still a separate, high-risk bypass operation.
- **NCGuard thread patching**: enumerates game threads ("Thread within NCGuard: …"), applies
  register-state patches logged as `+> Changed register from X to Y` with magic values
  `1048587 (0x10002B)` and `77` (thread-context patching to neutralize the guard thread).
- **API hooks**: `^(lstrcpyn|lstrcpynA|ReadFile)$` — hooks these in the game process
  (string-copy / file-read filtering used by the anti-cheat).
- **Window-class spoof**: memory patch of the 21-char window class string
  `AIONClientWndClass1.0` → `BIONClientWnd` (defeats class-name based anti-cheat lookups).
- Optional GUI toggle "[ ] Auto Inject Vanillatool" chains the bot injection after login.

### 6.3 Gameforge client helpers
- `SparkMod.exe` (1,078,784 B, packed; source path "Login manager\32Bit Writer") is dropped as
  **`spk.exe`** and run as
  `spk.exe /ErrorStdOut /PID=<gfclient_pid> /M=1|3|4 /N="<account>"` immediately after the
  Gameforge client starts — the "Anonify" step (per-account client identity/session patching;
  `/M` selects mode, `/N` the account name).
- Other embedded helpers: `GetThreads64.exe` (thread enumeration for the context patches),
  `SR.exe` (ScreenReader), `lr.exe`, `BBQ.bin`, `NovaApi.exe + api.dll + japi.dll`,
  `msgbox d3d reloader.dll` (ESP overlay reload helper), flag/icon JPGs.

---

## 7. VanillaTool — architecture & behavior

### 7.1 Stage-1 loader (outer script)
- `#RequireAdmin`; mutex; **anti-analysis process blacklist** (exits if any of these run):
  `Charles.exe`, `mitmproxy.exe`, `IDApro.exe`, `Fiddler.exe`, `ollydbg.exe`, `wireshark.exe` (and more via regex list).
- Reads a marker file/regex set; if the running script name ≠ registry-recorded name it
  re-copies itself and restarts renamed (self-relocation via
  `HKCU\...\{5E7D2FEC-DA12-4EF4-8DFC-15AC4BAB2107}` CLSID-style key).
- Writes **`explorer.exe`** (the stage-2 PE) to `%TEMP%\<random>` (`$BWL = @TempDir & $UVH`,
  `$EWL = "explorer.exe"`), registers an exit handler `_DelBinaryTempFiles`, re-runs it hidden
  with forwarded command-line args, then watches: opens `user32!MessageBoxW`-style
  `MsgBox`-flag polling on window titles, logs its stdout to `\Logs\Vanillatool Error\…`,
  edits `C:\Windows\System32\drivers\etc\hosts`
  (`... && ping 127.0.0.1 -n 2 > nul && ren ...` — domain redirect to the fallback IP
  `31.220.106.18` / IPv6 `2a02:4780:a:759:0:177b:3e9d:3` when `subvanillatool.com` is blocked),
  and shares `HKCU\Software\Para's NoAnimation` with AM (`fHide_MVT`, `fHide_VT` toggles).

### 7.2 Stage-2 payload set (embedded in the dropped PE)
| Payload | Size | Role |
|---|---|---|
| `aut99D8.tmp.tok` | 16,655,405 tokens | main VanillaTool bot script |
| `VanillaEsp_v1.3.8.dll` | 1,304,576 | ESP/overlay — dropped as **`d3dx9_30.dll`** next to the game (proxy-DLL hijack) |
| `GV.exe` | 671,173 | graphics/version helper |
| `main v6.75_Release_stripped.au3.tbl` | 1,496,450 | `$OS` constant table (offsets!) |
| `FS.exe` | 1,032,106 | "fastscript" helper |
| `GetThreads64.exe` | 1,307,136 | thread enumerator |
| `_skillsNA/_skillsEU/_skillsCNA/_skillsCEU/_skills4.6/_skills4.8/_skillsNOVA.ini` | 0.4–0.9 MB each | skill-rotation databases per server/client version (`[17] Skill_ID=17 …`, `ver=8.43/4.01/4.62/4.80/1.50`) |
| `ctrl.png`, `Gather.ini` | – | pixel-search templates / gather routes |
| `tk.exe` (TurboKeys) | 1,331,712 | key-spam/automation helper |
| `trimmedversionfixmouse.dll` | 46,592 | mouse-input fix DLL |
| `SR.exe` (ScreenReader) | 1,222,144 | OCR/screen reader for UI automation |
| chat page | – | `https://subvanillatool.com/data/chat.html` (in-app chat) |

### 7.3 Main script (stage 3)
- Build header: `#AutoIt3Wrapper_Outfile_x64=..\..\temp\Para's Vanillatool Rework new.exe`,
  description "Windows-Explorer", `Res_Fileversion=11.3.1.0`, `(c) Paraly`, `#RequireAdmin`,
  `#OnAutoItStartRegister` obfuscation preloader.
- License: same `subvanillatool.com` auth (auth URL assembled via ChrW codes; "License
  expired"/"expired" handlers; ORythm/PRythm flags).
- **Own scripting engine** (the actual product): user-editable bot scripts interpreted by VT —
  directives observed in the constant bank: `#EXECUTE=FlyingRoutine`, `#EXECUTE=Landing`,
  `#EXECUTE=TakingOff`, `#EXECUTE=WaitForFlightCD`, `#EXECUTE=CollectAether`,
  `#EXECUTE=CollectEssence`, `#EXECUTE=SellToMerchant`, `#EXECUTE=CloseWindows`,
  `#EXECUTE=CombatWizard`, `#EXECUTE=GatherWizard`, `#SCRIPT editor`, `#DYNAMIC`, `#DebugLog`,
  `#QuitAtRound`, `#UseNoLoo…`, `#UNTIL=%`, plus a per-server variable/offset dictionary
  (`%VAR=0x…` entries). "Script editor.." GUI, "Combat Wizard..", "Gather Wizard..",
  "Move Target Info..", "Select another Process..".
- **Game interaction**: `OpenProcess` / `ReadProcessMemory` / `WriteProcessMemory` /
  `VirtualAllocEx` / `LoadLibraryW` — direct user-mode patching of the client using the
  per-server offsets from the tbl (`%CamMax=0xBC`, `%ChatLog=0xB8`, `%FrameBorderDefault=0xCE`,
  `%InventorySlots=0xA3`, `%InventoryslotsMax=0xA48`, `%PrivateSellItemID=0xBD`, `%FoV=0xBC`,
  … 186 offset variables; full byte-patching loops write value arrays at
  `module + offset` — the NoAnimation/feature patches).
- **Injection paths**:
  1. drop `VanillaEsp_v1.3.8.dll` as `d3dx9_30.dll` into the game folder (DLL hijack; optional
     user-selected DLL via `FileOpenDialog` + remote `LoadLibraryW`);
  2. direct WPM patching of aion.bin/CrySystem modules;
  3. its **own NCGuard redirect** (constant bank: `NCGuard.dll`, `Game.dll`,
     `AIONClientWndClass1.0`, `aion.bin`/`aionclassic.bin`, process regex
     `(?i)^aion(?:classic|)[0-9]*?\.(?:bin|exe)$`) — the same anti-cheat name-swap AM performs;
  4. AM-side NCGuard redirect can auto-inject VT ("[ ] Auto Inject Vanillatool").
- **Web assist**: queries `http://aioncodex.com/` and
  `https://aioncodex.com/query.php?a=items&type=drop&id=` for item data; opens
  `iexplore.exe -k`.
- **Anti-VM**: `VMware Virtual Platform`, `Oracle VM VirtualBox`, `VBOX` string checks.
- Version-gated skill DBs match servers: NA/EU (8.43), Classic NA/EU (4.01), 4.6/4.8 clients,
  NOVA (1.50).

---

## 8. What the tools need to work (dependencies & requirements)

**Hard requirements**
1. Windows x64, administrator (`#RequireAdmin`) — needed for driver loading, HKLM writes,
   `etc\hosts` edit, process memory access.
2. License: valid machine-id on `https://subvanillatool.com/data/auth.php` returning
   `ORythm=>0`/`PRythm=>0` (offline → blocked; `expired` → blocked). Crypto material is tied
   to unmodified exe bytes (self-read key derivation) and to `CPU_ID:BIOS_SERIAL`.
3. AM: AION installed per registry (`HKLM\SOFTWARE\Wow6432Node\plaync\AION[ _CLASSIC]`
   `BaseDir`) or a Gameforge/Purple install; for Gameforge logins the saved session dirs and
   `spk.exe` ("32Bit Writer") path.
4. Driver chain: one loadable "vulnerable" provider (the mapper knows provider slots
   `-prv 1|2`); MSI Afterburner (RTCore64), Gigabyte (Gdrv) or ASRock (ATSZIO64) drivers
   must **not** already be loaded (conflict detection with explicit user hints);
   `VulnerableDriverBlocklistEnable=0` + HVCI off (the tool sets both).
5. VT: `d3dx9_30.dll` must be absent from the game folder (hijack) or a user DLL chosen;
   per-server offset table matching the running client build (skills ini + tbl).
6. Both: `%TEMP%` writable, `HKCU\Software\Para's NoAnimation` hive, hosts-file write access
   for the VT domain fallback.

**License-relevant "offsets"**
- AM: no game offsets required for its manager role; the injection offsets it *uses* are the
  NCGuard slots `aion.bin+0x863F8` and `CrySystem.dll+0x21A2DB` (hard-coded), the driver name
  patch sites `0x1FF0`/`0x2020` in `udk_2.bin`, and context-patch magic values `0x10002B`/`77`.
- VT: **all** game offsets are data-driven from `main v6.75_….tbl` (`%NAME=0x…` entries,
  186 offset variables, per-server blocks) — i.e., the "license offsets" are served/updated via
  the constants table, not compiled in; the tbl itself is integrity-dependent (see §3.4).

---

## 9. Workspace artifacts

| Path | Content |
|---|---|
| `analysis/AccountManager_5.43_decompiled.au3` | AM script, raw decompile (6.5 MB) |
| `analysis/AccountManager_5.43_resolved.au3` | AM script, `$OS` inlined + locals resolved (readable) |
| `analysis/VanillaTool_11.31_decompiled.au3` | VT stage-1 (loader) decompile incl. 8.6k hex-blob vars |
| `analysis/VanillaTool_stage2_main_decompiled.au3` | VT main script decompile (88k lines) |
| `analysis/VanillaTool_stage2_main_resolved.au3` | VT main script, all 91,165 constants inlined (readable, 7 MB) |
| `analysis/embedded_files/AM/` | AM payloads: `*.dec` (decoded, exact sizes), `*.raw` (LAME-decrypted streams), `aut42D.tmp.tok.tok` (script tokens) |
| `analysis/embedded_files/VT/` | VT stage-1 script tokens (`autDF73.tmp.tok`, 34,657,599 B) |
| `analysis/embedded_files/VT_stage2/` | VT stage-2 payloads (main tokens, VanillaEsp DLL, skills inis, tbl, helpers) |

Regeneration scripts (in `/tmp`, ephemeral): UPX/LZMA unpacker, `parse_a3x.py` (a3x record
parser), `resolve3.py` (`$OS` inliner + variable resolver), `eval_au3.py`/`eval_globals.py`
(literal-expression evaluator used to recover `https://subvanillatool.com/data/auth.php`).

### Driver-mapping emulation (`vanillatool_emulator/mapper.py`)

The HTTP emulator (`server.py`) only covers the license/update routes; the Account Manager
driver-mapping chain is a **local CLI contract** with the dropped `udk.bin`, so the emulator
ships a dedicated module reproducing it:

- `patch_device_names(data, name)` / `read_device_slots(data)` / `device_name(data)` — the
  0x1FF0/0x2020 UTF-16LE slot writes AM performs (11-char names enforced, matching AM's
  random default generator).
- `simulate(argv, unavailable_providers=...) -> MapperRun` — emulates
  `udk.bin -prv <id> -map <file>`: provider ids 1=RTCore64 (MSI Afterburner), 2=Gdrv
  (Gigabyte), 3=ATSZIO64 (ASUSTeK WinFlash); blocked providers produce the exact conflict
  transcript AM's `StringRegExp` pair parses, success produces a full KDU-style mapping
  transcript. `hint_conflict(transcript)` applies both client regexes and returns the GUI
  hint string the client would display.
- CLI: `python -m vanillatool_emulator.mapper -prv 1 -map udk_2.bin --missing 1`
- Tests: `tests/test_mapper.py` — validates the transcripts against AM's verbatim regex
  constants, the slot layout against the bundled `VanillaDrv_3.13.sys`, and the CLI via
  subprocess. Limitation: the `\\.\ <name>` kernel object AM probes after mapping can only
  exist with a real driver loaded; the emulator covers everything up to that final probe.

### Key IOCs
- Domains/hosts: `subvanillatool.com`, `vanillatool.com`, `31.220.106.18`,
  `2a02:4780:a:759:0:177b:3e9d:3…`, `spark.gameforge.com` (API reads), Google Drive file id
  `1ipfTih7ZmmYru-VCJCZkiprRvw-…`, UA `Vanillatool`.
- Files dropped: `%TEMP%\<rand>\explorer.exe` (VT2), `udk.bin`, `udk_1.dll`, `udk_2.bin`,
  `spk.exe`, `d3dx9_30.dll`, `lr.exe`, `SR.exe`, `BBQ.bin`, `tk.exe`, `FS.exe`, `GV.exe`,
  `NovaApi.exe`, `api.dll`, `japi.dll`, `GetThreads64.exe`.
- Registry: `HKCU\Software\Para's NoAnimation` (all settings), CLSID
  `{5E7D2FEC-DA12-4EF4-8DFC-15AC4BAB2107}`, `HKLM\...\CI\Config!VulnerableDriverBlocklistEnable=0`,
  `HKLM\...\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity!Enabled=0`.
- `hosts` file modifications; driver `\Device\<random-name>` creation; NCGuard → "Game.dll"
  string swaps at `aion.bin+0x863F8` / `CrySystem.dll+0x21A2DB`.
