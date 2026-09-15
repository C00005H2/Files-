# Para's Vanillatool -Rework- 11.31 — Deep Behavioral Analysis

**Target:** `Para's Vanillatool -Rework- 11.31.exe` (+ bundled ecosystem: Account Manager 5.43, Auto Update, Rename Processes, Unique-ID 0.8.5, fastscript.pscp, crackme.exe)
**Analyst:** Arena.ai Agent Mode (static + deobfuscation-driven behavioral reconstruction)
**Date:** 2026-09-15 · **Method:** full unpack → decompile → string-table decode → API/behavior inventory (no live detonation; every claim traced to recovered source)
**Artifacts:** deobfuscated inner script (7.7 MB, 91,165 strings), deobfuscated Account Manager (5.2 MB, 62,686 strings), 5 helper scripts, binary triage of 20+ executables — all paths in §19.

---

## 0. Executive summary

Para's Vanillatool -Rework- 11.31 is a **commercial, subscription-style cheat-and-bot platform for the MMORPG Aion** (retail NA/EU/Classic + private servers: EuroAion, Aion America, Destiny, EldenAion, GamezAion, Nova). It is not a single hack — it is a **toolchain**:

| Layer | What it does |
|---|---|
| **Vanillatool core** (AutoIt, 88k lines, obfuscated) | Bot engine + memory-hack framework + 37-window GUI + updater + anti-analysis watchdog |
| **pscp scripting language** (~336 commands) | User-programmable botting: combat rotation, movement, memory R/W, code patching, HTTP, captcha solving, process control |
| **ESP overlay** (`VanillaEsp_v1.3.8.dll`, native C++/D3D9/ImGui) | Injected wallhack/radar overlay, masquerades as `d3dx9_30.dll` |
| **Kernel driver** (`VanillaDrv_3.13.sys` + `udk.bin` mapper) | BYOVD-mapped unsigned driver for stealth memory access (`PRProt` service, `\\.\HIDKeyboard` device) |
| **5 helper processes** (AutoIt) | Thread dumper (GT), frame scanner (FS), OCR screen reader (SR), background key-sender (tk), TTS announcer (GV) |
| **Account Manager 5.43** | Multi-client launcher: credential vault, auto-login, PIN solving, unlimiter, mod installer, driver deployer |
| **Update network** | Author server + Google Drive + GitHub releases (`Lyzing/VT_Files`) + 7za/UnRAR self-extractors |
| **Anti-analysis** | Kills itself on Fiddler/ollydbg/IDA/Wireshark/Charles/mitmproxy; VM/bios checks; hosts-file sinkhole detection; filename randomization |

**Risk verdict:** aggressive game-cheat platform with **rootkit-grade components** (unsigned kernel driver via vulnerable-driver mapping), **credential handling on command lines**, a **remote offset/licensing phone-home**, and **anti-forensics**. To AV vendors: PUA/HackTool + BYOVD loader + stealer-adjacent credential flow. To players: every Aion password you type into Account Manager traverses command lines, config files, and (for captcha/PIN/login helpers) automated UI — on a machine with a kernel driver installed by a game-cheat vendor.

---

## 1. Package contents (repository)

| File | Size | Timestamp (PE) | Identity |
|---|---|---|---|
| `Para's Vanillatool -Rework- 11.31.exe` | 14,708,224 | 2025-10-29 15:59 UTC | UPX-LZMA outer → AutoIt inner (this report's main subject) |
| `Para's Account Manager - ver. 5.43.exe` | 9,375,744 | 2025-10-29 16:03 UTC | Same packer, same build day; multi-client launcher |
| `Auto Update.exe` | 1,452,544 | 2025-05-10 | Readable AutoIt; GitHub-release updater (§11.2) |
| `Rename Processes.exe` | 710,144 | 2024-11-30 | "Para's Process Randomizer"; resets `fHide_*` names (§11.3) |
| `Unique-ID 0.8.5.exe` | 1,028,096 | UPX-NRV (packed) | Lazarus/FreePascal GUI tool; HWID/ID utility (§11.4) |
| `fastscript.pscp` | 22,548 (897 lines) | n/a (text) | Documented sample bot: radar + rebuff + flight manager (§9.6) |
| `6aa4b6d3585e8875bcbebf80/crackme.exe` | 50,688 | 2026-09-11 (future-stamped!) | Packed/virtualized native crackme; references `frida` (§11.5) |

### 1.1 Inner bundle of Vanillatool (17 FileInstall items)

| # | Embedded source path (author's disk: `F:\Documents\…`) | Dropped as | Role |
|---|---|---|---|
| 1–7 | `Release VanillaTool\EXE\Para's Settings\_skills{NA,EU,CNA,CEU,4.6,4.8,NOVA}.ini` | `.\Para's Settings\_skills*.ini` | Skill databases per game version |
| 8 | `Hack rework\ctrl.png` | `%TEMP%\ctrl.png` | Control image (deleted on guarded exit) |
| 9 | `Hack rework\Gather.ini` | `%TEMP%\Gather.ini` | Gather-bot profile |
| 10 | `TurboKeys\tk.exe` | `%TEMP%\{GUID}\tk.bin` (`fHide_TK`) | Background key sender (§10.5) |
| 11 | `trimmedversionfixmouse.dll` | `%TEMP%\{GUID}\m-fix.dll` (`fHide_MF`) | Mouse-fix hook DLL (§10.8) |
| 12 | `Login manager\ScreenReader\SR.exe` | `%TEMP%\SR.exe` | WinRT-OCR screen reader (§10.4) |
| 13 | `GV.exe` | `%TEMP%\GV.bin` | Google-TTS voice announcer (§10.1) |
| 14 | `FS.exe` | `%TEMP%\FS.bin` | FrameSearch v1.00 UI-frame scanner (§10.2) |
| 15 | `Login manager\GetThreads64.exe` | `%TEMP%\{GUID}\GT.exe` (`fHide_GT`) | Thread/module dumper (§10.3) |
| 16 | `ESP\VanillaEsp_v1.3.8.dll` (2025-09-15) | `%TEMP%\d3dx9_30.dll` | ESP overlay, DX-masqueraded (§8.1) |
| 17 | `main v6.75_Release_stripped.au3.tbl` (1.5 MB) | (string table) | 91,165 obfuscated strings (§19.2) |

`{GUID}` = `{5E8D2FEC-DA12-4EF4-8DFC-15AC4BAB2107}` — a constant staging directory under `%TEMP%`.

### 1.2 Inner bundle of Account Manager 5.43 (20 items)

Notable beyond shared helpers (SR, GT): **`lr.exe` = "Para's UnLimiter" v1.2.8.0** (multiclient unlimiter), **`BBQ\BBQ.bin` = "Para's BBQ" v1.2.1.0**, **`SparkMod.exe`** ("32Bit Writer" memory writer), **`msgbox d3d reloader.dll` → `d3dx9_29.dll`**, **NovaApi trio** (`NovaApi.exe` + `api.dll` + `japi.dll`, PDBs leak dev user `ownlink`), **driver kit**: `VanillaDrv_3.13.sys` → `udk_2.bin`, `VanillaUDK_3.11.dll` → `udk_1.dll`, `VanillaUDK_3.13.bin` → `udk.bin`, plus flag/icon JPGs and `main_2.79_Release_stripped.au3.tbl` (62,686 strings).

---

## 2. Execution chain & packing

```
Para's Vanillatool -Rework- 11.31.exe  (AutoIt stub, UPX-LZMA packed, 14.7 MB)
 └─► UPX stub unpacks in memory (verified: RCDATA magic + byte-exact oracles, §19)
      └─► AutoIt interpreter + EA06 bytecode payload (9.3 MB image)
           └─► script.au3 (88,054 lines, 2,825 hash-named funcs, all strings hex-encoded)
                ├─► pulls 91,165 strings from .tbl via A0200001905($OS[N]) decoder
                ├─► drops helpers to %TEMP% / %TEMP%\{GUID}\  (FileInstall ×17)
                ├─► env-gate checks (debugger/VM/hosts) → Exit on trip
                ├─► license/auth POST → offset-table download (encrypted)
                ├─► waits for aion.bin (PID passed as RadarScanPID= on cmdline)
                ├─► loads per-version skill DB + 209 memory offsets
                ├─► injects ESP / maps driver (via AM) / spawns helpers
                └─► runs pscp bot engine + 37-window GUI + 11 background timers
```

**Packing forensics.**
- Outer: UPX with LZMA (method 14) — nonstandard, breaks stock `upx -d`; unpacked with a custom parser (PACKHEAD parse, adler verify, locator search).
- Inner script protection: function/variable names replaced with `A<16 hex>` hashes; **every string literal hex-encoded** behind a `|2{`/`!3{`-delimited table (`main v6.75…` build tag shows the obfuscator's own version).
- Two URLs additionally hidden as `ChrW(num)&…` chains (`auth.php`, `log.php`).
- Personalization: each distributed EXE is **stamped with the buyer's username at file offset 1634** (8 chars, read back at runtime — §4.1). The binary is traceable to its buyer.
- lr.exe / BBQ.bin / Unique-ID use UPX-NRV (method 8) and could not be unpacked with available tooling; triaged via resources + surface strings.

---

## 3. Startup sequence & environment gates

### 3.1 Main-body flow (`script_deobfuscated.au3` L76923–79159)

1. **Registry bootstrap** — reads/creates `HKCU\Software\Para's NoAnimation\fHide_{TK,GT,UDK,MF}` (helper filenames; UDK default = random 11-char string re-rolled per install).
2. **Staging** — creates `%TEMP%\{5E8D2FEC-…}\`, drops 7 skill INIs beside the EXE, helpers to temp.
3. **Compat cleanup** — deletes its own `AppCompatFlags\Layers` shim; writes potion/debuff config defaults.
4. **Guard cluster** (any trip → delete `ctrl.png` → `Exit`):
   - `HKLM\Hardware\…\SystemBiosVersion` ~ `Oracle VM VirtualBox Version` → exit
   - `…\VideoBiosVersion == "VBOX   - 1"` → exit
   - WMI `Win32_DiskDrive.Model` ∈ {`VBOX HARDDISK`, `QEMU HARDDISK`, `VMWARE VIRTUAL IDE HARD DRIVE`, `VIRTUAL HD`} → exit
   - WMI `Win32_ComputerSystemProduct.Name` ~ `(?i)Virt…` → exit
   - Shadow/Blade cloud-PC check (`ShadowSerial.exe` presence, `C:\Program Files\Blade Group\`, Aion's `System.szSystemManufacturerEnglish` ∈ {QEMU, BLADE, n/a})
   - Anti-debug watchdog `A5EA9C00B2A()` (§14.1)
5. **Aion rendezvous** — waits for the game process (PID comes from the `RadarScanPID=` command-line argument supplied by Account Manager), waits for a valid window handle, registers background worker `A1B89D05F3B`.
6. **Version select** — numeric game-version id → skill INI + 10 struct-field constants + 209 offsets (remote, §7.1).
7. **GUI + workers** — creates main GUI, registers `OnAutoItExit` cleanup + 10 `AdlibRegister` timers, enters `While ProcessExists(RadarScanPID)` loop.

### 3.2 Background workers (Adlib timers)

11 periodic callbacks drive the bot while the main thread sits in GUI/message loops: process watchdog, radar/entity refresh, chat-log pump, cooldown tracker, ESP keepalive, update poller, notification staleness (`Notification` = `@MDAY/@MON/@YEAR` registry stamp), and the script-exit janitor. 142 `AdlibRegister` call sites exist across features; 11 are armed at startup.

---

## 4. Identity, licensing & phone-home

### 4.1 Machine + buyer identity (3 parallel IDs)

| ID | Source | Where it goes |
|---|---|---|
| **Buyer username** | 8 bytes at **own-EXE offset 1634**, reversed | `aU=` field of auth POST; tray title |
| **HWID-1** | `ComputerName + UserName + HKCU\System\System\AppFlag` (random-persistent) | `aN=` encrypted blob (mode 1) |
| **HWID-2** | MAC addresses (excludes Virtual/Tunnel/Pseudo/Loopback) | `aN=` encrypted blob (mode 3) |
| Nonce | `msvcrt!time()` | `aH=` short hash |

`HKCU\System\System\AppFlag` is a deliberately oddball key (mimics a system path) holding the persistent random ID.

### 4.2 Offset/auth server — `https://subvanillatool.com/data/auth.php`

(ChrW-obfuscated in source.) WinHTTP POST, form-encoded:

```
aN=<encrypted HWID blob> & aU=<username> & aH=<time-hash> & aR=<…> & aC=<…> & aV=<game-version-id>
```

- Response is regex-scraped for `C:(.*?);`, then decrypted with an HWID-derived key into the **offset table** (`%Key=value|…` lines, §7.1).
- Two client modes (1 and 3) differ in HWID source and key derivation; both hit the same endpoint.
- Effect: **offsets are server-side** — the author can update hacks without shipping a new binary, and every launch **phones home with buyer identity + HWID + game version**. Failure to fetch = no offsets = tool cannot function (server-side kill switch / license gate; `License expired` string present).

### 4.3 Other first-party endpoints

| Endpoint | Use |
|---|---|
| `http://subvanillatool.com/Log/log.php` (ChrW-obfuscated; one branch has buggy `http:://`) | Startup beacon/MOTD fetch |
| `http://subvanillatool.com/Offsets.txt` | Per-client `[NA]/[EU]/[Classic]/[4.6]/[4.8]/[Nova]` offsets consumed by user scripts (`_HTTPGetVar`) |
| `https://subvanillatool.com/data/resourceversion.txt` | Gather-Icons pack version check |
| `http://subvanillatool.com/POST/` | Default callback sink for `_HTTPPost` (rate-limit bypass for this host) |
| `https://subvanillatool.com/data/chat.html` | Kiosk-mode (`iexplore -k`) community chat |
| `https://subvanillatool.com/data/7za.exe`, `/dbghelp.dll`, `/data/PIN/*`, `/data/mods/*` | Helper/mod distribution (§5) |

---

## 5. Network map (complete)

### 5.1 Author infrastructure

- `subvanillatool.com` (+ `31.220.106.18` — watched in hosts file): auth, logging, offsets, mods, PIN kit, chat, 7za, dbghelp.
- Google Drive (single leaked API key `AIzaSyAA9ERw-9LZVEohRYtCWka_TQc6oXmvcVU`):
  - `1jZJnBSuFlFFQzJUHQgybJ1DqhkLJXhFk` → `trsc.zip` (Gather Icons pack, unzipped with 7za)
  - `1ipfTih7ZmmYru-VCJCZkiprRvw-xuIp_` (Account Manager bundle)
- GitHub `Lyzing/VT_Files` release `1.1`: `Para.s.Vanillatool.-.Package.exe` (actually a password-`vt` RAR) — full-package updates via Auto Update (§11.2).

### 5.2 Third-party services

| Service | Use |
|---|---|
| `2captcha.com/in.php` + `/res.php?key=` (raw-socket HTTP POST :80, hand-rolled multipart) | Paid captcha solving from bot scripts (`SolveCaptcha=`) |
| `aioncodex.com/query.php?a=items&type=drop&id=` (+ local `aioncodex_cache\`) | Item-drop database lookups |
| `api.ipify.org`, `checkip.dyndns.org`, `myexternalip.com/raw`, `bot.whatismyipaddress.com` | Public-IP discovery (4 fallbacks) |
| `translate.google.com/?hl=en&tab=wT#auto/en/` (via embedded IE in GV.exe) | Text-to-speech event announcements |
| `i.epvpimg.com/SdZsh.jpg` → `cache.png` | Elitepvpers-CDN image (news/ad/cache) |
| `update.novaverso.online/nova.updater.config.xml` | Nova private-server updater config |
| `msdl.microsoft.com/download/symbols/` | Debug symbols for dbghelp stack walks |

### 5.3 Private-server game endpoints (hardcoded launch presets, AM)

`-ip:64.25.35.103 -port:2106` (EuroAion-class), `-ip:187.45.186.18 -port:2107 -gsip:… -gsport:7779 -chatip:… -chatport:17241` (Destiny-class), `-ip:79.110.83.80` (Gamez-class), plus `-authnToken:` flow for Nova. Launch args also inject `-account:`, `-password:`, `-lang:`, `-noauthgg`, `-ip:127.0.0.1` variants.

### 5.4 Protocols & fingerprints

- WinHTTP (`WinHttp.WinHttpRequest.5.1`) + AutoIt `InetGet/InetRead` + raw TCP (`TCPConnect` ×2: SMTP-dead-code + 2captcha) + `User-Agent: Vanillatool/…` and `Vanillatool Chat`/`Vanillatool_RefreshValues` markers.
- 11 `InetGet` mod downloads, 12-file PIN-kit download, GDrive zip, 7za, cache.png = 27 `InetGet` sites total.

---

## 6. Persistence & host footprint

| Area | Artifact |
|---|---|
| Registry (config) | `HKCU\Software\Para's NoAnimation\*`: `fHide_{TK,GT,UDK,LR,BBQ,VT,MF,MVT,MAM}`, `HPPotionID`, `GreaterHealingPotionID`, `HarmfulDebuffIDs`, `AMInstaScriptDelay`, `Notification` (date) |
| Registry (identity) | `HKCU\System\System\AppFlag` (random HWID part) |
| Registry (driver) | `HKLM\SYSTEM\…\Services\PRProt` (VanillaDrv), `…\Control\CI\Config` + DeviceGuard/HVCI keys probed (unsigned-driver preconditions) |
| Registry (cleanup) | Own `AppCompatFlags\Layers` value deleted at start |
| Files (staging) | `%TEMP%\{5E8D2FEC-DA12-4EF4-8DFC-15AC4BAB2107}\*` (helpers under `fHide_*` names), `%TEMP%\{SR.exe,ctrl.png,Gather.ini,d3dx9_30.dll,d3dx9_29.dll}` |
| Files (program) | `.\Para's Settings\{_skills*.ini,Resource\{7za.exe,Icons\…},version,_TurboKeys.cfg}`, `fastscript.pscp`, `Logs\Vanillatool Error\` |
| Files (game, MODIFIED) | `<GameDir>\Levels\pvt\x.pak` **overwritten** with NoFlyAnimation/GlideEverywhere mod; `Chat.log` ACLs rewritten via `icacls` |
| Firewall | `New-NetFirewallRule -DisplayName 'GFService' … -Action Block` on `…\gfservice.exe` (GameForge service outbound blocked) |
| Processes | No Run-key/service persistence for usermode parts — persistence is **on-demand per launch** (plus driver service while installed). Filename randomization (`Rename Processes.exe`) doubles as anti-signature. |

---

## 7. Game-hack engine

### 7.1 Version matrix & offsets

| Ver id | Client | Skills DB | Struct-field set |
|---|---|---|---|
| 1 / 2 | NA / EU | `_skillsNA/EU.ini` | base+0 |
| 5 / 6 | Classic NA / EU | `_skillsCNA/CEU.ini` | base+1 |
| 10–13 | EuroAion / AionAmerica / Destiny / EldenAion | `_skills4.6.ini` (shared) | 4.6 set |
| 14 | GamezAion (4.8) | `_skills4.8.ini` | 4.8 set |
| 15 | Nova | `_skillsNOVA.ini` | Nova set |

**209 offset keys** fetched encrypted from `auth.php` model the entire game state: player (`PosX/Y/Z`, HP/MP/DP/TP, `Level/Class/Race/Stance/Movement/FlightStatus/Transform/MorphDesign`, `Action0-3/X/Y/Z`, `Auge` gaze, `Attitude`, `AFK`), target mirror (`Target*`, `TargetGravity/New`, `TargetAuge/Anim`), entity system (`EntityMap`, `EntityMap_v2_{Main,Second,Rendered}`, `EntityID`), skills (`Skill_{ID,Type,Level,CD,Name,Available,Active}`, `Skill_Array_Start`, **writable**: `SkillAmountWritable/SkillMovedWritable/SkillTypeWritable/SkillZeroWritable`), buffs (`Buff/DebuffArray/Count`, target arrays), frames/UI (`Frame{X,Y,XF,YF,State,Name,Parent,…}`, dialog/scroll/PIN-tree offsets), camera (`CamPosX/Y/Z`, `CamMax`, `PiercingCam`, `Slopeview`, `ThirdPerson`, `FoV`), physics (`Gravity1-5/New`, `Collision`, `Pos{X,Y,Z}Limit`), economy (`InventoryKinah`, slots/counts, sell/exchange/private-sell arrays), chat (`ChatText1-3`, `ChatOpened1-3`, `ChatLog`), console (`Console/ConsoleSwitch/ConsoleText`), misc (`PetHP`, `Stigma1-12`, `Profession*`, `Quest*`, `MaxFPS`, `UISize`, `SeaLevel`, `WaterType`, `AirPort_ID`).

### 7.2 Memory access primitives

- `OpenProcess` ×23 / `ReadProcessMemory` ×11 / `WriteProcessMemory` / `VirtualProtectEx/QueryEx` / Toolhelp snapshots / `EnumProcessModules` / dbghelp `Sym*` stack walks — full external R/W.
- `SeDebugPrivilege` + full token-privilege set requested, incl. `SeLoadDriverPrivilege`, `SeImpersonatePrivilege`, `SeSecurityPrivilege`.
- Pointer-chain reads/writes exposed to scripts (`_MemPtrReadVar`, `MemPtrWrite=%Addr…`), AoB pattern scan (`_MemPattern`), code patching (`MemWrite=…BYTE[n]`), e.g. fastscript's PlayerScan hook rewrites `4A8B440950C3` → `48B8909E8E0600000000C333C0C3CC` trampoline + restores on `end_OnScriptExit`.
- `GetThreads64` (GT.exe, readable AutoIt/NomadMemory) enumerates target **modules + all thread start addresses + sizes** over a stdout protocol — feeds `#GetThreads`/`#ThreadEXECUTE` script commands.

### 7.3 Game-file mods (CryEngine `.pak` swap)

`InetGet` pulls per-server `NoFlyAnimation/*.pak` (Vanillatool) and `GlideEverywhere/*.pak` (AM) over `<GameDir>\Levels\pvt\x.pak` — stripping fly animations / enabling glide-anywhere. `#CheckPAK`/`#CheckUISize`/`#UltraLowGFX`/`#TabMod` support the mod pipeline.

### 7.4 Speed / physics / camera cheats

`UseSpeed/UseSpeedGlobal`, `#UseGravity/#UseNoGravity`, `#UseCollision/#UseNoCollision`, `Gravity=`/`Collision=`/`TeleportDialog=`/`_TeleportToTarget`/`MoveTo/MoveBy/MoveSmooth/FlySmooth`, `#Stick`, FPS-cap unlock (`MemPtrWrite %AddrFPS`), `TabDistance`/`#TabMod` (tab-target range), camera pierce/FoV/third-person writes.

## 8. Injection, overlay & kernel components

### 8.1 ESP overlay — `VanillaEsp_v1.3.8.dll` → `%TEMP%\d3dx9_30.dll`

- Native PE32+ C++ (MSVC 140, 1.3 MB, built 2025-09-15): imports `d3d9/d3dx9_43`, XInput, `Game.dll`/`NCGuard.dll` references, rapidxml config, `D3DXCreateTextureFromFileExA` texture loading, ImGui-style UI markers (`###…` ids), `AIONClientWndClass1.0` targeting, `OpenThread/GetThreadContext` + own `CreateThread`.
- Loader flow: module-presence check → drop → `A597A40153F(hwnd, pid, dllpath)` → **classic LoadLibrary injection**: `VirtualAllocEx` → `WriteProcessMemory(dllpath)` → `GetProcAddress(kernel32, LoadLibrary)` → `CreateRemoteThread` (×2 code paths: 32/64-bit) → `CloseHandle`/`VirtualFreeEx`.
- `#InjectDLL` script command + GUI file-picker allow injecting an **arbitrary user DLL** the same way; second built-in target is the downloaded `ImageSearchDLL.dll` (PIN solver).
- Sibling `msgbox d3d reloader.dll` → `d3dx9_29.dll` (AM) supports overlay reload.

### 8.2 Kernel driver — VanillaDrv / VanillaUDK (AM-deployed)

| File | On-disk name | Role |
|---|---|---|
| `VanillaDrv_3.13.sys` (13 KB, 2025-05-19) | `udk_2.bin` | Tiny kernel driver ("ByteCheck" build): stealth game-memory access from ring 0 |
| `VanillaUDK_3.13.bin` (526 KB) | `udk.bin` | **Vulnerable-driver mapper** (`-prv 1/2/3 -map udk_2.bin`): kdmapper lineage — "Query victim loaded driver layout", "Driver handler code modified", "Successfully loaded victim driver" |
| `VanillaUDK_3.11.dll` (1.3 MB) | `udk_1.dll` | Usermode companion; talks to `\\.\HIDKeyboard` via `DeviceIoControl` |

- Installed as service **`PRProt`** via registry + `SeLoadDriverPrivilege`/`ZwLoadDriver` path (no `CreateService` API — registry-direct, stealthier).
- Default device name **`HIDKeyboard`** masquerades as a keyboard HID driver; `Rename Processes` re-randomizes it.
- Probes `HKLM\SYSTEM\…\Control\CI\Config` and Hypervisor-Enforced-Code-Integrity state — the driver is **unsigned** and needs testsigning/HVCI-off style preconditions (BYOVD exists precisely to bypass signing).
- This is the single most dangerous component: a game cheat installing a **BYOVD-mapped kernel driver** = full ring-0 compromise primitive on the user's machine.

### 8.3 Input & stealth helpers

- `trimmedversionfixmouse.dll` → `m-fix.dll` (46 KB, native): mouse-input fix/hook for background botting.
- `SetWindowsHookEx`, RawInput, `GetAsyncKeyState/keybd_event/mouse_event/RegisterHotKey`, `BlockInput`, `ClipCursor`, `PrintWindow`/BitBlt screen capture, `SetWindowDisplayAffinity` (anti-capture), layered/DWM windows, desktop/window-station isolation (`Create/Open/SwitchDesktop`), clipboard-viewer chain, `Wow64DisableWow64FsRedirection`, ADS (`FindFirstStreamW`), job objects, `SfcIsFileProtected` probes.
- 310 GDI+ flat-API calls (rendering/screenshots/overlays) via a handle-passing wrapper.

---

## 9. Bot scripting language (`.pscp`)

### 9.1 Engine

A regex-dispatched interpreter (~672 dispatch patterns, **~336 unique commands**) with `%Placeholders%` (`%Var[name]`, `%RNG{a|b}`, `%AionTitle/Width/Height/ProcessAmount`, `%Addr*`, `%Offset*`, `%T`, `%VANILLATOOL%`…), `#IF/#ELSE/#ENDIF`, `#DO/#UNTIL` (×3 loop vars), `start_/end_` subroutines, `#EXECUTE/#ThreadEXECUTE`, timers, INI/log I/O, TTS (`Speech=`), clipboard, and `SessionGetVar/SessionPushVar` **cross-client variable sharing**.

### 9.2 Command families (condensed reference)

- **AutoCombat (~120 `_AC*`)**: `_AutoCombat`, `_ACSkills/_ACBuffs/_ACHeals/_ACItems/_ACPotion`, `_ACUseSkill`, `SmartSkill` (+Performance/Level variants), `_ACCooldownDetection/_ACExperimentalCooldown/_ACCustomCooldown`, `_ACRelyOn{Buff,Debuff,HP,MP,DP,Distance,Level,Race,Target,TargetHP,TargetDebuff,Aggro,Pet,PetHP,Weapon,Enemy,SelfTarget,Item}`, `_ACChainBlacklist`, `_ACAllow{AllMobs,EnemyRace,DPSkills}`, `_ACMob_{IgnoreLowLevel,Blacklist,Whitelist,Looting}`, `_ACHealPercentage/_ACManaPercentage/_ACRegenerate*`, `_ACDetectIfAttacked`, `_ACWeaponSwitching`, `_ACUseAnimation/_ACLongAnimation`, `_ACIncreasedAttackrange`, `_ACMidAir{Range,Timing,Distance}` (air combat), `_ACTimeout*`, `_ACResetPosition`, `_ACCheckMob`, `_ACUse{Bombs,Transformation}`, `_ACForceSpiritAttack`, `_ACIs{Minion,Active,Aimable,Daevanion}`, `_ACSkillIsAvailable`, `_ACReg*`, `_ACInitialRange`, `_ACManaRecover`, `_AutoChain`.
- **Memory**: `MemWrite/MemUnsignedWrite/MemPtrWrite`, `_MemReadVar/_MemPtrReadVar/_IFMemRead/_IFMemPtrRead/_MemPtrPrint/_MemPrint`, `_UNTILMem{,Ptr}Read` (×3), **`_MemPattern` (AoB scan)**.
- **Movement/teleport**: `MoveTo/MoveBy/MoveSmooth/FlySmooth`, `TeleportDialog`, `_TeleportToTarget`, `GoTowardsTarget`, `UseSpeed/UseSpeedGlobal`, `Gravity=`, `#Use{,No}Gravity`, `#Use{,No}Collision`, `#Stick`, `#SetWindow`.
- **Game interaction**: `UseID` (+Old/New/Performance systems), `FrameAction{,ByName}/FrameClick/_IFFrameVisible{,ByName}`, `DialogClick{,Pos,Delay}/DialogScroll`, `LootChest/#LootAll`, `Disenchant`, `SellItems{,AtInventory}/ExchangeItems`, `ReadInventory/_GetInventoryItemHandle/_IFInventoryContains` (+Quest variants), `SelectQuestByID`, `QuestInfo/_IFQuestAt{Step,Status,Counter}`, `Display/DisplayHex`, `GetCooldown/UsePotion`, `_IFSkillActive/_IFStigmaAvailable/_GetSkillArray/_GetProfessionLevel`, `_IF{,Target}{Buff,Debuff}Alive`, `GetEntity`.
- **Input/captcha/PIN**: `SendKey/Mouse/MouseDrag/MouseHoverClick`, `WaitForKey/_IFKey`, `#UsePIN/#EnterPIN=/_EnterPIN=/#SetPINTolerance=`, **`SolveCaptcha=` (2captcha pipeline)**, `ReadScreen=` (OCR pipeline), `#BypassAAInput`, `#EnableCaps/#DisableCaps/#ToggleCaps`.
- **Process/thread**: `#InjectDLL`, `ChangeProcess`, `ProcessPause/ProcessKill/_IFProcessAlive`, `#ThreadEXECUTE/#Thread/#GetThreads/#ThreadTest/#HKD`, `#Crash/#Minimize/#Hide/#UnHide/#ScriptHide`.
- **Net/IO**: `_HTTPPost/_HTTPGetVar`, `IniRead/IniWrite/LogWrite`, `_ClipGet/_ClipPut`, `_RegExp/_IFRegExp`, `StringSplit`, chat-log (`#EnableChatLog/#ClearChatLog/_SearchChatLog/_GetChatLog`), `Ask=` (user prompt), `Command=` (**arbitrary shell**), `Console=`.
- **Account/login**: `#AllowLogout/#UnRegister/#SetAsActive`, `#QuitAtRound`, quest/craft (`#WaitUntilCraftFinished/#Regenerate`), `_CheckDailyReset`, `RequireVersion/#NeedResolution`, `#CheckPAK/#CheckUISize/#UltraLowGFX/#TabMod`, `#UseMiol`, `#Alarm/Beep`, `SetAionTitle/SetScriptTitle/TrayInfo`, `MovementTimeout/Distance`.

### 9.3 `SolveCaptcha` pipeline

Screenshot region capture → `TCPConnect(2captcha.com:80)` → hand-built `POST /in.php` multipart (boundary `Random(10000000..99999999)`, file + `key=` + options) → poll `res.php` → result written back to script var. API key comes from the script line itself (user's own 2captcha balance).

### 9.4 PIN solver (`#EnterPIN` / `_EnterPIN`)

Two paths: (a) **memory-driven** — walks the game's frame tree via pointer reads until `width/height/name == second_password_dialog`, computes shuffled digit-button addresses, enters the PIN without screenshots; (b) **image-driven** — downloads `ImageSearchDLL.dll` + `0–9.bmp` + `submit.bmp`, injects the DLL into Aion and template-matches. `#SetPINTolerance=` tunes matching.

### 9.5 Chat-log & spam

`Chat.log` ACLs forced via `icacls`, log tailed for `_SearchChatLog/_GetChatLog` triggers; a spam template posts `/3 … subvanillat00l,c0m` (leet-obfuscated self-advertising) to in-game LFG chat.

### 9.6 Sample script walkthrough (`fastscript.pscp`, 897 lines)

`FastScript_Cooldown=350` loop implementing **PlayerScan radar + auto-rebuff + flight management**: class-ID dispatch (Assassin…Painter, 0–17), `_ACUseSkill` rebuffs, `_MemPattern`+`MemWrite` **code cave hook** for the scan array (`4A8B440950C3` → `48B8…` trampoline, restored on exit), per-client offsets fetched live from `Offsets.txt` (`[NA]/[EU]/[Classic]/[4.6]/[4.8]/[Nova]`), entity-struct reads (MapID/X/Y/Z/Level/Name), `[[pos:…]]` chat-link output, flight-potion/scroll automation with cooldown timers, FPS-cap unlock, `#TabMod`. It exercises memory, net, UI-frame, inventory, and combat subsystems in one file — the definitive usage specimen.

---

## 10. Helper binaries

| Helper | Type / size / date | Role & protocol |
|---|---|---|
| **GV.bin** (GV.exe) | AutoIt PE32, 671 KB, 2012-stamp | TTS announcer: embedded IE → Google Translate `?tab=wT` speaks `text=`; `_CLOSEPROCESSES` cleanup |
| **FS.bin** (FS.exe) | AutoIt PE32+ (obf. + `FrameSearch v1.00.au3.tbl`), 1.0 MB | **FrameSearch**: UI-frame memory scanner; `/ErrorStdOut p=<pid>…` |
| **GT.exe** (GetThreads64.exe) | AutoIt PE32+ **readable** (NomadMemory), 1.3 MB, 2024-11-26 | `GETMODULELIST` + `GETALLTHREADSSTARTADDRESS` + `GETMODULEBASE_ELEVATE` + `GETMODULESIZE`; `SeDebugPrivilege`; stdout protocol `/ErrorStdOut <PID> <MODULE>` |
| **SR.exe** | AutoIt PE32 **readable** (834 funcs), 1.2 MB, 2024-10-10 | **ScreenReader**: WinRT `Windows.Media.Ocr.OcrEngine.RecognizeAsync` → OCR text on stdout (`Error SR-1/2/3`); feeds `ReadScreen=` |
| **tk.bin** (tk.exe) | AutoIt PE32+ (obf. + `TurboKeys v1.00` .tbl), 1.3 MB, 2024-11-09 | **TurboKeys**: background key sender; `/H=<hwnd> /P=<pid> /F=Para's Settings\_TurboKeys.cfg` |
| **spk.exe** (SparkMod.exe) | AutoIt PE32 (implied), 1.1 MB, 2024-03-02 | "32Bit Writer": 32-bit memory writer for legacy clients |
| **lr → xxxxc.exe** ("Para's UnLimiter" 1.2.8.0) | AutoIt PE32+ UPX-NRV, 897 KB, 2025-09-15 | Multiclient **unlimiter**; per-client launch; `requireAdministrator` |
| **BBQ → xxxxd.bin** ("Para's BBQ" 1.2.1.0) | AutoIt PE32+ UPX-NRV, 1.0 MB, 2025-05-14 | Per-client helper, hex-token args; exact role n/r (packed) |
| **NovaApi** (exe + api.dll + japi.dll) | Native PE32, 11/30/696 KB | Nova private-server token bridge (`LoginService/loginUri/AionRequestToken`); PDBs: `C:\Users\ownlink\…` |
| **msgbox d3d reloader** → `d3dx9_29.dll` | Native PE32+, 51 KB, 2023-05-16 | D3D hook/reloader for overlay support |
| **VanillaEsp_v1.3.8** → `d3dx9_30.dll` | Native PE32+, 1.3 MB, 2025-09-15 | ESP overlay (§8.1) |
| **fixmouse** → `m-fix.dll` | Native PE32+, 46 KB, 2023-11-13 | Mouse-input fix/hook DLL |
| **UDK kit** | sys/dll/bin (§8.2) | Kernel driver + mapper + usermode lib |

GT/SR/GV scripts decompiled cleanly (readable UDF-based source); FS/tk are obfuscated with their own string tables (roles confirmed by name + invocation + strings).

---

## 11. Sibling tools

### 11.1 Account Manager 5.43 (fully deobfuscated: 5.2 MB, 2,466 funcs, 62,686 strings)

The **multi-client operations console**: account vault GUI (`Account Manager`, `AccountName`, `Security Code`, `Virtual Client`, `Custom .bin`, `Inventory Inspector`, `Aion Mods`, `Setup Paths`, `Settings`, `Find`, `Waiting`), per-client `aion.bin` launching with **`-account: -password:` on the command line** (visible to any process-list viewer/audit log), `-authnToken:` Nova flow, PIN auto-entry, unlimiter/BBQ/NovaApi orchestration, `.pak` mod installer (NoFlyAnimation + GlideEverywhere), `dbghelp.dll` fetcher, GDrive bundle #2, driver deployer (§8.2), GameForge-service firewall block, `RadarScanPID=` handoff to Vanillatool. SoW: same IP-check set, Nexus/Steam-style `Anonify_Nova`, release-time scraping of its own update channel.

### 11.2 Auto Update.exe (readable source, single custom func `UPDATE`)

`Vanillatool Updater` popup → scrapes `https://github.com/Lyzing/VT_Files/releases/expanded_assets/1.1` for `Para.s.Vanillatool.-.Package.exe` release time → compares `Para's Settings\version` → downloads the release asset as `temp\VT Package.rar` → extracts with bundled UnRAR masquerading as `temp\update.exe` (`x -av -o+ -pvt -y`, password `vt`) → overlays `Para's Vanillatool - Package\*` onto the install dir → self-replaces via `ping`-delay + `copy`. (Holding Shift forces update.) **Third distribution channel (GitHub) + password-protected RAR + exe-masked extractor.**

### 11.3 Rename Processes.exe ("Para's Process Randomizer")

One-shot GUI: re-rolls **all nine** `fHide_*` names (`TK→xxxxa.bin`, `GT→xxxxb.exe`, `UDK→11 random chars`, `LR→xxxxc.exe`, `BBQ→xxxxd.bin`, `VT→xxxxe.exe`, `MF→xxxxf.dll`, `MVT→xxxxg.exe`, `MAM→xxxxh.exe`), probes driver presence via `\\.\<UDK>` (`CreateFile`), offers restore-to-defaults (UDK→`HIDKeyboard`, "Restart your PC!"). Pure anti-signature/anti-ban utility.

### 11.4 Unique-ID 0.8.5 (UPX-NRV packed, Lazarus/FreePascal GUI)

Unreadable without an NRV unpacker (no root/toolchain in this environment); `LAZ_*` dialog resources + `UniqueID` marker + versioned release naming indicate a **HWID/unique-ID utility** (ban-evasion ID changer or ID generator). No AutoIt payload (no EA05 chunk).

### 11.5 crackme.exe (`6aa4b6d3585e8875bcbebf80/`)

50 KB native PE32+, **future timestamp 2026-09-11**, no readable imports (packed/virtualized: `voltmd`-style sections), only distinctive string **`frida`** (anti-instrumentation reference) amid code noise. Purpose n/r — likely an author-side license/reversing challenge; quarantined from the main toolset.

---

## 12. GUI surface (Vanillatool core)

37 top-level windows incl. **Gather Wizard, Combat Wizard, Radar (+EntityArea/FilterArea), Target Overlay, Frame Assistant, Cooldown Tracker (+Classes/Skills), Vanillatool Chat, 5cript Editor, DebugLog (+Add/Find), Assign Turbokeys, Alternative Menu, Hotkeys, Leave Feedback, How to, More Options, Waiting for Response, Answer, Aion not found** — plus hidden/untitled workers and a **random-titled main window** (anti-detection). 75 buttons / 154 labels / 31 inputs inventoried. Tray: `Para's VanillaTool [Rework] - …`.

---

## 13. Native API inventory (DllCall census, core script)

1,878 `DllCall`s resolved to **1,031 distinct dll+function pairs (1,433 calls) across 32 DLLs**, plus **310 GDI+ flat-API calls** (93% coverage; remainder = generic-wrapper + parse artifacts).

| DLL | Highlights (counts) |
|---|---|
| kernel32 (+Kernel32 handle) | `OpenProcess`×23, `ReadProcessMemory`×11, `WriteProcessMemory`, `Virtual{Protect,Query}Ex`, **`CreateRemoteThread`×2**, `OpenThread`×7, `TerminateThread`×3, `VirtualFreeEx`×3, Toolhelp, `SetLocalTime/TimeZone`, `BackupRead/Write`, `Wow64DisableWow64FsRedirection`, `FindFirstStreamW` (ADS), job objects, `CreateMutexW/OpenMutexW`, `DeviceIoControl`×15 |
| user32 | `SetWindowsHookEx`, `GetAsyncKeyState`, `keybd_event/mouse_event`, `RegisterHotKey`, RawInput, `ClipCursor`, `PrintWindow`, `SetWindowDisplayAffinity`, `Create/Open/SwitchDesktop`, window stations, clipboard listener, `BlockInput`, caret APIs |
| advapi32 | `OpenProcessToken`, `AdjustTokenPrivileges`, `DuplicateTokenEx`, `CreateProcessWithTokenW`, `ImpersonateSelf`, `CredUIPromptForCredentialsW` |
| credui/crypt32 | `Cred{Pack,UnPack}AuthenticationBuffer`, `CredUI*W`, EFS `Encrypt/DecryptFileW` |
| dbghelp | `SymInitialize/Cleanup/FromAddr/Enumerate…`, `MiniDumpWriteDump`-adjacent stack walking |
| wininet/ws2_32/sensapi | `inet_addr`, `SendARP`, `IsNetworkAlive`, ICMP present at import level |
| gdiplus (via generic handle) | 300 distinct `Gdip*` flat APIs — rendering/screenshot/overlay pipeline |
| uxtheme/msvcrt/shlwapi/psapi | `BufferedPaintInit`, `time()`, `PathFindNextComponentW`, `EnumProcessModules` |
| comdlg32/shell32/sfc | File dialogs, `ShellExecuteW`, `SfcIsFileProtected` |

AutoIt builtins of note: `InetGet`×27, `Run`×22 (+`RunWait`, `ShellExecute`×4 — incl. `cmd /c ipconfig /all`, `icacls Chat.log`, `powershell …MessageBox`, `mailto:` composer, `iexplore -k chat.html`), `Reg{Read84/Write104/Delete2}`, `ProcessClose`×22, `ProcessExists`×61, `FileDelete`×62, `ClipGet`×44/`ClipPut`×18, `Send`×19, `MouseMove`×21, `HotKeySet`×2, `AdlibRegister`×142, `TimerInit`×516. (The SMTP mail UDF ships but has **zero callers — dead code**, explicitly not exfiltration.)

## 14. Anti-analysis catalog

| # | Mechanism | Detail |
|---|---|---|
| 1 | Debugger/proxy process kill-switch | Exit if `Fiddler.exe`, `ollydbg.exe`, `IDApro.exe`, `wireshark.exe`, `Charles.exe`, `mitmproxy.exe` exist |
| 2 | Hosts-sinkhole detection | Exit if `%SystemRoot%\System32\drivers\etc\hosts` mentions `subvanillatool` or `31.220.106.18` |
| 3 | VM BIOS checks | `SystemBiosVersion`~VirtualBox, `VideoBiosVersion`==`VBOX   - 1` |
| 4 | VM hardware checks | WMI disk `.Model` ∈ VBOX/QEMU/VMWARE/VIRTUAL HD; `Win32_ComputerSystemProduct.Name` ~ `(?i)Virt…` |
| 5 | Cloud-PC check | ShadowSerial/Blade paths + Aion SystemInfo manufacturer ∈ {QEMU,BLADE,n/a} |
| 6 | String encryption | 91,165 hex-encoded strings + ChrW-URL chains + hash-named symbols |
| 7 | Filename masquerade | ESP→`d3dx9_30.dll`, reloader→`d3dx9_29.dll`, GV/FS→`.bin`, driver→`HIDKeyboard`, threadtest/GT dual names, 9× `fHide_*` randomization |
| 8 | Window hiding | Random-titled main GUI, hidden workers, `d3dx9` module blending, tray-only modes |
| 9 | Packing | UPX-LZMA (nonstandard) + UPX-NRV siblings + virtualized crackme |
| 10 | Server-side logic | Offsets + licensing server-side; analysis without the server yields a neutered binary |
| 11 | Personalized binaries | Username stamped at EXE offset 1634 — leaks + traitor-tracing per copy |

## 15. Data handled (sensitivity)

- **Aion credentials**: typed into AM GUI → stored in config → passed to `aion.bin` via **`-account: -password:` command line** (exposed to process enumeration, audit logs, crash dumps). PINs handled by solver; email→password tab automation (`TabFromEmailToPassword`, `BeforePastePassword`).
- **HWID/fingerprint**: computer+user names, MACs, random persistent ID, BIOS/disk data exfiltrated to `auth.php` on every launch.
- **Game chat**: `Chat.log` force-ACL'd + tailed; chat content drives script triggers; spam posted to public channels.
- **Clipboard**: 44 reads / 18 writes (script-accessible — any pasted password transits here).
- **Screenshots/OCR**: region captures → local OCR (SR) and/or **uploaded to 2captcha** (third-party human solvers see the pixels).
- **Keystrokes/mouse**: global hooks + background senders (tk) — full input visibility while running.
- **Kernel access**: unsigned driver mapping = any usermode privacy boundary is void while installed.

## 16. Risk assessment

**For cheat users:** kernel-driver install by an untrusted vendor; credentials on command lines and in plaintext-adjacent configs; HWID + identity beaconed to author server; private-server IPs hardcoded (traffic to gray infrastructure); ban risk (NCSoft/GameGuard) plus ban-evasion tooling that deepens ToS exposure.
**For enterprises:** BYOVD-capable dropper chain, firewall-rule tampering, hosts-file awareness, VM/sandbox evasion, GitHub + Drive + custom-C2 update paths, password-protected RAR sideloading, personalized-traceable binaries. Treat any host with `Para's NoAnimation` registry keys or the `{5E8D2FEC-…}` temp dir as compromised-by-policy-violation at minimum.
**For AV/content vendors:** detect as `HackTool/AutoIt`, `PUA:Win32/VanillaTool`, plus BYOVD mapping behavior (`udk.bin -map`), PRProt service, `VanillaDrv_3.13.sys` hash, and the §17 network IOCs. The personalized username stamp (file offset 1634, 8 bytes) is a per-sample pivot.
**For NCSoft/private servers:** full cheat suite (radar/ESP/teleport/speed/noanim/glide/fly-hack economy automation incl. kinah-address writes `%AddrKinah*`), multiclient unlimiter, credential-stuffing-capable mass launcher, in-game spam module.

## 17. Indicators of compromise (consolidated)

**Network (URLs):** `https://subvanillatool.com/data/auth.php`, `http://subvanillatool.com/Log/log.php`, `http://subvanillatool.com/Offsets.txt`, `https://subvanillatool.com/data/resourceversion.txt`, `https://subvanillatool.com/data/7za.exe`, `https://subvanillatool.com/data/dbghelp.dll`, `http://subvanillatool.com/data/mods/{NoFlyAnimation,GlideEverywhere}/*.pak`, `http://subvanillatool.com/data/PIN/{ImageSearchDLL.dll,0-9.bmp,submit.bmp}`, `http://subvanillatool.com/POST/`, `https://subvanillatool.com/data/chat.html`, `https://www.googleapis.com/drive/v3/files/1jZJnBSuFlFFQzJUHQgybJ1DqhkLJXhFk?…`, `…/drive/v3/files/1ipfTih7ZmmYru-VCJCZkiprRvw-xuIp_?…&key=AIzaSyAA9ERw-9LZVEohRYtCWka_TQc6oXmvcVU`, `https://github.com/Lyzing/VT_Files/releases/download/1.1/Para.s.Vanillatool.-.Package.exe`, `http://aioncodex.com/query.php?a=items&type=drop&id=`, `http://2captcha.com/in.php`, `…/res.php?key=`, `http://update.novaverso.online/nova.updater.config.xml`, `http://i.epvpimg.com/SdZsh.jpg`, `https://translate.google.com/?hl=en&tab=wT#auto/en/`, `https://api.ipify.org`, `http://checkip.dyndns.org`, `http://www.myexternalip.com/raw`, `http://bot.whatismyipaddress.com`, `https://msdl.microsoft.com/download/symbols/`.
**Network (IPs/ports):** `31.220.106.18` (hosts-watch), `64.25.35.103:2106`, `187.45.186.18:2107/7779/17241`, `79.110.83.80`, `2captcha.com:80` (raw HTTP), `-ip:127.0.0.1`.
**Registry:** `HKCU\Software\Para's NoAnimation` (+`fHide_*`, potion/debuff IDs, `AMInstaScriptDelay`, `Notification`), `HKCU\System\System\AppFlag`, `HKLM\SYSTEM\…\Services\PRProt`, AppCompat `Layers` self-delete.
**Files:** `%TEMP%\{5E8D2FEC-DA12-4EF4-8DFC-15AC4BAB2107}\*`, `%TEMP%\{SR.exe,ctrl.png,Gather.ini,d3dx9_30.dll,d3dx9_29.dll}`, `Para's Settings\{_skills*.ini,Resource\{7za.exe,Icons\…},version,_TurboKeys.cfg}`, `temp\VT Package.rar`, `temp\update.exe` (UnRAR), `<Game>\Levels\pvt\x.pak` (replaced), `Logs\Vanillatool Error\`.
**Processes/modules:** `GT.exe`/`threadtest.exe`, `GV.bin`, `FS.bin`, `tk.bin`, `SR.exe`, `spk.exe`, `NovaApi.exe`, `xxxx{c.exe,d.bin,e.exe,g.exe,h.exe}` (randomized lr/BBQ/VT/MVT/MAM), `iexplore.exe -k …/chat.html`, `7za.exe`, `VanillaEsp_v1.3.8.dll` as `d3dx9_30.dll` inside `aion.bin`.
**Driver:** `VanillaDrv_3.13.sys` / `udk_2.bin`, `udk.bin -prv {1,2,3} -map udk_2.bin`, `udk_1.dll`, device `\\.\HIDKeyboard` (or randomized `fHide_UDK`), service `PRProt`.
**Windows/classes:** `AIONClientWndClass1.0`, titles `Vanillatool Chat|Radar|Para's VanillaTool [Rework] - *|Account Manager|Aion Mods|Vanillatool Updater|Para's Process Randomizer`, `User-Agent: Vanillatool/`, spam `subvanillat00l,c0m`.
**Hashes (reference):** inner payload image sha256 `5d1a3f47…f0541` (8,557,568 B); unpacked image 9,345,005 B — see §19 paths for recomputation.

## 18. Detection & hunting ideas

- **YARA-able strings:** `VanillaEsp_v`, `\\.\HIDKeyboard`, `Services\PRProt`, `-prv 1 -map udk_2.bin`, `subvanillatool.com/data/auth.php`, `Para.s.Vanillatool.-.Package.exe`, `fHide_UDK`, `AIONClientWndClass1.0`, `second_password_dialog`, `Vanillatool_RefreshValues=`, `SolveCaptcha=`, `_MemPattern=`, `Para's UnLimiter`, `Para's BBQ`.
- **Behavioral:** `aion.bin` + `CreateRemoteThread` from an AutoIt-compiled parent; `d3dx9_30.dll` loaded from `%TEMP%`; `New-NetFirewallRule … -Action Block` on `gfservice.exe`; `icacls Chat.log`; `iexplore -k` to game-cheat domain; WinHTTP POST with `aN=/aV=` fields; hosts-file reads comparing against cheat domains; `SeLoadDriverPrivilege` + `Services\PRProt` writes; `ping 127.0.0.1 -n 3` self-update delay pattern.
- **Hunt:** `RadarScanPID=` command lines; `{5E8D2FEC-DA12-4EF4-8DFC-15AC4BAB2107}` temp dir; `HKCU\System\System\AppFlag`; EXE-offset-1634 username stamp clustering per-buyer samples.

## 19. Methodology & artifact inventory

No live detonation was performed (kernel-driver + anti-VM makes sandboxing hostile and low-yield); instead the **entire behavior was reconstructed from recovered source**:

1. Outer UPX-LZMA unpacked (`tools/upx_unpack.py`: PACKHEAD + raw-LZMA bisection + RCDATA carve) → 15.19 MB image → outer script → `payload.exe` reassembled (`tools/assemble_outer.py`, sha256-gated) → 9.35 MB inner image.
2. EA06 resources decompiled (`tools/ea06.py`, vendored `autoit_ripper`) → 88,054-line script + 18 files.
3. String tables hex-decoded (`tools/deobfuscate.py`, `!3{` + `|2{` dialects) → 91,165 (core) + 62,686 (AM) table entries; full substitution + ChrW-URL folding → readable source.
4. Inventories: DllCall resolver (per-func + global-var + handle-chain), builtin census with argument resolution, dispatch-pattern extraction (pscp), registry/file/net sweeps, context-walked startup/injection/updater/auth flows.
5. Helpers/siblings decompiled or triaged (`tools/ea06.py`, `tools/triage.py`: PE headers, version resources, surface strings).

Full offline reproduction: `python3 tools/run_all.py` (see `docs/OFFLINE_RUNBOOK.md`; self-verifying, 39 byte-exact oracles). Artifacts regenerate under `_work/`:

| Artifact | Path |
|---|---|
| Deobfuscated core script (7.7 MB) | `_work/core_deobf.au3` |
| Core strings (91,165 entries) | `_work/core_strings.txt` |
| Deobfuscated AM script (5.2 MB) | `_work/am_deobf.au3` |
| AM strings (62,686 entries) | `_work/am_strings.txt` |
| Helper scripts | `_work/{gv,fs,gt,sr,tk}_out/script.au3` (+`_work/spk_out/`) |
| Updater/Randomizer scripts | `_work/{au,rn}_out/script.au3` |
| Unpacked images | `_work/{outer,payload,am}.img` |
| Bundled binaries | `_work/{payload,am}_out/` (see `MANIFEST.txt` in each) |

## Appendix A — pscp command index (unique, alphabetical)

`#2DO/#2UNTIL/#3DO/#3UNTIL`, `#ACReset`, `_ACAllowAllMobs/_ACAllowDPSkills/_ACAllowEnemyRace`, `_ACBuffs/_ACChainBlacklist/_ACCheckMob/_ACCooldownDetection/_ACCustomCooldown`, `_ACDetectIfAttacked`, `_ACEnableAutoAttack/_ACExperimentalCooldown/_ACForceSpiritAttack`, `_ACHealPercentage/_ACHeals`, `_ACIncreasedAttackrange/_ACInitialRange/_ACIsActive/_ACIsAimable/_ACIsDaevanion/_ACIsMinion`, `_ACItems`, `_ACLongAnimation`, `_ACManaPercentage/_ACManaRecover/_ACMidAirDistance/_ACMidAirRange/_ACMidAirTiming`, `_ACMob_Blacklist/_ACMob_IgnoreLowLevel/_ACMob_Looting/_ACMob_Whitelist`, `_ACReg/_ACRegenerate{,Enabled}/_ACRegHPPercentage/_ACRegMPPercentage`, `_ACRelyOn{Aggro,Buff,DebuffAmount,Distance,DP,Enemy,Item,Level,Pet,PetHP,PlayerHP,PlayerMP,Race,SelfTarget,TargetDebuff,TargetHP,Weapon}`, `_ACSkillIsAvailable/_ACSkills`, `_ACTimeout{,NoDamage}`, `_ACUseAnimation/_ACUseBombs/_ACUseSkill/_ACUseTransformation/_ACWeaponSwitching`, `_AutoChain/_AutoCombat`, `Ask=`, `Beep=`, `#BypassAAInput`, `_CheckDailyReset/#CheckPAK/#CheckUISize`, `CheckScroll{,Buff}=`, `ChangeProcess=`, `Command=`, `Console=`, `CreateTimer=/DeleteTimer=`, `Delay{,Global}=`, `DialogClick{,Delay,Pos}=/DialogScroll=`, `Disenchant=`, `Display{,Hex}=`, `#DO/#ELSE/#ENDIF/#IF`, `end_/start_`, `end_OnScriptExit`, `#EndScript`, `_EnterPIN=/#EnterPIN=`, `ExchangeItems=`, `#EXECUTE/#ThreadEXECUTE`, `ExternalScriptLoad=`, `FlySmooth=`, `FrameAction{,ByName}=/FrameClick=`, `GetCooldown=`, `GetEntity=`, `_GetChatLog=/_SearchChatLog=`, `_GetInventoryItemHandle=/_GetQuestInventoryItemHandle=`, `_GetProfessionLevel=/_GetSkillArray=`, `GoTowardsTarget=`, `Gravity=`, `#Hide/#UnHide`, `_HTTPGetVar=/_HTTPPost=`, `_IFBuffAlive/_IFDebuffAlive/_IFTargetBuffAlive/_IFTargetDebuffAlive`, `_IFFrameVisible{,ByName}=`, `_IFInventoryContains=/_IFQuestInventoryContains=`, `_IFKey=`, `_IFMemRead/_IFMemPtrRead/_IFProcessAlive=`, `_IFQuestAt{Counter,Status,Step}=`, `_IFRegExp=/_RegExp=`, `_IFSkillActive=/_IFStigmaAvailable=`, `IniRead=/IniWrite=`, `#InjectDLL`, `Loo
...[truncated 1520 chars]

