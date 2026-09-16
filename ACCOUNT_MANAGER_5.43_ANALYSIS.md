# Para's Account Manager 5.43: emulator, protocol, and game-memory analysis

Analysis target: `Para's Account Manager - ver. 5.43.exe`.

The conclusions below are based on the recovered AutoIt source in `/tmp/account-extracted/script.au3`, the decoded working copy `/tmp/account-decoded-all.au3`, the embedded files extracted from the executable, and the repository's `vanillatool_emulator` implementation.

## Executive conclusion

There are two different compatibility questions:

1. **Service/wire compatibility:** **yes, substantially.** Account Manager uses the same host and `auth.php` route, the same URL-encoded form style, the same AES-256-CBC/CryptoAPI construction, the same fixed IV, the same response `C:<ciphertext>;` envelope, the same dynamic response-key construction, and the same `ORythm`/`PRythm` license markers in its license branch. The existing emulator can receive its requests without source modification because its parser is permissive about `aR` and `aV`.
2. **Operational/game compatibility:** **no, not out of the box.** Account Manager is not an account-only client. Its main Account Manager branch requests a server-supplied game-offset configuration and then opens Aion, locates `Game.dll`, scans and patches its memory, patches `aion.bin`/`CrySystem.dll`, and can install/use an injector and a kernel driver. The emulator's default `ORythm=1;PRythm=1;` response is not enough for that branch; a response fixture containing the expected offset configuration is required.

Therefore, the accurate answer is:

> `vanillatool_emulator` is service-protocol compatible without modifying its source, but it is not a drop-in emulator for Account Manager's game-offset/configuration service and it cannot provide game-memory compatibility by itself.

## 1. Remote endpoints and request forms

### Main service endpoint

The decoded Account Manager code sets the endpoint to:

```text
POST https://subvanillatool.com/data/auth.php
Content-Type: application/x-www-form-urlencoded
```

The primary configuration request, in both initial and retry paths, is:

```text
aN=<encrypted identity>
&aU=2010554045509183616
&aR=3
&aH=<first 8 characters of A26D8F0551A()>
&aC=<encrypted CPU-ID:BIOS-serial>
&aV=20.00
```

The source emits the body without line breaks. The request construction is at `/tmp/account-decoded-all.au3:25397` and `25421`.

The license/entitlement branch uses the same endpoint and same fields, but omits `aR=3`:

```text
aN=<encrypted identity>
&aU=2010554045509183616
&aH=<first 8 characters of A26D8F0551A()>
&aC=<encrypted CPU-ID:BIOS-serial>
&aV=20.00
```

Those requests are at `/tmp/account-decoded-all.au3:28597` and `28662`.

### Other network activity in Account Manager

The executable also contains unrelated or feature-specific network paths, including:

- Nova updater/configuration traffic.
- Debug-help download traffic.
- Public-IP discovery fallbacks.
- HTTP downloads of region-specific `GlideEverywhere` and `NoFlyAnimation` `.pak` files.
- A Google Drive resource download used by a resource-repair/update path.

These are not part of the VanillaTool `auth.php` service protocol. The emulator only covers its own documented service routes, not these feature/update downloads.

## 2. Exact `aU` value

The Account Manager function `A2CB8500E25()`:

1. Opens `@ScriptFullPath` in binary mode.
2. Trims 1,634 bytes.
3. Takes the next eight bytes.
4. Reverses the order of the four two-byte pairs.
5. Parses the result as hexadecimal.

For both checked executables, Account Manager 5.43 and VanillaTool Rework 11.31, the bytes at file offset `0x662` (decimal `1634`) are:

```text
a8 80 84 4c ec 40 1b e6
```

The pair-reversed value is:

```text
hex:     0x1BE6EC40844CA880
decimal: 2010554045509183616
```

Thus, for these two supplied executable samples, `aU` is the same. This resolves the earlier uncertainty about whether the Account Manager build generated a different executable/build value.

## 3. Crypto and response compatibility

### Shared crypto construction

Account Manager and the emulated VanillaTool client use the same recovered construction:

- AES-256-CBC.
- A 32-byte CryptoAPI `PLAINTEXTKEYBLOB` key.
- Same static key as `vanillatool_emulator.DEFAULT_STATIC_KEY`.
- Fixed IV, ASCII bytes:

  ```text
  9324463837711294
  ```

- CryptoAPI final-block padding.
- Hexadecimal ciphertext in the form fields.

The Account Manager's AES wrapper is `A07D8403F2B()`; the IV literal is visible at `/tmp/account-decoded-all.au3:2541`.

### Identity fields

`aN` encrypts the machine/user/AppFlag identity. The identity is built from:

- `@ComputerName`.
- `@UserName`.
- `HKCU\System\System\AppFlag`.
- A derived suffix based on the formatted identity.

If `AppFlag` is absent, the program generates a seven-digit random value and writes it back to that registry location.

`aC` encrypts:

```text
<Win32_Processor.ProcessorId>:<Win32_BIOS.SerialNumber>
```

### Dynamic response key

The response key is constructed as:

```text
first_8_characters_of_aH + first_24_characters_of_identity_component
```

The identity component is padded with `O` characters to 24 characters when needed. Account Manager uses the same `StringLeft(timestamp + identity, 32)` behavior as the emulator.

### Response envelope

Both Account Manager branches first locate:

```text
C:(.*?);
```

and decrypt that captured ciphertext with the dynamic response key.

The license branch then recognizes:

```text
ORythm=([0-9]*)
PRythm=([0-9]*)
expired
```

The later retry path also permits a minus sign in the numeric regex. Positive values set the corresponding license/feature flags.

This is the part that is behaviorally closest to the emulated VanillaTool 11.31 client.

## 4. Important protocol difference: the `aR=3` configuration branch

The Account Manager's primary setup path does not merely ask for `ORythm` and `PRythm`. It sends `aR=3` and expects the decrypted response to contain configuration lines of the form:

```text
UEU=0x...
UNA=0x...
...
MNA=0x...
...
CNA=0x...
...
CSNA=0x...
...
LPNA=0x...
...
TSNA=0x...
...
```

The parser is in `/tmp/account-decoded-all.au3:25436–25800`.

The existing emulator's parser accepts the extra `aR=3` field and does not reject `aV=20.00`. That is enough for transport-level compatibility. However, the emulator's default response is a positive license fixture:

```text
ORythm=1;PRythm=1;
```

That default is not a complete offset configuration. To make Account Manager's setup path proceed, run the existing emulator with a complete response fixture using its `--response` option, or extend the response policy in a separate configuration layer. No source modification is needed merely to receive or encrypt the request, but an offset-bearing plaintext response is required for functional setup.

The service's real acceptance of `aV=20.00` cannot be inferred solely from the permissive emulator; the live server's version policy was not tested.

## 5. Server-supplied configuration schema

The Account Manager parser recognizes 60 hexadecimal configuration keys: six groups for ten regions.

### Regions

```text
EU, NA, CL, CEU, EuroAion, America, Destiny, Gamez, Nova, Elden
```

### Groups and keys

```text
U:
  UEU UNA UCL UCEU UEuroAion UAmerica UDestiny UGamez UNova UElden

M:
  MEU MNA MCL MCEU MEuroAion MAmerica MDestiny MGamez MNova MElden

C:
  CEU CNA CCL CCEU CEuroAion CAmerica CDestiny CGamez CNova CElden

CS:
  CSEU CSNA CSCL CSCEU CSEuroAion CSAmerica CSDestiny CSGamez CSNova CSElden

LP:
  LPEU LPNA LPCL LPCEU LPEuroAion LPAmerica LPDestiny LPGamez LPNova LPElden

TS:
  TSEU TSNA TSCL TSCEU TSEuroAion TSAmerica TSDestiny TSGamez TSNova TSElden
```

Every accepted value is parsed from a line matching `^KEY=(0x.*)$` and converted with `Int()`. The values are not fixed offset constants in the Account Manager executable.

### Roles identified statically

- `U<region>`: read as a DWORD from the selected `Game.dll` module and used as a region-specific validity/guard check. The value must be greater than zero and less than `999999999` in the patch path.
- `M<region>`: used to locate/validate the MAC-related structure and then as the base for the region-specific MAC write delta.
- `C<region>`, `CS<region>`, `LP<region>`, and `TS<region>`: used by other game, launcher, limiter, or feature paths. Their exact meaning is not reducible to a single fixed executable offset; they are also server-supplied.

The patch routine uses the selected region's `U` and `M` values directly. The `M` value is cached in per-login INI files as a module-relative offset after a successful AOB scan.

## 6. Fixed game behavior and offsets

### Process/window requirements

The patch path requires:

- A running Aion process.
- A window with class:

  ```text
  AIONClientWndClass1.0
  ```

- A resolved `Game.dll` module.
- A process handle suitable for `ReadProcessMemory` and `WriteProcessMemory`.

### Fixed redirect writes

`A0E59103108()` waits for both `aion.bin` and `CrySystem.dll`, then writes the string `Game.dll` at:

```text
aion.bin      + 549880 decimal = +0x863F8
CrySystem.dll + 2204379 decimal = +0x21A2DB
```

The source labels these locations as `NCGuardRedirect_v2` and uses `WriteProcessMemory` with the length of `Game.dll`.

### Fixed primary AOB and MAC-write behavior

Let:

- `B` = base address of the target process's `Game.dll`.
- `I` = address of the primary region-specific AOB match.
- `M` = address found from the region's `M<region>` value or the cached/secondary MAC scan.

The core writes are:

| Region | Primary AOB | Replacement at `I` | MAC write address | Additional write |
|---|---|---|---|---|
| `CNA` | `410FB7440A024883C10266` | `420FB7441181` (six bytes) | `M - 80401` (`M - 0x13A11`) | Guard byte `B + 1280` (`B + 0x500`) = `1` |
| `CEU` | `410FB7440A024883C10266` | `420FB7441181` | `M - 14249` (`M - 0x37A9`) | Guard byte `B + 0x500` = `1` |
| `NA` | `410FB74409024883C10266` | `410FB7440981` | `M - 301` (`M - 0x12D`) | `I - 166` (`I - 0xA6`) = `C39090`; guard `B + 0x500` = `1` |
| `EU` | `410FB74409024883C10266` | `410FB7440981` | `M - 301` | Guard byte `B + 0x500` = `1` |
| `EuroAion` | region-specific scan; replacement site as below | `66428B4C1081` | `M - 213` (`M - 0xD5`) | Guard byte `B + 0x500` = `1` |
| `Aion America` | region-specific scan | `66428B4C1081` | `M - 213` | Guard byte `B + 0x500` = `1` |
| `Destiny` | region-specific scan | `66428B4C1081` | `M - 213` | Guard byte `B + 0x500` = `1` |
| `Elden Aion` | region-specific scan | `66428B4C1081` | `M - 213` | Guard byte `B + 0x500` = `1` |
| `GamezAion` | region-specific scan | `66428B4C1081` | `M - 237` (`M - 0xED`) | Guard byte `B + 0x500` = `1` |
| `NOVA` | region-specific scan | `420FB7441181` | `M - 1409` (`M - 0x581`) | Guard byte `B + 0x500` = `1` |

The actual MAC is a generated or configured 17-character wide-string MAC address. The program stores per-account custom MAC values in INI files and generates one if the stored value is invalid.

There is an apparent early `Return` in the `Aion America` validity branch at `/tmp/account-decoded-all.au3:8338–8340`; the later write branch still contains an `Aion America` case. This makes the normal reachability of that region's patch path uncertain without runtime testing.

### Cache behavior

The program stores module-relative `I` and `M` values in `[Cache]` sections of `logins.ini` or `logins_<n>.ini`. It validates the cached bytes/patterns and rescans `Game.dll` when they do not match. The scan range is derived from the target module's size, so the AOB match addresses are build-dependent and cannot be listed as absolute addresses from this executable alone.

### NA-specific duplicate bypass

A separate NA helper also scans:

```text
410FB74409024883C10266
```

and writes:

```text
0xC39090 at I - 166
```

This is the same `I - 0xA6` location used by the main NA branch.

## 7. Does the supplied root `game.dll` match?

The repository's `game.dll` is a valid 64-bit Aion `Game.dll` sample with:

```text
PE32+ / x86-64
image base: 0x10000000
file version: 4515.0319.0112.8880
export: CreateGameInstance
module name: Game.dll
```

That proves it is an Aion GameClient module, but it does **not** prove that it is the exact client build expected by Account Manager 5.43. The Account Manager does not contain a complete fixed table of absolute offsets; it expects the live server to provide the `U/M/C/...` configuration and it uses AOB signatures/cache validation against the running module. A build match therefore requires checking the supplied module's signatures, section layout, and the runtime process/module against the region-specific response fixture.

## 8. Registry, WMI, process, injector, and driver dependencies

### Registry

The service identity is not account-only. It reads and may create:

```text
HKCU\System\System\AppFlag
```

The source also uses Aion installation registry keys, compatibility flags, private-server settings, feature settings, and driver/code-integrity-related keys.

### WMI

The service and helper paths query WMI, including:

```text
Win32_Processor.ProcessorId
Win32_BIOS.SerialNumber
Win32_NetworkAdapterConfiguration where IPEnabled = True
Win32_ComputerSystemProduct
Win32_PhysicalMedia
```

This is a confirmed hardware fingerprint dependency.

### Direct process-memory operations

The AutoIt code itself imports/calls:

- `OpenProcess`.
- `ReadProcessMemory`.
- `WriteProcessMemory`.
- `VirtualAllocEx`.
- `CreateRemoteThread`.
- `LoadLibraryW` / `LoadLibraryA`.
- Thread and process enumeration APIs.

The game patch path therefore does not depend solely on an external helper; Account Manager directly reads and writes the target process.

### Embedded helper and driver behavior

The extracted embedded files confirm additional injector/driver functionality:

- `SparkMod.exe` is a 32-bit executable launched as `spk.exe` with `/PID=...` and mode selectors `/M=1` through `/M=9`; it imports process/memory-related Windows APIs including `LoadLibraryA` and `GetProcessMemoryInfo`.
- `msgbox d3d reloader.dll` is installed as `d3dx9_29.dll`; it imports `ReadProcessMemory`, `CreateThread`, `GetThreadContext`, `SetThreadContext`, and `LoadLibrary`, and contains strings for `AIONClient`, `NCGuard.dll`, and `Game.dll`.
- `VanillaUDK_3.13.bin` is an x64 loader with messages for mapping shellcode, writing kernel memory, locating victim-driver dispatch pages, and loading a vulnerable driver.
- The source installs `VanillaDrv_3.13.sys` as `udk_2.bin`, `VanillaUDK_3.11.dll` as `udk_1.dll`, and the loader as `udk.bin`.
- It patches the embedded driver name at file offsets `8176` (`0x1FF0`) and `8224` (`0x2020`) unless the device is `HIDKeyboard`.
- It invokes the loader with `-prv 1`, `-prv 2`, and `-prv 3`, corresponding to vulnerable-driver provider attempts including `RTCore64`, `Gdrv`, and `ATSZIO64`.
- Before trying this path, the source writes `VulnerableDriverBlocklistEnable=0` and disables Hypervisor-Enforced Code Integrity in the relevant system registry paths.
- `NovaApi.exe` contains the string `AionRequestToken` and is used by the Nova-specific path.

These helpers are not required to parse `auth.php`, but they demonstrate that the full executable is an Aion client launcher/patcher/injector with optional kernel-assisted behavior.

## 9. Compatibility matrix

| Item | Account Manager 5.43 vs emulator | Result |
|---|---|---|
| Host | `subvanillatool.com` | Same |
| Main route | `/data/auth.php` | Same |
| HTTP method | POST | Same |
| Form encoding | URL-encoded | Same |
| `aN`, `aH`, `aC` fields | Same construction family | Same service protocol family |
| `aU` | `2010554045509183616` for both supplied EXEs | Same for these samples |
| AES mode/key/IV | AES-256-CBC, same static key, IV `9324463837711294` | Same |
| Response envelope | `C:<ciphertext>;` | Same |
| Dynamic response key | timestamp + padded identity prefix | Same |
| `ORythm`/`PRythm` | License branch parses them | Same marker family |
| `expired` | Failure handling present | Same |
| `aR` | Account Manager's setup branch adds `aR=3` | Extra request field |
| Version | Account Manager sends `aV=20.00`; emulator defaults to `11.31` | Different literal; emulator currently permissive |
| Configuration response | Account Manager expects 60 offset keys in setup branch | Not supplied by emulator default |
| `/Updateless/Version.txt` | No confirmed Account Manager dependency | Not established as shared |
| Game process | Required for patch/launch features | Outside emulator scope |

## Final determination

- **Existing emulator source modification:** not required for HTTP parsing, request decryption, response encryption, or the shared license branch.
- **Existing emulator as a complete Account Manager replacement:** no. It needs a correctly shaped `aR=3` configuration response fixture with values for the selected Aion client/region, and it cannot emulate the target process, module layout, AOB scans, `WriteProcessMemory`, launcher, injection, or driver behavior.
- **Same VanillaTool 11.31 protocol:** same underlying service family and crypto, but not behaviorally identical. Account Manager is a version-20.00 client with an additional configuration request mode and a substantially larger game-management surface.
- **Offsets:** all fixed offsets and patch deltas listed above are recoverable precisely. The live `U/M/C/CS/LP/TS` DWORDs are server-supplied and are not recoverable from fixed executable constants alone. A captured/decrypted `aR=3` response or an equivalent region configuration fixture is still required to obtain their live values.
