# vanillatool_emulator

Local, deterministic emulation of the services that `Para's Vanillatool -Rework- 11.31.exe`
and `Para's Account Manager - ver. 5.43.exe` talk to, plus the backend that makes the
**unmodified original Account Manager EXE functional with its own GUI**: TLS license
emulator, hosts redirect, certificate handling, real Windows driver loading
(`driver.py`), and original-EXE launch/monitor (`interop.py`).  Everything is
**stdlib-only** — no pip packages required (Python ≥ 3.10).

## Run the ORIGINAL exe (Windows, elevated prompt)

```bash
# 1. One-time setup: cert + trust + hosts (plan unless --apply)
python -m vanillatool_emulator.interop setup --target-exe "Para's Account Manager - ver. 5.43.exe" --gen-cert --apply

# 2. One-time OS prep for the driver chain (blocklist/HVCI off), then REBOOT
python -m vanillatool_emulator.driver prepare --apply

# 3. Every session: start TLS emulator + launch the ORIGINAL exe (its GUI is the interface)
python -m vanillatool_emulator.interop launch --target-exe "Para's Account Manager - ver. 5.43.exe"

# Prove it will work (TLS handshake + real encrypted auth round-trip + driver probe)
python -m vanillatool_emulator.interop check --device-name <fHide_UDK name>

# Prove YOUR game client matches AM's hardcoded patch slots (read-only, needs the client installed)
python -m vanillatool_emulator.clientcheck --game-dir "D:\EuroAion"
# Definitive verdict for packed clients: read the RUNNING client's memory like AM does
# (run ELEVATED — GameGuard blocks non-elevated readers; --rva-aion/--rva-cry probe relocated candidates)
python -m vanillatool_emulator.clientcheck --live --process aion.bin
python -m vanillatool_emulator.interop stop     # stop the background emulator
python -m vanillatool_emulator.driver audit    # read-only driver pre-flight (never changes anything)
```

The original EXE drops and maps its own `udk.bin`/`udk_2.bin` chain — no extra
files needed: `udk.bin` (KDU 1.4.3 lineage) carries its own encrypted provider
payload (RCDATA 2001, ~50 KB, entropy 7.996) and needs only an elevated,
prepared OS.  Pre-loading / verifying outside the EXE is also possible:

```bash
python -m vanillatool_emulator.driver load --workdir am_workdir     # real ladder on Windows
python -m vanillatool_emulator.driver verify --device-name AbCdEfGhIjK
```

## All files (the complete runnable set)

| File | Role |
|---|---|
| `__init__.py` | Package exports (protocol + account_manager + offsets helpers). |
| `__main__.py` | `python -m vanillatool_emulator` → runs the HTTP server. |
| `crypto.py` | Dependency-free AES-256-CBC codec (PKCS#7), matches the client's CryptoAPI usage. |
| `protocol.py` | Recovered auth wire protocol: static key `Hk0xO0O00FF10OO0Hk0xO0O00FF10OO0`, IV `9324463837711294`, `aN/aU/aH/aC/aV` fields, dynamic `C:<hex>;` response keyed `StringLeft(ts8+id24,32)`. |
| `account_manager.py` | Account Manager 5.43 pre-GUI fixture: the 60 markers (`UEU…TSElden`) its second auth request must contain (zero placeholders only). |
| `offsets.py` | `/Offsets.txt` body builder/validator — the injected scripts spin on `#UNTIL=%Var[Offset_Base_SubText],>0`, so a body must have a `[section]` + non-zero `Base_SubText`. |
| `server.py` | The HTTP service emulator: auth, version, resource-version, log, Offsets.txt, resource ZIP (embedded Google Drive path), 7za, health. TLS optional. |
| `mapper.py` | Account Manager's local driver-mapping chain as a CLI: `kdu -prv 1/2/3/-map` provider ladder (RTCore64/Gdrv/ATSZIO64), the 0x1FF0/0x2020 `\\Device\\<name>` slot patching, and the exact conflict transcripts AM's regexes parse. |
| `local.py` | Headless automation library: `RegistryStore` (`HKCU\Software\Para's NoAnimation` mirror), `LoginsStore` (`logins.ini` accounts + 39-key `[Delay]` table), `PayloadStager` (13 recovered drivers/DLLs), `MapperRunner` (real ladder on Windows, faithful simulation elsewhere), NCGuard `Game.dll` prep (`aion.bin+0x863F8` / `CrySystem.dll+0x21A2DB`), `HostsManager`, `ServerSupervisor`, one-click `AutoFlow` (`python -m vanillatool_emulator.local`). |
| `driver.py` | **Real OS driver loading**: read-only `audit` (admin/build/SecureBoot/HVCI/blocklist/conflicts/payloads), `prepare --apply` (AM's own registry tweaks + backup/restore + reboot notice), `load` (real `udk.bin` ladder on Windows), `verify` (`\\.\<name>` + `QueryDosDevices` + slot check), `cleanup`. |
| `interop.py` | **Original-EXE interop** (no custom GUI): `setup` (cert `--gen-cert` via openssl, `certutil` trust, hosts), `launch` (TLS emulator on 443 in background + start + monitor the original EXE + teardown), `stop`/`status`, `check` (TCP → TLS → `/healthz` → real encrypted auth round-trip → driver probe). |
| `clientcheck.py` | **Game-client compatibility** (read-only): static mode parses the installed client's PE sections, reads the two `CHAR[128]` NCGuard slots AM 5.43 overwrites (`aion.bin+0x863F8`, `CrySystem.dll+0x21A2DB`), verdicts match/uncertain/mismatch (packed binaries report *inconclusive*, never false-fail); `--live` reads the running client's memory via `ReadProcessMemory` — the definitive verdict. Reports the per-server bypass dll (`EuroAion → Game.dll`). |
| `am_config.py` / `am_workspace.py` / `am_pipeline.py` | Automatic-lab core (dry-run/read-only by design): 10 server presets, hive/delay mirrors, 12-file recovery, 6-step run (env, workspace, mapper ladder, emulator self-test, target audit, launch plan). |
| `am_web.py` / `am_gui.py` / `am_cli.py` | Automatic-lab front-ends: browser GUI + JSON API, Windows Tk desktop GUI, headless `--auto`/`--serve`. See `AM_AUTO_README.md`. |

`tests/` (next to the package): `test_protocol.py`, `test_server.py`,
`test_offsets.py`, `test_account_manager.py`, `test_mapper.py`,
`test_am_pipeline.py`, `test_am_web.py`, `test_am_workspace.py`,
`test_local.py`, `test_driver.py`, `test_interop.py` — run
`python -m unittest discover -s tests` (expect all green).

## More runbook

```bash
# HTTP service emulator directly (listens on 0.0.0.0:8080)
python -m vanillatool_emulator.server --account-manager-startup   # AM 5.43 pre-GUI markers
python -m vanillatool_emulator.server --tls-cert cert.pem --tls-key key.pem --port 443

# Headless local chain without the EXE (stage/patch/map/gamedll/emulator)
python -m vanillatool_emulator.local --workdir am_workdir --game-dir "D:\Aion" --json

# Driver-mapping contract emulation only
python -m vanillatool_emulator.mapper -prv 1 -map udk_2.bin --missing 1

# Tests
python -m unittest discover -s tests
```

Useful server options: `--response-file` (a real decrypted offset profile),
`--offsets-file` (validated Offsets.txt override), `--resource-archive`/`--resource-tool`
(complete the Google-Drive resource flow locally), `--static-key-hex` (key override),
`--log-file` (JSON request log), `--prythm` (2 = named regions enabled, >7 = expired).

## Honest limits

- The auth fixture is **capabilities-only** (`ORythm/PRythm`): the original GUI and
  server-selection flow work; real process-memory features need a build-specific
  profile via `--response-file` (passable through `interop launch` → emulator).
- The driver loads only on **Windows x64, elevated**, with the blocklist/HVCI
  preparation + reboot (`driver prepare --apply`), and no conflicting vendor
  driver holding the provider (`driver audit` reports all of this read-only).
  The mapper carries its own provider payload — no extra downloads needed.
- A manually-mapped driver has no SCM entry: only a **reboot** fully unloads
  it (`driver cleanup` removes staged files and can restore the registry backup).
- The NCGuard name-swap itself (`aion.bin+0x863F8` / `CrySystem.dll+0x21A2DB` →
  `Game.dll`, window-class spoof, thread-context patches) is a live-memory
  operation performed by the original EXE once its license + driver steps pass.
- Original-EXE interop needs a locally-trusted TLS certificate for
  `subvanillatool.com` (HTTPS is hard-coded): `interop setup --gen-cert`
  needs `openssl` (Git for Windows bundles it); trust needs admin `certutil`.
