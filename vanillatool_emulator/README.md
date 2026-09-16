# vanillatool_emulator

Local, deterministic emulation of the services that `Para's Vanillatool -Rework- 11.31.exe`
and `Para's Account Manager - ver. 5.43.exe` talk to, plus an emulation of Account
Manager's local driver-mapping CLI contract — and now the full **local automation**
layer that recovers Account Manager's on-machine functionality (settings hive,
`logins.ini`, driver/DLL staging + patching, mapper ladder, NCGuard `Game.dll`
prep, hosts redirect, one-click chain) behind a desktop GUI, a browser panel,
and a headless CLI.  Everything is **stdlib-only** — no pip packages required
(Python ≥ 3.10).

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
| `local.py` | Account Manager 5.43 **local automation** (headless core, testable): `RegistryStore` (`HKCU\Software\Para's NoAnimation` mirror), `LoginsStore` (`logins.ini` accounts + 39-key `[Delay]` table), `PayloadStager` (13 recovered drivers/DLLs → `udk.bin`/`udk_1.dll`/`udk_2.bin`/`spk.exe`/…), `MapperRunner` (real ladder on Windows, faithful simulation elsewhere), NCGuard `Game.dll` prep (`aion.bin+0x863F8` / `CrySystem.dll+0x21A2DB`), `HostsManager` (`subvanillatool.com` redirect), `ServerSupervisor`, and one-click `AutoFlow`. |
| `gui.py` | **Desktop GUI** (tkinter, Windows-first): 5 tabs — Emulator, Driver & DLLs, NCGuard/Game, Accounts, Hosts & Launch — exposing every original option plus FULL AUTO. `python -m vanillatool_emulator.gui` |
| `panel.py` | **Browser control panel** (stdlib HTTP): the same options + FULL AUTO as a web page for headless/macOS/Linux use. `python -m vanillatool_emulator.panel --port 8090` |
| `am_config.py` / `am_workspace.py` / `am_pipeline.py` | Automatic-lab core (dry-run/read-only by design): 10 server presets, hive/delay mirrors, 12-file recovery, 6-step run (env, workspace, mapper ladder, emulator self-test, target audit, launch plan). |
| `am_web.py` / `am_gui.py` / `am_cli.py` | Automatic-lab front-ends: browser GUI + JSON API, Windows Tk desktop GUI, headless `--auto`/`--serve`. See `AM_AUTO_README.md`. |

`tests/` (next to the package): `test_protocol.py`, `test_server.py`,
`test_offsets.py`, `test_account_manager.py`, `test_mapper.py`,
`test_am_pipeline.py`, `test_am_web.py`, `test_am_workspace.py`,
`test_local.py` — **59 tests, all green** (26 emulator + 18 automatic-lab + 15 local-automation).

## Run

```bash
# *** Automatic Account Manager lab: GUI + one-click run (recommended) ***
python -m vanillatool_emulator.am_web --port 8090     # browser GUI (any OS)
python -m vanillatool_emulator.am_gui                  # desktop GUI (Windows Tk)
python -m vanillatool_emulator.am_cli --auto --target-exe game.dll   # headless
# Full guide: vanillatool_emulator/AM_AUTO_README.md

# Executing automation core: same chain, actually runs each step (Windows runs
# the real udk.bin ladder, stages payloads, starts the emulator, can launch)
python -m vanillatool_emulator.gui                     # desktop GUI, 5 tabs + FULL AUTO
python -m vanillatool_emulator.panel --port 8091       # browser panel (any OS)
python -m vanillatool_emulator.local --workdir am_workdir --game-dir "D:\Aion" --json   # headless
python -m vanillatool_emulator.local --workdir am_workdir --target-exe "Para's Account Manager - ver. 5.43.exe" --launch

# HTTP service emulator (listens on 0.0.0.0:8080)
python -m vanillatool_emulator.server
python -m vanillatool_emulator.server --account-manager-startup   # AM 5.43 pre-GUI markers
python -m vanillatool_emulator.server --tls-cert cert.pem --tls-key key.pem

# Driver-mapping emulation (Account Manager's udk.bin contract)
python -m vanillatool_emulator.mapper -prv 1 -map udk_2.bin --missing 1

# Tests
python -m unittest discover -s tests   # 44 tests: 26 emulator + 18 automatic-lab
```

The automatic lab (`am_config` / `am_workspace` / `am_pipeline` / `am_web` /
`am_gui` / `am_cli`) recovers all 12 local helper files, patches the driver
copy's device slots, mirrors every original checkbox/delay/server preset, and
runs emulator + mapper + target audit + launch plan from one button —
dry-run and read-only by design (see `AM_AUTO_README.md` for honest limits).

Useful server options: `--response-file` (a real decrypted offset profile),
`--offsets-file` (validated Offsets.txt override), `--resource-archive`/`--resource-tool`
(complete the Google-Drive resource flow locally), `--static-key-hex` (key override),
`--log-file` (JSON request log), `--prythm` (2 = named regions enabled, >7 = expired).

Useful `local` options: `--device-name` (11 chars, else reuse/generate),
`--server-preset`, `--game-dir` (enables `game.dll` prep + client verify),
`--apply-hosts` (needs admin), `--target-exe` + `--launch`,
`--force-simulated-mapping` (dry-run the ladder anywhere),
`--use-winreg` (sync the hive to the real Windows registry).

## What FULL AUTO does (in AM's order)

1. Ensures the settings hive (`Para's NoAnimation`, incl. the `fHide_UDK`
   11-char device name) — `Status: Preparing.. (0/3→1/3)`.
2. Ensures `logins.ini` with the full 39-key `[Delay]` timing table.
3. Stages the 13 recovered drivers/DLLs/helpers into the workdir.
4. Patches the `udk_2.bin` `\\Device\\`/`\\DosDevices\\` slots (0x1FF0/0x2020).
5. Runs the `-prv 1/2/3` + bare `-map` ladder (real `udk.bin` on Windows,
   exact-transcript simulation elsewhere) with AM's conflict hints.
6. Preps `bin64\game.dll` + verifies the client (`aion.bin`, `CrySystem.dll`,
   `x_World.pak`) for the NCGuard redirect.
7. Optionally applies the `subvanillatool.com → 127.0.0.1` hosts redirect
   (original-EXE interop; needs admin; TLS cert steps shown in the GUI).
8. Starts the emulator (AM 5.43 pre-GUI markers by default).
9. Optionally launches the original target EXE.

## Honest limits

- The auth fixture is **capabilities-only** (`ORythm/PRythm`): GUI and server-selection
  flow work; real process-memory features need a build-specific profile via
  `--response-file`.  `--account-manager-startup` supplies zero placeholders for the
  pre-GUI parser check only.
- `mapper.py` reproduces everything up to AM's final `\\\\.\\ <name>` `CreateFileW` probe;
  that kernel object only exists when a real driver is loaded on a Windows machine.
  `MapperRunner` runs the **real** `udk.bin` ladder on Windows when the staged
  payloads are present, and the exact-transcript simulation everywhere else.
- The NCGuard name-swap itself (`aion.bin+0x863F8` / `CrySystem.dll+0x21A2DB` →
  `Game.dll`, window-class spoof, thread-context patches) is a live-memory
  operation: the automation stages and verifies everything around it
  (`game.dll` placement, client checks, offsets documentation) but the
  in-memory writes only happen on a Windows machine with the game running.
- Original-EXE interop additionally needs a locally-trusted TLS certificate
  for `subvanillatool.com` (HTTPS is hard-coded); the GUI/panel show the exact
  `openssl` + `certutil` steps.
