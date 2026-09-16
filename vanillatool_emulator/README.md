# vanillatool_emulator

Local, deterministic emulation of the services that `Para's Vanillatool -Rework- 11.31.exe`
and `Para's Account Manager - ver. 5.43.exe` talk to, plus an emulation of Account
Manager's local driver-mapping CLI contract.  Everything is **stdlib-only** — no pip
packages required (Python ≥ 3.10).

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
| `mapper.py` | Account Manager's local driver-mapping chain as a CLI: `kdu -prv 1/2/3/-map` provider ladder (RTCore64/Gdrv/ATSZIO64), the 0x1FF0/0x2020 `\Device\<name>` slot patching, and the exact conflict transcripts AM's regexes parse. |

`tests/` (next to the package): `test_protocol.py`, `test_server.py`,
`test_offsets.py`, `test_account_manager.py`, `test_mapper.py` — **26 tests, all green**.

## Run

```bash
# *** Automatic Account Manager lab: GUI + one-click run (recommended) ***
python -m vanillatool_emulator.am_web --port 8090     # browser GUI (any OS)
python -m vanillatool_emulator.am_gui                  # desktop GUI (Windows Tk)
python -m vanillatool_emulator.am_cli --auto --target-exe game.dll   # headless
# Full guide: vanillatool_emulator/AM_AUTO_README.md

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

## Honest limits

- The auth fixture is **capabilities-only** (`ORythm/PRythm`): GUI and server-selection
  flow work; real process-memory features need a build-specific profile via
  `--response-file`.  `--account-manager-startup` supplies zero placeholders for the
  pre-GUI parser check only.
- `mapper.py` reproduces everything up to AM's final `\\.\ <name>` `CreateFileW` probe;
  that kernel object only exists when a real driver is loaded on a Windows machine.
