# Account Manager — Automatic Lab (GUI + one-click run)

This is the **automatic replacement** for `Para's Account Manager - ver. 5.43.exe`:
every original option, every local file, and the emulator — driven end-to-end
from a GUI with a single **Automatic Run** button.

Two front-ends, one backend:

| Front-end | Command | Where it shines |
|---|---|---|
| Browser GUI (portable) | `python -m vanillatool_emulator.am_web --port 8090` | any OS, no Tk needed, works in this sandbox preview |
| Desktop GUI (Windows-familiar) | `python -m vanillatool_emulator.am_gui` | Windows look, same `Status: ...` line as the original |
| Headless CLI | `python -m vanillatool_emulator.am_cli --auto --target-exe game.dll` | scripts, CI, machines without a display |

Backend modules (all stdlib-only):

| Module | Role |
|---|---|
| `am_config.py` | every original option: 10 server presets, 27 hive keys, 36 delays, 12 local files |
| `am_workspace.py` | recovers `analysis/embedded_files/AM/*.dec` → `bin/<runtime>` in a workspace, patches the `udk_2.bin` *copy's* device slots, stages `settings.json` + `logins.ini` |
| `am_pipeline.py` | the 6-step automatic run: environment → workspace → mapper ladder → emulator self-test → target audit → launch plan |
| `am_web.py` | browser GUI + JSON API + persistent-emulator lifecycle |
| `am_gui.py` | Tk desktop GUI (imports safely without Tk) |
| `am_cli.py` | headless `--auto` / `--serve` CLI |

## Quick start (2 minutes)

```bash
# 1. Start the browser GUI (bind 0.0.0.0 so the sandbox preview can reach it)
python -m vanillatool_emulator.am_web --bind 0.0.0.0 --port 8090
# open http://127.0.0.1:8090/ (or the preview URL)

# 2. In the GUI:
#    - Target EXE: point at bin64/aion.bin (or a copy; repo game.dll works for audit)
#    - Server preset: EuroAion / Aion America / Destiny / GamezAion / ...
#    - tick the original checkboxes (Auto Inject, Virtual Clients, Anonify, ...)
#    - press "▶ Automatic Run"
```

The run executes, in order, exactly what the original does at startup:

1. **Environment** — OS / admin / port / server-preset check.
2. **Workspace** — 12 local files recovered to `.am_workspace/bin/`
   (`udk.bin`, `udk_1.dll`, `udk_2.bin`, `spk.exe`, `lr.exe`, `SR.exe`,
   `BBQ.bin`, `GetThreads64.exe`, `Nova.exe`, `api.dll`, `japi.dll`, …),
   `fHide_*` renames honoured, `fHide_UDK` random 11-char default generated,
   `settings.json` + full 36-key `logins.ini [Delay]` staged.
3. **Mapper ladder** — emulated `-prv 1/2/3` + default transcripts with the
   exact conflict hints (`Status: Make sure MSI Afterburner is closed.`, …).
4. **Emulator self-test** — throwaway server round-trip: auth `C:...;`
   decrypt, all 60 pre-GUI markers, `Version.txt`, `Offsets.txt`,
   `resourceversion.txt`.
5. **Target audit (read-only)** — MZ/PE check, `bin64` layout, `x_World.pak`
   presence, NCGuard string offsets, registry/hosts notes.
6. **Launch plan** — per-account command lines, `LoginAllCap`/`AMLoginAllDelay`,
   Auto-Inject plan note; **dry-run by default** (no process starts).

Then, optionally, press **Start emulator** to keep a persistent service
running that a real client can point at (auth + version + offsets + logs).

## Accounts

`logins.ini` in the workspace holds accounts (`[Account]`, `[Password]`,
`[Client]`, `[GameAccount]`, `[Notes]`, `[LoginAll]`, …).  Manage them in the
GUI's Accounts panel or edit the file directly.  Passwords are stored
plaintext exactly like the original — keep the workspace private; the API
masks them (`***`) and the log never contains them.

Tick **Login All** and press Automatic Run to simulate the staggered
Login-All sequence (`Login All cap of N`, `waiting Ns for LoginAll Delay ..`,
`Logged all checked accounts in`) without starting anything.

## Headless examples

```bash
# full automatic run, JSON report
python -m vanillatool_emulator.am_cli --auto --target-exe game.dll --json

# with Login-All simulation and hive overrides
python -m vanillatool_emulator.am_cli --auto --target-exe /path/to/aion.bin \
  --server "Elden Aion" --login-all --set AutoInject=True --set LoginAllCap=6

# treat provider 1 as blocked (shows the MSI Afterburner hint path)
python -m vanillatool_emulator.am_cli --auto --target-exe game.dll \
  --missing-providers 1

# persistent emulator only (a real client talks to this)
python -m vanillatool_emulator.am_cli --serve --host 0.0.0.0 --port 8080
```

## Pointing a real client at the emulator

The original posts to `https://subvanillatool.com/data/auth.php`.  For lab
use, redirect that host to your emulator (example hosts line):

```
127.0.0.1 subvanillatool.com
```

The lab build **never writes this for you** (unattended hosts/registry writes
are refused by design).  Add it manually, back the file up first, and remove
it afterwards.  The emulator speaks plain HTTP; terminate TLS in front of it
(e.g. stunnel / nginx) if the client requires `https://`.

## Honest limits (by design, not by accident)

* The 60 pre-GUI markers are **zero placeholders** (`0x0`) that satisfy the
  parser/GUI boundary only.  Real build-specific memory profiles must come
  from a captured `--response-file`; the tool never invents addresses.
* `udk.bin -map` is **transcript emulation** (`mapper.simulate`); no driver
  is ever loaded, on any OS.
* NCGuard/target scans are **read-only audits**; no byte is ever patched.
* Auto-Inject is **plan-only**; no DLL is ever injected or hijacked.
* Real process launch is Windows-only, plain `CreateProcess` semantics,
  still without injection or patching — and dry-run unless you explicitly
  pass `--real-launch` / uncheck Dry-run.
* Passwords in `logins.ini` are plaintext (original-compatible).  The tool
  warns, masks API output, and never logs them.

## Tests

```bash
python -m unittest discover -s tests   # 44 tests: 26 emulator + 18 automatic-lab
```
