# Lab guide — observe Vanillatool without the real server

Goal: run the **original, unmodified** binaries in an isolated Windows VM
with `subvanillatool.com` redirected to the local stub (`lab/stub_server.py`)
and watch everything they do — startup, drops, beacons, auth attempts,
failure mode. **Observation only: the cheat will not fully function** (the
stub deliberately serves no valid offset table; forging one would crack the
licensing — out of scope).

## 0. Rules (read first)

- **Isolated VM only.** Host-only network. Snapshot before the first run.
  The Account Manager deploys an **unsigned kernel driver via a vulnerable-
  driver mapper** (§8.2) — never run it on hardware you care about.
- **Dummy credentials only.** The tool puts `-account: -password:` on game
  command lines and beacons HWID/username. Use a throwaway game account
  (ideally a private test server), never your main.
- **Ban risk is real** (NCSoft/GameGuard + ban-evasion tooling deepens it).
- **Do NOT "fix" the stub to return working offsets.** That crosses from
  lab observation into cracking + operating the cheat.

## 1. What you need

- A Windows 10/11 VM (isolated virtual network, no route to the internet
  except through your lab gateway if you want controlled egress logging).
- An Aion client installed in the VM (any version; the tool detects it —
  without offsets it still won't bot, but process rendezvous is observable).
- Python 3 on the VM *or* on the lab gateway/host (the stub runs anywhere;
  stdlib-only, Linux/macOS/Windows).
- Renamed analysis tools (see §4 — the client exits if it sees well-known
  debugger/proxy/sniffer process names).

## 2. Redirect `subvanillatool.com` (DNS, NOT hosts file!)

The client **exits if the hosts file mentions `subvanillatool` or
`31.220.106.18`** (§14, mechanism #2). So sinkhole at DNS level instead:

```sh
# example: dnsmasq on the lab gateway / stub host
address=/subvanillatool.com/192.0.2.10     # <- stub IP
```

Point the VM's DNS server at that resolver, then verify **inside the VM**:

```cmd
nslookup subvanillatool.com
:: must answer 192.0.2.10, and %SystemRoot%\System32\drivers\etc\hosts
:: must NOT contain the domain (leave hosts pristine)
```

Any private DNS works (dnsmasq, Technitium, pfSense/OPNsense override,
Windows Server DNS, INetSim appliance). Third-party domains (Google Drive,
GitHub, 2captcha, ipify, …) will simply fail to resolve — that is fine and
observable (watch retry/error behavior).

## 3. Serve HTTP + HTTPS from the stub

`auth.php`, `resourceversion.txt`, `7za.exe`, … are **https://** while the
beacon/offsets/sink are **http://**. Cover both:

```sh
# terminal 1 - plain HTTP (port 80 needs admin/root; else use DNAT)
python3 lab/stub_server.py --port 80 --log stub_http.jsonl

# terminal 2 - HTTPS with a LAB CA you generate (openssl):
#   openssl req -x509 -newkey rsa:2048 -keyout lab.key -out lab.crt \
#     -days 30 -nodes -subj "/CN=subvanillatool.com"
# install lab.crt into the VM's Trusted Root CA store, then:
python3 lab/stub_server.py --port 443 --tls-cert lab.crt --tls-key lab.key \
    --log stub_https.jsonl
```

With the lab CA trusted, the client's WinHTTP stack accepts the stub's
certificate and the encrypted POST lands in your log (field names + sizes;
the `aN` HWID blob itself stays opaque).

## 4. Tool-name camouflage (anti-analysis watchdog, §14 #1)

The client exits if processes named `Fiddler.exe`, `ollydbg.exe`,
`IDApro.exe`, `wireshark.exe`, `Charles.exe`, `mitmproxy.exe` exist. The
check is by **filename**, so in the lab:

- Rename your tools (`procmon.exe` → e.g. `pm.exe`, Wireshark → `ws.exe`,
  …) **before** launching the sample. Sysmon/ETW (no forbidden names, no
  window) is the lowest-visibility telemetry.
- Do NOT run a TLS-intercepting proxy under its default name — the stub's
  native `--tls-cert` mode exists precisely to avoid that need.

## 5. VM camouflage (env gates, §3.1 step 4 / §14 #3–5)

A stock VM trips the gates instantly (VirtualBox/QEMU/VMware BIOS strings,
`VBOX HARDDISK`-style disk models, `Win32_ComputerSystemProduct` names) and
the client just exits. To observe *past* the gates you must mask the VM:

- **VirtualBox:** `VBoxManage setextradata` DMI keys (`DmiSystemVendor`,
  `DmiSystemProduct`, `DmiBIOSVersion`, …) to innocuous strings; use a
  custom disk model string if your setup allows.
- **KVM/libvirt:** `<sysinfo type='smbios'>` with neutral vendor/product
  values; avoid `QEMU HARDDISK` model strings.
- **VMware:** `SMBIOS.reflectHost = "TRUE"` in the `.vmx`.

This is iterative: launch → check stub log + procmon → see which gate fired
(registry/WMI queries are visible) → mask → snapshot → repeat. If a gate
can't be masked on your hypervisor, document the boundary — the exit path
itself (guarded `ctrl.png` cleanup + `Exit`) is still an observation.

## 6. Run procedure

1. Snapshot the clean VM.
2. Start the stub(s) (§3), confirm `nslookup` (§2) inside the VM.
3. Start renamed ProcMon/Sysmon capture in the VM.
4. Launch `Para's Vanillatool -Rework- 11.31.exe` (or Account Manager).
5. Watch, in parallel:
   - stub console: `POST /data/auth.php route=auth ... fields={...}`,
     `GET /Log/log.php route=beacon`, `/Offsets.txt`, `/POST/`, `404`s;
   - `%TEMP%\{5E8D2FEC-DA12-4EF4-8DFC-15AC4BAB2107}\` drops;
   - `HKCU\Software\Para's NoAnimation` + `HKCU\System\System\AppFlag`;
   - dialogs: expect license/waiting/error windows, then exit.

## 7. Expected timeline (what "normal" looks like in the lab)

| # | Observable | Where |
|---|---|---|
| 1 | Process starts, registry bootstrap, temp staging dir created | ProcMon / fs |
| 2 | Env-gate queries (BIOS/WMI/disk/hosts read) | ProcMon / ETW |
| 3 | `GET /Log/log.php` beacon (maybe twice; one branch has buggy `http:://`) | stub log |
| 4 | `POST /data/auth.php` with `aN/aU/aH/aR/aC/aV` | stub log (HTTPS instance) |
| 5 | Client scrapes response for `C:…;`, finds nothing → no offsets | stub log (single POST, no follow-up) |
| 6 | License/waiting dialog or guarded exit (`ctrl.png` deleted) | VM screen / ProcMon |
| 7 | (If it proceeds) `aion.bin` rendezvous waits, `RadarScanPID=` handling | ProcMon |

Anything *beyond* step 5 without a real server would be new information —
record it.

## 8. Troubleshooting

| Symptom | Likely cause |
|---|---|
| Exits in <1 s, stub log empty | Env gate (§5) or tool-name watchdog (§4) fired first |
| `auth` POST never arrives, beacon does | HTTPS/cert issue — check lab CA trust + port 443 path |
| `unknown` routes in stub log | New/undocumented endpoints — record path + body; gold dust |
| Updater (`Auto Update.exe`) phones GitHub, not the stub | Expected — separate channel (§11.2); redirect `github.com` too if you want to observe it (TLS + CA as in §3) |
| Game client patched / won't start | Irrelevant to tool observation — the tool only needs `aion.bin` present to rendezvous with |

## 9. Mapping back to the report

- Endpoints + fields: §4–§5, §17 · Gates/watchdog: §3.1, §14 ·
  Drops/registry: §6 · Expected GUI: §12 · Updater channel: §11.2 ·
  Static recovery this complements: `docs/OFFLINE_RUNBOOK.md`.
