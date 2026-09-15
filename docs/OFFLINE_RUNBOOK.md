# Offline reproduction runbook — Vanillatool 11.31 case

Everything in `analysis.md` that derives from recovered source can be
regenerated on a machine with **no network access** using only this repository
plus a stock Python 3 (3.8+, `lzma` stdlib module). No `pip install`, no
downloads, no UPX binary, no Windows required.

```sh
git clone <this-repo> && cd <repo>
python3 tools/run_all.py            # ~4–8 min, verifies itself
# VERDICT: ALL ORACLES PASS — pipeline reproduces analysis.md artifacts
```

`run_all.py` writes all generated artifacts to `_work/` (git-ignored) and
checks every stage against byte-exact oracles (§4). A non-zero exit names
the failing oracle.

## 1. Tool map

| Tool | Input → output | Format knowledge |
|---|---|---|
| `tools/upx_unpack.py` | UPX-LZMA exe → memory image + `RT_RCDATA` blob | PACKHEAD parse (method 14); UPX1 = `18 03` + raw LZMA1 (`lc3/lp0/pb0`, 16 MB dict, no end marker — natural end bisected); image maps at `RVA = UPX0.VAddr + off`; `.rsrc` walked to the script blob (`AU3!EA06` @+0x10) |
| `tools/ea06.py` | `--rcdata` blob **or** `--exe` file → `script.au3` + bundle | Vendored `autoit_ripper` 1.2.0 (`vendor/`, unmodified; 10 MB script cap raised at runtime; `pefile` stubbed — the blob path never uses it). `--exe` uses the biggest file-backed `RT_RCDATA`, else carves `AU3!EA06` − 16 (GV/FS layout) |
| `tools/assemble_outer.py` | outer `script.au3` → `payload.exe` | 8,558 `$CWL[1] &= $VAR` hex chunks in order; first chunk `0x`-prefixed `MZ`; sha256-gated |
| `tools/deobfuscate.py` | `script.au3` + `.tbl` → readable source + `strings.txt` | Hex table split by dialect delimiter (`!3{` core / `\|2{` AM); `DECODER($OS[N])` substitution; `ChrW(Number($VAR))` URL-chain folding via table numbers |
| `tools/triage.py` | native/packed PE → summary + strings | Arch/link-time/sections + ASCII/UTF-16 strings + `--grep` probes (version resources surface as UTF-16) |
| `tools/run_all.py` | case dir → `_work/` + verdict | Master pipeline with oracles (§4) |

## 2. Manual walkthrough (equivalent of `run_all.py`)

```sh
# --- core chain: outer -> payload -> inner bundle -> readable source ---
python3 tools/upx_unpack.py "Para's Vanillatool -Rework- 11.31.exe" \
    --out _work/outer.img --rcdata _work/outer_rc.bin
python3 tools/ea06.py --rcdata _work/outer_rc.bin --out _work/outer_out
python3 tools/assemble_outer.py _work/outer_out/script.au3 --out _work/payload.exe
python3 tools/upx_unpack.py _work/payload.exe \
    --out _work/payload.img --rcdata _work/payload_rc.bin
python3 tools/ea06.py --rcdata _work/payload_rc.bin --out _work/payload_out
python3 tools/deobfuscate.py _work/payload_out/script.au3 \
    _work/payload_out/*.tbl --decoder A0200001905 --delim '!3{' \
    --out _work/core_deobf.au3 --strings _work/core_strings.txt

# --- Account Manager chain ---
python3 tools/upx_unpack.py "Para's Account Manager - ver. 5.43.exe" \
    --out _work/am.img --rcdata _work/am_rc.bin
python3 tools/ea06.py --rcdata _work/am_rc.bin --out _work/am_out
python3 tools/deobfuscate.py _work/am_out/script.au3 \
    _work/am_out/*.tbl --decoder A390000520A --delim '|2{' \
    --out _work/am_deobf.au3 --strings _work/am_strings.txt

# --- siblings & helpers (direct; RN is NRV-packed but its script
# --- resource is file-backed, so no NRV decoder is needed) ---
python3 tools/ea06.py --exe "Auto Update.exe" --out _work/au_out
python3 tools/ea06.py --exe "Rename Processes.exe" --out _work/rn_out
for h in GV FS GetThreads64 SR tk; do
  f=$(awk -F'\t' -v h="$h" '$2 ~ h {print $3; exit}' _work/payload_out/MANIFEST.txt)
  out=$(echo "$h" | tr 'A-Z' 'a-z')
  python3 tools/ea06.py --exe "_work/payload_out/$f" --out "_work/${out}_out"
done
# (GetThreads64 lands in _work/getthreads64_out; run_all.py uses _work/gt_out.)
# SparkMod is UPX-LZMA packed: unpack first, then decompile
f=$(awk -F'\t' '$2 ~ /SparkMod/ {print $3; exit}' _work/am_out/MANIFEST.txt)
python3 tools/upx_unpack.py "_work/am_out/$f" --out _work/spk.img --rcdata _work/spk_rc.bin
python3 tools/ea06.py --rcdata _work/spk_rc.bin --out _work/spk_out

# --- native / packed-component triage ---
python3 tools/triage.py _work/payload_out/*VanillaEsp*.dll \
    --grep AIONClientWndClass --grep d3d9 --strings _work/strings
python3 tools/triage.py _work/am_out/*VanillaUDK_3.13.bin \
    --grep "victim driver" --strings _work/strings
python3 tools/triage.py _work/am_out/*NovaApi.exe \
    --grep ownlink --grep LoginService --strings _work/strings
python3 tools/triage.py _work/am_out/*_lr.exe --grep UnLimiter --strings _work/strings
python3 tools/triage.py _work/am_out/*BBQ.bin --grep BBQ --strings _work/strings
python3 tools/triage.py "Unique-ID 0.8.5.exe" --grep LAZ_ --strings _work/strings
python3 tools/triage.py 6aa4b6d3585e8875bcbebf80/crackme.exe \
    --grep frida --strings _work/strings
```

`fastscript.pscp` is plaintext — read it directly (§9.6 walkthrough).

## 3. Reproducing key `analysis.md` claims

After the pipeline, each claim is one `grep`:

| Report claim | Command (in `_work/`) | Expect |
|---|---|---|
| §4.2 auth endpoint | `grep -c https://subvanillatool.com/data/auth.php core_deobf.au3` | `1` |
| §4.3 log beacon | `grep -c subvanillatool.com/Log/log.php core_deobf.au3` | `9` |
| §14 debugger kill-switch | `grep -c Fiddler core_deobf.au3` (+ ollydbg/IDApro/…) | `1` each |
| §8.1 twin injector | `grep -c CreateRemoteThread core_deobf.au3` | `2` |
| §7.2 mem primitives | `grep -c ReadProcessMemory core_deobf.au3` | `20` |
| §9 `SolveCaptcha=` | `grep -c 'SolveCaptcha=' core_deobf.au3` | `3` |
| §8.2 HIDKeyboard device | `grep -c HIDKeyboard am_deobf.au3` | `1` |
| §8.2 driver service | `grep -c PRProt am_deobf.au3` | `3` |
| §11.1 creds on cmdline | `grep -c -- '-account:' am_deobf.au3` / `-password:` | `11` / `10` |
| §11.2 updater | `grep -c Lyzing au_out/script.au3`; `grep -c '\-pvt' au_out/script.au3` | `2` / `1` |
| §11.2 UnRAR bundle | `ls au_out/` | `+ UnRAR.exe` (422,552 B) |
| §11.3 randomizer | `grep -c fHide_ rn_out/script.au3` | `28` |
| §10.1 GV TTS | `grep -c 'tab=wT' gv_out/script.au3` | `1` |
| §10.3 GT protocol | `grep -c GETALLTHREADSSTARTADDRESS gt_out/script.au3` | `4` |
| §10.4 SR OCR | `grep -c RecognizeAsync sr_out/script.au3` | `2` |
| §8.1 ESP markers | triage `--grep` output | `d3d9.dll`, `…WndClass1.0`, `D3DXCreate…` |
| §8.2 kdmapper | triage `--grep` output | `victim driver` ×8 |
| §10 NovaApi PDB | triage `--grep` output | `C:\Users\ownlink\…NovaApi.pdb` |
| §1.2 lr / BBQ identity | triage `--grep` output | `Para's UnLimiter` 1.2.8.0 / `Para's BBQ` 1.2.1.0 |
| §11.4 Lazarus UID | triage `--grep` output | `LAZ_PIC_DIALOG_TEMPLATE` |
| §11.5 crackme | triage output | `frida` ×1, stamp `2026-09-11` |

## 4. Oracle table (byte-exact; enforced by `run_all.py`)

| Artifact | Bytes / count |
|---|---|
| `outer.img` | 15,186,125 |
| `outer_rc.bin` | 13,904,442 |
| `outer_out/script.au3` | 17,385,073 (1 file) |
| `payload.exe` | 8,557,568 · sha256 `5d1a3f47…bb331f0541` (full hash in `assemble_outer.py`) |
| `payload.img` | 9,346,221 |
| `payload_rc.bin` | 8,068,770 |
| `payload_out/` | 18 files · `script.au3` 9,671,596 · `*.tbl` 1,496,450 |
| `core_deobf.au3` | 7,722,678 · 91,164 subs, 0 bad, 18 ChrW chains |
| `am.img` | 9,938,727 |
| `am_rc.bin` | 8,724,872 |
| `am_out/` | 20 files · `script.au3` 6,500,167 · `*.tbl` 1,104,699 |
| `am_deobf.au3` | 5,218,493 · 62,685 subs, 0 bad, 1 ChrW chain |
| `au_out/` | 2 files · script 312,623 · UnRAR.exe 422,552 |
| `rn_out/script.au3` | 183,690 |
| helpers | GV 118,231 · FS 63,888 (+7,635 .tbl) · GT 170,442 · SR 560,848 · tk 309,171 (+50,990 .tbl) · SPK 1,585,044 (+299,868 .tbl) |

## 5. Scope & known limits (all pre-existing in the analysis)

- **UPX-NRV (method 8)** samples — `Unique-ID 0.8.5.exe`, `lr.exe`,
  `BBQ.bin` — are triaged via resources + surface strings only (same as
  `analysis.md` §11.4/§1.2; no NRV decoder is shipped or needed).
- **FS / tk / SparkMod scripts** decompile to still-obfuscated source with
  their own per-build string tables (delimiters `]2[`, `t79[`, `!073o` —
  the obfuscator salts each build). Roles follow from name + invocation +
  strings, as reported in §10.
- **No live detonation** is performed or required: kernel-driver +
  anti-VM + server-side offsets make dynamic execution hostile and
  low-yield; every behavioral claim traces to recovered source above.
- The personalized username stamp (§2, EXE offset 1634) is read with
  `dd if="Para's Vanillatool -Rework- 11.31.exe" bs=1 skip=1634 count=8`.
- Windows-only conveniences (none needed): any CPython 3.8+ on
  Linux/macOS/Windows runs the kit; outputs are plain bytes/text.
