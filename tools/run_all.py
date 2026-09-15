#!/usr/bin/env python3
"""End-to-end offline reconstruction pipeline for the Vanillatool case.

Runs every stage (unpack -> decompile -> assemble -> deobfuscate -> triage)
with zero network access and verifies each artifact against hardcoded
byte-exact oracles (sizes, counts, hashes).  Any mismatch aborts with a
non-zero exit, so a clean run *is* the verification.

Stages (see docs/OFFLINE_RUNBOOK.md for the manual equivalent):

  1. outer Vanillatool exe -> UPX-LZMA image + RCDATA -> outer script
  2. outer script -> payload.exe (8,558 hex chunks, sha256-gated)
  3. payload.exe -> image + RCDATA -> 18 files (script + .tbl + bundle)
  4. core script + .tbl -> deobfuscated source (91,164 substitutions)
  5. Account Manager exe -> image + RCDATA -> 20 files -> deobfuscated
  6. Auto Update / Rename Processes / helpers (GV,FS,GT,SR,tk,SPK) scripts
  7. native/packed triage (ESP, driver kit, NovaApi, lr, BBQ, UID, crackme)

Usage:
    python3 tools/run_all.py [--work DIR] [--case DIR]
    # defaults: --work <repo>/_work  --case <repo>
"""

import argparse
import hashlib
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
PY = sys.executable

FAILURES = []


def run(*cmd):
    print(f'$ {" ".join(cmd)}', flush=True)
    r = subprocess.run(cmd, capture_output=True, text=True)
    sys.stderr.write(r.stderr)
    if r.returncode != 0:
        print(r.stdout[-3000:] if r.stdout else '')
        raise SystemExit(f'FAILED (exit {r.returncode}): {cmd[1]}')
    return r


def check(label, cond, detail=''):
    print(f'  [{"OK " if cond else "FAIL"}] {label} {detail}')
    if not cond:
        FAILURES.append(label)


def fsize(path):
    return os.path.getsize(path)


def manifest_sizes(outdir):
    out = {}
    with open(os.path.join(outdir, 'MANIFEST.txt'), encoding='utf-8') as fh:
        for line in fh:
            size, orig, _ = line.rstrip('\n').split('\t')
            out[orig] = int(size)
    return out


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as fh:
        for blk in iter(lambda: fh.read(1 << 20), b''):
            h.update(blk)
    return h.hexdigest()


def main() -> None:
    ap = argparse.ArgumentParser(description='offline reconstruction pipeline')
    ap.add_argument('--work', default=os.path.join(REPO, '_work'))
    ap.add_argument('--case', default=REPO)
    args = ap.parse_args()
    work, case = args.work, args.case
    os.makedirs(work, exist_ok=True)
    tool = lambda name: os.path.join(HERE, name)  # noqa: E731

    print('== 1. outer Vanillatool -> image + outer script ==')
    outer = os.path.join(case, "Para's Vanillatool -Rework- 11.31.exe")
    run(PY, tool('upx_unpack.py'), outer, '--out', f'{work}/outer.img',
        '--rcdata', f'{work}/outer_rc.bin')
    check('outer image bytes', fsize(f'{work}/outer.img') == 15186125)
    check('outer RCDATA bytes', fsize(f'{work}/outer_rc.bin') == 13904442)
    run(PY, tool('ea06.py'), '--rcdata', f'{work}/outer_rc.bin',
        '--out', f'{work}/outer_out')
    m = manifest_sizes(f'{work}/outer_out')
    check('outer files', len(m) == 1, f'({len(m)})')
    check('outer script bytes', m.get('script.au3') == 17385073)

    print('== 2. outer script -> payload.exe ==')
    run(PY, tool('assemble_outer.py'), f'{work}/outer_out/script.au3',
        '--out', f'{work}/payload.exe')
    check('payload bytes', fsize(f'{work}/payload.exe') == 8557568)
    check('payload sha256', sha256(f'{work}/payload.exe') ==
          '5d1a3f4741ebc15c3747530081bd739787ddc69a3fbe2559b95e91bb331f0541')

    print('== 3. payload.exe -> inner bundle ==')
    run(PY, tool('upx_unpack.py'), f'{work}/payload.exe', '--out',
        f'{work}/payload.img', '--rcdata', f'{work}/payload_rc.bin')
    check('payload image bytes', fsize(f'{work}/payload.img') == 9346221)
    check('payload RCDATA bytes', fsize(f'{work}/payload_rc.bin') == 8068770)
    run(PY, tool('ea06.py'), '--rcdata', f'{work}/payload_rc.bin',
        '--out', f'{work}/payload_out')
    m = manifest_sizes(f'{work}/payload_out')
    check('inner files', len(m) == 18, f'({len(m)})')
    check('inner script bytes', m.get('script.au3') == 9671596)
    tbl = [k for k in m if k.endswith('.tbl')]
    check('inner .tbl bytes', len(tbl) == 1 and m[tbl[0]] == 1496450)

    print('== 4. core deobfuscation ==')
    tbl_file = [f for f in os.listdir(f'{work}/payload_out') if f.endswith('.tbl')][0]
    r = run(PY, tool('deobfuscate.py'), f'{work}/payload_out/script.au3',
            f'{work}/payload_out/{tbl_file}', '--decoder', 'A0200001905',
            '--delim', '!3{', '--out', f'{work}/core_deobf.au3',
            '--strings', f'{work}/core_strings.txt')
    check('core deobf bytes', fsize(f'{work}/core_deobf.au3') == 7722678)
    check('core subs', 'substituted 91164 decoder calls (0 bad' in r.stderr)

    print('== 5. Account Manager chain ==')
    am = os.path.join(case, "Para's Account Manager - ver. 5.43.exe")
    run(PY, tool('upx_unpack.py'), am, '--out', f'{work}/am.img',
        '--rcdata', f'{work}/am_rc.bin')
    check('AM image bytes', fsize(f'{work}/am.img') == 9938727)
    run(PY, tool('ea06.py'), '--rcdata', f'{work}/am_rc.bin', '--out', f'{work}/am_out')
    m = manifest_sizes(f'{work}/am_out')
    check('AM files', len(m) == 20, f'({len(m)})')
    check('AM script bytes', m.get('script.au3') == 6500167)
    tbl = [k for k in m if k.endswith('.tbl')]
    check('AM .tbl bytes', len(tbl) == 1 and m[tbl[0]] == 1104699)
    tbl_file = [f for f in os.listdir(f'{work}/am_out') if f.endswith('.tbl')][0]
    r = run(PY, tool('deobfuscate.py'), f'{work}/am_out/script.au3',
            f'{work}/am_out/{tbl_file}', '--decoder', 'A390000520A',
            '--delim', '|2{', '--out', f'{work}/am_deobf.au3',
            '--strings', f'{work}/am_strings.txt')
    check('AM deobf bytes', fsize(f'{work}/am_deobf.au3') == 5218493)
    check('AM subs', 'substituted 62685 decoder calls (0 bad' in r.stderr)

    print('== 6. updater / randomizer / helpers ==')
    run(PY, tool('ea06.py'), '--exe', os.path.join(case, 'Auto Update.exe'),
        '--out', f'{work}/au_out')
    m = manifest_sizes(f'{work}/au_out')
    check('AU files', len(m) == 2 and m.get('script.au3') == 312623)
    run(PY, tool('ea06.py'), '--exe', os.path.join(case, 'Rename Processes.exe'),
        '--out', f'{work}/rn_out')
    m = manifest_sizes(f'{work}/rn_out')
    check('RN script bytes', m.get('script.au3') == 183690)

    def bundle_member(outdir, suffix):
        with open(os.path.join(outdir, 'MANIFEST.txt'), encoding='utf-8') as fh:
            for line in fh:
                parts = line.rstrip('\n').split('\t')
                if parts[1].endswith(suffix):
                    return os.path.join(outdir, parts[2])
        raise SystemExit(f'{suffix} not in {outdir}')

    helpers = [
        ('payload_out', 'GV.exe', 'gv_out', {'script.au3': 118231}),
        ('payload_out', 'FS.exe', 'fs_out', {'script.au3': 63888}),
        ('payload_out', 'GetThreads64.exe', 'gt_out', {'script.au3': 170442}),
        ('payload_out', 'SR.exe', 'sr_out', {'script.au3': 560848}),
        ('payload_out', 'tk.exe', 'tk_out', {'script.au3': 309171}),
        ('am_out', 'SparkMod.exe', 'spk_img', None),  # UPX-packed: unpack first
    ]
    for srcdir, member, dest, oracle in helpers:
        exe = bundle_member(f'{work}/{srcdir}', member)
        if oracle is None:
            run(PY, tool('upx_unpack.py'), exe, '--out', f'{work}/{dest}.img',
                '--rcdata', f'{work}/{dest}_rc.bin')
            run(PY, tool('ea06.py'), '--rcdata', f'{work}/{dest}_rc.bin',
                '--out', f'{work}/{dest}')
            m = manifest_sizes(f'{work}/{dest}')
            check('SPK script bytes', m.get('script.au3') == 1585044)
        else:
            run(PY, tool('ea06.py'), '--exe', exe, '--out', f'{work}/{dest}')
            m = manifest_sizes(f'{work}/{dest}')
            for name, size in oracle.items():
                check(f'{dest}/{name} bytes', m.get(name) == size)

    print('== 7. native/packed triage ==')
    tri = [
        ('payload_out', 'VanillaEsp_v1.3.8.dll', ['AIONClientWndClass1.0', 'd3d9.dll']),
        ('am_out', 'VanillaUDK_3.13.bin', ['victim driver']),
        ('am_out', 'NovaApi.exe', ['ownlink', 'LoginService']),
        ('am_out', 'lr.exe', ["Para's UnLimiter", '1.2.8.0']),
        ('am_out', 'BBQ.bin', ["Para's BBQ", '1.2.1.0']),
    ]
    for srcdir, member, markers in tri:
        exe = bundle_member(f'{work}/{srcdir}', member)
        r = run(PY, tool('triage.py'), exe,
                *sum((['--grep', mk] for mk in markers), []))
        for mk in markers:
            check(f'{member}: {mk!r}', f"grep {mk!r}:" in r.stdout
                  and f"grep {mk!r}: 0" not in r.stdout)
    r = run(PY, tool('triage.py'), os.path.join(case, 'Unique-ID 0.8.5.exe'),
            '--grep', 'LAZ_', '--grep', 'UniqueID')
    check('UID LAZ markers', "grep 'LAZ_': 0" not in r.stdout)
    crack = os.path.join(case, '6aa4b6d3585e8875bcbebf80', 'crackme.exe')
    if os.path.exists(crack):
        r = run(PY, tool('triage.py'), crack, '--grep', 'frida')
        check('crackme frida', "grep 'frida': 0" not in r.stdout)
        check('crackme future stamp', '2026-09-11' in r.stdout)

    print()
    if FAILURES:
        print(f'VERDICT: {len(FAILURES)} ORACLE FAILURES: {FAILURES}')
        return 1
    print('VERDICT: ALL ORACLES PASS — pipeline reproduces analysis.md artifacts')
    return 0


if __name__ == '__main__':
    sys.exit(main())
