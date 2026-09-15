"""Recover every layer of Para's Vanillatool -Rework- 11.31.exe.

usage:  python3 recover.py <outer-exe> <workdir>

produces, inside <workdir>:
    outer_image.bin          UPX-decompressed outer loader image
    outer_script.au3         decompiled (still obfuscated) loader script
    payload.bin              the embedded inner PE, re-assembled from hex blobs
    inner_image.bin          UPX-decompressed inner tool image
    inner_files/<name>       every FileInstall payload (ESP dll, helpers, inis)
    inner_script.au3         decompiled inner tool (obfuscated)
    inner_deob.au3           literals inlined (pass 1: string table)
    inner_deob2.au3          variable indirection folded (pass 2, scope aware)
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from autolib import (EA05_MAGIC, decode_table, deob_pass1, deob_pass2,
                     disassemble, ea06_entries, inflate, safe_name, upx_unpack)


def script_entry(entries):
    for e in entries:
        if e["subtype"] == ">>>AUTOIT SCRIPT<<<":
            return e
    raise SystemExit("no script entry found")


def main():
    exe = Path(sys.argv[1])
    work = Path(sys.argv[2])
    work.mkdir(parents=True, exist_ok=True)

    print(f"== outer: {exe.name}")
    img0 = upx_unpack(exe.read_bytes())
    (work / "outer_image.bin").write_bytes(img0)
    ent0 = ea06_entries(img0[img0.index(EA05_MAGIC):])
    tok0, crc0 = inflate(script_entry(ent0)["data"], work)
    src0 = disassemble(tok0)
    (work / "outer_script.au3").write_text(src0, encoding="utf-8")
    print(f"   outer script: {len(src0)} chars (crc {crc0})")

    # ---- re-assemble the embedded inner PE from the hex-blob chunks --------
    assign = re.compile(r'^\$([A-Za-z0-9_]+)\s*=\s*"(0[xX])?([0-9A-Fa-f]{64,})"\s*$')
    blobs = {}
    for ln in src0.splitlines():
        m = assign.match(ln.strip())
        if m:
            blobs[m.group(1)] = m.group(3)
    order = [m.group(1) for m in
             (re.match(r'^\$CWL\s*\[\s*1\s*\]\s*&=\s*\$([A-Za-z0-9_]+)\s*$', ln.strip())
              for ln in src0.splitlines()) if m]
    missing = [v for v in order if v not in blobs]
    if missing:
        raise SystemExit(f"missing blobs: {missing[:5]}")
    payload = bytes.fromhex("".join(blobs[v] for v in order))
    (work / "payload.bin").write_bytes(payload)
    print(f"   payload: {len(payload)} bytes from {len(order)} chunks")

    # ---- inner layer -------------------------------------------------------
    print("== inner")
    img1 = upx_unpack(payload)
    (work / "inner_image.bin").write_bytes(img1)
    ent1 = ea06_entries(img1[img1.index(EA05_MAGIC):])
    files = work / "inner_files"
    files.mkdir(exist_ok=True)
    src1 = None
    for i, e in enumerate(ent1):
        if e["size_cpr"] == 0:
            continue
        if e["comp"]:
            data, crc = inflate(e["data"], work)
            ok = crc == f"{e['crc']:08x}" and len(data) == e["size_unc"]
            print(f"   [{i}] {safe_name(e['name'], i)}: {len(data)} B crc_ok={ok}")
        else:
            data = e["data"]
            print(f"   [{i}] {safe_name(e['name'], i)}: {len(data)} B stored")
        (files / safe_name(e["name"], i)).write_bytes(data)
        if e["subtype"] == ">>>AUTOIT SCRIPT<<<":
            src1 = disassemble(data if not e["comp"] else
                               inflate(e["data"], work)[0])
    (work / "inner_script.au3").write_text(src1, encoding="utf-8")
    print(f"   inner script: {len(src1)} chars")

    # ---- de-obfuscate ------------------------------------------------------
    tbl = next(files.glob("*stripped.au3.tbl"), None)
    if tbl:
        table = decode_table(tbl.read_bytes().decode("latin-1").split("!3{"))
        d1 = deob_pass1(src1, table)
        (work / "inner_deob.au3").write_text(d1, encoding="utf-8")
        d2 = deob_pass2(d1)
        (work / "inner_deob2.au3").write_text(d2, encoding="utf-8")
        print(f"   deobfuscated: {len(d2)} chars, {d2.count(chr(10))} lines")
    print("done ->", work)


main()
