"""Shared helpers for recovering Para's VanillaTool payloads.

Chain (see README.md):
  UPX(LZMA) PE  ->  AutoIt EA06 container  ->  LAME+LZSS blob  ->  token stream
  ->  disassembled AutoIt source  ->  literal de-obfuscation
"""
from __future__ import annotations

import lzma
import re
import struct
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    from autoit_ripper.utils import ByteStream, AutoItVersion, EA06Decryptor
    from autoit_ripper.autoit_unpack import parse_all, EA05_MAGIC
    from autoit_ripper.opcodes import deassemble_script
except ImportError:  # pragma: no cover
    sys.exit("pip install autoit-ripper pefile   (required)")

HERE = Path(__file__).resolve().parent
EA06_CONTENT_KEY = 0x2477          # checksum(0 for EA06) + au3_ResContent


# --------------------------------------------------------------------------
# UPX / LZMA
# --------------------------------------------------------------------------
def pe_sections(d: bytes):
    e = struct.unpack_from("<I", d, 0x3C)[0]
    nsec = struct.unpack_from("<H", d, e + 6)[0]
    optsize = struct.unpack_from("<H", d, e + 20)[0]
    off = e + 24 + optsize
    out = []
    for i in range(nsec):
        o = off + i * 40
        name = d[o:o + 8].rstrip(b"\0").decode("latin1")
        vs, va, rs, rp = struct.unpack_from("<IIII", d, o + 8)
        out.append((name, va, vs, rp, rs))
    return out


def upx_unpack(d: bytes) -> bytes:
    """Decompress a UPX(LZMA)-packed PE image (method 14)."""
    ph = d.rindex(b"UPX!", 0, 0x400)
    method = d[ph + 6]
    u_len, c_len, u_file = struct.unpack_from("<III", d, ph + 16)
    if method != 14:
        raise ValueError(f"unsupported UPX method {method}")
    base = [s for s in pe_sections(d) if s[0] == "UPX1"][0][3]
    dictlog, props = d[base], d[base + 1]
    lc, rest = props % 9, props // 9
    lp, pb = rest % 5, rest // 5
    dec = lzma.LZMADecompressor(
        format=lzma.FORMAT_RAW,
        filters=[{"id": lzma.FILTER_LZMA1, "dict_size": 1 << dictlog,
                  "lc": lc, "lp": lp, "pb": pb}],
    )
    img = dec.decompress(d[base + 2:base + c_len])
    if len(img) not in (u_len, u_len + 1):
        raise ValueError(f"decompressed {len(img)} != u_len {u_len}")
    return img


# --------------------------------------------------------------------------
# AutoIt EA06 container
# --------------------------------------------------------------------------
def ea06_entries(blob: bytes):
    dec = EA06Decryptor()
    stream = ByteStream(blob[20:])
    if stream.get_bytes(4) != b"EA06":
        raise ValueError("not an EA06 container")
    sum(list(stream.get_bytes(16)))

    def rs(keys):
        n = stream.u32() ^ keys[0]
        return dec.decrypt(stream.get_bytes(n << 1), n + keys[1]).decode("utf-16")

    entries = []
    while True:
        if dec.decrypt(stream.get_bytes(4), dec.au3_ResType) != b"FILE":
            break
        subtype, name = rs(dec.au3_ResSubType), rs(dec.au3_ResName)
        comp = stream.u8()
        size_cpr = stream.u32() ^ dec.au3_ResSize
        size_unc = stream.u32() ^ dec.au3_ResSize
        crc = stream.u32() ^ dec.au3_ResCrcCompressed
        stream.skip_bytes(16)
        entries.append(dict(subtype=subtype, name=name, comp=comp, crc=crc,
                            size_cpr=size_cpr, size_unc=size_unc,
                            data=stream.get_bytes(size_cpr)))
    return entries


def build_autodec() -> Path:
    exe = HERE / "autodec"
    if not exe.exists():
        subprocess.run(["gcc", "-O2", "-o", str(exe), str(HERE / "autodec.c")], check=True)
    return exe


def inflate(enc: bytes, workdir: Path) -> bytes:
    """LAME-decrypt + LZSS-inflate one compressed EA06 entry."""
    workdir.mkdir(parents=True, exist_ok=True)
    fin, fout = workdir / "_enc.bin", workdir / "_dec.bin"
    fin.write_bytes(enc)
    r = subprocess.run([str(build_autodec()), hex(EA06_CONTENT_KEY), str(fin), str(fout)],
                       capture_output=True, text=True)
    expected = r.stdout.split("= ")[1].split()[0] if "= " in r.stdout else "?"
    if not fout.exists():
        raise RuntimeError(r.stderr)
    data = fout.read_bytes()
    fin.unlink(missing_ok=True)
    fout.unlink(missing_ok=True)
    return data, expected


def safe_name(name: str, i: int) -> str:
    base = Path(name.replace("\\\\", "\\")).name or f"entry{i}"
    return re.sub(r"[^A-Za-z0-9._-]", "_", base)


def disassemble(tokens: bytes) -> str:
    return deassemble_script(tokens)


# --------------------------------------------------------------------------
# de-obfuscation
# --------------------------------------------------------------------------
def decode_table(raw: list[str]) -> list[str]:
    """Every table entry is itself hex encoded ("204054656D7044697220" -> "@TempDir ")."""
    out = []
    for p in raw:
        try:
            out.append(bytes.fromhex(p).decode("utf-8", "replace")
                       if len(p) % 2 == 0 and p else p)
        except ValueError:
            out.append(p)
    return out


def deob_pass1(src: str, table: list[str]) -> str:
    """A0200001905($OS[n]) / A0200001905("hex") / Execute(BinaryToString(..))."""
    def q(s):
        return '"' + s.replace('"', '""') + '"'

    def unhex(h):
        return bytes.fromhex(h).decode("utf-8", "replace")

    def sub_table(m):
        j = int(m.group(1)) - 1                      # StringSplit arrays are 1-based
        return q(table[j]) if 0 <= j < len(table) else "<bad %s>" % m.group(1)

    src = re.sub(r"A0200001905 \( \$OS \[ (\d+) \] \)", sub_table, src)
    src = re.sub(r'A0200001905 \( "([0-9A-Fa-f]{2,})" \)',
                 lambda m: q(unhex(m.group(1))), src)

    def sub_exec(m):
        code = unhex(m.group(1)[2:])
        for _ in range(6):
            inner = re.findall(r"(?i)Binarytostring\('0x([0-9A-Fa-f]+)'\)", code)
            if not inner:
                break
            for h in inner:
                code = re.sub("(?i)Binarytostring\\('0x" + h + "'\\)", q(unhex(h)), code)
        return "/*EXEC*/ " + code.replace("\r\n", " ").replace("\n", " ")

    return re.sub(r'Execute \( BinaryToString \( "(0x[0-9A-Fa-f]+)" \) \)', sub_exec, src)


def deob_pass2(src: str) -> str:
    """Inline the per-function literal variables (scope aware)."""
    src = src.replace("\r\n", "\n")
    lines = src.split("\n")
    assign_re = re.compile(r'\$([A-Za-z0-9_]+) = "((?:[^"]|"")*)"')
    func_re = re.compile(r"^Func ([A-Za-z0-9_]+) \(")
    end_re = re.compile(r"^EndFunc")
    num_re = re.compile(r"^\s*[+-]?\d+(?:\.\d+)?\s*$")

    scopes, cur = [], None
    for i, ln in enumerate(lines):
        m = func_re.match(ln)
        if m and cur is None:
            cur = [i, i + 1]
            continue
        if cur is not None:
            cur[1] = i + 1
            if end_re.match(ln):
                scopes.append(tuple(cur))
                cur = None
    if cur:
        scopes.append(tuple(cur))
    covered = set()
    for a, b in scopes:
        covered.update(range(a, b))
    granges, start = [], 0
    for a, b in sorted(scopes):
        if a > start:
            granges.append((start, a))
        start = b
    if start < len(lines):
        granges.append((start, len(lines)))

    def build(rngs):
        m = {}
        for a, b in rngs:
            for ln in lines[a:b]:
                for name, lit in assign_re.findall(ln):
                    if name.startswith("SS"):
                        continue
                    if name in m and m[name] != lit:
                        m[name] = None
                    else:
                        m.setdefault(name, lit)
        return {k: v for k, v in m.items() if v is not None}

    def transform(text, m):
        def val(n):
            return m[n].replace('""', '"')

        def s_num(x):
            return m[x.group(1)].strip() if x.group(1) in m and num_re.match(m[x.group(1)]) else x.group(0)

        def s_exe(x):
            if x.group(1) not in m:
                return x.group(0)
            v = val(x.group(1)).strip()
            return v if v.startswith("@") else 'Execute("%s")' % v

        def s_plain(x):
            return '"' + val(x.group(1)) + '"' if x.group(1) in m else x.group(0)

        text = re.sub(r"Number \( \$([A-Za-z0-9_]+) \)", s_num, text)
        text = re.sub(r"Execute \( \$([A-Za-z0-9_]+) \)", s_exe, text)
        return re.sub(r"(?<![\$\w])\$([A-Za-z0-9_]+)(?![A-Za-z0-9_\(])(?!\s*=(?!=))", s_plain, text)

    gmap = build(granges)
    result = [None] * len(lines)
    for a, b in granges:
        for i in range(a, b):
            result[i] = transform(lines[i], gmap)
    for a, b in scopes:
        local = dict(gmap)
        local.update(build([(a, b)]))
        for i in range(a, b):
            result[i] = lines[i] if func_re.match(lines[i]) else transform(lines[i], local)
    text = "\n".join(result)
    text = re.sub(r"[ \t]*Global \$[A-Za-z0-9_]+ = \"(?:[^\"]|\"\")*\"(?: , \$[A-Za-z0-9_]+ = \"(?:[^\"]|\"\")*\")*\n", "", text)
    text = re.sub(r"[ \t]*If Not IsDeclared \( \"SS[A-Za-z0-9_]+\" \) Then\n[ \t]*Global \$SS[A-Za-z0-9_]+ =  1 \n[ \t]*EndIf\n", "", text)
    return text
