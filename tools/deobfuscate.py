#!/usr/bin/env python3
"""Deobfuscate Vanillatool-family AutoIt scripts (offline, stdlib-only).

The core + Account Manager scripts hide every string literal as hex in an
external string table (``*.tbl``), loaded at runtime and decoded through a
generated ``A<16 hex>`` function::

    Func A0200001905 ( $A0200001905 )
        ...
        $A0200001905_ &= Chr ( Dec ( StringMid ( $A0200001905 , $X , 2 ) ) )
        ...
    EndFunc

i.e. plain hex -> ANSI.  Two table dialects exist:

  * core script : delimiter ``!3{``  decoder ``A0200001905`` (91,164 strings)
  * Acct Manager: delimiter ``|2{``  decoder ``A390000520A`` (62,686 strings)

Additionally, two URLs are built as ``ChrW ( Number ( $VAR ) )`` chains where
each ``$VAR`` was initialised from the table with a decimal number string.
Those chains are folded back into readable URLs.

Usage:
    python3 deobfuscate.py SCRIPT.AU3 TABLE.TBL --decoder A0200001905 \
        --delim '!3{' --out SCRIPT_DEOBFUSCATED.AU3 --strings STRINGS.TXT
"""

import argparse
import re
import sys


def au3_quote(text: str) -> str:
    """Render text as an AutoIt string literal (keeps it single-line safe)."""
    text = text.replace('"', '""')
    text = text.replace('\r\n', '" & @CRLF & "')
    text = text.replace('\r', '" & @CR & "')
    text = text.replace('\n', '" & @LF & "')
    return f'"{text}"'


def load_table(path: str, delim: bytes) -> list[str]:
    raw = open(path, 'rb').read()
    parts = raw.split(delim)
    if parts and parts[-1] == b'':
        parts = parts[:-1]  # trailing delimiter
    strings = []
    for i, part in enumerate(parts, start=1):
        try:
            blob = bytes.fromhex(part.decode('ascii'))
        except ValueError:
            raise SystemExit(f'table entry {i} is not valid hex: {part[:60]!r}')
        strings.append(blob.decode('latin-1'))  # Chr() = ANSI byte value
    return strings


def main() -> None:
    ap = argparse.ArgumentParser(description='Vanillatool string-table deobfuscator')
    ap.add_argument('script', help='decompiled script.au3')
    ap.add_argument('table', help='string table (.tbl)')
    ap.add_argument('--decoder', required=True, help='decoder func name, e.g. A0200001905')
    ap.add_argument('--delim', required=True, help="table delimiter, e.g. '!3{'")
    ap.add_argument('--out', required=True, help='output deobfuscated script')
    ap.add_argument('--strings', required=True, help='output decoded-strings list')
    args = ap.parse_args()

    strings = load_table(args.table, args.delim.encode())
    print(f'[+] table: {len(strings)} strings', file=sys.stderr)
    by_index = {i + 1: s for i, s in enumerate(strings)}

    src = open(args.script, encoding='utf-8').read()
    dec = re.escape(args.decoder)

    # 1. Map $VAR -> table index from "$V = DECODER ( $OS [ N ] )" initialisers.
    varmap: dict[str, int] = {}
    multi = 0
    for m in re.finditer(
        r'(\$[A-Za-z0-9_]+)\s*=\s*' + dec + r'\s*\(\s*\$OS\s*\[\s*(\d+)\s*\]\s*\)', src
    ):
        var, idx = m.group(1), int(m.group(2))
        if var in varmap:
            multi += 1
        else:
            varmap[var] = idx
    print(f'[+] var->index map: {len(varmap)} vars ({multi} multi-assigned, first wins)',
          file=sys.stderr)

    # 2. Fold ChrW ( Number ( $VAR ) ) chains (table-driven URLs).
    unit = r'ChrW\s*\(\s*Number\s*\(\s*(\$[A-Za-z0-9_]+)\s*\)\s*\)'
    chain_re = re.compile(r'(?:' + unit + r'\s*&\s*){3,}' + unit)
    folded = 0

    def fold_var_chain(m: re.Match) -> str:
        nonlocal folded
        vars_ = re.findall(unit, m.group(0))
        chars = []
        for v in vars_:
            idx = varmap.get(v)
            if idx is None or idx not in by_index:
                return m.group(0)  # unresolvable: leave as-is
            num = by_index[idx].strip()
            if not num.isdigit():
                return m.group(0)
            chars.append(chr(int(num)))
        folded += 1
        return au3_quote(''.join(chars))

    src = chain_re.sub(fold_var_chain, src)
    print(f'[+] folded {folded} table-driven ChrW chains', file=sys.stderr)

    # 3. Fold plain ChrW(num) chains (defence in depth; none observed in v11.31).
    punit = r'ChrW\s*\(\s*(\d+)\s*\)'
    pchain_re = re.compile(r'(?:' + punit + r'\s*&\s*){3,}' + punit)
    pfolded = 0

    def fold_plain_chain(m: re.Match) -> str:
        nonlocal pfolded
        pfolded += 1
        return au3_quote(''.join(chr(int(n)) for n in re.findall(punit, m.group(0))))

    src = pchain_re.sub(fold_plain_chain, src)
    print(f'[+] folded {pfolded} plain ChrW chains', file=sys.stderr)

    # 4. Substitute DECODER ( $OS [ N ] ) -> "decoded".
    subbed, bad = 0, 0

    def sub_call(m: re.Match) -> str:
        nonlocal subbed, bad
        idx = int(m.group(1))
        if idx not in by_index:
            bad += 1
            return m.group(0)
        subbed += 1
        return au3_quote(by_index[idx])

    src = re.sub(dec + r'\s*\(\s*\$OS\s*\[\s*(\d+)\s*\]\s*\)', sub_call, src)
    print(f'[+] substituted {subbed} decoder calls ({bad} bad indices)', file=sys.stderr)

    open(args.out, 'w', encoding='utf-8').write(src)
    with open(args.strings, 'w', encoding='utf-8') as fh:
        for i, s in enumerate(strings, start=1):
            fh.write(f'{i}\t{s}\n')
    print(f'[+] wrote {args.out} ({len(src)} chars) and {args.strings}', file=sys.stderr)


if __name__ == '__main__':
    main()
