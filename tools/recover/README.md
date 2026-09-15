# VanillaTool recovery pipeline

Static recovery tooling for `Para's Vanillatool -Rework- 11.31.exe`. It unwraps all
four layers of the product and produces readable AutoIt source, which is what
`analysis/vanillatool-injection.md` is based on.

```sh
pip install autoit-ripper pefile        # plus gcc on PATH (autodec.c)
python3 recover.py "path/to/Para's Vanillatool -Rework- 11.31.exe" /tmp/vt
```

Outputs in `/tmp/vt`:

| File | Content |
| --- | --- |
| `outer_image.bin` | UPX-decompressed outer loader image |
| `outer_script.au3` | outer loader stub (17,330 lines) — payload assembly, temp dir, args |
| `payload.bin` | inner PE, re-assembled from 8,558 hex chunks (8,557,568 B) |
| `inner_image.bin` | UPX-decompressed inner image |
| `inner_files/*` | all 17 `FileInstall` payloads: ESP DLL, helper exes, skills/zone INIs, `.tbl` |
| `inner_script.au3` | inner tool, SecureAu3-obfuscated (88,053 lines) |
| `inner_deob.au3` | pass 1: string-table / hex / `Execute` literals inlined |
| `inner_deob2.au3` | pass 2: per-function variable indirection folded (84,282 lines) |

## How each layer is undone

1. **UPX (method 14, LZMA).** `upx -d` cannot handle this pack; the packheader at
   `0x3e0` gives `method=14`, `u_len`, `c_len`, and the LZMA property byte lives at
   `UPX1+1` (dict size at `UPX1+0`). `upx_unpack()` rebuilds the raw filter
   (`dict_size=1<<24`, `lc=3`, `lp=0`, `pb=0`) and decompresses the image in place.
2. **AutoIt container.** `EA05`/`EA06` magic, 16-byte checksum, then `FILE` records
   with three XOR keys read from the stream. Entry contents are decrypted with
   `EA06Decryptor` and content key `0x2477` (= checksum `0` + `au3_ResContent`).
3. **Compressed entries.** Each is LAME-encrypted then LZSS-compressed with AutoIt's
   `StringCompress` variant. `autodec.c` reimplements both (key derivation from the
   content key, per-file LAME state, sliding-window LZSS) and prints the CRC/length
   it produced so the container's stored CRC can be validated.
4. **Token stream → source.** `autoit_ripper.opcodes.deassemble_script` renders the
   compiled AutoIt script.
5. **SecureAu3 obfuscation.** Two passes:
   * pass 1 resolves `A0200001905($OS[n])` against the shipped string table
     (`…stripped.au3.tbl`, 91,165 entries — note `StringSplit` is 1-based, so entry
     `n` is `parts[n-1]`, and every entry is *itself* hex-encoded, e.g.
     `204054656D7044697220` → `" @TempDir "`), inlines literal
     `A0200001905("hex")` calls, and unwraps nested
     `Execute(BinaryToString("0x…"))` blobs (up to 6 nesting levels).
   * pass 2 folds the `$AXXXX = "literal"` indirection. It is **scope aware**: a
     function-local map is merged over the file-scope map, function headers are never
     rewritten, and the `Global $A… = "…"` prologues plus
     `If Not IsDeclared("SS…")` guards are stripped. A global-only pass corrupts the
     code (identical generated variable names collide across functions), so do not
     "simplify" it.

## Caveats

* De-obfuscation is best-effort text transformation, not a compiler: residual
  artifacts remain (e.g. `Execute("2040…")` where a macro was reached through a
  variable, and generated `$A1F2…` identifiers instead of meaningful names).
* The recovered sources describe a cheat/hack tool. They are reproduced here only to
  explain the failure mode of the injection path; do not redistribute.

## Reference digests

Re-running `recover.py` must reproduce these:

```
5d1a3f4741ebc15c3747530081bd739787ddc69a3fbe2559b95e91bb331f0541  payload.bin
0fa848e9631e0957f82f56c39c5bbcaa09979745970180f10d556fc1bf382eea  inner_image.bin
d268231a7c27f5e5943c6717256d16cd0812e3e3bc31b1d5e6bbcf6efbf93761  inner_files/…VanillaEsp_v1.3.8.dll
a36157d0fe443efdd90e2ff6385481389785f5dd45a7768ea52085642b66c42e  inner_deob2.au3
```
