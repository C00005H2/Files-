# Vendored dependencies (offline kit)

## `autoit_ripper/` — version 1.2.0 (PyPI), vendored verbatim

Pure-Python AutoIt EA05/EA06/JB01 decompiler. Only the EA06 *resource-blob*
code path is used by `tools/ea06.py`:

- `parse_all(ByteStream(blob[0x18:]), AutoItVersion.EA06)`

Two runtime adaptations are applied by `tools/ea06.py` (the vendored copy
itself is **unmodified upstream**):

1. `MAX_SCRIPT_SIZE` is raised from 10 MB to 256 MB — the Vanillatool outer
   script uncompresses to ~17 MB and would otherwise trip the guard.
2. A stub `pefile` module is injected into `sys.modules`: `autoit_unpack.py`
   imports `pefile` at module scope, but the blob-parse path never calls it,
   so the real dependency is not needed (PE/resource parsing is hand-rolled
   in `tools/`).

No other third-party packages are required. Everything else is Python 3
stdlib (`lzma`, `struct`, `re`, …).
