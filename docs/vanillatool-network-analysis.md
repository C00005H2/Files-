# Para's VanillaTool 11.31 — network analysis

This note records the static analysis of the repository binary and the local
emulator in [`server_emulator/`](../server_emulator/). The emulator is an
offline test double: it never forwards a request to the Internet.

## Sample and extraction chain

The repository sample is `Para's Vanillatool -Rework- 11.31.exe`. The
application script was recovered outside the repository while analyzing the
EA06 AutoIt `SCRIPT` resource:

| Artifact | Result |
|---|---|
| reconstructed payload | `/tmp/dropped.exe`, PE32+ x64, 8,557,568 bytes |
| UPX-unpacked payload | `/tmp/dropped/vanilla-payload-unpacked.exe`, 9,307,648 bytes |
| extracted AutoIt source | `/tmp/ripped2/script.au3`, 9,671,596 bytes |
| obfuscation table | `/tmp/ripped2/main v6.75_Release_stripped.au3.tbl`, 91,164 entries |

The table decoder is not an assumption about the obfuscator. The extracted
source defines `A0200001905` as a loop over two-character chunks using
`Dec()`/`Chr()` (source around line 17,721), and `A0200001905_` initializes
`$OS` with `StringSplit(FileRead(table), '!3{', 1)` (around line 53,310).
`tools/decode_vanillatool_table.py` reproduces that operation without
executing AutoIt:

```sh
python3 tools/decode_vanillatool_table.py \
  /tmp/ripped2/main\ v6.75_Release_stripped.au3.tbl
python3 tools/decode_vanillatool_table.py \
  /tmp/ripped2/main\ v6.75_Release_stripped.au3.tbl --entry 72732
```

## Confirmed network surfaces

### VanillaTool service host

The table contains these application-owned HTTP targets:

| Target | Evidence / use |
|---|---|
| `http://subvanillatool.com/POST/` | command interpreter strings for `_HTTPPost` (table entries 72717–72740; source in `A553A001251`, around lines 42,425–42,450) |
| `http://subvanillatool.com/Updates/Version.txt` | version/update check string (table entries 83706–83753; update code around source line 20,403) |
| `https://subvanillatool.com/data/resourceversion.txt` | resource update/version check (table entry 58576; function `A23F9000A37`, around line 4,603) |
| `https://subvanillatool.com/data/7za.exe` | resource archive helper (table entry 58551) |
| `http://subvanillatool.com/data/PIN/ImageSearchDLL.dll` | PIN helper download (table entry 69509) |
| `http://subvanillatool.com/data/PIN/0.bmp` through `9.bmp`, and `submit.bmp` | PIN image downloads (table entries 69512–69542; calls around lines 40,401–40,412) |
| `/data/mods/NoFlyAnimation/*.pak` | version-specific mod downloads; ten URLs are present in the table |
| `https://subvanillatool.com/data/chat.html` | browser launcher default in `A42CAC05E0B`, source line 86,727 |

The resource-version table also contains `7697274` repeatedly near entries
58578–58591. The emulator returns `7697274` from
`/data/resourceversion.txt` by default. Binary resources are **not** faked;
provide real test fixtures with `--fixture-dir` when the client must consume
an actual DLL, EXE, BMP, or PAK.

### Auth/update POST

The startup routine `A608AD0635E` (source around lines 20,403–20,506)
creates a `winhttp.winhttprequest.5.1` object and posts an
`application/x-www-form-urlencoded` request. The adjacent table strings name
these fields:

```text
aN=
&aU=
&aH=
&aC=
&aV=
```

The values are built from a local registry value, a machine/processor
fingerprint, a generated value, and helper routines that perform binary
encoding. A response is searched for patterns including:

```text
ORythm=([\-0-9]*)
PRythm=([\-0-9]*)
expired
```

The request body is therefore dynamic and should not be hard-coded into a
mock. The emulator accepts any body and returns `ORythm=0;PRythm=0` by
default; use `--auth-response` or `--auth-response-file` to test a specific
response. The recovered expression that constructs the URL evaluates to
`ttps://subvanillatool.com/data/auth.php` followed by U+00FF (`ÿ`) in the
stripped source (it starts at source line 2,307). Thus it has both a missing
leading `h` and a trailing non-ASCII byte; this is recorded as-is rather than
silently corrected. The emulator exposes both `/data/auth.php` and
`/auth.php` so a local redirect can test either interpretation.

### Script-command HTTP API

The embedded script interpreter recognizes these command forms:

```text
_HTTPPost=<comma-separated arguments>;
_HTTPGetVar=<comma-separated arguments>;
```

The table specifies the POST endpoint, the `POST` method, and
`Content-Type: application/x-www-form-urlencoded`. `_HTTPGetVar` also reads
`ResponseText` and applies a caller-provided regular expression. The command
handler is part of the large `A553A001251` function beginning around source
line 35,945. The emulator maps `/POST/`, `/POST`, and `/post/` to the configured
`--post-response` body and records the raw body plus parsed form fields in
JSONL when `--log` is supplied.

The stripped/decompiled command handler has several `Number()` operands whose
nearby table values are textual labels rather than numeric array indexes. As a
result, the exact argument ordering should be validated with a runtime trace
before claiming a fully compatible command protocol. The endpoint, method,
content type, command names, and response-regex behavior are directly
confirmed; the emulator intentionally treats the request body as opaque.

### Other HTTP dependencies

The string table also contains these third-party requests:

* `https://api.ipify.org`, `http://checkip.dyndns.org`,
  `http://www.myexternalip.com/raw`, and `http://bot.whatismyipaddress.com`
  are public-IP discovery fallbacks (table entries 27446–27449).
* `http://aioncodex.com/` and
  `https://aioncodex.com/query.php?a=items&type=drop&id=` support item/drop
  lookup (table entries 43439 and 43791).
* `http://i.epvpimg.com/SdZsh.jpg` is used as the chat-window image (table
  entry 85963).
* A Google Drive media URL appears at table entry 58606 as a resource archive
  source. Its query contains a key embedded in the sample; it is intentionally
  not reproduced here.

These are not required by the local emulator's core `/POST/`, auth, resource
version, and SMTP paths. They should be blocked or separately fixture-mapped
when doing a fully offline run.

### Captcha service

The table contains a separate 2Captcha flow:

* `2captcha.com:80`
* `http://2captcha.com/in.php`
* `http://2captcha.com/res.php?key=...&action=get&id=...`
* response patterns `OK\\|([0-9]+)` and `OK\\|([a-zA-Z0-9]+)`
* multipart fields including `file`, `method=base64`, and `key`

The source path is `A199A402352` around lines 47,623–47,724. As with the
auth flow, the stripped source has inconsistent-looking operand names in a
few calls, so this is an observed service dependency and payload vocabulary,
not proof that every branch is reachable in this build. The emulator offers
`/in.php` and `/res.php` for deterministic local tests and returns
`OK|<id>` / `OK|test-solution`.

### TCP/SMTP paths

There are two distinct TCP families:

1. `A2016F0371C` (around lines 33,425–33,800) is an SMTP-style client. It
   calls `TCPStartup`, resolves a host passed by its caller, connects to a
   caller-supplied port, then sends `HELO`/`EHLO`, `MAIL FROM`, `RCPT TO`, and
   `DATA`-style messages. The host, port, credentials, and message are not
   fixed constants in the visible routine; this is not a recovered VanillaTool
   service endpoint.
2. `A199A402352` uses a TCP connection as part of its 2Captcha upload path,
   followed by WinHTTP polling. The adjacent constants identify
   `2captcha.com` and port `80`.

The emulator's optional SMTP listener implements the first interaction for
safe local testing. It accepts the standard handshake, records messages, and
never delivers mail.

No separate Aion game-server hostname or game protocol was found in the
recovered script. The game-facing work is primarily process/memory/DLL
interaction (`VanillaEsp_v1.3.8.dll`, `GV.exe`, `FS.exe`, and
`GetThreads64.exe`), rather than a direct socket connection from this
script.

## Running the emulator

HTTP only, with a request log:

```sh
python3 server_emulator/vanillatool_emulator.py \
  --bind 127.0.0.1 --port 8080 \
  --log /tmp/vanillatool-network.jsonl
```

Useful local probes:

```sh
curl -i http://127.0.0.1:8080/healthz
curl -i http://127.0.0.1:8080/data/resourceversion.txt
curl -i -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'alpha=one&beta=two' http://127.0.0.1:8080/POST/
curl -i -X POST --data 'aN=test&aU=test' \
  http://127.0.0.1:8080/data/auth.php
```

With SMTP as well:

```sh
python3 server_emulator/vanillatool_emulator.py \
  --bind 127.0.0.1 --port 8080 --smtp-port 2525 \
  --log /tmp/vanillatool-network.jsonl
```

Use a fixture tree that mirrors URL paths for binary resources:

```text
fixtures/
└── data/
    ├── PIN/0.bmp
    └── mods/NoFlyAnimation/NA.pak
```

```sh
python3 server_emulator/vanillatool_emulator.py --fixture-dir ./fixtures
```

The sample hard-codes public hostnames. To redirect it to a local test
instance, use an isolated VM/container DNS or hosts-file mapping and an HTTP
proxy/redirect appropriate to the specific URL scheme. Do not change the
machine-wide hosts file on a production system, and do not expose this mock
beyond the analysis network. The default bind is loopback; `--bind
0.0.0.0` is available only when an intentionally exposed test preview is
needed.

## Validation

The dependency-free test suite covers resource/version responses, form-body
logging, fixture path containment, and the SMTP handshake:

```sh
python3 -m unittest discover -s server_emulator -p 'test_*.py' -v
```
