# Para's VanillaTool service emulator

This repository contains the original `Para's Vanillatool -Rework- 11.31.exe`
plus a small, dependency-free HTTP emulator for the remote services identified
in that executable. It emulates the service boundary only; it does not emulate
Aion, the injector, the game process, or the Windows registry/WMI calls.

## What is implemented

| Route | Behavior |
| --- | --- |
| `POST /data/auth.php` | Parses the `aN`, `aU`, `aH`, `aC`, and `aV` form fields and returns an encrypted `C:<payload>;` response containing positive `ORythm` and `PRythm` values. |
| `GET /Updateless/Version.txt` | Returns the configured version, `11.31` by default. |
| `GET`/`POST /Log/log.php` | Accepts telemetry and returns `OK`; requests can optionally be recorded as JSONL. |
| `GET`/`POST /POST/` and `GET /GET/` | Deterministic fixtures for the generic dynamic HTTP helper. The emulator deliberately does not proxy arbitrary URLs. |
| `GET /healthz` | Small JSON health/status response. |

The authentication codec mirrors the recovered CryptoAPI flow: AES-256-CBC,
PKCS#7 final-block padding, IV `9324463837711294`, and the executable's
static identity-field key. The response key is derived per request from the
8-character `aH` timestamp and the first 24 bytes of the decrypted identity.

## Run it

From the repository root:

```sh
python3 -m vanillatool_emulator --bind 0.0.0.0 --port 8080 --verbose
```

Useful options:

```text
--version VERSION             Version.txt fixture (default: 11.31)
--orythm VALUE                Positive ORythm value (default: 1)
--prythm VALUE                Positive PRythm value (default: 1)
--response TEXT               Complete decrypted auth response, if desired
--dynamic-response TEXT       Fixture for /POST/ and /GET/ (default: OK)
--log-file FILE               Append request diagnostics as JSONL
--static-key-hex HEX          Override the recovered 32-byte request key
--tls-cert FILE --tls-key FILE  Serve HTTPS with a supplied certificate
```

Check that it is alive:

```sh
curl http://127.0.0.1:8080/healthz
curl http://127.0.0.1:8080/Updateless/Version.txt
```

The extracted executable has hard-coded `https://subvanillatool.com` URLs, so
an ordinary HTTP listener is intended for protocol tests and for use behind a
local reverse proxy or test redirect. For a direct HTTPS setup, supply a PEM
certificate and key and place the emulator behind the DNS/hosts and TLS
configuration appropriate to the test machine. Do not use this as an
Internet-facing service: the positive auth fixture is intentionally a local
test policy, not a real license service.

## Tests

The test suite uses only the Python standard library:

```sh
python3 -m unittest discover -s tests -v
```

The protocol module can also be inspected without starting a server:

```sh
python3 - <<'PY'
from vanillatool_emulator.protocol import DEFAULT_STATIC_KEY, encrypt_client_field
print(DEFAULT_STATIC_KEY.hex())
print(encrypt_client_field("0123456789ABCDEF0123456789ABCDEF"))
PY
```
