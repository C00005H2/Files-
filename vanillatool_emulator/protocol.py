"""Para's VanillaTool request/response protocol helpers.

The extracted AutoIt client uses the following wire format:

* ``aN`` is the AES ciphertext of the machine identity prefix.
* ``aU`` is an executable/build value.
* ``aH`` is the first eight characters of the Unix timestamp.
* ``aC`` is the AES ciphertext of ``CPU_ID:BIOS_SERIAL``.
* ``aV`` is the client version.
* The response contains ``C:<hex-ciphertext>;``.  Its decrypted text is
  matched for ``ORythm=...`` and ``PRythm=...``.

The values below are recovered from the executable's CryptoAPI wrapper.
``A61CA706314`` reads the binary *inner* executable produced by the outer
loader.  AutoIt's binary-to-string conversion exposes hexadecimal text, so
its ``StringTrimLeft(..., 1602)`` selects byte offset 800.  The first fifteen
selected bytes are decremented by one to form the seed used twice in the
32-byte AES key.  Keeping the derived bytes here (rather than the old
placeholder ``00 01 ... 0e``) is important: it is what makes the emulator
interoperate with live ``aN`` and ``aC`` fields from 11.31.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Mapping
from urllib.parse import parse_qs

from .crypto import decrypt, encrypt

# At byte offset 800 in the extracted inner PE, A61CA706314 sees:
#     49 6c 31 79 50 31 50 31 31 47 47 32 31 50 50 00
# A211751270D applies Chr(byte - 1) to the first fifteen bytes, yielding
# ``Hk0xO0O00FF10OO``.  The source then inserts a literal ``0`` between two
# copies of that 15-byte seed.
STATIC_KEY_SEED = b"Hk0xO0O00FF10OO"
DEFAULT_STATIC_KEY = STATIC_KEY_SEED + b"0" + STATIC_KEY_SEED + b"0"
CRYPTO_IV = b"9324463837711294"
# A04BAF03F31 reverses the four bytes at the next marker and returns this
# decimal client/build identifier as aU.  The server does not need to reject
# other aU values, but exposing the recovered value makes fixtures faithful.
CLIENT_IDENTIFIER = "781769"

_AUTH_MARKER = re.compile(r"C:(.*?);")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_PROFILE_ASSIGNMENT = re.compile(r"^(?P<prefix>[%_]?)(?P<name>[A-Za-z][A-Za-z0-9_]*)=(?P<value>.*)$")
_PROFILE_FEATURE_HINTS = {
    # These names are the first memory fields used by the extracted client;
    # the diagnostic is intentionally a presence check, not an offset parser.
    "inject": ("Name",),
    "profile_validation": ("%ProfileName",),
    "radar": ("Users", "RadarZoom", "RadarRotation", "RadarViewAngle"),
    "target_info": ("TargetName", "TargetID"),
    "script_memory": ("SkillCDASM", "SkillActive"),
}


class ProtocolError(ValueError):
    """Raised when a client field cannot be decoded."""


@dataclass(frozen=True)
class AuthRequest:
    """Parsed values from an auth form submission."""

    a_n: str
    a_u: str
    a_h: str
    a_c: str
    a_v: str
    extra: Mapping[str, str]

    @property
    def timestamp(self) -> str:
        # The client always sends eight characters.  Being permissive here is
        # useful for hand-authored fixtures while keeping the response key 32
        # bytes long.
        return (self.a_h or "0" * 8)[:8].ljust(8, "0")


def parse_auth_form(body: bytes | str) -> AuthRequest:
    """Parse an ``application/x-www-form-urlencoded`` auth body."""
    if isinstance(body, bytes):
        body = body.decode("ascii", errors="replace")
    values = parse_qs(body, keep_blank_values=True, strict_parsing=False)

    def one(name: str) -> str:
        return values.get(name, [""])[-1]

    known = {"aN", "aU", "aH", "aC", "aV", "aR"}
    return AuthRequest(
        a_n=one("aN"),
        a_u=one("aU"),
        a_h=one("aH"),
        a_c=one("aC"),
        a_v=one("aV"),
        extra={key: items[-1] for key, items in values.items() if key not in known},
    )


def _ciphertext_from_field(value: str) -> bytes:
    value = value[2:] if value.lower().startswith("0x") else value
    if not value or len(value) % 2 or not _HEX_RE.fullmatch(value):
        raise ProtocolError("field is not an even-length hexadecimal ciphertext")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:  # pragma: no cover - guarded by the regex
        raise ProtocolError("field is not hexadecimal") from exc


def decrypt_client_field(value: str, static_key: bytes = DEFAULT_STATIC_KEY) -> bytes:
    """Decrypt an ``aN``/``aC`` field with the executable's static key."""
    try:
        return decrypt(_ciphertext_from_field(value), static_key, CRYPTO_IV)
    except (ValueError, TypeError) as exc:
        raise ProtocolError(f"unable to decrypt client field: {exc}") from exc


def encrypt_client_field(value: bytes | str, static_key: bytes = DEFAULT_STATIC_KEY) -> str:
    """Create a hex field in the same form as AutoIt's ``0x`` binary value."""
    if isinstance(value, str):
        value = value.encode("latin-1")
    # AutoIt's string representation of a Binary value uses upper-case
    # hexadecimal digits.  Hex case is not cryptographic, but matching it
    # keeps generated request fixtures byte-for-byte faithful on the wire.
    return encrypt(value, static_key, CRYPTO_IV).hex().upper()


def response_key(timestamp: str, identity_prefix: bytes | str) -> bytes:
    """Build the per-request 32-byte response key used by A161AC04848."""
    if isinstance(identity_prefix, str):
        identity_prefix = identity_prefix.encode("latin-1")
    # A608 pads the first identity component with O to 24 characters before
    # encrypting it.  A161 then takes StringLeft(timestamp + identity, 32).
    identity_prefix = identity_prefix[:24].ljust(24, b"O")
    return timestamp[:8].ljust(8, "0").encode("ascii") + identity_prefix


def encrypt_response(plaintext: bytes | str, timestamp: str, identity_prefix: bytes | str) -> str:
    """Encrypt an auth response and return the hex payload for ``C:...;``."""
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("latin-1")
    return encrypt(plaintext, response_key(timestamp, identity_prefix), CRYPTO_IV).hex().upper()


def decrypt_response(value: str, timestamp: str, identity_prefix: bytes | str) -> bytes:
    """Decode a response fixture using the client's dynamic key."""
    try:
        return decrypt(_ciphertext_from_field(value), response_key(timestamp, identity_prefix), CRYPTO_IV)
    except (ValueError, TypeError) as exc:
        raise ProtocolError(f"unable to decrypt response: {exc}") from exc


def inspect_response_profile(plaintext: str | None) -> dict[str, object]:
    """Return safe diagnostics for the decrypted client response.

    The live client uses capability markers and a separate line-oriented
    offset profile.  The emulator must not expose profile values in health
    output because they are process-memory addresses; this function reports
    only presence, counts, and blockers.
    """
    if plaintext is None:
        return {
            "status": "missing",
            "line_count": 0,
            "offset_key_count": 0,
            "prefix_counts": {},
            "missing_for_inject": ["Name"],
            "missing_profile_key": True,
            "feature_hints": {name: "blocked" for name in _PROFILE_FEATURE_HINTS},
            "warnings": ["no decrypted auth response is configured"],
        }

    assignments: dict[str, str] = {}
    prefix_counts: dict[str, int] = {}
    malformed: list[str] = []
    lines = plaintext.splitlines()
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("ORythm=") or line.startswith("PRythm="):
            continue
        match = _PROFILE_ASSIGNMENT.match(line)
        if not match:
            # Capability markers may share one semicolon-delimited line; only
            # report non-empty lines that look like profile data but cannot be
            # parsed as assignments.
            if "=" in line:
                malformed.append(line.split("=", 1)[0][:64])
            continue
        prefix = match.group("prefix")
        name = match.group("name")
        key = prefix + name
        assignments[key] = match.group("value").strip()
        prefix_counts[prefix or "plain"] = prefix_counts.get(prefix or "plain", 0) + 1

    present = set(assignments)
    missing_for_inject = [key for key in ("Name",) if key not in present or not assignments[key]]
    feature_hints: dict[str, str] = {}
    for feature, keys in _PROFILE_FEATURE_HINTS.items():
        missing = [key for key in keys if key not in present or not assignments.get(key, "")]
        feature_hints[feature] = "ready" if not missing else "missing: " + ", ".join(missing)

    warnings: list[str] = []
    if missing_for_inject:
        warnings.append("the client cannot calculate the target Name address; Inject will retry and then fail")
    if "%ProfileName" not in present:
        warnings.append("the region-specific ProfileName offset is absent")
    if malformed:
        warnings.append(f"{len(malformed)} non-empty profile line(s) could not be parsed")

    return {
        "status": "offset-profile" if not missing_for_inject else "capabilities-only",
        "line_count": len(lines),
        "offset_key_count": len(assignments),
        "prefix_counts": prefix_counts,
        "missing_for_inject": missing_for_inject,
        "missing_profile_key": "%ProfileName" not in present,
        "feature_hints": feature_hints,
        "warnings": warnings,
    }


def response_text(orythm: str = "1", prythm: str = "1") -> str:
    """Return a minimal positive fixture understood by A608AD0635E."""
    return f"ORythm={orythm};PRythm={prythm};"


def auth_response_for(
    request: AuthRequest,
    *,
    orythm: str = "1",
    prythm: str = "1",
    static_key: bytes = DEFAULT_STATIC_KEY,
    plaintext: str | None = None,
) -> tuple[str, bytes | None]:
    """Make the ``C:<cipher>;`` response for a parsed auth request.

    The second return value is the decrypted identity, useful to callers for
    diagnostics.  It is ``None`` when ``aN`` was malformed; in that case the
    compatibility fallback uses an all-``O`` prefix so a hand-authored fixture
    still has a valid shape.
    """
    identity: bytes | None
    try:
        identity = decrypt_client_field(request.a_n, static_key)
    except ProtocolError:
        identity = None
    prefix = identity if identity is not None else b"O" * 24
    text = plaintext if plaintext is not None else response_text(orythm, prythm)
    return encrypt_response(text, request.timestamp, prefix), identity


def extract_response_ciphertext(response: str) -> str:
    """Extract the captured value from a raw server response."""
    match = _AUTH_MARKER.search(response)
    if not match:
        raise ProtocolError("response does not contain a C:<cipher>; marker")
    return match.group(1)
