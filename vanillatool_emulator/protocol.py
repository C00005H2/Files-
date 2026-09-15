"""Para's VanillaTool request/response protocol helpers.

The extracted AutoIt client uses the following wire format:

* ``aN`` is the AES ciphertext of the machine identity prefix.
* ``aU`` is an executable/build value.
* ``aH`` is the first eight characters of the Unix timestamp.
* ``aC`` is the AES ciphertext of ``CPU_ID:BIOS_SERIAL``.
* ``aV`` is the client version.
* The response contains ``C:<hex-ciphertext>;``.  Its decrypted text is
  matched for ``ORythm=...`` and ``PRythm=...``.

The constants below are recovered from the executable's CryptoAPI wrapper.
The key seed is derived from the 16 bytes at the wrapper's offset used by
``A61CA706314``.  In the supplied 11.31 executable those bytes are zero, so
its arithmetic produces the byte sequence 0..14.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Mapping
from urllib.parse import parse_qs

from .crypto import decrypt, encrypt

# A61CA706314 reads 16 pairs from the wrapper and A211751270D turns the first
# 15 into Chr(0)..Chr(14).  The two one-character separators are literal '0'.
DEFAULT_STATIC_KEY = bytes(range(15)) + b"0" + bytes(range(15)) + b"0"
CRYPTO_IV = b"9324463837711294"

_AUTH_MARKER = re.compile(r"C:(.*?);")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


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
    return encrypt(value, static_key, CRYPTO_IV).hex()


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
    return encrypt(plaintext, response_key(timestamp, identity_prefix), CRYPTO_IV).hex()


def decrypt_response(value: str, timestamp: str, identity_prefix: bytes | str) -> bytes:
    """Decode a response fixture using the client's dynamic key."""
    try:
        return decrypt(_ciphertext_from_field(value), response_key(timestamp, identity_prefix), CRYPTO_IV)
    except (ValueError, TypeError) as exc:
        raise ProtocolError(f"unable to decrypt response: {exc}") from exc


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
