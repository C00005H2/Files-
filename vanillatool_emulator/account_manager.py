"""Account Manager 5.43's pre-GUI response fixture.

The extracted Account Manager client performs a second request to the same
``/data/auth.php`` service used by VanillaTool.  Before it creates its main
window, it requires one syntactically valid ``0x...`` assignment for each
marker below.

This module intentionally supplies zero placeholders only.  They are enough
to exercise the local startup/parser boundary, but they are not real
build-specific memory offsets and must not be used for process-memory features.
A real build profile can still be supplied with ``--response-file``.
"""

from __future__ import annotations

import re


# These names are recovered from Account Manager's A40B8800356 response
# parser.  Keep the order stable so generated fixtures are easy to compare.
ACCOUNT_MANAGER_PROFILE_KEYS: tuple[str, ...] = (
    "UEU",
    "UNA",
    "UCL",
    "UCEU",
    "UEuroAion",
    "UAmerica",
    "UDestiny",
    "UGamez",
    "UNova",
    "UElden",
    "MEU",
    "MNA",
    "MCL",
    "MCEU",
    "MEuroAion",
    "MAmerica",
    "MDestiny",
    "MGamez",
    "MNova",
    "MElden",
    "CEU",
    "CNA",
    "CCL",
    "CCEU",
    "CEuroAion",
    "CAmerica",
    "CDestiny",
    "CGamez",
    "CNova",
    "CElden",
    "CSEU",
    "CSNA",
    "CSCL",
    "CSCEU",
    "CSEuroAion",
    "CSAmerica",
    "CSDestiny",
    "CSGamez",
    "CSNova",
    "CSElden",
    "LPEU",
    "LPNA",
    "LPCL",
    "LPCEU",
    "LPEuroAion",
    "LPAmerica",
    "LPDestiny",
    "LPGamez",
    "LPNova",
    "LPElden",
    "TSEU",
    "TSNA",
    "TSCL",
    "TSCEU",
    "TSEuroAion",
    "TSAmerica",
    "TSDestiny",
    "TSGamez",
    "TSNova",
    "TSElden",
)

# Deliberately not a real address.  The bootstrap mode is for GUI/parser
# testing only; it does not enable a usable target-memory profile.
BOOTSTRAP_MARKER_VALUE = "0x0"
_PROFILE_LINE = re.compile(r"^(?P<name>[A-Za-z][A-Za-z0-9_]*)=(?P<value>0x.*)$", re.MULTILINE)


def account_manager_startup_response_text(orythm: str = "1", prythm: str = "2") -> str:
    """Return a deterministic response that satisfies the pre-GUI parser.

    ``ORythm`` and ``PRythm`` are positive capability markers consumed by the
    first Account Manager request.  The remaining assignments satisfy the
    second request's presence checks with zero placeholders.  The response is
    plaintext; :func:`vanillatool_emulator.protocol.auth_response_for` wraps
    it in the encrypted ``C:<payload>;`` format per request.
    """
    if not re.fullmatch(r"[0-9]+", orythm):
        raise ValueError("orythm must contain decimal digits")
    if not re.fullmatch(r"[0-9]+", prythm):
        raise ValueError("prythm must contain decimal digits")
    lines = [f"ORythm={orythm};PRythm={prythm};"]
    lines.extend(f"{name}={BOOTSTRAP_MARKER_VALUE}" for name in ACCOUNT_MANAGER_PROFILE_KEYS)
    return "\n".join(lines) + "\n"


def missing_account_manager_profile_keys(plaintext: str | None) -> list[str]:
    """Return required Account Manager marker names absent from a response.

    Only names and presence are reported.  Values are intentionally not
    returned because real response profiles can contain process-memory
    addresses.
    """
    if plaintext is None:
        return list(ACCOUNT_MANAGER_PROFILE_KEYS)
    present = {match.group("name") for match in _PROFILE_LINE.finditer(plaintext)}
    return [name for name in ACCOUNT_MANAGER_PROFILE_KEYS if name not in present]
