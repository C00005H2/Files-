"""Para's VanillaTool local service emulator.

Modules:

* ``protocol``  -- recovered auth request/response crypto (aN/aC/aH, ``C:…;``).
* ``account_manager`` -- Account Manager 5.43 pre-GUI marker fixture.
* ``offsets``   -- Offsets.txt body builder/validator for /Offsets.txt.
* ``server``    -- the HTTP service emulator (``python -m vanillatool_emulator.server``).
* ``mapper``    -- Account Manager driver-mapping CLI emulation
  (``python -m vanillatool_emulator.mapper``); kept out of this namespace
  because it doubles as a ``__main__``-style CLI entry point.
* ``crypto``    -- dependency-free AES-256-CBC codec used by ``protocol``.
* ``local``     -- Account Manager 5.43 local automation: settings hive,
  logins.ini, driver/DLL staging + patching, mapper ladder, NCGuard
  Game.dll prep, hosts redirect, server supervisor and one-click AutoFlow
  (``python -m vanillatool_emulator.local``); kept out of this namespace
  for the same ``__main__`` reason as ``mapper``.  The ``gui`` (tkinter
  desktop) and ``panel`` (browser) front-ends are thin wrappers over it.
"""

from .account_manager import (
    ACCOUNT_MANAGER_PROFILE_KEYS,
    BOOTSTRAP_MARKER_VALUE,
    account_manager_startup_response_text,
    missing_account_manager_profile_keys,
)
from .offsets import (
    PLACEHOLDER_VALUES,
    REQUIRED_KEYS,
    SECTION_NAME,
    build_offsets_text,
    load_offsets_file,
    parse_offsets_text,
    validate_offsets_text,
)
from .protocol import (
    CLIENT_IDENTIFIER,
    CRYPTO_IV,
    DEFAULT_STATIC_KEY,
    STATIC_KEY_SEED,
    AuthRequest,
    ProtocolError,
    auth_response_for,
    decrypt_client_field,
    decrypt_response,
    encrypt_client_field,
    encrypt_response,
    extract_response_ciphertext,
    inspect_response_profile,
    parse_auth_form,
    response_key,
    response_text,
)

__all__ = [
    # account_manager
    "ACCOUNT_MANAGER_PROFILE_KEYS",
    "BOOTSTRAP_MARKER_VALUE",
    "account_manager_startup_response_text",
    "missing_account_manager_profile_keys",
    # offsets
    "PLACEHOLDER_VALUES",
    "REQUIRED_KEYS",
    "SECTION_NAME",
    "build_offsets_text",
    "load_offsets_file",
    "parse_offsets_text",
    "validate_offsets_text",
    # protocol
    "CLIENT_IDENTIFIER",
    "CRYPTO_IV",
    "DEFAULT_STATIC_KEY",
    "STATIC_KEY_SEED",
    "AuthRequest",
    "ProtocolError",
    "auth_response_for",
    "decrypt_client_field",
    "decrypt_response",
    "encrypt_client_field",
    "encrypt_response",
    "extract_response_ciphertext",
    "inspect_response_profile",
    "parse_auth_form",
    "response_key",
    "response_text",
]
