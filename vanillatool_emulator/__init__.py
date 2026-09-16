"""Para's VanillaTool local service emulator."""

from .protocol import (
    CRYPTO_IV,
    DEFAULT_STATIC_KEY,
    AuthRequest,
    ProtocolError,
    auth_response_for,
    decrypt_client_field,
    decrypt_response,
    encrypt_client_field,
    encrypt_response,
    parse_auth_form,
)

# The mapper emulation lives in vanillatool_emulator.mapper and doubles as a
# ``python -m vanillatool_emulator.mapper`` CLI; import it explicitly instead
# of re-exporting it here so both entry points stay import-cycle free.

__all__ = [
    "CRYPTO_IV",
    "DEFAULT_STATIC_KEY",
    "AuthRequest",
    "ProtocolError",
    "auth_response_for",
    "decrypt_client_field",
    "decrypt_response",
    "encrypt_client_field",
    "encrypt_response",
    "parse_auth_form",
]

