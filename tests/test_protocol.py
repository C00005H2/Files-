from __future__ import annotations

import unittest

from vanillatool_emulator.crypto import decrypt, encrypt
from vanillatool_emulator.protocol import (
    CRYPTO_IV,
    DEFAULT_STATIC_KEY,
    auth_response_for,
    decrypt_client_field,
    decrypt_response,
    encrypt_client_field,
    parse_auth_form,
    response_key,
)


class CryptoTests(unittest.TestCase):
    def test_aes_round_trip_for_empty_and_multiblock_messages(self) -> None:
        key = bytes(range(32))
        iv = bytes(range(16))
        for message in (b"", b"one block exactly", b"a" * 31, b"a" * 32, bytes(range(256))):
            with self.subTest(length=len(message)):
                self.assertEqual(decrypt(encrypt(message, key, iv), key, iv), message)

    def test_known_aes256_cbc_vector_against_openssl_shape(self) -> None:
        # AES-256-CBC, zero plaintext block, zero key/IV.  The expected value
        # includes the full-padding block produced by CryptoAPI final mode.
        key = bytes(32)
        iv = bytes(16)
        self.assertEqual(
            encrypt(bytes(16), key, iv).hex(),
            "dc95c078a2408989ad48a21492842087"
            "f3c003ddc4a7b8a94baedffc3d214c38",
        )


class ProtocolTests(unittest.TestCase):
    def test_static_request_field_round_trip(self) -> None:
        identity = b"65-66-67-68-69-70_1234567"
        encoded = encrypt_client_field(identity)
        self.assertEqual(decrypt_client_field(encoded), identity)

    def test_auth_response_uses_timestamp_and_identity_prefix(self) -> None:
        identity = b"01-02-03-04-05-06_7654321"
        padded = identity.ljust(24, b"O")
        request = parse_auth_form(
            "aN=" + encrypt_client_field(padded) + "&aU=fixture&aH=17123456&aC=x&aV=11.31"
        )
        ciphertext, decoded = auth_response_for(request)
        self.assertEqual(decoded, padded)
        self.assertEqual(decrypt_response(ciphertext, "17123456", padded), b"ORythm=1;PRythm=1;")
        self.assertEqual(response_key("17123456", padded), b"17123456" + padded[:24])

    def test_default_key_and_iv_are_the_recovered_sizes(self) -> None:
        self.assertEqual(len(DEFAULT_STATIC_KEY), 32)
        self.assertEqual(len(CRYPTO_IV), 16)


if __name__ == "__main__":
    unittest.main()
