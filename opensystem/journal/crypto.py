"""Journal encryption — the attack journal is encrypted at rest.

The journal is the owner's private record of every attack performed. To keep
it readable by the owner and unreadable to anyone else who obtains the
database file, the journal content is encrypted with AES-256-GCM. The key is
derived from the owner's password via PBKDF2-HMAC-SHA256.

- Encrypted values are stored as ``v1:<salt>:<nonce>:<ciphertext>`` (hex).
- A password verifier is stored separately so the engine can confirm the
  correct password without storing it.
"""

from __future__ import annotations

import hashlib
import hmac
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

PREFIX = "v1"
SALT_BYTES = 16
NONCE_BYTES = 12
KEY_BYTES = 32
PBKDF2_ITERATIONS = 600_000


class JournalLockedError(Exception):
    """Raised when journal content is read without the owner password."""


class JournalDecryptError(Exception):
    """Raised when a password cannot decrypt stored journal content."""


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_BYTES,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_value(plaintext: str, password: str) -> str:
    """Encrypt a single journal field with the owner password."""
    salt = os.urandom(SALT_BYTES)
    nonce = os.urandom(NONCE_BYTES)
    key = _derive_key(password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return f"{PREFIX}:{salt.hex()}:{nonce.hex()}:{ciphertext.hex()}"


def decrypt_value(payload: str, password: str) -> str:
    """Decrypt a single journal field, validating the password."""
    parts = payload.split(":")
    if len(parts) != 4 or parts[0] != PREFIX:
        raise JournalDecryptError("Malformed encrypted journal value.")
    _, salt_hex, nonce_hex, cipher_hex = parts
    try:
        salt = bytes.fromhex(salt_hex)
        nonce = bytes.fromhex(nonce_hex)
        ciphertext = bytes.fromhex(cipher_hex)
    except ValueError as exc:
        raise JournalDecryptError("Malformed encrypted journal value.") from exc
    key = _derive_key(password, salt)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    except Exception as exc:
        raise JournalDecryptError("Wrong password or corrupted journal.") from exc
    return plaintext.decode("utf-8")


def is_encrypted(value: str) -> bool:
    """Return True if a stored value is an encrypted payload."""
    return value.startswith(f"{PREFIX}:") and value.count(":") == 3


def make_verifier(password: str) -> tuple[str, str]:
    """Return (salt_hex, verifier_hex) to confirm the password later."""
    salt = os.urandom(SALT_BYTES)
    digest = _pbkdf2(password, salt)
    return salt.hex(), digest.hex()


def verify_password(password: str, salt_hex: str, verifier_hex: str) -> bool:
    """Return True if the password matches the stored verifier."""
    try:
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(verifier_hex)
    except ValueError:
        return False
    digest = _pbkdf2(password, salt)
    return hmac.compare_digest(digest, expected)


def _pbkdf2(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=KEY_BYTES,
    )
