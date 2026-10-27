from __future__ import annotations

import secrets
import struct
import unicodedata
from typing import Final

from argon2.low_level import Type, hash_secret_raw
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256


ARGON_TIME_COST: Final = 3
ARGON_MEMORY_COST_KIB: Final = 64 * 1024
ARGON_PARALLELISM: Final = 4
SALT_LENGTH: Final = 16
ITEM_SECRET_LENGTH: Final = 32
GCM_NONCE_LENGTH: Final = 12
GCM_TAG_LENGTH: Final = 16
ItemContext = tuple[str, str, str]


class IntegrityError(ValueError):
    """Raised when authenticated ciphertext verification fails."""


def new_salt() -> bytes:
    return secrets.token_bytes(SALT_LENGTH)


def new_item_secret() -> bytes:
    return secrets.token_bytes(ITEM_SECRET_LENGTH)


def _context_bytes(ctx: ItemContext) -> bytes:
    if not isinstance(ctx, tuple) or len(ctx) != 3:
        raise TypeError("ctx must be a tuple of user ID, item ID, and cipher")
    if not all(isinstance(part, str) for part in ctx):
        raise TypeError("ctx values must be strings")
    if not all(ctx):
        raise ValueError("ctx values must not be empty")

    return b"".join(
        struct.pack(">I", len(part_bytes)) + part_bytes
        for part_bytes in (part.encode("utf-8") for part in ctx)
    )


def wrap_secret(kek: bytes, item_secret: bytes, ctx: ItemContext) -> bytes:
    if not isinstance(kek, bytes):
        raise TypeError("kek must be bytes")
    if len(kek) != 32:
        raise ValueError("kek must be 32 bytes")
    if not isinstance(item_secret, bytes):
        raise TypeError("item_secret must be bytes")
    if len(item_secret) != ITEM_SECRET_LENGTH:
        raise ValueError(f"item_secret must be {ITEM_SECRET_LENGTH} bytes")

    cipher = AES.new(
        kek,
        AES.MODE_GCM,
        nonce=secrets.token_bytes(GCM_NONCE_LENGTH),
        mac_len=GCM_TAG_LENGTH,
    )
    cipher.update(_context_bytes(ctx))
    ciphertext, tag = cipher.encrypt_and_digest(item_secret)
    return cipher.nonce + ciphertext + tag


def unwrap_secret(kek: bytes, wrapped: bytes, ctx: ItemContext) -> bytes:
    if not isinstance(kek, bytes):
        raise TypeError("kek must be bytes")
    if len(kek) != 32:
        raise ValueError("kek must be 32 bytes")
    if not isinstance(wrapped, bytes):
        raise TypeError("wrapped must be bytes")
    expected_length = GCM_NONCE_LENGTH + ITEM_SECRET_LENGTH + GCM_TAG_LENGTH
    if len(wrapped) != expected_length:
        raise IntegrityError("wrapped secret has an invalid length")

    nonce = wrapped[:GCM_NONCE_LENGTH]
    ciphertext = wrapped[GCM_NONCE_LENGTH:-GCM_TAG_LENGTH]
    tag = wrapped[-GCM_TAG_LENGTH:]
    cipher = AES.new(kek, AES.MODE_GCM, nonce=nonce, mac_len=GCM_TAG_LENGTH)
    cipher.update(_context_bytes(ctx))
    try:
        return cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as exc:
        raise IntegrityError("wrapped secret failed authentication") from exc


def _password_to_bytes(password: str | bytes) -> bytes:
    if isinstance(password, str):
        return unicodedata.normalize("NFC", password).encode("utf-8")
    if isinstance(password, bytes):
        return password
    raise TypeError("password must be str or bytes")


def _check_salt(salt: bytes) -> None:
    if not isinstance(salt, bytes):
        raise TypeError("salt must be bytes")
    if len(salt) < SALT_LENGTH:
        raise ValueError(f"salt must be at least {SALT_LENGTH} bytes")


def derive_keys(password: str | bytes, salt: bytes) -> tuple[bytes, bytes]:
    password_bytes = _password_to_bytes(password)
    _check_salt(salt)

    master = hash_secret_raw(
        secret=password_bytes,
        salt=salt,
        time_cost=ARGON_TIME_COST,
        memory_cost=ARGON_MEMORY_COST_KIB,
        parallelism=ARGON_PARALLELISM,
        hash_len=32,
        type=Type.ID,
    )
    login_key = HKDF(
        master,
        32,
        salt=None,
        hashmod=SHA256,
        context=b"labaccess/login",
    )
    kek = HKDF(
        master,
        32,
        salt=None,
        hashmod=SHA256,
        context=b"labaccess/kek",
    )
    return login_key, kek
