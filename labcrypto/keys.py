from __future__ import annotations

import secrets
import unicodedata
from typing import Final

from argon2.low_level import Type, hash_secret_raw
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256


_ARGON_TIME_COST: Final = 3
_ARGON_MEMORY_COST_KIB: Final = 64 * 1024
_ARGON_PARALLELISM: Final = 4
_MASTER_LENGTH: Final = 32
_DERIVED_KEY_LENGTH: Final = 32
_SALT_LENGTH: Final = 16
_MIN_SALT_LENGTH: Final = _SALT_LENGTH


def new_salt() -> bytes:
    return secrets.token_bytes(_SALT_LENGTH)


def _password_to_bytes(password: str | bytes) -> bytes:
    if isinstance(password, str):
        return unicodedata.normalize("NFC", password).encode("utf-8")
    if isinstance(password, bytes):
        return password
    raise TypeError("password must be str or bytes")


def _check_salt(salt: bytes) -> None:
    if not isinstance(salt, bytes):
        raise TypeError("salt must be bytes")
    if len(salt) < _MIN_SALT_LENGTH:
        raise ValueError(f"salt must be at least {_MIN_SALT_LENGTH} bytes")


def derive_keys(password: str | bytes, salt: bytes) -> tuple[bytes, bytes]:
    password_bytes = _password_to_bytes(password)
    _check_salt(salt)

    master = hash_secret_raw(
        secret=password_bytes,
        salt=salt,
        time_cost=_ARGON_TIME_COST,
        memory_cost=_ARGON_MEMORY_COST_KIB,
        parallelism=_ARGON_PARALLELISM,
        hash_len=_MASTER_LENGTH,
        type=Type.ID,
    )
    login_key = HKDF(
        master,
        _DERIVED_KEY_LENGTH,
        salt=None,
        hashmod=SHA256,
        context=b"labaccess/login",
    )
    kek = HKDF(
        master,
        _DERIVED_KEY_LENGTH,
        salt=None,
        hashmod=SHA256,
        context=b"labaccess/kek",
    )
    return login_key, kek
