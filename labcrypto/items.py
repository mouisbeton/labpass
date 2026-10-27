from __future__ import annotations

import secrets
import struct
from typing import Final

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF

from .keys import (
    GCM_TAG_LENGTH,
    ITEM_SECRET_LENGTH,
    IntegrityError,
    ItemContext,
    SALT_LENGTH,
    _context_bytes,
)


CHUNK_SIZE: Final = 1024 * 1024
_MAGIC: Final = b"LAC1"
_NONCE_LENGTH: Final = 12
_HEADER_FORMAT: Final = ">IBI"
_HEADER_LENGTH: Final = struct.calcsize(_HEADER_FORMAT)


def _check_item_secret(item_secret: bytes) -> None:
    if not isinstance(item_secret, bytes):
        raise TypeError("item_secret must be bytes")
    if len(item_secret) != ITEM_SECRET_LENGTH:
        raise ValueError(f"item_secret must be {ITEM_SECRET_LENGTH} bytes")


def _item_key(item_secret: bytes, ctx: ItemContext, salt: bytes) -> bytes:
    return HKDF(
        item_secret,
        32,
        salt=salt,
        hashmod=SHA256,
        context=b"labaccess/item/" + _context_bytes(ctx),
    )


def encrypt_item(
    cipher_name: str,
    plaintext: bytes,
    item_secret: bytes,
    ctx: ItemContext,
) -> bytes:
    """Encrypt an item; use a new item secret for every write."""
    if cipher_name != "aes-gcm":
        raise ValueError("only aes-gcm is implemented")
    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes")
    _check_item_secret(item_secret)
    context = _context_bytes(ctx)
    if ctx[2] != cipher_name:
        raise ValueError("context cipher does not match cipher_name")
    salt = secrets.token_bytes(SALT_LENGTH)
    key = _item_key(item_secret, ctx, salt)

    output = bytearray(_MAGIC + salt)
    plaintext_view = memoryview(plaintext)
    chunk_count = max(1, (len(plaintext_view) + CHUNK_SIZE - 1) // CHUNK_SIZE)

    for index in range(chunk_count):
        start = index * CHUNK_SIZE
        chunk = plaintext_view[start : start + CHUNK_SIZE]
        last = index == chunk_count - 1
        body_length = len(chunk)
        header = struct.pack(_HEADER_FORMAT, index, int(last), body_length)
        aad = context + header
        nonce = index.to_bytes(_NONCE_LENGTH, "big")
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=GCM_TAG_LENGTH)
        cipher.update(aad)
        ciphertext, tag = cipher.encrypt_and_digest(chunk)
        output.extend(header)
        output.extend(ciphertext)
        output.extend(tag)
    return bytes(output)


def decrypt_item(
    cipher_name: str,
    blob: bytes,
    item_secret: bytes,
    ctx: ItemContext,
) -> bytes:
    if cipher_name != "aes-gcm":
        raise ValueError("only aes-gcm is implemented")
    if not isinstance(blob, bytes):
        raise TypeError("blob must be bytes")
    _check_item_secret(item_secret)
    if len(blob) < len(_MAGIC) + SALT_LENGTH or not blob.startswith(_MAGIC):
        raise IntegrityError("blob has an invalid header")

    context = _context_bytes(ctx)
    if ctx[2] != cipher_name:
        raise ValueError("context cipher does not match cipher_name")
    salt_start = len(_MAGIC)
    salt = blob[salt_start : salt_start + SALT_LENGTH]
    key = _item_key(item_secret, ctx, salt)
    offset = salt_start + SALT_LENGTH
    expected_index = 0
    plaintext = bytearray()

    while offset < len(blob):
        if len(blob) - offset < _HEADER_LENGTH:
            raise IntegrityError("blob has a truncated chunk header")
        header = blob[offset : offset + _HEADER_LENGTH]
        offset += _HEADER_LENGTH
        index, last, chunk_length = struct.unpack(_HEADER_FORMAT, header)
        if index != expected_index or last not in (0, 1):
            raise IntegrityError("blob has invalid chunk ordering")
        if chunk_length > CHUNK_SIZE or (not last and chunk_length != CHUNK_SIZE):
            raise IntegrityError("blob has invalid chunk length")
        if len(blob) - offset < chunk_length + GCM_TAG_LENGTH:
            raise IntegrityError("blob has a truncated chunk")

        ciphertext = blob[offset : offset + chunk_length]
        offset += chunk_length
        tag = blob[offset : offset + GCM_TAG_LENGTH]
        offset += GCM_TAG_LENGTH
        nonce = index.to_bytes(_NONCE_LENGTH, "big")
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=GCM_TAG_LENGTH)
        cipher.update(context + header)
        try:
            plaintext.extend(cipher.decrypt_and_verify(ciphertext, tag))
        except ValueError as exc:
            raise IntegrityError("chunk failed authentication") from exc

        expected_index += 1
        if last:
            if offset != len(blob):
                raise IntegrityError("data follows the final chunk")
            return bytes(plaintext)

    raise IntegrityError("blob has no final chunk")
