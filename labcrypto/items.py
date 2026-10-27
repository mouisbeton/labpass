from __future__ import annotations

import secrets
import struct
import hmac
import hashlib
from typing import Final

from Crypto.Cipher import AES
from Crypto.Cipher import ARC4
from Crypto.Cipher import DES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Util.Padding import pad, unpad

from .keys import (
    GCM_TAG_LENGTH,
    ITEM_SECRET_LENGTH,
    IntegrityError,
    ItemContext,
    SALT_LENGTH,
    _context_bytes,
)


CHUNK_SIZE: Final = 1024 * 1024
APP_CIPHERS: Final = ("aes-gcm", "des-cbc", "rc4")
BENCHMARK_CIPHERS: Final = APP_CIPHERS + ("aes-cbc",)
_MAGIC: Final = b"LAC1"
_NONCE_LENGTH: Final = 12
_DES_IV_LENGTH: Final = 8
_AES_IV_LENGTH: Final = 16
_DES_BLOCK_SIZE: Final = 8
_AES_BLOCK_SIZE: Final = 16
_HMAC_LENGTH: Final = 32
_RC4_DROP_LENGTH: Final = 3072
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


def _des_keys(item_secret: bytes, ctx: ItemContext, salt: bytes, index: int) -> tuple[bytes, bytes]:
    material = HKDF(
        item_secret,
        8 + _HMAC_LENGTH,
        salt=salt,
        hashmod=SHA256,
        context=b"labaccess/des/" + _context_bytes(ctx) + index.to_bytes(8, "big"),
    )
    return material[:8], material[8:]


def _rc4_keys(item_secret: bytes, ctx: ItemContext, salt: bytes, index: int) -> tuple[bytes, bytes]:
    material = HKDF(
        item_secret,
        32 + _HMAC_LENGTH,
        salt=salt,
        hashmod=SHA256,
        context=b"labaccess/rc4/" + _context_bytes(ctx) + index.to_bytes(8, "big"),
    )
    return material[:32], material[32:]


def _aes_cbc_keys(
    item_secret: bytes, ctx: ItemContext, salt: bytes, index: int
) -> tuple[bytes, bytes]:
    material = HKDF(
        item_secret,
        32 + _HMAC_LENGTH,
        salt=salt,
        hashmod=SHA256,
        context=b"labaccess/aes-cbc/" + _context_bytes(ctx) + index.to_bytes(8, "big"),
    )
    return material[:32], material[32:]


def _rc4_crypt(key: bytes, data: bytes) -> bytes:
    return ARC4.new(key, drop=_RC4_DROP_LENGTH).encrypt(data)


def _unpad(data: bytes, block_size: int) -> bytes:
    try:
        return unpad(data, block_size)
    except ValueError as exc:
        raise IntegrityError("invalid padding") from exc


def encrypt_item(
    cipher_name: str,
    plaintext: bytes,
    item_secret: bytes,
    ctx: ItemContext,
) -> bytes:
    """Encrypt an item; use a new item secret for every write."""
    if cipher_name not in BENCHMARK_CIPHERS:
        raise ValueError("unsupported cipher")
    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes")
    _check_item_secret(item_secret)
    context = _context_bytes(ctx)
    if ctx[2] != cipher_name:
        raise ValueError("context cipher does not match cipher_name")
    salt = secrets.token_bytes(SALT_LENGTH)
    key = _item_key(item_secret, ctx, salt) if cipher_name == "aes-gcm" else None

    output = bytearray(_MAGIC + salt)
    plaintext_view = memoryview(plaintext)
    chunk_count = max(1, (len(plaintext_view) + CHUNK_SIZE - 1) // CHUNK_SIZE)

    for index in range(chunk_count):
        start = index * CHUNK_SIZE
        chunk = plaintext_view[start : start + CHUNK_SIZE]
        last = index == chunk_count - 1
        if cipher_name == "aes-gcm":
            header = struct.pack(_HEADER_FORMAT, index, int(last), len(chunk))
            aad = context + header
            nonce = index.to_bytes(_NONCE_LENGTH, "big")
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=GCM_TAG_LENGTH)
            cipher.update(aad)
            body, tag = cipher.encrypt_and_digest(chunk)
        elif cipher_name == "aes-cbc":
            aes_key, mac_key = _aes_cbc_keys(item_secret, ctx, salt, index)
            iv = secrets.token_bytes(_AES_IV_LENGTH)
            body = iv + AES.new(
                aes_key, AES.MODE_CBC, iv
            ).encrypt(pad(bytes(chunk), _AES_BLOCK_SIZE))
            header = struct.pack(_HEADER_FORMAT, index, int(last), len(body))
            aad = context + header
            tag = hmac.new(mac_key, aad + body, hashlib.sha256).digest()
        elif cipher_name == "des-cbc":
            des_key, mac_key = _des_keys(item_secret, ctx, salt, index)
            iv = secrets.token_bytes(_DES_IV_LENGTH)
            body = iv + DES.new(des_key, DES.MODE_CBC, iv).encrypt(pad(bytes(chunk), _DES_BLOCK_SIZE))
            header = struct.pack(_HEADER_FORMAT, index, int(last), len(body))
            aad = context + header
            tag = hmac.new(mac_key, aad + body, hashlib.sha256).digest()
        else:
            rc4_key, mac_key = _rc4_keys(item_secret, ctx, salt, index)
            body = _rc4_crypt(rc4_key, bytes(chunk))
            header = struct.pack(_HEADER_FORMAT, index, int(last), len(body))
            aad = context + header
            tag = hmac.new(mac_key, aad + body, hashlib.sha256).digest()
        output.extend(header)
        output.extend(body)
        output.extend(tag)
    return bytes(output)


def decrypt_item(
    cipher_name: str,
    blob: bytes,
    item_secret: bytes,
    ctx: ItemContext,
) -> bytes:
    if cipher_name not in BENCHMARK_CIPHERS:
        raise ValueError("unsupported cipher")
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
    key = _item_key(item_secret, ctx, salt) if cipher_name == "aes-gcm" else None
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
        if cipher_name in ("aes-gcm", "rc4") and (
            chunk_length > CHUNK_SIZE or (not last and chunk_length != CHUNK_SIZE)
        ):
            raise IntegrityError("blob has invalid chunk length")
        tag_length = GCM_TAG_LENGTH if cipher_name == "aes-gcm" else _HMAC_LENGTH
        if len(blob) - offset < chunk_length + tag_length:
            raise IntegrityError("blob has a truncated chunk")

        body = blob[offset : offset + chunk_length]
        offset += chunk_length
        tag = blob[offset : offset + tag_length]
        offset += tag_length
        if cipher_name == "aes-gcm":
            nonce = index.to_bytes(_NONCE_LENGTH, "big")
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=GCM_TAG_LENGTH)
            cipher.update(context + header)
            try:
                plaintext.extend(cipher.decrypt_and_verify(body, tag))
            except ValueError as exc:
                raise IntegrityError("chunk failed authentication") from exc
        elif cipher_name == "aes-cbc":
            if not last and len(body) != _AES_IV_LENGTH + CHUNK_SIZE + _AES_BLOCK_SIZE:
                raise IntegrityError("invalid chunk length")
            if len(body) < _AES_IV_LENGTH + _AES_BLOCK_SIZE or (
                len(body) - _AES_IV_LENGTH
            ) % _AES_BLOCK_SIZE:
                raise IntegrityError("invalid AES body length")
            if last and len(body) > _AES_IV_LENGTH + CHUNK_SIZE + _AES_BLOCK_SIZE:
                raise IntegrityError("invalid chunk length")
            aes_key, mac_key = _aes_cbc_keys(item_secret, ctx, salt, index)
            expected_tag = hmac.new(mac_key, context + header + body, hashlib.sha256).digest()
            if not hmac.compare_digest(tag, expected_tag):
                raise IntegrityError("chunk failed authentication")
            iv = body[:_AES_IV_LENGTH]
            decrypted = AES.new(
                aes_key, AES.MODE_CBC, iv
            ).decrypt(body[_AES_IV_LENGTH:])
            plaintext.extend(_unpad(decrypted, _AES_BLOCK_SIZE))
        elif cipher_name == "des-cbc":
            if len(body) < _DES_IV_LENGTH + _DES_BLOCK_SIZE or (len(body) - _DES_IV_LENGTH) % _DES_BLOCK_SIZE:
                raise IntegrityError("invalid DES body length")
            if not last and len(body) != _DES_IV_LENGTH + CHUNK_SIZE + _DES_BLOCK_SIZE:
                raise IntegrityError("invalid chunk length")
            if last and len(body) > _DES_IV_LENGTH + CHUNK_SIZE + _DES_BLOCK_SIZE:
                raise IntegrityError("invalid chunk length")
            des_key, mac_key = _des_keys(item_secret, ctx, salt, index)
            expected_tag = hmac.new(mac_key, context + header + body, hashlib.sha256).digest()
            if not hmac.compare_digest(tag, expected_tag):
                raise IntegrityError("chunk failed authentication")
            iv = body[:_DES_IV_LENGTH]
            decrypted = DES.new(des_key, DES.MODE_CBC, iv).decrypt(body[_DES_IV_LENGTH:])
            plaintext.extend(_unpad(decrypted, _DES_BLOCK_SIZE))
        else:
            rc4_key, mac_key = _rc4_keys(item_secret, ctx, salt, index)
            expected_tag = hmac.new(mac_key, context + header + body, hashlib.sha256).digest()
            if not hmac.compare_digest(tag, expected_tag):
                raise IntegrityError("chunk failed authentication")
            plaintext.extend(_rc4_crypt(rc4_key, body))

        expected_index += 1
        if last:
            if offset != len(blob):
                raise IntegrityError("data follows the final chunk")
            return bytes(plaintext)

    raise IntegrityError("blob has no final chunk")
