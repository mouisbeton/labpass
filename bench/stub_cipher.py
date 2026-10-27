"""TEMPORARY stand-in for labcrypto.encrypt_item / decrypt_item.

Used only by the benchmark until person 1's real cipher module lands.
It follows the shape in project-plan.md (1 MiB chunks, per-chunk keys for
DES/RC4, HMAC-SHA256 checked before decrypting) so the harness can be
tested end to end, but it is NOT the app's crypto and its numbers must
never go in the report.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import struct

from Crypto.Cipher import AES, ARC4, DES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Util.Padding import pad, unpad

CHUNK_SIZE = 1024 * 1024
CIPHERS = ("aes-gcm", "des-cbc", "rc4", "aes-cbc")


class IntegrityError(ValueError):
    pass


def _ctx_bytes(ctx: tuple[str, str, str]) -> bytes:
    return b"".join(struct.pack(">I", len(p)) + p for p in (s.encode() for s in ctx))


def _hkdf(secret: bytes, length: int, label: bytes) -> bytes:
    return HKDF(secret, length, salt=None, hashmod=SHA256, context=label)


def _chunk_aad(ctxb: bytes, index: int, last: bool) -> bytes:
    return ctxb + struct.pack(">QB", index, int(last))


def _chunks(data: bytes):
    if not data:
        yield 0, b"", True
        return
    count = (len(data) + CHUNK_SIZE - 1) // CHUNK_SIZE
    for i in range(count):
        yield i, data[i * CHUNK_SIZE:(i + 1) * CHUNK_SIZE], i == count - 1


def _mac(key: bytes, *parts: bytes) -> bytes:
    return hmac.new(key, b"".join(parts), hashlib.sha256).digest()


def encrypt_item(cipher: str, plaintext: bytes, item_secret: bytes, ctx) -> bytes:
    if cipher not in CIPHERS:
        raise ValueError(f"unknown cipher {cipher!r}")
    ctxb = _ctx_bytes(ctx)
    label = b"stub/" + cipher.encode() + b"/" + ctxb
    out = []

    if cipher in ("aes-gcm", "aes-cbc"):
        item_keys = _hkdf(item_secret, 64, label)

    for i, chunk, last in _chunks(plaintext):
        aad = _chunk_aad(ctxb, i, last)
        if cipher == "aes-gcm":
            c = AES.new(item_keys[:32], AES.MODE_GCM, nonce=struct.pack(">4xQ", i))
            c.update(aad)
            ct, tag = c.encrypt_and_digest(chunk)
            rec = ct + tag
        elif cipher == "aes-cbc":
            iv = secrets.token_bytes(16)
            ct = AES.new(item_keys[:32], AES.MODE_CBC, iv).encrypt(pad(chunk, 16))
            rec = iv + ct + _mac(item_keys[32:], aad, iv, ct)
        elif cipher == "des-cbc":
            keys = _hkdf(item_secret, 40, label + struct.pack(">Q", i))
            iv = secrets.token_bytes(8)
            ct = DES.new(keys[:8], DES.MODE_CBC, iv).encrypt(pad(chunk, 8))
            rec = iv + ct + _mac(keys[8:], aad, iv, ct)
        else:  # rc4
            keys = _hkdf(item_secret, 48, label + struct.pack(">Q", i))
            ct = ARC4.new(keys[:16], drop=3072).encrypt(chunk)
            rec = ct + _mac(keys[16:], aad, ct)
        out.append(struct.pack(">I", len(rec)) + rec)
    return b"".join(out)


def decrypt_item(cipher: str, blob: bytes, item_secret: bytes, ctx) -> bytes:
    if cipher not in CIPHERS:
        raise ValueError(f"unknown cipher {cipher!r}")
    ctxb = _ctx_bytes(ctx)
    label = b"stub/" + cipher.encode() + b"/" + ctxb

    records, pos = [], 0
    while pos < len(blob):
        (n,) = struct.unpack_from(">I", blob, pos)
        records.append(blob[pos + 4:pos + 4 + n])
        pos += 4 + n
    if not records:
        raise IntegrityError("empty blob")

    if cipher in ("aes-gcm", "aes-cbc"):
        item_keys = _hkdf(item_secret, 64, label)

    out = []
    for i, rec in enumerate(records):
        aad = _chunk_aad(ctxb, i, i == len(records) - 1)
        if cipher == "aes-gcm":
            c = AES.new(item_keys[:32], AES.MODE_GCM, nonce=struct.pack(">4xQ", i))
            c.update(aad)
            try:
                out.append(c.decrypt_and_verify(rec[:-16], rec[-16:]))
            except ValueError as exc:
                raise IntegrityError("bad tag") from exc
            continue
        if cipher == "aes-cbc":
            mac_key, iv, ct = item_keys[32:], rec[:16], rec[16:-32]
        elif cipher == "des-cbc":
            keys = _hkdf(item_secret, 40, label + struct.pack(">Q", i))
            mac_key, iv, ct = keys[8:], rec[:8], rec[8:-32]
        else:
            keys = _hkdf(item_secret, 48, label + struct.pack(">Q", i))
            mac_key, iv, ct = keys[16:], b"", rec[:-32]
        if not hmac.compare_digest(_mac(mac_key, aad, iv, ct), rec[-32:]):
            raise IntegrityError("bad HMAC")
        if cipher == "aes-cbc":
            out.append(unpad(AES.new(item_keys[:32], AES.MODE_CBC, iv).decrypt(ct), 16))
        elif cipher == "des-cbc":
            out.append(unpad(DES.new(keys[:8], DES.MODE_CBC, iv).decrypt(ct), 8))
        else:
            out.append(ARC4.new(keys[:16], drop=3072).decrypt(ct))
    return b"".join(out)
