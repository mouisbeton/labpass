import struct

import pytest

from labcrypto.items import CHUNK_SIZE, decrypt_item, encrypt_item
from labcrypto.keys import IntegrityError, new_item_secret


CTX = ("student-1", "item-1", "aes-gcm")
TAG_LENGTHS = {"aes-gcm": 16, "des-cbc": 32, "rc4": 32}
PREFIX_LENGTH = 4 + 16
HEADER_LENGTH = 9


def split_chunks(blob, tag_length):
    prefix = blob[:PREFIX_LENGTH]
    chunks = []
    offset = PREFIX_LENGTH
    while offset < len(blob):
        header = blob[offset : offset + HEADER_LENGTH]
        _, _, body_length = struct.unpack(">IBI", header)
        body_start = offset + HEADER_LENGTH
        tag_start = body_start + body_length
        chunks.append([
            bytearray(header),
            bytearray(blob[body_start:tag_start]),
            bytearray(blob[tag_start : tag_start + tag_length]),
        ])
        offset = tag_start + tag_length
    return prefix, chunks


def join_chunks(prefix, chunks):
    return prefix + b"".join(bytes(part) for chunk in chunks for part in chunk)


@pytest.mark.parametrize(
    "plaintext",
    [b"", b"hello", b"x" * CHUNK_SIZE, b"x" * (CHUNK_SIZE * 2), b"x" * (CHUNK_SIZE + 1)],
)
def test_aes_gcm_item_round_trip(plaintext):
    item_secret = new_item_secret()

    blob = encrypt_item("aes-gcm", plaintext, item_secret, CTX)

    assert decrypt_item("aes-gcm", blob, item_secret, CTX) == plaintext


@pytest.mark.parametrize("plaintext", [b"", b"hello", b"x" * (CHUNK_SIZE + 1)])
def test_des_cbc_item_round_trip(plaintext):
    item_secret = new_item_secret()
    ctx = ("student-1", "item-1", "des-cbc")

    blob = encrypt_item("des-cbc", plaintext, item_secret, ctx)

    assert decrypt_item("des-cbc", blob, item_secret, ctx) == plaintext


def test_des_cbc_rejects_tampered_body_and_tag():
    item_secret = new_item_secret()
    ctx = ("student-1", "item-1", "des-cbc")
    blob = encrypt_item("des-cbc", b"private", item_secret, ctx)
    prefix, chunks = split_chunks(blob, TAG_LENGTHS["des-cbc"])

    chunks[0][1][8] ^= 1
    with pytest.raises(IntegrityError):
        decrypt_item("des-cbc", join_chunks(prefix, chunks), item_secret, ctx)

    blob = encrypt_item("des-cbc", b"private", item_secret, ctx)
    prefix, chunks = split_chunks(blob, TAG_LENGTHS["des-cbc"])
    chunks[0][2][0] ^= 1
    with pytest.raises(IntegrityError):
        decrypt_item("des-cbc", join_chunks(prefix, chunks), item_secret, ctx)


def test_des_cbc_verifies_before_decrypting():
    item_secret = new_item_secret()
    ctx = ("student-1", "item-1", "des-cbc")
    blob = encrypt_item("des-cbc", b"private", item_secret, ctx)

    with pytest.raises(IntegrityError):
        decrypt_item("des-cbc", blob, new_item_secret(), ctx)


def test_wrong_context_and_secret_fail_authentication():
    item_secret = new_item_secret()
    blob = encrypt_item("aes-gcm", b"private", item_secret, CTX)

    with pytest.raises(IntegrityError):
        decrypt_item("aes-gcm", blob, item_secret, ("student-2", "item-1", "aes-gcm"))
    with pytest.raises(IntegrityError):
        decrypt_item("aes-gcm", blob, new_item_secret(), CTX)


def test_each_encryption_uses_a_fresh_hkdf_salt():
    item_secret = new_item_secret()

    first = encrypt_item("aes-gcm", b"private", item_secret, CTX)
    second = encrypt_item("aes-gcm", b"private", item_secret, CTX)

    first_prefix, first_chunks = split_chunks(first, TAG_LENGTHS["aes-gcm"])
    second_prefix, second_chunks = split_chunks(second, TAG_LENGTHS["aes-gcm"])
    assert first_prefix != second_prefix
    assert first_chunks[0][1] != second_chunks[0][1]
    assert decrypt_item("aes-gcm", first, item_secret, CTX) == b"private"
    assert decrypt_item("aes-gcm", second, item_secret, CTX) == b"private"


def test_cipher_name_must_match_context():
    item_secret = new_item_secret()

    with pytest.raises(ValueError):
        encrypt_item("aes-gcm", b"private", item_secret, ("student-1", "item-1", "des-cbc"))

    blob = encrypt_item("aes-gcm", b"private", item_secret, CTX)
    with pytest.raises(ValueError) as excinfo:
        decrypt_item("aes-gcm", blob, item_secret, ("student-1", "item-1", "des-cbc"))
    assert type(excinfo.value) is ValueError


def test_reordered_chunks_fail():
    item_secret = new_item_secret()
    plaintext = b"a" * (CHUNK_SIZE * 2)
    blob = encrypt_item("aes-gcm", plaintext, item_secret, CTX)

    prefix, chunks = split_chunks(blob, TAG_LENGTHS["aes-gcm"])
    reordered = join_chunks(prefix, [chunks[1], chunks[0]])

    with pytest.raises(IntegrityError):
        decrypt_item("aes-gcm", reordered, item_secret, CTX)


def test_reordered_chunks_with_rewritten_headers_fail():
    item_secret = new_item_secret()
    plaintext = b"a" * (CHUNK_SIZE * 2)
    blob = encrypt_item("aes-gcm", plaintext, item_secret, CTX)

    prefix, chunks = split_chunks(blob, TAG_LENGTHS["aes-gcm"])
    chunks[0], chunks[1] = chunks[1], chunks[0]
    struct.pack_into(">IBI", chunks[0][0], 0, 0, 0, len(chunks[0][1]))
    struct.pack_into(">IBI", chunks[1][0], 0, 1, 1, len(chunks[1][1]))

    with pytest.raises(IntegrityError):
        decrypt_item("aes-gcm", join_chunks(prefix, chunks), item_secret, CTX)


def test_flipped_body_byte_fails():
    item_secret = new_item_secret()
    blob = encrypt_item("aes-gcm", b"a" * CHUNK_SIZE, item_secret, CTX)
    prefix, chunks = split_chunks(blob, TAG_LENGTHS["aes-gcm"])
    chunks[0][1][0] ^= 1

    with pytest.raises(IntegrityError):
        decrypt_item("aes-gcm", join_chunks(prefix, chunks), item_secret, CTX)


def test_blob_cannot_be_swapped_between_students():
    item_secret = new_item_secret()
    blob = encrypt_item("aes-gcm", b"private", item_secret, CTX)

    with pytest.raises(IntegrityError):
        decrypt_item(
            "aes-gcm",
            blob,
            new_item_secret(),
            ("student-2", "item-1", "aes-gcm"),
        )


def test_deleted_final_chunk_fails():
    item_secret = new_item_secret()
    blob = encrypt_item("aes-gcm", b"a" * (CHUNK_SIZE + 1), item_secret, CTX)
    prefix, chunks = split_chunks(blob, TAG_LENGTHS["aes-gcm"])

    with pytest.raises(IntegrityError, match="no final chunk"):
        decrypt_item("aes-gcm", join_chunks(prefix, chunks[:-1]), item_secret, CTX)


def test_deleted_final_chunk_with_moved_last_flag_fails():
    item_secret = new_item_secret()
    blob = encrypt_item("aes-gcm", b"a" * (CHUNK_SIZE * 2) + b"b", item_secret, CTX)
    prefix, chunks = split_chunks(blob, TAG_LENGTHS["aes-gcm"])
    chunks[1][0][4] = 1

    with pytest.raises(IntegrityError):
        decrypt_item("aes-gcm", join_chunks(prefix, chunks[:2]), item_secret, CTX)


def test_non_final_chunk_must_have_full_chunk_length():
    item_secret = new_item_secret()
    blob = encrypt_item("aes-gcm", b"a" * (CHUNK_SIZE + 1), item_secret, CTX)
    prefix, chunks = split_chunks(blob, TAG_LENGTHS["aes-gcm"])
    chunks[0][1] = chunks[0][1][:-1]
    struct.pack_into(">I", chunks[0][0], 5, len(chunks[0][1]))

    with pytest.raises(IntegrityError, match="invalid chunk length"):
        decrypt_item("aes-gcm", join_chunks(prefix, chunks), item_secret, CTX)
