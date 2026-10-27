import struct

import pytest

import labcrypto.items as items_module
from labcrypto.items import (
    APP_CIPHERS,
    BENCHMARK_CIPHERS,
    CHUNK_SIZE,
    decrypt_item,
    encrypt_item,
)
from labcrypto.keys import IntegrityError, new_item_secret


CTX = ("student-1", "item-1", "aes-gcm")
TAG_LENGTHS = {"aes-gcm": 16, "aes-cbc": 32, "des-cbc": 32, "rc4": 32}
PREFIX_LENGTH = 4 + 16
HEADER_LENGTH = 9


@pytest.fixture(params=BENCHMARK_CIPHERS)
def cipher_name(request):
    return request.param


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
    [b"", b"hello", b"x" * 8, b"x" * CHUNK_SIZE, b"x" * (CHUNK_SIZE * 2), b"x" * (CHUNK_SIZE + 1)],
    ids=["empty", "small", "one-block", "one-chunk", "two-chunks", "one-chunk-plus-one"],
)
def test_item_round_trip(cipher_name, plaintext):
    item_secret = new_item_secret()
    ctx = ("student-1", "item-1", cipher_name)

    blob = encrypt_item(cipher_name, plaintext, item_secret, ctx)

    assert decrypt_item(cipher_name, blob, item_secret, ctx) == plaintext


@pytest.mark.parametrize("cipher_name", ["aes-cbc", "des-cbc", "rc4"])
def test_cbc_and_rc4_reject_tampered_tag(cipher_name):
    item_secret = new_item_secret()
    ctx = ("student-1", "item-1", cipher_name)
    blob = encrypt_item(cipher_name, b"private", item_secret, ctx)
    prefix, chunks = split_chunks(blob, TAG_LENGTHS[cipher_name])
    chunks[0][2][0] ^= 1

    with pytest.raises(IntegrityError):
        decrypt_item(cipher_name, join_chunks(prefix, chunks), item_secret, ctx)


@pytest.mark.parametrize("cipher_name", ["des-cbc", "aes-cbc"])
def test_cbc_verifies_before_decrypting(monkeypatch, cipher_name):
    item_secret = new_item_secret()
    ctx = ("student-1", "item-1", cipher_name)
    blob = encrypt_item(cipher_name, b"private", item_secret, ctx)
    prefix, chunks = split_chunks(blob, TAG_LENGTHS[cipher_name])
    iv_last_byte = 7 if cipher_name == "des-cbc" else 15
    chunks[0][1][iv_last_byte] ^= 1

    def fail_if_decrypted(*args, **kwargs):
        raise AssertionError("CBC decryption must not run before HMAC verification")

    if cipher_name == "des-cbc":
        monkeypatch.setattr(items_module.DES, "new", fail_if_decrypted)
    else:
        monkeypatch.setattr(items_module.AES, "new", fail_if_decrypted)
    with pytest.raises(IntegrityError):
        decrypt_item(cipher_name, join_chunks(prefix, chunks), item_secret, ctx)


def test_cipher_sets_separate_application_and_benchmark_ciphers():
    assert APP_CIPHERS == ("aes-gcm", "des-cbc", "rc4")
    assert BENCHMARK_CIPHERS == APP_CIPHERS + ("aes-cbc",)
    assert "aes-cbc" not in APP_CIPHERS


def test_wrong_context_and_secret_fail_authentication():
    item_secret = new_item_secret()
    blob = encrypt_item("aes-gcm", b"private", item_secret, CTX)

    with pytest.raises(IntegrityError):
        decrypt_item("aes-gcm", blob, item_secret, ("student-2", "item-1", "aes-gcm"))
    with pytest.raises(IntegrityError):
        decrypt_item("aes-gcm", blob, new_item_secret(), CTX)


def test_each_encryption_uses_a_fresh_hkdf_salt(cipher_name):
    item_secret = new_item_secret()
    ctx = ("student-1", "item-1", cipher_name)

    first = encrypt_item(cipher_name, b"private", item_secret, ctx)
    second = encrypt_item(cipher_name, b"private", item_secret, ctx)

    first_prefix, first_chunks = split_chunks(first, TAG_LENGTHS[cipher_name])
    second_prefix, second_chunks = split_chunks(second, TAG_LENGTHS[cipher_name])
    assert first_prefix != second_prefix
    assert first_chunks[0][1] != second_chunks[0][1]
    assert decrypt_item(cipher_name, first, item_secret, ctx) == b"private"
    assert decrypt_item(cipher_name, second, item_secret, ctx) == b"private"


def test_different_keys_per_chunk(cipher_name):
    item_secret = new_item_secret()
    ctx = ("student-1", "item-1", cipher_name)
    blob = encrypt_item(cipher_name, b"a" * (CHUNK_SIZE * 2), item_secret, ctx)
    _, chunks = split_chunks(blob, TAG_LENGTHS[cipher_name])

    assert chunks[0][1] != chunks[1][1]


def test_rc4_drops_3072_bytes_before_encrypting():
    item_secret = new_item_secret()
    ctx = ("student-1", "item-1", "rc4")
    blob = encrypt_item("rc4", bytes(100), item_secret, ctx)
    prefix, chunks = split_chunks(blob, TAG_LENGTHS["rc4"])
    key, _ = items_module._rc4_keys(item_secret, ctx, bytes(prefix[4:20]), 0)

    assert bytes(chunks[0][1]) == items_module.ARC4.new(key).encrypt(bytes(3072 + 100))[3072:]


def test_cipher_name_must_match_context():
    item_secret = new_item_secret()

    with pytest.raises(ValueError):
        encrypt_item("aes-gcm", b"private", item_secret, ("student-1", "item-1", "des-cbc"))

    blob = encrypt_item("aes-gcm", b"private", item_secret, CTX)
    with pytest.raises(ValueError) as excinfo:
        decrypt_item("aes-gcm", blob, item_secret, ("student-1", "item-1", "des-cbc"))
    assert type(excinfo.value) is ValueError


def test_reordered_chunks_fail(cipher_name):
    item_secret = new_item_secret()
    ctx = ("student-1", "item-1", cipher_name)
    plaintext = b"a" * (CHUNK_SIZE * 2)
    blob = encrypt_item(cipher_name, plaintext, item_secret, ctx)

    prefix, chunks = split_chunks(blob, TAG_LENGTHS[cipher_name])
    reordered = join_chunks(prefix, [chunks[1], chunks[0]])

    with pytest.raises(IntegrityError):
        decrypt_item(cipher_name, reordered, item_secret, ctx)


def test_reordered_chunks_with_rewritten_headers_fail(cipher_name):
    item_secret = new_item_secret()
    ctx = ("student-1", "item-1", cipher_name)
    plaintext = b"a" * (CHUNK_SIZE * 2)
    blob = encrypt_item(cipher_name, plaintext, item_secret, ctx)

    prefix, chunks = split_chunks(blob, TAG_LENGTHS[cipher_name])
    chunks[0], chunks[1] = chunks[1], chunks[0]
    struct.pack_into(">IBI", chunks[0][0], 0, 0, 0, len(chunks[0][1]))
    struct.pack_into(">IBI", chunks[1][0], 0, 1, 1, len(chunks[1][1]))

    with pytest.raises(IntegrityError):
        decrypt_item(cipher_name, join_chunks(prefix, chunks), item_secret, ctx)


def test_flipped_body_byte_fails(cipher_name):
    item_secret = new_item_secret()
    ctx = ("student-1", "item-1", cipher_name)
    blob = encrypt_item(cipher_name, b"a" * CHUNK_SIZE, item_secret, ctx)
    prefix, chunks = split_chunks(blob, TAG_LENGTHS[cipher_name])
    chunks[0][1][0] ^= 1

    with pytest.raises(IntegrityError):
        decrypt_item(cipher_name, join_chunks(prefix, chunks), item_secret, ctx)


def test_blob_cannot_be_swapped_between_students(cipher_name):
    item_secret = new_item_secret()
    ctx = ("student-1", "item-1", cipher_name)
    blob = encrypt_item(cipher_name, b"private", item_secret, ctx)

    with pytest.raises(IntegrityError):
        decrypt_item(
            cipher_name,
            blob,
            new_item_secret(),
            ("student-2", "item-1", cipher_name),
        )


def test_deleted_final_chunk_fails(cipher_name):
    item_secret = new_item_secret()
    ctx = ("student-1", "item-1", cipher_name)
    blob = encrypt_item(cipher_name, b"a" * (CHUNK_SIZE + 1), item_secret, ctx)
    prefix, chunks = split_chunks(blob, TAG_LENGTHS[cipher_name])

    with pytest.raises(IntegrityError, match="no final chunk"):
        decrypt_item(cipher_name, join_chunks(prefix, chunks[:-1]), item_secret, ctx)


def test_deleted_final_chunk_with_moved_last_flag_fails(cipher_name):
    item_secret = new_item_secret()
    ctx = ("student-1", "item-1", cipher_name)
    blob = encrypt_item(cipher_name, b"a" * (CHUNK_SIZE * 2) + b"b", item_secret, ctx)
    prefix, chunks = split_chunks(blob, TAG_LENGTHS[cipher_name])
    chunks[1][0][4] = 1

    with pytest.raises(IntegrityError):
        decrypt_item(cipher_name, join_chunks(prefix, chunks[:2]), item_secret, ctx)


def test_non_final_chunk_must_have_full_chunk_length(cipher_name):
    item_secret = new_item_secret()
    ctx = ("student-1", "item-1", cipher_name)
    blob = encrypt_item(cipher_name, b"a" * (CHUNK_SIZE + 1), item_secret, ctx)
    prefix, chunks = split_chunks(blob, TAG_LENGTHS[cipher_name])
    chunks[0][1] = chunks[0][1][:-8]
    struct.pack_into(">I", chunks[0][0], 5, len(chunks[0][1]))

    with pytest.raises(IntegrityError, match="invalid chunk length"):
        decrypt_item(cipher_name, join_chunks(prefix, chunks), item_secret, ctx)
