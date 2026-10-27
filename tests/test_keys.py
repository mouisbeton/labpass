import hashlib
import hmac

import pytest
from argon2.low_level import Type, hash_secret_raw

from labcrypto.keys import derive_keys, new_salt


SALT = b"0123456789abcdef"


def _hkdf_sha256(ikm: bytes, info: bytes, length: int = 32) -> bytes:
    """Independent RFC 5869 HKDF with an all-zero salt, using only the stdlib."""
    prk = hmac.new(b"\x00" * 32, ikm, hashlib.sha256).digest()
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def test_derive_keys_is_deterministic_for_same_password_and_salt():
    first = derive_keys("correct horse battery staple", SALT)
    second = derive_keys("correct horse battery staple", SALT)
    assert first == second


def test_derive_keys_returns_distinct_32_byte_keys():
    login_key, kek = derive_keys("password", SALT)
    assert len(login_key) == 32
    assert len(kek) == 32
    assert login_key != kek


def test_different_passwords_give_different_keys():
    first = derive_keys("password one", SALT)
    second = derive_keys("password two", SALT)
    assert first[0] != second[0]
    assert first[1] != second[1]


def test_different_salts_give_different_keys():
    first = derive_keys("password", b"0123456789abcdef")
    second = derive_keys("password", b"fedcba9876543210")
    assert first[0] != second[0]
    assert first[1] != second[1]


def test_matches_plan_parameters_and_labels():
    password = "correct horse battery staple"
    master = hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=SALT,
        time_cost=3,
        memory_cost=64 * 1024,
        parallelism=4,
        hash_len=32,
        type=Type.ID,
    )
    expected_login = _hkdf_sha256(master, b"labaccess/login")
    expected_kek = _hkdf_sha256(master, b"labaccess/kek")
    assert derive_keys(password, SALT) == (expected_login, expected_kek)


def test_known_answer_vector():
    login_key, kek = derive_keys("correct horse battery staple", SALT)
    assert login_key.hex() == (
        "5fd3cae38e5fdae15fc33e5017148ffcff2278ed0f3f2df8e9809c5e3b05f87d"
    )
    assert kek.hex() == (
        "c6c750a15fc5e2e8c5141b92ceea7b299b4006a7b08c920b4c62009f2df444b3"
    )


def test_password_string_and_utf8_bytes_are_equivalent():
    assert derive_keys("pässword", SALT) == derive_keys("pässword".encode(), SALT)


def test_string_passwords_are_normalized_to_nfc():
    composed = "pässword"
    decomposed = "pa\u0308ssword"
    assert derive_keys(composed, SALT) == derive_keys(decomposed, SALT)


def test_bytes_passwords_are_not_normalized():
    composed = "pässword".encode("utf-8")
    decomposed = "pa\u0308ssword".encode("utf-8")
    assert derive_keys(composed, SALT) != derive_keys(decomposed, SALT)


def test_new_salt_is_a_fresh_16_byte_value():
    first = new_salt()
    second = new_salt()
    assert isinstance(first, bytes)
    assert len(first) == 16
    assert len(second) == 16
    assert first != second


def test_new_salt_is_accepted_by_derive_keys():
    login_key, kek = derive_keys("password", new_salt())
    assert len(login_key) == 32
    assert len(kek) == 32


@pytest.mark.parametrize("salt", [b"a" * 16, b"a" * 32])
def test_derive_keys_accepts_salts_of_minimum_length_or_longer(salt):
    login_key, kek = derive_keys("password", salt)
    assert len(login_key) == 32
    assert len(kek) == 32


@pytest.mark.parametrize(
    ("password", "salt", "error"),
    [
        (123, SALT, TypeError),
        ("password", "0123456789abcdef", TypeError),
        ("password", b"", ValueError),
        ("password", b"123456789012345", ValueError),
    ],
)
def test_derive_keys_rejects_invalid_inputs(password, salt, error):
    with pytest.raises(error):
        derive_keys(password, salt)