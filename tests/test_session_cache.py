# File Purpose: Tests for session_cache.py (in-memory KEK cache): lookups, idle and absolute
# timeouts, deletion, KEK wiping, and purging of abandoned sessions. A fake clock replaces
# time.monotonic so timeouts can be tested without waiting.
# Related Files:
# - ../session_cache.py: the module under test

import pytest

import session_cache

KEK = b"k" * 32
MINUTE = 60


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


@pytest.fixture(autouse=True)
def clock(monkeypatch):
    # every test starts with an empty cache and a fake clock it can move forward
    fake = FakeClock()
    monkeypatch.setattr(session_cache, "_clock", fake)
    monkeypatch.setattr(session_cache, "_entries", {})
    return fake


# 1. A valid session returns (user_id, kek)
def test_valid_session_returns_user_id_and_kek():
    sid = session_cache.create("student-1", KEK)
    assert session_cache.get(sid) == ("student-1", KEK)


def test_get_returns_a_bytes_copy_of_the_kek():
    sid = session_cache.create("student-1", KEK)
    _, kek = session_cache.get(sid)
    assert isinstance(kek, bytes)


def test_create_stores_its_own_copy_of_the_kek():
    # wiping the caller's buffer after login must not wipe the cached KEK
    caller_kek = bytearray(KEK)
    sid = session_cache.create("student-1", caller_kek)
    caller_kek[:] = bytes(len(caller_kek))
    assert session_cache.get(sid) == ("student-1", KEK)


def test_session_ids_are_random_and_long():
    first = session_cache.create("student-1", KEK)
    second = session_cache.create("student-1", KEK)
    assert first != second
    assert len(first) >= 43  # token_urlsafe(32) gives 43 characters


# 2. An unknown ID returns None
@pytest.mark.parametrize("sid", ["does-not-exist", "", None])
def test_unknown_id_returns_none(sid):
    assert session_cache.get(sid) is None


# 3. 16 minutes idle means expired
def test_session_expires_after_16_minutes_idle(clock):
    sid = session_cache.create("student-1", KEK)
    clock.advance(16 * MINUTE)
    assert session_cache.get(sid) is None


def test_session_is_still_valid_after_14_minutes_idle(clock):
    sid = session_cache.create("student-1", KEK)
    clock.advance(14 * MINUTE)
    assert session_cache.get(sid) == ("student-1", KEK)


def test_activity_restarts_the_idle_window(clock):
    sid = session_cache.create("student-1", KEK)
    clock.advance(14 * MINUTE)
    assert session_cache.get(sid) is not None
    clock.advance(14 * MINUTE)  # 28 minutes since login, but only 14 since the last request
    assert session_cache.get(sid) == ("student-1", KEK)


def test_expired_session_is_removed_and_its_kek_wiped(clock):
    sid = session_cache.create("student-1", KEK)
    stored_kek = session_cache._entries[sid]["kek"]
    clock.advance(16 * MINUTE)

    session_cache.get(sid)

    assert sid not in session_cache._entries
    assert stored_kek == bytearray(len(KEK))


# 4. Active every 14 minutes but over 2 hours in total means expired
def test_session_expires_after_2_hours_even_if_active(clock):
    sid = session_cache.create("student-1", KEK)
    for _ in range(8):  # 8 x 14 = 112 minutes, still under 2 hours
        clock.advance(14 * MINUTE)
        assert session_cache.get(sid) is not None

    clock.advance(9 * MINUTE)  # 121 minutes after login
    assert session_cache.get(sid) is None


# 5. delete removes one session; delete_user removes only that user's sessions
def test_delete_removes_only_that_session():
    first = session_cache.create("student-1", KEK)
    second = session_cache.create("student-1", KEK)

    session_cache.delete(first)

    assert session_cache.get(first) is None
    assert session_cache.get(second) == ("student-1", KEK)


def test_delete_wipes_the_kek():
    sid = session_cache.create("student-1", KEK)
    stored_kek = session_cache._entries[sid]["kek"]
    session_cache.delete(sid)
    assert stored_kek == bytearray(len(KEK))


def test_delete_unknown_id_does_nothing():
    session_cache.delete("does-not-exist")


def test_delete_user_removes_only_that_users_sessions():
    a1 = session_cache.create("student-a", KEK)
    a2 = session_cache.create("student-a", KEK)
    b1 = session_cache.create("student-b", KEK)

    session_cache.delete_user("student-a")

    assert session_cache.get(a1) is None
    assert session_cache.get(a2) is None
    assert session_cache.get(b1) == ("student-b", KEK)


# 6. A new login purges old expired sessions
def test_new_login_purges_expired_sessions(clock):
    old = session_cache.create("student-1", KEK)
    old_kek = session_cache._entries[old]["kek"]
    clock.advance(16 * MINUTE)

    session_cache.create("student-2", KEK)

    assert old not in session_cache._entries
    assert old_kek == bytearray(len(KEK))
    assert len(session_cache._entries) == 1


def test_new_login_keeps_sessions_that_are_still_valid(clock):
    active = session_cache.create("student-1", KEK)
    clock.advance(5 * MINUTE)

    session_cache.create("student-2", KEK)

    assert session_cache.get(active) == ("student-1", KEK)
