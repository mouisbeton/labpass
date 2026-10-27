# File Purpose: In-memory KEK cache ("option B" in project-plan.md). After login the student's KEK
# is kept only in server RAM, looked up by a random session ID; the browser cookie holds just that ID.
# Entries expire after 15 minutes idle or 2 hours after login, whichever comes first.
# Related Files:
# - ./auth.py: calls create() at login, delete() at logout, delete_user() on consent withdrawal
# - ./app.py: reads the KEK with get() on upload and download

import secrets
import threading
import time

# A student is logged out after 15 minutes without a request,
# or 2 hours after logging in even if they stay active
IDLE_TIMEOUT = 15 * 60
ABSOLUTE_TIMEOUT = 2 * 60 * 60

# sid -> {"user_id", "kek" (bytearray), "created", "last_used"}
_entries = {}
# The app runs one worker with several threads, so every access goes through this lock
_lock = threading.Lock()
# Monotonic time never jumps backwards when the system clock changes; tests replace it
_clock = time.monotonic


# Overwrite the KEK with zeros (best effort: Python may still hold copies elsewhere)
def _wipe(entry):
    kek = entry["kek"]
    kek[:] = bytes(len(kek))


def _is_expired(entry, now):
    return (
        now - entry["last_used"] > IDLE_TIMEOUT
        or now - entry["created"] > ABSOLUTE_TIMEOUT
    )


# Remove every expired entry; the caller must hold _lock
def _purge_expired(now):
    for sid in [sid for sid, entry in _entries.items() if _is_expired(entry, now)]:
        _wipe(_entries.pop(sid))


# Store a new entry for a freshly logged-in student and return its random session ID
def create(user_id, kek):
    sid = secrets.token_urlsafe(32)
    now = _clock()
    with _lock:
        # Sessions that were abandoned without logout would otherwise keep their KEK in RAM forever
        _purge_expired(now)
        _entries[sid] = {
            "user_id": user_id,
            "kek": bytearray(kek),
            "created": now,
            "last_used": now,
        }
    return sid


# Return (user_id, kek) for a valid session ID, or None if it is unknown or expired
def get(sid):
    now = _clock()
    with _lock:
        entry = _entries.get(sid)
        if entry is None:
            return None

        if _is_expired(entry, now):
            # Remove it now so the KEK does not stay in RAM until the next logout
            _wipe(_entries.pop(sid))
            return None

        # Sliding idle timeout: every valid request restarts the 15-minute window
        entry["last_used"] = now
        # Return a copy so callers cannot change the stored KEK
        return entry["user_id"], bytes(entry["kek"])


# Remove one session (logout)
def delete(sid):
    with _lock:
        entry = _entries.pop(sid, None)
        if entry is not None:
            _wipe(entry)


# Remove every session of one student (consent withdrawal, password change)
def delete_user(user_id):
    with _lock:
        for sid in [sid for sid, entry in _entries.items() if entry["user_id"] == user_id]:
            _wipe(_entries.pop(sid))
