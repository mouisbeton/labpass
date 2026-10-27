# File Purpose: Tests for the encrypted records in app.py (file metadata and personal data):
# nothing in plaintext, every copy opens, survives a password change, deleted with the file/user.
# Related Files:
# - ../app.py: save_record, load_record, upload/download/delete and /profile routes
# - ../database.py: records table; DB_PATH is redirected to a temporary file for every test
# - ../auth.py: change_password and delete_user_data handle the records rows too

import io
import json
import os
import sqlite3
import tempfile

import pytest

import database
import session_cache
import storage

# Importing app.py runs init_db, so point it at a throwaway file instead of the real labaccess.db
_real_db_path = database.DB_PATH
database.DB_PATH = os.path.join(tempfile.mkdtemp(), "import.db")
import app as app_module  # noqa: E402

database.DB_PATH = _real_db_path

import auth  # noqa: E402

PASSWORD = "rahasia-panjang-sekali"
NEW_PASSWORD = "kata-sandi-baru-panjang"
FILENAME = "ktm-scan-budi.pdf"
CONTENT = b"%PDF-1.4 fake ktm scan " * 1000
PROFILE = {"name": "Budi Santoso", "nrp": "5025211001", "phone": "081234567890", "email": "budi@example.com"}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setattr(storage, "BLOB_DIR", str(tmp_path / "blobs"))
    os.makedirs(storage.BLOB_DIR)
    monkeypatch.setattr(session_cache, "_entries", {})
    database.init_db()
    auth.init_auth_db()
    monkeypatch.setitem(app_module.app.config, "TESTING", True)
    monkeypatch.setitem(app_module.app.config, "WTF_CSRF_ENABLED", False)
    monkeypatch.setitem(app_module.app.config, "SESSION_COOKIE_SECURE", False)

    client = app_module.app.test_client()
    client.post("/register", data={
        "username": "kucing.oren",
        "password": PASSWORD,
        "password_confirm": PASSWORD,
        "age_confirmed": "yes",
        "consent": "yes",
    })
    client.post("/login", data={"username": "kucing.oren", "password": PASSWORD})
    return client


def _rows(query, params=()):
    conn = sqlite3.connect(database.DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return rows


def _upload(client):
    client.post(
        "/upload",
        data={"file": (io.BytesIO(CONTENT), FILENAME, "application/pdf")},
        content_type="multipart/form-data",
    )
    return _rows("SELECT id FROM items")[0]["id"]


def test_upload_stores_no_plaintext_filename_or_mime_type(client):
    item_id = _upload(client)

    item = _rows("SELECT filename_enc, mime_type_enc FROM items")[0]
    assert (item["filename_enc"], item["mime_type_enc"]) == (b"", b"")
    records = _rows("SELECT record_id, cipher FROM records")
    assert sorted((r["record_id"], r["cipher"]) for r in records) == [
        (f"{item_id}/meta", c) for c in ("aes-gcm", "des-cbc", "rc4")
    ]
    with open(database.DB_PATH, "rb") as f:
        assert FILENAME.encode() not in f.read()


@pytest.mark.parametrize("cipher", ["aes-gcm", "des-cbc", "rc4"])
def test_every_copy_downloads_with_the_original_name_and_type(client, cipher):
    item_id = _upload(client)

    response = client.get(f"/download/{item_id}/{cipher}")

    assert response.status_code == 200
    assert response.data == CONTENT
    assert FILENAME in response.headers["Content-Disposition"]
    assert response.mimetype == "application/pdf"


def test_metadata_blob_cannot_be_swapped_with_profile_blob(client):
    item_id = _upload(client)
    client.post("/profile", data=PROFILE)
    conn = sqlite3.connect(database.DB_PATH)
    profile_row = conn.execute(
        "SELECT blob, wrapped_secret FROM records WHERE record_id = 'profile' AND cipher = 'aes-gcm'"
    ).fetchone()
    conn.execute(
        "UPDATE records SET blob = ?, wrapped_secret = ? WHERE record_id = ? AND cipher = 'aes-gcm'",
        (*profile_row, f"{item_id}/meta"),
    )
    conn.commit()
    conn.close()

    response = client.get(f"/download/{item_id}/aes-gcm")

    assert response.status_code == 302


def test_old_items_with_plaintext_columns_still_download(client):
    item_id = _upload(client)
    conn = sqlite3.connect(database.DB_PATH)
    conn.execute("DELETE FROM records")
    conn.execute("UPDATE items SET filename_enc = ?, mime_type_enc = ?", (b"old.pdf", b"application/pdf"))
    conn.commit()
    conn.close()

    response = client.get(f"/download/{item_id}/rc4")

    assert response.data == CONTENT
    assert "old.pdf" in response.headers["Content-Disposition"]


def test_profile_is_saved_encrypted_and_prefilled(client):
    assert client.post("/profile", data=PROFILE).status_code == 302

    assert len(_rows("SELECT * FROM records WHERE record_id = 'profile'")) == 3
    with open(database.DB_PATH, "rb") as f:
        db_bytes = f.read()
    for value in PROFILE.values():
        assert value.encode() not in db_bytes
    page = client.get("/profile").data.decode()
    for value in PROFILE.values():
        assert value in page


def test_saving_profile_again_uses_new_secrets(client):
    client.post("/profile", data=PROFILE)
    before = {r["cipher"]: r["wrapped_secret"] for r in _rows("SELECT * FROM records")}

    client.post("/profile", data={**PROFILE, "phone": "089999999999"})

    after = {r["cipher"]: r["wrapped_secret"] for r in _rows("SELECT * FROM records")}
    assert len(after) == 3
    assert all(before[c] != after[c] for c in after)
    assert "089999999999" in client.get("/profile").data.decode()


@pytest.mark.parametrize("change", [{"nrp": "12345"}, {"nrp": "50252110AB"}, {"name": ""}, {"email": " "}])
def test_invalid_profile_is_rejected_and_not_saved(client, change):
    response = client.post("/profile", data={**PROFILE, **change})

    assert response.status_code == 400
    assert _rows("SELECT * FROM records") == []


def test_file_and_profile_still_open_after_password_change(client):
    item_id = _upload(client)
    client.post("/profile", data=PROFILE)

    response = client.post("/change-password", data={
        "old_password": PASSWORD,
        "new_password": NEW_PASSWORD,
        "new_password_confirm": NEW_PASSWORD,
    })
    assert response.status_code == 302

    for cipher in ("aes-gcm", "des-cbc", "rc4"):
        download = client.get(f"/download/{item_id}/{cipher}")
        assert download.data == CONTENT
        assert FILENAME in download.headers["Content-Disposition"]
    assert PROFILE["name"] in client.get("/profile").data.decode()


def test_delete_file_removes_its_metadata_but_keeps_the_profile(client):
    item_id = _upload(client)
    client.post("/profile", data=PROFILE)

    client.post(f"/delete/{item_id}")

    assert _rows("SELECT * FROM records WHERE record_id = ?", (f"{item_id}/meta",)) == []
    assert len(_rows("SELECT * FROM records WHERE record_id = 'profile'")) == 3


def test_withdraw_consent_removes_every_record(client):
    _upload(client)
    client.post("/profile", data=PROFILE)

    client.post("/withdraw-consent", data={"password": PASSWORD})

    assert _rows("SELECT * FROM records") == []
