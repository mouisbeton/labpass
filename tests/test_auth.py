# File Purpose: Tests for the registration feature in auth.py (username rules, consent record,
# credential storage, failed and duplicate registrations, CSRF protection).
# Related Files:
# - ../auth.py: register route, validate_username, semester_end, init_app
# - ../database.py: DB_PATH is redirected to a temporary file for every test
# - ../templates/register.html: rendered by GET /register

import os
import re
import sqlite3
from datetime import date

import pytest
from flask import Flask

import auth
import database
import session_cache
from labcrypto import derive_keys

TEMPLATES = os.path.join(os.path.dirname(__file__), "..", "templates")

# A form that passes every check
VALID_FORM = {
    "username": "kucing.oren",
    "password": "rahasia-panjang-sekali",
    "password_confirm": "rahasia-panjang-sekali",
    "age_confirmed": "yes",
    "consent": "yes",
}


# Build a small Flask app with only the auth module, backed by a throwaway database
def _make_app(tmp_path, monkeypatch, csrf_enabled):
    # point the database at a throwaway file BEFORE init_app creates the tables
    monkeypatch.setattr(database, "DB_PATH", str(tmp_path / "test.db"))
    app = Flask(__name__, template_folder=TEMPLATES)
    app.config.update(TESTING=True, SECRET_KEY="test", WTF_CSRF_ENABLED=csrf_enabled)
    auth.init_app(app)
    app.add_url_rule("/dashboard", "dashboard", lambda: "dashboard")
    return app


@pytest.fixture
def client(tmp_path, monkeypatch):
    app = _make_app(tmp_path, monkeypatch, csrf_enabled=False)
    yield app.test_client()


def _rows(query):
    conn = sqlite3.connect(database.DB_PATH)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(query).fetchall()
    conn.close()
    return rows


def test_register_page_loads(client):
    response = client.get("/register")
    assert response.status_code == 200
    assert b"Create Account" in response.data


# Username validation


@pytest.mark.parametrize("username", ["kucing.oren", "budi_99", "a-b"])
def test_validate_username_accepts_valid_names(username):
    assert auth.validate_username(username) is None


@pytest.mark.parametrize(
    "username",
    ["ab", "x" * 33, "nama spasi", "Budi", "5025211234", "budi5025211234"],
)
def test_validate_username_rejects_invalid_names(username):
    assert auth.validate_username(username) is not None


# Successful registration


def test_valid_registration_creates_user_and_consent(client):
    response = client.post("/register", data=VALID_FORM)
    assert response.status_code == 302

    users = _rows("SELECT * FROM users")
    assert len(users) == 1
    assert users[0]["username"] == "kucing.oren"
    # cleanup.py deletes data based on this date
    assert users[0]["access_until"] == auth.semester_end(date.today()).isoformat()

    consents = _rows("SELECT * FROM consents")
    assert len(consents) == 1
    assert consents[0]["user_id"] == users[0]["id"]
    assert consents[0]["version"] == auth.CONSENT_VERSION
    assert consents[0]["age_confirmed"] == 1


def test_username_is_stored_in_lowercase(client):
    client.post("/register", data={**VALID_FORM, "username": "Kucing.Oren"})
    assert _rows("SELECT username FROM users")[0]["username"] == "kucing.oren"


# Credential storage


def test_database_has_login_key_but_no_password_or_kek(client):
    client.post("/register", data=VALID_FORM)
    user = _rows("SELECT * FROM users")[0]
    assert len(user["salt"]) == 16
    assert len(user["login_key"]) == 32

    login_key, kek = derive_keys(VALID_FORM["password"], user["salt"])
    assert user["login_key"] == login_key

    with open(database.DB_PATH, "rb") as f:
        raw = f.read()
    assert VALID_FORM["password"].encode() not in raw
    assert kek not in raw


# Failed and duplicate registration


@pytest.mark.parametrize(
    "changes",
    [
        {"username": "5025211234"},
        {"password": "pendek", "password_confirm": "pendek"},
        {"password_confirm": "beda-sedikit-saja"},
        {"age_confirmed": ""},
        {"consent": ""},
    ],
)
def test_invalid_registration_stores_nothing(client, changes):
    response = client.post("/register", data={**VALID_FORM, **changes})
    assert response.status_code == 400
    assert _rows("SELECT * FROM users") == []
    assert _rows("SELECT * FROM consents") == []


def test_duplicate_username_is_rejected(client):
    client.post("/register", data=VALID_FORM)
    response = client.post("/register", data={**VALID_FORM, "username": "KUCING.oren"})
    assert response.status_code == 400
    assert len(_rows("SELECT * FROM users")) == 1
    # the failed insert must not leave a second consent behind
    assert len(_rows("SELECT * FROM consents")) == 1


def test_password_is_not_echoed_back(client):
    response = client.post("/register", data={**VALID_FORM, "consent": ""})
    assert VALID_FORM["password"].encode() not in response.data


# CSRF protection


def test_post_without_csrf_token_is_rejected(tmp_path, monkeypatch):
    client = _make_app(tmp_path, monkeypatch, csrf_enabled=True).test_client()
    response = client.post("/register", data=VALID_FORM)
    assert response.status_code == 400
    assert _rows("SELECT * FROM users") == []


def test_post_with_csrf_token_is_accepted(tmp_path, monkeypatch):
    client = _make_app(tmp_path, monkeypatch, csrf_enabled=True).test_client()
    page = client.get("/register").get_data(as_text=True)
    token = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
    response = client.post("/register", data={**VALID_FORM, "csrf_token": token})
    assert response.status_code == 302
    assert len(_rows("SELECT * FROM users")) == 1


# Check login 


def test_check_login_accepts_correct_password(client):
    client.post("/register", data=VALID_FORM)
    with client.application.app_context():
        result = auth.check_login("kucing.oren", VALID_FORM["password"])

    user = _rows("SELECT id, salt FROM users")[0]
    _, expected_kek = derive_keys(VALID_FORM["password"], user["salt"])
    assert result == (user["id"], expected_kek)

def test_check_login_ignores_username_case_and_spaces(client):
    client.post("/register", data=VALID_FORM)
    with client.application.app_context():
        assert auth.check_login("  KUCING.Oren ", VALID_FORM["password"]) is not None

def test_check_login_rejects_wrong_password(client):
    client.post("/register", data=VALID_FORM)
    with client.application.app_context():
        assert auth.check_login("kucing.oren", "password-yang-salah") is None

def test_check_login_unknown_username_still_runs_argon2(client, monkeypatch):
    calls = []
    real_derive_keys = auth.derive_keys

    def counting_derive_keys(password, salt):
        calls.append(salt)
        return real_derive_keys(password, salt)

    monkeypatch.setattr(auth, "derive_keys", counting_derive_keys)
    with client.application.app_context():
        assert auth.check_login("tidak.ada", VALID_FORM["password"]) is None
    assert len(calls) == 1


# Login route and logout


@pytest.fixture
def registered(client, monkeypatch):
    # Start every login test with an empty KEK cache, as the cache tests do
    monkeypatch.setattr(session_cache, "_entries", {})
    client.post("/register", data=VALID_FORM)
    return client


LOGIN_FORM = {"username": VALID_FORM["username"], "password": VALID_FORM["password"]}


def test_login_page_loads(client):
    response = client.get("/login")
    assert response.status_code == 200
    assert b"Log In" in response.data


def test_register_redirects_to_login(client):
    response = client.post("/register", data=VALID_FORM)
    assert response.headers["Location"] == "/login"


def test_correct_login_creates_one_cache_entry(registered):
    response = registered.post("/login", data=LOGIN_FORM)
    assert response.status_code == 302
    assert response.headers["Location"] == "/dashboard"
    assert len(session_cache._entries) == 1


@pytest.mark.parametrize(
    "form",
    [
        {**LOGIN_FORM, "password": "password-yang-salah"},
        {**LOGIN_FORM, "username": "tidak.ada"},
    ],
)
def test_failed_login_gives_401_and_one_message(registered, form):
    response = registered.post("/login", data=form)
    assert response.status_code == 401
    assert auth.LOGIN_FAILED.encode() in response.data
    assert session_cache._entries == {}


def test_cookie_holds_only_the_session_id(registered):
    registered.post("/login", data=LOGIN_FORM)
    with registered.session_transaction() as s:
        assert list(s.keys()) == ["sid"]
        sid = s["sid"]

    user_id, kek = session_cache.get(sid)
    assert kek not in sid.encode()


def test_session_cookie_flags(registered):
    response = registered.post("/login", data=LOGIN_FORM)
    cookie = response.headers["Set-Cookie"]
    assert "Secure" in cookie
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie


def test_logout_removes_cache_entry_and_sid(registered):
    registered.post("/login", data=LOGIN_FORM)
    response = registered.post("/logout")
    assert response.status_code == 302
    assert session_cache._entries == {}
    with registered.session_transaction() as s:
        assert "sid" not in s


def test_logout_is_post_only(registered):
    assert registered.get("/logout").status_code == 405


def test_logging_in_twice_gives_a_new_sid(registered):
    registered.post("/login", data=LOGIN_FORM)
    with registered.session_transaction() as s:
        first = s["sid"]

    registered.post("/login", data=LOGIN_FORM)
    with registered.session_transaction() as s:
        second = s["sid"]

    assert first != second
    # the first session's KEK was wiped, not left behind
    assert list(session_cache._entries) == [second]
