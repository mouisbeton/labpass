# @code-comment-id
# File Purpose: Authentication blueprint. Step 1: account registration (username rules,
# age-18+ confirmation, and consent recording) and CSRF protection.
# Login, session/KEK caching, and logout will be implemented later.
# Related Files:
# - ./database.py: get_db/close_db/init_db for storing users and consents
# - ./labcrypto: new_salt and derive_keys for deriving login_key from the password
# - ./templates/register.html: registration form
# - ./app.py: only needs to call auth.init_app(app)

import hmac
import re
import sqlite3
import uuid
from datetime import date, datetime, timezone
from functools import wraps

from flask import Blueprint, flash, g, redirect, render_template, request, session, url_for
from flask_wtf import CSRFProtect

import database
import session_cache
from labcrypto import IntegrityError, derive_keys, new_salt, unwrap_secret, wrap_secret
from storage import delete_blob_file

bp = Blueprint("auth", __name__)
csrf = CSRFProtect()

# Username: lowercase letters, digits, periods, underscores, and hyphens; 3-32 characters
USERNAME_PATTERN = re.compile(r"[a-z0-9_.-]{3,32}")

# Our campus NRP consists of 10 digits; adjust this if the format differs
NRP_PATTERN = re.compile(r"\d{10}")
MIN_PASSWORD_LENGTH = 12

# One message for every login failure, so attackers cannot tell which usernames exist
LOGIN_FAILED = "Wrong username or password."

# Current consent text version; previous versions are retained for auditing historical consent
CONSENT_VERSION = "v1"
CONSENT_TEXTS = {
    "v1": (
        "I consent to the processing of the following data for registering access to the "
        "Informatics Lab door system using facial recognition: name, NRP, phone number, email, "
        "student ID scan, course registration (KRS), signed lab rules document, and facial video.\n"
        "Facial video is biometric data (specific personal data) and is used only for "
        "facial re-registration in the lab door system.\n"
        "All data is stored in encrypted form and automatically deleted when my lab access period ends.\n"
        "I may withdraw this consent at any time; all my data will be deleted.\n"
        "If I do not wish to use biometric data, I may request access through a lab assistant."
    ),
}


# Create the consents table owned by the auth module, if it does not already exist
def init_auth_db():
    conn = sqlite3.connect(database.DB_PATH)
    conn.execute("""
    CREATE TABLE IF NOT EXISTS consents (
        user_id TEXT NOT NULL,
        version TEXT NOT NULL,
        agreed_at TEXT NOT NULL,
        age_confirmed INTEGER NOT NULL,
        withdrawn_at TEXT,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    );
    """)
    conn.commit()
    conn.close()


# Attach the auth module to the Flask application; call this once from app.py
def init_app(app):
    app.config.update(
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )

    # Enable CSRF protection for all POST forms throughout the application, including the dashboard
    csrf.init_app(app)
    app.teardown_appcontext(database.close_db)

    # The users table (database.py) must exist before creating the consents table
    database.init_db()
    init_auth_db()
    app.register_blueprint(bp)


# Validate the username; return an error message or None if valid
def validate_username(username):
    if not USERNAME_PATTERN.fullmatch(username):
        return "Username must be 3-32 characters and contain only lowercase letters, digits, periods, underscores, or hyphens."

    # Reject usernames containing a sequence of digits matching an NRP, anywhere in the username
    if NRP_PATTERN.search(username):
        return "Username must not contain an NRP."

    return None


# Check a username and password for login.
# Returns (user_id, kek) on success, or None on any failure; callers must not reveal which check failed.
def check_login(username, password):
    # Normalise the same way as registration, so "Budi" finds "budi"
    username = username.strip().lower()

    db = database.get_db()
    user = db.execute(
        "SELECT id, salt, login_key FROM users WHERE username = ?", (username,)
    ).fetchone()

    if user is None:
        # Still run Argon2id so an unknown username takes as long as a wrong password
        derive_keys(password, bytes(16))
        return None

    # Recompute both keys from the typed password; the KEK is never read from the database
    login_key, kek = derive_keys(password, user["salt"])

    # Constant-time comparison so response timing does not leak how many bytes matched
    if not hmac.compare_digest(login_key, user["login_key"]):
        return None

    return user["id"], kek


# Calculate the end date of the current semester as the access_until limit
def semester_end(today):
    # Even semester: February-July, ending on July 31
    if 2 <= today.month <= 7:
        return date(today.year, 7, 31)

    # Odd semester: August-January, ending on January 31
    if today.month >= 8:
        return date(today.year + 1, 1, 31)

    return date(today.year, 1, 31)


@bp.route("/register", methods=["GET", "POST"])
def register():
    consent_text = CONSENT_TEXTS[CONSENT_VERSION]

    if request.method == "GET":
        return render_template(
            "register.html",
            consent_text=consent_text,
            errors=[],
            username=""
        )

    # Store usernames in lowercase so that "Budi" and "budi" cannot become separate accounts
    username = request.form.get("username", "").strip().lower()
    password = request.form.get("password", "")
    password_confirm = request.form.get("password_confirm", "")
    age_confirmed = request.form.get("age_confirmed") == "yes"
    consent_given = request.form.get("consent") == "yes"

    errors = []
    username_error = validate_username(username)

    if username_error:
        errors.append(username_error)

    if len(password) < MIN_PASSWORD_LENGTH:
        errors.append(f"Password must be at least {MIN_PASSWORD_LENGTH} characters long.")

    if password != password_confirm:
        errors.append("Password confirmation does not match.")

    if not age_confirmed:
        errors.append(
            "This portal is for users aged 18 and older. "
            "Users under 18 must register through the lab's offline process."
        )

    if not consent_given:
        errors.append("Consent to data processing is required for registration.")

    if errors:
        return render_template(
            "register.html",
            consent_text=consent_text,
            errors=errors,
            username=username
        ), 400

    # The KEK (the second return value) is intentionally discarded; only the salt and login_key are stored
    salt = new_salt()
    login_key, _ = derive_keys(password, salt)
    user_id = uuid.uuid4().hex
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    access_until = semester_end(date.today()).isoformat()

    db = database.get_db()

    try:
        # Single transaction: the user and consent are saved together, or neither is saved
        with db:
            db.execute(
                "INSERT INTO users (id, username, login_key, salt, access_until) VALUES (?, ?, ?, ?, ?)",
                (user_id, username, login_key, salt, access_until),
            )

            db.execute(
                "INSERT INTO consents (user_id, version, agreed_at, age_confirmed) VALUES (?, ?, ?, 1)",
                (user_id, CONSENT_VERSION, now),
            )

    except sqlite3.IntegrityError:
        return render_template(
            "register.html",
            consent_text=consent_text,
            errors=["Username is already taken. Please choose another."],
            username=username,
        ), 400

    flash("Account created successfully. Please log in.")

    return redirect(url_for("auth.login"))


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html", errors=[], username="")

    username = request.form.get("username", "")
    password = request.form.get("password", "")
    result = check_login(username, password)

    if result is None:
        return render_template(
            "login.html",
            errors=[LOGIN_FAILED],
            username=username.strip().lower(),
        ), 401

    user_id, kek = result

    # Fresh session at every login (prevents session fixation): drop any old cache entry,
    # empty the cookie, then store only the new random session ID in it
    old_sid = session.get("sid")
    if old_sid:
        session_cache.delete(old_sid)
    session.clear()
    session["sid"] = session_cache.create(user_id, kek)

    # "dashboard" is the endpoint name of Person 3's dashboard route in app.py
    return redirect(url_for("dashboard"))


# POST only: a link or image on another site cannot log a student out, and CSRF protects the form
@bp.route("/logout", methods=["POST"])
def logout():
    sid = session.get("sid")
    if sid:
        # Wipes the KEK from server RAM
        session_cache.delete(sid)
    session.clear()

    flash("You have been logged out.")
    return redirect(url_for("auth.login"))


# Protected routes


# Look up the cache entry behind this request's cookie; return (user_id, kek) or None
def _current_session():
    sid = session.get("sid")
    if not sid:
        return None

    entry = session_cache.get(sid)
    if entry is None:
        # Expired or unknown ID (for example after a server restart): drop it from the cookie
        session.pop("sid", None)
    return entry


# Return the KEK of the logged-in student, or None if there is no valid session
def get_kek():
    entry = _current_session()
    return entry[1] if entry else None


# Decorator for routes that need a logged-in student; sets g.user_id and g.kek for the route
def login_required(view):
    # wraps keeps the route's own name, so Flask does not see every protected route as "wrapped"
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        entry = _current_session()
        if entry is None:
            flash("Please log in first.")
            return redirect(url_for("auth.login"))

        g.user_id, g.kek = entry
        return view(*args, **kwargs)

    return wrapped_view


# Change password


# Check a password against the stored login_key of one user; return the KEK if it matches
def _verify_password(db, user_id, password):
    user = db.execute(
        "SELECT salt, login_key FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if user is None:
        return None

    login_key, kek = derive_keys(password, user["salt"])
    if not hmac.compare_digest(login_key, user["login_key"]):
        return None
    return kek


@bp.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "GET":
        return render_template("change_password.html", errors=[])

    old_password = request.form.get("old_password", "")
    new_password = request.form.get("new_password", "")
    new_password_confirm = request.form.get("new_password_confirm", "")

    db = database.get_db()
    old_kek = _verify_password(db, g.user_id, old_password)
    if old_kek is None:
        return render_template(
            "change_password.html", errors=["Current password is wrong."]
        ), 401

    errors = []
    if len(new_password) < MIN_PASSWORD_LENGTH:
        errors.append(f"New password must be at least {MIN_PASSWORD_LENGTH} characters long.")
    if new_password != new_password_confirm:
        errors.append("New password confirmation does not match.")
    if errors:
        return render_template("change_password.html", errors=errors), 400

    new_salt_value = new_salt()
    new_login_key, new_kek = derive_keys(new_password, new_salt_value)

    try:
        # One transaction: every item key is re-wrapped and the new password stored, or nothing is.
        # The files themselves are not re-encrypted; only the small wrapped secrets change.
        with db:
            # Read the keys inside the transaction so none can be missed between read and update
            wrapped_rows = db.execute(
                "SELECT w.item_id, w.cipher, w.wrapped_secret FROM wrapped_keys w "
                "JOIN items i ON i.id = w.item_id WHERE i.user_id = ?",
                (g.user_id,),
            ).fetchall()
            for row in wrapped_rows:
                ctx = (g.user_id, row["item_id"], row["cipher"])
                item_secret = unwrap_secret(old_kek, row["wrapped_secret"], ctx)
                db.execute(
                    "UPDATE wrapped_keys SET wrapped_secret = ? WHERE item_id = ? AND cipher = ?",
                    (wrap_secret(new_kek, item_secret, ctx), row["item_id"], row["cipher"]),
                )
            # Same for the small encrypted records (file metadata and personal data)
            record_rows = db.execute(
                "SELECT record_id, cipher, wrapped_secret FROM records WHERE user_id = ?",
                (g.user_id,),
            ).fetchall()
            for row in record_rows:
                ctx = (g.user_id, row["record_id"], row["cipher"])
                item_secret = unwrap_secret(old_kek, row["wrapped_secret"], ctx)
                db.execute(
                    "UPDATE records SET wrapped_secret = ? "
                    "WHERE user_id = ? AND record_id = ? AND cipher = ?",
                    (wrap_secret(new_kek, item_secret, ctx), g.user_id, row["record_id"], row["cipher"]),
                )
            db.execute(
                "UPDATE users SET salt = ?, login_key = ? WHERE id = ?",
                (new_salt_value, new_login_key, g.user_id),
            )
    except IntegrityError:
        # A wrapped key did not open with the old KEK (tampered data); nothing was changed
        return render_template(
            "change_password.html",
            errors=["Your stored keys could not be verified. The password was not changed."],
        ), 500

    # The old KEK is useless now: end every session of this student, then start a fresh one
    session_cache.delete_user(g.user_id)
    session.clear()
    session["sid"] = session_cache.create(g.user_id, new_kek)

    flash("Password changed.")
    return redirect(url_for("dashboard"))


# Withdraw consent


# Delete every database row of one student in one transaction and return their blob file paths.
# Rows are deleted child-first on purpose: SQLite foreign keys (ON DELETE CASCADE) are off by default.
def delete_user_data(db, user_id):
    item_ids = "SELECT id FROM items WHERE user_id = ?"
    with db:
        blob_paths = [
            row["blob_path"]
            for row in db.execute(
                f"SELECT blob_path FROM copies WHERE item_id IN ({item_ids})", (user_id,)
            )
        ]
        db.execute(f"DELETE FROM wrapped_keys WHERE item_id IN ({item_ids})", (user_id,))
        db.execute(f"DELETE FROM copies WHERE item_id IN ({item_ids})", (user_id,))
        db.execute("DELETE FROM items WHERE user_id = ?", (user_id,))
        db.execute("DELETE FROM records WHERE user_id = ?", (user_id,))
        db.execute("DELETE FROM consents WHERE user_id = ?", (user_id,))
        db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    return blob_paths


@bp.route("/withdraw-consent", methods=["GET", "POST"])
@login_required
def withdraw_consent():
    if request.method == "GET":
        return render_template("withdraw_consent.html", errors=[])

    db = database.get_db()
    # Deleting everything cannot be undone, so ask for the password again
    # (protects against someone using a student's unlocked computer)
    if _verify_password(db, g.user_id, request.form.get("password", "")) is None:
        return render_template(
            "withdraw_consent.html", errors=["Password is wrong. Nothing was deleted."]
        ), 401

    blob_paths = delete_user_data(db, g.user_id)

    # The wrapped keys are already gone, so the blobs can never be decrypted again
    # (crypto-shredding); deleting the files as well frees the disk
    for path in blob_paths:
        delete_blob_file(path)

    session_cache.delete_user(g.user_id)
    session.clear()

    flash("Your consent was withdrawn and all your data has been deleted.")
    return redirect(url_for("auth.login"))
