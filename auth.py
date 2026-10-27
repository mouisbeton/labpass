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

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_wtf import CSRFProtect

import database
from labcrypto import derive_keys, new_salt

bp = Blueprint("auth", __name__)
csrf = CSRFProtect()

# Username: lowercase letters, digits, periods, underscores, and hyphens; 3-32 characters
USERNAME_PATTERN = re.compile(r"[a-z0-9_.-]{3,32}")

# Our campus NRP consists of 10 digits; adjust this if the format differs
NRP_PATTERN = re.compile(r"\d{10}")
MIN_PASSWORD_LENGTH = 12

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

    # TODO Step 2: redirect to the login page once the login route has been implemented
    return redirect(url_for("auth.register"))