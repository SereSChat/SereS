import base64
import functools
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import sqlite3
import threading
import time
import urllib.parse
import uuid

import dotenv
import flask
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from flask import g
from PIL import Image, UnidentifiedImageError

import db
from legacy_migration import migrate_legacy_files

dotenv.load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.getenv("SERES_DATA_DIR", BASE_DIR)
USER_DATA = os.path.join(DATA_DIR, "user_data")
CHATS = os.path.join(DATA_DIR, "chats")
DB = os.path.join(DATA_DIR, "users.db")

SESSION_COOKIE = "sessioncookie"
CONSENT_COOKIE = "cookie_consent"
SESSION_DAYS = 90
DEFAULT_KDF_ITERATIONS = 600_000
MIN_KDF_ITERATIONS = 100_000
MAX_KDF_ITERATIONS = 5_000_000
MAX_GROUP_MEMBERS = 50
MAX_CIPHERTEXT_LEN = 64 * 1024
MAX_AVATAR_BYTES = 2 * 1024 * 1024

USERNAME_RE = re.compile(r"^[A-Za-z0-9_-]{3,20}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
B64_RE = re.compile(r"^[A-Za-z0-9+/_-]+={0,2}$")

app = flask.Flask(__name__, static_folder="../public", static_url_path="/")
app.config["DEBUG"] = False
app.config["MAX_CONTENT_LENGTH"] = 4 * 1024 * 1024
ph = PasswordHasher(time_cost=4)
# Used to keep login timing the same for unknown users.
DUMMY_HASH = ph.hash(secrets.token_hex(16))


# --------------------------------------------------------------------------
# Infrastructure
# --------------------------------------------------------------------------


def get_db():
    if "db" not in g:
        g.db = db.connect(DB)
    return g.db


@app.teardown_appcontext
def close_db(exception):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_app():
    os.makedirs(USER_DATA, exist_ok=True)
    conn = db.connect(DB)
    try:
        db.init_schema(conn)
        migrate_legacy_files(conn, USER_DATA, CHATS)
        db.server_secret(conn)
    finally:
        conn.close()


def start_heartbeat():
    url = os.getenv("URL")
    if not url:
        return
    try:
        import pyheartbeat

        pyheartbeat.setUrl(url)
        pyheartbeat.heartbeat(interval=600, name="uptime-checker")
    except Exception as e:  # monitoring must never take the chat down
        print("heartbeat disabled:", e)


class RateLimiter:
    """Small in-memory sliding window limiter (per process)."""

    def __init__(self):
        self._hits = {}
        self._lock = threading.Lock()

    def hit(self, key, limit, window):
        now = time.monotonic()
        with self._lock:
            hits = [t for t in self._hits.get(key, []) if now - t < window]
            allowed = len(hits) < limit
            if allowed:
                hits.append(now)
            self._hits[key] = hits
            if len(self._hits) > 50_000:
                self._hits = {k: v for k, v in self._hits.items() if v and now - v[-1] < 3600}
            return allowed


limiter = RateLimiter()


def rate_limited(key, limit, window):
    if app.config.get("TESTING_DISABLE_RATE_LIMIT"):
        return False
    return not limiter.hit(key, limit, window)


def client_ip():
    return flask.request.remote_addr or "?"


def error(message, status=400):
    return {"message": message, "success": False}, status


def ok(**data):
    return {"success": True, **data}, 200


def json_body():
    data = flask.request.get_json(silent=True)
    if not isinstance(data, dict):
        flask.abort(flask.make_response(error("Expected a JSON object")))
    return data


def str_field(data, name, max_len=256, required=True):
    value = data.get(name)
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value or len(value) > max_len:
        flask.abort(flask.make_response(error(f"Missing or invalid '{name}'")))
    return value


def b64_field(data, name, max_len=8192):
    value = str_field(data, name, max_len)
    if not B64_RE.match(value):
        flask.abort(flask.make_response(error(f"Invalid encoding of '{name}'")))
    return value


@app.before_request
def csrf_protect():
    if flask.request.method in ("GET", "HEAD", "OPTIONS"):
        return None
    origin = flask.request.headers.get("Origin")
    if origin:
        # Compare hosts only, so TLS terminating reverse proxies keep working.
        allowed = {flask.request.host, flask.request.headers.get("X-Forwarded-Host")}
        allowed.update(h.strip() for h in os.getenv("SERES_ALLOWED_HOSTS", "").split(",") if h.strip())
        if urllib.parse.urlsplit(origin).netloc not in allowed:
            return error("Cross-site request rejected", 403)
    return None


@app.after_request
def security_headers(response):
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' blob: data:; media-src 'self'; object-src 'self'; "
        "frame-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; "
        "frame-ancestors 'self'",
    )
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if flask.request.path.startswith("/api/"):
        response.headers.setdefault("Cache-Control", "no-store")
    if flask.request.is_secure:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
    return response


# --------------------------------------------------------------------------
# Sessions & users
# --------------------------------------------------------------------------


def hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(user_id):
    token = secrets.token_urlsafe(32)
    conn = get_db()
    conn.execute(
        "INSERT INTO user_sessions (token_hash, user_id, expires_at, created_at) VALUES (?, ?, strftime('%Y-%m-%dT%H:%M:%SZ', 'now', ?), ?)",
        (hash_token(token), user_id, f"+{SESSION_DAYS} days", db.now_iso()),
    )
    conn.commit()
    return token


def cookies_accepted():
    return flask.request.cookies.get(CONSENT_COOKIE) == "accepted"


def set_session_cookie(response, token, persistent=None):
    """Without cookie consent the login only lasts until the browser is closed."""
    if persistent is None:
        persistent = cookies_accepted()
    secure = flask.request.is_secure or flask.request.headers.get("X-Forwarded-Proto") == "https"
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=SESSION_DAYS * 24 * 3600 if persistent else None,
        httponly=True,
        secure=secure,
        samesite="Strict",
        path="/",
    )
    # The old frontend stored the username in a readable cookie; remove it.
    response.delete_cookie("username", path="/")


def current_user():
    if "user" in g:
        return g.user
    g.user = None
    token = flask.request.cookies.get(SESSION_COOKIE)
    if token:
        row = (
            get_db()
            .execute(
                """SELECT u.* FROM user_sessions s JOIN users u ON u.id = s.user_id
                   WHERE s.token_hash = ? AND s.expires_at > ?""",
                (hash_token(token), db.now_iso()),
            )
            .fetchone()
        )
        g.user = row
    return g.user


def login_required(view):
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        if current_user() is None:
            return error("Not logged in", 401)
        return view(*args, **kwargs)

    return wrapper


def find_user_by_name(username):
    if not isinstance(username, str) or not username.strip():
        return None
    return (
        get_db()
        .execute("SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username.strip(),))
        .fetchone()
    )


def find_user_by_login(nameomail):
    conn = get_db()
    if "@" in nameomail:
        return conn.execute(
            "SELECT * FROM users WHERE email = ? COLLATE NOCASE", (nameomail,)
        ).fetchone()
    return conn.execute(
        "SELECT * FROM users WHERE username = ? COLLATE NOCASE", (nameomail,)
    ).fetchone()


def display_name(row):
    """The name shown in the app: the display name, or the username without one."""
    keys = row.keys() if hasattr(row, "keys") else ()
    return (row["display_name"] if "display_name" in keys else None) or row["username"]


def public_user(row):
    return {"id": row["id"], "username": row["username"], "display_name": display_name(row)}


def own_user(row):
    return {
        **public_user(row),
        "email": row["email"],
        "pub_ecdh": row["pub_ecdh"],
        "pub_sign": row["pub_sign"],
        "enc_private": row["enc_private"],
    }


def fake_salt(identifier):
    secret = db.server_secret(get_db())
    digest = hmac.new(secret.encode(), identifier.lower().encode(), hashlib.sha256).digest()
    return base64.b64encode(digest[:16]).decode()


def verify_hash(stored, candidate):
    try:
        return ph.verify(stored or DUMMY_HASH, candidate) and stored is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def validate_key_bundle(data):
    keys = data.get("keys")
    if not isinstance(keys, dict):
        flask.abort(flask.make_response(error("Missing encryption keys")))
    return {
        "pub_ecdh": b64_field(keys, "pub_ecdh", 512),
        "pub_sign": b64_field(keys, "pub_sign", 512),
        "enc_private": str_field(keys, "enc_private", 8192),
    }


def validate_kdf(data):
    salt = b64_field(data, "kdf_salt", 64)
    iterations = data.get("kdf_iterations")
    if not isinstance(iterations, int) or not MIN_KDF_ITERATIONS <= iterations <= MAX_KDF_ITERATIONS:
        flask.abort(flask.make_response(error("Invalid kdf_iterations")))
    return salt, iterations


# --------------------------------------------------------------------------
# Pages & auth
# --------------------------------------------------------------------------


@app.route("/")
def index():
    return app.send_static_file("index.html")


@app.route("/api/online", methods=["GET", "POST"])
def online():
    return {"message": "im up", "success": True}, 200


@app.route("/api/prelogin", methods=["POST"])
def prelogin():
    data = json_body()
    nameomail = str_field(data, "nameomail", 254).strip()
    if rate_limited(("prelogin", client_ip()), 60, 60):
        return error("Too many attempts, please wait a minute", 429)
    user = find_user_by_login(nameomail)
    if user is None:
        return ok(kdf_salt=fake_salt(nameomail), kdf_iterations=DEFAULT_KDF_ITERATIONS, legacy=False)
    if user["auth_version"] == 0 and not user["kdf_salt"]:
        conn = get_db()
        conn.execute(
            "UPDATE users SET kdf_salt = ?, kdf_iterations = ? WHERE id = ?",
            (base64.b64encode(secrets.token_bytes(16)).decode(), DEFAULT_KDF_ITERATIONS, user["id"]),
        )
        conn.commit()
        user = find_user_by_login(nameomail)
    return ok(
        kdf_salt=user["kdf_salt"],
        kdf_iterations=user["kdf_iterations"] or DEFAULT_KDF_ITERATIONS,
        legacy=user["auth_version"] == 0,
    )


@app.route("/api/register", methods=["POST"])
def register():
    data = json_body()
    username = str_field(data, "username", 64).strip()
    email = str_field(data, "email", 254).strip()
    auth_hash = b64_field(data, "auth_hash", 128)
    kdf_salt, kdf_iterations = validate_kdf(data)
    keys = validate_key_bundle(data)

    if rate_limited(("register", client_ip()), 10, 3600):
        return error("Too many registrations, please try again later", 429)
    if not USERNAME_RE.match(username):
        return error("Username must be 3-20 characters: letters, numbers, '_' or '-'")
    if not EMAIL_RE.match(email):
        return error("Email is invalid")

    conn = get_db()
    if find_user_by_name(username):
        return error("Username already taken")
    if conn.execute("SELECT 1 FROM users WHERE email = ? COLLATE NOCASE", (email,)).fetchone():
        return error("Email already in use")

    conn.execute(
        """INSERT INTO users (id, email, username, passwd, auth_version, kdf_salt, kdf_iterations,
                              pub_ecdh, pub_sign, enc_private, created_at)
           VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?)""",
        (
            str(uuid.uuid4()),
            email,
            username,
            ph.hash(auth_hash),
            kdf_salt,
            kdf_iterations,
            keys["pub_ecdh"],
            keys["pub_sign"],
            keys["enc_private"],
            db.now_iso(),
        ),
    )
    conn.commit()
    return {"message": "User created successfully!", "success": True}, 200


@app.route("/api/login", methods=["POST"])
def login():
    data = json_body()
    nameomail = str_field(data, "nameomail", 254).strip()
    auth_hash = b64_field(data, "auth_hash", 128)

    if rate_limited(("login-ip", client_ip()), 60, 60) or rate_limited(
        ("login-account", nameomail.lower()), 10, 300
    ):
        return error("Too many login attempts, please wait a few minutes", 429)

    user = find_user_by_login(nameomail)
    conn = get_db()

    if user is not None and user["auth_version"] == 0:
        # Account from before end-to-end encryption: check the old password once,
        # then switch it to the client derived hash and store the new key bundle.
        legacy_password = data.get("passwd")
        if not isinstance(legacy_password, str) or not verify_hash(user["passwd"], legacy_password):
            return error("Login not succesfull")
        keys = validate_key_bundle(data)
        if not user["kdf_salt"]:
            return error("Please retry the login")
        conn.execute(
            """UPDATE users SET passwd = ?, auth_version = 1, pub_ecdh = ?, pub_sign = ?, enc_private = ?
               WHERE id = ?""",
            (ph.hash(auth_hash), keys["pub_ecdh"], keys["pub_sign"], keys["enc_private"], user["id"]),
        )
        conn.commit()
    elif user is None or not verify_hash(user["passwd"], auth_hash):
        if user is None:
            verify_hash(None, auth_hash)
        return error("Login not succesfull")

    user = conn.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
    response = flask.make_response(
        {
            "message": "Login succesfull!",
            "success": True,
            "user": own_user(user),
            "enc_private": user["enc_private"],
        }
    )
    set_session_cookie(response, create_session(user["id"]))
    return response, 200


@app.route("/api/logout", methods=["POST"])
def logout():
    token = flask.request.cookies.get(SESSION_COOKIE)
    if token:
        conn = get_db()
        conn.execute("DELETE FROM user_sessions WHERE token_hash = ?", (hash_token(token),))
        conn.commit()
    response = flask.make_response({"message": "Logout succesfull!", "success": True})
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie("username", path="/")
    return response, 200


@app.route("/api/cookie_consent", methods=["POST"])
def cookie_consent():
    accepted = (flask.request.get_json(silent=True) or {}).get("accepted") is True
    response = flask.make_response({"success": True, "accepted": accepted})
    # Remembering the decision itself is necessary, so it is always kept.
    response.set_cookie(
        CONSENT_COOKIE,
        "accepted" if accepted else "denied",
        max_age=365 * 24 * 3600,
        samesite="Lax",
        path="/",
    )
    # Re-issue the login cookie so it matches the new decision.
    token = flask.request.cookies.get(SESSION_COOKIE)
    if token and current_user() is not None:
        set_session_cookie(response, token, persistent=accepted)
    return response, 200


@app.route("/api/auth_cookie", methods=["POST", "GET"])
def auth_session_cookie():
    if current_user() is None:
        return error("Cookie invalid")
    return {"message": "Cookie valid", "success": True}, 200


@app.route("/api/me")
@login_required
def me():
    user = current_user()
    return ok(user=own_user(user))


@app.route("/api/change_password", methods=["POST"])
@login_required
def change_password():
    data = json_body()
    user = current_user()
    old_hash = b64_field(data, "old_auth_hash", 128)
    new_hash = b64_field(data, "auth_hash", 128)
    kdf_salt, kdf_iterations = validate_kdf(data)
    enc_private = str_field(data, "enc_private", 8192)
    if rate_limited(("change-password", user["id"]), 5, 300):
        return error("Too many attempts, please wait a few minutes", 429)
    if not verify_hash(user["passwd"], old_hash):
        return error("Current password is wrong")
    conn = get_db()
    conn.execute(
        "UPDATE users SET passwd = ?, kdf_salt = ?, kdf_iterations = ?, enc_private = ? WHERE id = ?",
        (ph.hash(new_hash), kdf_salt, kdf_iterations, enc_private, user["id"]),
    )
    token_hash = hash_token(flask.request.cookies.get(SESSION_COOKIE, ""))
    conn.execute(
        "DELETE FROM user_sessions WHERE user_id = ? AND token_hash != ?", (user["id"], token_hash)
    )
    conn.commit()
    return {"message": "Password changed", "success": True}, 200


@app.route("/api/users/keys")
@login_required
def user_keys():
    ids = [i for i in flask.request.args.get("ids", "").split(",") if i][:100]
    if not ids:
        return ok(users=[])
    placeholders = ",".join("?" * len(ids))
    rows = get_db().execute(
        f"SELECT id, username, display_name, pub_ecdh, pub_sign FROM users WHERE id IN ({placeholders})", ids
    )
    return ok(users=[{**dict(row), "display_name": display_name(row)} for row in rows])


# --------------------------------------------------------------------------
# Avatars
# --------------------------------------------------------------------------


def avatar_path(user_id):
    return os.path.join(USER_DATA, user_id, "avatar.png")


def send_avatar(user_id):
    path = avatar_path(user_id)
    if not os.path.exists(path):
        return error("No avatar uploaded", 404)
    response = flask.send_file(path, mimetype="image/png", max_age=300)
    return response


@app.route("/api/get_avatar")
@login_required
def get_avatar():
    return send_avatar(current_user()["id"])


def can_see_user(viewer_id, other_id):
    if viewer_id == other_id or are_friends(viewer_id, other_id):
        return True
    return (
        get_db()
        .execute(
            """SELECT 1 FROM chat_members a JOIN chat_members b ON a.chat_id = b.chat_id
               WHERE a.user_id = ? AND b.user_id = ? LIMIT 1""",
            (viewer_id, other_id),
        )
        .fetchone()
        is not None
    )


@app.route("/api/users/<username>/avatar")
@login_required
def get_user_avatar(username):
    other = find_user_by_name(username)
    if other is None or not can_see_user(current_user()["id"], other["id"]):
        return error("No avatar uploaded", 404)
    return send_avatar(other["id"])


@app.route("/api/upload_avatar", methods=["POST"])
@login_required
def upload_avatar():
    user_id = current_user()["id"]
    file = flask.request.files.get("avatar_img")
    if file is None or not file.filename:
        return error("No selected file")
    raw = file.read(MAX_AVATAR_BYTES + 1)
    if len(raw) > MAX_AVATAR_BYTES:
        return error("File size exceeds 2MB limit")
    try:
        image = Image.open(io.BytesIO(raw))
        if image.width * image.height > 40_000_000:
            return error("Image is too large")
        image = image.convert("RGBA")
        image.thumbnail((512, 512))
    except (UnidentifiedImageError, OSError, Image.DecompressionBombError):
        return error("Wrong filetype (png, jpg, gif or webp)")
    os.makedirs(os.path.join(USER_DATA, user_id), exist_ok=True)
    # Re-encoding strips metadata and anything that is not plain pixel data.
    image.save(avatar_path(user_id), "PNG")
    return {"message": "Image uploaded successfully", "success": True}, 200


# --------------------------------------------------------------------------
# Friends & blocking
# --------------------------------------------------------------------------


def pair(a, b):
    return tuple(sorted((a, b)))


def are_friends(a, b):
    return (
        get_db()
        .execute("SELECT 1 FROM friendships WHERE user_a = ? AND user_b = ?", pair(a, b))
        .fetchone()
        is not None
    )


def is_blocked_between(a, b):
    return (
        get_db()
        .execute(
            "SELECT 1 FROM blocks WHERE (blocker_id = ? AND blocked_id = ?) OR (blocker_id = ? AND blocked_id = ?)",
            (a, b, b, a),
        )
        .fetchone()
        is not None
    )


def target_user(data):
    other = find_user_by_name(data.get("username") or data.get("friend_username"))
    if other is None:
        flask.abort(flask.make_response(error("User not found", 404)))
    return other


def users_by_query(sql, params):
    return [public_user(row) for row in get_db().execute(sql, params)]


@app.route("/api/friends")
@login_required
def list_friends():
    me_id = current_user()["id"]
    return ok(
        friends=users_by_query(
            """SELECT u.id, u.username, u.display_name FROM friendships f JOIN users u
               ON u.id = CASE WHEN f.user_a = ? THEN f.user_b ELSE f.user_a END
               WHERE f.user_a = ? OR f.user_b = ? ORDER BY COALESCE(u.display_name, u.username) COLLATE NOCASE""",
            (me_id, me_id, me_id),
        ),
        incoming=users_by_query(
            """SELECT u.id, u.username, u.display_name FROM friend_requests r JOIN users u ON u.id = r.from_id
               WHERE r.to_id = ? ORDER BY r.created_at""",
            (me_id,),
        ),
        outgoing=users_by_query(
            """SELECT u.id, u.username, u.display_name FROM friend_requests r JOIN users u ON u.id = r.to_id
               WHERE r.from_id = ? ORDER BY r.created_at""",
            (me_id,),
        ),
        blocked=users_by_query(
            """SELECT u.id, u.username, u.display_name FROM blocks b JOIN users u ON u.id = b.blocked_id
               WHERE b.blocker_id = ? ORDER BY u.username COLLATE NOCASE""",
            (me_id,),
        ),
    )


def make_friends(conn, a, b):
    conn.execute(
        "INSERT OR IGNORE INTO friendships (user_a, user_b, created_at) VALUES (?, ?, ?)",
        (*pair(a, b), db.now_iso()),
    )
    conn.execute(
        "DELETE FROM friend_requests WHERE (from_id = ? AND to_id = ?) OR (from_id = ? AND to_id = ?)",
        (a, b, b, a),
    )


@app.route("/api/friends/request", methods=["POST"])
@app.route("/api/add_friend", methods=["POST"])
@login_required
def request_friend():
    return send_friend_request(current_user()["id"], target_user(json_body()))


def send_friend_request(me_id, other):
    if rate_limited(("friend-request", me_id), 30, 600):
        return error("Too many friend requests, please wait", 429)
    if other["id"] == me_id:
        return error("Cannot add yourself as a friend")
    if are_friends(me_id, other["id"]):
        return error("Already Friends")
    if is_blocked_between(me_id, other["id"]):
        # Do not reveal who blocked whom.
        return error("Friend request could not be sent")
    conn = get_db()
    if conn.execute(
        "SELECT 1 FROM friend_requests WHERE from_id = ? AND to_id = ?", (other["id"], me_id)
    ).fetchone():
        make_friends(conn, me_id, other["id"])
        conn.commit()
        return ok(message="Friend added successfully!", status="friends")
    if conn.execute(
        "SELECT 1 FROM friend_requests WHERE from_id = ? AND to_id = ?", (me_id, other["id"])
    ).fetchone():
        return error("Already pending request")
    conn.execute(
        "INSERT INTO friend_requests (from_id, to_id, created_at) VALUES (?, ?, ?)",
        (me_id, other["id"], db.now_iso()),
    )
    conn.commit()
    return ok(message="Request sent", status="pending")


# ------------------------------------------------------------ invite links


def invite_token(user_id, renew=False):
    conn = get_db()
    row = conn.execute("SELECT token FROM friend_invites WHERE user_id = ?", (user_id,)).fetchone()
    if row and not renew:
        return row["token"]
    token = secrets.token_urlsafe(16)
    conn.execute(
        "INSERT INTO friend_invites (token, user_id, created_at) VALUES (?, ?, ?) "
        "ON CONFLICT(user_id) DO UPDATE SET token = excluded.token, created_at = excluded.created_at",
        (token, user_id, db.now_iso()),
    )
    conn.commit()
    return token


def invite_owner(token):
    if rate_limited(("invite", client_ip()), 60, 60):
        flask.abort(flask.make_response(error("Too many requests, please wait", 429)))
    row = get_db().execute(
        """SELECT u.* FROM friend_invites i JOIN users u ON u.id = i.user_id
           WHERE i.token = ?""",
        (token[:64],),
    ).fetchone()
    if row is None:
        flask.abort(flask.make_response(error("This invite link is invalid or expired", 404)))
    return row


@app.route("/api/invite")
@login_required
def my_invite():
    return ok(token=invite_token(current_user()["id"]))


@app.route("/api/invite/renew", methods=["POST"])
@login_required
def renew_invite():
    # The old link stops working.
    return ok(token=invite_token(current_user()["id"], renew=True))


@app.route("/api/invite/<token>")
@login_required
def show_invite(token):
    owner = invite_owner(token)
    me_id = current_user()["id"]
    status = "self" if owner["id"] == me_id else "friends" if are_friends(me_id, owner["id"]) else "none"
    return ok(user=public_user(owner), status=status)


@app.route("/api/invite/<token>/accept", methods=["POST"])
@login_required
def accept_invite(token):
    return send_friend_request(current_user()["id"], invite_owner(token))


@app.route("/api/friends/accept", methods=["POST"])
@login_required
def accept_friend():
    me_id = current_user()["id"]
    other = target_user(json_body())
    conn = get_db()
    if not conn.execute(
        "SELECT 1 FROM friend_requests WHERE from_id = ? AND to_id = ?", (other["id"], me_id)
    ).fetchone():
        return error("Request doesnt exist")
    make_friends(conn, me_id, other["id"])
    conn.commit()
    return ok(message="Friend added successfully!")


@app.route("/api/friends/decline", methods=["POST"])
@app.route("/api/discard_request", methods=["POST"])
@login_required
def decline_friend():
    me_id = current_user()["id"]
    other = target_user(json_body())
    conn = get_db()
    cur = conn.execute(
        "DELETE FROM friend_requests WHERE from_id = ? AND to_id = ?", (other["id"], me_id)
    )
    conn.commit()
    if cur.rowcount == 0:
        return error("Request doesnt exist")
    return ok(message="successfully deleted the request")


@app.route("/api/friends/cancel", methods=["POST"])
@login_required
def cancel_friend_request():
    me_id = current_user()["id"]
    other = target_user(json_body())
    conn = get_db()
    conn.execute("DELETE FROM friend_requests WHERE from_id = ? AND to_id = ?", (me_id, other["id"]))
    conn.commit()
    return ok(message="Request cancelled")


@app.route("/api/friends/remove", methods=["POST"])
@login_required
def remove_friend():
    me_id = current_user()["id"]
    other = target_user(json_body())
    conn = get_db()
    conn.execute("DELETE FROM friendships WHERE user_a = ? AND user_b = ?", pair(me_id, other["id"]))
    conn.commit()
    return ok(message="Friend removed")


@app.route("/api/block", methods=["POST"])
@app.route("/api/block_user", methods=["POST"])
@login_required
def block_user():
    me_id = current_user()["id"]
    other = target_user(json_body())
    if other["id"] == me_id:
        return error("Cannot block yourself")
    conn = get_db()
    conn.execute(
        "INSERT OR IGNORE INTO blocks (blocker_id, blocked_id, created_at, was_friend) VALUES (?, ?, ?, ?)",
        (me_id, other["id"], db.now_iso(), int(are_friends(me_id, other["id"]))),
    )
    conn.execute("DELETE FROM friendships WHERE user_a = ? AND user_b = ?", pair(me_id, other["id"]))
    conn.execute(
        "DELETE FROM friend_requests WHERE (from_id = ? AND to_id = ?) OR (from_id = ? AND to_id = ?)",
        (me_id, other["id"], other["id"], me_id),
    )
    conn.commit()
    return ok(message="User blocked")


@app.route("/api/unblock", methods=["POST"])
@login_required
def unblock_user():
    me_id = current_user()["id"]
    other = target_user(json_body())
    conn = get_db()
    row = conn.execute(
        "SELECT was_friend FROM blocks WHERE blocker_id = ? AND blocked_id = ?", (me_id, other["id"])
    ).fetchone()
    conn.execute("DELETE FROM blocks WHERE blocker_id = ? AND blocked_id = ?", (me_id, other["id"]))
    restored = bool(row and row["was_friend"]) and not is_blocked_between(me_id, other["id"])
    if restored:
        make_friends(conn, me_id, other["id"])
    conn.commit()
    return ok(message="User unblocked", friends=restored)


def is_muted(me_id, other_id):
    return (
        get_db()
        .execute("SELECT 1 FROM muted_users WHERE user_id = ? AND muted_id = ?", (me_id, other_id))
        .fetchone()
        is not None
    )


@app.route("/api/users/mute", methods=["POST"])
@login_required
def mute_user():
    me_id = current_user()["id"]
    data = json_body()
    other = target_user(data)
    conn = get_db()
    if data.get("muted") is True:
        conn.execute(
            "INSERT OR IGNORE INTO muted_users (user_id, muted_id, created_at) VALUES (?, ?, ?)",
            (me_id, other["id"], db.now_iso()),
        )
    else:
        conn.execute("DELETE FROM muted_users WHERE user_id = ? AND muted_id = ?", (me_id, other["id"]))
    conn.commit()
    return ok(muted=data.get("muted") is True)


@app.route("/api/users/<username>/profile")
@login_required
def user_profile(username):
    me_id = current_user()["id"]
    other = find_user_by_name(username)
    if other is None:
        return error("User not found", 404)
    conn = get_db()
    request_row = conn.execute(
        "SELECT from_id FROM friend_requests WHERE (from_id = ? AND to_id = ?) OR (from_id = ? AND to_id = ?)",
        (me_id, other["id"], other["id"], me_id),
    ).fetchone()
    return ok(
        user={**public_user(other), "pub_ecdh": other["pub_ecdh"], "pub_sign": other["pub_sign"]},
        is_me=other["id"] == me_id,
        friend=are_friends(me_id, other["id"]),
        blocked=conn.execute(
            "SELECT 1 FROM blocks WHERE blocker_id = ? AND blocked_id = ?", (me_id, other["id"])
        ).fetchone()
        is not None,
        muted=is_muted(me_id, other["id"]),
        request=None if request_row is None else "outgoing" if request_row["from_id"] == me_id else "incoming",
    )


# --------------------------------------------------------------------------
# Chats
# --------------------------------------------------------------------------


def membership(chat_id, user_id):
    return (
        get_db()
        .execute(
            """SELECT c.*, m.role, m.joined_seq, m.cleared_seq, m.last_read_seq, m.hidden
               FROM chats c JOIN chat_members m ON m.chat_id = c.id
               WHERE c.id = ? AND m.user_id = ?""",
            (chat_id, user_id),
        )
        .fetchone()
    )


def require_membership(chat_id):
    chat = membership(chat_id, current_user()["id"])
    if chat is None:
        flask.abort(flask.make_response(error("Chat not found", 404)))
    return chat


def chat_members(chat_id):
    return get_db().execute(
        """SELECT u.id, u.username, u.display_name, u.pub_ecdh, u.pub_sign, m.role
           FROM chat_members m JOIN users u ON u.id = m.user_id
           WHERE m.chat_id = ? ORDER BY m.joined_at, u.username COLLATE NOCASE""",
        (chat_id,),
    ).fetchall()


def max_seq(conn, chat_id):
    return conn.execute(
        "SELECT COALESCE(MAX(seq), 0) AS s FROM messages WHERE chat_id = ?", (chat_id,)
    ).fetchone()["s"]


def serialize_message(row):
    payload = None
    if not row["deleted"] and row["payload"]:
        try:
            payload = json.loads(row["payload"])
        except ValueError:
            payload = None
    return {
        "seq": row["seq"],
        "rev": row["rev"],
        "id": row["id"],
        "sender_id": row["sender_id"],
        "sender": row["sender"],
        "sender_display": row["sender_display"] or row["sender"],
        "kind": row["kind"],
        "payload": payload,
        "created_at": row["created_at"],
        "deleted": bool(row["deleted"]),
    }


MESSAGE_SELECT = """SELECT m.*, u.username AS sender, u.display_name AS sender_display FROM messages m
                    LEFT JOIN users u ON u.id = m.sender_id"""


def add_system_message(conn, chat_id, event, **details):
    rev = db.next_rev(conn)
    conn.execute(
        "INSERT INTO messages (id, chat_id, sender_id, kind, payload, created_at, rev) VALUES (?, ?, NULL, 'system', ?, ?, ?)",
        (str(uuid.uuid4()), chat_id, json.dumps({"event": event, **details}), db.now_iso(), rev),
    )
    conn.execute("UPDATE chats SET last_activity = ? WHERE id = ?", (db.now_iso(), chat_id))


def add_member(conn, chat_id, user_id, role="member"):
    conn.execute(
        """INSERT INTO chat_members (chat_id, user_id, role, joined_at, joined_seq, cleared_seq, last_read_seq)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (chat_id, user_id, role, db.now_iso(), max_seq(conn, chat_id), 0, max_seq(conn, chat_id)),
    )


def chat_summary(chat, me_id):
    conn = get_db()
    floor = max(chat["joined_seq"], chat["cleared_seq"])
    last = conn.execute(
        MESSAGE_SELECT + " WHERE m.chat_id = ? AND m.seq > ? ORDER BY m.seq DESC LIMIT 1",
        (chat["id"], floor),
    ).fetchone()
    unread = conn.execute(
        """SELECT COUNT(*) AS c FROM messages WHERE chat_id = ? AND seq > ? AND deleted = 0
           AND kind != 'system' AND (sender_id IS NULL OR sender_id != ?)""",
        (chat["id"], max(floor, chat["last_read_seq"]), me_id),
    ).fetchone()["c"]
    members = chat_members(chat["id"])
    summary = {
        "id": chat["id"],
        "chat": chat["id"],
        "type": chat["type"],
        "name": chat["name"],
        "role": chat["role"],
        "member_count": len(members),
        "last_message": serialize_message(last) if last else None,
        "unread": unread,
        "last_activity": chat["last_activity"],
    }
    if chat["type"] == "dm":
        others = [m for m in members if m["id"] != me_id]
        other = others[0] if others else None
        summary["other_user"] = other["username"] if other else "Unknown User"
        summary["other_user_id"] = other["id"] if other else None
        summary["name"] = display_name(other) if other else summary["other_user"]
        summary["blocked"] = bool(other) and is_blocked_between(me_id, other["id"])
        summary["muted"] = bool(other) and is_muted(me_id, other["id"])
    return summary


@app.route("/api/chats")
@app.route("/api/load_chats")
@login_required
def list_chats():
    me_id = current_user()["id"]
    rows = get_db().execute(
        """SELECT c.*, m.role, m.joined_seq, m.cleared_seq, m.last_read_seq, m.hidden
           FROM chats c JOIN chat_members m ON m.chat_id = c.id
           WHERE m.user_id = ? AND m.hidden = 0 ORDER BY c.last_activity DESC""",
        (me_id,),
    ).fetchall()
    return ok(chats=[chat_summary(row, me_id) for row in rows])


def open_dm(me_id, other):
    if other["id"] == me_id:
        return error("Cannot create chat with yourself")
    if is_blocked_between(me_id, other["id"]):
        return error("Cannot create chat with this user")
    a, b = pair(me_id, other["id"])
    conn = get_db()
    existing = conn.execute("SELECT id FROM chats WHERE dm_key = ?", (f"{a}:{b}",)).fetchone()
    if existing:
        mine = membership(existing["id"], me_id)
        if mine is None:
            add_member(conn, existing["id"], me_id)
        else:
            conn.execute(
                "UPDATE chat_members SET hidden = 0 WHERE chat_id = ? AND user_id = ?",
                (existing["id"], me_id),
            )
        conn.commit()
        return ok(chat_id=existing["id"], message="Chat already exists", existing=True)
    if not are_friends(me_id, other["id"]):
        return error("Cannot create chat with a user who is not your friend")
    chat_id = str(uuid.uuid4())
    now = db.now_iso()
    conn.execute(
        "INSERT INTO chats (id, type, name, owner_id, dm_key, created_at, last_activity) VALUES (?, 'dm', NULL, NULL, ?, ?, ?)",
        (chat_id, f"{a}:{b}", now, now),
    )
    add_member(conn, chat_id, me_id)
    add_member(conn, chat_id, other["id"])
    conn.commit()
    return ok(chat_id=chat_id, message="Chat created successfully!")


@app.route("/api/profile/display_name", methods=["POST"])
@login_required
def set_display_name():
    value = json_body().get("display_name")
    if value is not None and not isinstance(value, str):
        return error("Invalid display name")
    value = " ".join((value or "").split())  # no line breaks or repeated spaces
    if len(value) > 32:
        return error("Display name can be at most 32 characters")
    conn = get_db()
    conn.execute("UPDATE users SET display_name = ? WHERE id = ?", (value or None, current_user()["id"]))
    conn.commit()
    return ok(display_name=value or current_user()["username"])


def validate_group_name(value):
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > 64:
        flask.abort(flask.make_response(error("Group name must be 1-64 characters")))
    return value.strip()


@app.route("/api/chats", methods=["POST"])
@login_required
def create_chat():
    data = json_body()
    me = current_user()
    if data.get("type", "dm") == "dm":
        return open_dm(me["id"], target_user(data))

    name = validate_group_name(data.get("name"))
    usernames = data.get("usernames")
    if not isinstance(usernames, list) or not usernames:
        return error("Pick at least one friend for the group")
    members = {}
    for username in usernames:
        other = find_user_by_name(username)
        if other is None or not are_friends(me["id"], other["id"]):
            return error(f"{username} is not your friend")
        members[other["id"]] = other
    members.pop(me["id"], None)
    if not members or len(members) + 1 > MAX_GROUP_MEMBERS:
        return error(f"A group needs 2-{MAX_GROUP_MEMBERS} members")

    conn = get_db()
    chat_id = str(uuid.uuid4())
    now = db.now_iso()
    conn.execute(
        "INSERT INTO chats (id, type, name, owner_id, dm_key, created_at, last_activity) VALUES (?, 'group', ?, ?, NULL, ?, ?)",
        (chat_id, name, me["id"], now, now),
    )
    add_member(conn, chat_id, me["id"], "owner")
    for user_id in members:
        add_member(conn, chat_id, user_id)
    add_system_message(conn, chat_id, "created", actor=display_name(me), name=name)
    conn.commit()
    return ok(chat_id=chat_id, message="Group created successfully!")


@app.route("/api/new_chat", methods=["POST"])
@login_required
def new_chat_legacy():
    return open_dm(current_user()["id"], target_user(json_body()))


@app.route("/api/chats/<chat_id>")
@login_required
def chat_details(chat_id):
    chat = require_membership(chat_id)
    me_id = current_user()["id"]
    summary = chat_summary(chat, me_id)
    summary["members"] = [{**dict(row), "display_name": display_name(row)} for row in chat_members(chat_id)]
    summary["owner_id"] = chat["owner_id"]
    return ok(chat=summary)


@app.route("/api/chats/<chat_id>/messages")
@login_required
def get_chat_messages(chat_id):
    chat = require_membership(chat_id)
    floor = max(chat["joined_seq"], chat["cleared_seq"])
    args = flask.request.args
    limit = min(max(args.get("limit", 50, type=int), 1), 200)
    conn = get_db()
    if args.get("since_rev") is not None:
        rows = conn.execute(
            MESSAGE_SELECT + " WHERE m.chat_id = ? AND m.seq > ? AND m.rev > ? ORDER BY m.rev ASC LIMIT ?",
            (chat_id, floor, args.get("since_rev", 0, type=int), limit),
        ).fetchall()
    else:
        before = args.get("before_seq", type=int)
        rows = conn.execute(
            MESSAGE_SELECT
            + " WHERE m.chat_id = ? AND m.seq > ? AND m.seq < ? ORDER BY m.seq DESC LIMIT ?",
            (chat_id, floor, before if before else 2**62, limit),
        ).fetchall()[::-1]
    return ok(messages=[serialize_message(row) for row in rows], has_more=len(rows) == limit)


@app.route("/api/get_messages")
@login_required
def get_messages_legacy():
    return get_chat_messages(flask.request.args.get("chat_id", ""))


def validate_envelope(payload, member_ids):
    if not isinstance(payload, dict) or payload.get("v") != 1:
        return "Unsupported message format"
    for field, max_len in (("iv", 64), ("sig", 256), ("ct", MAX_CIPHERTEXT_LEN)):
        value = payload.get(field)
        if not isinstance(value, str) or not value or len(value) > max_len or not B64_RE.match(value):
            return f"Invalid '{field}'"
    keys = payload.get("keys")
    if not isinstance(keys, dict) or set(keys) != set(member_ids):
        return "Message must be encrypted for exactly the current chat members"
    for wrapped in keys.values():
        if not isinstance(wrapped, dict):
            return "Invalid key"
        for field in ("iv", "k"):
            value = wrapped.get(field)
            if not isinstance(value, str) or len(value) > 128 or not B64_RE.match(value):
                return "Invalid key"
    if set(payload) - {"v", "iv", "ct", "sig", "keys"}:
        return "Unknown fields in message"
    return None


@app.route("/api/chats/<chat_id>/messages", methods=["POST"])
@login_required
def post_message(chat_id):
    me_id = current_user()["id"]
    chat = require_membership(chat_id)
    data = json_body()
    message_id = str_field(data, "id", 64)
    try:
        uuid.UUID(message_id)
    except ValueError:
        return error("Invalid message id")
    if rate_limited(("send", me_id), 30, 10):
        return error("You are sending messages too fast", 429)

    members = chat_members(chat_id)
    if chat["type"] == "dm":
        others = [m["id"] for m in members if m["id"] != me_id]
        if others and is_blocked_between(me_id, others[0]):
            return error("You can't send messages to this chat", 403)
    problem = validate_envelope(data.get("payload"), [m["id"] for m in members])
    if problem:
        return error(problem, 409 if "members" in problem else 400)

    conn = get_db()
    try:
        with db.write_transaction(conn):
            rev = db.next_rev(conn)
            cur = conn.execute(
                "INSERT INTO messages (id, chat_id, sender_id, kind, payload, created_at, rev) VALUES (?, ?, ?, 'e2e', ?, ?, ?)",
                (message_id, chat_id, me_id, json.dumps(data["payload"]), db.now_iso(), rev),
            )
            conn.execute("UPDATE chats SET last_activity = ? WHERE id = ?", (db.now_iso(), chat_id))
            conn.execute("UPDATE chat_members SET hidden = 0 WHERE chat_id = ?", (chat_id,))
            conn.execute(
                "UPDATE chat_members SET last_read_seq = ? WHERE chat_id = ? AND user_id = ?",
                (cur.lastrowid, chat_id, me_id),
            )
    except sqlite3.IntegrityError:
        return error("Duplicate message id", 409)
    return ok(message="Message sent successfully!", seq=cur.lastrowid, rev=rev)


@app.route("/api/send_message", methods=["POST"])
@login_required
def send_message_legacy():
    return error("This client is outdated. Please reload the page to use encrypted messaging.", 410)


@app.route("/api/chats/<chat_id>/messages/<message_id>/delete", methods=["POST"])
@login_required
def delete_message(chat_id, message_id):
    require_membership(chat_id)
    conn = get_db()
    with db.write_transaction(conn):
        cur = conn.execute(
            "UPDATE messages SET deleted = 1, payload = NULL, rev = ? WHERE id = ? AND chat_id = ? AND sender_id = ? AND deleted = 0",
            (db.next_rev(conn), message_id, chat_id, current_user()["id"]),
        )
    if cur.rowcount == 0:
        return error("Message not found", 404)
    return ok(message="Message deleted")


@app.route("/api/chats/<chat_id>/read", methods=["POST"])
@login_required
def mark_read(chat_id):
    require_membership(chat_id)
    seq = json_body().get("seq")
    if not isinstance(seq, int):
        return error("Invalid seq")
    conn = get_db()
    conn.execute(
        "UPDATE chat_members SET last_read_seq = MAX(last_read_seq, MIN(?, ?)) WHERE chat_id = ? AND user_id = ?",
        (seq, max_seq(conn, chat_id), chat_id, current_user()["id"]),
    )
    conn.commit()
    return ok()


def require_group(chat, owner_only=False):
    if chat["type"] != "group":
        flask.abort(flask.make_response(error("Only possible in groups")))
    if owner_only and chat["role"] != "owner":
        flask.abort(flask.make_response(error("Only the group owner can do that", 403)))


@app.route("/api/chats/<chat_id>/members", methods=["POST"])
@login_required
def add_group_member(chat_id):
    me = current_user()
    chat = require_membership(chat_id)
    require_group(chat)
    other = target_user(json_body())
    if not are_friends(me["id"], other["id"]):
        return error("You can only add your friends")
    if membership(chat_id, other["id"]):
        return error("Already in the group")
    conn = get_db()
    if len(chat_members(chat_id)) >= MAX_GROUP_MEMBERS:
        return error("The group is full")
    with db.write_transaction(conn):
        add_member(conn, chat_id, other["id"])
        add_system_message(conn, chat_id, "added", actor=display_name(me), target=display_name(other))
    return ok(message="Member added")


def leave_chat(conn, chat, user):
    chat_id = chat["id"]
    conn.execute("DELETE FROM chat_members WHERE chat_id = ? AND user_id = ?", (chat_id, user["id"]))
    remaining = chat_members(chat_id)
    if not remaining:
        conn.execute("DELETE FROM messages WHERE chat_id = ?", (chat_id,))
        conn.execute("DELETE FROM chats WHERE id = ?", (chat_id,))
        return
    if chat["owner_id"] == user["id"]:
        new_owner = remaining[0]
        conn.execute("UPDATE chats SET owner_id = ? WHERE id = ?", (new_owner["id"], chat_id))
        conn.execute(
            "UPDATE chat_members SET role = 'owner' WHERE chat_id = ? AND user_id = ?",
            (chat_id, new_owner["id"]),
        )
    add_system_message(conn, chat_id, "left", actor=display_name(user))


@app.route("/api/chats/<chat_id>/members/remove", methods=["POST"])
@login_required
def remove_group_member(chat_id):
    me = current_user()
    chat = require_membership(chat_id)
    require_group(chat, owner_only=True)
    other = target_user(json_body())
    if other["id"] == me["id"]:
        return error("Use 'leave group' instead")
    if not membership(chat_id, other["id"]):
        return error("Not a member")
    conn = get_db()
    with db.write_transaction(conn):
        conn.execute("DELETE FROM chat_members WHERE chat_id = ? AND user_id = ?", (chat_id, other["id"]))
        add_system_message(conn, chat_id, "removed", actor=display_name(me), target=display_name(other))
    return ok(message="Member removed")


@app.route("/api/chats/<chat_id>/rename", methods=["POST"])
@login_required
def rename_group(chat_id):
    me = current_user()
    chat = require_membership(chat_id)
    require_group(chat, owner_only=True)
    name = validate_group_name(json_body().get("name"))
    conn = get_db()
    with db.write_transaction(conn):
        conn.execute("UPDATE chats SET name = ? WHERE id = ?", (name, chat_id))
        add_system_message(conn, chat_id, "renamed", actor=display_name(me), name=name)
    return ok(message="Group renamed")


@app.route("/api/chats/<chat_id>/leave", methods=["POST"])
@app.route("/api/chats/<chat_id>/delete", methods=["POST"])
@login_required
def delete_chat(chat_id):
    me = current_user()
    chat = require_membership(chat_id)
    conn = get_db()
    with db.write_transaction(conn):
        if chat["type"] == "group":
            leave_chat(conn, chat, me)
        else:
            # Like WhatsApp: deleting a direct chat only clears it for yourself.
            conn.execute(
                "UPDATE chat_members SET hidden = 1, cleared_seq = ? WHERE chat_id = ? AND user_id = ?",
                (max_seq(conn, chat_id), chat_id, me["id"]),
            )
    return ok(message="Chat deleted successfully")


@app.route("/api/remove_chat", methods=["POST"])
@login_required
def remove_chat_legacy():
    return delete_chat(str_field(json_body(), "chat_id", 64))


@app.route("/api/pending_friends")
@login_required
def pending_friends_legacy():
    me_id = current_user()["id"]
    names = [
        row["username"]
        for row in get_db().execute(
            "SELECT u.username FROM friend_requests r JOIN users u ON u.id = r.from_id WHERE r.to_id = ?",
            (me_id,),
        )
    ]
    return ok(pending_friends=names)


init_app()
start_heartbeat()

if __name__ == "__main__":
    # Never enable the Werkzeug debugger on a public interface by default.
    app.config["DEBUG"] = os.getenv("SERES_DEBUG") == "1"
    app.run(host=os.getenv("HOST", "0.0.0.0"), port=int(os.getenv("PORT", "5000")), threaded=True)
