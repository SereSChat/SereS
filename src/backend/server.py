import flask
from flask import g
import sqlite3
import datetime
import os
import secrets
import uuid
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# TODO: add /api/load_chats
# TODO: add /api/add_friends
# TODO: add /api/get_avatar
# TODO: add /api/upload_avatar

app = flask.Flask(__name__, static_folder="../public", static_url_path="/")
DB = os.path.join(os.path.dirname(__file__), "users.db")
ph = PasswordHasher(time_cost=4)


def init_db():
    conn = sqlite3.connect(DB)
    cursor = conn.cursor()
    cursor.execute(
        "CREATE TABLE IF NOT EXISTS users (id VARCHAR(255) PRIMARY KEY, email VARCHAR(255), username VARCHAR(255), passwd TEXT)"
    )
    cursor.execute(
        "CREATE TABLE IF NOT EXISTS sessions (id VARCHAR(255) PRIMARY KEY, cookie VARCHAR(255), user_id VARCHAR(255), expires_at TIMESTAMP, created_at TIMESTAMP)"  # ID = UUID
    )
    conn.commit()
    conn.close()


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


@app.route("/")
def index():
    return app.send_static_file("index.html")


@app.route("/api/online")
def online():
    return {"message": "im up", "success": True}, 200


@app.route("/api/register", methods=["POST"])
def register():
    conn = get_db()
    cursor = conn.cursor()

    json = flask.request.get_json()
    hashed_passwd = ph.hash(json["passwd"])
    username = json["username"]
    if username_available(username):
        cursor.execute(
            "INSERT INTO users (id, email, username, passwd) VALUES (?, ?, ?, ?)",
            (
                str(uuid.uuid4()),
                json["email"],
                json["username"],
                hashed_passwd,
            ),
        )
        conn.commit()
        return {"message": "User created successfully!", "success": True}, 200
    else:
        return {"message": "Username already taken"}, 400


@app.route("/api/login", methods=["POST"])
def login():
    conn = get_db()
    cursor = conn.cursor()
    json = flask.request.get_json()
    nameomail = json["nameomail"]
    if nameomail and json["passwd"]:
        if "@" in nameomail:
            cursor.execute(
                "SELECT passwd FROM users WHERE email = ?",
                (nameomail,),
            )
        else:
            cursor.execute(
                "SELECT passwd FROM users WHERE username = ?",
                (nameomail,),
            )

        passwd = cursor.fetchone()

        if passwd:
            try:
                if ph.verify(passwd[0], json["passwd"]):
                    username, tid = get_username_and_id(cursor, nameomail)
                    response = flask.make_response(
                        {
                            "message": "Login succesfull!",
                            "success": True,
                        }
                    )
                    response.set_cookie("sessioncookie", generate_session_cookie(tid))
                    response.set_cookie("username", username)
                    return response, 200
                else:
                    return {"message": "Login not succesfull"}, 400
            except VerifyMismatchError:
                return {"message": "Login not succesfull"}, 400
        else:
            return {"message": "Login not succesfull"}, 400
    else:
        return {"message": "Login not succesfull, missing Arguments"}, 400


def get_username_and_id(cursor, nameomail):
    if "@" in nameomail:
        cursor.execute("SELECT username, id FROM users WHERE email = ?", (nameomail,))
        data = cursor.fetchone()
        username = data["username"]
        tid = data["id"]
    else:
        cursor.execute(
            "SELECT username, id FROM users WHERE username = ?", (nameomail,)
        )
        data = cursor.fetchone()
        username = data["username"]
        tid = data["id"]

    return username, tid


def generate_session_cookie(user_id):
    conn = get_db()
    cookie = str(secrets.token_urlsafe(16))
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO sessions (id, cookie, user_id, expires_at, created_at) VALUES (?, ?, ?, datetime('now'), datetime('now', '+1 year'))",
        (
            str(uuid.uuid4()),
            cookie,
            user_id,
        ),
    )
    conn.commit()
    return cookie


@app.route("/api/auth_cookie", methods=["POST"])
def auth_session_cookie():
    conn = get_db()
    cursor = conn.cursor()
    sessioncookie = flask.request.cookies.get("sessioncookie")
    cursor.execute(
        "SELECT expires_at FROM sessions WHERE cookie = ?",
        (sessioncookie,),
    )
    print("got cookie: ", sessioncookie)
    try:
        expire_date = cursor.fetchone()["expires_at"]
        print(expire_date)
    except Exception:
        return {"message": "Cookie invalid"}, 400
    if datetime.datetime.now() > expire_date:
        return {"message": "Cookie valid", "success": True}, 200
    else:
        return {"message": "Cookie expired"}, 400


def username_available(username: str) -> bool:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM users WHERE username = ?", (username,))
    return cursor.fetchone() is None


if __name__ == "__main__":
    with app.app_context():
        init_db()
    app.run(host="0.0.0.0", port=5000)
