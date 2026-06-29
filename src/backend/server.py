import flask
from flask import g
import sqlite3
import datetime
import os
import json
import secrets
import uuid
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

# TODO: add /api/get_avatar
# TODO: add /api/upload_avatar

app = flask.Flask(__name__, static_folder="../public", static_url_path="/")
CHATS = os.path.join(os.path.dirname(__file__), "chats")
DB = os.path.join(os.path.dirname(__file__), "users.db")
FRIENDS = os.path.join(os.path.dirname(__file__), "friends")
ph = PasswordHasher(time_cost=4)


def init_db():
    conn = get_db()
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


def get_chat_db(chat_id):
    chat_db_path = os.path.join(CHATS, chat_id, "history.db")
    if not os.path.exists(chat_db_path):
        raise FileNotFoundError(f"Chat database for chat_id {chat_id} does not exist.")

    if "chat_db" not in g:
        g.chat_db = sqlite3.connect(chat_db_path, detect_types=sqlite3.PARSE_DECLTYPES)
        g.chat_db.row_factory = sqlite3.Row
    return g.chat_db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()

    chat_db = g.pop("chat_db", None)
    if chat_db is not None:
        chat_db.close()


@app.route("/")
def index():
    return app.send_static_file("index.html")


@app.route("/api/online", methods=["GET", "POST"])
def online():
    return {"message": "im up", "success": True}, 200


@app.route("/api/register", methods=["POST"])
def register():
    conn = get_db()
    cursor = conn.cursor()

    req_json = flask.request.get_json()
    hashed_passwd = ph.hash(req_json["passwd"])
    try:
        username = req_json["username"]
        email = req_json["email"]
    except KeyError:
        return {"message": "Missing username or email in request body"}, 400
    if username_available(username):
        cursor.execute(
            "INSERT INTO users (id, email, username, passwd) VALUES (?, ?, ?, ?)",
            (
                str(uuid.uuid4()),
                email,
                username,
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
    req_json = flask.request.get_json()
    try:
        nameomail = req_json["nameomail"]
    except KeyError:
        return {"message": "Missing nameomail in request body"}, 400
    if nameomail and req_json["passwd"]:
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
                req_passwd = req_json["passwd"]
            except KeyError:
                return {"message": "Missing passwd in request body"}, 400
            try:
                if ph.verify(passwd[0], req_passwd):
                    username, tid = get_username_and_id(cursor, nameomail)
                    if not username or not tid:
                        return {"message": "Login not succesfull"}, 400
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


@app.route("/api/logout", methods=["POST"])
def logout():
    if not flask.request.cookies.get("sessioncookie"):
        return {"message": "Logout not succesfull, no sessioncookie"}, 400
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "DELETE FROM sessions WHERE cookie = ?",
            (flask.request.cookies.get("sessioncookie"),),
        )
        conn.commit()
    except Exception as e:
        print(e)
        return {"message": "Logout not succesfull, internal error"}, 400
    response = flask.make_response(
        {
            "message": "Logout succesfull!",
            "success": True,
        }
    )
    response.set_cookie("sessioncookie", "")
    response.set_cookie("username", "")

    return response, 200


@app.route("/api/add_friend", methods=["POST"])
def add_friend():  # TODO: add a function which asks the being added user to accept
    sessioncookie = flask.request.cookies.get("sessioncookie")
    if not sessioncookie:
        return {"message": "No sessioncookie provided"}, 400
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT user_id FROM sessions WHERE cookie = ?",
        (sessioncookie,),
    )
    try:
        user_id = cursor.fetchone()["user_id"]
    except Exception as e:
        print(e)
        return {"message": "Invalid sessioncookie"}, 400
    req_json = flask.request.get_json()
    try:
        friend_username = req_json["friend_username"]
    except KeyError:
        return {"message": "Missing friend_username in request body"}, 400
    cursor.execute("SELECT id FROM users WHERE username = ?", (friend_username,))
    try:
        friend_id = cursor.fetchone()["id"]
    except Exception as e:
        print(e)
        return {"message": "Friend username not found"}, 400
    if user_id == friend_id:
        return {"message": "Cannot add yourself as a friend"}, 400
    try:
        with open(os.path.join(FRIENDS, user_id + ".json"), "x") as f:
            json.dump({"friends": [friend_id]}, f)
    except FileExistsError:
        with open(os.path.join(FRIENDS, user_id + ".json"), "r+") as f:
            data = json.load(f)
            if friend_id in data["friends"]:
                return {"message": "Friend already added"}, 400
            data["friends"].append(friend_id)
            f.seek(0)
            json.dump(data, f)
            f.truncate()
    return {"message": "Friend added successfully!", "success": True}, 200


@app.route("/api/new_chat", methods=["POST"])
def new_chat():
    sessioncookie = flask.request.cookies.get("sessioncookie")
    if not sessioncookie:
        return {"message": "No sessioncookie provided"}, 400
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT user_id FROM sessions WHERE cookie = ?",
        (sessioncookie,),
    )
    try:
        user_id = cursor.fetchone()["user_id"]
    except Exception as e:
        print(e)
        return {"message": "Invalid sessioncookie"}, 400
    req_json = flask.request.get_json()
    try:
        friend_username = req_json["friend_username"]
    except KeyError:
        return {"message": "Missing friend_username in request body"}, 400
    cursor.execute("SELECT id FROM users WHERE username = ?", (friend_username,))
    try:
        friend_id = cursor.fetchone()["id"]
    except Exception as e:
        print(e)
        return {"message": "Friend username not found"}, 400

    if user_id == friend_id:
        return {"message": "Cannot create chat with yourself"}, 400

    if friend_id not in get_friends_for_user(user_id):
        return {"message": "Cannot create chat with a user who is not your friend"}, 400

    chat_id = str(uuid.uuid4())

    chats = return_chats_for_user(user_id)
    for chat in chats:
        with open(os.path.join(CHATS, chat, "users.json"), "r") as f:
            data = json.load(f)
            if friend_id in data["users"]:
                return {"message": "Chat already exists"}, 400
    try:
        os.makedirs(os.path.join(CHATS, chat_id), exist_ok=False)
    except FileExistsError:
        while True:
            chat_id = str(uuid.uuid4())
            try:
                os.makedirs(os.path.join(CHATS, chat_id), exist_ok=False)
                break
            except FileExistsError:
                continue
    with open(os.path.join(CHATS, chat_id, "users.json"), "w") as f:
        json.dump({"users": [user_id, friend_id]}, f)
    with open(os.path.join(CHATS, chat_id, "history.db"), "w") as f:
        pass
    chat_cursor = get_chat_db(chat_id).cursor()
    chat_cursor.execute(
        "CREATE TABLE IF NOT EXISTS messages (id VARCHAR(255) PRIMARY KEY, sender_id VARCHAR(255), content TEXT, timestamp TIMESTAMP)"
    )
    chat_cursor.connection.commit()
    with open(os.path.join(CHATS, chat_id, "cache.txt"), "w") as f:
        pass
    return {"message": "Chat created successfully!", "success": True}, 200


def get_friends_for_user(user_id):
    try:
        with open(os.path.join(FRIENDS, user_id + ".json"), "r") as f:
            data = json.load(f)
            return data["friends"]
    except FileNotFoundError:
        return []


def return_chats_for_user(user_id):
    chats = []
    for chat in os.listdir(CHATS):
        try:
            with open(os.path.join(CHATS, chat, "users.json"), "r") as f:
                data = json.load(f)
                if user_id in data["users"]:
                    chats.append(chat)
        except Exception as e:
            print(e)
            continue
    return chats


@app.route("/api/load_chats")
def load_chats():
    sessioncookie = flask.request.cookies.get("sessioncookie")
    if not sessioncookie:
        return {"message": "No sessioncookie provided"}, 400
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT user_id FROM sessions WHERE cookie = ?",
        (sessioncookie,),
    )
    try:
        user_id = cursor.fetchone()["user_id"]
    except Exception as e:
        print(e)
        return {"message": "Invalid sessioncookie"}, 400
    chats = return_chats_for_user(user_id)
    return_objects = []
    for chat in chats:
        with open(os.path.join(CHATS, chat, "users.json"), "r") as f:
            data = json.load(f)
            other_user_id = [uid for uid in data["users"] if uid != user_id][0]
            cursor.execute("SELECT username FROM users WHERE id = ?", (other_user_id,))
            try:
                other_username = cursor.fetchone()["username"]
            except Exception as e:
                print(e)
                other_username = "Unknown User"
        with open(os.path.join(CHATS, chat, "cache.txt"), "r") as f:
            last_message = f.read()
        return_objects.append(
            {"chat": chat, "other_user": other_username, "last_message": last_message}
        )

    return {"chats": return_objects, "success": True}, 200


@app.route("/api/send_message", methods=["POST"])
def send_message():
    sessioncookie = flask.request.cookies.get("sessioncookie")
    if not sessioncookie:
        return {"message": "No sessioncookie provided"}, 400
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT user_id FROM sessions WHERE cookie = ?",
        (sessioncookie,),
    )
    try:
        user_id = cursor.fetchone()["user_id"]
    except Exception as e:
        print(e)
        return {"message": "Invalid sessioncookie"}, 400
    reqjson = flask.request.get_json()
    try:
        chat_id = reqjson["chat_id"]
        content = reqjson["content"]
    except KeyError:
        return {"message": "Missing chat_id or content in request body"}, 400
    chats = return_chats_for_user(user_id)
    if chat_id not in chats:
        return {"message": "Invalid chat_id"}, 400
    try:
        chat_cursor = get_chat_db(chat_id).cursor()
    except Exception as e:
        print(e)
        return {"message": "Invalid chat_id"}, 400
    chat_cursor.execute(
        "INSERT INTO messages (id, sender_id, content, timestamp) VALUES (?, ?, ?, datetime('now'))",
        (
            str(uuid.uuid4()),
            user_id,
            content,
        ),
    )
    chat_cursor.connection.commit()
    with open(os.path.join(CHATS, chat_id, "cache.txt"), "w") as f:
        f.write(content)
    return {"message": "Message sent successfully!", "success": True}, 200


@app.route("/api/get_messages", methods=["GET"])
def get_messages():
    sessioncookie = flask.request.cookies.get("sessioncookie")
    if not sessioncookie:
        return {"message": "No sessioncookie provided"}, 400
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT user_id FROM sessions WHERE cookie = ?",
        (sessioncookie,),
    )
    try:
        user_id = cursor.fetchone()["user_id"]
    except Exception as e:
        print(e)
        return {"message": "Invalid sessioncookie"}, 400
    chat_id = flask.request.args.get("chat_id")
    chats = return_chats_for_user(user_id)
    if chat_id not in chats:
        return {"message": "Invalid chat_id"}, 400
    try:
        chat_cursor = get_chat_db(chat_id).cursor()
    except Exception as e:
        print(e)
        return {"message": "Invalid chat_id"}, 400
    chat_cursor.execute(
        "SELECT sender_id, content, timestamp FROM messages ORDER BY timestamp ASC"
    )

    messages = chat_cursor.fetchall()
    message_list = []
    for message in messages:
        message_list.append(
            {
                "sender": get_username_by_id(cursor, message["sender_id"]),
                "content": message["content"],
                "timestamp": message["timestamp"],
            }
        )
    return {"messages": message_list, "success": True}, 200


def get_username_by_id(cursor, id):
    cursor.execute("SELECT username FROM users WHERE id = ?", (id,))
    try:
        data = cursor.fetchone()["username"]
    except Exception as e:
        print(e)
        return None
    return data if data else None


def get_username_and_id(cursor, nameomail):
    if "@" in nameomail:
        cursor.execute("SELECT username, id FROM users WHERE email = ?", (nameomail,))
        data = cursor.fetchone()
        try:
            username = data["username"]
            tid = data["id"]
        except Exception as e:
            print(e)
            return None, None

    else:
        cursor.execute(
            "SELECT username, id FROM users WHERE username = ?", (nameomail,)
        )
        data = cursor.fetchone()
        try:
            username = data["username"]
            tid = data["id"]
        except Exception as e:
            print(e)
            return None, None

    return username, tid


def generate_session_cookie(user_id):
    conn = get_db()
    cookie = str(secrets.token_urlsafe(16))
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO sessions (id, cookie, user_id, expires_at, created_at) VALUES (?, ?, ?, datetime('now', '+1 year'), datetime('now'))",
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
    try:
        expire_date = cursor.fetchone()["expires_at"]
        print(expire_date)
    except Exception:
        return {"message": "Cookie invalid"}, 400
    if datetime.datetime.now() < expire_date:
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
