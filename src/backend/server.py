# TODO: add /api/auth_cookies
# TODO: add /api/load_chats
# TODO: add /api/add_friends
# TODO: add /api/load_usernames with cookie
import flask
import sqlite3
import os
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

app = flask.Flask(__name__, static_folder="../public", static_url_path="/")

ph = PasswordHasher(time_cost=4)


@app.route("/")
def index():
    return app.send_static_file("index.html")


@app.route("/api/online")
def online():
    return {"message": "im up", "success": True}, 200


@app.route("/api/auth_cookie")
def auth_cookie():
    pass


@app.route("/api/generate_cookie")
def generate_cookie():
    json = flask.request.get_json()
    json["email"]


@app.route("/api/register", methods=["POST"])
def register():
    json = flask.request.get_json()
    hashed_passwd = ph.hash(json["passwd"])
    username = json["username"]
    if check_for_username(username):
        with sqlite3.connect(
            os.path.join(os.path.dirname(__file__), "users.db")
        ) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT, username TEXT, passwd TEXT)"
            )
            cursor.execute(
                "INSERT INTO users (email, username, passwd) VALUES (?, ?, ?)",
                (
                    json["email"],
                    json["username"],
                    hashed_passwd,
                ),
            )

            conn.commit()
        return {"message": "User created successfully!", "success": True}, 200
    else:
        return {"message": "Username already taken"}, 400


@app.route("/api/read_users", methods=["GET"])  # only for development
def read_users():
    with sqlite3.connect(os.path.join(os.path.dirname(__file__), "users.db")) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users")
        result = cursor.fetchall()

        return result, 200


@app.route("/api/login", methods=["POST"])
def login():
    with sqlite3.connect(os.path.join(os.path.dirname(__file__), "users.db")) as conn:
        cursor = conn.cursor()
        json = flask.request.get_json()
        nameomail = json["nameomail"]
        if nameomail and json["passwd"]:
            if "@" in nameomail:
                cursor.execute(
                    "SELECT passwd FROM users WHERE email = (?)",
                    (nameomail,),
                )
            else:
                cursor.execute(
                    "SELECT passwd FROM users WHERE username = (?)",
                    (nameomail,),
                )

            passwd = cursor.fetchone()

            if passwd:
                try:
                    if ph.verify(passwd[0], json["passwd"]):
                        return {"message": "Login succesfull!", "success": True}, 200
                    else:
                        return {"message": "Login not succesfull"}, 400
                except VerifyMismatchError:
                    return {"message": "Login not succesfull"}, 400
            else:
                return {"message": "Login not succesfull"}, 400
        else:
            return {"message": "Login not succesfull, missing Arguments"}, 400


def check_for_username(username: str) -> bool:
    try:
        with sqlite3.connect(
            os.path.join(os.path.dirname(__file__), "users.db")
        ) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT username FROM users WHERE username = (?)", (username,)
            )
            usernames = cursor.fetchall()[0]
            return usernames is None
    except (sqlite3.OperationalError, IndexError) as e:
        if isinstance(e, IndexError):
            return True
        with sqlite3.connect(
            os.path.join(os.path.dirname(__file__), "users.db")
        ) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT, username TEXT, passwd TEXT)"
            )
            return check_for_username(username)


if __name__ == "__main__":
    app.run(port=5000)
