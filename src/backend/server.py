# TODO: API for frontend?
import flask
import sqlite3
import os
from argon2 import PasswordHasher

app = flask.Flask(__name__, static_folder="../public", static_url_path="/")

ph = PasswordHasher(time_cost=4)


@app.route("/")
def index():
    return app.send_static_file("index.html")


@app.route("/api/create_user", methods=["POST"])
def create_user():
    hashed_passwd = ph.hash(flask.request.args.get("passwd"))
    with sqlite3.connect(os.path.join(os.path.dirname(__file__), "users.db")) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, passwd TEXT)"
        )
        cursor.execute(
            "INSERT INTO users (name, passwd) VALUES (?, ?)",
            (flask.request.args.get("username"), hashed_passwd),
        )

        conn.commit()
    return {"message": "User created successfully!"}


@app.route("/api/read_users", methods=["GET"])
def read_users():
    with sqlite3.connect(os.path.join(os.path.dirname(__file__), "users.db")) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users")
        result = cursor.fetchall()

        return result


@app.route("/api/login", methods=["GET"])
def login():
    with sqlite3.connect(os.path.join(os.path.dirname(__file__), "users.db")) as conn:
        cursor = conn.cursor()
        print(flask.request.args.get("username"))
        cursor.execute(
            "SELECT passwd FROM users WHERE name = (?)",
            (flask.request.args.get("username"),),
        )

        passwd = cursor.fetchone()

        if ph.verify(passwd[0], flask.request.args.get("passwd")):
            return {"message": "Login succesfull!"}
        else:
            return {"message": "Login not succesfull"}


if __name__ == "__main__":
    app.run(port=5000)
