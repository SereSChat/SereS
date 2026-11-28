"""One-time import of the old file based storage into the SQLite database.

Before this version friends, friend requests and chats were stored in JSON
files below `user_data/` and `chats/`, every chat had its own `history.db`.
The old files are left untouched so nothing is lost; they are only read once.
"""

import datetime
import json
import os
import sqlite3
import uuid

from db import get_meta, now_iso, set_meta

MIGRATION_KEY = "legacy_files_migrated"


def _read_json(path):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _legacy_ts(value):
    try:
        parsed = datetime.datetime.strptime(str(value), "%Y-%m-%d %H:%M:%S")
        return parsed.strftime("%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return now_iso()


def migrate_legacy_files(conn, user_data_dir, chats_dir):
    if get_meta(conn, MIGRATION_KEY):
        return

    user_ids = {row["id"] for row in conn.execute("SELECT id FROM users")}
    now = now_iso()

    if os.path.isdir(user_data_dir):
        for user_id in os.listdir(user_data_dir):
            user_dir = os.path.join(user_data_dir, user_id)
            if user_id not in user_ids or not os.path.isdir(user_dir):
                continue
            friends = _read_json(os.path.join(user_dir, "friends.json"))
            friend_list = friends.get("friends") if isinstance(friends, dict) else None
            if isinstance(friend_list, list):
                for friend_id in friend_list:
                    if isinstance(friend_id, str) and friend_id in user_ids and friend_id != user_id:
                        a, b = sorted((user_id, friend_id))
                        conn.execute(
                            "INSERT OR IGNORE INTO friendships (user_a, user_b, created_at) VALUES (?, ?, ?)",
                            (a, b, now),
                        )
            pending = _read_json(os.path.join(user_dir, "pending_friends.json"))
            pending_list = pending.get("pending") if isinstance(pending, dict) else None
            if isinstance(pending_list, list):
                for from_id in pending_list:
                    if isinstance(from_id, str) and from_id in user_ids and from_id != user_id:
                        conn.execute(
                            "INSERT OR IGNORE INTO friend_requests (from_id, to_id, created_at) VALUES (?, ?, ?)",
                            (from_id, user_id, now),
                        )

    if os.path.isdir(chats_dir):
        for chat_id in os.listdir(chats_dir):
            chat_dir = os.path.join(chats_dir, chat_id)
            if not os.path.isdir(chat_dir):
                continue
            users_doc = _read_json(os.path.join(chat_dir, "users.json"))
            users = users_doc.get("users") if isinstance(users_doc, dict) else None
            if (
                not isinstance(users, list)
                or len(users) != 2
                or not all(isinstance(u, str) and u in user_ids for u in users)
                or users[0] == users[1]
            ):
                continue
            a, b = sorted(users)
            dm_key = f"{a}:{b}"
            if conn.execute("SELECT 1 FROM chats WHERE dm_key = ?", (dm_key,)).fetchone():
                continue
            new_chat_id = chat_id if _is_uuid(chat_id) else str(uuid.uuid4())

            messages = []
            history = os.path.join(chat_dir, "history.db")
            if os.path.isfile(history) and os.path.getsize(history) > 0:
                old = None
                try:
                    old = sqlite3.connect(history)
                    old.row_factory = sqlite3.Row
                    messages = old.execute(
                        "SELECT id, sender_id, content, timestamp FROM messages ORDER BY timestamp ASC"
                    ).fetchall()
                except sqlite3.Error:
                    messages = []
                finally:
                    if old is not None:
                        old.close()

            last_activity = _legacy_ts(messages[-1]["timestamp"]) if messages else now
            conn.execute(
                "INSERT INTO chats (id, type, name, owner_id, dm_key, created_at, last_activity) VALUES (?, 'dm', NULL, NULL, ?, ?, ?)",
                (new_chat_id, dm_key, now, last_activity),
            )
            for user_id in (a, b):
                conn.execute(
                    "INSERT INTO chat_members (chat_id, user_id, role, joined_at) VALUES (?, ?, 'member', ?)",
                    (new_chat_id, user_id, now),
                )
            for message in messages:
                if message["sender_id"] not in (a, b):
                    continue
                cur = conn.execute(
                    "INSERT OR IGNORE INTO messages (id, chat_id, sender_id, kind, payload, created_at) VALUES (?, ?, ?, 'legacy', ?, ?)",
                    (
                        message["id"] or str(uuid.uuid4()),
                        new_chat_id,
                        message["sender_id"],
                        json.dumps({"text": str(message["content"] or "")}),
                        _legacy_ts(message["timestamp"]),
                    ),
                )
                if cur.rowcount == 1 and cur.lastrowid:
                    conn.execute("UPDATE messages SET rev = seq WHERE seq = ?", (cur.lastrowid,))

    set_meta(conn, MIGRATION_KEY, now)
    conn.commit()


def _is_uuid(value):
    try:
        uuid.UUID(value)
        return True
    except (TypeError, ValueError, AttributeError):
        return False
