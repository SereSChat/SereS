"""Database schema and connection helpers for SereS.

Everything that used to live in loose JSON files and per-chat SQLite files
is stored in a single SQLite database. Message bodies are stored exactly as
the client sent them: an end-to-end encrypted envelope the server cannot read.
"""

import contextlib
import datetime
import secrets
import sqlite3

SCHEMA = [
    # `users` already exists on old installations with (id, email, username, passwd);
    # the extra columns are added in `_migrate_columns`.
    """CREATE TABLE IF NOT EXISTS users (
        id VARCHAR(255) PRIMARY KEY,
        email VARCHAR(255),
        username VARCHAR(255),
        passwd TEXT
    )""",
    """CREATE TABLE IF NOT EXISTS user_sessions (
        token_hash TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        created_at TEXT NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS idx_sessions_user ON user_sessions(user_id)",
    """CREATE TABLE IF NOT EXISTS friendships (
        user_a TEXT NOT NULL,
        user_b TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY (user_a, user_b)
    )""",
    """CREATE TABLE IF NOT EXISTS friend_requests (
        from_id TEXT NOT NULL,
        to_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY (from_id, to_id)
    )""",
    # One invite link per user; anyone who opens it can send that user a friend request.
    """CREATE TABLE IF NOT EXISTS friend_invites (
        token TEXT PRIMARY KEY,
        user_id TEXT NOT NULL UNIQUE,
        created_at TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS blocks (
        blocker_id TEXT NOT NULL,
        blocked_id TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY (blocker_id, blocked_id)
    )""",
    """CREATE TABLE IF NOT EXISTS chats (
        id TEXT PRIMARY KEY,
        type TEXT NOT NULL CHECK (type IN ('dm', 'group')),
        name TEXT,
        owner_id TEXT,
        dm_key TEXT UNIQUE,
        created_at TEXT NOT NULL,
        last_activity TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS chat_members (
        chat_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'member',
        joined_at TEXT NOT NULL,
        joined_seq INTEGER NOT NULL DEFAULT 0,
        cleared_seq INTEGER NOT NULL DEFAULT 0,
        last_read_seq INTEGER NOT NULL DEFAULT 0,
        hidden INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (chat_id, user_id)
    )""",
    "CREATE INDEX IF NOT EXISTS idx_members_user ON chat_members(user_id)",
    """CREATE TABLE IF NOT EXISTS messages (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        id TEXT NOT NULL UNIQUE,
        chat_id TEXT NOT NULL,
        sender_id TEXT,
        kind TEXT NOT NULL CHECK (kind IN ('e2e', 'legacy', 'system')),
        payload TEXT,
        created_at TEXT NOT NULL,
        deleted INTEGER NOT NULL DEFAULT 0,
        rev INTEGER NOT NULL DEFAULT 0
    )""",
    "CREATE INDEX IF NOT EXISTS idx_messages_chat_seq ON messages(chat_id, seq)",
    "CREATE INDEX IF NOT EXISTS idx_messages_chat_rev ON messages(chat_id, rev)",
    """CREATE TABLE IF NOT EXISTS meta (
        key TEXT PRIMARY KEY,
        value TEXT
    )""",
]

USER_COLUMNS = {
    "auth_version": "INTEGER NOT NULL DEFAULT 0",
    "kdf_salt": "TEXT",
    "kdf_iterations": "INTEGER",
    "pub_ecdh": "TEXT",
    "pub_sign": "TEXT",
    "enc_private": "TEXT",
    "created_at": "TEXT",
}


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def connect(path):
    conn = sqlite3.connect(path, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def _migrate_columns(conn):
    existing = {row["name"] for row in conn.execute("PRAGMA table_info(users)")}
    for column, definition in USER_COLUMNS.items():
        if column not in existing:
            conn.execute(f"ALTER TABLE users ADD COLUMN {column} {definition}")


def init_schema(conn):
    for statement in SCHEMA:
        conn.execute(statement)
    _migrate_columns(conn)
    try:
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_nocase ON users(username COLLATE NOCASE)"
        )
    except sqlite3.IntegrityError:
        # Old installations may contain usernames that only differ in case.
        # Uniqueness is still enforced on registration.
        pass
    conn.commit()


def get_meta(conn, key, default=None):
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_meta(conn, key, value):
    conn.execute(
        "INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )


def server_secret(conn):
    """Persistent random secret used e.g. to derive fake KDF salts for unknown users."""
    secret = get_meta(conn, "server_secret")
    if not secret:
        secret = secrets.token_hex(32)
        set_meta(conn, "server_secret", secret)
        conn.commit()
    return secret


@contextlib.contextmanager
def write_transaction(conn):
    """Serialises writers so revision numbers are strictly increasing."""
    conn.commit()
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.rollback()
        raise
    else:
        conn.commit()


def next_rev(conn):
    row = conn.execute("SELECT COALESCE(MAX(rev), 0) + 1 AS r FROM messages").fetchone()
    return row["r"]
