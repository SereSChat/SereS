"""Tests for the v1.3.0 features: reactions, attachments, pins, chat
preferences, disappearing messages and last seen."""

import uuid

import pytest

from test_api import alice_bob, envelope, user  # noqa: F401  (fixtures/helpers)


def dm(alice):
    return alice.post("/api/chats", json={"type": "dm", "username": "bob"}).json["chat_id"]


def send(client, chat_id, members, **extra):
    message_id = str(uuid.uuid4())
    res = client.post(
        f"/api/chats/{chat_id}/messages",
        json={"id": message_id, "payload": envelope(members), **extra},
    )
    assert res.status_code == 200, res.json
    return message_id


def test_silent_messages_are_not_unread_or_last(alice_bob):
    alice, bob = alice_bob
    chat_id = dm(alice)
    members = [alice.user_id, bob.user_id]
    first = send(alice, chat_id, members)
    send(alice, chat_id, members, silent=True)
    chat = bob.get("/api/chats").json["chats"][0]
    assert chat["unread"] == 1
    assert chat["last_message"]["id"] == first
    msgs = bob.get(f"/api/chats/{chat_id}/messages").json["messages"]
    assert [m["silent"] for m in msgs] == [False, True]


def test_encrypted_attachments(alice_bob, make_client):
    alice, bob = alice_bob
    chat_id = dm(alice)
    blob = b"\x00\x01ciphertext" * 100
    res = alice.post(f"/api/chats/{chat_id}/files", data=blob, content_type="application/octet-stream")
    file_id = res.json["file_id"]
    # Not visible to the other member before it is sent.
    assert bob.get(f"/api/chats/{chat_id}/files/{file_id}").status_code == 404
    assert alice.get(f"/api/chats/{chat_id}/files/{file_id}").data == blob
    # Bob can't attach Alice's upload.
    res = bob.post(
        f"/api/chats/{chat_id}/messages",
        json={"id": str(uuid.uuid4()), "payload": envelope([alice.user_id, bob.user_id]), "files": [file_id]},
    )
    assert res.status_code == 400
    message_id = send(alice, chat_id, [alice.user_id, bob.user_id], files=[file_id])
    res = bob.get(f"/api/chats/{chat_id}/files/{file_id}")
    assert res.data == blob and "private" in res.headers["Cache-Control"]
    eve = user(make_client, "eve")
    assert eve.get(f"/api/chats/{chat_id}/files/{file_id}").status_code == 404
    # Deleting the message deletes the file.
    alice.post(f"/api/chats/{chat_id}/messages/{message_id}/delete")
    assert bob.get(f"/api/chats/{chat_id}/files/{file_id}").status_code == 404


def test_pins(alice_bob):
    alice, bob = alice_bob
    chat_id = dm(alice)
    message_id = send(alice, chat_id, [alice.user_id, bob.user_id])
    res = bob.post(f"/api/chats/{chat_id}/pins", json={"message_id": message_id})
    assert res.json["pins"][0]["message_id"] == message_id
    details = alice.get(f"/api/chats/{chat_id}").json["chat"]
    assert details["pins"][0]["pinned_by"] == "bob"
    single = alice.get(f"/api/chats/{chat_id}/messages/{message_id}").json["message"]
    assert single["id"] == message_id
    events = [m["payload"]["event"] for m in alice.get(f"/api/chats/{chat_id}/messages").json["messages"] if m["kind"] == "system"]
    assert events == ["pinned"]
    alice.post(f"/api/chats/{chat_id}/pins", json={"message_id": message_id, "pinned": False})
    assert alice.get(f"/api/chats/{chat_id}").json["chat"]["pins"] == []


def test_chat_prefs_are_personal(alice_bob):
    alice, bob = alice_bob
    chat_id = dm(alice)
    assert alice.post(f"/api/chats/{chat_id}/prefs", json={"pinned": True, "archived": True}).status_code == 200
    mine = alice.get("/api/chats").json["chats"][0]
    theirs = bob.get("/api/chats").json["chats"][0]
    assert mine["pinned"] and mine["archived"]
    assert not theirs["pinned"] and not theirs["archived"]
    assert alice.post(f"/api/chats/{chat_id}/prefs", json={"pinned": "yes"}).status_code == 400


def test_disappearing_messages(alice_bob, app_module):
    alice, bob = alice_bob
    chat_id = dm(alice)
    assert alice.post(f"/api/chats/{chat_id}/disappearing", json={"seconds": 123}).status_code == 400
    assert bob.post(f"/api/chats/{chat_id}/disappearing", json={"seconds": 3600}).status_code == 200
    assert alice.get(f"/api/chats/{chat_id}").json["chat"]["disappear_seconds"] == 3600
    message_id = send(alice, chat_id, [alice.user_id, bob.user_id])
    msgs = bob.get(f"/api/chats/{chat_id}/messages").json["messages"]
    sent = [m for m in msgs if m["id"] == message_id][0]
    assert sent["expires_at"]

    # Let it expire.
    with app_module.app.app_context():
        conn = app_module.get_db()
        conn.execute("UPDATE messages SET expires_at = '2000-01-01T00:00:00Z' WHERE id = ?", (message_id,))
        conn.commit()
        app_module.purge_expired(conn, force=True)
    msgs = bob.get(f"/api/chats/{chat_id}/messages").json["messages"]
    assert [m for m in msgs if m["id"] == message_id][0]["deleted"]


def test_group_disappearing_owner_only(alice_bob):
    alice, bob = alice_bob
    chat_id = alice.post("/api/chats", json={"type": "group", "name": "G", "usernames": ["bob"]}).json["chat_id"]
    assert bob.post(f"/api/chats/{chat_id}/disappearing", json={"seconds": 86400}).status_code == 403
    assert alice.post(f"/api/chats/{chat_id}/disappearing", json={"seconds": 86400}).status_code == 200


def test_last_seen_respects_privacy(alice_bob):
    alice, bob = alice_bob
    dm(alice)
    bob.get("/api/me")
    presence = alice.get("/api/chats").json["chats"][0]["presence"]
    assert presence["online"] is True
    assert alice.get("/api/users/bob/profile").json["presence"]["online"] is True
    # Hiding your own last seen also hides the others' (like WhatsApp).
    alice.post("/api/profile/privacy", json={"show_last_seen": False})
    assert alice.get("/api/chats").json["chats"][0]["presence"] is None
    assert bob.get("/api/chats").json["chats"][0]["presence"] is None
    assert alice.get("/api/me").json["user"]["show_last_seen"] is False
    # Members of a chat never see the raw last-seen columns.
    chat_id = alice.get("/api/chats").json["chats"][0]["id"]
    member = alice.get(f"/api/chats/{chat_id}").json["chat"]["members"][0]
    assert "last_seen" not in member


def test_permissions_policy_allows_microphone_for_voice_messages(make_client):
    res = make_client().get("/api/online")
    assert "microphone=(self)" in res.headers["Permissions-Policy"]
    assert "media-src 'self' blob:" in res.headers["Content-Security-Policy"]
