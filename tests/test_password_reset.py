"""Password reset by e-mail: link, new keys, old history hidden for the user."""

import base64
import os
import re
import uuid

import pytest

from test_api import envelope, keys, login, register


def b64(n=32):
    return base64.b64encode(os.urandom(n)).decode()


@pytest.fixture
def mails(app_module, monkeypatch):
    sent = []
    monkeypatch.setattr(app_module.mailer, "configured", lambda: True)
    monkeypatch.setattr(app_module.mailer, "send_async", lambda to, subject, text: sent.append((to, subject, text)))
    return sent


def token_from(mail):
    return re.search(r"reset=([A-Za-z0-9_-]+)", mail[2]).group(1)


def test_disabled_without_smtp(make_client, app_module, monkeypatch):
    monkeypatch.setattr(app_module.mailer, "configured", lambda: False)
    assert make_client().post("/api/password_reset/request", json={"nameomail": "x"}).status_code == 503


def test_same_answer_for_unknown_accounts(make_client, mails):
    client = make_client()
    register(client, "erin")
    known = client.post("/api/password_reset/request", json={"nameomail": "erin"})
    unknown = client.post("/api/password_reset/request", json={"nameomail": "nobody"})
    assert known.status_code == unknown.status_code == 200
    assert known.json["message"] == unknown.json["message"]
    assert len(mails) == 1 and mails[0][0] == "erin@example.com"


def test_mail_language(make_client, mails):
    client = make_client()
    register(client, "erin")
    client.post("/api/password_reset/request", json={"nameomail": "erin@example.com", "lang": "de"})
    assert "zurücksetzen" in mails[0][1]


def test_reset_flow(make_client, mails):
    erin = make_client()
    pw = register(erin, "erin")
    login(erin, "erin", pw)
    frank = make_client()
    frank_pw = register(frank, "frank")
    login(frank, "frank", frank_pw)
    erin.post("/api/friends/request", json={"username": "frank"})
    frank.post("/api/friends/accept", json={"username": "erin"})
    chat_id = erin.post("/api/chats", json={"type": "dm", "username": "frank"}).json["chat_id"]
    ids = [m["id"] for m in erin.get(f"/api/chats/{chat_id}").json["chat"]["members"]]
    erin.post(f"/api/chats/{chat_id}/messages", json={"id": str(uuid.uuid4()), "payload": envelope(ids)})

    anon = make_client()
    anon.post("/api/password_reset/request", json={"nameomail": "erin"})
    token = token_from(mails[0])
    assert anon.post("/api/password_reset/check", json={"token": token}).json["username"] == "erin"

    new_pw = b64()
    new_keys = keys()
    res = anon.post(
        "/api/password_reset/confirm",
        json={"token": token, "auth_hash": new_pw, "kdf_salt": b64(16), "kdf_iterations": 600000, "keys": new_keys},
    )
    assert res.status_code == 200
    assert res.json["user"]["pub_ecdh"] == new_keys["pub_ecdh"]
    # Old sessions are gone, new password works, old one doesn't.
    assert erin.get("/api/me").status_code == 401
    assert login(make_client(), "erin", new_pw).status_code == 200
    assert login(make_client(), "erin", pw).status_code == 400
    # Erin only sees the notice, Frank still has the old message.
    erin_msgs = anon.get(f"/api/chats/{chat_id}/messages").json["messages"]
    assert [m["kind"] for m in erin_msgs] == ["system"]
    assert erin_msgs[0]["payload"]["event"] == "keys_reset"
    frank_msgs = frank.get(f"/api/chats/{chat_id}/messages").json["messages"]
    assert [m["kind"] for m in frank_msgs] == ["e2e", "system"]
    # Frank still gets Erin's old keys to verify her old messages.
    erin_member = [m for m in frank.get(f"/api/chats/{chat_id}").json["chat"]["members"] if m["username"] == "erin"][0]
    assert erin_member["pub_ecdh"] == new_keys["pub_ecdh"]
    assert len(erin_member["previous_keys"]) == 1 and erin_member["previous_keys"][0]["until"]
    looked_up = frank.get(f"/api/users/keys?ids={erin_member['id']}").json["users"][0]
    assert looked_up["previous_keys"] == erin_member["previous_keys"]
    # The link works only once.
    again = make_client().post(
        "/api/password_reset/confirm",
        json={"token": token, "auth_hash": b64(), "kdf_salt": b64(16), "kdf_iterations": 600000, "keys": keys()},
    )
    assert again.status_code == 404


def test_only_newest_link_works(make_client, mails):
    client = make_client()
    register(client, "erin")
    client.post("/api/password_reset/request", json={"nameomail": "erin"})
    client.post("/api/password_reset/request", json={"nameomail": "erin"})
    first, second = token_from(mails[0]), token_from(mails[1])
    assert client.post("/api/password_reset/check", json={"token": first}).status_code == 404
    assert client.post("/api/password_reset/check", json={"token": second}).status_code == 200


def test_expired_link(make_client, mails, app_module):
    client = make_client()
    register(client, "erin")
    client.post("/api/password_reset/request", json={"nameomail": "erin"})
    with app_module.app.app_context():
        conn = app_module.get_db()
        conn.execute("UPDATE password_resets SET expires_at = '2000-01-01T00:00:00Z'")
        conn.commit()
    assert client.post("/api/password_reset/check", json={"token": token_from(mails[0])}).status_code == 404


def test_mailer_debug_prints(capsys, monkeypatch):
    import mailer

    monkeypatch.setenv("MAIL_DEBUG", "1")
    assert mailer.configured()
    mailer.deliver(mailer.build_message("a@b.de", "Subject", "Body text"))
    assert "Body text" in capsys.readouterr().out
