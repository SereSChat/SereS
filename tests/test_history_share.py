"""After a reset by e-mail other members can share the old messages again."""

import uuid

from test_api import envelope, keys, register, user
from test_password_reset import b64, mails, token_from  # noqa: F401  (fixture)


def reset_by_mail(make_client, mails, name):
    anon = make_client()
    mails.clear()
    anon.post("/api/password_reset/request", json={"nameomail": name})
    new_keys = keys()
    res = anon.post(
        "/api/password_reset/confirm",
        json={"token": token_from(mails[0]), "auth_hash": b64(), "kdf_salt": b64(16), "kdf_iterations": 600000,
              "keys": new_keys},
    )
    assert res.status_code == 200
    anon.user_id = res.json["user"]["id"]
    return anon


def dm_with_messages(make_client, count=2):
    erin = user(make_client, "erin")
    frank = user(make_client, "frank")
    erin.post("/api/friends/request", json={"username": "frank"})
    frank.post("/api/friends/accept", json={"username": "erin"})
    chat_id = erin.post("/api/chats", json={"type": "dm", "username": "frank"}).json["chat_id"]
    ids = [erin.user_id, frank.user_id]
    sent = []
    for _ in range(count):
        message_id = str(uuid.uuid4())
        assert erin.post(f"/api/chats/{chat_id}/messages", json={"id": message_id, "payload": envelope(ids)}).status_code == 200
        sent.append(message_id)
    return erin, frank, chat_id, sent


def member(client, chat_id, user_id):
    return [m for m in client.get(f"/api/chats/{chat_id}").json["chat"]["members"] if m["id"] == user_id][0]


def wrapped():
    return {"iv": b64(12), "k": b64(48)}


def test_share_history_after_reset(make_client, mails):
    erin, frank, chat_id, sent = dm_with_messages(make_client)
    erin = reset_by_mail(make_client, mails, "erin")

    # Frank sees that Erin lost the old messages; Erin sees it too.
    waiting = member(frank, chat_id, erin.user_id)["history_reset"]
    assert waiting and waiting["until_seq"] >= 2
    assert member(erin, chat_id, erin.user_id)["history_reset"] == waiting
    assert member(frank, chat_id, frank.user_id)["history_reset"] is None
    assert [m["kind"] for m in erin.get(f"/api/chats/{chat_id}/messages").json["messages"]] == ["system"]

    # Erin can't share with herself, outsiders can't share at all.
    assert erin.post(f"/api/chats/{chat_id}/history/{erin.user_id}", json={"keys": {}}).status_code == 400
    outsider = user(make_client, "gina")
    assert outsider.post(f"/api/chats/{chat_id}/history/{erin.user_id}", json={"keys": {}}).status_code == 404

    # Frank shares in two parts; an unknown id is ignored.
    first = frank.post(f"/api/chats/{chat_id}/history/{erin.user_id}", json={"keys": {sent[0]: wrapped(), "x": wrapped()}})
    assert first.json["stored"] == 1
    last = frank.post(f"/api/chats/{chat_id}/history/{erin.user_id}", json={"keys": {sent[1]: wrapped()}, "done": True})
    assert last.json["stored"] == 1
    assert member(frank, chat_id, erin.user_id)["history_reset"] is None
    assert frank.post(f"/api/chats/{chat_id}/history/{erin.user_id}", json={"keys": {}}).status_code == 409

    # Erin sees the old messages again, each with the key Frank shared.
    messages = erin.get(f"/api/chats/{chat_id}/messages").json["messages"]
    old = [m for m in messages if m["id"] in sent]
    assert len(old) == 2 and all(m["share"]["from_pub"] == member(erin, chat_id, frank.user_id)["pub_ecdh"] for m in old)
    assert messages[-1]["payload"]["event"] == "history_shared"
    assert messages[-1]["payload"]["target_id"] == erin.user_id
    single = erin.get(f"/api/chats/{chat_id}/messages/{sent[0]}").json["message"]
    assert single["share"]["k"]
    # Frank's own view has no shares.
    assert all("share" not in m for m in frank.get(f"/api/chats/{chat_id}/messages").json["messages"])


def test_new_messages_are_not_shared(make_client, mails):
    erin, frank, chat_id, sent = dm_with_messages(make_client, count=1)
    erin = reset_by_mail(make_client, mails, "erin")
    ids = [erin.user_id, frank.user_id]
    newer = str(uuid.uuid4())
    erin.post(f"/api/chats/{chat_id}/messages", json={"id": newer, "payload": envelope(ids)})
    res = frank.post(
        f"/api/chats/{chat_id}/history/{erin.user_id}", json={"keys": {sent[0]: wrapped(), newer: wrapped()}, "done": True}
    )
    assert res.json["stored"] == 1


def test_second_reset_drops_old_shares(make_client, mails):
    erin, frank, chat_id, sent = dm_with_messages(make_client, count=1)
    erin = reset_by_mail(make_client, mails, "erin")
    frank.post(f"/api/chats/{chat_id}/history/{erin.user_id}", json={"keys": {sent[0]: wrapped()}, "done": True})
    erin = reset_by_mail(make_client, mails, "erin")
    # The shared key was for the keys before, so it is gone and can be shared again.
    assert member(frank, chat_id, erin.user_id)["history_reset"]["from_seq"] == 0
    res = frank.post(f"/api/chats/{chat_id}/history/{erin.user_id}", json={"keys": {sent[0]: wrapped()}, "done": True})
    assert res.json["stored"] == 1


def test_nothing_waits_without_old_messages(make_client, mails):
    register(make_client(), "erin")
    erin = reset_by_mail(make_client, mails, "erin")
    frank = user(make_client, "frank")
    erin.post("/api/friends/request", json={"username": "frank"})
    frank.post("/api/friends/accept", json={"username": "erin"})
    chat_id = erin.post("/api/chats", json={"type": "dm", "username": "frank"}).json["chat_id"]
    assert member(frank, chat_id, erin.user_id)["history_reset"] is None


def test_earlier_resets_are_marked_once(make_client, mails, app_module):
    erin, frank, chat_id, sent = dm_with_messages(make_client, count=1)
    erin = reset_by_mail(make_client, mails, "erin")
    # Like a reset from before this feature: nothing marked yet.
    conn = app_module.db.connect(app_module.DB)
    conn.execute("UPDATE chat_members SET reset_seq = 0, reset_cleared_seq = 0")
    conn.execute("DELETE FROM meta WHERE key = 'key_resets_marked'")
    conn.commit()
    assert member(frank, chat_id, erin.user_id)["history_reset"] is None
    app_module.db.init_schema(conn)
    conn.close()
    waiting = member(frank, chat_id, erin.user_id)["history_reset"]
    assert waiting and waiting["until_seq"] >= 1
    res = frank.post(f"/api/chats/{chat_id}/history/{erin.user_id}", json={"keys": {sent[0]: wrapped()}, "done": True})
    assert res.json["stored"] == 1
    assert sent[0] in [m["id"] for m in erin.get(f"/api/chats/{chat_id}/messages").json["messages"]]
