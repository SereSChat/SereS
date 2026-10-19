"""Backup codes: generate, check status, reset the password with one code."""

import base64
import os

from test_api import login, register

SLOTS = ["ABCD", "EFGH", "JKLM", "NPQR", "STUV", "WXYZ", "2345", "6789", "AB23", "CD45"]


def b64(n=32):
    return base64.b64encode(os.urandom(n)).decode()


def make_codes():
    return [
        {"slot": slot, "kdf_salt": b64(16), "auth_hash": b64(), "enc_private": f'{{"code": "{slot}"}}'}
        for slot in SLOTS
    ]


def setup_user(make_client):
    client = make_client()
    pw = register(client, "dora")
    assert login(client, "dora", pw).status_code == 200
    codes = make_codes()
    res = client.post("/api/recovery/codes", json={"old_auth_hash": pw, "codes": codes})
    assert res.status_code == 200, res.json
    return client, pw, codes


def test_generate_needs_password_and_ten_codes(make_client):
    client = make_client()
    pw = register(client, "dora")
    login(client, "dora", pw)
    assert client.post("/api/recovery/codes", json={"old_auth_hash": b64(), "codes": make_codes()}).status_code == 400
    assert client.post("/api/recovery/codes", json={"old_auth_hash": pw, "codes": make_codes()[:9]}).status_code == 400
    dup = make_codes()
    dup[1]["slot"] = dup[0]["slot"]
    assert client.post("/api/recovery/codes", json={"old_auth_hash": pw, "codes": dup}).status_code == 400
    assert client.get("/api/recovery/codes").json["total"] == 0


def test_status_never_returns_codes(make_client):
    client, _, _ = setup_user(make_client)
    status = client.get("/api/recovery/codes").json
    assert status["unused"] == 10 and status["total"] == 10
    assert "codes" not in status and "auth_hash" not in str(status)


def test_reset_with_code(make_client):
    _, _, codes = setup_user(make_client)
    code = codes[3]
    anon = make_client()
    pre = anon.post("/api/recovery/prelogin", json={"nameomail": "dora", "slot": code["slot"]}).json
    assert pre["kdf_salt"] == code["kdf_salt"]
    # Wrong secret part of the code.
    assert anon.post("/api/recovery/unlock", json={"nameomail": "dora", "slot": code["slot"], "auth_hash": b64()}).status_code == 400
    unlocked = anon.post("/api/recovery/unlock", json={"nameomail": "dora", "slot": code["slot"], "auth_hash": code["auth_hash"]}).json
    assert unlocked["enc_private"] == code["enc_private"]

    new_pw = b64()
    res = anon.post(
        "/api/recovery/reset",
        json={
            "nameomail": "dora",
            "slot": code["slot"],
            "auth_hash": code["auth_hash"],
            "new_auth_hash": new_pw,
            "kdf_salt": b64(16),
            "kdf_iterations": 600000,
            "enc_private": '{"new": true}',
        },
    )
    assert res.status_code == 200 and res.json["user"]["username"] == "dora"
    assert anon.get("/api/me").status_code == 200
    assert login(make_client(), "dora", new_pw).status_code == 200
    assert anon.get("/api/recovery/codes").json["unused"] == 9
    # A used code can't be used again.
    again = anon.post("/api/recovery/unlock", json={"nameomail": "dora", "slot": code["slot"], "auth_hash": code["auth_hash"]})
    assert again.status_code == 400


def test_reset_logs_out_other_sessions(make_client):
    client, _, codes = setup_user(make_client)
    code = codes[0]
    make_client().post(
        "/api/recovery/reset",
        json={
            "nameomail": "dora@example.com",
            "slot": code["slot"],
            "auth_hash": code["auth_hash"],
            "new_auth_hash": b64(),
            "kdf_salt": b64(16),
            "kdf_iterations": 600000,
            "enc_private": "{}",
        },
    )
    assert client.get("/api/me").status_code == 401


def test_new_codes_replace_old_ones(make_client):
    client, pw, codes = setup_user(make_client)
    client.post("/api/recovery/codes", json={"old_auth_hash": pw, "codes": make_codes()})
    old = codes[0]
    res = make_client().post("/api/recovery/unlock", json={"nameomail": "dora", "slot": old["slot"], "auth_hash": old["auth_hash"]})
    assert res.status_code == 400


def test_unknown_user_gets_stable_fake_salt(make_client):
    client = make_client()
    a = client.post("/api/recovery/prelogin", json={"nameomail": "nobody", "slot": "ABCD"}).json["kdf_salt"]
    b = client.post("/api/recovery/prelogin", json={"nameomail": "nobody", "slot": "ABCD"}).json["kdf_salt"]
    assert a == b
