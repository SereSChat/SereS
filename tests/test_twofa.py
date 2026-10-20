"""Two-factor authentication: authenticator app, backup codes as 2FA, limits."""

import base64
import os

import pytest

import totp
from test_api import login, register
from test_recovery import make_codes


def b64(n=32):
    return base64.b64encode(os.urandom(n)).decode()


@pytest.fixture
def user_with_totp(make_client):
    client = make_client()
    pw = register(client, "gina")
    login(client, "gina", pw)
    assert client.post("/api/2fa/totp/setup", json={"old_auth_hash": b64()}).status_code == 400
    setup = client.post("/api/2fa/totp/setup", json={"old_auth_hash": pw}).json
    assert setup["uri"].startswith("otpauth://totp/")
    assert client.post("/api/2fa/totp/enable", json={"code": "000000"}).status_code == 400
    code = totp.code_at(setup["secret"], totp.current_step())
    assert client.post("/api/2fa/totp/enable", json={"code": code}).status_code == 200
    return client, pw, setup["secret"]


def test_status(user_with_totp):
    client, _, _ = user_with_totp
    status = client.get("/api/2fa").json
    assert status["enabled"] and status["totp"] and status["passkeys"] == []
    assert "secret" not in str(status)


def test_login_needs_second_factor(user_with_totp, make_client):
    _, pw, secret = user_with_totp
    client = make_client()
    res = login(client, "gina", pw)
    challenge = res.json["two_factor"]
    assert challenge["methods"] == ["totp"]
    assert "enc_private" not in res.json and "Set-Cookie" not in res.headers
    assert client.get("/api/me").status_code == 401
    # The code of the setup step was used already; take the next one.
    next_code = totp.code_at(secret, totp.current_step() + 1)
    res = client.post("/api/login/2fa", json={"token": challenge["token"], "method": "totp", "code": next_code})
    assert res.status_code == 200 and res.json["enc_private"]
    assert client.get("/api/me").status_code == 200
    # Same code can't be used again.
    again = login(make_client(), "gina", pw).json["two_factor"]["token"]
    assert make_client().post("/api/login/2fa", json={"token": again, "method": "totp", "code": next_code}).status_code == 400


def test_too_many_wrong_codes(user_with_totp, make_client):
    _, pw, _ = user_with_totp
    client = make_client()
    token = login(client, "gina", pw).json["two_factor"]["token"]
    for _ in range(4):
        assert client.post("/api/login/2fa", json={"token": token, "method": "totp", "code": "123456"}).status_code == 400
    assert client.post("/api/login/2fa", json={"token": token, "method": "totp", "code": "123456"}).status_code == 401
    assert client.post("/api/login/2fa", json={"token": token, "method": "totp", "code": "123456"}).status_code == 401


def test_backup_code_as_second_factor(user_with_totp, make_client):
    client, pw, _ = user_with_totp
    codes = make_codes()
    client.post("/api/recovery/codes", json={"old_auth_hash": pw, "codes": codes})
    other = make_client()
    challenge = login(other, "gina", pw).json["two_factor"]
    assert challenge["backup_codes"] is True
    body = {"token": challenge["token"], "method": "backup", "slot": codes[0]["slot"], "auth_hash": codes[0]["auth_hash"]}
    assert other.post("/api/login/2fa", json=body).status_code == 200
    assert client.get("/api/recovery/codes").json["unused"] == 9


def test_disable_needs_password(user_with_totp, make_client):
    client, pw, _ = user_with_totp
    assert client.post("/api/2fa/totp/disable", json={"old_auth_hash": b64()}).status_code == 400
    assert client.post("/api/2fa/totp/disable", json={"old_auth_hash": pw}).status_code == 200
    assert "two_factor" not in login(make_client(), "gina", pw).json


def test_passkey_endpoints_check_input(user_with_totp):
    client, pw, _ = user_with_totp
    assert client.post("/api/2fa/passkeys/options", json={"old_auth_hash": b64()}).status_code == 400
    res = client.post("/api/2fa/passkeys/options", json={"old_auth_hash": pw})
    options = res.json["options"]
    assert options["rp"]["name"] == "SereS" and options["challenge"]
    bad = client.post("/api/2fa/passkeys/register", json={"token": res.json["token"], "credential": {"id": "x"}})
    assert bad.status_code == 400
    assert client.post("/api/2fa/passkeys/delete", json={"id": "x", "old_auth_hash": pw}).status_code == 404


def test_email_reset_blocked_with_2fa(user_with_totp, make_client, app_module, monkeypatch):
    sent = []
    monkeypatch.setattr(app_module.mailer, "configured", lambda: True)
    monkeypatch.setattr(app_module.mailer, "send_async", lambda to, subject, text: sent.append(text))
    client = make_client()
    client.post("/api/password_reset/request", json={"nameomail": "gina"})
    token = sent[0].split("reset=")[1].split()[0]
    res = client.post("/api/password_reset/check", json={"token": token})
    assert res.status_code == 403 and res.json["two_factor"]
