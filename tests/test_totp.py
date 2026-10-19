import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src", "backend"))

import totp  # noqa: E402


def test_rfc6238_vector():
    # RFC 6238 test secret "12345678901234567890", SHA-1, T = 59 s -> 94287082 (8 digits).
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    assert totp.code_at(secret, 59 // 30) == "287082"


def test_verify_window_and_reuse():
    secret = totp.new_secret()
    now = 1_700_000_000
    step = totp.current_step(now)
    code = totp.code_at(secret, step)
    assert totp.verify(secret, code, now=now) == step
    assert totp.verify(secret, totp.code_at(secret, step - 1), now=now) == step - 1
    assert totp.verify(secret, totp.code_at(secret, step - 3), now=now) is None
    # The same step can't be used twice.
    assert totp.verify(secret, code, last_step=step, now=now) is None
    assert totp.verify(secret, "12 34 5", now=now) is None


def test_provisioning_uri():
    uri = totp.provisioning_uri("ABC", "alice")
    assert uri.startswith("otpauth://totp/SereS%3Aalice?") and "secret=ABC" in uri and "issuer=SereS" in uri
