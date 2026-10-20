"""Time-based one-time passwords (RFC 6238) for authenticator apps.

Works with Google Authenticator, Microsoft Authenticator, Aegis, 1Password, ...
6 digits, 30 second steps, SHA-1 (the default every app supports).
"""

import base64
import hashlib
import hmac
import secrets
import struct
import time
import urllib.parse

STEP = 30
DIGITS = 6


def new_secret():
    """A random 160-bit secret in base32 (what the apps expect)."""
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def code_at(secret, step):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10**DIGITS).zfill(DIGITS)


def current_step(now=None):
    return int((time.time() if now is None else now) // STEP)


def verify(secret, code, last_step=0, now=None, window=1):
    """Returns the matching time step (to remember against reuse) or None.

    Accepts one step before and after the current one for clocks that are a
    little off, but never a step that was already used.
    """
    if not secret or not isinstance(code, str):
        return None
    code = code.replace(" ", "")
    if len(code) != DIGITS or not code.isdigit():
        return None
    step = current_step(now)
    for candidate in range(step - window, step + window + 1):
        if candidate > last_step and hmac.compare_digest(code_at(secret, candidate), code):
            return candidate
    return None


def provisioning_uri(secret, account, issuer="SereS"):
    label = urllib.parse.quote(f"{issuer}:{account}")
    query = urllib.parse.urlencode({"secret": secret, "issuer": issuer, "digits": DIGITS, "period": STEP})
    return f"otpauth://totp/{label}?{query}"
