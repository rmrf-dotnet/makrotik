"""Small, dependency-free TOTP implementation (RFC 6238).

The admin control room deliberately avoids adding a QR-code or OTP library:
the secret is shown as text and the provisioning URI can be imported by any
authenticator app. Recovery codes are generated once and stored as scrypt
hashes, never in plaintext.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import struct
import time
from urllib.parse import quote

from werkzeug.security import check_password_hash, generate_password_hash


def generate_secret():
    raw = secrets.token_bytes(20)
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def _normalise_secret(secret):
    value = (secret or "").strip().replace(" ", "").upper()
    return value + "=" * ((8 - len(value) % 8) % 8)


def provisioning_uri(secret, account_name, issuer="Makrotik Share"):
    label = quote(f"{issuer}:{account_name}", safe="")
    return (
        f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}"
        "&algorithm=SHA1&digits=6&period=30"
    )


def code_at(secret, timestamp=None, step=30, digits=6):
    if not secret:
        return ""
    counter = int((time.time() if timestamp is None else timestamp) // step)
    key = base64.b32decode(_normalise_secret(secret))
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    number = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(number % (10**digits)).zfill(digits)


def verify_code(secret, code, window=1, step=30, digits=6):
    supplied = "".join(ch for ch in (code or "") if ch.isdigit())
    if len(supplied) != digits:
        return False
    now = time.time()
    for offset in range(-window, window + 1):
        candidate = code_at(secret, now + offset * step, step, digits)
        if hmac.compare_digest(supplied, candidate):
            return True
    return False


def generate_recovery_codes(count=8):
    codes = []
    for _ in range(count):
        raw = secrets.token_hex(5).upper()
        codes.append(f"{raw[:5]}-{raw[5:]}")
    return codes


def hash_recovery_codes(codes):
    return json.dumps([generate_password_hash(code) for code in codes])


def verify_recovery_code(stored, code):
    """Return (ok, updated_json). A used recovery code is removed."""
    try:
        hashes = json.loads(stored or "[]")
    except (TypeError, ValueError):
        hashes = []
    supplied = (code or "").strip().upper()
    if not supplied:
        return False, stored
    for index, password_hash in enumerate(hashes):
        try:
            if check_password_hash(password_hash, supplied):
                remaining = hashes[:index] + hashes[index + 1 :]
                return True, json.dumps(remaining)
        except (TypeError, ValueError):
            continue
    return False, stored
