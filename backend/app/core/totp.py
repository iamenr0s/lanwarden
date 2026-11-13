"""TOTP (RFC 6238, HMAC-SHA1, 30 s steps, 6 digits) and single-use recovery codes, on the standard library.

SHA-1 / 6 digits / 30 s is what every authenticator app supports; it is not weakened by HMAC's use of SHA-1.
"""

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

STEP_S = 30
DIGITS = 6
WINDOW = 1  # accept the previous and next step too, for clock drift between phone and server
RECOVERY_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"  # no 0/o/1/i/l: codes get read aloud and typed


def _now() -> float:
    return time.time()  # separate function so tests can move the clock


def new_secret() -> str:
    """160 bits, base32 (what authenticator apps expect), no padding."""
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _hotp(secret: str, counter: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    value = (struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF) % 10**DIGITS
    return str(value).zfill(DIGITS)


def code_at(secret: str, at: float | None = None) -> str:
    return _hotp(secret, int((_now() if at is None else at) // STEP_S))


def verify(secret: str, code: str, last_step: int | None = None) -> int | None:
    """Return the matching 30 s step, or None. A step at or before `last_step` is rejected: a code
    (even a correct one that was shoulder-surfed) works exactly once."""
    code = "".join(code.split())
    if len(code) != DIGITS or not code.isdigit():
        return None
    now_step = int(_now() // STEP_S)
    for step in range(now_step - WINDOW, now_step + WINDOW + 1):
        if hmac.compare_digest(_hotp(secret, step), code) and (last_step is None or step > last_step):
            return step
    return None


def otpauth_uri(secret: str, account: str, issuer: str = "LanWarden") -> str:
    label = quote(f"{issuer}:{account}", safe=":@")  # the conventional "Issuer:account" form, colon unencoded
    return f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits={DIGITS}&period={STEP_S}"


def new_recovery_codes(count: int = 10) -> list[str]:
    """`xxxxx-xxxxx`: 10 symbols from a 31-letter alphabet, about 50 bits each."""
    return ["-".join("".join(secrets.choice(RECOVERY_ALPHABET) for _ in range(5)) for _ in range(2)) for _ in range(count)]


def normalize_recovery(code: str) -> str:
    return "".join(code.lower().split()).replace("-", "")


def hash_recovery(code: str, key: str) -> str:
    """Keyed hash (the instance secret key), so a stolen database cannot be used to test guesses offline."""
    return hmac.new(key.encode(), normalize_recovery(code).encode(), hashlib.sha256).hexdigest()
