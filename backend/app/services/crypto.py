import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MIN_KEY_LENGTH = 16  # refused below this; shorter than WARN_KEY_LENGTH is allowed but logged
WARN_KEY_LENGTH = 32
_V2 = "v2:"


def derive_key(master: str, purpose: str) -> bytes:
    """32 independent bytes per purpose from the master key (HKDF-SHA256), so one purpose's key never
    doubles as another's (the encryption key, the database key, ...)."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"lanwarden/" + purpose.encode()).derive(master.encode())


class SecretBox:
    """Encrypts the recoverable secrets (AdGuard/SMTP passwords, webhook URL and signing secret, TOTP secret)
    with a key derived from the instance secret key. Tokens are prefixed `v2:`; unprefixed tokens come from
    earlier versions (plain SHA-256 derivation) and still decrypt, so an upgrade needs no data migration.
    Changing the secret key makes stored secrets undecryptable unless they are re-encrypted with
    `python -m app rotate-key`."""

    def __init__(self, secret_key: str):
        self._fernet = Fernet(base64.urlsafe_b64encode(derive_key(secret_key, "secretbox-v2")))
        # The label keeps the project's former name on purpose: changing it would make every secret stored by
        # an earlier version undecryptable.
        legacy = hashlib.sha256(b"guardalert-secretbox-v1:" + secret_key.encode()).digest()
        self._legacy = Fernet(base64.urlsafe_b64encode(legacy))

    def encrypt(self, plaintext: str) -> str:
        return _V2 + self._fernet.encrypt(plaintext.encode()).decode()

    def decrypt(self, token: str) -> str | None:
        try:
            if token.startswith(_V2):
                return self._fernet.decrypt(token[len(_V2):].encode()).decode()
            return self._legacy.decrypt(token.encode()).decode()
        except InvalidToken:
            return None
