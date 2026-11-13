"""Key rotation and database (de)encryption: operator tools run through `python -m app`, never the web API."""

import os
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.system import NotificationRule, Setting, User
from app.services.crypto import SecretBox


class RotationError(Exception):
    """Something could not be re-encrypted; nothing has been changed (the caller rolls back)."""


def reencrypt_all(db: Session, old: SecretBox, new: SecretBox) -> dict[str, int]:
    """Move every stored secret from `old` to `new`. MFA recovery codes cannot move (they are one-way
    HMACs keyed by the secret key), so they are cleared: the admin regenerates them after the rotation."""

    def swap(token: str, what: str) -> str:
        plain = old.decrypt(token)
        if plain is None:
            raise RotationError(f"{what} cannot be decrypted with the current key; is LANWARDEN_SECRET_KEY the key that encrypted it?")
        return new.encrypt(plain)

    counts = {"secrets": 0, "recovery_code_sets_cleared": 0}
    for setting in db.scalars(select(Setting)):
        value = dict(setting.value)
        changed = False
        for k, v in value.items():
            if k.endswith("_enc") and v:
                value[k], changed = swap(v, f"setting {setting.key}.{k}"), True
                counts["secrets"] += 1
        if changed:
            setting.value = value
    for rule in db.scalars(select(NotificationRule)):
        cfg = dict(rule.config)
        changed = False
        for k, v in cfg.items():
            if k.endswith("_enc") and v:
                cfg[k], changed = swap(v, f"notification rule {rule.id} {k}"), True
                counts["secrets"] += 1
        if changed:
            rule.config = cfg
    for user in db.scalars(select(User)):
        if user.totp_secret_enc:
            user.totp_secret_enc = swap(user.totp_secret_enc, f"two-step secret of {user.username}")
            counts["secrets"] += 1
        if user.recovery_codes:
            user.recovery_codes = None
            counts["recovery_code_sets_cleared"] += 1
    return counts


def _hex_key(key: bytes) -> str:
    return f"x'{key.hex()}'"  # hex only, so it is safe to put in a PRAGMA/ATTACH statement


def _swap_in(db_path: Path, new_path: Path) -> Path:
    """Replace the database file; the old one is kept beside it with a .bak suffix."""
    backup = db_path.with_name(db_path.name + ".bak")
    for suffix in ("-wal", "-shm"):
        db_path.with_name(db_path.name + suffix).unlink(missing_ok=True)  # checkpointed by the export's source close
    os.replace(db_path, backup)
    os.replace(new_path, db_path)
    return backup


def encrypt_database(db_path: Path, key: bytes) -> Path:
    """Plain SQLite file -> SQLCipher file, in place. Returns the path of the plaintext backup, which still
    holds everything readable: the caller must tell the operator to delete it."""
    import sqlcipher3.dbapi2 as sqlcipher

    new_path = db_path.with_name(db_path.name + ".enc.tmp")
    new_path.unlink(missing_ok=True)
    src = sqlcipher.connect(str(db_path))
    try:
        src.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        src.execute(f"ATTACH DATABASE '{new_path}' AS enc KEY \"{_hex_key(key)}\"")
        src.execute("SELECT sqlcipher_export('enc')")
        before = _row_counts(src, "main")
        after = _row_counts(src, "enc")
        src.execute("DETACH DATABASE enc")
    finally:
        src.close()
    if before != after:
        new_path.unlink(missing_ok=True)
        raise RotationError("row counts differ after export; nothing was changed")
    return _swap_in(db_path, new_path)


def decrypt_database(db_path: Path, key: bytes) -> Path:
    """SQLCipher file -> plain SQLite file, in place (recovery path). Returns the encrypted backup."""
    import sqlcipher3.dbapi2 as sqlcipher

    new_path = db_path.with_name(db_path.name + ".dec.tmp")
    new_path.unlink(missing_ok=True)
    src = sqlcipher.connect(str(db_path))
    try:
        src.execute(f"PRAGMA key = \"{_hex_key(key)}\"")
        src.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        src.execute(f"ATTACH DATABASE '{new_path}' AS plain KEY ''")
        src.execute("SELECT sqlcipher_export('plain')")
        before = _row_counts(src, "main")
        after = _row_counts(src, "plain")
        src.execute("DETACH DATABASE plain")
    finally:
        src.close()
    if before != after:
        new_path.unlink(missing_ok=True)
        raise RotationError("row counts differ after export; nothing was changed")
    return _swap_in(db_path, new_path)


_SCHEMAS = ("main", "enc", "plain")  # the only schema names this module ever attaches


def _row_counts(conn, schema: str) -> dict[str, int]:
    """Row count per table. `schema` comes from the fixed list above and table names from the database's own
    catalogue (quoted); nothing user-supplied reaches these statements, but identifiers cannot be bound."""
    if schema not in _SCHEMAS:
        raise ValueError(schema)
    names = conn.execute(f"SELECT name FROM {schema}.sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")  # noqa: S608  # nosec B608
    counts = {}
    for (table,) in sorted(names.fetchall()):
        quoted = '"' + table.replace('"', '""') + '"'
        counts[table] = conn.execute(f"SELECT count(*) FROM {schema}.{quoted}").fetchone()[0]  # noqa: S608  # nosec B608
    return counts


def is_plain_sqlite(db_path: Path) -> bool:
    """True if the file starts with the SQLite magic header (an encrypted file looks like random bytes)."""
    try:
        with open(db_path, "rb") as fh:
            return fh.read(16) == b"SQLite format 3\x00"
    except OSError:
        return False


__all__ = ["RotationError", "reencrypt_all", "encrypt_database", "decrypt_database", "is_plain_sqlite"]
