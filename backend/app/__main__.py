"""`python -m app` starts the server (HTTP, or HTTPS when configured). The `create_app` factory is
unchanged, so `uvicorn app.main:create_app --factory` still works behind your own supervisor."""

import getpass
import os
import secrets
import sys
from pathlib import Path

import uvicorn
from sqlalchemy import delete, select
from sqlalchemy.engine import make_url

from app.core.config import Config
from app.core.security import hash_password
from app.core.tls import ensure_selfsigned
from app.db.session import make_engine, make_session_factory
from app.main import create_app, run_migrations
from app.models.system import LoginAttempt, User
from app.services import rotation
from app.services.crypto import MIN_KEY_LENGTH, SecretBox, derive_key
from app.services.netinfo import detect_local_ips


def tls_files(config: Config) -> tuple[str | None, str | None]:
    if config.tls_mode == "selfsigned":
        extra = [n for n in config.tls_names.split(",") if n.strip()]
        cert, key = ensure_selfsigned(config.data_dir, extra + detect_local_ips())  # cover the host's own addresses
        return str(cert), str(key)
    if config.tls_cert and config.tls_key:
        return str(config.tls_cert), str(config.tls_key)
    return None, None


def make_server(config: Config | None = None) -> uvicorn.Server:
    os.umask(0o077)  # certificate directory and key are created owner-only, like the rest of the data dir
    config = config or Config()
    cert, key = tls_files(config)
    return uvicorn.Server(
        uvicorn.Config(
            create_app(config), host=config.host, port=config.port, ssl_certfile=cert, ssl_keyfile=key,
            proxy_headers=True,  # honours FORWARDED_ALLOW_IPS: client IPs and scheme come from a trusted proxy only
        )
    )


def _db_key(config: Config) -> bytes | None:
    """The database key when encryption is on (this never creates a key file as a side effect when it is off)."""
    return config.db_key(config.resolve_secret_key()) if config.db_encryption != "off" else None


def _db_path(config: Config) -> Path:
    url = make_url(config.db_url)
    if url.get_backend_name() != "sqlite" or not url.database:
        raise ValueError("database encryption applies to SQLite files only")
    return Path(url.database)


def rotate_key(dry_run: bool = False) -> int:
    """Re-encrypt every stored secret under a new secret key. Back up the data volume first."""
    os.umask(0o077)
    config = Config()
    old_key = config.resolve_secret_key()
    new_key = os.environ.get("LANWARDEN_NEW_SECRET_KEY") or ""
    if not new_key and os.environ.get("LANWARDEN_NEW_SECRET_KEY_FILE"):
        new_key = Path(os.environ["LANWARDEN_NEW_SECRET_KEY_FILE"]).read_text().strip()
    generated = not new_key
    new_key = new_key or secrets.token_urlsafe(48)
    if len(new_key) < MIN_KEY_LENGTH or new_key == old_key:
        print(f"the new key must differ from the current one and be at least {MIN_KEY_LENGTH} characters", file=sys.stderr)
        return 1
    old_db = _db_key(config)
    new_db = derive_key(new_key, "database-v1") if old_db else None
    run_migrations(config.db_url, old_db)
    engine = make_engine(config.db_url, old_db)
    key_file = config.data_dir / "secret_key"
    staged = key_file.with_name("secret_key.new")
    try:
        with make_session_factory(engine)() as db:
            try:
                rotation.reencrypt_all(db, SecretBox(old_key), SecretBox(new_key))
            except rotation.RotationError as e:
                db.rollback()
                print(f"nothing changed: {e}", file=sys.stderr)
                return 1
            print("secret rotation completed; MFA recovery codes were cleared")
            if dry_run:
                db.rollback()
                print("dry run: nothing was written")
                return 0
            if config.secret_key_source == "data_dir":  # stage the new key before the database commits to it
                staged.write_text(new_key)
            db.commit()
        if new_db:
            with engine.connect() as conn:
                conn.exec_driver_sql(f"PRAGMA rekey = \"x'{new_db.hex()}'\"")
    finally:
        engine.dispose()
    if config.secret_key_source == "data_dir":
        os.replace(staged, key_file)
        print(f"the new key replaced {key_file}")
    else:
        where = "LANWARDEN_SECRET_KEY" if config.secret_key_source == "env" else f"the file {config.secret_key_file}"
        if generated:  # never print the key: write it to a 0600 file (umask above) for the operator to move
            staged.write_text(new_key)
            print(f"the generated key was saved to {staged}; move it into {where}, delete that file, and restart")
        else:
            print(f"now put the new key in {where} and restart")
    print("every session is signed out; regenerate MFA recovery codes in Settings")
    return 0


def encrypt_db(decrypt: bool = False) -> int:
    """Convert the database file between plain SQLite and SQLCipher (needs LANWARDEN_DB_ENCRYPTION=sqlcipher
    so the key can be derived). Stop LanWarden first."""
    os.umask(0o077)
    config = Config()
    if config.db_encryption != "sqlcipher":
        print("set LANWARDEN_DB_ENCRYPTION=sqlcipher (and the key outside the data directory) first", file=sys.stderr)
        return 1
    key = config.db_key(config.resolve_secret_key())
    path = _db_path(config)
    if not path.exists() or rotation.is_plain_sqlite(path) == decrypt:
        print(f"{path} is {'missing' if not path.exists() else 'already ' + ('plain' if decrypt else 'encrypted')}; nothing to do", file=sys.stderr)
        return 1
    backup = (rotation.decrypt_database if decrypt else rotation.encrypt_database)(path, key)
    print(f"done. The previous file was kept as {backup}; it is {'still encrypted' if decrypt else 'UNENCRYPTED and still holds everything'}.")
    if not decrypt:
        print("Delete it (and any copies) once you have checked LanWarden starts: shred -u <file>")
    return 0


def _with_user(username: str, action) -> int:
    """Run `action(db, user)` against the configured database. For operators locked out of the web UI
    (they already have shell access to the data directory, so this adds no new privilege)."""
    os.umask(0o077)
    config = Config()
    db_key = _db_key(config)
    run_migrations(config.db_url, db_key)
    engine = make_engine(config.db_url, db_key)
    try:
        with make_session_factory(engine)() as db:
            user = db.scalar(select(User).where(User.username == username))
            if user is None:
                print(f"no such user: {username}", file=sys.stderr)
                return 1
            action(db, user)
            db.commit()
            return 0
    finally:
        engine.dispose()


def reset_mfa(username: str) -> int:
    def clear(db, user):
        user.totp_enabled, user.totp_secret_enc, user.totp_last_step, user.recovery_codes = False, None, None, None
        print(f"two-step verification removed for {username}; every session is signed out")

    return _with_user(username, clear)


def reset_password(username: str) -> int:
    new = getpass.getpass("New password (min 10 characters): ")
    if len(new) < 10 or new != getpass.getpass("Repeat: "):
        print("passwords differ or are shorter than 10 characters; nothing changed", file=sys.stderr)
        return 1

    def change(db, user):
        user.password_hash = hash_password(new)
        db.execute(delete(LoginAttempt))  # and lift any lockout
        print(f"password changed for {username}; every session is signed out")

    return _with_user(username, change)


def main(argv: list[str] | None = None) -> int:
    try:
        return _main(argv)
    except (ValueError, RuntimeError) as e:  # configuration problems: say what is wrong, not a traceback
        print(f"error: {e}", file=sys.stderr)
        return 1


def _main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    command = argv[0] if argv else "serve"
    if command == "serve":
        make_server().run()
        return 0
    if command in ("reset-mfa", "reset-password") and len(argv) == 2:
        return (reset_mfa if command == "reset-mfa" else reset_password)(argv[1])
    if command == "rotate-key" and argv[1:] in ([], ["--dry-run"]):
        return rotate_key(dry_run=bool(argv[1:]))
    if command in ("encrypt-db", "decrypt-db") and len(argv) == 1:
        return encrypt_db(decrypt=command == "decrypt-db")
    print("usage: python -m app [serve | reset-mfa <user> | reset-password <user> | rotate-key [--dry-run] | encrypt-db | decrypt-db]", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
