import logging
import os
import secrets
from pathlib import Path

from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.services.crypto import MIN_KEY_LENGTH, WARN_KEY_LENGTH, derive_key

log = logging.getLogger("lanwarden.config")


def _adopt_legacy_env() -> None:
    """The project used to be called GuardAlert: honour its GUARDALERT_* variables so an upgrade does not
    silently drop settings such as the setup token or REQUIRE_MFA. LANWARDEN_* wins when both are set."""
    for key, value in list(os.environ.items()):
        if key.startswith("GUARDALERT_"):
            os.environ.setdefault("LANWARDEN_" + key[len("GUARDALERT_"):], value)


_adopt_legacy_env()


class Config(BaseSettings):
    """Process-level configuration (environment only). User-editable settings live in the DB."""

    model_config = SettingsConfigDict(env_prefix="LANWARDEN_", extra="ignore")

    data_dir: Path = Path("data")
    database_url: str | None = None
    secret_key: str | None = Field(default=None, repr=False)
    # Path of a file holding the secret key (a Docker/Podman secret, or a root-only file outside the data volume)
    secret_key_file: Path | None = None
    secure_cookies: bool = False
    session_hours: int = 24 * 7
    frontend_dir: Path = Path("frontend_dist")
    scheduler_enabled: bool = True  # tests turn the background scan loop off
    # If set, first-run setup must present it, so nobody else on the network can claim the admin account
    setup_token: str | None = Field(default=None, repr=False)
    # If true, every account must enrol a second factor before it can use the app
    require_mfa: bool = False

    # Serving (used by `python -m app`; the Dockerfile sets host 0.0.0.0)
    host: str = "127.0.0.1"
    port: int = 8080
    # Encrypt the whole database file (SQLCipher). The key is derived from the secret key, which must then NOT
    # live in the data directory (see secret_key_source), or the lock would sit next to its key.
    db_encryption: Literal["off", "sqlcipher"] = "off"

    # HTTPS: bring your own certificate, or let LanWarden generate a self-signed one in the data dir
    tls_mode: Literal["off", "selfsigned"] = "off"
    tls_cert: Path | None = None
    tls_key: Path | None = None
    tls_names: str = ""  # extra DNS names/IPs for the self-signed certificate, comma separated

    @property
    def tls_enabled(self) -> bool:
        return self.tls_mode == "selfsigned" or bool(self.tls_cert and self.tls_key)

    @property
    def cookies_secure(self) -> bool:
        """Secure cookie + HSTS: when declared (a proxy does the TLS) or when we terminate TLS ourselves."""
        return self.secure_cookies or self.tls_enabled

    @property
    def db_url(self) -> str:
        if self.database_url:
            return self.database_url
        old, new = self.data_dir / "guardalert.db", self.data_dir / "lanwarden.db"
        return f"sqlite:///{(old if old.exists() and not new.exists() else new).resolve()}"  # keep a pre-rename database

    def db_key(self, secret_key: str) -> bytes | None:
        if self.db_encryption == "off":
            return None
        if self.secret_key_source == "data_dir":
            raise ValueError(
                "LANWARDEN_DB_ENCRYPTION is on but the secret key is stored in the data directory, next to the database: "
                "anyone who copies the volume would get both. Provide the key with LANWARDEN_SECRET_KEY or LANWARDEN_SECRET_KEY_FILE."
            )
        return derive_key(secret_key, "database-v1")

    @property
    def secret_key_source(self) -> Literal["env", "file", "data_dir"]:
        """Where the master key comes from. Only "data_dir" keeps it beside the database it protects."""
        return "env" if self.secret_key else "file" if self.secret_key_file else "data_dir"

    def resolve_secret_key(self) -> str:
        """Env override, else the key file, else a random key persisted (0600) in the data dir."""
        key = self.secret_key
        if not key and self.secret_key_file:
            try:
                if self.secret_key_file.stat().st_mode & 0o077:
                    log.warning("key file %s is readable by group/others; use mode 0400 or 0600", self.secret_key_file)
                key = self.secret_key_file.read_text().strip()
            except OSError as e:
                raise ValueError(f"cannot read LANWARDEN_SECRET_KEY_FILE: {e.strerror}") from e
            if not key:
                raise ValueError("LANWARDEN_SECRET_KEY_FILE is empty")
        if key:
            if len(key) < MIN_KEY_LENGTH:
                raise ValueError(f"the secret key must be at least {MIN_KEY_LENGTH} characters (generate one: python -c 'import secrets; print(secrets.token_urlsafe(48))')")
            if len(key) < WARN_KEY_LENGTH:
                log.warning("the secret key is shorter than %d characters; a random 48-character key is recommended", WARN_KEY_LENGTH)
            return key
        self.data_dir.mkdir(parents=True, exist_ok=True)
        path = self.data_dir / "secret_key"
        if not path.exists():
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(secrets.token_urlsafe(48))
        return path.read_text().strip()
