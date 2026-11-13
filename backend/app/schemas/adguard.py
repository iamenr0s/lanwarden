from datetime import datetime
from typing import Annotated
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator


def normalize_url(raw: str) -> str:
    """http(s) URL with a host, no embedded credentials, query or fragment; trailing '/' stripped."""
    parts = urlsplit(raw.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("must be an http:// or https:// URL, e.g. http://192.168.1.2:3000")
    if parts.username or parts.password:
        raise ValueError("do not put credentials in the URL; use the username and password fields")
    if parts.query or parts.fragment:
        raise ValueError("must not contain a query string or fragment")
    try:
        parts.port  # noqa: B018  (raises on an invalid port)
    except ValueError as e:
        raise ValueError("invalid port") from e
    return raw.strip().rstrip("/")


Url = Annotated[str, Field(max_length=255)]


class AdGuardSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: Url
    username: Annotated[str, Field(max_length=128)] = ""
    verify_tls: bool = True
    timeout_seconds: Annotated[int, Field(ge=1, le=60)] = 10

    @field_validator("url")
    @classmethod
    def _url(cls, v: str) -> str:
        return normalize_url(v)


class AdGuardConfigIn(AdGuardSettings):
    # None keeps the stored password; there is no way to read it back
    password: Annotated[str | None, Field(max_length=256)] = None


class AdGuardConfigOut(BaseModel):
    configured: bool
    url: str | None = None
    username: str = ""
    verify_tls: bool = True
    timeout_seconds: int = 10
    password_set: bool = False


class AdGuardTestIn(BaseModel):
    """Every field optional: omitted ones fall back to the saved configuration."""

    model_config = ConfigDict(extra="forbid")

    url: Url | None = None
    username: Annotated[str | None, Field(max_length=128)] = None
    password: Annotated[str | None, Field(max_length=256)] = None
    verify_tls: bool | None = None
    timeout_seconds: Annotated[int | None, Field(ge=1, le=60)] = None

    @field_validator("url")
    @classmethod
    def _url(cls, v: str | None) -> str | None:
        return normalize_url(v) if v else None


class ErrorInfo(BaseModel):
    kind: str
    message: str


class ServerInfo(BaseModel):
    version: str
    running: bool | None = None
    protection_enabled: bool | None = None
    dns_addresses: list[str] = []
    dns_port: int | None = None
    http_port: int | None = None
    language: str | None = None


class AdGuardTestResult(BaseModel):
    ok: bool
    error: ErrorInfo | None = None
    server: ServerInfo | None = None
    dhcp_enabled: bool | None = None
    dhcp_leases: int | None = None
    configured_clients: int | None = None


class AdGuardHealth(BaseModel):
    configured: bool
    reachable: bool = False
    server: ServerInfo | None = None
    error: ErrorInfo | None = None


class AdGuardQuery(BaseModel):
    time: datetime | None
    domain: str
    type: str | None
    blocked: bool
    reason: str | None


class AdGuardDomainCount(BaseModel):
    domain: str
    count: int


class DeviceAdGuard(BaseModel):
    configured: bool
    available: bool = False
    error: ErrorInfo | None = None
    recognized: bool = False
    client_name: str | None = None
    client_ids: list[str] = []
    stats_queries: int | None = None  # from /stats top_clients, in AdGuard's own stats window
    sample_size: int = 0  # query-log entries examined below
    sample_blocked: int = 0
    last_query: datetime | None = None
    top_domains: list[AdGuardDomainCount] = []
    recent: list[AdGuardQuery] = []
