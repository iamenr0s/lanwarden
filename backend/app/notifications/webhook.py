import hashlib
import hmac
import json
from typing import Annotated
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.notifications.base import Message, NotificationError, NotificationProvider

TIMEOUT_S = 10


class WebhookConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: Annotated[str | None, Field(max_length=2000)] = None  # a webhook URL is a bearer token: write-only, None keeps the stored one
    secret: Annotated[str | None, Field(max_length=256)] = None  # signs the body; None keeps the stored one
    verify_tls: bool = True

    @field_validator("url")
    @classmethod
    def _url(cls, v: str | None) -> str | None:
        if v is None:
            return None
        parts = urlsplit(v.strip())
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError("must be an http:// or https:// URL")
        if parts.username or parts.password:
            raise ValueError("do not put credentials in the URL")
        return v.strip()


def _mask_url(url: str) -> str:
    """Where the hook points, without the path/query that usually carries the token."""
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}/…"


class WebhookProvider(NotificationProvider):
    """POSTs JSON: {source, title, text, events[]}. `text` makes it directly usable with Slack-style
    incoming webhooks. With a secret, the body is signed: X-LanWarden-Signature: sha256=<hmac hex>."""

    name = "webhook"
    Config = WebhookConfig
    secrets = ("secret", "url")
    required_secrets = ("url",)
    hints = {"url": _mask_url}

    def __init__(self):
        self.transport: httpx.BaseTransport | None = None  # tests inject a mock

    def send(self, cfg: WebhookConfig, message: Message) -> None:
        if not cfg.url:
            raise NotificationError("No webhook URL is configured")
        body = json.dumps(
            {"source": "lanwarden", "title": message.title, "text": f"{message.title}\n{message.body}", "events": message.events},
            separators=(",", ":"),
        ).encode()
        headers = {"Content-Type": "application/json", "User-Agent": "LanWarden"}
        if cfg.secret:
            headers["X-LanWarden-Signature"] = "sha256=" + hmac.new(cfg.secret.encode(), body, hashlib.sha256).hexdigest()
        host = urlsplit(cfg.url).hostname
        try:
            with httpx.Client(timeout=TIMEOUT_S, verify=cfg.verify_tls, follow_redirects=False, transport=self.transport) as c:
                resp = c.post(cfg.url, content=body, headers=headers)
        except httpx.TimeoutException as e:
            raise NotificationError(f"Timed out contacting {host}") from e
        except httpx.HTTPError as e:  # never echo the URL: it may carry a token
            raise NotificationError(f"Could not reach {host} ({type(e).__name__})") from e
        if resp.status_code >= 300:
            raise NotificationError(f"{host} answered HTTP {resp.status_code}")
