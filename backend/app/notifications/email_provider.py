import re
import smtplib
import ssl
from email.message import EmailMessage
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.notifications.base import Message, NotificationError, NotificationProvider

# no whitespace (so no CR/LF header injection), no display-name forms
_ADDR = re.compile(r"^[^@\s<>,;\"']+@[^@\s<>,;\"']+\.[^@\s<>,;\"']+$")
TIMEOUT_S = 10


def _addr(v: str) -> str:
    v = v.strip()
    if not _ADDR.match(v) or len(v) > 254:
        raise ValueError(f"invalid e-mail address: {v!r}")
    return v


class EmailConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    host: Annotated[str, Field(min_length=1, max_length=255, pattern=r"^[A-Za-z0-9.\-]+$")]
    port: Annotated[int, Field(ge=1, le=65535)] = 587
    security: Literal["starttls", "ssl", "none"] = "starttls"
    username: Annotated[str, Field(max_length=255)] = ""
    password: Annotated[str | None, Field(max_length=256)] = None  # None keeps the stored one
    from_addr: str
    to_addrs: Annotated[list[str], Field(min_length=1, max_length=10)]
    verify_tls: bool = True

    @field_validator("from_addr")
    @classmethod
    def _from(cls, v: str) -> str:
        return _addr(v)

    @field_validator("to_addrs")
    @classmethod
    def _to(cls, v: list[str]) -> list[str]:
        return [_addr(a) for a in v]


class EmailProvider(NotificationProvider):
    name = "email"
    Config = EmailConfig
    secrets = ("password",)

    def __init__(self):
        self.smtp_factory = smtplib.SMTP  # tests replace these
        self.smtp_ssl_factory = smtplib.SMTP_SSL

    def send(self, cfg: EmailConfig, message: Message) -> None:
        msg = EmailMessage()
        msg["Subject"] = re.sub(r"[\r\n]+", " ", message.title)[:200]
        msg["From"] = cfg.from_addr
        msg["To"] = ", ".join(cfg.to_addrs)
        msg.set_content(message.body)
        ctx = ssl.create_default_context()
        if not cfg.verify_tls:
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        try:
            if cfg.security == "ssl":
                server = self.smtp_ssl_factory(cfg.host, cfg.port, timeout=TIMEOUT_S, context=ctx)
            else:
                server = self.smtp_factory(cfg.host, cfg.port, timeout=TIMEOUT_S)
            with server:
                if cfg.security == "starttls":
                    server.starttls(context=ctx)
                if cfg.username:
                    server.login(cfg.username, cfg.password or "")
                server.send_message(msg)
        except smtplib.SMTPAuthenticationError as e:
            raise NotificationError("SMTP authentication failed") from e
        except smtplib.SMTPRecipientsRefused as e:
            raise NotificationError("SMTP server refused the recipient address(es)") from e
        except ssl.SSLError as e:
            raise NotificationError(f"TLS error talking to {cfg.host}: {getattr(e, 'reason', None) or 'handshake failed'}") from e
        except TimeoutError as e:
            raise NotificationError(f"Timed out talking to {cfg.host}:{cfg.port}") from e
        except (smtplib.SMTPException, OSError) as e:
            raise NotificationError(f"SMTP error: {type(e).__name__} ({cfg.host}:{cfg.port})") from e
