from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field

from pydantic import BaseModel


class NotificationError(Exception):
    """Delivery failed. The message is stored and shown in the UI: keep it short and secret-free."""


@dataclass(frozen=True)
class Message:
    title: str
    body: str  # plain-text rendering, used by email and as the `text` of webhooks
    events: list[dict] = field(default_factory=list)  # structured copy for machine consumers


class NotificationProvider(ABC):
    """To add Telegram/Discord/Slack/ntfy/Gotify/Pushover later: subclass, declare `Config`
    (pydantic), list recoverable secret fields in `secrets`, implement `send`, register in main."""

    name: str
    Config: type[BaseModel]
    secrets: tuple[str, ...] = ()  # config fields encrypted at rest and never returned by the API
    required_secrets: tuple[str, ...] = ()  # secret fields a new rule must supply (an edit may omit them to keep the stored value)
    # secret field -> function giving a non-secret description (e.g. the host of a URL) that is stored beside it
    # as `<field>_hint` so the UI can say what is configured without ever seeing the secret
    hints: dict[str, Callable[[str], str]] = {}  # noqa: RUF012  (class-level read-only table)

    @abstractmethod
    def send(self, cfg, message: Message) -> None:
        """`cfg` is a validated Config instance with secrets decrypted. Raise NotificationError."""
