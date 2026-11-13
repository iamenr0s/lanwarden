from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.models.enums import EventType

Provider = Literal["email", "webhook"]


class RuleIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: Annotated[str, Field(min_length=1, max_length=100)]
    provider: Provider
    event_types: Annotated[list[EventType], Field(min_length=1)]
    enabled: bool = True
    config: dict

    @model_validator(mode="after")
    def _config_matches_provider(self):
        # Local import: the provider modules are not needed to define the schema.
        from app.notifications.email_provider import EmailConfig
        from app.notifications.webhook import WebhookConfig

        {"email": EmailConfig, "webhook": WebhookConfig}[self.provider].model_validate(self.config)
        self.event_types = list(dict.fromkeys(self.event_types))
        return self


class RuleOut(BaseModel):
    id: int
    name: str
    provider: str
    event_types: list[str]
    enabled: bool
    config: dict  # secrets replaced by `<field>_set` booleans


class SendResult(BaseModel):
    ok: bool
    error: str | None = None


class DeliveryOut(BaseModel):
    id: int
    time: datetime
    rule_id: int
    rule_name: str
    provider: str
    events: int
    ok: bool
    error: str | None
