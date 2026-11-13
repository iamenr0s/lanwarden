from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    id: int
    device_id: int | None
    device_name: str | None = None
    timestamp: datetime
    event_type: str
    old_value: str | None
    new_value: str | None
    source: str | None
    metadata: dict | None = Field(default=None, validation_alias="meta")


class EventPage(BaseModel):
    items: list[EventOut]
    total: int


class SessionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    device_id: int
    connected_at: datetime
    disconnected_at: datetime | None
    last_seen: datetime
    source: str | None
    duration_seconds: int | None = None  # filled by the API; open sessions count up to last_seen
