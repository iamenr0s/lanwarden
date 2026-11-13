import re
from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator

from app.services.oui import is_locally_administered

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def _clean(v: str | None) -> str | None:
    """Strip control characters and surrounding whitespace; empty becomes None."""
    if v is None:
        return None
    v = _CONTROL.sub("", v).strip()
    return v or None


class DeviceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    mac_address: str | None
    current_ip: str | None
    hostname: str | None
    friendly_name: str | None
    vendor: str | None
    vendor_override: str | None
    device_type: str | None
    model: str | None
    type_guess: str | None
    device_group: str | None
    status: str
    is_online: bool
    first_seen: datetime | None
    last_seen: datetime | None
    last_connection: datetime | None
    last_disconnection: datetime | None
    is_known: bool
    is_favorite: bool
    always_connected: bool
    alert_enabled: bool
    is_ignored: bool
    is_trusted: bool
    notes: str | None
    created_at: datetime
    updated_at: datetime

    @computed_field
    @property
    def display_name(self) -> str:
        return self.friendly_name or self.hostname or self.mac_address or self.current_ip or f"device-{self.id}"

    @computed_field
    @property
    def effective_vendor(self) -> str | None:
        return self.vendor_override or self.vendor

    @computed_field
    @property
    def effective_type(self) -> str | None:
        return self.device_type or self.type_guess

    @computed_field
    @property
    def is_randomized_mac(self) -> bool:
        """Either a phone's per-network "private" address or a spoofed one; the MAC says little about
        the hardware, so the UI marks it."""
        return is_locally_administered(self.mac_address)


class DevicePage(BaseModel):
    items: list[DeviceOut]
    total: int


class DeviceUpdate(BaseModel):
    """Only user-owned fields; unknown fields are rejected."""

    model_config = ConfigDict(extra="forbid")

    friendly_name: Annotated[str | None, Field(max_length=100)] = None
    vendor_override: Annotated[str | None, Field(max_length=255)] = None
    device_type: Annotated[str | None, Field(max_length=50)] = None
    device_group: Annotated[str | None, Field(max_length=50)] = None
    notes: Annotated[str | None, Field(max_length=2000)] = None
    is_known: bool | None = None
    is_favorite: bool | None = None
    always_connected: bool | None = None
    alert_enabled: bool | None = None
    is_ignored: bool | None = None
    is_trusted: bool | None = None

    @field_validator("friendly_name", "vendor_override", "device_type", "device_group", "notes")
    @classmethod
    def _text(cls, v: str | None) -> str | None:
        return _clean(v)

    @field_validator("is_known", "is_favorite", "always_connected", "alert_enabled", "is_ignored", "is_trusted")
    @classmethod
    def _not_null(cls, v: bool | None) -> bool | None:
        # explicit null for a boolean flag is meaningless; omit the field instead
        if v is None:
            raise ValueError("must be true or false")
        return v


class PresenceSegment(BaseModel):
    start: datetime
    end: datetime


class PresenceOut(BaseModel):
    range: str
    start: datetime
    end: datetime
    segments: list[PresenceSegment]  # online intervals only; gaps are offline/untracked
    session_count: int
    online_seconds: int
    # window length the device could have been tracked for (starts at first_seen for new devices)
    tracked_seconds: int
    online_percent: float | None


class AddressHistory(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    ip: str
    first_seen: datetime
    last_seen: datetime
    source: str | None
    current: bool = False


class NameHistory(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    name: str
    source: str
    first_seen: datetime
    last_seen: datetime


class SourceHistory(BaseModel):
    source: str
    first_observed: datetime
    last_observed: datetime
    observations: int


class NetworkOut(BaseModel):
    addresses: list[AddressHistory]
    names: list[NameHistory]
    sources: list[SourceHistory]  # from raw observations, limited by the retention setting
    observation_retention_days: int


class DeviceCounts(BaseModel):
    total: int
    online: int
    offline: int
    new: int
    unknown: int
    always_connected_down: int


class StatusOut(BaseModel):
    version: str
    devices: DeviceCounts
    anomalies_7d: int = 0  # DEVICE_ANOMALY events in the last 7 days
