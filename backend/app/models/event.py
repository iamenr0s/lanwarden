from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, ForeignKey, Index, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.types import UTCDateTime, utcnow


class Event(Base):
    __tablename__ = "events"
    __table_args__ = (Index("ix_events_device_timestamp", "device_id", "timestamp"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    # SET NULL: history outlives a deleted device
    device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id", ondelete="SET NULL"))
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    event_type: Mapped[str] = mapped_column(String(48), index=True)
    old_value: Mapped[str | None] = mapped_column(String(512))
    new_value: Mapped[str | None] = mapped_column(String(512))
    source: Mapped[str | None] = mapped_column(String(128))  # comma-joined provider names
    # "metadata" is reserved on declarative classes, so the attribute is `meta`
    meta: Mapped[dict | None] = mapped_column("metadata", JSON)

    device = relationship("Device", lazy="joined")


class DiscoveryObservation(Base):
    __tablename__ = "discovery_observations"

    id: Mapped[int] = mapped_column(primary_key=True)
    observed_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    source: Mapped[str] = mapped_column(String(32))
    mac: Mapped[str | None] = mapped_column(String(17), index=True)
    ip: Mapped[str | None] = mapped_column(String(45), index=True)
    hostname: Mapped[str | None] = mapped_column(String(255))
    vendor: Mapped[str | None] = mapped_column(String(255))
    device_id: Mapped[int | None] = mapped_column(ForeignKey("devices.id", ondelete="SET NULL"))
    meta: Mapped[dict | None] = mapped_column("metadata", JSON)
