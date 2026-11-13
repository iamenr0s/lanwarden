from __future__ import annotations

from datetime import datetime

from sqlalchemy import ForeignKey, Index, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base
from app.db.types import UTCDateTime, utcnow
from app.models.enums import DeviceStatus


class Device(Base):
    """One physical device. Columns are split by owner:

    scanner-owned: mac_address, current_ip, hostname, vendor, model, type_guess, presence fields
    user-owned:    friendly_name, vendor_override, device_type, device_group, flags, notes
    The scanner never writes user-owned columns, so manual values survive every scan.
    """

    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(primary_key=True)
    mac_address: Mapped[str | None] = mapped_column(String(17), unique=True, index=True)
    current_ip: Mapped[str | None] = mapped_column(String(45), index=True)
    hostname: Mapped[str | None] = mapped_column(String(255), index=True)
    vendor: Mapped[str | None] = mapped_column(String(255))
    type_guess: Mapped[str | None] = mapped_column(String(50))
    model: Mapped[str | None] = mapped_column(String(120))

    friendly_name: Mapped[str | None] = mapped_column(String(100))
    vendor_override: Mapped[str | None] = mapped_column(String(255))
    device_type: Mapped[str | None] = mapped_column(String(50))
    device_group: Mapped[str | None] = mapped_column(String(50), index=True)

    status: Mapped[str] = mapped_column(String(16), default=DeviceStatus.UNKNOWN.value, index=True)
    is_online: Mapped[bool] = mapped_column(default=False)
    first_seen: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_seen: Mapped[datetime | None] = mapped_column(UTCDateTime, index=True)
    last_connection: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_disconnection: Mapped[datetime | None] = mapped_column(UTCDateTime)

    is_known: Mapped[bool] = mapped_column(default=False)
    is_favorite: Mapped[bool] = mapped_column(default=False)
    always_connected: Mapped[bool] = mapped_column(default=False)
    alert_enabled: Mapped[bool] = mapped_column(default=True)
    is_ignored: Mapped[bool] = mapped_column(default=False)
    is_trusted: Mapped[bool] = mapped_column(default=False)
    notes: Mapped[str | None] = mapped_column(Text)

    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)

    addresses: Mapped[list[DeviceAddress]] = relationship(cascade="all, delete-orphan")
    names: Mapped[list[DeviceName]] = relationship(cascade="all, delete-orphan")
    sessions: Mapped[list[DeviceSession]] = relationship(cascade="all, delete-orphan")


class DeviceAddress(Base):
    __tablename__ = "device_addresses"
    __table_args__ = (UniqueConstraint("device_id", "ip"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"))
    ip: Mapped[str] = mapped_column(String(45), index=True)
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    source: Mapped[str | None] = mapped_column(String(128))  # comma-joined provider names


class DeviceName(Base):
    __tablename__ = "device_names"
    __table_args__ = (UniqueConstraint("device_id", "name", "source"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(255), index=True)
    source: Mapped[str] = mapped_column(String(32))
    first_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class DeviceSession(Base):
    __tablename__ = "device_sessions"
    __table_args__ = (Index("ix_device_sessions_device_connected", "device_id", "connected_at"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id", ondelete="CASCADE"))
    connected_at: Mapped[datetime] = mapped_column(UTCDateTime, index=True)
    disconnected_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    last_seen: Mapped[datetime] = mapped_column(UTCDateTime)
    source: Mapped[str | None] = mapped_column(String(128))
